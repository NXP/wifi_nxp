/** @file spi_master_app.c
 *
 *  @brief main file
 *
 *  Copyright 2023 NXP
 *  All rights reserved.
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#ifdef CONFIG_SPI_BRIDGE
#include "stdint.h"
#include "spi_master_app.h"
#include "fsl_lpspi.h"
#include "fsl_clock.h"
#include "fsl_edma.h"
#include "fsl_iomuxc.h"
#include "fsl_dmamux.h"
#include "fsl_lpspi_edma.h"
#include "ncp_mcu_host_utils.h"
#include "ncp_mcu_host_cli.h"
#include "ncp_mcu_host_app.h"
#include "fsl_gpio.h"
#include "ncp_mcu_host_os.h"
#include "ncp_mcu_host_command.h"
#include "fsl_adapter_gpio.h"
#include "fsl_os_abstraction.h"

/*******************************************************************************
 * Variables
 ******************************************************************************/
AT_NONCACHEABLE_SECTION_INIT(lpspi_master_edma_handle_t masterHandle) = {0};
edma_handle_t masterTxHandle;
edma_handle_t masterRxHandle;

edma_config_t userConfig = {0};

extern os_thread_t ncp_host_tlv_thread;
/* for slave inform master prepare dma ready */
os_semaphore_t spi_slave_rx_ready;
/* for inform master transfer complete with slave */
os_semaphore_t spi_slave_tx_complete;
/* for spi tx and rx sync */
OSA_EVENT_HANDLE_DEFINE(spi_master_event);

GPIO_HANDLE_DEFINE(NcpTlvSpiRxDetectGpioHandle);
GPIO_HANDLE_DEFINE(NcpTlvSpiRxReadyDetectGpioHandle);


uint32_t spi_master_buff[(OSA_EVENT_HANDLE_SIZE + 3) / 4];

static int ncp_spi_state = NCP_MASTER_SPI_IDLE;

/*******************************************************************************
 * Code
 ******************************************************************************/
static void rx_int_callback(void *param)
{
    switch(ncp_spi_state)
    {
        case NCP_MASTER_SPI_IDLE:
            /* the first salve interrupt is to tell master that slave wants to send data */
            ncp_spi_state = NCP_MASTER_SPI_RX;
            mcu_d(" spi slave want to send data");
            OSA_EventClear(spi_master_event, MASTER_TX_ENABLE_EVENT);
            OSA_EventSet(spi_master_event, MASTER_RX_ENABLE_EVENT);
            break;
        case NCP_MASTER_SPI_TX:
            mcu_e(" receive the slave interrupt when master starts to send data is a Low probability event, prioritize data transmission for master");
            mcu_d(" spi master want to send data");
            /* slave tx have priority over master tx */
            ncp_spi_state = NCP_MASTER_SPI_RX;
            os_semaphore_put(&spi_slave_rx_ready);
            break;
        case NCP_MASTER_SPI_RX:
            mcu_e(" receive the slave interrupt when master is sending data is impossible ");
            break;
        default:
            mcu_e("spi invalid state");
            ncp_spi_state = NCP_MASTER_SPI_IDLE;
            break;
    }
}

/*******************************************************************************
 * Code
 ******************************************************************************/
static void rx_ready_int_callback(void *param)
{
    os_semaphore_put(&spi_slave_rx_ready);
}

static void ncp_host_spi_master_cb(LPSPI_Type *base,
                                   lpspi_master_edma_handle_t *handle,
                                   status_t status,
                                   void *userData)
{
     os_semaphore_put(&spi_slave_tx_complete);
}

static void ncp_host_master_send_signal(void)
{
    /* Toggle GPIO is used for master inform slave to rx data. */
    GPIO_PortToggle(NCP_HOST_GPIO, NCP_HOST_GPIO_TX_MASK);
    /* Change GPIO signal level with twice toggle operations */
    GPIO_PortToggle(NCP_HOST_GPIO, NCP_HOST_GPIO_TX_MASK);
}

int ncp_host_spi_master_tx(uint8_t *buff, uint16_t data_size)
{
    int ret = 0;
    lpspi_transfer_t masterXfer;
    uint16_t len = 0;
    uint8_t *p   = NULL;

    osa_event_flags_t events;
    OSA_SR_ALLOC();
resend:
    /* wait tx enable event */
    OSA_EventWait(spi_master_event, MASTER_TX_ENABLE_EVENT, 0, osaWaitForever_c, &events);
    OSA_ENTER_CRITICAL();
    /* check whether receive the slave interrupt before OSA_ENTER_CRITICAL*/
    if (ncp_spi_state == NCP_MASTER_SPI_RX)
    {
        OSA_EXIT_CRITICAL();
        mcu_e("receive the slave interrupt when master starts to send data, try to resend");
        goto resend;
    }
    /* inform slave about master wants to send cmd */
    ncp_host_master_send_signal();
    ncp_spi_state = NCP_MASTER_SPI_TX;
    OSA_EXIT_CRITICAL();

    os_semaphore_get(&spi_slave_rx_ready, OS_WAIT_FOREVER);
    /* the master tx is dropped by slave */
    if (ncp_spi_state == NCP_MASTER_SPI_RX)
    {
        goto resend;
    }
    /* Fill SPI transfer config */
    len = data_size;
    p   = buff;
    /* Send command header first */
    masterXfer.txData   = p;
    masterXfer.rxData   = NULL;
    masterXfer.dataSize = NCP_BRIDGE_CMD_HEADER_LEN;
    ret = (int)LPSPI_MasterTransferEDMALite(EXAMPLE_LPSPI_MASTER_BASEADDR, &masterHandle, &masterXfer);
    if (ret)
    {
        mcu_e("line = %d, read spi slave rx ready fail", __LINE__);
        goto done;
    }
    os_semaphore_get(&spi_slave_tx_complete, OS_WAIT_FOREVER);

    len -= NCP_BRIDGE_CMD_HEADER_LEN;
    p += NCP_BRIDGE_CMD_HEADER_LEN;
    while (len)
    {
        os_semaphore_get(&spi_slave_rx_ready, OS_WAIT_FOREVER);
        masterXfer.txData = p;
        masterXfer.rxData = NULL;
        if (len <= DMA_MAX_TRANSFER_COUNT)
            masterXfer.dataSize = len;
        else
            masterXfer.dataSize = DMA_MAX_TRANSFER_COUNT;
        ret = (int)LPSPI_MasterTransferEDMALite(EXAMPLE_LPSPI_MASTER_BASEADDR, &masterHandle, &masterXfer);
        if (ret)
        {
            mcu_e("line = %d, read spi slave rx ready fail", __LINE__);
            goto done;
        }
        os_semaphore_get(&spi_slave_tx_complete, OS_WAIT_FOREVER);
        len -= masterXfer.dataSize;
        p += masterXfer.dataSize;
    }
done:
    ncp_spi_state = NCP_MASTER_SPI_IDLE;
    OSA_EventSet(spi_master_event, MASTER_TX_ENABLE_EVENT);
    mcu_d("ncp master spi send data finished");
    return ret;
}

int ncp_host_spi_master_rx(uint8_t *buff)
{
    int ret = 0;
    lpspi_transfer_t masterXfer;
    uint16_t total_len = 0, resp_len = 0, len = 0;
    uint8_t *p   = NULL;
    osa_event_flags_t events;

    /* wait rx enable event */
    OSA_EventWait(spi_master_event, MASTER_RX_ENABLE_EVENT, 0, osaWaitForever_c, &events);
    os_semaphore_get(&spi_slave_rx_ready, OS_WAIT_FOREVER);
    p  = buff;
    masterXfer.txData   = NULL;
    masterXfer.rxData   = p;
    masterXfer.dataSize = NCP_BRIDGE_CMD_HEADER_LEN;
    ret = (int)LPSPI_MasterTransferEDMALite(EXAMPLE_LPSPI_MASTER_BASEADDR, &masterHandle, &masterXfer);
    if (ret)
    {
        mcu_e("line = %d, read spi slave rx ready fail", __LINE__);
        goto done;
    }
    os_semaphore_get(&spi_slave_tx_complete, OS_WAIT_FOREVER);

    /* Length of the packet is indicated by byte[4] & byte[5] of
     * the packet excluding checksum [4 bytes]*/
    resp_len = (p[NCP_HOST_CMD_SIZE_HIGH_BYTE] << 8) | p[NCP_HOST_CMD_SIZE_LOW_BYTE];
    total_len = resp_len + MCU_CHECKSUM_LEN;
    if (resp_len < NCP_BRIDGE_CMD_HEADER_LEN || total_len >= NCP_HOST_RESPONSE_LEN)
    {
        mcu_e("Invalid tlv reponse length from ncp bridge");
        goto done;
    }
    len = total_len - NCP_BRIDGE_CMD_HEADER_LEN;
    p += NCP_BRIDGE_CMD_HEADER_LEN;
    while (len)
    {
        os_semaphore_get(&spi_slave_rx_ready, OS_WAIT_FOREVER);
        masterXfer.txData = NULL;
        masterXfer.rxData = p;
        if (len <= DMA_MAX_TRANSFER_COUNT)
            masterXfer.dataSize = len;
        else
            masterXfer.dataSize = DMA_MAX_TRANSFER_COUNT;
        ret = (int)LPSPI_MasterTransferEDMALite(EXAMPLE_LPSPI_MASTER_BASEADDR, &masterHandle, &masterXfer);
        if (ret)
        {
            mcu_e("line = %d, read spi slave rx ready fail", __LINE__);
            goto done;
        }
        os_semaphore_get(&spi_slave_tx_complete, OS_WAIT_FOREVER);
        len -= masterXfer.dataSize;
        p += masterXfer.dataSize;
    }
done:
    ncp_spi_state = NCP_MASTER_SPI_IDLE;
    OSA_EventSet(spi_master_event, MASTER_TX_ENABLE_EVENT);
    return total_len;
}

static void ncp_host_master_dma_setup(void)
{
/*DMA Mux setting and EDMA init*/
#if defined(FSL_FEATURE_SOC_DMAMUX_COUNT) && FSL_FEATURE_SOC_DMAMUX_COUNT
    /* DMA MUX init*/
    DMAMUX_Init(EXAMPLE_LPSPI_MASTER_DMA_MUX_BASE);

    DMAMUX_SetSource(EXAMPLE_LPSPI_MASTER_DMA_MUX_BASE, EXAMPLE_LPSPI_MASTER_DMA_RX_CHANNEL,
                     EXAMPLE_LPSPI_MASTER_DMA_RX_REQUEST_SOURCE);
    DMAMUX_EnableChannel(EXAMPLE_LPSPI_MASTER_DMA_MUX_BASE, EXAMPLE_LPSPI_MASTER_DMA_RX_CHANNEL);

    DMAMUX_SetSource(EXAMPLE_LPSPI_MASTER_DMA_MUX_BASE, EXAMPLE_LPSPI_MASTER_DMA_TX_CHANNEL,
                     EXAMPLE_LPSPI_MASTER_DMA_TX_REQUEST_SOURCE);
    DMAMUX_EnableChannel(EXAMPLE_LPSPI_MASTER_DMA_MUX_BASE, EXAMPLE_LPSPI_MASTER_DMA_TX_CHANNEL);
#endif
    /* EDMA init*/
    EDMA_GetDefaultConfig(&userConfig);
#if defined(BOARD_GetEDMAConfig)
    BOARD_GetEDMAConfig(userConfig);
#endif
    EDMA_Init(EXAMPLE_LPSPI_MASTER_DMA_BASE, &userConfig);

    /*Set up lpspi master*/
    memset(&(masterRxHandle), 0, sizeof(masterRxHandle));
    memset(&(masterTxHandle), 0, sizeof(masterTxHandle));

    EDMA_CreateHandle(&(masterRxHandle), EXAMPLE_LPSPI_MASTER_DMA_BASE, EXAMPLE_LPSPI_MASTER_DMA_RX_CHANNEL);
    EDMA_CreateHandle(&(masterTxHandle), EXAMPLE_LPSPI_MASTER_DMA_BASE, EXAMPLE_LPSPI_MASTER_DMA_TX_CHANNEL);
#if defined(FSL_FEATURE_EDMA_HAS_CHANNEL_MUX) && FSL_FEATURE_EDMA_HAS_CHANNEL_MUX
    EDMA_SetChannelMux(EXAMPLE_LPSPI_MASTER_DMA_BASE, EXAMPLE_LPSPI_MASTER_DMA_TX_CHANNEL,
                       DEMO_LPSPI_TRANSMIT_EDMA_CHANNEL);
    EDMA_SetChannelMux(EXAMPLE_LPSPI_MASTER_DMA_BASE, EXAMPLE_LPSPI_MASTER_DMA_RX_CHANNEL,
                       DEMO_LPSPI_RECEIVE_EDMA_CHANNEL);
#endif
    NVIC_SetPriority(DMA0_DMA16_IRQn, NCP_HOST_DMA_IRQ_PRIO);
    NVIC_SetPriority(DMA1_DMA17_IRQn, NCP_HOST_DMA_IRQ_PRIO);
}

static int ncp_host_master_init(void)
{
    /* SPI init */
    int ret              = 0;
    uint32_t srcClock_Hz = 0U;
    lpspi_master_config_t masterConfig;
    srcClock_Hz = LPSPI_MASTER_CLK_FREQ;

    LPSPI_MasterGetDefaultConfig(&masterConfig);
    masterConfig.baudRate                      = NCP_SPI_MASTER_CLOCK; // decrease this value for testing purpose.
    masterConfig.whichPcs                      = kLPSPI_Pcs0;
    masterConfig.pcsToSckDelayInNanoSec        = 1000000000U / (masterConfig.baudRate * 2U);
    masterConfig.lastSckToPcsDelayInNanoSec    = 1000000000U / (masterConfig.baudRate * 2U);
    masterConfig.betweenTransferDelayInNanoSec = 1000000000U / (masterConfig.baudRate * 2U);

    srcClock_Hz = LPSPI_MASTER_CLK_FREQ;
    LPSPI_MasterInit(EXAMPLE_LPSPI_MASTER_BASEADDR, &masterConfig, srcClock_Hz);

    return ret;
}

void ncp_host_gpio_init(void)
{
    /* rx input interrupt */
    hal_gpio_pin_config_t rx_config = {
        kHAL_GpioDirectionIn,
        0,
        NCP_HOST_GPIO_NUM,
        NCP_HOST_GPIO_PIN_RX,
    };
    HAL_GpioInit(NcpTlvSpiRxDetectGpioHandle, &rx_config);
    HAL_GpioSetTriggerMode(NcpTlvSpiRxDetectGpioHandle, kHAL_GpioInterruptRisingEdge);
    HAL_GpioInstallCallback(NcpTlvSpiRxDetectGpioHandle, rx_int_callback, NULL);

    /* rx_ready input interrupt */
    hal_gpio_pin_config_t rx_ready_config = {
        kHAL_GpioDirectionIn,
        0,
        NCP_HOST_GPIO_NUM,
        NCP_HOST_GPIO_PIN_RX_READY,
    };
    HAL_GpioInit(NcpTlvSpiRxReadyDetectGpioHandle, &rx_ready_config);
    HAL_GpioSetTriggerMode(NcpTlvSpiRxReadyDetectGpioHandle, kHAL_GpioInterruptRisingEdge);
    HAL_GpioInstallCallback(NcpTlvSpiRxReadyDetectGpioHandle, rx_ready_int_callback, NULL);

    NVIC_SetPriority(NCP_HOST_GPIO_IRQ, NCP_HOST_GPIO_IRQ_PRIO);
    EnableIRQ(NCP_HOST_GPIO_IRQ);

    /* Enable GPIO pin interrupt */
    GPIO_PortEnableInterrupts(NCP_HOST_GPIO, 1U << NCP_HOST_GPIO_PIN_RX);
    /* Enable GPIO pin rx_ready interrupt */
    GPIO_PortEnableInterrupts(NCP_HOST_GPIO, 1U << NCP_HOST_GPIO_PIN_RX_READY);
/*
    GPIO_PinInit(NCP_HOST_GPIO, NCP_HOST_GPIO_PIN_TX, &gpio_input_interrupt_config);
    hal_gpio_pin_config_t tx_config = {
        kHAL_GpioDirectionIn,
        0,
        NCP_HOST_GPIO_NUM,
        NCP_HOST_GPIO_PIN_TX,
    };
    HAL_GpioInit(NcpTlvSpiTxDetectGpioHandle, &tx_config);
    HAL_GpioSetTriggerMode(NcpTlvSpiTxDetectGpioHandle, kHAL_GpioInterruptRisingEdge);
    HAL_GpioInstallCallback(NcpTlvSpiTxDetectGpioHandle, tx_int_callback, NULL);
    GPIO_PortEnableInterrupts(NCP_HOST_GPIO, 1U << NCP_HOST_GPIO_PIN_TX);
*/
    /* tx output notify spi slave */
    const gpio_pin_config_t tx_config = {
        kGPIO_DigitalOutput,
        1,
        kGPIO_NoIntmode,
    };
    GPIO_PinInit(NCP_HOST_GPIO, NCP_HOST_GPIO_PIN_TX, &tx_config);

    IOMUXC_SetPinMux(IOMUXC_GPIO_SD_B0_00_LPSPI1_SCK, 0U);
    IOMUXC_SetPinMux(IOMUXC_GPIO_SD_B0_01_LPSPI1_PCS0, 0U);
    IOMUXC_SetPinMux(IOMUXC_GPIO_SD_B0_02_LPSPI1_SDO, 0U);
    IOMUXC_SetPinMux(IOMUXC_GPIO_SD_B0_03_LPSPI1_SDI, 0U);
    IOMUXC_SetPinConfig(IOMUXC_GPIO_SD_B0_00_LPSPI1_SCK, 0x10B0U);
    IOMUXC_SetPinConfig(IOMUXC_GPIO_SD_B0_01_LPSPI1_PCS0, 0x10B0U);
    IOMUXC_SetPinConfig(IOMUXC_GPIO_SD_B0_02_LPSPI1_SDO, 0x10B0U);
    IOMUXC_SetPinConfig(IOMUXC_GPIO_SD_B0_03_LPSPI1_SDI, 0x10B0U);
}

int ncp_host_init_spi_master(void)
{
    int ret = WM_SUCCESS;
    ncp_host_gpio_init();
    ret = OSA_EventCreate(spi_master_event, 1);
    if (ret != kStatus_Success)
    {
        mcu_e("Create spi slave event fail");
        return ret;
    }
    OSA_EventSet(spi_master_event, MASTER_TX_ENABLE_EVENT);
    ret = os_semaphore_create(&spi_slave_tx_complete, "spi_slave_tx_complete");
    if (ret != WM_SUCCESS)
    {
        mcu_e("Error: Failed to create spi_slave_tx_complete semaphore: %d", ret);
        return -WM_FAIL;
    }
    os_semaphore_get(&spi_slave_tx_complete, OS_WAIT_FOREVER);
    ret = os_semaphore_create(&spi_slave_rx_ready, "spi_slave_rx_ready");
    if (ret != WM_SUCCESS)
    {
        mcu_e("Error: Failed to create spi_slave_rx_ready semaphore: %d", ret);
        return -WM_FAIL;
    }
    os_semaphore_get(&spi_slave_rx_ready, OS_WAIT_FOREVER);
    /*Set clock source for LPSPI*/
    CLOCK_SetMux(kCLOCK_LpspiMux, EXAMPLE_LPSPI_CLOCK_SOURCE_SELECT);
    CLOCK_SetDiv(kCLOCK_LpspiDiv, EXAMPLE_LPSPI_CLOCK_SOURCE_DIVIDER);
    ret = ncp_host_master_init();
    if (ret != WM_SUCCESS)
    {
        mcu_e("Failed to initialize SPI master(%d)", ret);
        return ret;
    }
    ncp_host_master_dma_setup();
    /* Set up handle for spi master */
    LPSPI_MasterTransferCreateHandleEDMA(EXAMPLE_LPSPI_MASTER_BASEADDR, &masterHandle, ncp_host_spi_master_cb, NULL,
                                         &masterRxHandle, &masterTxHandle);
    LPSPI_MasterTransferPrepareEDMALite(
        EXAMPLE_LPSPI_MASTER_BASEADDR, &masterHandle,
        EXAMPLE_LPSPI_MASTER_PCS_FOR_TRANSFER | kLPSPI_MasterByteSwap | kLPSPI_MasterPcsContinuous);
    return ret;
}
#endif /* CONFIG_SPI_BRIDGE */