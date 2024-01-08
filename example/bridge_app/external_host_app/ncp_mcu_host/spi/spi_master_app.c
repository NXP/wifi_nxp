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

/*******************************************************************************
 * Variables
 ******************************************************************************/
AT_NONCACHEABLE_SECTION_INIT(lpspi_master_edma_handle_t masterHandle) = {0};
edma_handle_t masterTxHandle;
edma_handle_t masterRxHandle;

edma_config_t userConfig = {0};

extern os_thread_t ncp_host_tlv_thread;
#define SPI_MASTER_INT_RX_MASK 0x10000
#define SPI_MASTER_INT_TX_MASK 0x20000
os_semaphore_t spi_master_sem;
os_semaphore_t spi_master_txrx_done;

/*******************************************************************************
 * Code
 ******************************************************************************/
void NCP_HOST_GPIO_IRQ_HANDLER(void)
{
    uint32_t status = 0;
    DisableIRQ(NCP_HOST_GPIO_IRQ);

    status = GPIO_PortGetInterruptFlags(NCP_HOST_GPIO);
    /* Notify mcu bridge resp task */
    if (status & SPI_MASTER_INT_RX_MASK)
    {
        GPIO_PortClearInterruptFlags(NCP_HOST_GPIO, 1U << NCP_HOST_GPIO_PIN_RX);
        os_event_notify_put(ncp_host_tlv_thread);
    }
    if (status & SPI_MASTER_INT_TX_MASK)
    {
        GPIO_PortClearInterruptFlags(NCP_HOST_GPIO, 1U << NCP_HOST_GPIO_PIN_TX);
        os_semaphore_put(&spi_master_sem);
    }
    EnableIRQ(NCP_HOST_GPIO_IRQ);
}

static void ncp_host_spi_master_cb(LPSPI_Type *base,
                                   lpspi_master_edma_handle_t *handle,
                                   status_t status,
                                   void *userData)
{
    if (status == kStatus_Success)
    {
        os_semaphore_put(&spi_master_txrx_done);
    }
}

int ncp_host_spi_master_transfer(uint8_t *buff, uint16_t data_size, int transfer_type, uint8_t is_header)
{
    int ret = 0;
    lpspi_transfer_t masterXfer;
    uint16_t len = 0;
    uint8_t *p   = NULL;

    /* Fill SPI transfer config */
    if (transfer_type == NCP_HOST_MASTER_TX)
    {
        /* Wait for slave Rx is ready */
        os_semaphore_get(&spi_master_sem, OS_WAIT_FOREVER);
        len = data_size;
        p   = buff;
        /* Send command header first */
        masterXfer.txData   = buff;
        masterXfer.rxData   = NULL;
        masterXfer.dataSize = NCP_BRIDGE_CMD_HEADER_LEN;

        ret = (int)LPSPI_MasterTransferEDMALite(EXAMPLE_LPSPI_MASTER_BASEADDR, &masterHandle, &masterXfer);
        if (ret)
        {
            (void)PRINTF("Error occurred in SPI_MasterTransferDMA\r\n");
            goto done;
        }
        /* Wait for both tx and rx DMA are done */
        os_semaphore_get(&spi_master_txrx_done, OS_WAIT_FOREVER);
        len -= NCP_BRIDGE_CMD_HEADER_LEN;
        p += NCP_BRIDGE_CMD_HEADER_LEN;
        while (len)
        {
            masterXfer.txData = p;
            masterXfer.rxData = NULL;
            if (len <= DMA_MAX_TRANSFER_COUNT)
                masterXfer.dataSize = len;
            else
                masterXfer.dataSize = DMA_MAX_TRANSFER_COUNT;
            os_semaphore_get(&spi_master_sem, OS_WAIT_FOREVER);
            ret = (int)LPSPI_MasterTransferEDMALite(EXAMPLE_LPSPI_MASTER_BASEADDR, &masterHandle, &masterXfer);
            if (ret)
            {
                (void)PRINTF("Error occurred in SPI_MasterTransferDMA\r\n");
                goto done;
            }
            os_semaphore_get(&spi_master_txrx_done, OS_WAIT_FOREVER);
            len -= masterXfer.dataSize;
            p += masterXfer.dataSize;
        }
    }
    else if (transfer_type == NCP_HOST_MASTER_RX)
    {
        if (is_header)
        {
            masterXfer.txData   = NULL;
            masterXfer.rxData   = buff;
            masterXfer.dataSize = data_size;
            ret = (int)LPSPI_MasterTransferEDMALite(EXAMPLE_LPSPI_MASTER_BASEADDR, &masterHandle, &masterXfer);
            if (ret)
            {
                (void)PRINTF("Error occurred in SPI_MasterTransferDMA\r\n");
                goto done;
            }
            os_semaphore_get(&spi_master_txrx_done, OS_WAIT_FOREVER);
        }
        else
        {
            len = data_size;
            p   = buff;
            while (len)
            {
                masterXfer.txData = NULL;
                masterXfer.rxData = p;
                if (len <= DMA_MAX_TRANSFER_COUNT)
                    masterXfer.dataSize = len;
                else
                    masterXfer.dataSize = DMA_MAX_TRANSFER_COUNT;
                os_event_notify_get(OS_WAIT_FOREVER);
                ret = (int)LPSPI_MasterTransferEDMALite(EXAMPLE_LPSPI_MASTER_BASEADDR, &masterHandle, &masterXfer);
                if (ret)
                {
                    (void)PRINTF("Error occurred in SPI_MasterTransferDMA\r\n");
                    goto done;
                }
                os_semaphore_get(&spi_master_txrx_done, OS_WAIT_FOREVER);
                len -= masterXfer.dataSize;
                p += masterXfer.dataSize;
            }
        }
    }
done:
    return ret;
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
    /* Define the init structure for the input switch pin */
    gpio_pin_config_t gpio_input_interrupt_config = {
        kGPIO_DigitalInput,
        0,
        kGPIO_IntRisingEdge,
    };

    GPIO_PinInit(NCP_HOST_GPIO, NCP_HOST_GPIO_PIN_RX, &gpio_input_interrupt_config);
    GPIO_PinInit(NCP_HOST_GPIO, NCP_HOST_GPIO_PIN_TX, &gpio_input_interrupt_config);
    NVIC_SetPriority(NCP_HOST_GPIO_IRQ, NCP_HOST_GPIO_IRQ_PRIO);
    EnableIRQ(NCP_HOST_GPIO_IRQ);
    /* Enable GPIO pin interrupt */
    GPIO_PortEnableInterrupts(NCP_HOST_GPIO, 1U << NCP_HOST_GPIO_PIN_RX);
    GPIO_PortEnableInterrupts(NCP_HOST_GPIO, 1U << NCP_HOST_GPIO_PIN_TX);

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
    ret = os_semaphore_create(&spi_master_sem, "spi master semaphore");
    if (ret != WM_SUCCESS)
    {
        PRINTF("Create spi master sem failed");
        return ret;
    }
    ret = os_semaphore_create(&spi_master_txrx_done, "spi master txrx done semaphore");
    if (ret != WM_SUCCESS)
    {
        PRINTF("Create spi master txrx done sem failed");
        return ret;
    }
    os_semaphore_get(&spi_master_txrx_done, OS_NO_WAIT);

    /*Set clock source for LPSPI*/
    CLOCK_SetMux(kCLOCK_LpspiMux, EXAMPLE_LPSPI_CLOCK_SOURCE_SELECT);
    CLOCK_SetDiv(kCLOCK_LpspiDiv, EXAMPLE_LPSPI_CLOCK_SOURCE_DIVIDER);
    ret = ncp_host_master_init();
    if (ret != WM_SUCCESS)
    {
        PRINTF("Failed to initialize SPI master(%d)\r\n", ret);
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