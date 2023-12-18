/** @file spi_master_app.c
 *
 *  @brief main file
 *
 *  Copyright 2023 NXP
 *  All rights reserved.
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include "stdint.h"
#include "spi_master_app.h"
#include "fsl_spi.h"
#include "fsl_spi_dma.h"
#include "fsl_dma.h"
#include "ncp_host_utils.h"
#include "ncp_host_command.h"
#include "fsl_gpio.h"
#include "ncp_host_os.h"

/*******************************************************************************
 * Variables
 ******************************************************************************/
dma_handle_t masterTxHandle;
dma_handle_t masterRxHandle;
spi_dma_handle_t masterHandle;
/* Define the init structure for the input switch pin */
gpio_pin_config_t input_pin = {
    kGPIO_DigitalInput,
    0
};
gpio_interrupt_config_t input_pin_cfg = {
    kGPIO_PinIntEnableEdge,
    kGPIO_PinIntEnableHighOrRise
};
extern os_thread_t ncp_host_resp_thread;
#define BOARD_DEBUG_FLEXCOMM0_FRG_CLK \
    (&(const clock_frg_clk_config_t){0, kCLOCK_FrgMainClk, 255, 0})
#define SPI_MASTER_INT_RX_MASK 0x8000000
#define SPI_MASTER_INT_TX_MASK 0x800
os_semaphore_t spi_master_sem;
os_semaphore_t spi_master_txrx_done;

/*******************************************************************************
 * Code
 ******************************************************************************/
void GPIO_INTA_IRQHandler(void)
{
    uint32_t status = 0;

    DisableIRQ(GPIO_INTA_IRQn);
    status = GPIO_PortGetInterruptStatus(GPIO, NCP_HOST_GPIO_PORT, 0);
    /* Notify mcu bridge resp task */
    if(status & SPI_MASTER_INT_RX_MASK)
    {
        GPIO_PinClearInterruptFlag(GPIO, NCP_HOST_GPIO_PORT, NCP_HOST_GPIO_PIN_RX, 0);
        os_event_notify_put(ncp_host_resp_thread);
    }
    if(status & SPI_MASTER_INT_TX_MASK)
    {
        GPIO_PinClearInterruptFlag(GPIO, NCP_HOST_GPIO_PORT, NCP_HOST_GPIO_PIN_TX, 0);
        os_semaphore_put(&spi_master_sem);
    }
    EnableIRQ(GPIO_INTA_IRQn);
}

static void ncp_host_spi_master_cb(SPI_Type *base,
                                     spi_dma_handle_t *handle,
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
    spi_transfer_t masterXfer;
    uint16_t len = 0;
    uint8_t *p = NULL;

    /* Fill SPI transfer config */
    if(transfer_type == NCP_HOST_MASTER_TX)
    {
        /* Wait for slave Rx is ready */
        os_semaphore_get(&spi_master_sem, OS_WAIT_FOREVER);
        len = data_size;
        p = buff;
        /* Send command header first */
        masterXfer.txData = buff;
        masterXfer.rxData = NULL;
        masterXfer.dataSize = NCP_BRIDGE_CMD_HEADER_LEN;
        masterXfer.configFlags = kSPI_FrameAssert;
        ret = (int)SPI_MasterTransferDMA(NCP_HOST_SPI_MASTER, &masterHandle, &masterXfer);
        if(ret)
        {
            (void)PRINTF("Error occurred in SPI_MasterTransferDMA\r\n");
            goto done;
        }
        /* Wait for both tx and rx DMA are done */
        os_semaphore_get(&spi_master_txrx_done, OS_WAIT_FOREVER);
        len -= NCP_BRIDGE_CMD_HEADER_LEN;
        p += NCP_BRIDGE_CMD_HEADER_LEN;
        while(len)
        {
            masterXfer.txData = p;
            masterXfer.rxData = NULL;
            if(len <= DMA_MAX_TRANSFER_COUNT)
                masterXfer.dataSize = len;
            else
                masterXfer.dataSize = DMA_MAX_TRANSFER_COUNT;
            masterXfer.configFlags = kSPI_FrameAssert;
            os_semaphore_get(&spi_master_sem, OS_WAIT_FOREVER);
            ret = (int)SPI_MasterTransferDMA(NCP_HOST_SPI_MASTER, &masterHandle, &masterXfer);
            if(ret)
            {
                (void)PRINTF("Error occurred in SPI_MasterTransferDMA\r\n");
                goto done;
            }
            os_semaphore_get(&spi_master_txrx_done, OS_WAIT_FOREVER);
            len -= masterXfer.dataSize;
            p += masterXfer.dataSize;
        }
    }
    else if(transfer_type == NCP_HOST_MASTER_RX)
    {
        if(is_header)
        {
            masterXfer.txData = NULL;
            masterXfer.rxData = buff;
            masterXfer.dataSize = data_size;
            masterXfer.configFlags = kSPI_FrameAssert;
            ret = (int)SPI_MasterTransferDMA(NCP_HOST_SPI_MASTER, &masterHandle, &masterXfer);
            if(ret)
            {
                (void)PRINTF("Error occurred in SPI_MasterTransferDMA\r\n");
                goto done;
            }
            os_semaphore_get(&spi_master_txrx_done, OS_WAIT_FOREVER);
        }
        else
        {
            len = data_size;
            p = buff;
            while(len)
            {
                masterXfer.txData = NULL;
                masterXfer.rxData = p;
                if(len <= DMA_MAX_TRANSFER_COUNT)
                    masterXfer.dataSize = len;
                else
                    masterXfer.dataSize = DMA_MAX_TRANSFER_COUNT;
                masterXfer.configFlags = kSPI_FrameAssert;
                os_event_notify_get(OS_WAIT_FOREVER);
                ret = (int)SPI_MasterTransferDMA(NCP_HOST_SPI_MASTER, &masterHandle, &masterXfer);
                if(ret)
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
    /* DMA init */
    DMA_Init(NCP_HOST_DMA);
    /* Configure the DMA channel,priority and handle. */
    DMA_EnableChannel(NCP_HOST_DMA, NCP_HOST_SPI_MASTER_TX_CHANNEL);
    DMA_EnableChannel(NCP_HOST_DMA, NCP_HOST_SPI_MASTER_RX_CHANNEL);
    DMA_SetChannelPriority(NCP_HOST_DMA, NCP_HOST_SPI_MASTER_TX_CHANNEL, kDMA_ChannelPriority3);
    DMA_SetChannelPriority(NCP_HOST_DMA, NCP_HOST_SPI_MASTER_RX_CHANNEL, kDMA_ChannelPriority2);
    DMA_CreateHandle(&masterTxHandle, NCP_HOST_DMA, NCP_HOST_SPI_MASTER_TX_CHANNEL);
    DMA_CreateHandle(&masterRxHandle, NCP_HOST_DMA, NCP_HOST_SPI_MASTER_RX_CHANNEL);
}

static int ncp_host_master_init(void)
{
    /* SPI init */
    int ret = 0;
    uint32_t srcClock_Hz = 0U;
    spi_master_config_t masterConfig;
    srcClock_Hz = NCP_HOST_SPI_MASTER_CLK_FREQ;

    SPI_MasterGetDefaultConfig(&masterConfig);
    masterConfig.baudRate_Bps = 30000000U; // decrease this value for testing purpose.
    masterConfig.sselNum = (spi_ssel_t)NCP_HOST_SPI_SSEL;
    masterConfig.sselPol = (spi_spol_t)NCP_HOST_MASTER_SPI_SPOL;
    ret = (int)SPI_MasterInit(NCP_HOST_SPI_MASTER, &masterConfig, srcClock_Hz);

    return ret;
}

void ncp_host_gpio_init(void)
{
    /* Config GPIO_11 and GPIO_27 as input GPIO */
    GPIO_PinInit(GPIO, NCP_HOST_GPIO_PORT, NCP_HOST_GPIO_PIN_RX, &input_pin);
    GPIO_PinInit(GPIO, NCP_HOST_GPIO_PORT, NCP_HOST_GPIO_PIN_TX, &input_pin);
    /* Config and enable GPIO pin interrupt */
    GPIO_SetPinInterruptConfig(GPIO, NCP_HOST_GPIO_PORT, NCP_HOST_GPIO_PIN_RX, &input_pin_cfg);
    GPIO_SetPinInterruptConfig(GPIO, NCP_HOST_GPIO_PORT, NCP_HOST_GPIO_PIN_TX, &input_pin_cfg);
    GPIO_PinEnableInterrupt(GPIO, NCP_HOST_GPIO_PORT, NCP_HOST_GPIO_PIN_RX, 0);
    GPIO_PinEnableInterrupt(GPIO, NCP_HOST_GPIO_PORT, NCP_HOST_GPIO_PIN_TX, 0);
    NVIC_SetPriority(GPIO_INTA_IRQn, 3U);
    NVIC_ClearPendingIRQ(GPIO_INTA_IRQn);
    EnableIRQ(GPIO_INTA_IRQn);
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
    /* Set FRG clock with main clk and attach Flexcomm0 to FRG clk */
    CLOCK_SetFRGClock(BOARD_DEBUG_FLEXCOMM0_FRG_CLK);
    CLOCK_AttachClk(kFRG_to_FLEXCOMM0);
    ret = ncp_host_master_init();
    if(ret != WM_SUCCESS)
    {
        PRINTF("Failed to initialize SPI master(%d)\r\n", ret);
        return ret;
    }
    ncp_host_master_dma_setup();
    /* Set up handle for spi master */
    ret = (int)SPI_MasterTransferCreateHandleDMA(NCP_HOST_SPI_MASTER, &masterHandle,
                                                 ncp_host_spi_master_cb, NULL,
                                                 &masterTxHandle, &masterRxHandle);

    return ret;
}
