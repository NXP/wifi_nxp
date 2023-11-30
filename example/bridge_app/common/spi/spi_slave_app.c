/** @file spi_slave_app.c
 *
 *  @brief main file
 *
 *  Copyright 2023 NXP
 *  All rights reserved.
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include "wm_os.h"
#include "wlan.h"
#include "ncp_bridge_cmd.h"
#include "spi_slave_app.h"
#include "fsl_spi.h"
#include "fsl_spi_dma.h"
#include "fsl_dma.h"
#include "fsl_gpio.h"

/*******************************************************************************
 * Variables
 ******************************************************************************/
dma_handle_t slaveTxHandle;
dma_handle_t slaveRxHandle;
spi_dma_handle_t slaveHandle;
/* Define the init structure for the output switch pin */
gpio_pin_config_t output_pin = {kGPIO_DigitalOutput, 0};
os_semaphore_t spi_slave_txrx_sem;
#define BOARD_DEBUG_FLEXCOMM0_FRG_CLK (&(const clock_frg_clk_config_t){0, kCLOCK_FrgMainClk, 255, 0})

/*******************************************************************************
 * Code
 ******************************************************************************/
static void ncp_bridge_spi_slave_cb(SPI_Type *base, spi_dma_handle_t *handle, status_t status, void *userData)
{
    if (status == kStatus_Success)
    {
        os_semaphore_put(&spi_slave_txrx_sem);
    }
}

void ncp_bridge_spi_slave_send_signal(uint8_t transfer_type)
{
    if (transfer_type == NCP_BRIDGE_SLAVE_TX)
    {
        /* Toggle GPIO to inform SPI master about slave TX ready. */
        GPIO_PortToggle(GPIO, 0, SPI_SLAVE_GPIO_TX_MASK);
        GPIO_PortToggle(GPIO, 0, SPI_SLAVE_GPIO_TX_MASK);
        os_semaphore_get(&spi_slave_txrx_sem, OS_WAIT_FOREVER);
    }
    else
    {
        /* Toggle GPIO to inform SPI master about slave RX ready. */
        GPIO_PortToggle(GPIO, 0, SPI_SLAVE_GPIO_RX_MASK);
        GPIO_PortToggle(GPIO, 0, SPI_SLAVE_GPIO_RX_MASK);
    }
}

int ncp_bridge_spi_slave_transfer(uint8_t *buff, uint16_t data_size, int transfer_type, uint8_t is_header)
{
    int ret = 0;
    spi_transfer_t slaveXfer;
    uint16_t left_len = 0;
    uint8_t *p        = NULL;

    /* Fill SPI transfer config */
    if (transfer_type == NCP_BRIDGE_SLAVE_TX)
    {
        left_len = data_size;
        p        = buff;
        /* Prepare DMA for header first */
        slaveXfer.txData      = buff;
        slaveXfer.rxData      = NULL;
        slaveXfer.dataSize    = NCP_BRIDGE_CMD_HEADER_LEN;
        slaveXfer.configFlags = kSPI_FrameAssert;
        ret                   = (int)SPI_SlaveTransferDMA(NCP_BRIDGE_SPI_SLAVE, &slaveHandle, &slaveXfer);
        if (ret)
        {
            (void)PRINTF("Error occurred in SPI_SlaveTransferDMA\r\n");
            return ret;
        }
        /* Signal master about slave Tx ready and wait for DMA txrx done */
        ncp_bridge_spi_slave_send_signal(NCP_BRIDGE_SLAVE_TX);
        /* Prepare DMA for remaining bytes */
        left_len -= NCP_BRIDGE_CMD_HEADER_LEN;
        p += NCP_BRIDGE_CMD_HEADER_LEN;
        while (left_len)
        {
            slaveXfer.txData = p;
            slaveXfer.rxData = NULL;
            if (left_len <= DMA_MAX_TRANSFER_COUNT)
                slaveXfer.dataSize = left_len;
            else
                slaveXfer.dataSize = DMA_MAX_TRANSFER_COUNT;
            slaveXfer.configFlags = kSPI_FrameAssert;
            ret                   = (int)SPI_SlaveTransferDMA(NCP_BRIDGE_SPI_SLAVE, &slaveHandle, &slaveXfer);
            if (ret)
            {
                (void)PRINTF("Error occurred in SPI_SlaveTransferDMA\r\n");
                return ret;
            }
            ncp_bridge_spi_slave_send_signal(NCP_BRIDGE_SLAVE_TX);
            left_len -= slaveXfer.dataSize;
            p += slaveXfer.dataSize;
        }
    }
    else if (transfer_type == NCP_BRIDGE_SLAVE_RX)
    {
        if (is_header)
        {
            /* Prepare DMA to receive header */
            slaveXfer.txData      = NULL;
            slaveXfer.rxData      = buff;
            slaveXfer.dataSize    = data_size;
            slaveXfer.configFlags = kSPI_FrameAssert;
            ret                   = (int)SPI_SlaveTransferDMA(NCP_BRIDGE_SPI_SLAVE, &slaveHandle, &slaveXfer);
            if (ret)
            {
                (void)PRINTF("Error occurred in SPI_SlaveTransferDMA\r\n");
                return ret;
            }
            /* Toggle GPIO to inform master about slave Rx ready */
            ncp_bridge_spi_slave_send_signal(NCP_BRIDGE_SLAVE_RX);
            os_semaphore_get(&spi_slave_txrx_sem, OS_WAIT_FOREVER);
        }
        else
        {
            left_len = data_size;
            p        = buff;
            while (left_len)
            {
                slaveXfer.txData = NULL;
                slaveXfer.rxData = p;
                if (left_len <= DMA_MAX_TRANSFER_COUNT)
                    slaveXfer.dataSize = left_len;
                else
                    slaveXfer.dataSize = DMA_MAX_TRANSFER_COUNT;
                slaveXfer.configFlags = kSPI_FrameAssert;
                ret                   = (int)SPI_SlaveTransferDMA(NCP_BRIDGE_SPI_SLAVE, &slaveHandle, &slaveXfer);
                if (ret)
                {
                    (void)PRINTF("Error occurred in SPI_SlaveTransferDMA\r\n");
                    return ret;
                }
                ncp_bridge_spi_slave_send_signal(NCP_BRIDGE_SLAVE_RX);
                os_semaphore_get(&spi_slave_txrx_sem, OS_WAIT_FOREVER);
                left_len -= slaveXfer.dataSize;
                p += slaveXfer.dataSize;
            }
        }
    }
    return ret;
}

void ncp_bridge_output_gpio_init(void)
{
    GPIO_PortInit(GPIO, 0);
    /* Init output GPIO. Default level is high */
    /* GPIO 27 for TX and GPIO 11 for RX */
    GPIO_PinInit(GPIO, 0, 27, &output_pin);
    GPIO_PinInit(GPIO, 0, 11, &output_pin);
}

static void ncp_bridge_slave_dma_setup(void)
{
    /* DMA init */
    DMA_Init(NCP_BRIDGE_DMA);
    /* Configure the DMA channel,priority and handle. */
    DMA_EnableChannel(NCP_BRIDGE_DMA, NCP_BRIDGE_SLAVE_TX_CHANNEL);
    DMA_EnableChannel(NCP_BRIDGE_DMA, NCP_BRIDGE_SLAVE_RX_CHANNEL);
    DMA_SetChannelPriority(NCP_BRIDGE_DMA, NCP_BRIDGE_SLAVE_TX_CHANNEL, kDMA_ChannelPriority3);
    DMA_SetChannelPriority(NCP_BRIDGE_DMA, NCP_BRIDGE_SLAVE_RX_CHANNEL, kDMA_ChannelPriority2);
    DMA_CreateHandle(&slaveTxHandle, NCP_BRIDGE_DMA, NCP_BRIDGE_SLAVE_TX_CHANNEL);
    DMA_CreateHandle(&slaveRxHandle, NCP_BRIDGE_DMA, NCP_BRIDGE_SLAVE_RX_CHANNEL);
}

static int ncp_bridge_slave_init(void)
{
    int ret = 0;
    spi_slave_config_t slaveConfig;

    SPI_SlaveGetDefaultConfig(&slaveConfig);
    /* Initialize the SPI slave. */
    slaveConfig.sselPol = (spi_spol_t)NCP_BRIDGE_SLAVE_SPI_SPOL;
    ret                 = (int)SPI_SlaveInit(NCP_BRIDGE_SPI_SLAVE, &slaveConfig);

    return ret;
}

int ncp_bridge_init_spi_slave(void)
{
    int ret = WM_SUCCESS;

    ncp_bridge_output_gpio_init();
    ret = os_semaphore_create(&spi_slave_txrx_sem, "spi slave txrx semaphore");
    if (ret != WM_SUCCESS)
    {
        PRINTF("Create spi slave txrx sem failed");
        return ret;
    }
    os_semaphore_get(&spi_slave_txrx_sem, OS_NO_WAIT);
    CLOCK_SetFRGClock(BOARD_DEBUG_FLEXCOMM0_FRG_CLK);
    CLOCK_AttachClk(kFRG_to_FLEXCOMM0);
    ret = ncp_bridge_slave_init();
    if (ret != WM_SUCCESS)
    {
        PRINTF("Failed to initialize SPI slave(%d)\r\n", ret);
        return ret;
    }
    ncp_bridge_slave_dma_setup();
    /* Set up handle for spi slave */
    ret = (int)SPI_SlaveTransferCreateHandleDMA(NCP_BRIDGE_SPI_SLAVE, &slaveHandle, ncp_bridge_spi_slave_cb, NULL,
                                                &slaveTxHandle, &slaveRxHandle);
    return ret;
}
