/** @file spi_master_app.h
 *
 *  @brief main file
 *
 *  Copyright 2023 NXP
 *  All rights reserved.
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#ifdef CONFIG_SPI_BRIDGE
/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define NCP_HOST_SPI_MASTER            SPI0
#define NCP_HOST_SPI_MASTER_CLK_FREQ   CLOCK_GetFlexCommClkFreq(0U)
#define NCP_HOST_SPI_MASTER_RX_CHANNEL 0
#define NCP_HOST_SPI_MASTER_TX_CHANNEL 1
#define DMA_MAX_TRANSFER_COUNT         1024

#define NCP_HOST_SPI_SSEL        kSPI_Ssel0
#define NCP_HOST_DMA             DMA0
#define NCP_HOST_MASTER_SPI_SPOL kSPI_SpolActiveAllLow

#define NCP_HOST_MASTER_TX    1
#define NCP_HOST_MASTER_RX    2

#define EXAMPLE_LPSPI_MASTER_BASEADDR              (LPSPI1)
#define EXAMPLE_LPSPI_MASTER_DMA_MUX_BASE          (DMAMUX)
#define EXAMPLE_LPSPI_MASTER_DMA_RX_REQUEST_SOURCE kDmaRequestMuxLPSPI1Rx
#define EXAMPLE_LPSPI_MASTER_DMA_TX_REQUEST_SOURCE kDmaRequestMuxLPSPI1Tx
#define EXAMPLE_LPSPI_MASTER_DMA_BASE              (DMA0)
#define EXAMPLE_LPSPI_MASTER_DMA_RX_CHANNEL        0U
#define EXAMPLE_LPSPI_MASTER_DMA_TX_CHANNEL        1U

#define EXAMPLE_LPSPI_MASTER_PCS_FOR_INIT     (kLPSPI_Pcs0)
#define EXAMPLE_LPSPI_MASTER_PCS_FOR_TRANSFER (kLPSPI_MasterPcs0)

/* Select USB1 PLL PFD0 (720 MHz) as lpspi clock source */
#define EXAMPLE_LPSPI_CLOCK_SOURCE_SELECT (1U)
/* Clock divider for master lpspi clock source */
#define EXAMPLE_LPSPI_CLOCK_SOURCE_DIVIDER (1U)

#define LPSPI_MASTER_CLK_FREQ (CLOCK_GetFreq(kCLOCK_Usb1PllPfd0Clk) / (EXAMPLE_LPSPI_CLOCK_SOURCE_DIVIDER + 1U))
#define NCP_SPI_MASTER_CLOCK   50000U

#define NCP_HOST_GPIO               GPIO1
#define NCP_HOST_GPIO_NUM           1
#define NCP_HOST_GPIO_PIN_RX        16U
#define NCP_HOST_GPIO_PIN_TX        17U
#define NCP_HOST_GPIO_PIN_RX_READY  21U
#define NCP_HOST_GPIO_RX_MASK       0x10000
#define NCP_HOST_GPIO_TX_MASK       0x20000
#define NCP_HOST_GPIO_RX_READY_MASK (1 << NCP_HOST_GPIO_PIN_RX_READY)


#define NCP_HOST_GPIO_IRQ_HANDLER GPIO1_Combined_16_31_IRQHandler

#define NCP_HOST_GPIO_IRQ_PRIO 3
#define NCP_HOST_DMA_IRQ_PRIO  4

#define MASTER_TX_ENABLE_EVENT       1 << 1
#define MASTER_RX_ENABLE_EVENT       1 << 2

/*******************************************************************************
 * API
 ******************************************************************************/
int ncp_host_spi_master_tx(uint8_t *buff, uint16_t data_size);
int ncp_host_spi_master_rx(uint8_t *buff);
int ncp_host_init_spi_master(void);
typedef enum
{
    NCP_MASTER_SPI_IDLE = 0,
    NCP_MASTER_SPI_TX,
    NCP_MASTER_SPI_RX,
    NCP_MASTER_SPI_DROP_SLAVE_TX,
    NCP_MASTER_SPI_END,
} ncp_state;


#endif /* CONFIG_SPI_BRIDGE */
