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
#define NCP_SPI_MASTER_CLOCK   20000000U

#define NCP_HOST_GPIO         GPIO1
#define NCP_HOST_GPIO_PIN_RX  16U
#define NCP_HOST_GPIO_PIN_TX  17U
#define NCP_HOST_GPIO_IRQ     GPIO1_Combined_16_31_IRQn

#define NCP_HOST_GPIO_IRQ_HANDLER GPIO1_Combined_16_31_IRQHandler

#define NCP_HOST_GPIO_IRQ_PRIO 3
#define NCP_HOST_DMA_IRQ_PRIO  4

/*******************************************************************************
 * API
 ******************************************************************************/
int ncp_host_spi_master_transfer(uint8_t *buff, uint16_t data_size, int transfer_type, uint8_t is_first);
int ncp_host_init_spi_master(void);
#endif /* CONFIG_SPI_BRIDGE */