/** @file spi_master_app.h
 *
 *  @brief main file
 *
 *  Copyright 2023 NXP
 *  All rights reserved.
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 */

/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define NCP_HOST_SPI_MASTER            SPI0
#define NCP_HOST_SPI_MASTER_CLK_FREQ   CLOCK_GetFlexCommClkFreq(0U)
#define NCP_HOST_SPI_MASTER_RX_CHANNEL 0
#define NCP_HOST_SPI_MASTER_TX_CHANNEL 1

#define NCP_HOST_SPI_SSEL        kSPI_Ssel0
#define NCP_HOST_DMA             DMA0
#define NCP_HOST_MASTER_SPI_SPOL kSPI_SpolActiveAllLow

#define NCP_HOST_MASTER_TX    1
#define NCP_HOST_MASTER_RX    2

#define NCP_HOST_GPIO_PORT    0U
#define NCP_HOST_GPIO_PIN_RX  27U
#define NCP_HOST_GPIO_PIN_TX  11U

/*******************************************************************************
 * API
 ******************************************************************************/
int ncp_host_spi_master_transfer(uint8_t *buff, uint16_t data_size, int transfer_type, uint8_t is_first);
int ncp_host_init_spi_master(void);
