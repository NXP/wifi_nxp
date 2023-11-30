/** @file spi_slave_app.h
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
#define NCP_BRIDGE_SPI_SLAVE        SPI0
#define NCP_BRIDGE_DMA              DMA0
#define NCP_BRIDGE_SLAVE_RX_CHANNEL 0
#define NCP_BRIDGE_SLAVE_TX_CHANNEL 1
#define NCP_BRIDGE_SLAVE_SPI_SPOL   kSPI_SpolActiveAllLow

#define NCP_BRIDGE_SLAVE_TX 1
#define NCP_BRIDGE_SLAVE_RX 2

#define SPI_SLAVE_GPIO_TX_MASK 0x8000000
#define SPI_SLAVE_GPIO_RX_MASK 0x800

/*******************************************************************************
 * API
 ******************************************************************************/
void ncp_bridge_spi_slave_send_signal(uint8_t transfer_type);
int ncp_bridge_spi_slave_transfer(uint8_t *buff, uint16_t data_size, int transfer_type, uint8_t is_header);
int ncp_bridge_init_spi_slave(void);
