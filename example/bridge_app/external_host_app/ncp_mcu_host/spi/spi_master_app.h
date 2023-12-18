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
#define MCU_BRIDGE_SPI_MASTER            SPI0
#define MCU_BRIDGE_SPI_MASTER_CLK_FREQ   CLOCK_GetFlexCommClkFreq(0U)
#define MCU_BRIDGE_SPI_MASTER_RX_CHANNEL 0
#define MCU_BRIDGE_SPI_MASTER_TX_CHANNEL 1

#define MCU_BRIDGE_SPI_SSEL        kSPI_Ssel0
#define MCU_BRIDGE_DMA             DMA0
#define MCU_BRIDGE_MASTER_SPI_SPOL kSPI_SpolActiveAllLow

#define MCU_BRIDGE_MASTER_TX    1
#define MCU_BRIDGE_MASTER_RX    2

#define MCU_BRIDGE_GPIO_PORT    0U
#define MCU_BRIDGE_GPIO_PIN_RX  27U
#define MCU_BRIDGE_GPIO_PIN_TX  11U

/*******************************************************************************
 * API
 ******************************************************************************/
int mcu_bridge_spi_master_transfer(uint8_t *buff, uint16_t data_size, int transfer_type, uint8_t is_first);
int mcu_bridge_init_spi_master(void);
