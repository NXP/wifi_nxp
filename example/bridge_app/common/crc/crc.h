/** @file crc.h
 *
 *  @brief main file
 *
 *  Copyright 2023 NXP
 *  All rights reserved.
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef _CRC_H_
#define _CRC_H_

/*******************************************************************************
 * Definitions
 ******************************************************************************/

#define CRC32_POLY   0x04c11db7
#define CHECKSUM_LEN 4

/*******************************************************************************
 * API
 ******************************************************************************/
uint32_t ncp_bridge_get_crc32(uint8_t *buf, uint16_t len);

#ifdef CONFIG_CRC32_HW_ACCELERATE
void hw_crc32_init();
#else
void ncp_bridge_init_crc32(void);
#endif
#endif
