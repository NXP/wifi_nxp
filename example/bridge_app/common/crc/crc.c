/** @file crc.c
 *
 *  @brief main file
 *
 *  Copyright 2023 NXP
 *  All rights reserved.
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 */
#include "wm_os.h"
#include "crc.h"
#include "fsl_crc.h"

#ifdef CONFIG_CRC32_HW_ACCELERATE
uint32_t ncp_bridge_get_crc32(uint8_t *buf, uint16_t len)
{
    uint32_t crc;

    CRC_WriteSeed(CRC, 0xffffffffU);
    CRC_WriteData(CRC, buf, len);
    crc = CRC_Get32bitResult(CRC);

    return ~crc;
}

void hw_crc32_init()
{
    crc_config_t crcUserConfig;
    crcUserConfig.seed          = 0U;
    crcUserConfig.polynomial    = kCRC_Polynomial_CRC_32;
    crcUserConfig.reverseIn     = false;
    crcUserConfig.reverseOut    = false;
    crcUserConfig.complementIn  = false;
    crcUserConfig.complementOut = false;
    CRC_Init(CRC, &crcUserConfig);
}
#else
void ncp_bridge_init_crc32(void)
{
    int i, j;
    unsigned int c;
    for (i = 0; i < 256; ++i)
    {
        for (c = i << 24, j = 8; j > 0; --j)
            c = c & 0x80000000 ? (c << 1) ^ CRC32_POLY : (c << 1);
        crc32_table[i] = c;
    }
}

uint32_t ncp_bridge_get_crc32(uint8_t *buf, uint16_t len)
{
    uint8_t *p;
    unsigned int crc;
    crc = 0xffffffff;
    for (p = buf; len > 0; ++p, --len)
        crc = (crc << 8) ^ (crc32_table[(crc >> 24) ^ *p]);
    return ~crc;
}
#endif
