/*
 * Copyright 2023 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#if defined(WIFI_IW612_BOARD_RD_USD) || defined(WIFI_IW612_BOARD_RD_M2)

#if defined(CONFIG_BT_IND_DNLD)

#include <stdint.h>

const uint8_t fw_cpu2[] = {
    #include <uart_nw61x.bin.inc>
};

const unsigned char *bt_fw_bin = (const unsigned char *)(void *)&fw_cpu2[0];
const unsigned int bt_fw_bin_len = sizeof(fw_cpu2);

#endif

#endif
