/*
 * Copyright 2023 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#if defined(WIFI_IW612_BOARD_RD_USD) || defined(WIFI_IW612_BOARD_RD_M2)

#if defined(CONFIG_WIFI_IND_DNLD)

#include <stdint.h>

const uint8_t fw_cpu1[] = {
    #include <sd_nw61x.bin.inc>
};

const unsigned char *wlan_fw_bin = (const unsigned char *)(void *)&fw_cpu1[0];
const unsigned int wlan_fw_bin_len = sizeof(fw_cpu1);

#endif

#endif
