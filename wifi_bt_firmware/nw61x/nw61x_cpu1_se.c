/*
 * Copyright 2023 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#if defined(WIFI_IW612_BOARD_MURATA_2EL_M2) || defined(WIFI_IW612_BOARD_MURATA_2EL_USD) || defined(WIFI_IW611_BOARD_MURATA_2DL_M2) || defined(WIFI_IW611_BOARD_MURATA_2DL_USD)

#if defined(CONFIG_WIFI_IND_DNLD)

#include <stdint.h>

const uint8_t fw_cpu1[] = {
    #include <sd_nw61x.bin.se.inc>
};

const unsigned char *wlan_fw_bin = (const unsigned char *)(void *)&fw_cpu1[0];
const unsigned int wlan_fw_bin_len = sizeof(fw_cpu1);

#endif

#endif
