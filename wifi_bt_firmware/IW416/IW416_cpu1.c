/*
 * Copyright 2023 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#if defined(SD8978)

#if defined(CONFIG_WIFI_IND_DNLD)

#include <stdint.h>

const uint8_t fw_cpu1[] = {
    #include <sdIW416_wlan.bin.inc>
};

const unsigned char *wlan_fw_bin = (const unsigned char *)(void *)&fw_cpu1[0];
const unsigned int wlan_fw_bin_len = sizeof(fw_cpu1);

#endif

#endif
