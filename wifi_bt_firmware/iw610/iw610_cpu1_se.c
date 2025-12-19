/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stdint.h>
#include <osa.h>

#if defined(IW610)

#if (CONFIG_WIFI_IND_DNLD)

const uint8_t fw_cpu1[] = {
#if CONFIG_UNCOMPRESSED_FIRMWARE
#include <sd_iw610.bin.se.inc>
#else
#include <sd_iw610_compressed.bin.se.inc>
#endif
};

const unsigned char *wlan_fw_bin   = (const unsigned char *)(void *)&fw_cpu1[0];
const unsigned int wlan_fw_bin_len = sizeof(fw_cpu1);

#endif

#endif
