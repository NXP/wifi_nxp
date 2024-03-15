/*
 * Copyright 2023 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stdint.h>
#include <osa.h>

#if defined(WIFI_IW612_BOARD_MURATA_2EL_M2) || defined(WIFI_IW612_BOARD_MURATA_2EL_USD) || \
    defined(WIFI_IW611_BOARD_MURATA_2DL_M2) || defined(WIFI_IW611_BOARD_MURATA_2DL_USD)

#if defined(CONFIG_BT_IND_DNLD)

const uint8_t fw_cpu2[] = {
#include <uart_nw61x.bin.se.inc>
};

const unsigned char *bt_fw_bin   = (const unsigned char *)(void *)&fw_cpu2[0];
const unsigned int bt_fw_bin_len = sizeof(fw_cpu2);

#endif

#endif
