/*
 *  Copyright 2020-2023 NXP
 *  All rights reserved.
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __MPU_BRIDGE_WIFI_CONFIG_H__
#define __MPU_BRIDGE_WIFI_CONFIG_H__

#define CONFIG_WPS2

/* WLAN SCAN OPT */
#define CONFIG_SCAN_WITH_RSSIFILTER

#define CONFIG_WPA2_ENTP
#define CONFIG_WIFI_CAPA

#define CONFIG_IPV6               1
#define CONFIG_MAX_IPV6_ADDRESSES 3

#define CONFIG_WIFI_DTIM_PERIOD

#undef CONFIG_MPU_IO_DUMP

#define CONFIG_MEM_MONITOR_DEBUG

#define CONFIG_5GHz_SUPPORT
#define CONFIG_11AC
#define CONFIG_NCP_RF_TEST_MODE

#endif /*__MPU_BRIDGE_WIFI_CONFIG_H__*/
