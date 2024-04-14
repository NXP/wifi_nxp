/*
 *  Copyright 2020-2022 NXP
 *  All rights reserved.
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _WIFI_CONFIG_H_
#define _WIFI_CONFIG_H_

#include "app_config.h"
#ifndef RW610
#include "wifi_bt_module_config.h"
#endif

#if defined (SD9177)
#define CONFIG_WMM 1
#endif

#if defined(RW610)
#define CONFIG_WMM_UAPSD 0
#define CONFIG_WIFI_GET_LOG 0
#define CONFIG_11K 0
#define CONFIG_POWER_MANAGER 0
#define CONFIG_CSI 0
#define CONFIG_WIFI_MEM_ACCESS 0
#define CONFIG_WIFI_REG_ACCESS 0
#define CONFIG_ECSA 0
#define CONFIG_WIFI_EU_CRYPTO 0
#define CONFIG_WPS2 1
#define CONFIG_WPA2_ENTP 1
#define CONFIG_DPP 1
#define CONFIG_WIFI_USB_FILE_ACCESS 1
#define CONFIG_PEAP_MSCHAPV2 1
#define CONFIG_UNII4_BAND_SUPPORT 1
#endif

/* WLCMGR debug */
#define CONFIG_WLCMGR_DEBUG 0

/*
 * Wifi extra debug options
 */
#define CONFIG_WIFI_EXTRA_DEBUG 0
#define CONFIG_WIFI_EVENTS_DEBUG 0
#define CONFIG_WIFI_CMD_RESP_DEBUG 0
#define CONFIG_WIFI_PKT_DEBUG 0
#define CONFIG_WIFI_SCAN_DEBUG 0
#define CONFIG_WIFI_IO_INFO_DUMP 0
#define CONFIG_WIFI_IO_DEBUG 0
#define CONFIG_WIFI_IO_DUMP 0
#define CONFIG_WIFI_MEM_DEBUG 0
#define CONFIG_WIFI_AMPDU_DEBUG 0
#define CONFIG_WIFI_TIMER_DEBUG 0
#define CONFIG_WIFI_SDIO_DEBUG 0
#define CONFIG_WIFI_FW_DEBUG 0
#define CONFIG_WIFI_UAP_DEBUG 0
#define CONFIG_WPS_DEBUG 0
#define CONFIG_FW_VDLL_DEBUG 0
#define CONFIG_DHCP_SERVER_DEBUG 0
#define CONFIG_WIFI_SDIO_DEBUG 0
#define CONFIG_FWDNLD_IO_DEBUG 0

/*
 * Heap debug options
 */
#define CONFIG_HEAP_DEBUG 0
#define CONFIG_HEAP_STAT 0

#endif /* _WIFI_CONFIG_H_ */
