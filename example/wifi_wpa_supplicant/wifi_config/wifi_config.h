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

#if defined(SD9177)
#define CONFIG_WMM 1
#define CONFIG_SDIO_MULTI_PORT_TX_AGGR 1
#define CONFIG_WIFI_FEATURES 1
#define CONFIG_OFFLOAD       1
#endif

#if defined(RW610)
#define CONFIG_MAX_RESCAN_LIMIT 30
#define PRINTF_FLOAT_ENABLE 1
/* WMM options */
#define CONFIG_WMM 1
/* OWE mode */
#define CONFIG_DRIVER_OWE 1
/* WLAN SCAN OPT */
#define CONFIG_SCAN_WITH_RSSIFILTER 1
/* WLAN white/black list opt */
#define CONFIG_UAP_STA_MAC_ADDR_FILTER 1
#define CONFIG_WIFI_DTIM_PERIOD 1
#define CONFIG_UART_INTERRUPT 1
#define CONFIG_WIFI_CAPA 1
#define CONFIG_WIFI_RTS_THRESHOLD 1
#define CONFIG_WIFI_FRAG_THRESHOLD 1
#define CONFIG_WIFI_MAX_CLIENTS_CNT 1
#define CONFIG_WMM_UAPSD 1
#define CONFIG_WIFI_GET_LOG 1
#define CONFIG_WIFI_TX_PER_TRACK 1
#define CONFIG_ROAMING 1
#define CONFIG_HOST_SLEEP 1
#define CONFIG_POWER_MANAGER 1
#define CONFIG_CSI 1
#define CONFIG_WIFI_RESET 1
#define CONFIG_NET_MONITOR 1
#define CONFIG_WIFI_MEM_ACCESS 1
#define CONFIG_WIFI_REG_ACCESS 1
#define CONFIG_ECSA 1
#define CONFIG_WIFI_EU_CRYPTO 1
#define CONFIG_EXT_SCAN_SUPPORT 1
#define CONFIG_11K 1
#define CONFIG_11V 1
#define CONFIG_11R 1
#define CONFIG_RX_ABORT_CFG 1
#define CONFIG_RX_ABORT_CFG_EXT 1
#define CONFIG_CCK_DESENSE_CFG 1
#define CONFIG_11AX_TWT 1
#define CONFIG_IPS 1
#define CONFIG_SUBSCRIBE_EVENT_SUPPORT 1
#define CONFIG_WIFI_FORCE_RTS 1
#define CONFIG_TX_AMPDU_PROT_MODE 1
#define CONFIG_TSP 1
#define CONFIG_TX_RX_HISTOGRAM 1
#define CONFIG_CLOUD_KEEP_ALIVE 1
#define CONFIG_TURBO_MODE 1
#define CONFIG_UNII4_BAND_SUPPORT 1
#define CONFIG_MMSF 1
#define CONFIG_COEX_DUTY_CYCLE 1
#define CONFIG_TX_RX_ZERO_COPY 1
#define CONFIG_WIFI_CLOCKSYNC 1
#define CONFIG_INACTIVITY_TIMEOUT_EXT 1
#define CONFIG_MEF_CFG 1
#define CONFIG_AUTO_NULL_TX 1
#define CONFIG_EXTERNAL_COEX_PTA 1
#define CONFIG_FW_VDLLV2 1
#endif

#if defined(SD8978) || defined(SD8987) || defined(SD8801) || defined(SD9177)
#define CONFIG_WIFI_CAPA        1
#define CONFIG_ROAMING          1
#define CONFIG_CLOUD_KEEP_ALIVE 1
#define CONFIG_TURBO_MODE       1
#define CONFIG_AUTO_RECONNECT   1
#define CONFIG_DRIVER_OWE       1
#define CONFIG_EXT_SCAN_SUPPORT 1
#define CONFIG_WIFI_EU_CRYPTO   1
#define CONFIG_11R              1
#define CONFIG_11K              1
#define CONFIG_11V              1
#endif

/*
 * Config options for wpa supplicant
 */
#define CONFIG_WPA_SUPP 1

#if CONFIG_WPA_SUPP
#ifdef RW610
#define CONFIG_WPA_SUPP_WPS               1
#define CONFIG_WPA_SUPP_WPA3              1
#define CONFIG_WPA_SUPP_CRYPTO_ENTERPRISE 1
#define CONFIG_WPA_SUPP_CRYPTO_AP_ENTERPRISE 1
#define CONFIG_WIFI_USB_FILE_ACCESS       1

#define CONFIG_WPA_SUPP_DPP 1

#if (CONFIG_WPA_SUPP_CRYPTO_ENTERPRISE || CONFIG_WPA_SUPP_CRYPTO_AP_ENTERPRISE)
#define CONFIG_EAP_TLS 1
#define CONFIG_EAP_PEAP 1
#define CONFIG_EAP_TTLS 1
#define CONFIG_EAP_FAST 1
#define CONFIG_EAP_SIM 1
#define CONFIG_EAP_AKA 1
#define CONFIG_EAP_AKA_PRIME 1

#if (CONFIG_EAP_PEAP || CONFIG_EAP_TTLS || CONFIG_EAP_FAST)
#define CONFIG_EAP_MSCHAPV2 1
#define CONFIG_EAP_GTC 1
#endif
#endif

#else
#define CONFIG_WPA_SUPP_WPS               1
#define CONFIG_WPA_SUPP_WPA3              1
#define CONFIG_WPA_SUPP_CRYPTO_ENTERPRISE 0

#if defined(SD9177)
#define CONFIG_WPA_SUPP_DPP 0

#if CONFIG_WPA_SUPP_DPP
#define CONFIG_WPA_SUPP_DPP2 1
#define CONFIG_WPA_SUPP_DPP3 1
#define CONFIG_RX_CHAN_INFO  1
#define CONFIG_TXPD_RXPD_V3  1
#endif
#endif

#if CONFIG_WPA_SUPP_CRYPTO_ENTERPRISE

#define CONFIG_WPA_SUPP_CRYPTO_AP_ENTERPRISE 1

#define CONFIG_EAP_TLS 1
#define CONFIG_EAP_PEAP 1
#define CONFIG_EAP_TTLS 1
#define CONFIG_EAP_FAST 1
#define CONFIG_EAP_SIM 1
#define CONFIG_EAP_AKA 1
#define CONFIG_EAP_AKA_PRIME 1
#define CONFIG_EAP_MSCHAPV2 1
#define CONFIG_EAP_GTC 1

#endif
#endif
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

/*
 * wpa supplicant debug options
 */
#define CONFIG_WPA_SUPP_DEBUG_LEVEL 6

#define CONFIG_SUPP_DEBUG 0

#endif /* _WIFI_CONFIG_H_ */
