/*
 *  Copyright 2020-2022 NXP
 *  All rights reserved.
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _WIFI_CONFIG_H_
#define _WIFI_CONFIG_H_

#define CONFIG_WIFI_MAX_PRIO (configMAX_PRIORITIES - 1)

#ifndef RW610
#define CONFIG_MAX_AP_ENTRIES 10
#else
#define CONFIG_MAX_AP_ENTRIES 30
#endif

#if defined(SD8977) || defined(SD8978) || defined(SD8987) || defined(RW610)
#define CONFIG_5GHz_SUPPORT 1
#endif

#ifndef RW610
#define CONFIG_SDIO_MULTI_PORT_RX_AGGR 1
#endif

#if defined(SD8987) || defined(RW610)
#define CONFIG_11AC
#undef CONFIG_WMM
#endif

#if defined(RW610)
#define PRINTF_FLOAT_ENABLE 1
#define CONFIG_11AX
#undef CONFIG_IMU_GDMA
/* WMM options */
#define CONFIG_WMM
#define CONFIG_WMM_ENH
#undef CONFIG_WMM_CERT
#undef AMSDU_IN_AMPDU
/* OWE mode */
#define CONFIG_OWE
/* WLAN SCAN OPT */
#define CONFIG_SCAN_WITH_RSSIFILTER
#define CONFIG_WIFI_DTIM_PERIOD
#define CONFIG_UART_INTERRUPT
#define CONFIG_WIFI_CAPA
#define CONFIG_WIFI_11D_ENABLE
#define CONFIG_WIFI_HIDDEN_SSID
#define CONFIG_WMM_UAPSD
#define CONFIG_WIFI_GET_LOG
#define CONFIG_WIFI_TX_PER_TRACK
#define CONFIG_ROAMING
#define CONFIG_HOST_SLEEP
#define CONFIG_POWER_MANAGER
#define CONFIG_CSI
#define CONFIG_WIFI_RESET
#define CONFIG_NET_MONITOR
#define CONFIG_WIFI_MEM_ACCESS
#define CONFIG_WIFI_REG_ACCESS
#define CONFIG_ECSA
#define CONFIG_WIFI_EU_CRYPTO
#define CONFIG_EXT_SCAN_SUPPORT
#define CONFIG_EVENT_MEM_ACCESS
#define CONFIG_COMPRESS_TX_PWTBL
#define CONFIG_RX_ABORT_CFG
#define CONFIG_RX_ABORT_CFG_EXT
#define CONFIG_CCK_DESENSE_CFG
#define CONFIG_11AX_TWT
#define CONFIG_IPS
#define CONFIG_11R
#define CONFIG_SUBSCRIBE_EVENT_SUPPORT
#define CONFIG_EU_VALIDATION
#define CONFIG_TSP
#define CONFIG_TX_RX_HISTOGRAM
#define CONFIG_CLOUD_KEEP_ALIVE
#define CONFIG_TURBO_MODE
#define CONFIG_MMSF
#define CONFIG_COEX_DUTY_CYCLE
#define CONFIG_TX_RX_ZERO_COPY
#define CONFIG_WIFI_CLOCKSYNC
#define CONFIG_INACTIVITY_TIMEOUT_EXT
#define CONFIG_UNII4_BAND_SUPPORT
#define CONFIG_MEF_CFG
#define CONFIG_CAU_TEMPERATURE
#define CONFIG_AUTO_NULL_TX
#define CONFIG_RF_TEST_MODE
#endif

#define CONFIG_IPV6               1
#define CONFIG_MAX_IPV6_ADDRESSES 3

#define CONFIG_NCP_IPV6 1
#define CONFIG_NCP_5GHz_SUPPORT
#define CONFIG_NCP_WIFI_CAPA
#define CONFIG_NCP_WIFI_DTIM_PERIOD
#define CONFIG_NCP_11R
#define CONFIG_NCP_OWE

#define CONFIG_SCAN_CHANNEL_GAP 1

/* Logs */
#define CONFIG_ENABLE_ERROR_LOGS   1
#define CONFIG_ENABLE_WARNING_LOGS 1

/*NCP config*/
#define CONFIG_NCP_BRIDGE
#undef CONFIG_NCP_BRIDGE_DEBUG
#define CONFIG_NCP_RF_TEST_MODE
#define CONFIG_APP_NOTIFY_DEBUG
#define CONFIG_CRC32_HW_ACCELERATE

#define CONFIG_UART_BRIDGE
#undef CONFIG_SPI_BRIDGE
#undef CONFIG_USB_BRIDGE
#undef CONFIG_SDIO_BRIDGE
#undef CONFIG_SDIO_TEST_LOOPBACK

#define CONFIG_NCP_SOCKET_SEND_FIFO

/*https client and websocket*/
#define CONFIG_ENABLE_HTTPC_SECURE
#define CONFIG_ENABLE_TLS
#define APPCONFIG_WEB_SOCKET_SUPPORT
#undef CONFIG_HTTPC_DEBUG

/* WLCMGR debug */
#undef CONFIG_WLCMGR_DEBUG

/*
 * Wifi extra debug options
 */
#undef CONFIG_WIFI_EXTRA_DEBUG
#undef CONFIG_WIFI_EVENTS_DEBUG
#undef CONFIG_WIFI_CMD_RESP_DEBUG
#undef CONFIG_WIFI_PKT_DEBUG
#undef CONFIG_WIFI_SCAN_DEBUG
#undef CONFIG_WIFI_IO_INFO_DUMP
#undef CONFIG_WIFI_IO_DEBUG
#undef CONFIG_WIFI_IO_DUMP
#undef CONFIG_WIFI_MEM_DEBUG
#undef CONFIG_WIFI_AMPDU_DEBUG
#undef CONFIG_WIFI_TIMER_DEBUG
#undef CONFIG_WIFI_SDIO_DEBUG
#undef CONFIG_WIFI_FW_DEBUG
#undef CONFIG_WIFI_UAP_DEBUG
#undef CONFIG_FIPS
/*
 * Heap debug options
 */
#undef CONFIG_HEAP_DEBUG
#undef CONFIG_HEAP_STAT

/*
 * Config options for supplicant
 */
#define WIFI_ADD_ON     1
#define CONFIG_WPA_SUPP 1
#ifdef CONFIG_WPA_SUPP
#define CONFIG_WIFI_NXP        1
#define CONFIG_WPA_SUPP_CRYPTO 1
#define CONFIG_WPA_SUPP_AP     1
#define CONFIG_HOSTAPD         1
#define CONFIG_WPA_SUPP_WPS    1
//#define CONFIG_WPA_SUPP_P2P 1
#undef CONFIG_WPA_SUPP_DPP
#define CONFIG_WPA_SUPP_WPA3                 1
#define CONFIG_WPA_SUPP_CRYPTO_ENTERPRISE    1
#define CONFIG_WPA_SUPP_CRYPTO_AP_ENTERPRISE 1
#define UAP_HOST_MLME                        1
#define CONFIG_HOST_MLME                     1

#if defined(CONFIG_WPA_SUPP_CRYPTO_ENTERPRISE) || defined(CONFIG_WPA_SUPP_CRYPTO_AP_ENTERPRISE)
#define CONFIG_EAP_TLS
#define CONFIG_EAP_PEAP
#define CONFIG_EAP_TTLS
#define CONFIG_EAP_FAST
#define CONFIG_EAP_SIM
#define CONFIG_EAP_AKA
#define CONFIG_EAP_AKA_PRIME

#if defined(CONFIG_EAP_PEAP) || defined(CONFIG_EAP_TTLS) || defined(CONFIG_EAP_FAST)
#define CONFIG_EAP_MSCHAPV2
#define CONFIG_EAP_GTC
#endif
#endif

#define CONFIG_WPA_SUPP_DEBUG_LEVEL 3
#define CONFIG_LOG_BUFFER_SIZE      2048
//#define CONFIG_NO_STDOUT_DEBUG 1
//#define WPA_SUPPLICANT_CLEANUP_INTERVAL 120
#define HOSTAPD_CLEANUP_INTERVAL 120
//#define CONFIG_WIFI_USB_FILE_ACCESS 1
#else
#define CONFIG_MBO
#endif

#if defined(CONFIG_WIFI_USB_FILE_ACCESS) && defined(CONFIG_USB_BRIDGE)
#error " CONFIG_USB_BRIDGE and CONFIG_WIFI_USB_FILE_ACCESS are exclusive for ncp and ncp_supp"
#endif

#endif /* _WIFI_CONFIG_H_ */
