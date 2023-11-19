/*
 *  Copyright 2023 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __NXP_WIFI_H__
#define __NXP_WIFI_H__

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef  __ZEPHYR__
#define CONFIG_ZEPHYR __ZEPHYR__
#endif

#if CONFIG_NXP_WIFI_MAX_AP_ENTRIES
#define CONFIG_MAX_AP_ENTRIES CONFIG_NXP_WIFI_MAX_AP_ENTRIES
#endif

#if CONFIG_NXP_WIFI_WLAN_KNOWN_NETWORKS
#define CONFIG_WLAN_KNOWN_NETWORKS CONFIG_NXP_WIFI_WLAN_KNOWN_NETWORKS
#endif

#ifdef CONFIG_NXP_WIFI_SDIO_MULTI_PORT_RX_AGGR
#define CONFIG_SDIO_MULTI_PORT_RX_AGGR CONFIG_NXP_WIFI_SDIO_MULTI_PORT_RX_AGGR
#endif

#ifdef CONFIG_NXP_WIFI_OFFLOAD
#define CONFIG_OFFLOAD CONFIG_NXP_WIFI_OFFLOAD
#endif

#if CONFIG_NXP_WIFI_MON_THREAD_STACK_SIZE
#define CONFIG_MON_THREAD_STACK_SIZE CONFIG_NXP_WIFI_MON_THREAD_STACK_SIZE
#endif

#if CONFIG_NXP_WIFI_WLCMGR_STACK_SIZE
#define CONFIG_WLCMGR_STACK_SIZE CONFIG_NXP_WIFI_WLCMGR_STACK_SIZE
#endif

#if CONFIG_NXP_WIFI_WPS_STACK_SIZE
#define CONFIG_WPS_STACK_SIZE CONFIG_NXP_WIFI_WPS_STACK_SIZE
#endif

#if CONFIG_NXP_WIFI_POWERSAVE_STACK_SIZE
#define CONFIG_POWERSAVE_STACK_SIZE CONFIG_NXP_WIFI_POWERSAVE_STACK_SIZE
#endif

#if CONFIG_NXP_WIFI_TX_STACK_SIZE
#define CONFIG_TX_STACK_SIZE CONFIG_NXP_WIFI_TX_STACK_SIZE
#endif

#if CONFIG_NXP_WIFI_DRIVER_STACK_SIZE
#define CONFIG_DRIVER_STACK_SIZE CONFIG_NXP_WIFI_DRIVER_STACK_SIZE
#endif

#if CONFIG_NXP_WIFI_DHCP_SERVER_STACK_SIZE
#define CONFIG_DHCP_SERVER_STACK_SIZE CONFIG_NXP_WIFI_DHCP_SERVER_STACK_SIZE
#endif

#ifdef CONFIG_NXP_WIFI_11AX
#define CONFIG_11AX CONFIG_NXP_WIFI_11AX
#endif

#ifdef CONFIG_NXP_WIFI_11AC
#define CONFIG_11AC CONFIG_NXP_WIFI_11AC
#endif

#ifdef CONFIG_NXP_WIFI_ENABLE_HTTPSERVER
#define CONFIG_ENABLE_HTTPSERVER CONFIG_NXP_WIFI_ENABLE_HTTPSERVER
#endif

#ifdef CONFIG_NXP_WIFI_TX_RX_ZERO_COPY
#define CONFIG_TX_RX_ZERO_COPY CONFIG_NXP_WIFI_TX_RX_ZERO_COPY
#endif

#ifdef CONFIG_NXP_WIFI_CAPA
#define CONFIG_WIFI_CAPA CONFIG_NXP_WIFI_CAPA
#endif

#ifdef CONFIG_NXP_WIFI_WMM_UAPSD
#define CONFIG_WMM_UAPSD CONFIG_NXP_WIFI_WMM_UAPSD
#endif

#ifdef CONFIG_NXP_WIFI_GET_LOG
#define CONFIG_WIFI_GET_LOG CONFIG_NXP_WIFI_GET_LOG
#endif

#ifdef CONFIG_NXP_WIFI_TX_PER_TRACK
#define CONFIG_WIFI_TX_PER_TRACK CONFIG_NXP_WIFI_TX_PER_TRACK
#endif

#ifdef CONFIG_NXP_WIFI_CSI
#define CONFIG_CSI CONFIG_NXP_WIFI_CSI
#endif

#ifdef CONFIG_NXP_WIFI_RESET
#define CONFIG_WIFI_RESET CONFIG_NXP_WIFI_RESET
#endif

#ifdef CONFIG_NXP_WIFI_NET_MONITOR
#define CONFIG_NET_MONITOR CONFIG_NXP_WIFI_NET_MONITOR
#endif

#ifdef CONFIG_NXP_WIFI_ECSA
#define CONFIG_ECSA CONFIG_NXP_WIFI_ECSA
#endif

#ifdef CONFIG_NXP_WIFI_UNII4_BAND_SUPPORT
#define CONFIG_UNII4_BAND_SUPPORT CONFIG_NXP_WIFI_UNII4_BAND_SUPPORT
#endif

#ifdef CONFIG_NXP_WIFI_CAU_TEMPERATURE
#define CONFIG_CAU_TEMPERATURE CONFIG_NXP_WIFI_CAU_TEMPERATURE
#endif

#ifdef CONFIG_NXP_WIFI_TSP
#define CONFIG_TSP CONFIG_NXP_WIFI_TSP
#endif

#ifdef CONFIG_NXP_WIFI_11AX_TWT
#define CONFIG_11AX_TWT CONFIG_NXP_WIFI_11AX_TWT
#endif

#ifdef CONFIG_NXP_WIFI_COMPRESS_TX_PWTBL
#define CONFIG_COMPRESS_TX_PWTBL CONFIG_NXP_WIFI_COMPRESS_TX_PWTBL
#endif

#ifdef CONFIG_NXP_WIFI_COMPRESS_RU_TX_PWTBL
#define CONFIG_COMPRESS_RU_TX_PWTBL CONFIG_NXP_WIFI_COMPRESS_RU_TX_PWTBL
#endif

#ifdef CONFIG_NXP_WIFI_MAX_PRIO
#define CONFIG_WIFI_MAX_PRIO CONFIG_NXP_WIFI_MAX_PRIO
#endif

#ifdef CONFIG_NXP_WIFI_IPS
#define CONFIG_IPS CONFIG_NXP_WIFI_IPS
#endif

#ifdef CONFIG_NXP_WIFI_EXT_SCAN_SUPPORT
#define CONFIG_EXT_SCAN_SUPPORT CONFIG_NXP_WIFI_EXT_SCAN_SUPPORT
#endif

#ifdef CONFIG_NXP_WIFI_SCAN_WITH_RSSIFILTER
#define CONFIG_SCAN_WITH_RSSIFILTER CONFIG_NXP_WIFI_SCAN_WITH_RSSIFILTER
#endif

#ifdef CONFIG_NXP_WIFI_DTIM_PERIOD
#define CONFIG_WIFI_DTIM_PERIOD CONFIG_NXP_WIFI_DTIM_PERIOD
#endif

#ifdef CONFIG_NXP_WIFI_RX_ABORT_CFG
#define CONFIG_RX_ABORT_CFG CONFIG_NXP_WIFI_RX_ABORT_CFG
#endif

#ifdef CONFIG_NXP_WIFI_RX_ABORT_CFG_EXT
#define CONFIG_RX_ABORT_CFG_EXT CONFIG_NXP_WIFI_RX_ABORT_CFG_EXT
#endif

#ifdef CONFIG_NXP_WIFI_CCK_DESENSE_CFG
#define CONFIG_CCK_DESENSE_CFG CONFIG_NXP_WIFI_CCK_DESENSE_CFG
#endif

#ifdef CONFIG_NXP_WIFI_MEM_ACCESS
#define CONFIG_WIFI_MEM_ACCESS CONFIG_NXP_WIFI_MEM_ACCESS
#endif

#ifdef CONFIG_NXP_WIFI_REG_ACCESS
#define CONFIG_WIFI_REG_ACCESS CONFIG_NXP_WIFI_REG_ACCESS
#endif

#ifdef CONFIG_NXP_WIFI_SUBSCRIBE_EVENT_SUPPORT
#define CONFIG_SUBSCRIBE_EVENT_SUPPORT CONFIG_NXP_WIFI_SUBSCRIBE_EVENT_SUPPORT
#endif

#ifdef CONFIG_NXP_WIFI_TX_RX_HISTOGRAM
#define CONFIG_TX_RX_HISTOGRAM CONFIG_NXP_WIFI_TX_RX_HISTOGRAM
#endif

#ifdef CONFIG_NXP_WIFI_COEX_DUTY_CYCLE
#define CONFIG_COEX_DUTY_CYCLE CONFIG_NXP_WIFI_COEX_DUTY_CYCLE
#endif

#ifdef CONFIG_NXP_WIFI_MMSF
#define CONFIG_MMSF CONFIG_NXP_WIFI_MMSF
#endif

#ifdef CONFIG_NXP_WIFI_USB_FILE_ACCESS
#define CONFIG_USB_FILE_ACCESS CONFIG_NXP_WIFI_USB_FILE_ACCESS
#endif

#if CONFIG_NXP_WIFI_SCAN_CHANNEL_GAP_TIME
#define CONFIG_SCAN_CHANNEL_GAP_TIME CONFIG_NXP_WIFI_SCAN_CHANNEL_GAP_TIME
#endif

#ifdef CONFIG_NXP_WIFI_RX_CHAN_INFO
#define CONFIG_RX_CHAN_INFO CONFIG_NXP_WIFI_RX_CHAN_INFO
#endif

#ifdef CONFIG_NXP_WIFI_TXPD_RXPD_V3
#define CONFIG_TXPD_RXPD_V3 CONFIG_NXP_WIFI_TXPD_RXPD_V3
#endif

#ifdef CONFIG_NXP_WIFI_RF_TEST_MODE
#define CONFIG_RF_TEST_MODE CONFIG_NXP_WIFI_RF_TEST_MODE
#endif

#ifdef CONFIG_NXP_WIFI_IMD3_CFG
#define CONFIG_IMD3_CFG CONFIG_NXP_WIFI_IMD3_CFG
#endif

#ifdef CONFIG_NXP_WIFI_EU_VALIDATION
#define CONFIG_EU_VALIDATION CONFIG_NXP_WIFI_EU_VALIDATION
#endif

#ifdef CONFIG_NXP_WIFI_CLOCKSYNC
#define CONFIG_CLOCKSYNC CONFIG_NXP_WIFI_CLOCKSYNC
#endif

#ifdef CONFIG_NXP_WIFI_WMM
#define CONFIG_WMM CONFIG_NXP_WIFI_WMM
#endif

#ifdef CONFIG_NXP_WIFI_IPV6
#define CONFIG_IPV6 CONFIG_NXP_WIFI_IPV6
#endif

#if CONFIG_NXP_WIFI_MAX_IPV6_ADDRESSES
#define CONFIG_MAX_IPV6_ADDRESSES CONFIG_NXP_WIFI_MAX_IPV6_ADDRESSES
#endif

#ifdef CONFIG_NXP_WIFI_5GHz_SUPPORT
#define CONFIG_5GHz_SUPPORT CONFIG_NXP_WIFI_5GHz_SUPPORT
#endif

#ifdef CONFIG_NXP_WIFI_HOST_SLEEP
#define CONFIG_HOST_SLEEP CONFIG_NXP_WIFI_HOST_SLEEP
#endif

#ifdef CONFIG_NXP_WIFI_ROAMING
#define CONFIG_ROAMING CONFIG_NXP_WIFI_ROAMING
#endif

#ifdef CONFIG_NXP_WIFI_CLOUD_KEEP_ALIVE
#define CONFIG_CLOUD_KEEP_ALIVE CONFIG_NXP_WIFI_CLOUD_KEEP_ALIVE
#endif

#ifdef CONFIG_NXP_WIFI_MEF_CFG
#define CONFIG_MEF_CFG CONFIG_NXP_WIFI_MEF_CFG
#endif

#ifdef CONFIG_NXP_WIFI_TURBO_MODE
#define CONFIG_TURBO_MODE CONFIG_NXP_WIFI_TURBO_MODE
#endif

#ifdef CONFIG_NXP_WIFI_EU_CRYPTO
#define CONFIG_EU_CRYPTO CONFIG_NXP_WIFI_EU_CRYPTO
#endif

#ifdef CONFIG_NXP_WIFI_FIPS
#define CONFIG_FIPS CONFIG_NXP_WIFI_FIPS
#endif

#ifdef CONFIG_NXP_WIFI_OWE
#define CONFIG_OWE CONFIG_NXP_WIFI_OWE
#endif

#ifdef CONFIG_NXP_WIFI_11K
#define CONFIG_11K CONFIG_NXP_WIFI_11K
#endif

#ifdef CONFIG_NXP_WIFI_11V
#define CONFIG_11V CONFIG_NXP_WIFI_11V
#endif

#ifdef CONFIG_NXP_WIFI_11R
#define CONFIG_11R CONFIG_NXP_WIFI_11R
#endif

#ifdef CONFIG_NXP_WIFI_UAP_WORKAROUND_STICKY_TIM
#define CONFIG_UAP_WORKAROUND_STICKY_TIM CONFIG_NXP_WIFI_UAP_WORKAROUND_STICKY_TIM
#endif

#ifdef CONFIG_NXP_WIFI_ENABLE_ERROR_LOGS
#define CONFIG_ENABLE_ERROR_LOGS CONFIG_NXP_WIFI_ENABLE_ERROR_LOGS
#endif

#ifdef CONFIG_NXP_WIFI_ENABLE_WARNING_LOGS
#define CONFIG_ENABLE_WARNING_LOGS CONFIG_NXP_WIFI_ENABLE_WARNING_LOGS
#endif

#ifdef CONFIG_NXP_WIFI_DEBUG_BUILD
#define CONFIG_DEBUG_BUILD CONFIG_NXP_WIFI_DEBUG_BUILD
#endif

#ifdef CONFIG_NXP_WIFI_OS_DEBUG
#define CONFIG_OS_DEBUG CONFIG_NXP_WIFI_OS_DEBUG
#endif

#ifdef CONFIG_NXP_WIFI_NET_DEBUG
#define CONFIG_NET_DEBUG CONFIG_NXP_WIFI_NET_DEBUG
#endif

#ifdef CONFIG_NXP_WIFI_WLCMGR_DEBUG
#define CONFIG_WLCMGR_DEBUG CONFIG_NXP_WIFI_WLCMGR_DEBUG
#endif

#ifdef CONFIG_NXP_WIFI_EXTRA_DEBUG
#define CONFIG_WIFI_EXTRA_DEBUG CONFIG_NXP_WIFI_EXTRA_DEBUG
#endif

#ifdef CONFIG_NXP_WIFI_UAP_DEBUG
#define CONFIG_WIFI_UAP_DEBUG CONFIG_NXP_WIFI_UAP_DEBUG
#endif

#ifdef CONFIG_NXP_WIFI_EVENTS_DEBUG
#define CONFIG_WIFI_EVENTS_DEBUG CONFIG_NXP_WIFI_EVENTS_DEBUG
#endif

#ifdef CONFIG_NXP_WIFI_CMD_RESP_DEBUG
#define CONFIG_WIFI_CMD_RESP_DEBUG CONFIG_NXP_WIFI_CMD_RESP_DEBUG
#endif

#ifdef CONFIG_NXP_WIFI_SCAN_DEBUG
#define CONFIG_WIFI_SCAN_DEBUG CONFIG_NXP_WIFI_SCAN_DEBUG
#endif

#ifdef CONFIG_NXP_WIFI_PKT_DEBUG
#define CONFIG_WIFI_PKT_DEBUG CONFIG_NXP_WIFI_PKT_DEBUG
#endif

#ifdef CONFIG_NXP_WIFI_IO_INFO_DUMP
#define CONFIG_WIFI_IO_INFO_DUMP CONFIG_NXP_WIFI_IO_INFO_DUMP
#endif

#ifdef CONFIG_NXP_WIFI_IO_DEBUG
#define CONFIG_WIFI_IO_DEBUG CONFIG_NXP_WIFI_IO_DEBUG
#endif

#ifdef CONFIG_NXP_WIFI_IO_DUMP
#define CONFIG_WIFI_IO_DUMP CONFIG_NXP_WIFI_IO_DUMP
#endif

#ifdef CONFIG_NXP_WIFI_MEM_DEBUG
#define CONFIG_WIFI_MEM_DEBUG CONFIG_NXP_WIFI_MEM_DEBUG
#endif

#ifdef CONFIG_NXP_WIFI_AMPDU_DEBUG
#define CONFIG_WIFI_AMPDU_DEBUG CONFIG_NXP_WIFI_AMPDU_DEBUG
#endif

#ifdef CONFIG_NXP_WIFI_TIMER_DEBUG
#define CONFIG_WIFI_TIMER_DEBUG CONFIG_NXP_WIFI_TIMER_DEBUG
#endif

#ifdef CONFIG_NXP_WIFI_SDIO_DEBUG
#define CONFIG_WIFI_SDIO_DEBUG CONFIG_NXP_WIFI_SDIO_DEBUG
#endif

#ifdef CONFIG_NXP_WIFI_SDIO_IO_DEBUG
#define CONFIG_SDIO_IO_DEBUG CONFIG_NXP_WIFI_SDIO_IO_DEBUG
#endif

#ifdef CONFIG_NXP_WIFI_FWDNLD_IO_DEBUG
#define CONFIG_FWDNLD_IO_DEBUG CONFIG_NXP_WIFI_FWDNLD_IO_DEBUG
#endif

#ifdef CONFIG_NXP_WIFI_FW_DEBUG
#define CONFIG_WIFI_FW_DEBUG CONFIG_NXP_WIFI_FW_DEBUG
#endif

#ifdef CONFIG_NXP_WIFI_FW_VDLL_DEBUG
#define CONFIG_FW_VDLL_DEBUG CONFIG_NXP_WIFI_FW_VDLL_DEBUG
#endif

#ifdef CONFIG_NXP_WIFI_DHCP_SERVER_DEBUG
#define CONFIG_DHCP_SERVER_DEBUG CONFIG_NXP_WIFI_DHCP_SERVER_DEBUG
#endif

#if defined(CONFIG_NXP_WIFI_8978) || defined(CONFIG_NXP_WIFI_8987) || defined(CONFIG_NXP_WIFI_9177)

#define CONFIG_GTK_REKEY_OFFLOAD 1

#define CONFIG_FW_VDLL     1

#endif

#if defined(CONFIG_NXP_WIFI_9177)
#define CONFIG_TCP_ACK_ENH 1
#endif

#ifdef CONFIG_11AX

#ifndef CONFIG_11K
#define CONFIG_11K 1
#endif

#ifndef CONFIG_11V
#define CONFIG_11V 1
#endif

#ifndef CONFIG_WPA_SUPP
#define CONFIG_DRIVER_MBO 1
#endif

#endif

#ifdef __cplusplus
}
#endif

#endif /* __NXP_WIFI_H__ */
