/*
 *  Copyright 2021 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __WLAN_BT_FW_H__
#define __WLAN_BT_FW_H__

#if defined(SD8801)
#include "sd8801_wlan.h"
#elif defined(SD8978)
#ifdef CONFIG_FW_VDLL
#include "sdIW416_wlan_vdllv2.h"
#else
#if !defined(CONFIG_WIFI_IND_DNLD) && !defined(CONFIG_BT_IND_DNLD)
#include "sduartIW416_wlan_bt.h"
#else
#include "sdIW416_wlan.h"
#include "uartIW416_bt.h"
#endif
#endif
#elif defined(SD8987)
#ifdef CONFIG_FW_VDLL
#include "sd8987_wlan_vdllv2.h"
#else
#if !defined(CONFIG_WIFI_IND_DNLD) && !defined(CONFIG_BT_IND_DNLD)
#include "sduart8987_wlan_bt.h"
#else
#include "sd8987_wlan.h"
#include "uart8987_bt.h"
#endif
#endif
#elif defined(SD8997)
#include "sduart8997_wlan_bt.h"
#elif defined(SD9097)
#include "pvt_sd9097_wlan.h"
#elif defined(SD9098)
#include "pvt_sd9098_wlan.h"
#elif defined(SD9177)
#if defined(CONFIG_UART_WIFI_BRIDGE)
#include "sduart_nw61x_mfg_se.h"
#else
#if !defined(CONFIG_WIFI_IND_DNLD) && !defined(CONFIG_BT_IND_DNLD)
#include "sduart_nw61x_se.h"
#else
#include "sd_nw61x_se.h"
#include "uart_nw61x_se.h"
#endif
#endif
#elif defined(RW610)
const unsigned char *wlan_fw_bin   = (const unsigned char *)(void *)0;
const unsigned int wlan_fw_bin_len = 0;
#endif

#endif /* __WLAN_BT_FW_H__ */
