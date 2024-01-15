/*
 *  Copyright 2021 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __WLAN_BT_FW_H__
#define __WLAN_BT_FW_H__

#if defined(SD8801)
#include "8801/sd8801_wlan.h"
#elif defined(SD8978)
#if !defined(CONFIG_WIFI_IND_DNLD) && !defined(CONFIG_BT_IND_DNLD)
#include "IW416/sduartIW416_wlan_bt.h"
#else
#include "IW416/sdIW416_wlan.h"
#include "IW416/uartIW416_bt.h"
#endif
#elif defined(SD8987)
#if !defined(CONFIG_WIFI_IND_DNLD) && !defined(CONFIG_BT_IND_DNLD)
#include "8987/sduart8987_wlan_bt.h"
#else
#include "8987/sd8987_wlan.h"
#include "8987/uart8987_bt.h"
#endif
#elif defined(SD9177)
#if !defined(CONFIG_WIFI_IND_DNLD) && !defined(CONFIG_BT_IND_DNLD)
#include "nw61x/sduart_nw61x_se.h"
#else
#include "nw61x/sd_nw61x_se.h"
#include "nw61x/uart_nw61x_se.h"
#endif
#endif

#endif /* __WLAN_BT_FW_H__ */
