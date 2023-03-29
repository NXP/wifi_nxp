/*
 *  Copyright 2021 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __WLAN_BT_FW_H__
#define __WLAN_BT_FW_H__

#if defined(SD8801)
#ifdef CONFIG_WPA_SUPP
#include "sd8801_fp92_wlan.h"
#else
#include "sd8801_wlan.h"
#endif
#elif defined(SD8978)
#ifdef CONFIG_WPA_SUPP
#include "sduartIW416_fp92_wlan_bt.h"
#else
#include "sduartIW416_wlan_bt.h"
#endif
#elif defined(SD8987)
#ifdef CONFIG_WPA_SUPP
#include "sduart8987_fp92_wlan_bt.h"
#else
#include "sduart8987_wlan_bt.h"
#endif
#elif defined(SD8997)
#include "sduart8997_wlan_bt.h"
#elif defined(SD9097)
#include "pvt_sd9097_wlan.h"
#elif defined(SD9098)
#include "pvt_sd9098_wlan.h"
#elif defined(IW61x)
#if defined(CONFIG_RF_TEST_MODE)
#include "sduart_nw61x_fp255.h"
#else
#include "sduart_nw61x.h"
#endif
#elif defined(RW610)
const unsigned char *wlan_fw_bin   = (void *)0;
const unsigned int wlan_fw_bin_len = 0;
#endif

#endif /* __WLAN_BT_FW_H__ */
