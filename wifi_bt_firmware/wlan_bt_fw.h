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
#include "sduartIW416_wlan_bt.h"
#elif defined(SD8987)
#include "sduart8987_wlan_bt.h"
#elif defined(SD8997)
#include "sduart8997_wlan_bt.h"
#elif defined(SD9097)
#include "pvt_sd9097_wlan.h"
#elif defined(SD9098)
#include "pvt_sd9098_wlan.h"
#elif defined(IW61x)
#if defined(CONFIG_RF_TEST_MODE)
#include "sduart_nw61x_fp255_se.h"
#else
#include "sduart_nw61x_se.h"
#endif
#elif defined(RW610)
const unsigned char *wlan_fw_bin   = (void *)0;
const unsigned int wlan_fw_bin_len = 0;
#endif

#endif /* __WLAN_BT_FW_H__ */
