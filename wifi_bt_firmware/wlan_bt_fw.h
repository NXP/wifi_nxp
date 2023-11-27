/*
 *  Copyright 2021 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __WLAN_BT_FW_H__
#define __WLAN_BT_FW_H__

#if defined(SD8801)
extern const unsigned char wlan_fw_bin[];
extern unsigned int wlan_fw_bin_len;
#elif defined(SD8978) || defined(SD8987) || defined(SD9177)
extern const unsigned char wlan_fw_bin[];
extern const unsigned int wlan_fw_bin_len;
extern const unsigned char bt_fw_bin[];
extern const unsigned int bt_fw_bin_len;
#elif defined(RW610)
extern const unsigned char *wlan_fw_bin;
extern unsigned int wlan_fw_bin_len;
#endif

#endif /* __WLAN_BT_FW_H__ */
