/** @file mlan.h
 *
 *  @brief This file declares all APIs that will be called from MOAL module.
 *  It also defines the data structures used for APIs between MLAN and MOAL.
 *
 *  Copyright 2008-2021, 2023 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 *
 */

/******************************************************
Change log:
    10/13/2008: initial version
    11/07/2008: split mlan.h into mlan_decl.h & mlan_ioctl.h
******************************************************/

#ifndef _MLAN_H_
#define _MLAN_H_

#ifndef CONFIG_WIFI_INTERNAL
#define CONFIG_WIFI_INTERNAL 1
#endif

#ifdef CONFIG_WIFI_INTERNAL
#define CONFIG_MLAN_WMSDK              1
#define CONFIG_11N                     1
#define STA_SUPPORT                    1
#define UAP_SUPPORT                    1
#define WPA                            1
#define KEY_MATERIAL_WEP               1
#define KEY_PARAM_SET_V2               1
#define ENABLE_802_11W                 1
#define ENABLE_GCMP_SUPPORT            1
#define CONFIG_STA_AMPDU_RX            1
#define CONFIG_STA_AMPDU_TX            1
#define CONFIG_ENABLE_AMSDU_RX         1
#define CONFIG_UAP_AMPDU_TX            1
#define CONFIG_UAP_AMPDU_RX            1
#define CONFIG_WNM_PS                  1
#define CONFIG_SCAN_CHANNEL_GAP        1
#define CONFIG_COMBO_SCAN              1
#define CONFIG_BG_SCAN                 1
#define CONFIG_HOST_MLME               1
#define UAP_HOST_MLME                  1
#define CONFIG_WIFI_MAX_CLIENTS_CNT    1
#define CONFIG_WIFI_RTS_THRESHOLD      1
#define CONFIG_UAP_STA_MAC_ADDR_FILTER 1
#define CONFIG_WIFI_FRAG_THRESHOLD     1
#define CONFIG_WIFI_FORCE_RTS          1
#define CONFIG_TX_AMPDU_PROT_MODE      1
#endif

#if !defined(SD8801)
#define CONFIG_GTK_REKEY_OFFLOAD       1
#endif

#if defined(SD9177)
#define CONFIG_TCP_ACK_ENH 1
#define CONFIG_FW_VDLL     1
#define CONFIG_WIFI_CAPA   1
#endif

#ifdef CONFIG_11AX
#define CONFIG_11K 1
#define CONFIG_11V 1
#ifndef CONFIG_WPA_SUPP
#define CONFIG_DRIVER_MBO 1
#endif
#endif

#include "mlan_decl.h"
#include "mlan_ioctl.h"
#include "mlan_ieee.h"

#endif /* !_MLAN_H_ */
