/** @file mlan.h
 *
 *  @brief This file declares all APIs that will be called from MOAL module.
 *  It also defines the data structures used for APIs between MLAN and MOAL.
 *
 *  Copyright 2008-2021 NXP
 *
 *  NXP CONFIDENTIAL
 *  The source code contained or described herein and all documents related to
 *  the source code ("Materials") are owned by NXP, its
 *  suppliers and/or its licensors. Title to the Materials remains with NXP,
 *  its suppliers and/or its licensors. The Materials contain
 *  trade secrets and proprietary and confidential information of NXP, its
 *  suppliers and/or its licensors. The Materials are protected by worldwide copyright
 *  and trade secret laws and treaty provisions. No part of the Materials may be
 *  used, copied, reproduced, modified, published, uploaded, posted,
 *  transmitted, distributed, or disclosed in any way without NXP's prior
 *  express written permission.
 *
 *  No license under any patent, copyright, trade secret or other intellectual
 *  property right is granted to or conferred upon you by disclosure or delivery
 *  of the Materials, either expressly, by implication, inducement, estoppel or
 *  otherwise. Any license under such intellectual property rights must be
 *  express and approved by NXP in writing.
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
#define CONFIG_MLAN_WMSDK         1
#define CONFIG_11N                1
#define STA_SUPPORT               1
#define UAP_SUPPORT               1
#define WPA                       1
#define KEY_MATERIAL_WEP          1
#define KEY_PARAM_SET_V2          1
#define ENABLE_802_11W            1
#define OTP_CHANINFO              1
#define CONFIG_STA_AMPDU_RX       1
#define CONFIG_STA_AMPDU_TX       1
#define CONFIG_ENABLE_AMSDU_RX    1
#define CONFIG_UAP_AMPDU_TX       1
#define CONFIG_UAP_AMPDU_RX       1
#define CONFIG_WIFIDRIVER_PS_LOCK 1
#endif

#include "mlan_decl.h"
#include "mlan_ioctl.h"
#include "mlan_ieee.h"

#endif /* !_MLAN_H_ */
