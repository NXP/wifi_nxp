/** @file mlan_mbo.h
 *
 *  @brief Interface for the BTM module implemented in mlan_11k.c
 *
 *  Driver interface functions and type declarations for the process RRM data
 *    module implemented in mlan_11k.c.
 *
 *  Copyright 2022-2022 NXP
 *
 *  NXP CONFIDENTIAL
 *  The source code contained or described herein and all documents related to
 *  the source code ("Materials") are owned by NXP, its
 *  suppliers and/or its licensors. Title to the Materials remains with NXP,
 *  its suppliers and/or its licensors. The Materials contain
 *  trade secrets and proprietary and confidential information of NXP, its
 *  suppliers and/or its licensors. The Materials are protected by worldwide
 * copyright and trade secret laws and treaty provisions. No part of the
 * Materials may be used, copied, reproduced, modified, published, uploaded,
 * posted, transmitted, distributed, or disclosed in any way without NXP's prior
 *  express written permission.
 *
 *  No license under any patent, copyright, trade secret or other intellectual
 *  property right is granted to or conferred upon you by disclosure or delivery
 *  of the Materials, either expressly, by implication, inducement, estoppel or
 *  otherwise. Any license under such intellectual property rights must be
 *  express and approved by NXP in writing.
 *
 */

/********************************************************
Change log:
    8/SEP/2022: initial version
********************************************************/
#ifndef _MLAN_MBO_H
#define _MLAN_MBO_H

#ifdef CONFIG_MBO
/** MBO attributes ID */
enum MBO_ATTRIB_ID
{
    MBO_AP_CAP_IND = 1,
    MBO_NON_PERFER_CH_REPORT,
    MBO_CELLULAR_DATA_CAP,
    MBO_ASSOC_DISALLOWED,
    MBO_CELLULAR_DATA_CONNECT_PREFER,
    MBO_TRANSIT_REASON,
    MBO_TRANSIT_REJECCT_REASON,
    MBO_ASSOC_RETRY_DELAY,
};

extern const t_u8 mbo_oui[];

t_u8 *wlan_add_mbo_oui(t_u8 *oui);
t_u8 *wlan_add_mbo_oui_type(t_u8 *oui_type);
t_u8 *wlan_add_mbo_cellular_cap(t_u8 *attrib);
t_u8 *wlan_add_mbo_prefer_ch(t_u8 *attrib, t_u8 ch0, t_u8 pefer0, t_u8 ch1, t_u8 pefer1);
void wlan_send_mgmt_wnm_notification(
    t_u8 *src_addr, t_u8 *dst_addr, t_u8 *target_bssid, t_u8 *tag_nr, t_u8 tag_len, bool protect);
#endif
#endif
