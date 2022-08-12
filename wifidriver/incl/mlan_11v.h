/** @file mlan_11v.h
 *
 *  @brief Interface for the BTM module implemented in mlan_11v.c
 *
 *  Driver interface functions and type declarations for the process BTM frame
 *    module implemented in mlan_11v.c.
 *
 *  Copyright 2022-2022 NXP
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

/********************************************************
Change log:
    08/11/2022: initial version
********************************************************/

#ifndef _MLAN_11V_H_
#define _MLAN_11V_H_

#ifdef CONFIG_11V

#define WLAN_WNM_MAX_NEIGHBOR_REPORT               5
#define MGMT_WNM_NEIGHBOR_BSS_TRANSITION_CANDIDATE 3

struct wnm_neighbor_report
{
    t_u8 bssid[MLAN_MAC_ADDR_LENGTH];
    t_u32 bssid_info;
    t_u8 reg_class;
    t_u8 channel;
    t_u8 PhyType;
    t_u8 prefer;
    t_u8 prefer_select;
};

/* IEEE Std 802.11-2016 - Table 9-357 BTM status code definitions */
enum wnm_btm_status_code
{
    WNM_BTM_ACCEPT                                 = 0,
    WNM_BTM_REJECT_UNSPECIFIED                     = 1,
    WNM_BTM_REJECT_INSUFFICIENT_BEACON_PROBE_RESP  = 2,
    WNM_BTM_REJECT_INSUFFICIENT_AVAILABLE_CAPABITY = 3,
    WNM_BTM_REJECT_TERMINATION_UNDESIRED           = 4,
    WNM_BTM_REJECT_TERMINATION_DELAY_REQUEST       = 5,
    WNM_BTM_REJECT_STA_CANDIDATE_LIST_PROVIDED     = 6,
    WNM_BTM_REJECT_NO_SUITABLE_CANDIDATES          = 7,
    WNM_BTM_REJECT_LEAVING_ESS                     = 8
};

/** process rx action frame */
void wlan_process_mgmt_wnm_btm_req(t_u8 *pos, t_u8 *end, t_u8 *src_addr, t_u8 *dest_addr, bool protect);
#endif /* CONFIG_11V */

#endif /* !_MLAN_11V_H_ */
