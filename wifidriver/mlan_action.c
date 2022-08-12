/** @file mlan_action.c
 *
 *  @brief  This file provides functions for action management frame
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

#include <mlan_api.h>

/********************************************************
                Local Variables
********************************************************/

/********************************************************
                Global Variables
********************************************************/

/********************************************************
                Local Functions
********************************************************/
/**
 *  @brief This function process rx action frame
 *
 *  @param payload      rx frame including 802.11 header
 *  @param payload_len  length of action frame
 *  @param src_addr     source address
 *
 *  @return             MLAN_STATUS_SUCCESS or MLAN_STATUS_FAILURE
 */
static mlan_status wlan_process_mgmt_wnm_action(t_u8 *payload, t_u32 payload_len, t_u8 *src_addr, t_u8 *dest_addr)
{
    IEEEtypes_WNM_ActionFieldType_e action_code = 0;
    t_u8 *pos;
    mlan_status ret = MLAN_STATUS_FAILURE;

    pos         = payload + sizeof(wlan_802_11_header) + 1;
    action_code = (IEEEtypes_WNM_ActionFieldType_e)(*pos++);

    switch (action_code)
    {
#ifdef CONFIG_11V
        case IEEE_MGMT_WNM_BTM_REQUEST:
        {
            IEEEtypes_FrameCtl_t *mgmt_fc_p =
                (IEEEtypes_FrameCtl_t *)(void *)&(((wlan_802_11_header *)(void *)payload)->frm_ctl);

            wlan_process_mgmt_wnm_btm_req(pos, (payload + payload_len), src_addr, dest_addr, (bool)mgmt_fc_p->wep);
            ret = MLAN_STATUS_SUCCESS;
            break;
        }
#endif
        default:
            wlcm_d("WNM: Unknown request");
            break;
    }
    return ret;
}

/********************************************************
                Global functions
********************************************************/
/**
 *  @brief This function process rx action frame
 *
 *  @param payload      rx frame including 802.11 header
 *  @param payload_len  length of action frame
 *
 *  @return             MLAN_STATUS_SUCCESS or MLAN_STATUS_FAILURE
 */
mlan_status wlan_process_mgmt_action(t_u8 *payload, t_u32 payload_len)
{
    wlan_802_11_header *pieee_pkt_hdr   = MNULL;
    IEEEtypes_ActionCategory_e category = 0;
    mlan_status ret                     = MLAN_STATUS_FAILURE;

    pieee_pkt_hdr = (wlan_802_11_header *)(void *)payload;
    category      = (IEEEtypes_ActionCategory_e)(*(payload + sizeof(wlan_802_11_header)));

    switch (category)
    {
        case IEEE_MGMT_ACTION_CATEGORY_WNM:
            ret = wlan_process_mgmt_wnm_action(payload, payload_len, pieee_pkt_hdr->addr1, pieee_pkt_hdr->addr2);
            break;
        default:
            wlcm_d("WNM: Unknown request");
            break;
    }
    return ret;
}
