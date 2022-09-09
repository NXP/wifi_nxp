/** @file mlan_action.h
 *
 *  @brief Interface for the mlan_action module implemented in mlan_action.c
 *
 *  Driver interface functions and type declarations for the process action frame
 *    module implemented in mlan_action.c.
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

#ifndef _MLAN_ACTION_H_
#define _MLAN_ACTION_H_

#include "mlan_fw.h"

/** process rx action frame */
mlan_status wlan_process_mgmt_action(t_u8 *payload, t_u32 payload_len, RxPD *rxpd);

#ifdef CONFIG_1AS
/* frame body for timing measurement action frame */
typedef PACK_START struct _wifi_wnm_timing_msmt_t
{
    t_u8 action; /* 1 */
    t_u8 dialog_token;
    t_u8 follow_up_dialog_token;
    t_u32 tod;
    t_u32 toa;
    t_u8 max_tod_err;
    t_u8 max_toa_err;
} PACK_END wifi_wnm_timing_msmt_t;

void wlan_process_timing_measurement_frame(t_u8 *payload, t_u32 payload_len, RxPD *rxpd);
void wlan_send_timing_measurement_req_frame(mlan_private *pmpriv, t_u8 *ta, t_u8 trigger);
mlan_status wlan_send_timing_measurement_frame(mlan_private *pmpriv);
#endif
#endif /* !_MLAN_ACTION_H_ */
