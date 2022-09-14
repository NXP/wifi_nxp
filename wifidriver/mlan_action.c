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
#include "wifi.h"
#ifdef RW610
#include "wifi-imu.h"
#else
#include "wifi-sdio.h"
#endif

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
 *  @brief This function process rx radio measurement action frame
 *
 *  @param payload      rx frame including 802.11 header
 *  @param payload_len  length of action frame
 *  @param src_addr     source address
 *
 *  @return             MLAN_STATUS_SUCCESS or MLAN_STATUS_FAILURE
 */
static mlan_status wlan_process_mgmt_radio_measurement_action(
    t_u8 *payload, t_u32 payload_len, t_u8 *dest_addr, t_u8 *src_addr, RxPD *rxpd)
{
    t_u8 action_code = 0;
    t_u8 *pos;
    mlan_status ret = MLAN_STATUS_FAILURE;

    pos         = payload + sizeof(wlan_802_11_header) + 1;
    action_code = *pos++;
    payload_len -= (sizeof(wlan_802_11_header) + 2);
#ifdef CONFIG_11K
    IEEEtypes_FrameCtl_t *mgmt_fc_p = (IEEEtypes_FrameCtl_t *)&(((wlan_802_11_header *)payload)->frm_ctl);
#endif

    switch (action_code)
    {
#ifdef CONFIG_11K
        case IEEE_MGMT_RRM_RADIO_MEASUREMENT_REQUEST:
        {
            wlan_process_radio_measurement_request(pos, payload_len, dest_addr, src_addr, mgmt_fc_p->wep);
            ret = MLAN_STATUS_SUCCESS;
            break;
        }
        case IEEE_MGMT_RRM_LINK_MEASUREMENT_REQUEST:
        {
            wlan_process_link_measurement_request(pos, payload_len, dest_addr, src_addr, mgmt_fc_p->wep, rxpd);
            ret = MLAN_STATUS_SUCCESS;
            break;
        }
#endif
        default:
            wifi_d("RRM: Unknown request: %u", action_code);
            break;
    }
    return ret;
}

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
            wifi_d("WNM: Unknown request: %u", action_code);
            break;
    }
    return ret;
}

static mlan_status wlan_process_mgmt_unprotect_wnm_action(t_u8 *payload, t_u32 payload_len, RxPD *rxpd)
{
    t_u8 action_code = 0;
    t_u8 *pos;
    mlan_status ret = MLAN_STATUS_FAILURE;

    pos         = payload + sizeof(wlan_802_11_header) + 1;
    action_code = *(pos++);

    switch (action_code)
    {
#ifdef CONFIG_1AS
        case 1:
            wlan_process_timing_measurement_frame(payload, payload_len, rxpd);
            ret = MLAN_STATUS_SUCCESS;
            break;
#endif
        default:
            wifi_d("unprotect WNM: Unknown request: %u", action_code);
            break;
    }
    return ret;
}

#ifdef CONFIG_1AS
/* imu_header + mgmt_txpd_len + sizeof(t_u16 frame_len) */
#define WLAN_MGMT_PKT_START_OFFSET (INTF_HEADER_LEN + 0x14)

static inline void wlan_outbuf_lock(void)
{
#ifdef RW610
    wifi_imu_lock();
#else
    wifi_sdio_lock();
#endif
}

static inline void wlan_outbuf_unlock(void)
{
#ifdef RW610
    wifi_imu_unlock();
#else
    wifi_sdio_unlock();
#endif
}

static void wlan_fill_mgmt_mac_header(mlan_private *pmpriv, wlan_mgmt_pkt *pkt_hdr, t_u16 subtype, t_u8 *da, t_u8 *sa)
{
    IEEEtypes_FrameCtl_t *frame_ctrl = (IEEEtypes_FrameCtl_t *)&pkt_hdr->wlan_header.frm_ctl;

    frame_ctrl->sub_type = subtype;
    frame_ctrl->type     = IEEE_TYPE_MANAGEMENT;
    memcpy(pkt_hdr->wlan_header.addr1, da, MLAN_MAC_ADDR_LENGTH);
    memcpy(pkt_hdr->wlan_header.addr2, sa, MLAN_MAC_ADDR_LENGTH);
    if (pmpriv->bss_index == 0)
        memcpy(pkt_hdr->wlan_header.addr3, da, MLAN_MAC_ADDR_LENGTH);
    else
        memcpy(pkt_hdr->wlan_header.addr3, sa, MLAN_MAC_ADDR_LENGTH);
    pkt_hdr->wlan_header.seq_ctl = 0;
    memset(pkt_hdr->wlan_header.addr4, 0x00, MLAN_MAC_ADDR_LENGTH);
}

void wlan_process_timing_measurement_frame(t_u8 *payload, t_u32 payload_len, RxPD *rxpd)
{
    mlan_private *pmpriv = mlan_adap->priv[rxpd->bss_type];
    t_u64 tsf;
    wlan_802_11_header *hdr        = (wlan_802_11_header *)payload;
    wifi_wnm_timing_msmt_t *tm_ind = MNULL;
    wifi_dot1as_info_t *info       = &pmpriv->dot1as_info;

    if (payload_len < sizeof(wlan_802_11_header) + sizeof(wifi_wnm_timing_msmt_t) + 1)
    {
        wifi_e("wlan_recv_tm_frame invalid packet length %d", payload_len);
        return;
    }

    info->role = 1;
    memcpy(info->peer_addr, hdr->addr2, MLAN_MAC_ADDR_LENGTH);

    /* get t2,t3 timestamp in rxpd */
    tsf      = rxpd->reserved1;
    tsf      = wlan_le64_to_cpu(tsf);
    info->t3 = tsf >> 32;
    info->t2 = (t_u32)tsf;

    /* t1 == tod, t4 == toa */
    /* skip category */
    tm_ind = (wifi_wnm_timing_msmt_t *)(payload + sizeof(wlan_802_11_header) + 1);
    /* 1 byte dialog_token + 1 byte prev_dialog_token + 4 bytes t1 + 4 bytes t4 */
    memcpy(&info->dialog_token, &tm_ind->dialog_token, 10);

    /* TODO: Vendor Specific */
    wifi_d("Recv timing measurement frame peer " MACSTR ", t1[%u] t2[%u] t3[%u] t4[%u]\r\n", MAC2STR(info->peer_addr),
           info->t1, info->t2, info->t3, info->t4);
    wlan_report_timing_measurement((wlan_dot1as_info_t *)info);
}

void wlan_send_timing_measurement_req_frame(mlan_private *pmpriv, t_u8 *ta, t_u8 trigger)
{
    t_u32 len;
    uint32_t max_len;
    t_u32 offset           = WLAN_MGMT_PKT_START_OFFSET;
    t_u8 *buf              = wifi_get_outbuf(&max_len);
    wlan_mgmt_pkt *pkt_hdr = MNULL;
    TxPD *txpd             = MNULL;

    assert(ta != MNULL);
    assert(buf != MNULL);
    wlan_outbuf_lock();

    pkt_hdr = (wlan_mgmt_pkt *)(buf + offset);
    wlan_fill_mgmt_mac_header(pmpriv, pkt_hdr, SUBTYPE_ACTION, ta, &pmpriv->curr_addr[0]);
    offset += sizeof(wlan_mgmt_pkt);

    /* WNM, Timimg Meaeurement Request action, Trigger */
    buf[offset]     = IEEE_MGMT_ACTION_CATEGORY_WNM;
    buf[offset + 1] = 25;
    buf[offset + 2] = trigger;
    len             = offset + 3;

    pkt_hdr->frm_len = len - WLAN_MGMT_PKT_START_OFFSET - sizeof(pkt_hdr->frm_len);

    raw_process_pkt_hdrs(buf, len, pmpriv->bss_index);
    /* set tx_token_id to 1 to get tx_status_event from FW */
    txpd              = (TxPD *)(buf + INTF_HEADER_LEN);
    txpd->tx_token_id = 1;
    wlan_xmit_pkt(len, pmpriv->bss_index);
    wlan_outbuf_unlock();
}

mlan_status wlan_send_timing_measurement_frame(mlan_private *pmpriv)
{
    mlan_status ret;
    t_u32 len;
    uint32_t max_len;
    t_u32 offset               = WLAN_MGMT_PKT_START_OFFSET;
    t_u8 *buf                  = wifi_get_outbuf(&max_len);
    wlan_mgmt_pkt *pkt_hdr     = MNULL;
    wifi_wnm_timing_msmt_t *tm = MNULL;
    TxPD *txpd                 = MNULL;

    assert(buf != MNULL);
    wlan_outbuf_lock();

    /* fill mac80211 header */
    pkt_hdr = (wlan_mgmt_pkt *)(buf + offset);
    wlan_fill_mgmt_mac_header(pmpriv, pkt_hdr, SUBTYPE_ACTION, &pmpriv->dot1as_info.peer_addr[0],
                              &pmpriv->curr_addr[0]);
    offset += sizeof(wlan_mgmt_pkt);

    /* Unprotected WNM */
    buf[offset] = IEEE_MGMT_ACTION_CATEGORY_UNPROTECT_WNM;
    offset += 1;

    /* fill tm body */
    tm = (wifi_wnm_timing_msmt_t *)&buf[offset];
    /* Timimg Measurement */
    tm->action = 1;
    /* 1 byte dialog_token + 1 byte prev_dialog_token + 4 bytes t1 + 4 bytes t4 */
    memcpy(&tm->dialog_token, &pmpriv->dot1as_info.dialog_token, 10);
    tm->max_tod_err = 0;
    tm->max_toa_err = 0;

    len              = offset + sizeof(wifi_wnm_timing_msmt_t);
    pkt_hdr->frm_len = len - WLAN_MGMT_PKT_START_OFFSET - sizeof(pkt_hdr->frm_len);
    /* TODO: Vendor Specific */

    raw_process_pkt_hdrs(buf, len, pmpriv->bss_index);
    /* set tx_token_id to 1 to get tx_status_event from FW */
    txpd              = (TxPD *)(buf + INTF_HEADER_LEN);
    txpd->tx_token_id = 1;
    ret               = wlan_xmit_pkt(len, pmpriv->bss_index);
    wlan_outbuf_unlock();
    return ret;
}
#endif

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
mlan_status wlan_process_mgmt_action(t_u8 *payload, t_u32 payload_len, RxPD *rxpd)
{
    wlan_802_11_header *pieee_pkt_hdr   = MNULL;
    IEEEtypes_ActionCategory_e category = 0;
    mlan_status ret                     = MLAN_STATUS_FAILURE;

    pieee_pkt_hdr = (wlan_802_11_header *)(void *)payload;
    category      = (IEEEtypes_ActionCategory_e)(*(payload + sizeof(wlan_802_11_header)));

    switch (category)
    {
        case IEEE_MGMT_ACTION_CATEGORY_RADIO_RSRC:
            ret = wlan_process_mgmt_radio_measurement_action(payload, payload_len, pieee_pkt_hdr->addr1,
                                                             pieee_pkt_hdr->addr2, rxpd);
            break;
        case IEEE_MGMT_ACTION_CATEGORY_WNM:
            ret = wlan_process_mgmt_wnm_action(payload, payload_len, pieee_pkt_hdr->addr1, pieee_pkt_hdr->addr2);
            break;
        case IEEE_MGMT_ACTION_CATEGORY_UNPROTECT_WNM:
            ret = wlan_process_mgmt_unprotect_wnm_action(payload, payload_len, rxpd);
            break;
        default:
            wifi_d("Action: Unknown request: %u", category);
            break;
    }
    return ret;
}
