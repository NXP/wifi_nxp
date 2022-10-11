/** @file mlan_11v.c
 *
 *  @brief  This file provides functions for process 11v(BTM) frames
 *
 *  Copyright 2022 NXP
 *
 *  Licensed under the LA_OPT_NXP_Software_License.txt (the "Agreement")
 *
 */

/********************************************************
Change log:
    08/11/2022: initial version
********************************************************/

#include <mlan_api.h>
#include "wifi-sdio.h"

#ifdef CONFIG_11V
#define BTM_RESP_BUF_SIZE 200
#define WLAN_FC_TYPE_MGMT 0

/********************************************************
                Local Variables
********************************************************/

/********************************************************
                Global Variables
********************************************************/

/********************************************************
                Local Functions
********************************************************/
static void wlan_wnm_parse_neighbor_report(t_u8 *pos, t_u8 len, struct wnm_neighbor_report *rep)
{
    t_u8 remain_len = 0;
    if (len < (t_u8)13U)
    {
        wifi_d("WNM: This neighbor report is too short");
    }

    (void)memcpy(rep->bssid, pos, MLAN_MAC_ADDR_LENGTH);
    rep->bssid_info = wlan_cpu_to_le32(*(t_u32 *)(void *)(pos + MLAN_MAC_ADDR_LENGTH));
    rep->reg_class  = *(pos + 10);
    rep->channel    = *(pos + 11);
    rep->PhyType    = *(pos + 12);
    pos += 13;
    remain_len = (t_u8)(len - (t_u8)13U);

    while (remain_len >= (t_u8)2U)
    {
        t_u8 e_id, e_len;

        e_id  = *pos++;
        e_len = *pos++;
        remain_len -= (t_u8)2U;
        if (e_len > remain_len)
        {
            wifi_d("WNM: neighbor report length not matched");
            break;
        }
        switch (e_id)
        {
            case MGMT_WNM_NEIGHBOR_BSS_TRANSITION_CANDIDATE:
                if (e_len < (t_u8)1U)
                {
                    break;
                }
                rep->prefer        = pos[0];
                rep->prefer_select = 1;
                break;
            default:
                (void)PRINTF("UNKNOWN nbor Report e id\r\n");
                break;
        }

        remain_len -= e_len;
        pos += e_len;
    }
}

static void wlan_send_mgmt_wnm_btm_resp(t_u8 dialog_token,
                                        enum wnm_btm_status_code status,
                                        t_u8 *dst_addr,
                                        t_u8 *src_addr,
                                        t_u8 *target_bssid,
                                        t_u8 *tag_nr,
                                        t_u8 tag_len,
                                        bool protect)
{
    wlan_mgmt_pkt *pmgmt_pkt_hdr    = MNULL;
    IEEEtypes_FrameCtl_t *mgmt_fc_p = MNULL;
    t_u8 *pos                       = MNULL;
    t_u16 pkt_len                   = 0;

    pmgmt_pkt_hdr = wifi_PrepDefaultMgtMsg(
        SUBTYPE_ACTION, (mlan_802_11_mac_addr *)(void *)dst_addr, (mlan_802_11_mac_addr *)(void *)src_addr,
        (mlan_802_11_mac_addr *)(void *)dst_addr, sizeof(wlan_mgmt_pkt) + (size_t)BTM_RESP_BUF_SIZE);
    if (pmgmt_pkt_hdr == MNULL)
    {
        wifi_d("No memory available for BTM resp");
        return;
    }

    mgmt_fc_p = (IEEEtypes_FrameCtl_t *)(void *)&pmgmt_pkt_hdr->wlan_header.frm_ctl;
    if (protect)
    {
        mgmt_fc_p->wep = 1;
    }

    /* 802.11 management body */
    pos    = (t_u8 *)pmgmt_pkt_hdr + sizeof(wlan_mgmt_pkt);
    pos[0] = (t_u8)IEEE_MGMT_ACTION_CATEGORY_WNM;
    pos[1] = (t_u8)IEEE_MGMT_WNM_BTM_RESPONSE;
    pos[2] = dialog_token;
    pos[3] = (t_u8)status;
    pos[4] = 0; /* delay */
    pos += 5;
    if (target_bssid != NULL)
    {
        (void)memcpy(&pos[5], target_bssid, MLAN_MAC_ADDR_LENGTH);
        pos += 6;
    }
    else if (status == WNM_BTM_ACCEPT)
    {
        (void)memcpy((void *)&pos[5], "\0\0\0\0\0\0", MLAN_MAC_ADDR_LENGTH);
        pos += 6;
    }
    else
    {
        /* Do nothing */
    }

    if (status == WNM_BTM_ACCEPT && tag_nr != NULL)
    {
        (void)memcpy(pos, tag_nr, tag_len);
        pos += tag_len;
    }
    pkt_len                = (t_u16)(pos - (t_u8 *)pmgmt_pkt_hdr);
    pmgmt_pkt_hdr->frm_len = (t_u16)((t_u16)pkt_len - sizeof(t_u16));
    (void)wifi_inject_frame(WLAN_BSS_TYPE_STA, (t_u8 *)pmgmt_pkt_hdr, pkt_len);
    os_mem_free(pmgmt_pkt_hdr);
}

/********************************************************
                Global functions
********************************************************/
/**
 *  @brief This function process BTM request frame
 *
 *  @param pos          BTM request frame head
 *  @param end          end of frame
 *  @param src_addr     source address
 *
 */
void wlan_process_mgmt_wnm_btm_req(t_u8 *pos, t_u8 *end, t_u8 *src_addr, t_u8 *dest_addr, bool protect)
{
    t_u8 dialog_token;
    t_u8 wnm_num_neighbor_report = 0, neighbor_index = 0;
    t_u8 btm_mode;
    t_u8 prefer_old = 0, prefer_select = 0;
    t_u8 *ptagnr   = NULL;
    t_u8 tagnr_len = 0;
    t_u8 *channels = (t_u8 *)os_mem_calloc((size_t)2U);

    if (channels == NULL)
    {
        return;
    }

    if (end - pos < 5)
    {
        return;
    }

    dialog_token = pos[0];
    btm_mode     = pos[1];
    pos += 5;

    if ((btm_mode & IEEE_WNM_BTM_REQUEST_BSS_TERMINATION_INCLUDED) != 0U)
    {
        pos += 12; /* BSS Termination Duration */
    }

    if ((btm_mode & IEEE_WNM_BTM_REQUEST_PREFERENCE_CAND_LIST_INCLUDED) != 0U)
    {
        struct wnm_neighbor_report *preport =
            os_mem_calloc((size_t)WLAN_WNM_MAX_NEIGHBOR_REPORT * sizeof(struct wnm_neighbor_report));
        if (preport == NULL)
        {
            wifi_e("No memory available for neighbor report.");
            return;
        }

        while (end - pos >= 2 && wnm_num_neighbor_report < (t_u8)WLAN_WNM_MAX_NEIGHBOR_REPORT)
        {
            t_u8 tag = *pos++;
            t_u8 len = *pos++;

            if ((int)len > (end - pos))
            {
                wifi_d("WNM: Truncated BTM request");
                os_mem_free(preport);
                return;
            }

            if (tag == (t_u8)NEIGHBOR_REPORT)
            {
                struct wnm_neighbor_report *rep;
                rep = &preport[wnm_num_neighbor_report];
                wlan_wnm_parse_neighbor_report(pos, len, rep);
                if (rep->prefer_select != (t_u8)0U && (rep->prefer > prefer_old))
                {
                    ptagnr         = pos - 2;
                    tagnr_len      = len + (t_u8)2U;
                    prefer_old     = (t_u8)rep->prefer;
                    prefer_select  = 1;
                    neighbor_index = wnm_num_neighbor_report;
                }
                wnm_num_neighbor_report++;
            }
            pos += len;
        }

        if (wnm_num_neighbor_report == (t_u8)0U || prefer_select == (t_u8)0U)
        {
            wlan_send_mgmt_wnm_btm_resp(dialog_token, WNM_BTM_REJECT_NO_SUITABLE_CANDIDATES, dest_addr, src_addr, NULL,
                                        ptagnr, tagnr_len, protect);
            os_mem_free(preport);
            return;
        }

        wlan_send_mgmt_wnm_btm_resp(dialog_token, WNM_BTM_ACCEPT, dest_addr, src_addr, preport[neighbor_index].bssid,
                                    ptagnr, tagnr_len, protect);

        /* disconnect and re-assocate with AP2 */
        // ssid_bssid.specific_channel = preport[neighbor_index].channel;
        channels[0] = btm_mode;
        channels[1] = 1;
        channels[2] = preport[neighbor_index].channel;
        if (wifi_event_completion(WIFI_EVENT_NLIST_REPORT, WIFI_EVENT_REASON_SUCCESS, (void *)channels) != WM_SUCCESS)
        {
            /* If fail to send message on queue, free allocated memory ! */
            os_mem_free((void *)channels);
        }
        os_mem_free(preport);
    }
    else
    {
        enum wnm_btm_status_code status;
        if ((btm_mode & IEEE_WNM_BTM_REQUEST_ESS_DISASSOC_IMMINENT) != 0U)
        {
            status = WNM_BTM_ACCEPT;
        }
        else
        {
            status = WNM_BTM_REJECT_UNSPECIFIED;
        }

        wlan_send_mgmt_wnm_btm_resp(dialog_token, status, dest_addr, src_addr, NULL, ptagnr, tagnr_len, protect);
    }
}
#endif /* CONFIG_11V */
