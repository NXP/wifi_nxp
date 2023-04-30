/** @file mlan_scan.c
 *
 *  @brief  This file provides wlan scan IOCTL and firmware command APIs
 *
 *  Copyright 2008-2023 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 *
 */

/******************************************************
Change log:
    10/28/2008: initial version
******************************************************/
#include <mlan_api.h>

/* Additional WMSDK header files */
#include <wmerrno.h>
#include <wm_os.h>

/* Always keep this include at the end of all include files */
#include <mlan_remap_mem_operations.h>
/********************************************************
                Local Constants
********************************************************/

int get_split_scan_delay_ms(void);

/** The maximum number of channels the firmware can scan per command */
#define MRVDRV_MAX_CHANNELS_PER_SPECIFIC_SCAN 3

/**
 * Number of channels to scan per firmware scan command issuance.
 *
 * Number restricted to prevent hitting the limit on the amount of scan data
 * returned in a single firmware scan command.
 */
#define MRVDRV_CHANNELS_PER_SCAN_CMD 4

/** Memory needed to store a max sized Channel List TLV for a firmware scan */
#define CHAN_TLV_MAX_SIZE \
    (sizeof(MrvlIEtypesHeader_t) + (MRVDRV_MAX_CHANNELS_PER_SPECIFIC_SCAN * sizeof(ChanScanParamSet_t)))

/** Memory needed to store supported rate */
#define RATE_TLV_MAX_SIZE (sizeof(MrvlIEtypes_RatesParamSet_t) + HOSTCMD_SUPPORTED_RATES)

/** Memory needed to store a max number/size WildCard SSID TLV for a firmware scan */
#define WILDCARD_SSID_TLV_MAX_SIZE \
    (MRVDRV_MAX_SSID_LIST_LENGTH * (sizeof(MrvlIEtypes_WildCardSsIdParamSet_t) + MRVDRV_MAX_SSID_LENGTH))

/** WPS TLV MAX size is MAX IE size plus 2 bytes for t_u16 MRVL TLV extension */
#define WPS_TLV_MAX_SIZE (sizeof(IEEEtypes_VendorSpecific_t) + 2)
/** Maximum memory needed for a wlan_scan_cmd_config with all TLVs at max */
#define MAX_SCAN_CFG_ALLOC                                                                          \
    (sizeof(wlan_scan_cmd_config) + sizeof(MrvlIEtypes_NumProbes_t) + sizeof(MrvlIETypes_HTCap_t) + \
     CHAN_TLV_MAX_SIZE + RATE_TLV_MAX_SIZE + WILDCARD_SSID_TLV_MAX_SIZE + WPS_TLV_MAX_SIZE)

/********************************************************
                Local Variables
********************************************************/

/* Global data required for split scan requests */
static bool abort_split_scan;

/**
 * Interally used to send a configured scan cmd between driver routines
 */
typedef union
{
    /** Scan configuration (variable length) */
    wlan_scan_cmd_config config;
    /** Max allocated block */
    t_u8 config_alloc_buf[MAX_SCAN_CFG_ALLOC];
} wlan_scan_cmd_config_tlv;

/********************************************************
                Global Variables
********************************************************/
bool split_scan_in_progress;

/********************************************************
                Local Functions
********************************************************/
/** Cipher suite definition */
typedef enum cipher_suite
{
    CIPHER_SUITE_TKIP,
    CIPHER_SUITE_CCMP,
    CIPHER_SUITE_MAX
} cipher_suite;

static t_u8 wpa_oui[CIPHER_SUITE_MAX][4] = {
    {0x00, 0x50, 0xf2, 0x02}, /* TKIP */
    {0x00, 0x50, 0xf2, 0x04}, /* AES */
};

static t_u8 rsn_oui[CIPHER_SUITE_MAX][4] = {
    {0x00, 0x0f, 0xac, 0x02}, /* TKIP */
    {0x00, 0x0f, 0xac, 0x04}, /* AES */
};

static t_u32 wlan_find_worst_network_in_list(const BSSDescriptor_t *pbss_desc, t_u32 num_entries);

bool is_split_scan_complete(void)
{
    return (split_scan_in_progress == false);
}

/*
 * wmsdk: Split scan needs to be aborted at times by the application. This
 * API will help the caller do that.
 */
void wlan_abort_split_scan(void)
{
    if (split_scan_in_progress)
    {
        abort_split_scan = true;
    }
#ifdef CONFIG_WPA_SUPP
    else
    {
        (void)wifi_event_completion(WIFI_EVENT_SCAN_RESULT, WIFI_EVENT_REASON_ABORT, NULL);
    }
#endif
}

/**
 *  @brief This function will parse a given IE for a given OUI
 *
 *  Parse a given WPA/RSN IE to find if it has a given oui in PTK,
 *  if no OUI found for PTK it returns 0.
 *
 *  @param pbss_desc       A pointer to current BSS descriptor
 *  @return                0 on failure to find OUI, 1 on success.
 */
static t_u8 search_oui_in_ie(mlan_adapter *pmadapter, IEBody *ie_body, t_u8 *oui)
{
    t_u8 count;

    count = ie_body->PtkCnt[0];

    ENTER();
    /* There could be multiple OUIs for PTK hence 1) Take the length. 2) Check
       all the OUIs for AES. 3) If one of them is AES then pass success. */
    while (count != 0U)
    {
        if (!__memcmp(pmadapter, ie_body->PtkBody, oui, sizeof(ie_body->PtkBody)))
        {
            LEAVE();
            return MLAN_OUI_PRESENT;
        }

        --count;
        if (count != 0U)
        {
            ie_body = (IEBody *)(void *)((t_u8 *)ie_body + sizeof(ie_body->PtkBody));
        }
    }

    PRINTM(MINFO, "The OUI %x:%x:%x:%x is not found in PTK \n", oui[0], oui[1], oui[2], oui[3]);
    LEAVE();
    return MLAN_OUI_NOT_PRESENT;
}

/**
 *  @brief This function will pass the correct ie and oui to search_oui_in_ie
 *
 *  Check the pbss_desc for appropriate IE and then check if RSN IE has AES
 *  OUI in it. If RSN IE does not have AES in PTK then return 0;
 *
 *  @param pbss_desc       A pointer to current BSS descriptor
 *  @return                0 on failure to find AES OUI, 1 on success.
 */
static t_u8 is_rsn_oui_present(mlan_adapter *pmadapter, BSSDescriptor_t *pbss_desc, cipher_suite cipher)
{
    t_u8 *oui       = MNULL;
    IEBody *ie_body = MNULL;
    t_u8 ret        = MLAN_OUI_NOT_PRESENT;

    ENTER();
    if (((pbss_desc->prsn_ie != MNULL) && ((*(pbss_desc->prsn_ie)).ieee_hdr.element_id == RSN_IE)))
    {
        ie_body = (IEBody *)(void *)(((t_u8 *)pbss_desc->prsn_ie->data) + RSN_GTK_OUI_OFFSET);
        oui     = &rsn_oui[cipher][0];
        if ((ret = search_oui_in_ie(pmadapter, ie_body, oui)) != 0U)
        {
            LEAVE();
            return ret;
        }
    }
    LEAVE();
    return ret;
}

/**
 *  @brief This function will pass the correct ie and oui to search_oui_in_ie
 *
 *  Check the pbss_desc for appropriate IE and then check if WPA IE has AES
 *  OUI in it. If WPA IE does not have AES in PTK then return 0;
 *
 *  @param pbss_desc       A pointer to current BSS descriptor
 *  @return                0 on failure to find AES OUI, 1 on success.
 */
static t_u8 is_wpa_oui_present(mlan_adapter *pmadapter, BSSDescriptor_t *pbss_desc, cipher_suite cipher)
{
    t_u8 *oui       = MNULL;
    IEBody *ie_body = MNULL;
    t_u8 ret        = MLAN_OUI_NOT_PRESENT;

    ENTER();
    if (((pbss_desc->pwpa_ie != MNULL) && ((*(pbss_desc->pwpa_ie)).vend_hdr.element_id == WPA_IE)))
    {
        ie_body = (IEBody *)(void *)pbss_desc->pwpa_ie->data;
        oui     = &wpa_oui[(int)cipher][0];
        if ((ret = search_oui_in_ie(pmadapter, ie_body, oui)) != 0U)
        {
            LEAVE();
            return ret;
        }
    }
    LEAVE();
    return ret;
}

/**
 *  @brief Convert radio type scan parameter to a band config used in join cmd
 *
 *  @param radio_type Scan parameter indicating the radio used for a channel
 *                    in a scan command.
 *
 *  @return          Band type conversion of scanBand used in join/assoc cmds
 *
 */
static t_u16 radio_type_to_band(t_u8 radio_type)
{
    t_u16 ret_band;

    switch (radio_type)
    {
        case HostCmd_SCAN_RADIO_TYPE_A:
            ret_band = BAND_A;
            break;
        case HostCmd_SCAN_RADIO_TYPE_BG:
        default:
            ret_band = BAND_G;
            break;
    }

    return ret_band;
}

#ifdef SCAN_CHANNEL_GAP
/**
 *  @brief This function will update the channel statistics from scan result
 *
 *  @param pmpriv           A pointer to mlan_private structure
 *  @param pchanstats_tlv   A pointer to MrvlIEtypes_ChannelStats_t tlv
 *
 *  @return                NA
 */
static void wlan_update_chan_statistics(mlan_private *pmpriv, MrvlIEtypes_ChannelStats_t *pchanstats_tlv)
{
    mlan_adapter *pmadapter = pmpriv->adapter;
    t_u8 i;
    chan_statistics_t *pchan_stats = (chan_statistics_t *)((t_u8 *)pchanstats_tlv + sizeof(MrvlIEtypesHeader_t));
    t_u8 num_chan                  = wlan_le16_to_cpu(pchanstats_tlv->header.len) / sizeof(chan_statistics_t);

    ENTER();

    for (i = 0; i < num_chan; i++)
    {
        if (pchan_stats->chan_num == 0U)
        {
            break;
        }

        if (pmadapter->idx_chan_stats >= pmadapter->num_in_chan_stats)
        {
            wifi_d("Over flow: idx_chan_stats=%d, num_in_chan_stats=%d", pmadapter->idx_chan_stats,
                   pmadapter->num_in_chan_stats);
            break;
        }
        pchan_stats->total_networks    = wlan_le16_to_cpu(pchan_stats->total_networks);
        pchan_stats->cca_scan_duration = wlan_le16_to_cpu(pchan_stats->cca_scan_duration);
        pchan_stats->cca_busy_duration = wlan_le16_to_cpu(pchan_stats->cca_busy_duration);
        wifi_d("chan=%d, noise=%d, total_network=%d scan_duration=%d, busy_duration=%d", pchan_stats->chan_num,
               pchan_stats->noise, pchan_stats->total_networks, pchan_stats->cca_scan_duration,
               pchan_stats->cca_busy_duration);
        __memcpy(pmadapter, (chan_statistics_t *)&pmadapter->pchan_stats[pmadapter->idx_chan_stats], pchan_stats,
                 sizeof(chan_statistics_t));
        pmadapter->idx_chan_stats++;
        pchan_stats++;
    }
    LEAVE();
    return;
}
#endif

/**
 *  @brief compare config band and a band from the scan result,
 *  which is defined by functiion radio_type_to_band(t_u8 radio_type) above
 *
 *  @param cfg_band:  band configured
 *         scan_band: band from scan result
 *
 *  @return  matched: non-zero. unmatched: 0
 *
 */
static t_u8 wlan_is_band_compatible(t_u16 cfg_band, t_u16 scan_band)
{
    t_u16 band;
    switch (scan_band)
    {
        case BAND_A:
            band = (BAND_A | BAND_AN | BAND_AAC);
            break;
        case BAND_G:
        default:
            band = (BAND_B | BAND_G | BAND_GN | BAND_GAC);
            break;
    }
    return (cfg_band & band);
}

#ifndef CONFIG_MLAN_WMSDK
/**
 *  @brief This function finds the best SSID in the Scan List
 *
 *  Search the scan table for the best SSID that also matches the current
 *   adapter network preference (infrastructure or adhoc)
 *
 *  @param pmpriv       A pointer to mlan_private structure
 *  @return             index in BSSID list
 */
static t_s32 wlan_find_best_network_in_list(IN mlan_private *pmpriv)
{
    mlan_adapter *pmadapter = pmpriv->adapter;
    t_u32 mode              = pmpriv->bss_mode;
    t_s32 best_net          = -1;
    t_s32 best_rssi         = 0;
    t_u32 i;

    ENTER();

    PRINTM(MINFO, "Num of BSSIDs = %d\n", pmadapter->num_in_scan_table);

    for (i = 0; i < pmadapter->num_in_scan_table; i++)
    {
        switch (mode)
        {
            case MLAN_BSS_MODE_INFRA:
            case MLAN_BSS_MODE_IBSS:
                if (wlan_is_network_compatible(pmpriv, i, mode) >= 0)
                {
                    if (SCAN_RSSI(pmadapter->pscan_table[i].rssi) > best_rssi)
                    {
                        best_rssi = SCAN_RSSI(pmadapter->pscan_table[i].rssi);
                        best_net  = i;
                    }
                }
                break;
            case MLAN_BSS_MODE_AUTO:
            default:
                if (SCAN_RSSI(pmadapter->pscan_table[i].rssi) > best_rssi)
                {
                    best_rssi = SCAN_RSSI(pmadapter->pscan_table[i].rssi);
                    best_net  = i;
                }
                break;
        }
    }

    LEAVE();
    return best_net;
}
#endif

/**
 *  @brief Create a channel list for the driver to scan based on region info
 *
 *  Use the driver region/band information to construct a comprehensive list
 *    of channels to scan.  This routine is used for any scan that is not
 *    provided a specific channel list to scan.
 *
 *  @param pmpriv           A pointer to mlan_private structure
 *  @param puser_scan_in    MNULL or pointer to scan configuration parameters
 *  @param pscan_chan_list  Output parameter: Resulting channel list to scan
 *  @param filtered_scan    Flag indicating whether or not a BSSID or SSID filter
 *                          is being sent in the command to firmware.  Used to
 *                          increase the number of channels sent in a scan
 *                          command and to disable the firmware channel scan
 *                          filter.
 *
 *  @return                 N/A
 */
static t_void wlan_scan_create_channel_list(IN mlan_private *pmpriv,
                                            IN const wlan_user_scan_cfg *puser_scan_in,
                                            OUT ChanScanParamSet_t *pscan_chan_list,
                                            IN t_u8 filtered_scan)
{
    mlan_adapter *pmadapter = pmpriv->adapter;
    region_chan_t *pscan_region;
    const chan_freq_power_t *cfp;
    t_u32 region_idx;
    t_u32 chan_idx = 0;
    t_u32 next_chan;
    mlan_scan_type scan_type;
    t_u8 radio_type;

    ENTER();

    for (region_idx = 0; region_idx < NELEMENTS(pmadapter->region_channel); region_idx++)
    {
        if (wlan_11d_support_is_enabled(pmpriv) && wlan_11d_is_enabled(pmpriv) && pmpriv->media_connected != MTRUE)
        {
            /* Scan all the supported chan for the first scan */
            if (!pmadapter->universal_channel[region_idx].valid)
            {
                continue;
            }
            pscan_region = &pmadapter->universal_channel[region_idx];
        }
        else
        {
            if (!pmadapter->region_channel[region_idx].valid)
            {
                continue;
            }
            pscan_region = &pmadapter->region_channel[region_idx];
        }

        if ((puser_scan_in != MNULL) && !puser_scan_in->chan_list[0].chan_number &&
            puser_scan_in->chan_list[0].radio_type & BAND_SPECIFIED)
        {
            radio_type = (t_u8)(puser_scan_in->chan_list[0].radio_type & ~BAND_SPECIFIED);
            if (!radio_type && (pscan_region->band != BAND_B) && (pscan_region->band != BAND_G))
            {
                continue;
            }
            if (radio_type && (pscan_region->band != BAND_A))
            {
                continue;
            }
        }
        if (!wlan_is_band_compatible(pmpriv->config_bands, pscan_region->band))
        {
            continue;
        }
        for (next_chan = 0; next_chan < pscan_region->num_cfp; next_chan++)
        {
            /* Set the default scan type to the user specified type, will later
               be changed to passive on a per channel basis if restricted by
               regulatory requirements (11d or 11h) */
            scan_type = pmadapter->scan_type;
            cfp       = pscan_region->pcfp + next_chan;
            if ((cfp->dynamic.flags & NXP_CHANNEL_DISABLED) != 0U)
            {
                continue;
            }

            if (scan_type == MLAN_SCAN_TYPE_ACTIVE && wlan_11d_support_is_enabled(pmpriv))
            {
                scan_type = wlan_11d_get_scan_type(pmpriv, pscan_region->band, (t_u8)cfp->channel,
                                                   &pmadapter->parsed_region_chan);
            }

            switch (pscan_region->band)
            {
#ifdef CONFIG_5GHz_SUPPORT
                case BAND_A:
                    pscan_chan_list[chan_idx].radio_type = HostCmd_SCAN_RADIO_TYPE_A;
                    /* 11D not available... play it safe on DFS channels */
                    if (wlan_11h_radar_detect_required(pmpriv, (t_u8)cfp->channel))
                    {
                        scan_type = MLAN_SCAN_TYPE_PASSIVE;
                    }
                    break;
#endif
                case BAND_B:
                case BAND_G:
                    if (wlan_bg_scan_type_is_passive(pmpriv, (t_u8)cfp->channel))
                    {
                        scan_type = MLAN_SCAN_TYPE_PASSIVE;
                    }
                    pscan_chan_list[chan_idx].radio_type = HostCmd_SCAN_RADIO_TYPE_BG;
                    break;
                default:
                    pscan_chan_list[chan_idx].radio_type = HostCmd_SCAN_RADIO_TYPE_BG;
                    break;
            }

            if ((puser_scan_in != MNULL) && puser_scan_in->chan_list[0].scan_time)
            {
                pscan_chan_list[chan_idx].max_scan_time =
                    wlan_cpu_to_le16((t_u16)puser_scan_in->chan_list[0].scan_time);
            }
            else if (scan_type == MLAN_SCAN_TYPE_PASSIVE)
            {
                pscan_chan_list[chan_idx].max_scan_time = wlan_cpu_to_le16(pmadapter->passive_scan_time);
            }
            else if (filtered_scan != 0U)
            {
                pscan_chan_list[chan_idx].max_scan_time = wlan_cpu_to_le16(pmadapter->specific_scan_time);
            }
            else
            {
                pscan_chan_list[chan_idx].max_scan_time = wlan_cpu_to_le16(pmadapter->active_scan_time);
            }

            if (scan_type == MLAN_SCAN_TYPE_PASSIVE)
            {
                pscan_chan_list[chan_idx].chan_scan_mode.passive_scan       = MTRUE;
                pscan_chan_list[chan_idx].chan_scan_mode.hidden_ssid_report = MTRUE;
            }
            else
            {
                pscan_chan_list[chan_idx].chan_scan_mode.passive_scan = MFALSE;
            }

            pscan_chan_list[chan_idx].chan_number = (t_u8)cfp->channel;

            wscan_d("Channel: %d Type: %s %d", cfp->channel, scan_type == MLAN_SCAN_TYPE_PASSIVE ? "Passive" : "Active",
                    cfp->max_tx_power);
            chan_idx++;

            if (filtered_scan != 0U)
            {
                pscan_chan_list[chan_idx].chan_scan_mode.disable_chan_filt = MTRUE;
            }
        }
    }

    LEAVE();
}

#ifndef CONFIG_MLAN_WMSDK
/**
 *  @brief Add WPS IE to probe request frame
 *
 *  @param pmpriv             A pointer to mlan_private structure
 *  @param pptlv_out          A pointer to TLV to fill in
 *
 *  @return                   N/A
 */
static void wlan_add_wps_probe_request_ie(IN mlan_private *pmpriv, OUT t_u8 **pptlv_out)
{
    MrvlIEtypesHeader_t *tlv;

    ENTER();

    if (pmpriv->wps.wps_ie.vend_hdr.len)
    {
        tlv       = (MrvlIEtypesHeader_t *)*pptlv_out;
        tlv->type = wlan_cpu_to_le16(VENDOR_SPECIFIC_221);
        tlv->len  = wlan_cpu_to_le16(pmpriv->wps.wps_ie.vend_hdr.len);
        *pptlv_out += sizeof(MrvlIEtypesHeader_t);
        (void)__memcpy(pmpriv->adapter, *pptlv_out, pmpriv->wps.wps_ie.vend_hdr.oui, pmpriv->wps.wps_ie.vend_hdr.len);
        *pptlv_out += (pmpriv->wps.wps_ie.vend_hdr.len + sizeof(MrvlIEtypesHeader_t));
    }
    LEAVE();
}
#endif /* CONFIG_MLAN_WMSDK */

/**
 *  @brief Construct and send multiple scan config commands to the firmware
 *
 *  Previous routines have created a wlan_scan_cmd_config with any requested
 *   TLVs.  This function splits the channel TLV into max_chan_per_scan lists
 *   and sends the portion of the channel TLV along with the other TLVs
 *   to the wlan_cmd routines for execution in the firmware.
 *
 *  @param pmpriv             A pointer to mlan_private structure
 *  @param pioctl_buf         A pointer to MLAN IOCTL Request buffer
 *  @param max_chan_per_scan  Maximum number channels to be included in each
 *                            scan command sent to firmware
 *  @param filtered_scan      Flag indicating whether or not a BSSID or SSID
 *                            filter is being used for the firmware command
 *                            scan command sent to firmware
 *  @param pscan_cfg_out      Scan configuration used for this scan.
 *  @param pchan_tlv_out      Pointer in the pscan_cfg_out where the channel TLV
 *                            should start.  This is past any other TLVs that
 *                            must be sent down in each firmware command.
 *  @param pscan_chan_list    List of channels to scan in max_chan_per_scan segments
 *
 *  @return                   MLAN_STATUS_SUCCESS or error return otherwise
 */
static mlan_status wlan_scan_channel_list(IN mlan_private *pmpriv,
                                          IN t_void *pioctl_buf,
                                          IN t_u32 max_chan_per_scan,
                                          IN t_u8 filtered_scan,
                                          OUT wlan_scan_cmd_config *pscan_cfg_out,
                                          OUT MrvlIEtypes_ChanListParamSet_t *pchan_tlv_out,
                                          IN ChanScanParamSet_t *pscan_chan_list)
{
    mlan_status ret         = MLAN_STATUS_SUCCESS;
    mlan_adapter *pmadapter = pmpriv->adapter;
    MrvlIEtypes_ChanListParamSet_t *pchan_tlv_out_temp;
    ChanScanParamSet_t *ptmp_chan_list;
    ChanScanParamSet_t *pstart_chan;
    pmlan_ioctl_req pioctl_req = (mlan_ioctl_req *)pioctl_buf;

    t_u32 tlv_idx;
    t_u32 total_scan_time;
    t_u32 done_early;
    t_u32 cmd_no;

    ENTER();

    if ((pscan_cfg_out == MNULL) || (pchan_tlv_out == MNULL) || (pscan_chan_list == MNULL))
    {
        PRINTM(MINFO, "Scan: Null detect: %p, %p, %p\n", pscan_cfg_out, pchan_tlv_out, pscan_chan_list);
        if (pioctl_req != MNULL)
        {
            pioctl_req->status_code = MLAN_ERROR_CMD_SCAN_FAIL;
        }
        LEAVE();
        return MLAN_STATUS_FAILURE;
    }
    if (!pscan_chan_list->chan_number)
    {
        PRINTM(MERROR, "Scan: No channel configured\n");
        if (pioctl_req != MNULL)
        {
            pioctl_req->status_code = MLAN_ERROR_CMD_SCAN_FAIL;
        }
        LEAVE();
        return MLAN_STATUS_FAILURE;
    }

    pchan_tlv_out->header.type = wlan_cpu_to_le16(TLV_TYPE_CHANLIST);

    pchan_tlv_out_temp = pchan_tlv_out;

    /* Set the temp channel struct pointer to the start of the desired list */
    ptmp_chan_list = pscan_chan_list;

    /* Loop through the desired channel list, sending a new firmware scan
       commands for each max_chan_per_scan channels (or for 1,6,11 individually
       if configured accordingly) */
    while (ptmp_chan_list->chan_number != 0U)
    {
        tlv_idx                   = 0;
        total_scan_time           = 0;
        pchan_tlv_out->header.len = 0;
        pstart_chan               = ptmp_chan_list;
        done_early                = MFALSE;

        t_u8 *ptlv_pos = (t_u8 *)pchan_tlv_out_temp;
        MrvlIEtypes_RatesParamSet_t *prates_tlv;
        t_u16 config_bands;
        WLAN_802_11_RATES rates;
        t_u32 rates_size;

        config_bands = pmpriv->config_bands;
        if (pstart_chan->chan_number > MAX_CHANNELS_BG)
        {
            config_bands &= ~(BAND_B
#ifdef CONFIG_11AC
                              | BAND_GAC
#endif
#ifdef CONFIG_11AX
                              | BAND_GAX
#endif
            );
        }

        config_bands = (pmpriv->bss_mode == MLAN_BSS_MODE_INFRA) ? config_bands : pmadapter->adhoc_start_band;

        /* Append rates tlv */
        (void)__memset(pmadapter, rates, 0, sizeof(rates));
        rates_size              = wlan_get_supported_rates(pmpriv, pmpriv->bss_mode, config_bands, rates);
        prates_tlv              = (MrvlIEtypes_RatesParamSet_t *)ptlv_pos;
        prates_tlv->header.type = wlan_cpu_to_le16(TLV_TYPE_RATES);
        prates_tlv->header.len  = wlan_cpu_to_le16((t_u16)rates_size);
        (void)__memcpy(pmadapter, prates_tlv->rates, rates, rates_size);
        ptlv_pos += sizeof(prates_tlv->header) + rates_size;

        PRINTM(MINFO, "SCAN_CMD: Rates size = %d\n", rates_size);

        pchan_tlv_out              = (MrvlIEtypes_ChanListParamSet_t *)ptlv_pos;
        pchan_tlv_out->header.type = wlan_cpu_to_le16(TLV_TYPE_CHANLIST);
        pchan_tlv_out->header.len  = 0;

        /*
         * Construct the Channel TLV for the scan command.  Continue to
         * insert channel TLVs until:
         *   - the tlv_idx hits the maximum configured per scan command
         *   - the next channel to insert is 0 (end of desired channel list)
         *   - done_early is set (controlling individual scanning of 1,6,11)
         */
        while (tlv_idx < max_chan_per_scan && ptmp_chan_list->chan_number && !done_early)
        {
            wscan_d("Scan: Chan(%3d), Radio(%d), Mode(%d,%d), Dur(%d)", ptmp_chan_list->chan_number,
                    ptmp_chan_list->radio_type, ptmp_chan_list->chan_scan_mode.passive_scan,
                    ptmp_chan_list->chan_scan_mode.disable_chan_filt, wlan_le16_to_cpu(ptmp_chan_list->max_scan_time));

            /* Copy the current channel TLV to the command being prepared */
            (void)__memcpy(pmadapter, pchan_tlv_out->chan_scan_param + tlv_idx, ptmp_chan_list,
                           sizeof(pchan_tlv_out->chan_scan_param));

            /* Increment the TLV header length by the size appended */
            pchan_tlv_out->header.len += (t_u16)sizeof(pchan_tlv_out->chan_scan_param);

            /*
             * The tlv buffer length is set to the number of bytes of the
             *   between the channel tlv pointer and the start of the
             *   tlv buffer.  This compensates for any TLVs that were appended
             *   before the channel list.
             */
            pscan_cfg_out->tlv_buf_len = (t_u32)((t_u8 *)pchan_tlv_out - pscan_cfg_out->tlv_buf);

            /* Add the size of the channel tlv header and the data length */
            pscan_cfg_out->tlv_buf_len += (sizeof(pchan_tlv_out->header) + pchan_tlv_out->header.len);

            /* Increment the index to the channel tlv we are constructing */
            tlv_idx++;

            /* Count the total scan time per command */
            total_scan_time += wlan_le16_to_cpu(ptmp_chan_list->max_scan_time);

            done_early = MFALSE;

            /* Stop the loop if the *current* channel is in the 1,6,11 set and
               we are not filtering on a BSSID or SSID. */
            if (!filtered_scan && (ptmp_chan_list->chan_number == 1U || ptmp_chan_list->chan_number == 6U ||
                                   ptmp_chan_list->chan_number == 11U))
            {
                done_early = MTRUE;
            }

            /* Increment the tmp pointer to the next channel to be scanned */
            ptmp_chan_list++;

            /* Stop the loop if the *next* channel is in the 1,6,11 set.  This
               will cause it to be the only channel scanned on the next
               interation */
            if (!filtered_scan && (ptmp_chan_list->chan_number == 1U || ptmp_chan_list->chan_number == 6U ||
                                   ptmp_chan_list->chan_number == 11U))
            {
                done_early = MTRUE;
            }
        }

        /* The total scan time should be less than scan command timeout value */
        if (total_scan_time > MRVDRV_MAX_TOTAL_SCAN_TIME)
        {
            wscan_d("Total scan time %d ms is over limit (%d ms), scan skipped", total_scan_time,
                    MRVDRV_MAX_TOTAL_SCAN_TIME);
            if (pioctl_req != MNULL)
            {
                pioctl_req->status_code = MLAN_ERROR_CMD_SCAN_FAIL;
            }
            ret = MLAN_STATUS_FAILURE;
            break;
        }

        pchan_tlv_out->header.len = wlan_cpu_to_le16(pchan_tlv_out->header.len);

        pmadapter->pscan_channels = pstart_chan;

        /* Do sleep confirm handshake if received sleep event.
         * Fw will delay all events if handshake is not done
         * yet after ps sleep event.
         */
        if (mlan_adap->ps_state == PS_STATE_PRE_SLEEP && split_scan_in_progress)
        {
            send_sleep_confirm_command((mlan_bss_type)WLAN_BSS_TYPE_STA);
        }

        if (!ptmp_chan_list->chan_number)
        {
            /* wmsdk: Once we set this the response handling code can
               send event to the WLC manager. Since the event is send
               only after command response we can be sure that there
               is no race condition */
            // split_scan_in_progress = false;
        }

        /* Send the scan command to the firmware with the specified cfg */
#ifdef CONFIG_EXT_SCAN_SUPPORT
        if (pmadapter->ext_scan)
        {
            cmd_no = HostCmd_CMD_802_11_SCAN_EXT;
        }
        else
#endif
        {
            cmd_no = HostCmd_CMD_802_11_SCAN;
        }
        ret = wlan_prepare_cmd(pmpriv, (t_u16)cmd_no, HostCmd_ACT_GEN_SET, 0, pioctl_buf, pscan_cfg_out);
        if (ret != MLAN_STATUS_SUCCESS)
        {
            break;
        }

        /* This delay helps the UAP send beacons and avoids clients from
           disconnecting from the UAP. Issue was observed on Windows */
        /* fixme: Should this delay be conditional on UAP active? */
        os_thread_sleep(os_msec_to_ticks((uint32_t)get_split_scan_delay_ms()));
        if (abort_split_scan)
        {
            abort_split_scan       = false;
            split_scan_in_progress = false;
#ifdef CONFIG_WPA_SUPP
            pmadapter->num_in_scan_table = 0;
            ret                          = MLAN_STATUS_FAILURE;
#endif
            break;
        }
    }

    LEAVE();

    if (ret != MLAN_STATUS_SUCCESS)
    {
        return MLAN_STATUS_FAILURE;
    }

    return MLAN_STATUS_SUCCESS;
}

/**
 *  @brief Construct a wlan_scan_cmd_config structure to use in scan commands
 *
 *  Application layer or other functions can invoke wlan_scan_networks
 *    with a scan configuration supplied in a wlan_ioctl_user_scan_cfg struct.
 *    This structure is used as the basis of one or many wlan_scan_cmd_config
 *    commands that are sent to the command processing module and sent to
 *    firmware.
 *
 *  Create a wlan_scan_cmd_config based on the following user supplied
 *    parameters (if present):
 *             - SSID filter
 *             - BSSID filter
 *             - Number of Probes to be sent
 *             - Channel list
 *
 *  If the SSID or BSSID filter is not present, disable/clear the filter.
 *  If the number of probes is not set, use the adapter default setting
 *  Qualify the channel
 *
 *  @param pmpriv              A pointer to mlan_private structure
 *  @param puser_scan_in       MNULL or pointer to scan config parameters
 *  @param pscan_cfg_out       Output parameter: Resulting scan configuration
 *  @param ppchan_list_out     Output parameter: Pointer to the start of the
 *                             channel TLV portion of the output scan config
 *  @param pscan_chan_list     Output parameter: Pointer to the resulting
 *                             channel list to scan
 *  @param pmax_chan_per_scan  Output parameter: Number of channels to scan for
 *                             each issuance of the firmware scan command
 *  @param pfiltered_scan      Output parameter: Flag indicating whether or not
 *                             a BSSID or SSID filter is being sent in the
 *                             command to firmware. Used to increase the number
 *                             of channels sent in a scan command and to
 *                             disable the firmware channel scan filter.
 *  @param pscan_current_only  Output parameter: Flag indicating whether or not
 *                             we are only scanning our current active channel
 *
 *  @return                 MLAN_STATUS_SUCCESS or MLAN_STATUS_FAILURE
 */
static mlan_status wlan_scan_setup_scan_config(IN mlan_private *pmpriv,
                                               IN const wlan_user_scan_cfg *puser_scan_in,
                                               OUT wlan_scan_cmd_config *pscan_cfg_out,
                                               OUT MrvlIEtypes_ChanListParamSet_t **ppchan_list_out,
                                               OUT ChanScanParamSet_t *pscan_chan_list,
                                               OUT t_u8 *pmax_chan_per_scan,
                                               OUT t_u8 *pfiltered_scan,
                                               OUT t_u8 *pscan_current_only)
{
    mlan_adapter *pmadapter = pmpriv->adapter;
    mlan_status ret         = MLAN_STATUS_SUCCESS;
    MrvlIEtypes_NumProbes_t *pnum_probes_tlv;
    MrvlIEtypes_WildCardSsIdParamSet_t *pwildcard_ssid_tlv;
#ifdef CONFIG_EXT_SCAN_SUPPORT
    MrvlIEtypes_Bssid_List_t *pbssid_tlv;
#endif
#ifdef CONFIG_SCAN_WITH_RSSIFILTER
    MrvlIEtypes_RssiThresholdParamSet_t *prssi_threshold_tlv;
#endif
    const t_u8 zero_mac[MLAN_MAC_ADDR_LENGTH] = {0, 0, 0, 0, 0, 0};
    t_u8 *ptlv_pos;
    t_u32 num_probes;
    t_u32 ssid_len;
    t_u32 chan_idx;
    mlan_scan_type scan_type;
    t_u16 scan_dur;
    t_u8 channel;
    t_u8 radio_type;
    t_u32 ssid_idx;
    t_u8 ssid_filter;
#ifdef CONFIG_SCAN_WITH_RSSIFILTER
    t_u8 rssi_threshold_enable;
    t_s16 rssi_threshold;
#endif
    MrvlIETypes_HTCap_t *pht_cap;
    MrvlIETypes_VHTCap_t *pvht_cap;
#ifdef CONFIG_11AX
    MrvlIEtypes_Extension_t *phe_cap;
    t_u16 len = 0;
#endif
#ifdef SCAN_CHANNEL_GAP
    MrvlIEtypes_ScanChanGap_t *pscan_gap_tlv;
#endif
    ENTER();

    pmpriv->ssid_filter = MFALSE;
    /* The tlv_buf_len is calculated for each scan command.  The TLVs added in
       this routine will be preserved since the routine that sends the command
       will append channelTLVs at *ppchan_list_out.  The difference between the
       *ppchan_list_out and the tlv_buf start will be used to calculate the
       size of anything we add in this routine. */
    pscan_cfg_out->tlv_buf_len = 0;

    /* Running tlv pointer.  Assigned to ppchan_list_out at end of function so
       later routines know where channels can be added to the command buf */
    ptlv_pos = pscan_cfg_out->tlv_buf;

    /* Initialize the scan as un-filtered; the flag is later set to TRUE below
       if a SSID or BSSID filter is sent in the command */
    *pfiltered_scan = MFALSE;

    /* Initialize the scan as not being only on the current channel.  If the
       channel list is customized, only contains one channel, and is the active
       channel, this is set true and data flow is not halted. */
    *pscan_current_only = MFALSE;

    if (puser_scan_in != MNULL)
    {
        ssid_filter = MFALSE;

        /* Set the bss type scan filter, use Adapter setting if unset */
        pscan_cfg_out->bss_mode =
            (puser_scan_in->bss_mode ? (t_u8)puser_scan_in->bss_mode : (t_u8)pmadapter->scan_mode);

        /* Set the number of probes to send, use Adapter setting if unset */
        num_probes = (puser_scan_in->num_probes ? puser_scan_in->num_probes : pmadapter->scan_probes);

#ifdef CONFIG_SCAN_WITH_RSSIFILTER
        /* Set the threshold value of rssi to send */
        rssi_threshold = puser_scan_in->rssi_threshold;
        /* Enable/Disable rssi threshold function */
        rssi_threshold_enable = (rssi_threshold < 0 ? MTRUE : MFALSE);
#endif
        /*
         * Set the BSSID filter to the incoming configuration,
         *   if non-zero.  If not set, it will remain disabled (all zeros).
         */
        (void)__memcpy(pmadapter, pscan_cfg_out->specific_bssid, puser_scan_in->specific_bssid,
                       sizeof(pscan_cfg_out->specific_bssid));

#ifdef CONFIG_EXT_SCAN_SUPPORT
        if (pmadapter->ext_scan && __memcmp(pmadapter, pscan_cfg_out->specific_bssid, &zero_mac, sizeof(zero_mac)))
        {
            pbssid_tlv              = (MrvlIEtypes_Bssid_List_t *)ptlv_pos;
            pbssid_tlv->header.type = TLV_TYPE_BSSID;
            pbssid_tlv->header.len  = MLAN_MAC_ADDR_LENGTH;
            (void)__memcpy(pmadapter, pbssid_tlv->bssid, puser_scan_in->specific_bssid, MLAN_MAC_ADDR_LENGTH);
            ptlv_pos += sizeof(MrvlIEtypes_Bssid_List_t);
        }
#endif

        for (ssid_idx = 0; ((ssid_idx < NELEMENTS(puser_scan_in->ssid_list)) &&
                            (*puser_scan_in->ssid_list[ssid_idx].ssid || puser_scan_in->ssid_list[ssid_idx].max_len));
             ssid_idx++)
        {
            ssid_len = wlan_strlen((const char *)puser_scan_in->ssid_list[ssid_idx].ssid);

            pwildcard_ssid_tlv                  = (MrvlIEtypes_WildCardSsIdParamSet_t *)(void *)ptlv_pos;
            pwildcard_ssid_tlv->header.type     = wlan_cpu_to_le16(TLV_TYPE_WILDCARDSSID);
            pwildcard_ssid_tlv->header.len      = (t_u16)(ssid_len + sizeof(pwildcard_ssid_tlv->max_ssid_length));
            pwildcard_ssid_tlv->max_ssid_length = puser_scan_in->ssid_list[ssid_idx].max_len;

            if ((ssid_len > 0) && (ssid_len <= MLAN_MAX_SSID_LENGTH))
            {
                (void)__memcpy(pmadapter, pwildcard_ssid_tlv->ssid, puser_scan_in->ssid_list[ssid_idx].ssid,
                               MIN(MLAN_MAX_SSID_LENGTH, ssid_len));
            }

            ptlv_pos += (sizeof(pwildcard_ssid_tlv->header) + pwildcard_ssid_tlv->header.len);

            pwildcard_ssid_tlv->header.len = wlan_cpu_to_le16(pwildcard_ssid_tlv->header.len);

            PRINTM(MINFO, "Scan: ssid_list[%d]: %s, %d\n", ssid_idx, pwildcard_ssid_tlv->ssid,
                   pwildcard_ssid_tlv->max_ssid_length);

            if (ssid_len != 0U)
            {
                ssid_filter = MTRUE;
            }
        }

        /*
         *  The default number of channels sent in the command is low to
         *    ensure the response buffer from the firmware does not truncate
         *    scan results.  That is not an issue with an SSID or BSSID
         *    filter applied to the scan results in the firmware.
         */
        if ((ssid_idx && ssid_filter) ||
            __memcmp(pmadapter, pscan_cfg_out->specific_bssid, &zero_mac, sizeof(zero_mac)))
        {
            if (ssid_filter)
            {
                pmpriv->ssid_filter = ssid_filter;
            }
            *pfiltered_scan = MTRUE;
        }
    }
    else
    {
        pscan_cfg_out->bss_mode = (t_u8)pmadapter->scan_mode;
        num_probes              = pmadapter->scan_probes;
#ifdef CONFIG_SCAN_WITH_RSSIFILTER
        rssi_threshold        = 0;
        rssi_threshold_enable = 0;
#endif
    }

    /*
     *  If a specific BSSID or SSID is used, the number of channels in the
     *  scan command will be increased to the absolute maximum.
     */
    if (*pfiltered_scan == MTRUE)
    {
        *pmax_chan_per_scan = MRVDRV_MAX_CHANNELS_PER_SPECIFIC_SCAN;
    }
    else
    {
        *pmax_chan_per_scan = MRVDRV_CHANNELS_PER_SCAN_CMD;
    }
#ifdef SCAN_CHANNEL_GAP
    if (puser_scan_in)
    {
        if (puser_scan_in->scan_chan_gap)
        {
            *pmax_chan_per_scan = MRVDRV_MAX_CHANNELS_PER_SPECIFIC_SCAN;
            PRINTM(MCMND, "Scan: channel gap = 0x%x\n", puser_scan_in->scan_chan_gap);
            pscan_gap_tlv              = (MrvlIEtypes_ScanChanGap_t *)ptlv_pos;
            pscan_gap_tlv->header.type = wlan_cpu_to_le16(TLV_TYPE_SCAN_CHANNEL_GAP);
            pscan_gap_tlv->header.len  = sizeof(pscan_gap_tlv->gap);
            pscan_gap_tlv->gap         = wlan_cpu_to_le16((t_u16)puser_scan_in->scan_chan_gap);
            ptlv_pos += sizeof(pscan_gap_tlv->header) + pscan_gap_tlv->header.len;
            pscan_gap_tlv->header.len = wlan_cpu_to_le16(pscan_gap_tlv->header.len);
        }
    }
    else if (pmadapter->scan_chan_gap)
    {
        *pmax_chan_per_scan = MRVDRV_MAX_CHANNELS_PER_SPECIFIC_SCAN;
        PRINTM(MCMND, "Scan: channel gap = 0x%x\n", pmadapter->scan_chan_gap);
        pscan_gap_tlv              = (MrvlIEtypes_ScanChanGap_t *)ptlv_pos;
        pscan_gap_tlv->header.type = wlan_cpu_to_le16(TLV_TYPE_SCAN_CHANNEL_GAP);
        pscan_gap_tlv->header.len  = sizeof(pscan_gap_tlv->gap);
        pscan_gap_tlv->gap         = wlan_cpu_to_le16((t_u16)pmadapter->scan_chan_gap);
        ptlv_pos += sizeof(pscan_gap_tlv->header) + pscan_gap_tlv->header.len;
        pscan_gap_tlv->header.len = wlan_cpu_to_le16(pscan_gap_tlv->header.len);
    }
#endif
    /* If the input config or adapter has the number of Probes set, add tlv */
    if (num_probes != 0U)
    {
        PRINTM(MINFO, "Scan: num_probes = %d\n", num_probes);

        pnum_probes_tlv              = (MrvlIEtypes_NumProbes_t *)(void *)ptlv_pos;
        pnum_probes_tlv->header.type = wlan_cpu_to_le16(TLV_TYPE_NUMPROBES);
        pnum_probes_tlv->header.len  = (t_u16)sizeof(pnum_probes_tlv->num_probes);
        pnum_probes_tlv->num_probes  = wlan_cpu_to_le16((t_u16)num_probes);

        ptlv_pos += sizeof(pnum_probes_tlv->header) + pnum_probes_tlv->header.len;

        pnum_probes_tlv->header.len = wlan_cpu_to_le16(pnum_probes_tlv->header.len);
    }

    if (ISSUPP_11NENABLED(pmpriv->adapter->fw_cap_info) &&
        (pmpriv->config_bands & BAND_GN || pmpriv->config_bands & BAND_AN) && wmsdk_is_11N_enabled())
    {
        pht_cap = (MrvlIETypes_HTCap_t *)(void *)ptlv_pos;
        (void)__memset(pmadapter, pht_cap, 0, sizeof(MrvlIETypes_HTCap_t));
        pht_cap->header.type = wlan_cpu_to_le16(HT_CAPABILITY);
        pht_cap->header.len  = (t_u16)sizeof(HTCap_t);
        wlan_fill_ht_cap_tlv(pmpriv, pht_cap, pmpriv->config_bands);
        HEXDUMP("SCAN: HT_CAPABILITIES IE", (t_u8 *)pht_cap, sizeof(MrvlIETypes_HTCap_t));
        ptlv_pos += sizeof(MrvlIETypes_HTCap_t);
        pht_cap->header.len = wlan_cpu_to_le16(pht_cap->header.len);
    }

    if (ISSUPP_11ACENABLED(pmpriv->adapter->fw_cap_info) && (pmpriv->config_bands & BAND_AAC))
    {
        pvht_cap = (MrvlIETypes_VHTCap_t *)(void *)ptlv_pos;
        (void)__memset(pmadapter, pvht_cap, 0, sizeof(MrvlIETypes_VHTCap_t));
        pvht_cap->header.type = wlan_cpu_to_le16(VHT_CAPABILITY);
        pvht_cap->header.len  = (t_u16)sizeof(VHT_capa_t);
        wlan_fill_vht_cap_tlv(pmpriv, pvht_cap, pmpriv->config_bands, MFALSE);
        HEXDUMP("SCAN: VHT_CAPABILITIES IE", (t_u8 *)pvht_cap, sizeof(MrvlIETypes_VHTCap_t));
        ptlv_pos += sizeof(MrvlIETypes_VHTCap_t);
        pvht_cap->header.len = wlan_cpu_to_le16(pvht_cap->header.len);
    }

#ifdef CONFIG_11AX
    if (IS_FW_SUPPORT_11AX(pmadapter) && (pmpriv->config_bands & BAND_AAX))
    {
        phe_cap = (MrvlIEtypes_Extension_t *)ptlv_pos;
        len     = wlan_fill_he_cap_tlv(pmpriv, BAND_A, phe_cap, MFALSE);
        HEXDUMP("SCAN: HE_CAPABILITIES IE", (t_u8 *)phe_cap, len);
        ptlv_pos += len;
    }
#endif

#ifdef CONFIG_SCAN_WITH_RSSIFILTER
    /*
     * Append rssi threshold tlv
     *
     * Note: According to the value of rssi_threshold, it is divided into three situations:
     *     rssi_threshold  |  rssi_threshold_enable  |  Whether to carry TLV
     *           <0        |          MTRUE          |          Yes
     *            0        |          MFALSE         |          No
     *           >0        |          MFALSE         |          Yes
     */
    if (rssi_threshold)
    {
        prssi_threshold_tlv              = (MrvlIEtypes_RssiThresholdParamSet_t *)ptlv_pos;
        prssi_threshold_tlv->header.type = wlan_cpu_to_le16(TLV_TYPE_RSSI_THRESHOLD);
        prssi_threshold_tlv->header.len =
            (t_u16)(sizeof(prssi_threshold_tlv->enable) + sizeof(prssi_threshold_tlv->rssi_threshold) +
                    sizeof(prssi_threshold_tlv->reserved));
        prssi_threshold_tlv->enable         = rssi_threshold_enable;
        prssi_threshold_tlv->rssi_threshold = rssi_threshold;

        ptlv_pos += sizeof(prssi_threshold_tlv->header) + prssi_threshold_tlv->header.len;

        prssi_threshold_tlv->header.len = wlan_cpu_to_le16(prssi_threshold_tlv->header.len);

        pmadapter->rssi_threshold = (rssi_threshold < 0 ? rssi_threshold : 0);

        PRINTM(MINFO, "SCAN_CMD: Rssi threshold = %d\n", rssi_threshold);
    }
#endif

    /* fixme: enable this later when req. */
#ifndef CONFIG_MLAN_WMSDK
    if (pmpriv->hotspot_cfg & HOTSPOT_ENABLED)
    {
        wlan_add_ext_capa_info_ie(pmpriv, &ptlv_pos);
    }

    wlan_add_wps_probe_request_ie(pmpriv, &ptlv_pos);
#endif /* CONFIG_MLAN_WMSDK */

#if defined(CONFIG_MBO) || defined(CONFIG_WPA_SUPP)
    wlan_add_ext_capa_info_ie(pmpriv, NULL, &ptlv_pos);
#endif

    /*
     * Set the output for the channel TLV to the address in the tlv buffer
     *   past any TLVs that were added in this function (SSID, num_probes).
     *   Channel TLVs will be added past this for each scan command, preserving
     *   the TLVs that were previously added.
     */
    *ppchan_list_out = (MrvlIEtypes_ChanListParamSet_t *)(void *)ptlv_pos;

    if ((puser_scan_in != MNULL) && puser_scan_in->chan_list[0].chan_number)
    {
        PRINTM(MINFO, "Scan: Using supplied channel list\n");

        for (chan_idx = 0; chan_idx < WLAN_USER_SCAN_CHAN_MAX && puser_scan_in->chan_list[chan_idx].chan_number;
             chan_idx++)
        {
            radio_type = puser_scan_in->chan_list[chan_idx].radio_type;
            if (!wlan_is_band_compatible(pmpriv->config_bands, radio_type_to_band(radio_type)))
            {
                continue;
            }

            channel                                   = puser_scan_in->chan_list[chan_idx].chan_number;
            (pscan_chan_list + chan_idx)->chan_number = channel;

            (pscan_chan_list + chan_idx)->radio_type = radio_type;

            scan_type = puser_scan_in->chan_list[chan_idx].scan_type;
            if (scan_type == MLAN_SCAN_TYPE_UNCHANGED)
            {
                scan_type = pmadapter->scan_type;
            }

            if (radio_type == HostCmd_SCAN_RADIO_TYPE_A)
            {
                if ((pmadapter->fw_bands & BAND_A) != 0U)
                {
                    PRINTM(MINFO, "UserScan request for A Band channel %d!!\n", channel);
                }
                else
                {
                    PRINTM(MERROR, "Scan in A band is not allowed!!\n");
                    ret = MLAN_STATUS_FAILURE;
                    LEAVE();
                    return ret;
                }
            }

            if (pmadapter->active_scan_triggered == MFALSE)
            {
                /* Prevent active scanning on a radar controlled channel */
#ifdef CONFIG_5GHz_SUPPORT
                if (radio_type == HostCmd_SCAN_RADIO_TYPE_A)
                {
                    if (wlan_11h_radar_detect_required(pmpriv, channel))
                    {
                        scan_type = MLAN_SCAN_TYPE_PASSIVE;
                    }
                }
#endif
                if (radio_type == HostCmd_SCAN_RADIO_TYPE_BG)
                {
                    if (wlan_bg_scan_type_is_passive(pmpriv, channel))
                    {
                        scan_type = MLAN_SCAN_TYPE_PASSIVE;
                    }
                }
            }
            if (scan_type == MLAN_SCAN_TYPE_PASSIVE)
            {
                (pscan_chan_list + chan_idx)->chan_scan_mode.passive_scan       = MTRUE;
                (pscan_chan_list + chan_idx)->chan_scan_mode.hidden_ssid_report = MTRUE;
            }
            else
            {
                (pscan_chan_list + chan_idx)->chan_scan_mode.passive_scan = MFALSE;
            }

            if (puser_scan_in->chan_list[chan_idx].scan_time != 0U)
            {
                scan_dur = (t_u16)puser_scan_in->chan_list[chan_idx].scan_time;
            }
            else
            {
                if (scan_type == MLAN_SCAN_TYPE_PASSIVE)
                {
                    scan_dur = pmadapter->passive_scan_time;
                }
                else if (*pfiltered_scan == MTRUE)
                {
                    scan_dur = pmadapter->specific_scan_time;
                }
                else
                {
                    scan_dur = pmadapter->active_scan_time;
                }
            }

            (pscan_chan_list + chan_idx)->min_scan_time = wlan_cpu_to_le16(scan_dur);
            (pscan_chan_list + chan_idx)->max_scan_time = wlan_cpu_to_le16(scan_dur);

            wscan_d("Channel: %d Type: %s ", channel, scan_type == MLAN_SCAN_TYPE_PASSIVE ? "Passive" : "Active");
        }

        /* Check if we are only scanning the current channel */
        if ((chan_idx == 1U) &&
            (puser_scan_in->chan_list[0].chan_number == pmpriv->curr_bss_params.bss_descriptor.channel))
        {
            *pscan_current_only = MTRUE;
            PRINTM(MINFO, "Scan: Scanning current channel only\n");
        }
    }
    else
    {
        PRINTM(MINFO, "Scan: Creating full region channel list\n");
        wlan_scan_create_channel_list(pmpriv, puser_scan_in, pscan_chan_list, *pfiltered_scan);
    }

    LEAVE();
    return ret;
}

#if !defined(CONFIG_EXT_SCAN_SUPPORT) || defined(CONFIG_BG_SCAN)
/**
 *  @brief Inspect the scan response buffer for pointers to expected TLVs
 *
 *  TLVs can be included at the end of the scan response BSS information.
 *    Parse the data in the buffer for pointers to TLVs that can potentially
 *    be passed back in the response
 *
 *  @param pmadapter        Pointer to the mlan_adapter structure
 *  @param ptlv             Pointer to the start of the TLV buffer to parse
 *  @param tlv_buf_size     Size of the TLV buffer
 *  @param req_tlv_type     Request TLV's type
 *  @param pptlv            Output parameter: Pointer to the request TLV if found
 *
 *  @return                 N/A
 */
static t_void wlan_ret_802_11_scan_get_tlv_ptrs(IN pmlan_adapter pmadapter,
                                                IN MrvlIEtypes_Data_t *ptlv,
                                                IN t_u32 tlv_buf_size,
                                                IN t_u32 req_tlv_type,
                                                OUT MrvlIEtypes_Data_t **pptlv)
{
    MrvlIEtypes_Data_t *pcurrent_tlv;
    t_u32 tlv_buf_left;
    t_u32 tlv_type;
    t_u32 tlv_len;
    bool invalid_tlv = MFALSE;

    ENTER();

    pcurrent_tlv = ptlv;
    tlv_buf_left = tlv_buf_size;
    *pptlv       = MNULL;

    PRINTM(MINFO, "SCAN_RESP: tlv_buf_size = %d\n", tlv_buf_size);

    while (tlv_buf_left >= sizeof(MrvlIEtypesHeader_t))
    {
        tlv_type = wlan_le16_to_cpu(pcurrent_tlv->header.type);
        tlv_len  = wlan_le16_to_cpu(pcurrent_tlv->header.len);

        if (sizeof(ptlv->header) + tlv_len > tlv_buf_left)
        {
            PRINTM(MERROR, "SCAN_RESP: TLV buffer corrupt\n");
            break;
        }

        if (req_tlv_type == tlv_type)
        {
            switch (tlv_type)
            {
                case TLV_TYPE_TSFTIMESTAMP:
                    PRINTM(MINFO, "SCAN_RESP: TSF Timestamp TLV, len = %d\n", tlv_len);
                    *pptlv = (MrvlIEtypes_Data_t *)pcurrent_tlv;
                    break;
                case TLV_TYPE_CHANNELBANDLIST:
                    PRINTM(MINFO, "SCAN_RESP: CHANNEL BAND LIST TLV, len = %d\n", tlv_len);
                    *pptlv = (MrvlIEtypes_Data_t *)pcurrent_tlv;
                    break;
#ifdef SCAN_CHANNEL_GAP
                case TLV_TYPE_CHANNEL_STATS:
                    PRINTM(MINFO, "SCAN_RESP: CHANNEL STATS TLV, len = %d\n", tlv_len);
                    *pptlv = (MrvlIEtypes_Data_t *)pcurrent_tlv;
                    break;
#endif

                default:
                    PRINTM(MERROR, "SCAN_RESP: Unhandled TLV = %d\n", tlv_type);
                    /* Give up, this seems corrupted */
                    invalid_tlv = MTRUE;
                    break;
            }
            if (invalid_tlv == MTRUE)
            {
                LEAVE();
                return;
            }
        }

        if (*pptlv != NULL)
        {
            // HEXDUMP("SCAN_RESP: TLV Buf", (t_u8 *)*pptlv+4, tlv_len);
            break;
        }

        tlv_buf_left -= (sizeof(ptlv->header) + tlv_len);
        pcurrent_tlv = (MrvlIEtypes_Data_t *)(void *)(pcurrent_tlv->data + tlv_len);

    } /* while */

    LEAVE();
}
#endif

#ifdef CONFIG_WPA_SUPP_WPS

void check_for_wps_ie(
    const uint8_t *OuiType, bool *wps_IE_exist, t_u16 *wps_session, void *element_data, unsigned element_len);
#endif /* CONFIG_WPA_SUPP_WPS */

/**
 *  @brief  Check if any hidden SSID found in passive scan channels
 *          and do specific SSID active scan for those channels
 *
 *  @param pmpriv       A pointer to mlan_private structure
 *  @param pioctl_buf   A pointer to mlan_ioctl_req structure
 *
 *  @return             MTRUE/MFALSE
 */
bool wlan_active_scan_req_for_passive_chan(mlan_private *pmpriv, wlan_user_scan_cfg *puser_scan_in)
{
    bool ret                = MFALSE;
    mlan_adapter *pmadapter = pmpriv->adapter;
    bool scan_reqd          = MFALSE;
    bool chan_listed        = MFALSE;
    t_u8 id                 = 0;
    t_u32 bss_idx, i;
    t_u8 null_ssid[MLAN_MAX_SSID_LENGTH] = {0};
    mlan_callbacks *pcb                  = (mlan_callbacks *)&pmpriv->adapter->callbacks;
    wlan_user_scan_cfg *user_scan_cfg    = MNULL;
    t_u16 band;

    ENTER();

    if (!pmpriv->ssid_filter)
    {
        goto done;
    }

    if (pmadapter->active_scan_triggered)
    {
        pmadapter->active_scan_triggered = MFALSE;
        goto done;
    }

    if ((pcb->moal_malloc(pmadapter->pmoal_handle, sizeof(wlan_user_scan_cfg), MLAN_MEM_DEF, (t_u8 **)&user_scan_cfg) !=
         MLAN_STATUS_SUCCESS) ||
        !user_scan_cfg)
    {
        wifi_d("Memory allocation for user_scan_cfg failed\r\n");
        goto done;
    }

    memset(user_scan_cfg, 0x00, sizeof(wlan_user_scan_cfg));

    for (bss_idx = 0; bss_idx < pmadapter->num_in_scan_table; bss_idx++)
    {
        scan_reqd = MFALSE;
        if (!memcmp(pmadapter->pscan_table[bss_idx].ssid.ssid, null_ssid,
                    pmadapter->pscan_table[bss_idx].ssid.ssid_len))
        {
            if (puser_scan_in && puser_scan_in->chan_list[0].chan_number)
            {
                for (i = 0; i < WLAN_USER_SCAN_CHAN_MAX && puser_scan_in->chan_list[i].chan_number; i++)
                {
                    if (puser_scan_in->chan_list[i].chan_number == pmadapter->pscan_table[bss_idx].channel)
                    {
                        if (puser_scan_in->chan_list[i].scan_type == MLAN_SCAN_TYPE_PASSIVE)
                            scan_reqd = MTRUE;
                        break;
                    }
                }
            }
            else if (pmadapter->scan_type == MLAN_SCAN_TYPE_PASSIVE)
            {
                scan_reqd = MTRUE;
            }
            else
            {
#ifdef CONFIG_5GHz_SUPPORT
                if ((pmadapter->pscan_table[bss_idx].bss_band & BAND_A) &&
                    wlan_11h_radar_detect_required(pmpriv, pmadapter->pscan_table[bss_idx].channel))
                    scan_reqd = MTRUE;
#endif
                if (pmadapter->pscan_table[bss_idx].bss_band & (BAND_B | BAND_G) &&
                    wlan_bg_scan_type_is_passive(pmpriv, pmadapter->pscan_table[bss_idx].channel))
                    scan_reqd = MTRUE;
            }

            if (scan_reqd)
            {
                chan_listed = MFALSE;
                for (i = 0; i < id; i++)
                {
                    band = radio_type_to_band(user_scan_cfg->chan_list[i].radio_type);

                    if ((user_scan_cfg->chan_list[i].chan_number == pmadapter->pscan_table[bss_idx].channel) &&
                        (band & pmadapter->pscan_table[bss_idx].bss_band))
                    {
                        chan_listed = MTRUE;
                        break;
                    }
                }
                if (chan_listed == MTRUE)
                    continue;
                user_scan_cfg->chan_list[id].chan_number = pmadapter->pscan_table[bss_idx].channel;
                if (pmadapter->pscan_table[bss_idx].bss_band & (BAND_B | BAND_G))
                    user_scan_cfg->chan_list[id].radio_type = BAND_2GHZ;
#ifdef CONFIG_5GHz_SUPPORT
                if (pmadapter->pscan_table[bss_idx].bss_band & BAND_A)
                    user_scan_cfg->chan_list[id].radio_type = BAND_5GHZ;
#endif
                user_scan_cfg->chan_list[id].scan_type = MLAN_SCAN_TYPE_ACTIVE;

                user_scan_cfg->chan_list[id].scan_time = MRVDRV_ACTIVE_SCAN_CHAN_TIME;

                id++;

                if (id >= WLAN_USER_SCAN_CHAN_MAX)
                    break;
            }
        }
    }
    if (id)
    {
        pmadapter->active_scan_triggered = MTRUE;
        (void)__memcpy(pmadapter, user_scan_cfg->ssid_list, puser_scan_in->ssid_list, sizeof(user_scan_cfg->ssid_list));
        user_scan_cfg->keep_previous_scan = MTRUE;
#ifdef EXT_SCAN_ENH
        if (pmadapter->ext_scan_type == EXT_SCAN_ENHANCE)
            user_scan_cfg->ext_scan_type = EXT_SCAN_ENHANCE;
#endif
        wifi_d("active scan request for passive channel %d\r\n", id);
        if (MLAN_STATUS_SUCCESS != wlan_scan_networks(pmpriv, NULL, user_scan_cfg))
        {
            goto done;
        }
        ret = MTRUE;
    }
done:
    split_scan_in_progress = false;
    if (user_scan_cfg)
        pcb->moal_mfree(pmadapter->pmoal_handle, (t_u8 *)user_scan_cfg);

    LEAVE();
    return ret;
}

/**
 *  @brief Interpret a BSS scan response returned from the firmware
 *
 *  Parse the various fixed fields and IEs passed back for a BSS probe
 *   response or beacon from the scan command.  Record information as needed
 *   in the scan table BSSDescriptor_t for that entry.
 *
 *  @param pmadapter    A pointer to mlan_adapter structure
 *  @param pbss_entry   Output parameter: Pointer to the BSS Entry
 *  @param pbeacon_info Pointer to the Beacon information
 *  @param bytes_left   Number of bytes left to parse
 *
 *  @return             MLAN_STATUS_SUCCESS or MLAN_STATUS_FAILURE
 */
static mlan_status wlan_interpret_bss_desc_with_ie(IN pmlan_adapter pmadapter,
                                                   OUT BSSDescriptor_t *pbss_entry,
                                                   IN t_u8 **pbeacon_info,
                                                   IN t_u32 *bytes_left,
                                                   IN t_u8 ext_scan)
{
    mlan_status ret = MLAN_STATUS_SUCCESS;
    IEEEtypes_ElementId_e element_id;
    IEEEtypes_FhParamSet_t *pfh_param_set;
    IEEEtypes_DsParamSet_t *pds_param_set;
    IEEEtypes_DtimParamSet_t *pdtim_param_set;
    IEEEtypes_CfParamSet_t *pcf_param_set;
    IEEEtypes_IbssParamSet_t *pibss_param_set;
    IEEEtypes_CapInfo_t *pcap_info;
    WLAN_802_11_FIXED_IEs fixed_ie;
    t_u8 *pcurrent_ptr;
    t_u8 *prate;
    t_u8 element_len;
    t_u16 total_ie_len;
    t_u8 bytes_to_copy;
    t_u8 rate_size;
    t_u16 beacon_size;
    t_u8 found_data_rate_ie;
    t_u32 bytes_left_for_current_beacon;
    /* IEEEtypes_ERPInfo_t *perp_info; */

    IEEEtypes_VendorSpecific_t *pvendor_ie;
    const t_u8 wpa_oui[3]  = {0x00, 0x50, 0xf2};
    const t_u8 wpa_type[1] = {0x01};
    const t_u8 wmm_oui[3]  = {0x00, 0x50, 0xf2};
    const t_u8 wmm_type[1] = {0x02};
#ifdef CONFIG_OWE
    const t_u8 owe_oui[3]  = {0x50, 0x6f, 0x9a};
    const t_u8 owe_type[1] = {0x01c};
#endif
#ifdef CONFIG_MBO
    const t_u8 scan_mbo_oui[3]  = {0x50, 0x6f, 0x9a};
    const t_u8 scan_mbo_type[1] = {0x016};
#endif

    IEEEtypes_CountryInfoSet_t *pcountry_info;
#ifdef CONFIG_11AX
    IEEEtypes_Extension_t *pext_tlv;
#endif

    ENTER();

    found_data_rate_ie = MFALSE;
    rate_size          = 0;
    beacon_size        = 0;

    if (*bytes_left >= sizeof(beacon_size))
    {
        /* Extract & convert beacon size from the command buffer */
        (void)__memcpy(pmadapter, &beacon_size, *pbeacon_info, sizeof(beacon_size));
        beacon_size = wlan_le16_to_cpu(beacon_size);
        *bytes_left -= sizeof(beacon_size);
        *pbeacon_info += sizeof(beacon_size);
    }

    if (!beacon_size || beacon_size > *bytes_left)
    {
        *pbeacon_info += *bytes_left;
        *bytes_left = 0;

        LEAVE();
        return MLAN_STATUS_FAILURE;
    }

    /* Initialize the current working beacon pointer for this BSS iteration */
    pcurrent_ptr = *pbeacon_info;

    /* Advance the return beacon pointer past the current beacon */
    *pbeacon_info += beacon_size;
    *bytes_left -= beacon_size;

    bytes_left_for_current_beacon = beacon_size;

    if (bytes_left_for_current_beacon < (MLAN_MAC_ADDR_LENGTH + sizeof(t_u8) + sizeof(WLAN_802_11_FIXED_IEs)))
    {
        PRINTM(MERROR, "InterpretIE: Not enough bytes left\n");
        LEAVE();
        return MLAN_STATUS_FAILURE;
    }

    (void)__memcpy(pmadapter, pbss_entry->mac_address, pcurrent_ptr, MLAN_MAC_ADDR_LENGTH);
    wifi_d("InterpretIE: AP MAC Addr-%02x:%02x:%02x:%02x:%02x:%02x", pbss_entry->mac_address[0],
           pbss_entry->mac_address[1], pbss_entry->mac_address[2], pbss_entry->mac_address[3],
           pbss_entry->mac_address[4], pbss_entry->mac_address[5]);

    pcurrent_ptr += MLAN_MAC_ADDR_LENGTH;
    bytes_left_for_current_beacon -= MLAN_MAC_ADDR_LENGTH;

    /*
     * Next 4 fields are RSSI (for legacy scan only), time stamp,
     *   beacon interval, and capability information
     */
#ifdef CONFIG_EXT_SCAN_SUPPORT
    if (ext_scan == (t_u8)0U)
    {
#endif
        /* RSSI is 1 byte long */
        pbss_entry->rssi = (t_s32)(*pcurrent_ptr);
        PRINTM(MINFO, "InterpretIE: RSSI=%02X\n", *pcurrent_ptr);
        pcurrent_ptr += 1;
        bytes_left_for_current_beacon -= 1U;
#ifdef CONFIG_EXT_SCAN_SUPPORT
    }
#endif

    /*
     *  The RSSI is not part of the beacon/probe response.  After we have
     *    advanced pcurrent_ptr past the RSSI field, save the remaining
     *    data for use at the application layer
     */
    pbss_entry->pbeacon_buf     = pcurrent_ptr;
    pbss_entry->beacon_buf_size = bytes_left_for_current_beacon;

#ifndef CONFIG_MLAN_WMSDK
    /* Time stamp is 8 bytes long */
    (void)__memcpy(pmadapter, fixed_ie.time_stamp, pcurrent_ptr, 8);
#endif /* CONFIG_MLAN_WMSDK */
    (void)__memcpy(pmadapter, pbss_entry->time_stamp, pcurrent_ptr, 8);

    pcurrent_ptr += 8;
    bytes_left_for_current_beacon -= 8U;

    /* Beacon interval is 2 bytes long */
    (void)__memcpy(pmadapter, &fixed_ie.beacon_interval, pcurrent_ptr, 2);
    pbss_entry->beacon_period = wlan_le16_to_cpu(fixed_ie.beacon_interval);
    pcurrent_ptr += 2;
    bytes_left_for_current_beacon -= 2U;

    /* Capability information is 2 bytes long */
    (void)__memcpy(pmadapter, &fixed_ie.capabilities, pcurrent_ptr, 2);
    PRINTM(MINFO, "InterpretIE: fixed_ie.capabilities=0x%X\n", fixed_ie.capabilities);
    fixed_ie.capabilities = wlan_le16_to_cpu(fixed_ie.capabilities);
    pcap_info             = (IEEEtypes_CapInfo_t *)(void *)&fixed_ie.capabilities;
    (void)__memcpy(pmadapter, &pbss_entry->cap_info, pcap_info, sizeof(IEEEtypes_CapInfo_t));
    pcurrent_ptr += 2;
    bytes_left_for_current_beacon -= 2U;

    /* Rest of the current buffer are IE's */
    wifi_d("InterpretIE: IELength for this AP = %d", bytes_left_for_current_beacon);

    HEXDUMP("InterpretIE: IE info", (t_u8 *)pcurrent_ptr, bytes_left_for_current_beacon);

#ifdef CONFIG_WPA_SUPP
    /* Store IE pointer and len for wpa supplicant scan result, no need to process each IE below*/
    if (pmadapter->wpa_supp_scan_triggered == MTRUE)
    {
        wifi_d("Alloc ies for BSS");
        pbss_entry->ies = (u8 *)os_mem_alloc(bytes_left_for_current_beacon);
        if (pbss_entry->ies == MNULL)
        {
            wifi_d("Failed to alloc memory for BSS ies");
            return MLAN_STATUS_FAILURE;
        }
        (void)__memcpy(pmadapter, pbss_entry->ies, (t_u8 *)pcurrent_ptr, bytes_left_for_current_beacon);
        pbss_entry->ies_len = bytes_left_for_current_beacon;
    }
#endif

    if (pcap_info->privacy == MTRUE)
    {
        PRINTM(MINFO, "InterpretIE: AP WEP enabled\n");
        pbss_entry->privacy = (t_u32)Wlan802_11PrivFilter8021xWEP;
    }
    else
    {
        pbss_entry->privacy = (t_u32)Wlan802_11PrivFilterAcceptAll;
    }

    if (pcap_info->ibss == 1U)
    {
        pbss_entry->bss_mode = MLAN_BSS_MODE_IBSS;
    }
    else
    {
        pbss_entry->bss_mode = MLAN_BSS_MODE_INFRA;
    }

#ifndef CONFIG_MLAN_WMSDK
    if (pcap_info->spectrum_mgmt == 1)
    {
        PRINTM(MINFO,
               "InterpretIE: 11h- Spectrum Management "
               "capability bit found\n");
        pbss_entry->wlan_11h_bss_info.sensed_11h = 1;
    }
#endif /* CONFIG_MLAN_WMSDK */

    /* Process variable IE */
    while (bytes_left_for_current_beacon >= 2U)
    {
        element_id   = (IEEEtypes_ElementId_e)(*((t_u8 *)pcurrent_ptr));
        element_len  = *((t_u8 *)pcurrent_ptr + 1);
        total_ie_len = (t_u16)(element_len + sizeof(IEEEtypes_Header_t));

        if (bytes_left_for_current_beacon < total_ie_len)
        {
            PRINTM(MERROR,
                   "InterpretIE: Error in processing IE, "
                   "bytes left < IE length\n");
            bytes_left_for_current_beacon = 0;
            continue;
        }

        switch (element_id)
        {
            case SSID:
                if (element_len > MRVDRV_MAX_SSID_LENGTH)
                {
                    bytes_left_for_current_beacon = 0;
                    continue;
                }
                pbss_entry->ssid.ssid_len = element_len;
                (void)__memcpy(pmadapter, pbss_entry->ssid.ssid, (pcurrent_ptr + 2), element_len);
                wscan_d("AP: %s", pbss_entry->ssid.ssid);
                PRINTM(MINFO, "InterpretIE: ssid: %-32s\n", pbss_entry->ssid.ssid);
                break;

            case SUPPORTED_RATES:
                if (element_len > WLAN_SUPPORTED_RATES)
                {
                    bytes_left_for_current_beacon = 0;
                    continue;
                }
                (void)__memcpy(pmadapter, pbss_entry->data_rates, pcurrent_ptr + 2, element_len);
                (void)__memcpy(pmadapter, pbss_entry->supported_rates, pcurrent_ptr + 2, element_len);
                HEXDUMP("InterpretIE: SupportedRates:", pbss_entry->supported_rates, element_len);
                rate_size          = element_len;
                found_data_rate_ie = MTRUE;
                break;

            case FH_PARAM_SET:
                pfh_param_set                = (IEEEtypes_FhParamSet_t *)(void *)pcurrent_ptr;
                pbss_entry->network_type_use = Wlan802_11FH;
                (void)__memcpy(pmadapter, &pbss_entry->phy_param_set.fh_param_set, pfh_param_set,
                               MIN(total_ie_len, sizeof(IEEEtypes_FhParamSet_t)));
                pbss_entry->phy_param_set.fh_param_set.len =
                    MIN(element_len, (sizeof(IEEEtypes_FhParamSet_t) - sizeof(IEEEtypes_Header_t)));
                pbss_entry->phy_param_set.fh_param_set.dwell_time =
                    wlan_le16_to_cpu(pbss_entry->phy_param_set.fh_param_set.dwell_time);
                break;

            case DS_PARAM_SET:
                pds_param_set = (IEEEtypes_DsParamSet_t *)(void *)pcurrent_ptr;

                pbss_entry->network_type_use = Wlan802_11DS;
                pbss_entry->channel          = pds_param_set->current_chan;

                (void)__memcpy(pmadapter, &pbss_entry->phy_param_set.ds_param_set, pds_param_set,
                               MIN(total_ie_len, sizeof(IEEEtypes_DsParamSet_t)));
                pbss_entry->phy_param_set.ds_param_set.len =
                    MIN(element_len, (sizeof(IEEEtypes_DsParamSet_t) - sizeof(IEEEtypes_Header_t)));
                break;

            case CF_PARAM_SET:
                pcf_param_set = (IEEEtypes_CfParamSet_t *)(void *)pcurrent_ptr;
                (void)__memcpy(pmadapter, &pbss_entry->ss_param_set.cf_param_set, pcf_param_set,
                               MIN(total_ie_len, sizeof(IEEEtypes_CfParamSet_t)));
                pbss_entry->ss_param_set.cf_param_set.len =
                    MIN(element_len, (sizeof(IEEEtypes_CfParamSet_t) - sizeof(IEEEtypes_Header_t)));
                break;

            case DTIM_PARAM_SET:
                pdtim_param_set = (IEEEtypes_DtimParamSet_t *)(void *)pcurrent_ptr;

                pbss_entry->dtim_period = pdtim_param_set->dtim_period;
                break;

            case IBSS_PARAM_SET:
                pibss_param_set         = (IEEEtypes_IbssParamSet_t *)(void *)pcurrent_ptr;
                pbss_entry->atim_window = wlan_le16_to_cpu(pibss_param_set->atim_window);
                (void)__memcpy(pmadapter, &pbss_entry->ss_param_set.ibss_param_set, pibss_param_set,
                               MIN(total_ie_len, sizeof(IEEEtypes_IbssParamSet_t)));
                pbss_entry->ss_param_set.ibss_param_set.len =
                    MIN(element_len, (sizeof(IEEEtypes_IbssParamSet_t) - sizeof(IEEEtypes_Header_t)));
                break;

                /* Handle Country Info IE */
            case COUNTRY_INFO:
                /* Disabling this because IEEEtypes_CountryInfoSet_t size
                   is 254 bytes. Check later if can be optimized */
                pcountry_info = (IEEEtypes_CountryInfoSet_t *)(void *)pcurrent_ptr;

                if (pcountry_info->len < sizeof(pcountry_info->country_code) ||
                    (unsigned)(pcountry_info->len + 2) > sizeof(IEEEtypes_CountryInfoFullSet_t))
                {
                    PRINTM(MERROR,
                           "InterpretIE: 11D- Err "
                           "country_info len =%d min=%d max=%d\n",
                           pcountry_info->len, sizeof(pcountry_info->country_code),
                           sizeof(IEEEtypes_CountryInfoFullSet_t));
                    LEAVE();
                    return MLAN_STATUS_FAILURE;
                }

                (void)__memcpy(pmadapter, &pbss_entry->country_info, pcountry_info, pcountry_info->len + 2);
                HEXDUMP("InterpretIE: 11D- country_info:", (t_u8 *)pcountry_info, (t_u32)(pcountry_info->len + 2));
                break;
#ifndef CONFIG_MLAN_WMSDK
            case ERP_INFO:
                perp_info             = (IEEEtypes_ERPInfo_t *)pcurrent_ptr;
                pbss_entry->erp_flags = perp_info->erp_flags;
                break;
#endif /* CONFIG_MLAN_WMSDK */
            case POWER_CONSTRAINT:
            case POWER_CAPABILITY:
            case TPC_REPORT:
            case CHANNEL_SWITCH_ANN:
            case QUIET:
            case IBSS_DFS:
            case SUPPORTED_CHANNELS:
            case TPC_REQUEST:
                /* fixme: Not enabled yet */
                /* wlan_11h_process_bss_elem(pmadapter, &pbss_entry->wlan_11h_bss_info, */
                /*                       pcurrent_ptr); */
                break;
            case EXTENDED_SUPPORTED_RATES:
                /*
                 * Only process extended supported rate
                 * if data rate is already found.
                 * Data rate IE should come before
                 * extended supported rate IE
                 */
                if (found_data_rate_ie == MTRUE)
                {
                    if ((element_len + rate_size) > WLAN_SUPPORTED_RATES)
                    {
                        bytes_to_copy = (WLAN_SUPPORTED_RATES - rate_size);
                    }
                    else
                    {
                        bytes_to_copy = element_len;
                    }

                    prate = (t_u8 *)pbss_entry->data_rates;
                    prate += rate_size;
                    (void)__memcpy(pmadapter, prate, pcurrent_ptr + 2, bytes_to_copy);

                    prate = (t_u8 *)pbss_entry->supported_rates;
                    prate += rate_size;
                    (void)__memcpy(pmadapter, prate, pcurrent_ptr + 2, bytes_to_copy);
                }
                HEXDUMP("InterpretIE: ExtSupportedRates:", pbss_entry->supported_rates, element_len + rate_size);
                break;

            case VENDOR_SPECIFIC_221:
                pvendor_ie = (IEEEtypes_VendorSpecific_t *)(void *)pcurrent_ptr;

                if ((__memcmp(pmadapter, pvendor_ie->vend_hdr.oui, wpa_oui, sizeof(wpa_oui))) == 0 &&
                    (pvendor_ie->vend_hdr.oui_type == wpa_type[0]))
                {
                    /* Save it here since we do not have beacon buffer */
                    /* fixme : Verify if this is the right approach. This had to be
                       done because IEEEtypes_Rsn_t was not the correct data
                       structure to map here  */
                    if (element_len <= (sizeof(pbss_entry->wpa_ie_buff) - sizeof(IEEEtypes_Header_t)))
                    {
                        (void)__memcpy(NULL, pbss_entry->wpa_ie_buff, pcurrent_ptr,
                                       element_len + sizeof(IEEEtypes_Header_t));
                        pbss_entry->pwpa_ie         = (IEEEtypes_VendorSpecific_t *)(void *)pbss_entry->wpa_ie_buff;
                        pbss_entry->wpa_ie_buff_len = element_len + sizeof(IEEEtypes_Header_t);

                        if (wifi_check_bss_entry_wpa2_entp_only(pbss_entry, VENDOR_SPECIFIC_221) != MLAN_STATUS_SUCCESS)
                        {
                            return MLAN_STATUS_RESOURCE;
                        }
                    }
                    else
                    {
                        wifi_e("Insufficient space to save WPA_IE size: %d", element_len);
                    }

                    /* pbss_entry->pwpa_ie = */
                    /*     (IEEEtypes_VendorSpecific_t *) pcurrent_ptr; */
                    /* pbss_entry->wpa_offset = */
                    /*     (t_u16) (pcurrent_ptr - pbss_entry->pbeacon_buf); */
                    HEXDUMP("InterpretIE: Resp WPA_IE", (t_u8 *)pbss_entry->pwpa_ie,
                            ((*(pbss_entry->pwpa_ie)).vend_hdr.len + sizeof(IEEEtypes_Header_t)));
                }
                else if ((__memcmp(pmadapter, pvendor_ie->vend_hdr.oui, wmm_oui, sizeof(wmm_oui))) == 0 &&
                         (pvendor_ie->vend_hdr.oui_type == wmm_type[0]))
                {
                    if (total_ie_len == sizeof(IEEEtypes_WmmParameter_t) || total_ie_len == sizeof(IEEEtypes_WmmInfo_t))
                    {
                        /*
                         * Only accept and copy the WMM IE if it matches
                         * the size expected for the WMM Info IE or the
                         * WMM Parameter IE.
                         */
                        (void)__memcpy(pmadapter, (t_u8 *)&pbss_entry->wmm_ie, pcurrent_ptr, total_ie_len);
                        HEXDUMP("InterpretIE: Resp WMM_IE", (t_u8 *)&pbss_entry->wmm_ie, total_ie_len);
                    }
                }
#ifdef CONFIG_OWE
                else if (IS_FW_SUPPORT_EMBEDDED_OWE(pmadapter) &&
                         (!__memcmp(pmadapter, pvendor_ie->vend_hdr.oui, owe_oui, sizeof(owe_oui)) &&
                          (pvendor_ie->vend_hdr.oui_type == owe_type[0])))
                {
                    /* Current Format of OWE IE is element_id:element_len:oui:MAC Address:SSID length:SSID */
                    t_u8 trans_ssid_len =
                        *(pcurrent_ptr + sizeof(IEEEtypes_Header_t) + sizeof(owe_oui) + MLAN_MAC_ADDR_LENGTH);

                    if (!trans_ssid_len || trans_ssid_len > MRVDRV_MAX_SSID_LENGTH)
                    {
                        bytes_left_for_current_beacon = 0;
                        continue;
                    }
                    if (!pcap_info->privacy)
                    {
                        pbss_entry->owe_transition_mode = OWE_TRANS_MODE_OPEN;
                    }
                    else
                    {
                        pbss_entry->owe_transition_mode = OWE_TRANS_MODE_OWE;
                    }

                    (void)__memcpy(pmadapter, pbss_entry->trans_mac_address,
                                   (pcurrent_ptr + sizeof(IEEEtypes_Header_t) + sizeof(owe_oui)), MLAN_MAC_ADDR_LENGTH);
                    pbss_entry->trans_ssid.ssid_len = trans_ssid_len;
                    (void)__memcpy(pmadapter, pbss_entry->trans_ssid.ssid,
                                   (pcurrent_ptr + sizeof(IEEEtypes_Header_t) + sizeof(owe_oui) + MLAN_MAC_ADDR_LENGTH +
                                    sizeof(t_u8)),
                                   trans_ssid_len);

                    PRINTM(MCMND, "InterpretIE: OWE Transition AP privacy=%d MAC Addr-" MACSTR " ssid %s\n",
                           pbss_entry->owe_transition_mode, MAC2STR(pbss_entry->trans_mac_address),
                           pbss_entry->trans_ssid.ssid);
                }
#endif
#ifdef CONFIG_MBO
                else if (__memcmp(pmadapter, pvendor_ie->vend_hdr.oui, scan_mbo_oui, sizeof(scan_mbo_oui)) == 0 &&
                         (pvendor_ie->vend_hdr.oui_type == scan_mbo_type[0]))
                {
                    t_u8 *pcurrent_attr = pcurrent_ptr + MBO_IE_HEADER_LEN;
                    t_u8 mbo_attr_id;
                    t_u8 mbo_attr_len = 0;
                    t_u8 mbo_cur_len  = MBO_IE_HEADER_LEN - sizeof(IEEEtypes_Header_t);

                    pbss_entry->mbo_assoc_disallowed = false;

                    while (mbo_cur_len < element_len)
                    {
                        mbo_attr_id  = *((t_u8 *)pcurrent_attr);
                        mbo_attr_len = *((t_u8 *)pcurrent_attr + 1);

                        if (mbo_attr_id == 0x4U)
                        {
                            pbss_entry->mbo_assoc_disallowed = true;
                        }

                        mbo_cur_len += (t_u8)MBO_ATTR_HEADER_LEN + mbo_attr_len;
                        pcurrent_attr = pcurrent_attr + MBO_ATTR_HEADER_LEN + mbo_attr_len;
                    }
                }
#endif
#ifdef CONFIG_11K
                /* Voice Enterprise Test Plan V1.2, test case 5.4, store other vendor specific ie */
                else
                {
                    if (pbss_entry->vendor_ie_len + element_len + (t_u8)sizeof(IEEEtypes_Header_t) <
                        (t_u8)sizeof(pbss_entry->vendor_ie_buff))
                    {
                        (void)__memcpy(pmadapter, pbss_entry->vendor_ie_buff + pbss_entry->vendor_ie_len, pcurrent_ptr,
                                       element_len + sizeof(IEEEtypes_Header_t));
                        pbss_entry->vendor_ie_len += element_len + (t_u8)sizeof(IEEEtypes_Header_t);
                    }
                }
#else
                else
                {
                    /* Do Nothing */
                }
#endif

#ifdef CONFIG_WPA_SUPP_WPS
                /* fixme: Added for WMSDK. Check if can be merged properly with
                   mlan. There should be a better way */
                check_for_wps_ie(pvendor_ie->vend_hdr.oui, &pbss_entry->wps_IE_exist, &pbss_entry->wps_session,
                                 pcurrent_ptr + 2, element_len);
#endif /* CONFIG_WPA_SUPP_WPS */
                break;
            case RSN_IE:
                /* Save it here since we do not have beacon buffer */
                /* fixme : Verify if this is the right approach. This had to be
                   done because IEEEtypes_Rsn_t was not the correct data
                   structure to map here  */
                if (element_len <= (sizeof(pbss_entry->rsn_ie_buff) - sizeof(IEEEtypes_Header_t)))
                {
                    (void)__memcpy(NULL, pbss_entry->rsn_ie_buff, pcurrent_ptr,
                                   element_len + sizeof(IEEEtypes_Header_t));
                    pbss_entry->rsn_ie_buff_len = element_len + sizeof(IEEEtypes_Header_t);
                    pbss_entry->prsn_ie         = (IEEEtypes_Generic_t *)(void *)pbss_entry->rsn_ie_buff;

                    if (wifi_check_bss_entry_wpa2_entp_only(pbss_entry, RSN_IE) != MLAN_STATUS_SUCCESS)
                    {
                        return MLAN_STATUS_RESOURCE;
                    }
                }
                else
                {
                    wifi_e("Insufficient space to save RSN_IE size: %d", element_len);
                }

                /* pbss_entry->prsn_ie = (IEEEtypes_Generic_t *) pcurrent_ptr; */
                /* pbss_entry->rsn_offset = */
                /*     (t_u16) (pcurrent_ptr - pbss_entry->pbeacon_buf); */
                HEXDUMP("InterpretIE: Resp RSN_IE", (t_u8 *)pbss_entry->prsn_ie,
                        (*(pbss_entry->prsn_ie)).ieee_hdr.len + sizeof(IEEEtypes_Header_t));
                break;
#if defined(CONFIG_11R) || defined(CONFIG_11K)
            case MOBILITY_DOMAIN:
                if (element_len <= (sizeof(pbss_entry->md_ie_buff) - sizeof(IEEEtypes_Header_t)))
                {
                    (void)__memcpy(NULL, pbss_entry->md_ie_buff, pcurrent_ptr,
                                   element_len + sizeof(IEEEtypes_Header_t));
                    pbss_entry->md_ie_buff_len   = element_len + sizeof(IEEEtypes_Header_t);
                    pbss_entry->pmd_ie           = (IEEEtypes_MobilityDomain_t *)(void *)pbss_entry->md_ie_buff;
                    pbss_entry->mob_domain_exist = 1;
                    /* dump_hex(pbss_entry->pmd_ie, pbss_entry->md_ie_buff_len); */
                }
                else
                {
                    wifi_e("Insufficient space to save MD_IE size: %d", element_len);
                }
                break;
#endif
#ifdef CONFIG_11K
            case RRM_ENABLED_CAP:
                /* Save it here since we do not have beacon buffer */
                (void)__memcpy(NULL, &pbss_entry->rm_cap_saved, pcurrent_ptr, sizeof(IEEEtypes_RrmElement_t));
                pbss_entry->rm_cap_exist = 1;
                break;
#endif
            case WAPI_IE:
#ifndef CONFIG_MLAN_WMSDK
                pbss_entry->pwapi_ie    = (IEEEtypes_Generic_t *)pcurrent_ptr;
                pbss_entry->wapi_offset = (t_u16)(pcurrent_ptr - pbss_entry->pbeacon_buf);
                HEXDUMP("InterpretIE: Resp WAPI_IE", (t_u8 *)pbss_entry->pwapi_ie,
                        (*(pbss_entry->pwapi_ie)).ieee_hdr.len + sizeof(IEEEtypes_Header_t));
#endif /* CONFIG_MLAN_WMSDK */
                break;
#ifdef MULTI_BSSID_SUPPORT
            case MULTI_BSSID:
                if (IS_FW_SUPPORT_MULTIBSSID(pmadapter))
                {
                    pbss_entry->multi_bssid_ap = MULTI_BSSID_AP;
                    HEXDUMP("InterpretIE: Multi BSSID IE", (t_u8 *)pcurrent_ptr, total_ie_len);
                }
                break;
#endif
            case HT_CAPABILITY:
                /* Save it here since we do not have beacon buffer */
                (void)__memcpy(NULL, &pbss_entry->ht_cap_saved, pcurrent_ptr, sizeof(IEEEtypes_HTCap_t));
                pbss_entry->pht_cap = &pbss_entry->ht_cap_saved;
                /* pbss_entry->pht_cap = (IEEEtypes_HTCap_t *) pcurrent_ptr; */
                /* pbss_entry->ht_cap_offset = */
                /*     (t_u16) (pcurrent_ptr - pbss_entry->pbeacon_buf); */
                HEXDUMP("InterpretIE: Resp HTCAP_IE", (t_u8 *)pbss_entry->pht_cap,
                        (*(pbss_entry->pht_cap)).ieee_hdr.len + sizeof(IEEEtypes_Header_t));
                break;
            case HT_OPERATION:
                /* Save it here since we do not have beacon buffer */
                (void)__memcpy(NULL, &pbss_entry->ht_info_saved, pcurrent_ptr, sizeof(IEEEtypes_HTInfo_t));
                pbss_entry->pht_info = &pbss_entry->ht_info_saved;
                /* pbss_entry->pht_info = (IEEEtypes_HTInfo_t *) pcurrent_ptr; */
                /* pbss_entry->ht_info_offset = */
                /*     (t_u16) (pcurrent_ptr - pbss_entry->pbeacon_buf); */
                HEXDUMP("InterpretIE: Resp HTINFO_IE", (t_u8 *)pbss_entry->pht_info,
                        (*(pbss_entry->pht_info)).ieee_hdr.len + sizeof(IEEEtypes_Header_t));
                break;
            case BSSCO_2040:
                /* Save it here since we do not have beacon buffer */
                (void)__memcpy(NULL, &pbss_entry->bss_co_2040_saved, pcurrent_ptr, sizeof(IEEEtypes_2040BSSCo_t));
                pbss_entry->pbss_co_2040 = &pbss_entry->bss_co_2040_saved;
                /* pbss_entry->pbss_co_2040 = (IEEEtypes_2040BSSCo_t *) pcurrent_ptr; */
                /* pbss_entry->bss_co_2040_offset = */
                /*     (t_u16) (pcurrent_ptr - pbss_entry->pbeacon_buf); */
                HEXDUMP("InterpretIE: Resp 2040BSSCOEXISTANCE_IE", (t_u8 *)pbss_entry->pbss_co_2040,
                        (*(pbss_entry->pbss_co_2040)).ieee_hdr.len + sizeof(IEEEtypes_Header_t));
                break;
#ifdef CONFIG_11AC
            case VHT_CAPABILITY:
                /* Save it here since we do not have beacon buffer */
                (void)__memcpy(NULL, &pbss_entry->vht_cap_saved, pcurrent_ptr, sizeof(IEEEtypes_VHTCap_t));
                pbss_entry->pvht_cap = &pbss_entry->vht_cap_saved;
                break;
            case VHT_OPERATION:
                /* Save it here since we do not have beacon buffer */
                (void)__memcpy(NULL, &pbss_entry->vht_oprat_saved, pcurrent_ptr, sizeof(IEEEtypes_VHTOprat_t));
                pbss_entry->pvht_oprat = &pbss_entry->vht_oprat_saved;
                break;
            case VHT_TX_POWER_ENV:
                /* Save it here since we do not have beacon buffer */
                (void)__memcpy(NULL, &pbss_entry->vht_txpower_saved, pcurrent_ptr, sizeof(IEEEtypes_VHTtxpower_t));
                pbss_entry->pvht_txpower = &pbss_entry->vht_txpower_saved;
                break;
            case OPER_MODE_NTF:
                /* Save it here since we do not have beacon buffer */
                (void)__memcpy(NULL, &pbss_entry->poper_mode_saved, pcurrent_ptr, sizeof(IEEEtypes_OperModeNtf_t));
                pbss_entry->ppoper_mode = &pbss_entry->poper_mode_saved;
                break;
#endif
            case EXT_CAPABILITY:
                /* Save it here since we do not have beacon buffer */
                (void)__memcpy(NULL, &pbss_entry->ext_cap_saved, pcurrent_ptr, sizeof(IEEEtypes_ExtCap_t));
                pbss_entry->pext_cap = &pbss_entry->ext_cap_saved;
                break;
#ifndef CONFIG_MLAN_WMSDK
            case OVERLAPBSSSCANPARAM:
                pbss_entry->poverlap_bss_scan_param = (IEEEtypes_OverlapBSSScanParam_t *)pcurrent_ptr;
                pbss_entry->overlap_bss_offset      = (t_u16)(pcurrent_ptr - pbss_entry->pbeacon_buf);
                HEXDUMP("InterpretIE: Resp HTCAP_IE", (t_u8 *)pbss_entry->poverlap_bss_scan_param,
                        (*(pbss_entry->poverlap_bss_scan_param)).ieee_hdr.len + sizeof(IEEEtypes_Header_t));
                break;
#endif /* CONFIG_MLAN_WMSDK */
#ifdef CONFIG_11AX
            case EXTENSION:
                pext_tlv = (IEEEtypes_Extension_t *)pcurrent_ptr;
                switch (pext_tlv->ext_id)
                {
                    case HE_CAPABILITY:
                        pbss_entry->phe_cap       = (IEEEtypes_HECap_t *)pcurrent_ptr;
                        pbss_entry->he_cap_offset = (t_u16)(pcurrent_ptr - pbss_entry->pbeacon_buf);
                        break;
                    case HE_OPERATION:
                        pbss_entry->phe_oprat       = pext_tlv;
                        pbss_entry->he_oprat_offset = (t_u16)(pcurrent_ptr - pbss_entry->pbeacon_buf);
                        break;
                    default:
                        PRINTM(MINFO, "Unexpected extension id\n");
                        break;
                }
                break;
#endif
            case RSNX_IE:
                (void)__memcpy(NULL, &pbss_entry->rsnx_ie_saved, pcurrent_ptr, sizeof(pbss_entry->rsnx_ie_saved));
                pbss_entry->prsnx_ie = &pbss_entry->rsnx_ie_saved;
                wscan_d("RSNX_IE: tag len %d data 0x%02x", pbss_entry->prsnx_ie->ieee_hdr.len,
                        pbss_entry->prsnx_ie->data[0]);
                break;

            default:
                PRINTM(MINFO, "Unexpected IE \n");
                break;
        }

        pcurrent_ptr += element_len + 2U;

        /* Need to account for IE ID and IE Len */
        bytes_left_for_current_beacon -= (element_len + 2U);

    } /* while (bytes_left_for_current_beacon > 2) */

    if (wifi_check_bss_entry_wpa2_entp_only(pbss_entry, SSID) != MLAN_STATUS_SUCCESS)
    {
        return MLAN_STATUS_RESOURCE;
    }

    LEAVE();
    return ret;
}

#ifndef CONFIG_MLAN_WMSDK
/**
 *  @brief Adjust ie's position in BSSDescriptor_t
 *
 *  @param pmpriv       A pointer to mlan_private structure
 *  @param pbss_entry   A pointer to BSSDescriptor_t structure
 *
 *  @return           N/A
 */
static t_void wlan_adjust_ie_in_bss_entry(IN mlan_private *pmpriv, IN BSSDescriptor_t *pbss_entry)
{
    ENTER();
    if (pbss_entry->pbeacon_buf)
    {
        if (pbss_entry->pwpa_ie)
        {
            pbss_entry->pwpa_ie = (IEEEtypes_VendorSpecific_t *)(pbss_entry->pbeacon_buf + pbss_entry->wpa_offset);
        }
        if (pbss_entry->prsn_ie)
        {
            pbss_entry->prsn_ie = (IEEEtypes_Generic_t *)(pbss_entry->pbeacon_buf + pbss_entry->rsn_offset);
        }
        if (pbss_entry->pwapi_ie)
        {
            pbss_entry->pwapi_ie = (IEEEtypes_Generic_t *)(pbss_entry->pbeacon_buf + pbss_entry->wapi_offset);
        }
        if (pbss_entry->pht_cap)
        {
            pbss_entry->pht_cap = (IEEEtypes_HTCap_t *)(pbss_entry->pbeacon_buf + pbss_entry->ht_cap_offset);
        }
        if (pbss_entry->pht_info)
        {
            pbss_entry->pht_info = (IEEEtypes_HTInfo_t *)(pbss_entry->pbeacon_buf + pbss_entry->ht_info_offset);
        }
        if (pbss_entry->pbss_co_2040)
        {
            pbss_entry->pbss_co_2040 =
                (IEEEtypes_2040BSSCo_t *)(pbss_entry->pbeacon_buf + pbss_entry->bss_co_2040_offset);
        }
        if (pbss_entry->pext_cap)
        {
            pbss_entry->pext_cap = (IEEEtypes_ExtCap_t *)(pbss_entry->pbeacon_buf + pbss_entry->ext_cap_offset);
        }
        if (pbss_entry->poverlap_bss_scan_param)
        {
            pbss_entry->poverlap_bss_scan_param =
                (IEEEtypes_OverlapBSSScanParam_t *)(pbss_entry->pbeacon_buf + pbss_entry->overlap_bss_offset);
        }
    }
    else
    {
        pbss_entry->pwpa_ie                 = MNULL;
        pbss_entry->wpa_offset              = 0;
        pbss_entry->prsn_ie                 = MNULL;
        pbss_entry->rsn_offset              = 0;
        pbss_entry->pwapi_ie                = MNULL;
        pbss_entry->wapi_offset             = 0;
        pbss_entry->pht_cap                 = MNULL;
        pbss_entry->ht_cap_offset           = 0;
        pbss_entry->pht_info                = MNULL;
        pbss_entry->ht_info_offset          = 0;
        pbss_entry->pbss_co_2040            = MNULL;
        pbss_entry->bss_co_2040_offset      = 0;
        pbss_entry->pext_cap                = MNULL;
        pbss_entry->ext_cap_offset          = 0;
        pbss_entry->poverlap_bss_scan_param = MNULL;
        pbss_entry->overlap_bss_offset      = 0;
    }
    LEAVE();
    return;
}

/**
 *  @brief Store a beacon or probe response for a BSS returned in the scan
 *
 *  Store a new scan response or an update for a previous scan response.  New
 *    entries need to verify that they do not exceed the total amount of
 *    memory allocated for the table.

 *  Replacement entries need to take into consideration the amount of space
 *    currently allocated for the beacon/probe response and adjust the entry
 *    as needed.
 *
 *  A small amount of extra pad (SCAN_BEACON_ENTRY_PAD) is generally reserved
 *    for an entry in case it is a beacon since a probe response for the
 *    network will by larger per the standard.  This helps to reduce the
 *    amount of memory copying to fit a new probe response into an entry
 *    already occupied by a network's previously stored beacon.
 *
 *  @param pmpriv       A pointer to mlan_private structure
 *  @param beacon_idx   Index in the scan table to store this entry; may be
 *                      replacing an older duplicate entry for this BSS
 *  @param num_of_ent   Number of entries currently in the table
 *  @param pnew_beacon  Pointer to the new beacon/probe response to save
 *
 *  @return           N/A
 */
static t_void wlan_ret_802_11_scan_store_beacon(IN mlan_private *pmpriv,
                                                IN t_u32 beacon_idx,
                                                IN t_u32 num_of_ent,
                                                IN BSSDescriptor_t *pnew_beacon)
{
    mlan_adapter *pmadapter = pmpriv->adapter;
    t_u8 *pbcn_store;
    t_u32 new_bcn_size;
    t_u32 old_bcn_size;
    t_u32 bcn_space;
    t_u32 adj_idx;
    mlan_status ret = MLAN_STATUS_SUCCESS;
    t_u8 *tmp_buf;
    t_u16 bcn_size   = 0;
    t_u32 bcn_offset = 0;

    ENTER();

    if (pmadapter->pscan_table[beacon_idx].pbeacon_buf)
    {
        new_bcn_size = pnew_beacon->beacon_buf_size;
        old_bcn_size = pmadapter->pscan_table[beacon_idx].beacon_buf_size;
        bcn_space    = pmadapter->pscan_table[beacon_idx].beacon_buf_size_max;
        pbcn_store   = pmadapter->pscan_table[beacon_idx].pbeacon_buf;

        /* Set the max to be the same as current entry unless changed below */
        pnew_beacon->beacon_buf_size_max = bcn_space;

        if (new_bcn_size == old_bcn_size)
        {
            /*
             * Beacon is the same size as the previous entry.
             *   Replace the previous contents with the scan result
             */
            (void)__memcpy(pmadapter, pbcn_store, pnew_beacon->pbeacon_buf, pnew_beacon->beacon_buf_size);
        }
        else if (new_bcn_size <= bcn_space)
        {
            /*
             * New beacon size will fit in the amount of space
             *   we have previously allocated for it
             */

            /* Copy the new beacon buffer entry over the old one */
            (void)__memcpy(pmadapter, pbcn_store, pnew_beacon->pbeacon_buf, new_bcn_size);

            /*
             *  If the old beacon size was less than the maximum
             *  we had allotted for the entry, and the new entry
             *  is even smaller, reset the max size to the old beacon
             *  entry and compress the storage space (leaving a new
             *  pad space of (old_bcn_size - new_bcn_size).
             */
            if (old_bcn_size < bcn_space && new_bcn_size <= old_bcn_size)
            {
                /*
                 * Old Beacon size is smaller than the allotted storage size.
                 *   Shrink the allotted storage space.
                 */
                PRINTM(MINFO,
                       "AppControl: Smaller Duplicate Beacon (%d), "
                       "old = %d, new = %d, space = %d, left = %d\n",
                       beacon_idx, old_bcn_size, new_bcn_size, bcn_space,
                       (pmadapter->bcn_buf_size - (pmadapter->pbcn_buf_end - pmadapter->bcn_buf)));

                /*
                 *  memmove (since the memory overlaps) the data
                 *  after the beacon we just stored to the end of
                 *  the current beacon.  This cleans up any unused
                 *  space the old larger beacon was using in the buffer
                 */
                (void)__memmove(pmadapter, (void *)((t_ptr)pbcn_store + (t_ptr)old_bcn_size),
                                (void *)((t_ptr)pbcn_store + (t_ptr)bcn_space),
                                (t_u32)((t_ptr)pmadapter->pbcn_buf_end - ((t_ptr)pbcn_store + (t_ptr)bcn_space)));

                /*
                 * Decrement the end pointer by the difference between
                 *  the old larger size and the new smaller size since
                 *  we are using less space due to the new beacon being
                 *  smaller
                 */
                pmadapter->pbcn_buf_end -= (bcn_space - old_bcn_size);

                /* Set the maximum storage size to the old beacon size */
                pnew_beacon->beacon_buf_size_max = old_bcn_size;

                /* Adjust beacon buffer pointers that are past the current */
                for (adj_idx = 0; adj_idx < num_of_ent; adj_idx++)
                {
                    if (pmadapter->pscan_table[adj_idx].pbeacon_buf > pbcn_store)
                    {
                        pmadapter->pscan_table[adj_idx].pbeacon_buf -= (bcn_space - old_bcn_size);
                        wlan_adjust_ie_in_bss_entry(pmpriv, &pmadapter->pscan_table[adj_idx]);
                    }
                }
            }
        }
        else if (pmadapter->pbcn_buf_end + (new_bcn_size - bcn_space) < (pmadapter->bcn_buf + pmadapter->bcn_buf_size))
        {
            /*
             * Beacon is larger than space previously allocated (bcn_space)
             *   and there is enough space left in the beaconBuffer to store
             *   the additional data
             */
            PRINTM(MINFO,
                   "AppControl: Larger Duplicate Beacon (%d), "
                   "old = %d, new = %d, space = %d, left = %d\n",
                   beacon_idx, old_bcn_size, new_bcn_size, bcn_space,
                   (pmadapter->bcn_buf_size - (pmadapter->pbcn_buf_end - pmadapter->bcn_buf)));

            /*
             * memmove (since the memory overlaps) the data
             *  after the beacon we just stored to the end of
             *  the current beacon.  This moves the data for
             *  the beacons after this further in memory to
             *  make space for the new larger beacon we are
             *  about to copy in.
             */
            (void)__memmove(pmadapter, (void *)((t_ptr)pbcn_store + (t_ptr)new_bcn_size),
                            (void *)((t_ptr)pbcn_store + (t_ptr)bcn_space),
                            (t_u32)((t_ptr)pmadapter->pbcn_buf_end - ((t_ptr)pbcn_store + (t_ptr)bcn_space)));

            /* Copy the new beacon buffer entry over the old one */
            (void)__memcpy(pmadapter, pbcn_store, pnew_beacon->pbeacon_buf, new_bcn_size);

            /* Move the beacon end pointer by the amount of new beacon data we
               are adding */
            pmadapter->pbcn_buf_end += (new_bcn_size - bcn_space);

            /*
             * This entry is bigger than the allotted max space
             *  previously reserved.  Increase the max space to
             *  be equal to the new beacon size
             */
            pnew_beacon->beacon_buf_size_max = new_bcn_size;

            /* Adjust beacon buffer pointers that are past the current */
            for (adj_idx = 0; adj_idx < num_of_ent; adj_idx++)
            {
                if (pmadapter->pscan_table[adj_idx].pbeacon_buf > pbcn_store)
                {
                    pmadapter->pscan_table[adj_idx].pbeacon_buf += (new_bcn_size - bcn_space);
                    wlan_adjust_ie_in_bss_entry(pmpriv, &pmadapter->pscan_table[adj_idx]);
                }
            }
        }
        else
        {
            /*
             * Beacon is larger than the previously allocated space, but
             *   there is not enough free space to store the additional data
             */
            PRINTM(MERROR,
                   "AppControl: Failed: Larger Duplicate Beacon (%d),"
                   " old = %d, new = %d, space = %d, left = %d\n",
                   beacon_idx, old_bcn_size, new_bcn_size, bcn_space,
                   (pmadapter->bcn_buf_size - (pmadapter->pbcn_buf_end - pmadapter->bcn_buf)));

            /* Storage failure, keep old beacon intact */
            pnew_beacon->beacon_buf_size = old_bcn_size;
            if (pnew_beacon->pwpa_ie)
                pnew_beacon->wpa_offset = pmadapter->pscan_table[beacon_idx].wpa_offset;
            if (pnew_beacon->prsn_ie)
                pnew_beacon->rsn_offset = pmadapter->pscan_table[beacon_idx].rsn_offset;
            if (pnew_beacon->pwapi_ie)
                pnew_beacon->wapi_offset = pmadapter->pscan_table[beacon_idx].wapi_offset;
            if (pnew_beacon->pht_cap)
                pnew_beacon->ht_cap_offset = pmadapter->pscan_table[beacon_idx].ht_cap_offset;
            if (pnew_beacon->pht_info)
                pnew_beacon->ht_info_offset = pmadapter->pscan_table[beacon_idx].ht_info_offset;
            if (pnew_beacon->pbss_co_2040)
                pnew_beacon->bss_co_2040_offset = pmadapter->pscan_table[beacon_idx].bss_co_2040_offset;
            if (pnew_beacon->pext_cap)
                pnew_beacon->ext_cap_offset = pmadapter->pscan_table[beacon_idx].ext_cap_offset;
            if (pnew_beacon->poverlap_bss_scan_param)
                pnew_beacon->overlap_bss_offset = pmadapter->pscan_table[beacon_idx].overlap_bss_offset;
        }
        /* Point the new entry to its permanent storage space */
        pnew_beacon->pbeacon_buf = pbcn_store;
        wlan_adjust_ie_in_bss_entry(pmpriv, pnew_beacon);
    }
    else
    {
        if ((pmadapter->pbcn_buf_end + pnew_beacon->beacon_buf_size + SCAN_BEACON_ENTRY_PAD >
             (pmadapter->bcn_buf + pmadapter->bcn_buf_size)) &&
            (pmadapter->bcn_buf_size < MAX_SCAN_BEACON_BUFFER))
        {
            /* no space for this entry, realloc bcn buffer */
            ret = pmadapter->callbacks.moal_malloc(pmadapter->pmoal_handle,
                                                   pmadapter->bcn_buf_size + DEFAULT_SCAN_BEACON_BUFFER, MLAN_MEM_DEF,
                                                   (t_u8 **)&tmp_buf);
            if ((ret == MLAN_STATUS_SUCCESS) && (tmp_buf))
            {
                PRINTM(MCMND, "Realloc Beacon buffer, old size=%d, new_size=%d\n", pmadapter->bcn_buf_size,
                       pmadapter->bcn_buf_size + DEFAULT_SCAN_BEACON_BUFFER);
                bcn_size = pmadapter->pbcn_buf_end - pmadapter->bcn_buf;
                (void)__memcpy(pmadapter, tmp_buf, pmadapter->bcn_buf, bcn_size);
                /* Adjust beacon buffer pointers that are past the current */
                for (adj_idx = 0; adj_idx < num_of_ent; adj_idx++)
                {
                    bcn_offset = pmadapter->pscan_table[adj_idx].pbeacon_buf - pmadapter->bcn_buf;
                    pmadapter->pscan_table[adj_idx].pbeacon_buf = tmp_buf + bcn_offset;
                    wlan_adjust_ie_in_bss_entry(pmpriv, &pmadapter->pscan_table[adj_idx]);
                }
                pmadapter->pbcn_buf_end = tmp_buf + bcn_size;
                pmadapter->callbacks.moal_mfree(pmadapter->pmoal_handle, (t_u8 *)pmadapter->bcn_buf);
                pmadapter->bcn_buf = tmp_buf;
                pmadapter->bcn_buf_size += DEFAULT_SCAN_BEACON_BUFFER;
            }
        }
        /*
         * No existing beacon data exists for this entry, check to see
         *   if we can fit it in the remaining space
         */
        if (pmadapter->pbcn_buf_end + pnew_beacon->beacon_buf_size + SCAN_BEACON_ENTRY_PAD <
            (pmadapter->bcn_buf + pmadapter->bcn_buf_size))
        {
            /*
             * Copy the beacon buffer data from the local entry to the
             *   adapter dev struct buffer space used to store the raw
             *   beacon data for each entry in the scan table
             */
            (void)__memcpy(pmadapter, pmadapter->pbcn_buf_end, pnew_beacon->pbeacon_buf, pnew_beacon->beacon_buf_size);

            /* Update the beacon ptr to point to the table save area */
            pnew_beacon->pbeacon_buf         = pmadapter->pbcn_buf_end;
            pnew_beacon->beacon_buf_size_max = (pnew_beacon->beacon_buf_size + SCAN_BEACON_ENTRY_PAD);
            wlan_adjust_ie_in_bss_entry(pmpriv, pnew_beacon);

            /* Increment the end pointer by the size reserved */
            pmadapter->pbcn_buf_end += pnew_beacon->beacon_buf_size_max;

            PRINTM(MINFO,
                   "AppControl: Beacon[%02d] sz=%03d,"
                   " used = %04d, left = %04d\n",
                   beacon_idx, pnew_beacon->beacon_buf_size, (pmadapter->pbcn_buf_end - pmadapter->bcn_buf),
                   (pmadapter->bcn_buf_size - (pmadapter->pbcn_buf_end - pmadapter->bcn_buf)));
        }
        else
        {
            /*
             * No space for new beacon
             */
            PRINTM(MCMND,
                   "AppControl: No space beacon (%d): "
                   "%02x:%02x:%02x:%02x:%02x:%02x; sz=%03d, left=%03d\n",
                   beacon_idx, pnew_beacon->mac_address[0], pnew_beacon->mac_address[1], pnew_beacon->mac_address[2],
                   pnew_beacon->mac_address[3], pnew_beacon->mac_address[4], pnew_beacon->mac_address[5],
                   pnew_beacon->beacon_buf_size,
                   (pmadapter->bcn_buf_size - (pmadapter->pbcn_buf_end - pmadapter->bcn_buf)));

            /* Storage failure; clear storage records for this bcn */
            pnew_beacon->pbeacon_buf         = MNULL;
            pnew_beacon->beacon_buf_size     = 0;
            pnew_beacon->beacon_buf_size_max = 0;
            wlan_adjust_ie_in_bss_entry(pmpriv, pnew_beacon);
        }
    }

    LEAVE();
}

/**
 *  @brief Restore a beacon buffer of the current bss descriptor
 *
 *  @param pmpriv       A pointer to mlan_private structure
 *
 *  @return             N/A
 */
static t_void wlan_restore_curr_bcn(IN mlan_private *pmpriv)
{
    mlan_adapter *pmadapter    = pmpriv->adapter;
    mlan_callbacks *pcb        = (pmlan_callbacks)&pmadapter->callbacks;
    BSSDescriptor_t *pcurr_bss = &pmpriv->curr_bss_params.bss_descriptor;

    ENTER();

    if (pmpriv->pcurr_bcn_buf &&
        ((pmadapter->pbcn_buf_end + pmpriv->curr_bcn_size) < (pmadapter->bcn_buf + pmadapter->bcn_buf_size)))
    {
        pcb->moal_spin_lock(pmadapter->pmoal_handle, pmpriv->curr_bcn_buf_lock);

        /* restore the current beacon buffer */
        (void)__memcpy(pmadapter, pmadapter->pbcn_buf_end, pmpriv->pcurr_bcn_buf, pmpriv->curr_bcn_size);
        pcurr_bss->pbeacon_buf     = pmadapter->pbcn_buf_end;
        pcurr_bss->beacon_buf_size = pmpriv->curr_bcn_size;
        pmadapter->pbcn_buf_end += pmpriv->curr_bcn_size;

        /* adjust the pointers in the current bss descriptor */
        if (pcurr_bss->pwpa_ie)
        {
            pcurr_bss->pwpa_ie = (IEEEtypes_VendorSpecific_t *)(pcurr_bss->pbeacon_buf + pcurr_bss->wpa_offset);
        }
        if (pcurr_bss->prsn_ie)
        {
            pcurr_bss->prsn_ie = (IEEEtypes_Generic_t *)(pcurr_bss->pbeacon_buf + pcurr_bss->rsn_offset);
        }
        if (pcurr_bss->pht_cap)
        {
            pcurr_bss->pht_cap = (IEEEtypes_HTCap_t *)(pcurr_bss->pbeacon_buf + pcurr_bss->ht_cap_offset);
        }

        if (pcurr_bss->pht_info)
        {
            pcurr_bss->pht_info = (IEEEtypes_HTInfo_t *)(pcurr_bss->pbeacon_buf + pcurr_bss->ht_info_offset);
        }

        if (pcurr_bss->pbss_co_2040)
        {
            pcurr_bss->pbss_co_2040 = (IEEEtypes_2040BSSCo_t *)(pcurr_bss->pbeacon_buf + pcurr_bss->bss_co_2040_offset);
        }

        if (pcurr_bss->pext_cap)
        {
            pcurr_bss->pext_cap = (IEEEtypes_ExtCap_t *)(pcurr_bss->pbeacon_buf + pcurr_bss->ext_cap_offset);
        }

        if (pcurr_bss->poverlap_bss_scan_param)
        {
            pcurr_bss->poverlap_bss_scan_param =
                (IEEEtypes_OverlapBSSScanParam_t *)(pcurr_bss->pbeacon_buf + pcurr_bss->overlap_bss_offset);
        }

        pcb->moal_spin_unlock(pmadapter->pmoal_handle, pmpriv->curr_bcn_buf_lock);

        PRINTM(MINFO, "current beacon restored %d\n", pmpriv->curr_bcn_size);
    }
    else
    {
        PRINTM(MWARN, "curr_bcn_buf not saved or bcn_buf has no space\n");
    }

    LEAVE();
}
#endif /* CONFIG_MLAN_WMSDK */

#ifdef SCAN_CHANNEL_GAP
/**
 *  @brief get the chan load from chan stats.
 *
 *  @param pmadapter    A pointer to mlan_adapter structure
 *  @param channel      channel  *
 *
 *  @return             channel load
 */
static t_u16 wlan_get_chan_load(mlan_adapter *pmadapter, t_u8 channel)
{
    t_u16 chan_load = 0;
    int i;
    for (i = 0; i < (int)pmadapter->num_in_chan_stats; i++)
    {
        if ((pmadapter->pchan_stats[i].chan_num == channel) && pmadapter->pchan_stats[i].cca_scan_duration)
        {
            chan_load =
                (pmadapter->pchan_stats[i].cca_busy_duration * 100) / pmadapter->pchan_stats[i].cca_scan_duration;
            break;
        }
    }
    return chan_load;
}

static t_u16 wlan_get_chan_noise(mlan_adapter *pmadapter, t_u8 channel)
{
    t_u16 chan_noise = 0;
    int i;
    for (i = 0; i < (int)pmadapter->num_in_chan_stats; i++)
    {
        if ((pmadapter->pchan_stats[i].chan_num == channel) && pmadapter->pchan_stats[i].noise)
        {
            chan_noise = pmadapter->pchan_stats[i].noise;
            break;
        }
    }
    return chan_noise;
}

/**
 *  @brief get the chan min/max rssi
 *
 *  @param pmadapter    A pointer to mlan_adapter structure
 *  @param channel      channel  *
 *  @param min_flag     flag to get min rssi
 *  @return             rssi
 */
static t_u8 wlan_get_chan_rssi(mlan_adapter *pmadapter, t_u8 channel, t_u8 min_flag)
{
    t_u8 rssi = 0;
    int i;
    for (i = 0; i < (int)pmadapter->num_in_scan_table; i++)
    {
        if (pmadapter->pscan_table[i].channel == channel)
        {
            if (rssi == 0)
                rssi = (t_s32)pmadapter->pscan_table[i].rssi;
            else
            {
                if (min_flag)
                    rssi = MIN(rssi, pmadapter->pscan_table[i].rssi);
                else
                    rssi = MAX(rssi, pmadapter->pscan_table[i].rssi);
            }
        }
    }
    return rssi;
}

/**
 *  @brief update the min/max rssi for channel statistics.
 *
 *  @param pmadapter    A pointer to mlan_adapter structure
 *	@return             N/A
 */
static t_void wlan_update_chan_rssi(mlan_adapter *pmadapter)
{
    int i;
    t_s8 min_rssi = 0;
    t_s8 max_rssi = 0;
    t_s8 rss      = 0;
    for (i = 0; i < (int)pmadapter->num_in_chan_stats; i++)
    {
        if (pmadapter->pchan_stats[i].chan_num && pmadapter->pchan_stats[i].cca_scan_duration)
        {
            min_rssi = -wlan_get_chan_rssi(pmadapter, pmadapter->pchan_stats[i].chan_num, MFALSE);
            max_rssi = -wlan_get_chan_rssi(pmadapter, pmadapter->pchan_stats[i].chan_num, MTRUE);
            rss      = min_rssi - pmadapter->pchan_stats[i].noise;
            // rss should always > 0, FW need fix the wrong
            // rssi/noise in scantable
            if (rss > 0)
                pmadapter->pchan_stats[i].min_rss = rss;
            else
                pmadapter->pchan_stats[i].min_rss = 0;

            rss = max_rssi - pmadapter->pchan_stats[i].noise;
            if (rss > 0)
                pmadapter->pchan_stats[i].max_rss = rss;
            else
                pmadapter->pchan_stats[i].max_rss = 0;
            PRINTM(MCMND, "chan=%d, min_rssi=%d, max_rssi=%d noise=%d min_rss=%d, max_rss=%d\n",
                   pmadapter->pchan_stats[i].chan_num, min_rssi, max_rssi, pmadapter->pchan_stats[i].noise,
                   pmadapter->pchan_stats[i].min_rss, pmadapter->pchan_stats[i].max_rss);
        }
    }
    return;
}
#endif

/**
 *  @brief Post process the scan table after a new scan command has completed
 *
 *  Inspect each entry of the scan table and try to find an entry that
 *    matches our current associated/joined network from the scan.  If
 *    one is found, update the stored copy of the BSSDescriptor for our
 *    current network.
 *
 *  Debug dump the current scan table contents if compiled accordingly.
 *
 *  @param pmpriv       A pointer to mlan_private structure
 *
 *  @return             N/A
 */
/* static */ void wlan_scan_process_results(IN mlan_private *pmpriv)
{
    mlan_adapter *pmadapter = pmpriv->adapter;
    t_u32 i;

#ifndef CONFIG_MLAN_WMSDK
    t_s32 j;

    ENTER();

    /* wmsdk: Not needed right now */
    if (pmpriv->media_connected == MTRUE)
    {
        j = wlan_find_ssid_in_list(pmpriv, &pmpriv->curr_bss_params.bss_descriptor.ssid,
                                   pmpriv->curr_bss_params.bss_descriptor.mac_address, pmpriv->bss_mode);

        if (j >= 0)
        {
            pmadapter->callbacks.moal_spin_lock(pmadapter->pmoal_handle, pmpriv->curr_bcn_buf_lock);
            pmpriv->curr_bss_params.bss_descriptor.pwpa_ie                 = MNULL;
            pmpriv->curr_bss_params.bss_descriptor.wpa_offset              = 0;
            pmpriv->curr_bss_params.bss_descriptor.prsn_ie                 = MNULL;
            pmpriv->curr_bss_params.bss_descriptor.rsn_offset              = 0;
            pmpriv->curr_bss_params.bss_descriptor.pwapi_ie                = MNULL;
            pmpriv->curr_bss_params.bss_descriptor.wapi_offset             = 0;
            pmpriv->curr_bss_params.bss_descriptor.pht_cap                 = MNULL;
            pmpriv->curr_bss_params.bss_descriptor.ht_cap_offset           = 0;
            pmpriv->curr_bss_params.bss_descriptor.pht_info                = MNULL;
            pmpriv->curr_bss_params.bss_descriptor.ht_info_offset          = 0;
            pmpriv->curr_bss_params.bss_descriptor.pbss_co_2040            = MNULL;
            pmpriv->curr_bss_params.bss_descriptor.bss_co_2040_offset      = 0;
            pmpriv->curr_bss_params.bss_descriptor.pext_cap                = MNULL;
            pmpriv->curr_bss_params.bss_descriptor.ext_cap_offset          = 0;
            pmpriv->curr_bss_params.bss_descriptor.poverlap_bss_scan_param = MNULL;
            pmpriv->curr_bss_params.bss_descriptor.overlap_bss_offset      = 0;
            pmpriv->curr_bss_params.bss_descriptor.pbeacon_buf             = MNULL;
            pmpriv->curr_bss_params.bss_descriptor.beacon_buf_size         = 0;
            pmpriv->curr_bss_params.bss_descriptor.beacon_buf_size_max     = 0;

            PRINTM(MINFO, "Found current ssid/bssid in list @ index #%d\n", j);
            /* Make a copy of current BSSID descriptor */
            (void)__memcpy(pmadapter, &pmpriv->curr_bss_params.bss_descriptor, &pmadapter->pscan_table[j],
                           sizeof(pmpriv->curr_bss_params.bss_descriptor));

            wlan_save_curr_bcn(pmpriv);
            pmadapter->callbacks.moal_spin_unlock(pmadapter->pmoal_handle, pmpriv->curr_bcn_buf_lock);
        }
        else
        {
            wlan_restore_curr_bcn(pmpriv);
        }
    }
#endif /* CONFIG_MLAN_WMSDK */

    for (i = 0; i < pmadapter->num_in_scan_table; i++)
    {
        PRINTM(MINFO,
               "Scan:(%02d) %02x:%02x:%02x:%02x:%02x:%02x, "
               "RSSI[%03d], SSID[%s]\n",
               i, pmadapter->pscan_table[i].mac_address[0], pmadapter->pscan_table[i].mac_address[1],
               pmadapter->pscan_table[i].mac_address[2], pmadapter->pscan_table[i].mac_address[3],
               pmadapter->pscan_table[i].mac_address[4], pmadapter->pscan_table[i].mac_address[5],
               (t_s32)pmadapter->pscan_table[i].rssi, pmadapter->pscan_table[i].ssid.ssid);
#ifdef SCAN_CHANNEL_GAP
        pmadapter->pscan_table[i].chan_load  = wlan_get_chan_load(pmadapter, pmadapter->pscan_table[i].channel);
        pmadapter->pscan_table[i].chan_noise = wlan_get_chan_noise(pmadapter, pmadapter->pscan_table[i].channel);
#endif
    }
#ifdef SCAN_CHANNEL_GAP
    wlan_update_chan_rssi(pmadapter);
#endif
    /*
     * Prepares domain info from scan table and downloads the
     *   domain info command to the FW.
     */
    if (wlan_11d_support_is_enabled(pmpriv))
    {
        if (pmpriv->support_11d != NULL)
        {
            (void)pmpriv->support_11d->wlan_11d_prepare_dnld_domain_info_cmd_p(pmpriv);
        }
    }

    LEAVE();
}

#ifndef CONFIG_MLAN_WMSDK
/**
 *  @brief Delete a specific indexed entry from the scan table.
 *
 *  Delete the scan table entry indexed by table_idx.  Compact the remaining
 *    entries and adjust any buffering of beacon/probe response data
 *    if needed.
 *
 *  @param pmpriv       A pointer to mlan_private structure
 *  @param table_idx    Scan table entry index to delete from the table
 *
 *  @return             N/A
 *
 *  @pre                table_idx must be an index to a valid entry
 */
static t_void wlan_scan_delete_table_entry(IN mlan_private *pmpriv, IN t_s32 table_idx)
{
    mlan_adapter *pmadapter = pmpriv->adapter;
    t_u32 del_idx;
    t_u32 beacon_buf_adj;
    t_u8 *pbeacon_buf;

    ENTER();

    /*
     * Shift the saved beacon buffer data for the scan table back over the
     *   entry being removed.  Update the end of buffer pointer.  Save the
     *   deleted buffer allocation size for pointer adjustments for entries
     *   compacted after the deleted index.
     */
    beacon_buf_adj = pmadapter->pscan_table[table_idx].beacon_buf_size_max;

    PRINTM(MINFO, "Scan: Delete Entry %d, beacon buffer removal = %d bytes\n", table_idx, beacon_buf_adj);

    /* Check if the table entry had storage allocated for its beacon */
    if (beacon_buf_adj)
    {
        pbeacon_buf = pmadapter->pscan_table[table_idx].pbeacon_buf;

        /*
         * Remove the entry's buffer space, decrement the table end pointer
         *   by the amount we are removing
         */
        pmadapter->pbcn_buf_end -= beacon_buf_adj;

        PRINTM(MINFO, "Scan: Delete Entry %d, compact data: %p <- %p (sz = %d)\n", table_idx, pbeacon_buf,
               pbeacon_buf + beacon_buf_adj, pmadapter->pbcn_buf_end - pbeacon_buf);

        /*
         * Compact data storage.  Copy all data after the deleted entry's
         *   end address (pbeacon_buf + beacon_buf_adj) back to the original
         *   start address (pbeacon_buf).
         *
         * Scan table entries affected by the move will have their entry
         *   pointer adjusted below.
         *
         * Use memmove since the dest/src memory regions overlap.
         */
        (void)__memmove(pmadapter, pbeacon_buf, (void *)((t_ptr)pbeacon_buf + (t_ptr)beacon_buf_adj),
                        (t_u32)((t_ptr)pmadapter->pbcn_buf_end - (t_ptr)pbeacon_buf));
    }

    PRINTM(MINFO, "Scan: Delete Entry %d, num_in_scan_table = %d\n", table_idx, pmadapter->num_in_scan_table);

    /* Shift all of the entries after the table_idx back by one, compacting the
       table and removing the requested entry */
    for (del_idx = table_idx; (del_idx + 1) < pmadapter->num_in_scan_table; del_idx++)
    {
        /* Copy the next entry over this one */
        (void)__memcpy(pmadapter, pmadapter->pscan_table + del_idx, pmadapter->pscan_table + del_idx + 1,
                       sizeof(BSSDescriptor_t));

        /*
         * Adjust this entry's pointer to its beacon buffer based on the
         *   removed/compacted entry from the deleted index.  Don't decrement
         *   if the buffer pointer is MNULL (no data stored for this entry).
         */
        if (pmadapter->pscan_table[del_idx].pbeacon_buf)
        {
            pmadapter->pscan_table[del_idx].pbeacon_buf -= beacon_buf_adj;
            if (pmadapter->pscan_table[del_idx].pwpa_ie)
            {
                pmadapter->pscan_table[del_idx].pwpa_ie =
                    (IEEEtypes_VendorSpecific_t *)(pmadapter->pscan_table[del_idx].pbeacon_buf +
                                                   pmadapter->pscan_table[del_idx].wpa_offset);
            }
            if (pmadapter->pscan_table[del_idx].prsn_ie)
            {
                pmadapter->pscan_table[del_idx].prsn_ie =
                    (IEEEtypes_Generic_t *)(pmadapter->pscan_table[del_idx].pbeacon_buf +
                                            pmadapter->pscan_table[del_idx].rsn_offset);
            }
            if (pmadapter->pscan_table[del_idx].pwapi_ie)
            {
                pmadapter->pscan_table[del_idx].pwapi_ie =
                    (IEEEtypes_Generic_t *)(pmadapter->pscan_table[del_idx].pbeacon_buf +
                                            pmadapter->pscan_table[del_idx].wapi_offset);
            }
            if (pmadapter->pscan_table[del_idx].pht_cap)
            {
                pmadapter->pscan_table[del_idx].pht_cap =
                    (IEEEtypes_HTCap_t *)(pmadapter->pscan_table[del_idx].pbeacon_buf +
                                          pmadapter->pscan_table[del_idx].ht_cap_offset);
            }

            if (pmadapter->pscan_table[del_idx].pht_info)
            {
                pmadapter->pscan_table[del_idx].pht_info =
                    (IEEEtypes_HTInfo_t *)(pmadapter->pscan_table[del_idx].pbeacon_buf +
                                           pmadapter->pscan_table[del_idx].ht_info_offset);
            }
            if (pmadapter->pscan_table[del_idx].pbss_co_2040)
            {
                pmadapter->pscan_table[del_idx].pbss_co_2040 =
                    (IEEEtypes_2040BSSCo_t *)(pmadapter->pscan_table[del_idx].pbeacon_buf +
                                              pmadapter->pscan_table[del_idx].bss_co_2040_offset);
            }
            if (pmadapter->pscan_table[del_idx].pext_cap)
            {
                pmadapter->pscan_table[del_idx].pext_cap =
                    (IEEEtypes_ExtCap_t *)(pmadapter->pscan_table[del_idx].pbeacon_buf +
                                           pmadapter->pscan_table[del_idx].ext_cap_offset);
            }
            if (pmadapter->pscan_table[del_idx].poverlap_bss_scan_param)
            {
                pmadapter->pscan_table[del_idx].poverlap_bss_scan_param =
                    (IEEEtypes_OverlapBSSScanParam_t *)(pmadapter->pscan_table[del_idx].pbeacon_buf +
                                                        pmadapter->pscan_table[del_idx].overlap_bss_offset);
            }
        }
    }

    /* The last entry is invalid now that it has been deleted or moved back */
    (void)__memset(pmadapter, pmadapter->pscan_table + pmadapter->num_in_scan_table - 1, 0x00, sizeof(BSSDescriptor_t));

    pmadapter->num_in_scan_table--;

    LEAVE();
}

/**
 *  @brief Delete all occurrences of a given SSID from the scan table
 *
 *  Iterate through the scan table and delete all entries that match a given
 *    SSID.  Compact the remaining scan table entries.
 *
 *  @param pmpriv       A pointer to mlan_private structure
 *  @param pdel_ssid    Pointer to an SSID to be used in deleting all
 *                        matching SSIDs from the scan table
 *
 *  @return             MLAN_STATUS_SUCCESS or MLAN_STATUS_FAILURE
 */
static mlan_status wlan_scan_delete_ssid_table_entry(IN mlan_private *pmpriv, IN mlan_802_11_ssid *pdel_ssid)
{
    mlan_status ret = MLAN_STATUS_FAILURE;
    t_s32 table_idx;

    ENTER();

    PRINTM(MINFO, "Scan: Delete Ssid Entry: %-32s\n", pdel_ssid->ssid);

    /* If the requested SSID is found in the table, delete it.  Then keep
       searching the table for multiple entries for the SSID until no more are
       found */
    while ((table_idx = wlan_find_ssid_in_list(pmpriv, pdel_ssid, MNULL, MLAN_BSS_MODE_AUTO)) >= 0)
    {
        PRINTM(MINFO, "Scan: Delete SSID Entry: Found Idx = %d\n", table_idx);
        ret = MLAN_STATUS_SUCCESS;
        wlan_scan_delete_table_entry(pmpriv, table_idx);
    }

    LEAVE();
    return ret;
}
#endif /* CONFIG_MLAN_WMSDK */
/********************************************************
                Global Functions
********************************************************/

/**
 *  @brief Check if a scanned network compatible with the driver settings
 *
 *   WEP     WPA     WPA2    ad-hoc  encrypt                      Network
 * enabled enabled  enabled   AES     mode   Privacy  WPA  WPA2  Compatible
 *    0       0        0       0      NONE      0      0    0   yes No security
 *    0       1        0       0       x        1x     1    x   yes WPA (disable HT if no AES)
 *    0       0        1       0       x        1x     x    1   yes WPA2 (disable HT if no AES)
 *    0       0        0       1      NONE      1      0    0   yes Ad-hoc AES
 *    1       0        0       0      NONE      1      0    0   yes Static WEP (disable HT)
 *    0       0        0       0     !=NONE     1      0    0   yes Dynamic WEP
 *
 *  @param pmpriv  A pointer to mlan_private
 *  @param index   Index in scan table to check against current driver settings
 *  @param mode    Network mode: Infrastructure or IBSS
 *
 *  @return        Index in ScanTable, or negative value if error
 */
t_s32 wlan_is_network_compatible(IN mlan_private *pmpriv, IN t_u32 index, IN mlan_bss_mode mode)
{
    mlan_adapter *pmadapter = pmpriv->adapter;
    BSSDescriptor_t *pbss_desc;

    ENTER();

    pbss_desc              = &pmadapter->pscan_table[index];
    pbss_desc->disable_11n = MFALSE;

    /* Don't check for compatibility if roaming */
    if ((pmpriv->media_connected == MTRUE) && (pmpriv->bss_mode == MLAN_BSS_MODE_INFRA) &&
        (pbss_desc->bss_mode == MLAN_BSS_MODE_INFRA))
    {
        LEAVE();
        return (t_s32)index;
    }

#ifdef CONFIG_11AC
    /* if the VHT CAP IE exists, the HT CAP IE should exist too */
    if ((pbss_desc->pvht_cap != MNULL) && (pbss_desc->pht_cap == MNULL))
    {
        PRINTM(MINFO, "Disable 11n if HT CAP IE is not found from the 11AC AP\n");
        pbss_desc->disable_11n = MTRUE;
    }
#endif
#ifdef CONFIG_11AX
    /* if the HE CAP IE exists, HT CAP IE should exist too */
    /* 2.4G AX AP, don't have VHT CAP */
    if (pbss_desc->phe_cap && !pbss_desc->pht_cap)
    {
        PRINTM(MINFO, "Disable 11n if VHT CAP/HT CAP IE is not found from the 11AX AP\n");
        pbss_desc->disable_11n = MTRUE;
    }
#endif

#ifndef CONFIG_MLAN_WMSDK
    if (pbss_desc->wlan_11h_bss_info.chan_switch_ann.element_id == CHANNEL_SWITCH_ANN)
    {
        PRINTM(MINFO, "Don't connect to AP with CHANNEL_SWITCH_ANN IE.\n");
        LEAVE();
        return -1;
    }
#endif /* CONFIG_MLAN_WMSDK */

    /* fixme: Disabled for now */
#ifndef CONFIG_MLAN_WMSDK
    if (pmpriv->wps.session_enable == MTRUE)
    {
        PRINTM(MINFO, "Return success directly in WPS period\n");
        LEAVE();
        return index;
    }
#endif /* CONFIG_MLAN_WMSDK */
#ifdef CONFIG_OWE
    if ((pbss_desc->owe_transition_mode == OWE_TRANS_MODE_OPEN) &&
        (pmpriv->sec_info.authentication_mode != MLAN_AUTH_MODE_OWE))
    {
        PRINTM(MINFO, "Return success directly in OWE Transition mode\n");
        LEAVE();
        return index;
    }
#endif
    if ((pbss_desc->bss_mode == mode) && (pmpriv->sec_info.ewpa_enabled == MTRUE))
    {
        if (((pbss_desc->pwpa_ie != MNULL) && ((*(pbss_desc->pwpa_ie)).vend_hdr.element_id == WPA_IE)) ||
            ((pbss_desc->prsn_ie != MNULL) && ((*(pbss_desc->prsn_ie)).ieee_hdr.element_id == RSN_IE)))
        {
            if (((pmpriv->adapter->config_bands & BAND_GN || pmpriv->adapter->config_bands & BAND_AN) &&
                 (pbss_desc->pht_cap != MNULL)) &&
                (pmpriv->bss_mode == MLAN_BSS_MODE_INFRA) &&
                !is_wpa_oui_present(pmpriv->adapter, pbss_desc, CIPHER_SUITE_CCMP) &&
                !is_rsn_oui_present(pmpriv->adapter, pbss_desc, CIPHER_SUITE_CCMP))
            {
                if (is_wpa_oui_present(pmpriv->adapter, pbss_desc, CIPHER_SUITE_TKIP) ||
                    is_rsn_oui_present(pmpriv->adapter, pbss_desc, CIPHER_SUITE_TKIP))
                {
                    PRINTM(MINFO, "Disable 11n if AES is not supported by AP\n");
                    pbss_desc->disable_11n = MTRUE;
                }
                else
                {
                    LEAVE();
                    return -1;
                }
            }
            LEAVE();
            return (t_s32)index;
        }
        else
        {
            PRINTM(MINFO, "ewpa_enabled: Ignore none WPA/WPA2 AP\n");
            LEAVE();
            return -1;
        }
    }

    if (pmpriv->sec_info.wapi_enabled &&
        ((pbss_desc->pwapi_ie != MNULL) && ((*(pbss_desc->pwapi_ie)).ieee_hdr.element_id == WAPI_IE)))
    {
        PRINTM(MINFO, "Return success for WAPI AP\n");
        LEAVE();
        return (t_s32)index;
    }

    if (pbss_desc->bss_mode == mode)
    {
        if (pmpriv->sec_info.wep_status == Wlan802_11WEPDisabled && !pmpriv->sec_info.wpa_enabled &&
            !pmpriv->sec_info.wpa2_enabled &&
            ((pbss_desc->pwpa_ie == MNULL) || ((*(pbss_desc->pwpa_ie)).vend_hdr.element_id != WPA_IE)) &&
            ((pbss_desc->prsn_ie == MNULL) || ((*(pbss_desc->prsn_ie)).ieee_hdr.element_id != RSN_IE)) &&
            !pmpriv->adhoc_aes_enabled && pmpriv->sec_info.encryption_mode == MLAN_ENCRYPTION_MODE_NONE &&
            !pbss_desc->privacy)
        {
            /* No security */
            LEAVE();
            return (t_s32)index;
        }
        else if (pmpriv->sec_info.wep_status == Wlan802_11WEPEnabled && !pmpriv->sec_info.wpa_enabled &&
                 !pmpriv->sec_info.wpa2_enabled && !pmpriv->adhoc_aes_enabled && pbss_desc->privacy)
        {
            /* Static WEP enabled */
            PRINTM(MINFO, "Disable 11n in WEP mode\n");
            pbss_desc->disable_11n = MTRUE;
            LEAVE();
            return (t_s32)index;
        }
        else if (pmpriv->sec_info.wep_status == Wlan802_11WEPDisabled && pmpriv->sec_info.wpa_enabled &&
                 !pmpriv->sec_info.wpa2_enabled &&
                 ((pbss_desc->pwpa_ie != MNULL) && ((*(pbss_desc->pwpa_ie)).vend_hdr.element_id == WPA_IE)) &&
                 !pmpriv->adhoc_aes_enabled
                 /*
                  * Privacy bit may NOT be set in some APs like LinkSys WRT54G
                  * && pbss_desc->privacy
                  */
        )
        {
            /* WPA enabled */
            PRINTM(MINFO,
                   "wlan_is_network_compatible() WPA: index=%d wpa_ie=%#x "
                   "rsn_ie=%#x WEP=%s WPA=%s WPA2=%s EncMode=%#x "
                   "privacy=%#x\n",
                   index, (pbss_desc->pwpa_ie) ? (*(pbss_desc->pwpa_ie)).vend_hdr.element_id : 0,
                   (pbss_desc->prsn_ie) ? (*(pbss_desc->prsn_ie)).ieee_hdr.element_id : 0,
                   (pmpriv->sec_info.wep_status == Wlan802_11WEPEnabled) ? "e" : "d",
                   (pmpriv->sec_info.wpa_enabled) ? "e" : "d", (pmpriv->sec_info.wpa2_enabled) ? "e" : "d",
                   pmpriv->sec_info.encryption_mode, pbss_desc->privacy);
            if (((pmpriv->adapter->config_bands & BAND_GN || pmpriv->adapter->config_bands & BAND_AN) &&
                 (pbss_desc->pht_cap != MNULL)) &&
                (pmpriv->bss_mode == MLAN_BSS_MODE_INFRA) &&
                !is_wpa_oui_present(pmpriv->adapter, pbss_desc, CIPHER_SUITE_CCMP))
            {
                if (is_wpa_oui_present(pmpriv->adapter, pbss_desc, CIPHER_SUITE_TKIP) != 0U)
                {
                    PRINTM(MINFO, "Disable 11n if AES is not supported by AP\n");
                    pbss_desc->disable_11n = MTRUE;
                }
                else
                {
                    LEAVE();
                    return -1;
                }
            }
            LEAVE();
            return (t_s32)index;
        }
        else if (pmpriv->sec_info.wep_status == Wlan802_11WEPDisabled && !pmpriv->sec_info.wpa_enabled &&
                 pmpriv->sec_info.wpa2_enabled &&
                 ((pbss_desc->prsn_ie != MNULL) && ((*(pbss_desc->prsn_ie)).ieee_hdr.element_id == RSN_IE)) &&
                 !pmpriv->adhoc_aes_enabled
                 /*
                  * Privacy bit may NOT be set in some APs like LinkSys WRT54G
                  * && pbss_desc->privacy
                  */
        )
        {
            /* WPA2 enabled */
            PRINTM(MINFO,
                   "wlan_is_network_compatible() WPA2: index=%d wpa_ie=%#x "
                   "rsn_ie=%#x WEP=%s WPA=%s WPA2=%s EncMode=%#x "
                   "privacy=%#x\n",
                   index, (pbss_desc->pwpa_ie) ? (*(pbss_desc->pwpa_ie)).vend_hdr.element_id : 0,
                   (pbss_desc->prsn_ie) ? (*(pbss_desc->prsn_ie)).ieee_hdr.element_id : 0,
                   (pmpriv->sec_info.wep_status == Wlan802_11WEPEnabled) ? "e" : "d",
                   (pmpriv->sec_info.wpa_enabled) ? "e" : "d", (pmpriv->sec_info.wpa2_enabled) ? "e" : "d",
                   pmpriv->sec_info.encryption_mode, pbss_desc->privacy);
            if (((pmpriv->adapter->config_bands & BAND_GN || pmpriv->adapter->config_bands & BAND_AN) &&
                 (pbss_desc->pht_cap != MNULL)) &&
                (pmpriv->bss_mode == MLAN_BSS_MODE_INFRA) &&
                !is_rsn_oui_present(pmpriv->adapter, pbss_desc, CIPHER_SUITE_CCMP))
            {
                if (is_rsn_oui_present(pmpriv->adapter, pbss_desc, CIPHER_SUITE_TKIP) != 0U)
                {
                    PRINTM(MINFO, "Disable 11n if AES is not supported by AP\n");
                    pbss_desc->disable_11n = MTRUE;
                }
                else
                {
                    LEAVE();
                    return -1;
                }
            }
            LEAVE();
            return (t_s32)index;
        }
        else if (pmpriv->sec_info.wep_status == Wlan802_11WEPDisabled && !pmpriv->sec_info.wpa_enabled &&
                 !pmpriv->sec_info.wpa2_enabled &&
                 ((pbss_desc->pwpa_ie == MNULL) || ((*(pbss_desc->pwpa_ie)).vend_hdr.element_id != WPA_IE)) &&
                 ((pbss_desc->prsn_ie == MNULL) || ((*(pbss_desc->prsn_ie)).ieee_hdr.element_id != RSN_IE)) &&
                 pmpriv->adhoc_aes_enabled && pmpriv->sec_info.encryption_mode == MLAN_ENCRYPTION_MODE_NONE &&
                 pbss_desc->privacy)
        {
            /* Ad-hoc AES enabled */
            LEAVE();
            return (t_s32)index;
        }
        else if (pmpriv->sec_info.wep_status == Wlan802_11WEPDisabled && !pmpriv->sec_info.wpa_enabled &&
                 !pmpriv->sec_info.wpa2_enabled &&
                 ((pbss_desc->pwpa_ie == MNULL) || ((*(pbss_desc->pwpa_ie)).vend_hdr.element_id != WPA_IE)) &&
                 ((pbss_desc->prsn_ie == MNULL) || ((*(pbss_desc->prsn_ie)).ieee_hdr.element_id != RSN_IE)) &&
                 !pmpriv->adhoc_aes_enabled && pmpriv->sec_info.encryption_mode != MLAN_ENCRYPTION_MODE_NONE &&
                 pbss_desc->privacy)
        {
            /* Dynamic WEP enabled */
            PRINTM(MINFO,
                   "wlan_is_network_compatible() dynamic WEP: index=%d "
                   "wpa_ie=%#x rsn_ie=%#x EncMode=%#x privacy=%#x\n",
                   index, (pbss_desc->pwpa_ie) ? (*(pbss_desc->pwpa_ie)).vend_hdr.element_id : 0,
                   (pbss_desc->prsn_ie) ? (*(pbss_desc->prsn_ie)).ieee_hdr.element_id : 0,
                   pmpriv->sec_info.encryption_mode, pbss_desc->privacy);
            LEAVE();
            return (t_s32)index;
        }

        else
        {
            /* Security doesn't match */
            PRINTM(MINFO,
                   "wlan_is_network_compatible() FAILED: index=%d wpa_ie=%#x "
                   "rsn_ie=%#x WEP=%s WPA=%s WPA2=%s EncMode=%#x privacy=%#x\n",
                   index, (pbss_desc->pwpa_ie) ? (*(pbss_desc->pwpa_ie)).vend_hdr.element_id : 0,
                   (pbss_desc->prsn_ie) ? (*(pbss_desc->prsn_ie)).ieee_hdr.element_id : 0,
                   (pmpriv->sec_info.wep_status == Wlan802_11WEPEnabled) ? "e" : "d",
                   (pmpriv->sec_info.wpa_enabled) ? "e" : "d", (pmpriv->sec_info.wpa2_enabled) ? "e" : "d",
                   pmpriv->sec_info.encryption_mode, pbss_desc->privacy);
            LEAVE();
            return -1;
        }
    }

    /* Mode doesn't match */
    LEAVE();
    return -1;
}

#ifndef CONFIG_MLAN_WMSDK
/**
 *  @brief Internal function used to flush the scan list
 *
 *  @param pmadapter    A pointer to mlan_adapter structure
 *
 *  @return             MLAN_STATUS_SUCCESS
 */
mlan_status wlan_flush_scan_table(IN pmlan_adapter pmadapter)
{
#ifdef SCAN_CHANNEL_GAP
    t_u8 i = 0;
#endif

    ENTER();

    PRINTM(MINFO, "Flushing scan table\n");

    (void)__memset(pmadapter, pmadapter->pscan_table, 0, (sizeof(BSSDescriptor_t) * MRVDRV_MAX_BSSID_LIST));
    pmadapter->num_in_scan_table = 0;

    (void)__memset(pmadapter, pmadapter->bcn_buf, 0, pmadapter->bcn_buf_size);
    pmadapter->pbcn_buf_end = pmadapter->bcn_buf;

#ifdef SCAN_CHANNEL_GAP
    for (i = 0; i < pmadapter->num_in_chan_stats; i++)
        pmadapter->pchan_stats[i].cca_scan_duration = 0;
    pmadapter->idx_chan_stats = 0;
#endif

    LEAVE();
    return MLAN_STATUS_SUCCESS;
}
#endif /* CONFIG_MLAN_WMSDK */

/**
 *  @brief Internal function used to start a scan based on an input config
 *
 *  Use the input user scan configuration information when provided in
 *    order to send the appropriate scan commands to firmware to populate or
 *    update the internal driver scan table
 *
 *  @param pmpriv          A pointer to mlan_private structure
 *  @param pioctl_buf      A pointer to MLAN IOCTL Request buffer
 *  @param puser_scan_in   Pointer to the input configuration for the requested
 *                         scan.
 *
 *  @return              MLAN_STATUS_SUCCESS or < 0 if error
 */
mlan_status wlan_scan_networks(IN mlan_private *pmpriv,
                               IN t_void *pioctl_buf,
                               IN const wlan_user_scan_cfg *puser_scan_in)
{
    mlan_status ret         = MLAN_STATUS_SUCCESS;
    mlan_adapter *pmadapter = pmpriv->adapter;
    mlan_callbacks *pcb     = (mlan_callbacks *)&pmadapter->callbacks;
    /* cmd_ctrl_node *pcmd_node = MNULL; */
    pmlan_ioctl_req pioctl_req = (mlan_ioctl_req *)pioctl_buf;

    wlan_scan_cmd_config_tlv *pscan_cfg_out = MNULL;
    MrvlIEtypes_ChanListParamSet_t *pchan_list_out;
    t_u32 buf_size;
    ChanScanParamSet_t *pscan_chan_list;

    t_u8 keep_previous_scan;
    t_u8 filtered_scan;
    t_u8 scan_current_chan_only;
    t_u8 max_chan_per_scan;

    ENTER();

    ret = pcb->moal_malloc(pmadapter->pmoal_handle, sizeof(wlan_scan_cmd_config_tlv), MLAN_MEM_DEF,
                           (t_u8 **)(void **)&pscan_cfg_out);
    if (ret != MLAN_STATUS_SUCCESS || (pscan_cfg_out == MNULL))
    {
        PRINTM(MERROR, "Memory allocation for pscan_cfg_out failed!\n");
        if (pioctl_req != MNULL)
        {
            pioctl_req->status_code = MLAN_ERROR_NO_MEM;
        }
        LEAVE();
        return MLAN_STATUS_FAILURE;
    }

    buf_size = sizeof(ChanScanParamSet_t) * WLAN_USER_SCAN_CHAN_MAX;
    ret      = pcb->moal_malloc(pmadapter->pmoal_handle, buf_size, MLAN_MEM_DEF, (t_u8 **)(void **)&pscan_chan_list);
    if (ret != MLAN_STATUS_SUCCESS || (pscan_chan_list == MNULL))
    {
        PRINTM(MERROR, "Failed to allocate scan_chan_list\n");
        (void)pcb->moal_mfree(pmadapter->pmoal_handle, (t_u8 *)pscan_cfg_out);
        if (pioctl_req != MNULL)
        {
            pioctl_req->status_code = MLAN_ERROR_NO_MEM;
        }
        LEAVE();
        return MLAN_STATUS_FAILURE;
    }

    (void)__memset(pmadapter, pscan_chan_list, 0x00, buf_size);
    (void)__memset(pmadapter, pscan_cfg_out, 0x00, sizeof(wlan_scan_cmd_config_tlv));

    keep_previous_scan = MFALSE;

    ret = wlan_scan_setup_scan_config(pmpriv, puser_scan_in, &pscan_cfg_out->config, &pchan_list_out, pscan_chan_list,
                                      &max_chan_per_scan, &filtered_scan, &scan_current_chan_only);
    if (ret != MLAN_STATUS_SUCCESS)
    {
        PRINTM(MERROR, "Failed to setup scan config\n");
        (void)pcb->moal_mfree(pmadapter->pmoal_handle, (t_u8 *)pscan_cfg_out);
        (void)pcb->moal_mfree(pmadapter->pmoal_handle, (t_u8 *)pscan_chan_list);
        if (pioctl_req != MNULL)
        {
            pioctl_req->status_code = MLAN_ERROR_INVALID_PARAMETER;
        }
        LEAVE();
        return MLAN_STATUS_FAILURE;
    }

    if (puser_scan_in != MNULL)
    {
        keep_previous_scan = puser_scan_in->keep_previous_scan;
    }

    if (keep_previous_scan == MFALSE)
    {
        (void)__memset(pmadapter, pmadapter->pscan_table, 0x00, sizeof(BSSDescriptor_t) * MRVDRV_MAX_BSSID_LIST);
        pmadapter->num_in_scan_table = 0;
#ifndef CONFIG_MLAN_WMSDK
        pmadapter->pbcn_buf_end = pmadapter->bcn_buf;
#endif /* CONFIG_MLAN_WMSDK */
    }

#ifdef SCAN_CHANNEL_GAP
    pmadapter->idx_chan_stats = 0;
#endif

    split_scan_in_progress = true;
    ret = wlan_scan_channel_list(pmpriv, pioctl_buf, max_chan_per_scan, filtered_scan, &pscan_cfg_out->config,
                                 pchan_list_out, pscan_chan_list);
    /* Get scan command from scan_pending_q and put to cmd_pending_q */
    if (ret == MLAN_STATUS_SUCCESS)
    {
        /* fixme: This functionality is not needed. Recheck later */
#ifndef CONFIG_MLAN_WMSDK
        if (util_peek_list(pmadapter->pmoal_handle, &pmadapter->scan_pending_q, pcb->moal_spin_lock,
                           pcb->moal_spin_unlock))
        {
            pcmd_node = (cmd_ctrl_node *)util_dequeue_list(pmadapter->pmoal_handle, &pmadapter->scan_pending_q,
                                                           pcb->moal_spin_lock, pcb->moal_spin_unlock);
            pmadapter->pext_scan_ioctl_req = pioctl_req;
            wlan_request_cmd_lock(pmadapter);
            pmadapter->scan_processing = MTRUE;
            wlan_release_cmd_lock(pmadapter);
            wlan_insert_cmd_to_pending_q(pmadapter, pcmd_node, MTRUE);
        }
#endif /* CONFIG_MLAN_WMSDK */
    }
    (void)pcb->moal_mfree(pmadapter->pmoal_handle, (t_u8 *)pscan_cfg_out);
    (void)pcb->moal_mfree(pmadapter->pmoal_handle, (t_u8 *)pscan_chan_list);

    LEAVE();
    return ret;
}

#ifndef CONFIG_EXT_SCAN_SUPPORT
/**
 *  @brief Prepare a scan command to be sent to the firmware
 *
 *  Use the wlan_scan_cmd_config sent to the command processing module in
 *   the wlan_prepare_cmd to configure a HostCmd_DS_802_11_SCAN command
 *   struct to send to firmware.
 *
 *  The fixed fields specifying the BSS type and BSSID filters as well as a
 *   variable number/length of TLVs are sent in the command to firmware.
 *
 *  @param pmpriv     A pointer to mlan_private structure
 *  @param pcmd       A pointer to HostCmd_DS_COMMAND structure to be sent to
 *                    firmware with the HostCmd_DS_801_11_SCAN structure
 *  @param pdata_buf  Void pointer cast of a wlan_scan_cmd_config struct used
 *                    to set the fields/TLVs for the command sent to firmware
 *
 *  @return           MLAN_STATUS_SUCCESS
 */
mlan_status wlan_cmd_802_11_scan(IN mlan_private *pmpriv, IN HostCmd_DS_COMMAND *pcmd, IN t_void *pdata_buf)
{
    HostCmd_DS_802_11_SCAN *pscan_cmd = &pcmd->params.scan;
    wlan_scan_cmd_config *pscan_cfg;

    ENTER();

    pscan_cfg = (wlan_scan_cmd_config *)pdata_buf;

    /* Set fixed field variables in scan command */
    pscan_cmd->bss_mode = pscan_cfg->bss_mode;
    (void)__memcpy(pmpriv->adapter, pscan_cmd->bssid, pscan_cfg->specific_bssid, sizeof(pscan_cmd->bssid));
    (void)__memcpy(pmpriv->adapter, pscan_cmd->tlv_buffer, pscan_cfg->tlv_buf, pscan_cfg->tlv_buf_len);

    pcmd->command = wlan_cpu_to_le16(HostCmd_CMD_802_11_SCAN);

    /* Size is equal to the sizeof(fixed portions) + the TLV len + header */
    pcmd->size = (t_u16)wlan_cpu_to_le16(
        (t_u16)(sizeof(pscan_cmd->bss_mode) + sizeof(pscan_cmd->bssid) + pscan_cfg->tlv_buf_len + S_DS_GEN));

    LEAVE();
    return MLAN_STATUS_SUCCESS;
}
#endif

/*
 * Fills the pointer variables with correct address.
 *
 * Original mlan stores the entire beacon. We cannot do that as it would
 * take approx 4K RAM per entry. Instead we have added some variables to
 * the original BSSDescriptor_t structure. These will keep the data needed
 * later. The pointers in this structure which would (ideally) point to
 * addresses in beacon buffer now point to these internal variables.
 *
 * Due beacon parsing a separate structure was used. That is mem-copied
 * into an entry in the static BSS_List. After this copy the internal
 * pointers still point to buffer addresses in the separate structure. We
 * will update them here.
 */
static void adjust_pointers_to_internal_buffers(BSSDescriptor_t *pbss_entry, BSSDescriptor_t *pbss_new_entry)
{
    if (pbss_entry->pht_cap != NULL)
    {
        pbss_entry->pht_cap = &pbss_entry->ht_cap_saved;
    }
    if (pbss_entry->pht_info != NULL)
    {
        pbss_entry->pht_info = &pbss_entry->ht_info_saved;
    }
#ifdef CONFIG_11AC
    if (pbss_entry->pvht_cap != NULL)
    {
        pbss_entry->pvht_cap = &pbss_entry->vht_cap_saved;
    }
    if (pbss_entry->pvht_oprat != NULL)
    {
        pbss_entry->pvht_oprat = &pbss_entry->vht_oprat_saved;
    }
    if (pbss_entry->pvht_txpower != NULL)
    {
        pbss_entry->pvht_txpower = &pbss_entry->vht_txpower_saved;
    }
    if (pbss_entry->ppoper_mode != NULL)
    {
        pbss_entry->ppoper_mode = &pbss_entry->poper_mode_saved;
    }
    if (pbss_entry->pext_cap != NULL)
    {
        pbss_entry->pext_cap = &pbss_entry->ext_cap_saved;
    }
#endif
    if (pbss_entry->pbss_co_2040 != NULL)
    {
        pbss_entry->pbss_co_2040 = &pbss_entry->bss_co_2040_saved;
    }
    if (pbss_entry->pwpa_ie != NULL)
    {
        pbss_entry->pwpa_ie = (IEEEtypes_VendorSpecific_t *)(void *)pbss_entry->wpa_ie_buff;
    }
    if (pbss_entry->prsn_ie != NULL)
    {
        pbss_entry->prsn_ie = (IEEEtypes_Generic_t *)(void *)pbss_entry->rsn_ie_buff;
    }
    if (pbss_entry->prsnx_ie != NULL)
    {
        pbss_entry->prsnx_ie = &pbss_entry->rsnx_ie_saved;
    }
#ifdef CONFIG_WPA_SUPP
    if (pbss_new_entry->ies != NULL)
    {
        if (pbss_entry->ies != NULL)
        {
            os_mem_free(pbss_entry->ies);
        }

        pbss_entry->ies = pbss_new_entry->ies;
    }
#endif
}

#if !defined(CONFIG_EXT_SCAN_SUPPORT) || defined(CONFIG_BG_SCAN)
/**
 *  @brief This function handles the command response of scan
 *
 *   The response buffer for the scan command has the following
 *      memory layout:
 *
 *     .-------------------------------------------------------------.
 *     |  Header (4 * sizeof(t_u16)):  Standard command response hdr |
 *     .-------------------------------------------------------------.
 *     |  BufSize (t_u16) : sizeof the BSS Description data          |
 *     .-------------------------------------------------------------.
 *     |  NumOfSet (t_u8) : Number of BSS Descs returned             |
 *     .-------------------------------------------------------------.
 *     |  BSSDescription data (variable, size given in BufSize)      |
 *     .-------------------------------------------------------------.
 *     |  TLV data (variable, size calculated using Header->Size,    |
 *     |            BufSize and sizeof the fixed fields above)       |
 *     .-------------------------------------------------------------.
 *
 *  @param pmpriv       A pointer to mlan_private structure
 *  @param resp         A pointer to HostCmd_DS_COMMAND
 *  @param pioctl_buf   A pointer to mlan_ioctl_req structure
 *
 *  @return             MLAN_STATUS_SUCCESS or MLAN_STATUS_FAILURE
 */
mlan_status wlan_ret_802_11_scan(IN mlan_private *pmpriv, IN HostCmd_DS_COMMAND *resp, IN t_void *pioctl_buf)
{
    mlan_status ret            = MLAN_STATUS_SUCCESS;
    mlan_adapter *pmadapter    = pmpriv->adapter;
    mlan_callbacks *pcb        = MNULL;
    mlan_ioctl_req *pioctl_req = (mlan_ioctl_req *)pioctl_buf;
    /* cmd_ctrl_node *pcmd_node = MNULL; */
    HostCmd_DS_802_11_SCAN_RSP *pscan_rsp = MNULL;
    BSSDescriptor_t *bss_new_entry        = MNULL;
    MrvlIEtypes_Data_t *ptlv;
    MrvlIEtypes_TsfTimestamp_t *ptsf_tlv = MNULL;
    t_u8 *pbss_info;
    t_u32 scan_resp_size;
    t_u32 bytes_left;
    t_u32 num_in_table;
    t_u32 bss_idx;
    t_u32 idx;
    t_u32 tlv_buf_size;
    t_u64 tsf_val;
    const chan_freq_power_t *cfp;
    MrvlIEtypes_ChanBandListParamSet_t *pchan_band_tlv = MNULL;
    ChanBandParamSet_t *pchan_band;
    t_u16 band;
#ifdef CONFIG_BG_SCAN
    t_u8 is_bgscan_resp;
#endif
    /* t_u32 age_ts_usec; */
    t_u32 lowest_rssi_index = 0;
#ifdef SCAN_CHANNEL_GAP
    MrvlIEtypes_ChannelStats_t *pchanstats_tlv = MNULL;
#endif
    t_u8 null_ssid[MLAN_MAX_SSID_LENGTH] = {0};

    ENTER();
    pcb = (pmlan_callbacks)&pmadapter->callbacks;
#ifdef CONFIG_BG_SCAN
    is_bgscan_resp = ((resp->command & HostCmd_CMD_ID_MASK) == HostCmd_CMD_802_11_BG_SCAN_QUERY);
    if (is_bgscan_resp)
    {
        pscan_rsp = &resp->params.bg_scan_query_resp.scan_resp;
    }
    else
#endif
    {
        pscan_rsp = &resp->params.scan_resp;
    }

    /* Note: We do not expect to have the entire list of AP's with us in
       the driver. This is because we are memory constrained. So will
       modify the handling of the AP list and keep only AP's with high RSSI */
#ifndef CONFIG_MLAN_WMSDK
    if (pscan_rsp->number_of_sets > MRVDRV_MAX_BSSID_LIST)
    {
        PRINTM(MERROR, "SCAN_RESP: Invalid number of AP returned (%d)!!\n", pscan_rsp->number_of_sets);
        if (pioctl_req)
            pioctl_req->status_code = MLAN_ERROR_CMD_SCAN_FAIL;
        ret = MLAN_STATUS_FAILURE;
        goto done;
    }
#endif /* CONFIG_MLAN_WMSDK */

    bytes_left = wlan_le16_to_cpu(pscan_rsp->bss_descript_size);
    PRINTM(MINFO, "SCAN_RESP: bss_descript_size %d\n", bytes_left);

    scan_resp_size = resp->size;

    PRINTM(MINFO, "SCAN_RESP: returned %d APs before parsing\n", pscan_rsp->number_of_sets);

    num_in_table = pmadapter->num_in_scan_table;
    pbss_info    = pscan_rsp->bss_desc_and_tlv_buffer;

    /*
     * The size of the TLV buffer is equal to the entire command response
     *   size (scan_resp_size) minus the fixed fields (sizeof()'s), the
     *   BSS Descriptions (bss_descript_size as bytesLef) and the command
     *   response header (S_DS_GEN)
     */
    tlv_buf_size = scan_resp_size - (bytes_left + sizeof(pscan_rsp->bss_descript_size) +
                                         sizeof(pscan_rsp->number_of_sets) + S_DS_GEN);

#ifdef CONFIG_BG_SCAN
    if (is_bgscan_resp && (tlv_buf_size > sizeof(resp->params.bg_scan_query_resp.report_condition)))
    {
        tlv_buf_size -= sizeof(resp->params.bg_scan_query_resp.report_condition);
    }
#endif
    ptlv = (MrvlIEtypes_Data_t *)(void *)(pscan_rsp->bss_desc_and_tlv_buffer + bytes_left);

    /* Search the TLV buffer space in the scan response for any valid TLVs */
    wlan_ret_802_11_scan_get_tlv_ptrs(pmadapter, ptlv, tlv_buf_size, TLV_TYPE_TSFTIMESTAMP,
                                      (MrvlIEtypes_Data_t **)(void **)&ptsf_tlv);

    /* Search the TLV buffer space in the scan response for any valid TLVs */
    wlan_ret_802_11_scan_get_tlv_ptrs(pmadapter, ptlv, tlv_buf_size, TLV_TYPE_CHANNELBANDLIST,
                                      (MrvlIEtypes_Data_t **)(void **)&pchan_band_tlv);

#ifdef SCAN_CHANNEL_GAP
    wlan_ret_802_11_scan_get_tlv_ptrs(pmadapter, ptlv, tlv_buf_size, TLV_TYPE_CHANNEL_STATS,
                                      (MrvlIEtypes_Data_t **)&pchanstats_tlv);

    if (pchanstats_tlv)
        wlan_update_chan_statistics(pmpriv, pchanstats_tlv);
#endif

    /*
     *  Process each scan response returned (pscan_rsp->number_of_sets).  Save
     *    the information in the bss_new_entry and then insert into the
     *    driver scan table either as an update to an existing entry
     *    or as an addition at the end of the table
     */
    ret = pcb->moal_malloc(pmadapter->pmoal_handle, sizeof(BSSDescriptor_t), MLAN_MEM_DEF,
                           (t_u8 **)(void **)&bss_new_entry);

    if (ret != MLAN_STATUS_SUCCESS || (bss_new_entry == MNULL))
    {
        PRINTM(MERROR, "Memory allocation for bss_new_entry failed!\n");
        if (pioctl_req != MNULL)
        {
            pioctl_req->status_code = MLAN_ERROR_NO_MEM;
        }
        ret = MLAN_STATUS_FAILURE;
        goto done;
    }

    idx = 0;
    while (idx < pscan_rsp->number_of_sets && bytes_left)
    {
        /* Zero out the bss_new_entry we are about to store info in */
        (void)__memset(pmadapter, bss_new_entry, 0x00, sizeof(BSSDescriptor_t));

        /* Process the data fields and IEs returned for this BSS */
        if (wlan_interpret_bss_desc_with_ie(pmadapter, bss_new_entry, &pbss_info, &bytes_left, MFALSE) ==
            MLAN_STATUS_SUCCESS)
        {
            wscan_d("SCAN_RESP: BSSID = %02x:%02x:%02x:%02x:%02x:%02x", bss_new_entry->mac_address[0],
                    bss_new_entry->mac_address[1], bss_new_entry->mac_address[2], bss_new_entry->mac_address[3],
                    bss_new_entry->mac_address[4], bss_new_entry->mac_address[5]);

            /*
             * Search the scan table for the same bssid
             */
            for (bss_idx = 0; bss_idx < num_in_table; bss_idx++)
            {
                if (!__memcmp(pmadapter, bss_new_entry->mac_address, pmadapter->pscan_table[bss_idx].mac_address,
                              sizeof(bss_new_entry->mac_address)))
                {
                    /*
                     * If the SSID matches as well, it is a duplicate of
                     *   this entry.  Keep the bss_idx set to this
                     *   entry so we replace the old contents in the table
                     */
                    if ((bss_new_entry->ssid.ssid_len == pmadapter->pscan_table[bss_idx].ssid.ssid_len) &&
                        (!__memcmp(pmadapter, bss_new_entry->ssid.ssid, pmadapter->pscan_table[bss_idx].ssid.ssid,
                                   bss_new_entry->ssid.ssid_len)))
                    {
                        wscan_d("SCAN_RESP: Duplicate of index: %d", bss_idx);
                        break;
                    }
                    /*
                     * If the SSID is NULL for same BSSID
                     * keep the bss_idx set to this entry
                     * so we replace the old contents in
                     * the table
                     */
                    if (!__memcmp(pmadapter, pmadapter->pscan_table[bss_idx].ssid.ssid, null_ssid,
                                  pmadapter->pscan_table[bss_idx].ssid.ssid_len))
                    {
                        wscan_d("SCAN_RESP: Duplicate of index: %d", bss_idx);
                        break;
                    }
                }
            }
            /*
             * If the bss_idx is equal to the number of entries in the table,
             *   the new entry was not a duplicate; append it to the scan
             *   table
             */
            if (bss_idx == num_in_table)
            {
                /* Range check the bss_idx, keep it limited to the last entry */
                if (bss_idx == MRVDRV_MAX_BSSID_LIST)
                {
                    lowest_rssi_index = wlan_find_worst_network_in_list(pmadapter->pscan_table, MRVDRV_MAX_BSSID_LIST);
                }
                else
                {
                    num_in_table++;
                }
            }
            else
            {
                if ((bss_new_entry->channel != pmadapter->pscan_table[bss_idx].channel) &&
                    (bss_new_entry->rssi > pmadapter->pscan_table[bss_idx].rssi))
                {
                    wscan_d("skip update the duplicate entry with low rssi");
                    continue;
                }
            }

            /* fixme: Don't know if we need this right now */
#ifndef CONFIG_MLAN_WMSDK
            /*
             * Save the beacon/probe response returned for later application
             *   retrieval.  Duplicate beacon/probe responses are updated if
             *   possible
             */
            wlan_ret_802_11_scan_store_beacon(pmpriv, (bss_idx == MRVDRV_MAX_BSSID_LIST)
                                              : lowest_rssi_index
                                              : bss_idx, num_in_table, bss_new_entry);
            if (bss_new_entry->pbeacon_buf == MNULL)
            {
                wscan_d("No space for beacon, drop this entry");
                num_in_table--;
                continue;
            }
#endif /* CONFIG_MLAN_WMSDK */
            /*
             * If the TSF TLV was appended to the scan results, save
             *   this entry's TSF value in the networkTSF field.  The
             *   networkTSF is the firmware's TSF value at the time the
             *   beacon or probe response was received.
             */
            if (ptsf_tlv != MNULL)
            {
                (void)__memcpy(pmpriv->adapter, &tsf_val, &ptsf_tlv->tsf_data[idx * TSF_DATA_SIZE], sizeof(tsf_val));
                tsf_val = wlan_le64_to_cpu(tsf_val);
                (void)__memcpy(pmpriv->adapter, &bss_new_entry->network_tsf, &tsf_val,
                               sizeof(bss_new_entry->network_tsf));
            }
            band = BAND_G;
            if (pchan_band_tlv != MNULL)
            {
                pchan_band = &pchan_band_tlv->chan_band_param[idx];
                if (bss_new_entry->channel == 0)
                {
                    bss_new_entry->channel = pchan_band->chan_number;
                }
                band = radio_type_to_band(pchan_band->radio_type & (MBIT(0) | MBIT(1)));
            }

            /* Save the band designation for this entry for use in join */
            bss_new_entry->bss_band = band;
            cfp = wlan_find_cfp_by_band_and_channel(pmadapter, bss_new_entry->bss_band, (t_u16)bss_new_entry->channel);

            if (cfp != MNULL)
            {
                bss_new_entry->freq = cfp->freq;
            }
            else
            {
                bss_new_entry->freq = 0;
            }

            if (bss_idx == MRVDRV_MAX_BSSID_LIST)
            {
                if (pmadapter->pscan_table[lowest_rssi_index].rssi > bss_new_entry->rssi)
                {
                    (void)__memcpy(pmadapter, &pmadapter->pscan_table[lowest_rssi_index], bss_new_entry,
                                   sizeof(pmadapter->pscan_table[lowest_rssi_index]));
                    adjust_pointers_to_internal_buffers(&pmadapter->pscan_table[lowest_rssi_index], bss_new_entry);
                }
            }
            else
            {
                /* Copy the locally created bss_new_entry to the scan table */
                (void)__memcpy(pmadapter, &pmadapter->pscan_table[bss_idx], bss_new_entry,
                               sizeof(pmadapter->pscan_table[bss_idx]));
                adjust_pointers_to_internal_buffers(&pmadapter->pscan_table[bss_idx], bss_new_entry);
            }
        }
        else
        {
            /* Error parsing/interpreting the scan response, skipped */
            PRINTM(MERROR, "SCAN_RESP: wlan_interpret_bss_desc_with_ie returned error\n");
        }
        idx++;
    }

    wscan_d("SCAN_RESP: Scanned %2d APs, %d valid, %d total", pscan_rsp->number_of_sets,
            num_in_table - pmadapter->num_in_scan_table, num_in_table);

    /* Update the total number of BSSIDs in the scan table */
    pmadapter->num_in_scan_table = num_in_table;

    /* fixme: the following code does not seem relevant */
#ifndef CONFIG_MLAN_WMSDK
    /* Update the age_in_second */
    pmadapter->callbacks.moal_get_system_time(pmadapter->pmoal_handle, &pmadapter->age_in_secs, &age_ts_usec);
    if (is_bgscan_resp)
        goto done;
    if (!util_peek_list(pmadapter->pmoal_handle, &pmadapter->scan_pending_q, pcb->moal_spin_lock,
                        pcb->moal_spin_unlock))
    {
        wlan_request_cmd_lock(pmadapter);
        pmadapter->scan_processing = MFALSE;
        wlan_release_cmd_lock(pmadapter);
        /*
         * Process the resulting scan table:
         *   - Remove any bad ssids
         *   - Update our current BSS information from scan data
         */
        wlan_scan_process_results(pmpriv);

        /* Need to indicate IOCTL complete */
        if (pioctl_req != MNULL)
        {
            pioctl_req->status_code = MLAN_ERROR_NO_ERROR;

            /* Indicate ioctl complete */
            pcb->moal_ioctl_complete(pmadapter->pmoal_handle, (pmlan_ioctl_req)pioctl_buf, MLAN_STATUS_SUCCESS);
        }
        wlan_recv_event(pmpriv, MLAN_EVENT_ID_DRV_SCAN_REPORT, MNULL);
    }
    else
    {
        /* If firmware not ready, do not issue any more scan commands */
        if (pmadapter->hw_status != WlanHardwareStatusReady)
        {
            /* Flush all pending scan commands */
            wlan_flush_scan_queue(pmadapter);
            /* Indicate IOCTL complete */
            if (pioctl_req != MNULL)
            {
                pioctl_req->status_code = MLAN_ERROR_FW_NOT_READY;

                /* Indicate ioctl complete */
                pcb->moal_ioctl_complete(pmadapter->pmoal_handle, (pmlan_ioctl_req)pioctl_buf, MLAN_STATUS_FAILURE);
            }
        }
        else
        {
            /* Get scan command from scan_pending_q and put to cmd_pending_q */
            pcmd_node = (cmd_ctrl_node *)util_dequeue_list(pmadapter->pmoal_handle, &pmadapter->scan_pending_q,
                                                           pcb->moal_spin_lock, pcb->moal_spin_unlock);

            wlan_insert_cmd_to_pending_q(pmadapter, pcmd_node, MTRUE);
        }
    }
#endif /* CONFIG_MLAN_WMSDK */

done:
    if (bss_new_entry != MNULL)
    {
        (void)pcb->moal_mfree(pmadapter->pmoal_handle, (t_u8 *)bss_new_entry);
    }

    LEAVE();
    return ret;
}
#endif

#if defined(CONFIG_EXT_SCAN_SUPPORT)
/**
 *  @brief Prepare an extended scan command to be sent to the firmware
 *
 *  Use the wlan_scan_cmd_config sent to the command processing module in
 *   the wlan_prepare_cmd to configure a HostCmd_DS_802_11_SCAN_EXT command
 *   struct to send to firmware.
 *
 *  @param pmpriv     A pointer to mlan_private structure
 *  @param pcmd       A pointer to HostCmd_DS_COMMAND structure to be sent to
 *                    firmware with the HostCmd_DS_802_11_SCAN_EXT structure
 *  @param pdata_buf  Void pointer cast of a wlan_scan_cmd_config struct used
 *                    to set the fields/TLVs for the command sent to firmware
 *
 *  @return           MLAN_STATUS_SUCCESS
 */
mlan_status wlan_cmd_802_11_scan_ext(IN mlan_private *pmpriv, IN HostCmd_DS_COMMAND *pcmd, IN t_void *pdata_buf)
{
    HostCmd_DS_802_11_SCAN_EXT *pext_scan_cmd = &pcmd->params.ext_scan;
    wlan_scan_cmd_config *pscan_cfg           = MNULL;

    ENTER();

    pscan_cfg = (wlan_scan_cmd_config *)pdata_buf;

    /* Set fixed field variables in scan command */
    pext_scan_cmd->reserved = 0x00;
    (void)__memcpy(pmpriv->adapter, pext_scan_cmd->tlv_buffer, pscan_cfg->tlv_buf, pscan_cfg->tlv_buf_len);

    pcmd->command = wlan_cpu_to_le16(HostCmd_CMD_802_11_SCAN_EXT);

    /* Size is equal to the sizeof(fixed portions) + the TLV len + header */
    pcmd->size = wlan_cpu_to_le16((t_u16)(sizeof(pext_scan_cmd->reserved) + pscan_cfg->tlv_buf_len + S_DS_GEN));

    LEAVE();
    return MLAN_STATUS_SUCCESS;
}

/**
 *  @brief This function handles the command response of extended scan
 *
 *  @param pmpriv       A pointer to mlan_private structure
 *  @param resp         A pointer to HostCmd_DS_COMMAND
 *  @param pioctl_buf   A pointer to mlan_ioctl_req structure
 *
 *  @return             MLAN_STATUS_SUCCESS or MLAN_STATUS_FAILURE
 */
mlan_status wlan_ret_802_11_scan_ext(IN mlan_private *pmpriv, IN HostCmd_DS_COMMAND *resp, IN t_void *pioctl_buf)
{
#if defined(SCAN_CHANNEL_GAP) || defined(EXT_SCAN_ENH)
    HostCmd_DS_802_11_SCAN_EXT *pext_scan_cmd = &(resp->params.ext_scan);
#endif
#ifdef SCAN_CHANNEL_GAP
    MrvlIEtypesHeader_t *tlv                  = MNULL;
    MrvlIEtypes_ChannelStats_t *tlv_chanstats = MNULL;
    t_u16 tlv_buf_left                        = 0;
    t_u16 tlv_type                            = 0;
    t_u16 tlv_len                             = 0;
#endif
#ifdef EXT_SCAN_ENH
    t_u32 ext_scan_type;
    mlan_callbacks *pcb        = (mlan_callbacks *)&pmpriv->adapter->callbacks;
    pmlan_ioctl_req pioctl_req = (pmlan_ioctl_req)pioctl_buf;
    mlan_adapter *pmadapter    = pmpriv->adapter;
#endif
    ENTER();

    PRINTM(MINFO, "EXT scan returns successfully\n");
#ifdef EXT_SCAN_ENH
    pmadapter->scan_state |= wlan_get_ext_scan_state(resp);
    ext_scan_type = pext_scan_cmd->ext_scan_type;
    if (ext_scan_type == EXT_SCAN_CANCEL)
    {
        PRINTM(MCMND, "Cancel scan command completed!\n");
        wlan_request_cmd_lock(pmadapter);
        pmadapter->scan_processing = MFALSE;
        pmadapter->scan_state |= SCAN_STATE_SCAN_COMPLETE;
        pmadapter->ext_scan_type = EXT_SCAN_DEFAULT;
#ifdef HOST_CCX
        pmadapter->scan_data_block = MFALSE;
#endif
        wlan_release_cmd_lock(pmadapter);
        /* Need to indicate IOCTL complete */
        if (pioctl_req != MNULL)
        {
            pioctl_req->status_code = MLAN_STATUS_SUCCESS;
            /* Indicate ioctl complete */
            pcb->moal_ioctl_complete(pmadapter->pmoal_handle, (pmlan_ioctl_req)pioctl_req, MLAN_STATUS_SUCCESS);
        }
        LEAVE();
        return MLAN_STATUS_SUCCESS;
    }
    else if (ext_scan_type == EXT_SCAN_ENHANCE)
    {
        /* Setup the timer after scan command response */
        pcb->moal_start_timer(pmpriv->adapter->pmoal_handle, pmpriv->adapter->pmlan_cmd_timer, MFALSE,
                              MRVDRV_TIMER_10S * 2);
        pmpriv->adapter->cmd_timer_is_set = MTRUE;
        LEAVE();
        return MLAN_STATUS_SUCCESS;
    }
#endif
#ifdef SCAN_CHANNEL_GAP
    tlv          = (MrvlIEtypesHeader_t *)pext_scan_cmd->tlv_buffer;
    tlv_buf_left = resp->size - (sizeof(HostCmd_DS_802_11_SCAN_EXT) - 1 + S_DS_GEN);
    while (tlv_buf_left >= sizeof(MrvlIEtypesHeader_t))
    {
        tlv_type = wlan_le16_to_cpu(tlv->type);
        tlv_len  = wlan_le16_to_cpu(tlv->len);
        if (tlv_buf_left < (tlv_len + sizeof(MrvlIEtypesHeader_t)))
        {
            PRINTM(MERROR, "Error processing scan gap TLV\n");
            break;
        }
        switch (tlv_type)
        {
            case TLV_TYPE_CHANNEL_STATS:
                tlv_chanstats = (MrvlIEtypes_ChannelStats_t *)tlv;
                wlan_update_chan_statistics(pmpriv, tlv_chanstats);
                break;
            default:
                break;
        }
        tlv_buf_left -= tlv_len + sizeof(MrvlIEtypesHeader_t);
        tlv = (MrvlIEtypesHeader_t *)((t_u8 *)tlv + tlv_len + sizeof(MrvlIEtypesHeader_t));
    }
#endif
    LEAVE();
    return MLAN_STATUS_SUCCESS;
}

#ifdef MULTI_BSSID_SUPPORT
/** 8 bytes timestamp, 2 bytest interval, 2 bytes capability */
#define BEACON_FIX_SIZE 12

/**
 *  @brief This function realloc the beacon buffer and update ssid for new entry
 *
 *  @param pmadpater        A pointer to mlan_adapter structure
 *  @param pbss_entry       A pointer to the bss_entry which has multi-bssid IE
 *  @param pnew_entry       A pinter to new entry
 *  @param pssid            A pointer to ssid IE
 *
 *  @return                MLAN_STATUS_FAILURE/MLAN_STATUS_SUCCESS
 */
static mlan_status wlan_update_ssid_in_beacon_buf(mlan_adapter *pmadapter,
                                                  BSSDescriptor_t *pbss_entry,
                                                  BSSDescriptor_t *pnew_entry,
                                                  IEEEtypes_Ssid_t *pssid,
                                                  IEEEtypes_ExtCap_t *pnew_extcap,
                                                  IEEEtypes_Generic_t *pnew_rsnx)
{
#ifndef CONFIG_MLAN_WMSDK
    mlan_callbacks *pcb = (pmlan_callbacks)&pmadapter->callbacks;
    t_u8 *pbeacon_buf   = MNULL;
#endif
    t_u32 beacon_buf_size = 0;
    t_s8 offset           = pnew_entry->ssid.ssid_len - pbss_entry->ssid.ssid_len;
    mlan_status ret       = MLAN_STATUS_FAILURE;

    if (pnew_entry->ssid.ssid_len >= pbss_entry->ssid.ssid_len)
        beacon_buf_size = pbss_entry->beacon_buf_size + (pnew_entry->ssid.ssid_len - pbss_entry->ssid.ssid_len);
    else
        beacon_buf_size = pbss_entry->beacon_buf_size - (pbss_entry->ssid.ssid_len - pnew_entry->ssid.ssid_len);

    if (pnew_rsnx)
        beacon_buf_size += pnew_rsnx->ieee_hdr.len + sizeof(IEEEtypes_Header_t);
#ifndef CONFIG_MLAN_WMSDK
    ret = pcb->moal_malloc(pmadapter->pmoal_handle, beacon_buf_size, MLAN_MEM_DEF, (t_u8 **)&pbeacon_buf);
    if (ret != MLAN_STATUS_SUCCESS || !pbeacon_buf)
    {
        PRINTM(MERROR, "Memory allocation for beacon buf for bss_new_entry\n");
        goto done;
    }
#endif
    pnew_entry->beacon_buf_size = beacon_buf_size;
    pnew_entry->pbeacon_buf     = pbss_entry->pbeacon_buf;
    if (pnew_entry->pext_cap)
    {
        pnew_entry->ext_cap_offset += offset;
        if (pnew_extcap)
        {
            (void)__memcpy(pmadapter, &pnew_entry->ext_cap_saved, pnew_extcap, sizeof(IEEEtypes_ExtCap_t));
            pnew_entry->pext_cap = &pnew_entry->ext_cap_saved;
        }
    }
    if (pnew_rsnx)
    {
        (void)__memcpy(pmadapter, &pnew_entry->rsnx_ie_saved, pnew_rsnx,
                       pnew_rsnx->ieee_hdr.len + sizeof(IEEEtypes_Header_t));
        pnew_entry->prsnx_ie = &pnew_entry->rsnx_ie_saved;
    }

#ifndef CONFIG_MLAN_WMSDK
    /** copy fixed IE */
    (void)memcpy(pmadapter, pbeacon_buf, pbss_entry->pbeacon_buf, BEACON_FIX_SIZE);
    /** copy new ssid ie */
    (void)memcpy(pmadapter, pbeacon_buf + BEACON_FIX_SIZE, (t_u8 *)pssid, pssid->len + sizeof(IEEEtypes_Header_t));
    /** copy left IE to new beacon buffer */
    (void)memcpy(
        pmadapter, pbeacon_buf + BEACON_FIX_SIZE + pssid->len + sizeof(IEEEtypes_Header_t),
        pbss_entry->pbeacon_buf + BEACON_FIX_SIZE + pbss_entry->ssid.ssid_len + sizeof(IEEEtypes_Header_t),
        pbss_entry->beacon_buf_size - BEACON_FIX_SIZE - (pbss_entry->ssid.ssid_len + sizeof(IEEEtypes_Header_t)));
    /* adjust the ie pointer */
    if (pnew_entry->pwpa_ie)
        pnew_entry->wpa_offset += offset;
    if (pnew_entry->prsn_ie)
        pnew_entry->rsn_offset += offset;
#ifdef WAPI
    if (pnew_entry->pwapi_ie)
        pnew_entry->wapi_offset += offset;
#endif /* WAPI */

#ifdef ENABLE_HOTSPOT
    if (pnew_entry->posen_ie)
        pnew_entry->osen_offset += offset;
#endif /* ENABLE_HOTSPOT */
#ifdef ENABLE_802_11R
    if (pnew_entry->pmd_ie)
        pnew_entry->md_offset += offset;
#endif /* ENABLE_HOTSPOT */
    if (pnew_entry->pht_cap)
        pnew_entry->ht_cap_offset += offset;
    if (pnew_entry->pht_info)
        pnew_entry->ht_info_offset += offset;
    if (pnew_entry->pbss_co_2040)
        pnew_entry->bss_co_2040_offset += offset;
    if (pnew_entry->poverlap_bss_scan_param)
        pnew_entry->overlap_bss_offset += offset;
#ifdef ENABLE_802_11AC
    if (pnew_entry->pvht_cap)
        pnew_entry->vht_cap_offset += offset;
    if (pnew_entry->pvht_oprat)
        pnew_entry->vht_oprat_offset += offset;
    if (pnew_entry->pvht_txpower)
        pnew_entry->vht_txpower_offset += offset;
    if (pnew_entry->pext_pwer)
        pnew_entry->ext_pwer_offset += offset;
    if (pnew_entry->pext_bssload)
        pnew_entry->ext_bssload_offset += offset;
    if (pnew_entry->pquiet_chan)
        pnew_entry->quiet_chan_offset += offset;
    if (pnew_entry->poper_mode)
        pnew_entry->oper_mode_offset += offset;
#endif /* ENABLE_802_11AC */
#ifdef ENABLE_802_11AX
    if (pnew_entry->phe_cap)
        pnew_entry->he_cap_offset += offset;
    if (pnew_entry->phe_oprat)
        pnew_entry->he_oprat_offset += offset;
#endif /* ENABLE_802_11AX */
#ifdef ENABLE_802_116E
    if (pnew_entry->phe_6g_cap)
        pnew_entry->he_6g_cap_offset += offset;
#endif
    DBG_HEXDUMP(MCMD_D, "MBSSID beacon buf", pbeacon_buf, beacon_buf_size);
#endif
    ret = MLAN_STATUS_SUCCESS;
#ifndef CONFIG_MLAN_WMSDK
done:
#endif
    return ret;
}

/**
 *  @brief This function generate the bssid from bssid_idx
 *
 *  @param pmadpater        A pointer to mlan_adapter structure
 *  @param pbss_entry       A pointer to the bss_entry which has multi-bssid IE
 *  @param pnew_entry       A pinter to new entry
 *  @param bssid_index      bssid_index from BSSID_IDX IE
 *
 *  @return                N/A
 */
static void wlan_gen_multi_bssid_by_bssid_index(pmlan_adapter pmadapter,
                                                BSSDescriptor_t *pbss_entry,
                                                BSSDescriptor_t *pnew_entry,
                                                t_u8 bssid_index,
                                                t_u8 max_bssid_indicator)
{
    t_u8 mask = 0xff;
    t_u8 new_bssid[6];
    t_u8 bssid_a;
    t_u8 src_bssid[6];
    (void)__memcpy(pmadapter, (t_u8 *)src_bssid, pbss_entry->mac_address,
                   MIN(sizeof(mlan_802_11_mac_addr), sizeof(src_bssid)));
    (void)__memcpy(pmadapter, (t_u8 *)new_bssid, (t_u8 *)&pbss_entry->mac_address,
                   MIN(sizeof(mlan_802_11_mac_addr), sizeof(new_bssid)));

    mask         = (mask >> (8 - max_bssid_indicator));
    bssid_a      = src_bssid[5] & (~mask);
    src_bssid[5] = (src_bssid[5] + bssid_index) & mask;
    new_bssid[5] = bssid_a | src_bssid[5];

    (void)__memcpy(pmadapter, (t_u8 *)&pnew_entry->mac_address, new_bssid,
                   MIN(sizeof(new_bssid), sizeof(mlan_802_11_mac_addr)));
    (void)__memcpy(pmadapter, (t_u8 *)&pnew_entry->multi_bssid_ap_addr, (t_u8 *)&pbss_entry->mac_address,
                   MIN(sizeof(mlan_802_11_mac_addr), sizeof(mlan_802_11_mac_addr)));
}

/**
 *  @brief This function parse the non_trans_bssid_profile
 *
 *  @param pmadapter        A pointer to mlan_adapter structure
 *  @param pbss_entry       A pointer to BSSDescriptor_t which has multi-bssid
 * IE
 *  @param pbss_profile     A pointer to IEEEtypes_NonTransBSSIDprofile_t
 *  @param num_in_table     A pointer to buffer to save num of entry in scan
 * table.
 *  @param  max_bssid_indicator max bssid indicator
 *
 *  @return                 N/A
 */
static t_void wlan_parse_non_trans_bssid_profile(mlan_private *pmpriv,
                                                 BSSDescriptor_t *pbss_entry,
                                                 IEEEtypes_NonTransBSSIDProfile_t *pbss_profile,
                                                 t_u32 *num_in_table,
                                                 t_u8 max_bssid_indicator)
{
    mlan_adapter *pmadapter                   = pmpriv->adapter;
    IEEEtypes_Header_t *pheader               = (IEEEtypes_Header_t *)pbss_profile->profile_data;
    IEEEtypes_MultiBSSIDIndex_t *pbssid_index = MNULL;
    IEEEtypes_Ssid_t *pssid                   = MNULL;
    IEEEtypes_NotxBssCap_t *pcap              = (IEEEtypes_NotxBssCap_t *)pbss_profile->profile_data;
    t_u8 *pos                                 = pbss_profile->profile_data;
    t_s8 left_len                             = pbss_profile->ieee_hdr.len;
    t_u8 ret                                  = MFALSE;
    t_u32 bss_idx;
    t_u32 lowest_rssi_index        = 0;
    t_u32 num_in_tbl               = *num_in_table;
    mlan_callbacks *pcb            = (pmlan_callbacks)&pmadapter->callbacks;
    BSSDescriptor_t *bss_new_entry = MNULL;
#ifndef CONFIG_MLAN_WMSDK
    t_u8 *pbeacon_buf = MNULL;
#endif
    IEEEtypes_ExtCap_t *pextcap = MNULL;
    IEEEtypes_Generic_t *prsnx  = MNULL;

    ENTER();

    /* The first element within the Nontransmitted
     * BSSID Profile is not the Nontransmitted
     * BSSID Capability element.
     */
    if (pcap->element_id != NONTX_BSSID_CAP || pcap->len != 2)
    {
        PRINTM(MERROR,
               "The first element within the Nontransmitted BSSID Profile is not the NontransmittedBSSID Capability "
               "element\n");
        LEAVE();
        return;
    }

    while (left_len >= 2)
    {
        pheader = (IEEEtypes_Header_t *)pos;
        if ((t_s8)(pheader->len + sizeof(IEEEtypes_Header_t)) > left_len)
        {
            PRINTM(MMSG, "invalid IE length = %d left len %d\n", pheader->len, left_len);
            break;
        }
        switch (pheader->element_id)
        {
            case MBSSID_INDEX:
                pbssid_index = (IEEEtypes_MultiBSSIDIndex_t *)pos;
                if (pbssid_index->bssid_index == 0 || pbssid_index->bssid_index > 46)
                {
                    PRINTM(MERROR, " No valid Multiple BSSID-Index element\n");
                    goto done;
                }
                PRINTM(MCMND, "MBSSID: Find mbssid_index=%d\n", pbssid_index->bssid_index);
                ret = MTRUE;
                break;
            case EXT_CAPABILITY:
                pextcap = (IEEEtypes_ExtCap_t *)pos;
                DBG_HEXDUMP(MCMD_D, "MBSSID extcap", pos, pextcap->ieee_hdr.len + sizeof(IEEEtypes_Header_t));
                break;
            case RSNX_IE:
                prsnx = (IEEEtypes_Generic_t *)pos;
                DBG_HEXDUMP(MCMD_D, "MBSSID RSNX", pos, prsnx->ieee_hdr.len + sizeof(IEEEtypes_Header_t));
                break;
            case SSID:
                pssid = (IEEEtypes_Ssid_t *)pos;
                PRINTM(MCMND, "MBSSID: Find mbssid ssid=%s\n", pssid->ssid);
                break;
            default:
                break;
        }
        left_len -= pheader->len + sizeof(IEEEtypes_Header_t);
        pos += pheader->len + sizeof(IEEEtypes_Header_t);
    }
    if (ret == MTRUE)
    {
        ret = pcb->moal_malloc(pmadapter->pmoal_handle, sizeof(BSSDescriptor_t), MLAN_MEM_DEF, (t_u8 **)&bss_new_entry);
        if (ret != MLAN_STATUS_SUCCESS || !bss_new_entry)
        {
            PRINTM(MERROR, "Memory allocation for bss_new_entry failed!\n");
            goto done;
        }
        (void)__memcpy(pmadapter, bss_new_entry, pbss_entry, sizeof(BSSDescriptor_t));
        wlan_gen_multi_bssid_by_bssid_index(pmadapter, pbss_entry, bss_new_entry, pbssid_index->bssid_index,
                                            max_bssid_indicator);
        if (pssid)
        {
            __memset(pmadapter, (t_u8 *)&bss_new_entry->ssid, 0, sizeof(mlan_802_11_ssid));
            bss_new_entry->ssid.ssid_len = pssid->len;
            (void)__memcpy(pmadapter, bss_new_entry->ssid.ssid, pssid->ssid, MIN(pssid->len, MLAN_MAX_SSID_LENGTH));
            if (MLAN_STATUS_SUCCESS !=
                wlan_update_ssid_in_beacon_buf(pmadapter, pbss_entry, bss_new_entry, pssid, pextcap, prsnx))
            {
                PRINTM(MERROR, "Fail to update MBSSID beacon buf\n");
                pcb->moal_mfree(pmadapter->pmoal_handle, (t_u8 *)bss_new_entry);
                goto done;
            }
#ifndef CONFIG_MLAN_WMSDK
            pbeacon_buf = bss_new_entry->pbeacon_buf;
#endif
        }
        (void)__memcpy(pmadapter, &bss_new_entry->cap_info, &pcap->cap,
                       MIN(sizeof(IEEEtypes_CapInfo_t), sizeof(IEEEtypes_CapInfo_t)));
        bss_new_entry->multi_bssid_ap = MULTI_BSSID_SUB_AP;
        /*add to scan table*/
        /*
         * Search the scan table for the same bssid
         */
        for (bss_idx = 0; bss_idx < num_in_tbl; bss_idx++)
        {
            if (!__memcmp(pmadapter, bss_new_entry->mac_address, pmadapter->pscan_table[bss_idx].mac_address,
                          sizeof(bss_new_entry->mac_address)))
            {
                /*
                 * If the SSID matches as well, it is a duplicate of
                 *   this entry.  Keep the bss_idx set to this
                 *   entry so we replace the old contents in the table
                 */
                if ((bss_new_entry->ssid.ssid_len == pmadapter->pscan_table[bss_idx].ssid.ssid_len) &&
                    (!__memcmp(pmadapter, bss_new_entry->ssid.ssid, pmadapter->pscan_table[bss_idx].ssid.ssid,
                               bss_new_entry->ssid.ssid_len)))
                {
                    PRINTM(MINFO, "SCAN_RESP: Duplicate of index: %d\n", bss_idx);
                    break;
                }
            }
        }
        if (bss_idx == num_in_tbl)
        {
            /* Range check the bss_idx, keep it limited to the last entry */
            if (bss_idx == MRVDRV_MAX_BSSID_LIST)
            {
                lowest_rssi_index = wlan_find_worst_network_in_list(pmadapter->pscan_table, MRVDRV_MAX_BSSID_LIST);
            }
            else
            {
                num_in_tbl++;
            }
        }

        if (bss_idx == MRVDRV_MAX_BSSID_LIST)
        {
            if (pmadapter->pscan_table[lowest_rssi_index].rssi > bss_new_entry->rssi)
            {
                (void)__memcpy(pmadapter, &pmadapter->pscan_table[lowest_rssi_index], bss_new_entry,
                               sizeof(pmadapter->pscan_table[lowest_rssi_index]));
                adjust_pointers_to_internal_buffers(&pmadapter->pscan_table[lowest_rssi_index], bss_new_entry);
            }
        }
        else
        {
            /* Copy the locally created bss_new_entry to the scan table */
            (void)__memcpy(pmadapter, &pmadapter->pscan_table[bss_idx], bss_new_entry,
                           sizeof(pmadapter->pscan_table[bss_idx]));
            adjust_pointers_to_internal_buffers(&pmadapter->pscan_table[bss_idx], bss_new_entry);
        }
#ifndef CONFIG_MLAN_WMSDK
        if (pssid && pbeacon_buf)
            pcb->moal_mfree(pmadapter->pmoal_handle, (t_u8 *)pbeacon_buf);
#endif
        pcb->moal_mfree(pmadapter->pmoal_handle, (t_u8 *)bss_new_entry);
    }
done:
    *num_in_table = num_in_tbl;
    LEAVE();
    return;
}

/**
 *  @brief This function parse the multi_bssid IE from pbss_entry
 *
 *  @param pmpriv        A pointer to mlan_private structure
 *  @param pbss_entry       A pointer to BSSDescriptor_t which has multi-bssid
 * IE
 *  @param num_in_table     A pointer to buffer to save num of entry in scan
 * table.
 *
 *  @return                 number entry in scan table
 */
static t_void wlan_parse_multi_bssid_ie(mlan_private *pmpriv,
                                        BSSDescriptor_t *pbss_entry,
                                        IEEEtypes_MultiBSSID_t *pmulti_bssid,
                                        t_u32 *num_in_table)
{
    t_u32 bytes_left                                 = 0;
    t_u8 *pcurrent_ptr                               = MNULL;
    IEEEtypes_NonTransBSSIDProfile_t *pbssid_profile = MNULL;

    if (!pmulti_bssid)
        return;
    bytes_left   = pmulti_bssid->ieee_hdr.len - 1;
    pcurrent_ptr = pmulti_bssid->sub_elem_data;
    while (bytes_left >= 2)
    {
        pbssid_profile = (IEEEtypes_NonTransBSSIDProfile_t *)pcurrent_ptr;
        if (pbssid_profile->ieee_hdr.element_id != NONTRANS_BSSID_PROFILE_SUBELEM_ID)
        {
            PRINTM(MERROR, "Invalid multi-bssid IE\n");
            break;
        }
        if (bytes_left < (t_u32)(pbssid_profile->ieee_hdr.len + 2))
        {
            PRINTM(MERROR, "Invalid multi-bssid IE\n");
            break;
        }
        wlan_parse_non_trans_bssid_profile(pmpriv, pbss_entry, pbssid_profile, num_in_table,
                                           pmulti_bssid->max_bssid_indicator);
        pcurrent_ptr += pbssid_profile->ieee_hdr.len + 2;
        bytes_left -= pbssid_profile->ieee_hdr.len + 2;
    }
    return;
}

/**
 *  @brief This function search all the mbssid IE in the beacon buffer
 *
 *  @param pmpriv           A pointer to mlan_private structure
 *  @param pbss_entry       A pointer to BSSDescriptor_t which has multi-bssid
 * IE
 *  @param num_in_table     A pointer to buffer to save num of entry in scan
 * table.
 *
 *  @return                 N/A
 */
static void wlan_parse_multi_bssid_ap(mlan_private *pmpriv, BSSDescriptor_t *pbss_entry, t_u32 *num_in_table)
{
    IEEEtypes_ElementId_e element_id;
    t_u8 element_len;
    t_u16 total_ie_len;
    t_u32 bytes_left        = pbss_entry->beacon_buf_size - BEACON_FIX_SIZE;
    t_u8 *pcurrent_ptr      = pbss_entry->pbeacon_buf + BEACON_FIX_SIZE;
    IEEEtypes_Ssid_t *pssid = (IEEEtypes_Ssid_t *)pcurrent_ptr;

    if (pssid->element_id != SSID)
    {
        PRINTM(MERROR, "Invalid beacon ie, ssid should be in the first element\n");
        return;
    }
    /* Process variable IE */
    while (bytes_left >= 2)
    {
        element_id   = (IEEEtypes_ElementId_e)(*((t_u8 *)pcurrent_ptr));
        element_len  = *((t_u8 *)pcurrent_ptr + 1);
        total_ie_len = element_len + sizeof(IEEEtypes_Header_t);

        if (bytes_left < total_ie_len)
        {
            PRINTM(MERROR,
                   "InterpretIE: Error in processing IE, "
                   "bytes left < IE length\n");
            bytes_left = 0;
            continue;
        }
        if (element_id == MULTI_BSSID)
            wlan_parse_multi_bssid_ie(pmpriv, pbss_entry, (IEEEtypes_MultiBSSID_t *)pcurrent_ptr, num_in_table);
        pcurrent_ptr += total_ie_len;
        bytes_left -= total_ie_len;
    }
    return;
}
#endif

/**
 *  @brief This function parse and store the extended scan results
 *
 *  @param pmpriv           A pointer to mlan_private structure
 *  @param number_of_sets   Number of BSS
 *  @param pscan_resp       A pointer to scan response buffer
 *  @param scan_resp_size   Size of scan response buffer
 *
 *  @return             MLAN_STATUS_SUCCESS or MLAN_STATUS_FAILURE
 */
static mlan_status wlan_parse_ext_scan_result(IN mlan_private *pmpriv,
                                              IN t_u8 number_of_sets,
                                              IN t_u8 *pscan_resp,
                                              IN t_u16 scan_resp_size)
{
    mlan_status ret                = MLAN_STATUS_SUCCESS;
    mlan_adapter *pmadapter        = pmpriv->adapter;
    mlan_callbacks *pcb            = MNULL;
    BSSDescriptor_t *bss_new_entry = MNULL;
    t_u8 *pbss_info;
    t_u32 bytes_left;
    t_u32 bytes_left_for_tlv;
    t_u32 num_in_table;
    t_u32 bss_idx;
    t_u32 idx;
    t_u64 tsf_val;
    const chan_freq_power_t *cfp;
    t_u16 tlv_type, tlv_len;
    MrvlIEtypes_Data_t *ptlv                    = MNULL;
    MrvlIEtypes_Bss_Scan_Rsp_t *pscan_rsp_tlv   = MNULL;
    MrvlIEtypes_Bss_Scan_Info_t *pscan_info_tlv = MNULL;
    t_u16 band;
    /* t_u32 age_ts_usec; */
    t_u32 lowest_rssi_index              = 0;
    t_u8 null_ssid[MLAN_MAX_SSID_LENGTH] = {0};

    ENTER();
    pcb = (pmlan_callbacks)&pmadapter->callbacks;

#ifndef CONFIG_MLAN_WMSDK
    if (number_of_sets > MRVDRV_MAX_BSSID_LIST)
    {
        PRINTM(MERROR, "EXT_SCAN: Invalid number of AP returned (%d)!!\n", number_of_sets);
        ret = MLAN_STATUS_FAILURE;
        goto done;
    }
#endif

    bytes_left = scan_resp_size;
    PRINTM(MINFO, "EXT_SCAN: bss_descript_size %d\n", scan_resp_size);
    PRINTM(MINFO, "EXT_SCAN: returned %d APs before parsing\n", number_of_sets);

    num_in_table = pmadapter->num_in_scan_table;
    ptlv         = (MrvlIEtypes_Data_t *)pscan_resp;

    /*
     *  Process each scan response returned number_of_sets. Save
     *    the information in the bss_new_entry and then insert into the
     *    driver scan table either as an update to an existing entry
     *    or as an addition at the end of the table
     */
    ret = pcb->moal_malloc(pmadapter->pmoal_handle, sizeof(BSSDescriptor_t), MLAN_MEM_DEF, (t_u8 **)&bss_new_entry);

    if (ret != MLAN_STATUS_SUCCESS || !bss_new_entry)
    {
        PRINTM(MERROR, "Memory allocation for bss_new_entry failed!\n");
        ret = MLAN_STATUS_FAILURE;
        goto done;
    }

    for (idx = 0; idx < number_of_sets && bytes_left > sizeof(MrvlIEtypesHeader_t); idx++)
    {
        tlv_type = wlan_le16_to_cpu(ptlv->header.type);
        tlv_len  = wlan_le16_to_cpu(ptlv->header.len);
        if (bytes_left < sizeof(MrvlIEtypesHeader_t) + tlv_len)
        {
            PRINTM(MERROR, "EXT_SCAN: Error bytes left < TLV length\n");
            break;
        }
        pscan_rsp_tlv      = MNULL;
        pscan_info_tlv     = MNULL;
        bytes_left_for_tlv = bytes_left;
        /* BSS response TLV with beacon or probe response buffer at the initial
           position of each descriptor */
        if (tlv_type == TLV_TYPE_BSS_SCAN_RSP)
        {
            pbss_info     = (t_u8 *)ptlv;
            pscan_rsp_tlv = (MrvlIEtypes_Bss_Scan_Rsp_t *)ptlv;
            ptlv          = (MrvlIEtypes_Data_t *)(ptlv->data + tlv_len);
            bytes_left_for_tlv -= (tlv_len + sizeof(MrvlIEtypesHeader_t));
        }
        else
            break;

        /* Process variable TLV */
        while (bytes_left_for_tlv >= sizeof(MrvlIEtypesHeader_t) &&
               wlan_le16_to_cpu(ptlv->header.type) != TLV_TYPE_BSS_SCAN_RSP)
        {
            tlv_type = wlan_le16_to_cpu(ptlv->header.type);
            tlv_len  = wlan_le16_to_cpu(ptlv->header.len);
            if (bytes_left_for_tlv < sizeof(MrvlIEtypesHeader_t) + tlv_len)
            {
                PRINTM(MERROR,
                       "EXT_SCAN: Error in processing TLV, "
                       "bytes left < TLV length\n");
                pscan_rsp_tlv      = MNULL;
                bytes_left_for_tlv = 0;
                continue;
            }
            switch (tlv_type)
            {
                case TLV_TYPE_BSS_SCAN_INFO:
                    pscan_info_tlv = (MrvlIEtypes_Bss_Scan_Info_t *)ptlv;
                    if (tlv_len != sizeof(MrvlIEtypes_Bss_Scan_Info_t) - sizeof(MrvlIEtypesHeader_t))
                    {
                        bytes_left_for_tlv = 0;
                        continue;
                    }
                    break;
                default:
                    PRINTM(MINFO, "Unexpected tlv in scan result\n");
                    break;
            }
            ptlv = (MrvlIEtypes_Data_t *)(ptlv->data + tlv_len);
            bytes_left -= (tlv_len + sizeof(MrvlIEtypesHeader_t));
            bytes_left_for_tlv -= (tlv_len + sizeof(MrvlIEtypesHeader_t));
        }
        /* No BSS response TLV */
        if (pscan_rsp_tlv == MNULL)
            break;

        /* Advance pointer to the beacon buffer length and update the bytes
           count so that the function wlan_interpret_bss_desc_with_ie() can
           handle the scan buffer withut any change */
        pbss_info += sizeof(t_u16);
        bytes_left -= sizeof(t_u16);

        /* Zero out the bss_new_entry we are about to store info in */
        (void)__memset(pmadapter, bss_new_entry, 0x00, sizeof(BSSDescriptor_t));

        /* Process the data fields and IEs returned for this BSS */
        if (wlan_interpret_bss_desc_with_ie(pmadapter, bss_new_entry, &pbss_info, &bytes_left, MTRUE) ==
            MLAN_STATUS_SUCCESS)
        {
            PRINTM(MINFO, "EXT_SCAN: BSSID = %02x:%02x:%02x:%02x:%02x:%02x\n", bss_new_entry->mac_address[0],
                   bss_new_entry->mac_address[1], bss_new_entry->mac_address[2], bss_new_entry->mac_address[3],
                   bss_new_entry->mac_address[4], bss_new_entry->mac_address[5]);

            /*
             * Search the scan table for the same bssid
             */
            for (bss_idx = 0; bss_idx < num_in_table; bss_idx++)
            {
                if (!__memcmp(pmadapter, bss_new_entry->mac_address, pmadapter->pscan_table[bss_idx].mac_address,
                              sizeof(bss_new_entry->mac_address)))
                {
                    /*
                     * If the SSID matches as well, it is a duplicate of
                     *   this entry.  Keep the bss_idx set to this
                     *   entry so we replace the old contents in the table
                     */
                    if ((bss_new_entry->ssid.ssid_len == pmadapter->pscan_table[bss_idx].ssid.ssid_len) &&
                        (!__memcmp(pmadapter, bss_new_entry->ssid.ssid, pmadapter->pscan_table[bss_idx].ssid.ssid,
                                   bss_new_entry->ssid.ssid_len)))
                    {
                        PRINTM(MINFO, "EXT_SCAN: Duplicate of index: %d\n", bss_idx);
                        break;
                    }
                    /*
                     * If the SSID is NULL for same BSSID
                     * keep the bss_idx set to this entry
                     * so we replace the old contents in
                     * the table
                     */
                    if (!__memcmp(pmadapter, pmadapter->pscan_table[bss_idx].ssid.ssid, null_ssid,
                                  pmadapter->pscan_table[bss_idx].ssid.ssid_len))
                    {
                        PRINTM(MINFO, "SCAN_RESP: Duplicate of index: %d\n", bss_idx);
                        break;
                    }
                }
            }
            /*
             * If the bss_idx is equal to the number of entries in the table,
             *   the new entry was not a duplicate; append it to the scan
             *   table
             */
            if (bss_idx == num_in_table)
            {
                /* Range check the bss_idx, keep it limited to the last entry */
                if (bss_idx == MRVDRV_MAX_BSSID_LIST)
                {
                    lowest_rssi_index = wlan_find_worst_network_in_list(pmadapter->pscan_table, MRVDRV_MAX_BSSID_LIST);
                }
                else
                {
                    num_in_table++;
                }
            }
            else
            {
                if ((bss_new_entry->channel != pmadapter->pscan_table[bss_idx].channel) &&
                    (bss_new_entry->rssi > pmadapter->pscan_table[bss_idx].rssi))
                {
                    PRINTM(MCMND, "skip update the duplicate entry with low rssi\n");
                    continue;
                }
            }

            band = BAND_G;
            /*
             * If the BSS info TLV was appended to the scan results, save
             *   this entry's TSF value in the networkTSF field. The
             *   networkTSF is the firmware's TSF value at the time the
             *   beacon or probe response was received.
             */
            if (pscan_info_tlv)
            {
                /* RSSI is 2 byte long */
                bss_new_entry->rssi = -(t_s32)(wlan_le16_to_cpu(pscan_info_tlv->rssi));
#if 0
		if(bss_new_entry->rssi > 0x7f)
                bss_new_entry->rssi = - (256 - bss_new_entry->rssi);
#endif
                PRINTM(MINFO, "EXT_SCAN: RSSI=%d\n", bss_new_entry->rssi);
                (void)__memcpy(pmpriv->adapter, &tsf_val, &pscan_info_tlv->tsf, sizeof(tsf_val));
                tsf_val = wlan_le64_to_cpu(tsf_val);
                (void)__memcpy(pmpriv->adapter, &bss_new_entry->network_tsf, &tsf_val,
                               sizeof(bss_new_entry->network_tsf));
                band = radio_type_to_band(pscan_info_tlv->band);
                if (bss_new_entry->channel == 0)
                    bss_new_entry->channel = pscan_info_tlv->channel;
            }
#ifndef CONFIG_MLAN_WMSDK
            /*
             * Save the beacon/probe response returned for later application
             *   retrieval. Duplicate beacon/probe responses are updated if
             *   possible
             */
            wlan_ret_802_11_scan_store_beacon(pmpriv, bss_idx, num_in_table, bss_new_entry);
            if (bss_new_entry->pbeacon_buf == MNULL)
            {
                PRINTM(MCMND, "No space for beacon, drop this entry\n");
                num_in_table--;
                continue;
            }
#endif /* CONFIG_MLAN_WMSDK */
            /* Save the band designation for this entry for use in join */
            bss_new_entry->bss_band = band;
            cfp = wlan_find_cfp_by_band_and_channel(pmadapter, bss_new_entry->bss_band, (t_u16)bss_new_entry->channel);

            if (cfp)
                bss_new_entry->freq = cfp->freq;
            else
                bss_new_entry->freq = 0;
#ifdef MULTI_BSSID_SUPPORT
            if (IS_FW_SUPPORT_MULTIBSSID(pmadapter))
            {
                if (bss_new_entry->multi_bssid_ap == MULTI_BSSID_AP)
                    wlan_parse_multi_bssid_ap(pmpriv, bss_new_entry, &num_in_table);
            }
#endif
            if (bss_idx == MRVDRV_MAX_BSSID_LIST)
            {
                if (pmadapter->pscan_table[lowest_rssi_index].rssi > bss_new_entry->rssi)
                {
                    (void)__memcpy(pmadapter, &pmadapter->pscan_table[lowest_rssi_index], bss_new_entry,
                                   sizeof(pmadapter->pscan_table[lowest_rssi_index]));
                    adjust_pointers_to_internal_buffers(&pmadapter->pscan_table[lowest_rssi_index], bss_new_entry);
                }
            }
            else
            {
                /* Copy the locally created bss_new_entry to the scan table */
                (void)__memcpy(pmadapter, &pmadapter->pscan_table[bss_idx], bss_new_entry,
                               sizeof(pmadapter->pscan_table[bss_idx]));
                adjust_pointers_to_internal_buffers(&pmadapter->pscan_table[bss_idx], bss_new_entry);
            }
        }
        else
        {
            /* Error parsing/interpreting the scan response, skipped */
            PRINTM(MERROR, "EXT_SCAN: wlan_interpret_bss_desc_with_ie returned error\n");
        }
    }

    PRINTM(MINFO, "EXT_SCAN: Scanned %2d APs, %d valid, %d total\n", number_of_sets,
           num_in_table - pmadapter->num_in_scan_table, num_in_table);

    /* Update the total number of BSSIDs in the scan table */
    pmadapter->num_in_scan_table = num_in_table;
    /* fixme: the following code does not seem relevant */
#ifndef CONFIG_MLAN_WMSDK
    /* Update the age_in_second */
    pmadapter->callbacks.moal_get_system_time(pmadapter->pmoal_handle, &pmadapter->age_in_secs, &age_ts_usec);
#endif /* CONFIG_MLAN_WMSDK */
done:
    if (bss_new_entry)
    {
        pcb->moal_mfree(pmadapter->pmoal_handle, (t_u8 *)bss_new_entry);
    }

    LEAVE();
    return ret;
}

/**
 *  @brief This function handles the event extended scan report
 *
 *  @param pmpriv       A pointer to mlan_private structure
 *  @param pmbuf        A pointer to mlan_buffer
 *
 *  @return             MLAN_STATUS_SUCCESS or MLAN_STATUS_FAILURE
 */
mlan_status wlan_handle_event_ext_scan_report(IN mlan_private *pmpriv, IN t_u8 *pmbuf)
{
    /* mlan_adapter *pmadapter = pmpriv->adapter;
    mlan_callbacks *pcb = &pmadapter->callbacks;
    mlan_ioctl_req *pioctl_req = MNULL;
    cmd_ctrl_node *pcmd_node = MNULL; */
    mlan_status ret = MLAN_STATUS_SUCCESS;

    mlan_event_scan_result *pevent_scan = (pmlan_event_scan_result)(pmbuf);
    t_u8 *ptlv                          = (pmbuf + sizeof(mlan_event_scan_result));
    t_u16 tlv_buf_left                  = wlan_cpu_to_le16(pevent_scan->buf_size);

    DBG_HEXDUMP(MCMD_D, "EVENT EXT_SCAN", pmbuf->pbuf + pmbuf->data_offset, pmbuf->data_len);
    ret = wlan_parse_ext_scan_result(pmpriv, pevent_scan->num_of_set, ptlv, tlv_buf_left);

#if 0
    if (!pevent_scan->more_event) {
        pioctl_req = pmadapter->pext_scan_ioctl_req;
        if (!util_peek_list(pmadapter->pmoal_handle,
                            &pmadapter->scan_pending_q, pcb->moal_spin_lock,
                            pcb->moal_spin_unlock)) {
            pmadapter->pext_scan_ioctl_req = MNULL;
            wlan_request_cmd_lock(pmadapter);
            pmadapter->scan_processing = MFALSE;
            wlan_release_cmd_lock(pmadapter);
            /*
             * Process the resulting scan table:
             *   - Remove any bad ssids
             *   - Update our current BSS information from scan data
             */
            wlan_scan_process_results(pmpriv);

            /* Need to indicate IOCTL complete */
            if (pioctl_req != MNULL) {
                pioctl_req->status_code = MLAN_ERROR_NO_ERROR;
                /* Indicate ioctl complete */
                pcb->moal_ioctl_complete(pmadapter->pmoal_handle,
                                         (pmlan_ioctl_req) pioctl_req,
                                         MLAN_STATUS_SUCCESS);
            }
            wlan_recv_event(pmpriv, MLAN_EVENT_ID_DRV_SCAN_REPORT, MNULL);
        } else {
            /* If firmware not ready, do not issue any more scan commands */
            if (pmadapter->hw_status != WlanHardwareStatusReady) {
                /* Flush all pending scan commands */
                wlan_flush_scan_queue(pmadapter);
                /* Indicate IOCTL complete */
                if (pioctl_req != MNULL) {
                    pioctl_req->status_code = MLAN_ERROR_FW_NOT_READY;

                    /* Indicate ioctl complete */
                    pcb->moal_ioctl_complete(pmadapter->pmoal_handle,
                                             (pmlan_ioctl_req) pioctl_req,
                                             MLAN_STATUS_FAILURE);
                }
            } else {
                /* Get scan command from scan_pending_q and put to
                   cmd_pending_q */
                pcmd_node =
                    (cmd_ctrl_node *) util_dequeue_list(pmadapter->pmoal_handle,
                                                        &pmadapter->
                                                        scan_pending_q,
                                                        pcb->moal_spin_lock,
                                                        pcb->moal_spin_unlock);
                wlan_insert_cmd_to_pending_q(pmadapter, pcmd_node, MTRUE);
            }
        }
    }
#endif
    LEAVE();
    return ret;
}
#endif /* CONFIG_EXT_SCAN_SUPPORT */

#ifdef CONFIG_BG_SCAN
/**
 *  @brief This function prepares command of bg_scan_query.
 *
 *  @param pmpriv     A pointer to mlan_private structure
 *  @param pcmd       A pointer to HostCmd_DS_COMMAND structure
 *  @param pdata_buf  Void pointer cast of a wlan_scan_cmd_config struct used
 *                    to set the fields/TLVs for the command sent to firmware
 *
 *  @return           MLAN_STATUS_SUCCESS
 */
mlan_status wlan_cmd_802_11_bg_scan_query(IN mlan_private *pmpriv, IN HostCmd_DS_COMMAND *pcmd, IN t_u16 cmd_action)
{
    HostCmd_DS_802_11_BG_SCAN_QUERY *bg_query = &pcmd->params.bg_scan_query;

    ENTER();

    pcmd->command = wlan_cpu_to_le16(HostCmd_CMD_802_11_BG_SCAN_QUERY);
    pcmd->size    = wlan_cpu_to_le16(sizeof(HostCmd_DS_802_11_BG_SCAN_QUERY) + S_DS_GEN);

    bg_query->flush = MTRUE;

    LEAVE();
    return MLAN_STATUS_SUCCESS;
}

/**
 *  @brief Create a channel list for the driver to scan based on region info
 *
 *  Use the driver region/band information to construct a comprehensive list
 *    of channels to scan.  This routine is used for any scan that is not
 *    provided a specific channel list to scan.
 *
 *  @param pmpriv           A pointer to mlan_private structure
 *  @param pbg_scan_in      pointer to scan configuration parameters
 *  @param tlv_chan_list    A pointer to structure MrvlIEtypes_ChanListParamSet_t
 *
 *  @return                 channel number
 */
static t_u8 wlan_bgscan_create_channel_list(IN mlan_private *pmpriv,
                                            IN const wlan_bgscan_cfg *pbg_scan_in,
                                            MrvlIEtypes_ChanListParamSet_t *tlv_chan_list)
{
    mlan_adapter *pmadapter = pmpriv->adapter;
    region_chan_t *pscan_region;
    const chan_freq_power_t *cfp;
    t_u32 region_idx;
    t_u32 chan_idx = 0;
    t_u32 next_chan;
    t_u8 scan_type;
    t_u8 radio_type;

    ENTER();

    for (region_idx = 0; region_idx < NELEMENTS(pmadapter->region_channel); region_idx++)
    {
        if (wlan_11d_is_enabled(pmpriv) && pmpriv->media_connected != MTRUE)
        {
            /* Scan all the supported chan for the first scan */
            if (!pmadapter->universal_channel[region_idx].valid)
                continue;
            pscan_region = &pmadapter->universal_channel[region_idx];
        }
        else
        {
            if (!pmadapter->region_channel[region_idx].valid)
                continue;
            pscan_region = &pmadapter->region_channel[region_idx];
        }

        if (pbg_scan_in && !pbg_scan_in->chan_list[0].chan_number &&
            pbg_scan_in->chan_list[0].radio_type & BAND_SPECIFIED)
        {
            radio_type = pbg_scan_in->chan_list[0].radio_type & ~BAND_SPECIFIED;
            if (!radio_type && (pscan_region->band != BAND_B) && (pscan_region->band != BAND_G))
                continue;
            if (radio_type && (pscan_region->band != BAND_A))
                continue;
        }
        if (!wlan_is_band_compatible(pmpriv->config_bands | pmadapter->adhoc_start_band, pscan_region->band))
            continue;
        for (next_chan = 0; next_chan < pscan_region->num_cfp; next_chan++, chan_idx++)
        {
            if (chan_idx >= WLAN_BG_SCAN_CHAN_MAX)
                break;
            /* Set the default scan type to ACTIVE SCAN type, will later be
               changed to passive on a per channel basis if restricted by
               regulatory requirements (11d or 11h) */
            scan_type = MLAN_SCAN_TYPE_ACTIVE;
            cfp       = pscan_region->pcfp + next_chan;
            if (scan_type == MLAN_SCAN_TYPE_ACTIVE && wlan_11d_support_is_enabled(pmpriv))
            {
                scan_type = wlan_11d_get_scan_type(pmpriv, pscan_region->band, (t_u8)cfp->channel,
                                                   &pmadapter->parsed_region_chan);
            }
            switch (pscan_region->band)
            {
#ifdef CONFIG_5GHz_SUPPORT
                case BAND_A:
                    tlv_chan_list->chan_scan_param[chan_idx].radio_type = HostCmd_SCAN_RADIO_TYPE_A;
                    if (!wlan_11d_is_enabled(pmpriv))
                    {
                        /* 11D not available... play it safe on DFS channels */
                        if (wlan_11h_radar_detect_required(pmpriv, (t_u8)cfp->channel))
                            scan_type = MLAN_SCAN_TYPE_PASSIVE;
                    }
                    break;
#endif
                case BAND_B:
                case BAND_G:
                    if (wlan_bg_scan_type_is_passive(pmpriv, (t_u8)cfp->channel))
                        scan_type = MLAN_SCAN_TYPE_PASSIVE;
                default:
                    tlv_chan_list->chan_scan_param[chan_idx].radio_type = HostCmd_SCAN_RADIO_TYPE_BG;
                    break;
            }

            if (pbg_scan_in && pbg_scan_in->chan_list[0].scan_time)
            {
                tlv_chan_list->chan_scan_param[chan_idx].max_scan_time =
                    wlan_cpu_to_le16((t_u16)pbg_scan_in->chan_list[0].scan_time);
                tlv_chan_list->chan_scan_param[chan_idx].min_scan_time =
                    wlan_cpu_to_le16((t_u16)pbg_scan_in->chan_list[0].scan_time);
            }
            else if (scan_type == MLAN_SCAN_TYPE_PASSIVE)
            {
                tlv_chan_list->chan_scan_param[chan_idx].max_scan_time = wlan_cpu_to_le16(pmadapter->passive_scan_time);
                tlv_chan_list->chan_scan_param[chan_idx].min_scan_time = wlan_cpu_to_le16(pmadapter->passive_scan_time);
            }
            else
            {
                tlv_chan_list->chan_scan_param[chan_idx].max_scan_time =
                    wlan_cpu_to_le16(pmadapter->specific_scan_time);
                tlv_chan_list->chan_scan_param[chan_idx].min_scan_time =
                    wlan_cpu_to_le16(pmadapter->specific_scan_time);
            }

            if (scan_type == MLAN_SCAN_TYPE_PASSIVE)
            {
                tlv_chan_list->chan_scan_param[chan_idx].chan_scan_mode.passive_scan = MTRUE;
            }
            else
            {
                tlv_chan_list->chan_scan_param[chan_idx].chan_scan_mode.passive_scan = MFALSE;
            }

            tlv_chan_list->chan_scan_param[chan_idx].chan_number                      = (t_u8)cfp->channel;
            tlv_chan_list->chan_scan_param[chan_idx].chan_scan_mode.disable_chan_filt = MTRUE;
        }
    }

    LEAVE();
    return chan_idx;
}
/**
 *  @brief This function prepares command of bg_scan_config
 *
 *  @param pmpriv     A pointer to mlan_private structure
 *  @param pcmd       A pointer to HostCmd_DS_COMMAND structure
 *  @param pdata_buf  Void pointer cast of a wlan_scan_cmd_config struct used
 *                    to set the fields/TLVs for the command sent to firmware
 *
 *  @return           MLAN_STATUS_SUCCESS
 */
mlan_status wlan_cmd_bgscan_config(IN mlan_private *pmpriv,
                                   IN HostCmd_DS_COMMAND *pcmd,
                                   IN t_u16 cmd_action,
                                   IN t_void *pdata_buf)
{
    mlan_adapter *pmadapter                                = pmpriv->adapter;
    HostCmd_DS_802_11_BG_SCAN_CONFIG *bg_scan              = &pcmd->params.bg_scan_config;
    wlan_bgscan_cfg *bg_scan_in                            = (wlan_bgscan_cfg *)pdata_buf;
    t_u16 cmd_size                                         = 0;
    MrvlIEtypes_NumProbes_t *pnum_probes_tlv               = MNULL;
    MrvlIEtypes_BeaconLowRssiThreshold_t *rssi_tlv         = MNULL;
    MrvlIEtypes_BeaconLowSnrThreshold_t *snr_tlv           = MNULL;
    MrvlIEtypes_WildCardSsIdParamSet_t *pwildcard_ssid_tlv = MNULL;
    MrvlIEtypes_ChanListParamSet_t *tlv_chan_list          = MNULL;
    MrvlIEtypes_StartLater_t *tlv_start_later              = MNULL;
    MrvlIEtypes_RepeatCount_t *tlv_repeat                  = MNULL;
    t_u8 *tlv                                              = MNULL;
    t_u16 num_probes                                       = 0;
    t_u32 ssid_idx;
    t_u32 ssid_len = 0;
    t_u32 chan_idx;
    t_u32 chan_num;
    t_u8 radio_type;
    t_u16 scan_dur;
    t_u8 scan_type;

    ENTER();

    pcmd->command     = wlan_cpu_to_le16(HostCmd_CMD_802_11_BG_SCAN_CONFIG);
    bg_scan->action   = wlan_cpu_to_le16(bg_scan_in->action);
    bg_scan->enable   = bg_scan_in->enable;
    bg_scan->bss_type = bg_scan_in->bss_type;
    cmd_size          = sizeof(HostCmd_DS_802_11_BG_SCAN_CONFIG) + S_DS_GEN;
    if (bg_scan_in->chan_per_scan)
        bg_scan->chan_per_scan = bg_scan_in->chan_per_scan;
    else
        bg_scan->chan_per_scan = MRVDRV_MAX_CHANNELS_PER_SPECIFIC_SCAN;
    if (bg_scan_in->scan_interval)
        bg_scan->scan_interval = wlan_cpu_to_le32(bg_scan_in->scan_interval);
    else
        bg_scan->scan_interval = wlan_cpu_to_le32(DEFAULT_BGSCAN_INTERVAL);
    bg_scan->report_condition = wlan_cpu_to_le32(bg_scan_in->report_condition);

    if ((bg_scan_in->action == BG_SCAN_ACT_GET)
#ifdef CONFIG_WMM_UAPSD
        || (bg_scan_in->action == BG_SCAN_ACT_GET_PPS_UAPSD)
#endif
        || (!bg_scan->enable))
        goto done;

    tlv        = (t_u8 *)bg_scan + sizeof(HostCmd_DS_802_11_BG_SCAN_CONFIG);
    num_probes = (bg_scan_in->num_probes ? bg_scan_in->num_probes : pmadapter->scan_probes);
    if (num_probes)
    {
        pnum_probes_tlv              = (MrvlIEtypes_NumProbes_t *)tlv;
        pnum_probes_tlv->header.type = wlan_cpu_to_le16(TLV_TYPE_NUMPROBES);
        pnum_probes_tlv->header.len  = wlan_cpu_to_le16(sizeof(pnum_probes_tlv->num_probes));
        pnum_probes_tlv->num_probes  = wlan_cpu_to_le16((t_u16)num_probes);
        tlv += sizeof(MrvlIEtypes_NumProbes_t);
        cmd_size += sizeof(MrvlIEtypes_NumProbes_t);
    }
    if (bg_scan_in->rssi_threshold)
    {
        rssi_tlv              = (MrvlIEtypes_BeaconLowRssiThreshold_t *)tlv;
        rssi_tlv->header.type = wlan_cpu_to_le16(TLV_TYPE_RSSI_LOW);
        rssi_tlv->header.len =
            wlan_cpu_to_le16(sizeof(MrvlIEtypes_BeaconLowRssiThreshold_t) - sizeof(MrvlIEtypesHeader_t));
        rssi_tlv->value     = bg_scan_in->rssi_threshold;
        rssi_tlv->frequency = 0;
        tlv += sizeof(MrvlIEtypes_BeaconLowRssiThreshold_t);
        cmd_size += sizeof(MrvlIEtypes_BeaconLowRssiThreshold_t);
    }
    if (bg_scan_in->snr_threshold)
    {
        snr_tlv              = (MrvlIEtypes_BeaconLowSnrThreshold_t *)tlv;
        snr_tlv->header.type = wlan_cpu_to_le16(TLV_TYPE_SNR_LOW);
        snr_tlv->header.len =
            wlan_cpu_to_le16(sizeof(MrvlIEtypes_BeaconLowSnrThreshold_t) - sizeof(MrvlIEtypesHeader_t));
        snr_tlv->value     = bg_scan_in->snr_threshold;
        snr_tlv->frequency = 0;
        tlv += sizeof(MrvlIEtypes_BeaconLowRssiThreshold_t);
        cmd_size += sizeof(MrvlIEtypes_BeaconLowRssiThreshold_t);
    }
    if (bg_scan_in->repeat_count)
    {
        tlv_repeat               = (MrvlIEtypes_RepeatCount_t *)tlv;
        tlv_repeat->header.type  = wlan_cpu_to_le16(TLV_TYPE_REPEAT_COUNT);
        tlv_repeat->header.len   = wlan_cpu_to_le16(sizeof(MrvlIEtypes_RepeatCount_t) - sizeof(MrvlIEtypesHeader_t));
        tlv_repeat->repeat_count = wlan_cpu_to_le16(bg_scan_in->repeat_count);
        tlv += sizeof(MrvlIEtypes_RepeatCount_t);
        cmd_size += sizeof(MrvlIEtypes_RepeatCount_t);
    }
    for (ssid_idx = 0; ((ssid_idx < NELEMENTS(bg_scan_in->ssid_list)) &&
                        (*bg_scan_in->ssid_list[ssid_idx].ssid || bg_scan_in->ssid_list[ssid_idx].max_len));
         ssid_idx++)
    {
        ssid_len                            = wlan_strlen((t_s8 *)bg_scan_in->ssid_list[ssid_idx].ssid);
        pwildcard_ssid_tlv                  = (MrvlIEtypes_WildCardSsIdParamSet_t *)tlv;
        pwildcard_ssid_tlv->header.type     = wlan_cpu_to_le16(TLV_TYPE_WILDCARDSSID);
        pwildcard_ssid_tlv->header.len      = (t_u16)(ssid_len + sizeof(pwildcard_ssid_tlv->max_ssid_length));
        pwildcard_ssid_tlv->max_ssid_length = bg_scan_in->ssid_list[ssid_idx].max_len;
        (void)__memcpy(pmadapter, pwildcard_ssid_tlv->ssid, bg_scan_in->ssid_list[ssid_idx].ssid,
                       MIN(MLAN_MAX_SSID_LENGTH, ssid_len));
        tlv += sizeof(pwildcard_ssid_tlv->header) + pwildcard_ssid_tlv->header.len;
        cmd_size += sizeof(pwildcard_ssid_tlv->header) + pwildcard_ssid_tlv->header.len;
        pwildcard_ssid_tlv->header.len = wlan_cpu_to_le16(pwildcard_ssid_tlv->header.len);
        PRINTM(MINFO, "Scan: ssid_list[%d]: %s, %d\n", ssid_idx, pwildcard_ssid_tlv->ssid,
               pwildcard_ssid_tlv->max_ssid_length);
    }
    if (bg_scan_in->chan_list[0].chan_number)
    {
        tlv_chan_list = (MrvlIEtypes_ChanListParamSet_t *)tlv;
        PRINTM(MINFO, "Scan: Using supplied channel list\n");
        chan_num = 0;
        for (chan_idx = 0; chan_idx < WLAN_BG_SCAN_CHAN_MAX && bg_scan_in->chan_list[chan_idx].chan_number; chan_idx++)
        {
            radio_type = bg_scan_in->chan_list[chan_idx].radio_type;
            if (!wlan_is_band_compatible(pmpriv->config_bands | pmadapter->adhoc_start_band,
                                         radio_type_to_band(radio_type)))
                continue;
            scan_type = bg_scan_in->chan_list[chan_idx].scan_type;
            /* Prevent active scanning on a radar controlled channel */
#ifdef CONFIG_5GHz_SUPPORT
            if (radio_type == HostCmd_SCAN_RADIO_TYPE_A)
            {
                if (wlan_11h_radar_detect_required(pmpriv, bg_scan_in->chan_list[chan_idx].chan_number))
                {
                    scan_type = MLAN_SCAN_TYPE_PASSIVE;
                }
            }
#endif
            if (radio_type == HostCmd_SCAN_RADIO_TYPE_BG)
            {
                if (wlan_bg_scan_type_is_passive(pmpriv, bg_scan_in->chan_list[chan_idx].chan_number))
                {
                    scan_type = MLAN_SCAN_TYPE_PASSIVE;
                }
            }
            tlv_chan_list->chan_scan_param[chan_num].chan_number = bg_scan_in->chan_list[chan_idx].chan_number;
            tlv_chan_list->chan_scan_param[chan_num].radio_type  = bg_scan_in->chan_list[chan_idx].radio_type;

            if (scan_type == MLAN_SCAN_TYPE_PASSIVE)
            {
                tlv_chan_list->chan_scan_param[chan_num].chan_scan_mode.passive_scan = MTRUE;
            }
            else
            {
                tlv_chan_list->chan_scan_param[chan_num].chan_scan_mode.passive_scan = MFALSE;
            }
            if (bg_scan_in->chan_list[chan_idx].scan_time)
            {
                scan_dur = (t_u16)bg_scan_in->chan_list[chan_idx].scan_time;
            }
            else
            {
                if (scan_type == MLAN_SCAN_TYPE_PASSIVE)
                {
                    scan_dur = pmadapter->passive_scan_time;
                }
                else
                {
                    scan_dur = pmadapter->specific_scan_time;
                }
            }
            tlv_chan_list->chan_scan_param[chan_num].min_scan_time = wlan_cpu_to_le16(scan_dur);
            tlv_chan_list->chan_scan_param[chan_num].max_scan_time = wlan_cpu_to_le16(scan_dur);
            chan_num++;
        }
        tlv_chan_list->header.type = wlan_cpu_to_le16(TLV_TYPE_CHANLIST);
        tlv_chan_list->header.len  = wlan_cpu_to_le16(sizeof(ChanScanParamSet_t) * chan_num);
        tlv += sizeof(MrvlIEtypesHeader_t) + sizeof(ChanScanParamSet_t) * chan_num;
        cmd_size += sizeof(MrvlIEtypesHeader_t) + sizeof(ChanScanParamSet_t) * chan_num;
    }
    else
    {
        tlv_chan_list              = (MrvlIEtypes_ChanListParamSet_t *)tlv;
        chan_num                   = wlan_bgscan_create_channel_list(pmpriv, bg_scan_in, tlv_chan_list);
        tlv_chan_list->header.type = wlan_cpu_to_le16(TLV_TYPE_CHANLIST);
        tlv_chan_list->header.len  = wlan_cpu_to_le16(sizeof(ChanScanParamSet_t) * chan_num);
        tlv += sizeof(MrvlIEtypesHeader_t) + sizeof(ChanScanParamSet_t) * chan_num;
        cmd_size += sizeof(MrvlIEtypesHeader_t) + sizeof(ChanScanParamSet_t) * chan_num;
    }
    tlv_start_later              = (MrvlIEtypes_StartLater_t *)tlv;
    tlv_start_later->header.type = wlan_cpu_to_le16(TLV_TYPE_STARTBGSCANLATER);
    tlv_start_later->header.len  = wlan_cpu_to_le16(sizeof(MrvlIEtypes_StartLater_t) - sizeof(MrvlIEtypesHeader_t));
    tlv_start_later->value       = 0;
    tlv += sizeof(MrvlIEtypes_StartLater_t);
    cmd_size += sizeof(MrvlIEtypes_StartLater_t);
done:
    pcmd->size = wlan_cpu_to_le16(cmd_size);
    LEAVE();
    return MLAN_STATUS_SUCCESS;
}
/**
 *  @brief This function handles the command response of extended scan
 *
 *  @param pmpriv       A pointer to mlan_private structure
 *  @param resp         A pointer to HostCmd_DS_COMMAND
 *  @param pioctl_buf   A pointer to mlan_ioctl_req structure
 *
 *  @return             MLAN_STATUS_SUCCESS or MLAN_STATUS_FAILURE
 */
mlan_status wlan_ret_bgscan_config(IN mlan_private *pmpriv, IN HostCmd_DS_COMMAND *resp, IN mlan_ioctl_req *pioctl_buf)
{
    mlan_ds_scan *pscan                       = MNULL;
    HostCmd_DS_802_11_BG_SCAN_CONFIG *bg_scan = &resp->params.bg_scan_config;
    wlan_bgscan_cfg *bg_scan_out              = MNULL;

    ENTER();
    if (pioctl_buf)
    {
        pscan               = (mlan_ds_scan *)pioctl_buf->pbuf;
        bg_scan_out         = (wlan_bgscan_cfg *)pscan->param.user_scan.scan_cfg_buf;
        bg_scan_out->action = wlan_le16_to_cpu(bg_scan->action);
#ifdef CONFIG_WMM_UAPSD
        if ((bg_scan_out->action == BG_SCAN_ACT_GET) && (bg_scan_out->action == BG_SCAN_ACT_GET_PPS_UAPSD))
        {
            bg_scan_out->enable           = bg_scan->enable;
            bg_scan_out->bss_type         = bg_scan->bss_type;
            bg_scan_out->chan_per_scan    = bg_scan->chan_per_scan;
            bg_scan_out->scan_interval    = wlan_le32_to_cpu(bg_scan->scan_interval);
            bg_scan_out->report_condition = wlan_le32_to_cpu(bg_scan->report_condition);
            pioctl_buf->data_read_written = sizeof(mlan_ds_scan) + MLAN_SUB_COMMAND_SIZE;
        }
#endif
    }
    LEAVE();
    return MLAN_STATUS_SUCCESS;
}
#endif

/**
 *  @brief This function finds ssid in ssid list.
 *
 *  @param pmpriv       A pointer to mlan_private structure
 *  @param ssid         SSID to find in the list
 *  @param bssid        BSSID to qualify the SSID selection (if provided)
 *  @param mode         Network mode: Infrastructure or IBSS
 *
 *  @return             index in BSSID list or < 0 if error
 */
t_s32 wlan_find_ssid_in_list(IN mlan_private *pmpriv, IN mlan_802_11_ssid *ssid, IN t_u8 *bssid, IN mlan_bss_mode mode)
{
    mlan_adapter *pmadapter = pmpriv->adapter;
    t_s32 net               = -1, j;
    t_u8 best_rssi          = 0;
    t_u32 i                 = 0U;

    ENTER();
    PRINTM(MINFO, "Num of entries in scan table = %d\n", pmadapter->num_in_scan_table);

    /*
     * Loop through the table until the maximum is reached or until a match
     *   is found based on the bssid field comparison
     */
    while (i < pmadapter->num_in_scan_table && (bssid == MNULL || net < 0))
    {
        if ((wlan_ssid_cmp(pmadapter, &pmadapter->pscan_table[i].ssid, ssid) == 0) &&
            ((bssid == MNULL) ||
             (__memcmp(pmadapter, pmadapter->pscan_table[i].mac_address, bssid, MLAN_MAC_ADDR_LENGTH) == 0)))
        {
            if (((mode == MLAN_BSS_MODE_INFRA) &&
                 (wlan_is_band_compatible(pmpriv->config_bands, pmadapter->pscan_table[i].bss_band) == 0U)) ||
                (wlan_find_cfp_by_band_and_channel(pmadapter, pmadapter->pscan_table[i].bss_band,
                                                   (t_u16)pmadapter->pscan_table[i].channel) == MNULL))
            {
                i++;
                continue;
            }

            switch (mode)
            {
                case MLAN_BSS_MODE_INFRA:
                case MLAN_BSS_MODE_IBSS:
                    j = wlan_is_network_compatible(pmpriv, (t_u32)i, mode);

                    if (j >= 0)
                    {
                        if (SCAN_RSSI(pmadapter->pscan_table[i].rssi) > best_rssi)
                        {
                            best_rssi = (t_u8)(SCAN_RSSI(pmadapter->pscan_table[i].rssi));
                            net       = (t_s32)i;
                        }
                    }
                    else
                    {
                        if (net == -1)
                        {
                            net = j;
                        }
                    }
                    break;
                case MLAN_BSS_MODE_AUTO:
                default:
                    /*
                     * Do not check compatibility if the mode requested is
                     *   Auto/Unknown.  Allows generic find to work without
                     *   verifying against the Adapter security settings
                     */
                    if (SCAN_RSSI(pmadapter->pscan_table[i].rssi) > best_rssi)
                    {
                        best_rssi = (t_u8)(SCAN_RSSI(pmadapter->pscan_table[i].rssi));
                        net       = (t_s32)i;
                    }
                    break;
            }
        }
        i++;
    }

    LEAVE();
    return net;
}

/**
 *  @brief This function finds a specific compatible BSSID in the scan list
 *
 *  @param pmpriv       A pointer to mlan_private structure
 *  @param bssid        BSSID to find in the scan list
 *  @param mode         Network mode: Infrastructure or IBSS
 *
 *  @return             index in BSSID list or < 0 if error
 */
t_s32 wlan_find_bssid_in_list(IN mlan_private *pmpriv, IN const t_u8 *bssid, IN mlan_bss_mode mode)
{
    mlan_adapter *pmadapter = pmpriv->adapter;
    t_s32 net               = -1;
    t_u32 i                 = 0U;

    ENTER();

    if (bssid == MNULL)
    {
        LEAVE();
        return -1;
    }

    PRINTM(MINFO, "FindBSSID: Num of BSSIDs = %d\n", pmadapter->num_in_scan_table);

    /*
     * Look through the scan table for a compatible match. The ret return
     *   variable will be equal to the index in the scan table (greater
     *   than zero) if the network is compatible.  The loop will continue
     *   past a matched bssid that is not compatible in case there is an
     *   AP with multiple SSIDs assigned to the same BSSID
     */
    while (net < 0 && i < pmadapter->num_in_scan_table)
    {
        if ((__memcmp(pmadapter, pmadapter->pscan_table[i].mac_address, bssid, MLAN_MAC_ADDR_LENGTH) == 0))
        {
            if (((mode == MLAN_BSS_MODE_INFRA) &&
                 (wlan_is_band_compatible(pmpriv->config_bands, pmadapter->pscan_table[i].bss_band) == 0U)) ||
                (wlan_find_cfp_by_band_and_channel(pmadapter, pmadapter->pscan_table[i].bss_band,
                                                   (t_u16)pmadapter->pscan_table[i].channel) == MNULL))
            {
                i++;
                continue;
            }
            switch (mode)
            {
                case MLAN_BSS_MODE_INFRA:
                case MLAN_BSS_MODE_IBSS:
                    /* fixme: temp disable. enable after below function is enabled */
                    /* net = wlan_is_network_compatible(pmpriv, i, mode); */
                    break;
                default:
                    net = (t_s32)i;
                    break;
            }
        }
        i++;
    }

    LEAVE();
    return net;
}

/**
 *  @brief Compare two SSIDs
 *
 *  @param pmadapter A pointer to mlan_adapter structure
 *  @param ssid1     A pointer to ssid to compare
 *  @param ssid2     A pointer to ssid to compare
 *
 *  @return         0--ssid is same, otherwise is different
 */
t_s32 wlan_ssid_cmp(IN pmlan_adapter pmadapter, IN mlan_802_11_ssid *ssid1, IN mlan_802_11_ssid *ssid2)
{
    ENTER();

    if ((ssid1 == MNULL) || (ssid2 == MNULL))
    {
        LEAVE();
        return -1;
    }

    if (ssid1->ssid_len != ssid2->ssid_len)
    {
        LEAVE();
        return -1;
    }

    LEAVE();
    return __memcmp(pmadapter, ssid1->ssid, ssid2->ssid, ssid1->ssid_len);
}

#ifndef CONFIG_MLAN_WMSDK
/**
 *  @brief This function inserts scan command node to scan_pending_q.
 *
 *  @param pmpriv       A pointer to mlan_private structure
 *  @param pcmd_node    A pointer to cmd_ctrl_node structure
 *  @return             N/A
 */
t_void wlan_queue_scan_cmd(IN mlan_private *pmpriv, IN cmd_ctrl_node *pcmd_node)
{
    mlan_adapter *pmadapter = pmpriv->adapter;

    ENTER();

    if (pcmd_node == MNULL)
        goto done;
    util_enqueue_list_tail(pmadapter->pmoal_handle, &pmadapter->scan_pending_q, (pmlan_linked_list)pcmd_node,
                           pmadapter->callbacks.moal_spin_lock, pmadapter->callbacks.moal_spin_unlock);

done:
    LEAVE();
}

/**
 *  @brief Find the AP with specific ssid in the scan list
 *
 *  @param pmpriv               A pointer to mlan_private structure
 *  @param preq_ssid_bssid      A pointer to AP's ssid returned
 *
 *  @return                     MLAN_STATUS_SUCCESS--success, otherwise--fail
 */
mlan_status wlan_find_best_network(IN mlan_private *pmpriv, OUT mlan_ssid_bssid *preq_ssid_bssid)
{
    mlan_adapter *pmadapter = pmpriv->adapter;
    mlan_status ret         = MLAN_STATUS_SUCCESS;
    BSSDescriptor_t *preq_bss;
    t_s32 i;

    ENTER();

    (void)__memset(pmadapter, preq_ssid_bssid, 0, sizeof(mlan_ssid_bssid));

    i = wlan_find_best_network_in_list(pmpriv);

    if (i >= 0)
    {
        preq_bss = &pmadapter->pscan_table[i];
        (void)__memcpy(pmadapter, &preq_ssid_bssid->ssid, &preq_bss->ssid, sizeof(mlan_802_11_ssid));
        (void)__memcpy(pmadapter, (t_u8 *)&preq_ssid_bssid->bssid, (t_u8 *)&preq_bss->mac_address,
                       MLAN_MAC_ADDR_LENGTH);

        /* Make sure we are in the right mode */
        if (pmpriv->bss_mode == MLAN_BSS_MODE_AUTO)
            pmpriv->bss_mode = preq_bss->bss_mode;
    }

    if (!preq_ssid_bssid->ssid.ssid_len)
    {
        ret = MLAN_STATUS_FAILURE;
        goto done;
    }

    PRINTM(MINFO,
           "Best network found = [%s], "
           "[%02x:%02x:%02x:%02x:%02x:%02x]\n",
           preq_ssid_bssid->ssid.ssid, preq_ssid_bssid->bssid[0], preq_ssid_bssid->bssid[1], preq_ssid_bssid->bssid[2],
           preq_ssid_bssid->bssid[3], preq_ssid_bssid->bssid[4], preq_ssid_bssid->bssid[5]);

done:
    LEAVE();
    return ret;
}

/**
 *  @brief Send a scan command for all available channels filtered on a spec
 *
 *  @param pmpriv       A pointer to mlan_private structure
 *  @param pioctl_buf   A pointer to MLAN IOCTL Request buffer
 *  @param preq_ssid    A pointer to AP's ssid returned
 *
 *  @return             MLAN_STATUS_SUCCESS--success, otherwise--fail
 */
mlan_status wlan_scan_specific_ssid(IN mlan_private *pmpriv, IN t_void *pioctl_buf, IN mlan_802_11_ssid *preq_ssid)
{
    mlan_status ret     = MLAN_STATUS_SUCCESS;
    mlan_callbacks *pcb = (mlan_callbacks *)&pmpriv->adapter->callbacks;
    wlan_user_scan_cfg *pscan_cfg;
    pmlan_ioctl_req pioctl_req = (mlan_ioctl_req *)pioctl_buf;

    ENTER();

    if (!preq_ssid)
    {
        if (pioctl_req)
            pioctl_req->status_code = MLAN_ERROR_CMD_SCAN_FAIL;
        ret = MLAN_STATUS_FAILURE;
        goto done;
    }

    wlan_scan_delete_ssid_table_entry(pmpriv, preq_ssid);

    ret =
        pcb->moal_malloc(pmpriv->adapter->pmoal_handle, sizeof(wlan_user_scan_cfg), MLAN_MEM_DEF, (t_u8 **)&pscan_cfg);

    if (ret != MLAN_STATUS_SUCCESS || !pscan_cfg)
    {
        PRINTM(MERROR, "Memory allocation for pscan_cfg failed!\n");
        if (pioctl_req)
            pioctl_req->status_code = MLAN_ERROR_NO_MEM;
        ret = MLAN_STATUS_FAILURE;
        goto done;
    }

    (void)__memset(pmpriv->adapter, pscan_cfg, 0x00, sizeof(wlan_user_scan_cfg));

    (void)__memcpy(pmpriv->adapter, pscan_cfg->ssid_list[0].ssid, preq_ssid->ssid, preq_ssid->ssid_len);
    pscan_cfg->keep_previous_scan = MTRUE;

    ret = wlan_scan_networks(pmpriv, pioctl_buf, pscan_cfg);

    if (pscan_cfg)
        pcb->moal_mfree(pmpriv->adapter->pmoal_handle, (t_u8 *)pscan_cfg);

done:
    LEAVE();
    return ret;
}

/**
 *  @brief Save a beacon buffer of the current bss descriptor
 *  Save the current beacon buffer to restore in the following cases that
 *  makes the bcn_buf not to contain the current ssid's beacon buffer.
 *    - the current ssid was not found somehow in the last scan.
 *    - the current ssid was the last entry of the scan table and overloaded.
 *
 *  @param pmpriv       A pointer to mlan_private structure
 *
 *  @return             N/A
 */
t_void wlan_save_curr_bcn(IN mlan_private *pmpriv)
{
    mlan_adapter *pmadapter    = pmpriv->adapter;
    mlan_callbacks *pcb        = (pmlan_callbacks)&pmadapter->callbacks;
    BSSDescriptor_t *pcurr_bss = &pmpriv->curr_bss_params.bss_descriptor;
    mlan_status ret            = MLAN_STATUS_SUCCESS;

    ENTER();
    /* save the beacon buffer if it is not saved or updated */
    if ((pmpriv->pcurr_bcn_buf == MNULL) || (pmpriv->curr_bcn_size != pcurr_bss->beacon_buf_size) ||
        (__memcmp(pmpriv->adapter, pmpriv->pcurr_bcn_buf, pcurr_bss->pbeacon_buf, pcurr_bss->beacon_buf_size)))
    {
        if (pmpriv->pcurr_bcn_buf)
        {
            pcb->moal_mfree(pmadapter->pmoal_handle, pmpriv->pcurr_bcn_buf);
            pmpriv->pcurr_bcn_buf = MNULL;
        }
        pmpriv->curr_bcn_size = pcurr_bss->beacon_buf_size;

        if (pmpriv->curr_bcn_size)
        {
            ret = pcb->moal_malloc(pmadapter->pmoal_handle, pcurr_bss->beacon_buf_size, MLAN_MEM_DEF,
                                   &pmpriv->pcurr_bcn_buf);

            if ((ret == MLAN_STATUS_SUCCESS) && pmpriv->pcurr_bcn_buf)
            {
                (void)__memcpy(pmpriv->adapter, pmpriv->pcurr_bcn_buf, pcurr_bss->pbeacon_buf,
                               pcurr_bss->beacon_buf_size);
                PRINTM(MINFO, "current beacon saved %d\n", pmpriv->curr_bcn_size);
            }
        }
    }
    LEAVE();
}

/**
 *  @brief Free a beacon buffer of the current bss descriptor
 *
 *  @param pmpriv       A pointer to mlan_private structure
 *
 *  @return             N/A
 */
t_void wlan_free_curr_bcn(IN mlan_private *pmpriv)
{
    mlan_adapter *pmadapter = pmpriv->adapter;
    mlan_callbacks *pcb     = (pmlan_callbacks)&pmadapter->callbacks;

    ENTER();
    if (pmpriv->pcurr_bcn_buf)
    {
        pcb->moal_mfree(pmadapter->pmoal_handle, pmpriv->pcurr_bcn_buf);
        pmpriv->pcurr_bcn_buf = MNULL;
    }
    LEAVE();
}
#endif /* CONFIG_MLAN_WMSDK */

static t_u32 wlan_find_worst_network_in_list(const BSSDescriptor_t *pbss_desc, t_u32 num_entries)
{
    t_u32 worst_net = 0U;
    /* To start with */
    t_s32 worst_rssi = pbss_desc[worst_net].rssi;
    t_u32 i          = 0U;

    ENTER();

    for (i = 1; i < num_entries; i++)
    {
        /* Smaller is better i.e. smaller rssi value here means better
           signal strength */
        if (pbss_desc[i].rssi > worst_rssi)
        {
            worst_rssi = pbss_desc[i].rssi;
            worst_net  = i;
        }
    }

    LEAVE();
    return worst_net;
}
