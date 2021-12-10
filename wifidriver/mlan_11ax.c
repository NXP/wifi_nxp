/** @file mlan_11ax.c
 *
 *  @brief This file defines the private and adapter data
 *  structures and declares global function prototypes used
 *  in MLAN module.
 *
 *  Copyright 2021 NXP
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

#ifdef CONFIG_11AX
#include <mlan_api.h>

/* Additional WMSDK header files */
#include <wmerrno.h>
#include <wm_os.h>

/* Always keep this include at the end of all include files */
#include <mlan_remap_mem_operations.h>

#include "wifi-sdio.h"
/********************************************************
 *    Local Variables
 *    ********************************************************/

/********************************************************
 *    Global Variables
 *    ********************************************************/

/********************************************************
 *    Local Functions
 *    *******************************************************/

/**
 *  @brief This function check if AP support TWT Response.
 *
 *  @param pbss_desc    A pointer to BSSDescriptor_t structure
 *
 *  @return        MTRUE/MFALSE
 */
t_u8 wlan_check_ap_11ax_twt_supported(BSSDescriptor_t *pbss_desc)
{
    if (!pbss_desc->phe_cap)
        return MFALSE;
    if (!(pbss_desc->phe_cap->he_mac_cap[0] & HE_MAC_CAP_TWT_REQ_SUPPORT))
        return MFALSE;
    if (!pbss_desc->pext_cap)
        return MFALSE;
    if (!ISSUPP_EXTCAP_EXT_TWT_RESP(pbss_desc->pext_cap->ext_cap))
        return MFALSE;
    return MTRUE;
}

/**
 *  @brief This function check if we should enable TWT support
 *
 *  @param pmpriv       A pointer to mlan_private structure
 *  @param pbss_desc    A pointer to BSSDescriptor_t structure
 *
 *  @return        MTRUE/MFALSE
 */
t_u8 wlan_check_11ax_twt_supported(mlan_private *pmpriv, BSSDescriptor_t *pbss_desc)
{
    mlan_adapter *pmadapter = pmpriv->adapter;
#ifdef CONFIG_5GHz_SUPPORT
    MrvlIEtypes_He_cap_t *phecap    = (MrvlIEtypes_He_cap_t *)&pmpriv->user_he_cap;
    MrvlIEtypes_He_cap_t *hw_he_cap = (MrvlIEtypes_He_cap_t *)&pmadapter->hw_he_cap;
#else
    MrvlIEtypes_He_cap_t *phecap    = (MrvlIEtypes_He_cap_t *)&pmpriv->user_2g_he_cap;
    MrvlIEtypes_He_cap_t *hw_he_cap = (MrvlIEtypes_He_cap_t *)&pmadapter->hw_2g_he_cap;
#endif

    if (pbss_desc && !wlan_check_ap_11ax_twt_supported(pbss_desc))
    {
        PRINTM(MINFO, "AP don't support twt feature\n");
        return MFALSE;
    }
    if (pbss_desc)
    {
        if (pbss_desc->bss_band & BAND_A)
        {
            hw_he_cap = (MrvlIEtypes_He_cap_t *)&pmadapter->hw_he_cap;
            phecap    = (MrvlIEtypes_He_cap_t *)&pmpriv->user_he_cap;
        }
        else
        {
            hw_he_cap = (MrvlIEtypes_He_cap_t *)&pmadapter->hw_2g_he_cap;
            phecap    = (MrvlIEtypes_He_cap_t *)&pmpriv->user_2g_he_cap;
        }
    }
    if (!(hw_he_cap->he_mac_cap[0] & HE_MAC_CAP_TWT_REQ_SUPPORT))
    {
        PRINTM(MINFO, "FW don't support TWT\n");
        return MFALSE;
    }
    if (phecap->he_mac_cap[0] & HE_MAC_CAP_TWT_REQ_SUPPORT)
        return MTRUE;
    PRINTM(MINFO, "USER HE_MAC_CAP don't support TWT\n");
    return MFALSE;
}

/**
 *  @brief This function fills the HE cap tlv out put format is LE, not CPU
 *
 *  @param pmpriv         A pointer to mlan_private structure
 *  @param band           5G or 2.4 G
 *  @param phe_cap        A pointer to MrvlIEtypes_Data_t structure
 *  @param flag           MTRUE -- phe_cap has the setting for resp
 *                                 MFALSE -- phe_cap is clean
 *
 *  @return bytes added to the phe_cap
 */
t_u16 wlan_fill_he_cap_tlv(mlan_private *pmpriv, t_u8 band, MrvlIEtypes_Extension_t *phe_cap, t_u8 flag)
{
    t_u16 len = 0;

    if (!phe_cap)
        return 0;
    if (band & BAND_A)
    {
        (void)__memcpy(pmpriv->adapter, (t_u8 *)phe_cap, pmpriv->user_he_cap, pmpriv->user_hecap_len);
        len = pmpriv->user_hecap_len;
    }
    else
    {
        (void)__memcpy(pmpriv->adapter, (t_u8 *)phe_cap, pmpriv->user_2g_he_cap, pmpriv->user_2g_hecap_len);
        len = pmpriv->user_2g_hecap_len;
    }
    phe_cap->type = wlan_cpu_to_le16(phe_cap->type);
    phe_cap->len  = wlan_cpu_to_le16(phe_cap->len);

    return len;
}

/**
 *  @brief This function append the 802_11ax HE capability  tlv
 *
 *  @param pmpriv       A pointer to mlan_private structure
 *  @param pbss_desc    A pointer to BSSDescriptor_t structure
 *  @param ppbuffer     A Pointer to command buffer pointer
 *
 *  @return bytes added to the buffer
 */
int wlan_cmd_append_11ax_tlv(mlan_private *pmpriv, BSSDescriptor_t *pbss_desc, t_u8 **ppbuffer)
{
    MrvlIEtypes_He_cap_t *phecap = MNULL;
    int len                      = 0;

    ENTER();
    /* Null Checks */
    if (ppbuffer == MNULL)
    {
        LEAVE();
        return 0;
    }
    if (*ppbuffer == MNULL)
    {
        LEAVE();
        return 0;
    }
    /** check if AP support HE, if not return right away */
    if (!pbss_desc->phe_cap)
    {
        LEAVE();
        return 0;
    }
    phecap = (MrvlIEtypes_He_cap_t *)*ppbuffer;
    if (pbss_desc->bss_band & BAND_A)
    {
        (void)__memcpy(pmpriv->adapter, *ppbuffer, pmpriv->user_he_cap, pmpriv->user_hecap_len);
        *ppbuffer += pmpriv->user_hecap_len;
        len = pmpriv->user_hecap_len;
    }
    else
    {
        (void)__memcpy(pmpriv->adapter, *ppbuffer, pmpriv->user_2g_he_cap, pmpriv->user_2g_hecap_len);
        *ppbuffer += pmpriv->user_2g_hecap_len;
        len = pmpriv->user_2g_hecap_len;
    }
    phecap->type = wlan_cpu_to_le16(phecap->type);
    phecap->len  = wlan_cpu_to_le16(phecap->len);
    phecap->he_phy_cap[0] &= ~(MBIT(3) | MBIT(4));
    PRINTF("******* HE Cap ******\n\r");
    PRINTF("Type: %d\n\r", phecap->type);
    PRINTF("Len: %d\n\r", phecap->len);
    LEAVE();
    return len;
}

/**
 *  @brief This function save the 11ax cap from FW.
 *
 *  @param pmadapater   A pointer to mlan_adapter
 *  @param hw_he_cap    A pointer to MrvlIEtypes_Extension_t
 *
 *  @return N/A
 */
void wlan_update_11ax_cap(mlan_adapter *pmadapter, MrvlIEtypes_Extension_t *hw_he_cap)
{
    MrvlIEtypes_He_cap_t *phe_cap = MNULL;
    t_u8 i                        = 0;
    t_u8 he_cap_2g                = 0;

    ENTER();
    if ((hw_he_cap->len + sizeof(MrvlIEtypesHeader_t)) > sizeof(pmadapter->hw_he_cap))
    {
        PRINTM(MERROR, "hw_he_cap too big, len=%d\n", hw_he_cap->len);
        LEAVE();
        return;
    }
    phe_cap = (MrvlIEtypes_He_cap_t *)hw_he_cap;
    if (phe_cap->he_phy_cap[0] & (AX_2G_20MHZ_SUPPORT | AX_2G_40MHZ_SUPPORT))
    {
        pmadapter->hw_2g_hecap_len = hw_he_cap->len + sizeof(MrvlIEtypesHeader_t);
        (void)__memcpy(pmadapter, pmadapter->hw_2g_he_cap, (t_u8 *)hw_he_cap,
                       hw_he_cap->len + sizeof(MrvlIEtypesHeader_t));
        pmadapter->fw_bands |= BAND_GAX;
        pmadapter->config_bands |= BAND_GAX;
        he_cap_2g = MTRUE;
        DBG_HEXDUMP(MCMD_D, "2.4G HE capability IE ", (t_u8 *)pmadapter->hw_2g_he_cap, pmadapter->hw_2g_hecap_len);
    }
    else
    {
        pmadapter->fw_bands |= BAND_AAX;
        pmadapter->config_bands |= BAND_AAX;
        pmadapter->hw_hecap_len = hw_he_cap->len + sizeof(MrvlIEtypesHeader_t);
        (void)__memcpy(pmadapter, pmadapter->hw_he_cap, (t_u8 *)hw_he_cap,
                       hw_he_cap->len + sizeof(MrvlIEtypesHeader_t));
        DBG_HEXDUMP(MCMD_D, "5G HE capability IE ", (t_u8 *)pmadapter->hw_he_cap, pmadapter->hw_hecap_len);
    }
    for (i = 0; i < pmadapter->priv_num; i++)
    {
        if (pmadapter->priv[i])
        {
            pmadapter->priv[i]->config_bands = pmadapter->config_bands;
            if (he_cap_2g)
            {
                pmadapter->priv[i]->user_2g_hecap_len = pmadapter->hw_2g_hecap_len;
                (void)__memcpy(pmadapter, pmadapter->priv[i]->user_2g_he_cap, pmadapter->hw_2g_he_cap,
                               pmadapter->hw_2g_hecap_len);
            }
            else
            {
                pmadapter->priv[i]->user_hecap_len = pmadapter->hw_hecap_len;
                (void)__memcpy(pmadapter, pmadapter->priv[i]->user_he_cap, pmadapter->hw_he_cap,
                               pmadapter->hw_hecap_len);
            }
        }
    }
    LEAVE();
    return;
}

/**
 *  @brief This function check if 11AX is allowed in bandcfg
 *
 *  @param pmpriv	A pointer to mlan_private structure
 *  @param bss_band 	bss band
 *
 *  @return 0--not allowed, other value allowed
 */
t_u16 wlan_11ax_bandconfig_allowed(mlan_private *pmpriv, t_u16 bss_band)
{
    if (!IS_FW_SUPPORT_11AX(pmpriv->adapter))
        return MFALSE;
    if (pmpriv->bss_mode == MLAN_BSS_MODE_IBSS)
    {
        if (bss_band & BAND_G)
            return (pmpriv->adapter->adhoc_start_band & BAND_GAX);
#ifdef CONFIG_5GHz_SUPPORT
        else if (bss_band & BAND_A)
            return (pmpriv->adapter->adhoc_start_band & BAND_AAX);
#endif
    }
    else
    {
        if (bss_band & BAND_G)
            return (pmpriv->config_bands & BAND_GAX);
#ifdef CONFIG_5GHz_SUPPORT
        else if (bss_band & BAND_A)
            return (pmpriv->config_bands & BAND_AAX);
#endif
    }
    return MFALSE;
}

/**
 *  @brief This function prepares and sends 11ax cfg command
 *
 *  @param pmpriv       A pointer to mlan_private structure
 *  @param action       the action: GET or SET
 *  @param he_cfg       A pointer to mlan_ds_11ax_he_cfg structure
 *
 *  @return         MLAN_STATUS_SUCCESS
 */
int wlan_cmd_11ax_cfg(mlan_private *pmpriv, t_u16 action, mlan_ds_11ax_he_cfg *he_cfg)
{
    HostCmd_DS_11AX_CFG *axcfg   = MNULL;
    t_u8 *pos                    = MNULL;
    MrvlIEtypes_Extension_t *tlv = MNULL;

    ENTER();
    wifi_get_command_lock();
    HostCmd_DS_COMMAND *cmd = wifi_get_command_buffer();
    cmd->command            = wlan_cpu_to_le16(HostCmd_CMD_11AX_CFG);
    cmd->size               = S_DS_GEN + sizeof(HostCmd_DS_11AX_CFG);
    axcfg                   = (HostCmd_DS_11AX_CFG *)((t_u32)cmd + S_DS_GEN);
    axcfg->action           = action;
    axcfg->band_config      = he_cfg->band & 0xFF;
    pos                     = (t_u8 *)axcfg->val;
    /** HE Capability */
    if (he_cfg->he_cap.len && (he_cfg->he_cap.ext_id == HE_CAPABILITY))
    {
        tlv       = (MrvlIEtypes_Extension_t *)pos;
        tlv->type = wlan_cpu_to_le16(he_cfg->he_cap.id);
        tlv->len  = wlan_cpu_to_le16(he_cfg->he_cap.len);
        (void)__memcpy(pmpriv->adapter, &tlv->ext_id, &he_cfg->he_cap.ext_id, he_cfg->he_cap.len);
        cmd->size += he_cfg->he_cap.len + sizeof(MrvlIEtypesHeader_t);
        pos += he_cfg->he_cap.len + sizeof(MrvlIEtypesHeader_t);
    }
    cmd->seq_num = (0x01) << 12;
    cmd->result  = 0x00;

    wifi_wait_for_cmdresp(action == HostCmd_ACT_GEN_GET ? he_cfg : NULL);
    LEAVE();
    return wm_wifi.cmd_resp_status;
}

/**
 *  @brief This function handles the command response of 11axcfg
 *
 *  @param pmpriv       A pointer to mlan_private structure
 *  @param resp         A pointer to HostCmd_DS_COMMAND
 *  @param hecfg        A pointer to mlan_ds_11ax_he_cfg structure
 *
 *  @return        MLAN_STATUS_SUCCESS
 */
mlan_status wlan_ret_11ax_cfg(pmlan_private pmpriv, HostCmd_DS_COMMAND *resp, mlan_ds_11ax_he_cfg *hecfg)
{
    HostCmd_DS_11AX_CFG *axcfg   = (HostCmd_DS_11AX_CFG *)&resp->params.axcfg;
    mlan_ds_11ax_he_capa *hecap  = MNULL;
    MrvlIEtypes_Extension_t *tlv = MNULL;
    t_u16 left_len = 0, tlv_type = 0, tlv_len = 0;

    ENTER();

    if (hecfg == MNULL)
        goto done;

    hecfg->band = axcfg->band_config;
    hecap       = (mlan_ds_11ax_he_capa *)&hecfg->he_cap;

    /* TLV parse */
    left_len = resp->size - sizeof(HostCmd_DS_11AX_CFG) - S_DS_GEN;
    tlv      = (MrvlIEtypes_Extension_t *)axcfg->val;

    while (left_len > sizeof(MrvlIEtypesHeader_t))
    {
        tlv_type = wlan_le16_to_cpu(tlv->type);
        tlv_len  = wlan_le16_to_cpu(tlv->len);
        if (tlv_type == EXTENSION)
        {
            switch (tlv->ext_id)
            {
                case HE_CAPABILITY:
                    hecap->id  = tlv_type;
                    hecap->len = tlv_len;
                    (void)__memcpy(pmpriv->adapter, (t_u8 *)&hecap->ext_id, (t_u8 *)&tlv->ext_id, tlv_len);
                    if (hecfg->band & MBIT(1))
                    {
                        (void)__memcpy(pmpriv->adapter, (t_u8 *)&pmpriv->user_he_cap, (t_u8 *)tlv,
                                       tlv_len + sizeof(MrvlIEtypesHeader_t));
                        pmpriv->user_hecap_len =
                            MIN(tlv_len + sizeof(MrvlIEtypesHeader_t), sizeof(pmpriv->user_he_cap));
                        PRINTM(MCMND, "user_hecap_len=%d\n", pmpriv->user_hecap_len);
                        PRINTF("user_hecap_len=%d\n", pmpriv->user_hecap_len);
                    }
                    else
                    {
                        (void)__memcpy(pmpriv->adapter, (t_u8 *)&pmpriv->user_2g_he_cap, (t_u8 *)tlv,
                                       tlv_len + sizeof(MrvlIEtypesHeader_t));
                        pmpriv->user_2g_hecap_len =
                            MIN(tlv_len + sizeof(MrvlIEtypesHeader_t), sizeof(pmpriv->user_2g_he_cap));
                        PRINTM(MCMND, "user_2g_hecap_len=%d\n", pmpriv->user_2g_hecap_len);
                        PRINTF("user_2g_hecap_len=%d\n", pmpriv->user_2g_hecap_len);
                    }
                    break;
                default:
                    break;
            }
        }

        left_len -= (sizeof(MrvlIEtypesHeader_t) + tlv_len);
        tlv = (MrvlIEtypes_Extension_t *)((t_u8 *)tlv + tlv_len + sizeof(MrvlIEtypesHeader_t));
    }
done:
    LEAVE();
    return MLAN_STATUS_SUCCESS;
}

/**
 *  @brief              This function prepares TWT cfg command to configure setup/teardown
 *
 *  @param pmpriv       A pointer to mlan_private structure
 *  @param cmd          A pointer to HostCmd_DS_COMMAND structure
 *  @param cmd_action   The action: GET or SET
 *  @param pdata_buf    A pointer to data buffer
 *
 *  @return             Status returned
 */
mlan_status wlan_cmd_twt_cfg(pmlan_private pmpriv, HostCmd_DS_COMMAND *cmd, t_u16 cmd_action, t_void *pdata_buf)
{
    HostCmd_DS_TWT_CFG *hostcmd_twtcfg        = (HostCmd_DS_TWT_CFG *)&cmd->params.twtcfg;
    mlan_ds_twtcfg *ds_twtcfg                 = (mlan_ds_twtcfg *)pdata_buf;
    hostcmd_twt_setup *twt_setup_params       = MNULL;
    hostcmd_twt_teardown *twt_teardown_params = MNULL;
    mlan_status ret                           = MLAN_STATUS_SUCCESS;

    ENTER();
    cmd->command = wlan_cpu_to_le16(HostCmd_CMD_TWT_CFG);

    hostcmd_twtcfg->action = wlan_cpu_to_le16(cmd_action);
    hostcmd_twtcfg->sub_id = wlan_cpu_to_le16(ds_twtcfg->sub_id);

    cmd->size = S_DS_GEN + sizeof(hostcmd_twtcfg->action) + sizeof(hostcmd_twtcfg->sub_id);
    switch (hostcmd_twtcfg->sub_id)
    {
        case MLAN_11AX_TWT_SETUP_SUBID:
            twt_setup_params = &hostcmd_twtcfg->param.twt_setup;
            __memset(pmpriv->adapter, twt_setup_params, 0x00, sizeof(hostcmd_twtcfg->param.twt_setup));
            twt_setup_params->implicit            = ds_twtcfg->param.twt_setup.implicit;
            twt_setup_params->announced           = ds_twtcfg->param.twt_setup.announced;
            twt_setup_params->trigger_enabled     = ds_twtcfg->param.twt_setup.trigger_enabled;
            twt_setup_params->twt_info_disabled   = ds_twtcfg->param.twt_setup.twt_info_disabled;
            twt_setup_params->negotiation_type    = ds_twtcfg->param.twt_setup.negotiation_type;
            twt_setup_params->twt_wakeup_duration = ds_twtcfg->param.twt_setup.twt_wakeup_duration;
            twt_setup_params->flow_identifier     = ds_twtcfg->param.twt_setup.flow_identifier;
            twt_setup_params->hard_constraint     = ds_twtcfg->param.twt_setup.hard_constraint;
            twt_setup_params->twt_exponent        = ds_twtcfg->param.twt_setup.twt_exponent;
            twt_setup_params->twt_mantissa        = wlan_cpu_to_le16(ds_twtcfg->param.twt_setup.twt_mantissa);
            twt_setup_params->twt_request         = ds_twtcfg->param.twt_setup.twt_request;
            cmd->size += sizeof(hostcmd_twtcfg->param.twt_setup);
            break;
        case MLAN_11AX_TWT_TEARDOWN_SUBID:
            twt_teardown_params = &hostcmd_twtcfg->param.twt_teardown;
            __memset(pmpriv->adapter, twt_teardown_params, 0x00, sizeof(hostcmd_twtcfg->param.twt_teardown));
            twt_teardown_params->flow_identifier  = ds_twtcfg->param.twt_teardown.flow_identifier;
            twt_teardown_params->negotiation_type = ds_twtcfg->param.twt_teardown.negotiation_type;
            twt_teardown_params->teardown_all_twt = ds_twtcfg->param.twt_teardown.teardown_all_twt;
            cmd->size += sizeof(hostcmd_twtcfg->param.twt_teardown);
            break;
        default:
            PRINTM(MERROR, "Unknown subcmd %x\n", ds_twtcfg->sub_id);
            ret = MLAN_STATUS_FAILURE;
            break;
    }
    cmd->size = wlan_cpu_to_le16(cmd->size);

    LEAVE();
    return ret;
}

/**
 *  @brief This function prepares 11ax command
 *
 *  @param pmpriv       A pointer to mlan_private structure
 *  @param cmd      A pointer to HostCmd_DS_COMMAND structure
 *  @param cmd_action   the action: GET or SET
 *  @param pdata_buf    A pointer to data buffer
 *  @return         MLAN_STATUS_SUCCESS
 */
mlan_status wlan_cmd_11ax_cmd(pmlan_private pmpriv, HostCmd_DS_COMMAND *cmd, t_u16 cmd_action, t_void *pdata_buf)
{
    HostCmd_DS_11AX_CMD_CFG *axcmd    = &cmd->params.axcmd;
    mlan_ds_11ax_cmd_cfg *ds_11ax_cmd = (mlan_ds_11ax_cmd_cfg *)pdata_buf;
    mlan_ds_11ax_txomi_cmd *txomi_cmd = (mlan_ds_11ax_txomi_cmd *)&ds_11ax_cmd->param;

#ifndef CONFIG_MLAN_WMSDK
    mlan_ds_11ax_sr_cmd *sr_cmd           = (mlan_ds_11ax_sr_cmd *)&ds_11ax_cmd->param;
    mlan_ds_11ax_beam_cmd *beam_cmd       = (mlan_ds_11ax_beam_cmd *)&ds_11ax_cmd->param;
    mlan_ds_11ax_htc_cmd *htc_cmd         = (mlan_ds_11ax_htc_cmd *)&ds_11ax_cmd->param;
    mlan_ds_11ax_txop_cmd *txop_cmd       = (mlan_ds_11ax_txop_cmd *)&ds_11ax_cmd->param;
    mlan_ds_11ax_toltime_cmd *toltime_cmd = (mlan_ds_11ax_toltime_cmd *)&ds_11ax_cmd->param;
    MrvlIEtypes_Data_t *tlv               = MNULL;
#endif /* CONFIG_MLAN_WMSDK */

    ENTER();
    cmd->command = wlan_cpu_to_le16(HostCmd_CMD_11AX_CMD);
    cmd->size    = sizeof(HostCmd_DS_11AX_CMD_CFG) + S_DS_GEN;

    axcmd->action = wlan_cpu_to_le16(cmd_action);
    axcmd->sub_id = wlan_cpu_to_le16(ds_11ax_cmd->sub_id);
    switch (ds_11ax_cmd->sub_id)
    {
        case MLAN_11AXCMD_TXOMI_SUBID:
            (void)__memcpy(pmpriv->adapter, axcmd->val, &txomi_cmd->omi, sizeof(t_u16));
            cmd->size += sizeof(t_u16);
            break;
#ifndef CONFIG_MLAN_WMSDK
        case MLAN_11AXCMD_SR_SUBID:
            tlv              = (MrvlIEtypes_Data_t *)axcmd->val;
            tlv->header.type = wlan_cpu_to_le16(sr_cmd->type);
            tlv->header.len  = wlan_cpu_to_le16(sr_cmd->len);
            (void)__memcpy(pmpriv->adapter, tlv->data, &sr_cmd->param.obss_pd_offset.offset, sr_cmd->len);
            cmd->size += sizeof(MrvlIEtypesHeader_t) + sr_cmd->len;
            break;
        case MLAN_11AXCMD_BEAM_SUBID:
            axcmd->val[0] = beam_cmd->value;
            cmd->size += sizeof(t_u8);
            break;
        case MLAN_11AXCMD_HTC_SUBID:
            axcmd->val[0] = htc_cmd->value;
            cmd->size += sizeof(t_u8);
            break;
        case MLAN_11AXCMD_TXOPRTS_SUBID:
            (void)__memcpy(pmpriv->adapter, axcmd->val, &txop_cmd->rts_thres, sizeof(t_u16));
            cmd->size += sizeof(t_u16);
            break;
        case MLAN_11AXCMD_OBSS_TOLTIME_SUBID:
            (void)__memcpy(pmpriv->adapter, axcmd->val, &toltime_cmd->tol_time, sizeof(t_u32));
            cmd->size += sizeof(t_u32);
            break;
#endif /* CONFIG_MLAN_WMSDK */
        default:
            PRINTM(MERROR, "Unknown subcmd %x\n", ds_11ax_cmd->sub_id);
            break;
    }

    cmd->size = wlan_cpu_to_le16(cmd->size);

    LEAVE();
    return MLAN_STATUS_SUCCESS;
}

/**
 *  @brief This function handles the command response of 11axcmd
 *
 *  @param pmpriv       A pointer to mlan_private structure
 *  @param resp         A pointer to HostCmd_DS_COMMAND
 *  @param pioctl_buf   A pointer to mlan_ioctl_req structure
 *
 *  @return        MLAN_STATUS_SUCCESS
 */
mlan_status wlan_ret_11ax_cmd(pmlan_private pmpriv, HostCmd_DS_COMMAND *resp, mlan_ioctl_req *pioctl_buf)
{
    mlan_ds_11ax_cmd_cfg *cfg      = MNULL;
    HostCmd_DS_11AX_CMD_CFG *axcmd = &resp->params.axcmd;
    MrvlIEtypes_Data_t *tlv        = MNULL;
    t_s16 left_len                 = 0;
    t_u16 tlv_len                  = 0;

    ENTER();

    if (pioctl_buf == MNULL)
    {
        goto done;
    }

    cfg         = (mlan_ds_11ax_cmd_cfg *)pioctl_buf->pbuf;
    cfg->sub_id = wlan_le16_to_cpu(axcmd->sub_id);

    switch (axcmd->sub_id)
    {
        case MLAN_11AXCMD_SR_SUBID:
            /* TLV parse */
            left_len = resp->size - sizeof(HostCmd_DS_11AX_CMD_CFG) - S_DS_GEN;
            tlv      = (MrvlIEtypes_Data_t *)axcmd->val;
            while (left_len > (t_s16)sizeof(MrvlIEtypesHeader_t))
            {
                tlv_len = wlan_le16_to_cpu(tlv->header.len);
                (void)__memcpy(pmpriv->adapter, cfg->param.sr_cfg.param.obss_pd_offset.offset, tlv->data, tlv_len);
                left_len -= (sizeof(MrvlIEtypesHeader_t) + tlv_len);
                tlv = (MrvlIEtypes_Data_t *)((t_u8 *)tlv + tlv_len + sizeof(MrvlIEtypesHeader_t));
            }
            break;
        case MLAN_11AXCMD_BEAM_SUBID:
            cfg->param.beam_cfg.value = *axcmd->val;
            break;
        case MLAN_11AXCMD_HTC_SUBID:
            cfg->param.htc_cfg.value = *axcmd->val;
            break;
        case MLAN_11AXCMD_TXOPRTS_SUBID:
            (void)__memcpy(pmpriv->adapter, &cfg->param.txop_cfg.rts_thres, axcmd->val, sizeof(t_u16));
            break;
        case MLAN_11AXCMD_TXOMI_SUBID:
            (void)__memcpy(pmpriv->adapter, &cfg->param.txomi_cfg.omi, axcmd->val, sizeof(t_u16));
            break;
        case MLAN_11AXCMD_OBSS_TOLTIME_SUBID:
            (void)__memcpy(pmpriv->adapter, &cfg->param.toltime_cfg.tol_time, axcmd->val, sizeof(t_u32));
            break;
        default:
            PRINTM(MERROR, "Unknown subcmd %x\n", axcmd->sub_id);
            break;
    }

done:
    LEAVE();
    return MLAN_STATUS_SUCCESS;
}
#endif
