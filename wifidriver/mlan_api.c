/** @file mlan_api.c
 *
 *  @brief This file provides more APIs for mlan.
 *
 *  Copyright 2008-2022 NXP
 *
 *  Licensed under the LA_OPT_NXP_Software_License.txt (the "Agreement")
 *
 */

#include <stdio.h>
#include <mlan_api.h>
#ifdef CONFIG_COMBO_SCAN
#include <string.h>
#endif
/* Additional WMSDK header files */
#include <wmerrno.h>
#include <wm_os.h>

#include <wifi.h>

#if defined(RW610)
#include "wifi-imu.h"
#else
#include "wifi-sdio.h"
#endif
#include "wifi-internal.h"

#ifdef CONFIG_MBO
#include "mlan_mbo.h"
#endif

/*
 * Bit 0 : Assoc Req
 * Bit 1 : Assoc Resp
 * Bit 2 : ReAssoc Req
 * Bit 3 : ReAssoc Resp
 * Bit 4 : Probe Req
 * Bit 5 : Probe Resp
 * Bit 8 : Beacon
 */
/** Mask for Assoc request frame */
#define MGMT_MASK_ASSOC_REQ 0x01
/** Mask for ReAssoc request frame */
#define MGMT_MASK_REASSOC_REQ 0x04
/** Mask for Assoc response frame */
#define MGMT_MASK_ASSOC_RESP 0x02
/** Mask for ReAssoc response frame */
#define MGMT_MASK_REASSOC_RESP 0x08
/** Mask for probe request frame */
#define MGMT_MASK_PROBE_REQ 0x10
/** Mask for probe response frame */
#define MGMT_MASK_PROBE_RESP 0x20
/** Mask for beacon frame */
#define MGMT_MASK_BEACON 0x100
/** Mask for action frame */
#define MGMT_MASK_ACTION 0x2000
/** Mask to clear previous settings */
#define MGMT_MASK_CLEAR 0x000

static const char driver_version_format[] = "SD878x-%s-%s-WM";
static const char driver_version[]        = "702.1.0";

static unsigned int mgmt_ie_index_bitmap = 0x00;
country_code_t wifi_11d_country          = COUNTRY_NONE;

/* This were static functions in mlan file */
mlan_status wlan_cmd_802_11_deauthenticate(IN pmlan_private pmpriv, IN HostCmd_DS_COMMAND *cmd, IN t_void *pdata_buf);
mlan_status wlan_cmd_reg_access(IN HostCmd_DS_COMMAND *cmd, IN t_u16 cmd_action, IN t_void *pdata_buf);
mlan_status wlan_cmd_mem_access(IN HostCmd_DS_COMMAND *cmd, IN t_u16 cmd_action, IN t_void *pdata_buf);
#ifdef CONFIG_WLAN_BRIDGE
mlan_status wlan_cmd_bridge_mode(IN HostCmd_DS_COMMAND *cmd, IN t_u16 cmd_action, IN t_void *pdata_buf);
#endif
mlan_status wlan_cmd_auto_reconnect(IN HostCmd_DS_COMMAND *cmd, IN t_u16 cmd_action, IN t_void *pdata_buf);
mlan_status wlan_misc_ioctl_region(IN pmlan_adapter pmadapter, IN pmlan_ioctl_req pioctl_req);
#ifdef CONFIG_11K_OFFLOAD
mlan_status wlan_cmd_11k_neighbor_req(mlan_private *pmpriv, HostCmd_DS_COMMAND *pcmd);
#endif

int wifi_set_mac_multicast_addr(const char *mlist, t_u32 num_of_addr);
int wifi_send_disable_supplicant(int mode);
int wifi_send_rf_channel_cmd(wifi_rf_channel_t *rf_channel);
int wifi_get_set_rf_tx_power(t_u16 cmd_action, wifi_tx_power_t *tx_power);

int wifi_deauthenticate(uint8_t *bssid)
{
    HostCmd_DS_COMMAND *cmd = wifi_get_command_buffer();

    (void)wifi_get_command_lock();

    /* fixme: check if this static selection is ok */
#ifdef CONFIG_P2P
    cmd->seq_num = (0x01) << 13;
#else
    cmd->seq_num = 0x0;
#endif
    cmd->result = 0x0;

    (void)wlan_cmd_802_11_deauthenticate((mlan_private *)mlan_adap->priv[0], cmd, bssid);
    (void)wifi_wait_for_cmdresp(NULL);
    return WM_SUCCESS;
}

int wifi_get_eeprom_data(uint32_t offset, uint32_t byte_count, uint8_t *buf)
{
    mlan_ds_read_eeprom eeprom_rd;
    eeprom_rd.offset     = offset;
    eeprom_rd.byte_count = byte_count;

    (void)wifi_get_command_lock();
    HostCmd_DS_COMMAND *cmd = wifi_get_command_buffer();

    cmd->command = HostCmd_CMD_802_11_EEPROM_ACCESS;
    cmd->seq_num = 0x0;
    cmd->result  = 0x0;

    (void)wlan_cmd_reg_access(cmd, HostCmd_ACT_GEN_GET, &eeprom_rd);
    (void)wifi_wait_for_cmdresp(buf);
    return wm_wifi.cmd_resp_status;
}

int wifi_reg_access(wifi_reg_t reg_type, uint16_t action, uint32_t offset, uint32_t *value)
{
    mlan_ds_reg_rw reg_rw;
    reg_rw.offset = offset;
    reg_rw.value  = *value;
    uint16_t hostcmd;
    int ret = WM_SUCCESS;
    switch (reg_type)
    {
        case REG_MAC:
            hostcmd = HostCmd_CMD_MAC_REG_ACCESS;
            break;
        case REG_BBP:
            hostcmd = HostCmd_CMD_BBP_REG_ACCESS;
            break;
        case REG_RF:
            hostcmd = HostCmd_CMD_RF_REG_ACCESS;
            break;
        default:
            wifi_e("Incorrect register type");
            ret = -WM_FAIL;
            break;
    }

    if (ret != WM_SUCCESS)
    {
        return ret;
    }

    (void)wifi_get_command_lock();
    HostCmd_DS_COMMAND *cmd = wifi_get_command_buffer();

    cmd->command = hostcmd;
    cmd->seq_num = 0x0;
    cmd->result  = 0x0;

    (void)wlan_cmd_reg_access(cmd, action, &reg_rw);
    (void)wifi_wait_for_cmdresp(action == HostCmd_ACT_GEN_GET ? value : NULL);
    return wm_wifi.cmd_resp_status;
}

int wifi_mem_access(uint16_t action, uint32_t addr, uint32_t *value)
{
    mlan_ds_mem_rw mem_rw;
    mem_rw.addr  = addr;
    mem_rw.value = *value;

    (void)wifi_get_command_lock();
    HostCmd_DS_COMMAND *cmd = wifi_get_command_buffer();

    cmd->command = HostCmd_CMD_MEM_ACCESS;
    cmd->seq_num = 0x0;
    cmd->result  = 0x0;

    (void)wlan_cmd_mem_access(cmd, action, &mem_rw);

    (void)wifi_wait_for_cmdresp(action == HostCmd_ACT_GEN_GET ? value : NULL);
    return wm_wifi.cmd_resp_status;
}

#ifndef CONFIG_MLAN_WMSDK
static int wifi_auto_reconnect(uint16_t action, wifi_auto_reconnect_config_t *auto_reconnect_config)
{
    mlan_ds_auto_reconnect auto_reconnect;

    (void)memset(&auto_reconnect, 0x00, sizeof(mlan_ds_auto_reconnect));

    if (auto_reconnect_config)
    {
        auto_reconnect.reconnect_counter  = auto_reconnect_config->reconnect_counter;
        auto_reconnect.reconnect_interval = auto_reconnect_config->reconnect_interval;
        auto_reconnect.flags              = auto_reconnect_config->flags;
    }

    wifi_get_command_lock();
    HostCmd_DS_COMMAND *cmd = wifi_get_command_buffer();

    cmd->command = HostCmd_CMD_AUTO_RECONNECT;
    cmd->seq_num = 0x0;
    cmd->result  = 0x0;

    wlan_cmd_auto_reconnect(cmd, action, &auto_reconnect);

    wifi_wait_for_cmdresp(action == HostCmd_ACT_GEN_GET ? auto_reconnect_config : NULL);

    return wm_wifi.cmd_resp_status;
}

int wifi_auto_reconnect_enable(wifi_auto_reconnect_config_t auto_reconnect_config)
{
    return wifi_auto_reconnect(HostCmd_ACT_GEN_SET, &auto_reconnect_config);
}

int wifi_auto_reconnect_disable(void)
{
    return wifi_auto_reconnect(HostCmd_ACT_GEN_SET, NULL);
}

int wifi_get_auto_reconnect_config(wifi_auto_reconnect_config_t *auto_reconnect_config)
{
    return wifi_auto_reconnect(HostCmd_ACT_GEN_GET, auto_reconnect_config);
}
#endif

int wifi_get_tsf(uint32_t *tsf_high, uint32_t *tsf_low)
{
    t_u64 tsf = 0x00;

    (void)wifi_get_command_lock();
    HostCmd_DS_COMMAND *cmd = wifi_get_command_buffer();

    (void)memset(cmd, 0, sizeof(HostCmd_DS_COMMAND));

    cmd->seq_num = 0x0;
    cmd->result  = 0x0;

    mlan_status rv = wlan_ops_sta_prepare_cmd((mlan_private *)mlan_adap->priv[0], HostCmd_CMD_GET_TSF,
                                              HostCmd_ACT_GEN_GET, 0, NULL, NULL, cmd);
    if (rv != MLAN_STATUS_SUCCESS)
    {
        return -WM_FAIL;
    }

    (void)wifi_wait_for_cmdresp(&tsf);

    *tsf_high = tsf >> 32;
    *tsf_low  = (t_u32)tsf;

    return wm_wifi.cmd_resp_status;
}

#ifdef CONFIG_WLAN_BRIDGE
static int wifi_bridge_mode(uint16_t action, uint8_t *enable, wifi_bridge_cfg_t *bridgecfg)
{
    mlan_bridge_mode bridge_mode;
    bridge_mode.enable = *enable;

    t_u8 *tlv                                       = NULL;
    MrvlIEtypes_BridgeParamSet_t *bridge_params     = NULL;
    MrvlIEtypes_AutoLinkParamSet_t *autolink_params = NULL;
    MrvlIEtypes_SsIdParamSet_t *ssid                = NULL;
    MrvlIEtypes_Passphrase_t *pass                  = NULL;

    wifi_get_command_lock();
    HostCmd_DS_COMMAND *cmd = wifi_get_command_buffer();

    cmd->command = HostCmd_CMD_BRIDGE_MODE;
    cmd->seq_num = 0x0;
    cmd->result  = 0x0;

    wlan_cmd_bridge_mode(cmd, action, &bridge_mode);

    if (action == HostCmd_ACT_GEN_GET)
        goto done;

    if (bridgecfg == NULL)
        goto done;

    tlv = (t_u8 *)cmd + sizeof(HostCmd_BRIDGE_MODE) + S_DS_GEN;

    bridge_params = (MrvlIEtypes_BridgeParamSet_t *)tlv;

    bridge_params->header.type = wlan_cpu_to_le16(TLV_TYPE_BRIDGE_PARAM);
    bridge_params->header.len  = 4 * sizeof(MrvlIEtypesHeader_t) + bridgecfg->ex_ap_ssid_len +
                                bridgecfg->ex_ap_pass_len + bridgecfg->bridge_ssid_len + bridgecfg->bridge_pass_len;
    tlv = (t_u8 *)bridge_params;

    ssid              = (MrvlIEtypes_SsIdParamSet_t *)(tlv + sizeof(MrvlIEtypesHeader_t));
    ssid->header.type = wlan_cpu_to_le16(TLV_TYPE_SSID);
    ssid->header.len  = bridgecfg->ex_ap_ssid_len;
    (void)memcpy((void *)ssid->ssid, (const void *)bridgecfg->ex_ap_ssid, bridgecfg->ex_ap_ssid_len);
    tlv = (t_u8 *)ssid;

    pass              = (MrvlIEtypes_Passphrase_t *)(tlv + sizeof(MrvlIEtypesHeader_t) + ssid->header.len);
    pass->header.type = wlan_cpu_to_le16(TLV_TYPE_PASSPHRASE);
    pass->header.len  = bridgecfg->ex_ap_pass_len;
    (void)memcpy((void *)pass->passphrase, (const void *)bridgecfg->ex_ap_pass, bridgecfg->ex_ap_pass_len);

    tlv = (t_u8 *)pass;

    ssid              = (MrvlIEtypes_SsIdParamSet_t *)(tlv + sizeof(MrvlIEtypesHeader_t) + pass->header.len);
    ssid->header.type = wlan_cpu_to_le16(TLV_TYPE_SSID);
    ssid->header.len  = bridgecfg->bridge_ssid_len;
    (void)memcpy((void *)ssid->ssid, (const void *)bridgecfg->bridge_ssid, bridgecfg->bridge_ssid_len);

    tlv = (t_u8 *)ssid;

    pass              = (MrvlIEtypes_Passphrase_t *)(tlv + sizeof(MrvlIEtypesHeader_t) + ssid->header.len);
    pass->header.type = wlan_cpu_to_le16(TLV_TYPE_PASSPHRASE);
    pass->header.len  = bridgecfg->bridge_pass_len;
    (void)memcpy((void *)pass->passphrase, (const void *)bridgecfg->bridge_pass, bridgecfg->bridge_pass_len);

    cmd->size += bridge_params->header.len + sizeof(MrvlIEtypesHeader_t);

    /*prepare autolink info*/
    tlv             = (t_u8 *)pass;
    autolink_params = (MrvlIEtypes_AutoLinkParamSet_t *)(tlv + sizeof(MrvlIEtypesHeader_t) + pass->header.len);
    autolink_params->header.type          = wlan_cpu_to_le16(TLV_TYPE_AUTOLINK_PARAM);
    autolink_params->header.len           = sizeof(MrvlIEtypes_AutoLinkParamSet_t) - sizeof(MrvlIEtypesHeader_t);
    autolink_params->scan_timer_interval  = wlan_cpu_to_le32(bridgecfg->autolink.scan_timer_interval);
    autolink_params->scan_timer_condition = bridgecfg->autolink.scan_timer_condition;
    autolink_params->scan_channel_list    = bridgecfg->autolink.scan_channel_list;
    cmd->size += autolink_params->header.len + sizeof(MrvlIEtypesHeader_t);

done:

    wifi_wait_for_cmdresp(action == HostCmd_ACT_GEN_GET ? bridgecfg : NULL);

    return wm_wifi.cmd_resp_status;
}

int wifi_enable_bridge_mode(wifi_bridge_cfg_t *cfg)
{
    uint8_t enable = 0x01;

    if (cfg->auto_link)
    {
        enable |= 1 << ENABLE_AUTOLINK_BIT;
    }
    if (cfg->hidden_ssid)
    {
        enable |= 1 << HIDDEN_SSID_BIT;
    }

    return wifi_bridge_mode(HostCmd_ACT_GEN_SET, &enable, cfg);
}

int wifi_disable_bridge_mode()
{
    uint8_t disable = 0x00;
    return wifi_bridge_mode(HostCmd_ACT_GEN_SET, &disable, NULL);
}

int wifi_get_bridge_mode_config(wifi_bridge_cfg_t *cfg)
{
    uint8_t config = 0x00;
    return wifi_bridge_mode(HostCmd_ACT_GEN_GET, &config, cfg);
}

int wifi_config_bridge_tx_buf(uint16_t buf_size)
{
    wifi_get_command_lock();
    HostCmd_DS_COMMAND *cmd = wifi_get_command_buffer();

    cmd->command = HostCmd_CMD_RECONFIGURE_TX_BUFF;
    cmd->seq_num = 0x0;
    cmd->result  = 0x0;

    wlan_cmd_recfg_tx_buf((mlan_private *)mlan_adap->priv[0], cmd, HostCmd_ACT_GEN_SET, &buf_size);

    wifi_wait_for_cmdresp(NULL);
    return wm_wifi.cmd_resp_status;
}
#endif

int wifi_send_rssi_info_cmd(wifi_rssi_info_t *rssi_info)
{
    (void)wifi_get_command_lock();
    HostCmd_DS_COMMAND *cmd = wifi_get_command_buffer();

    cmd->seq_num = 0x0;
    cmd->result  = 0x0;

    mlan_status rv = wlan_ops_sta_prepare_cmd((mlan_private *)mlan_adap->priv[0], HostCmd_CMD_RSSI_INFO,
                                              HostCmd_ACT_GEN_GET, 0, NULL, NULL, cmd);
    if (rv != MLAN_STATUS_SUCCESS)
    {
        return -WM_FAIL;
    }

    (void)wifi_wait_for_cmdresp(rssi_info);
    return wm_wifi.cmd_resp_status;
}

int wifi_send_rf_channel_cmd(wifi_rf_channel_t *rf_channel)
{
    (void)wifi_get_command_lock();
    HostCmd_DS_COMMAND *cmd = wifi_get_command_buffer();

    cmd->seq_num = 0x0;
    cmd->result  = 0x0;

    /*
      SET operation is not supported according to spec. So we are
      sending NULL as one param below.
    */
    mlan_status rv = wlan_ops_sta_prepare_cmd((mlan_private *)mlan_adap->priv[0], HostCmd_CMD_802_11_RF_CHANNEL,
                                              HostCmd_ACT_GEN_GET, 0, NULL, NULL, cmd);
    if (rv != MLAN_STATUS_SUCCESS)
    {
        return -WM_FAIL;
    }

    (void)wifi_wait_for_cmdresp(rf_channel);
    return wm_wifi.cmd_resp_status;
}

int wifi_send_remain_on_channel_cmd(unsigned int bss_type, wifi_remain_on_channel_t *remain_on_channel)
{
    (void)wifi_get_command_lock();
    HostCmd_DS_COMMAND *cmd = wifi_get_command_buffer();

    cmd->seq_num = HostCmd_SET_SEQ_NO_BSS_INFO(0U /* seq_num */, 0U /* bss_num */, bss_type);
    cmd->result  = 0x0;

    mlan_status rv = wlan_ops_sta_prepare_cmd((mlan_private *)mlan_adap->priv[0], HostCmd_CMD_802_11_REMAIN_ON_CHANNEL,
                                              HostCmd_ACT_GEN_SET, 0, NULL, remain_on_channel, cmd);
    if (rv != MLAN_STATUS_SUCCESS)
    {
        return -WM_FAIL;
    }

    (void)wifi_wait_for_cmdresp(NULL);
    return wm_wifi.cmd_resp_status;
}

/* power_level is not used when cmd_action is GET */
int wifi_get_set_rf_tx_power(t_u16 cmd_action, wifi_tx_power_t *tx_power)
{
    (void)wifi_get_command_lock();
    HostCmd_DS_COMMAND *cmd = wifi_get_command_buffer();

    cmd->seq_num   = 0x0;
    cmd->result    = 0x0;
    mlan_status rv = wlan_ops_sta_prepare_cmd((mlan_private *)mlan_adap->priv[0], HostCmd_CMD_802_11_RF_TX_POWER,
                                              cmd_action, 0, NULL, &tx_power->current_level, cmd);
    if (rv != MLAN_STATUS_SUCCESS)
    {
        return -WM_FAIL;
    }

    (void)wifi_wait_for_cmdresp(cmd_action == HostCmd_ACT_GEN_GET ? tx_power : NULL);
    return wm_wifi.cmd_resp_status;
}

int wifi_get_data_rate(wifi_ds_rate *ds_rate)
{
    (void)wifi_get_command_lock();
    HostCmd_DS_COMMAND *cmd = wifi_get_command_buffer();

    cmd->seq_num = 0x0;
    cmd->result  = 0x0;

    mlan_status rv;
    if (is_sta_connected())
    {
        rv = wlan_ops_sta_prepare_cmd((mlan_private *)mlan_adap->priv[0], HostCmd_CMD_802_11_TX_RATE_QUERY, 0, 0, NULL,
                                      NULL, cmd);
    }
    else
    {
        cmd->seq_num = HostCmd_SET_SEQ_NO_BSS_INFO(0U /* seq_num */, 0U /* bss_num */, MLAN_BSS_TYPE_UAP);
        rv = wlan_ops_uap_prepare_cmd((mlan_private *)mlan_adap->priv[0], HostCmd_CMD_802_11_TX_RATE_QUERY, 0, 0, NULL,
                                      NULL, cmd);
    }

    if (rv != MLAN_STATUS_SUCCESS)
    {
        return -WM_FAIL;
    }

    (void)wifi_wait_for_cmdresp(ds_rate);
    return wm_wifi.cmd_resp_status;
}

int wifi_set_pmfcfg(t_u8 mfpc, t_u8 mfpr)
{
    mlan_private *pmpriv = (mlan_private *)mlan_adap->priv[0];

    pmpriv->pmfcfg.mfpc = mfpc;
    pmpriv->pmfcfg.mfpr = mfpr;

    return WM_SUCCESS;
}

int wifi_get_pmfcfg(t_u8 *mfpc, t_u8 *mfpr)
{
    mlan_private *pmpriv = (mlan_private *)mlan_adap->priv[0];

    *mfpc = pmpriv->pmfcfg.mfpc;
    *mfpr = pmpriv->pmfcfg.mfpr;

    return WM_SUCCESS;
}

#ifndef CONFIG_MLAN_WMSDK
int wifi_get_tbtt_offset(wifi_tbtt_offset_t *tbtt_offset)
{
    wifi_get_command_lock();
    HostCmd_DS_COMMAND *cmd = wifi_get_command_buffer();

    cmd->seq_num = 0x0;
    cmd->result  = 0x0;

    mlan_status rv =
        wlan_ops_sta_prepare_cmd((mlan_private *)mlan_adap->priv[0], HostCmd_CMD_TBTT_OFFSET, 0, 0, NULL, NULL, cmd);
    if (rv != MLAN_STATUS_SUCCESS)
        return -WM_FAIL;

    wifi_wait_for_cmdresp(tbtt_offset);

    return wm_wifi.cmd_resp_status;
}
#endif /* CONFIG_MLAN_WMSDK */

int wifi_set_packet_filters(wifi_flt_cfg_t *flt_cfg)
{
    (void)wifi_get_command_lock();
    HostCmd_DS_COMMAND *cmd = wifi_get_command_buffer();
    HostCmd_DS_MEF_CFG *mef_hdr;
    mef_entry_header *entry_hdr;
    t_u8 *buf = (t_u8 *)cmd, *filter_buf = NULL;
    t_u32 buf_len;
    int i, j;
    mef_op op;
    t_u32 dnum;

    (void)memset(cmd, 0, WIFI_FW_CMDBUF_SIZE);

    cmd->seq_num = 0x0;
    cmd->result  = 0x0;

    cmd->command = wlan_cpu_to_le16(HostCmd_CMD_MEF_CFG);
    buf_len      = S_DS_GEN;

    for (i = 0; i < flt_cfg->nentries; i++)
    {
        /** Fill entry header data */
        entry_hdr         = (mef_entry_header *)(buf + buf_len);
        entry_hdr->mode   = flt_cfg->mef_entry[i].mode;
        entry_hdr->action = flt_cfg->mef_entry[i].action;
        buf_len += sizeof(mef_entry_header);
        for (j = 0; j < flt_cfg->mef_entry[i].filter_num; j++)
        {
            if (flt_cfg->mef_entry[i].filter_item[j].type == TYPE_DNUM_EQ)
            {
                /* Format of decimal num:
                 * |   5 bytes  |    5 bytes    |    5 bytes    |        1 byte         |
                 * |   pattern  |     offset    |  num of bytes |  type (TYPE_DNUM_EQ)  |
                 */
                filter_buf = (t_u8 *)(buf + buf_len);

                /* push pattern */
                op.operand_type = OPERAND_DNUM;
                dnum            = flt_cfg->mef_entry[i].filter_item[j].pattern;
                (void)memcpy(filter_buf, &dnum, sizeof(dnum));
                (void)memcpy(filter_buf + sizeof(dnum), &(op.operand_type), 1);
                buf_len += sizeof(dnum) + 1;
                filter_buf = (t_u8 *)(buf + buf_len);

                /* push offset */
                op.operand_type = OPERAND_DNUM;
                dnum            = flt_cfg->mef_entry[i].filter_item[j].offset;
                (void)memcpy(filter_buf, &dnum, sizeof(dnum));
                (void)memcpy(filter_buf + sizeof(dnum), &(op.operand_type), 1);
                buf_len += sizeof(dnum) + 1;
                filter_buf = (t_u8 *)(buf + buf_len);

                /* push num of bytes */
                op.operand_type = OPERAND_DNUM;
                dnum            = flt_cfg->mef_entry[i].filter_item[j].num_bytes;
                (void)memcpy(filter_buf, &dnum, sizeof(dnum));
                (void)memcpy(filter_buf + sizeof(dnum), &(op.operand_type), 1);
                buf_len += sizeof(dnum) + 1;
                filter_buf = (t_u8 *)(buf + buf_len);

                /* push type */
                op.operand_type = TYPE_DNUM_EQ;
                (void)memcpy(filter_buf, &(op.operand_type), 1);
                buf_len += 1;
                filter_buf = (t_u8 *)(buf + buf_len);
            }
            else if (flt_cfg->mef_entry[i].filter_item[j].type == TYPE_BYTE_EQ)
            {
                /* Format of byte seq:
                 * |   5 bytes  |      val      |    5 bytes    |        1 byte         |
                 * |   repeat   |   bytes seq   |    offset     |  type (TYPE_BYTE_EQ)  |
                 */
                filter_buf = (t_u8 *)(buf + buf_len);

                /* push repeat */
                op.operand_type = OPERAND_DNUM;
                dnum            = flt_cfg->mef_entry[i].filter_item[j].repeat;
                (void)memcpy(filter_buf, &dnum, sizeof(dnum));
                (void)memcpy(filter_buf + sizeof(dnum), &(op.operand_type), 1);
                buf_len += sizeof(dnum) + 1;
                filter_buf = (t_u8 *)(buf + buf_len);

                /* push bytes seq */
                op.operand_type = OPERAND_BYTE_SEQ;
                (void)memcpy(filter_buf, flt_cfg->mef_entry[i].filter_item[j].byte_seq,
                             flt_cfg->mef_entry[i].filter_item[j].num_byte_seq);
                (void)memcpy(filter_buf + flt_cfg->mef_entry[i].filter_item[j].num_byte_seq,
                             &(flt_cfg->mef_entry[i].filter_item[j].num_byte_seq), 1);
                (void)memcpy(filter_buf + flt_cfg->mef_entry[i].filter_item[j].num_byte_seq + 1, &(op.operand_type), 1);
                buf_len += flt_cfg->mef_entry[i].filter_item[j].num_byte_seq + 2;
                filter_buf = (t_u8 *)(buf + buf_len);

                /* push offset */
                op.operand_type = OPERAND_DNUM;
                dnum            = flt_cfg->mef_entry[i].filter_item[j].offset;
                (void)memcpy(filter_buf, &dnum, sizeof(dnum));
                (void)memcpy(filter_buf + sizeof(dnum), &(op.operand_type), 1);
                buf_len += sizeof(dnum) + 1;
                filter_buf = (t_u8 *)(buf + buf_len);

                /* push type */
                op.operand_type = TYPE_BYTE_EQ;
                (void)memcpy(filter_buf, &(op.operand_type), 1);
                buf_len += 1;
                filter_buf = (t_u8 *)(buf + buf_len);
            }
            else if (flt_cfg->mef_entry[i].filter_item[j].type == TYPE_BIT_EQ)
            {
                /* Format of bit seq:
                 * |   val      |    5 bytes    |      val      |        1 byte         |
                 * | bytes seq  |    offset     |    mask seq   |  type (TYPE_BIT_EQ)   |
                 */
                filter_buf = (t_u8 *)(buf + buf_len);

                /* push bytes seq */
                op.operand_type = OPERAND_BYTE_SEQ;
                (void)memcpy(filter_buf, flt_cfg->mef_entry[i].filter_item[j].byte_seq,
                             flt_cfg->mef_entry[i].filter_item[j].num_byte_seq);
                (void)memcpy(filter_buf + flt_cfg->mef_entry[i].filter_item[j].num_byte_seq,
                             &(flt_cfg->mef_entry[i].filter_item[j].num_byte_seq), 1);
                (void)memcpy(filter_buf + flt_cfg->mef_entry[i].filter_item[j].num_byte_seq + 1, &(op.operand_type), 1);
                buf_len += flt_cfg->mef_entry[i].filter_item[j].num_byte_seq + 2;
                filter_buf = (t_u8 *)(buf + buf_len);

                /* push offset */
                op.operand_type = OPERAND_DNUM;
                dnum            = flt_cfg->mef_entry[i].filter_item[j].offset;
                (void)memcpy(filter_buf, &dnum, sizeof(dnum));
                (void)memcpy(filter_buf + sizeof(dnum), &(op.operand_type), 1);
                buf_len += sizeof(dnum) + 1;
                filter_buf = (t_u8 *)(buf + buf_len);

                /* push mask seq */
                op.operand_type = OPERAND_BYTE_SEQ;
                (void)memcpy(filter_buf, flt_cfg->mef_entry[i].filter_item[j].mask_seq,
                             flt_cfg->mef_entry[i].filter_item[j].num_mask_seq);
                (void)memcpy(filter_buf + flt_cfg->mef_entry[i].filter_item[j].num_mask_seq,
                             &(flt_cfg->mef_entry[i].filter_item[j].num_mask_seq), 1);
                (void)memcpy(filter_buf + flt_cfg->mef_entry[i].filter_item[j].num_mask_seq + 1, &(op.operand_type), 1);
                buf_len += flt_cfg->mef_entry[i].filter_item[j].num_mask_seq + 2;
                filter_buf = (t_u8 *)(buf + buf_len);

                /* push type */
                op.operand_type = TYPE_BIT_EQ;
                (void)memcpy(filter_buf, &(op.operand_type), 1);
                buf_len += 1;
                filter_buf = (t_u8 *)(buf + buf_len);
            }
            else
                goto done;
            if (j != 0)
            {
                filter_buf      = (t_u8 *)(buf + buf_len);
                op.operand_type = flt_cfg->mef_entry[i].rpn[j];
                (void)memcpy(filter_buf, &(op.operand_type), 1);
                buf_len += 1;
                filter_buf = (t_u8 *)(buf + buf_len);
            }
        }
        if (filter_buf != NULL)
            entry_hdr->len = (t_u32)filter_buf - (t_u32)entry_hdr - sizeof(mef_entry_header);
    }

    cmd->size = wlan_cpu_to_le16(buf_len);
done:
    (void)wifi_wait_for_cmdresp(NULL);

    return wm_wifi.cmd_resp_status;
}

#ifdef ENABLE_OFFLOAD

#define FLTR_BUF_IP_OFFSET 24

int wifi_set_auto_arp(t_u32 *ipv4_addr)
{
    wifi_get_command_lock();
    HostCmd_DS_COMMAND *cmd = wifi_get_command_buffer();
    HostCmd_DS_MEF_CFG *mef_hdr;
    t_u8 *buf = (t_u8 *)cmd, *filter = NULL;
    t_u32 buf_len;
    t_u8 fltr_buf[] = {0x01, 0x10, 0x21, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x02, 0x02,
                       0x14, 0x00, 0x00, 0x00, 0x01, 0x41, 0x01, 0x00, 0x00, 0x00, 0x01, 0xc0, 0xa8,
                       0x01, 0x6d, 0x04, 0x02, 0x2e, 0x00, 0x00, 0x00, 0x01, 0x41, 0x44};

    (void)memset(cmd, 0, WIFI_FW_CMDBUF_SIZE);

    cmd->seq_num = 0x0;
    cmd->result  = 0x0;

    cmd->command = wlan_cpu_to_le16(HostCmd_CMD_MEF_CFG);
    buf_len      = S_DS_GEN;

    /** Fill HostCmd_DS_MEF_CFG*/
    mef_hdr           = (HostCmd_DS_MEF_CFG *)(buf + buf_len);
    mef_hdr->criteria = wlan_cpu_to_le32(MBIT(0) | MBIT(1) | MBIT(3));
    mef_hdr->nentries = wlan_cpu_to_le16(1);
    buf_len += sizeof(HostCmd_DS_MEF_CFG);

    filter = buf + buf_len;
    (void)memcpy((void *)filter, (const void *)fltr_buf, sizeof(fltr_buf));
    (void)memcpy((void *)&filter[FLTR_BUF_IP_OFFSET], (const void *)ipv4_addr, sizeof(t_u32));
    buf_len += sizeof(fltr_buf);

    cmd->size = wlan_cpu_to_le16(buf_len);
    wifi_wait_for_cmdresp(NULL);

    return wm_wifi.cmd_resp_status;
}

int wifi_tcp_keep_alive(wifi_tcp_keep_alive_t *keep_alive, t_u8 *src_mac, t_u32 src_ip)
{
    wifi_get_command_lock();
    HostCmd_DS_COMMAND *cmd = wifi_get_command_buffer();
    t_u16 cmd_action        = HostCmd_ACT_GEN_SET;

    HostCmd_DS_AUTO_TX *auto_tx_cmd = (HostCmd_DS_AUTO_TX *)((t_u8 *)cmd + S_DS_GEN);
    t_u8 *pos                       = (t_u8 *)auto_tx_cmd + sizeof(auto_tx_cmd->action);
    t_u16 len                       = 0;

    MrvlIEtypes_Cloud_Keep_Alive_t *keep_alive_tlv = MNULL;
    MrvlIEtypes_Keep_Alive_Ctrl_t *ctrl_tlv        = MNULL;
    MrvlIEtypes_Keep_Alive_Pkt_t *pkt_tlv          = MNULL;
    t_u8 eth_ip[]                                  = {0x08, 0x00};
    t_u8 ip_packet[67] = {0x45, 0x00, 0x00, 0x43, 0x8c, 0x9e, 0x00, 0x00, 0xff, 0x06, 0xac, 0xbf, 0xc0, 0xa8,
                          0x00, 0x7c, 0xc0, 0xa8, 0x00, 0x8a, 0xc0, 0x03, 0x22, 0xb7, 0xb0, 0xb6, 0x60, 0x9f,
                          0x42, 0xdd, 0x9e, 0x1e, 0x50, 0x18, 0x80, 0x00, 0xd0, 0x88, 0x00, 0x00, 0x74, 0x68,
                          0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x6b, 0x65, 0x65, 0x70, 0x20, 0x61,
                          0x6c, 0x69, 0x76, 0x65, 0x20, 0x70, 0x61, 0x63, 0x6b, 0x65, 0x74};
#if 0
	t_u8 ip_packet2[41] = {0x45, 0x00, 0x00, 0x29, 0x76, 0x51, 0x40, 0x00, 0x80, 0x06, 0xf2, 0x4c, 0xc0, 0xa8, 0x01, 0x0a, 0xc0, 0xa8, 0x01, 0x0c, 0xfb, 0xd8, 0x01, 0xbd, 0x76, 0xe3, 0x34, 0x62, 0x06, 0x80, 0x8b, 0x62, 0x50, 0x10, 0x01, 0x00, 0xe1, 0xe4, 0x00, 0x00, 0x00};
#endif
    t_u16 pkt_len = 67;

    if (keep_alive->reset)
        cmd_action = HostCmd_ACT_GEN_RESET;

    cmd->command        = wlan_cpu_to_le16(HostCmd_CMD_AUTO_TX);
    cmd->size           = S_DS_GEN + sizeof(HostCmd_DS_AUTO_TX);
    auto_tx_cmd->action = wlan_cpu_to_le16(cmd_action);

    keep_alive_tlv = (MrvlIEtypes_Cloud_Keep_Alive_t *)pos;

    keep_alive_tlv->header.type   = wlan_cpu_to_le16(TLV_TYPE_CLOUD_KEEP_ALIVE);
    keep_alive_tlv->keep_alive_id = 1; // keep_alive->mkeep_alive_id;
    keep_alive_tlv->enable        = keep_alive->enable;
    len                           = len + sizeof(keep_alive_tlv->keep_alive_id) + sizeof(keep_alive_tlv->enable);
    pos                           = pos + len + sizeof(MrvlIEtypesHeader_t);
    if (cmd_action == HostCmd_ACT_GEN_SET)
    {
        if (keep_alive->enable)
        {
            ctrl_tlv              = (MrvlIEtypes_Keep_Alive_Ctrl_t *)pos;
            ctrl_tlv->header.type = wlan_cpu_to_le16(TLV_TYPE_KEEP_ALIVE_CTRL);
            ctrl_tlv->header.len =
                wlan_cpu_to_le16(sizeof(MrvlIEtypes_Keep_Alive_Ctrl_t) - sizeof(MrvlIEtypesHeader_t));
            ctrl_tlv->snd_interval   = wlan_cpu_to_le32(keep_alive->timeout);
            ctrl_tlv->retry_interval = wlan_cpu_to_le16(keep_alive->interval);
            ctrl_tlv->retry_count    = wlan_cpu_to_le16(keep_alive->max_keep_alives);
            len                      = len + sizeof(MrvlIEtypes_Keep_Alive_Ctrl_t);

            pos                  = pos + sizeof(MrvlIEtypes_Keep_Alive_Ctrl_t);
            pkt_tlv              = (MrvlIEtypes_Keep_Alive_Pkt_t *)pos;
            pkt_tlv->header.type = wlan_cpu_to_le16(TLV_TYPE_KEEP_ALIVE_PKT);
            (void)memcpy((void *)pkt_tlv->eth_header.dest_addr, (const void *)keep_alive->dst_mac,
                         MLAN_MAC_ADDR_LENGTH);
            (void)memcpy((void *)pkt_tlv->eth_header.src_addr, (const void *)src_mac, MLAN_MAC_ADDR_LENGTH);
            (void)memcpy((void *)((t_u8 *)&pkt_tlv->eth_header.h803_len), (const void *)eth_ip, sizeof(t_u16));
            (void)memcpy((void *)(ip_packet + 12), (const void *)&src_ip, sizeof(t_u32));
            (void)memcpy((void *)(ip_packet + 16), (const void *)&keep_alive->dst_ip, sizeof(t_u32));
            (void)memcpy((void *)pkt_tlv->ip_packet, (const void *)ip_packet, pkt_len);
            pkt_tlv->header.len = wlan_cpu_to_le16(sizeof(Eth803Hdr_t) + pkt_len);
            len                 = len + sizeof(MrvlIEtypesHeader_t) + sizeof(Eth803Hdr_t) + pkt_len;
        }
        else
        {
            pkt_tlv              = (MrvlIEtypes_Keep_Alive_Pkt_t *)pos;
            pkt_tlv->header.type = wlan_cpu_to_le16(TLV_TYPE_KEEP_ALIVE_PKT);
            pkt_tlv->header.len  = 0;
            len                  = len + sizeof(MrvlIEtypesHeader_t);
        }
    }
    if (cmd_action == HostCmd_ACT_GEN_RESET)
    {
        pkt_tlv              = (MrvlIEtypes_Keep_Alive_Pkt_t *)pos;
        pkt_tlv->header.type = wlan_cpu_to_le16(TLV_TYPE_KEEP_ALIVE_PKT);
        pkt_tlv->header.len  = 0;
        len                  = len + sizeof(MrvlIEtypesHeader_t);
    }
    keep_alive_tlv->header.len = wlan_cpu_to_le16(len);

    cmd->size = cmd->size + len + sizeof(MrvlIEtypesHeader_t);
    cmd->size = wlan_cpu_to_le16(cmd->size);

    cmd->seq_num = 0x00;
    cmd->result  = 0x00;

    wifi_wait_for_cmdresp(NULL);

    return wm_wifi.cmd_resp_status;
}
#endif /*ENABLE_OFFLOAD */

#ifndef CONFIG_MLAN_WMSDK
int wifi_nat_keep_alive(wifi_nat_keep_alive_t *keep_alive, t_u8 *src_mac, t_u32 src_ip, t_u16 src_port)
{
    t_u16 d_port, s_port;

    wifi_get_command_lock();
    HostCmd_DS_COMMAND *cmd = wifi_get_command_buffer();
    t_u8 payload[40]        = {0x00, 0x26, 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00, 0x00, 0x1d,
                        0xbe, 0xef, 0x00, 0x00, 0x80, 0x11, 0xf9, 0xc5, 0xc0, 0xa8, 0x01, 0x03, 0xff, 0xff,
                        0xff, 0xff, 0x11, 0x94, 0x11, 0x94, 0x00, 0x09, 0x5b, 0x98, 0xff, 0x00};
    t_u8 payload_len        = 40;

    cmd->command = wlan_cpu_to_le16(HostCmd_CMD_AUTO_TX);

    HostCmd_DS_802_11_AUTO_TX *auto_tx_cmd = (HostCmd_DS_802_11_AUTO_TX *)((t_u8 *)cmd + S_DS_GEN);

    auto_tx_cmd->action = HostCmd_ACT_GEN_SET;

    MrvlIEtypesHeader_t *header = &auto_tx_cmd->auto_tx.header;

    header->type = wlan_cpu_to_le16(TLV_TYPE_AUTO_TX);
    header->len  = wlan_cpu_to_le16(0x3a);

    AutoTx_MacFrame_t *atmf = &auto_tx_cmd->auto_tx.auto_tx_mac_frame;

    (void)memset(atmf, 0, sizeof(AutoTx_MacFrame_t));

    atmf->interval  = wlan_cpu_to_le16(keep_alive->interval);
    atmf->priority  = 0x07;
    atmf->frame_len = wlan_cpu_to_le16(0x34);

    (void)memcpy((void *)atmf->dest_mac_addr, (const void *)keep_alive->dst_mac, MLAN_MAC_ADDR_LENGTH);
    (void)memcpy((void *)atmf->src_mac_addr, (const void *)src_mac, MLAN_MAC_ADDR_LENGTH);

    (void)memcpy((void *)atmf->payload, (const void *)payload, payload_len);

    (void)memcpy((void *)(atmf->payload + 22), (const void *)&src_ip, sizeof(t_u32));
    (void)memcpy((void *)(atmf->payload + 26), (const void *)&keep_alive->dst_ip, sizeof(t_u32));

    s_port = mlan_htons(src_port);
    (void)memcpy((void *)(atmf->payload + 30), (const void *)&s_port, sizeof(t_u16));

    d_port = mlan_htons(keep_alive->dst_port);
    (void)memcpy((void *)(atmf->payload + 32), (const void *)&d_port, sizeof(t_u16));

    cmd->size = 0x48;
    cmd->size = wlan_cpu_to_le16(cmd->size);

    cmd->seq_num = 0x00;
    cmd->result  = 0x00;

    wifi_wait_for_cmdresp(NULL);

    return wm_wifi.cmd_resp_status;
}
#endif /* CONFIG_MLAN_WMSDK */

#ifdef CONFIG_RF_TEST_MODE
static uint8_t channel_set    = 0;
static uint8_t band_set       = 0;
static uint8_t bandwidth_set  = 0;
static uint8_t tx_antenna_set = 0;
static uint8_t rx_antenna_set = 0;

int wifi_get_set_rf_test_generic(t_u16 cmd_action, wifi_mfg_cmd_generic_cfg_t *wifi_mfg_cmd_generic_cfg)
{
    wifi_get_command_lock();
    HostCmd_DS_COMMAND *cmd = wifi_get_command_buffer();

    cmd->seq_num   = 0x0;
    cmd->result    = 0x0;
    mlan_status rv = wlan_ops_sta_prepare_cmd((mlan_private *)mlan_adap->priv[0], HostCmd_CMD_MFG_COMMAND, cmd_action,
                                              0, NULL, wifi_mfg_cmd_generic_cfg, cmd);
    if (rv != MLAN_STATUS_SUCCESS)
        return -WM_FAIL;

    wifi_wait_for_cmdresp(cmd_action == HostCmd_ACT_GEN_GET ? wifi_mfg_cmd_generic_cfg : NULL);
    return wm_wifi.cmd_resp_status;
}

int wifi_get_set_rf_test_tx_frame(t_u16 cmd_action, wifi_mfg_cmd_tx_frame_t *wifi_mfg_cmd_tx_frame)
{
    wifi_get_command_lock();
    HostCmd_DS_COMMAND *cmd = wifi_get_command_buffer();

    cmd->seq_num   = 0x0;
    cmd->result    = 0x0;
    mlan_status rv = wlan_ops_sta_prepare_cmd((mlan_private *)mlan_adap->priv[0], HostCmd_CMD_MFG_COMMAND, cmd_action,
                                              0, NULL, wifi_mfg_cmd_tx_frame, cmd);
    if (rv != MLAN_STATUS_SUCCESS)
        return -WM_FAIL;

    wifi_wait_for_cmdresp(cmd_action == HostCmd_ACT_GEN_GET ? wifi_mfg_cmd_tx_frame : NULL);
    return wm_wifi.cmd_resp_status;
}

int wifi_get_set_rf_test_tx_cont(t_u16 cmd_action, wifi_mfg_cmd_tx_cont_t *wifi_mfg_cmd_tx_cont)
{
    wifi_get_command_lock();
    HostCmd_DS_COMMAND *cmd = wifi_get_command_buffer();

    cmd->seq_num   = 0x0;
    cmd->result    = 0x0;
    mlan_status rv = wlan_ops_sta_prepare_cmd((mlan_private *)mlan_adap->priv[0], HostCmd_CMD_MFG_COMMAND, cmd_action,
                                              0, NULL, wifi_mfg_cmd_tx_cont, cmd);
    if (rv != MLAN_STATUS_SUCCESS)
        return -WM_FAIL;

    wifi_wait_for_cmdresp(cmd_action == HostCmd_ACT_GEN_GET ? wifi_mfg_cmd_tx_cont : NULL);
    return wm_wifi.cmd_resp_status;
}

int wifi_set_rf_test_mode(void)
{
    wifi_mfg_cmd_generic_cfg_t wifi_mfg_cmd_generic_cfg;

    (void)memset(&wifi_mfg_cmd_generic_cfg, 0x00, sizeof(wifi_mfg_cmd_generic_cfg_t));

    wifi_mfg_cmd_generic_cfg.mfg_cmd = MFG_CMD_SET_TEST_MODE;
    wifi_mfg_cmd_generic_cfg.action  = HostCmd_ACT_GEN_SET;

    return wifi_get_set_rf_test_generic(HostCmd_ACT_GEN_SET, &wifi_mfg_cmd_generic_cfg);
}

int wifi_set_rf_channel(const uint8_t channel)
{
    int ret;

    wifi_mfg_cmd_generic_cfg_t wifi_mfg_cmd_generic_cfg;

    /* Check if Channel is allowed as per WWSM */
    if (!wlan_is_channel_valid(channel))
        return -WM_FAIL;

    (void)memset(&wifi_mfg_cmd_generic_cfg, 0x00, sizeof(wifi_mfg_cmd_generic_cfg_t));

    wifi_mfg_cmd_generic_cfg.mfg_cmd = MFG_CMD_RF_CHAN;
    wifi_mfg_cmd_generic_cfg.action  = HostCmd_ACT_GEN_SET;

    wifi_mfg_cmd_generic_cfg.data1 = channel;

    ret = wifi_get_set_rf_test_generic(HostCmd_ACT_GEN_SET, &wifi_mfg_cmd_generic_cfg);

    if (ret == WM_SUCCESS)
        channel_set = 1;

    return ret;
}

int wifi_get_rf_channel(uint8_t *channel)
{
    int ret;

    wifi_mfg_cmd_generic_cfg_t wifi_mfg_cmd_generic_cfg;

    if (!channel_set)
    {
        wifi_e("RF Channel not set");
        return -WM_FAIL;
    }

    (void)memset(&wifi_mfg_cmd_generic_cfg, 0x00, sizeof(wifi_mfg_cmd_generic_cfg_t));

    wifi_mfg_cmd_generic_cfg.mfg_cmd = MFG_CMD_RF_CHAN;
    wifi_mfg_cmd_generic_cfg.action  = HostCmd_ACT_GEN_GET;

    ret = wifi_get_set_rf_test_generic(HostCmd_ACT_GEN_GET, &wifi_mfg_cmd_generic_cfg);

    if (ret == WM_SUCCESS)
        *channel = wifi_mfg_cmd_generic_cfg.data1;

    return ret;
}

int wifi_set_rf_band(const uint8_t band)
{
    int ret;

    wifi_mfg_cmd_generic_cfg_t wifi_mfg_cmd_generic_cfg;

    if (band != 0U
#ifdef CONFIG_5GHz_SUPPORT
        && band != 1U
#endif
    )
        return -WM_FAIL;

    (void)memset(&wifi_mfg_cmd_generic_cfg, 0x00, sizeof(wifi_mfg_cmd_generic_cfg_t));

    wifi_mfg_cmd_generic_cfg.mfg_cmd = MFG_CMD_RF_BAND_AG;
    wifi_mfg_cmd_generic_cfg.action  = HostCmd_ACT_GEN_SET;

    wifi_mfg_cmd_generic_cfg.data1 = band;

    ret = wifi_get_set_rf_test_generic(HostCmd_ACT_GEN_SET, &wifi_mfg_cmd_generic_cfg);

    if (ret == WM_SUCCESS)
        band_set = 1;

    return ret;
}

int wifi_get_rf_band(uint8_t *band)
{
    int ret;

    wifi_mfg_cmd_generic_cfg_t wifi_mfg_cmd_generic_cfg;

    if (!band_set)
    {
        wifi_e("RF Band not set");
        return -WM_FAIL;
    }

    (void)memset(&wifi_mfg_cmd_generic_cfg, 0x00, sizeof(wifi_mfg_cmd_generic_cfg_t));

    wifi_mfg_cmd_generic_cfg.mfg_cmd = MFG_CMD_RF_BAND_AG;
    wifi_mfg_cmd_generic_cfg.action  = HostCmd_ACT_GEN_GET;

    ret = wifi_get_set_rf_test_generic(HostCmd_ACT_GEN_GET, &wifi_mfg_cmd_generic_cfg);

    if (ret == WM_SUCCESS)
        *band = wifi_mfg_cmd_generic_cfg.data1;

    return ret;
}

int wifi_set_rf_bandwidth(const uint8_t bandwidth)
{
    int ret;

    wifi_mfg_cmd_generic_cfg_t wifi_mfg_cmd_generic_cfg;

    if ((bandwidth != 0U)
#ifdef CONFIG_5GHz_SUPPORT
        && (bandwidth != 1U)
#endif
#ifdef CONFIG_11AC
        && (bandwidth != 4U)
#endif
    )
        return -WM_FAIL;

    (void)memset(&wifi_mfg_cmd_generic_cfg, 0x00, sizeof(wifi_mfg_cmd_generic_cfg_t));

    wifi_mfg_cmd_generic_cfg.mfg_cmd = MFG_CMD_RF_CHANNELBW;
    wifi_mfg_cmd_generic_cfg.action  = HostCmd_ACT_GEN_SET;

    wifi_mfg_cmd_generic_cfg.data1 = bandwidth;

    ret = wifi_get_set_rf_test_generic(HostCmd_ACT_GEN_SET, &wifi_mfg_cmd_generic_cfg);

    if (ret == WM_SUCCESS)
        bandwidth_set = 1;

    return ret;
}

int wifi_get_rf_bandwidth(uint8_t *bandwidth)
{
    int ret;

    wifi_mfg_cmd_generic_cfg_t wifi_mfg_cmd_generic_cfg;

    if (!bandwidth_set)
    {
        wifi_e("Bandwidth not set");
        return -WM_FAIL;
    }

    (void)memset(&wifi_mfg_cmd_generic_cfg, 0x00, sizeof(wifi_mfg_cmd_generic_cfg_t));

    wifi_mfg_cmd_generic_cfg.mfg_cmd = MFG_CMD_RF_CHANNELBW;
    wifi_mfg_cmd_generic_cfg.action  = HostCmd_ACT_GEN_GET;

    ret = wifi_get_set_rf_test_generic(HostCmd_ACT_GEN_GET, &wifi_mfg_cmd_generic_cfg);

    if (ret == WM_SUCCESS)
        *bandwidth = wifi_mfg_cmd_generic_cfg.data1;

    return ret;
}

int wifi_get_rf_per(uint32_t *rx_tot_pkt_count, uint32_t *rx_mcast_bcast_count, uint32_t *rx_pkt_fcs_error)
{
    int ret;

    wifi_mfg_cmd_generic_cfg_t wifi_mfg_cmd_generic_cfg;

    (void)memset(&wifi_mfg_cmd_generic_cfg, 0x00, sizeof(wifi_mfg_cmd_generic_cfg_t));

    wifi_mfg_cmd_generic_cfg.mfg_cmd = MFG_CMD_CLR_RX_ERR;
    wifi_mfg_cmd_generic_cfg.action  = HostCmd_ACT_GEN_GET;

    ret = wifi_get_set_rf_test_generic(HostCmd_ACT_GEN_GET, &wifi_mfg_cmd_generic_cfg);

    if (ret == WM_SUCCESS)
    {
        *rx_tot_pkt_count     = wifi_mfg_cmd_generic_cfg.data1;
        *rx_mcast_bcast_count = wifi_mfg_cmd_generic_cfg.data2;
        *rx_pkt_fcs_error     = wifi_mfg_cmd_generic_cfg.data3;
    }

    return ret;
}

int wifi_set_rf_tx_cont_mode(const uint32_t enable_tx,
                             const uint32_t cw_mode,
                             const uint32_t payload_pattern,
                             const uint32_t cs_mode,
                             const uint32_t act_sub_ch,
                             const uint32_t tx_rate)
{
    wifi_mfg_cmd_tx_cont_t wifi_mfg_cmd_tx_cont;

    if ((enable_tx > 1U) || (cw_mode > 1U) || (cs_mode > 1U) || (act_sub_ch == 2U || act_sub_ch > 3U))
        return -WM_FAIL;

    (void)memset(&wifi_mfg_cmd_tx_cont, 0x00, sizeof(wifi_mfg_cmd_tx_cont_t));

    wifi_mfg_cmd_tx_cont.mfg_cmd = MFG_CMD_TX_CONT;
    wifi_mfg_cmd_tx_cont.action  = HostCmd_ACT_GEN_SET;

    wifi_mfg_cmd_tx_cont.enable_tx       = enable_tx;
    wifi_mfg_cmd_tx_cont.cw_mode         = cw_mode;
    wifi_mfg_cmd_tx_cont.payload_pattern = payload_pattern;
    wifi_mfg_cmd_tx_cont.cs_mode         = cs_mode;
    wifi_mfg_cmd_tx_cont.act_sub_ch      = act_sub_ch;
    wifi_mfg_cmd_tx_cont.tx_rate         = tx_rate;

    return wifi_get_set_rf_test_tx_cont(HostCmd_ACT_GEN_SET, &wifi_mfg_cmd_tx_cont);
}

int wifi_set_rf_tx_antenna(const uint8_t antenna)
{
    int ret;

    wifi_mfg_cmd_generic_cfg_t wifi_mfg_cmd_generic_cfg;

    if (antenna != 1U && antenna != 2U)
        return -WM_FAIL;

    (void)memset(&wifi_mfg_cmd_generic_cfg, 0x00, sizeof(wifi_mfg_cmd_generic_cfg_t));

    wifi_mfg_cmd_generic_cfg.mfg_cmd = MFG_CMD_TX_ANT;
    wifi_mfg_cmd_generic_cfg.action  = HostCmd_ACT_GEN_SET;

    wifi_mfg_cmd_generic_cfg.data1 = antenna;

    ret = wifi_get_set_rf_test_generic(HostCmd_ACT_GEN_SET, &wifi_mfg_cmd_generic_cfg);

    if (ret == WM_SUCCESS)
        tx_antenna_set = 1;

    return ret;
}

int wifi_get_rf_tx_antenna(uint8_t *antenna)
{
    int ret;

    wifi_mfg_cmd_generic_cfg_t wifi_mfg_cmd_generic_cfg;

    if (!tx_antenna_set)
    {
        wifi_e("Tx Antenna not set");
        return -WM_FAIL;
    }

    (void)memset(&wifi_mfg_cmd_generic_cfg, 0x00, sizeof(wifi_mfg_cmd_generic_cfg_t));

    wifi_mfg_cmd_generic_cfg.mfg_cmd = MFG_CMD_TX_ANT;
    wifi_mfg_cmd_generic_cfg.action  = HostCmd_ACT_GEN_GET;

    ret = wifi_get_set_rf_test_generic(HostCmd_ACT_GEN_GET, &wifi_mfg_cmd_generic_cfg);

    if (ret == WM_SUCCESS)
        *antenna = wifi_mfg_cmd_generic_cfg.data1;

    return ret;
}

int wifi_set_rf_rx_antenna(const uint8_t antenna)
{
    int ret;

    wifi_mfg_cmd_generic_cfg_t wifi_mfg_cmd_generic_cfg;

    if (antenna != 1U && antenna != 2U)
        return -WM_FAIL;

    (void)memset(&wifi_mfg_cmd_generic_cfg, 0x00, sizeof(wifi_mfg_cmd_generic_cfg_t));

    wifi_mfg_cmd_generic_cfg.mfg_cmd = MFG_CMD_RX_ANT;
    wifi_mfg_cmd_generic_cfg.action  = HostCmd_ACT_GEN_SET;

    wifi_mfg_cmd_generic_cfg.data1 = antenna;

    ret = wifi_get_set_rf_test_generic(HostCmd_ACT_GEN_SET, &wifi_mfg_cmd_generic_cfg);

    if (ret == WM_SUCCESS)
        rx_antenna_set = 1;

    return ret;
}

int wifi_get_rf_rx_antenna(uint8_t *antenna)
{
    int ret;

    wifi_mfg_cmd_generic_cfg_t wifi_mfg_cmd_generic_cfg;

    if (!rx_antenna_set)
    {
        wifi_e("Rx antenna not set");
        return -WM_FAIL;
    }

    (void)memset(&wifi_mfg_cmd_generic_cfg, 0x00, sizeof(wifi_mfg_cmd_generic_cfg_t));

    wifi_mfg_cmd_generic_cfg.mfg_cmd = MFG_CMD_RX_ANT;
    wifi_mfg_cmd_generic_cfg.action  = HostCmd_ACT_GEN_GET;

    ret = wifi_get_set_rf_test_generic(HostCmd_ACT_GEN_GET, &wifi_mfg_cmd_generic_cfg);

    if (ret == WM_SUCCESS)
        *antenna = wifi_mfg_cmd_generic_cfg.data1;

    return ret;
}

int wifi_set_rf_tx_power(const uint8_t power, const uint8_t mod, const uint8_t path_id)
{
    wifi_mfg_cmd_generic_cfg_t wifi_mfg_cmd_generic_cfg;

    if (power > 24U)
        return -WM_FAIL;

    if (mod != 0U && mod != 1U && mod != 2U)
        return -WM_FAIL;

    if (path_id != 0U && path_id != 1U && path_id != 2U)
        return -WM_FAIL;

    (void)memset(&wifi_mfg_cmd_generic_cfg, 0x00, sizeof(wifi_mfg_cmd_generic_cfg_t));

    wifi_mfg_cmd_generic_cfg.mfg_cmd = MFG_CMD_RFPWR;
    wifi_mfg_cmd_generic_cfg.action  = HostCmd_ACT_GEN_SET;

    wifi_mfg_cmd_generic_cfg.data1 = power;
    wifi_mfg_cmd_generic_cfg.data2 = mod;
    wifi_mfg_cmd_generic_cfg.data3 = path_id;

    return wifi_get_set_rf_test_generic(HostCmd_ACT_GEN_SET, &wifi_mfg_cmd_generic_cfg);
}

int wifi_set_rf_tx_frame(const uint32_t enable,
                         const uint32_t data_rate,
                         const uint32_t frame_pattern,
                         const uint32_t frame_length,
                         const uint32_t adjust_burst_sifs,
                         const uint32_t burst_sifs_in_us,
                         const uint32_t short_preamble,
                         const uint32_t act_sub_ch,
                         const uint32_t short_gi,
                         const uint32_t adv_coding,
                         const uint32_t tx_bf,
                         const uint32_t gf_mode,
                         const uint32_t stbc,
                         const uint32_t *bssid)
{
    wifi_mfg_cmd_tx_frame_t wifi_mfg_cmd_tx_frame;

    if (enable > 1U || frame_length < 1U || frame_length > 0x400U || burst_sifs_in_us > 255U || short_preamble > 1U ||
        act_sub_ch == 2U || act_sub_ch > 3U || short_gi > 1U || adv_coding > 1U || tx_bf > 1U || gf_mode > 1U ||
        stbc > 1U)
        return -WM_FAIL;

    (void)memset(&wifi_mfg_cmd_tx_frame, 0x00, sizeof(wifi_mfg_cmd_tx_frame_t));

    wifi_mfg_cmd_tx_frame.mfg_cmd = MFG_CMD_TX_FRAME;
    wifi_mfg_cmd_tx_frame.action  = HostCmd_ACT_GEN_SET;

    wifi_mfg_cmd_tx_frame.enable        = enable;
    wifi_mfg_cmd_tx_frame.data_rate     = data_rate;
    wifi_mfg_cmd_tx_frame.frame_pattern = frame_pattern;
    wifi_mfg_cmd_tx_frame.frame_length  = frame_length;
    (void)memcpy((void *)wifi_mfg_cmd_tx_frame.bssid, (const void *)bssid, MLAN_MAC_ADDR_LENGTH);
    wifi_mfg_cmd_tx_frame.adjust_burst_sifs = adjust_burst_sifs;
    wifi_mfg_cmd_tx_frame.burst_sifs_in_us  = burst_sifs_in_us;
    wifi_mfg_cmd_tx_frame.short_preamble    = short_preamble;
    wifi_mfg_cmd_tx_frame.act_sub_ch        = act_sub_ch;
    wifi_mfg_cmd_tx_frame.short_gi          = short_gi;
    wifi_mfg_cmd_tx_frame.adv_coding        = adv_coding;
    wifi_mfg_cmd_tx_frame.tx_bf             = tx_bf;
    wifi_mfg_cmd_tx_frame.gf_mode           = gf_mode;
    wifi_mfg_cmd_tx_frame.stbc              = stbc;

    return wifi_get_set_rf_test_tx_frame(HostCmd_ACT_GEN_SET, &wifi_mfg_cmd_tx_frame);
}
#endif

/*
 * fixme: Currently, we support only single SSID based scan. We can extend
 * this to a list of multiple SSIDs. The mlan API supports this.
 */
int wifi_send_scan_cmd(t_u8 bss_mode,
                       const t_u8 *specific_bssid,
                       const char *ssid,
                       const char *ssid2,
                       const t_u8 num_channels,
                       const wifi_scan_channel_list_t *chan_list,
                       const t_u8 num_probes,
#ifdef CONFIG_SCAN_WITH_RSSIFILTER
                       const t_s16 rssi_threshold,
#endif
#ifdef CONFIG_EXT_SCAN_SUPPORT
                       const t_u16 scan_chan_gap,
#endif
                       const bool keep_previous_scan,
                       const bool active_scan_triggered)
{
    int ssid_len  = 0;
    int ssid2_len = 0;
    t_u8 i;
#ifdef CONFIG_COMBO_SCAN
    const char wildcard_ssid[] = "*";
#endif
    mlan_adap->active_scan_triggered = MFALSE;

    if (ssid != NULL)
    {
        ssid_len = strlen(ssid);
        if (ssid_len > MLAN_MAX_SSID_LENGTH)
        {
            return -WM_E_INVAL;
        }
    }

    if (ssid2 != NULL)
    {
        ssid2_len = strlen(ssid2);
        if (ssid2_len > MLAN_MAX_SSID_LENGTH)
        {
            return -WM_E_INVAL;
        }
    }

    wlan_user_scan_cfg *user_scan_cfg = os_mem_alloc(sizeof(wlan_user_scan_cfg));
    if (user_scan_cfg == MNULL)
    {
        return -WM_E_NOMEM;
    }

    (void)memset(user_scan_cfg, 0x00, sizeof(wlan_user_scan_cfg));

    user_scan_cfg->bss_mode           = bss_mode;
    user_scan_cfg->keep_previous_scan = keep_previous_scan;

#ifdef CONFIG_SCAN_WITH_RSSIFILTER
    user_scan_cfg->rssi_threshold = rssi_threshold;
#endif

    if (num_probes > 0U && num_probes <= MAX_PROBES)
    {
        user_scan_cfg->num_probes = num_probes;
    }

    if (specific_bssid != NULL)
    {
        (void)memcpy((void *)user_scan_cfg->specific_bssid, (const void *)specific_bssid, MLAN_MAC_ADDR_LENGTH);
    }

    if (ssid != NULL)
    {
        (void)memcpy((void *)user_scan_cfg->ssid_list[0].ssid, (const void *)ssid, ssid_len);
        /* For Wildcard SSID do not set max len */
        /* user_scan_cfg->ssid_list[0].max_len = ssid_len; */
    }

    if (ssid2 != NULL)
    {
        (void)memcpy((void *)user_scan_cfg->ssid_list[1].ssid, (const void *)ssid2, ssid2_len);
    }

#ifdef CONFIG_COMBO_SCAN
    for (i = 0; (i < MRVDRV_MAX_SSID_LIST_LENGTH) && (*user_scan_cfg->ssid_list[i].ssid); i++)
    {
        if (!strncmp(wildcard_ssid, (char *)(user_scan_cfg->ssid_list[i].ssid), strlen(wildcard_ssid)))
        {
            (void)memset(user_scan_cfg->ssid_list[i].ssid, 0x00, sizeof(wlan_user_scan_ssid));
            user_scan_cfg->ssid_list[i].max_len = 40;
        }
    }
#endif

    if (num_channels > 0U && num_channels <= WLAN_USER_SCAN_CHAN_MAX && chan_list != MNULL)
    {
        for (i = 0; i < num_channels; i++)
        {
            /** Channel Number to scan */
            user_scan_cfg->chan_list[i].chan_number = chan_list[i].chan_number;
            /** Radio type: 'B/G' Band = 0, 'A' Band = 1 */
            /* fixme: B/G is hardcoded here. Ask the caller first to
               send the radio type and then change here */
            if (chan_list[i].chan_number > 14U)
            {
                user_scan_cfg->chan_list[i].radio_type = 1;
            }
            /** Scan type: Active = 1, Passive = 2 */
            /* fixme: Active is hardcoded here. Ask the caller first to
               send the  type and then change here */
            user_scan_cfg->chan_list[i].scan_type = chan_list[i].scan_type;
            /** Scan duration in milliseconds; if 0 default used */
            user_scan_cfg->chan_list[i].scan_time = chan_list[i].scan_time;
        }
    }

    if (active_scan_triggered)
    {
        mlan_adap->active_scan_triggered = MTRUE;
    }

    if (wm_wifi.g_user_scan_cfg != NULL)
    {
        os_mem_free((void *)user_scan_cfg);
        return WM_SUCCESS;
    }

    wm_wifi.g_user_scan_cfg = user_scan_cfg;

    (void)os_event_notify_put(wifi_scan_thread);

    return WM_SUCCESS;
}

static int wifi_send_key_material_cmd(int bss_index, mlan_ds_sec_cfg *sec)
{
    /* fixme: check if this needs to go on heap */
    mlan_ioctl_req req;
    mlan_status rv = MLAN_STATUS_SUCCESS;

    (void)memset(&req, 0x00, sizeof(mlan_ioctl_req));
    req.pbuf      = (t_u8 *)sec;
    req.buf_len   = sizeof(mlan_ds_sec_cfg);
    req.bss_index = bss_index;
    req.req_id    = MLAN_IOCTL_SEC_CFG;
    req.action    = MLAN_ACT_SET;

    if (bss_index != 0)
    {
        rv = wlan_ops_uap_ioctl(mlan_adap, &req);
    }
    else
    {
        rv = wlan_ops_sta_ioctl(mlan_adap, &req);
    }

    if (rv != MLAN_STATUS_SUCCESS && rv != MLAN_STATUS_PENDING)
    {
        return -WM_FAIL;
    }

    return WM_SUCCESS;
}

int wifi_set_key(int bss_index,
                 bool is_pairwise,
                 const uint8_t key_index,
                 const uint8_t *key,
                 unsigned key_len,
                 const uint8_t *mac_addr)
{
    /* fixme: check if this needs to go on heap */
    mlan_ds_sec_cfg sec;

    (void)memset(&sec, 0x00, sizeof(mlan_ds_sec_cfg));
    sec.sub_command = MLAN_OID_SEC_CFG_ENCRYPT_KEY;

    if (key_len > MAX_WEP_KEY_SIZE)
    {
        sec.param.encrypt_key.key_flags = KEY_FLAG_TX_SEQ_VALID | KEY_FLAG_RX_SEQ_VALID;
        if (is_pairwise)
        {
            sec.param.encrypt_key.key_flags |= KEY_FLAG_SET_TX_KEY;
        }
        else
        {
            sec.param.encrypt_key.key_flags |= KEY_FLAG_GROUP_KEY;
        }
        sec.param.encrypt_key.key_index = key_index;
        (void)memcpy((void *)sec.param.encrypt_key.mac_addr, (const void *)mac_addr, MLAN_MAC_ADDR_LENGTH);
    }
    else
    {
        sec.param.encrypt_key.key_index          = MLAN_KEY_INDEX_DEFAULT;
        sec.param.encrypt_key.is_current_wep_key = MTRUE;
    }

    sec.param.encrypt_key.key_len = key_len;
    (void)memcpy((void *)sec.param.encrypt_key.key_material, (const void *)key, key_len);

    return wifi_send_key_material_cmd(bss_index, &sec);
}

int wifi_set_igtk_key(int bss_index, const uint8_t *pn, const uint16_t key_index, const uint8_t *key, unsigned key_len)
{
    /* fixme: check if this needs to go on heap */
    mlan_ds_sec_cfg sec;

    (void)memset(&sec, 0x00, sizeof(mlan_ds_sec_cfg));
    sec.sub_command = MLAN_OID_SEC_CFG_ENCRYPT_KEY;

    sec.param.encrypt_key.key_flags = KEY_FLAG_AES_MCAST_IGTK;
    sec.param.encrypt_key.key_index = key_index;

    (void)memcpy((void *)sec.param.encrypt_key.pn, (const void *)pn, SEQ_MAX_SIZE);
    sec.param.encrypt_key.key_len = key_len;
    (void)memcpy((void *)sec.param.encrypt_key.key_material, (const void *)key, key_len);

    return wifi_send_key_material_cmd(bss_index, &sec);
}

int wifi_remove_key(int bss_index, bool is_pairwise, const uint8_t key_index, const uint8_t *mac_addr)
{
    /* fixme: check if this needs to go on heap */
    mlan_ds_sec_cfg sec;

    (void)memset(&sec, 0x00, sizeof(mlan_ds_sec_cfg));
    sec.sub_command = MLAN_OID_SEC_CFG_ENCRYPT_KEY;

    sec.param.encrypt_key.key_flags  = KEY_FLAG_REMOVE_KEY;
    sec.param.encrypt_key.key_remove = MTRUE;

    sec.param.encrypt_key.key_index = key_index;
    (void)memcpy((void *)sec.param.encrypt_key.mac_addr, (const void *)mac_addr, MLAN_MAC_ADDR_LENGTH);

    sec.param.encrypt_key.key_len = WPA_AES_KEY_LEN;

    return wifi_send_key_material_cmd(bss_index, &sec);
}

#ifdef STREAM_2X2
static int wifi_send_11n_cfg_cmd(t_u16 action, uint16_t httxcfg)
{
    mlan_private *pmpriv = (mlan_private *)mlan_adap->priv[0];
    mlan_ds_11n_tx_cfg dot11n_tx_cfg;

    (void)memset(&dot11n_tx_cfg, 0x00, sizeof(mlan_ds_11n_tx_cfg));

    dot11n_tx_cfg.httxcap = httxcfg;

    if (action != HostCmd_ACT_GEN_GET && action != HostCmd_ACT_GEN_SET)
        return -WM_FAIL;

    wifi_get_command_lock();
    HostCmd_DS_COMMAND *cmd = wifi_get_command_buffer();

    cmd->seq_num = 0x0;
    cmd->result  = 0x0;

    mlan_status rv = wlan_ops_sta_prepare_cmd(pmpriv, HostCmd_CMD_11N_CFG, action, 0, NULL, &dot11n_tx_cfg, cmd);
    if (rv != MLAN_STATUS_SUCCESS)
        return -WM_FAIL;

    return wifi_wait_for_cmdresp(NULL);
}

static int wifi_send_11ac_cfg_cmd(t_u16 action, uint32_t vhtcap, uint16_t tx_mcs_map, uint16_t rx_mcs_map)
{
    mlan_private *pmpriv = (mlan_private *)mlan_adap->priv[0];
    mlan_ds_11ac_vht_cfg dot11ac_cfg;

    (void)memset(&dot11ac_cfg, 0x00, sizeof(mlan_ds_11ac_vht_cfg));

    dot11ac_cfg.band         = 2;
    dot11ac_cfg.txrx         = 1;
    dot11ac_cfg.vht_cap_info = vhtcap;
    dot11ac_cfg.vht_tx_mcs   = tx_mcs_map;
    dot11ac_cfg.vht_rx_mcs   = rx_mcs_map;

    if (action != HostCmd_ACT_GEN_GET && action != HostCmd_ACT_GEN_SET)
        return -WM_FAIL;

    wifi_get_command_lock();
    HostCmd_DS_COMMAND *cmd = wifi_get_command_buffer();

    cmd->seq_num = 0x0;
    cmd->result  = 0x0;

    mlan_status rv = wlan_ops_sta_prepare_cmd(pmpriv, HostCmd_CMD_11AC_CFG, action, 0, NULL, &dot11ac_cfg, cmd);
    if (rv != MLAN_STATUS_SUCCESS)
        return -WM_FAIL;

    return wifi_wait_for_cmdresp(NULL);
}

#endif

#ifdef STREAM_2X2
static int wifi_send_rf_antenna_cmd(t_u16 action, uint8_t tx_antenna, uint8_t rx_antenna)
{
    mlan_private *pmpriv = (mlan_private *)mlan_adap->priv[0];
    mlan_ds_ant_cfg ant_cfg;

    (void)memset(&ant_cfg, 0x00, sizeof(mlan_ds_ant_cfg));

    ant_cfg.tx_antenna = tx_antenna;
    ant_cfg.rx_antenna = rx_antenna;

    if (action != HostCmd_ACT_GEN_GET && action != HostCmd_ACT_GEN_SET)
        return -WM_FAIL;

    wifi_get_command_lock();
    HostCmd_DS_COMMAND *cmd = wifi_get_command_buffer();

    cmd->seq_num = 0x0;
    cmd->result  = 0x0;

    mlan_status rv = wlan_ops_sta_prepare_cmd(pmpriv, HostCmd_CMD_802_11_RF_ANTENNA, action, 0, NULL, &ant_cfg, cmd);
    if (rv != MLAN_STATUS_SUCCESS)
        return -WM_FAIL;

    return wifi_wait_for_cmdresp(/*action == HostCmd_ACT_GEN_GET ? ant_mode : */ NULL);
}

#else
static wifi_antcfg_t wifi_antcfg;

static int wifi_send_rf_antenna_cmd(t_u16 action, t_u32 *ant_mode, t_u16 *evaluate_time)
{
    mlan_private *pmpriv = (mlan_private *)mlan_adap->priv[0];
    mlan_ds_ant_cfg_1x1 ant_cfg_1x1;

    (void)memset(&ant_cfg_1x1, 0x00, sizeof(mlan_ds_ant_cfg_1x1));

    ant_cfg_1x1.antenna = *ant_mode;
    ant_cfg_1x1.evaluate_time = *evaluate_time;

    if (action != HostCmd_ACT_GEN_GET && action != HostCmd_ACT_GEN_SET)
    {
        return -WM_FAIL;
    }

    (void)wifi_get_command_lock();
    HostCmd_DS_COMMAND *cmd = wifi_get_command_buffer();

    (void)memset(cmd, 0x00, S_DS_GEN + sizeof(HostCmd_DS_802_11_RF_ANTENNA));

    cmd->seq_num = 0x0;
    cmd->result = 0x0;

    mlan_status rv =
        wlan_ops_sta_prepare_cmd(pmpriv, HostCmd_CMD_802_11_RF_ANTENNA, action, 0, NULL, &ant_cfg_1x1, cmd);
    if (rv != MLAN_STATUS_SUCCESS)
    {
        (void)wifi_put_command_lock();
        return -WM_FAIL;
    }

    (void)wifi_wait_for_cmdresp(action == HostCmd_ACT_GEN_GET ? &wifi_antcfg : NULL);

    *ant_mode = wifi_antcfg.ant_mode;
    *evaluate_time = wifi_antcfg.evaluate_time;

    return wm_wifi.cmd_resp_status;
}

int wifi_get_antenna(t_u32 *ant_mode, t_u16 *evaluate_time)
{
    if (ant_mode == MNULL)
    {
        return -WM_E_INVAL;
    }

    int rv = wifi_send_rf_antenna_cmd(HostCmd_ACT_GEN_GET, ant_mode, evaluate_time);
    if (rv != WM_SUCCESS || wm_wifi.cmd_resp_status != WM_SUCCESS)
    {
        return -WM_FAIL;
    }

    return WM_SUCCESS;
}
#endif

#ifdef STREAM_2X2
int wifi_set_11n_cfg(uint16_t httxcfg)
{
    return wifi_send_11n_cfg_cmd(HostCmd_ACT_GEN_SET, httxcfg);
}

int wifi_set_11ac_cfg(uint32_t vhtcap, uint16_t tx_mcs_map, uint16_t rx_mcs_map)
{
    return wifi_send_11ac_cfg_cmd(HostCmd_ACT_GEN_SET, vhtcap, tx_mcs_map, rx_mcs_map);
}

#endif

#ifdef STREAM_2X2
int wifi_set_antenna(t_u8 tx_antenna, t_u8 rx_antenna)
{
    return wifi_send_rf_antenna_cmd(HostCmd_ACT_GEN_SET, tx_antenna, rx_antenna);
}
#else
int wifi_set_antenna(t_u32 ant_mode, t_u16 evaluate_time)
{
    return wifi_send_rf_antenna_cmd(HostCmd_ACT_GEN_SET, &ant_mode, &evaluate_time);
}
#endif

#ifdef CONFIG_WIFI_GET_LOG
static int wifi_send_get_log_cmd(wlan_pkt_stats_t *stats, mlan_bss_type bss_type)
{
    mlan_private *pmpriv = (mlan_private *)mlan_adap->priv[0];

    wifi_get_command_lock();
    HostCmd_DS_COMMAND *cmd = wifi_get_command_buffer();

    cmd->seq_num = HostCmd_SET_SEQ_NO_BSS_INFO(0 /* seq_num */, 0 /* bss_num */, bss_type);
    cmd->result  = 0x0;

    mlan_status rv =
        wlan_ops_sta_prepare_cmd(pmpriv, HostCmd_CMD_802_11_GET_LOG, HostCmd_ACT_GEN_GET, 0, NULL, NULL, cmd);
    if (rv != MLAN_STATUS_SUCCESS)
        return -WM_FAIL;

    return wifi_wait_for_cmdresp(stats);
}

int wifi_get_log(wlan_pkt_stats_t *stats, mlan_bss_type bss_type)

{
    int rv = wifi_send_get_log_cmd(stats, bss_type);
    if (rv != WM_SUCCESS || wm_wifi.cmd_resp_status != WM_SUCCESS)
        return -WM_FAIL;

    return WM_SUCCESS;
}
#endif

static int wifi_send_cmd_802_11_supplicant_pmk(int mode, mlan_ds_sec_cfg *sec, mlan_act_ioctl action)
{
    /* fixme: check if this needs to go on heap */
    mlan_ioctl_req req;

    (void)memset(&req, 0x00, sizeof(mlan_ioctl_req));
    req.pbuf      = (t_u8 *)sec;
    req.buf_len   = sizeof(mlan_ds_sec_cfg);
    req.bss_index = 0;
    req.req_id    = MLAN_IOCTL_SEC_CFG;
    req.action    = action;

    mlan_status rv = wlan_ops_sta_ioctl(mlan_adap, &req);
    if (rv != MLAN_STATUS_SUCCESS && rv != MLAN_STATUS_PENDING)
    {
        return -WM_FAIL;
    }

    return WM_SUCCESS;
}

int wifi_send_add_wpa_pmk(int mode, char *ssid, char *bssid, char *pmk, unsigned int len)
{
    if (ssid == MNULL || (len != MLAN_MAX_KEY_LENGTH))
    {
        return -WM_E_INVAL;
    }

    mlan_ds_sec_cfg sec;

    (void)memset(&sec, 0x00, sizeof(mlan_ds_sec_cfg));
    sec.sub_command = MLAN_OID_SEC_CFG_PASSPHRASE;

    /* SSID */
    int ssid_len = strlen(ssid);
    if (ssid_len > MLAN_MAX_SSID_LENGTH)
    {
        return -WM_E_INVAL;
    }

    mlan_ds_passphrase *pp = &sec.param.passphrase;
    pp->ssid.ssid_len      = ssid_len;
    (void)memcpy((void *)pp->ssid.ssid, (const void *)ssid, ssid_len);

    /* MAC */
    if (bssid != NULL)
    {
        (void)memcpy((void *)pp->bssid, (const void *)bssid, MLAN_MAC_ADDR_LENGTH);
    }

    /* PMK */
    pp->psk_type = MLAN_PSK_PMK;
    (void)memcpy((void *)pp->psk.pmk.pmk, (const void *)pmk, len);

    return wifi_send_cmd_802_11_supplicant_pmk(mode, &sec, MLAN_ACT_SET);
}

/* fixme: This function has not been tested because of known issue in
   calling function. The calling function has been disabled for that */
int wifi_send_get_wpa_pmk(int mode, char *ssid)
{
    if (ssid == MNULL)
    {
        return -WM_E_INVAL;
    }

    mlan_ds_sec_cfg sec;

    (void)memset(&sec, 0x00, sizeof(mlan_ds_sec_cfg));
    sec.sub_command = MLAN_OID_SEC_CFG_PASSPHRASE;

    /* SSID */
    int ssid_len = strlen(ssid);
    if (ssid_len > MLAN_MAX_SSID_LENGTH)
    {
        return -WM_E_INVAL;
    }

    mlan_ds_passphrase *pp = &sec.param.passphrase;
    pp->ssid.ssid_len      = ssid_len;
    (void)memcpy((void *)pp->ssid.ssid, (const void *)ssid, ssid_len);

    /* Zero MAC */

    pp->psk_type = MLAN_PSK_QUERY;

    return wifi_send_cmd_802_11_supplicant_pmk(mode, &sec, MLAN_ACT_GET);
}

/*
Note:
Passphrase can be between 8 to 63 if it is ASCII and 64 if its PSK
hexstring
*/
int wifi_send_add_wpa_psk(int mode, char *ssid, char *passphrase, unsigned int len)
{
    if (ssid == MNULL || ((len < MLAN_MIN_PASSPHRASE_LENGTH) || (len > MLAN_MAX_PASSPHRASE_LENGTH)))
    {
        return -WM_E_INVAL;
    }

    mlan_ds_sec_cfg sec;

    (void)memset(&sec, 0x00, sizeof(mlan_ds_sec_cfg));
    sec.sub_command = MLAN_OID_SEC_CFG_PASSPHRASE;

    /* SSID */
    int ssid_len = strlen(ssid);
    if (ssid_len > MLAN_MAX_SSID_LENGTH)
    {
        return -WM_E_INVAL;
    }

    mlan_ds_passphrase *pp = &sec.param.passphrase;
    pp->ssid.ssid_len      = ssid_len;
    (void)memcpy((void *)pp->ssid.ssid, (const void *)ssid, ssid_len);

    /* Zero MAC */

    /* Passphrase */
    pp->psk_type                      = MLAN_PSK_PASSPHRASE;
    pp->psk.passphrase.passphrase_len = len;
    (void)memcpy((void *)pp->psk.passphrase.passphrase, (const void *)passphrase, len);

    return wifi_send_cmd_802_11_supplicant_pmk(mode, &sec, MLAN_ACT_SET);
}

/*
Note:
Password can be between 1 to 255 if it is ASCII
*/
int wifi_send_add_wpa3_password(int mode, char *ssid, char *password, unsigned int len)
{
    if (ssid == MNULL || ((len < MLAN_MIN_PASSWORD_LENGTH) || (len > MLAN_MAX_PASSWORD_LENGTH)))
    {
        return -WM_E_INVAL;
    }

    mlan_ds_sec_cfg sec;

    (void)memset(&sec, 0x00, sizeof(mlan_ds_sec_cfg));
    sec.sub_command = MLAN_OID_SEC_CFG_PASSWORD;

    /* SSID */
    int ssid_len = strlen(ssid);
    if (ssid_len > MLAN_MAX_SSID_LENGTH)
    {
        return -WM_E_INVAL;
    }

    mlan_ds_passphrase *pp = &sec.param.passphrase;
    pp->ssid.ssid_len      = ssid_len;
    (void)memcpy((void *)pp->ssid.ssid, (const void *)ssid, ssid_len);

    /* Zero MAC */

    /* Passphrase */
    pp->psk_type              = MLAN_PSK_PASSWORD;
    pp->password.password_len = len;
    (void)memcpy((void *)pp->password.password, (const void *)password, len);

    return wifi_send_cmd_802_11_supplicant_pmk(mode, &sec, MLAN_ACT_SET);
}

int wifi_send_clear_wpa_psk(int mode, const char *ssid)
{
    if (ssid == MNULL)
    {
        return -WM_E_INVAL;
    }

    mlan_ds_sec_cfg sec;

    (void)memset(&sec, 0x00, sizeof(mlan_ds_sec_cfg));
    sec.sub_command = MLAN_OID_SEC_CFG_PASSPHRASE;

    /* SSID */
    int ssid_len = strlen(ssid);
    if (ssid_len > MLAN_MAX_SSID_LENGTH)
    {
        return -WM_E_INVAL;
    }

    sec.param.passphrase.ssid.ssid_len = ssid_len;
    (void)strcpy((char *)sec.param.passphrase.ssid.ssid, ssid);

    /* Zero MAC */

    sec.param.passphrase.psk_type = MLAN_PSK_CLEAR;
    return wifi_send_cmd_802_11_supplicant_pmk(mode, &sec, MLAN_ACT_SET);
}

int wifi_send_enable_supplicant(int mode, const char *ssid)
{
    if (ssid == MNULL)
    {
        return -WM_E_INVAL;
    }

    mlan_ds_sec_cfg sec;

    (void)memset(&sec, 0x00, sizeof(mlan_ds_sec_cfg));
    sec.sub_command = MLAN_OID_SEC_CFG_PASSPHRASE;

    /* SSID */
    int ssid_len = strlen(ssid);
    if (ssid_len > MLAN_MAX_SSID_LENGTH)
    {
        return -WM_E_INVAL;
    }

    sec.param.passphrase.ssid.ssid_len = ssid_len;
    (void)strcpy((char *)sec.param.passphrase.ssid.ssid, ssid);

    /* Zero MAC */

    sec.param.passphrase.psk_type = MLAN_PSK_PASSPHRASE;
    return wifi_send_cmd_802_11_supplicant_pmk(mode, &sec, MLAN_ACT_SET);
}

int wifi_send_disable_supplicant(int mode)
{
    mlan_ds_sec_cfg sec;

    (void)memset(&sec, 0x00, sizeof(mlan_ds_sec_cfg));
    sec.sub_command = MLAN_OID_SEC_CFG_PASSPHRASE;

    sec.param.passphrase.psk_type = MLAN_PSK_CLEAR;

    return wifi_send_cmd_802_11_supplicant_pmk(mode, &sec, MLAN_ACT_SET);
}

int wifi_set_mac_multicast_addr(const char *mlist, t_u32 num_of_addr)
{
    if (mlist == MNULL)
    {
        return -WM_E_INVAL;
    }
    if (num_of_addr > MLAN_MAX_MULTICAST_LIST_SIZE)
    {
        return -WM_E_INVAL;
    }

    mlan_multicast_list mcast_list;

    (void)memcpy((void *)mcast_list.mac_list, (const void *)mlist, num_of_addr * MLAN_MAC_ADDR_LENGTH);
    mcast_list.num_multicast_addr = num_of_addr;
    (void)wifi_get_command_lock();
    HostCmd_DS_COMMAND *cmd = wifi_get_command_buffer();

    mlan_status rv = wlan_ops_sta_prepare_cmd((mlan_private *)mlan_adap->priv[0], HostCmd_CMD_MAC_MULTICAST_ADR,
                                              HostCmd_ACT_GEN_SET, 0, NULL, &mcast_list, cmd);

    if (rv != MLAN_STATUS_SUCCESS)
    {
        return -WM_FAIL;
    }
    (void)wifi_wait_for_cmdresp(NULL);
    return WM_SUCCESS;
}

int wifi_get_otp_user_data(uint8_t *buf, uint16_t len)
{
    (void)wifi_get_command_lock();
    HostCmd_DS_COMMAND *cmd = wifi_get_command_buffer();
    mlan_ds_misc_otp_user_data pdata;

    if (buf == MNULL)
    {
        return -WM_E_INVAL;
    }

    cmd->seq_num           = 0x0;
    cmd->result            = 0x0;
    pdata.user_data_length = len > MAX_OTP_USER_DATA_LEN ? MAX_OTP_USER_DATA_LEN : len;

    mlan_status rv = wlan_ops_sta_prepare_cmd((mlan_private *)mlan_adap->priv[0], HostCmd_CMD_OTP_READ_USER_DATA,
                                              HostCmd_ACT_GEN_GET, 0, NULL, &pdata, cmd);
    if (rv != MLAN_STATUS_SUCCESS)
    {
        return -WM_FAIL;
    }

    (void)wifi_wait_for_cmdresp(buf);
    return wm_wifi.cmd_resp_status;
}

int wifi_get_cal_data(wifi_cal_data_t *cal_data)
{
    uint32_t size = S_DS_GEN + sizeof(HostCmd_DS_802_11_CFG_DATA) - 1U;

    (void)wifi_get_command_lock();
    HostCmd_DS_COMMAND *cmd = wifi_get_command_buffer();

    cmd->command = wlan_cpu_to_le16(HostCmd_CMD_CFG_DATA);

    HostCmd_DS_802_11_CFG_DATA *cfg_data_cmd = (HostCmd_DS_802_11_CFG_DATA *)((uint32_t)cmd + S_DS_GEN);

    cfg_data_cmd->action   = HostCmd_ACT_GEN_GET;
    cfg_data_cmd->type     = 0x02;
    cfg_data_cmd->data_len = 0x00;

    cmd->size    = size;
    cmd->seq_num = 0x00;
    cmd->result  = 0x00;

    (void)wifi_wait_for_cmdresp(cal_data);

    return wm_wifi.cmd_resp_status;
}

int wifi_get_firmware_version_ext(wifi_fw_version_ext_t *version_ext)
{
    if (version_ext == MNULL)
    {
        return -WM_E_INVAL;
    }

    mlan_private *pmpriv = (mlan_private *)mlan_adap->priv[0];
    mlan_status rv       = wifi_prepare_and_send_cmd(pmpriv, HostCmd_CMD_VERSION_EXT, HostCmd_ACT_GEN_GET, 0, NULL,
                                               &version_ext->version_str_sel, MLAN_BSS_TYPE_STA, version_ext);
    return (rv == MLAN_STATUS_SUCCESS ? WM_SUCCESS : -WM_FAIL);
}

int wifi_get_firmware_version(wifi_fw_version_t *ver)
{
    if (ver == MNULL)
    {
        return -WM_E_INVAL;
    }

    union
    {
        uint32_t l;
        uint8_t c[4];
    } u_ver;
    char fw_ver[32];

    u_ver.l = mlan_adap->fw_release_number;
    (void)sprintf(fw_ver, "%u.%u.%u.p%u", u_ver.c[2], u_ver.c[1], u_ver.c[0], u_ver.c[3]);

    (void)snprintf(ver->version_str, MLAN_MAX_VER_STR_LEN, driver_version_format, fw_ver, driver_version);

    return WM_SUCCESS;
}

/* Region: US(US) or Canada(CA) or Singapore(SG) 2.4 GHz */
static wifi_sub_band_set_t subband_US_CA_SG_2_4_GHz[] = {{1, 11, 20}};

/* Region: Europe(EU), Australia(AU), Republic of Korea(KR),
China(CN) 2.4 GHz */
static wifi_sub_band_set_t subband_EU_AU_KR_CN_2_4GHz[] = {{1, 13, 20}};

/* Region: Japan(JP) 2.4 GHz */
static wifi_sub_band_set_t subband_JP_2_4GHz[] = {
    {1, 14, 20},
};

/* Region: World Wide Safe Mode(WWSM) 2.4 GHz */
static wifi_sub_band_set_t subband_WWSM_2_4GHz[] = {
    {1, 14, 8},
};

/* Region: Constrained 2.4 Ghz */
static wifi_sub_band_set_t subband_CS_2_4GHz[] = {{1, 9, 20}, {10, 2, 10}};

#ifdef CONFIG_5GHz_SUPPORT

#if defined(IW61x)
/* Region: US(US) 5 GHz */
wifi_sub_band_set_t subband_US_5_GHz[] = {{36, 8, 20}, {100, 11, 20}, {149, 8, 20}};

/* Region: France(FR) or Singapore(SG) 5 GHz */
wifi_sub_band_set_t subband_SG_FR_5_GHz[] = {{36, 8, 20}, {100, 11, 20}, {149, 5, 20}};
#else
/* Region: US(US) or France(FR) or Singapore(SG) 5 GHz */
static wifi_sub_band_set_t subband_US_SG_FR_5_GHz[] = {{36, 8, 20}, {100, 11, 20}, {149, 5, 20}};
#endif

/* Region: Canada(CA) 5 GHz */
static wifi_sub_band_set_t subband_CA_5_GHz[] = {{36, 8, 20}, {100, 5, 20}, {132, 3, 20}, {149, 5, 20}};

/* Region: Region: Europe(EU), Australia(AU), Republic of Korea(KR)
 * 5 GHz */
static wifi_sub_band_set_t subband_EU_AU_KR_5_GHz[] = {
    {36, 8, 20},
    {100, 11, 20},
};

/* Region: Japan(JP) 5 GHz */
static wifi_sub_band_set_t subband_JP_5_GHz[] = {
    {8, 3, 23},
    {36, 8, 23},
    {100, 11, 23},
};

/* Region: China(CN) 5 Ghz */
static wifi_sub_band_set_t subband_CN_5_GHz[] = {
    {149, 5, 33},
};

/* Region: World Wide Safe Mode(WWSM) 5 GHz */
static wifi_sub_band_set_t subband_WWSM_5_GHz[] = {{36, 8, 8}, {100, 12, 8}, {149, 6, 8}};

#endif /* CONFIG_5GHz_SUPPORT */

int wifi_get_region_code(t_u32 *region_code)
{
    mlan_ds_misc_cfg misc;

    mlan_ioctl_req req = {
        .bss_index = 0,
        .pbuf      = (t_u8 *)&misc,
        .action    = MLAN_ACT_GET,
    };

    mlan_status mrv = wlan_misc_ioctl_region(mlan_adap, &req);
    if (mrv != MLAN_STATUS_SUCCESS)
    {
        wifi_w("Unable to get region code");
        return -WM_FAIL;
    }

    *region_code = misc.param.region_code;
    return WM_SUCCESS;
}

int wifi_set_region_code(t_u32 region_code)
{
    mlan_ds_misc_cfg misc = {
        .param.region_code = region_code,
    };

    if((misc.param.region_code == 0x41) || (misc.param.region_code == 0xFE))
    {
        (void)PRINTF("Region code 0XFF is used for Japan to support channels of both 2.4GHz band and 5GHz band.\r\n");
        (void)PRINTF("Region code 0X40 is used for Japan to support channels of 5GHz band.\r\n");
        return -WM_FAIL;
    }

    mlan_ioctl_req req = {
        .bss_index = 0,
        .pbuf      = (t_u8 *)&misc,
        .action    = MLAN_ACT_SET,
    };

    mlan_status mrv = wlan_misc_ioctl_region(mlan_adap, &req);
    if (mrv != MLAN_STATUS_SUCCESS)
    {
        wifi_w("Unable to set region code");
        return -WM_FAIL;
    }

    return WM_SUCCESS;
}

static int wifi_send_11d_cfg_ioctl(mlan_ds_11d_cfg *d_cfg)
{
    /* fixme: check if this needs to go on heap */
    mlan_ioctl_req req;

    (void)memset(&req, 0x00, sizeof(mlan_ioctl_req));
    req.pbuf      = (t_u8 *)d_cfg;
    req.buf_len   = sizeof(mlan_ds_11d_cfg);
    req.bss_index = 0;
    req.req_id    = MLAN_IOCTL_11D_CFG;
    req.action    = (mlan_act_ioctl)HostCmd_ACT_GEN_SET;

    mlan_status rv = wlan_ops_sta_ioctl(mlan_adap, &req);
    if (rv != MLAN_STATUS_SUCCESS && rv != MLAN_STATUS_PENDING)
    {
        return -WM_FAIL;
    }

    return WM_SUCCESS;
}
int wifi_set_domain_params(wifi_domain_param_t *dp)
{
    if (dp == MNULL)
    {
        return -WM_E_INVAL;
    }

    mlan_ds_11d_cfg d_cfg;

    (void)memset(&d_cfg, 0x00, sizeof(mlan_ds_11d_cfg));

    d_cfg.sub_command = MLAN_OID_11D_DOMAIN_INFO;

    (void)memcpy((void *)&d_cfg.param.domain_info.country_code, (const void *)dp->country_code, COUNTRY_CODE_LEN);

    d_cfg.param.domain_info.band = (BAND_B | BAND_G);

#ifdef CONFIG_11N
    d_cfg.param.domain_info.band |= BAND_GN;
#ifdef CONFIG_5GHz_SUPPORT
    d_cfg.param.domain_info.band |= BAND_AN;
#endif
#else
#ifdef CONFIG_5GHz_SUPPORT
    d_cfg.param.domain_info.band |= BAND_A;
#endif
#endif
    d_cfg.param.domain_info.no_of_sub_band = dp->no_of_sub_band;

    wifi_sub_band_set_t *is  = dp->sub_band;
    mlan_ds_subband_set_t *s = d_cfg.param.domain_info.sub_band;
    t_u8 i;
    for (i = 0; i < dp->no_of_sub_band; i++)
    {
        s[i].first_chan = is[i].first_chan;
        s[i].no_of_chan = is[i].no_of_chan;
        s[i].max_tx_pwr = is[i].max_tx_pwr;
    }

    (void)wifi_enable_11d_support_APIs();

    return wifi_send_11d_cfg_ioctl(&d_cfg);
}

int wifi_enable_11d_support(void)
{
    mlan_private *pmpriv = (mlan_private *)mlan_adap->priv[0];

    (void)wrapper_wlan_11d_enable();

    (void)wlan_11d_support_APIs(pmpriv);

    return wlan_enable_11d_support(pmpriv);
}

int wifi_enable_11d_support_APIs(void)
{
    mlan_private *pmpriv = (mlan_private *)mlan_adap->priv[0];

    return wlan_11d_support_APIs(pmpriv);
}

wifi_sub_band_set_t *get_sub_band_from_country(country_code_t country, t_u8 *nr_sb)
{
    *nr_sb                        = 1;
    wifi_sub_band_set_t *ret_band = NULL;

    switch (country)
    {
        case COUNTRY_WW:
            ret_band = subband_WWSM_2_4GHz;
            break;
        case COUNTRY_US:
        case COUNTRY_CA:
        case COUNTRY_SG:
            ret_band = subband_US_CA_SG_2_4_GHz;
            break;
        case COUNTRY_EU:
        case COUNTRY_AU:
        case COUNTRY_KR:
        case COUNTRY_FR:
        case COUNTRY_CN:
            ret_band = subband_EU_AU_KR_CN_2_4GHz;
            break;
        case COUNTRY_JP:
            ret_band = subband_JP_2_4GHz;
            break;
        default:
            *nr_sb   = 2;
            ret_band = subband_CS_2_4GHz;
            break;
    }
    return ret_band;
}

static wifi_sub_band_set_t *get_sub_band_from_region_code(int region_code, t_u8 *nr_sb)
{
    *nr_sb                        = 1;
    wifi_sub_band_set_t *ret_band = NULL;

    switch (region_code)
    {
        case 0x10:
            ret_band = subband_US_CA_SG_2_4_GHz;
            break;
        case 0x30:
        case 0x32:
            ret_band = subband_EU_AU_KR_CN_2_4GHz;
            break;
        case 0xFF:
            return subband_JP_2_4GHz;
            break;
        case 0xAA:
            ret_band = subband_WWSM_2_4GHz;
            break;
        default:
            *nr_sb   = 2;
            ret_band = subband_CS_2_4GHz;
            break;
    }
    return ret_band;
}

#ifdef CONFIG_5GHz_SUPPORT
wifi_sub_band_set_t *get_sub_band_from_country_5ghz(country_code_t country, t_u8 *nr_sb)
{
    *nr_sb                        = 1;
    wifi_sub_band_set_t *ret_band = NULL;

    switch (country)
    {
        case COUNTRY_WW:
            *nr_sb   = 3;
            ret_band = subband_WWSM_5_GHz;
            break;
        case COUNTRY_US:
#if defined(IW61x)
            *nr_sb   = 3;
            ret_band = subband_US_5_GHz;
            break;
#endif
        case COUNTRY_SG:
        case COUNTRY_FR:
            *nr_sb = 3;
#if defined(IW61x)
            ret_band = subband_SG_FR_5_GHz;
#else
            ret_band = subband_US_SG_FR_5_GHz;
#endif
            break;
        case COUNTRY_CA:
            *nr_sb   = 4;
            ret_band = subband_CA_5_GHz;
            break;
        case COUNTRY_EU:
        case COUNTRY_AU:
        case COUNTRY_KR:
            *nr_sb   = 2;
            ret_band = subband_EU_AU_KR_5_GHz;
            break;
        case COUNTRY_JP:
            *nr_sb   = 3;
            ret_band = subband_JP_5_GHz;
            break;
        case COUNTRY_CN:
            ret_band = subband_CN_5_GHz;
            break;
        default:
            *nr_sb = 3;
#if defined(IW61x)
            ret_band = subband_US_5_GHz;
#else
            ret_band = subband_US_SG_FR_5_GHz;
            break;
#endif
    }
    return ret_band;
}

static wifi_sub_band_set_t *get_sub_band_from_region_code_5ghz(int region_code, t_u8 *nr_sb)
{
    *nr_sb                        = 1;
    wifi_sub_band_set_t *ret_band = NULL;

    switch (region_code)
    {
        case 0x10:
#if defined(IW61x)
            *nr_sb = 3;
            return subband_US_5_GHz;
#endif
        case 0x32:
            *nr_sb = 3;
#if defined(IW61x)
            ret_band = subband_SG_FR_5_GHz;
#else
            ret_band = subband_US_SG_FR_5_GHz;
#endif
            break;
        case 0x20:
            *nr_sb   = 4;
            ret_band = subband_CA_5_GHz;
            break;
        case 0x30:
            *nr_sb   = 2;
            ret_band = subband_EU_AU_KR_5_GHz;
            break;
        case 0x40:
            *nr_sb   = 3;
            ret_band = subband_JP_5_GHz;
            break;
        case 0x50:
            ret_band = subband_CN_5_GHz;
            break;
        case 0xAA:
            *nr_sb   = 3;
            ret_band = subband_WWSM_5_GHz;
            break;
        default:
            *nr_sb = 3;
#if defined(IW61x)
            ret_band = subband_US_5_GHz;
#else
            ret_band = subband_US_SG_FR_5_GHz;
#endif
            break;
    }
    return ret_band;
}
#endif /* CONFIG_5GHz_SUPPORT */

bool wifi_11d_is_channel_allowed(int channel)
{
    t_u8 i, j;
    t_u8 k;
    t_u8 nr_sb = 0;

    mlan_private *pmpriv = (mlan_private *)mlan_adap->priv[0];

    wifi_sub_band_set_t *sub_band = NULL;

    if (channel > 14)
    {
#ifdef CONFIG_5GHz_SUPPORT
        if (wifi_11d_country == COUNTRY_NONE)
        {
            sub_band = get_sub_band_from_region_code_5ghz(pmpriv->adapter->region_code, &nr_sb);
        }
        else
        {
            sub_band = get_sub_band_from_country_5ghz(wifi_11d_country, &nr_sb);
        }
#else
        wifi_w("5 GHz support is not enabled");

#endif /* CONFIG_5GHz_SUPPORT */
    }
    else
    {
        if (wifi_11d_country == COUNTRY_NONE)
        {
            sub_band = get_sub_band_from_region_code(pmpriv->adapter->region_code, &nr_sb);
        }
        else
        {
            sub_band = get_sub_band_from_country(wifi_11d_country, &nr_sb);
        }
    }

    for (i = 0; i < nr_sb; i++)
    {
        j = sub_band[i].first_chan;

        for (k = 0; k < sub_band[i].no_of_chan; k++)
        {
            if (j == channel)
            {
                return true;
            }

            if (channel > 14)
            {
                j += 4;
            }
            else
            {
                j++;
            }
        }
    }

    return false;
}

const char *wifi_get_country_str(country_code_t country)
{
    if (country == COUNTRY_WW)
    {
        return "WW ";
    }
    else if (country == COUNTRY_US)
    {
        return "US ";
    }
    else if (country == COUNTRY_CA)
    {
        return "CA ";
    }
    else if (country == COUNTRY_SG)
    {
        return "SG ";
    }
    else if (country == COUNTRY_EU)
    {
        return "EU ";
    }
    else if (country == COUNTRY_AU)
    {
        return "AU ";
    }
    else if (country == COUNTRY_KR)
    {
        return "KR ";
    }
    else if (country == COUNTRY_FR)
    {
        return "FR ";
    }
    else if (country == COUNTRY_JP)
    {
        return "JP ";
    }
    else if (country == COUNTRY_CN)
    {
        return "CN ";
    }
    else
    {
        return "WW ";
    }
}

wifi_domain_param_t *get_11d_domain_params(country_code_t country, wifi_sub_band_set_t *sub_band, t_u8 nr_sb)
{
    wifi_domain_param_t *dp = os_mem_alloc(sizeof(wifi_domain_param_t) + (sizeof(wifi_sub_band_set_t) * (nr_sb - 1U)));

    (void)memcpy((void *)dp->country_code, (const void *)wifi_get_country_str(country), COUNTRY_CODE_LEN);

    dp->no_of_sub_band = nr_sb;
    (void)memcpy((void *)&dp->sub_band[0], (const void *)sub_band, nr_sb * sizeof(wifi_sub_band_set_t));

    return dp;
}

country_code_t wifi_get_country(void)
{
    return wifi_11d_country;
}

int wifi_set_country(country_code_t country)
{
    int ret;
    t_u8 nr_sb;

    if (wlan_enable_11d() != WM_SUCCESS)
    {
        wifi_e("unable to enabled 11d feature\r\n");
        return -WM_FAIL;
    }

    wifi_11d_country = country;

    wifi_sub_band_set_t *sub_band = get_sub_band_from_country(country, &nr_sb);

    wifi_domain_param_t *dp = get_11d_domain_params(country, sub_band, nr_sb);

    ret = wifi_set_domain_params(dp);

    if (ret != WM_SUCCESS)
    {
        wifi_11d_country = COUNTRY_NONE;
        os_mem_free(dp);
        return ret;
    }

    os_mem_free(dp);
    return WM_SUCCESS;
}

int wifi_enable_ecsa_support(void)
{
    return wrapper_wlan_ecsa_enable();
}

bool wifi_is_ecsa_enabled(void)
{
    return mlan_adap->ecsa_enable;
}

static int get_free_mgmt_ie_index(unsigned int *mgmt_ie_index)
{
    unsigned int idx;

    for (idx = 0; idx < 32; idx++)
    {
        if ((mgmt_ie_index_bitmap & MBIT((t_u32)idx)) == 0U)
        {
            *mgmt_ie_index = idx;
            return WM_SUCCESS;
        }
    }
    return -WM_FAIL;
}

static void set_ie_index(unsigned int index)
{
    mgmt_ie_index_bitmap |= (MBIT(index));
}

static void clear_ie_index(unsigned int index)
{
    mgmt_ie_index_bitmap &= ~(MBIT(index));
}

#ifdef SD8801
static int wifi_config_ext_coex(int action,
                                const wifi_ext_coex_config_t *ext_coex_config,
                                wifi_ext_coex_stats_t *ext_coex_stats)
{
    int ret;
    HostCmd_DS_COMMAND *cmd = wifi_get_command_buffer();

    (void)wifi_get_command_lock();

    cmd->command                                           = HostCmd_CMD_ROBUST_COEX;
    cmd->size                                              = sizeof(HostCmd_DS_ExtBLECoex_Config_t) + S_DS_GEN;
    cmd->seq_num                                           = 0;
    cmd->result                                            = 0;
    cmd->params.ext_ble_coex_cfg.action                    = action;
    cmd->params.ext_ble_coex_cfg.reserved                  = 0;
    cmd->params.ext_ble_coex_cfg.coex_cfg_data.header.type = TLV_TYPE_EXT_BLE_COEX_CFG;
    cmd->params.ext_ble_coex_cfg.coex_cfg_data.header.len =
        sizeof(MrvlIETypes_ExtBLECoex_Config_t) - sizeof(MrvlIEtypesHeader_t);

    if (action == HostCmd_ACT_GEN_SET)
    {
        cmd->params.ext_ble_coex_cfg.coex_cfg_data.Enabled         = ext_coex_config->Enabled;
        cmd->params.ext_ble_coex_cfg.coex_cfg_data.IgnorePriority  = ext_coex_config->IgnorePriority;
        cmd->params.ext_ble_coex_cfg.coex_cfg_data.DefaultPriority = ext_coex_config->DefaultPriority;
        cmd->params.ext_ble_coex_cfg.coex_cfg_data.EXT_RADIO_REQ_ip_gpio_num =
            ext_coex_config->EXT_RADIO_REQ_ip_gpio_num;
        cmd->params.ext_ble_coex_cfg.coex_cfg_data.EXT_RADIO_REQ_ip_gpio_polarity =
            ext_coex_config->EXT_RADIO_REQ_ip_gpio_polarity;
        cmd->params.ext_ble_coex_cfg.coex_cfg_data.EXT_RADIO_PRI_ip_gpio_num =
            ext_coex_config->EXT_RADIO_PRI_ip_gpio_num;
        cmd->params.ext_ble_coex_cfg.coex_cfg_data.EXT_RADIO_PRI_ip_gpio_polarity =
            ext_coex_config->EXT_RADIO_PRI_ip_gpio_polarity;
        cmd->params.ext_ble_coex_cfg.coex_cfg_data.WLAN_GRANT_op_gpio_num = ext_coex_config->WLAN_GRANT_op_gpio_num;
        cmd->params.ext_ble_coex_cfg.coex_cfg_data.WLAN_GRANT_op_gpio_polarity =
            ext_coex_config->WLAN_GRANT_op_gpio_polarity;
        cmd->params.ext_ble_coex_cfg.coex_cfg_data.reserved_1 = ext_coex_config->reserved_1;
        cmd->params.ext_ble_coex_cfg.coex_cfg_data.reserved_2 = ext_coex_config->reserved_2;
    }
    ret = wifi_wait_for_cmdresp(ext_coex_stats);
    return ret;
}
#endif

static bool ie_index_is_set(unsigned int index)
{
    return (mgmt_ie_index_bitmap & (MBIT(index))) ? MTRUE : MFALSE;
}

static int wifi_config_mgmt_ie(mlan_bss_type bss_type,
                               t_u16 action,
                               IEEEtypes_ElementId_t index,
                               void *buffer,
                               unsigned int *ie_len,
                               int mgmt_bitmap_index)
{
    uint8_t *buf, *pos;
    IEEEtypes_Header_t *ptlv_header = NULL;
    uint16_t buf_len                = 0;
    tlvbuf_custom_ie *tlv           = NULL;
    custom_ie *ie_ptr               = NULL;
    unsigned int mgmt_ie_index      = -1;
    int total_len =
        sizeof(tlvbuf_custom_ie) + 2U * (sizeof(custom_ie) - MAX_IE_SIZE) + sizeof(IEEEtypes_Header_t) + *ie_len;
    int ret = WM_SUCCESS;

    buf = (uint8_t *)os_mem_alloc(total_len);
    if (buf == MNULL)
    {
        wifi_e("Cannot allocate memory");
        return -WM_FAIL;
    }

    (void)memset(buf, 0, total_len);

    tlv       = (tlvbuf_custom_ie *)(void *)buf;
    tlv->type = MRVL_MGMT_IE_LIST_TLV_ID;

    /* Locate headers */
    ie_ptr = (custom_ie *)(tlv->ie_data);
    /* Set TLV fields */
    buf_len = sizeof(tlvbuf_custom_ie);

    if (action == HostCmd_ACT_GEN_SET)
    {
        if (*ie_len == 0U)
        {
            /*
               MGMT_WPA_IE = MGMT_VENDOR_SPECIFIC_221
               MGMT_WPS_IE = MGMT_VENDOR_SPECIFIC_221
               */

            if (!ie_index_is_set(mgmt_bitmap_index))
            {
                os_mem_free(buf);
                return -WM_FAIL;
            }

            ie_ptr->mgmt_subtype_mask = MGMT_MASK_CLEAR;
            ie_ptr->ie_length         = 0;
            ie_ptr->ie_index          = (t_u16)mgmt_bitmap_index;

            tlv->length = sizeof(custom_ie) - MAX_IE_SIZE;
            buf_len += tlv->length;
            clear_ie_index(mgmt_bitmap_index);
        }
        else
        {
            ret = get_free_mgmt_ie_index(&mgmt_ie_index);

            if (WM_SUCCESS != ret)
            {
                os_mem_free(buf);
                return -WM_FAIL;
            }

            pos         = ie_ptr->ie_buffer;
            ptlv_header = (IEEEtypes_Header_t *)(void *)pos;
            pos += sizeof(IEEEtypes_Header_t);

            ptlv_header->element_id = (IEEEtypes_ElementId_e)index;
            ptlv_header->len        = *ie_len;
            if (bss_type == MLAN_BSS_TYPE_UAP)
            {
                ie_ptr->mgmt_subtype_mask =
                    MGMT_MASK_BEACON | MGMT_MASK_PROBE_RESP | MGMT_MASK_ASSOC_RESP | MGMT_MASK_REASSOC_RESP;
            }
            else if (bss_type == MLAN_BSS_TYPE_STA)
            {
                ie_ptr->mgmt_subtype_mask = MGMT_MASK_PROBE_REQ | MGMT_MASK_ASSOC_REQ | MGMT_MASK_REASSOC_REQ;
            }
            else
            { /* Do Nothing */
            }

            tlv->length       = sizeof(custom_ie) + sizeof(IEEEtypes_Header_t) + *ie_len - MAX_IE_SIZE;
            ie_ptr->ie_length = sizeof(IEEEtypes_Header_t) + *ie_len;
            ie_ptr->ie_index  = mgmt_ie_index;

            buf_len += tlv->length;

            (void)memcpy((void *)pos, (const void *)buffer, *ie_len);
        }
    }
    else if (action == HostCmd_ACT_GEN_GET)
    {
        /* Get WPS IE */
        tlv->length = 0;
    }
    else
    { /* Do Nothing */
    }

    mlan_status rv = wrapper_wlan_cmd_mgmt_ie(bss_type, buf, buf_len, action);

    if (rv != MLAN_STATUS_SUCCESS && rv != MLAN_STATUS_PENDING)
    {
        os_mem_free(buf);
        return -WM_FAIL;
    }

    if (action == HostCmd_ACT_GEN_GET)
    {
        if (wm_wifi.cmd_resp_status != 0)
        {
            wifi_w("Unable to get mgmt ie buffer");
            os_mem_free(buf);
            return wm_wifi.cmd_resp_status;
        }
        ie_ptr = (custom_ie *)(void *)(buf);
        (void)memcpy((void *)buffer, (const void *)ie_ptr->ie_buffer, ie_ptr->ie_length);
        *ie_len = ie_ptr->ie_length;
    }

    os_mem_free(buf);

    if ((action == HostCmd_ACT_GEN_SET) && *ie_len)
    {
        set_ie_index(mgmt_ie_index);
        return mgmt_ie_index;
    }
    else
    {
        return WM_SUCCESS;
    }
}

int wifi_get_mgmt_ie(mlan_bss_type bss_type, IEEEtypes_ElementId_t index, void *buf, unsigned int *buf_len)
{
    return wifi_config_mgmt_ie(bss_type, HostCmd_ACT_GEN_GET, index, buf, buf_len, 0);
}

int wifi_set_mgmt_ie(mlan_bss_type bss_type, IEEEtypes_ElementId_t id, void *buf, unsigned int buf_len)
{
    unsigned int data_len = buf_len;

    return wifi_config_mgmt_ie(bss_type, HostCmd_ACT_GEN_SET, id, buf, &data_len, 0);
}

int wifi_clear_mgmt_ie(mlan_bss_type bss_type, IEEEtypes_ElementId_t index, int mgmt_bitmap_index)
{
    unsigned int data_len = 0;
    return wifi_config_mgmt_ie(bss_type, HostCmd_ACT_GEN_SET, index, NULL, &data_len, mgmt_bitmap_index);
}

#ifdef SD8801
int wifi_get_ext_coex_stats(wifi_ext_coex_stats_t *ext_coex_stats)
{
    if (ext_coex_stats == NULL)
    {
        wifi_e("Invalid structure passed");
        return -WM_FAIL;
    }

    return wifi_config_ext_coex(HostCmd_ACT_GEN_GET, NULL, ext_coex_stats);
}

int wifi_set_ext_coex_config(const wifi_ext_coex_config_t *ext_coex_config)
{
    if (ext_coex_config == NULL)
    {
        wifi_e("Invalid structure passed");
        return -WM_FAIL;
    }

    return wifi_config_ext_coex(HostCmd_ACT_GEN_SET, ext_coex_config, NULL);
}
#endif

int wifi_set_chanlist(wifi_chanlist_t *chanlist)
{
    mlan_status ret;
    t_u8 i         = 0;
    t_u8 cfp_no_bg = 0;
#ifdef CONFIG_5GHz_SUPPORT
    t_u8 cfp_no_a = 0;
#endif

#ifdef OTP_CHANINFO
    mlan_adapter *pmadapter = mlan_adap->priv[0]->adapter;
    if ((pmadapter->otp_region == MNULL) || (pmadapter->otp_region->force_reg == 0U))
    {
#endif
        /*
         * Validate if the channels provided in the channel list
         * are valid channels according to World Wide Safe Mode.
         */
        for (i = 0; i < chanlist->num_chans; i++)
        {
            if (!wlan_is_channel_and_freq_valid(chanlist->chan_info[i].chan_num, chanlist->chan_info[i].chan_freq))
            {
                wifi_e("Invalid channel %d\r\n", chanlist->chan_info[i].chan_num);
                return -WM_FAIL;
            }
        }

        /* Configure Custom CFP Tables */
#ifdef CONFIG_5GHz_SUPPORT
        ret = wlan_set_custom_cfp_table(chanlist, &cfp_no_bg, &cfp_no_a);
#else
    ret = wlan_set_custom_cfp_table(chanlist, &cfp_no_bg);
#endif
        if (ret != MLAN_STATUS_SUCCESS)
        {
            wifi_e("Failed to set Custom CFP Table");
            return -WM_FAIL;
        }

        /* Set Region Table */
#ifdef CONFIG_5GHz_SUPPORT
        wlan_set_custom_regiontable((mlan_private *)mlan_adap->priv[0], cfp_no_bg, cfp_no_a);
#else
    wlan_set_custom_regiontable((mlan_private *)mlan_adap->priv[0], cfp_no_bg);
#endif
#ifdef OTP_CHANINFO
    }
#endif

    return WM_SUCCESS;
}

int wifi_get_chanlist(wifi_chanlist_t *chanlist)
{
    mlan_adapter *pmadapter      = mlan_adap->priv[0]->adapter;
    region_chan_t *pchan_region  = MNULL;
    const chan_freq_power_t *cfp = MNULL;
    t_u32 region_idx             = 0;
    t_u32 next_chan              = 0;
    chanlist->num_chans          = 0;

    for (region_idx = 0; region_idx < NELEMENTS(pmadapter->region_channel); region_idx++)
    {
        if (!pmadapter->region_channel[region_idx].valid)
        {
            continue;
        }

        pchan_region = &pmadapter->region_channel[region_idx];

        for (next_chan = 0; next_chan < pchan_region->num_cfp; next_chan++)
        {
            cfp = pchan_region->pcfp + next_chan;
            if (cfp == MNULL)
            {
                wifi_e("No cfp configured");
                return -WM_FAIL;
            }

            if ((cfp->dynamic.flags & NXP_CHANNEL_DISABLED) != 0U)
            {
                continue;
            }

            chanlist->chan_info[chanlist->num_chans].chan_num                     = cfp->channel;
            chanlist->chan_info[chanlist->num_chans].chan_freq                    = cfp->freq;
            chanlist->chan_info[chanlist->num_chans].passive_scan_or_radar_detect = cfp->passive_scan_or_radar_detect;
            chanlist->num_chans++;

            if (chanlist->num_chans >= NELEMENTS(chanlist->chan_info))
            {
                break;
            }
        }
    }

    return WM_SUCCESS;
}

void wifi_get_active_channel_list(t_u8 *chan_list, t_u8 *num_chans)
{
    if (chan_list != MNULL && num_chans != MNULL)
    {
        wlan_get_active_channel_list((mlan_private *)mlan_adap->priv[0], chan_list, num_chans);
    }
}

int wifi_set_txpwrlimit(wifi_txpwrlimit_t *txpwrlimit)
{
    t_u8 i;
    int ret;
    HostCmd_DS_COMMAND *cmd                = wifi_get_command_buffer();
    t_u8 *pByte                            = NULL;
    MrvlIETypes_ChanTRPCConfig_t *trpc_tlv = NULL;

    (void)wifi_get_command_lock();

    cmd->command = HostCmd_CMD_CHANNEL_TRPC_CONFIG;
    cmd->seq_num = 0x0;
    cmd->result  = 0x0;
    cmd->size    = S_DS_GEN + 2U * sizeof(t_u16) +
                txpwrlimit->num_chans * (sizeof(MrvlIEtypesHeader_t) + sizeof(MrvlChannelDesc_t)) +
                (txpwrlimit->num_chans * txpwrlimit->txpwrlimit_config->num_mod_grps * sizeof(MrvlChanTrpcEntry_t));

    HostCmd_DS_CHAN_TRPC_CONFIG *txpwrlimit_config = (HostCmd_DS_CHAN_TRPC_CONFIG *)(void *)((uint8_t *)cmd + S_DS_GEN);

    txpwrlimit_config->action   = HostCmd_ACT_GEN_SET;
    txpwrlimit_config->reserved = txpwrlimit->subband;

    pByte = (t_u8 *)txpwrlimit_config->tlv_buffer;

    for (i = 0; i < txpwrlimit->num_chans; i++)
    {
        trpc_tlv              = (MrvlIETypes_ChanTRPCConfig_t *)(void *)pByte;
        trpc_tlv->header.type = TLV_TYPE_CHANNEL_TRPC_CONFIG;
        trpc_tlv->header.len =
            sizeof(MrvlChannelDesc_t) + txpwrlimit->txpwrlimit_config->num_mod_grps * sizeof(MrvlChanTrpcEntry_t);
        trpc_tlv->start_freq = txpwrlimit->txpwrlimit_config[i].chan_desc.start_freq;
        trpc_tlv->width      = txpwrlimit->txpwrlimit_config[i].chan_desc.chan_width;
        trpc_tlv->chan_num   = txpwrlimit->txpwrlimit_config[i].chan_desc.chan_num;
        (void)memcpy((void *)trpc_tlv->mod_group, (const void *)txpwrlimit->txpwrlimit_config[i].txpwrlimit_entry,
                     txpwrlimit->txpwrlimit_config->num_mod_grps * sizeof(MrvlChanTrpcEntry_t));
        pByte += trpc_tlv->header.len + sizeof(trpc_tlv->header);
    }
    ret = wifi_wait_for_cmdresp(NULL);
    return ret;
}

int wifi_get_txpwrlimit(wifi_SubBand_t subband, wifi_txpwrlimit_t *txpwrlimit)
{
    int ret;

    HostCmd_DS_COMMAND *cmd = wifi_get_command_buffer();

    (void)wifi_get_command_lock();

    cmd->command = HostCmd_CMD_CHANNEL_TRPC_CONFIG;
    cmd->seq_num = 0x0;
    cmd->result  = 0x0;
    cmd->size    = S_DS_GEN + 2U * sizeof(t_u16);

    HostCmd_DS_CHAN_TRPC_CONFIG *txpwrlimit_config = (HostCmd_DS_CHAN_TRPC_CONFIG *)(void *)((uint8_t *)cmd + S_DS_GEN);

    txpwrlimit_config->action   = HostCmd_ACT_GEN_GET;
    txpwrlimit_config->reserved = subband;

    ret = wifi_wait_for_cmdresp(txpwrlimit);
    return ret;
}

#ifdef CONFIG_WIFI_RTS_THRESHOLD
int wifi_set_rts(int rts, mlan_bss_type bss_type)
{
    mlan_ioctl_req req;
    mlan_ds_snmp_mib *mib = NULL;
    mlan_status ret       = MLAN_STATUS_FAILURE;
    wifi_sta_list_t *sl   = NULL;

    (void)memset(&req, 0x00, sizeof(mlan_ioctl_req));

    /* Allocate an IOCTL request buffer */
    mib = os_mem_alloc(sizeof(mlan_ds_snmp_mib));
    if (mib == NULL)
        return -WM_FAIL;

    /* Fill request buffer */
    mib->sub_command = MLAN_OID_SNMP_MIB_RTS_THRESHOLD;
    req.pbuf         = (t_u8 *)mib;
    req.buf_len      = sizeof(mlan_ds_snmp_mib);
    req.req_id       = MLAN_IOCTL_SNMP_MIB;
    req.action       = MLAN_ACT_SET;
    req.bss_index    = bss_type;

    if (req.action == MLAN_ACT_SET)
    {
        if (rts < MLAN_RTS_MIN_VALUE || rts > MLAN_RTS_MAX_VALUE)
        {
            os_mem_free(mib);
            return -WM_FAIL;
        }
        mib->param.rts_threshold = rts;
    }

    if (bss_type == MLAN_BSS_TYPE_UAP)
    {
        if (!is_uap_started())
        {
            wifi_e("uap isn't up\n\r");
            return -WM_FAIL;
        }
        wifi_uap_bss_sta_list(&sl);
        if (!sl)
        {
            wifi_e("Failed to get sta list\n\r");
            return -WM_FAIL;
        }
        if (sl->count >= 1)
            ret = wlan_ops_sta_ioctl(mlan_adap, &req);
        else
            wifi_e("uap required sta to connect before setting rts threshold\n\r");
    }
    else if (bss_type == MLAN_BSS_TYPE_STA)
    {
        if (is_sta_connected())
            ret = wlan_ops_sta_ioctl(mlan_adap, &req);
        else
            wifi_e("sta connection required before setting rts threshold\n\r");
    }

    if (ret != MLAN_STATUS_SUCCESS && ret != MLAN_STATUS_PENDING)
    {
        os_mem_free(mib);
        return -WM_FAIL;
    }

    os_mem_free(mib);

    return WM_SUCCESS;
}
#endif

#ifdef CONFIG_WIFI_FRAG_THRESHOLD
int wifi_set_frag(int frag, mlan_bss_type bss_type)
{
    mlan_ioctl_req req;
    mlan_ds_snmp_mib *mib = NULL;
    mlan_status ret       = MLAN_STATUS_FAILURE;
    wifi_sta_list_t *sl   = NULL;

    (void)memset(&req, 0x00, sizeof(mlan_ioctl_req));

    /* Allocate an IOCTL request buffer */
    mib = os_mem_alloc(sizeof(mlan_ds_snmp_mib));
    if (mib == NULL)
        return -WM_FAIL;

    /* Fill request buffer */
    mib->sub_command = MLAN_OID_SNMP_MIB_FRAG_THRESHOLD;
    req.pbuf         = (t_u8 *)mib;
    req.buf_len      = sizeof(mlan_ds_snmp_mib);
    req.req_id       = MLAN_IOCTL_SNMP_MIB;
    req.action       = MLAN_ACT_SET;
    req.bss_index    = bss_type;

    if (req.action == MLAN_ACT_SET)
    {
        if (frag < MLAN_FRAG_MIN_VALUE || frag > MLAN_FRAG_MAX_VALUE)
        {
            os_mem_free(mib);
            return -WM_FAIL;
        }
        mib->param.frag_threshold = frag;
    }

    if (bss_type == MLAN_BSS_TYPE_UAP)
    {
        if (!is_uap_started())
        {
            wifi_e("uap isn't up\n\r");
            return -WM_FAIL;
        }
        wifi_uap_bss_sta_list(&sl);
        if (!sl)
        {
            wifi_e("Failed to get sta list\n\r");
            return -WM_FAIL;
        }

        if (sl->count >= 1)
            ret = wlan_ops_sta_ioctl(mlan_adap, &req);
        else
            wifi_e("uap required sta to connect before setting fragment threshold\n\r");
    }
    else if (bss_type == MLAN_BSS_TYPE_STA)
    {
        if (is_sta_connected())
            ret = wlan_ops_sta_ioctl(mlan_adap, &req);
        else
            wifi_e("sta connection required before setting fragment threshold\n\r");
    }

    if (ret != MLAN_STATUS_SUCCESS && ret != MLAN_STATUS_PENDING)
    {
        os_mem_free(mib);
        return -WM_FAIL;
    }

    os_mem_free(mib);

    return WM_SUCCESS;
}
#endif

void wifi_set_curr_bss_channel(uint8_t channel)
{
    mlan_private *pmpriv = (mlan_private *)mlan_adap->priv[0];

    pmpriv->curr_bss_params.bss_descriptor.channel = channel;
}

#ifdef CONFIG_11K_OFFLOAD
int wifi_11k_cfg(int enable_11k)
{
    mlan_ioctl_req req;
    mlan_ds_11k_cfg *pcfg_11k = NULL;
    mlan_status ret           = MLAN_STATUS_SUCCESS;

    (void)memset(&req, 0x00, sizeof(mlan_ioctl_req));

    /* Allocate an IOCTL request buffer */
    pcfg_11k = os_mem_alloc(sizeof(mlan_ds_11k_cfg));
    if (pcfg_11k == NULL)
    {
        ret = MLAN_STATUS_FAILURE;
        return ret;
    }

    /* Fill request buffer */
    pcfg_11k->sub_command = MLAN_OID_11K_CFG_ENABLE;
    req.pbuf              = (t_u8 *)pcfg_11k;
    req.buf_len           = sizeof(mlan_ds_11k_cfg);
    req.req_id            = MLAN_IOCTL_11K_CFG;
    req.action            = MLAN_ACT_SET;

    if (enable_11k != 0 && enable_11k != 1)
    {
        ret = MLAN_STATUS_FAILURE;
        os_mem_free(pcfg_11k);
        return ret;
    }

    pcfg_11k->param.enable_11k = enable_11k;

    if (!is_sta_connected())
    {
        ret = wlan_ops_sta_ioctl(mlan_adap, &req);
        if (ret != MLAN_STATUS_SUCCESS && ret != MLAN_STATUS_PENDING)
        {
            os_mem_free(pcfg_11k);
            return -WM_FAIL;
        }
    }
    else
        wifi_e("sta disconnection is required before enable/disable 11k\r\n");

    os_mem_free(pcfg_11k);

    return WM_SUCCESS;
}

int wifi_11k_neighbor_req()
{
    if (!is_sta_connected())
    {
        wifi_e("sta connection is required before sending neighbor report req\r\n");
        return -WM_FAIL;
    }

    HostCmd_DS_COMMAND *cmd = wifi_get_command_buffer();

    wifi_get_command_lock();

    cmd->seq_num = 0x0;
    cmd->result  = 0x0;

    wlan_cmd_11k_neighbor_req((mlan_private *)mlan_adap->priv[0], cmd);

    wifi_wait_for_cmdresp(NULL);

    return WM_SUCCESS;
}
#endif

#ifdef CONFIG_11K
int wifi_host_11k_cfg(int enable_11k)
{
    mlan_private *pmpriv = (mlan_private *)mlan_adap->priv[0];
    IEEEtypes_RrmElement_t rrmCap;
    int ret = (int)MLAN_STATUS_SUCCESS;

#ifdef CONFIG_11K_OFFLOAD
    /* Check if fw base 11k is enabled */
    if (enable_11k == 1 && pmpriv->enable_11k == (t_u8)1U)
    {
        return -WM_E_PERM;
    }
#endif
    if (enable_11k == (int)pmpriv->enable_host_11k)
    {
        return (int)MLAN_STATUS_SUCCESS;
    }

    if (enable_11k == 1)
    {
        rrmCap.element_id = (t_u8)MGMT_RRM_ENABLED_CAP;
        rrmCap.len        = (t_u8)sizeof(IEEEtypes_RrmEnabledCapabilities_t);
        wlan_dot11k_formatRrmCapabilities(&(rrmCap.RrmEnabledCapabilities), 100);
        pmpriv->rrm_mgmt_bitmap_index = wifi_set_mgmt_ie(MLAN_BSS_TYPE_STA, MGMT_RRM_ENABLED_CAP,
                                                         (void *)&(rrmCap.RrmEnabledCapabilities), rrmCap.len);
    }
    else
    {
        ret = wifi_clear_mgmt_ie(MLAN_BSS_TYPE_STA, MGMT_RRM_ENABLED_CAP, pmpriv->rrm_mgmt_bitmap_index);
    }
    pmpriv->enable_host_11k = (t_u8)enable_11k;

    if (pmpriv->enable_host_11k == (t_u8)1U)
    {
        pmpriv->ext_cap.BSS_Transition = 1U;
    }
    else
    {
        pmpriv->ext_cap.BSS_Transition = 0U;
    }

    return ret;
}

int wifi_host_11k_neighbor_req(t_u8 *ssid)
{
    if (wlan_strlen((t_s8 *)ssid) > IEEEtypes_SSID_SIZE)
    {
        return -WM_FAIL;
    }
    else
    {
        return wlan_send_mgmt_rm_neighbor_request(mlan_adap->priv[0], ssid, (t_u8)wlan_strlen((t_s8 *)ssid));
    }
}
#endif

#ifdef CONFIG_11V
int wifi_host_11v_bss_trans_query(t_u8 query_reason)
{
    return wlan_send_mgmt_bss_trans_query(mlan_adap->priv[0], query_reason);
}
#endif

#ifdef CONFIG_MBO
int wifi_host_mbo_cfg(int enable_mbo)
{
    mlan_private *pmpriv = (mlan_private *)mlan_adap->priv[0];
    IEEEtypes_VendorSpecific_t mboie;
    int ret = (int)MLAN_STATUS_SUCCESS;
    t_u8 *pos;
    int meas_vend_hdr_len = 0;

    if ((t_u8)enable_mbo == pmpriv->enable_mbo)
    {
        /* Do nothing */
        return (int)MLAN_STATUS_SUCCESS;
    }

    if (enable_mbo != 0)
    {
        mboie.vend_hdr.element_id = (IEEEtypes_ElementId_e)MGMT_MBO_IE;
        pos                       = mboie.vend_hdr.oui;
        pos                       = wlan_add_mbo_oui(pos);
        pos                       = wlan_add_mbo_oui_type(pos);
        pos                       = wlan_add_mbo_cellular_cap(pos);
        meas_vend_hdr_len         = pos - mboie.vend_hdr.oui;
        mboie.vend_hdr.len        = (t_u8)meas_vend_hdr_len;
        pmpriv->mbo_mgmt_bitmap_index =
            wifi_set_mgmt_ie(MLAN_BSS_TYPE_STA, MGMT_MBO_IE, (void *)&(mboie.vend_hdr.oui), mboie.vend_hdr.len);
        pmpriv->ext_cap.BSS_Transition = 1U;
    }
    else
    {
        ret = wifi_clear_mgmt_ie(MLAN_BSS_TYPE_STA, MGMT_MBO_IE, pmpriv->mbo_mgmt_bitmap_index);
        pmpriv->ext_cap.BSS_Transition = 0U;
    }
    pmpriv->enable_mbo = (t_u8)enable_mbo;

    return ret;
}

int wifi_mbo_preferch_cfg(t_u8 ch0, t_u8 pefer0, t_u8 ch1, t_u8 pefer1)
{
    mlan_private *pmpriv = (mlan_private *)mlan_adap->priv[0];
    IEEEtypes_VendorSpecific_t mboie;
    int ret = (int)MLAN_STATUS_SUCCESS;
    t_u8 *pos;
    int meas_vend_hdr_len = 0;

    if (0U == pmpriv->enable_mbo)
    {
        wifi_e("Please enable MBO first!");
        return (int)MLAN_STATUS_FAILURE;
    }

    if (pmpriv->enable_mbo != 0U)
    {
        /* remove MBO OCE IE in case there is already a MBO OCE IE. */
        ret                       = wifi_clear_mgmt_ie(MLAN_BSS_TYPE_STA, MGMT_MBO_IE, pmpriv->mbo_mgmt_bitmap_index);
        mboie.vend_hdr.element_id = (IEEEtypes_ElementId_e)MGMT_MBO_IE;
        pos                       = mboie.vend_hdr.oui;
        pos                       = wlan_add_mbo_oui(pos);
        pos                       = wlan_add_mbo_oui_type(pos);
        pos                       = wlan_add_mbo_cellular_cap(pos);
        pos                       = wlan_add_mbo_prefer_ch(pos, ch0, pefer0, ch1, pefer1);
        meas_vend_hdr_len         = pos - mboie.vend_hdr.oui;
        mboie.vend_hdr.len        = (t_u8)meas_vend_hdr_len;
        pmpriv->mbo_mgmt_bitmap_index =
            wifi_set_mgmt_ie(MLAN_BSS_TYPE_STA, MGMT_MBO_IE, (void *)&(mboie.vend_hdr.oui), mboie.vend_hdr.len);
    }

    return ret;
}

int wifi_mbo_send_preferch_wnm(t_u8 *src_addr, t_u8 *target_bssid, t_u8 ch0, t_u8 pefer0, t_u8 ch1, t_u8 pefer1)
{
    mlan_private *pmpriv = (mlan_private *)mlan_adap->priv[0];
    IEEEtypes_VendorSpecific_t mboie;
    int ret = (int)MLAN_STATUS_SUCCESS;
    t_u8 *pos;
    int meas_vend_hdr_len = 0;

    if (0U == pmpriv->enable_mbo)
    {
        wifi_e("Please enable MBO first!\r\n");
        return (int)MLAN_STATUS_FAILURE;
    }

    if (pmpriv->enable_mbo != 0U)
    {
        mboie.vend_hdr.element_id = (IEEEtypes_ElementId_e)MGMT_MBO_IE;
        pos                       = mboie.vend_hdr.oui;
        pos                       = wlan_add_mbo_oui(pos);
        pos                       = wlan_add_mbo_oui_type(pos);
        pos                       = wlan_add_mbo_cellular_cap(pos);
        pos                       = wlan_add_mbo_prefer_ch(pos, ch0, pefer0, ch1, pefer1);
        meas_vend_hdr_len         = pos - mboie.vend_hdr.oui;
        mboie.vend_hdr.len        = (t_u8)meas_vend_hdr_len;
        /*Wi-Fi CERTIFIED Agile Multiband. Test Plan v1.4 section 2.5.1 Test bed AP requirements. For 2.4/5 GHz:?E MFPC
         * (bit 7) set to 1?E MFPR (bit 6) set to 0*/
        wlan_send_mgmt_wnm_notification(src_addr, target_bssid, target_bssid, (t_u8 *)&mboie,
                                        mboie.vend_hdr.len + (t_u8)2U, false);
    }

    return ret;
}
#endif

#ifdef OTP_CHANINFO
int wifi_get_fw_region_and_cfp_tables(void)
{
    int ret;

    HostCmd_DS_COMMAND *cmd = wifi_get_command_buffer();

    (void)wifi_get_command_lock();

    cmd->command = HostCmd_CMD_CHAN_REGION_CFG;
    cmd->seq_num = 0x0;
    cmd->result  = 0x0;
    cmd->size    = S_DS_GEN + sizeof(HostCmd_DS_CHAN_REGION_CFG);

    HostCmd_DS_CHAN_REGION_CFG *chan_region_cfg = (HostCmd_DS_CHAN_REGION_CFG *)(void *)((uint8_t *)cmd + S_DS_GEN);

    chan_region_cfg->action = HostCmd_ACT_GEN_GET;

    ret = wifi_wait_for_cmdresp(NULL);
    return ret;
}

void wifi_free_fw_region_and_cfp_tables(void)
{
    mlan_adapter *pmadapter = mlan_adap->priv[0]->adapter;
    wlan_free_fw_cfp_tables(pmadapter);
}
#endif

int wifi_set_ed_mac_mode(wifi_ed_mac_ctrl_t *wifi_ed_mac_ctrl, int bss_type)
{
    int ret;

    if (wifi_ed_mac_ctrl == MNULL)
    {
        return -WM_FAIL;
    }

    mlan_private *pmpriv    = (mlan_private *)mlan_adap->priv[bss_type];
    HostCmd_DS_COMMAND *cmd = wifi_get_command_buffer();

    (void)wifi_get_command_lock();

    cmd->command = HostCmd_CMD_ED_MAC_MODE;
    cmd->seq_num = HostCmd_SET_SEQ_NO_BSS_INFO(0 /* seq_num */, 0 /* bss_num */, bss_type);
    cmd->result  = 0x0;
    cmd->size    = S_DS_GEN + sizeof(HostCmd_CONFIG_ED_MAC_MODE);

    HostCmd_CONFIG_ED_MAC_MODE *ed_mac_mode = (HostCmd_CONFIG_ED_MAC_MODE *)(void *)((uint8_t *)cmd + S_DS_GEN);

    ed_mac_mode->ed_ctrl_2g   = wlan_cpu_to_le16(wifi_ed_mac_ctrl->ed_ctrl_2g);
    ed_mac_mode->ed_offset_2g = wlan_cpu_to_le16(wifi_ed_mac_ctrl->ed_offset_2g);
#ifdef CONFIG_5GHz_SUPPORT
    ed_mac_mode->ed_ctrl_5g   = wlan_cpu_to_le16(wifi_ed_mac_ctrl->ed_ctrl_5g);
    ed_mac_mode->ed_offset_5g = wlan_cpu_to_le16(wifi_ed_mac_ctrl->ed_offset_5g);
#if defined(IW61x)
    ed_mac_mode->ed_bitmap_txq_lock = 0x1e00ff;
#else
    ed_mac_mode->ed_bitmap_txq_lock = 0xff;
#endif
#endif

    pmpriv->ed_mac_mode.ed_ctrl_2g   = wlan_cpu_to_le16(wifi_ed_mac_ctrl->ed_ctrl_2g);
    pmpriv->ed_mac_mode.ed_offset_2g = wlan_cpu_to_le16(wifi_ed_mac_ctrl->ed_offset_2g);
#ifdef CONFIG_5GHz_SUPPORT
    pmpriv->ed_mac_mode.ed_ctrl_5g   = wlan_cpu_to_le16(wifi_ed_mac_ctrl->ed_ctrl_5g);
    pmpriv->ed_mac_mode.ed_offset_5g = wlan_cpu_to_le16(wifi_ed_mac_ctrl->ed_offset_5g);
#endif

    ret = wifi_wait_for_cmdresp(NULL);
    return ret;
}

int wifi_get_ed_mac_mode(wifi_ed_mac_ctrl_t *wifi_ed_mac_ctrl, int bss_type)
{
    mlan_private *pmpriv = (mlan_private *)mlan_adap->priv[bss_type];

    if (wifi_ed_mac_ctrl == MNULL)
    {
        return -WM_FAIL;
    }

    (void)memset(wifi_ed_mac_ctrl, 0x00, sizeof(wifi_ed_mac_ctrl_t));

    wifi_ed_mac_ctrl->ed_ctrl_2g   = wlan_cpu_to_le16(pmpriv->ed_mac_mode.ed_ctrl_2g);
    wifi_ed_mac_ctrl->ed_offset_2g = wlan_cpu_to_le16(pmpriv->ed_mac_mode.ed_offset_2g);
#ifdef CONFIG_5GHz_SUPPORT
    wifi_ed_mac_ctrl->ed_ctrl_5g   = wlan_cpu_to_le16(pmpriv->ed_mac_mode.ed_ctrl_5g);
    wifi_ed_mac_ctrl->ed_offset_5g = wlan_cpu_to_le16(pmpriv->ed_mac_mode.ed_offset_5g);
#endif

    return WM_SUCCESS;
}

#ifndef IEEEtypes_SSID_SIZE
#define IEEEtypes_SSID_SIZE 32
#endif /* IEEEtypes_SSID_SIZE */
#define MRVL_SSID_TLV_ID          0x0000
#define MRVL_BEACON_PERIOD_TLV_ID (PROPRIETARY_TLV_BASE_ID + 0x2cU)
#define TLV_TYPE_SMCADDRRANGE     (PROPRIETARY_TLV_BASE_ID + 0xccU)
#define TLV_TYPE_SMCFRAMEFILTER   (PROPRIETARY_TLV_BASE_ID + 0xd1U)

int wifi_set_smart_mode_cfg(char *ssid,
                            int beacon_period,
                            wifi_chan_list_param_set_t *chan_list,
                            uint8_t *smc_start_addr,
                            uint8_t *smc_end_addr,
                            uint16_t filter_type,
                            int smc_frame_filter_len,
                            uint8_t *smc_frame_filter,
                            int custom_ie_len,
                            uint8_t *custom_ie)
{
    unsigned int ssid_len                              = 0, i;
    uint32_t size                                      = S_DS_GEN + sizeof(HostCmd_DS_SYS_CONFIG) - 1U;
    MrvlIEtypes_SsIdParamSet_t *tlv_ssid               = NULL;
    MrvlIEtypes_beacon_period_t *tlv_beacon_period     = NULL;
    MrvlIEtypes_ChanListParamSet_t *tlv_chan_list      = NULL;
    MrvlIEtypes_Data_t *tlv_custom_ie                  = NULL;
    MrvlIETypes_SmcAddrRange_t *tlv_smc_addr_range     = NULL;
    MrvlIETypes_SmcFrameFilter_t *tlv_smc_frame_filter = NULL;

    (void)wifi_get_command_lock();
    HostCmd_DS_COMMAND *cmd = wifi_get_command_buffer();

    cmd->command                          = wlan_cpu_to_le16(HOST_CMD_SMART_MODE_CFG);
    HostCmd_DS_SYS_CONFIG *sys_config_cmd = (HostCmd_DS_SYS_CONFIG *)((uint32_t)cmd + S_DS_GEN);
    sys_config_cmd->action                = HostCmd_ACT_GEN_SET;
    uint8_t *tlv                          = (uint8_t *)sys_config_cmd->tlv_buffer;

    ssid_len = strlen(ssid);
    if (ssid_len > IEEEtypes_SSID_SIZE || custom_ie_len > 255)
    {
        return -WM_E_INVAL;
    };

    tlv_ssid              = (MrvlIEtypes_SsIdParamSet_t *)(void *)sys_config_cmd->tlv_buffer;
    tlv_ssid->header.type = MRVL_SSID_TLV_ID;
    tlv_ssid->header.len  = strlen(ssid);
    (void)memcpy((void *)tlv_ssid->ssid, (const void *)ssid, strlen(ssid));
    size += sizeof(tlv_ssid->header) + tlv_ssid->header.len;
    tlv += sizeof(tlv_ssid->header) + tlv_ssid->header.len;
    tlv_beacon_period                = (MrvlIEtypes_beacon_period_t *)(void *)tlv;
    tlv_beacon_period->header.type   = MRVL_BEACON_PERIOD_TLV_ID;
    tlv_beacon_period->header.len    = sizeof(uint16_t);
    tlv_beacon_period->beacon_period = beacon_period;

    size += sizeof(tlv_beacon_period->header) + tlv_beacon_period->header.len;
    tlv += sizeof(tlv_beacon_period->header) + tlv_beacon_period->header.len;

    tlv_chan_list              = (MrvlIEtypes_ChanListParamSet_t *)(void *)tlv;
    tlv_chan_list->header.type = TLV_TYPE_CHANLIST;
    tlv_chan_list->header.len  = chan_list->no_of_channels * sizeof(ChanScanParamSet_t);

    for (i = 0; i < chan_list->no_of_channels; i++)
    {
        tlv_chan_list->chan_scan_param[i].chan_number   = chan_list->chan_scan_param[i].chan_number;
        tlv_chan_list->chan_scan_param[i].min_scan_time = chan_list->chan_scan_param[i].min_scan_time;
        tlv_chan_list->chan_scan_param[i].max_scan_time = chan_list->chan_scan_param[i].max_scan_time;
    }

    size += sizeof(tlv_chan_list->header) + tlv_chan_list->header.len;
    tlv += sizeof(tlv_chan_list->header) + tlv_chan_list->header.len;

    if (custom_ie != MNULL && custom_ie_len > 0)
    {
        tlv_custom_ie              = (MrvlIEtypes_Data_t *)(void *)tlv;
        tlv_custom_ie->header.type = TLV_TYPE_PASSTHROUGH;
        tlv_custom_ie->header.len  = custom_ie_len;
        (void)memcpy((void *)tlv_custom_ie->data, (const void *)custom_ie, custom_ie_len);

        size += sizeof(tlv_custom_ie->header) + tlv_custom_ie->header.len;
        tlv += sizeof(tlv_custom_ie->header) + tlv_custom_ie->header.len;
    }

    if (smc_start_addr != MNULL && smc_end_addr != MNULL)
    {
        tlv_smc_addr_range              = (MrvlIETypes_SmcAddrRange_t *)(void *)tlv;
        tlv_smc_addr_range->header.type = TLV_TYPE_SMCADDRRANGE;
        tlv_smc_addr_range->header.len  = 2U * MLAN_MAC_ADDR_LENGTH + sizeof(uint16_t);

        (void)memcpy((void *)tlv_smc_addr_range->smcstartAddr, (const void *)smc_start_addr, MLAN_MAC_ADDR_LENGTH);
        (void)memcpy((void *)tlv_smc_addr_range->smcendAddr, (const void *)smc_end_addr, MLAN_MAC_ADDR_LENGTH);

        tlv_smc_addr_range->filter_type = filter_type;

        size += sizeof(tlv_smc_addr_range->header) + tlv_smc_addr_range->header.len;
        tlv += sizeof(tlv_smc_addr_range->header) + tlv_smc_addr_range->header.len;
    }

    tlv_smc_frame_filter              = (MrvlIETypes_SmcFrameFilter_t *)(void *)tlv;
    tlv_smc_frame_filter->header.type = TLV_TYPE_SMCFRAMEFILTER;
    tlv_smc_frame_filter->header.len  = smc_frame_filter_len;
    (void)memcpy((void *)tlv_smc_frame_filter->frame_filter, (const void *)smc_frame_filter, smc_frame_filter_len);

    size += sizeof(tlv_smc_frame_filter->header) + tlv_smc_frame_filter->header.len;
    tlv += sizeof(tlv_smc_frame_filter->header) + tlv_smc_frame_filter->header.len;

    cmd->size    = size;
    cmd->seq_num = 0x00;
    cmd->result  = 0x00;

    (void)wifi_wait_for_cmdresp(NULL);

    return WM_SUCCESS;
}

int wifi_get_smart_mode_cfg(void)
{
    uint32_t size = S_DS_GEN + sizeof(HostCmd_DS_SYS_CONFIG) - 1U;

    (void)wifi_get_command_lock();
    HostCmd_DS_COMMAND *cmd = wifi_get_command_buffer();

    cmd->command                          = wlan_cpu_to_le16(HOST_CMD_SMART_MODE_CFG);
    HostCmd_DS_SYS_CONFIG *sys_config_cmd = (HostCmd_DS_SYS_CONFIG *)((uint32_t)cmd + S_DS_GEN);
    sys_config_cmd->action                = HostCmd_ACT_GEN_GET;

    cmd->size    = size;
    cmd->seq_num = 0x00;
    cmd->result  = 0x00;

    (void)wifi_wait_for_cmdresp(NULL);
    return WM_SUCCESS;
}

int wifi_start_smart_mode(void)
{
    uint32_t size = S_DS_GEN + sizeof(HostCmd_DS_SYS_CONFIG) - 1U;

    (void)wifi_get_command_lock();
    HostCmd_DS_COMMAND *cmd = wifi_get_command_buffer();

    cmd->command                          = wlan_cpu_to_le16(HOST_CMD_SMART_MODE_CFG);
    HostCmd_DS_SYS_CONFIG *sys_config_cmd = (HostCmd_DS_SYS_CONFIG *)((uint32_t)cmd + S_DS_GEN);
    sys_config_cmd->action                = HostCmd_ACT_GEN_START;

    cmd->size    = size;
    cmd->seq_num = 0x00;
    cmd->result  = 0x00;

    (void)wifi_wait_for_cmdresp(NULL);
    return WM_SUCCESS;
}

int wifi_stop_smart_mode(void)
{
    uint32_t size = S_DS_GEN + sizeof(HostCmd_DS_SYS_CONFIG) - 1U;

    (void)wifi_get_command_lock();
    HostCmd_DS_COMMAND *cmd = wifi_get_command_buffer();

    cmd->command                          = wlan_cpu_to_le16(HOST_CMD_SMART_MODE_CFG);
    HostCmd_DS_SYS_CONFIG *sys_config_cmd = (HostCmd_DS_SYS_CONFIG *)((uint32_t)cmd + S_DS_GEN);
    sys_config_cmd->action                = HostCmd_ACT_GEN_STOP;

    cmd->size    = size;
    cmd->seq_num = 0x00;
    cmd->result  = 0x00;

    (void)wifi_wait_for_cmdresp(NULL);

    return WM_SUCCESS;
}

#ifdef CONFIG_ROAMING
void wifi_get_band(mlan_private *pmpriv, int *band)
{
    int support_band = 0;

    if (pmpriv->config_bands & (BAND_B | BAND_G | BAND_GN))
        support_band |= WIFI_FREQUENCY_BAND_2GHZ;
#ifdef CONFIG_5GHz_SUPPORT
    if (pmpriv->config_bands & (BAND_A | BAND_AN))
        support_band |= WIFI_FREQUENCY_BAND_5GHZ;
#endif
    *band = support_band;
    if (support_band == WIFI_FREQUENCY_ALL_BAND)
        *band = WIFI_FREQUENCY_BAND_AUTO;
}

int wifi_get_bgscan_results(mlan_private *pmpriv)
{
    mlan_adapter *pmadapter = pmpriv->adapter;
    int ret                 = 0;

    ENTER();
    memset(pmadapter->pscan_table, 0x00, sizeof(BSSDescriptor_t) * MRVDRV_MAX_BSSID_LIST);
    pmadapter->num_in_scan_table = 0;
    ret                          = wifi_request_bgscan_query(pmpriv);
    pmadapter->bgscan_reported   = MFALSE;
    LEAVE();
    return ret;
}

int wifi_send_scan_query(void)
{
    mlan_private *pmpriv = (mlan_private *)mlan_adap->priv[0];
    int ret              = 0;

    ENTER();
    ret = wifi_get_bgscan_results(pmpriv);
    if (ret)
    {
        PRINTM(MERROR, "Failed to get scan results\n");
        goto done;
    }
done:
    /* config rssi low threshold again */
    pmpriv->rssi_low = DEFAULT_RSSI_LOW_THRESHOLD;
    LEAVE();
    return ret;
}
#endif

int wifi_send_hostcmd(
    void *cmd_buf, uint32_t cmd_buf_len, void *resp_buf, uint32_t resp_buf_len, uint32_t *reqd_resp_len)
{
    uint32_t ret = WM_SUCCESS;
    /* Store IN & OUT params to be used by driver to update internaally*/
    /* These variables are updated from reponse handlers */
    wm_wifi.hostcmd_cfg.resp_buf      = resp_buf;
    wm_wifi.hostcmd_cfg.resp_buf_len  = resp_buf_len;
    wm_wifi.hostcmd_cfg.reqd_resp_len = reqd_resp_len;

    /* Check if command is larger than the command size that can be handled by firmware */
    if (cmd_buf_len > WIFI_FW_CMDBUF_SIZE)
    {
        *reqd_resp_len = 0;
        return WM_E_INBIG;
    }
    else if (cmd_buf_len < WIFI_HOST_CMD_FIXED_HEADER_LEN)
    /* Check if command is smaller than the minimum command size needed, which is WIFI_HOST_CMD_FIXED_HEADER_LEN */
    {
        *reqd_resp_len = 0;
        return WM_E_INSMALL;
    }
    else
    {
        /* Do Nothing */
    }
    (void)wifi_get_command_lock();
    /* Copy command buffer to driver command buffer */
    HostCmd_DS_COMMAND *cmd = wifi_get_command_buffer();
    (void)memcpy((void *)cmd, (const void *)cmd_buf, cmd_buf_len);

    /* Set global variable to say that this command is from user invocation */
    wm_wifi.hostcmd_cfg.is_hostcmd = true;
    (void)wifi_wait_for_cmdresp(&wm_wifi.hostcmd_cfg);

    if (*reqd_resp_len > resp_buf_len)
    {
        ret = WM_E_OUTBIG;
    }
    /*Response fail check not checked here, as thats caller's responsibility */
    return ret;
}

#ifdef CONFIG_WIFI_EU_CRYPTO
int wifi_set_eu_crypto(EU_Crypto *Crypto_Data, enum _crypto_algorithm Algorithm, t_u16 EncDec)
{
    HostCmd_DS_COMMAND *cmd = wifi_get_command_buffer();
    t_u16 cmd_size;
    t_u16 *DataLength = Crypto_Data->DataLength;

    wifi_get_command_lock();

    (void)memset(cmd, 0x00, WIFI_FW_CMDBUF_SIZE);
    cmd->command = HostCmd_CMD_EU_CRYPTO;
    cmd->seq_num = HostCmd_SET_SEQ_NO_BSS_INFO(0 /* seq_num */, 0 /* bss_num */, MLAN_BSS_ROLE_STA);

    switch (Algorithm)
    {
        case CRYPTO_RC4:
        case CRYPTO_AES_ECB:
        case CRYPTO_AES_WRAP:
        {
            cmd_size                        = sizeof(HostCmd_DS_EU_CRYPTO) - 1 + 8 /*cmd header */;
            cmd->params.eu_crypto.Algorithm = Algorithm;
            cmd->params.eu_crypto.KeyLength = Crypto_Data->KeyLength;
            memcpy(cmd->params.eu_crypto.Key, Crypto_Data->Key, Crypto_Data->KeyLength);
            cmd->params.eu_crypto.KeyIVLength = Crypto_Data->KeyIVLength;
            memcpy(cmd->params.eu_crypto.KeyIV, Crypto_Data->KeyIV, Crypto_Data->KeyIVLength);
            cmd->params.eu_crypto.DataLength = *DataLength;
            memcpy(cmd->params.eu_crypto.Data, Crypto_Data->Data, *DataLength);
            cmd_size += cmd->params.eu_crypto.DataLength;
            cmd->params.eu_crypto.EncDec   = EncDec;
            cmd->params.eu_crypto.DataType = 0x0111;
            break;
        }
        case CRYPTO_AES_CCMP:
        case CRYPTO_AES_GCMP:
        {
            cmd_size                            = sizeof(HostCmd_DS_EU_AES_CRYPTO) - 1 + 8 /* cmd header */;
            cmd->params.eu_aes_crypto.Algorithm = Algorithm;
            cmd->params.eu_aes_crypto.KeyLength = Crypto_Data->KeyLength;
            memcpy(cmd->params.eu_aes_crypto.Key, Crypto_Data->Key, Crypto_Data->KeyLength);
            cmd->params.eu_aes_crypto.NonceLength = Crypto_Data->NonceLength;
            memcpy(cmd->params.eu_aes_crypto.Nonce, Crypto_Data->Nonce, Crypto_Data->NonceLength);
            cmd->params.eu_aes_crypto.AADLength = Crypto_Data->AADLength;
            memcpy(cmd->params.eu_aes_crypto.AAD, Crypto_Data->AAD, Crypto_Data->AADLength);
            cmd->params.eu_aes_crypto.DataLength = *DataLength;
            memcpy(cmd->params.eu_aes_crypto.Data, Crypto_Data->Data, *DataLength);
            cmd_size += cmd->params.eu_aes_crypto.DataLength;
            cmd->params.eu_aes_crypto.EncDec   = EncDec;
            cmd->params.eu_aes_crypto.DataType = 0x0111;
            break;
        }
        default:
            return -WM_FAIL;
    }
    cmd->size = cmd_size;

    return wifi_wait_for_cmdresp(Crypto_Data);
}
#endif

int wifi_set_rx_mgmt_indication(unsigned int bss_type, unsigned int mgmt_subtype_mask)
{
    mlan_private *pmpriv = (mlan_private *)mlan_adap->priv[0];

    mlan_ds_rx_mgmt_indication rx_mgmt_indication;

    memset(&rx_mgmt_indication, 0x00, sizeof(mlan_ds_rx_mgmt_indication));

    rx_mgmt_indication.mgmt_subtype_mask = mgmt_subtype_mask;

    wifi_get_command_lock();
    HostCmd_DS_COMMAND *cmd = wifi_get_command_buffer();

    cmd->command = HostCmd_CMD_RX_MGMT_IND;
#ifdef CONFIG_P2P
    cmd->seq_num = HostCmd_SET_SEQ_NO_BSS_INFO(0U /* seq_num */, 0U /* bss_num */, MLAN_BSS_TYPE_WIFIDIRECT);
#else
    cmd->seq_num = HostCmd_SET_SEQ_NO_BSS_INFO(0U /* seq_num */, 0U /* bss_num */, bss_type);
#endif /* CONFIG_P2P */
    cmd->result = 0x0;

    wlan_cmd_rx_mgmt_indication(pmpriv, cmd, HostCmd_ACT_GEN_SET, &rx_mgmt_indication);

    wifi_wait_for_cmdresp(NULL);

    return wm_wifi.cmd_resp_status;
}

wlan_mgmt_pkt *wifi_PrepDefaultMgtMsg(t_u8 sub_type,
                                      mlan_802_11_mac_addr *DestAddr,
                                      mlan_802_11_mac_addr *SrcAddr,
                                      mlan_802_11_mac_addr *Bssid,
                                      t_u16 pkt_len)
{
    wlan_mgmt_pkt *pmgmt_pkt_hdr    = MNULL;
    IEEEtypes_FrameCtl_t *mgmt_fc_p = MNULL;
    t_u8 *pBuf                      = MNULL;

    pBuf = os_mem_calloc(pkt_len);
    if (pBuf == MNULL)
    {
        return MNULL;
    }

    pmgmt_pkt_hdr = (wlan_mgmt_pkt *)(void *)pBuf;
    /* 802.11 header */
    mgmt_fc_p           = (IEEEtypes_FrameCtl_t *)(void *)&pmgmt_pkt_hdr->wlan_header.frm_ctl;
    mgmt_fc_p->sub_type = sub_type;
    mgmt_fc_p->type     = (t_u8)IEEE_TYPE_MANAGEMENT;
    (void)memcpy(pmgmt_pkt_hdr->wlan_header.addr1, DestAddr, MLAN_MAC_ADDR_LENGTH);
    (void)memcpy(pmgmt_pkt_hdr->wlan_header.addr2, SrcAddr, MLAN_MAC_ADDR_LENGTH);
    (void)memcpy(pmgmt_pkt_hdr->wlan_header.addr3, Bssid, MLAN_MAC_ADDR_LENGTH);

    return pmgmt_pkt_hdr;
}

#ifdef CONFIG_ECSA
mlan_ecsa_block_tx_control ecsa_block_tx_control = {false, 0};

void set_ecsa_block_tx_time(t_u8 switch_count)
{
    ecsa_block_tx_control.block_time = switch_count;
}

t_u8 get_ecsa_block_tx_time()
{
    return ecsa_block_tx_control.block_time;
}

void set_ecsa_block_tx_flag(bool block_tx)
{
    ecsa_block_tx_control.required = block_tx;
}

bool get_ecsa_block_tx_flag()
{
    return ecsa_block_tx_control.required;
}

int wlan_get_nonglobal_operclass_by_bw_channel(t_u8 bandwidth, t_u8 channel, t_u8 *oper_class)
{
    int ret = 0;
    mlan_ioctl_req req;
    mlan_ds_misc_cfg *misc = NULL;
    mlan_status status     = MLAN_STATUS_SUCCESS;

    (void)memset(&req, 0x00, sizeof(mlan_ioctl_req));

    misc = os_mem_alloc(sizeof(mlan_ds_misc_cfg));
    if (misc == NULL)
    {
        return -WM_FAIL;
    }

    req.bss_index                      = MLAN_BSS_ROLE_UAP;
    req.pbuf                           = (t_u8 *)misc;
    misc->sub_command                  = MLAN_OID_MISC_OPER_CLASS;
    req.req_id                         = MLAN_IOCTL_MISC_CFG;
    req.action                         = MLAN_ACT_GET;
    misc->param.bw_chan_oper.bandwidth = bandwidth;
    misc->param.bw_chan_oper.channel   = channel;

    status = wlan_ops_uap_ioctl(mlan_adap, &req);
    if (status != MLAN_STATUS_SUCCESS)
    {
        wifi_e("Failed to get operclass\n");
        os_mem_free(misc);
        return -WM_FAIL;
    }
    *oper_class = misc->param.bw_chan_oper.oper_class;

    os_mem_free(misc);

    return ret;
}

int wifi_set_ecsa_cfg(t_u8 block_tx, t_u8 oper_class, t_u8 channel, t_u8 switch_count, t_u8 band_width, t_u8 ecsa)
{
    IEEEtypes_ExtChanSwitchAnn_t *ext_chan_switch = NULL;
    IEEEtypes_ChanSwitchAnn_t *chan_switch        = NULL;
    custom_ie *pcust_chansw_ie                    = NULL;
    t_u32 usr_dot_11n_dev_cap                     = 0;
    mlan_private *pmpriv                          = (mlan_private *)mlan_adap->priv[1];
    BSSDescriptor_t *pbss_desc;
    pbss_desc           = &pmpriv->curr_bss_params.bss_descriptor;
    t_u8 new_oper_class = oper_class;
    t_u8 bw;
    int ret = MLAN_STATUS_SUCCESS;
#if defined(CONFIG_11AC)
    t_u8 center_freq_idx                       = 0;
    IEEEtypes_Header_t *pChanSwWrap_ie         = NULL;
    IEEEtypes_WideBWChanSwitch_t *pbwchansw_ie = NULL;
    IEEEtypes_VhtTpcEnvelope_t *pvhttpcEnv_ie  = NULL;
#endif
    uint8_t *buf               = NULL;
    tlvbuf_custom_ie *tlv      = NULL;
    unsigned int mgmt_ie_index = -1;
    int total_len = sizeof(tlvbuf_custom_ie) + (sizeof(custom_ie) - MAX_IE_SIZE) + sizeof(IEEEtypes_ChanSwitchAnn_t) +
                    sizeof(IEEEtypes_ExtChanSwitchAnn_t);
#if defined(CONFIG_11AC)
    total_len += sizeof(IEEEtypes_WideBWChanSwitch_t) + sizeof(IEEEtypes_VhtTpcEnvelope_t) + sizeof(IEEEtypes_Header_t);
#endif
    uint16_t buf_len = 0;

    buf = (uint8_t *)os_mem_alloc(total_len);
    if (!buf)
    {
        wifi_e("ECSA allocate memory failed \r\n");
        return -WM_FAIL;
    }

    (void)memset(buf, 0, total_len);
    tlv       = (tlvbuf_custom_ie *)buf;
    tlv->type = MRVL_MGMT_IE_LIST_TLV_ID;

    ret = get_free_mgmt_ie_index(&mgmt_ie_index);
    if (WM_SUCCESS != ret)
    {
        os_mem_free(buf);
        return -WM_FAIL;
    }

    pcust_chansw_ie                    = (custom_ie *)(tlv->ie_data);
    pcust_chansw_ie->ie_index          = mgmt_ie_index;
    pcust_chansw_ie->ie_length         = sizeof(IEEEtypes_ChanSwitchAnn_t);
    pcust_chansw_ie->mgmt_subtype_mask = MGMT_MASK_BEACON | MGMT_MASK_PROBE_RESP; /*Add IE for
                                                                 BEACON/probe resp*/
    chan_switch                    = (IEEEtypes_ChanSwitchAnn_t *)pcust_chansw_ie->ie_buffer;
    chan_switch->element_id        = CHANNEL_SWITCH_ANN;
    chan_switch->len               = 3;
    chan_switch->chan_switch_mode  = block_tx;
    chan_switch->new_channel_num   = channel;
    chan_switch->chan_switch_count = switch_count;
    DBG_HEXDUMP(MCMD_D, "CSA IE", (t_u8 *)pcust_chansw_ie->ie_buffer, pcust_chansw_ie->ie_length);

#ifdef CONFIG_5GHz_SUPPORT
    if (pbss_desc->bss_band & BAND_A)
        usr_dot_11n_dev_cap = mlan_adap->usr_dot_11n_dev_cap_a;
    else
#endif
        usr_dot_11n_dev_cap = mlan_adap->usr_dot_11n_dev_cap_bg;

    if (!ISSUPP_CHANWIDTH40(usr_dot_11n_dev_cap))
    {
        band_width = 0;
    }

    switch (band_width)
    {
        case CHANNEL_BW_40MHZ_ABOVE:
        case CHANNEL_BW_40MHZ_BELOW:
            bw = 40;
            break;
#if defined(CONFIG_11AC)
        case CHANNEL_BW_80MHZ:
            bw = 80;
            break;
        case CHANNEL_BW_160MHZ:
            bw = 160;
            break;
#endif
        default:
            bw = 20;
            break;
    }

    if (!new_oper_class && ecsa)
        wlan_get_nonglobal_operclass_by_bw_channel(bw, channel, &new_oper_class);

    if (new_oper_class)
    {
        pcust_chansw_ie->ie_length += sizeof(IEEEtypes_ExtChanSwitchAnn_t);
        ext_chan_switch =
            (IEEEtypes_ExtChanSwitchAnn_t *)(pcust_chansw_ie->ie_buffer + sizeof(IEEEtypes_ChanSwitchAnn_t));
        ext_chan_switch->element_id        = EXTEND_CHANNEL_SWITCH_ANN;
        ext_chan_switch->len               = 4;
        ext_chan_switch->chan_switch_mode  = block_tx;
        ext_chan_switch->new_oper_class    = new_oper_class;
        ext_chan_switch->new_channel_num   = channel;
        ext_chan_switch->chan_switch_count = switch_count;
        DBG_HEXDUMP(MCMD_D, "ECSA IE", (t_u8 *)(pcust_chansw_ie->ie_buffer + sizeof(IEEEtypes_ChanSwitchAnn_t)),
                    pcust_chansw_ie->ie_length - sizeof(IEEEtypes_ChanSwitchAnn_t));
    }

#if defined(CONFIG_11AC)
    /* bandwidth 40/80/160 should set channel switch wrapper ie for 11ac 5G
     * channel*/
    if (band_width && channel > 14)
    {
        pChanSwWrap_ie             = (IEEEtypes_Header_t *)(pcust_chansw_ie->ie_buffer + pcust_chansw_ie->ie_length);
        pChanSwWrap_ie->element_id = EXT_POWER_CONSTR;
        pChanSwWrap_ie->len        = sizeof(IEEEtypes_WideBWChanSwitch_t);

        pbwchansw_ie = (IEEEtypes_WideBWChanSwitch_t *)((t_u8 *)pChanSwWrap_ie + sizeof(IEEEtypes_Header_t));
        pbwchansw_ie->ieee_hdr.element_id = BW_CHANNEL_SWITCH;
        pbwchansw_ie->ieee_hdr.len        = sizeof(IEEEtypes_WideBWChanSwitch_t) - sizeof(IEEEtypes_Header_t);

        center_freq_idx = wlan_get_center_freq_idx((mlan_private *)mlan_adap->priv[1], BAND_AAC, channel, band_width);
        if (band_width == CHANNEL_BW_40MHZ_ABOVE || band_width == CHANNEL_BW_40MHZ_BELOW)
        {
            pbwchansw_ie->new_channel_width        = 0;
            pbwchansw_ie->new_channel_center_freq0 = center_freq_idx;
        }
        else if (band_width == CHANNEL_BW_80MHZ)
        {
            pbwchansw_ie->new_channel_width        = 1;
            pbwchansw_ie->new_channel_center_freq0 = center_freq_idx - 4;
            pbwchansw_ie->new_channel_center_freq1 = center_freq_idx + 4;
        }
        else if (band_width == CHANNEL_BW_160MHZ)
        {
            pbwchansw_ie->new_channel_width        = 2;
            pbwchansw_ie->new_channel_center_freq0 = center_freq_idx - 8;
            pbwchansw_ie->new_channel_center_freq1 = center_freq_idx + 8;
        }
        else
            wifi_e("Invalid bandwidth.Support value 1/3/4/5 for 40+/40-/80/160MHZ\n");

        /*prepare the VHT Transmit Power Envelope IE*/
        pvhttpcEnv_ie = (IEEEtypes_VhtTpcEnvelope_t *)((t_u8 *)pChanSwWrap_ie + sizeof(IEEEtypes_Header_t) +
                                                       sizeof(IEEEtypes_WideBWChanSwitch_t));
        pvhttpcEnv_ie->ieee_hdr.element_id = VHT_TX_POWER_ENV;
        pvhttpcEnv_ie->ieee_hdr.len        = sizeof(IEEEtypes_VhtTpcEnvelope_t) - sizeof(IEEEtypes_Header_t);
        /* Local Max TX Power Count= 3,
         * Local TX Power Unit Inter=EIP(0) */
        pvhttpcEnv_ie->tpc_info                     = 3;
        pvhttpcEnv_ie->local_max_tp_20mhz           = 0xff;
        pvhttpcEnv_ie->local_max_tp_40mhz           = 0xff;
        pvhttpcEnv_ie->local_max_tp_80mhz           = 0xff;
        pvhttpcEnv_ie->local_max_tp_160mhz_80_80mhz = 0xff;
        pChanSwWrap_ie->len += sizeof(IEEEtypes_VhtTpcEnvelope_t);
        pcust_chansw_ie->ie_length += pChanSwWrap_ie->len + sizeof(IEEEtypes_Header_t);
        DBG_HEXDUMP(MCMD_D, "Channel switch wrapper IE", (t_u8 *)pChanSwWrap_ie,
                    pChanSwWrap_ie->len + sizeof(IEEEtypes_Header_t));
    }
#endif
    tlv->length = sizeof(custom_ie) + pcust_chansw_ie->ie_length - MAX_IE_SIZE;

    buf_len = pcust_chansw_ie->ie_length + sizeof(tlvbuf_custom_ie) + sizeof(custom_ie) - MAX_IE_SIZE;

    ret = wrapper_wlan_cmd_mgmt_ie(MLAN_BSS_TYPE_UAP, buf, buf_len, HostCmd_ACT_GEN_SET);
    if (ret != MLAN_STATUS_SUCCESS && ret != MLAN_STATUS_PENDING)
    {
        wifi_e("Failed to set ECSA IE\n");
        os_mem_free(buf);
        return -WM_FAIL;
    }
    set_ie_index(mgmt_ie_index);
    os_thread_sleep((switch_count + 2) * wm_wifi.beacon_period);

    if (!ie_index_is_set(mgmt_ie_index))
    {
        os_mem_free(buf);
        return -WM_FAIL;
    }

    /*Clear ECSA ie*/
    (void)memset(buf, 0, total_len);
    tlv         = (tlvbuf_custom_ie *)buf;
    tlv->type   = MRVL_MGMT_IE_LIST_TLV_ID;
    tlv->length = sizeof(custom_ie) - MAX_IE_SIZE;

    pcust_chansw_ie->mgmt_subtype_mask = MGMT_MASK_CLEAR;
    pcust_chansw_ie->ie_length         = 0;
    pcust_chansw_ie->ie_index          = mgmt_ie_index;
    buf_len                            = sizeof(tlvbuf_custom_ie) + tlv->length;

    ret = wrapper_wlan_cmd_mgmt_ie(MLAN_BSS_TYPE_UAP, buf, buf_len, HostCmd_ACT_GEN_SET);
    if (ret != MLAN_STATUS_SUCCESS && ret != MLAN_STATUS_PENDING)
    {
        wifi_e("Failed to clear ECSA IE\n");
        os_mem_free(buf);
        return -WM_FAIL;
    }
    clear_ie_index(mgmt_ie_index);

    os_mem_free(buf);

    return WM_SUCCESS;
}

int wifi_set_action_ecsa_cfg(t_u8 block_tx, t_u8 oper_class, t_u8 channel, t_u8 switch_count)
{
    mlan_status ret  = MLAN_STATUS_SUCCESS;
    mlan_ds_bss *bss = NULL;
    mlan_ioctl_req req;

    (void)memset(&req, 0x00, sizeof(mlan_ioctl_req));

    bss = os_mem_alloc(sizeof(mlan_ds_bss));
    if (bss == NULL)
    {
        return -WM_FAIL;
    }

    req.bss_index                           = MLAN_BSS_ROLE_UAP;
    req.pbuf                                = (t_u8 *)bss;
    bss->sub_command                        = MLAN_OID_ACTION_CHAN_SWITCH;
    req.req_id                              = MLAN_IOCTL_BSS;
    req.action                              = MLAN_ACT_SET;
    bss->param.chanswitch.chan_switch_mode  = block_tx;
    bss->param.chanswitch.new_channel_num   = channel;
    bss->param.chanswitch.chan_switch_count = switch_count;
    bss->param.chanswitch.new_oper_class    = oper_class;

    ret = wlan_ops_uap_ioctl(mlan_adap, &req);

    if (ret != MLAN_STATUS_SUCCESS && ret != MLAN_STATUS_PENDING)
    {
        wifi_e("Failed to set ECSA IE\n");
        os_mem_free(bss);
        return -WM_FAIL;
    }
    os_mem_free(bss);

    return WM_SUCCESS;
}

#endif

#ifdef CONFIG_WMM_UAPSD
int wifi_set_wmm_qos_cfg(t_u8 qos_cfg)
{
    mlan_status ret = MLAN_STATUS_SUCCESS;
    mlan_ioctl_req req;
    mlan_ds_wmm_cfg cfg;

    (void)memset(&req, 0x00, sizeof(mlan_ioctl_req));
    (void)memset(&cfg, 0x00, sizeof(mlan_ds_wmm_cfg));
    cfg.sub_command   = MLAN_OID_WMM_CFG_QOS;
    cfg.param.qos_cfg = qos_cfg;
    req.pbuf          = (t_u8 *)&cfg;
    req.buf_len       = sizeof(mlan_ds_wmm_cfg);
    req.req_id        = MLAN_IOCTL_WMM_CFG;
    req.action        = MLAN_ACT_SET;

    ret = wlan_ops_sta_ioctl(mlan_adap, &req);
    return ret;
}

void wifi_set_sleep_period(uint16_t sleep_period)
{
    wifi_get_command_lock();
    HostCmd_DS_COMMAND *cmd = wifi_get_command_buffer();
    (void)memset(cmd, 0x00, sizeof(HostCmd_DS_COMMAND));
    cmd->seq_num = HostCmd_SET_SEQ_NO_BSS_INFO(0 /* seq_num */, 0 /* bss_num */, MLAN_BSS_TYPE_STA);
    cmd->result  = 0x0;
    wlan_ops_sta_prepare_cmd((mlan_private *)mlan_adap->priv[0], HostCmd_CMD_802_11_SLEEP_PERIOD, HostCmd_ACT_GEN_SET,
                             0, NULL, &sleep_period, cmd);
    wifi_wait_for_cmdresp(NULL);
}
#endif

#ifdef CONFIG_TX_AMPDU_PROT_MODE
int wifi_tx_ampdu_prot_mode(tx_ampdu_prot_mode_para *prot_mode, t_u16 action)
{
    wifi_get_command_lock();
    HostCmd_DS_COMMAND *cmd = wifi_get_command_buffer();

    cmd->seq_num = 0x00;
    cmd->result  = 0x0;

    wlan_ops_sta_prepare_cmd((mlan_private *)mlan_adap->priv[0], HostCmd_CMD_TX_AMPDU_PROT_MODE, action, 0, NULL,
                             prot_mode, cmd);

    return wifi_wait_for_cmdresp(action == HostCmd_ACT_GEN_GET ? prot_mode : NULL);
}
#endif
