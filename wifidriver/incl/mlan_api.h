/** @file mlan_api.h
 *
 *  @brief MLAN Interface
 *
 *  Copyright 2008-2022 NXP
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

#ifndef __MLAN_API_H__
#define __MLAN_API_H__
#include <string.h>
#include <wmtypes.h>
#include <wlan.h>

#include "fsl_debug_console.h"

#define MLAN_WMSDK_MAX_WPA_IE_LEN 256

#include "mlan.h"
#include "mlan_join.h"
#include "mlan_util.h"
#include "mlan_fw.h"
#include "mlan_main.h"
#include "mlan_wmm.h"
#include "mlan_11n.h"
#include "mlan_11h.h"
#include "mlan_11ac.h"
#ifdef CONFIG_11AX
#include "mlan_11ax.h"
#endif
#include "mlan_decl.h"
#include "mlan_11n_aggr.h"
#include "mlan_sdio.h"
#include "mlan_11n_rxreorder.h"
#include "mlan_meas.h"
#include "mlan_ioctl.h"
#include "mlan_uap.h"
#include <wifi-debug.h>
#include "wifi-internal.h"

/* #define CONFIG_WIFI_DEBUG */

#ifdef CONFIG_WIFI_DEBUG
/* #define DEBUG_11N_ASSOC */
/* #define DEBUG_11N_AGGR */
/* #define DEBUG_11N_REORDERING */
#define DEBUG_MLAN
/* #define DEBUG_DEVELOPMENT */
/* #define DUMP_PACKET_MAC */
#endif /* CONFIG_WIFI_DEBUG */

#ifdef EXIT
#undef EXIT
#define EXIT(...)
#endif /* EXIT */

#ifdef DEBUG_MLAN

#ifdef PRINTM
#undef PRINTM
#define PRINTM(level, ...)                   \
    do                                       \
    {                                        \
        (void)PRINTF("[mlan] " __VA_ARGS__); \
        (void)PRINTF("\n\r");                \
    } while (0)
#else
#define PRINTM(...)
#endif /* PRINTM */

#ifdef DBG_HEXDUMP
#undef DBG_HEXDUMP
#define DBG_HEXDUMP(level, x, y, z)       \
    do                                    \
    {                                     \
        (void)PRINTF("[mlan] %s\r\n", x); \
        dump_hex(y, z);                   \
        (void)PRINTF("\r\n");             \
    } while (0)
#else
#define DBG_HEXDUMP(...)
#endif /* DBG_HEXDUMP */

#ifdef HEXDUMP
#undef HEXDUMP
#define HEXDUMP(x, y, z)                  \
    do                                    \
    {                                     \
        (void)PRINTF("[mlan] %s\r\n", x); \
        dump_hex(y, z);                   \
        (void)PRINTF("\r\n");             \
    } while (0)
#else
#define HEXDUMP(...)
#endif /* HEXDUMP */
#endif /* DEBUG_MLAN */

#define DOT11N_CFG_ENABLE_RIFS            0x08
#define DOT11N_CFG_ENABLE_GREENFIELD_XMIT (1 << 4)
#define DOT11N_CFG_ENABLE_SHORT_GI_20MHZ  (1 << 5)
#define DOT11N_CFG_ENABLE_SHORT_GI_40MHZ  (1 << 6)

#define CLOSEST_DTIM_TO_LISTEN_INTERVAL 65534

#define SDIO_DMA_ALIGNMENT 4

/* Following is allocated in mlan_register */
extern mlan_adapter *mlan_adap;

#ifdef CONFIG_WPS2
extern int wps_session_attempt;
#endif

extern os_rw_lock_t ps_rwlock;

#ifdef CONFIG_STA_AMPDU_RX
extern bool sta_ampdu_rx_enable;
#endif
#ifdef DUMP_PACKET_MAC
void dump_mac_addr(const char *msg, unsigned char *addr);
#endif /* DUMP_PACKET_MAC */
#ifdef DEBUG_11N_ASSOC
void dump_htcap_info(const MrvlIETypes_HTCap_t *htcap);
void dump_ht_info(const MrvlIETypes_HTInfo_t *htinfo);
#endif /* DEBUG_11N_ASSOC */
mlan_status wifi_prepare_and_send_cmd(IN mlan_private *pmpriv,
                                      IN t_u16 cmd_no,
                                      IN t_u16 cmd_action,
                                      IN t_u32 cmd_oid,
                                      IN t_void *pioctl_buf,
                                      IN t_void *pdata_buf,
                                      int bss_type,
                                      void *priv);
int wifi_uap_prepare_and_send_cmd(mlan_private *pmpriv,
                                  t_u16 cmd_no,
                                  t_u16 cmd_action,
                                  t_u32 cmd_oid,
                                  t_void *pioctl_buf,
                                  t_void *pdata_buf,
                                  int bss_type,
                                  void *priv);

bool wmsdk_is_11N_enabled(void);

/**
 * Abort the split scan if it is in progress.
 *
 * After this call returns this scan function will abort the current split
 * scan and return back to the caller. The scan list may be incomplete at
 * this moment. There are no other side effects on the scan function apart
 * from this. The next call to scan function should proceed as normal.
 */
void wlan_abort_split_scan(void);

void wlan_scan_process_results(IN mlan_private *pmpriv);

bool check_for_wpa2_entp_ie(bool *wpa2_entp_IE_exist, const void *element_data, unsigned element_len);

#ifdef CONFIG_WPA2_ENTP
bool wifi_get_scan_enable_wpa2_enterprise_ap_only();

static inline mlan_status wifi_check_bss_entry_wpa2_entp_only(BSSDescriptor_t *pbss_entry, t_u8 element_id)
{
    if (element_id == RSN_IE)
    {
        if ((wifi_get_scan_enable_wpa2_enterprise_ap_only()) &&
            (!check_for_wpa2_entp_ie(&pbss_entry->wpa2_entp_IE_exist, pbss_entry->rsn_ie_buff + 8,
                                     pbss_entry->rsn_ie_buff_len - 10)))
        {
            return MLAN_STATUS_RESOURCE;
        }
        else
        {
            check_for_wpa2_entp_ie(&pbss_entry->wpa2_entp_IE_exist, pbss_entry->rsn_ie_buff + 8,
                                   pbss_entry->rsn_ie_buff_len - 10);
        }
    }
    else if (element_id == VENDOR_SPECIFIC_221)
    {
        if (wifi_get_scan_enable_wpa2_enterprise_ap_only())
            return MLAN_STATUS_RESOURCE;
    }
    else if (!element_id)
    {
        if ((wifi_get_scan_enable_wpa2_enterprise_ap_only()) && (pbss_entry->privacy != Wlan802_11PrivFilter8021xWEP) &&
            (!pbss_entry->pwpa_ie) && (!pbss_entry->prsn_ie))
            return MLAN_STATUS_RESOURCE;
    }

    return MLAN_STATUS_SUCCESS;
}
#else
static inline mlan_status wifi_check_bss_entry_wpa2_entp_only(BSSDescriptor_t *pbss_entry, t_u8 element_id)
{
    if (element_id == RSN_IE)
    {
        check_for_wpa2_entp_ie(&pbss_entry->wpa2_entp_IE_exist, pbss_entry->rsn_ie_buff + 8,
                               pbss_entry->rsn_ie_buff_len - 10);
    }
    return MLAN_STATUS_SUCCESS;
}
#endif

int wifi_send_hostcmd(
    void *cmd_buf, uint32_t cmd_buf_len, void *resp_buf, uint32_t resp_buf_len, uint32_t *reqd_resp_len);

int wifi_send_get_wpa_pmk(int mode, char *ssid);
int wifi_deauthenticate(uint8_t *bssid);
int wifi_get_eeprom_data(uint32_t offset, uint32_t byte_count, uint8_t *buf);
int wifi_get_mgmt_ie(unsigned int bss_type, IEEEtypes_ElementId_t index, void *buf, unsigned int *buf_len);
int wifi_send_remain_on_channel_cmd(unsigned int bss_type, wifi_remain_on_channel_t *remain_on_channel);
int wifi_set_smart_mode_cfg(char *ssid,
                            int beacon_period,
                            wifi_chan_list_param_set_t *chan_list,
                            uint8_t *smc_start_addr,
                            uint8_t *smc_end_addr,
                            uint16_t filter_type,
                            int smc_frame_filter_len,
                            uint8_t *smc_frame_filter,
                            int custom_ie_len,
                            uint8_t *custom_ie);
void wifi_uap_set_beacon_period(const t_u16 beacon_period);
wifi_sub_band_set_t *get_sub_band_from_country(int country, int *nr_sb);
int wifi_set_mgmt_ie(unsigned int bss_type, IEEEtypes_ElementId_t index, void *buf, unsigned int buf_len);
int wifi_clear_mgmt_ie(unsigned int bss_type, IEEEtypes_ElementId_t index);
int wifi_send_enable_supplicant(int mode, const char *ssid);
int wifi_send_clear_wpa_psk(int mode, const char *ssid);
int wifi_send_add_wpa_psk(int mode, char *ssid, char *passphrase, unsigned int len);
int wifi_send_add_wpa3_password(int mode, char *ssid, char *password, unsigned int len);
int wifi_send_add_wpa_pmk(int mode, char *bssid, char *ssid, char *pmk, unsigned int len);
bool wifi_11d_is_channel_allowed(int channel);
#endif /* __MLAN_API_H__ */
