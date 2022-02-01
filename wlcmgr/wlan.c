/** @file wlan.c
 *
 *  @brief  This file provides Core WLAN definition
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

#include <string.h>
#include <wm_utils.h>
#include <wlan.h>
#include <wifi.h>
#include <wm_os.h>
#include <wm_net.h>
#include <wifi-debug.h>
#ifdef CONFIG_WMSTATS
#include <wmstats.h>
#endif /* CONFIG_WMSTATS */
#include <stdint.h>
#include <mlan_sdio_api.h>
#ifdef CONFIG_HOST_PMK
#include <wm_mbedtls_helper_api.h>
#include <mbedtls/x509_crt.h>
#endif /* CONFIG_HOST_PMK */
#ifdef OVERRIDE_CALIBRATION_DATA
#include OVERRIDE_CALIBRATION_DATA
#endif
#include <fsl_common.h>

#define DELAYED_SLP_CFM_DUR 10U
#define BAD_MIC_TIMEOUT     (60 * 1000)

#define WL_ID_CONNECT      "wifi_connect"
#define WL_ID_DEEPSLEEP_SM "wlcm_deepsleep_sm"
#define WL_ID_WIFI_RSSI    "wifi_rssi"

bool g_req_sl_confirm;
static bool wlan_uap_scan_chan_list_set;

int wlan_set_wwsm_txpwrlimit(void);
static bool wlan_is_ieeeps_active(void);
static int ps_wakeup_card_cb(os_rw_lock_t *lock, unsigned int wait_time);

#ifdef CONFIG_WPA2_ENTP
extern int wpa2_ent_connect(struct wlan_network *wpa2_network);
extern void wpa2_shutdown();
#endif

#ifdef CONFIG_WMSTATS
struct wm_stats g_wm_stats;
#endif /* CONFIG_WMSTATS */
os_rw_lock_t ps_rwlock;

#ifdef CONFIG_WPS2
int wps_session_attempt;
#endif

#define MAX_EVENTS 20
#define CONNECTION_EVENT(r, data) \
    if (wlan.cb != NULL)          \
    {                             \
        (void)wlan.cb(r, data);   \
    }

bool ps_sleep_cb_sent;
enum user_request_type
{
    /* we append our user-generated events to the wifi interface events and
     * handle them accordingly */
    CM_STA_USER_REQUEST_CONNECT = WIFI_EVENT_LAST + 1,
    CM_STA_USER_REQUEST_DISCONNECT,
    CM_STA_USER_REQUEST_SCAN,
    CM_STA_USER_REQUEST_PS_ENTER,
    CM_STA_USER_REQUEST_PS_EXIT,
    CM_STA_USER_REQUEST_LAST,
    /* All the STA related request are above and uAP related requests are
       below */
    CM_UAP_USER_REQUEST_START,
    CM_UAP_USER_REQUEST_STOP,
    CM_UAP_USER_REQUEST_PS_ENTER,
    CM_UAP_USER_REQUEST_PS_EXIT,
    CM_UAP_USER_REQUEST_LAST,
    CM_WLAN_USER_REQUEST_DEINIT
};

enum cm_sta_state
{
    CM_STA_INITIALIZING = 0,
    CM_STA_IDLE,
    CM_STA_SCANNING,
    CM_STA_SCANNING_USER,
    CM_STA_ASSOCIATING,
    CM_STA_ASSOCIATED,
    CM_STA_REQUESTING_ADDRESS,
    CM_STA_OBTAINING_ADDRESS,
    CM_STA_CONNECTED,
    CM_STA_DEEP_SLEEP,
};

enum cm_uap_state
{
    CM_UAP_INITIALIZING = 0,
    CM_UAP_CONFIGURED,
    CM_UAP_STARTED,
    CM_UAP_IP_UP,
};

#define WL_ID_WIFI_AWAKE_IEEEPS "wifi_awake_from_ieeeps"

enum wlan_ieeeps_event
{
    IEEEPS_EVENT_ENTER,
    IEEEPS_EVENT_ENABLE,
    IEEEPS_EVENT_ENABLE_DONE,
    IEEEPS_EVENT_AWAKE,
    IEEEPS_EVENT_SLEEP,
    IEEEPS_EVENT_SLP_CFM,
    IEEEPS_EVENT_DISABLE,
    IEEEPS_EVENT_DISABLE_DONE,

};

enum wlan_ieeeps_state
{
    IEEEPS_INIT,
    IEEEPS_CONFIGURING,
    IEEEPS_AWAKE,
    IEEEPS_PRE_SLEEP,
    IEEEPS_SLEEP,
    IEEEPS_PRE_DISABLE,
    IEEEPS_DISABLING
};

enum wlan_deepsleepps_state
{
    DEEPSLEEPPS_INIT,
    DEEPSLEEPPS_CONFIGURING,
    DEEPSLEEPPS_AWAKE,
    DEEPSLEEPPS_PRE_SLEEP,
    DEEPSLEEPPS_SLEEP,
    DEEPSLEEPPS_PRE_DISABLE,
    DEEPSLEEPPS_DISABLING
};

enum wlan_deepsleepps_event
{
    DEEPSLEEPPS_EVENT_ENTER,
    DEEPSLEEPPS_EVENT_ENABLE,
    DEEPSLEEPPS_EVENT_ENABLE_DONE,
    DEEPSLEEPPS_EVENT_AWAKE,
    DEEPSLEEPPS_EVENT_SLEEP,
    DEEPSLEEPPS_EVENT_SLP_CFM,
    DEEPSLEEPPS_EVENT_DISABLE,
    DEEPSLEEPPS_EVENT_DISABLE_DONE,
};

static struct wifi_scan_params_t g_wifi_scan_params = {NULL,
                                                       NULL,
                                                       {
                                                           0,
                                                       },
                                                       BSS_ANY,
                                                       60,
                                                       153};

static os_queue_pool_define(g_wlan_event_queue_data, sizeof(struct wifi_message) * MAX_EVENTS);
#ifdef CONFIG_WPA2_ENTP
static os_thread_stack_define(g_cm_stack, 4096);
#else
static os_thread_stack_define(g_cm_stack, 4096);
#endif

typedef enum
{
    WLCMGR_INACTIVE,
    WLCMGR_INIT_DONE,
    WLCMGR_ACTIVATED,
    WLCMGR_THREAD_STOPPED,
    WLCMGR_THREAD_DELETED,
} wlcmgr_status_t;

static struct
{
    /* This lock enables the scan response data to be accessed by multiple
     * threads with the expectation that any thread accessing the scan lock may
     * have to sleep until it is available.  The lock is taken by calling
     * wlan_scan() and it is released by the WLAN Connection Manager main
     * thread when the scan response data has been handled and
     * is therefore free for another user.  This lock must never be taken
     * in the WLAN Connection Manager main thread and it must only be
     * released by that thread. The lock count must be 0 or 1. */
    os_semaphore_t scan_lock;
    bool is_scan_lock;

    /* The WLAN Connection Manager event queue receives events (command
     * responses, WiFi events, TCP stack events) from the wifi interface as
     * well as user requests (connect, disconnect, scan).  This is the main
     * blocking point for the main thread and acts as the state machine tick.*/
    os_queue_t events;
    os_queue_pool_t events_queue_data;

    /* internal state */
    enum cm_sta_state sta_state, sta_ipv4_state;
#ifdef CONFIG_IPV6
    enum cm_sta_state sta_ipv6_state;
#endif
    enum cm_sta_state sta_return_to;
    enum cm_uap_state uap_state;
    enum cm_uap_state uap_return_to;

    uint8_t mac[MLAN_MAC_ADDR_LENGTH];
#ifdef CONFIG_P2P
    uint8_t wfd_mac[MLAN_MAC_ADDR_LENGTH];
#endif
    /* callbacks */
    int (*cb)(enum wlan_event_reason reason, void *data);
    int (*scan_cb)(unsigned int count);
    void (*event_cb)(int type);

    /* known networks list */
    struct wlan_network networks[WLAN_MAX_KNOWN_NETWORKS];
    unsigned int cur_network_idx;
    unsigned int cur_uap_network_idx;

    unsigned int num_networks;
    unsigned int scan_count;

    unsigned int uap_supported_max_sta_num;

    /* CM thread */
    os_thread_t cm_main_thread;
    os_thread_stack_t cm_stack;
    unsigned running : 1;
    unsigned stop_request : 1;
    wlcmgr_status_t status;

    /*
     * Power save state configuration
     * These are states corresponding to the network that we are currently
     * connected to. Not relevant, when we are not connected.
     */
    enum wlan_ps_state cm_ps_state;
    enum wlan_ieeeps_state ieeeps_state;
    enum wlan_ieeeps_state ieeeps_prev_state;
    enum wlan_deepsleepps_state deepsleepps_state;
    bool skip_ds_exit_cb : 1;
    bool cm_ieeeps_configured : 1;
    bool cm_deepsleepps_configured : 1;
    bool connect_wakelock_taken : 1;
    unsigned int wakeup_conditions;
    wifi_fw_version_ext_t fw_ver_ext;

#ifdef CONFIG_WLAN_FAST_PATH
    /* Data structures for fast path connection */
    bool auth_cache_valid : 1;
    bool fast_path_cache_valid : 1;
    uint8_t fast_path_bss[MLAN_MAC_ADDR_LENGTH];
    unsigned int fp_network;
#endif /* CONFIG_WLAN_FAST_PATH */
    int uap_rsn_ie_index;
    bool smart_mode_active : 1;
    os_timer_t assoc_timer;
    bool assoc_paused : 1;
    bool pending_assoc_request : 1;
    bool reassoc_control : 1;
    bool reassoc_request : 1;
    unsigned int reassoc_count;
    bool hs_configured;
    unsigned int hs_wakeup_condition;
    wifi_scan_chan_list_t scan_chan_list;
#ifdef CONFIG_WPA2_ENTP
    bool allow_wpa2_enterprise_ap_only : 1;
#endif
    bool hidden_scan_on : 1;
#ifdef CONFIG_WIFI_FW_DEBUG
    void (*wlan_usb_init_cb)(void);
#endif
} wlan;

void wlan_wake_up_card(void);
#ifdef CONFIG_WLCMGR_DEBUG
static char *dbg_sta_state_name(enum cm_sta_state state)
{
    switch (state)
    {
        case CM_STA_INITIALIZING:
            return "initializing";
        case CM_STA_IDLE:
            return "idle";
        case CM_STA_SCANNING:
            return "scanning";
        case CM_STA_SCANNING_USER:
            return "user scanning";
        case CM_STA_ASSOCIATING:
            return "associating";
        case CM_STA_ASSOCIATED:
            return "associated";
        case CM_STA_REQUESTING_ADDRESS:
            return "requesting address";
        case CM_STA_OBTAINING_ADDRESS:
            return "obtaining address";
        case CM_STA_CONNECTED:
            return "connected";
        case CM_STA_DEEP_SLEEP:
            return "deep sleep";
        default:
            return "unknown";
    }
}

static char *dbg_uap_state_name(enum cm_uap_state state)
{
    switch (state)
    {
        case CM_UAP_INITIALIZING:
            return "initializing";
        case CM_UAP_CONFIGURED:
            return "configured";
        case CM_UAP_STARTED:
            return "started";
        case CM_UAP_IP_UP:
            return "IP configured";
        default:
            return "unknown";
    }
}

static void dbg_lock_info(void)
{
#if 0
	int ret;
	char *name;
	unsigned long cur_val, suspended_count;
	TX_THREAD *first_suspended;
	TX_SEMAPHORE *next;

	ret = tx_semaphore_info_get(&wlan.scan_lock, &name, &cur_val,
				    &first_suspended, &suspended_count, &next);
	if (ret) {
		wlcm_e("unable to fetch scan lock info");
		return;
	}

	wlcm_d("scan lock info: count=%ld, suspended=%ld", cur_val,
	       suspended_count);
#endif
}
#else
#define dbg_lock_info(...)
#define dbg_sta_state_name(...)
#define dbg_uap_state_name(...)
#endif /* CONFIG_WLCMGR_DEBUG */

/*
 * Utility Functions
 */

int verify_scan_duration_value(int scan_duration)
{
    if (scan_duration >= 50 && scan_duration <= 500)
    {
        return WM_SUCCESS;
    }
    return -WM_FAIL;
}

int verify_scan_channel_value(int channel)
{
    if (channel >= 0 && channel <= 11)
    {
        return WM_SUCCESS;
    }
    return -WM_FAIL;
}

int verify_split_scan_delay(int delay)
{
    if (delay >= 30 && delay <= 300)
    {
        return WM_SUCCESS;
    }
    return -WM_FAIL;
}

int set_scan_params(struct wifi_scan_params_t *wifi_scan_params)
{
    if (!verify_scan_duration_value(wifi_scan_params->scan_duration))
    {
        g_wifi_scan_params.scan_duration = wifi_scan_params->scan_duration;
    }
    if (!verify_scan_channel_value(wifi_scan_params->channel[0]))
    {
        g_wifi_scan_params.channel[0] = wifi_scan_params->channel[0];
    }
    if (!verify_split_scan_delay(wifi_scan_params->split_scan_delay))
    {
        g_wifi_scan_params.split_scan_delay = wifi_scan_params->split_scan_delay;
    }
    return WM_SUCCESS;
}

int get_scan_params(struct wifi_scan_params_t *wifi_scan_params)
{
    wifi_scan_params->scan_duration    = g_wifi_scan_params.scan_duration;
    wifi_scan_params->channel[0]       = g_wifi_scan_params.channel[0];
    wifi_scan_params->split_scan_delay = g_wifi_scan_params.split_scan_delay;
    return WM_SUCCESS;
}

static uint32_t wlan_map_to_wifi_wakeup_condtions(const uint32_t wlan_wakeup_condtions)
{
    uint32_t conditions = 0;
    if ((wlan_wakeup_condtions & WAKE_ON_UNICAST) != 0U)
    {
        conditions |= WIFI_WAKE_ON_UNICAST;
    }

    if ((wlan_wakeup_condtions & WAKE_ON_ALL_BROADCAST) != 0U)
    {
        conditions |= WIFI_WAKE_ON_ALL_BROADCAST;
    }

    if ((wlan_wakeup_condtions & WAKE_ON_MULTICAST) != 0U)
    {
        conditions |= WIFI_WAKE_ON_MULTICAST;
    }

    if ((wlan_wakeup_condtions & WAKE_ON_ARP_BROADCAST) != 0U)
    {
        conditions |= WIFI_WAKE_ON_ARP_BROADCAST;
    }

    if ((wlan_wakeup_condtions & WAKE_ON_MAC_EVENT) != 0U)
    {
        conditions |= WIFI_WAKE_ON_MAC_EVENT;
    }

    if ((wlan_wakeup_condtions & WAKE_ON_MGMT_FRAME) != 0U)
    {
        conditions |= WIFI_WAKE_ON_MGMT_FRAME;
    }

    return conditions;
}

int wlan_get_ipv4_addr(unsigned int *ipv4_addr)
{
    struct wlan_network network;
    int ret;
    if (is_uap_started() != 0)
    {
        ret = wlan_get_current_uap_network(&network);
    }
    else
    {
        ret = wlan_get_current_network(&network);
    }
    if (ret != WM_SUCCESS)
    {
        wlcm_e("cannot get network info");
        *ipv4_addr = 0;
        return -WM_FAIL;
    }
    *ipv4_addr = network.ip.ipv4.address;
    return ret;
}

static int is_user_scanning(void)
{
    return (wlan.sta_state == CM_STA_SCANNING_USER);
}

static bool is_state(enum cm_sta_state state)
{
    if (is_user_scanning() != 0)
    {
        return (wlan.sta_return_to == state);
    }

    return (wlan.sta_state == state);
}

int wlan_send_host_sleep(uint32_t wakeup_condition)
{
    int ret;
    unsigned int ipv4_addr;
    enum wlan_bss_type type = WLAN_BSS_TYPE_STA;

    if (wlan.hs_configured == MTRUE)
    {
        if (wakeup_condition == HOST_SLEEP_CFG_CANCEL)
        {
            wlan.hs_configured       = MFALSE;
            wlan.hs_wakeup_condition = wakeup_condition;
        }
        else if (wlan.hs_wakeup_condition != wlan_map_to_wifi_wakeup_condtions(wakeup_condition))
        {
            wlcm_d("Cancel previous confiuration to configure new configuration\r\n");
            /* already configured */
            return -WM_FAIL;
        }
    }
    else
    {
        wlan.hs_configured       = MTRUE;
        wlan.hs_wakeup_condition = wlan_map_to_wifi_wakeup_condtions(wakeup_condition);
    }
    ret = wlan_get_ipv4_addr(&ipv4_addr);
    if (ret != WM_SUCCESS)
    {
        wlcm_e("HS: cannot get IP");
        return -WM_FAIL;
    }
    /* If uap interface is up
     * configure host sleep for uap interface
     * else confiugre host sleep for station
     * interface.
     */
    if (is_uap_started() != 0)
    {
        type = WLAN_BSS_TYPE_UAP;
    }

    return wifi_send_hs_cfg_cmd((mlan_bss_type)type, ipv4_addr, HS_CONFIGURE, wlan.hs_wakeup_condition);
}

static void wlan_host_sleep_and_sleep_confirm(void)
{
    int ret                 = WM_SUCCESS;
    enum wlan_bss_type type = WLAN_BSS_TYPE_STA;

    if (wifi_get_xfer_pending())
    {
        g_req_sl_confirm = 1;
        return;
    }
    ret = os_rwlock_write_lock(&ps_rwlock, OS_NO_WAIT);
    if (ret != WM_SUCCESS)
    {
        /* Couldn't get the semaphore, someone has already taken
         * it. */
        g_req_sl_confirm = 1;
        return;
    }
    if (wlan.hs_configured)
    {
        ret = wlan_send_host_sleep(wlan.hs_wakeup_condition);
        if ((ret != WM_SUCCESS) || (!(is_uap_started()) && !(is_state(CM_STA_CONNECTED))))
        {
            g_req_sl_confirm = 1;
            os_rwlock_write_unlock(&ps_rwlock);
            return;
        }
    }
    /* tbdel */
    wlan.cm_ps_state = PS_STATE_SLEEP_CFM;

    // if (is_uap_started())
    //	type = WLAN_BSS_TYPE_UAP;

    send_sleep_confirm_command((mlan_bss_type)type);

    g_req_sl_confirm = 0;
}

static void wlan_send_sleep_confirm(void)
{
    enum wlan_bss_type type = WLAN_BSS_TYPE_STA;

    if (is_uap_started() != 0)
    {
        type = WLAN_BSS_TYPE_UAP;
    }

    wlan.cm_ps_state = PS_STATE_SLEEP_CFM;
    send_sleep_confirm_command((mlan_bss_type)type);
}

static void wlan_ieeeps_sm(enum wlan_ieeeps_event event)
{
    enum wlan_ieeeps_state next_state;
    enum wlan_ieeeps_state prev_state;
begin:
    next_state = wlan.ieeeps_state;
    prev_state = wlan.ieeeps_prev_state;
    wlcm_d("IEEE PS Event : %d", event);

    switch (wlan.ieeeps_state)
    {
        case IEEEPS_INIT:
            if (event == IEEEPS_EVENT_ENABLE)
            {
                (void)wifi_enter_ieee_power_save();
            }

            if (event == IEEEPS_EVENT_ENABLE_DONE)
            {
                next_state = IEEEPS_CONFIGURING;
            }

            break;
        case IEEEPS_CONFIGURING:
            if (event == IEEEPS_EVENT_AWAKE)
            {
                (void)os_rwlock_write_lock(&ps_rwlock, OS_WAIT_FOREVER);
                next_state = IEEEPS_AWAKE;
            }
            if (event == IEEEPS_EVENT_SLEEP)
            {
                next_state = IEEEPS_PRE_SLEEP;
                // wakelock_get(WL_ID_WIFI_AWAKE_IEEEPS);
            }
            if (event == IEEEPS_EVENT_DISABLE)
            {
                next_state = IEEEPS_DISABLING;
            }

            break;
        case IEEEPS_AWAKE:
            if (event == IEEEPS_EVENT_ENTER)
            {
                // wakelock_get(WL_ID_WIFI_AWAKE_IEEEPS);
                os_rwlock_write_unlock(&ps_rwlock);
                wlan.cm_ps_state = PS_STATE_AWAKE;
            }

            if (event == IEEEPS_EVENT_SLEEP)
            {
                next_state = IEEEPS_PRE_SLEEP;
            }

            if (event == IEEEPS_EVENT_DISABLE)
            {
                // wakelock_put(WL_ID_WIFI_AWAKE_IEEEPS);
                next_state = IEEEPS_DISABLING;
            }

            break;
        case IEEEPS_PRE_SLEEP:
            if (event == IEEEPS_EVENT_ENTER)
            {
                wlan_host_sleep_and_sleep_confirm();
            }

            if (event == IEEEPS_EVENT_SLEEP)
            {
                wlan_host_sleep_and_sleep_confirm();
            }

            if (event == IEEEPS_EVENT_SLP_CFM)
            {
                next_state = IEEEPS_SLEEP;
            }

            if (event == IEEEPS_EVENT_DISABLE)
            {
                g_req_sl_confirm = 0;
                next_state       = IEEEPS_DISABLING;
                os_rwlock_write_unlock(&ps_rwlock);
                // wakelock_put(WL_ID_WIFI_AWAKE_IEEEPS);
                wlan_wake_up_card();
            }
            break;
        case IEEEPS_SLEEP:
            if (event == IEEEPS_EVENT_ENTER)
            {
                g_req_sl_confirm = 0;
                // wakelock_put(WL_ID_WIFI_AWAKE_IEEEPS);
            }

            if (event == IEEEPS_EVENT_AWAKE)
            {
                next_state = IEEEPS_AWAKE;
            }

            if (event == IEEEPS_EVENT_SLEEP)
            {
                /* We already sent the sleep confirm but it appears that
                 * the firmware is still up */
                // wakelock_get(WL_ID_WIFI_AWAKE_IEEEPS);
                os_rwlock_write_unlock(&ps_rwlock);
                next_state = IEEEPS_PRE_SLEEP;
            }

            if (event == IEEEPS_EVENT_DISABLE)
            {
                if (is_state(CM_STA_CONNECTED))
                {
                    next_state = IEEEPS_PRE_DISABLE;
                }
                else
                {
                    next_state = IEEEPS_DISABLING;
                }
                os_rwlock_write_unlock(&ps_rwlock);
            }
            break;
        case IEEEPS_PRE_DISABLE:
            if (event == IEEEPS_EVENT_ENTER)
            {
                wlan_wake_up_card();
            }

            if (event == IEEEPS_EVENT_AWAKE)
            {
                next_state = IEEEPS_DISABLING;
            }

            break;
        case IEEEPS_DISABLING:
            if ((prev_state == IEEEPS_CONFIGURING || prev_state == IEEEPS_AWAKE || prev_state == IEEEPS_SLEEP ||
                 prev_state == IEEEPS_PRE_DISABLE) &&
                (event == IEEEPS_EVENT_ENTER))
            {
                (void)wifi_exit_ieee_power_save();
            }

            if (prev_state == IEEEPS_PRE_SLEEP && event == IEEEPS_EVENT_AWAKE)
            {
                (void)wifi_exit_ieee_power_save();
            }

            if (event == IEEEPS_EVENT_DISABLE_DONE)
            {
                next_state = IEEEPS_INIT;
            }

            break;

    } /* end of switch  */

    /* state change detected
     * call the same function with event ENTER*/
    if (wlan.ieeeps_state != next_state)
    {
        wlcm_d("IEEE PS: %d ---> %d", wlan.ieeeps_state, next_state);

        wlan.ieeeps_prev_state = wlan.ieeeps_state;
        wlan.ieeeps_state      = next_state;
        event                  = IEEEPS_EVENT_ENTER;
        goto begin;
    }
}

static void wlan_deepsleepps_sm(enum wlan_deepsleepps_event event)
{
    enum wlan_deepsleepps_state next_state;

begin:
    next_state = wlan.deepsleepps_state;
    wlcm_d("Deep Sleep Event : %d", event);

    switch (wlan.deepsleepps_state)
    {
        case DEEPSLEEPPS_INIT:
            if (event == DEEPSLEEPPS_EVENT_ENABLE)
            {
                // wakelock_get(WL_ID_DEEPSLEEP_SM);
                (void)wifi_enter_deepsleep_power_save();
            }
            if (event == DEEPSLEEPPS_EVENT_ENABLE_DONE)
            {
                next_state = DEEPSLEEPPS_CONFIGURING;
            }
            break;
        case DEEPSLEEPPS_CONFIGURING:
            if (event == DEEPSLEEPPS_EVENT_SLEEP)
            {
                next_state = DEEPSLEEPPS_PRE_SLEEP;
            }

            break;
        case DEEPSLEEPPS_AWAKE:
            if (event == DEEPSLEEPPS_EVENT_ENTER)
            {
                wlan.cm_ps_state = PS_STATE_AWAKE;
            }

            if (event == DEEPSLEEPPS_EVENT_SLEEP)
            {
                next_state = DEEPSLEEPPS_PRE_SLEEP;
            }
            break;
        case DEEPSLEEPPS_PRE_SLEEP:
            if (event == DEEPSLEEPPS_EVENT_ENTER)
            {
                wlan_send_sleep_confirm();
            }

            if (event == DEEPSLEEPPS_EVENT_SLP_CFM)
            {
                // wakelock_put(WL_ID_DEEPSLEEP_SM);
                next_state = DEEPSLEEPPS_SLEEP;
            }
            break;
        case DEEPSLEEPPS_SLEEP:
            if (event == DEEPSLEEPPS_EVENT_AWAKE)
            {
                next_state = DEEPSLEEPPS_AWAKE;
            }

            if (event == DEEPSLEEPPS_EVENT_DISABLE)
            {
                next_state = DEEPSLEEPPS_PRE_DISABLE;
            }

            break;
        case DEEPSLEEPPS_PRE_DISABLE:
            if (event == DEEPSLEEPPS_EVENT_ENTER)
            {
                // wakelock_get(WL_ID_DEEPSLEEP_SM);
                wlan_wake_up_card();
            }

            if (event == DEEPSLEEPPS_EVENT_AWAKE)
            {
                next_state = DEEPSLEEPPS_DISABLING;
            }

            break;
        case DEEPSLEEPPS_DISABLING:
            if (event == DEEPSLEEPPS_EVENT_ENTER)
            {
                (void)wifi_exit_deepsleep_power_save();
            }

            if (event == DEEPSLEEPPS_EVENT_DISABLE_DONE)
            {
                // wakelock_put(WL_ID_DEEPSLEEP_SM);
                next_state = DEEPSLEEPPS_INIT;
            }

            break;

    } /* end of switch  */

    /* state change detected
     * call the same function with event ENTER*/
    if (wlan.deepsleepps_state != next_state)
    {
        wlcm_d("Deep Sleep: %d ---> %d", wlan.deepsleepps_state, next_state);
        wlan.deepsleepps_state = next_state;
        event                  = DEEPSLEEPPS_EVENT_ENTER;
        goto begin;
    }
}

static int is_bssid_any(char *b)
{
    return (!b[0] && !b[1] && !b[2] && !b[3] && !b[4] && !b[5]);
}

/* Check to see if the security features of our network, 'config', match with
 * those of a scan result, 'res' and return 1 if they do, 0 if they do not. */
static int security_profile_matches(const struct wlan_network *network, const struct wifi_scan_result *res)
{
    const struct wlan_network_security *config = &network->security;

    /* No security: just check that the scan result doesn't specify security */
    if (config->type == WLAN_SECURITY_NONE)
    {
#ifdef CONFIG_WPS2
        if (res->wps_session != WPS_SESSION_INACTIVE)
            return 1;
#endif
#ifdef CONFIG_OWE
        if (res->trans_mode == OWE_TRANS_MODE_OPEN)
        {
            return res->trans_ssid_len;
        }
        else if (res->trans_mode == OWE_TRANS_MODE_OWE)
        {
            return res->WPA_WPA2_WEP.wpa2;
        }
        else
        { /* Do Nothing */
        }
#endif

        if (res->WPA_WPA2_WEP.wepStatic || res->WPA_WPA2_WEP.wpa2 || res->WPA_WPA2_WEP.wpa)
        {
            return WM_SUCCESS;
        }

        return 1;
    }

    /* WEP mode: if we are using WEP, the AP must use static WEP */
    if (config->type == WLAN_SECURITY_WEP_OPEN || config->type == WLAN_SECURITY_WEP_SHARED)
    {
        if (res->phtcap_ie_present)
        {
            wlcm_e(
                "As per Wi-Fi Certification WEP "
                "is not used with HT associations "
                "in 11n devices");
            return 0;
        }
        return res->WPA_WPA2_WEP.wepStatic;
    }

    /* WPA/WPA2 mode: if we are using WPA/WPA2, the AP must use WPA/WPA2 */
    if (config->type == WLAN_SECURITY_WPA_WPA2_MIXED)
    {
        return res->WPA_WPA2_WEP.wpa | res->WPA_WPA2_WEP.wpa2;
    }

    /* WPA2 mode: if we are using WPA2, the AP must use WPA2 */
    if (config->type == WLAN_SECURITY_WPA2
#ifdef CONFIG_OWE
        || config->type == WLAN_SECURITY_OWE_ONLY
#endif
    )
    {
        return res->WPA_WPA2_WEP.wpa2;
    }

    /* WPA mode: if we are using WPA, the AP must use WPA */
    if (config->type == WLAN_SECURITY_WPA)
    {
        if (res->wpa_ucstCipher.tkip != 0U)
        {
            wlcm_e(
                "As per Wi-Fi Certification security "
                "combinations \"WPA\" alone is not allowed "
                "security type.");
            wlcm_e(
                "Please use WLAN_SECURITY_WPA_WPA2_MIXED "
                "security type to connect to "
                "WPA(TKIP) Only AP.");
            return !res->wpa_ucstCipher.tkip;
        }
        return res->WPA_WPA2_WEP.wpa;
    }

#ifdef CONFIG_WPA2_ENTP
    /* WPA2 Enterprise mode: if we are using WPA2 Enterprise,
     * the AP must use WPA2 Enterpise */
    if (config->type == WLAN_SECURITY_EAP_TLS || config->type == WLAN_SECURITY_PEAP_MSCHAPV2)
        return res->wpa2_entp_IE_exist;
#endif

    if (config->type == WLAN_SECURITY_WPA3_SAE)
    {
        uint8_t mfpc, mfpr;

        (void)wlan_get_pmfcfg(&mfpc, &mfpr);

        if (!mfpc && !mfpr)
        {
            wlcm_e("As per WPA3 SAE Certification, PMF is mandatory.\r\n");
            return WM_SUCCESS;
        }
        return res->WPA_WPA2_WEP.wpa3_sae | res->WPA_WPA2_WEP.wpa2;
    }
    return WM_SUCCESS;
}

/* Check if 'network' matches the scan result 'res' based on network properties
 * and the security profile.  If we found a match, update 'network' with any
 * new information discovered when parsing 'res'. 192 We may update the channel,
 * BSSID, or SSID but not the security profile. */
static int network_matches_scan_result(const struct wlan_network *network,
                                       const struct wifi_scan_result *res,
                                       uint8_t *num_channels,
                                       wlan_scan_channel_list_t *chan_list)
{
    uint8_t null_ssid[IEEEtypes_SSID_SIZE] = {0};

    /* Check basic network information that we know */
    if (network->channel_specific && network->channel != res->Channel)
    {
        wlcm_d("%s: Channel mismatch. Got: %d Expected: %d", network->ssid, res->Channel, network->channel);
        return WM_SUCCESS;
    }
    if (network->bssid_specific && memcmp(network->bssid, res->bssid, 6))
    {
        wlcm_d("%s: bssid mismatch.", network->ssid);
        return WM_SUCCESS;
    }

    if (network->ssid_specific != 0U)
    {
        if (!wlan.hidden_scan_on && (!memcmp(null_ssid, (char *)res->ssid, res->ssid_len)))
        {
            chan_list[*num_channels].chan_number = res->Channel;
            chan_list[*num_channels].scan_type   = 1;
            chan_list[*num_channels].scan_time   = 150;
            (*num_channels)++;
        }
        if ((!res->ssid_len) || (memcmp(network->ssid, (char *)res->ssid, res->ssid_len))
#ifdef CONFIG_OWE
            ||
            ((res->trans_mode == OWE_TRANS_MODE_OWE) && (memcmp(network->trans_ssid, (char *)res->ssid, res->ssid_len)))
#endif
#ifdef CONFIG_WLAN_BRIDGE
            || (memcmp(network->bridge_ssid, (char *)res->ssid, res->ssid_len))
#endif
        )
        {
            wlcm_d("ssid mismatch: Got: %s Expected: %s", (char *)res->ssid, network->ssid);
            return WM_SUCCESS;
        }
    }

    /* In case of CONFIG_WD_EXTERAL we don't parse and
       store the security profile.
       Instead the respective IE are stored in network struct as is */
    /* Check security information */
    if (network->security_specific != 0U)
    {
        if (!security_profile_matches(network, res))
        {
            wlcm_d("%s: security profile mismatch", network->ssid);
            return WM_SUCCESS;
        }
    }

    if (!(res->WPA_WPA2_WEP.wepStatic || res->WPA_WPA2_WEP.wpa2 || res->WPA_WPA2_WEP.wpa) && network->security.psk_len)
    {
        wlcm_d("%s: security profile mismatch", network->ssid);
        return WM_SUCCESS;
    }

    if (!wifi_11d_is_channel_allowed(res->Channel))
    {
        wlcm_d("%d: Channel not allowed.", res->Channel);
        return WM_SUCCESS;
    }

#ifdef CONFIG_OWE
    wlcm_d("%s: Match successful", res->trans_mode == OWE_TRANS_MODE_OWE ? network->trans_ssid : network->ssid);
#endif
    return 1;
}

#ifdef CONFIG_WPA2_ENTP
static int wpa2_tls_init(struct wlan_network *network)
{
    network->security.wlan_ctx =
        wm_mbedtls_ssl_config_new(&network->security.tls_cert, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_VERIFY_NONE);

    if (!network->security.wlan_ctx)
    {
        wlcm_e("TLS session init failed (ctx failed)");
        return -WM_FAIL;
    }

    network->security.wlan_ssl = wm_mbedtls_ssl_new(network->security.wlan_ctx, 0, NULL);

    if (!network->security.wlan_ssl)
    {
        wlcm_e("TLS session init failed (ssl failed)");
        wm_mbedtls_ssl_config_free(network->security.wlan_ctx);
        network->security.wlan_ctx = NULL;
        return -WM_FAIL;
    }

    /* Disable SSL application data splitting as FreeRADIUS fails to
     * process splitted data
     */
    mbedtls_ssl_conf_cbc_record_splitting(network->security.wlan_ctx, MBEDTLS_SSL_CBC_RECORD_SPLITTING_DISABLED);

    return WM_SUCCESS;
}

static void wpa2_tls_cleanup(struct wlan_network *network, bool force)
{
    if (force)
    {
        if (network->security.wlan_ssl)
        {
            wm_mbedtls_ssl_free(network->security.wlan_ssl);
            network->security.wlan_ssl = NULL;
            if (network->security.wlan_ctx)
            {
                wm_mbedtls_ssl_config_free(network->security.wlan_ctx);
                network->security.wlan_ctx = NULL;
            }
        }
    }

    wpa2_shutdown();
}
#endif

static void wlcm_request_reconnect(enum cm_sta_state *next, struct wlan_network *network);
int load_wep_key(const uint8_t *input, uint8_t *output, uint8_t *output_len, const unsigned max_output_len);

/* Configure the firmware and PSK Supplicant for the security settings
 * specified in 'network'.  For WPA and WPA2 networks, we must chose between
 * the older TKIP cipher or the newer CCMP cipher.  We prefer CCMP, however we
 * will chose TKIP if the AP doesn't report CCMP support.  CCMP is optional for
 * WPA and required for WPA2, however a WPA2 AP may still have it disabled. */
static int configure_security(struct wlan_network *network, struct wifi_scan_result *res)
{
    int ret = WM_SUCCESS;
    switch (network->security.type)
    {
#ifdef CONFIG_WPA2_ENTP
        case WLAN_SECURITY_EAP_TLS:
        case WLAN_SECURITY_PEAP_MSCHAPV2:
            wps_session_attempt = 1;
            ret                 = wifi_send_enable_supplicant(network->role, network->ssid);
            if (ret != WM_SUCCESS)
                return -WM_FAIL;

            ret = wpa2_tls_init(network);
            if (ret != WM_SUCCESS)
                return -WM_FAIL;

            break;
#endif
        case WLAN_SECURITY_WPA:
        case WLAN_SECURITY_WPA2:
        case WLAN_SECURITY_WPA_WPA2_MIXED:
#ifdef CONFIG_WPS2
            wps_session_attempt = 0;
#endif
            if (network->security.type == WLAN_SECURITY_WPA)
            {
                wlcm_d("configuring WPA security");
            }
            else if (network->security.type == WLAN_SECURITY_WPA2)
            {
                wlcm_d("configuring WPA2 security");
            }
            else
            {
                wlcm_d("configuring WPA/WPA2 Mixed security");
            }

            /* the handler for the "add PSK" command calls supplicantEnable() so we
             * don't do it here
             *
             * TODO: at this time, the firmware will not generate a specific
             * response to the command sent by wifi_add_wpa_psk().  The
             * command+response sequence should be worked into the WLAN Connection
             * Manager once this is fixed.
             *
             * TODO: at this time, the PSK Supplicant caches passphrases on the
             * SSID however this won't work for networks with a hidden SSID.  The
             * WLAN Connection manager will need to be updated once that's
             * resolved. */
            if (network->security.pmk_valid)
            {
                wlcm_d("adding SSID and PMK to supplicant cache");

                /* Do not pass BSSID here as embedded supplicant fails
                 * to derive session keys
                 */
                ret = wifi_send_add_wpa_pmk(network->role, network->ssid, NULL, network->security.pmk, WLAN_PMK_LENGTH);
            }
            else
            {
                wlcm_d("adding SSID and PSK to supplicant cache");
                ret = wifi_send_add_wpa_psk(network->role, network->ssid, network->security.psk,
                                            network->security.psk_len);
            }

            if (ret != WM_SUCCESS)
            {
                return -WM_FAIL;
            }
#ifdef CONFIG_WLAN_BRIDGE
            if (network->bridge_ssid)
            {
                if (network->security.bridge_pmk_valid)
                {
                    ret = wifi_send_add_wpa_pmk(network->role, network->bridge_ssid, NULL, network->security.bridge_pmk,
                                                WLAN_PMK_LENGTH);
                }
                else
                {
                    ret = wifi_send_add_wpa_psk(network->role, network->bridge_ssid, network->security.bridge_psk,
                                                network->security.bridge_psk_len);
                }

                if (ret != WM_SUCCESS)
                    return -WM_FAIL;
            }
#endif
            break;
        case WLAN_SECURITY_WPA3_SAE:
            if (res->WPA_WPA2_WEP.wpa3_sae != 0U)
            {
                wlcm_d("configuring WPA3 SAE security");
                wlcm_d("adding SSID and WPA3 SAE PASSWORD to supplicant cache");
                ret = wifi_send_add_wpa3_password(network->role, network->ssid, network->security.password,
                                                  network->security.password_len);
            }
            else if (res->WPA_WPA2_WEP.wpa2 != 0U)
            {
                wlcm_d("configuring WPA2 security");
                wlcm_d("adding SSID and PSK to supplicant cache");
                ret = wifi_send_add_wpa_psk(network->role, network->ssid, network->security.password,
                                            network->security.password_len);
            }
            else
            { /* Do Nothing */
            }
            if (ret != WM_SUCCESS)
            {
                return -WM_FAIL;
            }
            break;
        case WLAN_SECURITY_WEP_OPEN:
        case WLAN_SECURITY_WEP_SHARED:
            ret = load_wep_key((const uint8_t *)network->security.psk, (uint8_t *)network->security.psk,
                               (uint8_t *)&network->security.psk_len, sizeof(network->security.psk));
            if (ret != WM_SUCCESS)
            {
                return -WM_E_INVAL;
            }

            ret = wifi_set_key(BSS_TYPE_STA, true, 0, (const uint8_t *)network->security.psk, network->security.psk_len,
                               (const uint8_t *)network->bssid);

            if (ret != WM_SUCCESS)
            {
                return -WM_FAIL;
            }
            break;

        case WLAN_SECURITY_NONE:
#ifdef CONFIG_WPS2
            if (network->wps_specific && res->wps_session != WPS_SESSION_INACTIVE)
                wps_session_attempt = 1;
#endif
        default:
            break;
    }

    return WM_SUCCESS;
}

static int is_running(void)
{
    return (wlan.running && wlan.sta_state >= CM_STA_IDLE);
}

static int is_uap_state(enum cm_uap_state state)
{
    return (wlan.uap_state == state);
}

static int is_sta_connecting(void)
{
    return ((wlan.sta_state > CM_STA_ASSOCIATING) && (wlan.sta_state <= CM_STA_CONNECTED));
}

/* Check whether we are allowed to start a user-requested scan right now. */
static bool is_scanning_allowed(void)
{
    if (wlan.cm_ieeeps_configured || wlan.cm_deepsleepps_configured)
    {
        return false;
    }
    return (is_state(CM_STA_IDLE) || is_state(CM_STA_CONNECTED));
}

/*
 * Connection Manager actions
 */
static void do_scan(struct wlan_network *network)
{
    int ret;
    uint8_t *bssid = NULL;
    char *ssid     = NULL;
#ifdef CONFIG_WLAN_BRIDGE
    char *bridge_ssid = NULL;
#endif
    int channel = 0;
    IEEEtypes_Bss_t type;
    wlan_scan_channel_list_t chan_list[1];

    wlcm_d("initiating scan for network \"%s\"", network->name);

    if (network->bssid_specific != 0U)
    {
        bssid = (uint8_t *)network->bssid;
    }
    if (network->ssid_specific != 0U)
    {
        ssid = network->ssid;
#ifdef CONFIG_WLAN_BRIDGE
        bridge_ssid = network->bridge_ssid;
#endif
    }
#ifdef CONFIG_OWE
    if (network->owe_trans_mode == OWE_TRANS_MODE_OPEN)
    {
        ssid    = network->trans_ssid;
        channel = network->channel;
    }
#endif
    if (network->channel_specific != 0U)
        channel = network->channel;

    switch (network->role)
    {
        default:
        case WLAN_BSS_ROLE_STA:
            type = BSS_INFRASTRUCTURE;
            break;
    }

    wlan.sta_state = CM_STA_SCANNING;
    if (wrapper_wlan_11d_support_is_enabled() && wlan.scan_count < WLAN_11D_SCAN_LIMIT)
    {
        ret = wifi_send_scan_cmd(g_wifi_scan_params.bss_type, g_wifi_scan_params.bssid, g_wifi_scan_params.ssid, NULL,
                                 0, NULL, 0, false, false);
    }
    else
    {
        if (channel != 0)
        {
            chan_list[0].chan_number = channel;
            chan_list[0].scan_type   = 1;
            chan_list[0].scan_time   = 120;
#ifdef CONFIG_WLAN_BRIDGE
            ret = wifi_send_scan_cmd(type, bssid, ssid, bridge_ssid, 1, chan_list, 0, false, false);
#else
            ret = wifi_send_scan_cmd(type, bssid, ssid, NULL, 1, chan_list, 0, false, false);
#endif
        }
        else
        {
            ret = wifi_send_scan_cmd(type, bssid, ssid, NULL, 0, NULL, 0, false, false);
        }
    }
    if (ret != 0)
    {
        (void)wlan_wlcmgr_send_msg(WIFI_EVENT_SCAN_RESULT, WIFI_EVENT_REASON_FAILURE, NULL);
        wlcm_e("error: scan failed");
    }
    else
    {
        wlan.scan_count++;
    }
}

static void do_hidden_scan(struct wlan_network *network, uint8_t num_channels, wlan_scan_channel_list_t *chan_list)
{
    int ret;
    uint8_t *bssid = NULL;
    char *ssid     = NULL;
    IEEEtypes_Bss_t type;

    wlcm_d("initiating scan for hidden network \"%s\"", network->name);

    if (network->bssid_specific != 0U)
    {
        bssid = (uint8_t *)network->bssid;
    }
    if (network->ssid_specific != 0U)
    {
        ssid = network->ssid;
    }

    switch (network->role)
    {
        default:
        case WLAN_BSS_ROLE_STA:
            type = BSS_INFRASTRUCTURE;
            break;
    }

    wlan.sta_state = CM_STA_SCANNING;

    ret = wifi_send_scan_cmd(type, bssid, ssid, NULL, num_channels, chan_list, 0, false, true);
    if (ret != 0)
    {
        (void)wlan_wlcmgr_send_msg(WIFI_EVENT_SCAN_RESULT, WIFI_EVENT_REASON_FAILURE, NULL);
        wlcm_e("error: scan failed");
    }
}

static void do_connect_failed(enum wlan_event_reason reason);

/* Start a connection attempt.  To do this we choose a specific network to scan
 * for or the first of our list of known networks. If that network uses WEP
 * security, we first issue the WEP configuration command and enter the
 * CM_STA_CONFIGURING state, we'll get a response to this command which will
 * transition us to the CM_STA_SCANNING state.  Otherwise we issue a scan and
 * enter the CM_STA_SCANNING state now. */
static int do_connect(int netindex)
{
#ifdef CONFIG_WLAN_FAST_PATH
    int ret;
#endif /* CONFIG_WLAN_FAST_PATH */

#ifdef CONFIG_WMSTATS
    g_wm_stats.wm_conn_att++;
#endif /* CONFIG_WMSTATS */

    /* try the specified network */
    if (wlan.networks[netindex].role != WLAN_BSS_ROLE_STA)
    {
        return -WM_E_INVAL;
    }

#ifdef CONFIG_OWE
    wlan.networks[netindex].owe_trans_mode = 0;
#endif
    wlan.cur_network_idx = netindex;
    wlan.scan_count      = 0;

#ifdef CONFIG_WLAN_FAST_PATH
    if (((wlan.auth_cache_valid == true) || (wlan.fast_path_cache_valid == true)) &&
        (wlan.cur_network_idx == wlan.fp_network))
    {
        wlcm_d("Fast Path: Taking fast path");

        /* Fast path: Jump directly to associating state */
        wlan.sta_state = CM_STA_ASSOCIATING;
        ret            = wrapper_wifi_assoc(wlan.fast_path_bss, wlan.networks[wlan.cur_network_idx].security.type,
                                 wlan.networks[wlan.cur_network_idx].security.ucstCipher.tkip, 0);
        if (ret == WM_SUCCESS)
            return WM_SUCCESS;

        wlcm_d("Fast path assoc failed. Will try normal assoc");
        wlan.auth_cache_valid      = false;
        wlan.fast_path_cache_valid = false;
    }

#endif /* CONFIG_WLAN_FAST_PATH */
    do_scan(&wlan.networks[netindex]);

    return WM_SUCCESS;
}

static int do_start(struct wlan_network *network)
{
    int ret;
    uint8_t active_chan_list[40];
    uint8_t active_num_chans = 0;
    wifi_scan_chan_list_t scan_chan_list;

    if (network->role == WLAN_BSS_ROLE_UAP)
    {
        if (!network->channel_specific)
        {
            network->channel = UAP_DEFAULT_CHANNEL;

            if (wlan.running && (is_state(CM_STA_CONNECTED) || is_state(CM_STA_ASSOCIATED)))
            {
                network->channel = wlan.networks[wlan.cur_network_idx].channel;
            }
            else
            {
                if (!wlan_uap_scan_chan_list_set)
                {
                    wifi_get_active_channel_list(active_chan_list, &active_num_chans);

                    if (active_num_chans != 0U)
                    {
                        scan_chan_list.num_of_chan = active_num_chans;
                        (void)memcpy((void *)scan_chan_list.chan_number, (const void *)active_chan_list,
                                     active_num_chans);
                        wlan_uap_set_scan_chan_list(scan_chan_list);
                    }
                }
            }
        }

        wlcm_d("starting our own network");
        ret = wifi_uap_start(network->type, network->ssid,
#ifdef CONFIG_P2P
                             wlan.wfd_mac,
#else
                             wlan.mac,
#endif
                             network->security.type, &network->security.psk[0], &network->security.password[0],
                             network->channel, wlan.scan_chan_list, network->security.mfpc, network->security.mfpr);
        if (ret != 0)
        {
            wlcm_e("uAP start failed, giving up");
            CONNECTION_EVENT(WLAN_REASON_UAP_START_FAILED, NULL);
            return -WM_FAIL;
        }

        wlan.uap_state = CM_UAP_CONFIGURED;
    }
    return WM_SUCCESS;
}

static int do_stop(struct wlan_network *network)
{
    int ret = WM_SUCCESS;

    wlcm_d("stopping our own network");

    if (network->role == WLAN_BSS_ROLE_UAP)
    {
        ret = wifi_uap_stop(network->type);

        if (ret != 0)
        {
            wlcm_e("uAP stop failed, giving up");
            CONNECTION_EVENT(WLAN_REASON_UAP_STOP_FAILED, NULL);
            return -WM_FAIL;
        }
        wlan.uap_state = CM_UAP_INITIALIZING;
    }

    return WM_SUCCESS;
}

/* A connection attempt has failed for 'reason', decide whether to try to
 * connect to another network (in that case, tell the state machine to
 * transition to CM_STA_CONFIGURING to try that network) or finish attempting to
 * connect by releasing the scan lock and informing the user. */
static void do_connect_failed(enum wlan_event_reason reason)
{
#ifdef CONFIG_OWE
    struct wlan_network *network = &wlan.networks[wlan.cur_network_idx];
#endif
#ifdef CONFIG_WMSTATS
    g_wm_stats.wm_conn_fail++;
    switch (reason)
    {
        case WLAN_REASON_NETWORK_AUTH_FAILED:
            g_wm_stats.wm_auth_fail++;
            break;
        case WLAN_REASON_NETWORK_NOT_FOUND:
            g_wm_stats.wm_nwnt_found++;
            break;
        default:
            break;
    }
#endif /* CONFIG_WMSTATS */

    if (wlan.cm_ieeeps_configured)
    {
        /* disable ieeeps mode*/
        wlan_ieeeps_sm(IEEEPS_EVENT_DISABLE);
    }
#ifdef CONFIG_WPA2_ENTP
    wpa2_tls_cleanup(network, false);
#endif
    if (wlan.connect_wakelock_taken)
    {
        // wakelock_put(WL_ID_CONNECT);
        wlan.connect_wakelock_taken = false;
    }

#ifdef CONFIG_OWE
    if (network->trans_ssid_specific && network->trans_ssid_len)
    {
        (void)memset(&network->trans_ssid, 0x00, sizeof(network->trans_ssid));
        network->trans_ssid_len = 0;
    }
#endif

    wlcm_d("connecting to \"%s\" failed", wlan.networks[wlan.cur_network_idx].name);

    CONNECTION_EVENT(reason, NULL);
    wlan.sta_state = CM_STA_IDLE;

    if (wlan.sta_state == CM_STA_SCANNING_USER)
    {
        wlan.sta_return_to = CM_STA_IDLE;
    }
}

static void report_scan_results(void)
{
    unsigned int count;
    if (wlan.scan_cb != NULL)
    {
        if (wifi_get_scan_result_count(&count) != WM_SUCCESS)
        {
            count = 0;
        }
        (void)wlan.scan_cb(count);
        wlan.scan_cb = NULL;
    }
}

static void update_network_params(struct wlan_network *network, const struct wifi_scan_result *res)
{
    if (!network->security_specific)
    {
        /* Wildcard: If wildcard security is specified, copy the highest
         * security available in the scan result to the configuration
         * structure
         */
        enum wlan_security_type t;

        if (res->WPA_WPA2_WEP.wpa3_sae != 0U)
        {
            t = WLAN_SECURITY_WPA3_SAE;
        }
        else if (res->WPA_WPA2_WEP.wpa2 != 0U)
        {
            t = WLAN_SECURITY_WPA2;
        }
        else if (res->WPA_WPA2_WEP.wpa != 0U)
        {
            t = WLAN_SECURITY_WPA_WPA2_MIXED;
        }
        else if (res->WPA_WPA2_WEP.wepStatic != 0U)
        {
            t = WLAN_SECURITY_WEP_OPEN;
        }
#ifdef CONFIG_OWE
        else if (res->WPA_WPA2_WEP.wpa2 && res->WPA_WPA2_WEP.owe)
        {
            t = WLAN_SECURITY_OWE_ONLY;
        }
#endif
        else
        {
            t = WLAN_SECURITY_NONE;
        }
        network->security.type = t;
    }

    /* We have a match based on the criteria we checked, update the known
     * network with any additional information that we got from the scan but
     * did not know before */
    if (!network->channel_specific)
    {
        network->channel = res->Channel;
    }
    if (!network->bssid_specific)
    {
        (void)memcpy((void *)network->bssid, (const void *)res->bssid, MLAN_MAC_ADDR_LENGTH);
    }
    if (!network->ssid_specific)
    {
        (void)memcpy((void *)network->ssid, (const void *)res->ssid, res->ssid_len);
    }

    network->beacon_period = res->beacon_period;
    network->dtim_period   = res->dtim_period;
#ifdef CONFIG_OWE
    network->owe_trans_mode = res->trans_mode;

    if (res->trans_mode == OWE_TRANS_MODE_OPEN)
    {
        (void)memset(&network->trans_ssid, 0x00, sizeof(network->trans_ssid));
        (void)memcpy((void *)network->trans_ssid, (const void *)res->trans_ssid, res->trans_ssid_len);
        network->trans_ssid_len = res->trans_ssid_len;
    }
#endif

    network->security.is_pmf_required = res->is_pmf_required;

    switch (network->security.type)
    {
        case WLAN_SECURITY_WPA:
            network->security.mcstCipher.tkip = res->wpa_mcstCipher.tkip;
            network->security.ucstCipher.tkip = res->wpa_ucstCipher.tkip;
            network->security.mcstCipher.ccmp = res->wpa_mcstCipher.ccmp;
            network->security.ucstCipher.ccmp = res->wpa_ucstCipher.ccmp;
            break;
        case WLAN_SECURITY_WPA2:
        case WLAN_SECURITY_WPA_WPA2_MIXED:
#ifdef CONFIG_WPA2_ENTP
        case WLAN_SECURITY_EAP_TLS:
        case WLAN_SECURITY_PEAP_MSCHAPV2:
#endif
            network->security.mcstCipher.tkip = res->rsn_mcstCipher.tkip;
            network->security.ucstCipher.tkip = res->rsn_ucstCipher.tkip;
            network->security.mcstCipher.ccmp = res->rsn_mcstCipher.ccmp;
            network->security.ucstCipher.ccmp = res->rsn_ucstCipher.ccmp;
            if (!res->rsn_mcstCipher.tkip && !res->rsn_ucstCipher.tkip && !res->rsn_mcstCipher.ccmp &&
                !res->rsn_ucstCipher.ccmp)
            {
                network->security.mcstCipher.tkip = res->wpa_mcstCipher.tkip;
                network->security.ucstCipher.tkip = res->wpa_ucstCipher.tkip;
                network->security.mcstCipher.ccmp = res->wpa_mcstCipher.ccmp;
                network->security.ucstCipher.ccmp = res->wpa_ucstCipher.ccmp;
            }
            break;
        default:
            break;
    }
}

static int start_association(struct wlan_network *network, struct wifi_scan_result *res)
{
    int ret = WM_SUCCESS;

    wlcm_d("starting association to \"%s\"", network->name);

    ret = configure_security(network, res);
    if (ret != 0)
    {
        wlcm_d("setting security params failed");
        do_connect_failed(WLAN_REASON_NETWORK_NOT_FOUND);
        return -WM_FAIL;
    }
#ifdef CONFIG_OWE
    ret = wrapper_wifi_assoc(res->bssid, network->security.type, network->security.ucstCipher.tkip, res->trans_mode);
#else
    ret = wrapper_wifi_assoc(res->bssid, network->security.type, network->security.ucstCipher.tkip, 0);
#endif
    if (ret != 0)
    {
        wlcm_d("association failed");
#ifdef CONFIG_WLAN_FAST_PATH
        wlan.auth_cache_valid      = false;
        wlan.fast_path_cache_valid = false;
#endif /* CONFIG_WLAN_FAST_PATH */
        do_connect_failed(WLAN_REASON_NETWORK_NOT_FOUND);
        return -WM_FAIL;
    }
#ifdef CONFIG_WLAN_FAST_PATH
    else
    {
        /* cache the scan result for fast path.
         * It will be marked as valid only on
         * successful association and authentication */
        wlan.auth_cache_valid      = false;
        wlan.fast_path_cache_valid = false;
        (void)memcpy((void *)wlan.fast_path_bss, (const void *)res->bssid, MLAN_MAC_ADDR_LENGTH);
        wlan.fp_network = wlan.cur_network_idx;
    }
#endif /* CONFIG_WLAN_FAST_PATH */

    return ret;
}

static void handle_scan_results(void)
{
    unsigned int count;
    int ret;
    unsigned int i;
    struct wifi_scan_result *res;
    struct wlan_network *network = &wlan.networks[wlan.cur_network_idx];
    bool matching_ap_found       = false;
    uint8_t num_channels         = 0;
    wlan_scan_channel_list_t chan_list[40];

    if (wrapper_wlan_11d_support_is_enabled() && wlan.scan_count < WLAN_11D_SCAN_LIMIT)
    {
        wlcm_d("11D enabled, re-scanning");
        do_scan(network);
        return;
    }

    /*
     * We need an allocation here because the lower layer puts all the
     * results into the same global buffer. Hence, we need a private
     * copy. fixme: Can be removed after this issue is fixed in the
     * lower layer.
     */
    struct wifi_scan_result *best_ap = os_mem_alloc(sizeof(struct wifi_scan_result));
    if (best_ap == NULL)
    {
        wlcm_d("%s: Failed to alloc scan result object", __func__);
        return;
    }

    /* We're associating unless an error occurs, in which case we make a
     * decision to rescan (transition to CM_STA_SCANNING) or fail
     * (transition to CM_STA_IDLE or a new connection attempt) */
    wlan.sta_state = CM_STA_ASSOCIATING;

    ret = wifi_get_scan_result_count(&count);
    if (ret != 0)
    {
        count = 0;
    }

    /* 'count' scan results available, is our network there? */
    for (i = 0; i < count; i++)
    {
        ret = wifi_get_scan_result(i, &res);
        if (ret == WM_SUCCESS && network_matches_scan_result(network, res, &num_channels, chan_list))
        {
            if (!matching_ap_found)
            {
                /* First matching AP found */
                (void)memcpy((void *)best_ap, (const void *)res, sizeof(struct wifi_scan_result));
                matching_ap_found = true;
                /*
                 * Continue the search. There may be an AP
                 * with same name but better RSSI.
                 */
                continue;
            }

            if (best_ap->RSSI > res->RSSI)
            {
                /*
                 * We found a network better that current
                 * best_ap
                 */
                wlcm_d("Found better AP %s on channel %d", res->ssid, res->Channel);
                /* Assign the new found as curr_best */
                (void)memcpy((void *)best_ap, (const void *)res, sizeof(struct wifi_scan_result));
            }

            /* Continue the search */
        }
    }

    if (matching_ap_found)
    {
        update_network_params(network, best_ap);
#ifdef CONFIG_OWE
        if (network->owe_trans_mode == OWE_TRANS_MODE_OPEN)
        {
            wlcm_d("do scan for OWE Transition SSID: %s", network->trans_ssid);
            do_scan(network);
        }
        else
        {
#endif
            ret = start_association(network, best_ap);
            if (ret == WM_SUCCESS)
            {
                os_mem_free(best_ap);
                return;
            }
#ifdef CONFIG_OWE
        }
#endif
    }
    else if (num_channels != 0U)
    {
        os_mem_free(best_ap);
        wlan.hidden_scan_on = true;
        do_hidden_scan(network, num_channels, chan_list);
        return;
    }
    else
    { /* Do Nothing */
    }

    os_mem_free(best_ap);

    /* We didn't find our network in the scan results set: rescan if we
     * have rescan attempts remaining, otherwise give up.
     */
    if (wlan.scan_count < WLAN_RESCAN_LIMIT)
    {
        wlcm_d("network not found, re-scanning");
        wlan.hidden_scan_on = false;
        do_scan(network);
    }
    else
    {
        wlcm_d("rescan limit exceeded, giving up");
        do_connect_failed(WLAN_REASON_NETWORK_NOT_FOUND);

        if (wlan.reassoc_control)
        {
            wlcm_request_reconnect(&wlan.sta_state, network);
        }
    }
}

static void wlan_disable_power_save(int action)
{
    switch (action)
    {
        case WLAN_DEEP_SLEEP:
            wlcm_d("stopping deep sleep ps mode");
            wlan_deepsleepps_sm(DEEPSLEEPPS_EVENT_DISABLE);
            break;
        case WLAN_IEEE:
            wlcm_d("stopping IEEE ps mode");
            wlan_ieeeps_sm(IEEEPS_EVENT_DISABLE);
            break;
    }
}

static void wlan_enable_power_save(int action)
{
    switch (action)
    {
        case WLAN_DEEP_SLEEP:
            if (!is_state(CM_STA_IDLE))
            {
                wlcm_d("entering deep sleep mode");
                break;
            }
            wlcm_d("starting deep sleep ps mode");
            wlan.cm_deepsleepps_configured = true;
            /* Enter Deep Sleep power save mode */
            wlan_deepsleepps_sm(DEEPSLEEPPS_EVENT_ENABLE);
            break;
        case WLAN_IEEE:
            wlcm_d("starting IEEE ps mode");
            wlan.cm_ieeeps_configured = true;
            /* Enter IEEE power save mode
             * via the state machine
             */
            wlan_ieeeps_sm(IEEEPS_EVENT_ENABLE);
            break;
    }
}

static void wlcm_process_awake_event(void)
{
    /* tbdel */
    wlan.cm_ps_state = PS_STATE_AWAKE;
    wlan_ieeeps_sm(IEEEPS_EVENT_AWAKE);
    wlan_deepsleepps_sm(DEEPSLEEPPS_EVENT_AWAKE);
}

static void wlcm_process_ieeeps_event(struct wifi_message *msg)
{
    ENH_PS_MODES action = (ENH_PS_MODES)((uint32_t)msg->data);
    wlcm_d("got msg data :: %x", action);

    if (msg->reason == WIFI_EVENT_REASON_SUCCESS)
    {
        if (action == EN_AUTO_PS)
        {
            wlan_ieeeps_sm(IEEEPS_EVENT_ENABLE_DONE);
        }
        else if (action == DIS_AUTO_PS)
        {
            wlan.cm_ieeeps_configured = false;
            wlan.cm_ps_state          = PS_STATE_AWAKE;
            ps_sleep_cb_sent          = false;
            CONNECTION_EVENT(WLAN_REASON_PS_EXIT, (void *)WLAN_IEEE);
            /* This sends event to state machine
             * to finally set state to init*/
            wlan_ieeeps_sm(IEEEPS_EVENT_DISABLE_DONE);
        }
        else if (action == SLEEP_CONFIRM)
        {
            wlan.cm_ps_state = PS_STATE_SLEEP_CFM;

            wlan_ieeeps_sm(IEEEPS_EVENT_SLP_CFM);

            if (!ps_sleep_cb_sent)
            {
                CONNECTION_EVENT(WLAN_REASON_PS_ENTER, (void *)WLAN_IEEE);
                ps_sleep_cb_sent = true;
            }
        }
        else
        { /* Do Nothing */
        }
    }
}

static void wlcm_process_deepsleep_event(struct wifi_message *msg, enum cm_sta_state *next)
{
    uint16_t action = (uint16_t)((uint32_t)msg->data);
    wlcm_d("got msg data :: %x", action);

    if (msg->reason == WIFI_EVENT_REASON_SUCCESS)
    {
        if (action == EN_AUTO_PS)
        {
            wlan_deepsleepps_sm(DEEPSLEEPPS_EVENT_ENABLE_DONE);
        }
        else if (action == SLEEP_CONFIRM)
        {
            wlan.cm_ps_state = PS_STATE_SLEEP_CFM;
            *next            = CM_STA_DEEP_SLEEP;

            wlan_deepsleepps_sm(DEEPSLEEPPS_EVENT_SLP_CFM);

            CONNECTION_EVENT(WLAN_REASON_PS_ENTER, (void *)WLAN_DEEP_SLEEP);
        }
        else if (action == DIS_AUTO_PS)
        {
            wlan.cm_deepsleepps_configured = false;
            wlan.cm_ps_state               = PS_STATE_AWAKE;
            *next                          = CM_STA_IDLE;
            wlan_deepsleepps_sm(DEEPSLEEPPS_EVENT_DISABLE_DONE);
#ifdef CONFIG_P2P
            /* This call is made to initiate WFD
             * We are not interested in the response
             * since mac addr is already populated
             * in wlan_start
             */
            wifi_get_wfd_mac_address();
#endif
            // CONNECTION_EVENT(WLAN_REASON_INITIALIZED, NULL);
            /* Skip ps-exit event for the first time
               after waking from PM4+DS. This will ensure
               that we do not send ps-exit event until
               wlan-init event has been sent */
            if (wlan.skip_ds_exit_cb)
            {
                wlan.skip_ds_exit_cb = false;
            }
            else
            {
                CONNECTION_EVENT(WLAN_REASON_PS_EXIT, (void *)WLAN_DEEP_SLEEP);
            }
        }
        else
        { /* Do Nothing */
        }
    }
}

#define WL_ID_STA_DISCONN "sta_disconnected"

/* fixme: duplicated from legacy. Needs to be removed later. */
#define IEEEtypes_REASON_MIC_FAILURE          14U
#define IEEEtypes_REASON_4WAY_HANDSHK_TIMEOUT 15
#define WPA2_ENTERPRISE_FAILED                0xFF

static void wlcm_process_scan_result_event(struct wifi_message *msg, enum cm_sta_state *next)
{
    if (msg->reason == WIFI_EVENT_REASON_SUCCESS)
    {
        wifi_scan_process_results();
    }

    if (wlan.sta_state == CM_STA_SCANNING)
    {
        wlcm_d("SM: returned to %s", dbg_sta_state_name(*next));
        handle_scan_results();
        *next = wlan.sta_state;
        wlcm_d("releasing scan lock (connect scan)");
    }
    else if (wlan.sta_state == CM_STA_SCANNING_USER)
    {
        report_scan_results();
        *next = wlan.sta_return_to;
        wlcm_d("SM: returned to %s", dbg_sta_state_name(*next));
        wlcm_d("releasing scan lock (user scan)");
    }
    else
    { /* Do Nothing */
    }
    (void)os_semaphore_put(&wlan.scan_lock);
    wlan.is_scan_lock = 0;
}

static void wlcm_process_sta_addr_config_event(struct wifi_message *msg,
                                               enum cm_sta_state *next,
                                               struct wlan_network *network)
{
    /* We have a response to our configuration request from the TCP stack.
     * If we configured the stack with a static IP address and this was
     * successful, we are effectively connected so we can report success
     * and proceed to CM_STA_CONNECTED.  If we configured the stack with
     * DHCP and the response is successful then the TCP stack is trying to
     * obtain an address for us and we should proceed to the
     * CM_STA_OBTAINING_ADDRESS state and wait for the
     * WIFI_EVENT_DHCP_CONFIG event,
     * which will tell us whether or not the DHCP address was
     * obtained.  Otherwise, if we got an unsuccessful response then we
     * must report a connection error.
     *
     * This event is only relevant if we are connecting and have requested
     * a TCP stack configuration (that is, we are in the
     * CM_STA_REQUESTING_ADDRESS state).  Otherwise, we ignore it. */

    if (!is_state(CM_STA_REQUESTING_ADDRESS))
    {
        wlcm_d("ignoring TCP configure response");
        return;
    }
    if (msg->reason != WIFI_EVENT_REASON_SUCCESS)
    {
        do_connect_failed(WLAN_REASON_ADDRESS_FAILED);
        *next = wlan.sta_state;
        return;
    }
    void *if_handle = NULL;
    switch (network->ip.ipv4.addr_type)
    {
        case ADDR_TYPE_STATIC:
#ifdef CONFIG_WMSTATS
            g_wm_stats.wm_addr_type = 0;
#endif /* CONFIG_WMSTATS */
            net_configure_dns(&network->ip, network->role);
            if (network->type == WLAN_BSS_TYPE_STA)
            {
                if_handle = net_get_mlan_handle();
            }
#ifdef CONFIG_P2P
            else if (network->type == WLAN_BSS_TYPE_WIFIDIRECT)
                if_handle = net_get_wfd_handle();
#endif /* CONFIG_P2P */
            (void)net_get_if_addr(&network->ip, if_handle);
            wlan.sta_state = CM_STA_CONNECTED;
            // wakelock_put(WL_ID_CONNECT);
            wlan.connect_wakelock_taken = false;
            *next                       = CM_STA_CONNECTED;
            wlan.sta_ipv4_state         = CM_STA_CONNECTED;
#ifdef CONFIG_P2P
            if (network->security.type != WLAN_SECURITY_NONE)
#endif
                if (wlan.reassoc_control && wlan.reassoc_request)
                {
                    wlan.reassoc_count   = 0;
                    wlan.reassoc_request = false;
                }
            CONNECTION_EVENT(WLAN_REASON_SUCCESS, NULL);
#ifdef CONFIG_P2P
            wifi_wfd_event(false, false, (void *)1);
#endif
            break;
        case ADDR_TYPE_DHCP:
        case ADDR_TYPE_LLA:
#ifdef CONFIG_WMSTATS
            g_wm_stats.wm_addr_type = 1;
#endif /* CONFIG_WMSTATS */
            *next               = CM_STA_OBTAINING_ADDRESS;
            wlan.sta_ipv4_state = CM_STA_OBTAINING_ADDRESS;
            break;
        default:
            break;
    } /* end of switch */
#ifdef CONFIG_IPV6
    /* Set the ipv6 state to obtaining address */
    wlan.sta_ipv6_state = CM_STA_OBTAINING_ADDRESS;
#endif
}

static void wlcm_process_channel_switch_ann(enum cm_sta_state *next, struct wlan_network *network)
{
    if (!wifi_is_ecsa_enabled())
    {
        if (is_state(CM_STA_CONNECTED))
        {
            wlcm_d("Sending deauth because of channel switch");
            set_event_chanswann();
            (void)wifi_deauthenticate((uint8_t *)network->bssid);
            /*
              This function call is already present in
              wlan_11h_handle_event_chanswann(). Remove it from here when
              that function is used directly.
            */
            wrapper_wlan_11d_clear_parsedtable();
            wrapper_clear_media_connected_event();
#ifdef CONFIG_WLAN_FAST_PATH
            /*
             * Flush fast path cache. We do not want fast path code to
             * push out assoc requests on the same channel on which
             * radar interference was detected.
             */
            wlan.auth_cache_valid      = false;
            wlan.fast_path_cache_valid = false;
#endif /* CONFIG_WLAN_FAST_PATH */
            clear_event_chanswann();
            wlan.sta_state = CM_STA_IDLE;
            *next          = CM_STA_IDLE;
            CONNECTION_EVENT(WLAN_REASON_CHAN_SWITCH, NULL);
        }
    }
}

static void wlcm_process_channel_switch(struct wifi_message *msg)
{
    if (wifi_is_ecsa_enabled())
    {
        if (msg->data != NULL)
        {
            (void)PRINTF("Switch to channel %d success!\r\n", *((uint8_t *)msg->data));
            wlan.networks[wlan.cur_network_idx].channel = *((uint8_t *)msg->data);
            wifi_set_curr_bss_channel(wlan.networks[wlan.cur_network_idx].channel);
            os_mem_free((void *)msg->data);
        }
    }
}

static void wlcm_process_hs_config_event(void)
{
    /* host sleep config done event received */
    int ret = WM_SUCCESS;
    unsigned int ipv4_addr;
    enum wlan_bss_type type = WLAN_BSS_TYPE_STA;

    ret = wlan_get_ipv4_addr(&ipv4_addr);
    if (ret != WM_SUCCESS)
    {
        wlcm_e("HS : Cannot get IP");
        return;
    }
    /* If uap interface is up
     * configure host sleep for uap interface
     * else confiugre host sleep for station
     * interface.
     */
    if (is_uap_started() != 0)
    {
        type = WLAN_BSS_TYPE_UAP;
    }

    (void)wifi_send_hs_cfg_cmd((mlan_bss_type)type, ipv4_addr, HS_ACTIVATE, 0);
}

#ifdef CONFIG_11N
static void wlcm_process_addba_request(struct wifi_message *msg)
{
    if (is_state(CM_STA_ASSOCIATED) || is_state(CM_STA_REQUESTING_ADDRESS) || is_state(CM_STA_OBTAINING_ADDRESS) ||
        is_state(CM_STA_CONNECTED) || is_uap_started())
    {
        (void)wrapper_wlan_cmd_11n_addba_rspgen(msg->data);
    }
    else
    {
        wlcm_d("Ignore ADDBA Request event in disconnected state");
        os_mem_free((void *)msg->data);
    }
}

static void wlcm_process_delba_request(struct wifi_message *msg)
{
    if (is_state(CM_STA_ASSOCIATED) || is_state(CM_STA_REQUESTING_ADDRESS) || is_state(CM_STA_OBTAINING_ADDRESS) ||
        is_state(CM_STA_CONNECTED) || is_uap_started())
    {
        (void)wrapper_wlan_cmd_11n_delba_rspgen(msg->data);
    }
    else
    {
        wlcm_d("Ignore DELBA Request event in disconnected state");
        os_mem_free((void *)msg->data);
    }
}

static void wlcm_process_ba_stream_timeout_request(struct wifi_message *msg)
{
    if (is_state(CM_STA_ASSOCIATED) || is_state(CM_STA_REQUESTING_ADDRESS) || is_state(CM_STA_OBTAINING_ADDRESS) ||
        is_state(CM_STA_CONNECTED) || is_uap_started())
    {
        (void)wrapper_wlan_cmd_11n_ba_stream_timeout(msg->data);
    }
    else
    {
        wlcm_d(
            "Ignore BA STREAM TIMEOUT Request"
            " event in disconnected state");
        os_mem_free((void *)msg->data);
    }
}
#endif

static void wlcm_process_association_event(struct wifi_message *msg, enum cm_sta_state *next)
{
#ifdef CONFIG_WPA2_ENTP
    int ret;
    struct wlan_network *network = &wlan.networks[wlan.cur_network_idx];
#endif

#ifdef CONFIG_WLAN_FAST_PATH
    if (wlan.is_scan_lock)
    {
        wlcm_d("releasing scan lock for fast path");
        os_semaphore_put(&wlan.scan_lock);
        wlan.is_scan_lock = 0;
    }
#endif

    /* We have received a response to the association command.  We may now
     * proceed to authenticating if it was successful, otherwise this
     * connection attempt has failed.
     *
     * This event is only relevant if we have sent an association command
     * while connecting (that is, we are in the CM_STA_ASSOCIATING state).
     * Otherwise, it is ignored. */

    if (!is_state(CM_STA_ASSOCIATING))
    {
        wlcm_d("ignoring association result event");
        return;
    }
    if (msg->reason == WIFI_EVENT_REASON_SUCCESS)
    {
        wlan.sta_state = CM_STA_ASSOCIATED;
        *next          = CM_STA_ASSOCIATED;

#ifdef CONFIG_WPS2
        if (wps_session_attempt)
        {
#ifdef CONFIG_WPA2_ENTP
            ret = wpa2_ent_connect(network);
            if (ret != WM_SUCCESS)
                wlcm_e("wpa2_ent_connect failed");
#endif
        }
#endif
        wlan.scan_count = 0;
    }
    else if (wlan.scan_count < WLAN_RESCAN_LIMIT)
    {
        wlcm_d("association failed, re-scanning");
#ifdef CONFIG_WPA2_ENTP
        wpa2_tls_cleanup(network, true);
#endif
        do_scan(&wlan.networks[wlan.cur_network_idx]);
        *next = CM_STA_SCANNING;
    }
    else
    {
#ifdef CONFIG_WPA2_ENTP
        wpa2_tls_cleanup(network, true);
#endif
        do_connect_failed(WLAN_REASON_NETWORK_NOT_FOUND);

        if (wlan.reassoc_control)
        {
            wlcm_request_reconnect(next, &wlan.networks[wlan.cur_network_idx]);
        }

        *next = wlan.sta_state;
    }
}

static void wlcm_process_pmk_event(struct wifi_message *msg, enum cm_sta_state *next, struct wlan_network *network)
{
    if (msg->data != NULL)
    {
        network->security.pmk_valid = true;
        (void)memcpy((void *)network->security.pmk, (const void *)msg->data, WLAN_PMK_LENGTH);
        if (network->role == WLAN_BSS_ROLE_STA)
        {
            (void)wifi_send_add_wpa_pmk(network->role, network->ssid, network->bssid, network->security.pmk,
                                        WLAN_PMK_LENGTH);
        }
    }
}

static void wlcm_process_authentication_event(struct wifi_message *msg,
                                              enum cm_sta_state *next,
                                              struct wlan_network *network)
{
    int ret         = 0;
    void *if_handle = NULL;

#ifndef CONFIG_WPA2_ENTP
#ifdef CONFIG_WPS2
    if (wps_session_attempt)
        return;
#endif
#endif

    if (!is_state(CM_STA_ASSOCIATING) && !is_state(CM_STA_ASSOCIATED) && !is_state(CM_STA_REQUESTING_ADDRESS) &&
        !is_state(CM_STA_OBTAINING_ADDRESS) && !is_state(CM_STA_CONNECTED))
    {
        wlcm_d("ignoring authentication event");
        return;
    }

    if (msg->reason == WIFI_EVENT_REASON_SUCCESS)
    {
#ifdef CONFIG_WMSTATS
        g_wm_stats.wm_conn_succ++;
#endif /* CONFIG_WMSTATS */
#ifdef CONFIG_WLAN_FAST_PATH
        if (wlan.fast_path_cache_valid == true && (wlan.cur_network_idx == wlan.fp_network))
        {
            if_handle = net_get_mlan_handle();
            net_interface_up(if_handle);
            // wakelock_put(WL_ID_CONNECT);
            wlan.connect_wakelock_taken = false;
            wlan.sta_ipv4_state         = CM_STA_CONNECTED;
            *next                       = CM_STA_CONNECTED;

            if (wlan.reassoc_control && wlan.reassoc_request)
            {
                wlan.reassoc_count   = 0;
                wlan.reassoc_request = false;
            }
            CONNECTION_EVENT(WLAN_REASON_SUCCESS, NULL);
        }
        else
        {
#endif /* CONFIG_WLAN_FAST_PATH */
            if (network->type == WLAN_BSS_TYPE_STA)
            {
                if_handle = net_get_mlan_handle();
            }
#ifdef CONFIG_P2P
            else if (network->type == WLAN_BSS_TYPE_WIFIDIRECT)
            {
                if_handle = net_get_wfd_handle();
            }
            else
            {
                /* Do nothing */
            }
#endif /* CONFIG_P2P */
            ret = net_configure_address(&network->ip, if_handle);
            if (ret != 0)
            {
                wlcm_e("Configure Address failed");
                do_connect_failed(WLAN_REASON_ADDRESS_FAILED);
                *next = wlan.sta_state;
            }
            else
            {
                *next               = CM_STA_REQUESTING_ADDRESS;
                wlan.sta_ipv4_state = CM_STA_REQUESTING_ADDRESS;
#ifdef CONFIG_IPV6
                wlan.sta_ipv6_state = CM_STA_REQUESTING_ADDRESS;
#endif
            }
#ifdef CONFIG_WLAN_FAST_PATH
            wlan.auth_cache_valid = false;
            /* Mark the fast path cache valid after
             * successful connection. */
            wlcm_d("Fast Path: validating settings");
            wlan.fast_path_cache_valid = true;
        }
#endif /* CONFIG_WLAN_FAST_PATH */
#ifdef CONFIG_WPA2_ENTP
        wpa2_tls_cleanup(network, false);
#endif
    }
    else
    {
#ifdef CONFIG_WLAN_FAST_PATH
        wlan.auth_cache_valid = true;
        /* Mark the fast path cache invalid. */
        wlan.fast_path_cache_valid = false;
#endif /* CONFIG_WLAN_FAST_PATH */
#ifdef CONFIG_WPA2_ENTP
        wpa2_tls_cleanup(network, false);
#endif
        if (*((uint16_t *)msg->data) == IEEEtypes_REASON_MIC_FAILURE)
        {
            wlan.assoc_paused = true;
            (void)os_timer_activate(&wlan.assoc_timer);
        }

        if (is_state(CM_STA_REQUESTING_ADDRESS) || is_state(CM_STA_OBTAINING_ADDRESS))
        {
            void *if_handle = NULL;
            /* On Link loss, we need to take down the interface. */
            if (network->type == WLAN_BSS_TYPE_STA)
            {
                if_handle = net_get_mlan_handle();
            }

            if (if_handle != NULL)
            {
                /* Forcefully stop dhcp on given interface.
                 * net_interface_dhcp_stop internally does nothing
                 * if dhcp client is not started.
                 */
                net_interface_dhcp_stop(if_handle);
                net_interface_down(if_handle);
            }
        }

        if (is_state(CM_STA_ASSOCIATED))
        {
            (void)wifi_deauthenticate((uint8_t *)network->bssid);
        }
        wlan.sta_state      = CM_STA_IDLE;
        wlan.sta_state      = CM_STA_IDLE;
        *next               = CM_STA_IDLE;
        wlan.sta_ipv4_state = CM_STA_IDLE;
#ifdef CONFIG_IPV6
        wlan.sta_ipv6_state = CM_STA_IDLE;
#endif
        do_connect_failed(WLAN_REASON_NETWORK_AUTH_FAILED);

        if (wlan.reassoc_control)
        {
            wlcm_request_reconnect(next, network);
        }

#ifdef CONFIG_P2P
        wifi_wfd_event(false, false, NULL);
#endif
    }
}

static void wlcm_process_link_loss_event(struct wifi_message *msg,
                                         enum cm_sta_state *next,
                                         struct wlan_network *network)
{
    /* We're being informed about an asynchronous link loss (ex: beacon loss
     * counter detected that the AP is gone, security failure, etc). If we
     * were connected, we need to report this event and proceed to idle.
     * If we were in the middle of a connection attempt, we need to treat
     * this as a connection attempt failure via do_connect_fail() and
     * proceed accordingly.
     */
#ifdef CONFIG_WMSTATS
    g_wm_stats.wm_lloss++;
#endif /* CONFIG_WMSTATS */
    if (is_state(CM_STA_IDLE))
    {
        wlcm_d("ignoring link loss event in idle state");
        return;
    }

    void *if_handle = NULL;
    /* On Link loss, we need to take down the interface. */
    if (network->type == WLAN_BSS_TYPE_STA)
    {
        if_handle = net_get_mlan_handle();
    }

    if (if_handle != NULL)
    {
        /* Forcefully stop dhcp on given interface.
         * net_interface_dhcp_stop internally does nothing
         * if dhcp client is not started.
         */
        net_interface_dhcp_stop(if_handle);
        net_interface_down(if_handle);
    }

    /* If we were connected and lost the link, we must report that now and
     * return to CM_STA_IDLE
     */
    if (is_state(CM_STA_CONNECTED))
    {
        wlan.sta_state      = CM_STA_IDLE;
        wlan.sta_ipv4_state = CM_STA_IDLE;
#ifdef CONFIG_IPV6
        wlan.sta_ipv6_state = CM_STA_IDLE;
#endif
        if (wlan.cm_ieeeps_configured)
        {
            /* on link loss disable ieeeps mode*/
            wlan_ieeeps_sm(IEEEPS_EVENT_DISABLE);
        }

        if ((int)msg->data == IEEEtypes_REASON_MIC_FAILURE)
        {
            /* In case of a LINK loss because of bad MIC
             * failure, directly send a deauth.
             */
            wlcm_d(
                "Sending deauth because of"
                " successive bad MIC failures");
            (void)wlan_disconnect();
            *next = CM_STA_IDLE;
        }

        CONNECTION_EVENT(WLAN_REASON_LINK_LOST, NULL);
        if (is_user_scanning() != 0)
        {
            wlan.sta_return_to = CM_STA_IDLE;
        }
        else
        {
            *next = CM_STA_IDLE;
        }
    }
    else
    {
        /* we were attempting a connection and lost the link,
         * so treat this as a connection attempt failure
         */
        switch ((int)msg->data)
        {
            case IEEEtypes_REASON_4WAY_HANDSHK_TIMEOUT:
                do_connect_failed(WLAN_REASON_NETWORK_AUTH_FAILED);
                break;
            default:
                do_connect_failed(WLAN_REASON_NETWORK_NOT_FOUND);
                break;
        }
        *next = wlan.sta_state;
    }
#ifdef CONFIG_WPA2_ENTP
    wpa2_tls_cleanup(network, false);
#endif
#ifdef CONFIG_P2P
    wifi_wfd_event(false, false, NULL);
#endif

    if (wlan.reassoc_control)
    {
        wlcm_request_reconnect(next, network);
    }
}

#ifdef CONFIG_WLAN_BRIDGE
static void wlcm_process_network_switch_event(struct wifi_message *msg,
                                              enum cm_sta_state *next,
                                              struct wlan_network *network)
{
    Event_AutoLink_SW_Node_t *pnewNode = (Event_AutoLink_SW_Node_t *)msg->data;

    char *p = os_mem_calloc(pnewNode->len_ssid + 1);

    /*print new network info*/
    (void)PRINTF("\r\nBssid=");
    extern void print_mac(const char *mac);
    print_mac((char *)pnewNode->peer_mac_addr);
    if (p)
    {
        (void)memcpy((void *)p, (const void *)pnewNode->ssid, pnewNode->len_ssid);
        (void)PRINTF("\r\nSsid=%s\r\n", p);
        os_mem_free(p);
    }
    (void)PRINTF("channel=%d,chanBand=%d,chanWidth=%d,chan2Offset=%d,scanMode=%d", pnewNode->chanBand.chanNum,
                 pnewNode->chanBand.bandConfig.chanBand, pnewNode->chanBand.bandConfig.chanWidth,
                 pnewNode->chanBand.bandConfig.chan2Offset, pnewNode->chanBand.bandConfig.scanMode);
    (void)PRINTF("\r\nSecurityType=%d", pnewNode->secutype);
    (void)PRINTF("\r\nmcstCipher=%d", pnewNode->mcstcipher);
    (void)PRINTF("\r\nucstCipher=%d\r\n", pnewNode->ucstcipher);

    os_mem_free(msg->data);
}
#endif

static void wlcm_process_disassoc_event(struct wifi_message *msg, enum cm_sta_state *next, struct wlan_network *network)
{
    /* We're being informed about an asynchronous disassociation from AP
     * As were in the middle of a connection attempt, we need to treat
     * this as a connection attempt failure via do_connect_fail() and
     * proceed accordingly.
     */
#ifdef CONFIG_WPA2_ENTP
    wpa2_tls_cleanup(network, false);
#endif
#ifdef CONFIG_P2P
    wifi_wfd_event(false, false, NULL);
#endif
    *next          = CM_STA_IDLE;
    wlan.sta_state = CM_STA_IDLE;

    if (is_user_scanning() != 0)
    {
        wlan.sta_return_to = CM_STA_IDLE;
    }

    do_connect_failed(WLAN_REASON_NETWORK_AUTH_FAILED);

    if (wlan.reassoc_control)
    {
        wlcm_request_reconnect(next, network);
    }
}

static void wlcm_process_deauthentication_event(struct wifi_message *msg,
                                                enum cm_sta_state *next,
                                                struct wlan_network *network)
{
#ifdef CONFIG_WPA2_ENTP
    wpa2_tls_cleanup(network, false);
#endif
    if (wlan.cm_ieeeps_configured)
    {
        /* disable ieeeps mode*/
        wlan_ieeeps_sm(IEEEPS_EVENT_DISABLE);
    }
#ifdef CONFIG_P2P
    wifi_wfd_event(false, false, NULL);
#endif
}

static void wlcm_process_net_dhcp_config(struct wifi_message *msg,
                                         enum cm_sta_state *next,
                                         struct wlan_network *network)
{
    /* We have received a response from the embedded DHCP client.  If
     * successful, we now have a DHCP lease and can update our IP address
     * information and procceed to the CM_STA_CONNECTED state, otherwise we
     * failed to obtain a DHCP lease and report that we failed to connect.
     *
     * This event is only relevant if we are attempting a connection and
     * are in the CM_STA_OBTAINING_ADDRESS state (due to configuring the TCP
     * stack with DHCP), otherwise we ignore it. */

    void *if_handle = NULL;
    // wakelock_put(WL_ID_CONNECT);
    wlan.connect_wakelock_taken = false;
    if (wlan.sta_ipv4_state == CM_STA_OBTAINING_ADDRESS)
    {
        if (msg->reason != WIFI_EVENT_REASON_SUCCESS)
        {
#ifdef CONFIG_WMSTATS
            g_wm_stats.wm_dhcp_fail++;
#endif /* CONFIG_WMSTATS */
            wlcm_d("got event: DHCP failure");
#ifdef CONFIG_IPV6
            if (wlan.sta_ipv6_state != CM_STA_CONNECTED)
            {
#endif
                if (wlan.cm_ieeeps_configured)
                {
                    /* if dhcp address fails,
                     * disable ieeeps mode*/
                    wlan_ieeeps_sm(IEEEPS_EVENT_DISABLE);
                }

                // wlan_disconnect();
#ifdef CONFIG_WLAN_FAST_PATH
                /* Mark the fast path cache invalid. */
                wlan.auth_cache_valid      = false;
                wlan.fast_path_cache_valid = false;
#endif /* CONFIG_WLAN_FAST_PATH */

                do_connect_failed(WLAN_REASON_ADDRESS_FAILED);

                if (wlan.reassoc_control)
                    wlcm_request_reconnect(next, network);

                *next = wlan.sta_state;
#ifdef CONFIG_IPV6
            }
#endif
            return;
        }
        char ip[16];
#ifdef CONFIG_WMSTATS
        g_wm_stats.wm_dhcp_succ++;
#endif /* CONFIG_WMSTATS */
        wlcm_d("got event: DHCP success");
        net_configure_dns(&network->ip, network->role);
        if (network->type == WLAN_BSS_TYPE_STA)
        {
            if_handle = net_get_mlan_handle();
        }
#ifdef CONFIG_P2P
        else if (network->type == WLAN_BSS_TYPE_WIFIDIRECT)
            if_handle = net_get_wfd_handle();
#endif /* CONFIG_P2P */
        (void)net_get_if_addr(&network->ip, if_handle);
        // net_inet_ntoa(network->ip.ipv4.address, ip);
        wlan.sta_state      = CM_STA_CONNECTED;
        *next               = CM_STA_CONNECTED;
        wlan.sta_ipv4_state = CM_STA_CONNECTED;

#ifdef CONFIG_WPS2
        wps_session_attempt = 0;
#endif
        if (wlan.reassoc_control && wlan.reassoc_request)
        {
            wlan.reassoc_count   = 0;
            wlan.reassoc_request = false;
        }

        CONNECTION_EVENT(WLAN_REASON_SUCCESS, &ip);
#ifdef CONFIG_P2P
        wifi_wfd_event(false, false, (void *)1);
#endif
    }
    else
    {
        wlcm_d("got event from dhcp client %d", msg->reason);
        if (msg->reason != WIFI_EVENT_REASON_SUCCESS)
        {
#ifdef CONFIG_WMSTATS
            g_wm_stats.wm_leas_fail++;
#endif      /* CONFIG_WMSTATS */
            /* There was some problem with dhcp lease
             * renewal, so just disconnect from wlan.
             */

#ifdef CONFIG_IPV6
            /* Do not disconnect-connect if the STA interface has
             * obtained IPv6 address */
            if (wlan.sta_ipv6_state != CM_STA_CONNECTED)
            {
#endif
                wlcm_d("Lease renewal failed, disconnecting");

                if (wlan.cm_ieeeps_configured)
                {
                    /* if lease renewal fails,
                     * disable ieeeps mode*/
                    wlan_ieeeps_sm(IEEEPS_EVENT_DISABLE);
                }

                // wlan_disconnect();
#ifdef CONFIG_WLAN_FAST_PATH
                /* Mark the fast path cache invalid. */
                wlan.auth_cache_valid      = false;
                wlan.fast_path_cache_valid = false;
#endif /* CONFIG_WLAN_FAST_PATH */

                do_connect_failed(WLAN_REASON_ADDRESS_FAILED);

                if (wlan.reassoc_control)
                    wlcm_request_reconnect(next, network);

                *next = wlan.sta_state;
#ifdef CONFIG_IPV6
            }
#endif
            return;
        }
#ifdef CONFIG_WMSTATS
        g_wm_stats.wm_leas_succ++;
#endif /* CONFIG_WMSTATS */
        /* Successful in getting ip address, so update
         * local wlan-info params */
        wlcm_d("update wlan-info params");
        if (network->type == WLAN_BSS_TYPE_STA)
        {
            if_handle = net_get_mlan_handle();
        }
#ifdef CONFIG_P2P
        else if (network->type == WLAN_BSS_TYPE_WIFIDIRECT)
        {
            if_handle = net_get_wfd_handle();
        }
        else
        {
            /*Do nothing*/
        }
#endif /* CONFIG_P2P */
        (void)net_get_if_addr(&network->ip, if_handle);
        CONNECTION_EVENT(WLAN_REASON_ADDRESS_SUCCESS, NULL);
    }
}

#ifdef CONFIG_IPV6
static void wlcm_process_net_ipv6_config(struct wifi_message *msg,
                                         enum cm_sta_state *next,
                                         struct wlan_network *network)
{
    void *if_handle = net_get_mlan_handle();
    int i, found = 0;
    if (network->type != WLAN_BSS_TYPE_STA || !if_handle)
        return;

    net_get_if_ipv6_addr(&network->ip, if_handle);
    for (i = 0; i < CONFIG_MAX_IPV6_ADDRESSES; i++)
    {
        if (network->ip.ipv6[i].addr_state == IP6_ADDR_PREFERRED && i != 0)
        {
            found++;
            /* Not considering link-local address as of now */
            if (wlan.sta_ipv6_state != CM_STA_CONNECTED)
            {
                wlan.sta_ipv6_state = CM_STA_CONNECTED;
                wlan.sta_state      = CM_STA_CONNECTED;
                *next               = CM_STA_CONNECTED;

                if (wlan.reassoc_control && wlan.reassoc_request)
                {
                    wlan.reassoc_count   = 0;
                    wlan.reassoc_request = false;
                }
                CONNECTION_EVENT(WLAN_REASON_SUCCESS, NULL);
            }
        }
    }

    if (wlan.sta_ipv6_state >= CM_STA_OBTAINING_ADDRESS && !found)
    {
        /* If the state is either obtaining address or connected and
         * if none of the IP addresses is preferred, then
         * change/maintain the state to obtaining address */
        wlan.sta_ipv6_state = CM_STA_OBTAINING_ADDRESS;
    }
}
#endif /* CONFIG_IPV6 */

#define MAX_RETRY_TICKS 50

static void wlcm_process_net_if_config_event(struct wifi_message *msg, enum cm_sta_state *next)
{
    if (wlan.sta_state != CM_STA_INITIALIZING)
    {
        wlcm_d("ignoring TCP configure response");
        return;
    }

    if (msg->reason != WIFI_EVENT_REASON_SUCCESS)
    {
        wlcm_e("Interfaces init failed");
        CONNECTION_EVENT(WLAN_REASON_INITIALIZATION_FAILED, NULL);
        /* stay here until user re-inits */
        *next = CM_STA_INITIALIZING;
        return;
    }

    wlan.sta_state = CM_STA_IDLE;
    *next          = CM_STA_IDLE;

    /* If WIFI is in deepsleep on  exit from PM4 disable dee-psleep */

    *next = CM_STA_IDLE;
#ifdef CONFIG_P2P
    /* This call is made to initiate WFD, We are not interested
     * in the response since mac addr is already populated in
     * wlan_start
     */
    wifi_get_wfd_mac_address();
#endif

#ifdef OTP_CHANINFO
    (void)wifi_get_fw_region_and_cfp_tables();
#endif

    (void)wifi_get_uap_max_clients(&wlan.uap_supported_max_sta_num);

    (void)wrapper_wlan_cmd_get_hw_spec();

    wlan_ed_mac_ctrl_t wlan_ed_mac_ctrl;

#ifdef SD8801
    wlan_ed_mac_ctrl.ed_ctrl_2g   = 0x1;
    wlan_ed_mac_ctrl.ed_offset_2g = 0x1b;
#elif defined(SD8977) || defined(SD8978) || defined(SD8987) || defined(SD8997) || defined(SD9097) || \
    defined(SD9098) || defined(IW61x)
    wlan_ed_mac_ctrl.ed_ctrl_2g   = 0x1;
    wlan_ed_mac_ctrl.ed_offset_2g = 0x9;
#ifdef CONFIG_5GHz_SUPPORT
    wlan_ed_mac_ctrl.ed_ctrl_5g   = 0x1;
    wlan_ed_mac_ctrl.ed_offset_5g = 0xC;
#endif
#endif

    (void)wlan_set_ed_mac_mode(wlan_ed_mac_ctrl);

    (void)wifi_enable_ecsa_support();

    //		uint16_t ant = 1; //board_antenna_select();
    //                if (board_antenna_switch_ctrl())
    //			rfctrl_set_config(ant);

#ifdef STREAM_2X2
    uint8_t tx_antenna = 3, rx_antenna = 3;

    ret = wifi_set_antenna(tx_antenna, rx_antenna);
    if (ret != WM_SUCCESS)
    {
        wlcm_e("Failed to set antenna configuration");
        return;
    }
    wlcm_d("Antenna selected: tx: %d, rx:%x", tx_antenna, rx_antenna);
#if 0
    uint16_t httxcfg = 0x1FF;

    ret = wifi_set_11n_cfg(httxcfg);
    if (ret != WM_SUCCESS) {
	    wlcm_e("Failed to set 11n ht tx configuration");
	    return;
    }
#endif

#ifdef CONFIG_11AC
    uint32_t vhtcap     = 0x33D179B0;
    uint16_t tx_mcs_map = 0xfffa;
    uint16_t rx_mcs_map = 0xfffa;

    ret = wifi_set_11ac_cfg(vhtcap, tx_mcs_map, rx_mcs_map);
    if (ret != WM_SUCCESS)
    {
        wlcm_e("Failed to set 11ac configuration");
        return;
    }
#endif
#else
#if defined(SD8801)
    uint32_t ant                  = 1;
    uint16_t evaluate_time        = 0x1770;

    int ret = wifi_set_antenna(ant, evaluate_time);
    if (ret != WM_SUCCESS)
    {
        wlcm_e("Failed to set antenna configuration");
        return;
    }
    wlcm_d("Antenna selected: %d", ant);
#endif /* defined(SD8801) */
#endif

#ifdef CONFIG_5GHz_SUPPORT
    uint16_t httxcfg = 0x62;

    int ret = wlan_set_httxcfg(httxcfg);
    if (ret != WM_SUCCESS)
    {
        wlcm_e("Failed to set HT TX configuration");
        return;
    }
    wlcm_d("HT TX configuration selected: %x", httxcfg);
#endif

    wifi_set_packet_retry_count(MAX_RETRY_TICKS);
}

static enum cm_uap_state uap_state_machine(struct wifi_message *msg)
{
    struct wlan_network *network = NULL;
    enum cm_uap_state next       = wlan.uap_state;
    int ret                      = 0;
    void *if_handle              = NULL;

    network = &wlan.networks[wlan.cur_uap_network_idx];

    switch (msg->event)
    {
        case CM_UAP_USER_REQUEST_START:
            wlan.cur_uap_network_idx = (int)msg->data;
            wlan.scan_count          = 0;

            (void)do_start(&wlan.networks[wlan.cur_uap_network_idx]);
            next = wlan.uap_state;
            break;
        case CM_UAP_USER_REQUEST_STOP:
            if (wlan.uap_state < CM_UAP_CONFIGURED)
            {
                break;
            }

            (void)do_stop(&wlan.networks[wlan.cur_uap_network_idx]);
            next = wlan.uap_state;
            break;
        case WIFI_EVENT_UAP_STARTED:
            if (!is_uap_state(CM_UAP_CONFIGURED))
            {
                wlcm_w(
                    "Ignoring address config event as uap not "
                    "in configured state");
                break;
            }

            if (msg->reason == WIFI_EVENT_REASON_SUCCESS)
            {
                if (network->type == WLAN_BSS_TYPE_UAP)
                {
                    (void)memcpy((void *)&network->bssid[0], (const void *)&wlan.mac[0], 6);
                    if_handle = net_get_uap_handle();
                }
#ifdef CONFIG_P2P
                else if (network->type == WLAN_BSS_TYPE_WIFIDIRECT)
                {
                    (void)memcpy((void *)&network->bssid[0], (const void *)&wlan.wfd_mac[0], 6);
                    if_handle = net_get_wfd_handle();
                }
#endif /* CONFIG_P2P */

                ret = net_configure_address(&network->ip, if_handle);
                if (ret != 0)
                {
                    wlcm_e("TCP/IP stack setup failed");
                    CONNECTION_EVENT(WLAN_REASON_ADDRESS_FAILED, (void *)ret);
                }
                else
                {
                    next = CM_UAP_STARTED;
                }
            }
            else
            {
                CONNECTION_EVENT(WLAN_REASON_UAP_START_FAILED, NULL);
            }
            break;
        case WIFI_EVENT_UAP_CLIENT_ASSOC:
#ifdef CONFIG_WIFI_UAP_WORKAROUND_STICKY_TIM
            if (network->type == WLAN_BSS_TYPE_UAP)
            {
                wifi_uap_enable_sticky_bit(msg->data);
            }
#endif /* CONFIG_WIFI_UAP_WORKAROUND_STICKY_TIM */
            CONNECTION_EVENT(WLAN_REASON_UAP_CLIENT_ASSOC, msg->data);
            /* This was allocated by the sender */
            os_mem_free(msg->data);
            break;
        case WIFI_EVENT_UAP_CLIENT_DEAUTH:
            CONNECTION_EVENT(WLAN_REASON_UAP_CLIENT_DISSOC, msg->data);
            /* This was allocated by the sender */
            os_mem_free(msg->data);
            break;
        case WIFI_EVENT_UAP_STOPPED:
            CONNECTION_EVENT(WLAN_REASON_UAP_STOPPED, NULL);
            break;
        case WIFI_EVENT_UAP_NET_ADDR_CONFIG:
            if (!is_uap_state(CM_UAP_STARTED))
            {
                wlcm_w(
                    "Ignoring address config event as uap not "
                    "in started state");
                break;
            }

            if (msg->reason == WIFI_EVENT_REASON_SUCCESS && network->ip.ipv4.addr_type == ADDR_TYPE_STATIC)
            {
                if (network->type == WLAN_BSS_TYPE_UAP)
                {
                    if_handle = net_get_uap_handle();
                }
#ifdef CONFIG_P2P
                else if (network->type == WLAN_BSS_TYPE_WIFIDIRECT)
                {
                    if_handle = net_get_wfd_handle();
                }
                else
                {
                    /*Do Nothing*/
                }
#endif /* CONFIG_P2P */

                (void)net_get_if_addr(&network->ip, if_handle);
#ifdef CONFIG_IPV6
                (void)net_get_if_ipv6_addr(&network->ip, if_handle);
#endif
                next = CM_UAP_IP_UP;
                CONNECTION_EVENT(WLAN_REASON_UAP_SUCCESS, NULL);
            }
            else
            {
                CONNECTION_EVENT(WLAN_REASON_ADDRESS_FAILED, NULL);
                next = CM_UAP_INITIALIZING;
            }
            break;
        default:
            wlcm_w("got unknown message  UAP  : %d", msg->event);
            break;
    }
    return next;
}

static void wlcm_request_scan(struct wifi_message *msg, enum cm_sta_state *next)
{
    if (msg->data == NULL)
    {
        wlcm_w("ignoring scan request with NULL scan params");
        wlcm_d("releasing scan lock");
        (void)os_semaphore_put(&wlan.scan_lock);
        wlan.is_scan_lock = 0;
        return;
    }

    wlan_scan_params_v2_t *wlan_scan_param = (wlan_scan_params_v2_t *)msg->data;

    if ((!is_scanning_allowed())
#ifdef CONFIG_WPS2
        || (wps_session_attempt)
#endif
    )
    {
        wlcm_w("ignoring scan result in invalid state");
        wlcm_d("releasing scan lock");
        /* Free allocated wifi scan parameters */
        os_mem_free(wlan_scan_param);
        (void)os_semaphore_put(&wlan.scan_lock);
        wlan.is_scan_lock = 0;
        return;
    }

    wlcm_d("initiating wlan-scan (return to %s)", dbg_sta_state_name(wlan.sta_state));

    int ret = wifi_send_scan_cmd(g_wifi_scan_params.bss_type, wlan_scan_param->bssid,
#ifdef CONFIG_COMBO_SCAN
                                wlan_scan_param->ssid[0], wlan_scan_param->ssid[1],
#else
                                wlan_scan_param->ssid, NULL,
#endif
                                wlan_scan_param->num_channels, wlan_scan_param->chan_list, wlan_scan_param->num_probes,
                                 false, false);
    if (ret != WM_SUCCESS)
    {
        wlcm_e("wifi send scan cmd failed");
        *next = wlan.sta_state;
        wlcm_d("releasing scan lock");
        (void)os_semaphore_put(&wlan.scan_lock);
        wlan.is_scan_lock = 0;
    }
    else
    {
        wlan.scan_cb       = (int (*)(unsigned int count))(wlan_scan_param->cb);
        wlan.sta_return_to = wlan.sta_state;
        *next              = CM_STA_SCANNING_USER;
    }
    /* Free allocated wifi scan parameters */
    os_mem_free(wlan_scan_param);
}

static void wlcm_deinit(int action)
{
    if ((wlan.status != WLCMGR_ACTIVATED) && (wlan.status != WLCMGR_INIT_DONE))
    {
        wlcm_e("cannot deinit wlcmgr. unexpected status: %d\n\r", wlan.status);
        return;
    }

    wifi_deinit();

    wlan.status = WLCMGR_INACTIVE;
}

static void wlcm_request_disconnect(enum cm_sta_state *next, struct wlan_network *curr_nw)
{
    void *if_handle = NULL;
    /* On disconnect request, we need to take down the interface.
       This is required to fix bug # 52964 */
    if (curr_nw->type == WLAN_BSS_TYPE_STA)
    {
        if_handle = net_get_mlan_handle();
    }
#ifdef CONFIG_P2P
    else if (curr_nw->type == WLAN_BSS_TYPE_WIFIDIRECT)
    {
        if_handle = net_get_wfd_handle();
    }
    else
    {
        /* Do Nothing */
    }
#endif /* CONFIG_P2P */
    if (if_handle == NULL)
    {
        wlcm_w("No interface is up\r\n");
        return;
    }
    /* Forcefully stop dhcp on given interface.
     * net_interface_dhcp_stop internally does nothing
     * if dhcp client is not started.
     */
    net_interface_dhcp_stop(if_handle);
    net_interface_down(if_handle);

    if (
#ifdef CONFIG_WPS2
        (!wps_session_attempt) &&
#endif
        (wlan.sta_state < CM_STA_IDLE || is_state(CM_STA_IDLE) || is_state(CM_STA_DEEP_SLEEP)))
    {
        (void)os_rwlock_read_unlock(&ps_rwlock);
        wifi_set_xfer_pending(false);
        // wakelock_put(WL_ID_STA_DISCONN);
        return;
    }

    if (is_user_scanning() && wlan.sta_return_to != CM_STA_IDLE)
    {
        /* we're in a user scan: we'll need to disconnect and
         * return to the idle state once this scan completes */
        if (wlan.sta_return_to >= CM_STA_ASSOCIATING)
        {
            (void)wifi_deauthenticate((uint8_t *)curr_nw->bssid);
            wlan.sta_return_to  = CM_STA_IDLE;
            *next               = CM_STA_IDLE;
            wlan.sta_ipv4_state = CM_STA_IDLE;
#ifdef CONFIG_IPV6
            wlan.sta_ipv6_state = CM_STA_IDLE;
#endif
        }
    }
    else if (wlan.sta_state >= CM_STA_ASSOCIATING)
    {
        /* if we aren't idle or user scanning,
         * we'll need to actually
         * disconnect */
        (void)wifi_deauthenticate((uint8_t *)curr_nw->bssid);
        wlan.sta_state      = CM_STA_IDLE;
        *next               = CM_STA_IDLE;
        wlan.sta_ipv4_state = CM_STA_IDLE;
#ifdef CONFIG_IPV6
        wlan.sta_ipv6_state = CM_STA_IDLE;
#endif
    }
    else if (wlan.sta_state == CM_STA_SCANNING)
    {
        wlan.sta_state      = CM_STA_IDLE;
        *next               = CM_STA_IDLE;
        wlan.sta_ipv4_state = CM_STA_IDLE;
#ifdef CONFIG_IPV6
        wlan.sta_ipv6_state = CM_STA_IDLE;
#endif
    }
    else
    { /* Do Nothing */
    }

#ifndef CONFIG_WPA2_ENTP
#ifdef CONFIG_WPS2
    if (wps_session_attempt)
    {
        CONNECTION_EVENT(WLAN_REASON_WPS_DISCONNECT, NULL);
        wps_session_attempt = 0;
    }
    else
#endif
#endif
        CONNECTION_EVENT(WLAN_REASON_USER_DISCONNECT, NULL);

    if (wlan.reassoc_control && wlan.reassoc_request)
    {
        wlan.scan_count      = WLAN_RESCAN_LIMIT;
        wlan.reassoc_count   = WLAN_RECONNECT_LIMIT;
        wlan.reassoc_request = false;
    }

    if (wlan.connect_wakelock_taken)
    {
        // wakelock_put(WL_ID_CONNECT);
        wlan.connect_wakelock_taken = false;
    }
    (void)os_rwlock_read_unlock(&ps_rwlock);
    wifi_set_xfer_pending(false);
    // wakelock_put(WL_ID_STA_DISCONN);
}

static void wlcm_request_connect(struct wifi_message *msg, enum cm_sta_state *next, struct wlan_network *network)
{
    int ret;
    struct wlan_network *new_network = &wlan.networks[(int)msg->data];

    // wakelock_get(WL_ID_CONNECT);
    wlan.connect_wakelock_taken = true;
#ifdef CONFIG_WLAN_FAST_PATH
    /* Mark the fast path cache invalid. */
    if ((int)msg->data != wlan.cur_network_idx)
        wlan.auth_cache_valid = false;
#endif /* CONFIG_WLAN_FAST_PATH */

    (void)wlan_set_pmfcfg(new_network->security.mfpc, new_network->security.mfpr);

    if (is_state(CM_STA_DEEP_SLEEP))
    {
        /* Release the connect scan lock as scanning is not allowed,
         * when Wi-Fi firmware is in deep sleep or power down mode
         */
        if (wlan.is_scan_lock)
        {
            wlcm_d("releasing scan lock (connect scan)");
            (void)os_semaphore_put(&wlan.scan_lock);
            wlan.is_scan_lock = 0;
        }
        return;
    }

    if (wlan.sta_state >= CM_STA_ASSOCIATING)
    {
        if (new_network->role == WLAN_BSS_ROLE_STA)
        {
            wlcm_d(
                "deauthenticating before"
                " attempting new connection");
            (void)wifi_deauthenticate((uint8_t *)network->bssid);
        }
    }

    wlcm_d("starting connection to network: %d", (int)msg->data);

    ret = do_connect((int)msg->data);

    /* Release the connect scan lock if do_connect fails,
     * in successful case it gets freed in scan result event.
     */
    if (ret != WM_SUCCESS)
    {
        if (wlan.is_scan_lock)
        {
            wlcm_d("releasing scan lock (connect scan)");
            (void)os_semaphore_put(&wlan.scan_lock);
            wlan.is_scan_lock = 0;
        }
        CONNECTION_EVENT(WLAN_REASON_CONNECT_FAILED, NULL);
    }

    *next = wlan.sta_state;
}

static void wlcm_request_reconnect(enum cm_sta_state *next, struct wlan_network *network)
{
    struct wifi_message msg;
    msg.event  = 0;
    msg.reason = 0;
    msg.data   = (void *)(wlan.cur_network_idx);

    wlcm_d("Reconnect in progress ...");

    wlan.reassoc_request = true;

    if (wlan.reassoc_count < WLAN_RECONNECT_LIMIT)
    {
        wlcm_d("Reconnect attempt # %d", wlan.reassoc_count + 1);
        wlan.reassoc_count++;
        wlcm_request_connect(&msg, next, network);
    }
    else
    {
        wlcm_d("Reconnection failed. Giving up.");
        wlan.reassoc_request = false;
        wlan.reassoc_count   = 0;

        wlcm_d("Disconnecting ... ");
        (void)wlan_disconnect();
    }
}

#ifdef CONFIG_WIFI_FW_DEBUG
static void wlcm_process_fw_debug_info(struct wifi_message *msg)
{
    (void)PRINTF("EVENT: FW Debug Info %s\r\n", msg->data);
    os_mem_free(msg->data);
}
#endif

/*
 * Event Handlers
 */

static enum cm_sta_state handle_message(struct wifi_message *msg)
{
    enum cm_sta_state next       = wlan.sta_state;
    struct wlan_network *network = NULL;

    network = &wlan.networks[wlan.cur_network_idx];

    switch (msg->event)
    {
        case CM_STA_USER_REQUEST_CONNECT:
            wlan.pending_assoc_request = false;
            if (!wlan.assoc_paused)
            {
                wlcm_request_connect(msg, &next, network);
            }
            else
            {
                wlan.pending_assoc_request = true;
            }
            break;

        case CM_STA_USER_REQUEST_DISCONNECT:
            wlcm_request_disconnect(&next, network);
            break;

        case CM_STA_USER_REQUEST_SCAN:
            wlcm_request_scan(msg, &next);
            break;

        case CM_STA_USER_REQUEST_PS_ENTER:
            if (wlan.sta_state >= CM_STA_SCANNING && wlan.sta_state <= CM_STA_OBTAINING_ADDRESS)
            {
                wlcm_w("ignoring ps enter in invalid state");
                wlcm_e("Error entering power save mode");
                break;
            }
            if (msg->data == NULL)
            {
                wlcm_w("ignoring ps enter request with NULL ps mode");
                wlcm_e("entering power save mode");
                break;
            }
            wlan_enable_power_save((int)msg->data);
            break;
        case CM_STA_USER_REQUEST_PS_EXIT:
            if (msg->data == NULL)
            {
                wlcm_w("ignoring ps exit request with NULL ps mode");
                break;
            }
            wlan_disable_power_save((int)msg->data);
            break;
        case WIFI_EVENT_SCAN_RESULT:
            wlcm_d("got event: scan result");
            wlcm_process_scan_result_event(msg, &next);
            break;

        case WIFI_EVENT_ASSOCIATION:
            wlcm_d("got event: association result: %s",
                   msg->reason == WIFI_EVENT_REASON_SUCCESS ? "success" : "failure");

            wlcm_process_association_event(msg, &next);
            break;
        case WIFI_EVENT_PMK:
            wlcm_d("got event: PMK result: %s", msg->reason == WIFI_EVENT_REASON_SUCCESS ? "success" : "failure");
            wlcm_process_pmk_event(msg, &next, network);
            break;
            /* We have received a event from firmware whether
             * authentication with given wireless credentials was successful
             * or not. If successful, we are authenticated and can proceed
             * to IP-level setup by configuring the TCP stack for our
             * desired address and transitioning to the
             * CM_STA_REQUESTING_ADDRESS state where we wait for the TCP
             * stack configuration response.  Otherwise we have failed to
             * connect to the network.
             */
        case WIFI_EVENT_AUTHENTICATION:
            wlcm_d("got event: authentication result: %s",
                   msg->reason == WIFI_EVENT_REASON_SUCCESS ? "success" : "failure");
            wlcm_process_authentication_event(msg, &next, network);
            break;

        case WIFI_EVENT_LINK_LOSS:
            wlcm_d("got event: link loss, code=%d", (int)msg->data);
            wlcm_process_link_loss_event(msg, &next, network);
            break;
#ifdef CONFIG_WLAN_BRIDGE
        case WIFI_EVENT_AUTOLINK_NETWORK_SWITCHED:
            wlcm_d("got event: auto link switch network");
            wlcm_process_network_switch_event(msg, &next, network);
            break;
#endif
        case WIFI_EVENT_DISASSOCIATION:
            wlcm_d("got event: disassociation, code=%d", (int)(msg->data));
            wlcm_process_disassoc_event(msg, &next, network);
            break;

        case WIFI_EVENT_DEAUTHENTICATION:
            wlcm_d("got event: deauthentication");
            wlcm_process_deauthentication_event(msg, &next, network);
            break;

        case WIFI_EVENT_NET_STA_ADDR_CONFIG:
            wlcm_d("got event: TCP configured");
            wlcm_process_sta_addr_config_event(msg, &next, network);
            break;

        case WIFI_EVENT_GET_HW_SPEC:
            CONNECTION_EVENT(WLAN_REASON_INITIALIZED, NULL);
            break;

        case WIFI_EVENT_NET_INTERFACE_CONFIG:
            wlcm_d("got event: Interfaces configured");
            wlcm_process_net_if_config_event(msg, &next);
            break;

        case WIFI_EVENT_NET_DHCP_CONFIG:
            wlcm_process_net_dhcp_config(msg, &next, network);
            break;
#ifdef CONFIG_IPV6
        case WIFI_EVENT_NET_IPV6_CONFIG:
            wlcm_process_net_ipv6_config(msg, &next, network);
            break;
#endif /* CONFIG_IPV6 */
        case WIFI_EVENT_CHAN_SWITCH_ANN:
            wlcm_d("got event: channel switch announcement");
            wlcm_process_channel_switch_ann(&next, network);
            break;
        case WIFI_EVENT_CHAN_SWITCH:
            wlcm_d("got event: channel switch");
            wlcm_process_channel_switch(msg);
            break;
        case WIFI_EVENT_SLEEP:
            wlcm_d("got event: sleep");
            wlan_ieeeps_sm(IEEEPS_EVENT_SLEEP);
            wlan_deepsleepps_sm(DEEPSLEEPPS_EVENT_SLEEP);
            break;
        case WIFI_EVENT_AWAKE:
            wlcm_d("got event: awake");
            wlcm_process_awake_event();
            break;

        case WIFI_EVENT_IEEE_PS:
            wlcm_d("got event: IEEE ps result: %s", msg->reason == WIFI_EVENT_REASON_SUCCESS ? "success" : "failure");
            wlcm_process_ieeeps_event(msg);
            break;

        case WIFI_EVENT_DEEP_SLEEP:
            wlcm_d("got event: deep sleep result: %s",
                   msg->reason == WIFI_EVENT_REASON_SUCCESS ? "success" : "failure");
            wlcm_process_deepsleep_event(msg, &next);
            break;
        /* fixme : This will be removed later
         * We do not allow HS config without IEEEPS */
        case WIFI_EVENT_HS_CONFIG:
            if (wlan.hs_configured)
                wlcm_process_hs_config_event();
            break;
#ifdef CONFIG_11N
        case WIFI_EVENT_11N_ADDBA:
            wlcm_process_addba_request(msg);
            break;
        case WIFI_EVENT_11N_DELBA:
            wlcm_process_delba_request(msg);
            break;
        case WIFI_EVENT_11N_BA_STREAM_TIMEOUT:
            wlcm_process_ba_stream_timeout_request(msg);
            break;
        case WIFI_EVENT_11N_AGGR_CTRL:
            wlcm_d("AGGR_CTRL ignored for now");
            break;
#endif /* CONFIG_11N */
        case WIFI_EVENT_MAC_ADDR_CONFIG:
            if (msg->data != NULL)
            {
                (void)memcpy((void *)&wlan.mac[0], (const void *)msg->data, MLAN_MAC_ADDR_LENGTH);
                os_mem_free(msg->data);
            }
            break;
#ifdef CONFIG_WIFI_FW_DEBUG
        case WIFI_EVENT_FW_DEBUG_INFO:
            wlcm_d("got event: fw debug info");
            wlcm_process_fw_debug_info(msg);
            break;
#endif
        default:
            wlcm_w("got unknown message: %d", msg->event);
            break;
    }

    return next;
}

static int is_uap_msg(struct wifi_message *msg)
{
    return (((msg->event >= CM_UAP_USER_REQUEST_START) && (msg->event < CM_WLAN_USER_REQUEST_DEINIT)) ||
            (msg->event <= WIFI_EVENT_UAP_LAST));
}

/*
 * Main Thread: the WLAN Connection Manager event queue handler and state
 * machine.
 */

static void cm_main(os_thread_arg_t data)
{
    int ret;
    struct wifi_message msg;
    enum cm_sta_state next_sta_state;
    enum cm_uap_state next_uap_state;

    /* Wait for all the data structures to be created */
    while (!wlan.running)
    {
        os_thread_sleep(os_msec_to_ticks(500));
    }

    (void)net_wlan_init();

    while (true)
    {
        /* If delayed sleep confirmed should be performed, wait for
           DELAYED_SLP_CFM_DUR else wait forever */
        ret = os_queue_recv(&wlan.events, &msg,
                            os_msec_to_ticks(g_req_sl_confirm ? DELAYED_SLP_CFM_DUR : OS_WAIT_FOREVER));

        if (wlan.stop_request != 0U)
        {
            wlcm_d("Received shutdown request\n\r");
            wlan.status = WLCMGR_THREAD_STOPPED;
            os_thread_self_complete(NULL);
        }

        if (ret == WM_SUCCESS)
        {
            wlcm_d("got wifi message: %d %d %p", msg.event, msg.reason, msg.data);

            if (is_uap_msg(&msg) != 0)
            {
                /* uAP related msg */
                next_uap_state = uap_state_machine(&msg);
                if (wlan.uap_state == next_uap_state)
                {
                    continue;
                }

                wlcm_d("SM uAP %s -> %s", dbg_uap_state_name(wlan.uap_state), dbg_uap_state_name(next_uap_state));
                wlan.uap_state = next_uap_state;
            }
            else if (msg.event == CM_WLAN_USER_REQUEST_DEINIT)
            {
                wlcm_deinit((int)msg.data);
            }
            else
            {
                /* STA related msg */
                next_sta_state = handle_message(&msg);
                if (wlan.sta_state == next_sta_state)
                {
                    continue;
                }

                wlcm_d("SM STA %s -> %s", dbg_sta_state_name(wlan.sta_state), dbg_sta_state_name(next_sta_state));
                wlan.sta_state = next_sta_state;
            }
        }
        else
        {
            wlcm_d("SM queue recv Timed out ");

            if (!is_state(CM_STA_CONNECTED))
            {
                continue;
            }

            if (g_req_sl_confirm)
            {
                wlan_ieeeps_sm(IEEEPS_EVENT_SLEEP);
            }
        }
    }
}

/*
 * WLAN API
 */

static int send_user_request(enum user_request_type request, int data)
{
    struct wifi_message msg;

    msg.event  = request;
    msg.reason = 0;
    msg.data   = (void *)data;

    if (os_queue_send(&wlan.events, &msg, OS_NO_WAIT) == WM_SUCCESS)
    {
        return WM_SUCCESS;
    }

    return -WM_FAIL;
}

static void copy_network(struct wlan_network *dst, struct wlan_network *src)
{
    (void)memcpy((void *)dst, (const void *)src, sizeof(struct wlan_network));
    /* Omit any information that was dynamically
     * learned from the network so that users can
     * see which parameters were actually
     * configured by the user.
     */
    if (!src->bssid_specific)
    {
        (void)memset(dst->bssid, 0, IEEEtypes_ADDRESS_SIZE);
    }
    if (!src->ssid_specific)
    {
        (void)memset(dst->ssid, 0, IEEEtypes_SSID_SIZE);
    }
    if (!src->channel_specific)
    {
        dst->channel = 0;
    }
    if (src->ip.ipv4.addr_type != 0U)
    {
        dst->ip.ipv4.address = 0;
        dst->ip.ipv4.gw      = 0;
        dst->ip.ipv4.netmask = 0;
        dst->ip.ipv4.dns1    = 0;
        dst->ip.ipv4.dns2    = 0;
    }
}

static int ps_wakeup_card_cb(os_rw_lock_t *plock, unsigned int wait_time)
{
    int ret = os_semaphore_get(&(plock->rw_lock), 0);
    if (ret == -WM_FAIL)
    {
        wlan_wake_up_card();
        wifi_set_xfer_pending(true);
        ret = os_semaphore_get(&(plock->rw_lock), wait_time);
    }
    return ret;
}

int wlan_init(const uint8_t *fw_ram_start_addr, const size_t size)
{
    int ret;

    if (wlan.status != WLCMGR_INACTIVE)
    {
        return WM_SUCCESS;
    }

#ifdef OVERRIDE_CALIBRATION_DATA
    wlan_set_cal_data(ext_cal_data, sizeof(ext_cal_data));
#endif

#ifdef CONFIG_HOST_PMK
    wm_mbedtls_lib_init();
#endif /* CONFIG_HOST_PMK */

    ret = os_rwlock_create_with_cb(&ps_rwlock, "ps_mutex", "ps_lock", ps_wakeup_card_cb);
    ret = wifi_init(fw_ram_start_addr, size);
    if (ret != 0)
    {
        wlcm_e("wifi_init failed. status code %d", ret);
        return ret;
    }

    /* Set World Wide Safe Mode Tx Power Limits in Wi-Fi firmware */
    (void)wlan_set_wwsm_txpwrlimit();

    wlan.status = WLCMGR_INIT_DONE;
    wifi_mac_addr_t mac_addr;
    ret = wifi_get_device_mac_addr(&mac_addr);
    if (ret != WM_SUCCESS)
    {
        wlcm_e("Failed to get mac address");
        return ret;
    }

    (void)memcpy((void *)&wlan.mac[0], (const void *)mac_addr.mac, MLAN_MAC_ADDR_LENGTH);
    (void)PRINTF("MAC Address: ");
    print_mac((const char *)&wlan.mac);
    (void)PRINTF("\r\n");
#ifdef CONFIG_P2P
    (void)memcpy((void *)&wlan.wfd_mac[0], (const void *)mac_addr.mac, MLAN_MAC_ADDR_LENGTH);
    wlan.wfd_mac[0] |= (0x01 << 1);
#endif

    ret = wifi_get_device_firmware_version_ext(&wlan.fw_ver_ext);
    if (ret != WM_SUCCESS)
    {
        wlcm_e("Failed to get verext");
        return ret;
    }
    wlcm_d("WLAN FW ext_version: %s", wlan.fw_ver_ext.version_str);

#ifdef CONFIG_WIFI_FW_DEBUG
    if (wlan.wlan_usb_init_cb != NULL)
        wlan.wlan_usb_init_cb();
    else
        wifi_e("USB init callback is not registered");
#endif
    return ret;
}

void wlan_deinit(int action)
{
    if (wlan.running != 0U)
    {
        (void)send_user_request(CM_WLAN_USER_REQUEST_DEINIT, action);
    }
    else
    {
        wlcm_deinit(action);
    }
}

#ifdef CONFIG_WPA2_ENTP
#ifdef CONFIG_WPS2
static int wlcm_wps_callback(enum wps_event event, void *data, uint16_t len)
{
    int ret = WM_SUCCESS;

    wlcm_d("WPS EVENT = %d data = %p len=%d", event, data, len);

    if (event == WPS_SESSION_SUCCESSFUL)
    {
        if (!data)
            return -WM_FAIL;

        ret = wlan_wlcmgr_send_msg(WIFI_EVENT_PMK, WIFI_EVENT_REASON_SUCCESS, data);
    }
    else if (event == WPS_SESSION_TIMEOUT || event == WPS_SESSION_FAILED)
    {
        ret =
            wlan_wlcmgr_send_msg(WIFI_EVENT_AUTHENTICATION, WIFI_EVENT_REASON_FAILURE, (void *)WPA2_ENTERPRISE_FAILED);
    }

    return ret;
}

static struct wps_config wps_conf = {
    .role                    = 1,
    .pin_generator           = 1,
    .version                 = 0x20,
    .version2                = 0x20,
    .device_name             = "NXP-Embedded-Client",
    .manufacture             = "NXP",
    .model_name              = "RD-88W-PLUG-8787-A0",
    .model_number            = "0001",
    .serial_number           = "0001",
    .config_methods          = 0x2388,
    .primary_dev_category    = 01,
    .primary_dev_subcategory = 01,
    .rf_bands                = 1,
    .os_version              = 0xFFFFFFFF,
    .wps_msg_max_retry       = 5,
    .wps_msg_timeout         = 5000,
    .pin_len                 = 8,
    .wps_callback            = wlcm_wps_callback,
};
#endif
#endif

static void assoc_timer_cb(os_timer_arg_t arg)
{
    wlan.assoc_paused = false;
    if (wlan.pending_assoc_request)
    {
        (void)send_user_request(CM_STA_USER_REQUEST_CONNECT, 0);
    }
}

int wlan_start(int (*cb)(enum wlan_event_reason reason, void *data))
{
    int ret;

    if (!((wlan.status == WLCMGR_INIT_DONE) || (wlan.status == WLCMGR_INACTIVE)))
    {
        wlcm_e("cannot start wlcmgr. unexpected status: %d", wlan.status);
        return WLAN_ERROR_STATE;
    }

    if (cb == NULL)
    {
        return -WM_E_INVAL;
    }

    if (wlan.running != 0U)
    {
        return WLAN_ERROR_STATE;
    }

    wlan.sta_state = CM_STA_INITIALIZING;

    wlan.sta_return_to = CM_STA_IDLE;
    wlan.uap_state     = CM_UAP_INITIALIZING;
    wlan.uap_return_to = CM_UAP_INITIALIZING;

    wlan.reassoc_control = true;
    wlan.hidden_scan_on  = false;

    wlan.cm_ps_state          = PS_STATE_AWAKE;
    wlan.cm_ieeeps_configured = false;

    wlan.cm_deepsleepps_configured = false;

    wlan.wakeup_conditions = WAKE_ON_UNICAST | WAKE_ON_MAC_EVENT | WAKE_ON_MULTICAST | WAKE_ON_ARP_BROADCAST;

    wlan.cur_network_idx     = -1;
    wlan.cur_uap_network_idx = -1;

    wlan.num_networks = 0;
    (void)memset(&wlan.networks[0], 0, sizeof(wlan.networks));
    (void)memset(&wlan.scan_chan_list, 0, sizeof(wifi_scan_chan_list_t));
    wlan.scan_count        = 0;
    wlan.cb                = cb;
    wlan.scan_cb           = NULL;
    wlan.events_queue_data = g_wlan_event_queue_data;
    ret = os_queue_create(&wlan.events, "wlan-events", sizeof(struct wifi_message), &wlan.events_queue_data);
    if (ret != WM_SUCCESS)
    {
        wlcm_e("unable to create event queue: %d", ret);
        return -WM_FAIL;
    }

    ret = wifi_register_event_queue(&wlan.events);
    if (ret != 0)
    {
        wlcm_e("unable to register event queue");
        (void)os_queue_delete(&wlan.events);
        return -WM_FAIL;
    }

    wlan.cm_stack = g_cm_stack;
    ret           = os_thread_create(&wlan.cm_main_thread, "wlcmgr", cm_main, NULL, &wlan.cm_stack, OS_PRIO_3);

    if (ret != 0)
    {
        wlan.cb = NULL;
        (void)wifi_unregister_event_queue(&wlan.events);
        (void)os_queue_delete(&wlan.events);
        return -WM_FAIL;
    }

    if (os_semaphore_create(&wlan.scan_lock, "wlan-scan") != 0)
    {
        (void)wifi_unregister_event_queue(&wlan.events);
        (void)os_queue_delete(&wlan.events);
        (void)os_thread_delete(&wlan.cm_main_thread);
        return -WM_FAIL;
    }
    wlan.running = 1;

    wlan.status = WLCMGR_ACTIVATED;

#ifdef CONFIG_WPA2_ENTP
#ifdef CONFIG_WPS2
    wlcm_d("WPS started");
    wps_start(&wps_conf);
#endif
#endif

    ret = os_timer_create(&wlan.assoc_timer, "assoc-timer", os_msec_to_ticks(BAD_MIC_TIMEOUT), &assoc_timer_cb, NULL,
                          OS_TIMER_ONE_SHOT, OS_TIMER_NO_ACTIVATE);
    if (ret != WM_SUCCESS)
    {
        wlcm_e("Unable to start unicast bad mic timer");
        return ret;
    }

    return WM_SUCCESS;
}

int wlan_stop(void)
{
    int ret             = WM_SUCCESS;
    int total_wait_time = 1000; /* millisecs */
    int check_interval  = 200;  /* millisecs */
    int num_iterations  = total_wait_time / check_interval;

    if (wlan.status != WLCMGR_ACTIVATED)
    {
        wlcm_e("cannot stop wlcmgr. unexpected status: %d", wlan.status);
        return WLAN_ERROR_STATE;
    }

    if (!wlan.running)
    {
        return WLAN_ERROR_STATE;
    }
    wlan.running = 0;

    /* We need to wait for scan_lock as wifi scan might have been
     * scheduled, so it must be completed before deleting cm_main_thread
     * here. Otherwise deadlock situation might arrive as both of them
     * share command_lock semaphore.
     */
    ret = os_semaphore_get(&wlan.scan_lock, OS_WAIT_FOREVER);
    if (ret != WM_SUCCESS)
    {
        wlcm_w("failed to get scan lock: %d.", ret);
        return WLAN_ERROR_STATE;
    }

    ret = os_semaphore_delete(&wlan.scan_lock);
    if (ret != WM_SUCCESS)
    {
        wlcm_w("failed to delete scan lock: %d.", ret);
        return WLAN_ERROR_STATE;
    }

    wlan.is_scan_lock = 0;

    ret = os_timer_delete(&wlan.assoc_timer);
    if (ret != WM_SUCCESS)
    {
        wlcm_w("failed to delete multicast bad mic timer: %d.", ret);
        return WLAN_ERROR_STATE;
    }

    /* We need to tell the AP that we're going away, however we've already
     * stopped the main thread so we can't do this by means of the state
     * machine.  Unregister from the wifi interface and explicitly send a
     * deauth request and then proceed to tearing the main thread down. */

    /* Set stop_request and wait for wlcmgr thread to acknowledge it */
    wlan.stop_request = true;

    wlcm_d("Sent wlcmgr shutdown request. Current State: %d\r\n", wlan.status);

    while (wlan.status != WLCMGR_THREAD_STOPPED && --num_iterations)
    {
        os_thread_sleep(os_msec_to_ticks(check_interval));
    }

    if (wlan.status != WLCMGR_THREAD_STOPPED && !num_iterations)
    {
        wlcm_d("Timed out waiting for wlcmgr to stop\r\n");
        wlcm_d("Forcing halt for wlcmgr thread\r\n");
        /* Reinitiailize variable states */
        wlan.status = WLCMGR_THREAD_STOPPED;
    }

    wlan.stop_request = false;

    ret = wifi_unregister_event_queue(&wlan.events);

    if (ret != WM_SUCCESS)
    {
        wlcm_w("failed to unregister wifi event queue: %d", ret);
        return WLAN_ERROR_STATE;
    }

    ret = os_queue_delete(&wlan.events);

    if (ret != WM_SUCCESS)
    {
        wlcm_w("failed to delete event queue: %d", ret);
        return WLAN_ERROR_STATE;
    }

    if (wlan.sta_state > CM_STA_ASSOCIATING)
    {
        (void)wifi_deauthenticate((uint8_t *)wlan.networks[wlan.cur_network_idx].bssid);
        wlan.sta_return_to = CM_STA_IDLE;
    }
    if (wlan.uap_state > CM_UAP_CONFIGURED)
    {
        (void)wifi_uap_stop(wlan.networks[wlan.cur_uap_network_idx].type);
    }

    ret = os_thread_delete(&wlan.cm_main_thread);

    if (ret != WM_SUCCESS)
    {
        wlcm_w("failed to terminate thread: %d", ret);
        return WLAN_ERROR_STATE;
    }

#ifdef CONFIG_WLAN_FW_HEARTBEAT
    // wlan_fw_heartbeat_unregister_healthmon();
#endif

    wlan.status = WLCMGR_INACTIVE;
    wlcm_d("WLCMGR thread deleted\n\r");

    return ret;
}

#define DEF_UAP_IP 0xc0a80a01UL /* 192.168.10.1 */
static unsigned int uap_ip = DEF_UAP_IP;

void wlan_initialize_uap_network(struct wlan_network *net)
{
    (void)memset(net, 0, sizeof(struct wlan_network));
    /* Set profile name */
    (void)strcpy(net->name, "uap-network");
    /* Set channel selection to auto (0) */
    net->channel = 0;
    /* Set network type to uAP */
    net->type = WLAN_BSS_TYPE_UAP;
    /* Set network role to uAP */
    net->role = WLAN_BSS_ROLE_UAP;
    /* Set IP address to 192.168.10.1 */
    net->ip.ipv4.address = htonl(uap_ip);
    /* Set default gateway to 192.168.10.1 */
    net->ip.ipv4.gw = htonl(uap_ip);
    /* Set netmask to 255.255.255.0 */
    net->ip.ipv4.netmask = htonl(0xffffff00UL);
    /* Specify address type as static assignment */
    net->ip.ipv4.addr_type = ADDR_TYPE_STATIC;
}

int wlan_add_network(struct wlan_network *network)
{
    int pos = -1;
    unsigned int i;
    unsigned int len;
    int ret;

    if (network == NULL)
    {
        return -WM_E_INVAL;
    }

    if (network->role == WLAN_BSS_ROLE_STA)
    {
        if (is_running() && !is_state(CM_STA_IDLE) && !is_state(CM_STA_ASSOCIATED) && !is_state(CM_STA_CONNECTED))
        {
            return WLAN_ERROR_STATE;
        }
    }

    /* make sure that the network name length is acceptable */
    len = strlen(network->name);
    if (len < WLAN_NETWORK_NAME_MIN_LENGTH || len >= WLAN_NETWORK_NAME_MAX_LENGTH)
    {
        return -WM_E_INVAL;
    }

    /* make sure that either the SSID or BSSID field is present */
    if (network->ssid[0] == '\0' && is_bssid_any(network->bssid))
    {
        return -WM_E_INVAL;
    }

#ifdef CONFIG_WPA2_ENTP
    /* make sure that if in policy wireless connection is allowed
     * only with WPA2 Enterprise AP then add the network
     */
    if ((network->role == WLAN_BSS_ROLE_STA) &&
        ((network->security.type != WLAN_SECURITY_EAP_TLS) ||
         (network->security.type != WLAN_SECURITY_PEAP_MSCHAPV2)) &&
        wlan.allow_wpa2_enterprise_ap_only)
        return -WM_E_INVAL;
#endif

    if ((network->role == WLAN_BSS_ROLE_STA) && (network->security.type == WLAN_SECURITY_WPA3_SAE) &&
        (!network->security.mfpc))
    {
        return -WM_E_INVAL;
    }

    if ((network->role == WLAN_BSS_ROLE_UAP) &&
        ((network->security.type == WLAN_SECURITY_WPA3_SAE) ||
         (network->security.type == WLAN_SECURITY_WPA2_WPA3_SAE_MIXED)) &&
        (!network->security.mfpc))
    {
        return -WM_E_INVAL;
    }

    if ((network->role == WLAN_BSS_ROLE_STA) && (network->security.type == WLAN_SECURITY_WPA2_WPA3_SAE_MIXED))
    {
        return -WM_E_INVAL;
    }

    /* Make sure network type is set correctly if not
     * set correct values as per role*/
    if ((network->type == WLAN_BSS_TYPE_STA) || (network->type == WLAN_BSS_TYPE_ANY))
    {
        if (network->role == WLAN_BSS_ROLE_UAP)
        {
            network->type = WLAN_BSS_TYPE_UAP;
        }
        else if (network->role == WLAN_BSS_ROLE_STA)
        {
            network->type = WLAN_BSS_TYPE_STA;
        }
        else
        { /* Do Nothing */
        }
    }

    /* Find a slot for the new network but check all existing networks in
     * case the new one has a duplicate name, which is not allowed. */
    for (i = 0; i < ARRAY_SIZE(wlan.networks); i++)
    {
        if (wlan.networks[i].name[0] != '\0')
        {
            if (strlen(wlan.networks[i].name) == len && !strncmp(wlan.networks[i].name, network->name, len))
            {
                return -WM_E_INVAL;
            }
        }
        else if (pos == -1)
        {
            pos = i;
        }
        else
        { /* Do Nothing */
        }
    }

    if (pos < 0)
    {
        return -WM_E_NOMEM;
    }

    /* save and set private fields */
    (void)memcpy((void *)&wlan.networks[pos], (const void *)network, sizeof(struct wlan_network));
    wlan.networks[pos].ssid_specific    = (network->ssid[0] != '\0');
    wlan.networks[pos].bssid_specific   = !is_bssid_any(network->bssid);
    wlan.networks[pos].channel_specific = (network->channel != 0U);
    if (network->security.type != WLAN_SECURITY_WILDCARD)
    {
        wlan.networks[pos].security_specific = 1;
    }

    if ((network->role == WLAN_BSS_ROLE_STA) &&
        (network->security.type != WLAN_SECURITY_NONE && network->security.type != WLAN_SECURITY_WEP_OPEN))
    {
        ret = wifi_send_clear_wpa_psk(network->role, network->ssid);
        if (ret != WM_SUCCESS)
        {
            return WLAN_ERROR_ACTION;
        }
#ifdef CONFIG_WLAN_BRIDGE
        if (network->bridge_ssid)
        {
            ret = wifi_send_clear_wpa_psk(network->role, network->bridge_ssid);
            if (ret != WM_SUCCESS)
                return WLAN_ERROR_ACTION;
        }
#endif
#ifdef CONFIG_HOST_PMK
        if ((network->security.type != WLAN_SECURITY_OWE_ONLY) && (network->security.type != WLAN_SECURITY_WPA3_SAE))
        {
            ret = mrvl_generate_psk(network->ssid, strlen(network->ssid), network->security.psk,
                                    wlan.networks[pos].security.pmk);

            if (ret == WM_SUCCESS)
                wlan.networks[pos].security.pmk_valid = true;
        }

#ifdef CONFIG_WLAN_BRIDGE
        if (network->bridge_ssid)
        {
            ret = mrvl_generate_psk(network->bridge_ssid, strlen(network->bridge_ssid), network->security.bridge_psk,
                                    wlan.networks[pos].security.bridge_pmk);

            if (ret == WM_SUCCESS)
                wlan.networks[pos].security.bridge_pmk_valid = true;
        }
#endif
    }
#else
    }
#endif
    wlan.num_networks++;
#ifdef CONFIG_WLAN_FAST_PATH
    /* On station network addition,
     * flush the FP cache since the index changes */
    if (network->role == WLAN_BSS_ROLE_STA)
    {
        wlan.auth_cache_valid      = false;
        wlan.fast_path_cache_valid = false;
    }
#endif /* CONFIG_WLAN_FAST_PATH */

    return WM_SUCCESS;
}

int wlan_remove_network(const char *name)
{
    unsigned int len, i;

    if (!is_running())
    {
        return WLAN_ERROR_STATE;
    }

    if (name == NULL)
    {
        return -WM_E_INVAL;
    }

    len = strlen(name);

    /* find the first network whose name matches and clear it out */
    for (i = 0; i < ARRAY_SIZE(wlan.networks); i++)
    {
        if (wlan.networks[i].name[0] != '\0' && strlen(wlan.networks[i].name) == len &&
            !strncmp(wlan.networks[i].name, name, len))
        {
            if (wlan.running && wlan.cur_network_idx == i)
            {
#ifdef CONFIG_WLAN_FAST_PATH
                /* On station network removal,
                 * flush the FP cache since the index changes */
                wlan.auth_cache_valid      = false;
                wlan.fast_path_cache_valid = false;
#endif /* CONFIG_WLAN_FAST_PATH */
                if (is_state(CM_STA_CONNECTED))
                {
                    return WLAN_ERROR_STATE;
                }
            }
            if (wlan.cur_uap_network_idx == i)
            {
                if (is_uap_state(CM_UAP_IP_UP) != 0)
                {
                    return WLAN_ERROR_STATE;
                }
            }

            (void)memset(&wlan.networks[i], 0, sizeof(struct wlan_network));
            wlan.num_networks--;
            return WM_SUCCESS;
        }
    }
    /* network name wasn't found */
    return -WM_E_INVAL;
}

int wlan_get_network_count(unsigned int *count)
{
    if (count == NULL)
    {
        return -WM_E_INVAL;
    }

    *count = wlan.num_networks;
    return WM_SUCCESS;
}

int wlan_get_current_network(struct wlan_network *network)
{
    if (network == NULL)
    {
        return -WM_E_INVAL;
    }

    if (wlan.running && (is_state(CM_STA_CONNECTED) || is_state(CM_STA_ASSOCIATED)))
    {
        (void)memcpy((void *)network, (const void *)&wlan.networks[wlan.cur_network_idx], sizeof(struct wlan_network));
        return WM_SUCCESS;
    }

    return WLAN_ERROR_STATE;
}

int wlan_get_current_uap_network(struct wlan_network *network)
{
    if (network == NULL)
    {
        return -WM_E_INVAL;
    }

    if (wlan.running && (is_uap_state(CM_UAP_IP_UP) || is_uap_state(CM_UAP_STARTED)))
    {
        (void)memcpy((void *)network, (const void *)&wlan.networks[wlan.cur_uap_network_idx],
                     sizeof(struct wlan_network));
        return WM_SUCCESS;
    }
    return WLAN_ERROR_STATE;
}

int is_uap_started(void)
{
    return is_uap_state(CM_UAP_IP_UP);
}
bool is_sta_connected(void)
{
    return (wlan.sta_state == CM_STA_CONNECTED);
}

bool is_sta_ipv4_connected(void)
{
    return (wlan.sta_ipv4_state == CM_STA_CONNECTED);
}

#ifdef CONFIG_IPV6
bool is_sta_ipv6_connected()
{
    return (wlan.sta_ipv6_state == CM_STA_CONNECTED);
}
#endif

int wlan_get_network(unsigned int index, struct wlan_network *network)
{
    unsigned int i;
    int pos = -1;

    if (network == NULL || index > ARRAY_SIZE(wlan.networks))
    {
        return -WM_E_INVAL;
    }

    for (i = 0; i < ARRAY_SIZE(wlan.networks); i++)
    {
        if (wlan.networks[i].name[0] != '\0' && ++pos == index)
        {
            copy_network(network, &wlan.networks[i]);
            return WM_SUCCESS;
        }
    }

    return -WM_E_INVAL;
}

int wlan_get_current_nf(void)
{
    return -g_data_nf_last;
}

int wlan_get_current_signal_strength(short *rssi, int *snr)
{
    wifi_rssi_info_t rssi_info;
    (void)wifi_send_rssi_info_cmd(&rssi_info);

    *snr  = rssi_info.bcn_rssi_last - rssi_info.bcn_nf_last;
    *rssi = rssi_info.bcn_rssi_last;
    return WM_SUCCESS;
}

int wlan_get_average_signal_strength(short *rssi, int *snr)
{
    wifi_rssi_info_t rssi_info;
    (void)wifi_send_rssi_info_cmd(&rssi_info);

    *snr  = rssi_info.bcn_snr_avg;
    *rssi = rssi_info.bcn_rssi_avg;
    return WM_SUCCESS;
}

int wlan_get_current_rssi(short *rssi)
{
    g_rssi = g_data_snr_last - g_data_nf_last;
    *rssi  = g_rssi - 256U;
    return WM_SUCCESS;
}

int wlan_get_network_byname(char *name, struct wlan_network *network)
{
    unsigned int i;

    if (network == NULL || name == NULL)
    {
        return -WM_E_INVAL;
    }

    for (i = 0; i < ARRAY_SIZE(wlan.networks); i++)
    {
        if (wlan.networks[i].name[0] != '\0' && !strcmp(wlan.networks[i].name, name))
        {
            copy_network(network, &wlan.networks[i]);
            return WM_SUCCESS;
        }
    }

    return -WM_E_INVAL;
}

int wlan_disconnect(void)
{
    if (!wlan.running)
    {
        return WLAN_ERROR_STATE;
    }

    // wakelock_get(WL_ID_STA_DISCONN);

    int ret = os_rwlock_read_lock(&ps_rwlock, OS_WAIT_FOREVER);
    if (ret != WM_SUCCESS)
    {
        // wakelock_put(WL_ID_STA_DISCONN);
        return ret;
    }

    (void)send_user_request(CM_STA_USER_REQUEST_DISCONNECT, 0);
    return WM_SUCCESS;
}

int wlan_connect(char *name)
{
    unsigned int len = name != NULL ? strlen(name) : 0U;
    int i            = 0, ret;

    if (!wlan.running)
    {
        return WLAN_ERROR_STATE;
    }

    if (wlan.num_networks == 0U || len == 0U)
    {
        return -WM_E_INVAL;
    }

    /* connect to a specific network */
    for (i = 0; i < ARRAY_SIZE(wlan.networks); i++)
    {
        if (wlan.networks[i].name[0] != '\0' && strlen(wlan.networks[i].name) == len &&
            !strncmp(wlan.networks[i].name, name, len))
        {
            wlcm_d("taking the scan lock (connect scan)");
            dbg_lock_info();
            ret = os_semaphore_get(&wlan.scan_lock, OS_WAIT_FOREVER);
            if (ret != WM_SUCCESS)
            {
                wlcm_e("failed to get scan lock: 0x%X", ret);
                return WLAN_ERROR_ACTION;
            }
            wlcm_d("got the scan lock (connect scan)");
            wlan.is_scan_lock = 1;
            return send_user_request(CM_STA_USER_REQUEST_CONNECT, i);
        }
    }

    /* specified network was not found */
    return -WM_E_INVAL;
}

int wlan_start_network(const char *name)
{
    int i;
    unsigned int len;

    if (name == NULL)
    {
        return -WM_E_INVAL;
    }

    len = strlen(name);
    if (len == 0 || wlan.num_networks == 0U)
    {
        return -WM_E_INVAL;
    }

    if (wlan_is_ieeeps_active())
    {
        wlcm_w("Station in IEEE Power Save, UAP cannot be started");
        return WLAN_ERROR_STATE;
    }

    if (wlan.cm_deepsleepps_configured)
    {
        wlcm_w("Station in Deepsleep, UAP cannot be started");
        return WLAN_ERROR_STATE;
    }

    if (is_uap_started() != 0)
    {
        wlcm_e(
            "%s network cannot be started, "
            "as the uAP is already running",
            name);
        return WLAN_ERROR_STATE;
    }

    for (i = 0; i < ARRAY_SIZE(wlan.networks); i++)
    {
        if (wlan.networks[i].name[0] != '\0' && strlen(wlan.networks[i].name) == len &&
            !strncmp(wlan.networks[i].name, name, len) && (wlan.networks[i].role == WLAN_BSS_ROLE_UAP) &&
            wlan.networks[i].ssid_specific)
        {
            if (wlan.networks[i].channel_specific && is_sta_connecting())
            {
                wlcm_e(
                    "uAP can not be started on specific "
                    "channel when station is connected."
                    "Please use channel 0 (auto) for uAP");
                return -WM_E_INVAL;
            }
            if ((wlan.networks[i].channel_specific) && (wlan.networks[i].channel != 0U))
            {
                wlcm_w(
                    "NOTE: uAP will automatically switch to"
                    " the channel that station is on.");
            }
            if (wlan.networks[i].role == WLAN_BSS_ROLE_UAP)
            {
                return send_user_request(CM_UAP_USER_REQUEST_START, i);
            }
        }
    }

    /* specified network was not found */
    return -WM_E_INVAL;
}

int wlan_stop_network(const char *name)
{
    int i;
    unsigned int len;

    if (name == NULL)
    {
        return -WM_E_INVAL;
    }

    len = strlen(name);
    if (len == 0U || wlan.num_networks == 0U)
    {
        return -WM_E_INVAL;
    }

    /* Search for matching SSID
     * If found send stop request
     */
    for (i = 0; i < ARRAY_SIZE(wlan.networks); i++)
    {
        if ((wlan.networks[i].name[0] == '\0') || (strlen(wlan.networks[i].name) != len) ||
            (strncmp(wlan.networks[i].name, name, len)) != 0)
        {
            continue;
        }

        if (wlan.networks[i].role == WLAN_BSS_ROLE_UAP && wlan.networks[i].ssid_specific)
        {
            net_interface_down(net_get_uap_handle());
            return send_user_request(CM_UAP_USER_REQUEST_STOP, i);
        }
    } /* end of loop */
    /* specified network was not found */
    return -WM_E_INVAL;
}

int wlan_get_scan_result(unsigned int index, struct wlan_scan_result *res)
{
    struct wifi_scan_result *desc;

    if (res == NULL)
    {
        return -WM_E_INVAL;
    }

    if (!is_running())
    {
        return WLAN_ERROR_STATE;
    }

    if (wifi_get_scan_result(index, &desc) != 0)
    {
        return -WM_FAIL;
    }

    (void)memset(res, 0, sizeof(struct wlan_scan_result));

    (void)memcpy((void *)&res->bssid[0], (const void *)&desc->bssid[0], sizeof(res->bssid));
    (void)memcpy((void *)&res->ssid[0], (const void *)((char *)&desc->ssid[0]), desc->ssid_len);
    res->ssid[desc->ssid_len] = 0;
    res->ssid_len             = desc->ssid_len;
    res->channel              = desc->Channel;
    res->beacon_period        = desc->beacon_period;
    res->dtim_period          = desc->dtim_period;

    if (!desc->is_ibss_bit_set)
    {
        res->role = WLAN_BSS_ROLE_STA;
    }

    res->wmm = desc->wmm_ie_present;
#ifdef CONFIG_WPS2
    if (desc->wps_IE_exist == true)
    {
        res->wps         = desc->wps_IE_exist;
        res->wps_session = desc->wps_session;
    }
#endif
    if (desc->wpa2_entp_IE_exist)
    {
        res->wpa2_entp = desc->wpa2_entp_IE_exist;
    }
    else
    {
        if (desc->WPA_WPA2_WEP.wpa != 0U)
        {
            res->wpa = 1;
        }
        if (desc->WPA_WPA2_WEP.wpa2 && desc->WPA_WPA2_WEP.wpa3_sae)
        {
            res->wpa3_sae = 1;
        }
        else if (desc->WPA_WPA2_WEP.wpa2 != 0U)
        {
            res->wpa2 = 1;
        }
        else
        { /* Do nothing */
        }
        if (desc->WPA_WPA2_WEP.wepStatic || desc->WPA_WPA2_WEP.wepDynamic)
        {
            res->wep = 1;
        }
    }

    res->rssi = desc->RSSI;

    (void)memcpy((void *)&res->trans_bssid[0], (const void *)&desc->trans_bssid[0], sizeof(res->trans_bssid));
    (void)memcpy((void *)&res->trans_ssid[0], (const void *)((char *)&desc->trans_ssid[0]), desc->trans_ssid_len);
    res->trans_ssid[desc->trans_ssid_len] = 0;
    res->trans_ssid_len                   = desc->trans_ssid_len;

    return WM_SUCCESS;
}

void wlan_set_cal_data(uint8_t *cal_data, unsigned int cal_data_size)
{
    wifi_set_cal_data(cal_data, cal_data_size);
}

void wlan_set_mac_addr(uint8_t *mac)
{
    if (wlan.status == WLCMGR_INIT_DONE || wlan.status == WLCMGR_ACTIVATED)
    {
        _wifi_set_mac_addr(mac);
    }
    else
    {
        wifi_set_mac_addr(mac);
    }
}

int wlan_scan(int (*cb)(unsigned int count))
{
    int ret;

    wlan_scan_params_v2_t wlan_scan_param;

    (void)memset(&wlan_scan_param, 0, sizeof(wlan_scan_params_v2_t));

    wlan_scan_param.cb = cb;

    ret = wlan_scan_with_opt(wlan_scan_param);

    return ret;
}

static int wlan_pscan(int (*cb)(unsigned int count))
{
    struct wlan_network network;
    int ret;
    wlan_scan_params_v2_t wlan_scan_param;

    ret = wlan_get_current_network(&network);
    if (ret != WM_SUCCESS)
    {
        wlcm_e("cannot get network info");
        return -WM_FAIL;
    }

    (void)memset(&wlan_scan_param, 0, sizeof(wlan_scan_params_v2_t));

    wlan_scan_param.cb = cb;

    (void)memcpy((void *)wlan_scan_param.bssid, (const void *)network.bssid, MLAN_MAC_ADDR_LENGTH);

    (void)memcpy((void *)wlan_scan_param.ssid, (const void *)network.ssid, strlen(network.ssid));

    wlan_scan_param.num_channels = 1;

    wlan_scan_param.chan_list[0].chan_number = network.channel;
    wlan_scan_param.chan_list[0].scan_type   = 2;
    wlan_scan_param.chan_list[0].scan_time   = 200;

    ret = wlan_scan_with_opt(wlan_scan_param);

    return ret;
}

int wlan_scan_with_opt(wlan_scan_params_v2_t t_wlan_scan_param)
{
    int ret;

    wlan_scan_params_v2_t *wlan_scan_param = NULL;

    if (t_wlan_scan_param.cb == NULL)
    {
        return -WM_E_INVAL;
    }

    if (!is_running() || !is_scanning_allowed())
    {
        return WLAN_ERROR_STATE;
    }

    wlan_scan_param = (wlan_scan_params_v2_t *)os_mem_calloc(sizeof(wlan_scan_params_v2_t));

    if (wlan_scan_param == NULL)
    {
        return -WM_E_NOMEM;
    }

    (void)memcpy((void *)wlan_scan_param, (const void *)&t_wlan_scan_param, sizeof(wlan_scan_params_v2_t));

    wlcm_d("taking the scan lock (user scan)");
    dbg_lock_info();
    ret = os_semaphore_get(&wlan.scan_lock, OS_WAIT_FOREVER);
    if (ret != WM_SUCCESS)
    {
        wlcm_e("failed to get scan lock: 0x%X", ret);
        os_mem_free(wlan_scan_param);
        return -WM_FAIL;
    }
    wlcm_d("got the scan lock (user scan)");
    wlan.is_scan_lock = 1;

    ret = send_user_request(CM_STA_USER_REQUEST_SCAN, (int)wlan_scan_param);

    if (ret != WM_SUCCESS)
    {
        os_mem_free(wlan_scan_param);
    }

    return ret;
}

int wlan_get_connection_state(enum wlan_connection_state *state)
{
    enum cm_sta_state cur;

    if (state == NULL)
    {
        return -WM_E_INVAL;
    }

    if (!is_running())
    {
        return WLAN_ERROR_STATE;
    }

    if (is_user_scanning() != 0)
    {
        cur = wlan.sta_return_to;
    }
    else
    {
        cur = wlan.sta_state;
    }

    switch (cur)
    {
        default:
        case CM_STA_IDLE:
            *state = WLAN_DISCONNECTED;
            break;
        case CM_STA_SCANNING:
            *state = WLAN_SCANNING;
            break;
        case CM_STA_ASSOCIATING:
            *state = WLAN_ASSOCIATING;
            break;
        case CM_STA_ASSOCIATED:
            *state = WLAN_ASSOCIATED;
            break;
        case CM_STA_REQUESTING_ADDRESS:
        case CM_STA_OBTAINING_ADDRESS:
            *state = WLAN_CONNECTING;
            break;
        case CM_STA_CONNECTED:
            *state = WLAN_CONNECTED;
            break;
    }
    return WM_SUCCESS;
}

static bool wlan_is_ieeeps_active(void)
{
    if (wlan.ieeeps_state >= IEEEPS_CONFIGURING && wlan.ieeeps_state < IEEEPS_PRE_DISABLE)
    {
        return true;
    }
    else
    {
        return false;
    }
}
static bool wlan_is_deepsleepps_active(void)
{
    if (wlan.deepsleepps_state >= DEEPSLEEPPS_CONFIGURING)
    {
        return true;
    }
    else
    {
        return false;
    }
}

int wlan_get_ps_mode(enum wlan_ps_mode *ps_mode)
{
    if (ps_mode == NULL)
    {
        return -WM_E_INVAL;
    }

    *ps_mode = WLAN_ACTIVE;

    if (wlan_is_deepsleepps_active())
    {
        *ps_mode = WLAN_DEEP_SLEEP;
    }
    else if (wlan_is_ieeeps_active())
    {
        *ps_mode = WLAN_IEEE;
    }
    else
    { /* Do Nothing */
    }

    return WM_SUCCESS;
}

int wlan_get_uap_connection_state(enum wlan_connection_state *state)
{
    enum cm_uap_state cur;

    if (state == NULL)
    {
        return -WM_E_INVAL;
    }

    if (!is_running())
    {
        return WLAN_ERROR_STATE;
    }

    cur = wlan.uap_state;

    switch (cur)
    {
        default:
        case CM_UAP_INITIALIZING:
        case CM_UAP_CONFIGURED:
            *state = WLAN_UAP_STOPPED;
            break;
        case CM_UAP_STARTED:
        case CM_UAP_IP_UP:
            *state = WLAN_UAP_STARTED;
            break;
    }
    return WM_SUCCESS;
}

int wlan_get_address(struct wlan_ip_config *addr)
{
    void *if_handle = NULL;
    if (addr == NULL)
    {
        return -WM_E_INVAL;
    }

    if (!is_running() || !is_state(CM_STA_CONNECTED))
    {
        return WLAN_ERROR_STATE;
    }

    if_handle = net_get_mlan_handle();
    if (net_get_if_addr(addr, if_handle) != 0)
    {
        return -WM_FAIL;
    }

    return WM_SUCCESS;
}

int wlan_get_uap_address(struct wlan_ip_config *addr)
{
    void *if_handle = NULL;
    if (addr == NULL)
    {
        return -WM_E_INVAL;
    }
    if (!is_running() || !is_uap_state(CM_UAP_IP_UP))
    {
        return WLAN_ERROR_STATE;
    }

    if_handle = net_get_uap_handle();
    if (net_get_if_addr(addr, if_handle) != 0)
    {
        return -WM_FAIL;
    }
    return WM_SUCCESS;
}

#ifdef CONFIG_P2P
int wlan_get_wfd_address(struct wlan_ip_config *addr)
{
    void *if_handle = NULL;
    if (addr == NULL)
        return -WM_E_INVAL;
    if (!is_running())
        return WLAN_ERROR_STATE;

    if_handle = net_get_wfd_handle();
    if (net_get_if_addr(addr, if_handle))
        return -WM_FAIL;
    return WM_SUCCESS;
}
#endif

int wlan_get_mac_address(unsigned char *dest)
{
    if (dest == NULL)
    {
        return -WM_E_INVAL;
    }
    (void)memset((void *)dest, 0, MLAN_MAC_ADDR_LENGTH);
    (void)memcpy((void *)dest, (const void *)&wlan.mac[0], MLAN_MAC_ADDR_LENGTH);
    return WM_SUCCESS;
}

#ifdef CONFIG_P2P
int wlan_get_wfd_mac_address(unsigned char *dest)
{
    if (dest == NULL)
        return -WM_E_INVAL;
    (void)memset((void *)dest, 0, MLAN_MAC_ADDR_LENGTH);
    (void)memcpy((void *)dest, (const void *)&wlan.wfd_mac[0], MLAN_MAC_ADDR_LENGTH);
    return WM_SUCCESS;
}
#endif

void wlan_wake_up_card(void)
{
    uint32_t resp;

    wifi_wake_up_card(&resp);
}

void wlan_configure_listen_interval(int listen_interval)
{
    wifi_configure_listen_interval(listen_interval);
}

void wlan_configure_null_pkt_interval(int time_in_secs)
{
    wifi_configure_null_pkt_interval(time_in_secs);
}
int wlan_ieeeps_on(unsigned int wakeup_conditions)
{
    if (!wlan.running)
    {
        return WLAN_ERROR_STATE;
    }
    enum wlan_connection_state state;
    if (wlan_get_uap_connection_state(&state) != 0)
    {
        wlcm_e("unable to get uAP connection state");
        return WLAN_ERROR_STATE;
    }
    if (state == WLAN_UAP_STARTED)
    {
        return WLAN_ERROR_PS_ACTION;
    }
    if (wlan.cm_ieeeps_configured || wlan.cm_deepsleepps_configured)
    {
        return WLAN_ERROR_STATE;
    }

    wlan.wakeup_conditions = wakeup_conditions;

    return send_user_request(CM_STA_USER_REQUEST_PS_ENTER, WLAN_IEEE);
}

int wlan_ieeeps_off(void)
{
    if (wlan.cm_ieeeps_configured)
    {
        return send_user_request(CM_STA_USER_REQUEST_PS_EXIT, WLAN_IEEE);
    }
    else
    {
        return WLAN_ERROR_STATE;
    }
}

int wlan_deepsleepps_on(void)
{
    if (!wlan.running)
    {
        return WLAN_ERROR_STATE;
    }
    enum wlan_connection_state state;
    if (wlan_get_uap_connection_state(&state) != 0)
    {
        wlcm_e("unable to get uAP connection state");
        return WLAN_ERROR_STATE;
    }
    if (state == WLAN_UAP_STARTED)
    {
        return WLAN_ERROR_PS_ACTION;
    }

    if (wlan.cm_ieeeps_configured || wlan.cm_deepsleepps_configured)
    {
        return WLAN_ERROR_STATE;
    }

    if (is_state(CM_STA_CONNECTED))
    {
        return WLAN_ERROR_STATE;
    }

    return send_user_request(CM_STA_USER_REQUEST_PS_ENTER, WLAN_DEEP_SLEEP);
}

int wlan_deepsleepps_off(void)
{
    if (wlan.cm_deepsleepps_configured)
    {
        return send_user_request(CM_STA_USER_REQUEST_PS_EXIT, WLAN_DEEP_SLEEP);
    }
    else
    {
        return WLAN_ERROR_STATE;
    }
}

#ifdef STREAM_2X2
int wlan_set_current_ant(uint8_t tx_antenna, uint8_t rx_antenna)
{
    int rv = wifi_set_antenna(tx_antenna, rx_antenna);
    if (rv != WM_SUCCESS)
    {
        wlcm_e("Unable to set antenna");
        return WLAN_ERROR_STATE;
    }

    return WM_SUCCESS;
}
#else
int wlan_set_antcfg(uint32_t ant, uint16_t evaluate_time)
{
#if defined(SD8801)
    int rv = wifi_set_antenna(ant, evaluate_time);
    if (rv != WM_SUCCESS)
    {
        wlcm_e("Unable to set antenna");
        return WLAN_ERROR_STATE;
    }

    return WM_SUCCESS;
#else
    wlcm_e("Antenna config not supported");
    return WLAN_ERROR_STATE;
#endif
}

int wlan_get_antcfg(uint32_t *ant, uint16_t *evaluate_time)
{
#if defined(SD8801)
    int rv = wifi_get_antenna((unsigned int *)ant, evaluate_time);
    if (rv != WM_SUCCESS)
    {
        wlcm_e("Unable to get current antenna");
        return WLAN_ERROR_STATE;
    }

    return WM_SUCCESS;
#else
    wlcm_e("Antenna config not supported");
    return WLAN_ERROR_STATE;
#endif
}

#endif

int wlan_wlcmgr_send_msg(enum wifi_event event, int reason, void *data)
{
    struct wifi_message msg;

    msg.event  = event;
    msg.reason = reason;
    msg.data   = (void *)data;

    if (os_queue_send(&wlan.events, &msg, OS_NO_WAIT) == WM_SUCCESS)
    {
        return WM_SUCCESS;
    }

    return -WM_FAIL;
}

/*
  This function validates input string for a valid WEP key, converts
  it to appropriate format

  Returns positive integer equal to size of the output string
  for successful operation or -WM_FAIL in case of failure to convert. Note
  that the output string is not NULL terminated.
 */
int load_wep_key(const uint8_t *input, uint8_t *output, uint8_t *output_len, const unsigned max_output_len)
{
    if (input == NULL || output == NULL)
    {
        return -WM_FAIL;
    }

    unsigned len = *output_len;

    /* fixme: add macros here after mlan integration */
    if (len == 10U || len == 26U)
    {
        /* Looks like this is an hexadecimal key */
        int ret = hex2bin(input, output, max_output_len);
        if (ret == 0)
        {
            return -WM_FAIL;
        }

        len = len / 2U;
    }
    else if (len == 5U || len == 13U)
    {
        /* Looks like this is ASCII key  */
        if (len > max_output_len)
        {
            return -WM_FAIL;
        }

        (void)memcpy((void *)output, (const void *)input, len);
    }
    else
    {
        return -WM_FAIL;
    }

    *output_len = len;

    return WM_SUCCESS;
}

int get_split_scan_delay_ms(void)
{
    return g_wifi_scan_params.split_scan_delay;
}

char *wlan_get_firmware_version_ext(void)
{
    return wlan.fw_ver_ext.version_str;
}

unsigned int wlan_get_uap_supported_max_clients(void)
{
    return wlan.uap_supported_max_sta_num;
}

int wlan_get_uap_max_clients(unsigned int *max_sta_num)
{
    return wifi_get_uap_max_clients(max_sta_num);
}

int wlan_set_uap_max_clients(unsigned int max_sta_num)
{
    if (is_uap_started() != 0)
    {
        wlcm_e(
            "Cannot set the max station number "
            "as the uAP is already running");
        return -WM_FAIL;
    }
    else if (max_sta_num > wlan.uap_supported_max_sta_num)
    {
        wlcm_e(
            "Maximum supported station number "
            "limit is = %d",
            wlan.uap_supported_max_sta_num);
        return -WM_FAIL;
    }
    else
    {
        return wifi_set_uap_max_clients(&max_sta_num);
    }
}

int wlan_get_mgmt_ie(enum wlan_bss_type bss_type, IEEEtypes_ElementId_t index, void *buf, unsigned int *buf_len)
{
    return wifi_get_mgmt_ie(bss_type, index, buf, buf_len);
}

int wlan_set_mgmt_ie(enum wlan_bss_type bss_type, IEEEtypes_ElementId_t id, void *buf, unsigned int buf_len)
{
    return wifi_set_mgmt_ie(bss_type, id, buf, buf_len);
}

int wlan_clear_mgmt_ie(enum wlan_bss_type bss_type, IEEEtypes_ElementId_t index)
{
    return wifi_clear_mgmt_ie(bss_type, index);
}

int wlan_set_htcapinfo(unsigned int htcapinfo)
{
    return wifi_set_htcapinfo(htcapinfo);
}

int wlan_set_httxcfg(unsigned short httxcfg)
{
    return wifi_set_httxcfg(httxcfg);
}

int wlan_set_txratecfg(wlan_ds_rate ds_rate)
{
    return wifi_set_txratecfg(ds_rate);
}

int wlan_get_txratecfg(wlan_ds_rate *ds_rate)
{
    int ret;

    ret = wifi_get_txratecfg(ds_rate);

    if (ret != WM_SUCCESS)
    {
        return ret;
    }

    ret = wifi_get_data_rate(ds_rate);

    if (ret != WM_SUCCESS)
    {
        return ret;
    }

    return WM_SUCCESS;
}

int wlan_set_sta_tx_power(t_u32 power_level)
{
    return wifi_set_tx_power(power_level);
}

int wlan_get_sta_tx_power(t_u32 *power_level)
{
    return wifi_get_tx_power(power_level);
}

int wlan_set_chanlist_and_txpwrlimit(wifi_chanlist_t *chanlist, wifi_txpwrlimit_t *txpwrlimit)
{
    int ret = WM_SUCCESS;

    ret = wlan_set_chanlist(chanlist);
    if (ret != WM_SUCCESS)
    {
        wlcm_e("Cannot set Channel List");
        return ret;
    }

    ret = wlan_set_txpwrlimit(txpwrlimit);
    if (ret != WM_SUCCESS)
    {
        wlcm_e("Cannot set Tx Power");
    }

    return ret;
}

int wlan_set_chanlist(wifi_chanlist_t *chanlist)
{
    if (chanlist != NULL)
    {
        return wifi_set_chanlist(chanlist);
    }

    return -WM_FAIL;
}

int wlan_get_chanlist(wifi_chanlist_t *chanlist)
{
    if (chanlist != NULL)
    {
        return wifi_get_chanlist(chanlist);
    }

    return -WM_FAIL;
}

int wlan_set_txpwrlimit(wifi_txpwrlimit_t *txpwrlimit)
{
    if (txpwrlimit != NULL)
    {
        return wifi_set_txpwrlimit(txpwrlimit);
    }

    return -WM_FAIL;
}

int wlan_get_txpwrlimit(wifi_SubBand_t subband, wifi_txpwrlimit_t *txpwrlimit)
{
    if (txpwrlimit != NULL)
    {
        (void)memset(txpwrlimit, 0x00, sizeof(wifi_txpwrlimit_t));
        return wifi_get_txpwrlimit(subband, txpwrlimit);
    }

    return -WM_FAIL;
}

#ifdef WLAN_LOW_POWER_ENABLE
int wlan_enable_low_pwr_mode()
{
    if (wlan.status == WLCMGR_INACTIVE)
    {
        wifi_enable_low_pwr_mode();
        return WM_SUCCESS;
    }
    else
        return -WM_FAIL;
}
#endif

void wlan_set_reassoc_control(bool reassoc_control)
{
    wlan.reassoc_control = reassoc_control;
    wlcm_d("Reassoc control %s", reassoc_control ? "enabled" : "disabled");
}

int wlan_set_ed_mac_mode(wlan_ed_mac_ctrl_t wlan_ed_mac_ctrl)
{
    return wifi_set_ed_mac_mode(&wlan_ed_mac_ctrl);
}

int wlan_get_ed_mac_mode(wlan_ed_mac_ctrl_t *wlan_ed_mac_ctrl)
{
    return wifi_get_ed_mac_mode(wlan_ed_mac_ctrl);
}

bool wlan_get_11d_enable_status(void)
{
    return wrapper_wlan_11d_support_is_enabled();
}

int wlan_remain_on_channel(const enum wlan_bss_type bss_type,
                           const bool status,
                           const uint8_t channel,
                           const uint32_t duration)
{
    wifi_remain_on_channel_t roc;

    (void)memset(&roc, 0x00, sizeof(wifi_remain_on_channel_t));

    roc.remove = !status;

    roc.channel = channel;

    roc.remain_period = duration;

    return wifi_send_remain_on_channel_cmd(bss_type, &roc);
}

int wlan_get_otp_user_data(uint8_t *buf, uint16_t len)
{
    if (buf == NULL)
    {
        return -WM_E_INVAL;
    }

    return wifi_get_otp_user_data(buf, len);
}

#ifdef CONFIG_WIFI_GET_LOG
int wlan_get_log(wlan_pkt_stats_t *stats)
{
    if (!stats)
        return -WM_E_INVAL;

    return wifi_get_log(stats, MLAN_BSS_TYPE_STA);
}

int wlan_uap_get_log(wlan_pkt_stats_t *stats)
{
    if (!stats)
        return -WM_E_INVAL;

    return wifi_get_log(stats, MLAN_BSS_TYPE_UAP);
}
#endif

int wlan_get_cal_data(wlan_cal_data_t *cal_data)
{
    if (cal_data == NULL)
    {
        return -WM_E_INVAL;
    }

    return wifi_get_cal_data(cal_data);
}

void wlan_set_smart_mode_active(void)
{
    wlan.smart_mode_active = true;
}

void wlan_set_smart_mode_inactive(void)
{
    wlan.smart_mode_active = false;
}

bool wlan_get_smart_mode_status(void)
{
    return wlan.smart_mode_active;
}

#ifndef CONFIG_MLAN_WMSDK
int wlan_auto_reconnect_enable(wlan_auto_reconnect_config_t auto_reconnect_config)
{
    return wifi_auto_reconnect_enable(auto_reconnect_config);
}

int wlan_auto_reconnect_disable()
{
    return wifi_auto_reconnect_disable();
}
#endif

int wlan_get_tsf(uint32_t *tsf_high, uint32_t *tsf_low)
{
    return wifi_get_tsf(tsf_high, tsf_low);
}

#ifdef ENABLE_OFFLOAD
int wlan_tcp_keep_alive(wlan_tcp_keep_alive_t *tcp_keep_alive)
{
    int ret;
    unsigned int ipv4_addr;

    ret = wlan_get_ipv4_addr(&ipv4_addr);
    if (ret != WM_SUCCESS)
    {
        wlcm_e("Cannot get IP");
        return -WM_FAIL;
    }

    return wifi_tcp_keep_alive(tcp_keep_alive, wlan.mac, ipv4_addr);
}
#endif /*ENABLE_OFFLOAD*/

#ifndef CONFIG_MLAN_WMSDK
int wlan_nat_keep_alive(wlan_nat_keep_alive_t *nat_keep_alive)
{
    int ret;
    unsigned int ipv4_addr;
    t_u16 src_port = 4500;

    ret = wlan_get_ipv4_addr(&ipv4_addr);
    if (ret != WM_SUCCESS)
    {
        wlcm_e("Cannot get IP");
        return -WM_FAIL;
    }

    return wifi_nat_keep_alive(nat_keep_alive, wlan.mac, ipv4_addr, src_port);
}
#endif

uint16_t wlan_get_beacon_period(void)
{
    struct wlan_network network;
    int ret;

    ret = wlan_get_current_network(&network);
    if (ret != WM_SUCCESS)
    {
        wlcm_e("cannot get network info");
        return 0;
    }

    return network.beacon_period;
}

os_semaphore_t wlan_dtim_sem;
static uint8_t dtim_period;

static int pscan_cb(unsigned int count)
{
    struct wlan_scan_result res;
    unsigned int i;
    int err;

    dtim_period = 0;

    if (count == 0U)
    {
        (void)PRINTF("networks not found\r\n");
        (void)os_semaphore_put(&wlan_dtim_sem);
        return 0;
    }

    for (i = 0; i < count; i++)
    {
        err = wlan_get_scan_result(i, &res);
        if (err != 0)
        {
            (void)PRINTF("Error: can't get scan res %d\r\n", i);
            continue;
        }

        dtim_period = res.dtim_period;
    }

    (void)os_semaphore_put(&wlan_dtim_sem);

    return 0;
}

uint8_t wlan_get_dtim_period(void)
{
    int rv;

    rv = os_semaphore_create(&wlan_dtim_sem, "wlandtimsem");
    if (rv != WM_SUCCESS)
    {
        return 0;
    }

    /* Consume so that 'get' blocks when used later */
    (void)os_semaphore_get(&wlan_dtim_sem, OS_WAIT_FOREVER);

    if (wlan_pscan(pscan_cb) != 0)
    {
        (void)PRINTF("Error: scan request failed\r\n");
        (void)os_semaphore_put(&wlan_dtim_sem);
        (void)os_semaphore_delete(&wlan_dtim_sem);
        return 0;
    }

    /* Wait till scan for DTIM is complete */
    /*TODO:This need to be handled in better way. */
    if (os_semaphore_get(&wlan_dtim_sem, os_msec_to_ticks(500)) != WM_SUCCESS)
    {
        wlcm_e("Do not call this API from wlan event handler\r\n");
        dtim_period = 0;
    }
    (void)os_semaphore_delete(&wlan_dtim_sem);

    return dtim_period;
}

int wlan_get_data_rate(wlan_ds_rate *ds_rate)
{
    return wifi_get_data_rate(ds_rate);
}

int wlan_set_pmfcfg(uint8_t mfpc, uint8_t mfpr)
{
    if (!mfpc && mfpr)
    {
        return -WM_FAIL;
    }

    return wifi_set_pmfcfg(mfpc, mfpr);
}

int wlan_get_pmfcfg(uint8_t *mfpc, uint8_t *mfpr)
{
    return wifi_get_pmfcfg(mfpc, mfpr);
}

#ifndef CONFIG_MLAN_WMSDK
int wlan_get_tbtt_offset(wlan_tbtt_offset_t *tbtt_offset)
{
    return wifi_get_tbtt_offset(tbtt_offset);
}
#endif

#ifdef ENABLE_OFFLOAD
int wlan_set_packet_filters(wlan_flt_cfg_t *flt_cfg)
{
    return wifi_set_packet_filters(flt_cfg);
}

int wlan_set_auto_arp()
{
    int ret;
    unsigned int ipv4_addr;
    wlan_flt_cfg_t flt_cfg;

    ret = wlan_get_ipv4_addr(&ipv4_addr);
    if (ret != WM_SUCCESS)
    {
        wlcm_e("Cannot get IP");
        return -WM_FAIL;
    }

    (void)memset(&flt_cfg, 0, sizeof(wlan_flt_cfg_t));

    flt_cfg.criteria = CRITERIA_BROADCAST;
    flt_cfg.nentries = 1;

    flt_cfg.mef_entry.mode   = MEF_MODE_HOST_SLEEP; // MBIT(0);
    flt_cfg.mef_entry.action = MEF_AUTO_ARP;

    flt_cfg.mef_entry.filter_num = 3;

    flt_cfg.mef_entry.filter_item[0].type         = TYPE_BYTE_EQ;
    flt_cfg.mef_entry.filter_item[0].repeat       = 6;
    flt_cfg.mef_entry.filter_item[0].offset       = 0;
    flt_cfg.mef_entry.filter_item[0].num_byte_seq = 1;
    flt_cfg.mef_entry.filter_item[0].byte_seq[0]  = 0xff;
    flt_cfg.mef_entry.rpn[1]                      = RPN_TYPE_AND;

    flt_cfg.mef_entry.filter_item[1].type         = TYPE_BYTE_EQ;
    flt_cfg.mef_entry.filter_item[1].repeat       = 1;
    flt_cfg.mef_entry.filter_item[1].offset       = 20;
    flt_cfg.mef_entry.filter_item[1].num_byte_seq = 2;
    (void)memcpy((void *)flt_cfg.mef_entry.filter_item[1].byte_seq, (const void *)"\x08\x06", 2);
    flt_cfg.mef_entry.rpn[2] = RPN_TYPE_AND;

    flt_cfg.mef_entry.filter_item[2].type         = TYPE_BYTE_EQ;
    flt_cfg.mef_entry.filter_item[2].repeat       = 1;
    flt_cfg.mef_entry.filter_item[2].offset       = 46;
    flt_cfg.mef_entry.filter_item[2].num_byte_seq = 4;
    (void)memcpy((void *)flt_cfg.mef_entry.filter_item[2].byte_seq, (const void *)&ipv4_addr, 4);

    return wifi_set_packet_filters(&flt_cfg);
}

#define DIV_ROUND_UP(n, d) (((n) + (d)-1) / (d))

static inline bool is_broadcast_ether_addr(const u8_t *addr)
{
    return (*(const u16_t *)(addr + 0) & *(const u16_t *)(addr + 2) & *(const u16_t *)(addr + 4)) == 0xffff;
}

/**
 * @brief is_wowlan_pattern_supported
 *
 * @param priv                 A pointer to moal_private
 * @param pat                 A pointer to wowlan pattern
 * @param byte_seq       A pointer to byte_seq
 *
 * @return                      1 -- support, 0 -- not support
 */
static t_bool is_wowlan_pattern_supported(wifi_wowlan_pattern_t *pat, u8_t *byte_seq)
{
    int j, k, valid_byte_cnt = 0;
    t_bool dont_care_byte = MFALSE;

    for (j = 0; j < DIV_ROUND_UP(pat->pattern_len, 8); j++)
    {
        for (k = 0; k < 8; k++)
        {
            if (pat->mask[j] & 1 << k)
            {
                (void)memcpy((void *)(byte_seq + valid_byte_cnt), (const void *)&pat->pattern[j * 8 + k], 1);
                valid_byte_cnt++;
                if (dont_care_byte)
                    return MFALSE;
            }
            else
            {
                if (valid_byte_cnt)
                    dont_care_byte = MTRUE;
            }

            if (valid_byte_cnt > MAX_NUM_BYTE_SEQ)
                return MFALSE;
        }
    }

    byte_seq[MAX_NUM_BYTE_SEQ] = valid_byte_cnt;

    return MTRUE;
}

int wlan_wowlan_cfg_ptn_match(wlan_wowlan_ptn_cfg_t *ptn_cfg)
{
    wlan_flt_cfg_t flt_cfg;
    wifi_mef_entry_t *mef_entry;
    t_u8 byte_seq[MAX_NUM_BYTE_SEQ + 1];
    const t_u8 ipv4_mc_mac[] = {0x33, 0x33};
    const t_u8 ipv6_mc_mac[] = {0x01, 0x00, 0x5e};
    int filt_num = 0, i = 0, ret = 0;
    t_bool first_pat = MTRUE;
    memset(&flt_cfg, 0, sizeof(flt_cfg));
    //  mef_cfg.mef_act_type = MEF_ACT_WOWLAN;
    mef_entry = &flt_cfg.mef_entry;

    mef_entry->mode   = MEF_MODE_HOST_SLEEP;
    mef_entry->action = MEF_ACTION_ALLOW_AND_WAKEUP_HOST;

    for (i = 0; i < ptn_cfg->n_patterns; i++)
    {
        memset(byte_seq, 0, sizeof(byte_seq));
        if (!is_wowlan_pattern_supported(&ptn_cfg->patterns[i], byte_seq))
        {
            PRINTM(MERROR, "Pattern not supported\n");
            ret = -EOPNOTSUPP;
            return ret;
        }
        if (!ptn_cfg->patterns[i].pkt_offset)
        {
            if (!(byte_seq[0] & 0x01) && (byte_seq[MAX_NUM_BYTE_SEQ] == 1))
            {
                flt_cfg.criteria |= CRITERIA_UNICAST;
                continue;
            }
            else if (is_broadcast_ether_addr(byte_seq))
            {
                flt_cfg.criteria |= CRITERIA_BROADCAST;
                continue;
            }
            else if ((!memcmp(byte_seq, ipv4_mc_mac, 2) && (byte_seq[MAX_NUM_BYTE_SEQ] == 2)) ||
                     (!memcmp(byte_seq, ipv6_mc_mac, 3) && (byte_seq[MAX_NUM_BYTE_SEQ] == 3)))
            {
                flt_cfg.criteria |= CRITERIA_MULTICAST;
                continue;
            }
        }

        //    mef_entry->filter_item[filt_num].fill_flag =
        //          (FILLING_TYPE | FILLING_REPEAT | FILLING_BYTE_SEQ |
        //         FILLING_OFFSET);
        mef_entry->filter_item[filt_num].repeat = 1;
        mef_entry->filter_item[filt_num].offset = ptn_cfg->patterns[i].pkt_offset;
        (void)memcpy((void *)mef_entry->filter_item[filt_num].byte_seq, (const void *)byte_seq, MAX_NUM_BYTE_SEQ);
        mef_entry->filter_item[filt_num].num_byte_seq = byte_seq[MAX_NUM_BYTE_SEQ];
        mef_entry->filter_item[filt_num].type         = TYPE_BYTE_EQ;
        if (first_pat)
            first_pat = MFALSE;
        else
            mef_entry->rpn[filt_num] = RPN_TYPE_OR;

        filt_num++;
    }
    if (ptn_cfg->enable)
    {
        //   (void)memset(&flt_cfg, 0, sizeof(wlan_flt_cfg_t));

        flt_cfg.criteria = CRITERIA_UNICAST | CRITERIA_BROADCAST | CRITERIA_MULTICAST;
        flt_cfg.nentries = 1;

        flt_cfg.mef_entry.mode   = MEF_MODE_HOST_SLEEP;
        flt_cfg.mef_entry.action = MEF_ACTION_ALLOW_AND_WAKEUP_HOST;

        flt_cfg.mef_entry.filter_num = 2;

        flt_cfg.mef_entry.filter_item[filt_num].type         = TYPE_BYTE_EQ;
        flt_cfg.mef_entry.filter_item[filt_num].repeat       = 16;
        flt_cfg.mef_entry.filter_item[filt_num].offset       = 56;
        flt_cfg.mef_entry.filter_item[filt_num].num_byte_seq = MLAN_MAC_ADDR_LENGTH;
        (void)memcpy((void *)flt_cfg.mef_entry.filter_item[filt_num].byte_seq, (const void *)wlan.mac,
                     MLAN_MAC_ADDR_LENGTH);
        if (filt_num)
            flt_cfg.mef_entry.rpn[filt_num] = RPN_TYPE_OR;
        filt_num++;
        // flt_cfg.mef_entry.filter_item[1].fill_flag	  = (FILLING_TYPE | FILLING_REPEAT | FILLING_BYTE_SEQ |
        // FILLING_OFFSET);
        flt_cfg.mef_entry.filter_item[filt_num].type         = TYPE_BYTE_EQ;
        flt_cfg.mef_entry.filter_item[filt_num].repeat       = 16;
        flt_cfg.mef_entry.filter_item[filt_num].offset       = 28;
        flt_cfg.mef_entry.filter_item[filt_num].num_byte_seq = MLAN_MAC_ADDR_LENGTH;
        (void)memcpy((void *)flt_cfg.mef_entry.filter_item[filt_num].byte_seq, (const void *)wlan.mac,
                     MLAN_MAC_ADDR_LENGTH);
        if (filt_num)
            flt_cfg.mef_entry.rpn[filt_num] = RPN_TYPE_OR;
        filt_num++;
    }
    flt_cfg.mef_entry.filter_num = filt_num;
    return wifi_set_packet_filters(&flt_cfg);
}
#endif /*ENABLE_OFFLOAD*/

#ifndef CONFIG_MLAN_WMSDK
int wlan_set_auto_ping()
{
    wlan_flt_cfg_t flt_cfg;

    (void)memset(&flt_cfg, 0, sizeof(wlan_flt_cfg_t));

    flt_cfg.criteria = (MBIT(0) | MBIT(1));
    flt_cfg.nentries = 1;

    flt_cfg.mef_entry.mode   = MBIT(0);
    flt_cfg.mef_entry.action = 0x20;

    flt_cfg.mef_entry.filter_num = 2;

    flt_cfg.mef_entry.filter_item[0].type         = TYPE_BYTE_EQ;
    flt_cfg.mef_entry.filter_item[0].repeat       = 1;
    flt_cfg.mef_entry.filter_item[0].offset       = IPV4_PKT_OFFSET;
    flt_cfg.mef_entry.filter_item[0].num_byte_seq = 2;
    (void)memcpy((void *)flt_cfg.mef_entry.filter_item[0].byte_seq, (const void *)"\x08\x00", 2);
    flt_cfg.mef_entry.rpn[1] = RPN_TYPE_AND;

    flt_cfg.mef_entry.filter_item[1].type      = TYPE_DNUM_EQ;
    flt_cfg.mef_entry.filter_item[1].pattern   = ICMP_OF_IP_PROTOCOL;
    flt_cfg.mef_entry.filter_item[1].offset    = IP_PROTOCOL_OFFSET;
    flt_cfg.mef_entry.filter_item[1].num_bytes = 1;

    return wifi_set_packet_filters(&flt_cfg);
}
#endif /* CONFIG_MLAN_WMSDK */

#ifdef ENABLE_OFFLOAD
int wlan_set_ipv6_ns_offload()
{
    wlan_flt_cfg_t flt_cfg;

    (void)memset(&flt_cfg, 0, sizeof(wlan_flt_cfg_t));

    flt_cfg.criteria = (MBIT(1) | MBIT(3));
    flt_cfg.nentries = 1;

    flt_cfg.mef_entry.mode   = MBIT(0);
    flt_cfg.mef_entry.action = 0x40;

    flt_cfg.mef_entry.filter_num = 2;

    flt_cfg.mef_entry.filter_item[0].type         = TYPE_BYTE_EQ;
    flt_cfg.mef_entry.filter_item[0].repeat       = 1;
    flt_cfg.mef_entry.filter_item[0].offset       = 20;
    flt_cfg.mef_entry.filter_item[0].num_byte_seq = 2;
    (void)memcpy((void *)flt_cfg.mef_entry.filter_item[0].byte_seq, (const void *)"\x86\xdd", 2);
    flt_cfg.mef_entry.rpn[1] = RPN_TYPE_AND;

    flt_cfg.mef_entry.filter_item[1].type         = TYPE_BYTE_EQ;
    flt_cfg.mef_entry.filter_item[1].repeat       = 1;
    flt_cfg.mef_entry.filter_item[1].offset       = 62;
    flt_cfg.mef_entry.filter_item[1].num_byte_seq = 1;
    (void)memcpy((void *)flt_cfg.mef_entry.filter_item[1].byte_seq, (const void *)"\x87", 1);

    return wifi_set_packet_filters(&flt_cfg);
}
#endif

int wlan_get_current_bssid(uint8_t *bssid)
{
    struct wlan_network network;
    int ret;

    ret = wlan_get_current_network(&network);
    if (ret != WM_SUCCESS)
    {
        wlcm_e("cannot get network info");
        return -WM_FAIL;
    }
    if (bssid != NULL)
    {
        (void)memcpy((void *)bssid, (const void *)network.bssid, IEEEtypes_ADDRESS_SIZE);
        return WM_SUCCESS;
    }

    return -WM_FAIL;
}

uint8_t wlan_get_current_channel(void)
{
    struct wlan_network network;
    int ret;

    ret = wlan_get_current_network(&network);
    if (ret != WM_SUCCESS)
    {
        wlcm_e("cannot get network info");
        return 0;
    }

    return network.channel;
}

#ifndef CONFIG_MLAN_WMSDK
int wlan_get_auto_reconnect_config(wlan_auto_reconnect_config_t *auto_reconnect_config)
{
    if (!auto_reconnect_config)
        return -WM_E_INVAL;

    return wifi_get_auto_reconnect_config(auto_reconnect_config);
}
#endif

void wlan_sta_ampdu_tx_enable(void)
{
    wifi_sta_ampdu_tx_enable();
}

void wlan_sta_ampdu_tx_disable(void)
{
    wifi_sta_ampdu_tx_disable();
}

void wlan_sta_ampdu_rx_enable(void)
{
    wifi_sta_ampdu_rx_enable();
}

void wlan_sta_ampdu_rx_disable(void)
{
    wifi_sta_ampdu_rx_disable();
}

void wlan_uap_set_scan_chan_list(wifi_scan_chan_list_t scan_chan_list)
{
    wlan_uap_scan_chan_list_set = true;
    (void)memcpy((void *)&wlan.scan_chan_list, (const void *)&scan_chan_list, sizeof(wifi_scan_chan_list_t));
}

void wlan_uap_set_beacon_period(const uint16_t beacon_period)
{
    wifi_uap_set_beacon_period(beacon_period);
}

void wlan_uap_set_hidden_ssid(const bool bcast_ssid_ctl)
{
    wifi_uap_set_hidden_ssid(bcast_ssid_ctl);
}

void wlan_uap_ctrl_deauth(const bool enable)
{
    (void)wifi_uap_ctrl_deauth(enable);
}

void wlan_uap_set_ecsa(void)
{
    wifi_uap_set_ecsa();
}

void wlan_uap_set_htcapinfo(const uint16_t ht_cap_info)
{
    wifi_uap_set_htcapinfo(ht_cap_info);
}

uint32_t wlan_get_value1(void)
{
    if (wlan.status == WLCMGR_ACTIVATED)
    {
        return wifi_get_value1();
    }
    else
    {
        return -WM_FAIL;
    }
}

#ifdef CONFIG_WIFI_RTS_THRESHOLD
int wlan_set_rts(int rts)
{
    return wifi_set_rts(rts, MLAN_BSS_TYPE_STA);
}

int wlan_set_uap_rts(int rts)
{
    return wifi_set_rts(rts, MLAN_BSS_TYPE_UAP);
}
#endif

#ifdef CONFIG_WIFI_FRAG_THRESHOLD
int wlan_set_frag(int frag)
{
    return wifi_set_frag(frag, MLAN_BSS_TYPE_STA);
}

int wlan_set_uap_frag(int frag)
{
    return wifi_set_frag(frag, MLAN_BSS_TYPE_UAP);
}

#endif

#ifdef CONFIG_UAP_STA_MAC_ADDR_FILTER
int  wlan_set_sta_mac_filter(int filter_mode, int mac_count, unsigned char *mac_addr)
{
    return wifi_set_sta_mac_filter(filter_mode, mac_count, mac_addr);

}
#endif

#ifdef CONFIG_WPA2_ENTP
void wlan_enable_wpa2_enterprise_ap_only()
{
    wlan.allow_wpa2_enterprise_ap_only = true;
    wifi_scan_enable_wpa2_enterprise_ap_only();
}
#endif

void wlan_version_extended()
{
#if SDK_DEBUGCONSOLE != DEBUGCONSOLE_DISABLE
    char *version_str;

    version_str = wlan_get_firmware_version_ext();

    (void)PRINTF("WLAN Driver Version   : %s\r\n", WLAN_DRV_VERSION);
    (void)PRINTF("WLAN Firmware Version : %s\r\n", version_str);
#endif
}

#ifdef CONFIG_RF_TEST_MODE

int wlan_set_rf_test_mode(void)
{
    return wifi_set_rf_test_mode();
}

int wlan_set_rf_channel(const uint8_t channel)
{
    return wifi_set_rf_channel(channel);
}

int wlan_get_rf_channel(uint8_t *channel)
{
    if (channel != NULL)
        return wifi_get_rf_channel(channel);

    return -WM_FAIL;
}

int wlan_set_rf_bandwidth(const uint8_t bandwidth)
{
    return wifi_set_rf_bandwidth(bandwidth);
}

int wlan_set_rf_band(const uint8_t band)
{
    return wifi_set_rf_band(band);
}

int wlan_get_rf_band(uint8_t *band)
{
    if (band != NULL)
        return wifi_get_rf_band(band);

    return -WM_FAIL;
}

int wlan_get_rf_bandwidth(uint8_t *bandwidth)
{
    if (bandwidth != NULL)
        return wifi_get_rf_bandwidth(bandwidth);

    return -WM_FAIL;
}

int wlan_get_rf_per(uint32_t *rx_tot_pkt_count, uint32_t *rx_mcast_bcast_count, uint32_t *rx_pkt_fcs_error)
{
    if ((rx_tot_pkt_count != NULL) && (rx_mcast_bcast_count != NULL) && (rx_pkt_fcs_error != NULL))
        return wifi_get_rf_per(rx_tot_pkt_count, rx_mcast_bcast_count, rx_pkt_fcs_error);

    return -WM_FAIL;
}

int wlan_set_rf_tx_cont_mode(const uint32_t enable_tx,
                             const uint32_t cw_mode,
                             const uint32_t payload_pattern,
                             const uint32_t cs_mode,
                             const uint32_t act_sub_ch,
                             const uint32_t tx_rate)
{
    return wifi_set_rf_tx_cont_mode(enable_tx, cw_mode, payload_pattern, cs_mode, act_sub_ch, tx_rate);
}

int wlan_set_rf_tx_antenna(const uint8_t antenna)
{
    return wifi_set_rf_tx_antenna(antenna);
}

int wlan_get_rf_tx_antenna(uint8_t *antenna)
{
    if (antenna != NULL)
        return wifi_get_rf_tx_antenna(antenna);

    return -WM_FAIL;
}

int wlan_set_rf_rx_antenna(const uint8_t antenna)
{
    return wifi_set_rf_rx_antenna(antenna);
}

int wlan_get_rf_rx_antenna(uint8_t *antenna)
{
    if (antenna != NULL)
        return wifi_get_rf_rx_antenna(antenna);

    return -WM_FAIL;
}

int wlan_set_rf_tx_power(const uint8_t power, const uint8_t mod, const uint8_t path_id)
{
    return wifi_set_rf_tx_power(power, mod, path_id);
}

int wlan_set_rf_tx_frame(const uint32_t enable,
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
    return wifi_set_rf_tx_frame(enable, data_rate, frame_pattern, frame_length, adjust_burst_sifs, burst_sifs_in_us,
                                short_preamble, act_sub_ch, short_gi, adv_coding, tx_bf, gf_mode, stbc, bssid);
}
#endif
#ifdef CONFIG_WIFI_FW_DEBUG
void wlan_register_fw_dump_cb(void (*wlan_usb_init_cb)(void),
                              int (*wlan_usb_mount_cb)(),
                              int (*wlan_usb_file_open_cb)(char *test_file_name),
                              int (*wlan_usb_file_write_cb)(uint8_t *data, size_t data_len),
                              int (*wlan_usb_file_close_cb)())
{
    wlan.wlan_usb_init_cb = wlan_usb_init_cb;
    wifi_register_fw_dump_cb(wlan_usb_mount_cb, wlan_usb_file_open_cb, wlan_usb_file_write_cb, wlan_usb_file_close_cb);
}
#endif

int wlan_send_hostcmd(
    void *cmd_buf, uint32_t cmd_buf_len, void *resp_buf, uint32_t resp_buf_len, uint32_t *reqd_resp_len)
{
    if ((cmd_buf == NULL) || (resp_buf == NULL) || (reqd_resp_len == NULL))
    {
        return WM_E_NOMEM;
    }
    if (!cmd_buf_len || !resp_buf_len)
    {
        return WM_E_INVAL;
    }

    return wifi_send_hostcmd(cmd_buf, cmd_buf_len, resp_buf, resp_buf_len, reqd_resp_len);
}

#ifdef CONFIG_11AX
int wlan_set_11ax_tx_omi(const t_u16 tx_omi)
{
    if (is_sta_connected())
        return wifi_set_11ax_tx_omi(tx_omi);
    else
    {
        wifi_d("STA not connected");
        return -WM_FAIL;
    }
}
#endif
