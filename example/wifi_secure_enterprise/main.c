/** @file main.c
 *
 *  @brief main file
 *
 *  Copyright 2026 NXP
 *  All rights reserved.
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 */

///////////////////////////////////////////////////////////////////////////////
//  Includes
///////////////////////////////////////////////////////////////////////////////

// SDK Included Files
#include "board.h"
#include "fsl_debug_console.h"
#include "wlan_bt_fw.h"
#include "wlan.h"
#include "wifi.h"
#include "wm_net.h"
#include <osa.h>
#if CONFIG_NXP_WIFI_SOFTAP_SUPPORT
#include "dhcp-server.h"
#endif
#include "cli.h"
#include "wifi_ping.h"
#include "iperf.h"
#include "app.h"
#include "fsl_rtc.h"
#include "cli_utils.h"
#if CONFIG_HOST_SLEEP
#include "host_sleep.h"
#endif
#include "wpa_cli.h"
#if defined(MBEDTLS_NXP_SSSAPI)
#include "sssapi_mbedtls.h"
#elif defined(MBEDTLS_MCUX_CSS_API)
#include "platform_hw_ip.h"
#include "css_mbedtls.h"
#elif defined(MBEDTLS_MCUX_CSS_PKC_API)
#include "platform_hw_ip.h"
#include "css_pkc_mbedtls.h"
#elif defined(MBEDTLS_MCUX_ELS_PKC_API)
#include "platform_hw_ip.h"
#include "els_pkc_mbedtls.h"
#elif defined(MBEDTLS_MCUX_ELS_API)
#include "platform_hw_ip.h"
#include "els_mbedtls.h"
#elif defined(MBEDTLS_MCUX_ELE_S400_API)
#include "ele_mbedtls.h"
#else
#if CONFIG_KSDK_MBEDTLS
#include "ksdk_mbedtls.h"
#endif
#endif
#if defined(MBEDTLS_USER_CONFIG_FILE)
#include MBEDTLS_USER_CONFIG_FILE
#endif
#if defined(MBEDTLS_THREADING_C) && defined(MBEDTLS_THREADING_ALT)
#include "threading_alt.h"
#endif
#if defined(CONFIG_WIFI_ENTERPRISE_SECURE_BLOB)
#include "secure_storage.h"
#include "el2go_psa_import.h"
#include "wlan_secure.h"
#endif
/*******************************************************************************
 * Definitions
 ******************************************************************************/

/*******************************************************************************
 * Prototypes
 ******************************************************************************/
int wlan_driver_init(void);
#if CONFIG_HOST_SLEEP
int wlan_hs_cli_init(void);
int wlan_hs_cli_deinit(void);
#endif

static int wlan_prov_cli_init(void);

extern int wpa_cli_init(void);
/*******************************************************************************
 * Code
 ******************************************************************************/

#if defined(CONFIG_WIFI_ENTERPRISE_SECURE_BLOB)
#define MAIN_TASK_STACK_SIZE 9216
#define MAX_SECURE_BLOB_KEYS 4
psa_key_id_t wifi_client_key_id = PSA_KEY_ID_NULL;
#else
#define MAIN_TASK_STACK_SIZE 4096
#endif

static void main_task(osa_task_param_t arg);

static OSA_TASK_DEFINE(main_task, WLAN_TASK_PRI_LOW, 1, MAIN_TASK_STACK_SIZE, 0);

OSA_TASK_HANDLE_DEFINE(main_task_Handle);

static void printSeparator(void)
{
    PRINTF("========================================\r\n");
}

/* Callback Function passed to WLAN Connection Manager. The callback function
 * gets called when there are WLAN Events that need to be handled by the
 * application.
 */
int wlan_event_callback(enum wlan_event_reason reason, void *data)
{
    int ret;
    struct wlan_ip_config addr;
    char ssid[IEEEtypes_SSID_SIZE + 1] = {0};
    char ip[16];
    static int auth_fail = 0;
#if CONFIG_NXP_WIFI_SOFTAP_SUPPORT
    wlan_uap_client_disassoc_t *disassoc_resp = data;
    wlan_uap_client_event_t *client_event;
#endif

#if CONFIG_WPA_SUPP_P2P
    struct wlan_network *uap_network = NULL;
#endif
    enum wlan_bss_type bss_type;

    switch (reason)
    {
        case WLAN_REASON_INITIALIZED:
            PRINTF("app_cb: WLAN initialized\r\n");
            printSeparator();

            ret = wlan_basic_cli_init();
            if (ret != WM_SUCCESS)
            {
                PRINTF("Failed to initialize BASIC WLAN CLIs\r\n");
                return 0;
            }

            ret = wlan_cli_init();
            if (ret != WM_SUCCESS)
            {
                PRINTF("Failed to initialize WLAN CLIs\r\n");
                return 0;
            }
            PRINTF("WLAN CLIs are initialized\r\n");
            printSeparator();

            ret = wlan_enhanced_cli_init();
            if (ret != WM_SUCCESS)
            {
                PRINTF("Failed to initialize WLAN CLIs\r\n");
                return 0;
            }
            PRINTF("ENHANCED WLAN CLIs are initialized\r\n");
            printSeparator();
#ifdef RW610
#if CONFIG_HOST_SLEEP
            ret = host_sleep_cli_init();
            if (ret != WM_SUCCESS)
            {
                PRINTF("Failed to initialize WLAN CLIs\r\n");
                return 0;
            }
            PRINTF("HOST SLEEP CLIs are initialized\r\n");
            printSeparator();
#endif
#endif
            ret = ping_cli_init();
            if (ret != WM_SUCCESS)
            {
                PRINTF("Failed to initialize PING CLI\r\n");
                return 0;
            }

            ret = iperf_cli_init();
            if (ret != WM_SUCCESS)
            {
                PRINTF("Failed to initialize IPERF CLI\r\n");
                return 0;
            }

#if CONFIG_NXP_WIFI_SOFTAP_SUPPORT
            ret = dhcpd_cli_init();
            if (ret != WM_SUCCESS)
            {
                PRINTF("Failed to initialize DHCP Server CLI\r\n");
                return 0;
            }
#endif

            ret = wpa_cli_init();
            if (ret != WM_SUCCESS)
            {
                PRINTF("Failed to initialize WPA SUPP CLI\r\n");
                return 0;
            }
            ret = wlan_prov_cli_init();
            if (ret != WM_SUCCESS)
            {
                PRINTF("Failed to initialize PROV CLI\r\n");
                return 0;
            }

            PRINTF("CLIs Available:\r\n");
            printSeparator();
            help_command(0, NULL);
            printSeparator();
            break;
        case WLAN_REASON_INITIALIZATION_FAILED:
            PRINTF("app_cb: WLAN: initialization failed\r\n");
            break;
        case WLAN_REASON_AUTH_SUCCESS:
            PRINTF("app_cb: WLAN: authenticated to network\r\n");
            break;
        case WLAN_REASON_SUCCESS:
            PRINTF("app_cb: WLAN: connected to network\r\n");
            ret = wlan_get_address(&addr);
            if (ret != WM_SUCCESS)
            {
                PRINTF("failed to get IP address\r\n");
                return 0;
            }

            net_inet_ntoa(addr.ipv4.address, ip);

            ret = wlan_get_current_network_ssid(ssid);
            if (ret != WM_SUCCESS)
            {
                PRINTF("Failed to get External AP network\r\n");
                return 0;
            }

            PRINTF("Connected to following BSS:\r\n");
            PRINTF("SSID = [%s]\r\n", ssid);
            if (addr.ipv4.address != 0U)
            {
                PRINTF("IPv4 Address: [%s]\r\n", ip);
            }
#if CONFIG_IPV6
            int i;
            for (i = 0; i < CONFIG_MAX_IPV6_ADDRESSES; i++)
            {
                if (ip6_addr_isvalid(addr.ipv6[i].addr_state))
                {
                    (void)PRINTF("IPv6 Address: %-13s:\t%s (%s)\r\n",
                                 ipv6_addr_type_to_desc((struct net_ipv6_config *)&addr.ipv6[i]),
                                 inet6_ntoa(addr.ipv6[i].address), ipv6_addr_state_to_desc(addr.ipv6[i].addr_state));
                }
            }
            (void)PRINTF("\r\n");
#endif
            auth_fail = 0;
            break;
        case WLAN_REASON_CONNECT_FAILED:
            PRINTF("app_cb: WLAN: connect failed\r\n");
            break;
        case WLAN_REASON_NETWORK_NOT_FOUND:
            PRINTF("app_cb: WLAN: network not found\r\n");
            break;
        case WLAN_REASON_NETWORK_AUTH_FAILED:
            PRINTF("app_cb: WLAN: network authentication failed\r\n");
            auth_fail++;
            if (auth_fail >= 3)
            {
                PRINTF("Authentication Failed. Disconnecting ... \r\n");
                wlan_disconnect();
                auth_fail = 0;
            }
            break;
        case WLAN_REASON_ADDRESS_SUCCESS:
            PRINTF("network mgr: DHCP new lease\r\n");
            break;
        case WLAN_REASON_ADDRESS_FAILED:
            PRINTF("app_cb: failed to obtain an IP address\r\n");
            break;
        case WLAN_REASON_USER_DISCONNECT:
            PRINTF("app_cb: disconnected\r\n");
            auth_fail = 0;
            break;
        case WLAN_REASON_LINK_LOST:
            if ((int)data == IEEEtypes_REASON_DEAUTH_LEAVING)
            {
                PRINTF("app_cb: WLAN: Deauthenticated \r\n");
            }
            else
            {
                PRINTF("app_cb: WLAN: link lost\r\n");
            }
            break;
        case WLAN_REASON_CHAN_SWITCH:
            PRINTF("app_cb: WLAN: channel switch\r\n");
            break;
#if CONFIG_NXP_WIFI_SOFTAP_SUPPORT
        case WLAN_REASON_UAP_SUCCESS:
            bss_type = (enum wlan_bss_type)(uintptr_t)data;
            if (bss_type == WLAN_BSS_TYPE_UAP)
            {
                PRINTF("app_cb: WLAN: UAP Started\r\n");
                void *intrfc_handle;
                ret = wlan_get_current_uap_network_ssid(ssid);

                if (ret != WM_SUCCESS)
                {
                    PRINTF("Failed to get Soft AP network\r\n");
                    return 0;
                }

                printSeparator();
                PRINTF("Soft AP \"%s\" started successfully\r\n", ssid);
                printSeparator();
                intrfc_handle = net_get_uap_handle();

                ret = dhcp_server_start_ex(intrfc_handle, DHCP_INSTANCE_UAP);
                if (ret != 0)
                {
                    PRINTF("%s\r\n", dhcp_server_err_str(ret));
                }
                else
                {
                    (void)PRINTF("DHCP Server started successfully\r\n");
                }
            }
#if CONFIG_WPA_SUPP_P2P
            else
            {
                PRINTF("app_cb: WLAN: P2P GO Started\r\n");
                void *intrfc_handle;
                ret = wlan_get_current_wfd_network_ssid(ssid);

                if (ret != WM_SUCCESS)
                {
                    PRINTF("Failed to get P2P GO network\r\n");
                    return 0;
                }

                printSeparator();
                PRINTF("P2P GO \"%s\" started successfully\r\n", ssid);
                printSeparator();
                intrfc_handle = net_get_wfd_handle();

                ret = dhcp_server_start_ex(intrfc_handle, DHCP_INSTANCE_WFD_GO);
                if (ret != 0)
                {
                    PRINTF("%s\r\n", dhcp_server_err_str(ret));
                }
                else
                {
                    (void)PRINTF("DHCP Server started successfully\r\n");
                }
            }
#endif
            printSeparator();
            break;
        case WLAN_REASON_UAP_CLIENT_ASSOC:
            PRINTF("app_cb: WLAN: UAP a Client Associated\r\n");
            printSeparator();
            PRINTF("Client => ");
            print_mac((const char *)data);
            PRINTF("Associated with Soft AP\r\n");
            printSeparator();
            break;
        case WLAN_REASON_UAP_CLIENT_CONN:
            client_event = (wlan_uap_client_event_t *)data;
#if CONFIG_WPA_SUPP_P2P
            if (client_event->bss_type == WLAN_BSS_TYPE_WIFIDIRECT)
            {
                PRINTF("app_cb: WLAN: P2P GO a Client Connected\r\n");
                printSeparator();
                PRINTF("Client => ");
                print_mac((const char *)client_event->mac);
                PRINTF("Connected with P2P GO\r\n");
                printSeparator();
            }

            else
            {
#endif
                PRINTF("app_cb: WLAN: UAP a Client Connected\r\n");
                printSeparator();
                PRINTF("Client => ");
                print_mac((const char *)client_event->mac);
                PRINTF("Connected with Soft AP\r\n");
                printSeparator();
#if CONFIG_WPA_SUPP_P2P
            }
#endif
            break;
        case WLAN_REASON_UAP_CLIENT_DISSOC:
#if CONFIG_WPA_SUPP_P2P
            if (disassoc_resp->bss_type == WLAN_BSS_TYPE_WIFIDIRECT)
            {
                printSeparator();
                PRINTF("app_cb: WLAN: P2P GO a Client Dissociated:");
                PRINTF(" Client MAC => ");
                print_mac((const char *)(disassoc_resp->sta_addr));
                PRINTF(" Reason code => ");
                PRINTF("%d\r\n", disassoc_resp->reason_code);
                printSeparator();
            }

            else
            {
#endif
                printSeparator();
                PRINTF("app_cb: WLAN: UAP a Client Dissociated:");
                PRINTF(" Client MAC => ");
                print_mac((const char *)(disassoc_resp->sta_addr));
                PRINTF(" Reason code => ");
                PRINTF("%d\r\n", disassoc_resp->reason_code);
                printSeparator();
#if CONFIG_WPA_SUPP_P2P
            }
#endif
            break;
        case WLAN_REASON_UAP_STOPPED:
            bss_type = (enum wlan_bss_type)(uintptr_t)data;
            if (bss_type == WLAN_BSS_TYPE_UAP)
            {
                PRINTF("app_cb: WLAN: UAP Stopped\r\n");
                printSeparator();
                PRINTF("Soft AP stopped successfully\r\n");
                printSeparator();

                dhcp_server_stop_ex(DHCP_INSTANCE_UAP);

                PRINTF("DHCP Server stopped successfully\r\n");
                printSeparator();
            }
#if CONFIG_WPA_SUPP_P2P
            else
            {
                PRINTF("app_cb: WLAN: P2P GO Stopped\r\n");
                printSeparator();
                PRINTF("P2P GO stopped successfully\r\n");
                printSeparator();

                dhcp_server_stop_ex(DHCP_INSTANCE_WFD_GO);

                PRINTF("DHCP Server stopped successfully\r\n");
                printSeparator();
            }
#endif
            break;
#endif /* CONFIG_NXP_WIFI_SOFTAP_SUPPORT */
        case WLAN_REASON_PS_ENTER:
            break;
        case WLAN_REASON_PS_EXIT:
            break;
        case WLAN_REASON_RSSI_LOW:
#if CONFIG_SUBSCRIBE_EVENT_SUPPORT
        case WLAN_REASON_RSSI_HIGH:
        case WLAN_REASON_SNR_LOW:
        case WLAN_REASON_SNR_HIGH:
        case WLAN_REASON_MAX_FAIL:
        case WLAN_REASON_BEACON_MISSED:
        case WLAN_REASON_DATA_RSSI_LOW:
        case WLAN_REASON_DATA_RSSI_HIGH:
        case WLAN_REASON_DATA_SNR_LOW:
        case WLAN_REASON_DATA_SNR_HIGH:
        case WLAN_REASON_LINK_QUALITY:
        case WLAN_REASON_PRE_BEACON_LOST:
#endif
            break;
        case WLAN_REASON_FW_HANG:
        case WLAN_REASON_FW_RESET:
#ifdef RW610
            PRINTF("app_cb: WLAN: FW hang Event: %d\r\n", reason);
#endif
            break;
        default:
            PRINTF("app_cb: WLAN: Unknown Event: %d\r\n", reason);
            break;
    }
    return 0;
}

int wlan_driver_init(void)
{
    int result = 0;

    /* Initialize WIFI Driver */
    result = wlan_init(wlan_fw_bin, wlan_fw_bin_len);

    assert(0 == result);

    result = wlan_start(wlan_event_callback);

    assert(0 == result);

    return result;
}

#ifdef RW610
static void dump_set_rtc_time_usage(void)
{
    (void)PRINTF("Usage: wlan-set-rtc-time <year> <month> <day> <hour> <minute> <second>\r\n");
    (void)PRINTF("\r\nUsage example : \r\n");
    (void)PRINTF("wlan-set-rtc-time 2022 12 31 19 00\r\n");
}

static void test_wlan_set_rtc_time(int argc, char **argv)
{
    rtc_datetime_t date;
    int ret;

    if (argc < 0)
    {
        (void)PRINTF("Error: invalid number of arguments\r\n");
        dump_set_rtc_time_usage();
        return;
    }
    date.year   = (uint16_t)atoi(argv[1]);
    date.month  = (uint8_t)atoi(argv[2]);
    date.day    = (uint8_t)atoi(argv[3]);
    date.hour   = (uint8_t)atoi(argv[4]);
    date.minute = (uint8_t)atoi(argv[5]);
    date.second = (uint8_t)atoi(argv[6]);

    /* RTC time counter has to be stopped before setting the date & time in the TSR register */
    RTC_EnableTimer(RTC, false);

    /* Set RTC time to default */
    ret = RTC_SetDatetime(RTC, &date);
    if (ret != kStatus_Success)
    {
        (void)PRINTF("Error: invalid number of arguments\r\n");
        dump_set_rtc_time_usage();
    }

    /* Start the RTC time counter */
    RTC_EnableTimer(RTC, true);

    /* Get date time */
    RTC_GetDatetime(RTC, &date);

    /* print default time */
    (void)PRINTF("Current datetime: %04hd-%02hd-%02hd %02hd:%02hd:%02hd\r\n", date.year, date.month, date.day,
                 date.hour, date.minute, date.second);
}

static void test_wlan_get_rtc_time(int argc, char **argv)
{
    rtc_datetime_t date;

    /* Get date time */
    RTC_GetDatetime(RTC, &date);

    /* print default time */
    (void)PRINTF("Current datetime: %04hd-%02hd-%02hd %02hd:%02hd:%02hd\r\n", date.year, date.month, date.day,
                 date.hour, date.minute, date.second);
}
#endif

static struct cli_command wlan_prov_commands[] = {
#ifdef RW610
    {"wlan-set-rtc-time", "<year> <month> <day> <hour> <minute> <second>", test_wlan_set_rtc_time},
    {"wlan-get-rtc-time", NULL, test_wlan_get_rtc_time},
#endif
};

static int wlan_prov_cli_init(void)
{
    unsigned int i;

    for (i = 0; i < sizeof(wlan_prov_commands) / sizeof(struct cli_command); i++)
    {
        if (cli_register_command(&wlan_prov_commands[i]) != 0)
        {
            return -1;
        }
    }

    return 0;
}

static void main_task(osa_task_param_t arg)
{
    int32_t result = 0;
    (void)result;
#if defined(CONFIG_WIFI_ENTERPRISE_SECURE_BLOB)
    psa_status_t psa_status = PSA_SUCCESS;
    size_t blobs_imported = 0U;
    psa_key_id_t psa_key_id_list[MAX_SECURE_BLOB_KEYS] = {0};

    psa_status = psa_crypto_init();
    if (psa_status != PSA_SUCCESS)
    {
        PRINTF("psa_crypto_init failed! status=%d\r\n", psa_status);
        return;
    }

    psa_status = secure_storage_its_initialize();
    if (psa_status != PSA_SUCCESS)
    {
        PRINTF("secure_storage_its_initialize failed! status=%d\r\n", psa_status);
        return;
    }
    else
    {
        PRINTF("secure_storage_its_initialize is successful!\r\n");
    }

    psa_status = iot_agent_utils_psa_import_blobs_from_flash_exp_key_id((uint8_t *)BLOB_AREA,
        BLOB_AREA_SIZE, &blobs_imported, psa_key_id_list, MAX_SECURE_BLOB_KEYS);
    if (psa_status != PSA_SUCCESS)
    {
        PRINTF("import blobs failed! status=%d\r\n", psa_status);
        return;
    }
    PRINTF("%zx blob(s) imported from flash (0x%08X) successfully\r\n", blobs_imported, BLOB_AREA);

    psa_status = wlan_find_eap_tls_client_key(psa_key_id_list, MAX_SECURE_BLOB_KEYS, &wifi_client_key_id);
    if (psa_status != PSA_SUCCESS)
    {
        PRINTF("EAP-TLS client key not found in imported blobs\r\n");
        return;
    }
    PRINTF("Found Wi-Fi enterprise client key: 0x%08X\r\n", wifi_client_key_id);
#endif /* CONFIG_WIFI_ENTERPRISE_SECURE_BLOB */

    PRINTF("Initialize CLI\r\n");
    printSeparator();

    result = cli_init();

    assert(WM_SUCCESS == result);

#if CONFIG_HOST_SLEEP
    hostsleep_init();
#endif

    PRINTF("Initialize WLAN Driver\r\n");
    printSeparator();

    /* Initialize WIFI Driver */
    result = wlan_driver_init();

    assert(WM_SUCCESS == result);

    while (1)
    {
        /* wait for interface up */
        OSA_TimeDelay(5000);
    }
}

/*******************************************************************************
 * Prototypes
 ******************************************************************************/
int main(void)
{
    OSA_Init();

    BOARD_InitHardware();

    printSeparator();
    PRINTF("wifi secure enterprise demo\r\n");
    printSeparator();
#if defined(MBEDTLS_THREADING_C) && defined(MBEDTLS_THREADING_ALT)
    config_mbedtls_threading_alt();
#endif
#ifdef RW610
    RTC_Init(RTC);
#endif

    (void)OSA_TaskCreate((osa_task_handle_t)main_task_Handle, OSA_TASK(main_task), NULL);

    OSA_Start();

    return 0;
}
