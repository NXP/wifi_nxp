/** @file main.c
 *
 *  @brief main file
 *
 *  Copyright 2020 NXP
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
#include <wm_os.h>
#include "dhcp-server.h"
#include "cli.h"
#include "wifi_ping.h"
#include "iperf.h"
#include "app.h"
#include "fsl_power.h"
#ifndef RW610
#include "wifi_bt_config.h"
#else
#include "pin_mux.h"
#include "fsl_power.h"
#include "fsl_pm_core.h"
#include "fsl_pm_device.h"
#include "fsl_rtc.h"
#endif
#ifdef CONFIG_WPS2
#include "wmtime.h"
#endif

#include "cli_utils.h"
#ifdef CONFIG_WIFI_USB_FILE_ACCESS
#include "usb_api.h"
#endif

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

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
#else
#include "ksdk_mbedtls.h"
#endif



/*******************************************************************************
 * Definitions
 ******************************************************************************/
/*******************************************************************************
 * Prototypes
 ******************************************************************************/
int wlan_driver_init(void);
int wlan_driver_deinit(void);
int wlan_driver_reset(void);
int wlan_reset_cli_init(void);
#ifdef CONFIG_WPS2
static int wlan_prov_cli_init(void);
static int wlan_prov_cli_deinit(void);
#endif

/*******************************************************************************
 * Variables
 ******************************************************************************/

const int TASK_MAIN_PRIO = OS_PRIO_3;
#ifdef CONFIG_WPS2
const int TASK_MAIN_STACK_SIZE = 1500;
#else
const int TASK_MAIN_STACK_SIZE = 800;
#endif

portSTACK_TYPE *task_main_stack = NULL;
TaskHandle_t task_main_task_handler;
#ifdef RW610
#ifdef CONFIG_POWER_MANAGER
/* Global power manager handle */
AT_ALWAYS_ON_DATA(pm_handle_t pm_handle);
AT_ALWAYS_ON_DATA(pm_wakeup_source_t wlanWakeupSource);
AT_ALWAYS_ON_DATA(pm_wakeup_source_t rtcWakeupSource);
AT_ALWAYS_ON_DATA(pm_wakeup_source_t pin1WakeupSource);
extern pm_notify_element_t wlan_notify;
extern bool is_wakeup_cond_set;
#define APP_PM2_CONSTRAINTS                                                                           \
    6U, PM_RESC_SRAM_0K_384K_STANDBY, PM_RESC_SRAM_384K_448K_STANDBY, PM_RESC_SRAM_448K_512K_STANDBY, \
        PM_RESC_SRAM_512K_640K_STANDBY, PM_RESC_SRAM_640K_896K_STANDBY, PM_RESC_SRAM_896K_1216K_STANDBY
#if defined(configLIBRARY_MAX_SYSCALL_INTERRUPT_PRIORITY)
#ifndef POWER_MANAGER_RTC_PIN1_PRIORITY
#define POWER_MANAGER_RTC_PIN1_PRIORITY (configLIBRARY_MAX_SYSCALL_INTERRUPT_PRIORITY + 1)
#endif
#else
#ifndef POWER_MANAGER_RTC_PIN1_PRIORITY
#define POWER_MANAGER_RTC_PIN1_PRIORITY (3U)
#endif
#endif
#endif
#endif

/*******************************************************************************
 * Code
 ******************************************************************************/

static void printSeparator(void)
{
    PRINTF("========================================\r\n");
}

static struct wlan_network sta_network;
static struct wlan_network uap_network;

/* Callback Function passed to WLAN Connection Manager. The callback function
 * gets called when there are WLAN Events that need to be handled by the
 * application.
 */
int wlan_event_callback(enum wlan_event_reason reason, void *data)
{
    int ret;
    struct wlan_ip_config addr;
    char ip[16];
    static int auth_fail = 0;

    printSeparator();
    PRINTF("app_cb: WLAN: received event %d\r\n", reason);
    printSeparator();

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

            ret = dhcpd_cli_init();
            if (ret != WM_SUCCESS)
            {
                PRINTF("Failed to initialize DHCP Server CLI\r\n");
                return 0;
            }

#ifdef CONFIG_WPS2
            ret = wlan_prov_cli_init();
            if (ret != WM_SUCCESS)
            {
                PRINTF("Failed to initialize PROV CLI\r\n");
                return 0;
            }
#endif

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

            ret = wlan_get_current_network(&sta_network);
            if (ret != WM_SUCCESS)
            {
                PRINTF("Failed to get External AP network\r\n");
                return 0;
            }

            PRINTF("Connected to following BSS:\r\n");
            PRINTF("SSID = [%s]\r\n", sta_network.ssid);
            if (addr.ipv4.address != 0U)
            {
                PRINTF("IPv4 Address: [%s]\r\n", ip);
            }
#ifdef CONFIG_IPV6
            int i;
            for (i = 0; i < CONFIG_MAX_IPV6_ADDRESSES; i++)
            {
                if (ip6_addr_isvalid(addr.ipv6[i].addr_state))
                {
                    (void)PRINTF("IPv6 Address: %-13s:\t%s (%s)\r\n", ipv6_addr_type_to_desc((struct net_ipv6_config *)&addr.ipv6[i]),
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
            PRINTF("app_cb: WLAN: link lost\r\n");
            break;
        case WLAN_REASON_CHAN_SWITCH:
            PRINTF("app_cb: WLAN: channel switch\r\n");
            break;
        case WLAN_REASON_UAP_SUCCESS:
            PRINTF("app_cb: WLAN: UAP Started\r\n");
            ret = wlan_get_current_uap_network(&uap_network);

            if (ret != WM_SUCCESS)
            {
                PRINTF("Failed to get Soft AP network\r\n");
                return 0;
            }

            printSeparator();
            PRINTF("Soft AP \"%s\" started successfully\r\n", uap_network.ssid);
            printSeparator();
            if (dhcp_server_start(net_get_uap_handle()))
                PRINTF("Error in starting dhcp server\r\n");

            PRINTF("DHCP Server started successfully\r\n");
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
        case WLAN_REASON_UAP_CLIENT_DISSOC:
            PRINTF("app_cb: WLAN: UAP a Client Dissociated\r\n");
            printSeparator();
            PRINTF("Client => ");
            print_mac((const char *)data);
            PRINTF("Dis-Associated from Soft AP\r\n");
            printSeparator();
            break;
        case WLAN_REASON_UAP_STOPPED:
            PRINTF("app_cb: WLAN: UAP Stopped\r\n");
            printSeparator();
            PRINTF("Soft AP \"%s\" stopped successfully\r\n", uap_network.ssid);
            printSeparator();

            dhcp_server_stop();

            PRINTF("DHCP Server stopped successfully\r\n");
            printSeparator();
            break;
        case WLAN_REASON_PS_ENTER:
            PRINTF("app_cb: WLAN: PS_ENTER\r\n");
            break;
        case WLAN_REASON_PS_EXIT:
            PRINTF("app_cb: WLAN: PS EXIT\r\n");
            break;
        default:
            PRINTF("app_cb: WLAN: Unknown Event: %d\r\n", reason);
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

#ifndef RW610
int wlan_driver_deinit(void)
{
    int result = 0;

    result = wlan_stop();
    assert(0 == result);
    wlan_deinit(0);

    return result;
}

static void wlan_hw_reset(void)
{
    BOARD_WIFI_BT_Enable(false);
    os_thread_sleep(1);
    BOARD_WIFI_BT_Enable(true);
}

int wlan_driver_reset(void)
{
    int result = 0;

    result = wlan_driver_deinit();
    assert(0 == result);

    wlan_hw_reset();

    result = wlan_driver_init();
    assert(0 == result);

    return result;
}

static void test_wlan_reset(int argc, char **argv)
{
    (void)wlan_driver_reset();
}

static struct cli_command wlan_reset_commands[] = {
    {"wlan-reset", NULL, test_wlan_reset},
};

int wlan_reset_cli_init(void)
{
    unsigned int i;

    for (i = 0; i < sizeof(wlan_reset_commands) / sizeof(struct cli_command); i++)
    {
        if (cli_register_command(&wlan_reset_commands[i]) != 0)
        {
            return -1;
        }
    }

    return 0;
}
#endif

#ifdef RW610
#ifdef CONFIG_POWER_MANAGER
void powerManager_StartRtcTimer(uint64_t timeOutUs)
{
    uint32_t currSeconds;

    PM_EnableWakeupSource(&rtcWakeupSource);
    /* Read the RTC seconds register to get current time in seconds */
    currSeconds = RTC_GetSecondsTimerCount(RTC);
    /* Add alarm seconds to current time */
    currSeconds += (timeOutUs + 999999U) / 1000000U;
    /* Set alarm time in seconds */
    RTC_SetSecondsTimerMatch(RTC, currSeconds);
}

void powerManager_StopRtcTimer()
{
    RTC_ClearStatusFlags(RTC, kRTC_AlarmFlag);
    PM_DisableWakeupSource(&rtcWakeupSource);
}

void RTC_IRQHandler()
{
    if (RTC_GetStatusFlags(RTC) & kRTC_AlarmFlag)
    {
        RTC_ClearStatusFlags(RTC, kRTC_AlarmFlag);
        PM_DisableWakeupSource(&rtcWakeupSource);
        wakeup_by = WAKEUP_BY_RTC;
    }
}

void PIN1_INT_IRQHandler()
{
    POWER_ConfigWakeupPin(kPOWER_WakeupPin1, kPOWER_WakeupEdgeHigh);
    NVIC_ClearPendingIRQ(PIN1_INT_IRQn);
    DisableIRQ(PIN1_INT_IRQn);
    POWER_ClearWakeupStatus(PIN1_INT_IRQn);
    POWER_DisableWakeup(PIN1_INT_IRQn);
    wakeup_by = WAKEUP_BY_PIN1;
}

void powerManager_RTC_Init()
{
    DisableIRQ(RTC_IRQn);
    POWER_ClearWakeupStatus(RTC_IRQn);
    POWER_DisableWakeup(RTC_IRQn);
    RTC_Init(RTC);
    /* Enable wakeup in PD mode */
    RTC_EnableAlarmTimerInterruptFromDPD(RTC, true);
    /* Start RTC */
    RTC_ClearStatusFlags(RTC, kRTC_AlarmFlag);
    RTC_StartTimer(RTC);
    /* Register RTC timer callbacks in power manager */
    PM_RegisterTimerController(&pm_handle, powerManager_StartRtcTimer, powerManager_StopRtcTimer, NULL, NULL);
}

void powerManager_Wakeupsource_Init()
{
    memset(&wlanWakeupSource, 0x0, sizeof(pm_wakeup_source_t));
    memset(&rtcWakeupSource, 0x0, sizeof(pm_wakeup_source_t));
    memset(&pin1WakeupSource, 0x0, sizeof(pm_wakeup_source_t));
    /* Init WLAN wakeup source. Power manager API PM_InitWakeupSource()
     * can't be called to init WLAN wakeup source since RW610 use IMU
     * interrupt to wakeup host and can't be disabled here.
     */
    wlanWakeupSource.wsId    = WL_MCI_WAKEUP0_IRQn;
    wlanWakeupSource.service = NULL;
    wlanWakeupSource.enabled = false;
    wlanWakeupSource.active  = false;
    POWER_ClearWakeupStatus(WL_MCI_WAKEUP0_IRQn);
    POWER_DisableWakeup(WL_MCI_WAKEUP0_IRQn);
    /* Init other wakeup sources. Corresponding IRQ numbers act as wsId here. */
    PM_InitWakeupSource(&rtcWakeupSource, RTC_IRQn, NULL, false);
    PM_InitWakeupSource(&pin1WakeupSource, PM_WSID_WAKEUP_PIN1_LOW_LEVEL, NULL, false);
}

void powerManager_WakeupSourceDump()
{
    if (wakeup_by == 0x1)
        PRINTF("Woken up by WLAN\r\n");
    if (wakeup_by == 0x2)
        PRINTF("Woken up by RTC\r\n");
    if (wakeup_by == 0x4)
        PRINTF("Woken up by PIN1\r\n");
}

void powerManager_EnterLowPower()
{
    if (pm_handle.enable && !wakelock_isheld()i && is_wakeup_cond_set)
    {
        PM_SetConstraints(PM_LP_STATE_PM2, APP_PM2_CONSTRAINTS);
        /* Enable PIN1 as wakeup sources */
        PM_EnableWakeupSource(&pin1WakeupSource);
        /* duration unit is us here */
        PM_EnterLowPower(60000000);
        powerManager_WakeupSourceDump();
        wakeup_by = 0;
        /* Exit low power and reset constraints */
        PM_ReleaseConstraints(PM_LP_STATE_PM2, APP_PM2_CONSTRAINTS);
    }
}

void powerManager_Init()
{
    uint32_t resetSrc;
    power_init_config_t initCfg =
    {
        /* VCORE AVDD18 supplied from iBuck on RD board. */
        .iBuck         = true,
        /* CAU_SOC_SLP_REF_CLK not needed. */
        .gateCauRefClk = true,
    };
    
    POWER_InitPowerConfig(&initCfg);
    resetSrc = POWER_GetResetCause();
    PRINTF("\r\nMCU wakeup source 0x%x...\r\n", resetSrc);
    /* In case PM3/PM4 wakeup, the wakeup config and status need to be cleared */
    POWER_ClearResetCause(resetSrc);

    PM_CreateHandle(&pm_handle);
    /* Init and start RTC time counter */
    powerManager_RTC_Init();
    /* Set priority of RTC and PIN1 interrupt */
    NVIC_SetPriority(RTC_IRQn, POWER_MANAGER_RTC_PIN1_PRIORITY);
    NVIC_SetPriority(PIN1_INT_IRQn, POWER_MANAGER_RTC_PIN1_PRIORITY);
    /* Register WLAN notifier */
    PM_RegisterNotify(kPM_NotifyGroup0, &wlan_notify);
    /* Init WLAN wakeup source */
    powerManager_Wakeupsource_Init();
    PM_EnablePowerManager(true);
    os_setup_idle_function(powerManager_EnterLowPower);
    wakeup_by = 0;
}
#endif
#endif

#ifdef CONFIG_WPS2
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

#ifdef CONFIG_WIFI_USB_FILE_ACCESS
static void dump_read_usb_file_usage(void)
{
    (void)PRINTF("Usage: wlan-read-usb-file <type:ca-cert/client-cert/client-key> <file name>\r\n");
    (void)PRINTF("\r\nUsage example : \r\n");
    (void)PRINTF("wlan-read-usb-file ca-cert 1:/ca.der\r\n");
}

static void test_wlan_read_usb_file(int argc, char **argv)
{
    int ret, data_len, usb_f_type = 0;
    uint8_t *file_buf  = NULL;
    char file_name[32] = {0};

    if (argc < 3)
    {
        (void)PRINTF("Error: invalid number of arguments\r\n");
        dump_read_usb_file_usage();
        return;
    }
    if (string_equal("ca-cert", argv[1]))
        usb_f_type = FILE_TYPE_ENTP_CA_CERT;
    else if (string_equal("client-cert", argv[1]))
        usb_f_type = FILE_TYPE_ENTP_CLIENT_CERT;
    else if (string_equal("client-key", argv[1]))
        usb_f_type = FILE_TYPE_ENTP_CLIENT_KEY;

    memset(file_name, 0, sizeof(file_name));
    (void)memcpy(file_name, argv[2], strlen(argv[2]) < 32 ? strlen(argv[2]) : 32);

    if (WM_SUCCESS != usb_mount())
    {
        PRINTF("Error: USB mounting failed\r\n");
        return;
    }

    ret = usb_file_open_by_mode(file_name, FA_READ);
    if (ret != WM_SUCCESS)
    {
        PRINTF("File opening failed\r\n");
        return;
    }

    data_len = usb_file_size();
    if (data_len == 0)
    {
        PRINTF("File size failed\r\n");
        goto file_err;
    }
    file_buf = os_mem_alloc(data_len);
    if (!file_buf)
    {
        PRINTF("File size allocate memory failed\r\n");
        goto file_err;
    }
    ret = usb_file_read((uint8_t *)file_buf, data_len);
    if (ret != data_len)
    {
        PRINTF("read file %s size not match!(%d,%d)\r\n", file_name, ret, data_len);
        goto file_err;
    }
    (void)wlan_set_entp_cert_files(usb_f_type, file_buf, data_len);

file_err:
    os_mem_free(file_buf);
    usb_file_close();
}

static void test_wlan_dump_usb_file(int argc, char **argv)
{
    int data_len, usb_f_type = 0;
    uint8_t *file_buf = NULL;

    if (string_equal("ca-cert", argv[1]))
        usb_f_type = FILE_TYPE_ENTP_CA_CERT;
    else if (string_equal("client-cert", argv[1]))
        usb_f_type = FILE_TYPE_ENTP_CLIENT_CERT;
    else if (string_equal("client-key", argv[1]))
        usb_f_type = FILE_TYPE_ENTP_CLIENT_KEY;

    data_len = wlan_get_entp_cert_files(usb_f_type, &file_buf);
    (void)PRINTF("[USB File] %s\r\n", argv[1]);
    dump_hex(file_buf, data_len);
    (void)PRINTF("\r\n");
}
#endif

static struct cli_command wlan_prov_commands[] = {
    {"wlan-set-rtc-time", "<year> <month> <day> <hour> <minute> <second>", test_wlan_set_rtc_time},
    {"wlan-get-rtc-time", NULL, test_wlan_get_rtc_time},
#ifdef CONFIG_WIFI_USB_FILE_ACCESS
    {"wlan-read-usb-file", "<type:ca-cert/client-cert/client-key> <file name>", test_wlan_read_usb_file},
    {"wlan-dump-usb-file", "<type:ca-cert/client-cert/client-key>", test_wlan_dump_usb_file},
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

static int wlan_prov_cli_deinit(void)
{
    unsigned int i;

    for (i = 0; i < sizeof(wlan_prov_commands) / sizeof(struct cli_command); i++)
    {
        if (cli_unregister_command(&wlan_prov_commands[i]) != 0)
        {
            return -1;
        }
    }

    return 0;
}
#endif

void task_main(void *param)
{
    int32_t result = 0;
    (void)result;

    PRINTF("Initialize CLI\r\n");
    printSeparator();

    result = cli_init();

    assert(WM_SUCCESS == result);

#ifdef RW610
#ifdef CONFIG_POWER_MANAGER
    PRINTF("Initialize Power Manager\r\n");
    powerManager_Init();
    printSeparator();
#endif
#endif

    PRINTF("Initialize WLAN Driver\r\n");
    printSeparator();

    /* Initialize WIFI Driver */
    result = wlan_driver_init();

    assert(WM_SUCCESS == result);

#ifndef RW610
    result = wlan_reset_cli_init();

    assert(WM_SUCCESS == result);
#endif

    while (1)
    {
        /* wait for interface up */
        os_thread_sleep(os_msec_to_ticks(5000));
    }
}

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

int main(void)
{
    BaseType_t result = 0;
#ifdef CONFIG_WPS2
    struct rtc_cb_t rtc;
#endif
    (void)result;

    BOARD_InitHardware();
#ifdef RW610
    POWER_PowerOffBle();
#endif
    CRYPTO_InitHardware();

    printSeparator();
    PRINTF("wifi cli demo\r\n");
    printSeparator();

    RTC_Init(RTC);

#ifdef CONFIG_WPS2
    memset(&rtc, 0, sizeof(struct rtc_cb_t));
    rtc.base         = (uint32_t)RTC;
    rtc.set_datetime = (int (*)(void *, struct datetime_t *))RTC_SetDatetime;
    rtc.get_datetime = (void (*)(void *, struct datetime_t *))RTC_GetDatetime;
    rtc.initialized  = 1;

    if (rtc.initialized != 0)
        wmtime_register_rtc_cb(&rtc);
#endif

#ifdef CONFIG_WIFI_USB_FILE_ACCESS
    usb_init();
#endif

    result =
        xTaskCreate(task_main, "main", TASK_MAIN_STACK_SIZE, task_main_stack, TASK_MAIN_PRIO, &task_main_task_handler);
    assert(pdPASS == result);

    vTaskStartScheduler();
    for (;;)
        ;
}
