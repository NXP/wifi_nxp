/** @file fw_heartbeat.c
 *
 *  @brief  This file provides Core WLAN definition
 *
 *  Copyright 2008-2023 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <wlan.h>
#include <healthmon.h>
#include <string.h>
#include <wmtypes.h>
#include <wifi.h>

/* The threshold time for maximum time difference allowed between the response
 * of last command sent to the firmware and current time. (in msec)
 */
#define CMD_THRESHOLD_TIME 30000

unsigned char cmd_sent_flag;

extern int wlan_healthmon_test_cmd_to_firmware(void);

#define FW_HEARTBEAT_NAME "fw_heartbeat"

static bool fw_is_sick(unsigned int cur_msec)
{
    /* If the difference in time between the response of last command sent
     * to the WLAN FW and the current time <= CMD_THRESHOLD_TIME,
     * then the system is healthy and there is no need to send the
     * heartbeat command to the WLAN FW.
     */

    if ((cur_msec - wifi_get_last_cmd_sent_ms()) > CMD_THRESHOLD_TIME)
    {
        /* If cmd_sent_flag is not set and and time difference >
         * CMD_THRESHOLD_TIME, then this is the first unsuccessful
         * iteration and the WLAN FW may be dead. So, to verify, send a
         * heartbeat command to the WLAN FW.
         */
        if (!cmd_sent_flag)
        {
            wlan_healthmon_test_cmd_to_firmware();
            cmd_sent_flag = 1;
        }
        /* Else, if cmd_sent_flag is set and time difference >
         * CMD_THRESHOLD_TIME, then this is the second consecutive
         * unsuccessful iteration. Now, the function returns 1, and
         * the healthmon notices that the WLAN FW is dead and does not
         * strobe the watchdog timer next time. So the system reboots
         * after the watchdog timer expires.
         */
        return 1;
    }

    cmd_sent_flag = 0;
    return 0;
}

static void fw_about_to_die(bool is_fw_sick)
{
    /* The system is sick and needs to be rebooted. Before that, just
     * update the diagnostics with reboot reason as WLAN FW unresponsive.
     */
    if (is_fw_sick)
    {
        // diagnostics_set_reboot_reason(REASON_WLAN_FW_UNRESPONSIVE);
    }
}

int wlan_fw_heartbeat_register_healthmon()
{
    struct healthmon_handler handler;

    strncpy(handler.name, FW_HEARTBEAT_NAME, HM_NAME_MAX);
    handler.is_sick      = fw_is_sick;
    handler.about_to_die = fw_about_to_die;
    /* After every 10 sec healthmon should monitor
     * the health of WLAN firmware.
     */
    handler.check_interval = 10;
    /* The number of unhealthy probes after which system should die
     * is kept as 2.
     * Please Note: Setting the value of consecutive failures other
     * than 2 may result in incorrect behaviour.
     */
    handler.consecutive_failures = 2;

    return healthmon_register_handler(&handler);
}

int wlan_fw_heartbeat_unregister_healthmon()
{
    return healthmon_unregister_handler(FW_HEARTBEAT_NAME);
}
