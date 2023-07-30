/*
 * Copyright 2020-2023 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _WPL_H_
#define _WPL_H_

#include "stdbool.h"

#define WPL_WIFI_SSID_LENGTH      32
#define WPL_WIFI_PASSWORD_MIN_LEN 8
#define WPL_WIFI_PASSWORD_LENGTH  63

/* IP Address of Wi-Fi interface in AP (Access Point) mode */
#ifndef WPL_WIFI_AP_IP_ADDR
#define WPL_WIFI_AP_IP_ADDR "192.168.1.1"
#endif /* WPL_WIFI_AP_IP_ADDR */

typedef void (*linkLostCb_t)(bool linkState);

typedef enum _wpl_ret
{
    WPLRET_SUCCESS,
    WPLRET_FAIL,
    WPLRET_NOT_FOUND,
    WPLRET_AUTH_FAILED,
    WPLRET_ADDR_FAILED,
    WPLRET_NOT_CONNECTED,
    WPLRET_NOT_READY,
    WPLRET_TIMEOUT,
    WPLRET_BAD_PARAM,
} wpl_ret_t;

typedef enum _wpl_security
{
    /* Used when the user only knows SSID and password. This option should be used
     * for WPA2 security and lower. */
    WPL_SECURITY_WILDCARD,
    /* Use WPA3 SAE security */
    WPL_SECURITY_WPA3_SAE,
} wpl_security_t;

#endif /* _WPL_H_ */
