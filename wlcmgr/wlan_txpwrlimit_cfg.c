/** @file wlan_txpwrlimit_cfg.c
 *
 *  @brief  This file provides WLAN World Wide Safe Mode Tx Power Limit APIs.
 *
 *  Copyright 2008-2021, 2023 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <wlan.h>
#include <wifi.h>

#ifdef WIFI_BT_TX_PWR_LIMITS
#include WIFI_BT_TX_PWR_LIMITS
#else
#error "Region tx power config not defined"
#endif

#define ARG_UNUSED(x) (void)(x)

#if defined(RW610) && defined(CONFIG_COMPRESS_TX_PWTBL)
typedef struct _rg_power_cfg
{
    t_u16 region_code;
    t_u8 *rg_power_table;
    t_u16 rg_len;
} rg_power_cfg;

rg_power_cfg rg_power_cfg_rw610[] = {
    {
        0x10,
        (t_u8 *)rg_rw610,
        sizeof(rg_rw610),
    },
    /*
    There is no power table for below region, comment out temporary, fill Later
    {0xAA, (t_u8 *)rg_rw610, sizeof(rg_rw610),},
    {0x20, (t_u8 *)rg_rw610, sizeof(rg_rw610),},
    {0x30, (t_u8 *)rg_rw610, sizeof(rg_rw610),},
    {0x32, (t_u8 *)rg_rw610, sizeof(rg_rw610),},
    {0x40, (t_u8 *)rg_rw610, sizeof(rg_rw610),},
    {0x41, (t_u8 *)rg_rw610, sizeof(rg_rw610),},
    {0x50, (t_u8 *)rg_rw610, sizeof(rg_rw610),},
    {0xfe, (t_u8 *)rg_rw610, sizeof(rg_rw610),},
    {0xff, (t_u8 *)rg_rw610, sizeof(rg_rw610),},
    */
};

int wlan_set_rg_power_cfg(t_u16 region_code)
{
    int i  = 0;
    int rv = WM_SUCCESS;

    for (i = 0; i < sizeof(rg_power_cfg_rw610) / sizeof(rg_power_cfg); i++)
    {
        if (region_code == rg_power_cfg_rw610[i].region_code)
        {
            rv = wlan_set_region_power_cfg(rg_power_cfg_rw610[i].rg_power_table, rg_power_cfg_rw610[i].rg_len);
            if (rv != WM_SUCCESS)
                (void)PRINTF("Unable to set compressed TX power table configuration\r\n");
            return rv;
        }
    }

    return -WM_FAIL;
}
#elif defined(CONFIG_COMPRESS_TX_PWTBL)
typedef struct _rg_power_cfg
{
    t_u16 region_code;
    t_u8 *rg_power_table;
    t_u16 rg_len;
} rg_power_cfg;

rg_power_cfg rg_power_cfg_FC[] = {
    {
        0x10,
        (t_u8 *)rg_table_fc,
        sizeof(rg_table_fc),
    },
};

int wlan_set_rg_power_cfg(t_u16 region_code)
{
    int i  = 0;
    int rv = WM_SUCCESS;

    for (i = 0; i < sizeof(rg_power_cfg_FC) / sizeof(rg_power_cfg); i++)
    {
        if (region_code == rg_power_cfg_FC[i].region_code)
        {
            rv = wlan_set_region_power_cfg(rg_power_cfg_FC[i].rg_power_table, rg_power_cfg_FC[i].rg_len);
            if (rv != WM_SUCCESS)
                (void)PRINTF("Unable to set compressed TX power table configuration\r\n");
            return rv;
        }
    }

    return -WM_FAIL;
}

#endif

#ifdef CONFIG_COMPRESS_TX_PWTBL
int wlan_set_wwsm_txpwrlimit()
{
    ARG_UNUSED(tx_pwrlimit_2g_cfg);
    ARG_UNUSED(tx_pwrlimit_5g_cfg);

    int rv = WM_SUCCESS;

    rv = wlan_set_chanlist(&chanlist_2g_cfg);
    if (rv != WM_SUCCESS)
        (void)PRINTF("Unable to set 2G chanlist configuration\r\n");
#ifdef CONFIG_5GHz_SUPPORT
    rv = wlan_set_chanlist(&chanlist_5g_cfg);
    if (rv != WM_SUCCESS)
        (void)PRINTF("Unable to set 5G chanlist configuration\r\n");
#endif
#if defined(RW610)
    rv = wlan_set_region_power_cfg(rg_rw610, rg_rw610_len);
#else
    rv = wlan_set_region_power_cfg(rg_table_fc, rg_table_fc_len);
#endif
    if (rv != WM_SUCCESS)
        (void)PRINTF("Unable to set compressed TX power table configuration\r\n");
    return rv;
}
#else
int wlan_set_wwsm_txpwrlimit(void)
{
    int rv = WM_SUCCESS;

#ifdef CONFIG_11AX
    ARG_UNUSED(rutxpowerlimit_cfg_set);
#endif

    rv = wlan_set_chanlist_and_txpwrlimit(&chanlist_2g_cfg, &tx_pwrlimit_2g_cfg);
    if (rv != WM_SUCCESS)
    {
        (void)PRINTF("Unable to set 2G TX PWR Limit configuration\r\n");
    }
#ifdef CONFIG_5GHz_SUPPORT
    rv = wlan_set_chanlist_and_txpwrlimit(&chanlist_5g_cfg, &tx_pwrlimit_5g_cfg);
    if (rv != WM_SUCCESS)
    {
        (void)PRINTF("Unable to set 5G TX PWR Limit configuration\r\n");
    }
#endif
    return rv;
}
#endif
