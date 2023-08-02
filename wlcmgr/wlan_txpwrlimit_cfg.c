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
#ifdef RW610
#include "fsl_ocotp.h"
#endif

#ifdef WIFI_BT_TX_PWR_LIMITS
#include WIFI_BT_TX_PWR_LIMITS
#else
#error "Region tx power config not defined"
#endif

#if defined(RW610) && defined(CONFIG_COMPRESS_TX_PWTBL)
#define MAX_SOC_OTP_LINE 64
#define OTP_PKG_TAG      0x15D
#define PKG_TYPE_QFN     0x00
#define PKG_TYPE_CSP     0x01
#define PKG_TYPE_BGA     0x02
#define PKG_TYPE_MAX     3

typedef struct _rg_power_info
{
    t_u8 *rg_power_table;
    t_u16 rg_len;
} rg_power_info;

typedef struct _rg_power_cfg
{
    t_u16 region_code;
    rg_power_info power_info[PKG_TYPE_MAX];
} rg_power_cfg;

/* For CSP board, we didn't get tx_power_table data, so use bga data temporary
 * And maybe no BGA or QFN data for avaliable region, use other type data
 */
rg_power_cfg rg_power_cfg_rw610[] = {
    {0x10, .power_info[PKG_TYPE_QFN] = {(t_u8 *)rg_rw610_qfn, sizeof(rg_rw610_qfn)},
     .power_info[PKG_TYPE_CSP] = {(t_u8 *)rg_rw610, sizeof(rg_rw610)},
     .power_info[PKG_TYPE_BGA] = {(t_u8 *)rg_rw610, sizeof(rg_rw610)}},
    {0x30, .power_info[PKG_TYPE_QFN] = {(t_u8 *)rg_rw610_EU, sizeof(rg_rw610_EU)},
     .power_info[PKG_TYPE_CSP] = {(t_u8 *)rg_rw610_EU, sizeof(rg_rw610_EU)},
     .power_info[PKG_TYPE_BGA] = {(t_u8 *)rg_rw610_EU, sizeof(rg_rw610_EU)}},
    {0x40, .power_info[PKG_TYPE_QFN] = {(t_u8 *)rg_rw610_JP, sizeof(rg_rw610_JP)},
     .power_info[PKG_TYPE_CSP] = {(t_u8 *)rg_rw610_JP, sizeof(rg_rw610_JP)},
     .power_info[PKG_TYPE_BGA] = {(t_u8 *)rg_rw610_JP, sizeof(rg_rw610_JP)}},
    {0x50, .power_info[PKG_TYPE_QFN] = {(t_u8 *)rg_rw610_CA, sizeof(rg_rw610_CA)},
     .power_info[PKG_TYPE_CSP] = {(t_u8 *)rg_rw610_CA, sizeof(rg_rw610_CA)},
     .power_info[PKG_TYPE_BGA] = {(t_u8 *)rg_rw610_CA, sizeof(rg_rw610_CA)}},
    {0xFF, .power_info[PKG_TYPE_QFN] = {(t_u8 *)rg_rw610_JP, sizeof(rg_rw610_JP)},
     .power_info[PKG_TYPE_CSP] = {(t_u8 *)rg_rw610_JP, sizeof(rg_rw610_JP)},
     .power_info[PKG_TYPE_BGA] = {(t_u8 *)rg_rw610_JP, sizeof(rg_rw610_JP)}},
};

static uint32_t soc_otp_read_line(uint32_t addr_line, uint64_t *value)
{
    uint32_t dly                   = (0x2AU * 1000);
    SOC_OTP_CTRL->OTP_ADDR         = addr_line;
    SOC_OTP_CTRL->OTP_BYPASS_MODE1 = 0;
    SOC_OTP_CTRL->OTP_CMD_START    = 0;
    SOC_OTP_CTRL->OTP_CMD_START |= SOC_OTP_CTRL_OTP_CMD_START_OTP_CMD_START_MASK;
    while (dly && ((SOC_OTP_CTRL->OTP_CTRL0 & SOC_OTP_CTRL_OTP_CTRL0_CTRL_CMD_DONE_MASK) == 0U))
    {
        dly--; /* If something horrible happens, bail out after a delay */
    }

    if (dly && ((SOC_OTP_CTRL->OTP_WDATA4 & SOC_OTP_CTRL_OTP_WDATA4_DATA_LINE_VALID_BIT_MASK) != 0U))
    {
        *value = ((uint64_t)SOC_OTP_CTRL->OTP_WDATA3 << 48) | ((uint64_t)SOC_OTP_CTRL->OTP_WDATA2 << 32) |
                 ((uint64_t)SOC_OTP_CTRL->OTP_WDATA1 << 16) | ((uint64_t)SOC_OTP_CTRL->OTP_WDATA0);
        return 1;
    }

    return 0;
}

int OCOTP_Read_pkgtype(uint8_t *board_type)
{
    int status    = kStatus_Fail;
    uint64_t data = 0ULL;
    uint32_t i;

    /* Read SOC_OTP values */
    for (i = 0U; i < MAX_SOC_OTP_LINE; i++)
    {
        if (soc_otp_read_line(i, &data) == 0U)
            continue;

        if ((data & 0xFFFF) == OTP_PKG_TAG)
        {
            status      = kStatus_Success;
            *board_type = (data >> 16) & 0xFF;
            break;
        }
    }

    return status;
}

int wlan_set_rg_power_cfg(t_u16 region_code)
{
    int i              = 0;
    uint8_t board_type = 0;
    int rv             = WM_SUCCESS;
    OCOTP_OtpInit();

    for (i = 0; i < sizeof(rg_power_cfg_rw610) / sizeof(rg_power_cfg); i++)
    {
        if (region_code == rg_power_cfg_rw610[i].region_code)
        {
            if (kStatus_Success == OCOTP_Read_pkgtype(&board_type))
            {
                /*Get board type correctly*/
                if (PKG_TYPE_QFN == board_type)
                {
                    (void)PRINTF("PKG_TYPE: QFN\r\n");
                    (void)PRINTF("Set QFN tx power table data \r\n");
                }
                else if (PKG_TYPE_BGA == board_type)
                {
                    (void)PRINTF("PKG_TYPE: BGA\r\n");
                    (void)PRINTF("Set BGA tx power table data \r\n");
                }
                else if (PKG_TYPE_CSP == board_type)
                {
                    (void)PRINTF("PKG_TYPE: CSP\r\n");
                    (void)PRINTF("Set BGA tx power table data \r\n");
                    (void)PRINTF("We didn't get data of CSP baord, so use bga data temporary \r\n");
                }
            }
            else
            {
                board_type = PKG_TYPE_BGA;
                (void)PRINTF("PKG_TYPE: UNKNOWN\r\n");
                (void)PRINTF("Set BGA tx power table data \r\n");
                (void)PRINTF("Can't get board type, we use bga data default \r\n");
            }

            rv = wlan_set_region_power_cfg(rg_power_cfg_rw610[i].power_info[board_type].rg_power_table,
                                           rg_power_cfg_rw610[i].power_info[board_type].rg_len);

            OCOTP_OtpDeinit();

            return rv;
        }
    }

    OCOTP_OtpDeinit();

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
        0x00,
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

int wlan_set_wwsm_txpwrlimit()
{
    int rv = WM_SUCCESS;
#ifdef RW610
    ARG_UNUSED(tx_pwrlimit_2g_cfg);
#ifdef CONFIG_5GHz_SUPPORT
    ARG_UNUSED(tx_pwrlimit_5g_cfg);
#endif
#endif
#ifdef CONFIG_COMPRESS_TX_PWTBL
    rv = wlan_set_chanlist(&chanlist_2g_cfg);
    if (rv != WM_SUCCESS)
        (void)PRINTF("Unable to set 2G chanlist configuration\r\n");
#ifdef CONFIG_5GHz_SUPPORT
    rv = wlan_set_chanlist(&chanlist_5g_cfg);
    if (rv != WM_SUCCESS)
        (void)PRINTF("Unable to set 5G chanlist configuration\r\n");
#endif
#ifdef RW610
    /*Default set FCC power table */
    rv = wlan_set_rg_power_cfg(0x10);
#else
    rv = wlan_set_region_power_cfg(rg_table_fc, rg_table_fc_len);
#endif
    if (rv != WM_SUCCESS)
        (void)PRINTF("Unable to set compressed TX power table configuration\r\n");
#else
int wlan_set_wwsm_txpwrlimit(void)
{
    int rv = WM_SUCCESS;

#ifdef CONFIG_11AX
#ifndef RW610
    ARG_UNUSED(rutxpowerlimit_cfg_set);
#endif
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
#endif

#ifdef RW610
    return rv;
#else

#ifdef CONFIG_11AX
#ifdef CONFIG_COMPRESS_RU_TX_PWTBL
    rv = wlan_set_11ax_rutxpowerlimit(rutxpowerlimit_cfg_set, sizeof(rutxpowerlimit_cfg_set));
    if (rv != WM_SUCCESS)
    {
        (void)PRINTF("Unable to set RU TX PWR Limit configuration\r\n");
    }
#else
    rv = wlan_set_11ax_rutxpowerlimit_legacy(&rutxpowerlimit_2g_cfg_set);
    if (rv != WM_SUCCESS)
    {
        (void)PRINTF("Unable to set 2G RU TX PWR Limit configuration\r\n");
    }
#ifdef CONFIG_5GHz_SUPPORT
    else
    {
        rv = wlan_set_11ax_rutxpowerlimit_legacy(&rutxpowerlimit_5g_cfg_set);
        if (rv != WM_SUCCESS)
        {
            (void)PRINTF("Unable to set 5G RU TX PWR Limit configuration\r\n");
        }
    }
#endif
#endif
#endif

#ifdef WLAN_REGION_CODE
    return wlan_set_country_code(WLAN_REGION_CODE);
#endif
#endif /* RW610 */
}

#ifndef RW610
const char *wlan_get_wlan_region_code(void)
{
#ifdef WLAN_REGION_CODE
    return WLAN_REGION_CODE;
#else
#error "Please define WLAN_REGION_CODE in Region tx power config file"
#endif
}
#endif