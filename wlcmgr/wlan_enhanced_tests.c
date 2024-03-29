/** @file wlan_enhanced_tests.c
 *
 *  @brief  This file provides WLAN ENHANCED Test API
 *
 *  Copyright 2008-2020, 2023 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <wlan.h>
#include <cli.h>
#include <cli_utils.h>
#include <string.h>
#include <wm_net.h> /* for net_inet_aton */
#include <wifi.h>
#include <wlan_tests.h>

#ifdef WIFI_BT_TX_PWR_LIMITS
#include WIFI_BT_TX_PWR_LIMITS
#else
#error "Region tx power config not defined"
#endif

/*
 * NXP Test Framework (MTF) functions
 */

static void dump_wlan_uap_get_pmfcfg_usage()
{
    (void)PRINTF("Usage:\r\n");
    (void)PRINTF("wlan-uap-get-pmfcfg \r\n");
}

static void wlan_uap_pmfcfg_get(int argc, char *argv[])
{
    int ret;
    uint8_t mfpc = 0U;
    uint8_t mfpr = 0U;

    if (argc != 1)
    {
        dump_wlan_uap_get_pmfcfg_usage();
        return;
    }

    ret = wlan_uap_get_pmfcfg(&mfpc, &mfpr);
    if (ret == WM_SUCCESS)
    {
        (void)PRINTF("Uap Management Frame Protection Capability: %s\r\n", mfpc == 1 ? "Yes" : "No");
        if (mfpc != 0U)
            (void)PRINTF("Uap Management Frame Protection: %s\r\n", mfpr == 1 ? "Required" : "Optional");
    }
    else
    {
        (void)PRINTF("Uap PMF configuration read failed\r\n");
        dump_wlan_uap_get_pmfcfg_usage();
    }
}

static void dump_wlan_get_pmfcfg_usage(void)
{
    (void)PRINTF("Usage:\r\n");
    (void)PRINTF("wlan-get-pmfcfg \r\n");
}

static void wlan_pmfcfg_get(int argc, char *argv[])
{
    int ret;
    uint8_t mfpc, mfpr;

    if (argc != 1)
    {
        dump_wlan_get_pmfcfg_usage();
        return;
    }

    ret = wlan_get_pmfcfg(&mfpc, &mfpr);
    if (ret == WM_SUCCESS)
    {
        (void)PRINTF("Management Frame Protection Capability: %s\r\n", mfpc == 1U ? "Yes" : "No");
        if (mfpc != 0U)
        {
            (void)PRINTF("Management Frame Protection: %s\r\n", mfpr == 1U ? "Required" : "Optional");
        }
    }
    else
    {
        (void)PRINTF("PMF configuration read failed\r\n");
        dump_wlan_get_pmfcfg_usage();
    }
}

static void dump_wlan_set_ed_mac_mode_usage(void)
{
    (void)PRINTF("Usage:\r\n");
#ifdef CONFIG_5GHz_SUPPORT
    (void)PRINTF("wlan-set-ed-mac-mode <interface> <ed_ctrl_2g> <ed_offset_2g> <ed_ctrl_5g> <ed_offset_5g>\r\n");
#else
    (void)PRINTF("wlan-set-ed-mac-mode <interface> <ed_ctrl_2g> <ed_offset_2g>\r\n");
#endif
    (void)PRINTF("\r\n");
    (void)PRINTF("\tinterface \r\n");
    (void)PRINTF("\t    # 0       - for STA\r\n");
    (void)PRINTF("\t    # 1       - for uAP\r\n");
    (void)PRINTF("\ted_ctrl_2g \r\n");
    (void)PRINTF("\t    # 0       - disable EU adaptivity for 2.4GHz band\r\n");
    (void)PRINTF("\t    # 1       - enable EU adaptivity for 2.4GHz band\r\n");
    (void)PRINTF("\ted_offset_2g \r\n");
    (void)PRINTF("\t    # 0       - Default Energy Detect threshold\r\n");
    (void)PRINTF("\t    #offset value range: 0x80 to 0x7F\r\n");
#ifdef CONFIG_5GHz_SUPPORT
    (void)PRINTF("\ted_ctrl_5g \r\n");
    (void)PRINTF("\t    # 0       - disable EU adaptivity for 5GHz band\r\n");
    (void)PRINTF("\t    # 1       - enable EU adaptivity for 5GHz band\r\n");
    (void)PRINTF("\ted_offset_2g \r\n");
    (void)PRINTF("\t    # 0       - Default Energy Detect threshold\r\n");
    (void)PRINTF("\t    #offset value range: 0x80 to 0x7F\r\n");
#endif
}

static void wlan_ed_mac_mode_set(int argc, char *argv[])
{
    int ret;
    wlan_ed_mac_ctrl_t wlan_ed_mac_ctrl;
    t_u8 interface;

#ifdef CONFIG_5GHz_SUPPORT
    if (argc != 6)
#else
    if (argc != 4)
#endif
    {
        dump_wlan_set_ed_mac_mode_usage();
        return;
    }

    errno     = 0;
    interface = (t_u8)strtol(argv[1], NULL, 16);
    if (errno != 0)
    {
        (void)PRINTF("Error during strtoul errno:%d", errno);
    }
    errno                       = 0;
    wlan_ed_mac_ctrl.ed_ctrl_2g = (t_u16)strtol(argv[2], NULL, 16);
    if (errno != 0)
    {
        (void)PRINTF("Error during strtoul errno:%d", errno);
    }
    errno                         = 0;
    wlan_ed_mac_ctrl.ed_offset_2g = (t_s16)strtol(argv[3], NULL, 16);
    if (errno != 0)
    {
        (void)PRINTF("Error during strtoul errno:%d", errno);
    }
#ifdef CONFIG_5GHz_SUPPORT
    errno                       = 0;
    wlan_ed_mac_ctrl.ed_ctrl_5g = (t_u16)strtol(argv[4], NULL, 16);
    if (errno != 0)
    {
        (void)PRINTF("Error during strtoul errno:%d", errno);
    }
    errno                         = 0;
    wlan_ed_mac_ctrl.ed_offset_5g = (t_s16)strtol(argv[5], NULL, 16);
    if (errno != 0)
    {
        (void)PRINTF("Error during strtoul errno:%d", errno);
    }
#endif

    if (wlan_ed_mac_ctrl.ed_ctrl_2g != 0U && wlan_ed_mac_ctrl.ed_ctrl_2g != 1U)
    {
        dump_wlan_set_ed_mac_mode_usage();
        return;
    }
#ifdef CONFIG_5GHz_SUPPORT
    if (wlan_ed_mac_ctrl.ed_ctrl_5g != 0U && wlan_ed_mac_ctrl.ed_ctrl_5g != 1U)
    {
        dump_wlan_set_ed_mac_mode_usage();
        return;
    }
#endif

    if (interface == MLAN_BSS_TYPE_STA)
    {
        ret = wlan_set_ed_mac_mode(wlan_ed_mac_ctrl);
    }
    else
    {
        ret = wlan_set_uap_ed_mac_mode(wlan_ed_mac_ctrl);
    }
    if (ret == WM_SUCCESS)
    {
        (void)PRINTF("ED MAC MODE settings configuration successful\r\n");
    }
    else
    {
        (void)PRINTF("ED MAC MODE settings configuration failed\r\n");
        dump_wlan_set_ed_mac_mode_usage();
    }
}

static void dump_wlan_get_ed_mac_mode_usage(void)
{
    (void)PRINTF("Usage:\r\n");
    (void)PRINTF("wlan-get-ed-mac-mode <interface>\r\n");
    (void)PRINTF("\r\n");
    (void)PRINTF("\tinterface \r\n");
    (void)PRINTF("\t    # 0       - for STA\r\n");
    (void)PRINTF("\t    # 1       - for uAP\r\n");
}

static void wlan_ed_mac_mode_get(int argc, char *argv[])
{
    int ret;
    wlan_ed_mac_ctrl_t wlan_ed_mac_ctrl;
    int interface;

    if (argc != 2)
    {
        dump_wlan_get_ed_mac_mode_usage();
        return;
    }
    errno     = 0;
    interface = (t_u8)strtol(argv[1], NULL, 16);
    if (errno != 0)
    {
        (void)PRINTF("Error during strtoul errno:%d", errno);
    }

    if (interface == MLAN_BSS_TYPE_STA)
    {
        ret = wlan_get_ed_mac_mode(&wlan_ed_mac_ctrl);
    }
    else
    {
        ret = wlan_get_uap_ed_mac_mode(&wlan_ed_mac_ctrl);
    }
    if (ret == WM_SUCCESS)
    {
        (void)PRINTF("EU adaptivity for 2.4GHz band : %s\r\n",
                     wlan_ed_mac_ctrl.ed_ctrl_2g == 1U ? "Enabled" : "Disabled");
        if (wlan_ed_mac_ctrl.ed_ctrl_2g != 0U)
        {
            (void)PRINTF("Energy Detect threshold offset : 0X%x\r\n", wlan_ed_mac_ctrl.ed_offset_2g);
        }
#ifdef CONFIG_5GHz_SUPPORT
        (void)PRINTF("EU adaptivity for 5GHz band : %s\r\n",
                     wlan_ed_mac_ctrl.ed_ctrl_5g == 1U ? "Enabled" : "Disabled");
        if (wlan_ed_mac_ctrl.ed_ctrl_5g != 0U)
        {
            (void)PRINTF("Energy Detect threshold offset : 0X%x\r\n", wlan_ed_mac_ctrl.ed_offset_5g);
        }
#endif
    }
    else
    {
        (void)PRINTF("ED MAC MODE read failed\r\n");
        dump_wlan_get_ed_mac_mode_usage();
    }
}
#if 0
static int wlan_memrdwr_getset(int argc, char *argv[])
{
    uint8_t action;
    uint32_t value;
    int ret;

    if (argc != 3 && argc != 4)
    {
        return -WM_FAIL;
    }

    if (argc == 3)
    {
        action = ACTION_GET;
        value  = 0;
    }
    else
    {
        action = ACTION_SET;
        value  = a2hex_or_atoi(argv[3]);
    }

    ret = wifi_mem_access(action, a2hex_or_atoi(argv[2]), &value);

    if (ret == WM_SUCCESS)
    {
        if (action == ACTION_GET)
        {
            (void)PRINTF("At Memory 0x%x: 0x%x\r\n", a2hex_or_atoi(argv[2]), value);
        }
        else
        {
            (void)PRINTF("Set the Memory successfully\r\n");
        }
    }
    else
    {
        wlcm_e("Read/write Mem failed");
        return -WM_FAIL;
    }
    return WM_SUCCESS;
}
#endif

#if SDK_DEBUGCONSOLE != DEBUGCONSOLE_DISABLE
static char *bw[]           = {"20 MHz", "40 MHz", "80 MHz", "160 MHz"};
static char *rate_format[4] = {"LG", "HT", "VHT", "HE"};
static char *lg_rate[]      = {"1 Mbps",  "2 Mbps",  "5.5 Mbps", "11 Mbps", "6 Mbps",  "9 Mbps",
                          "12 Mbps", "18 Mbps", "24 Mbps",  "36 Mbps", "48 Mbps", "54 Mbps"};
#endif

static void print_ds_rate(wlan_ds_rate ds_rate)
{
#if SDK_DEBUGCONSOLE != DEBUGCONSOLE_DISABLE
    if (ds_rate.sub_command == WIFI_DS_RATE_CFG)
    {
        (void)PRINTF("Tx Rate Configuration: \r\n");
        /* format */
        if (ds_rate.param.rate_cfg.rate_format == MLAN_RATE_FORMAT_AUTO)
        {
            (void)PRINTF("    Type:       0xFF (Auto)\r\n");
        }
        else if ((unsigned int)(ds_rate.param.rate_cfg.rate_format) <= 3U)
        {
            (void)PRINTF("    Type:         %d (%s)\r\n", ds_rate.param.rate_cfg.rate_format,
                         rate_format[ds_rate.param.rate_cfg.rate_format]);
            if (ds_rate.param.rate_cfg.rate_format == MLAN_RATE_FORMAT_LG)
            {
                (void)PRINTF("    Rate Index: %d (%s)\r\n", ds_rate.param.rate_cfg.rate_index,
                             lg_rate[ds_rate.param.rate_cfg.rate_index]);
            }
            else if (ds_rate.param.rate_cfg.rate_format >= MLAN_RATE_FORMAT_HT)
            {
                (void)PRINTF("    MCS Index:  %d\r\n", (int)ds_rate.param.rate_cfg.rate_index);
            }
            else
            { /* Do Nothing */
            }
#if defined(CONFIG_11AC) || defined(CONFIG_11AX)
            if ((ds_rate.param.rate_cfg.rate_format == MLAN_RATE_FORMAT_VHT)
            )
            {
                (void)PRINTF("    NSS:        %d\r\n", (int)ds_rate.param.rate_cfg.nss);
            }
#endif
        }
        else
        {
            (void)PRINTF("    Unknown rate format.\r\n");
        }
    }
    else if (ds_rate.sub_command == WIFI_DS_GET_DATA_RATE)
    {
        wifi_data_rate_t *datarate = (wifi_data_rate_t *)&(ds_rate.param.data_rate);
        (void)PRINTF("Data Rate:\r\n");
#ifdef SD8801
        (void)PRINTF("  TX: \r\n");
        if (datarate->tx_data_rate < 12)
        {
            (void)PRINTF("    Type: %s\r\n", rate_format[0]);
            /* LG */
            (void)PRINTF("    Rate: %s\r\n", lg_rate[datarate->tx_data_rate]);
        }
        else
        {
            /* HT*/
            (void)PRINTF("    Type: %s\r\n", rate_format[1]);
            if (datarate->tx_bw <= 2)
                (void)PRINTF("    BW:   %s\r\n", bw[datarate->tx_bw]);
            if (datarate->tx_gi == 0)
                (void)PRINTF("    GI:   Long\r\n");
            else
                (void)PRINTF("    GI:   Short\r\n");
            (void)PRINTF("    MCS:  MCS %d\r\n", (int)(datarate->tx_data_rate - 12));
        }

        (void)PRINTF("  RX: \n");
        if (datarate->rx_data_rate < 12)
        {
            (void)PRINTF("    Type: %s\r\n", rate_format[0]);
            /* LG */
            (void)PRINTF("    Rate: %s\r\n", lg_rate[datarate->rx_data_rate]);
        }
        else
        {
            /* HT*/
            (void)PRINTF("    Type: %s\r\n", rate_format[1]);
            if (datarate->rx_bw <= 2)
            {
                (void)PRINTF("    BW:   %s\r\n", bw[datarate->rx_bw]);
            }
            if (datarate->rx_gi == 0)
            {
                (void)PRINTF("    GI:   Long\r\n");
            }
            else
            {
                (void)PRINTF("    GI:   Short\r\n");
            }
            (void)PRINTF("    MCS:  MCS %d\r\n", (int)(datarate->rx_data_rate - 12));
        }
#else
        (void)PRINTF("  TX: \r\n");
        if ((unsigned int)(datarate->tx_rate_format) <= 3U)
        {
            (void)PRINTF("    Type: %s\r\n", rate_format[datarate->tx_rate_format]);
            if ((datarate->tx_rate_format == MLAN_RATE_FORMAT_LG) && datarate->tx_data_rate <= 11U)
            {
                /* LG */
                (void)PRINTF("    Rate: %s\r\n", lg_rate[datarate->tx_data_rate]);
            }
            else
            {
                /* HT, VHT, HE*/
                if (datarate->tx_bw <= 3)
                    (void)PRINTF("    BW:   %s\r\n", bw[datarate->tx_bw]);
                if (datarate->tx_rate_format < 3)
                {
                    if (datarate->tx_gi == 0)
                        (void)PRINTF("    GI:   Long\r\n");
                    else
                        (void)PRINTF("    GI:   Short\r\n");
                }
#if defined(CONFIG_11AC) || defined(CONFIG_11AX)
                if (datarate->tx_rate_format >= 2)
                    (void)PRINTF("    NSS:  %d\r\n", datarate->tx_nss + 1);
#endif
                if (datarate->tx_mcs_index != 0xFFU)
                {
                    (void)PRINTF("    MCS:  MCS %d\r\n", (int)datarate->tx_mcs_index);
                }
                else
                {
                    (void)PRINTF("    MCS:  Auto\r\n");
                }
                (void)PRINTF("    Rate: %.2f Mbps\r\n", (double)datarate->tx_data_rate / 2);
            }
        }

        (void)PRINTF("  RX: \r\n");
        if ((unsigned int)(datarate->rx_rate_format) <= 3U)
        {
            (void)PRINTF("    Type: %s\r\n", rate_format[datarate->rx_rate_format]);
            if ((datarate->rx_rate_format == MLAN_RATE_FORMAT_LG) && datarate->rx_data_rate <= 11U)
            {
                /* LG */
                (void)PRINTF("    Rate: %s\r\n", lg_rate[datarate->rx_data_rate]);
            }
            else
            {
                /* HT, VHT, HE*/
                if (datarate->rx_bw <= 3)
                    (void)PRINTF("    BW:   %s\r\n", bw[datarate->rx_bw]);
                if (datarate->rx_rate_format < 3)
                {
                    if (datarate->rx_gi == 0)
                        (void)PRINTF("    GI:   Long\r\n");
                    else
                        (void)PRINTF("    GI:   Short\r\n");
                }
#if defined(CONFIG_11AC) || defined(CONFIG_11AX)
                if (datarate->rx_rate_format >= 2)
                    (void)PRINTF("    NSS:  %d\r\n", datarate->rx_nss + 1);
#endif
                if (datarate->rx_mcs_index != 0xFFU)
                {
                    (void)PRINTF("    MCS:  MCS %d\r\n", (int)datarate->rx_mcs_index);
                }
                else
                {
                    (void)PRINTF("    MCS:  Auto\n");
                }
                (void)PRINTF("    Rate: %.2f Mbps\r\n", (double)datarate->rx_data_rate / 2);
            }
        }
#endif
    }
    else
    { /* Do Nothing */
    }
#endif
}

static void dump_wlan_set_txratecfg_usage(void)
{
    (void)PRINTF("Usage:\r\n");
    (void)PRINTF("wlan-set-txratecfg <sta/uap> <format> <index> ");
#if defined(CONFIG_11AC) || defined(CONFIG_11AX)
    (void)PRINTF("<nss> ");
    (void)PRINTF("<rate_setting>\r\n");
#endif
    (void)PRINTF("\r\n");

    (void)PRINTF("\tWhere\r\n");
    (void)PRINTF("\t<format> - This parameter specifies the data rate format used in this command\r\n");
    (void)PRINTF("\t        0:    LG\r\n");
    (void)PRINTF("\t        1:    HT\r\n");
#ifdef CONFIG_11AC
    (void)PRINTF("\t        2:    VHT\r\n");
#endif
    (void)PRINTF("\t        0xff: Auto\r\n");
    (void)PRINTF("\t<index> - This parameter specifies the rate or MCS index\r\n");
    (void)PRINTF("\tIf <format> is 0 (LG),\r\n");
    (void)PRINTF("\t        0       1 Mbps\r\n");
    (void)PRINTF("\t        1       2 Mbps\r\n");
    (void)PRINTF("\t        2       5.5 Mbps\r\n");
    (void)PRINTF("\t        3       11 Mbps\r\n");
    (void)PRINTF("\t        4       6 Mbps\r\n");
    (void)PRINTF("\t        5       9 Mbps\r\n");
    (void)PRINTF("\t        6       12 Mbps\r\n");
    (void)PRINTF("\t        7       18 Mbps\r\n");
    (void)PRINTF("\t        8       24 Mbps\r\n");
    (void)PRINTF("\t        9       36 Mbps\r\n");
    (void)PRINTF("\t        10      48 Mbps\r\n");
    (void)PRINTF("\t        11      54 Mbps\r\n");
    (void)PRINTF("\tIf <format> is 1 (HT),\r\n");
    (void)PRINTF("\t        0       MCS0\r\n");
    (void)PRINTF("\t        1       MCS1\r\n");
    (void)PRINTF("\t        2       MCS2\r\n");
    (void)PRINTF("\t        3       MCS3\r\n");
    (void)PRINTF("\t        4       MCS4\r\n");
    (void)PRINTF("\t        5       MCS5\r\n");
    (void)PRINTF("\t        6       MCS6\r\n");
    (void)PRINTF("\t        7       MCS7\r\n");
#ifdef CONFIG_11AC
    (void)PRINTF("\tIf <format> is 2 (VHT),\r\n");
    (void)PRINTF("\t        0       MCS0\r\n");
    (void)PRINTF("\t        1       MCS1\r\n");
    (void)PRINTF("\t        2       MCS2\r\n");
    (void)PRINTF("\t        3       MCS3\r\n");
    (void)PRINTF("\t        4       MCS4\r\n");
    (void)PRINTF("\t        5       MCS5\r\n");
    (void)PRINTF("\t        6       MCS6\r\n");
    (void)PRINTF("\t        7       MCS7\r\n");
    (void)PRINTF("\t        8       MCS8\r\n");
    (void)PRINTF("\t        9       MCS9\r\n");
#endif
#if defined(CONFIG_11AX) || defined(CONFIG_11AC)
    (void)PRINTF("\t<nss> - This parameter specifies the NSS. It is valid only for VHT and HE\r\n");
    (void)PRINTF("\tIf <format> is 2 (VHT) or 3 (HE),\r\n");
    (void)PRINTF("\t        1       NSS1\r\n");
    (void)PRINTF("\t        2       NSS2\r\n");
#endif
    (void)PRINTF("\t<rate_setting> - This parameter can only specifies the GI types now.\r\n");
    (void)PRINTF("\tIf <format> is 1 (HT),\r\n");
    (void)PRINTF("\t        0x0000  Long GI\r\n");
    (void)PRINTF("\t        0x0020  Short GI\r\n");
#ifdef CONFIG_11AC
    (void)PRINTF("\tIf <format> is 2 (VHT),\r\n");
    (void)PRINTF("\t        0x0000  Long GI\r\n");
    (void)PRINTF("\t        0x0020  Short GI\r\n");
    (void)PRINTF("\t        0x0060  Short GI and Nsym mod 10=9\r\n");
#endif
}

static void test_wlan_set_txratecfg(int argc, char **argv)
{
    mlan_bss_type bss_type = (mlan_bss_type)0;
    wlan_ds_rate ds_rate;
    int rv = WM_SUCCESS;

    if (argc < 3 ||
#if defined(CONFIG_11AC) || defined(CONFIG_11AX)
        argc > 6)
    {
#else
        argc > 4)
    {
#endif
        (void)PRINTF("Invalid arguments\r\n");
        goto done;
    }

    if (string_equal("sta", argv[1]))
        bss_type = MLAN_BSS_TYPE_STA;
    else if (string_equal("uap", argv[1]))
        bss_type = MLAN_BSS_TYPE_UAP;
    else
    {
        (void)PRINTF("Invalid bss type selection\r\n");
        goto done;
    }

    (void)memset(&ds_rate, 0, sizeof(wlan_ds_rate));

    ds_rate.sub_command = WIFI_DS_RATE_CFG;

    errno                              = 0;
    ds_rate.param.rate_cfg.rate_format = (mlan_rate_format)(strtol(argv[2], NULL, 0));
    if (errno != 0)
    {
        (void)PRINTF("Error during strtoul errno:%d", errno);
    }
    errno                             = 0;
    ds_rate.param.rate_cfg.rate_index = (t_u32)strtol(argv[3], NULL, 0);
    if (errno != 0)
    {
        (void)PRINTF("Error during strtoul errno:%d", errno);
    }
#if defined(CONFIG_11AC) || defined(CONFIG_11AX)
    if (argc >= 5)
    {
        errno                      = 0;
        ds_rate.param.rate_cfg.nss = strtol(argv[4], NULL, 0);
        if (errno != 0)
        {
            (void)PRINTF("Error during strtoul errno:%d", errno);
        }
        else
        {
            /*Do Nothing*/
        }
    }
#endif
    if (argc == 6)
    {
        errno                               = 0;
        ds_rate.param.rate_cfg.rate_setting = strtol(argv[5], NULL, 0);
        if (errno != 0)
            (void)PRINTF("Error during strtoul errno:%d", errno);
    }
    else
    {
        errno                               = 0;
        ds_rate.param.rate_cfg.rate_setting = 0xffff;
        if (errno != 0)
            (void)PRINTF("Error during strtoul errno:%d", errno);
    }

    if ((ds_rate.param.rate_cfg.rate_format != MLAN_RATE_FORMAT_AUTO)
#if   defined(CONFIG_11AC)
        && (ds_rate.param.rate_cfg.rate_format > MLAN_RATE_FORMAT_VHT)
#else
    && (ds_rate.param.rate_cfg.rate_format > MLAN_RATE_FORMAT_HT)
#endif
    )
    {
        (void)PRINTF("Invalid format selection\r\n");
        goto done;
    }

    if (ds_rate.param.rate_cfg.rate_format != MLAN_RATE_FORMAT_AUTO)
    {
        if (((ds_rate.param.rate_cfg.rate_format == MLAN_RATE_FORMAT_LG) &&
             (ds_rate.param.rate_cfg.rate_index > MLAN_RATE_INDEX_OFDM7))
            || ((ds_rate.param.rate_cfg.rate_format == MLAN_RATE_FORMAT_HT) &&
                (ds_rate.param.rate_cfg.rate_index != 32U) &&
                (ds_rate.param.rate_cfg.rate_index > 7U)
                    )
#ifdef CONFIG_11AC
            || ((ds_rate.param.rate_cfg.rate_format == MLAN_RATE_FORMAT_VHT) &&
                (ds_rate.param.rate_cfg.rate_index > MLAN_RATE_INDEX_MCS9))
#endif
        )
        {
            (void)PRINTF("Invalid index selection\r\n");
            goto done;
        }
#if defined(CONFIG_11AC) || defined(CONFIG_11AX)
        /* NSS is supported up to 2 */
        if ((ds_rate.param.rate_cfg.nss <= 0) || (ds_rate.param.rate_cfg.nss >= 3))
        {
            (void)PRINTF("Invalid nss selection\r\n");
            goto done;
        }
#endif

        if (argc == 6)
        {
        }
    }

    rv = wlan_set_txratecfg(ds_rate, bss_type);
    if (rv != WM_SUCCESS)
    {
        (void)PRINTF("Unable to set txratecfg\r\n");
        goto done;
    }
    (void)PRINTF("Configured txratecfg as below:\r\n");
    print_ds_rate(ds_rate);
    return;

done:
    dump_wlan_set_txratecfg_usage();
}

static void test_wlan_get_txratecfg(int argc, char **argv)
{
    mlan_bss_type bss_type = (mlan_bss_type)0;
    wlan_ds_rate ds_rate;

    if (argc != 2)
    {
        (void)PRINTF("Invalid arguments\r\n");
        (void)PRINTF("Usage: wlan-get-txratecfg <sta/uap>\r\n");
        return;
    }

    if (string_equal("sta", argv[1]))
        bss_type = MLAN_BSS_TYPE_STA;
    else if (string_equal("uap", argv[1]))
        bss_type = MLAN_BSS_TYPE_UAP;
    else
    {
        (void)PRINTF("Invalid bss type selection\r\n");
        return;
    }

    (void)memset(&ds_rate, 0, sizeof(wlan_ds_rate));

    ds_rate.sub_command = WIFI_DS_RATE_CFG;

    int rv = wlan_get_txratecfg(&ds_rate, bss_type);
    if (rv != WM_SUCCESS)
    {
        (void)PRINTF("Unable to get tx rate cfg\r\n");
        return;
    }

    print_ds_rate(ds_rate);
}

static void test_wlan_get_data_rate(int argc, char **argv)
{
    mlan_bss_type bss_type = (mlan_bss_type)0;
    wlan_ds_rate ds_rate;

    if (argc != 2)
    {
        (void)PRINTF("Invalid arguments\r\n");
        (void)PRINTF("Usage: wlan-get-data-rate <sta/uap>\r\n");
        return;
    }

    if (string_equal("sta", argv[1]))
        bss_type = MLAN_BSS_TYPE_STA;
    else if (string_equal("uap", argv[1]))
        bss_type = MLAN_BSS_TYPE_UAP;
    else
    {
        (void)PRINTF("Invalid bss type selection\r\n");
        return;
    }

    (void)memset(&ds_rate, 0, sizeof(wlan_ds_rate));

    ds_rate.sub_command = WIFI_DS_GET_DATA_RATE;

    int rv = wlan_get_data_rate(&ds_rate, bss_type);
    if (rv != WM_SUCCESS)
    {
        (void)PRINTF("Unable to get tx rate cfg\r\n");
        return;
    }

    print_ds_rate(ds_rate);
}

void print_txpwrlimit(wlan_txpwrlimit_t *txpwrlimit)
{
    int i, j;

    (void)PRINTF("--------------------------------------------------------------------------------\r\n");
    (void)PRINTF("Get txpwrlimit: sub_band=%x \r\n", txpwrlimit->subband);
    for (i = 0; i < txpwrlimit->num_chans; i++)
    {
        (void)PRINTF("StartFreq: %d\r\n", txpwrlimit->txpwrlimit_config[i].chan_desc.start_freq);
        (void)PRINTF("ChanWidth: %d\r\n", txpwrlimit->txpwrlimit_config[i].chan_desc.chan_width);
        (void)PRINTF("ChanNum:   %d\r\n", txpwrlimit->txpwrlimit_config[i].chan_desc.chan_num);
        (void)PRINTF("Pwr:");
        for (j = 0; j < txpwrlimit->txpwrlimit_config[i].num_mod_grps; j++)
        {
            if (j == (txpwrlimit->txpwrlimit_config[i].num_mod_grps - 1))
                (void)PRINTF("%d,%d", txpwrlimit->txpwrlimit_config[i].txpwrlimit_entry[j].mod_group,
                             txpwrlimit->txpwrlimit_config[i].txpwrlimit_entry[j].tx_power);
            else
                (void)PRINTF("%d,%d,", txpwrlimit->txpwrlimit_config[i].txpwrlimit_entry[j].mod_group,
                             txpwrlimit->txpwrlimit_config[i].txpwrlimit_entry[j].tx_power);
        }
        (void)PRINTF("\r\n");
    }
    (void)PRINTF("\r\n");
}


static void print_chanlist(wlan_chanlist_t chanlist)
{
    unsigned char i;

    (void)PRINTF("--------------------------------------------------------------------------------\r\n");
    (void)PRINTF("Number of channels configured: %d\r\n", chanlist.num_chans);
    (void)PRINTF("\r\n");
    for (i = 0; i < chanlist.num_chans; i++)
    {
        (void)PRINTF("ChanNum: %d\t", chanlist.chan_info[i].chan_num);
        (void)PRINTF("ChanFreq: %d\t", chanlist.chan_info[i].chan_freq);
        (void)PRINTF("%s", chanlist.chan_info[i].passive_scan_or_radar_detect ? "Passive" : "Active");
        (void)PRINTF("\r\n");
    }
}

static void dump_wlan_get_txpwrlimit_usage(void)
{
    (void)PRINTF("Usage:\r\n");
    (void)PRINTF("wlan-get-txpwrlimit <subband> \r\n");
    (void)PRINTF("\r\n");
    (void)PRINTF("\t Where subband is: \r\n");
    (void)PRINTF("\t       0x00 2G subband  (2.4G: channel 1-14)\r\n");
#ifdef CONFIG_5GHz_SUPPORT
    (void)PRINTF("\t       0x10 5G subband0 (5G: channel 36,40,44,48,\r\n");
    (void)PRINTF("\t                                     52,56,60,64)\r\n");
    (void)PRINTF("\t       0x11 5G subband1 (5G: channel 100,104,108,112,\r\n");
    (void)PRINTF("\t                                     116,120,124,128,\r\n");
    (void)PRINTF("\t                                     132,136,140,144)\r\n");
    (void)PRINTF("\t       0x12 5G subband2 (5G: channel 149,153,157,161,165,172)\r\n");
    (void)PRINTF("\t       0x13 5G subband3 (5G: channel 183,184,185,187,188,\r\n");
    (void)PRINTF("\t                                     189, 192,196;\r\n");
    (void)PRINTF("\t                         5G: channel 7,8,11,12,16,34)\r\n");
#endif
}

static void test_wlan_get_txpwrlimit(int argc, char **argv)
{
    wifi_SubBand_t subband;
    wlan_txpwrlimit_t *txpwrlimit = NULL;

    if (argc != 2)
    {
        dump_wlan_get_txpwrlimit_usage();
        return;
    }

    errno   = 0;
    subband = (wifi_SubBand_t)strtol(argv[1], NULL, 16);
    if (errno != 0)
    {
        (void)PRINTF("Error during strtoul errno:%d", errno);
    }

    if (subband != SubBand_2_4_GHz
#ifdef CONFIG_5GHz_SUPPORT
        && subband != SubBand_5_GHz_0 && subband != SubBand_5_GHz_1 && subband != SubBand_5_GHz_2 &&
        subband != SubBand_5_GHz_3
#endif
    )
    {
        dump_wlan_get_txpwrlimit_usage();
        return;
    }

    txpwrlimit = os_mem_alloc(sizeof(wlan_txpwrlimit_t));
    if (txpwrlimit == NULL)
    {
        (void)PRINTF("Cannot allocate memory\r\n");
        return;
    }

    int rv = wlan_get_txpwrlimit(subband, txpwrlimit);
    if (rv != WM_SUCCESS)
    {
        (void)PRINTF("Unable to get TX PWR Limit configuration\r\n");
    }
    else
    {
        print_txpwrlimit(txpwrlimit);
    }
	os_mem_free(txpwrlimit);
}

static void test_wlan_set_txpwrlimit(int argc, char **argv)
{
    wlan_txpwrlimit_t *txpwrlimit = NULL;

    txpwrlimit = os_mem_alloc(sizeof(wlan_txpwrlimit_t));
    if (txpwrlimit == NULL)
    {
        (void)PRINTF("Cannot allocate memory\r\n");
        return;
    }

    int rv = wlan_set_txpwrlimit(&tx_pwrlimit_2g_cfg);
    if (rv != WM_SUCCESS)
    {
        (void)PRINTF("Unable to set 2G TX PWR Limit configuration\r\n");
    }
    else
    {
#ifdef CONFIG_5GHz_SUPPORT
        rv = wlan_set_txpwrlimit(&tx_pwrlimit_5g_cfg);
        if (rv != WM_SUCCESS)
        {
            (void)PRINTF("Unable to set 5G TX PWR Limit configuration\r\n");
        }
        else
        {
#endif
            txpwrlimit->subband = SubBand_2_4_GHz;
            rv                 = wlan_get_txpwrlimit(txpwrlimit->subband, txpwrlimit);
            if (rv != WM_SUCCESS)
            {
                (void)PRINTF("Unable to get 2G TX PWR Limit configuration\r\n");
            }
            else
            {
                print_txpwrlimit(txpwrlimit);
            }
#ifdef CONFIG_5GHz_SUPPORT
            txpwrlimit->subband = SubBand_5_GHz_0;
            rv                 = wlan_get_txpwrlimit(txpwrlimit->subband, txpwrlimit);
            if (rv != WM_SUCCESS)
            {
                (void)PRINTF("Unable to get 5G SubBand0 TX PWR Limit configuration\r\n");
            }
            else
            {
                print_txpwrlimit(txpwrlimit);
            }
            txpwrlimit->subband = SubBand_5_GHz_1;
            rv                 = wlan_get_txpwrlimit(txpwrlimit->subband, txpwrlimit);
            if (rv != WM_SUCCESS)
            {
                (void)PRINTF("Unable to get 5G SubBand1 TX PWR Limit configuration\r\n");
            }
            else
            {
                print_txpwrlimit(txpwrlimit);
            }
            txpwrlimit->subband = SubBand_5_GHz_2;
            rv                 = wlan_get_txpwrlimit(txpwrlimit->subband, txpwrlimit);
            if (rv != WM_SUCCESS)
            {
                (void)PRINTF("Unable to get 5G SubBand2 TX PWR Limit configuration\r\n");
            }
            else
            {
                print_txpwrlimit(txpwrlimit);
            }
        }
#endif
    }
    os_mem_free(txpwrlimit);
}

static void test_wlan_set_chanlist_and_txpwrlimit(int argc, char **argv)
{
    wlan_txpwrlimit_t *txpwrlimit = NULL;

    txpwrlimit = os_mem_alloc(sizeof(wlan_txpwrlimit_t));
    if (txpwrlimit == NULL)
    {
        (void)PRINTF("Cannot allocate memory\r\n");
        return;
    }

    int rv = wlan_set_chanlist_and_txpwrlimit(&chanlist_2g_cfg, &tx_pwrlimit_2g_cfg);
    if (rv != WM_SUCCESS)
    {
        (void)PRINTF("Unable to set 2G TX PWR Limit configuration\r\n");
    }
    else
    {
#ifdef CONFIG_5GHz_SUPPORT
        rv = wlan_set_chanlist_and_txpwrlimit(&chanlist_5g_cfg, &tx_pwrlimit_5g_cfg);
        if (rv != WM_SUCCESS)
        {
            (void)PRINTF("Unable to set 5G TX PWR Limit configuration\r\n");
        }
        else
        {
#endif
            txpwrlimit->subband = SubBand_2_4_GHz;
            rv                 = wlan_get_txpwrlimit(txpwrlimit->subband, txpwrlimit);
            if (rv != WM_SUCCESS)
            {
                (void)PRINTF("Unable to get 2G TX PWR Limit configuration\r\n");
            }
            else
            {
                print_txpwrlimit(txpwrlimit);
            }
#ifdef CONFIG_5GHz_SUPPORT
            txpwrlimit->subband = SubBand_5_GHz_0;
            rv                 = wlan_get_txpwrlimit(txpwrlimit->subband, txpwrlimit);
            if (rv != WM_SUCCESS)
            {
                (void)PRINTF("Unable to get 5G SubBand0 TX PWR Limit configuration\r\n");
            }
            else
            {
                print_txpwrlimit(txpwrlimit);
            }
            txpwrlimit->subband = SubBand_5_GHz_1;
            rv                 = wlan_get_txpwrlimit(txpwrlimit->subband, txpwrlimit);
            if (rv != WM_SUCCESS)
            {
                (void)PRINTF("Unable to get 5G SubBand1 TX PWR Limit configuration\r\n");
            }
            else
            {
                print_txpwrlimit(txpwrlimit);
            }
            txpwrlimit->subband = SubBand_5_GHz_2;
            rv                 = wlan_get_txpwrlimit(txpwrlimit->subband, txpwrlimit);
            if (rv != WM_SUCCESS)
            {
                (void)PRINTF("Unable to get 5G SubBand2 TX PWR Limit configuration\r\n");
            }
            else
            {
                print_txpwrlimit(txpwrlimit);
            }
        }
#endif
        wlan_chanlist_t chanlist;

        (void)memset(&chanlist, 0x00, sizeof(wlan_chanlist_t));
        rv = wlan_get_chanlist(&chanlist);
        if (rv != WM_SUCCESS)
        {
            (void)PRINTF("Unable to get channel list configuration\r\n");
        }
        else
        {
            print_chanlist(chanlist);
        }
    }
    os_mem_free(txpwrlimit);
}

static void test_wlan_set_chanlist(int argc, char **argv)
{
    wlan_chanlist_t chanlist;

    (void)memset(&chanlist, 0x00, sizeof(wlan_chanlist_t));

    int rv = wlan_set_chanlist(&chanlist_2g_cfg);
    if (rv != WM_SUCCESS)
    {
        (void)PRINTF("Unable to set 2G channel list configuration\r\n");
    }
    else
    {
#ifdef CONFIG_5GHz_SUPPORT
        rv = wlan_set_chanlist(&chanlist_5g_cfg);
        if (rv != WM_SUCCESS)
        {
            (void)PRINTF("Unable to set 5G channel list configuration\r\n");
        }
        else
        {
#endif
            rv = wlan_get_chanlist(&chanlist);
            if (rv != WM_SUCCESS)
            {
                (void)PRINTF("Unable to get channel list configuration\r\n");
            }
            else
            {
                print_chanlist(chanlist);
            }
#ifdef CONFIG_5GHz_SUPPORT
        }
#endif
    }
}

static void test_wlan_get_chanlist(int argc, char **argv)
{
    wlan_chanlist_t chanlist;

    (void)memset(&chanlist, 0x00, sizeof(wlan_chanlist_t));
    int rv = wlan_get_chanlist(&chanlist);
    if (rv != WM_SUCCESS)
    {
        (void)PRINTF("Unable to get channel list configuration\r\n");
    }
    else
    {
        print_chanlist(chanlist);
    }
}


#ifdef CONFIG_WIFI_CLOCKSYNC
static void dump_wlan_get_tsf_info_usage(void)
{
    (void)PRINTF("Usage:\r\n");
    (void)PRINTF("wlan-get-tsfinfo <tsf_format>\r\n");
    (void)PRINTF("where, tsf_format =\r\n");
    (void)PRINTF("0:    Report GPIO assert TSF\r\n");
    (void)PRINTF("1:    Report Beacon TSF and Offset (valid if CONFIG Mode 2)\r\n");
}

static void test_get_tsf_info(int argc, char **argv)
{
    wlan_tsf_info_t tsf_info;
    (void)memset(&tsf_info, 0, sizeof(wlan_tsf_info_t));
    if (argc != 2)
    {
        dump_wlan_get_tsf_info_usage();
        return;
    }

    errno               = 0;
    tsf_info.tsf_format = (uint16_t)strtol(argv[1], NULL, 0);

    if (errno != 0)
    {
        (void)PRINTF("Error during strtoul errno:%d", errno);
    }

    int rv = wlan_get_tsf_info(&tsf_info);

    if (rv != WM_SUCCESS)
    {
        (void)PRINTF("Unable to get TSF info\r\n");
    }
    else
    {
        (void)PRINTF("tsf format:              %d\n\r", tsf_info.tsf_format);
        (void)PRINTF("tsf info:                %d\n\r", tsf_info.tsf_info);
        (void)PRINTF("tsf:                     %llu\n\r", tsf_info.tsf);
        (void)PRINTF("tsf offset:              %d\n\r", tsf_info.tsf_offset);
    }
}

static void dump_wlan_set_clocksync_cfg_usage(void)
{
    (void)PRINTF("Usage:\r\n");
    (void)PRINTF("wlan-set-clocksync <mode> <role> <gpio_pin> <gpio_level> <pulse width>\r\n");
    (void)PRINTF("Set WIFI TSF based clock sync setting. \r\nWhere, \r\n");
    (void)PRINTF("<mode> is use to configure GPIO TSF latch mode\r\n");
    (void)PRINTF("\t\t0:    GPIO level\r\n");
    (void)PRINTF("\t\t1:    GPIO toggle\r\n");
    (void)PRINTF("\t\t2:    GPIO toggle on Next Beacon\r\n");
    (void)PRINTF("<role> \r\n");
    (void)PRINTF("\t\t0: when mode set to 0 or 1\r\n");
    (void)PRINTF("\t\t1:  AP\r\n");
    (void)PRINTF("\t\t2: STA\r\n");
    (void)PRINTF("<gpio pin number>\r\n");
    (void)PRINTF("<GPIO Level/Toggle>\r\n");
    (void)PRINTF("\t\tmode = 0\r\n");
    (void)PRINTF("\t\t0: low    1: high\r\n");
    (void)PRINTF("\t\tmode = 1 or 2\r\n");
    (void)PRINTF("\t\t0: low to high\r\n");
    (void)PRINTF("\t\t1: high to low\r\n");
    (void)PRINTF("GPIO pulse width\r\n");
    (void)PRINTF("\t\tmode = 0,  reserved, set to 0\r\n");
    (void)PRINTF("\t\tmode 1 or 2\r\n");
    (void)PRINTF("\t\t0: GPIO remain on toggle level (high or low)\r\n");
    (void)PRINTF("\t\tNon-0: GPIO pulse width in microseconds (min 1 us)\r\n");
}

static void test_set_clocksync_cfg(int argc, char **argv)
{
    wlan_clock_sync_gpio_tsf_t tsf_latch;

    if (argc != 6)
    {
        dump_wlan_set_clocksync_cfg_usage();
        return;
    }

    errno                     = 0;
    tsf_latch.clock_sync_mode = (uint8_t)strtol(argv[1], NULL, 0);

    if (errno != 0)
    {
        (void)PRINTF("Error during strtoul errno:%d", errno);
    }

    errno                     = 0;
    tsf_latch.clock_sync_Role = (uint8_t)strtol(argv[2], NULL, 0);

    if (errno != 0)
    {
        (void)PRINTF("Error during strtoul errno:%d", errno);
    }

    errno                                = 0;
    tsf_latch.clock_sync_gpio_pin_number = (uint8_t)strtol(argv[3], NULL, 0);

    if (errno != 0)
    {
        (void)PRINTF("Error during strtoul errno:%d", errno);
    }

    errno                                  = 0;
    tsf_latch.clock_sync_gpio_level_toggle = (uint8_t)strtol(argv[4], NULL, 0);

    if (errno != 0)
    {
        (void)PRINTF("Error during strtoul errno:%d", errno);
    }

    errno                                 = 0;
    tsf_latch.clock_sync_gpio_pulse_width = (uint16_t)strtol(argv[5], NULL, 0);

    if (errno != 0)
    {
        (void)PRINTF("Error during strtoul errno:%d", errno);
    }

    int rv = wlan_set_clocksync_cfg(&tsf_latch);

    if (rv != WM_SUCCESS)
    {
        (void)PRINTF("Unable to set clocksync config\r\n");
    }
    else
    {
        (void)PRINTF("Clock Sync config set as:\r\n");
        (void)PRINTF("Mode                 :%d\n\r", tsf_latch.clock_sync_mode);
        (void)PRINTF("Role                 :%d\n\r", tsf_latch.clock_sync_Role);
        (void)PRINTF("GPIO Pin Number      :%d\n\r", tsf_latch.clock_sync_gpio_pin_number);
        (void)PRINTF("GPIO Level or Toggle :%d\n\r", tsf_latch.clock_sync_gpio_level_toggle);
        (void)PRINTF("GPIO Pulse Width     :%d\n\r", tsf_latch.clock_sync_gpio_pulse_width);
    }
}
#endif /* CONFIG_WIFI_CLOCKSYNC */


static struct cli_command wlan_enhanced_commands[] = {
    {"wlan-get-txpwrlimit", "<subband>", test_wlan_get_txpwrlimit},
    {"wlan-set-txpwrlimit", NULL, test_wlan_set_txpwrlimit},
    {"wlan-set-chanlist-and-txpwrlimit", NULL, test_wlan_set_chanlist_and_txpwrlimit},
    {"wlan-set-chanlist", NULL, test_wlan_set_chanlist},
    {"wlan-get-chanlist", NULL, test_wlan_get_chanlist},
#ifdef CONFIG_11AC
    {"wlan-set-txratecfg", "<sta/uap> <format> <index> <nss> <rate_setting>", test_wlan_set_txratecfg},
#else
    {"wlan-set-txratecfg", "<sta/uap> <format> <index>", test_wlan_set_txratecfg},
#endif
    {"wlan-get-txratecfg", "<sta/uap>", test_wlan_get_txratecfg},
    {"wlan-get-data-rate", "<sta/uap>", test_wlan_get_data_rate},
    {"wlan-get-pmfcfg", NULL, wlan_pmfcfg_get},
    {"wlan-uap-get-pmfcfg", NULL, wlan_uap_pmfcfg_get},
#ifdef CONFIG_5GHz_SUPPORT
    {"wlan-set-ed-mac-mode", "<interface> <ed_ctrl_2g> <ed_offset_2g> <ed_ctrl_5g> <ed_offset_5g>",
     wlan_ed_mac_mode_set},
#else
    {"wlan-set-ed-mac-mode", "<interface> <ed_ctrl_2g> <ed_offset_2g>", wlan_ed_mac_mode_set},
#endif
    {"wlan-get-ed-mac-mode", "<interface>", wlan_ed_mac_mode_get},
#ifdef CONFIG_WIFI_CLOCKSYNC
    {"wlan-get-tsfinfo", "<format-type>", test_get_tsf_info},
    {"wlan-set-clocksync", "<mode> <role> <gpio_pin> <gpio_level> <pulse width>", test_set_clocksync_cfg},
#endif /* CONFIG_WIFI_CLOCKSYNC */
};

int wlan_enhanced_cli_init(void)
{
    if (cli_register_commands(wlan_enhanced_commands,
                              (int)(sizeof(wlan_enhanced_commands) / sizeof(struct cli_command))) != 0)
    {
        return -WM_FAIL;
    }

    return WM_SUCCESS;
}
