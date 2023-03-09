/** @file wlan_tests.c
 *
 *  @brief  This file provides WLAN Test API
 *
 *  Copyright 2008-2023 NXP
 *
 *  Licensed under the LA_OPT_NXP_Software_License.txt (the "Agreement")
 *
 */

#include <string.h>
#include <wm_os.h>
#include <wm_net.h> /* for net_inet_aton */
#include <wlan.h>
#include <cli.h>
#include <cli_utils.h>
#include <wifi.h>
#include <wlan_tests.h>
/*
 * NXP Test Framework (MTF) functions
 */

#ifdef CONFIG_CSI
static uint8_t broadcast_mac[MLAN_MAC_ADDR_LENGTH] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
wlan_csi_config_params_t g_csi_params              = {
    .csi_enable         = 1,
    .head_id            = 0x00010203,
    .tail_id            = 0x00010203,
    .csi_filter_cnt     = 0,
    .chip_id            = 0xaa,
    .band_config        = 0,
    .channel            = 0,
    .csi_monitor_enable = 0,
    .ra4us              = 0,
    /*				  mac_addr						  pkt_type	subtype  flags*/
    //.csi_filter[0] = {0x00,0x00,0x00,0x00,0x00,0x00 , 0x00,     0x00,	 0}
};
#endif

#ifdef CONFIG_NET_MONITOR
wlan_net_monitor_t g_net_monitor_param = {
    .action           = 0x01,
    .monitor_activity = 0x01,
    .filter_flags     = 0x07,
    .radio_type       = 0x0,
    .chan_number      = 0x01,
};
#endif

static void print_address(struct wlan_ip_config *addr, enum wlan_bss_role role)
{
#if SDK_DEBUGCONSOLE != DEBUGCONSOLE_DISABLE
    struct ip4_addr ip, gw, nm, dns1, dns2;
    char addr_type[10] = {0};

    /* If the current network role is STA and ipv4 is not connected then do
     * not print the addresses */
    if (role == WLAN_BSS_ROLE_STA && !is_sta_ipv4_connected())
    {
        goto out;
    }
    ip.addr   = addr->ipv4.address;
    gw.addr   = addr->ipv4.gw;
    nm.addr   = addr->ipv4.netmask;
    dns1.addr = addr->ipv4.dns1;
    dns2.addr = addr->ipv4.dns2;
    if (addr->ipv4.addr_type == ADDR_TYPE_STATIC)
    {
        (void)strncpy(addr_type, "STATIC", strlen("STATIC"));
    }
    else if (addr->ipv4.addr_type == ADDR_TYPE_STATIC)
    {
        (void)strncpy(addr_type, "AUTO IP", strlen("AUTO IP"));
    }
    else
    {
        (void)strncpy(addr_type, "DHCP", strlen("DHCP"));
    }

    (void)PRINTF("\r\n\tIPv4 Address\r\n");
    (void)PRINTF("\taddress: %s", addr_type);
    (void)PRINTF("\r\n\t\tIP:\t\t%s", inet_ntoa(ip));
    (void)PRINTF("\r\n\t\tgateway:\t%s", inet_ntoa(gw));
    (void)PRINTF("\r\n\t\tnetmask:\t%s", inet_ntoa(nm));
    (void)PRINTF("\r\n\t\tdns1:\t\t%s", inet_ntoa(dns1));
    (void)PRINTF("\r\n\t\tdns2:\t\t%s", inet_ntoa(dns2));
    (void)PRINTF("\r\n");
out:
#ifdef CONFIG_IPV6
    if (role == WLAN_BSS_ROLE_STA || role == WLAN_BSS_ROLE_UAP)
    {
        int i;
        (void)PRINTF("\r\n\tIPv6 Addresses\r\n");
        for (i = 0; i < CONFIG_MAX_IPV6_ADDRESSES; i++)
        {
            if (addr->ipv6[i].addr_state != (unsigned char)IP6_ADDR_INVALID)
            {
                (void)PRINTF("\t%-13s:\t%s (%s)\r\n", ipv6_addr_type_to_desc(&addr->ipv6[i]),
                             ipv6_addr_addr_to_desc(&addr->ipv6[i]), ipv6_addr_state_to_desc(addr->ipv6[i].addr_state));
            }
        }
        (void)PRINTF("\r\n");
    }
#endif
    return;
#endif
}

#if SDK_DEBUGCONSOLE != DEBUGCONSOLE_DISABLE
static const char *print_role(enum wlan_bss_role role)
{
    if (role == WLAN_BSS_ROLE_STA)
    {
        return "Infra";
    }
    else if (role == WLAN_BSS_ROLE_UAP)
    {
        return "uAP";
    }
    else if (role == WLAN_BSS_ROLE_ANY)
    {
        return "any";
    }
    else
    {
        return "unknown";
    }
}
#endif

static inline const char *sec_tag(struct wlan_network *network)
{
    if (network->security_specific == 0U)
    {
        return "\tsecurity [Wildcard]";
    }
    else
    {
        return "\tsecurity";
    }
}
#ifdef CONFIG_WIFI_CAPA
static int get_capa(char *arg, uint8_t *wlan_capa)
{
    if (!arg)
        return 1;
#ifdef CONFIG_11AX
    if (string_equal(arg, "11ax") != 0)
    {
        *wlan_capa = (WIFI_SUPPORT_11AX | WIFI_SUPPORT_11AC | WIFI_SUPPORT_11N | WIFI_SUPPORT_LEGACY);
        return 0;
    }
    else
#endif
#ifdef CONFIG_11AC
        if (string_equal(arg, "11ac") != 0)
    {
        *wlan_capa = (WIFI_SUPPORT_11AC | WIFI_SUPPORT_11N | WIFI_SUPPORT_LEGACY);
        return 0;
    }
    else
#endif
        if (string_equal(arg, "11n") != 0)
    {
        *wlan_capa = (WIFI_SUPPORT_11N | WIFI_SUPPORT_LEGACY);
        return 0;
    }
    else if (string_equal(arg, "legacy") != 0)
    {
        *wlan_capa = WIFI_SUPPORT_LEGACY;
        return 0;
    }
    else
        return 1;
}
#endif

static void print_network(struct wlan_network *network)
{
#if SDK_DEBUGCONSOLE != DEBUGCONSOLE_DISABLE
    (void)PRINTF("\"%s\"\r\n\tSSID: %s\r\n\tBSSID: ", network->name,
                 network->ssid[0] != '\0' ? network->ssid : "(hidden)");
    print_mac(network->bssid);
    if (network->channel != 0U)
    {
        (void)PRINTF("\r\n\tchannel: %d", network->channel);
    }
    else
    {
        (void)PRINTF("\r\n\tchannel: %s", "(Auto)");
    }
    (void)PRINTF("\r\n\trole: %s\r\n", print_role(network->role));

    switch (network->security.type)
    {
        case WLAN_SECURITY_NONE:
            (void)PRINTF("%s: none\r\n", sec_tag(network));
            break;
        case WLAN_SECURITY_WEP_OPEN:
            (void)PRINTF("%s: WEP (open)\r\n", sec_tag(network));
            break;
        case WLAN_SECURITY_WEP_SHARED:
            (void)PRINTF("%s: WEP (shared)\r\n", sec_tag(network));
            break;
        case WLAN_SECURITY_WPA:
            (void)PRINTF("%s: WPA\r\n", sec_tag(network));
            break;
        case WLAN_SECURITY_WPA2:
            (void)PRINTF("%s: WPA2", sec_tag(network));
#ifdef CONFIG_11R
            if (network->ft_psk == 1U)
            {
                (void)PRINTF(" with FT_PSK");
            }
#endif
            (void)PRINTF("\r\n");
            break;
        case WLAN_SECURITY_WPA_WPA2_MIXED:
            (void)PRINTF("%s: WPA/WPA2 Mixed\r\n", sec_tag(network));
            break;
#ifdef CONFIG_WPA2_ENTP
        case WLAN_SECURITY_EAP_TLS:
            (void)PRINTF("%s: WPA2 Enterprise EAP-TLS", sec_tag(network));
#ifdef CONFIG_11R
            if (network->ft_1x == 1U)
            {
                (void)PRINTF(" with FT_1X");
            }
#endif
            (void)PRINTF("\r\n");
            break;
#endif
#ifdef CONFIG_PEAP_MSCHAPV2
        case WLAN_SECURITY_PEAP_MSCHAPV2:
            (void)PRINTF("%s: WPA2 Enterprise PEAP-MSCHAPV2\r\n", sec_tag(network));
            break;
#endif
#ifdef CONFIG_OWE
        case WLAN_SECURITY_OWE_ONLY:
            (void)PRINTF("%s: OWE Only\r\n", sec_tag(network));
            break;
#endif
        case WLAN_SECURITY_WPA3_SAE:
            (void)PRINTF("%s: WPA3 SAE", sec_tag(network));
#ifdef CONFIG_11R
            if (network->ft_sae == 1U)
            {
                (void)PRINTF(" with FT_SAE");
            }
#endif
            (void)PRINTF("\r\n");
            break;
        case WLAN_SECURITY_WPA2_WPA3_SAE_MIXED:
            (void)PRINTF("%s: WPA2/WPA3 SAE Mixed\r\n", sec_tag(network));
            break;
        default:
            (void)PRINTF("\r\nUnexpected WLAN SECURITY\r\n");
            break;
    }
#ifdef CONFIG_WIFI_CAPA
    if (network->role == WLAN_BSS_ROLE_UAP)
    {
        uint8_t enable_11ax = false;
        uint8_t enable_11ac = false;
        uint8_t enable_11n  = false;

        enable_11ac = wlan_check_11ac_capa(network->channel);
        enable_11ax = wlan_check_11ax_capa(network->channel);
        enable_11n  = wlan_check_11n_capa(network->channel);
#ifdef CONFIG_11AX
        if (network->wlan_capa & WIFI_SUPPORT_11AX)
        {
            if (!enable_11ax)
            {
                if (enable_11ac)
                {
                    (void)PRINTF("\twifi capability: 11ac\r\n");
                }
                else
                {
                    (void)PRINTF("\twifi capability: 11n\r\n");
                }
            }
            else
            {
                (void)PRINTF("\twifi capability: 11ax\r\n");
            }

            (void)PRINTF("\tuser configure: 11ax\r\n");
        }
        else
#endif
#ifdef CONFIG_11AC
            if (network->wlan_capa & WIFI_SUPPORT_11AC)
        {
            if (!enable_11ac)
            {
                (void)PRINTF("\twifi capability: 11n\r\n");
            }
            else
            {
                (void)PRINTF("\twifi capability: 11ac\r\n");
            }

            (void)PRINTF("\tuser configure: 11ac\r\n");
        }
        else
#endif
            if (network->wlan_capa & WIFI_SUPPORT_11N)
        {
            if (!enable_11n)
            {
                (void)PRINTF("\twifi capability: legacy\r\n");
            }
            else
            {
                (void)PRINTF("\twifi capability: 11n\r\n");
            }

            (void)PRINTF("\tuser configure: 11n\r\n");
        }
        else
        {
            (void)PRINTF("\twifi capability: legacy\r\n");
            (void)PRINTF("\tuser configure: legacy\r\n");
        }
    }
#endif
    print_address(&network->ip, network->role);
#ifdef CONFIG_SCAN_WITH_RSSIFILTER
    (void)PRINTF("\r\n\trssi threshold: %d \r\n", network->rssi_threshold);
#endif
#endif
}

/* Parse the 'arg' string as "ip:ipaddr,gwaddr,netmask,[dns1,dns2]" into
 * a wlan_ip_config data structure */
static int get_address(char *arg, struct wlan_ip_config *ip)
{
    char *ipaddr = NULL, *gwaddr = NULL, *netmask = NULL;
    char *dns1 = NULL, *dns2 = NULL;

    ipaddr = strstr(arg, "ip:");
    if (ipaddr == NULL)
    {
        return -1;
    }
    ipaddr += 3;

    gwaddr = strstr(ipaddr, ",");
    if (gwaddr == NULL)
    {
        return -1;
    }
    *gwaddr++ = (char)0;

    netmask = strstr(gwaddr, ",");
    if (netmask == NULL)
    {
        return -1;
    }
    *netmask++ = (char)0;

    dns1 = strstr(netmask, ",");
    if (dns1 != NULL)
    {
        *dns1++ = (char)0;
        dns2    = strstr(dns1, ",");
    }
    ip->ipv4.address = net_inet_aton(ipaddr);
    ip->ipv4.gw      = net_inet_aton(gwaddr);
    ip->ipv4.netmask = net_inet_aton(netmask);

    if (dns1 != NULL)
    {
        ip->ipv4.dns1 = net_inet_aton(dns1);
    }

    if (dns2 != NULL)
    {
        ip->ipv4.dns2 = net_inet_aton(dns2);
    }

    return 0;
}

static int get_security(int argc, char **argv, enum wlan_security_type type, struct wlan_network_security *sec)
{
    int ret = WM_SUCCESS;
    if (argc < 1)
    {
        return -WM_FAIL;
    }

    switch (type)
    {
        case WLAN_SECURITY_WPA:
        case WLAN_SECURITY_WPA2:
        case WLAN_SECURITY_WPA2_SHA256:
            /* copy the PSK phrase */
            sec->psk_len = (uint8_t)strlen(argv[0]);
            if (sec->psk_len < WLAN_PSK_MIN_LENGTH)
            {
                return -WM_FAIL;
            }
            if (sec->psk_len < sizeof(sec->psk))
            {
                (void)strcpy(sec->psk, argv[0]);
            }
            else
            {
                return -WM_FAIL;
            }
            sec->type = type;
            break;
        default:
            ret = -WM_FAIL;
            break;
    }

    return ret;
}

static bool get_role(char *arg, enum wlan_bss_role *role)
{
    if (arg == NULL)
    {
        return true;
    }

    if (string_equal(arg, "sta") != false)
    {
        *role = WLAN_BSS_ROLE_STA;
        return false;
    }
    else if (string_equal(arg, "uap") != false)
    {
        *role = WLAN_BSS_ROLE_UAP;
        return false;
    }
    else
    {
        return true;
    }
}

/*
 * MTF Shell Commands
 */
static void dump_wlan_add_usage(void)
{
    (void)PRINTF("Usage:\r\n");
    (void)PRINTF("For Station interface\r\n");
    (void)PRINTF("  For DHCP IP Address assignment:\r\n");
    (void)PRINTF(
        "    wlan-add <profile_name> ssid <ssid> [wpa2 <secret>]"
        "\r\n");
    (void)PRINTF("      If using WPA2 security, set the PMF configuration if required.\r\n");
#ifdef CONFIG_OWE
    (void)PRINTF(
        "    wlan-add <profile_name> ssid <ssid> [owe_only] mfpc 1 mfpr 1"
        "\r\n");
    (void)PRINTF("      If using OWE only security, always set the PMF configuration.\r\n");
#endif
    (void)PRINTF(
        "    wlan-add <profile_name> ssid <ssid> [wpa3 sae <secret> mfpc <1> mfpr <0/1>]"
        "\r\n");
    (void)PRINTF("      If using WPA3 SAE security, always set the PMF configuration.\r\n");

    (void)PRINTF("  For static IP address assignment:\r\n");
    (void)PRINTF(
        "    wlan-add <profile_name> ssid <ssid>\r\n"
        "    ip:<ip_addr>,<gateway_ip>,<netmask>\r\n");
    (void)PRINTF(
        "    [bssid <bssid>] [channel <channel number>]\r\n"
        "    [wpa2 <secret>]"
        "\r\n");

    (void)PRINTF("For Micro-AP interface\r\n");
    (void)PRINTF(
        "    wlan-add <profile_name> ssid <ssid>\r\n"
        "    ip:<ip_addr>,<gateway_ip>,<netmask>\r\n");
    (void)PRINTF(
        "    role uap [bssid <bssid>]\r\n"
        "    [channel <channelnumber>]\r\n");
    (void)PRINTF(
        "    [wpa2 <secret>]/[wpa <secret> wpa2 <secret>]/[wpa3 sae <secret> [pwe <0/1/2> tr <0/1>]]/[wpa2 <secret> "
        "wpa3 sae "
        "<secret> [pwe <0/1/2> tr <0/1>]]");
    (void)PRINTF("    [mfpc <0/1>] [mfpr <0/1>]\r\n");
#ifdef CONFIG_WIFI_DTIM_PERIOD
    (void)PRINTF("If seting dtim\r\n");
    (void)PRINTF("The value of dtim is an integer. The default value is 10.\r\n");
#endif
#ifdef CONFIG_11AC
    (void)PRINTF(
        "Note: Setting the channel value greater than or equal to 36 is mandatory,\r\n"
        "      if UAP bandwidth is set to 80MHz.\r\n");
#endif
#ifdef CONFIG_WIFI_CAPA
    (void)PRINTF("\r\n");
#if defined CONFIG_11AX
    (void)PRINTF("    [capa <11ax/11ac/11n/legacy>]\r\n");
#elif defined CONFIG_11AC
    (void)PRINTF("    [capa <11ac/11n/legacy>]\r\n");
#else
    (void)PRINTF("    [capa <11n/legacy>]\r\n");
#endif
#endif
    (void)PRINTF("If Set channel to 0, set acs_band to 0 1.\r\n");
    (void)PRINTF("0: 2.4GHz channel   1: 5GHz channel  Not support to select dual band automatically.\r\n");
}

static void test_wlan_add(int argc, char **argv)
{
    struct wlan_network network;
    int ret    = 0;
    int arg    = 1;
    size_t len = 0U;
    struct
    {
        unsigned ssid : 1;
        unsigned bssid : 1;
        unsigned channel : 1;
        unsigned address : 2;
        unsigned security : 1;
        unsigned security2 : 1;
        unsigned security3 : 1;
        unsigned role : 1;
        unsigned mfpc : 1;
        unsigned mfpr : 1;
#ifdef CONFIG_WIFI_DTIM_PERIOD
        unsigned dtim : 1;
#endif
#ifdef CONFIG_WIFI_CAPA
        unsigned wlan_capa : 1;
#endif
        unsigned acs_band : 1;
    } info;

    (void)memset(&info, 0, sizeof(info));
    (void)memset(&network, 0, sizeof(struct wlan_network));

    if (argc < 4)
    {
        dump_wlan_add_usage();
        (void)PRINTF("Error: invalid number of arguments\r\n");
        return;
    }

    len = strlen(argv[arg]);
    if (len >= WLAN_NETWORK_NAME_MAX_LENGTH)
    {
        (void)PRINTF("Error: network name too long\r\n");
        return;
    }

    (void)memcpy(network.name, argv[arg], len);
    arg++;
    info.address = (u8_t)ADDR_TYPE_DHCP;
    do
    {
        if ((info.ssid == 0U) && string_equal("ssid", argv[arg]))
        {
            len = strlen(argv[arg + 1]);
            if (len > IEEEtypes_SSID_SIZE)
            {
                (void)PRINTF("Error: SSID is too long\r\n");
                return;
            }
            (void)memcpy(network.ssid, argv[arg + 1], len);
            arg += 2;
            info.ssid = 1;
        }
        else if ((info.bssid == 0U) && string_equal("bssid", argv[arg]))
        {
            if (get_mac(argv[arg + 1], network.bssid, ':') != false)
            {
                (void)PRINTF(
                    "Error: invalid BSSID argument"
                    "\r\n");
                return;
            }
            arg += 2;
            info.bssid = 1;
        }
        else if ((info.channel == 0U) && string_equal("channel", argv[arg]))
        {
            if (arg + 1 >= argc || get_uint(argv[arg + 1], &network.channel, strlen(argv[arg + 1])))
            {
                (void)PRINTF(
                    "Error: invalid channel"
                    " argument\n");
                return;
            }
            arg += 2;
            info.channel = 1;
        }
        else if (strncmp(argv[arg], "ip:", 3) == 0)
        {
            if (get_address(argv[arg], &network.ip) != 0)
            {
                (void)PRINTF(
                    "Error: invalid address"
                    " argument\n");
                return;
            }
            arg++;
            info.address = (u8_t)ADDR_TYPE_STATIC;
        }
        else if ((info.security == 0U) && string_equal("wpa", argv[arg]))
        {
            if (get_security(argc - arg - 1, argv + arg + 1, WLAN_SECURITY_WPA, &network.security) != 0)
            {
                (void)PRINTF(
                    "Error: invalid WPA security"
                    " argument\r\n");
                return;
            }
            arg += 2;
            info.security++;
        }
        else if ((info.security2 == 0U) && (string_equal("wpa2", argv[arg]) || string_equal("wpa2-sha256", argv[arg])))
        {
            if (string_equal("wpa2", argv[arg]))
            {
                network.security.type = WLAN_SECURITY_WPA2;
            }
            else if (string_equal("wpa2-sha256", argv[arg]))
            {
                network.security.type = WLAN_SECURITY_WPA2_SHA256;
            }
            if (get_security(argc - arg - 1, argv + arg + 1, network.security.type, &network.security) != 0)
            {
                (void)PRINTF(
                    "Error: invalid WPA2 security"
                    " argument\r\n");
                return;
            }
            arg += 2;
            info.security2++;
        }
#ifdef CONFIG_OWE
        else if (!info.security && string_equal("owe_only", argv[arg]))
        {
            network.security.type = WLAN_SECURITY_OWE_ONLY;
            arg += 1;
            info.security++;
        }
#endif
        else if ((info.security3 == 0U) && string_equal("wpa3", argv[arg]))
        {
            if (string_equal(argv[arg + 1], "sae") != false)
            {
                network.security.type = WLAN_SECURITY_WPA3_SAE;
                /* copy the PSK phrase */
                network.security.password_len = strlen(argv[arg + 2]);
                if (network.security.password_len == 0U)
                {
                    (void)PRINTF(
                        "Error: invalid WPA3 security"
                        " argument\r\n");
                    return;
                }
                if (network.security.password_len < sizeof(network.security.password))
                {
                    (void)strcpy(network.security.password, argv[arg + 2]);
                }
                else
                {
                    (void)PRINTF(
                        "Error: invalid WPA3 security"
                        " argument\r\n");
                    return;
                }
                arg += 2;

                if (string_equal(argv[arg + 1], "pwe") != false)
                {
                    errno                           = 0;
                    network.security.pwe_derivation = (bool)strtol(argv[arg + 2], NULL, 10);
                    if (errno != 0)
                    {
                        (void)PRINTF("Error during strtoul:pwe errno:%d\r\n", errno);
                    }
                    if (arg + 2 >= argc ||
                        (network.security.pwe_derivation != 0U && network.security.pwe_derivation != 1U &&
                         network.security.pwe_derivation != 2U))
                    {
                        (void)PRINTF(
                            "Error: invalid wireless"
                            " network pwe derivation\r\n");
                        return;
                    }
                    arg += 2;

                    if (string_equal(argv[arg + 1], "tr") != false)
                    {
                        errno                               = 0;
                        network.security.transition_disable = (bool)strtol(argv[arg + 2], NULL, 10);
                        if (errno != 0)
                        {
                            (void)PRINTF("Error during strtoul:pwe errno:%d\r\n", errno);
                        }
                        if (arg + 2 >= argc ||
                            (network.security.transition_disable != 0U && network.security.transition_disable != 1U))
                        {
                            (void)PRINTF(
                                "Error: invalid wireless"
                                " network transition state\r\n");
                            return;
                        }
                        arg += 2;
                    }
                }
            }
            else
            {
                (void)PRINTF(
                    "Error: invalid WPA3 security"
                    " argument\r\n");
                return;
            }
            arg += 1;
            info.security3++;
        }
        else if ((info.role == 0U) && string_equal("role", argv[arg]))
        {
            if (arg + 1 >= argc || get_role(argv[arg + 1], &network.role))
            {
                (void)PRINTF(
                    "Error: invalid wireless"
                    " network role\r\n");
                return;
            }
            arg += 2;
            info.role++;
        }
        else if ((info.mfpc == 0U) && string_equal("mfpc", argv[arg]))
        {
            errno                 = 0;
            network.security.mfpc = (bool)strtol(argv[arg + 1], NULL, 10);
            if (errno != 0)
            {
                (void)PRINTF("Error during strtoul:mfpc errno:%d\r\n", errno);
            }
            if (arg + 1 >= argc || (network.security.mfpc != false && network.security.mfpc != true))
            {
                (void)PRINTF(
                    "Error: invalid wireless"
                    " network mfpc\r\n");
                return;
            }
            arg += 2;
            info.mfpc++;
        }
        else if ((info.mfpr == 0U) && string_equal("mfpr", argv[arg]))
        {
            errno                 = 0;
            network.security.mfpr = (bool)strtol(argv[arg + 1], NULL, 10);
            if (errno != 0)
            {
                (void)PRINTF("Error during strtoul:mfpr errno:%d\r\n", errno);
            }
            if (arg + 1 >= argc || (network.security.mfpr != false && network.security.mfpr != true))
            {
                (void)PRINTF(
                    "Error: invalid wireless"
                    " network mfpr\r\n");
                return;
            }
            arg += 2;
            info.mfpr++;
        }
        else if (strncmp(argv[arg], "autoip", 6) == 0)
        {
            info.address = (u8_t)ADDR_TYPE_LLA;
            arg++;
        }
#ifdef CONFIG_WIFI_DTIM_PERIOD
        else if (!info.dtim && string_equal("dtim", argv[arg]))
        {
            unsigned int dtim_period;
            if (arg + 1 >= argc || get_uint(argv[arg + 1], &dtim_period, strlen(argv[arg + 1])))
            {
                (void)PRINTF(
                    "Error: invalid dtim"
                    " argument \r\n");
                return;
            }
            network.dtim_period = (uint8_t)(dtim_period & 0XFF);
            arg += 2;
            info.dtim = 1;
        }
#endif
#ifdef CONFIG_WIFI_CAPA
        else if (!info.wlan_capa && network.role == WLAN_BSS_ROLE_UAP && string_equal("capa", argv[arg]))
        {
            if (arg + 1 >= argc || get_capa(argv[arg + 1], &network.wlan_capa))
            {
                (void)PRINTF(
                    "Error: invalid wireless"
                    " capability\r\n");
                return;
            }
            arg += 2;
            info.wlan_capa++;
        }
#endif
        else if (!info.acs_band && string_equal("acs_band", argv[arg]))
        {
            unsigned int ACS_band = 0;
            if (arg + 1 >= argc || get_uint(argv[arg + 1], &ACS_band, strlen(argv[arg + 1])))
            {
                (void)PRINTF("Error: invalid acs_band\r\n");
                return;
            }
            if (ACS_band != 0 && ACS_band != 1)
            {
                (void)PRINTF("Pls Set acs_band to 0 or 1.\r\n");
                (void)PRINTF(
                    "0: 2.4GHz channel   1: 5GHz channel\r\n"
                    "Not support to select dual band automatically.\r\n");
                return;
            }
            network.acs_band = (uint16_t)ACS_band;
            arg += 2;
            info.acs_band = 1;
        }
        else
        {
            dump_wlan_add_usage();
            (void)PRINTF("Error: argument %d is invalid\r\n", arg);
            return;
        }
    } while (arg < argc);

    if ((info.ssid == 0U) && (info.bssid == 0U))
    {
        dump_wlan_add_usage();
        (void)PRINTF("Error: specify at least the SSID or BSSID\r\n");
        return;
    }

    if ((info.security && info.security2 && info.security3) ||
        ((network.security.type == WLAN_SECURITY_WPA) && info.security && !info.security2))
    {
        dump_wlan_add_usage();
        (void)PRINTF("Error: not support WPA or WPA/WPA2/WPA3 Mixed\r\n");
        return;
    }

    if ((network.security.type == WLAN_SECURITY_WPA) || (network.security.type == WLAN_SECURITY_WPA2))
    {
        if (network.security.psk_len && info.security && info.security2)
            network.security.type = WLAN_SECURITY_WPA_WPA2_MIXED;
    }

    if ((network.security.type == WLAN_SECURITY_WPA2) || (network.security.type == WLAN_SECURITY_WPA3_SAE))
    {
        if ((network.security.psk_len != 0U) && (network.security.password_len != 0U))
        {
            network.security.type = WLAN_SECURITY_WPA2_WPA3_SAE_MIXED;
        }
    }

    network.ip.ipv4.addr_type = (enum address_types)(info.address);

    ret = wlan_add_network(&network);
    switch (ret)
    {
        case WM_SUCCESS:
            (void)PRINTF("Added \"%s\"\r\n", network.name);
            break;
        case -WM_E_INVAL:
            (void)PRINTF("Error: network already exists or invalid arguments\r\n");
            break;
        case -WM_E_NOMEM:
            (void)PRINTF("Error: network list is full\r\n");
            break;
        case WLAN_ERROR_STATE:
            (void)PRINTF("Error: can't add networks in this state\r\n");
            break;
        default:
            (void)PRINTF(
                "Error: unable to add network for unknown"
                " reason\r\n");
            break;
    }
}

static int __scan_cb(unsigned int count)
{
#if SDK_DEBUGCONSOLE != DEBUGCONSOLE_DISABLE
    struct wlan_scan_result res;
    unsigned int i;
    int err;

    if (count == 0U)
    {
        (void)PRINTF("no networks found\r\n");
        return 0;
    }

    (void)PRINTF("%d network%s found:\r\n", count, count == 1U ? "" : "s");

    for (i = 0; i < count; i++)
    {
        err = wlan_get_scan_result(i, &res);
        if (err != 0)
        {
            (void)PRINTF("Error: can't get scan res %d\r\n", i);
            continue;
        }

        print_mac(res.bssid);

        if (res.ssid[0] != '\0')
        {
            (void)PRINTF(" \"%s\" %s\r\n", res.ssid, print_role(res.role));
        }
        else
        {
            (void)PRINTF(" (hidden) %s\r\n", print_role(res.role));
        }

        (void)PRINTF("\tchannel: %d\r\n", res.channel);
        (void)PRINTF("\trssi: -%d dBm\r\n", res.rssi);
        (void)PRINTF("\tsecurity: ");
        if (res.wep != 0U)
        {
            (void)PRINTF("WEP ");
        }
        if ((res.wpa != 0U) && (res.wpa2 != 0U))
        {
            (void)PRINTF("WPA/WPA2 Mixed ");
        }
        else if ((res.wpa2 != 0U) && (res.wpa3_sae != 0U))
        {
            (void)PRINTF("WPA2/WPA3 SAE Mixed ");
        }
        else
        {
            if (res.wpa != 0U)
            {
                (void)PRINTF("WPA ");
            }
            if (res.wpa2 != 0U)
            {
                (void)PRINTF("WPA2 ");
            }
            if (res.wpa3_sae != 0U)
            {
                (void)PRINTF("WPA3 SAE ");
            }
            if (res.wpa2_entp != 0U)
            {
                (void)PRINTF("WPA2 Enterprise ");
            }
        }
#ifdef CONFIG_11R
        if (res.ft_1x != 0U)
        {
            (void)PRINTF("with FT_802.1x");
        }
        if (res.ft_psk != 0U)
        {
            (void)PRINTF("with FT_PSK");
        }
        if (res.ft_sae != 0U)
        {
            (void)PRINTF("with FT_SAE");
        }
#endif
        if (!((res.wep != 0U) || (res.wpa != 0U) || (res.wpa2 != 0U) || (res.wpa3_sae != 0U) || (res.wpa2_entp != 0U)))
        {
            (void)PRINTF("OPEN ");
        }
        (void)PRINTF("\r\n");

        (void)PRINTF("\tWMM: %s\r\n", (res.wmm != 0U) ? "YES" : "NO");

#ifdef CONFIG_11K
        if (res.neighbor_report_supported == true)
        {
            (void)PRINTF("\t802.11K: YES\r\n");
        }
#endif
#ifdef CONFIG_11V
        if (res.bss_transition_supported == true)
        {
            (void)PRINTF("\t802.11V: YES\r\n");
        }
#endif
        if ((res.ap_mfpc == true) && (res.ap_mfpr == true))
        {
            (void)PRINTF("\t802.11W: Capable, Required\r\n");
        }
        if ((res.ap_mfpc == true) && (res.ap_mfpr == false))
        {
            (void)PRINTF("\t802.11W: Capable\r\n");
        }
        if ((res.ap_mfpc == false) && (res.ap_mfpr == false))
        {
            (void)PRINTF("\t802.11W: NA\r\n");
        }
#ifdef CONFIG_WPS2
        if (res.wps)
        {
            if (res.wps_session == WPS_SESSION_PBC)
                (void)PRINTF("\tWPS: %s, Session: %s\r\n", "YES", "Push Button");
            else if (res.wps_session == WPS_SESSION_PIN)
                (void)PRINTF("\tWPS: %s, Session: %s\r\n", "YES", "PIN");
            else
                (void)PRINTF("\tWPS: %s, Session: %s\r\n", "YES", "Not active");
        }
        else
            (void)PRINTF("\tWPS: %s \r\n", "NO");
#endif
#ifdef CONFIG_OWE
        if (res.trans_ssid_len != 0U)
        {
            (void)PRINTF("\tOWE BSSID: ");
            print_mac(res.trans_bssid);
            (void)PRINTF("\r\n\tOWE SSID:");
            if (res.trans_ssid_len != 0U)
            {
                (void)PRINTF(" \"%s\"\r\n", res.trans_ssid);
            }
        }
#endif
    }
#endif

    return 0;
}

static void test_wlan_scan(int argc, char **argv)
{
    if (wlan_scan(__scan_cb) != 0)
    {
        (void)PRINTF("Error: scan request failed\r\n");
    }
    else
    {
        (void)PRINTF("Scan scheduled...\r\n");
    }
}

static void dump_wlan_scan_opt_usage(void)
{
    (void)PRINTF("Usage:\r\n");
    (void)PRINTF(
        "    wlan-scan-opt ssid <ssid> bssid <bssid> "
#ifdef CONFIG_SCAN_WITH_RSSIFILTER
        "channel <channel> probes <probes> rssi_threshold <rssi_threshold>"
#else
        "channel <channel> probes <probes>"
#endif
        "\r\n");
}

static void test_wlan_scan_opt(int argc, char **argv)
{
    wlan_scan_params_v2_t wlan_scan_param;
    int arg = 1;
#ifdef CONFIG_COMBO_SCAN
    int num_ssid = 0;
#endif
    struct
    {
        unsigned ssid : 1;
        unsigned bssid : 1;
        unsigned channel : 1;
        unsigned probes : 1;
#ifdef CONFIG_SCAN_WITH_RSSIFILTER
        unsigned rssi_threshold : 1;
#endif
    } info;

    (void)memset(&info, 0, sizeof(info));
    (void)memset(&wlan_scan_param, 0, sizeof(wlan_scan_params_v2_t));

    if (argc < 3)
    {
        dump_wlan_scan_opt_usage();
        (void)PRINTF("Error: invalid number of arguments\r\n");
        return;
    }
    do
    {
        if ((info.ssid == 0U) && string_equal("ssid", argv[arg]))
        {
#ifdef CONFIG_COMBO_SCAN
            if (num_ssid > MAX_NUM_SSID)
            {
                (void)PRINTF("Error: the number of SSID is more than 2\r\n");
                return;
            }
#endif
            if (strlen(argv[arg + 1]) > IEEEtypes_SSID_SIZE)
            {
                (void)PRINTF("Error: SSID is too long\r\n");
                return;
            }
#ifdef CONFIG_COMBO_SCAN
            (void)memcpy(wlan_scan_param.ssid[num_ssid], argv[arg + 1], strlen(argv[arg + 1]));
            num_ssid++;
#else
            (void)memcpy(wlan_scan_param.ssid, argv[arg + 1], strlen(argv[arg + 1]));
#endif
            arg += 2;
            info.ssid = 1;
        }
        else if ((info.bssid == 0U) && string_equal("bssid", argv[arg]))
        {
            if (get_mac(argv[arg + 1], (char *)wlan_scan_param.bssid, ':') != false)
            {
                (void)PRINTF(
                    "Error: invalid BSSID argument"
                    "\r\n");
                return;
            }
            arg += 2;
            info.bssid = 1;
        }
        else if ((info.channel == 0U) && string_equal("channel", argv[arg]))
        {
            if (arg + 1 >= argc ||
                get_uint(argv[arg + 1], (unsigned int *)(void *)&wlan_scan_param.chan_list[0].chan_number,
                         strlen(argv[arg + 1])))
            {
                (void)PRINTF(
                    "Error: invalid channel"
                    " argument\n");
                return;
            }
            wlan_scan_param.num_channels           = 1;
            wlan_scan_param.chan_list[0].scan_type = MLAN_SCAN_TYPE_ACTIVE;
            wlan_scan_param.chan_list[0].scan_time = 120;
            arg += 2;
            info.channel = 1;
        }
        else if ((info.probes == 0U) && string_equal("probes", argv[arg]))
        {
            if (arg + 1 >= argc ||
                get_uint(argv[arg + 1], (unsigned int *)(void *)&wlan_scan_param.num_probes, strlen(argv[arg + 1])))
            {
                (void)PRINTF(
                    "Error: invalid probes"
                    " argument\n");
                return;
            }
            if (wlan_scan_param.num_probes > 4U)
            {
                (void)PRINTF(
                    "Error: invalid number of probes"
                    "\r\n");
                return;
            }
            arg += 2;
            info.probes = 1;
        }
#ifdef CONFIG_SCAN_WITH_RSSIFILTER
        else if (!info.rssi_threshold && string_equal("rssi_threshold", argv[arg]))
        {
            if (arg + 1 >= argc)
            {
                (void)PRINTF(
                    "Error: invalid rssi threshold"
                    " argument\n");
                return;
            }
            wlan_scan_param.rssi_threshold = atoi(argv[arg + 1]);
            if (wlan_scan_param.rssi_threshold < -101)
            {
                (void)PRINTF(
                    "Error: invalid value of rssi threshold"
                    "\r\n");
                return;
            }
            arg += 2;
            info.rssi_threshold = 1;
        }
#endif
        else
        {
            dump_wlan_scan_opt_usage();
            (void)PRINTF("Error: argument %d is invalid\r\n", arg);
            return;
        }
    } while (arg < argc);

    if ((info.ssid == 0U) && (info.bssid == 0U))
    {
        dump_wlan_scan_opt_usage();
        (void)PRINTF("Error: specify at least the SSID or BSSID\r\n");
        return;
    }

    wlan_scan_param.cb = __scan_cb;

    if (wlan_scan_with_opt(wlan_scan_param) != 0)
    {
        (void)PRINTF("Error: scan request failed\r\n");
    }
    else
    {
        (void)PRINTF("Scan for ");
        if (info.ssid != 0U)
        {
#ifdef CONFIG_COMBO_SCAN
            (void)PRINTF("ssid \"%s\" ", wlan_scan_param.ssid[0]);
#else
            (void)PRINTF("ssid \"%s\" ", wlan_scan_param.ssid);
#endif
        }
        if (info.bssid != 0U)
        {
            (void)PRINTF("bssid ");
            print_mac((const char *)wlan_scan_param.bssid);
        }
        if (info.probes != 0U)
        {
            (void)PRINTF("with %d probes ", wlan_scan_param.num_probes);
#ifdef CONFIG_SCAN_WITH_RSSIFILTER
            wlan_set_rssi_threshold(wlan_scan_param.rssi_threshold);
            if (info.rssi_threshold != 0U)
                (void)PRINTF("with %d rssi_threshold ", wlan_scan_param.rssi_threshold);
#endif
        }
        (void)PRINTF("scheduled...\r\n");
    }
}

static void test_wlan_remove(int argc, char **argv)
{
    int ret;

    if (argc < 2)
    {
        (void)PRINTF("Usage: %s <profile_name>\r\n", argv[0]);
        (void)PRINTF("Error: specify network to remove\r\n");
        return;
    }

    ret = wlan_remove_network(argv[1]);
    switch (ret)
    {
        case WM_SUCCESS:
            (void)PRINTF("Removed \"%s\"\r\n", argv[1]);
            break;
        case -WM_E_INVAL:
            (void)PRINTF("Error: network not found\r\n");
            break;
        case WLAN_ERROR_STATE:
            (void)PRINTF("Error: can't remove network in this state\r\n");
            break;
        default:
            (void)PRINTF("Error: unable to remove network\r\n");
            break;
    }
}

static void test_wlan_connect(int argc, char **argv)
{
    int ret = wlan_connect(argc >= 2 ? argv[1] : NULL);

    if (ret == WLAN_ERROR_STATE)
    {
        (void)PRINTF("Error: connect manager not running\r\n");
        return;
    }

    if (ret == -WM_E_INVAL)
    {
        (void)PRINTF("Usage: %s <profile_name>\r\n", argv[0]);
        (void)PRINTF("Error: specify a network to connect\r\n");
        return;
    }
    (void)PRINTF(
        "Connecting to network...\r\nUse 'wlan-stat' for "
        "current connection status.\r\n");
}

static void test_wlan_start_network(int argc, char **argv)
{
    int ret;

    if (argc < 2)
    {
        (void)PRINTF("Usage: %s <profile_name>\r\n", argv[0]);
        (void)PRINTF("Error: specify a network to start\r\n");
        return;
    }

    ret = wlan_start_network(argv[1]);
    if (ret != WM_SUCCESS)
    {
        (void)PRINTF("Error: unable to start network\r\n");
    }
}

static void test_wlan_stop_network(int argc, char **argv)
{
    int ret;
    struct wlan_network network;

    (void)memset(&network, 0x00, sizeof(struct wlan_network));
    (void)wlan_get_current_uap_network(&network);
    ret = wlan_stop_network(network.name);
    if (ret != WM_SUCCESS)
    {
        (void)PRINTF("Error: unable to stop network\r\n");
    }
}

static void test_wlan_disconnect(int argc, char **argv)
{
    if (wlan_disconnect() != WM_SUCCESS)
    {
        (void)PRINTF("Error: unable to disconnect\r\n");
    }
}

static void test_wlan_stat(int argc, char **argv)
{
    enum wlan_connection_state state;
    enum wlan_ps_mode ps_mode;
    char ps_mode_str[30];

    if (wlan_get_ps_mode(&ps_mode) != 0)
    {
        (void)PRINTF(
            "Error: unable to get power save"
            " mode\r\n");
        return;
    }

    switch (ps_mode)
    {
        case WLAN_IEEE:
            (void)strcpy(ps_mode_str, "IEEE ps");
            break;
        case WLAN_DEEP_SLEEP:
            (void)strcpy(ps_mode_str, "Deep sleep");
            break;
#ifdef CONFIG_WIFIDRIVER_PS_LOCK
        case WLAN_IEEE_DEEP_SLEEP:
            (void)strcpy(ps_mode_str, "IEEE ps and Deep sleep");
            break;
#ifdef CONFIG_WNM_PS
        case WLAN_WNM:
            (void)strcpy(ps_mode_str, "WNM ps");
            break;
        case WLAN_WNM_DEEP_SLEEP:
            (void)strcpy(ps_mode_str, "WNM ps and Deep sleep");
            break;
#endif
#endif
        case WLAN_ACTIVE:
        default:
            (void)strcpy(ps_mode_str, "Active");
            break;
    }

    if (wlan_get_connection_state(&state) != 0)
    {
        (void)PRINTF(
            "Error: unable to get STA connection"
            " state\r\n");
    }
    else
    {
        switch (state)
        {
            case WLAN_DISCONNECTED:
                (void)PRINTF("Station disconnected (%s)\r\n", ps_mode_str);
                break;
            case WLAN_SCANNING:
                (void)PRINTF("Station scanning (%s)\r\n", ps_mode_str);
                break;
            case WLAN_ASSOCIATING:
                (void)PRINTF("Station associating (%s)\r\n", ps_mode_str);
                break;
            case WLAN_ASSOCIATED:
                (void)PRINTF("Station associated (%s)\r\n", ps_mode_str);
                break;
            case WLAN_CONNECTING:
                (void)PRINTF("Station connecting (%s)\r\n", ps_mode_str);
                break;
            case WLAN_CONNECTED:
                (void)PRINTF("Station connected (%s)\r\n", ps_mode_str);
                break;
            default:
                (void)PRINTF(
                    "Error: invalid STA state"
                    " %d\r\n",
                    state);
                break;
        }
    }
    if (wlan_get_uap_connection_state(&state) != 0)
    {
        (void)PRINTF(
            "Error: unable to get uAP connection"
            " state\r\n");
    }
    else
    {
        switch (state)
        {
            case WLAN_UAP_STARTED:
                (void)strcpy(ps_mode_str, "Active");
                (void)PRINTF("uAP started (%s)\r\n", ps_mode_str);
                break;
            case WLAN_UAP_STOPPED:
                (void)PRINTF("uAP stopped\r\n");
                break;
            default:
                (void)PRINTF(
                    "Error: invalid uAP state"
                    " %d\r\n",
                    state);
                break;
        }
    }
}

static void test_wlan_list(int argc, char **argv)
{
    struct wlan_network network;
    unsigned int count;
    unsigned int i;

    if (wlan_get_network_count(&count) != 0)
    {
        (void)PRINTF("Error: unable to get number of networks\r\n");
        return;
    }

    (void)PRINTF("%d network%s%s\r\n", count, count == 1U ? "" : "s", count > 0U ? ":" : "");
    for (i = 0; i < WLAN_MAX_KNOWN_NETWORKS; i++)
    {
        if (wlan_get_network(i, &network) == WM_SUCCESS)
        {
            print_network(&network);
        }
    }
}

static void test_wlan_info(int argc, char **argv)
{
    enum wlan_connection_state state;
    struct wlan_network sta_network;
    struct wlan_network uap_network;
#ifndef CONFIG_MULTI_CHAN
    int sta_found = 0;
#endif

    if (wlan_get_connection_state(&state) != 0)
    {
        (void)PRINTF(
            "Error: unable to get STA connection"
            " state\r\n");
    }
    else
    {
        switch (state)
        {
            case WLAN_CONNECTED:
                if (wlan_get_current_network(&sta_network) == WM_SUCCESS)
                {
                    (void)PRINTF("Station connected to:\r\n");
                    print_network(&sta_network);
#ifndef CONFIG_MULTI_CHAN
                    sta_found = 1;
#endif
                }
                else
                {
                    (void)PRINTF("Station not connected\r\n");
                }
                break;
            default:
                (void)PRINTF("Station not connected\r\n");
                break;
        }
    }

    if (wlan_get_current_uap_network(&uap_network) != 0)
    {
        (void)PRINTF("uAP not started\r\n");
    }
    else
    {
#ifndef CONFIG_MULTI_CHAN
        /* Since uAP automatically changes the channel to the one that
         * STA is on */
        if (sta_found == 1)
        {
            uap_network.channel = sta_network.channel;
        }
#endif
        if (uap_network.role == WLAN_BSS_ROLE_UAP)
        {
            (void)PRINTF("uAP started as:\r\n");
        }

        print_network(&uap_network);
    }
}

static void test_wlan_address(int argc, char **argv)
{
    struct wlan_network network;

    if (wlan_get_current_network(&network) != 0)
    {
        (void)PRINTF("not connected\r\n");
        return;
    }
    print_address(&network.ip, network.role);
}

static void test_wlan_get_uap_channel(int argc, char **argv)
{
    int channel;
    int rv = wlan_get_uap_channel(&channel);
    if (rv != WM_SUCCESS)
    {
        (void)PRINTF("Unable to get channel: %d\r\n", rv);
    }
    else
    {
        (void)PRINTF("uAP channel: %d\r\n", channel);
    }
}

static void test_wlan_get_uap_sta_list(int argc, char **argv)
{
#if SDK_DEBUGCONSOLE != DEBUGCONSOLE_DISABLE
    int i;
    wifi_sta_list_t *sl = NULL;

    (void)wifi_uap_bss_sta_list(&sl);

    if (sl == NULL)
    {
        (void)PRINTF("Failed to get sta list\n\r");
        return;
    }

    wifi_sta_info_t *si = (wifi_sta_info_t *)(void *)(&sl->count + 1);

    (void)PRINTF("Number of STA = %d \r\n\r\n", sl->count);
    for (i = 0; i < sl->count; i++)
    {
        (void)PRINTF("STA %d information:\r\n", i + 1);
        (void)PRINTF("=====================\r\n");
        (void)PRINTF("MAC Address: %02X:%02X:%02X:%02X:%02X:%02X\r\n", si[i].mac[0], si[i].mac[1], si[i].mac[2],
                     si[i].mac[3], si[i].mac[4], si[i].mac[5]);
        (void)PRINTF("Power mfg status: %s\r\n", (si[i].power_mgmt_status == 0U) ? "active" : "power save");
        (void)PRINTF("Rssi : %d dBm\r\n\r\n", (signed char)si[i].rssi);
    }

    os_mem_free(sl);
#endif
}

static void test_wlan_ieee_ps(int argc, char **argv)
{
    int choice             = -1;
    int ret                = -WM_FAIL;
    unsigned int condition = 0;

    if (argc < 2)
    {
        (void)PRINTF("Usage: %s <0/1>\r\n", argv[0]);
        (void)PRINTF("Error: Specify 0 to Disable or 1 to Enable\r\n");
        return;
    }

    errno  = 0;
    choice = strtol(argv[1], NULL, 10);
    if (errno != 0)
    {
        (void)PRINTF("Error during strtoul:mfpc errno:%d\r\n", errno);
    }

    if (choice == 0)
    {
        ret = wlan_ieeeps_off();
        if (ret == WM_SUCCESS)
        {
            (void)PRINTF("Turned off IEEE Power Save mode");
        }
        else
        {
            (void)PRINTF("Failed to turn off IEEE Power Save mode, error: %d", ret);
        }
    }
    else if (choice == 1)
    {
        condition = (uint32_t)WAKE_ON_ARP_BROADCAST | (uint32_t)WAKE_ON_UNICAST | (uint32_t)WAKE_ON_MULTICAST |
                    (uint32_t)WAKE_ON_MAC_EVENT;
        ret = wlan_ieeeps_on(condition);
        if (ret == WM_SUCCESS)
        {
            (void)PRINTF("Turned on IEEE Power Save mode");
        }
        else
        {
            (void)PRINTF("Failed to turn on IEEE Power Save mode, error: %d", ret);
        }
    }
    else
    {
        (void)PRINTF("Error: Specify 0 to Disable or 1 to Enable\r\n");
    }
}

#if defined(CONFIG_WIFIDRIVER_PS_LOCK) && defined(CONFIG_WNM_PS)
static void test_wlan_wnm_ps(int argc, char **argv)
{
    int choice                = -1;
    int ret                   = -WM_FAIL;
    unsigned int condition    = 0;
    unsigned int wnm_interval = 0;

    if (argc < 2)
    {
        (void)PRINTF("Usage: %s <0/1>\r\n", argv[0]);
        (void)PRINTF("Error: Specify 0 to Disable or 1 to Enable\r\n");
        (void)PRINTF("If enable, please specify sleep_interval\r\n");
        (void)PRINTF("Example:\r\n");
        (void)PRINTF("	  wlan-wnm-ps 1 5\r\n");
        return;
    }

    choice = atoi(argv[1]);

    if (choice == 0)
    {
        ret = wlan_wnmps_off();
        if (ret == WM_SUCCESS)
            (void)PRINTF("Turned off WNM Power Save mode");
        else
            (void)PRINTF("Failed to turn off WNM Power Save mode, error: %d", ret);
    }
    else if (choice == 1)
    {
        if (get_uint(argv[2], &wnm_interval, strlen(argv[2])) == 0)
        {
            condition = WAKE_ON_ARP_BROADCAST | WAKE_ON_UNICAST | WAKE_ON_MULTICAST | WAKE_ON_MAC_EVENT;
            ret       = wlan_wnmps_on(condition, (t_u16)wnm_interval);
        }
        else
        {
            (void)PRINTF("Error: please specify sleep_interval\r\n");
            return;
        }

        if (ret == WM_SUCCESS)
            (void)PRINTF("Turned on WNM Power Save mode");
        else
            (void)PRINTF("Failed to turn on WNM Power Save mode, error: %d", ret);
    }
    else
    {
        (void)PRINTF("Error: Specify 0 to Disable or 1 to Enable\r\n");
    }
}
#endif

static void test_wlan_deep_sleep_ps(int argc, char **argv)
{
    int choice = -1;
    int ret    = -WM_FAIL;

    if (argc < 2)
    {
        (void)PRINTF("Usage: %s <0/1>\r\n", argv[0]);
        (void)PRINTF("Error: Specify 0 to Disable or 1 to Enable\r\n");
        return;
    }

    errno  = 0;
    choice = strtol(argv[1], NULL, 10);
    if (errno != 0)
    {
        (void)PRINTF("Error during strtoul:deep_sleep_ps errno:%d\r\n", errno);
    }

    if (choice == 0)
    {
        ret = wlan_deepsleepps_off();
        if (ret == WM_SUCCESS)
        {
            (void)PRINTF("Turned off Deep Sleep Power Save mode");
        }
        else
        {
            (void)PRINTF("Failed to turn off Deep Sleep Power Save mode, error: %d", ret);
        }
    }
    else if (choice == 1)
    {
        ret = wlan_deepsleepps_on();
        if (ret == WM_SUCCESS)
        {
            (void)PRINTF("Turned on Deep Sleep Power Save mode");
        }
        else
        {
            (void)PRINTF("Failed to turn on Deep Sleep Power Save mode, error: %d", ret);
        }
    }
    else
    {
        (void)PRINTF("Error: Specify 0 to Disable or 1 to Enable\r\n");
    }
}

#ifdef CONFIG_WIFI_TX_PER_TRACK
static void dump_wlan_tx_pert_usage(void)
{
    (void)PRINTF("Usage:\r\n");
    (void)PRINTF(
        "    wlan-tx-pert <0/1> <STA/AP> <p:tx_pert_check_period> "
        "<r:tx_pert_check_ratio> <n:tx_pert_check_num>"
        "\r\n");
    (void)PRINTF("Options:\r\n");
    (void)PRINTF("    <0/1>: Disable/enable Tx Pert tracking.\r\n");
    (void)PRINTF("    <STA/UAP>: User needs to indicate which interface this tracking for.\r\n");
    (void)PRINTF("    <p>: Tx Pert check period. Unit is second.\r\n");
    (void)PRINTF(
        "    <r>: Tx Pert ratio threshold (unit 10%). (Fail TX packet)/(Total TX packets). The default value is "
        "5.\r\n");
    (void)PRINTF(
        "    <n>: A watermark of check number (default 5). Fw will start tracking Tx Pert after sending n "
        "packets.\r\n");
    (void)PRINTF("Example:\r\n");
    (void)PRINTF("    wlan-tx-pert 1 AP 5 3 5\r\n");
    (void)PRINTF("Note:\r\n");
    (void)PRINTF("    Please verify by iperf or ping\r\n");
    (void)PRINTF("    When the traffic quality is good enough, it will not be triggered\r\n");
}

static void test_wlan_tx_pert(int argc, char **argv)
{
    struct wlan_tx_pert_info tx_pert;
    mlan_bss_type bss_type = MLAN_BSS_TYPE_STA;

    if (argc < 2)
    {
        dump_wlan_tx_pert_usage();
        (void)PRINTF("Error: invalid number of arguments\r\n");
        return;
    }
    (void)memset(&tx_pert, 0, sizeof(tx_pert));
    tx_pert.tx_pert_check = atoi(argv[1]);
    if (tx_pert.tx_pert_check == 1 && argc < 6)
    {
        (void)PRINTF("Error: invalid number of arguments.\r\n");
        (void)PRINTF(
            "Need specify bss_type tx_pert_chk_prd, tx_perf_chk_ratio and tx_pert_chk_num"
            "\r\n");
        return;
    }
    if (string_equal("STA", argv[2]))
        bss_type = MLAN_BSS_TYPE_STA;
    else if (string_equal("UAP", argv[2]))
        bss_type = MLAN_BSS_TYPE_UAP;
    if (tx_pert.tx_pert_check == 1)
    {
        tx_pert.tx_pert_check_peroid = (t_u8)atoi(argv[3]);
        tx_pert.tx_pert_check_ratio  = (t_u8)atoi(argv[4]);
        tx_pert.tx_pert_check_num    = atoi(argv[5]);
    }
    wlan_set_tx_pert(&tx_pert, bss_type);
}
#endif

#ifdef CONFIG_TX_RX_HISTOGRAM
static void dump_wlan_txrx_histogram_usage()
{
    (void)PRINTF("Usage:\r\n");
    (void)PRINTF("    wlan_txrx_histogram <action> <enable>\r\n");
    (void)PRINTF("        <enable> : 0 - disable TX/RX statistics\r\n");
    (void)PRINTF("                   1 - enable TX/RX statistics\r\n");
    (void)PRINTF("                   2 - get TX/RX statistics\r\n");
    (void)PRINTF("        <action> : 1 - enable/disable/get TX statistics\r\n");
    (void)PRINTF("                   2 - enable/disable/get RX statistics\r\n");
    (void)PRINTF("                   3 - enable/disable/get TX and RX statistics\r\n");
    (void)PRINTF("Note:\r\n");
    (void)PRINTF("    When enable is 0 or 1, the action parameter should not be entered\r\n");
    (void)PRINTF("Example:\r\n");
    (void)PRINTF("    wlan_txrx_histogram 2 3\r\n");
}

static void test_wlan_txrx_histogram(int argc, char **argv)
{
    struct wlan_txrx_histogram_info txrx_histogram;
    t_u8 *buf = NULL;

    tx_pkt_ht_rate_info *tx_ht_info;
    tx_pkt_vht_rate_info *tx_vht_info;
    tx_pkt_he_rate_info *tx_he_info;
    tx_pkt_rate_info *tx_info;
    rx_pkt_ht_rate_info *rx_ht_info;
    rx_pkt_vht_rate_info *rx_vht_info;
    rx_pkt_he_rate_info *rx_he_info;
    rx_pkt_rate_info *rx_info;

    t_u8 *pos             = NULL;
    t_u16 resp_value_size = 0;
    int i                 = 0;
    t_u16 buf_size        = 0;

    if (argc < 2)
    {
        (void)PRINTF("Error: invalid number of arguments\r\n");
        dump_wlan_txrx_histogram_usage();
        return;
    }

    (void)memset(&txrx_histogram, 0, sizeof(txrx_histogram));
    txrx_histogram.enable = atoi(argv[1]);
    if (argc == 2)
    {
        txrx_histogram.action = 0;
    }
    else
    {
        txrx_histogram.action = atoi(argv[2]);
    }

    if ((txrx_histogram.enable > 2) || (txrx_histogram.action > 3))
    {
        (void)PRINTF("Error: invalid arguments.\r\n");
        dump_wlan_txrx_histogram_usage();
        return;
    }
    if ((txrx_histogram.enable == 0 || txrx_histogram.enable == 1) && (txrx_histogram.action != 0))
    {
        (void)PRINTF("Error: invalid arguments.\r\n");
        dump_wlan_txrx_histogram_usage();
        return;
    }

    if (txrx_histogram.enable & GET_TX_RX_HISTOGRAM)
    {
        if (txrx_histogram.action == FLAG_TX_HISTOGRAM)
        {
            buf_size = sizeof(resp_value_size) + sizeof(tx_pkt_ht_rate_info) + sizeof(tx_pkt_vht_rate_info) +
                       sizeof(tx_pkt_he_rate_info) + sizeof(tx_pkt_rate_info);
        }
        else if (txrx_histogram.action == FLAG_RX_HISTOGRAM)
        {
            buf_size = sizeof(resp_value_size) + sizeof(rx_pkt_ht_rate_info) + sizeof(rx_pkt_vht_rate_info) +
                       sizeof(rx_pkt_he_rate_info) + sizeof(rx_pkt_rate_info);
        }
        else if ((txrx_histogram.action & FLAG_TX_HISTOGRAM) && (txrx_histogram.action & FLAG_RX_HISTOGRAM))
        {
            buf_size = sizeof(resp_value_size) + sizeof(tx_pkt_ht_rate_info) + sizeof(tx_pkt_vht_rate_info) +
                       sizeof(tx_pkt_he_rate_info) + sizeof(tx_pkt_rate_info) + sizeof(rx_pkt_ht_rate_info) +
                       sizeof(rx_pkt_vht_rate_info) + sizeof(rx_pkt_he_rate_info) + sizeof(rx_pkt_rate_info);
        }
    }
    if (buf_size > 0)
    {
        buf = os_mem_alloc(buf_size);
        if (!buf)
        {
            PRINTF("test_wlan_txrx_histogram buf allocate memory failed\r\n");
            return;
        }
        (void)memset(buf, 0, sizeof(buf_size));
        (void)memcpy(buf, &buf_size, sizeof(buf_size));
    }

    wlan_set_txrx_histogram(&txrx_histogram, buf);

    /*Make the pos pointer points to the size*/
    pos = (t_u8 *)buf;
    memcpy(&resp_value_size, pos, sizeof(resp_value_size));
    /*Make the pos pointer points to the data replied by fw*/
    pos += sizeof(resp_value_size);

    if (txrx_histogram.enable & GET_TX_RX_HISTOGRAM)
    {
        if (txrx_histogram.action & FLAG_TX_HISTOGRAM)
        {
            PRINTF("The TX histogram statistic:\n");
            PRINTF("============================================\n");
            tx_ht_info = (tx_pkt_ht_rate_info *)pos;
            for (i = 0; i < 16; i++)
            {
                PRINTF("htmcs_txcnt[%d]       = %u\n", i, tx_ht_info->htmcs_txcnt[i]);
                PRINTF("htsgi_txcnt[%d]       = %u\n", i, tx_ht_info->htsgi_txcnt[i]);
                PRINTF("htstbcrate_txcnt[%d]  = %u\n", i, tx_ht_info->htstbcrate_txcnt[i]);
            }
            pos += sizeof(tx_pkt_ht_rate_info);
            tx_vht_info = (tx_pkt_vht_rate_info *)pos;
            for (i = 0; i < 10; i++)
            {
                PRINTF("vhtmcs_txcnt[%d]      = %u\n", i, tx_vht_info->vhtmcs_txcnt[i]);
                PRINTF("vhtsgi_txcnt[%d]      = %u\n", i, tx_vht_info->vhtsgi_txcnt[i]);
                PRINTF("vhtstbcrate_txcnt[%d] = %u\n", i, tx_vht_info->vhtstbcrate_txcnt[i]);
            }
            pos += sizeof(tx_pkt_vht_rate_info);
            if (resp_value_size == (sizeof(tx_pkt_ht_rate_info) + sizeof(tx_pkt_vht_rate_info) +
                                    sizeof(tx_pkt_he_rate_info) + sizeof(tx_pkt_rate_info)) ||
                resp_value_size ==
                    (sizeof(tx_pkt_ht_rate_info) + sizeof(tx_pkt_vht_rate_info) + sizeof(tx_pkt_he_rate_info) +
                     sizeof(tx_pkt_rate_info) + sizeof(rx_pkt_ht_rate_info) + sizeof(rx_pkt_vht_rate_info) +
                     sizeof(rx_pkt_he_rate_info) + sizeof(rx_pkt_rate_info)))
            {
                tx_he_info = (tx_pkt_he_rate_info *)pos;
                for (i = 0; i < 12; i++)
                {
                    PRINTF("hemcs_txcnt[%d]      = %u\n", i, tx_he_info->hemcs_txcnt[i]);
                    PRINTF("hestbcrate_txcnt[%d] = %u\n", i, tx_he_info->hestbcrate_txcnt[i]);
                }
                pos += sizeof(tx_pkt_he_rate_info);
            }
            tx_info = (tx_pkt_rate_info *)pos;
            for (i = 0; i < 2; i++)
                PRINTF("nss_txcnt[%d]         = %u\n", i, tx_info->nss_txcnt[i]);
            for (i = 0; i < 3; i++)
                PRINTF("bandwidth_txcnt[%d]   = %u\n", i, tx_info->bandwidth_txcnt[i]);
            for (i = 0; i < 4; i++)
                PRINTF("preamble_txcnt[%d]    = %u\n", i, tx_info->preamble_txcnt[i]);
            PRINTF("ldpc_txcnt           = %u\n", tx_info->ldpc_txcnt);
            PRINTF("rts_txcnt            = %u\n", tx_info->rts_txcnt);
            PRINTF("ack_RSSI             = %d\n\n", tx_info->ack_RSSI);
            pos += sizeof(tx_pkt_rate_info);
        }
        if (txrx_histogram.action & FLAG_RX_HISTOGRAM)
        {
            PRINTF("The RX histogram statistic:\n");
            PRINTF("============================================\n");
            rx_ht_info = (rx_pkt_ht_rate_info *)pos;
            for (i = 0; i < 16; i++)
            {
                PRINTF("htmcs_rxcnt[%d]       = %u\n", i, rx_ht_info->htmcs_rxcnt[i]);
                PRINTF("htsgi_rxcnt[%d]       = %u\n", i, rx_ht_info->htsgi_rxcnt[i]);
                PRINTF("htstbcrate_rxcnt[%d]  = %u\n", i, rx_ht_info->htstbcrate_rxcnt[i]);
            }
            pos += sizeof(rx_pkt_ht_rate_info);
            rx_vht_info = (rx_pkt_vht_rate_info *)pos;
            for (i = 0; i < 10; i++)
            {
                PRINTF("vhtmcs_rxcnt[%d]      = %u\n", i, rx_vht_info->vhtmcs_rxcnt[i]);
                PRINTF("vhtsgi_rxcnt[%d]      = %u\n", i, rx_vht_info->vhtsgi_rxcnt[i]);
                PRINTF("vhtstbcrate_rxcnt[%d] = %u\n", i, rx_vht_info->vhtstbcrate_rxcnt[i]);
            }
            pos += sizeof(rx_pkt_vht_rate_info);
            if (resp_value_size == (sizeof(rx_pkt_ht_rate_info) + sizeof(rx_pkt_vht_rate_info) +
                                    sizeof(rx_pkt_he_rate_info) + sizeof(rx_pkt_rate_info)) ||
                resp_value_size ==
                    (sizeof(tx_pkt_ht_rate_info) + sizeof(tx_pkt_vht_rate_info) + sizeof(tx_pkt_he_rate_info) +
                     sizeof(tx_pkt_rate_info) + sizeof(rx_pkt_ht_rate_info) + sizeof(rx_pkt_vht_rate_info) +
                     sizeof(rx_pkt_he_rate_info) + sizeof(rx_pkt_rate_info)))
            {
                rx_he_info = (rx_pkt_he_rate_info *)pos;
                for (i = 0; i < 12; i++)
                {
                    PRINTF("hemcs_rxcnt[%d]      = %u\n", i, rx_he_info->hemcs_rxcnt[i]);
                    PRINTF("hestbcrate_rxcnt[%d] = %u\n", i, rx_he_info->hestbcrate_rxcnt[i]);
                }
                pos += sizeof(rx_pkt_he_rate_info);
            }
            rx_info = (rx_pkt_rate_info *)pos;
            for (i = 0; i < 2; i++)
                PRINTF("nss_rxcnt[%d]         = %u\n", i, rx_info->nss_rxcnt[i]);
            PRINTF("nsts_rxcnt           = %u\n", rx_info->nsts_rxcnt);
            for (i = 0; i < 3; i++)
                PRINTF("bandwidth_rxcnt[%d]   = %u\n", i, rx_info->bandwidth_rxcnt[i]);
            for (i = 0; i < 6; i++)
                PRINTF("preamble_rxcnt[%d]    = %u\n", i, rx_info->preamble_rxcnt[i]);
            for (i = 0; i < 2; i++)
                PRINTF("ldpc_txbfcnt[%d]      = %u\n", i, rx_info->ldpc_txbfcnt[i]);
            for (i = 0; i < 2; i++)
                PRINTF("rssi_value[%d]        = %d\n", i, rx_info->rssi_value[i]);
            for (i = 0; i < 4; i++)
                PRINTF("rssi_chain0[%d]       = %d\n", i, rx_info->rssi_chain0[i]);
            for (i = 0; i < 4; i++)
                PRINTF("rssi_chain1[%d]       = %d\n", i, rx_info->rssi_chain1[i]);
            PRINTF("\n");
        }
    }
    else if (txrx_histogram.enable & ENABLE_TX_RX_HISTOGRAM)
        PRINTF("Enable the TX and RX histogram statistic\n");
    else
    {
        PRINTF("Disable the TX and RX histogram statistic\n");
    }
    if (buf)
    {
        os_mem_free(buf);
    }
}
#endif

#ifdef CONFIG_ROAMING
#define DEFAULT_RSSI_THRESHOLD 70
static void dump_wlan_roaming_usage(void)
{
    (void)PRINTF("Usage:\r\n");
    (void)PRINTF(
        "    wlan-roaming <0/1>"
        "\r\n");
    (void)PRINTF("Example:\r\n");
    (void)PRINTF("    wlan-roaming 1\r\n");
}

static void test_wlan_roaming(int argc, char **argv)
{
    int enable = 0;

    if (argc != 2)
    {
        dump_wlan_roaming_usage();
        (void)PRINTF("Error: invalid number of arguments\r\n");
        return;
    }

    errno  = 0;
    enable = (int)strtol(argv[1], NULL, 10);
    if (errno != 0)
    {
        (void)PRINTF("Error during strtol:wlan roaming errno:%d\r\n", errno);
    }
    wlan_set_roaming(enable);
    return;
}
#endif

#ifdef CONFIG_WIFI_MAX_CLIENTS_CNT
static void test_wlan_set_max_clients_count(int argc, char **argv)
{
    int max_clients_count;
    int ret;

    if (argc != 2)
    {
        (void)PRINTF("Usage: %s  max_clients_count\r\n", argv[0]);
        return;
    }

    max_clients_count = atoi(argv[1]);

    ret = wlan_set_uap_max_clients(max_clients_count);

    if (ret != WM_SUCCESS)
    {
        (void)PRINTF("Failed to set max clients count\r\n");
    }
}
#endif

#ifdef CONFIG_WIFI_HIDDEN_SSID
static void test_wlan_set_hidden_ssid(int argc, char **argv)
{
    int bcast_ssid_ctl;

    if (argc != 2)
    {
        (void)PRINTF("Usage: %s hidden ssid control\r\n", argv[0]);
        return;
    }

    bcast_ssid_ctl = atoi(argv[1]);

    wlan_uap_set_hidden_ssid(bcast_ssid_ctl);
}
#endif

#ifdef CONFIG_WIFI_RTS_THRESHOLD
static void test_wlan_set_rts(int argc, char **argv)
{
    int rthr;
    int ret;
    mlan_bss_type bss_type = MLAN_BSS_TYPE_STA;

    if (argc != 3)
    {
        (void)PRINTF("Usage: %s <sta/uap> <rts threshold>\r\n", argv[0]);
        return;
    }
    if (string_equal("sta", argv[1]))
        bss_type = MLAN_BSS_TYPE_STA;
    else if (string_equal("uap", argv[1]))
        bss_type = MLAN_BSS_TYPE_UAP;
    else
    {
        (void)PRINTF("Usage: %s <sta/uap> <rts threshold>\r\n", argv[0]);
        return;
    }

    rthr = atoi(argv[2]);

    if (bss_type == MLAN_BSS_TYPE_STA)
        ret = wlan_set_rts(rthr);
    else
        ret = wlan_set_uap_rts(rthr);

    if (ret != WM_SUCCESS)
    {
        (void)PRINTF("Failed to set rts threshold\r\n");
    }
}
#endif

#ifdef CONFIG_WIFI_FRAG_THRESHOLD
static void test_wlan_set_frag(int argc, char **argv)
{
    int frag;
    int ret;
    mlan_bss_type bss_type = MLAN_BSS_TYPE_STA;

    if (argc != 3)
    {
        (void)PRINTF("Usage: %s <sta/uap> <fragment threshold>\r\n", argv[0]);
        return;
    }

    if (string_equal("sta", argv[1]))
        bss_type = MLAN_BSS_TYPE_STA;
    else if (string_equal("uap", argv[1]))
        bss_type = MLAN_BSS_TYPE_UAP;
    else
    {
        (void)PRINTF("Usage: %s <sta/uap> <fragment threshold>\r\n", argv[0]);
        return;
    }

    frag = atoi(argv[2]);

    if (bss_type == MLAN_BSS_TYPE_STA)
        ret = wlan_set_frag(frag);
    else
        ret = wlan_set_uap_frag(frag);

    if (ret != WM_SUCCESS)
    {
        (void)PRINTF("Failed to set fragment threshold\r\n");
    }
}
#endif

#ifdef CONFIG_11K_OFFLOAD
static void test_wlan_11k_cfg(int argc, char **argv)
{
    int enable_11k;
    int ret;

    if (argc != 2)
    {
        (void)PRINTF("Usage: %s <0/1> < 0--disable 11k; 1---enable 11k>\r\n", argv[0]);
        return;
    }

    errno      = 0;
    enable_11k = (int)strtol(argv[1], NULL, 10);
    if (errno != 0)
    {
        (void)PRINTF("Error during strtol:wlan_11k errno:%d\r\n", errno);
    }

    ret = wlan_11k_cfg(enable_11k);

    if (ret != WM_SUCCESS)
    {
        (void)PRINTF("Failed to 11k config\r\n");
    }
}

static void test_wlan_11k_neighbor_req(int argc, char **argv)
{
    int ret;

    ret = wlan_11k_neighbor_req();

    if (ret != WM_SUCCESS)
    {
        (void)PRINTF("Failed to send 11k neighbor req\r\n");
    }
}

#endif

#ifdef CONFIG_11K
static void test_wlan_host_11k_cfg(int argc, char **argv)
{
    int enable_11k;
    int ret;

    if (argc != 2)
    {
        (void)PRINTF("Usage: %s <0/1> < 0--disable host 11k; 1---enable host 11k>\r\n", argv[0]);
        return;
    }

    errno      = 0;
    enable_11k = (int)strtol(argv[1], NULL, 10);
    if (errno != 0)
    {
        (void)PRINTF("Error during strtol:wlan_host_11k errno:%d\r\n", errno);
    }

    ret = wlan_host_11k_cfg(enable_11k);

    if (ret == -WM_E_PERM)
    {
        (void)PRINTF("Please disable fw base 11k.(wlan-host-11k-enable 0)\r\n");
    }
    else if (ret != WM_SUCCESS)
    {
        (void)PRINTF("Failed to set 11k config\r\n");
    }
    else
    {
        /* Do nothing */
    }
}

static void test_wlan_host_11k_neighbor_request(int argc, char **argv)
{
    int ret;
    t_u8 ssid[IEEEtypes_SSID_SIZE + 1] = {0};

    if ((argc != 1 && argc != 3) || (argc == 3 && !string_equal("ssid", argv[1])))
    {
        (void)PRINTF("Usage: %s\r\n", argv[0]);
        (void)PRINTF("or     %s ssid <ssid>\r\n", argv[0]);
        return;
    }

    if (argc == 3)
    {
        if (strlen(argv[2]) > IEEEtypes_SSID_SIZE)
        {
            (void)PRINTF("Error: ssid too long\r\n");
            return;
        }
        else
        {
            (void)memcpy((void *)ssid, (const void *)argv[2], (size_t)strlen(argv[2]));
        }
    }

    ret = wlan_host_11k_neighbor_req(ssid);
    if (ret != WM_SUCCESS)
    {
        (void)PRINTF("Error: send neighbor report request fail\r\n");
        return;
    }
}
#endif

#ifdef CONFIG_11V
static void test_wlan_host_11v_bss_trans_query(int argc, char **argv)
{
    int ret;
    int query_reason;

    if (argc != 2)
    {
        (void)PRINTF("Usage: %s <query_reason[0..16]>\r\n", argv[0]);
        return;
    }

    errno        = 0;
    query_reason = (int)strtol(argv[1], NULL, 10);
    if (errno != 0)
    {
        (void)PRINTF("Error during strtol:wlan_host_11v_bss_trans_query errno:%d\r\n", errno);
    }

    if (query_reason < 0 || query_reason > 16)
    {
        (void)PRINTF("Usage: %s <query_reason[0..16]>\r\n", argv[0]);
        return;
    }

    ret = wlan_host_11v_bss_trans_query((t_u8)query_reason);
    if (ret != WM_SUCCESS)
    {
        (void)PRINTF("Error: send bss transition query failed\r\n");
        return;
    }
}
#endif

#ifdef CONFIG_MBO
static void test_wlan_mbo_cfg(int argc, char **argv)
{
    int enable_mbo;
    int ret;

    if (argc != 2)
    {
        (void)PRINTF("Usage: %s <0/1> < 0--disable MBO; 1---enable MBO>\r\n", argv[0]);
        return;
    }

    errno      = 0;
    enable_mbo = (int)strtol(argv[1], NULL, 10);
    if (errno != 0)
    {
        (void)PRINTF("Error during strtol:wlan mbo cfg:%d\r\n", errno);
    }

    ret = wlan_host_mbo_cfg(enable_mbo);

    if (ret == -WM_E_PERM)
    {
        (void)PRINTF("Please disable MBO.(wlan-mbo-enable 0)\r\n");
    }
    else if (ret != WM_SUCCESS)
    {
        (void)PRINTF("Failed to config MBO\r\n");
    }
    else
    {
        /* Do nothing */
    }
}

static void test_wlan_mbo_non_prefer_chs(int argc, char **argv)
{
    int ret;
    uint8_t ch0, ch1, preference0, preference1;

    if (argc != 5)
    {
        (void)PRINTF(
            "Usage: %s <ch0> <Preference0: 0/1/255> <ch1> <Preference1: 0/1/255> < 0--non-operable; 1--prefers not to "
            "operate; 255--prefers to operate>\r\n",
            argv[0]);
        return;
    }

    errno = 0;
    ch0   = (uint8_t)strtol(argv[1], NULL, 10);
    if (errno != 0)
    {
        (void)PRINTF("Error during strtol:wlan mbo non prefer chs:%d\r\n", errno);
    }

    errno       = 0;
    preference0 = (uint8_t)strtol(argv[2], NULL, 10);
    if (errno != 0)
    {
        (void)PRINTF("Error during strtol:wlan mbo non prefer chs:%d\r\n", errno);
    }

    errno = 0;
    ch1   = (uint8_t)strtol(argv[3], NULL, 10);
    if (errno != 0)
    {
        (void)PRINTF("Error during strtol:wlan mbo non prefer chs:%d\r\n", errno);
    }

    errno       = 0;
    preference1 = (uint8_t)strtol(argv[4], NULL, 10);
    if (errno != 0)
    {
        (void)PRINTF("Error during strtol:wlan mbo non prefer chs:%d\r\n", errno);
    }

    ret = wlan_mbo_peferch_cfg(ch0, preference0, ch1, preference1);

    if (ret == -WM_E_PERM)
    {
        (void)PRINTF("Please add pefer or non-pefer channels.\r\n");
    }
    else if (ret != WM_SUCCESS)
    {
        (void)PRINTF("Failed to add pefer or non-pefer channels.\r\n");
    }
    else
    {
        /* Do nothing */
    }
}

#endif

#ifdef CONFIG_UAP_STA_MAC_ADDR_FILTER
/**
 *  @brief Show usage information for the sta_filter_table command
 *
 *  $return         N/A
 */
static void print_sta_filter_table_usage(void)
{
    (void)PRINTF("\r\nUsage : sta_filter_table <FILTERMODE> <MACADDRESS_LIST>\r\n");
    (void)PRINTF("\r\nOptions: FILTERMODE : 0 - Disable filter table");
    (void)PRINTF("\r\n                      1 - allow MAC addresses specified in the allowed list");
    (void)PRINTF("\r\n                      2 - block MAC addresses specified in the banned list");
    (void)PRINTF("\r\n         MACADDRESS_LIST is the list of MAC addresses to be acted upon. Each");
    (void)PRINTF("\r\n                      MAC address must be separated with a space. Maximum of");
    (void)PRINTF("\r\n                      16 MAC addresses are supported.\r\n");
    return;
}

static void test_wlan_set_sta_filter(int argc, char **argv)
{
    int i           = 0;
    int ret         = WM_SUCCESS;
    int filter_mode = 0;
    int mac_count   = 0;
    unsigned char mac_addr[WLAN_MAX_STA_FILTER_NUM * WLAN_MAC_ADDR_LENGTH];

    if (argc < 2 || argc > (WLAN_MAX_STA_FILTER_NUM + 2))
    {
        (void)PRINTF("ERR:Too many or too few farguments.\r\n");
        print_sta_filter_table_usage();
        return;
    }

    argc--;
    argv++;

    if (((atoi(argv[0]) < 0) || (atoi(argv[0]) > 2)))
    {
        (void)PRINTF("ERR:Illegal FILTERMODE parameter %s. Must be either '0', '1', or '2'.\r\n", argv[1]);
        print_sta_filter_table_usage();
        return;
    }

    filter_mode = atoi(argv[0]);

    mac_count = argc - 1;

    if (mac_count)
    {
        for (i = 0; i < mac_count; i++)
        {
            ret = get_mac(argv[i + 1], (char *)&mac_addr[i * WLAN_MAC_ADDR_LENGTH], ':');
            if (ret != 0)
            {
                (void)PRINTF("Error: invalid MAC argument\r\n");
                return;
            }
        }
    }
    else
    {
        memset(mac_addr, 0, 16 * WLAN_MAC_ADDR_LENGTH);
    }

    wlan_set_sta_mac_filter(filter_mode, mac_count, mac_addr);

    return;
}
#endif

#ifdef CONFIG_WIFI_GET_LOG
static void test_wlan_get_log(int argc, char **argv)
{
    wlan_pkt_stats_t stats;
    int ret, i;

    if (argc < 2)
    {
        (void)PRINTF("Usage: %s <sta/uap> <ext>\r\n", argv[0]);
        return;
    }

    if (string_equal("sta", argv[1]))
        ret = wlan_get_log(&stats);
    else if (string_equal("uap", argv[1]))
        ret = wlan_uap_get_log(&stats);
    else
    {
        (void)PRINTF("Usage: %s <sta/uap> <ext>\r\n", argv[0]);
        return;
    }

    if (ret != WM_SUCCESS)
    {
        (void)PRINTF("Failed to get log\r\n");
    }
    else
    {
        (void)PRINTF(
            "dot11GroupTransmittedFrameCount    %u\r\n"
            "dot11FailedCount                   %u\r\n"
            "dot11RetryCount                    %u\r\n"
            "dot11MultipleRetryCount            %u\r\n"
            "dot11FrameDuplicateCount           %u\r\n"
            "dot11RTSSuccessCount               %u\r\n"
            "dot11RTSFailureCount               %u\r\n"
            "dot11ACKFailureCount               %u\r\n"
            "dot11ReceivedFragmentCount         %u\r\n"
            "dot11GroupReceivedFrameCount       %u\r\n"
            "dot11FCSErrorCount                 %u\r\n"
            "dot11TransmittedFrameCount         %u\r\n"
            "wepicverrcnt-1                     %u\r\n"
            "wepicverrcnt-2                     %u\r\n"
            "wepicverrcnt-3                     %u\r\n"
            "wepicverrcnt-4                     %u\r\n"
            "beaconReceivedCount                %u\r\n"
            "beaconMissedCount                  %u\r\n",
            stats.mcast_tx_frame, stats.failed, stats.retry, stats.multi_retry, stats.frame_dup, stats.rts_success,
            stats.rts_failure, stats.ack_failure, stats.rx_frag, stats.mcast_rx_frame, stats.fcs_error, stats.tx_frame,
            stats.wep_icv_error[0], stats.wep_icv_error[1], stats.wep_icv_error[2], stats.wep_icv_error[3],
            stats.bcn_rcv_cnt, stats.bcn_miss_cnt);

        if (argc == 3 && !(strcmp(argv[2], "ext")))
        {
            (void)PRINTF(
                "rxStuckIssueCount-1                %u\r\n"
                "rxStuckIssueCount-2                %u\r\n"
                "rxStuckRecoveryCount               %u\r\n"
                "rxStuckTsf-1                       %llu\r\n"
                "rxStuckTsf-2                       %llu\r\n"
                "txWatchdogRecoveryCount            %u\r\n"
                "txWatchdogTsf-1                    %llu\r\n"
                "txWatchdogTsf-2                    %llu\r\n"
                "channelSwitchAnnouncementSent      %u\r\n"
                "channelSwitchState                 %u\r\n"
                "registerClass                      %u\r\n"
                "channelNumber                      %u\r\n"
                "channelSwitchMode                  %u\r\n"
                "RxResetRecoveryCount               %u\r\n"
                "RxIsr2NotDoneCnt                   %u\r\n"
                "gdmaAbortCnt                       %u\r\n"
                "gResetRxMacCnt                     %u\r\n"
                "gOwnrshpCtlErrCnt                  %u\r\n"
                "gOwnrshpBcnErrCnt                  %u\r\n"
                "gOwnrshpMgtErrCnt                  %u\r\n"
                "gOwnrshpDatErrCnt                  %u\r\n"
                "bigtk_mmeGoodCnt                   %u\r\n"
                "bigtk_replayErrCnt                 %u\r\n"
                "bigtk_micErrCnt                    %u\r\n"
                "bigtk_mmeNotFoundCnt               %u\r\n",
                stats.rx_stuck_issue_cnt[0], stats.rx_stuck_issue_cnt[1], stats.rx_stuck_recovery_cnt,
                stats.rx_stuck_tsf[0], stats.rx_stuck_tsf[1], stats.tx_watchdog_recovery_cnt, stats.tx_watchdog_tsf[0],
                stats.tx_watchdog_tsf[1], stats.channel_switch_ann_sent, stats.channel_switch_state, stats.reg_class,
                stats.channel_number, stats.channel_switch_mode, stats.rx_reset_mac_recovery_cnt,
                stats.rx_Isr2_NotDone_Cnt, stats.gdma_abort_cnt, stats.g_reset_rx_mac_cnt, stats.dwCtlErrCnt,
                stats.dwBcnErrCnt, stats.dwMgtErrCnt, stats.dwDatErrCnt, stats.bigtk_mmeGoodCnt,
                stats.bigtk_replayErrCnt, stats.bigtk_micErrCnt, stats.bigtk_mmeNotFoundCnt);
        }

        (void)PRINTF("dot11TransmittedFragmentCount      %u\r\n", stats.tx_frag_cnt);
        (void)PRINTF("dot11QosTransmittedFragmentCount   ");
        for (i = 0; i < 8; i++)
        {
            (void)PRINTF("%u ", stats.qos_tx_frag_cnt[i]);
        }
        (void)PRINTF("\r\ndot11QosFailedCount                ");
        for (i = 0; i < 8; i++)
        {
            (void)PRINTF("%u ", stats.qos_failed_cnt[i]);
        }
        (void)PRINTF("\r\ndot11QosRetryCount                 ");
        for (i = 0; i < 8; i++)
        {
            (void)PRINTF("%u ", stats.qos_retry_cnt[i]);
        }
        (void)PRINTF("\r\ndot11QosMultipleRetryCount         ");
        for (i = 0; i < 8; i++)
        {
            (void)PRINTF("%u ", stats.qos_multi_retry_cnt[i]);
        }
        (void)PRINTF("\r\ndot11QosFrameDuplicateCount        ");
        for (i = 0; i < 8; i++)
        {
            (void)PRINTF("%u ", stats.qos_frm_dup_cnt[i]);
        }
        (void)PRINTF("\r\ndot11QosRTSSuccessCount            ");
        for (i = 0; i < 8; i++)
        {
            (void)PRINTF("%u ", stats.qos_rts_suc_cnt[i]);
        }
        (void)PRINTF("\r\ndot11QosRTSFailureCount            ");
        for (i = 0; i < 8; i++)
        {
            (void)PRINTF("%u ", stats.qos_rts_failure_cnt[i]);
        }
        (void)PRINTF("\r\ndot11QosACKFailureCount            ");
        for (i = 0; i < 8; i++)
        {
            (void)PRINTF("%u ", stats.qos_ack_failure_cnt[i]);
        }
        (void)PRINTF("\r\ndot11QosReceivedFragmentCount      ");
        for (i = 0; i < 8; i++)
        {
            (void)PRINTF("%u ", stats.qos_rx_frag_cnt[i]);
        }
        (void)PRINTF("\r\ndot11QosTransmittedFrameCount      ");
        for (i = 0; i < 8; i++)
        {
            (void)PRINTF("%u ", stats.qos_tx_frm_cnt[i]);
        }
        (void)PRINTF("\r\ndot11QosDiscardedFrameCount        ");
        for (i = 0; i < 8; i++)
        {
            (void)PRINTF("%u ", stats.qos_discarded_frm_cnt[i]);
        }
        (void)PRINTF("\r\ndot11QosMPDUsReceivedCount         ");
        for (i = 0; i < 8; i++)
        {
            (void)PRINTF("%u ", stats.qos_mpdus_rx_cnt[i]);
        }
        (void)PRINTF("\r\ndot11QosRetriesReceivedCount       ");
        for (i = 0; i < 8; i++)
        {
            (void)PRINTF("%u ", stats.qos_retries_rx_cnt[i]);
        }
        (void)PRINTF(
            "\r\ndot11RSNAStatsCMACICVErrors          %u\r\n"
            "dot11RSNAStatsCMACReplays            %u\r\n"
            "dot11RSNAStatsRobustMgmtCCMPReplays  %u\r\n"
            "dot11RSNAStatsTKIPICVErrors          %u\r\n"
            "dot11RSNAStatsTKIPReplays            %u\r\n"
            "dot11RSNAStatsCCMPDecryptErrors      %u\r\n"
            "dot11RSNAstatsCCMPReplays            %u\r\n"
            "dot11TransmittedAMSDUCount           %u\r\n"
            "dot11FailedAMSDUCount                %u\r\n"
            "dot11RetryAMSDUCount                 %u\r\n"
            "dot11MultipleRetryAMSDUCount         %u\r\n"
            "dot11TransmittedOctetsInAMSDUCount   %llu\r\n"
            "dot11AMSDUAckFailureCount            %u\r\n"
            "dot11ReceivedAMSDUCount              %u\r\n"
            "dot11ReceivedOctetsInAMSDUCount      %llu\r\n"
            "dot11TransmittedAMPDUCount           %u\r\n"
            "dot11TransmittedMPDUsInAMPDUCount    %u\r\n"
            "dot11TransmittedOctetsInAMPDUCount   %llu\r\n"
            "dot11AMPDUReceivedCount              %u\r\n"
            "dot11MPDUInReceivedAMPDUCount        %u\r\n"
            "dot11ReceivedOctetsInAMPDUCount      %llu\r\n"
            "dot11AMPDUDelimiterCRCErrorCount     %u\r\n",
            stats.cmacicv_errors, stats.cmac_replays, stats.mgmt_ccmp_replays, stats.tkipicv_errors, stats.tkip_replays,
            stats.ccmp_decrypt_errors, stats.ccmp_replays, stats.tx_amsdu_cnt, stats.failed_amsdu_cnt,
            stats.retry_amsdu_cnt, stats.multi_retry_amsdu_cnt, stats.tx_octets_in_amsdu_cnt,
            stats.amsdu_ack_failure_cnt, stats.rx_amsdu_cnt, stats.rx_octets_in_amsdu_cnt, stats.tx_ampdu_cnt,
            stats.tx_mpdus_in_ampdu_cnt, stats.tx_octets_in_ampdu_cnt, stats.ampdu_rx_cnt, stats.mpdu_in_rx_ampdu_cnt,
            stats.rx_octets_in_ampdu_cnt, stats.ampdu_delimiter_crc_error_cnt);
    }
}
#endif

#ifdef CONFIG_MEF_CFG
extern wlan_flt_cfg_t g_flt_cfg;
#endif
static void test_wlan_host_sleep(int argc, char **argv)
{
    int choice = -1, wowlan = 0;
    int ret = -WM_FAIL;

    if (argc < 2)
    {
        goto done;
    }

    errno  = 0;
    choice = (int)strtol(argv[1], NULL, 10);
    if (errno != 0)
    {
        (void)PRINTF("Error during strtoul:host_sleep errno:%d\r\n", errno);
    }

    if (choice == 0)
    {
        ret = wlan_send_host_sleep(HOST_SLEEP_CFG_CANCEL);
        if (ret == WM_SUCCESS)
        {
            (void)PRINTF("Cancel Previous configured Host sleep configuration");
        }
        else
        {
            (void)PRINTF("Failed to Cancel Previous configured Host sleep configuration, error: %d", ret);
        }
    }
    else if (choice == 1)
    {
#ifdef CONFIG_MEF_CFG
        if (argc < 3)
#else
        if (argc < 4)
#endif
        {
            goto done;
        }

        if (string_equal(argv[2], "wowlan"))
        {
            errno  = 0;
            wowlan = (int)strtol(argv[3], NULL, 10);
            if (errno != 0)
            {
                (void)PRINTF("Error during strtoul:wowlan errno:%d\r\n", errno);
            }
            if (wowlan == 0)
            {
                ret = wlan_send_host_sleep(HOST_SLEEP_DEF_COND);
                if (ret == WM_SUCCESS)
                {
                    (void)PRINTF("Host sleep configuration successs with regular condition");
                }
                else
                {
                    (void)PRINTF("Failed to host sleep configuration, error: %d", ret);
                }
            }
            else
            {
                ret = wlan_send_host_sleep(wowlan);
                if (ret == WM_SUCCESS)
                {
                    (void)PRINTF("Host sleep configuration successs with regular condition");
                }
                else
                {
                    (void)PRINTF("Failed to host sleep configuration, error: %d", ret);
                }
            }
        }
#ifdef CONFIG_MEF_CFG
        else if (string_equal(argv[2], "mef"))
        {
            if (g_flt_cfg.nentries == 0)
            {
                /* User doesn't configure MEF, use default MEF entry */
                wlan_mef_set_auto_arp(MEF_ACTION_ALLOW_AND_WAKEUP_HOST);
            }
            wifi_set_packet_filters(&g_flt_cfg);
            ret = wlan_send_host_sleep(HOST_SLEEP_NO_COND);
            if (ret == WM_SUCCESS)
            {
                (void)PRINTF("Host sleep configuration successs with MEF");
            }
            else
            {
                (void)PRINTF("Failed to host sleep configuration, error: %d", ret);
            }
        }
#endif
    }
    else
    {
    done:
        (void)PRINTF("Error: invalid number of arguments\r\n");
        (void)PRINTF("Usage:\r\n");
        (void)PRINTF("    wlan-host-sleep <1/0> [wowlan <val>/mef]\r\n");
        (void)PRINTF("    [val] -- value for host wakeup conditions only\r\n");
        (void)PRINTF("	       bit 0: WAKE_ON_ALL_BROADCAST\r\n");
        (void)PRINTF("	       bit 1: WAKE_ON_UNICAST\r\n");
        (void)PRINTF("	       bit 2: WAKE_ON_MAC_EVENT\r\n");
        (void)PRINTF("	       bit 3: WAKE_ON_MULTICAST\r\n");
        (void)PRINTF("	       bit 4: WAKE_ON_ARP_BROADCAST\r\n");
        (void)PRINTF("	       bit 6: WAKE_ON_MGMT_FRAME\r\n");
        (void)PRINTF("	       All bit 0 discard and not wakeup host\r\n");
#ifdef CONFIG_MEF_CFG
        (void)PRINTF("    mef     -- MEF host wakeup\r\n");
        (void)PRINTF("Example:\r\n");
        (void)PRINTF("    wlan-host-sleep mef\r\n");

#endif
        (void)PRINTF("    wlan-host-sleep <1/0> wowlan 0x1e\r\n");
        return;
    }
}

#ifdef CONFIG_MEF_CFG
static void dump_multiple_mef_config_usage()
{
    (void)PRINTF("Usage:\r\n");
    (void)PRINTF("    wlan-multi-mef <ping/arp/multicast/del> [<action>]\r\n");
    (void)PRINTF("        ping/arp/multicast\r\n");
    (void)PRINTF("                 -- MEF entry type, will add one mef entry at a time\r\n");
    (void)PRINTF("        del      -- Delete all previous MEF entries\r\n");
    (void)PRINTF("        action   -- 0--discard and not wake host\r\n");
    (void)PRINTF("                    1--discard and wake host\r\n");
    (void)PRINTF("                    3--allow and wake host\r\n");
    (void)PRINTF("Example:\r\n");
    (void)PRINTF("    wlan-multi-mef ping 3\r\n");
    (void)PRINTF("    wlan-multi-mef del\r\n");
}

static void test_wlan_set_multiple_mef_config(int argc, char **argv)
{
    int type        = MEF_TYPE_END;
    t_u8 mef_action = 0;
    if (argc < 2)
    {
        dump_multiple_mef_config_usage();
        (void)PRINTF("Error: invalid number of arguments\r\n");
        return;
    }
    /* Delete previous MEF configure */
    if (argc == 2)
    {
        if (string_equal("del", argv[1]))
            type = MEF_TYPE_DELETE;
        else
        {
            dump_multiple_mef_config_usage();
            (void)PRINTF("Error: invalid mef type\r\n");
            return;
        }
    }
    /* Add MEF entry */
    else if (argc >= 3)
    {
        if (string_equal("ping", argv[1]))
        {
            type       = MEF_TYPE_PING;
            mef_action = (t_u8)atoi(argv[2]);
        }
        else if (string_equal("arp", argv[1]))
        {
            type       = MEF_TYPE_ARP;
            mef_action = (t_u8)atoi(argv[2]);
        }
        else if (string_equal("multicast", argv[1]))
        {
            type       = MEF_TYPE_MULTICAST;
            mef_action = (t_u8)atoi(argv[2]);
        }
        else
        {
            (void)PRINTF("Error: invalid mef type\r\n");
            return;
        }
    }
    wlan_config_mef(type, mef_action);
}
#endif

#define HOSTCMD_RESP_BUFF_SIZE 1024
static u8_t host_cmd_resp_buf[HOSTCMD_RESP_BUFF_SIZE] = {0};
/* Command taken from Robust_btc.conf*/
static u8_t host_cmd_buf[] = {0xe0, 0,    0x18, 0, 0x29, 0, 0,    0, 0x01, 0,    0, 0,
                              0x38, 0x02, 0x08, 0, 0x05, 0, 0x01, 0, 0x02, 0x01, 0, 0x01};

static void test_wlan_send_hostcmd(int argc, char **argv)
{
    int ret           = -WM_FAIL;
    uint32_t reqd_len = 0;
    uint32_t len;

    ret = wlan_send_hostcmd(host_cmd_buf, sizeof(host_cmd_buf) / sizeof(u8_t), host_cmd_resp_buf,
                            HOSTCMD_RESP_BUFF_SIZE, &reqd_len);

    if (ret == WM_SUCCESS)
    {
        (void)PRINTF("Hostcmd success, response is");
        for (len = 0; len < reqd_len; len++)
        {
            (void)PRINTF("%x\t", host_cmd_resp_buf[len]);
        }
    }
    else
    {
        (void)PRINTF("Hostcmd failed error: %d", ret);
    }
}

#ifdef SD8801
static void test_wlan_8801_enable_ext_coex(int argc, char **argv)
{
    int ret = -WM_FAIL;
    wlan_ext_coex_config_t ext_coex_config;

    ext_coex_config.Enabled                        = 1;
    ext_coex_config.IgnorePriority                 = 0;
    ext_coex_config.DefaultPriority                = 0;
    ext_coex_config.EXT_RADIO_REQ_ip_gpio_num      = 3;
    ext_coex_config.EXT_RADIO_REQ_ip_gpio_polarity = 1;
    ext_coex_config.EXT_RADIO_PRI_ip_gpio_num      = 2;
    ext_coex_config.EXT_RADIO_PRI_ip_gpio_polarity = 1;
    ext_coex_config.WLAN_GRANT_op_gpio_num         = 1;
    ext_coex_config.WLAN_GRANT_op_gpio_polarity    = 0;
    ext_coex_config.reserved_1                     = 0x28;
    ext_coex_config.reserved_2                     = 0x3c;

    ret = wlan_set_ext_coex_config(ext_coex_config);

    if (ret == WM_SUCCESS)
    {
        (void)PRINTF("8801 External Coex Config set successfully");
    }
    else
    {
        (void)PRINTF("8801 External Coex Config error: %d", ret);
    }
}

static void test_wlan_8801_ext_coex_stats(int argc, char **argv)
{
    int ret = -WM_FAIL;
    wlan_ext_coex_stats_t ext_coex_stats;

    ret = wlan_get_ext_coex_stats(&ext_coex_stats);

    if (ret != WM_SUCCESS)
    {
        (void)PRINTF("Unable to get external Coex statistics\r\n");
    }
    else
    {
        (void)PRINTF("BLE_EIP: %d, BLE_PRI: %d, WLAN_EIP: %d\r\n", ext_coex_stats.ext_radio_req_count,
                     ext_coex_stats.ext_radio_pri_count, ext_coex_stats.wlan_grant_count);
    }
}
#endif

#if !defined(SD8801)
static void test_wlan_set_uap_bandwidth(int argc, char **argv)
{
    uint8_t bandwidth;
    int ret = -WM_FAIL;

    if (argc < 2)
    {
#ifdef CONFIG_11AC
        (void)PRINTF("Usage: %s <1/2/3>\r\n", argv[0]);
        (void)PRINTF("Error: Specify 1 to set bandwidth 20MHz or 2 for 40MHz or 3 for 80MHz\r\n");
#else
        (void)PRINTF("Usage: %s <1/2>\r\n", argv[0]);
        (void)PRINTF("Error: Specify 1 to set bandwidth 20MHz or 2 for 40MHz\r\n");
#endif
        return;
    }

    errno     = 0;
    bandwidth = (uint8_t)strtol(argv[1], NULL, 10);
    if (errno != 0)
    {
        (void)PRINTF("Error during strtoul:uap_bandwidth errno:%d\r\n", errno);
    }

    ret = wlan_uap_set_bandwidth(bandwidth);

    if (ret != WM_SUCCESS)
    {
#ifdef CONFIG_11AC
        (void)PRINTF("Usage: %s <1/2/3>\r\n", argv[0]);
        (void)PRINTF("Error: Specify 1 to set bandwidth 20MHz or 2 for 40MHz or 3 for 80MHz\r\n");
#else
        (void)PRINTF("Usage: %s <1/2>\r\n", argv[0]);
        (void)PRINTF("Error: Specify 1 to set bandwidth 20MHz or 2 for 40MHz\r\n");
#endif
    }
    else
    {
        (void)PRINTF("bandwidth set successfully\r\n");
    }
}
#endif

#ifdef CONFIG_WIFI_MEM_ACCESS
static void dump_wlan_mem_access_usage(void)
{
    (void)PRINTF("Usage:\r\n");
    (void)PRINTF("Get value of memory:\r\n");
    (void)PRINTF("    wlan-mem-access <memeory_address>\r\n");
    (void)PRINTF("Set value of memory:\r\n");
    (void)PRINTF("    wlan-mem-access <memeory_address> <value>\r\n");
    (void)PRINTF("The format of memory address and value:\r\n");
    (void)PRINTF(
        "    Hexadecimal value. For example:\r\n"
        "        0x00001200\r\n"
        "        0X00001200\r\n"
        "        0x1200\r\n"
        "        0X1200\r\n");
}

static void test_wlan_mem_access(int argc, char **argv)
{
    int ret;
    t_u16 action  = 0;
    t_u32 address = 0;
    t_u32 value   = 0;
    if (argc < 2 || argc > 3)
    {
        dump_wlan_mem_access_usage();
        (void)PRINTF("Error: invalid number of arguments\r\n");
        return;
    }
    else if (argc == 2)
        action = ACTION_GET;
    else
    {
        action = ACTION_SET;
        if (argv[2][0] == '0' && (argv[2][1] == 'x' || argv[2][1] == 'X'))
            value = a2hex_or_atoi(argv[2]);
        else
        {
            dump_wlan_mem_access_usage();
            (void)PRINTF("Error: invalid value argument\r\n");
            return;
        }
    }
    if (argv[1][0] == '0' && (argv[1][1] == 'x' || argv[1][1] == 'X'))
        address = a2hex_or_atoi(argv[1]);
    else
    {
        dump_wlan_mem_access_usage();
        (void)PRINTF("Error: invalid address argument\r\n");
        return;
    }

    ret = wlan_mem_access(action, address, &value);

    if (ret == WM_SUCCESS)
    {
        if (action == ACTION_GET)
            (void)PRINTF("At Memory 0x%x: 0x%x\r\n", address, value);
        else
            (void)PRINTF("Set the Memory successfully\r\n");
    }
    else
        wlcm_e("Read/write Mem failed");
}
#endif

#ifdef CONFIG_11R
static void dump_wlan_ft_roam_usage(void)
{
    (void)PRINTF("Usage:\r\n");
    (void)PRINTF("Roam to new AP using FT:\r\n");
    (void)PRINTF("    wlan-ft-roam <bssid> <channel>\r\n");
}

static void test_wlan_ft_roam(int argc, char **argv)
{
    int ret;
    t_u8 bssid[IEEEtypes_ADDRESS_SIZE] = {0};
    t_u8 channel                       = 0;
    if (argc != 3)
    {
        dump_wlan_ft_roam_usage();
        (void)PRINTF("Error: invalid number of arguments\r\n");
        return;
    }

    if (get_mac(argv[1], (char *)bssid, ':') != false)
    {
        (void)PRINTF(
            "Error: invalid BSSID argument"
            "\r\n");
        dump_wlan_ft_roam_usage();
        return;
    }

    errno   = 0;
    channel = (t_u8)strtol(argv[2], NULL, 10);
    if (errno != 0)
    {
        (void)PRINTF("Error during strtol:channel errno:%d\r\n", errno);
        dump_wlan_ft_roam_usage();
        return;
    }

    ret = wlan_ft_roam(bssid, channel);
    if (ret == WM_SUCCESS)
    {
        (void)PRINTF("Started FT roaming\r\n");
    }
    else
    {
        (void)PRINTF("Failed to start FT roaming\r\n");
    }
}
#endif

#ifdef CONFIG_HEAP_STAT
static void test_heap_stat(int argc, char **argv)
{
    os_dump_mem_stats();
}
#endif

#ifdef CONFIG_EU_VALIDATION
static void dump_wlan_eu_validation(void)
{
    (void)PRINTF("Usage:\r\n");
    (void)PRINTF("wlan-eu-validation <value>\r\n");
    (void)PRINTF("Values to choose:\r\n");
    (void)PRINTF("     0x05   GCMP_128_ENC\r\n");
    (void)PRINTF("     0x06   GCMP_128_DEC\r\n");
    (void)PRINTF("     0x07   GCMP_256_ENC\r\n");
    (void)PRINTF("     0x08   GCMP_256_DEC\r\n");
    (void)PRINTF("     0x09   DUMMY_PAYLOAD\r\n");
    (void)PRINTF("     0x0a   CRYPTO\r\n");
    (void)PRINTF("     0x0b   CRYPTO_LARGE_PAYLOAD\r\n");
    (void)PRINTF("     0x0c   CRYPTO_CCMP_128_ENC\r\n");
    (void)PRINTF("     0x0d   CRYPTO_CCMP_128_DEC\r\n");
    (void)PRINTF("     0x0e   CRYPTO_CCMP_256_ENC\r\n");
    (void)PRINTF("     0x0f   CRYPTO_CCMP_256_DEC\r\n");
    (void)PRINTF("     0x10   CRYPTO_CCMP_128_MGMT_ENC\r\n");
    (void)PRINTF("     0x11   CRYPTO_CCMP_128_MGMT_DEC\r\n");
    (void)PRINTF("     0x12   GCMP_256_ENC_FIPS\r\n");
    (void)PRINTF("     0x13   GCMP_256_DEC_FIPS\r\n");
    (void)PRINTF("     0x14   GCMP_128_ENC_FIPS\r\n");
    (void)PRINTF("     0x15   GCMP_128_DEC_FIPS\r\n");
    (void)PRINTF("     0x16   TKIP_ENC_FIPS\r\n");
    (void)PRINTF("     0x17   TKIP_DEC_FIPS\r\n");
}

static void test_wlan_eu_validation(int argc, char **argv)
{
    u8_t cmd_eu_buf[] = {0x34, 0x02, 0x0c, 0, 0, 0, 0, 0, 0x04, 0, 0x05, 0};
    int value;
    int ret           = -WM_FAIL;
    uint32_t reqd_len = 0;

    if (argc != 2)
    {
        dump_wlan_eu_validation();
        (void)PRINTF("Error: invalid number of arguments\r\n");
        return;
    }

    if (argv[1][0] == '0' && (argv[1][1] == 'x' || argv[1][1] == 'X'))
        value = a2hex_or_atoi(argv[1]);
    else
    {
        dump_wlan_eu_validation();
        (void)PRINTF("Error: invalid value format\r\n");
        return;
    }

    if (value < 5 || value > 23)
    {
        dump_wlan_eu_validation();
        (void)PRINTF("Error: invalid value\r\n");
        return;
    }

    cmd_eu_buf[10] = value;

    ret = wlan_send_hostcmd(cmd_eu_buf, sizeof(cmd_eu_buf) / sizeof(u8_t), host_cmd_resp_buf, HOSTCMD_RESP_BUFF_SIZE,
                            &reqd_len);
    if (ret == WM_SUCCESS)
    {
        (void)PRINTF("Hostcmd success, response is:\r\n");
        for (ret = 0; ret < reqd_len; ret++)
        {
            (void)PRINTF("%x\t", host_cmd_resp_buf[ret]);
            host_cmd_resp_buf[ret] = 0;
        }
    }
    else
        (void)PRINTF("Hostcmd failed error: %d", ret);
}
#endif /* CONFIG_EU_VALIDATION */

#ifdef CONFIG_WIFI_EU_CRYPTO
static void dump_wlan_eu_crypto(void)
{
    (void)PRINTF("Usage:\r\n");
    (void)PRINTF("Algorithm AES-WRAP encryption and decryption verification\r\n");
    (void)PRINTF("wlan-eu-crypto <EncDec>\r\n");
    (void)PRINTF("EncDec: 0-Decrypt, 1-Encrypt\r\n");
}
static void test_wlan_eu_crypto(int argc, char **argv)
{
    unsigned int EncDec = 0U;
    t_u8 DATA[80]       = {0};
    t_u16 Length;
    int ret;
    t_u16 Dec_DataLength;
    t_u16 Enc_DataLength;
    t_u16 KeyLength;
    t_u16 KeyIVLength;
    if (argc != 2)
    {
        dump_wlan_eu_crypto();
        (void)PRINTF("Error: invalid number of arguments\r\n");
        return;
    }
    (void)get_uint(argv[1], &EncDec, 1);
    if (EncDec != 0U && EncDec != 1U)
    {
        dump_wlan_eu_crypto();
        (void)PRINTF("Error: invalid EncDec\r\n");
        return;
    }
    /*Algorithm: AES_WRAP*/
    t_u8 Key[16]     = {0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22};
    KeyLength        = 16;
    t_u8 EncData[16] = {0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12};
    Enc_DataLength   = 16;
    t_u8 DecData[24] = {0xfa, 0xda, 0x96, 0x53, 0x30, 0x97, 0x4b, 0x61, 0x77, 0xc6, 0xd4, 0x3c,
                        0xd2, 0x0e, 0x1f, 0x6d, 0x43, 0x8a, 0x0a, 0x1c, 0x4f, 0x6a, 0x1a, 0xd7};
    Dec_DataLength   = 24;
    t_u8 KeyIV[8]    = {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11};
    KeyIVLength      = 8;

    if (EncDec == 0U)
    {
        (void)memcpy(DATA, DecData, Dec_DataLength);
        Length = Dec_DataLength;
        ret    = wlan_set_crypto_AES_WRAP_decrypt(Key, KeyLength, KeyIV, KeyIVLength, DATA, &Length);
    }
    else
    {
        (void)memcpy(DATA, EncData, Enc_DataLength);
        Length = Enc_DataLength;
        ret    = wlan_set_crypto_AES_WRAP_encrypt(Key, KeyLength, KeyIV, KeyIVLength, DATA, &Length);
    }
    if (ret == WM_SUCCESS)
    {
        (void)PRINTF("Raw Data:\r\n");
        if (EncDec == 0U)
        {
            dump_hex((t_u8 *)DecData, Dec_DataLength);
            (void)PRINTF("Decrypted Data:\r\n");
            dump_hex((t_u8 *)DATA, Length);
        }
        else
        {
            dump_hex((t_u8 *)EncData, Enc_DataLength);
            (void)PRINTF("Encrypted Data:\r\n");
            dump_hex((t_u8 *)DATA, Length);
        }
    }
    else
    {
        (void)PRINTF("Hostcmd failed error: %d", ret);
    }
}
#endif

#ifdef CONFIG_HEAP_DEBUG
int os_mem_alloc_cnt = 0;
int os_mem_free_cnt  = 0;

static void test_wlan_os_mem_stat(int argc, char **argv)
{
    (void)PRINTF("os_mem_alloc_cnt: %d \r\n", os_mem_alloc_cnt);
    (void)PRINTF("os_mem_free_cnt : %d \r\n", os_mem_free_cnt);
    (void)PRINTF("FreeHeapSize    : %d \r\n\r\n", xPortGetFreeHeapSize());
    wlan_show_os_mem_stat();
}
#endif

#ifdef CONFIG_MULTI_CHAN
static void test_wlan_set_multi_chan_status(int argc, char **argv)
{
    int ret;
    int enable;

    if (argc != 2)
    {
        (void)PRINTF("Invalid arguments\r\n");
        return;
    }

    errno  = 0;
    enable = strtol(argv[1], NULL, 10);
    if (errno != 0)
    {
        (void)PRINTF("Error during strtol:enable multi chan status errno:%d\r\n", errno);
    }

    ret = wlan_set_multi_chan_status(enable);
    if (ret != WM_SUCCESS)
    {
        (void)PRINTF("Set multi_chan_status fail, please set before uap start/sta connect\r\n");
    }
}

static void test_wlan_get_multi_chan_status(int argc, char **argv)
{
    int ret;
    int enable;

    ret = wlan_get_multi_chan_status(&enable);
    if (ret != WM_SUCCESS)
    {
        (void)PRINTF("Get multi_chan_policy fail\r\n");
        return;
    }

    (void)PRINTF("Get multi_chan_policy %d\r\n", enable);
}

static void dump_drcs_cfg(void)
{
    (void)PRINTF("wlan-set-drcs usage:\r\n");
    (void)PRINTF("arguments group <channel_time> <switch_time> <undoze_time> <mode>\r\n");
    (void)PRINTF("input one group, same settings for both channel 0 and channel 1\r\n");
    (void)PRINTF("input two groups, different settings for channel 0 first and then channel 1\r\n");
    (void)PRINTF("channel_time: Channel time stayed (in TU 1024us) for chan_idx\r\n");
    (void)PRINTF(
        "switch_time: Channel switch time (in TU 1024us) for chan_idx, including doze for old channel and undoze for "
        "new channel\r\n");
    (void)PRINTF("undoze_time: Undoze time during switch time (in TU 1024us) for chan_idx\r\n");
    (void)PRINTF("mode: Channel switch scheme 0-PM1, 1-Null2Self\r\n");
    (void)PRINTF("Example for same settings for channel 0 and 1:\r\n");
    (void)PRINTF("wlan-set-drcs 15 10 5 0:\r\n");
    (void)PRINTF("Example for different settings for channel 0 and 1:\r\n");
    (void)PRINTF("wlan-set-drcs 15 10 5 0 16 8 4 1:\r\n");
}

static void get_drcs_cfg(char **data, wlan_drcs_cfg_t *drcs_cfg)
{
    errno              = 0;
    drcs_cfg->chantime = (t_u8)strtol(data[0], NULL, 10);
    if (errno != 0)
    {
        (void)PRINTF("Error during strtol:drcs_cfg chantime errno:%d\r\n", errno);
    }

    errno                = 0;
    drcs_cfg->switchtime = (t_u8)strtol(data[1], NULL, 10);
    if (errno != 0)
    {
        (void)PRINTF("Error during strtol:drcs_cfg switchtime errno:%d\r\n", errno);
    }

    errno                = 0;
    drcs_cfg->undozetime = (t_u8)strtol(data[2], NULL, 10);
    if (errno != 0)
    {
        (void)PRINTF("Error during strtol:drcs_cfg undozetime errno:%d\r\n", errno);
    }

    errno          = 0;
    drcs_cfg->mode = (t_u8)strtol(data[3], NULL, 10);
    if (errno != 0)
    {
        (void)PRINTF("Error during strtol:drcs_cfg mode errno:%d\r\n", errno);
    }
}

static void test_wlan_set_drcs_cfg(int argc, char **argv)
{
    wlan_drcs_cfg_t drcs_cfg[2] = {0};

    if (argc != 5 && argc != 9)
    {
        dump_drcs_cfg();
        return;
    }

    if (argc == 5)
    {
        get_drcs_cfg(&argv[1], &drcs_cfg[0]);
        drcs_cfg[0].chan_idx = 0x03;
    }
    else
    {
        get_drcs_cfg(&argv[1], &drcs_cfg[0]);
        get_drcs_cfg(&argv[5], &drcs_cfg[1]);
        drcs_cfg[0].chan_idx = 0x01;
        drcs_cfg[1].chan_idx = 0x02;
    }

    (void)wlan_set_drcs_cfg(&drcs_cfg[0], 2);
}

static void test_wlan_get_drcs_cfg(int argc, char **argv)
{
    int ret;
    wlan_drcs_cfg_t drcs_cfg[2] = {0};

    ret = wlan_get_drcs_cfg(&drcs_cfg[0], 2);
    if (ret != WM_SUCCESS)
    {
        (void)PRINTF("get drcs cfg fail\r\n");
        return;
    }

    (void)PRINTF("chan_idx: 0x%02x\r\n", drcs_cfg[0].chan_idx);
    (void)PRINTF("chan_time: %d\r\n", drcs_cfg[0].chantime);
    (void)PRINTF("switch_time: %d\r\n", drcs_cfg[0].switchtime);
    (void)PRINTF("undoze_time: %d\r\n", drcs_cfg[0].undozetime);
    (void)PRINTF("mode: %d\r\n", drcs_cfg[0].mode);
    if (drcs_cfg[0].chan_idx != (t_u16)0x03U)
    {
        (void)PRINTF("chan_idx: 0x%02x\r\n", drcs_cfg[1].chan_idx);
        (void)PRINTF("chan_time: %d\r\n", drcs_cfg[1].chantime);
        (void)PRINTF("switch_time: %d\r\n", drcs_cfg[1].switchtime);
        (void)PRINTF("undoze_time: %d\r\n", drcs_cfg[1].undozetime);
        (void)PRINTF("mode: %d\r\n", drcs_cfg[1].mode);
    }
}
#endif

#ifndef STREAM_2X2
static void dump_wlan_set_antcfg_usage(void)
{
    (void)PRINTF("Usage:\r\n");
    (void)PRINTF("wlan-set-antcfg <ant mode> [evaluate_time] \r\n");
    (void)PRINTF("\r\n");
    (void)PRINTF("\t<ant mode>: \r\n");
    (void)PRINTF("\t           Bit 0   -- Tx/Rx antenna 1\r\n");
    (void)PRINTF("\t           Bit 1   -- Tx/Rx antenna 2\r\n");
    (void)PRINTF("\t           0xFFFF  -- Tx/Rx antenna diversity\r\n");
    (void)PRINTF("\t[evaluate_time]: \r\n");
    (void)PRINTF("\t           if ant mode = 0xFFFF, SAD evaluate time interval,\r\n");
    (void)PRINTF("\t           default value is 6s(0x1770)\r\n");
}

static void wlan_antcfg_set(int argc, char *argv[])
{
    int ret;
    uint32_t ant_mode;
    uint16_t evaluate_time = 0;

    if (!(argc >= 2 && argc <= 3))
    {
        dump_wlan_set_antcfg_usage();
        return;
    }

    errno    = 0;
    ant_mode = (uint32_t)strtol(argv[1], NULL, 16);
    if (errno != 0)
    {
        (void)PRINTF("Error during strtoul errno:%d", errno);
    }

    if ((argc == 3) && (ant_mode != 0xFFFFU))
    {
        dump_wlan_set_antcfg_usage();
        return;
    }

    errno = 0;
    if (argc == 3)
    {
        evaluate_time = (uint16_t)strtol(argv[2], NULL, 16);
    }
    if (errno != 0)
    {
        (void)PRINTF("Error during strtoul errno:%d", errno);
    }

    ret = wlan_set_antcfg(ant_mode, evaluate_time);
    if (ret == WM_SUCCESS)
    {
        (void)PRINTF("Antenna configuration successful\r\n");
    }
    else
    {
        (void)PRINTF("Antenna configuration failed\r\n");
        dump_wlan_set_antcfg_usage();
    }
}

static void dump_wlan_get_antcfg_usage(void)
{
    (void)PRINTF("Usage:\r\n");
    (void)PRINTF("wlan-get-antcfg \r\n");
}

static void wlan_antcfg_get(int argc, char *argv[])
{
    int ret;
    uint32_t ant_mode;
    uint16_t evaluate_time = 0;

    if (argc != 1)
    {
        dump_wlan_get_antcfg_usage();
        return;
    }

    ret = wlan_get_antcfg(&ant_mode, &evaluate_time);
    if (ret == WM_SUCCESS)
    {
        (void)PRINTF("Mode of Tx/Rx path is : %x\r\n", ant_mode);
        if (ant_mode == 0XFFFFU)
        {
            (void)PRINTF("Evaluate time : %x\r\n", evaluate_time);
        }
    }
    else
    {
        (void)PRINTF("antcfg configuration read failed\r\n");
        dump_wlan_get_antcfg_usage();
    }
}
#endif

#ifdef CONFIG_EXT_SCAN_SUPPORT
static void test_wlan_set_scan_channel_gap(int argc, char **argv)
{
    unsigned scan_chan_gap;
    if (argc != 2)
    {
        (void)PRINTF("Invalid arguments\r\n");
        (void)PRINTF("Usage:\r\n");
        (void)PRINTF("wlan-scan-channel-gap <scan_gap_value>\r\n");
        (void)PRINTF("scan_gap_value: [2,500]\r\n");
        return;
    }
    scan_chan_gap = a2hex_or_atoi(argv[1]);
    if (scan_chan_gap < 2 || scan_chan_gap > 500)
    {
        (void)PRINTF("Invaild scan_gap value!\r\n");
        (void)PRINTF("Usage:\r\n");
        (void)PRINTF("wlan-scan-channel-gap <scan_gap_value>\r\n");
        (void)PRINTF("scan_gap_value: [2,500]\r\n");
        return;
    }
    wlan_set_scan_channel_gap(scan_chan_gap);
}
#endif

#if defined(CONFIG_WMM) && defined(CONFIG_WMM_ENH)
static void test_wlan_wmm_tx_stats(int argc, char **argv)
{
    int bss_type = atoi(argv[1]);

    wlan_wmm_tx_stats_dump(bss_type);
}
#endif

static void dump_wlan_set_regioncode_usage(void)
{
    (void)PRINTF("Usage:\r\n");
    (void)PRINTF("wlan-set-regioncode <region-code>\r\n");
    (void)PRINTF("where, region code =\r\n");
    (void)PRINTF("0xAA : World Wide Safe Mode\r\n");
    (void)PRINTF("0x10 : US FCC, Singapore\r\n");
    (void)PRINTF("0x20 : IC Canada\r\n");
    (void)PRINTF("0x30 : ETSI, Australia, Republic of Korea\r\n");
    (void)PRINTF("0x32 : France\r\n");
    (void)PRINTF("0x40 : Japan\r\n");
    (void)PRINTF("0x50 : China\r\n");
    (void)PRINTF("0xFF : Japan Special\r\n");
#ifndef CONFIG_MLAN_WMSDK
    (void)PRINTF("0x41 : Japan\r\n");
    (void)PRINTF("0xFE : Japan\r\n");
#endif
}

static void test_wlan_set_regioncode(int argc, char **argv)
{
    if (argc != 2)
    {
        dump_wlan_set_regioncode_usage();
        return;
    }

    errno             = 0;
    t_u32 region_code = (t_u32)strtol(argv[1], NULL, 0);
    if (errno != 0)
    {
        (void)PRINTF("Error during strtoul errno:%d", errno);
    }
    int rv = wifi_set_region_code(region_code);
    if (rv != WM_SUCCESS)
    {
        (void)PRINTF("Unable to set region code: 0x%x\r\n", region_code);
    }
    else
    {
        (void)PRINTF("Region code: 0x%x set\r\n", region_code);
    }
#if defined(RW610) && defined(CONFIG_COMPRESS_TX_PWTBL)
    rv = wlan_set_rg_power_cfg(region_code);
    if (rv != WM_SUCCESS)
        (void)PRINTF("Set region 0x%x tx power table failed \r\n", region_code);
    else
        (void)PRINTF("Set region 0x%x tx power table success \r\n", region_code);
#endif
}

static void test_wlan_get_regioncode(int argc, char **argv)
{
    t_u32 region_code = 0;
    int rv            = wifi_get_region_code(&region_code);
    if (rv != WM_SUCCESS)
    {
        (void)PRINTF("Unable to get region code: 0x%x\r\n", region_code);
    }
    else
    {
        (void)PRINTF("Region code: 0x%x\r\n", region_code);
    }
}
static void test_wlan_set_mac_address(int argc, char **argv)
{
    int ret;
    uint8_t raw_mac[MLAN_MAC_ADDR_LENGTH];

    if (argc != 2)
    {
        (void)PRINTF("Usage: %s MAC_Address\r\n", argv[0]);
        return;
    }

    ret = get_mac(argv[1], (char *)raw_mac, ':');
    if (ret != 0)
    {
        (void)PRINTF("Error: invalid MAC argument\r\n");
        return;
    }

    wlan_set_mac_addr(raw_mac);
}
#if defined(RW610) && defined(CONFIG_WIFI_RESET)
static void test_wlan_reset(int argc, char **argv)
{
    int option;

    option = atoi(argv[1]);
    if (argc != 2 || (option != 0 && option != 1 && option != 2))
    {
        (void)PRINTF("Usage: %s <options>\r\n", argv[0]);
        (void)PRINTF("0 to Disable WiFi\r\n");
        (void)PRINTF("1 to Enable WiFi\r\n");
        (void)PRINTF("2 to Reset WiFi\r\n");
        return;
    }

    wlan_reset((cli_reset_option)option);
}
#endif

#ifdef CONFIG_ECSA
static void test_wlan_uap_set_ecsa_cfg(int argc, char **argv)
{
    int ret;
    t_u8 block_tx     = 0;
    t_u8 oper_class   = 0;
    t_u8 new_channel  = 0;
    t_u8 switch_count = 0;
    t_u8 band_width   = 0;

    if ((5 == argc) || (6 == argc))
    {
        block_tx     = (t_u8)atoi(argv[1]);
        oper_class   = (t_u8)atoi(argv[2]);
        new_channel  = (t_u8)atoi(argv[3]);
        switch_count = (t_u8)atoi(argv[4]);

        if (6 == argc)
        {
            band_width = (t_u8)atoi(argv[5]);
        }
    }
    else
    {
        (void)PRINTF("Error        : invalid number of arguments \r\n");
        (void)PRINTF("Usage        : %s <block_tx> <oper_class> <new_channel> <switch_count> <bandwidth>\r\n", argv[0]);
        (void)PRINTF("block_tx     : 0 -- no need to block traffic, 1 -- need block traffic \r\n");
        (void)PRINTF("oper_class   : Operating class according to IEEE std802.11 spec \r\n");
        (void)PRINTF("new_channel  : The channel will switch to \r\n");
        (void)PRINTF("switch count : Channel switch time to send ECSA ie \r\n");
        (void)PRINTF("bandwidth    : Channel width switch to(optional),RW610 only support 20M channels \r\n");

        (void)PRINTF("\r\nUsage example : wlan-set-ecsa-cfg 1 0 36 10 1 \r\n");

        return;
    }

    /* Disable action Temporary */
    if (0 == switch_count)
    {
        (void)PRINTF("Error : invalid arguments \r\n");
        (void)PRINTF("argv[4] switch_count cannot be 0\r\n");
        return;
    }

    ret = wlan_uap_set_ecsa_cfg(block_tx, oper_class, new_channel, switch_count, band_width);

    if (ret != WM_SUCCESS)
    {
        (void)PRINTF("Failed to set ecsa cfg \r\n");
    }
}
#endif /* CONFIG_ECSA */

#ifdef CONFIG_11AX
static void dump_wlan_set_tol_time_usage()
{
    (void)PRINTF("Usage:\r\n");
    (void)PRINTF("set OBSS Narrow Bandwidth RU Tolerance Time\r\n");
    (void)PRINTF("Pls set toltime when sta is in disconnect state.\r\n");
    (void)PRINTF("wlan-set-toltime value\r\n");
    (void)PRINTF("value:\r\n");
    (void)PRINTF("Valid range[1..3600]\r\n");
}

static void test_wlan_set_toltime(int argc, char **argv)
{
    unsigned int value;
    int ret;
    if (argc != 2)
    {
        (void)PRINTF("Error: invalid number of arguments\r\n");
        dump_wlan_set_tol_time_usage();
        return;
    }

    if (get_uint(argv[1], &value, strlen(argv[1])))
    {
        (void)PRINTF("Error: invalid option argument\r\n");
        dump_wlan_set_tol_time_usage();
        return;
    }

    if (value < 1 || value > 3600)
    {
        (void)PRINTF("Error: invalid tolerance time value\r\n");
        dump_wlan_set_tol_time_usage();
        return;
    }

    ret = wlan_set_tol_time(value);

    if (ret != WM_SUCCESS)
    {
        (void)PRINTF("Error: Failed to set Tolerance Time.\r\n");
        dump_wlan_set_tol_time_usage();
        return;
    }
}

#endif /* CONFIG_11AX */

#ifdef CONFIG_SUBSCRIBE_EVENT_SUPPORT
/**
 *  @brief This function print the get subscribe event from firmware for user test.
 */
static void print_get_sub_event(wlan_ds_subscribe_evt *sub_evt)
{
    t_u16 evt_bitmap = sub_evt->evt_bitmap;
    PRINTF("evt_bitmap = %u\r\n", evt_bitmap);
    if (evt_bitmap & SUBSCRIBE_EVT_RSSI_LOW)
    {
        PRINTF("rssi low is enabled! ");
        PRINTF("value = %u, freq = %u\r\n", sub_evt->low_rssi, sub_evt->low_rssi_freq);
    }
    if (evt_bitmap & SUBSCRIBE_EVT_RSSI_HIGH)
    {
        PRINTF("rssi high is enabled! ");
        PRINTF("value = %u, freq = %u\r\n", sub_evt->high_rssi, sub_evt->high_rssi_freq);
    }
    if (evt_bitmap & SUBSCRIBE_EVT_SNR_LOW)
    {
        PRINTF("snr low is enabled! ");
        PRINTF("value = %u, freq = %u\r\n", sub_evt->low_snr, sub_evt->low_snr_freq);
    }
    if (evt_bitmap & SUBSCRIBE_EVT_SNR_HIGH)
    {
        PRINTF("snr high is enabled! ");
        PRINTF("value = %u, freq = %u\r\n", sub_evt->high_snr, sub_evt->high_snr_freq);
    }
    if (evt_bitmap & SUBSCRIBE_EVT_MAX_FAIL)
    {
        PRINTF("max fail is enabled! ");
        PRINTF("value = %u, freq = %u\r\n", sub_evt->failure_count, sub_evt->failure_count_freq);
    }
    if (evt_bitmap & SUBSCRIBE_EVT_BEACON_MISSED)
    {
        PRINTF("beacon miss is enabled! ");
        PRINTF("value = %u, freq = %u\r\n", sub_evt->beacon_miss, sub_evt->beacon_miss_freq);
    }
    if (evt_bitmap & SUBSCRIBE_EVT_DATA_RSSI_LOW)
    {
        PRINTF("data rssi low is enabled! ");
        PRINTF("value = %u, freq = %u\r\n", sub_evt->data_low_rssi, sub_evt->data_low_rssi_freq);
    }
    if (evt_bitmap & SUBSCRIBE_EVT_DATA_RSSI_HIGH)
    {
        PRINTF("data rssi high is enabled! ");
        PRINTF("value = %u, freq = %u\r\n", sub_evt->data_high_rssi, sub_evt->data_high_rssi_freq);
    }
    if (evt_bitmap & SUBSCRIBE_EVT_DATA_SNR_LOW)
    {
        PRINTF("data snr low is enabled! ");
        PRINTF("value = %u, freq = %u\r\n", sub_evt->data_low_snr, sub_evt->data_low_snr_freq);
    }
    if (evt_bitmap & SUBSCRIBE_EVT_DATA_SNR_HIGH)
    {
        PRINTF("data snr high is enabled! ");
        PRINTF("value = %u, freq = %u\r\n", sub_evt->data_high_snr, sub_evt->data_high_snr_freq);
    }
    if (evt_bitmap & SUBSCRIBE_EVT_LINK_QUALITY)
    {
        PRINTF("link quality is enabled! ");
        PRINTF("value = %u\r\n", sub_evt->pre_beacon_miss);
    }
    if (evt_bitmap & SUBSCRIBE_EVT_PRE_BEACON_LOST)
    {
        PRINTF("pre beacon lost is enabled! ");
        PRINTF(
            "link_snr = %u, link_snr_freq = %u, "
            "link_rate = %u, link_rate_freq = %u, "
            "link_tx_latency = %u, link_tx_lantency_freq = %u\r\n",
            sub_evt->link_snr, sub_evt->link_snr_freq, sub_evt->link_rate, sub_evt->link_rate_freq,
            sub_evt->link_tx_latency, sub_evt->link_tx_lantency_freq);
    }
}

/**
 *  @brief This function dump the usage of wlan-subscribe-event cmd for user test.
 */
static void dump_wlan_subscribe_event_usage(void)
{
    (void)PRINTF("Usage:\r\n");
    (void)PRINTF("Subscribe event to firmware:\r\n");
    (void)PRINTF("    wlan-subscribe-event <action> <type> <value>\r\n");
    (void)PRINTF("Options: \r\n");
    (void)PRINTF("    <action>  : 1:set, 2:get, 3:clear\r\n");
    (void)PRINTF(
        "    <type>: 0:rssi_low, 1:rssi_high 2:snr_low, 3:snr_high, 4:max_fail, 5:beacon_missed, 6:data_rssi_low, "
        "7:data_rssi_high, 8:data_snr_low, 9:data_snr_high, 10:link_quality, 11:pre_beacon_lost\r\n");
    (void)PRINTF("    <value>  : when action is set, specific int type value\r\n");
    (void)PRINTF("    <freq>  : when action is set, specific unsigned int type freq\r\n");
    (void)PRINTF("For example:\r\n");
    (void)PRINTF(
        "    wlan-subscribe-event set 0 50 0 : Subscribe the rssi low event, threshold is 50, freq is 0\r\n"
        "    wlan-subscribe-event set 2 50 0 : Subscribe the snr low event, threshold is 50, freq is 0\r\n"
        "    wlan-subscribe-event set 4 50 0 : Subscribe the max_fail event, threshold is 50, freq is 0\r\n"
        "    wlan-subscribe-event set 5 50 0 : Subscribe the beacon_missed event, threshold is 50, freq is 0\r\n"
        "    wlan-subscribe-event set 6 50 0 : Subscribe the data rssi low event, threshold is 50, freq is 0\r\n"
        "    wlan-subscribe-event set 8 50 0 : Subscribe the data snr low event, threshold is 50, freq is 0\r\n"
        "    wlan-subscribe-event set 11 50 0 : Subscribe the pre_beacon_lost event, threshold is 50, freq is 0\r\n");
    (void)PRINTF(
        "    wlan-subscribe-event set 10 5 0 5 0 5 0  : Subscribe the link quanlity event"
        "    link_snr threshold is 5, link_snr freq is 0"
        "    link_rate threshold is 5, link_rate freq is 0"
        "    link_tx_latency threshold is 5, link_tx_latency freq is 0\r\n");
    (void)PRINTF("    wlan-subscribe-event get      : Get the all subscribe event parameter\r\n");
    (void)PRINTF(
        "    wlan-subscribe-event clear 0  : Disable the rssi_low event\r\n"
        "    wlan-subscribe-event clear 2  : Disable the snr_low event\r\n"
        "    wlan-subscribe-event clear 4  : Disable the max_fail event\r\n"
        "    wlan-subscribe-event clear 5  : Disable the beacon_missed event\r\n"
        "    wlan-subscribe-event clear 6  : Disable the data_rssi_low event\r\n"
        "    wlan-subscribe-event clear 8  : Disable the data_snr_low event\r\n"
        "    wlan-subscribe-event clear 10 : Disable the link_quality event\r\n"
        "    wlan-subscribe-event clear 11 : Disable the pre_beacon_lost event\r\n");
}

/**
 *  @brief This function subscribe event to firmware for user test.
 */
static void test_wlan_subscribe_event(int argc, char **argv)
{
    int ret                   = 0;
    unsigned int thresh_value = 0, freq = 0;

    /*analyse action type*/
    switch (argc)
    {
        case 2:
        {
            if (strncmp(argv[1], "get", strlen(argv[1])))
            {
                dump_wlan_subscribe_event_usage();
                return;
            }
            wlan_ds_subscribe_evt sub_evt;
            ret = wlan_get_subscribe_event(&sub_evt);
            if (ret == WM_SUCCESS)
                print_get_sub_event(&sub_evt);
            break;
        }
        case 3:
        {
            if (strncmp(argv[1], "clear", strlen(argv[1])))
            {
                dump_wlan_subscribe_event_usage();
                return;
            }
            unsigned int event_id = MAX_EVENT_ID;
            if (get_uint(argv[2], &event_id, strlen(argv[2])))
            {
                dump_wlan_subscribe_event_usage();
                return;
            }
            if (event_id >= MAX_EVENT_ID)
            {
                dump_wlan_subscribe_event_usage();
                return;
            }
            ret = wlan_clear_subscribe_event(event_id);
            break;
        }
        case 5:
        {
            if (strncmp(argv[1], "set", strlen(argv[1])))
            {
                dump_wlan_subscribe_event_usage();
                return;
            }
            if (get_uint(argv[3], &thresh_value, strlen(argv[3])) || get_uint(argv[4], &freq, strlen(argv[4])))
            {
                dump_wlan_subscribe_event_usage();
                return;
            }
            unsigned int event_id = MAX_EVENT_ID;
            if (get_uint(argv[2], &event_id, strlen(argv[2])))
            {
                dump_wlan_subscribe_event_usage();
                return;
            }
            if (event_id >= MAX_EVENT_ID)
            {
                dump_wlan_subscribe_event_usage();
                return;
            }
            ret = wlan_set_subscribe_event(event_id, thresh_value, freq);
            break;
        }
        case 9:
        {
            unsigned int link_snr = 0, link_snr_freq = 0, link_rate = 0;
            unsigned int link_rate_freq = 0, link_tx_latency = 0, link_tx_lantency_freq = 0;
            if (strncmp(argv[1], "set", strlen(argv[1])))
            {
                dump_wlan_subscribe_event_usage();
                return;
            }
            if (get_uint(argv[3], &link_snr, strlen(argv[3])))
            {
                dump_wlan_subscribe_event_usage();
                return;
            }
            if (get_uint(argv[4], &link_snr_freq, strlen(argv[4])))
            {
                dump_wlan_subscribe_event_usage();
                return;
            }
            if (get_uint(argv[5], &link_rate, strlen(argv[5])))
            {
                dump_wlan_subscribe_event_usage();
                return;
            }
            if (get_uint(argv[6], &link_rate_freq, strlen(argv[6])))
            {
                dump_wlan_subscribe_event_usage();
                return;
            }
            if (get_uint(argv[7], &link_tx_latency, strlen(argv[7])))
            {
                dump_wlan_subscribe_event_usage();
                return;
            }
            if (get_uint(argv[8], &link_tx_lantency_freq, strlen(argv[8])))
            {
                dump_wlan_subscribe_event_usage();
                return;
            }
            unsigned int event_id = MAX_EVENT_ID;
            if (get_uint(argv[2], &event_id, strlen(argv[2])))
            {
                dump_wlan_subscribe_event_usage();
                return;
            }
            if (event_id >= MAX_EVENT_ID)
            {
                dump_wlan_subscribe_event_usage();
                return;
            }
            ret = wlan_set_threshold_link_quality(event_id, link_snr, link_snr_freq, link_rate, link_rate_freq,
                                                  link_tx_latency, link_tx_lantency_freq);
        }
        break;
        default:
            dump_wlan_subscribe_event_usage();
            return;
    }
    if (ret == WM_E_INVAL)
        dump_wlan_subscribe_event_usage();
    else if (ret != WM_SUCCESS)
        (void)PRINTF("wlan-subscribe-event unkown fail\r\n");
    return;
}
#endif

#ifdef CONFIG_WIFI_REG_ACCESS
static void dump_wlan_reg_access_usage()
{
    (void)PRINTF("Usage:\r\n");
    (void)PRINTF("Read the register:\r\n");
    (void)PRINTF("    wlan-reg-access <type> <offset>\r\n");
    (void)PRINTF("Write the register:\r\n");
    (void)PRINTF("    wlan-reg-access <type> <offset> <value>\r\n");
    (void)PRINTF("Options: \r\n");
    (void)PRINTF("    <type>  : 1:MAC, 2:BBP, 3:RF, 4:CAU\r\n");
    (void)PRINTF("    <offset>: offset of register\r\n");
    (void)PRINTF("For example:\r\n");
    (void)PRINTF("    wlan-reg-access 1 0x9b8             : Read the MAC register\r\n");
    (void)PRINTF("    wlan-reg-access 1 0x9b8 0x80000000 : Write 0x80000000 to MAC register\r\n");
}

static void test_wlan_reg_access(int argc, char **argv)
{
    t_u32 type, offset, value;
    t_u16 action = ACTION_GET;
    int ret;

    if (argc < 3 || argc > 4)
    {
        dump_wlan_reg_access_usage();
        (void)PRINTF("Error: invalid number of arguments\r\n");
        return;
    }

    if ((a2hex_or_atoi(argv[1]) != 1 && a2hex_or_atoi(argv[1]) != 2 && a2hex_or_atoi(argv[1]) != 3 &&
         a2hex_or_atoi(argv[1]) != 4))
    {
        dump_wlan_reg_access_usage();
        (void)PRINTF("Error: Illegal register type %s. Must be either '1','2','3' or '4'.\r\n", argv[1]);
        return;
    }
    type   = a2hex_or_atoi(argv[1]);
    offset = a2hex_or_atoi(argv[2]);
    if (argc == 4)
    {
        action = ACTION_SET;
        value  = a2hex_or_atoi(argv[3]);
    }

    ret = wlan_reg_access((wifi_reg_t)type, action, offset, (uint32_t *)&value);

    if (ret == WM_SUCCESS)
    {
        if (action == ACTION_GET)
            (void)PRINTF("Value = 0x%x\r\n", value);
        else
            (void)PRINTF("Set the register successfully\r\n");
    }
    else
        (void)PRINTF("Read/write register failed");
}
#endif

#ifdef CONFIG_WMM_UAPSD
static void test_wlan_wmm_uapsd_qosinfo(int argc, char **argv)
{
    unsigned int qos_info = 0xf;
    if (argc == 1)
    {
        wlan_wmm_uapsd_qosinfo((t_u8 *)&qos_info, 0);
        (void)PRINTF("qos_info = %d\r\n", qos_info);
    }
    else if (argc == 2 && !get_uint(argv[1], &qos_info, strlen(argv[1])))
    {
        if (qos_info == 0)
            (void)PRINTF("qos_info can't be zero\r\n", argv[0]);
        else
            wlan_wmm_uapsd_qosinfo((t_u8 *)&qos_info, 1);
    }
    else
    {
        (void)PRINTF("Usage: %s <null|qos_info>\r\n", argv[0]);
        (void)PRINTF("set qos_info value to UAPSD QOS_INFO\r\n");
        (void)PRINTF("bit0:VO; bit1:VI; bit2:BK; bit3:BE\r\n");
        return;
    }
}
static void test_wlan_set_wmm_uapsd(int argc, char **argv)
{
    t_u8 enable;

    enable = atoi(argv[1]);
    if (argc != 2 || (enable != 0 && enable != 1))
    {
        (void)PRINTF("Usage: %s <enable>\r\n", argv[0]);
        (void)PRINTF("0 to Disable UAPSD\r\n");
        (void)PRINTF("1 to Enable UAPSD\r\n");
        return;
    }

    wlan_set_wmm_uapsd(enable);
}

static void test_wlan_sleep_period(int argc, char **argv)
{
    unsigned int period = 0;
    if (argc == 1)
    {
        wlan_sleep_period(&period, 0);
        (void)PRINTF("period = %d\r\n", period);
    }
    else if (argc == 2 && !get_uint(argv[1], &period, strlen(argv[1])))
        wlan_sleep_period(&period, 1);
    else
    {
        (void)PRINTF("Usage: %s <period(ms)>\r\n", argv[0]);
    }
}
#endif

#if defined(RW610)
#ifdef CONFIG_WIFI_AMPDU_CTRL
static void dump_wlan_ampdu_enable_usage()
{
    (void)PRINTF("Usage:\r\n");
    (void)PRINTF("wlan-ampdu-enable <sta/uap> <xx: rx:tx bit map. Tx (bit 0), Rx (bit 1> <xx: TID bit map> \r\n");
    (void)PRINTF("xx: TID bit map\r\n");
    (void)PRINTF("  1 - TID 0 enable \r\n");
    (void)PRINTF("  2 - TID 1 enable\r\n");
    (void)PRINTF("  4 - TID 2 enable\r\n");
    (void)PRINTF("  7 - TID0, 1, 2 enable\r\n");
    (void)PRINTF("  ---------\r\n");
    (void)PRINTF("  255 - TID 0-7 enable \r\n");
    (void)PRINTF("  0 - Disable ampdu \r\n");
    (void)PRINTF("Example: disable sta rx/tx ampdu\r\n");
    (void)PRINTF("  wlan-ampdu-enable sta 3 0\r\n");
}

static void test_wlan_ampdu_enable(int argc, char **argv)
{
    t_u8 tid;
    t_u8 direction;
    int bss_type = 0;

    if (argc != 4)
    {
        dump_wlan_ampdu_enable_usage();
        return;
    }

    if (string_equal("sta", argv[1]))
        bss_type = MLAN_BSS_TYPE_STA;
    else if (string_equal("uap", argv[1]))
        bss_type = MLAN_BSS_TYPE_UAP;
    else
    {
        dump_wlan_ampdu_enable_usage();
        return;
    }

    direction = atoi(argv[2]);
    tid       = atoi(argv[3]);

    if (bss_type == MLAN_BSS_TYPE_STA)
    {
        if (is_sta_connected())
        {
            (void)PRINTF("Error: configure ampdu control before sta connection!\r\n", argv[0]);
            return;
        }

        if (tid)
        {
            if (direction & 0x01)
            {
                wlan_sta_ampdu_tx_enable();
                wlan_sta_ampdu_tx_enable_per_tid(tid);
            }

            if (direction & 0x02)
            {
                wlan_sta_ampdu_rx_enable();
                wlan_sta_ampdu_rx_enable_per_tid(tid);
            }
        }
        else
        {
            if (direction & 0x01)
            {
                wlan_sta_ampdu_tx_disable();
                wlan_sta_ampdu_tx_enable_per_tid(tid);
            }

            if (direction & 0x02)
            {
                wlan_sta_ampdu_rx_disable();
                wlan_sta_ampdu_rx_enable_per_tid(tid);
            }
        }
    }
    else
    {
        if (is_uap_started())
        {
            (void)PRINTF("Error: configure ampdu control before uap start!\r\n", argv[0]);
            return;
        }
        if (tid)
        {
            if (direction & 0x01)
            {
                wlan_uap_ampdu_tx_enable();
                wlan_uap_ampdu_tx_enable_per_tid(tid);
            }

            if (direction & 0x02)
            {
                wlan_uap_ampdu_rx_enable();
                wlan_uap_ampdu_rx_enable_per_tid(tid);
            }
        }
        else
        {
            if (direction & 0x01)
            {
                wlan_uap_ampdu_tx_disable();
                wlan_uap_ampdu_tx_enable_per_tid(tid);
            }

            if (direction & 0x02)
            {
                wlan_uap_ampdu_rx_disable();
                wlan_uap_ampdu_rx_enable_per_tid(tid);
            }
        }
    }
}
#endif

#ifdef CONFIG_TX_AMPDU_PROT_MODE
static void dump_wlan_tx_ampdu_prot_mode_usage()
{
    (void)PRINTF("Usage:\r\n");
    (void)PRINTF("    wlan-tx-ampdu-prot-mode <mode>\r\n");
    (void)PRINTF("    <mode>: 0 - Set RTS/CTS mode \r\n");
    (void)PRINTF("            1 - Set CTS2SELF mode \r\n");
    (void)PRINTF("            2 - Disable Protection mode \r\n");
    (void)PRINTF("            3 - Set Dynamic RTS/CTS mode \r\n");
    (void)PRINTF("Example:\r\n");
    (void)PRINTF("    wlan-tx-ampdu-prot-mode\r\n");
    (void)PRINTF("    - Get currently set protection mode for TX AMPDU.\r\n");
    (void)PRINTF("    wlan-tx-ampdu-prot-mode 1\r\n");
    (void)PRINTF("    - Set protection mode for TX AMPDU to CTS2SELF.\r\n");
}

static void test_wlan_tx_ampdu_prot_mode(int argc, char **argv)
{
    tx_ampdu_prot_mode_para data;

    if (argc > 2)
    {
        (void)PRINTF("Error: invalid number of arguments\r\n");
        dump_wlan_tx_ampdu_prot_mode_usage();
        return;
    }

    /* GET */
    if (argc == 1)
    {
        dump_wlan_tx_ampdu_prot_mode_usage();
        wlan_tx_ampdu_prot_mode(&data, ACTION_GET);
        (void)PRINTF("\r\nTx AMPDU protection mode: ");
        switch (data.mode)
        {
            case TX_AMPDU_RTS_CTS:
                (void)PRINTF("RTS/CTS\r\n");
                break;
            case TX_AMPDU_CTS_2_SELF:
                (void)PRINTF("CTS-2-SELF\r\n");
                break;
            case TX_AMPDU_DISABLE_PROTECTION:
                (void)PRINTF("Disabled\r\n");
                break;
            case TX_AMPDU_DYNAMIC_RTS_CTS:
                (void)PRINTF("DYNAMIC RTS/CTS\r\n");
                break;
            default:
                (void)PRINTF("Invalid protection mode\r\n");
                break;
        }
    }
    else /* SET */
    {
        data.mode = atoi(argv[1]);
        if (data.mode < 0 || data.mode > 3)
        {
            (void)PRINTF("Error: invalid protection mode\r\n");
            dump_wlan_tx_ampdu_prot_mode_usage();
            return;
        }
        wlan_tx_ampdu_prot_mode(&data, ACTION_SET);
    }
}
#endif
#endif

#ifdef CONFIG_CSI
static void dump_wlan_csi_filter_usage()
{
    (void)PRINTF("Error: invalid number of arguments\r\n");
    (void)PRINTF("Usage : wlan-set-csi-filter <opt> <macaddr> <pkt_type> <type> <flag>\r\n");
    (void)PRINTF("opt   : add/delete/clear/dump \r\n");
    (void)PRINTF("add   : All options need to be filled in \r\n");
    (void)PRINTF("delete: Delete recent filter information \r\n");
    (void)PRINTF("clear : Clear all filter information \r\n");
    (void)PRINTF("dump  : Dump csi cfg information \r\n");

    (void)PRINTF("\r\nUsage example : \r\n");
    (void)PRINTF("wlan-set-csi-filter add 00:18:E7:ED:2D:C1 255 255 0 \r\n");
    (void)PRINTF("wlan-set-csi-filter delete \r\n");
    (void)PRINTF("wlan-set-csi-filter clear \r\n");
    (void)PRINTF("wlan-set-csi-filter dump \r\n");
}

void dump_csi_param_header()
{
    (void)PRINTF("\r\nThe current csi_param is: \r\n");
    (void)PRINTF("csi_enable    : %d \r\n", g_csi_params.csi_enable);
    (void)PRINTF("head_id       : %d \r\n", g_csi_params.head_id);
    (void)PRINTF("tail_id       : %d \r\n", g_csi_params.tail_id);
    (void)PRINTF("csi_filter_cnt: %d \r\n", g_csi_params.csi_filter_cnt);
    (void)PRINTF("chip_id       : %d \r\n", g_csi_params.chip_id);
    (void)PRINTF("band_config   : %d \r\n", g_csi_params.band_config);
    (void)PRINTF("channel       : %d \r\n", g_csi_params.channel);
    (void)PRINTF("csi_monitor_enable : %d \r\n", g_csi_params.csi_monitor_enable);
    (void)PRINTF("ra4us         : %d \r\n", g_csi_params.ra4us);

    (void)PRINTF("\r\n");
}

void set_csi_param_header(t_u16 csi_enable,
                          t_u32 head_id,
                          t_u32 tail_id,
                          t_u8 chip_id,
                          t_u8 band_config,
                          t_u8 channel,
                          t_u8 csi_monitor_enable,
                          t_u8 ra4us)
{
    g_csi_params.csi_enable         = csi_enable;
    g_csi_params.head_id            = head_id;
    g_csi_params.tail_id            = tail_id;
    g_csi_params.chip_id            = chip_id;
    g_csi_params.band_config        = band_config;
    g_csi_params.channel            = channel;
    g_csi_params.csi_monitor_enable = csi_monitor_enable;
    g_csi_params.ra4us              = ra4us;

    dump_csi_param_header();
}

void set_csi_filter(t_u8 pkt_type, t_u8 subtype, t_u8 flags, int op_index, t_u8 *mac)
{
    t_u8 temp_filter_cnt = g_csi_params.csi_filter_cnt;
    int i                = 0;

    switch (op_index)
    {
        case CSI_FILTER_OPT_ADD:
            if (temp_filter_cnt < CSI_FILTER_MAX)
            {
                (void)memcpy(&g_csi_params.csi_filter[temp_filter_cnt].mac_addr[0], mac, MLAN_MAC_ADDR_LENGTH);
                g_csi_params.csi_filter[temp_filter_cnt].pkt_type = pkt_type;
                g_csi_params.csi_filter[temp_filter_cnt].subtype  = subtype;
                g_csi_params.csi_filter[temp_filter_cnt].flags    = flags;
                g_csi_params.csi_filter_cnt++;
            }
            else
            {
                (void)PRINTF("max csi filter cnt is 16 \r\n");
                return;
            }
            break;

        case CSI_FILTER_OPT_DELETE:
            if (temp_filter_cnt > 0)
            {
                memset(&g_csi_params.csi_filter[temp_filter_cnt], 0, sizeof(wifi_csi_filter_t));
                g_csi_params.csi_filter_cnt--;
            }
            else
            {
                (void)PRINTF("csi filter cnt is 0 \r\n");
                return;
            }
            break;

        case CSI_FILTER_OPT_CLEAR:
            for (i = 0; i < temp_filter_cnt; i++)
            {
                memset(&g_csi_params.csi_filter[i], 0, sizeof(wifi_csi_filter_t));
            }
            g_csi_params.csi_filter_cnt = 0;
            break;

        case CSI_FILTER_OPT_DUMP:
            dump_csi_param_header();

            for (i = 0; i < temp_filter_cnt; i++)
            {
                (void)PRINTF("mac_addr      : %02X:%02X:%02X:%02X:%02X:%02X \r\n",
                             g_csi_params.csi_filter[i].mac_addr[0], g_csi_params.csi_filter[i].mac_addr[1],
                             g_csi_params.csi_filter[i].mac_addr[2], g_csi_params.csi_filter[i].mac_addr[3],
                             g_csi_params.csi_filter[i].mac_addr[4], g_csi_params.csi_filter[i].mac_addr[5]);

                (void)PRINTF("pkt_type      : %d \r\n", g_csi_params.csi_filter[i].pkt_type);
                (void)PRINTF("subtype       : %d \r\n", g_csi_params.csi_filter[i].subtype);
                (void)PRINTF("flags         : %d \r\n", g_csi_params.csi_filter[i].flags);
                (void)PRINTF("\r\n");
            }
            break;

        default:
            (void)PRINTF("unknown argument!\r\n");
            break;
    }
}

static void test_wlan_set_csi_param_header(int argc, char **argv)
{
    t_u16 csi_enable        = 0;
    t_u32 head_id           = 0;
    t_u32 tail_id           = 0;
    t_u8 chip_id            = 0;
    t_u8 band_config        = 0;
    t_u8 channel            = 0;
    t_u8 csi_monitor_enable = 0;
    t_u8 ra4us              = 0;

    if (argc != 9)
    {
        (void)PRINTF("Error: invalid number of arguments\r\n");
        (void)PRINTF(
            "Usage: %s <csi_enable> <head_id> <tail_id> <chip_id> <band_config> <channel> <csi_monitor_enable> "
            "<ra4us>\r\n\r\n",
            argv[0]);

        (void)PRINTF("[csi_enable] :1/2 to Enable/DisEnable CSI\r\n");
        (void)PRINTF("[head_id, head_id, chip_id] are used to seperate CSI event records received from FW\r\n");
        (void)PRINTF(
            "[Bandcfg] defined as below: \r\n"
            "    Band Info - (00)=2.4GHz, (01)=5GHz \r\n"
            "    t_u8  chanBand    : 2;\r\n"
            "    Channel Width - (00)=20MHz, (10)=40MHz, (11)=80MHz\r\n"
            "    t_u8  chanWidth   : 2;\r\n"
            "    Secondary Channel Offset - (00)=None, (01)=Above, (11)=Below\r\n"
            "    t_u8  chan2Offset : 2;\r\n"
            "    Channel Selection Mode - (00)=manual, (01)=ACS, (02)=Adoption mode\r\n"
            "    t_u8  scanMode    : 2;\r\n");
        (void)PRINTF("[channel] : monitor channel number\r\n");
        (void)PRINTF("[csi_monitor_enable] : 1-csi_monitor enable, 0-MAC filter enable\r\n");
        (void)PRINTF(
            "[ra4us] : 1/0 to Enable/DisEnable CSI data received in cfg channel with mac addr filter, not only RA is "
            "us or other\r\n");

        (void)PRINTF("\r\nUsage example : \r\n");
        (void)PRINTF("wlan-set-csi-param-header 1 66051 66051 170 0 11 1 1\r\n");

        dump_csi_param_header();

        return;
    }

    /*
     * csi param header headid, tailid, chipid are used to seperate CSI event records received from FW.
     * FW adds user configured headid, chipid and tailid for each CSI event record.
     * User could configure these fields and used these fields to parse CSI event buffer and do verification.
     * All the CSI filters share the same CSI param header.
     */
    csi_enable         = (t_u16)atoi(argv[1]);
    head_id            = (t_u32)atoi(argv[2]);
    tail_id            = (t_u32)atoi(argv[3]);
    chip_id            = (t_u8)atoi(argv[4]);
    band_config        = (t_u8)atoi(argv[5]);
    channel            = (t_u8)atoi(argv[6]);
    csi_monitor_enable = (t_u8)atoi(argv[7]);
    ra4us              = (t_u8)atoi(argv[8]);

    set_csi_param_header(csi_enable, head_id, tail_id, chip_id, band_config, channel, csi_monitor_enable, ra4us);
}

static void test_wlan_set_csi_filter(int argc, char **argv)
{
    int ret = 0;
    t_u8 raw_mac[MLAN_MAC_ADDR_LENGTH];
    t_u8 pkt_type = 0;
    t_u8 subtype  = 0;
    t_u8 flags    = 0;
    int op_index  = 0;

    if (argc < 2)
    {
        dump_wlan_csi_filter_usage();
        return;
    }

    if (string_equal("add", argv[1]))
    {
        if (6 == argc)
        {
            ret = get_mac(argv[2], (char *)raw_mac, ':');
            if (ret != 0)
            {
                (void)PRINTF("Error: invalid MAC argument\r\n");
                return;
            }
            if ((memcmp(&raw_mac[0], broadcast_mac, MLAN_MAC_ADDR_LENGTH) == 0) || (raw_mac[0] & 0x01))
            {
                (void)PRINTF("Error: only support unicast mac\r\n");
                return;
            }

            /*
             * pkt_type and subtype are the 802.11 framecontrol pkttype and subtype
             * flags:
             * bit0 reserved, must be 0
             * bit1 set to 1: wait for trigger
             * bit2 set to 1: send csi error event when timeout
             */
            pkt_type = (t_u8)atoi(argv[3]);
            subtype  = (t_u8)atoi(argv[4]);
            flags    = (t_u8)atoi(argv[5]);

            op_index = CSI_FILTER_OPT_ADD;
        }
        else
        {
            dump_wlan_csi_filter_usage();
            return;
        }
    }
    else if (string_equal("delete", argv[1]))
        op_index = CSI_FILTER_OPT_DELETE;
    else if (string_equal("clear", argv[1]))
        op_index = CSI_FILTER_OPT_CLEAR;
    else if (string_equal("dump", argv[1]))
        op_index = CSI_FILTER_OPT_DUMP;
    else
    {
        (void)PRINTF("Unknown argument!\r\n");
        return;
    }

    set_csi_filter(pkt_type, subtype, flags, op_index, raw_mac);
}

static void test_wlan_csi_cfg(int argc, char **argv)
{
    int ret;

    ret = wlan_csi_cfg(&g_csi_params);

    if (ret != WM_SUCCESS)
    {
        (void)PRINTF("Failed to send csi cfg\r\n");
    }
}
#endif

#if defined(CONFIG_11K) || defined(CONFIG_11V) || defined(CONFIG_11R) || defined(CONFIG_ROAMING)
static void test_wlan_rssi_low_threshold(int argc, char **argv)
{
    uint8_t rssi_threshold;

    if (argc < 2)
    {
        (void)PRINTF("Usage: %s <rssi threshold value>\r\n", argv[0]);
        (void)PRINTF("Error: Default value is 70. Specify the value you want to set as threshold.\r\n");
        return;
    }

    errno          = 0;
    rssi_threshold = (uint8_t)strtol(argv[1], NULL, 10);
    if (errno != 0)
    {
        (void)PRINTF("Error during strtoul:rssi_threshold errno:%d\r\n", errno);
        return;
    }

    wlan_set_rssi_low_threshold(rssi_threshold);

    (void)PRINTF("rssi threshold set successfully.\r\n");
}
#endif

#ifdef CONFIG_NET_MONITOR
static void dump_wlan_set_monitor_filter_usage()
{
    (void)PRINTF("Error : invalid arguments\r\n");
    (void)PRINTF("Usage : wlan-set-monitor-filter <opt> <macaddr>\r\n");
    (void)PRINTF("opt   : add/delete/clear/dump \r\n");
    (void)PRINTF("add   : All options need to be filled in \r\n");
    (void)PRINTF("delete: Delete recent mac addr \r\n");
    (void)PRINTF("clear : Clear all mac addr \r\n");
    (void)PRINTF("dump  : Dump monitor cfg information \r\n");

    (void)PRINTF("\r\nUsage example ：\r\n");
    (void)PRINTF("wlan-set-monitor-filter add 64:64:4A:D6:FA:7B \r\n");
    (void)PRINTF("wlan-set-monitor-filter delete \r\n");
    (void)PRINTF("wlan-set-monitor-filter clear  \r\n");
    (void)PRINTF("wlan-set-monitor-filter dump   \r\n");
}

static void dump_monitor_param()
{
    int i = 0;

    (void)PRINTF("\r\n");
    (void)PRINTF("current parameters: \r\n");
    (void)PRINTF("action            : %d \r\n", g_net_monitor_param.action);
    (void)PRINTF("monitor_activity  : %d \r\n", g_net_monitor_param.monitor_activity);
    (void)PRINTF("filter_flags      : %d \r\n", g_net_monitor_param.filter_flags);
    (void)PRINTF("radio_type        : %d \r\n", g_net_monitor_param.radio_type);
    (void)PRINTF("chan_number       : %d \r\n", g_net_monitor_param.chan_number);
    (void)PRINTF("filter_num        : %d \r\n", g_net_monitor_param.filter_num);
    (void)PRINTF("\r\n");

    for (i = 0; i < g_net_monitor_param.filter_num; i++)
    {
        (void)PRINTF("mac_addr      : %02X:%02X:%02X:%02X:%02X:%02X \r\n", g_net_monitor_param.mac_addr[i][0],
                     g_net_monitor_param.mac_addr[i][1], g_net_monitor_param.mac_addr[i][2],
                     g_net_monitor_param.mac_addr[i][3], g_net_monitor_param.mac_addr[i][4],
                     g_net_monitor_param.mac_addr[i][5]);
    }
}

static void test_wlan_set_monitor_param(int argc, char **argv)
{
    if (argc != 6)
    {
        (void)PRINTF("Error             : invalid number of arguments\r\n");
        (void)PRINTF("Usage             : %s <action> <monitor_activity> <filter_flags> <radio_type> <chan_number>\r\n",
                     argv[0]);
        (void)PRINTF("action            : 0/1 to Action Get/Set \r\n");
        (void)PRINTF("monitor_activity  : 1 to enable and other parameters to disable monitor activity \r\n");
        (void)PRINTF("filter_flags      : network monitor fitler flag \r\n");
        (void)PRINTF("chan_number       : channel to monitor \r\n");

        (void)PRINTF("\r\nUsage example ：\r\n");
        (void)PRINTF("wlan-set-monitor-param 1 1 7 0 1 \r\n");

        dump_monitor_param();
        return;
    }

    g_net_monitor_param.action           = (t_u16)atoi(argv[1]);
    g_net_monitor_param.monitor_activity = (t_u16)atoi(argv[2]);

    /*
     * filter_flags:
     * bit 0: (1/0) enable/disable management frame
     * bit 1: (1/0) enable/disable control frame
     * bit 2: (1/0) enable/disable data frame
     */
    g_net_monitor_param.filter_flags = (t_u16)atoi(argv[3]);

    /*
     * radio_type:
     * Band Info - (00)=2.4GHz, (01)=5GHz
     * t_u8  chanBand    : 2;
     * Channel Width - (00)=20MHz, (10)=40MHz, (11)=80MHz
     * t_u8  chanWidth   : 2;
     * Secondary Channel Offset - (00)=None, (01)=Above, (11)=Below
     * t_u8  chan2Offset : 2;
     * Channel Selection Mode - (00)=manual, (01)=ACS, (02)=Adoption mode
     * t_u8  scanMode    : 2;
     */
    g_net_monitor_param.radio_type  = (t_u8)atoi(argv[4]);
    g_net_monitor_param.chan_number = (t_u8)atoi(argv[5]);

    dump_monitor_param();
}

void set_monitor_filter(int op_index, t_u8 *mac)
{
    t_u8 temp_filter_num = g_net_monitor_param.filter_num;

    switch (op_index)
    {
        case MONITOR_FILTER_OPT_ADD_MAC:
            if (temp_filter_num < MAX_MONIT_MAC_FILTER_NUM)
            {
                (void)memcpy(&g_net_monitor_param.mac_addr[temp_filter_num], mac, MLAN_MAC_ADDR_LENGTH);
                g_net_monitor_param.filter_num++;
            }
            else
            {
                (void)PRINTF("Max filter num is 3 \r\n");
                return;
            }
            break;

        case MONITOR_FILTER_OPT_DELETE_MAC:
            if (temp_filter_num > 0)
            {
                memset(&g_net_monitor_param.mac_addr[temp_filter_num], 0, MLAN_MAC_ADDR_LENGTH);
                g_net_monitor_param.filter_num--;
            }
            else
            {
                (void)PRINTF("Monitor filter num is 0 \r\n");
                return;
            }
            break;

        case MONITOR_FILTER_OPT_CLEAR_MAC:
            memset(&g_net_monitor_param.mac_addr[0], 0, MAX_MONIT_MAC_FILTER_NUM * MLAN_MAC_ADDR_LENGTH);
            g_net_monitor_param.filter_num = 0;
            break;

        case MONITOR_FILTER_OPT_DUMP:
            dump_monitor_param();
            break;

        default:
            (void)PRINTF("unknown argument!\r\n");
            break;
    }
}

static void test_wlan_set_monitor_filter(int argc, char **argv)
{
    int ret = 0;
    t_u8 raw_mac[MLAN_MAC_ADDR_LENGTH];
    int op_index = 0;

    if (3 == argc)
    {
        if (string_equal("add", argv[1]))
        {
            ret = get_mac(argv[2], (char *)raw_mac, ':');
            if (ret != 0)
            {
                (void)PRINTF("Error: invalid MAC argument\r\n");
                return;
            }
            if ((memcmp(&raw_mac[0], broadcast_mac, MLAN_MAC_ADDR_LENGTH) == 0) || (raw_mac[0] & 0x01))
            {
                (void)PRINTF("Error: only support unicast mac\r\n");
                return;
            }
            op_index = MONITOR_FILTER_OPT_ADD_MAC;
        }
        else
        {
            dump_wlan_set_monitor_filter_usage();
            return;
        }
    }
    else if (2 == argc)
    {
        if (string_equal("delete", argv[1]))
            op_index = MONITOR_FILTER_OPT_DELETE_MAC;
        else if (string_equal("clear", argv[1]))
            op_index = MONITOR_FILTER_OPT_CLEAR_MAC;
        else if (string_equal("dump", argv[1]))
            op_index = MONITOR_FILTER_OPT_DUMP;
        else
        {
            (void)PRINTF("Unknown argument!\r\n\r\n");
            dump_wlan_set_monitor_filter_usage();
            return;
        }
    }
    else
    {
        dump_wlan_set_monitor_filter_usage();
        return;
    }

    set_monitor_filter(op_index, raw_mac);
}

/* Due to hardware issues, 9177 needs to scan the specified channel
 * that will be monitored before run wlan-net-monitor-cfg
 */
static void test_wlan_net_monitor_cfg(int argc, char **argv)
{
    int ret;

    ret = wlan_net_monitor_cfg(&g_net_monitor_param);

    if (ret != WM_SUCCESS)
    {
        (void)PRINTF("Failed to send monitor cfg\r\n");
    }
}
#endif

#ifdef CONFIG_CPU_TASK_STATUS
void test_wlan_cpu_task_info(int argc, char **argv)
{
    /* Take a snapshot of the number of tasks while this
     * function is executing. */
    uint32_t task_nums       = uxTaskGetNumberOfTasks();
    uint32_t task_status_len = task_nums * sizeof(TaskStatus_t);

    char *CPU_RunInfo = (char *)os_mem_alloc(task_status_len);

    if (!CPU_RunInfo)
    {
        (void)PRINTF("os mem alloc failed for CPU run info \r\n");
        return;
    }

    memset(CPU_RunInfo, 0, task_status_len);
    // Get tasks status
    os_get_task_list(CPU_RunInfo);

    /*Relationship between task status and show info
     *
     * task status   show info
     * tskRUNNING       X
     * tskBLOCKED       B
     * tskREADY         R
     * tskDELETED       D
     * tskSUSPENDED     S
     */
    (void)PRINTF("---------------------------------------------\r\n");
    (void)PRINTF("taskName           Status   priority  freeStack pid\r\n");
    (void)PRINTF("%s", CPU_RunInfo);
    (void)PRINTF("---------------------------------------------\r\n");

    memset(CPU_RunInfo, 0, task_status_len);
    // Get tasks percentage
    os_get_runtime_stats(CPU_RunInfo);
    (void)PRINTF("taskName                runTime         Percentage\r\n");
    (void)PRINTF("%s", CPU_RunInfo);
    (void)PRINTF("---------------------------------------------\r\n\n");

    os_mem_free(CPU_RunInfo);
}
#endif

#ifdef CONFIG_TSP
static void dump_wlan_tsp_cfg_usage()
{
    (void)PRINTF("Usage:\r\n");
    (void)PRINTF("    wlan-set-tsp-cfg enable <enable> backoff <backoff> high <highThreshold> low <lowThreshold>\r\n");
    (void)PRINTF("    <enable>: 0 -- disable   1 -- enable\r\n");
    (void)PRINTF("	  <backoff>: power backoff [0...20]\r\n");
    (void)PRINTF("	  <highThreshold>: High power Threshold [0...300]\r\n");
    (void)PRINTF("	  <lowThreshold>: Low power Threshold [0...300]\r\n");
    (void)PRINTF("	   High Threshold must be greater than Low Threshold\r\n");
    (void)PRINTF("	   If you want to get tsp cfg, you can just use wlan-get-tsp-cfg.\r\n");
}
static void test_wlan_set_tsp_cfg(int argc, char **argv)
{
    int arg = 0;
    unsigned int value;
    t_u16 enable        = 0;
    t_u32 back_off      = 0;
    t_u32 highThreshold = 0;
    t_u32 lowThreshold  = 0;
    int ret             = WM_SUCCESS;

    struct
    {
        unsigned enable : 1;
        unsigned backoff : 1;
        unsigned high : 1;
        unsigned low : 1;
    } info;

    (void)memset(&info, 0, sizeof(info));

    if (argc < 3 || argc > 9)
    {
        (void)PRINTF("Error: invalid number of arguments\r\n");
        dump_wlan_tsp_cfg_usage();
        return;
    }

    arg++;
    do
    {
        if (!info.enable && string_equal("enable", argv[arg]))
        {
            if (get_uint(argv[arg + 1], &value, strlen(argv[arg + 1])) || (value != 0 && value != 1))
            {
                (void)PRINTF("Error: invalid enable argument\r\n");
                dump_wlan_tsp_cfg_usage();
                return;
            }
            arg += 2;
            info.enable = 1;
            enable      = value & 0xFF;
        }
        else if (!info.backoff && string_equal("backoff", argv[arg]))
        {
            if (get_uint(argv[arg + 1], &value, strlen(argv[arg + 1])) || value > 20)
            {
                (void)PRINTF("Error: invalid backoff argument\r\n");
                dump_wlan_tsp_cfg_usage();
                return;
            }
            arg += 2;
            info.backoff = 1;
            back_off     = value;
        }
        else if (!info.high && string_equal("high", argv[arg]))
        {
            if (get_uint(argv[arg + 1], &value, strlen(argv[arg + 1])) || value > 300)
            {
                (void)PRINTF("Error: invalid high threshold argument\r\n");
                dump_wlan_tsp_cfg_usage();
                return;
            }
            arg += 2;
            info.high     = 1;
            highThreshold = value;
        }
        else if (!info.low && string_equal("low", argv[arg]))
        {
            if (get_uint(argv[arg + 1], &value, strlen(argv[arg + 1])) || value > 300)
            {
                (void)PRINTF("Error: invalid low threshold argument\r\n");
                dump_wlan_tsp_cfg_usage();
                return;
            }
            arg += 2;
            info.low     = 1;
            lowThreshold = value;
        }
        else
        {
            (void)PRINTF("Error: invalid [%d] argument\r\n", arg + 1);
            dump_wlan_tsp_cfg_usage();
            return;
        }

    } while (arg < argc);

    if (highThreshold <= lowThreshold)
    {
        (void)PRINTF("Error: High Threshold must be greater than Low Threshold\r\n");
        dump_wlan_tsp_cfg_usage();
        return;
    }
    ret = wlan_set_tsp_cfg(enable, back_off, highThreshold, lowThreshold);

    if (ret != WM_SUCCESS)
    {
        (void)PRINTF("Unable to set TSP config\r\n");
        return;
    }
}

static void test_wlan_get_tsp_cfg(int argc, char **argv)
{
    t_u16 enable        = 0;
    t_u32 back_off      = 0;
    t_u32 highThreshold = 0;
    t_u32 lowThreshold  = 0;
    int ret             = WM_SUCCESS;

    if (argc != 1)
    {
        dump_wlan_tsp_cfg_usage();
        return;
    }

    ret = wlan_get_tsp_cfg(&enable, &back_off, &highThreshold, &lowThreshold);

    if (ret != WM_SUCCESS)
    {
        (void)PRINTF("Unable to get TSP config\r\n");
        return;
    }

    (void)PRINTF("TSP Configuration:\r\n");
    (void)PRINTF("	Enable TSP Algorithm: %d\r\n", enable);
    (void)PRINTF("		0: disable 1: enable\r\n");
    (void)PRINTF("	Power Management Backoff: %d dB\r\n", back_off);
    (void)PRINTF("	Low Power BOT Threshold: %d °C\r\n", lowThreshold);
    (void)PRINTF("	High Power BOT Threshold: %d °C\r\n", highThreshold);
}
#endif

#ifdef STA_SUPPORT
static void test_wlan_get_signal(int argc, char **argv)
{
    wlan_rssi_info_t signal;
    int ret = WM_SUCCESS;

    if (!is_sta_connected())
    {
        (void)PRINTF("Can not get RSSI information in disconnected state\r\n");
        return;
    }

    (void)memset(&signal, 0, sizeof(wlan_rssi_info_t));

    ret = wlan_get_signal_info(&signal);
    if (ret != WM_SUCCESS)
    {
        (void)PRINTF("Unable to get RSSI information\r\n");
        return;
    }
    (void)PRINTF("\tBeaconLast\tBeacon Average\tData Last\tData Average\r\n");
    (void)PRINTF("RSSI\t%-10d \t%-10d \t%-10d \t%-10d\r\n", (int)signal.bcn_rssi_last, (int)signal.bcn_rssi_avg,
                 (int)signal.data_rssi_last, (int)signal.data_rssi_avg);
    (void)PRINTF("SNR \t%-10d \t%-10d \t%-10d \t%-10d\r\n", (int)signal.bcn_snr_last, (int)signal.bcn_snr_avg,
                 (int)signal.data_snr_last, (int)signal.data_snr_avg);
    (void)PRINTF("NF  \t%-10d \t%-10d \t%-10d \t%-10d\r\n", (int)signal.bcn_nf_last, (int)signal.bcn_nf_avg,
                 (int)signal.data_nf_last, (int)signal.data_nf_avg);
}
#endif

#ifdef CONFIG_WIFI_FORCE_RTS
#define HOSTCMD_RESP_BUFF_SIZE 1024
u8_t debug_resp_buf[HOSTCMD_RESP_BUFF_SIZE] = {0};

static void dump_wlan_set_forceRTS_usage(void)
{
    (void)PRINTF("Usage:\r\n");
    (void)PRINTF("    wlan-set-forceRTS <0/1>\r\n");
    (void)PRINTF("    <start/stop>: 1 -- start forceRTS\r\n");
    (void)PRINTF("                  0 -- stop forceRTS\r\n");
    (void)PRINTF("Example:\r\n");
    (void)PRINTF("    wlan-set-forceRTS\r\n");
    (void)PRINTF("    - Get current forceRTS state.\r\n");
    (void)PRINTF("    wlan-set-forceRTS 1\r\n");
    (void)PRINTF("    - Set start forceRTS\r\n");
}

/* Bypass wmmTurboMode TxopLimit setting if for certificate is true, for BE traffic only. (Case: HE 5.71.1) */
static void test_wlan_set_forceRTS(int argc, char **argv)
{
    int ret           = -WM_FAIL;
    uint32_t reqd_len = 0;
    uint8_t state;
    /**
     * Command taken from debug.conf
     * start_forceRTS={
     *      CmdCode=0x008b
     *      Action:2=1
     *      SUBID:2=0x104
     *      Value:1=1           # 1 -- start forceRTS;
     *                          # 0 -- stop forceRTS;
     */
    uint8_t debug_cmd_buf[] = {0x8b, 0, 0x0d, 0, 0, 0, 0, 0, 0x01, 0, 0x04, 0x01, 0x01};

    if (argc > 2)
    {
        (void)PRINTF("Error: invalid number of arguments\r\n");
        dump_wlan_set_forceRTS_usage();
        return;
    }

    /* SET */
    if (argc == 2)
    {
        state             = atoi(argv[1]);
        debug_cmd_buf[12] = state;
    }
    else /* GET */
    {
        dump_wlan_set_forceRTS_usage();
        debug_cmd_buf[8] = 0;
    }

    ret = wlan_send_hostcmd(debug_cmd_buf, sizeof(debug_cmd_buf) / sizeof(u8_t), debug_resp_buf, HOSTCMD_RESP_BUFF_SIZE,
                            &reqd_len);

    if (ret == WM_SUCCESS)
    {
        (void)PRINTF("Hostcmd success, response is\r\n");
        for (ret = 0; ret < reqd_len; ret++)
            (void)PRINTF("%x\t", debug_resp_buf[ret]);
    }
    else
    {
        (void)PRINTF("Hostcmd failed error: %d", ret);
    }
}
#endif

#if defined(CONFIG_IPS)
static void dump_wlan_set_ips_usage()
{
    (void)PRINTF("Usage:\r\n");
    (void)PRINTF("wlan-set-ips option\r\n");
    (void)PRINTF("option:\r\n");
    (void)PRINTF("0: disable ips enhance\r\n");
    (void)PRINTF("1: enable ips enhance\r\n");
}
static void test_wlan_set_ips(int argc, char **argv)
{
    unsigned int option;

    if (argc != 2)
    {
        (void)PRINTF("Error: invalid number of arguments\r\n");
        dump_wlan_set_ips_usage();
        return;
    }

    if (get_uint(argv[1], &option, strlen(argv[1])))
    {
        (void)PRINTF("Error: invalid option argument\r\n");
        dump_wlan_set_ips_usage();
        return;
    }

    if (option != 0 && option != 1)
    {
        (void)PRINTF("Error: invalid option argument\r\n");
        dump_wlan_set_ips_usage();
        return;
    }

    wlan_set_ips(option);
}
#endif

static struct cli_command tests[] = {
    {"wlan-set-mac", "<MAC_Address>", test_wlan_set_mac_address},
    {"wlan-scan", NULL, test_wlan_scan},
    {"wlan-scan-opt", "ssid <ssid> bssid ...", test_wlan_scan_opt},
    {"wlan-add", "<profile_name> ssid <ssid> bssid...", test_wlan_add},
    {"wlan-remove", "<profile_name>", test_wlan_remove},
    {"wlan-list", NULL, test_wlan_list},
    {"wlan-connect", "<profile_name>", test_wlan_connect},
    {"wlan-start-network", "<profile_name>", test_wlan_start_network},
    {"wlan-stop-network", NULL, test_wlan_stop_network},
    {"wlan-disconnect", NULL, test_wlan_disconnect},
    {"wlan-stat", NULL, test_wlan_stat},
    {"wlan-info", NULL, test_wlan_info},
    {"wlan-address", NULL, test_wlan_address},
    {"wlan-get-uap-channel", NULL, test_wlan_get_uap_channel},
    {"wlan-get-uap-sta-list", NULL, test_wlan_get_uap_sta_list},
    {"wlan-ieee-ps", "<0/1>", test_wlan_ieee_ps},
    {"wlan-deep-sleep-ps", "<0/1>", test_wlan_deep_sleep_ps},
#if defined(CONFIG_WIFIDRIVER_PS_LOCK) && defined(CONFIG_WNM_PS)
    {"wlan-wnm-ps", "<0/1> <sleep_interval>", test_wlan_wnm_ps},
#endif
#ifdef CONFIG_WIFI_MAX_CLIENTS_CNT
    {"wlan-set-max-clients-count", "<max clients count>", test_wlan_set_max_clients_count},
#endif
#ifdef CONFIG_WIFI_HIDDEN_SSID
    {"wlan-set-hidden-ssid", "<0/1>", test_wlan_set_hidden_ssid},
#endif
#ifdef CONFIG_WIFI_RTS_THRESHOLD
    {"wlan-rts", "<sta/uap> <rts threshold>", test_wlan_set_rts},
#endif
#ifdef CONFIG_WIFI_FRAG_THRESHOLD
    {"wlan-frag", "<sta/uap> <fragment threshold>", test_wlan_set_frag},
#endif
#ifdef CONFIG_11K_OFFLOAD
    {"wlan-11k-enable", "<0/1>", test_wlan_11k_cfg},
    {"wlan-11k-neighbor-req", NULL, test_wlan_11k_neighbor_req},
#endif
#ifdef CONFIG_11K
    {"wlan-host-11k-enable", "<0/1>", test_wlan_host_11k_cfg},
    {"wlan-host-11k-neighbor-req", "[ssid <ssid>]", test_wlan_host_11k_neighbor_request},
#endif
#ifdef CONFIG_11V
    {"wlan-host-11v-bss-trans-query", "<0..16>", test_wlan_host_11v_bss_trans_query},
#endif
#ifdef CONFIG_MBO
    {"wlan-mbo-enable", "<0/1>", test_wlan_mbo_cfg},
    {"wlan-mbo-nonprefer-ch", "<ch0> <Preference0: 0/1/255> <ch1> <Preference1: 0/1/255>",
     test_wlan_mbo_non_prefer_chs},
#endif
#ifdef CONFIG_UAP_STA_MAC_ADDR_FILTER
    {"wlan-sta-filter", " <filter mode> [<mac address list>]", test_wlan_set_sta_filter},
#endif
#ifdef CONFIG_WIFI_GET_LOG
    {"wlan-get-log", "<sta/uap> <ext>", test_wlan_get_log},
#endif
#ifdef CONFIG_WIFI_TX_PER_TRACK
    {"wlan-tx-pert", "<0/1> <STA/AP> <p> <r> <n>", test_wlan_tx_pert},
#endif
#ifdef CONFIG_ROAMING
    {"wlan-roaming", "<0/1>", test_wlan_roaming},
#endif
#ifdef CONFIG_MEF_CFG
    {"wlan-multi-mef", "<ping/arp/multicast/del> [<action>]", test_wlan_set_multiple_mef_config},
    {"wlan-host-sleep", "<0/1> mef/[wowlan_test <0/1>]", test_wlan_host_sleep},
#else
    {"wlan-host-sleep", "<0/1> wowlan_test <0/1>", test_wlan_host_sleep},
#endif
    {"wlan-send-hostcmd", NULL, test_wlan_send_hostcmd},
#if !defined(SD8801)
#ifdef CONFIG_11AC
    {"wlan-set-uap-bandwidth", "<1/2/3> 1:20 MHz 2:40MHz 3:80MHz", test_wlan_set_uap_bandwidth},
#else
    {"wlan-set-uap-bandwidth", "<1/2> 1:20 MHz 2:40MHz", test_wlan_set_uap_bandwidth},
#endif
#endif
#ifdef SD8801
    {"wlan-8801-enable-ext-coex", NULL, test_wlan_8801_enable_ext_coex},
    {"wlan-8801-get-ext-coex-stats", NULL, test_wlan_8801_ext_coex_stats},
#endif
#ifdef CONFIG_WIFI_EU_CRYPTO
    {"wlan-eu-crypto", "<EncDec>", test_wlan_eu_crypto},
#endif
#ifdef CONFIG_WIFI_MEM_ACCESS
    {"wlan-mem-access", "<memory_address> [<value>]", test_wlan_mem_access},
#endif
#ifdef CONFIG_HEAP_STAT
    {"heap-stat", NULL, test_heap_stat},
#endif
#ifdef CONFIG_EU_VALIDATION
    {"wlan-eu-validation", "<value>", test_wlan_eu_validation},
#endif
#ifdef CONFIG_HEAP_DEBUG
    {"wlan-os-mem-stat", NULL, test_wlan_os_mem_stat},
#endif
#ifdef CONFIG_MULTI_CHAN
    {"wlan-set-mc-policy", "<0/1>(disable/enable)", test_wlan_set_multi_chan_status},
    {"wlan-get-mc-policy", NULL, test_wlan_get_multi_chan_status},
    {"wlan-set-drcs",
     "<channel_time> <switch_time> <undoze_time> <mode> [<channel_time> <switch_time> <undoze_time> <mode>]",
     test_wlan_set_drcs_cfg},
    {"wlan-get-drcs", NULL, test_wlan_get_drcs_cfg},
#endif
#ifdef CONFIG_11R
    {"wlan-ft-roam", "<bssid> <channel>", test_wlan_ft_roam},
#endif
#ifndef STREAM_2X2
    {"wlan-set-antcfg", "<ant mode> [evaluate_time]", wlan_antcfg_set},
    {"wlan-get-antcfg", NULL, wlan_antcfg_get},
#endif
#ifdef CONFIG_EXT_SCAN_SUPPORT
    {"wlan-scan-channel-gap", "<channel_gap_value>", test_wlan_set_scan_channel_gap},
#endif
#if defined(CONFIG_WMM) && defined(CONFIG_WMM_ENH)
    {"wlan-wmm-stat", "<bss_type>", test_wlan_wmm_tx_stats},
#endif
#if defined(RW610) && defined(CONFIG_WIFI_RESET)
    {"wlan-reset", NULL, test_wlan_reset},
#endif
    {"wlan-set-regioncode", "<region-code>", test_wlan_set_regioncode},
    {"wlan-get-regioncode", NULL, test_wlan_get_regioncode},
#ifdef CONFIG_ECSA
    {"wlan-uap-set-ecsa-cfg", "<block_tx> <oper_class> <new_channel> <switch_count> <bandwidth>",
     test_wlan_uap_set_ecsa_cfg},
#endif
#ifdef CONFIG_CSI
    {"wlan-csi-cfg", NULL, test_wlan_csi_cfg},
    {"wlan-set-csi-param-header",
     " <csi_enable> <head_id> <tail_id> <chip_id> <band_config> <channel> <csi_monitor_enable> <ra4us>",
     test_wlan_set_csi_param_header},
    {"wlan-set-csi-filter", "<opt> <macaddr> <pkt_type> <type> <flag>", test_wlan_set_csi_filter},
#endif
#ifdef CONFIG_TX_RX_HISTOGRAM
    {"wlan-txrx-histogram", "<action> <enable>", test_wlan_txrx_histogram},
#endif
#ifdef CONFIG_SUBSCRIBE_EVENT_SUPPORT
    {"wlan-subscribe-event", "<action> <type> <value> <freq>", test_wlan_subscribe_event},
#endif
#ifdef CONFIG_WIFI_REG_ACCESS
    {"wlan-reg-access", "<type> <offset> [value]", test_wlan_reg_access},
#endif
#ifdef CONFIG_WMM_UAPSD
    {"wlan-uapsd-enable", "<uapsd_enable>", test_wlan_set_wmm_uapsd},
    {"wlan-uapsd-qosinfo", "<qos_info>", test_wlan_wmm_uapsd_qosinfo},
    {"wlan-uapsd-sleep-period", "<sleep_period>", test_wlan_sleep_period},
#endif
#if defined(RW610)
#ifdef CONFIG_WIFI_AMPDU_CTRL
    {"wlan-ampdu-enable", "<sta/uap> <xx: rx/tx bit map. Tx(bit 0), Rx(bit 1> <xx: TID bit map>",
     test_wlan_ampdu_enable},
#endif
#ifdef CONFIG_TX_AMPDU_PROT_MODE
    {"wlan-tx-ampdu-prot-mode", "<mode>", test_wlan_tx_ampdu_prot_mode},
#endif
#endif
#if defined(CONFIG_11K) || defined(CONFIG_11V) || defined(CONFIG_11R) || defined(CONFIG_ROAMING)
    {"wlan-rssi-low-threshold", "<threshold_value>", test_wlan_rssi_low_threshold},
#endif
#ifdef CONFIG_NET_MONITOR
    {"wlan-net-monitor-cfg", NULL, test_wlan_net_monitor_cfg},
    {"wlan-set-monitor-filter", "<opt> <macaddr>", test_wlan_set_monitor_filter},
    {"wlan-set-monitor-param", "<action> <monitor_activity> <filter_flags> <radio_type> <chan_number>",
     test_wlan_set_monitor_param},
#endif
#ifdef CONFIG_TSP
    {"wlan-set-tsp-cfg", "<enable> <backoff> <highThreshold> <lowThreshold>", test_wlan_set_tsp_cfg},
    {"wlan-get-tsp-cfg", NULL, test_wlan_get_tsp_cfg},
#endif
#ifdef CONFIG_CPU_TASK_STATUS
    {"wlan-cpu-task-info", NULL, test_wlan_cpu_task_info},
#endif
#ifdef STA_SUPPORT
    {"wlan-get-signal", NULL, test_wlan_get_signal},
#endif
#if defined(CONFIG_IPS)
    {"wlan-set-ips", "<option>", test_wlan_set_ips},
#endif
#ifdef CONFIG_WIFI_FORCE_RTS
    {"wlan-set-forceRTS", "<0/1>", test_wlan_set_forceRTS},
#endif
    {"wlan-set-toltime", "<value>", test_wlan_set_toltime},
};

/* Register our commands with the MTF. */
int wlan_cli_init(void)
{
    int i;

    i = wlan_basic_cli_init();
    if (i != WLAN_ERROR_NONE)
    {
        return i;
    }

    if (cli_register_commands(tests, (int)(sizeof(tests) / sizeof(struct cli_command))) != 0)
    {
        return -WM_FAIL;
    }

    return WM_SUCCESS;
}
