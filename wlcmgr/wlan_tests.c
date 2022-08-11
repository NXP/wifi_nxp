/** @file wlan_tests.c
 *
 *  @brief  This file provides WLAN Test API
 *
 *  Copyright 2008-2022 NXP
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
        return WM_FAIL;
    }

    switch (type)
    {
        case WLAN_SECURITY_WPA:
        case WLAN_SECURITY_WPA2:
            /* copy the PSK phrase */
            sec->psk_len = (uint8_t)strlen(argv[0]);
            if (sec->psk_len < WLAN_PSK_MIN_LENGTH)
            {
                return WM_FAIL;
            }
            if (sec->psk_len < sizeof(sec->psk))
            {
                (void)strcpy(sec->psk, argv[0]);
            }
            else
            {
                return WM_FAIL;
            }
            sec->type = type;
            break;
        default:
            ret = WM_FAIL;
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
        "    wlan-add <profile_name> ssid <ssid> [owe_only]"
        "\r\n");
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
    (void)PRINTF("    [wpa2 <secret>] [wpa3 sae <secret>]\r\n");
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
        unsigned role : 1;
        unsigned mfpc : 1;
        unsigned mfpr : 1;
#ifdef CONFIG_WIFI_DTIM_PERIOD
        unsigned dtim : 1;
#endif
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
        else if ((info.security == 0U) && string_equal("wpa2", argv[arg]))
        {
            if (get_security(argc - arg - 1, argv + arg + 1, WLAN_SECURITY_WPA2, &network.security) != 0)
            {
                (void)PRINTF(
                    "Error: invalid WPA2 security"
                    " argument\r\n");
                return;
            }
            arg += 2;
            info.security++;
        }
#ifdef CONFIG_OWE
        else if (!info.security && string_equal("owe_only", argv[arg]))
        {
            network.security.type = WLAN_SECURITY_OWE_ONLY;
            arg += 2;
            info.security++;
        }
#endif
        else if ((info.security2 == 0U) && string_equal("wpa3", argv[arg]))
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
                arg += 3;
            }
            else
            {
                (void)PRINTF(
                    "Error: invalid WPA3 security"
                    " argument\r\n");
                return;
            }
            info.security2++;
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
#ifdef CONFIG_WNM_PS
    unsigned int wnm_set      = 0;
    unsigned int wnm_interval = 0;
#endif

    if (argc < 2)
    {
        (void)PRINTF("Usage: %s <0/1>\r\n", argv[0]);
        (void)PRINTF("Error: Specify 0 to Disable or 1 to Enable\r\n");
        (void)PRINTF("If <WNM> <sleep_interval> is specified, fw will enable WNM and use sleep_interval\r\n");
        (void)PRINTF("Example:\r\n");
        (void)PRINTF("	  wlan-ieee-ps 1 WNM 5\r\n");
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
#ifdef CONFIG_WNM_PS
        if (argc == 4)
        {
            if ((string_equal("WNM", argv[2])) && (get_uint(argv[3], &wnm_interval, strlen(argv[3])) == 0))
                wnm_set = 1;
            else
            {
                (void)PRINTF("Error: Only WNM <sleep_interval> is allowed for input\r\n");
                return;
            }
        }
#endif
        condition = (uint32_t)WAKE_ON_ARP_BROADCAST | (uint32_t)WAKE_ON_UNICAST | (uint32_t)WAKE_ON_MULTICAST |
                    (uint32_t)WAKE_ON_MAC_EVENT;
#ifdef CONFIG_WNM_PS
        ret = wlan_ieeeps_on(condition, (bool)wnm_set, (t_u16)wnm_interval);
#else
        ret = wlan_ieeeps_on(condition);
#endif
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
    (void)PRINTF("Example:\r\n");
    (void)PRINTF("    wlan-tx-pert 1 AP 5 3 5\r\n");
}

static void test_wlan_tx_pert(int argc, char **argv)
{
    struct wlan_tx_pert_info tx_pert;
    int bss_type;

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

#ifdef CONFIG_ROAMING
#define DEFAULT_RSSI_THRESHOLD 70
static void dump_wlan_roaming_usage(void)
{
    (void)PRINTF("Usage:\r\n");
    (void)PRINTF(
        "    wlan-roaming <0/1> rssi_low <rssi_threshold>"
        "\r\n");
    (void)PRINTF("rssi_low is optional. Use default value 70 if not provided \r\n");
    (void)PRINTF("Example:\r\n");
    (void)PRINTF("    wlan-roaming 1 rssi_low 70\r\n");
}

static void test_wlan_roaming(int argc, char **argv)
{
    int enable   = 0;
    int rssi_low = 0;

    if (argc < 2)
    {
        dump_wlan_roaming_usage();
        (void)PRINTF("Error: invalid number of arguments\r\n");
        return;
    }
    enable = atoi(argv[1]);
    if (enable)
    {
        if (argc == 4 && string_equal("rssi_low", argv[2]))
            rssi_low = atoi(argv[3]);
        else
            rssi_low = DEFAULT_RSSI_THRESHOLD;
    }
    wlan_set_roaming(enable, rssi_low);
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
    int bss_type = 0;

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
    int bss_type = 0;

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

#ifdef CONFIG_11K
static void test_wlan_11k_cfg(int argc, char **argv)
{
    int enable_11k;
    int ret;

    if (argc != 2)
    {
        (void)PRINTF("Usage: %s <0/1> < 0--disable 11k; 1---enable 11k>\r\n", argv[0]);
        return;
    }

    enable_11k = atoi(argv[1]);

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
    int bss_type = 0;

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

static void test_wlan_host_sleep(int argc, char **argv)
{
    int choice = -1, wowlan = 0;
    int ret = -WM_FAIL;

    if (argc < 2)
    {
        (void)PRINTF("Usage: %s <0/1> wowlan_test <0/1>\r\n", argv[0]);
        return;
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
        if (argc < 4)
        {
            (void)PRINTF("Usage: %s <0/1> wowlan_test <0/1>\r\n", argv[0]);
            return;
        }

        errno  = 0;
        wowlan = (int)strtol(argv[3], NULL, 10);
        if (errno != 0)
        {
            (void)PRINTF("Error during strtoul:wowlan errno:%d\r\n", errno);
        }

        if (string_equal(argv[2], "wowlan_test"))
        {
            if (wowlan == 1)
            {
                ret = wlan_send_host_sleep(HOST_SLEEP_NO_COND);
                if (ret == WM_SUCCESS)
                {
                    (void)PRINTF("Host sleep configuration successs for wowlan test");
                }
                else
                {
                    (void)PRINTF("Failed to host sleep configuration, error: %d", ret);
                }
            }
            else if (wowlan == 0)
            {
                ret = wlan_send_host_sleep((uint32_t)WAKE_ON_ARP_BROADCAST | (uint32_t)WAKE_ON_UNICAST |
                                           (uint32_t)WAKE_ON_MULTICAST | (uint32_t)WAKE_ON_MAC_EVENT);
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
                /*Do Nothing*/
            }
        }
        else
        {
            (void)PRINTF("Usage: %s <0/1> wowlan_test <0/1>\r\n", argv[0]);
            return;
        }
    }
    else
    {
        (void)PRINTF("Usage: %s <0/1> wowlan_test <0/1>\r\n", argv[0]);
        return;
    }
}

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
    t_u32 value;
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
    u8_t cmd_eu_buf[] = {0x02, 0x34, 0x0c, 0, 0, 0, 0, 0, 0x04, 0, 0x05, 0};
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
        (void)PRINTF("Hostcmd success, response is");
        for (ret = 0; ret < reqd_len; ret++)
        {
            (void)PRINTF("%x\t", host_cmd_resp_buf[ret]);
            host_cmd_resp_buf[ret] = 0;
        }
    }
    else
        (void)PRINTF("Hostcmd failed error: %d", ret);
}
#endif

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

static struct cli_command tests[] = {
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
#ifdef CONFIG_WNM_PS
    {"wlan-ieee-ps", "<0/1> <WNM> <sleep_interval>", test_wlan_ieee_ps},
#else
    {"wlan-ieee-ps", "<0/1>", test_wlan_ieee_ps},
#endif
    {"wlan-deep-sleep-ps", "<0/1>", test_wlan_deep_sleep_ps},
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
#ifdef CONFIG_11K
    {"wlan-11k-enable", "<0/1>", test_wlan_11k_cfg},
    {"wlan-11k-neighbor-req", NULL, test_wlan_11k_neighbor_req},
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
    {"wlan-roaming", "<0/1> rssi_low <rssi_threshold>", test_wlan_roaming},
#endif
    {"wlan-host-sleep", "<0/1> wowlan_test <0/1>", test_wlan_host_sleep},
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
