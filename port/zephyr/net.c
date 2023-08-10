/**
 * @file net.c
 * Shim layer between wifi driver connection manager and zephyr
 * ethernet L2 layer
 */

#include <zephyr/net/ethernet.h>
#include <zephyr/net/net_pkt.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/dns_resolve.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/device.h>
#include <soc.h>
#include <ethernet/eth_stats.h>
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(wifi_nxp, CONFIG_WIFI_LOG_LEVEL);

#include "wlan_bt_fw.h"
#include "wlan.h"
#include "wpl.h"
#include "wifi.h"
#include <wm_os.h>
#include "netif_decl.h"
#include "wm_net.h"
#include "dhcp-server.h"
#include "wifi_shell.h"
#ifdef CONFIG_WPA_SUPP
#include "wifi_nxp.h"

#ifdef CONFIG_IPV6
#define IPV6_ADDR_STATE_TENTATIVE  "Tentative"
#define IPV6_ADDR_STATE_PREFERRED  "Preferred"
#define IPV6_ADDR_STATE_INVALID    "Invalid"
#define IPV6_ADDR_STATE_VALID      "Valid"
#define IPV6_ADDR_STATE_DEPRECATED "Deprecated"
#define IPV6_ADDR_TYPE_LINKLOCAL   "Link-Local"
#define IPV6_ADDR_TYPE_GLOBAL      "Global"
#define IPV6_ADDR_TYPE_UNIQUELOCAL "Unique-Local"
#define IPV6_ADDR_TYPE_SITELOCAL   "Site-Local"
#define IPV6_ADDR_UNKNOWN          "Unknown"
#endif

extern const rtos_wpa_supp_dev_ops wpa_supp_ops;
#endif

#define net_e(...) wmlog_e("net", ##__VA_ARGS__)

#ifdef CONFIG_NET_DEBUG
#define net_d(...) wmlog("net", ##__VA_ARGS__)
#else
#define net_d(...)
#endif /* ! CONFIG_NET_DEBUG */

#ifdef CONFIG_IPV6
#define DHCP_TIMEOUT (60 * 1000)
#else
#define DHCP_TIMEOUT (120 * 1000)
#endif

/*******************************************************************************
 * Definitions
 ******************************************************************************/

#define MAX_JSON_NETWORK_RECORD_LENGTH 185

#define WPL_SYNC_TIMEOUT_MS K_FOREVER

#define UAP_NETWORK_NAME "uap-network"

#define EVENT_BIT(event) (1 << event)

#define WPL_SYNC_INIT_GROUP EVENT_BIT(WLAN_REASON_INITIALIZED) | EVENT_BIT(WLAN_REASON_INITIALIZATION_FAILED)

#define WPL_SYNC_CONNECT_GROUP                                                                  \
    EVENT_BIT(WLAN_REASON_SUCCESS) | EVENT_BIT(WLAN_REASON_CONNECT_FAILED) |                    \
        EVENT_BIT(WLAN_REASON_NETWORK_NOT_FOUND) | EVENT_BIT(WLAN_REASON_NETWORK_AUTH_FAILED) | \
        EVENT_BIT(WLAN_REASON_ADDRESS_FAILED)

#define WPL_SYNC_DISCONNECT_GROUP EVENT_BIT(WLAN_REASON_USER_DISCONNECT)

#define WPL_SYNC_UAP_START_GROUP EVENT_BIT(WLAN_REASON_UAP_SUCCESS) | EVENT_BIT(WLAN_REASON_UAP_START_FAILED)

#define WPL_SYNC_UAP_STOP_GROUP EVENT_BIT(WLAN_REASON_UAP_STOPPED) | EVENT_BIT(WLAN_REASON_UAP_STOP_FAILED)

#define EVENT_SCAN_DONE     23
#define WPL_SYNC_SCAN_GROUP EVENT_BIT(EVENT_SCAN_DONE)

typedef enum _wpl_state
{
    WPL_NOT_INITIALIZED,
    WPL_INITIALIZED,
    WPL_STARTED,
} wpl_state_t;

enum netif_mac_filter_action {
  /** Delete a filter entry */
  NET_IF_DEL_MAC_FILTER = 0,
  /** Add a filter entry */
  NET_IF_ADD_MAC_FILTER = 1
};

/*******************************************************************************
 * Variables
 ******************************************************************************/
static wpl_state_t s_wplState            = WPL_NOT_INITIALIZED;
static bool s_wplStaConnected            = false;
static bool s_wplUapActivated            = false;
static struct k_event s_wplSyncEvent;
static linkLostCb_t s_linkLostCb         = NULL;

/*******************************************************************************
 * Prototypes
 ******************************************************************************/
int wlan_event_callback(enum wlan_event_reason reason, void *data);
static int WLP_process_results(unsigned int count);
static void LinkStatusChangeCallback(bool linkState);

static int igmp_mac_filter(struct netif *netif, const struct in_addr *group, enum netif_mac_filter_action action);

#ifdef CONFIG_IPV6
static int mld_mac_filter(struct netif *netif, const struct in6_addr *group, enum netif_mac_filter_action action);
#endif

uint16_t g_data_nf_last;
uint16_t g_data_snr_last;

static t_u8 rfc1042_eth_hdr[MLAN_MAC_ADDR_LENGTH] =
	{0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00};

typedef struct {
    struct net_if *netif;
    struct net_addr ipaddr;
    struct net_addr nmask;
    struct net_addr gw;
    struct ethernetif state;
    scan_result_cb_t scan_cb;
} interface_t;

static struct net_mgmt_event_callback net_event_v4_cb;
#define DHCPV4_MASK (NET_EVENT_IPV4_DHCP_BOUND | NET_EVENT_IPV4_DHCP_STOP)
#define MCASTV4_MASK (NET_EVENT_IPV4_MADDR_ADD | NET_EVENT_IPV4_MADDR_DEL)

#ifdef CONFIG_IPV6
static struct net_mgmt_event_callback net_event_v6_cb;
#define MCASTV6_MASK (NET_EVENT_IPV6_MADDR_ADD | NET_EVENT_IPV6_MADDR_DEL)
#endif

static interface_t g_mlan;
static interface_t g_uap;

static int net_wlan_init_done = 0;
static os_timer_t dhcp_timer;

void deliver_packet_above(struct net_pkt *p, int recv_interface)
{
    int lwiperr = 0;
    /* points to packet payload, which starts with an Ethernet header */
    struct net_eth_hdr *ethhdr = NET_ETH_HDR(p);

    switch (htons(ethhdr->type))
    {
        case NET_ETH_PTYPE_IP:
#ifdef CONFIG_IPV6
        case NET_ETH_PTYPE_IPV6:
#endif
        case NET_ETH_PTYPE_ARP:
            if (recv_interface >= MAX_INTERFACES_SUPPORTED)
            {
                while (true)
                {
                    ;
                }
            }

            /* full packet send to tcpip_thread to process */
            if (recv_interface == WLAN_BSS_TYPE_UAP)
                lwiperr = net_recv_data(g_uap.netif, p);
            else
                lwiperr = net_recv_data(g_mlan.netif, p);
            if (lwiperr != 0)
            {
                LOG_ERR("Net input error");
                (void)net_pkt_unref(p);
                p = NULL;
            }
            break;
        case ETHTYPE_EAPOL:

            (void)net_pkt_unref(p);
            p = NULL;
            break;
        default:
            /* drop the packet */
            (void)net_pkt_unref(p);
            p = NULL;
            break;
    }
}

static struct net_pkt *gen_pkt_from_data(t_u8 interface, t_u8 *payload, t_u16 datalen)
{
    struct net_pkt *pkt = NULL;
    struct net_eth_hdr *ethhdr = (struct net_eth_hdr *)payload;
    t_u8 llc = 0;

    if (!memcmp((t_u8 *)payload + SIZEOF_ETH_HDR, rfc1042_eth_hdr, sizeof(rfc1042_eth_hdr)))
    {
        struct eth_llc_hdr *ethllchdr = (struct eth_llc_hdr *)(void *)((t_u8 *)payload + SIZEOF_ETH_HDR);
        ethhdr->type                  = ethllchdr->type;
	datalen -= SIZEOF_ETH_LLC_HDR;
        llc = 1;
    }

    /* TODO: port wifi_netif.c and use netif_arr[] */
    /* We allocate a network buffer */
    if (interface == WLAN_BSS_TYPE_UAP)
        pkt = net_pkt_rx_alloc_with_buffer(g_uap.netif, datalen, AF_UNSPEC, 0, K_NO_WAIT);
    else
        pkt = net_pkt_rx_alloc_with_buffer(g_mlan.netif, datalen, AF_UNSPEC, 0, K_NO_WAIT);

    if (pkt == NULL)
    {
        return NULL;
    }

    if (llc)
    {
        if (net_pkt_write(pkt, payload, SIZEOF_ETH_HDR) != 0) {
	    net_pkt_unref(pkt);
	    pkt = NULL;
        }
        if (net_pkt_write(pkt, payload + SIZEOF_ETH_HDR + SIZEOF_ETH_LLC_HDR, datalen - SIZEOF_ETH_HDR) != 0) {
	    net_pkt_unref(pkt);
	    pkt = NULL;
        }
    }
    else if (net_pkt_write(pkt, payload, datalen) != 0) {
	    net_pkt_unref(pkt);
	    pkt = NULL;
    }
    return pkt;
}

static void process_data_packet(const t_u8 *rcvdata, const t_u16 datalen)
{
    RxPD *rxpd                   = (RxPD *)(void *)((t_u8 *)rcvdata + INTF_HEADER_LEN);
    mlan_bss_type recv_interface = (mlan_bss_type)(rxpd->bss_type);

    if (rxpd->rx_pkt_type == PKT_TYPE_AMSDU)
    {
        (void)wrapper_wlan_handle_amsdu_rx_packet(rcvdata, datalen);
        return;
    }

    if (recv_interface == MLAN_BSS_TYPE_STA || recv_interface == MLAN_BSS_TYPE_UAP)
    {
        g_data_nf_last  = rxpd->nf;
        g_data_snr_last = rxpd->snr;
    }

    t_u8 *payload  = (t_u8 *)rxpd + rxpd->rx_pkt_offset;
    struct net_pkt *p = gen_pkt_from_data(recv_interface, payload, rxpd->rx_pkt_length);
    /* If there are no more buffers, we do nothing, so the data is
       lost. We have to go back and read the other ports */
    if (p == NULL)
    {
        return;
    }

    /* points to packet payload, which starts with an Ethernet header */
    struct net_eth_hdr *ethhdr = NET_ETH_HDR(p);

#ifdef CONFIG_FILTER_LOCALLY_ADMINISTERED_AND_SELF_MAC_ADDR
    /* TODO: port wifi_netif.c */
    if ((ISLOCALLY_ADMINISTERED_ADDR(ethhdr->src.addr[0]) &&
         (!memcmp(&ethhdr->src.addr[3], &iw416_data.mac_addr[3], 3))) ||
        (!memcmp(&ethhdr->src.addr, &iw416_data.mac_addr[0], ETHARP_HWADDR_LEN)))
    {
        net_pkt_unref(p);
        p = NULL;
        return;
    }
#endif

    switch (htons(ethhdr->type))
    {
        case NET_ETH_PTYPE_IP:
#ifdef CONFIG_IPV6
        case NET_ETH_PTYPE_IPV6:
#endif
            /* To avoid processing of unwanted udp broadcast packets, adding
             * filter for dropping packets received on ports other than
             * pre-defined ports.
             */

            if (recv_interface == MLAN_BSS_TYPE_STA)
            {
                int rv = wrapper_wlan_handle_rx_packet(datalen, rxpd, p, payload);
                if (rv != WM_SUCCESS)
                {
                    /* mlan was unsuccessful in delivering the
                       packet */

                    (void)net_pkt_unref(p);
                }
            }
            else
            {
                deliver_packet_above(p, recv_interface);
            }
            p = NULL;
            break;
        case NET_ETH_PTYPE_ARP:
        case ETHTYPE_EAPOL:

            deliver_packet_above(p, recv_interface);
            break;
        default:
            /* fixme: avoid pbuf allocation in this case */

            (void)net_pkt_unref(p);
            break;
    }
}

/* Callback function called from the wifi module */
void handle_data_packet(const t_u8 interface, const t_u8 *rcvdata, const t_u16 datalen)
{
    process_data_packet(rcvdata, datalen);
}

void handle_amsdu_data_packet(t_u8 interface, t_u8 *rcvdata, t_u16 datalen)
{
    struct net_pkt *p = gen_pkt_from_data(interface, rcvdata, datalen);
    if (p == NULL)
    {
        w_pkt_e("[amsdu] No pbuf available. Dropping packet");
        return;
    }

    deliver_packet_above(p, interface);
}

void handle_deliver_packet_above(t_void *rxpd, t_u8 interface, t_void *lwip_pbuf)
{
    struct net_pkt *p = (struct net_pkt *)lwip_pbuf;

#ifndef CONFIG_WIFI_RX_REORDER
    (void)rxpd;
    deliver_packet_above(p, interface);
#else
    RxPD *prxpd = (RxPD *)rxpd;
    deliver_packet_above(prxpd, p, interface);
#endif
}

bool wrapper_net_is_ip_or_ipv6(const t_u8 *buffer)
{
    struct net_eth_hdr *hdr = (struct net_eth_hdr *)buffer;
    uint16_t type = ntohs(hdr->type);
    if ((type == NET_ETH_PTYPE_IP) || type == NET_ETH_PTYPE_IPV6) {
        return true;
    }
    return false;
}

static void printSeparator(void)
{
    printk("========================================\n");
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
    static int auth_fail                      = 0;
    wlan_uap_client_disassoc_t *disassoc_resp = data;

    printSeparator();
    PRINTF("app_cb: WLAN: received event %d\r\n", reason);
    printSeparator();

    if (s_wplState >= WPL_INITIALIZED)
    {
        k_event_set(&s_wplSyncEvent, EVENT_BIT(reason));
    }

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
#ifdef RW610
            ret = wlan_enhanced_cli_init();
            if (ret != WM_SUCCESS)
            {
                PRINTF("Failed to initialize WLAN CLIs\r\n");
                return 0;
            }
            PRINTF("ENHANCED WLAN CLIs are initialized\r\n");
            printSeparator();

#ifdef CONFIG_HOST_SLEEP
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
            help_command(0, NULL);
            printSeparator();
            break;
        case WLAN_REASON_INITIALIZATION_FAILED:
            PRINTF("app_cb: WLAN: initialization failed\r\n");
            break;
        case WLAN_REASON_AUTH_SUCCESS:
            net_eth_carrier_on(g_mlan.netif);
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
#ifndef CONFIG_ZEPHYR
            for (i = 0; i < CONFIG_MAX_IPV6_ADDRESSES; i++)
            {
                if (ip6_addr_isvalid(addr.ipv6[i].addr_state))
#else
            for (i = 0; i < CONFIG_MAX_IPV6_ADDRESSES && i < sta_network.ip.ipv6_count; i++)
            {
                if ((addr.ipv6[i].addr_state == NET_ADDR_TENTATIVE) ||
                        (addr.ipv6[i].addr_state == NET_ADDR_PREFERRED))
#endif
                {
                    (void)PRINTF("IPv6 Address: %-13s:\t%s (%s)\r\n", ipv6_addr_type_to_desc(&addr.ipv6[i]),
                                 ipv6_addr_addr_to_desc(&addr.ipv6[i]), ipv6_addr_state_to_desc(addr.ipv6[i].addr_state));
                }
            }
            (void)PRINTF("\r\n");
#endif
            auth_fail = 0;
            break;
        case WLAN_REASON_CONNECT_FAILED:
            net_eth_carrier_off(g_mlan.netif);
            PRINTF("app_cb: WLAN: connect failed\r\n");
            break;
        case WLAN_REASON_NETWORK_NOT_FOUND:
            net_eth_carrier_off(g_mlan.netif);
            PRINTF("app_cb: WLAN: network not found\r\n");
            break;
        case WLAN_REASON_NETWORK_AUTH_FAILED:
            net_eth_carrier_off(g_mlan.netif);
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
            net_eth_carrier_off(g_mlan.netif);
            PRINTF("app_cb: disconnected\r\n");
            auth_fail = 0;
            break;
        case WLAN_REASON_LINK_LOST:
            net_eth_carrier_off(g_mlan.netif);
            PRINTF("app_cb: WLAN: link lost\r\n");
            break;
        case WLAN_REASON_CHAN_SWITCH:
            PRINTF("app_cb: WLAN: channel switch\r\n");
            break;
        case WLAN_REASON_UAP_SUCCESS:
            net_eth_carrier_on(g_uap.netif);
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
            {
                PRINTF("Error in starting dhcp server\r\n");
                break;
            }

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
        case WLAN_REASON_UAP_CLIENT_CONN:
            PRINTF("app_cb: WLAN: UAP a Client Connected\r\n");
            printSeparator();
            PRINTF("Client => ");
            print_mac((const char *)data);
            PRINTF("Connected with Soft AP\r\n");
            printSeparator();
            break;
        case WLAN_REASON_UAP_CLIENT_DISSOC:
            printSeparator();
            PRINTF("app_cb: WLAN: UAP a Client Dissociated:");
            PRINTF(" Client MAC => ");
            print_mac((const char *)(disassoc_resp->sta_addr));
            PRINTF(" Reason code => ");
            PRINTF("%d\r\n", disassoc_resp->reason_code);
            printSeparator();
            break;
        case WLAN_REASON_UAP_STOPPED:
            net_eth_carrier_off(g_uap.netif);
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
#ifdef CONFIG_SUBSCRIBE_EVENT_SUPPORT
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
            break;
#endif
        default:
            PRINTF("app_cb: WLAN: Unknown Event: %d\r\n", reason);
    }
    return 0;
}

/* Link lost callback */
static void LinkStatusChangeCallback(bool linkState)
{
    if (linkState == false)
    {
        PRINTF("-------- LINK LOST --------\r\n");
    }
    else
    {
        PRINTF("-------- LINK REESTABLISHED --------\r\n");
    }
}

int WPL_Init(void)
{
    wpl_ret_t status = WPLRET_SUCCESS;
    int ret;

    if (s_wplState != WPL_NOT_INITIALIZED)
    {
        status = WPLRET_FAIL;
    }

    if (status == WPLRET_SUCCESS)
    {
        k_event_init(&s_wplSyncEvent);
    }

    if (status == WPLRET_SUCCESS)
    {
        ret = wlan_init(wlan_fw_bin, wlan_fw_bin_len);
        if (ret != WM_SUCCESS)
        {
            status = WPLRET_FAIL;
        }
    }

    if (status == WPLRET_SUCCESS)
    {
        s_wplState = WPL_INITIALIZED;
    }

    if (status != WPLRET_SUCCESS)
        return -1;

    return 0;
}

int WPL_Start(linkLostCb_t callbackFunction)
{
    wpl_ret_t status = WPLRET_SUCCESS;
    int ret;
    uint32_t syncBit;

    if (s_wplState != WPL_INITIALIZED)
    {
        status = WPLRET_NOT_READY;
    }

    if (status == WPLRET_SUCCESS)
    {
        k_event_clear(&s_wplSyncEvent, WPL_SYNC_INIT_GROUP);

        ret = wlan_start(wlan_event_callback);
        if (ret != WM_SUCCESS)
        {
            status = WPLRET_FAIL;
        }
    }

    if (status == WPLRET_SUCCESS)
    {
        syncBit = k_event_wait(&s_wplSyncEvent, WPL_SYNC_INIT_GROUP, true, WPL_SYNC_TIMEOUT_MS);
        if (syncBit & EVENT_BIT(WLAN_REASON_INITIALIZED))
        {
            s_linkLostCb = callbackFunction;
            status       = WPLRET_SUCCESS;
        }
        else if (syncBit & EVENT_BIT(WLAN_REASON_INITIALIZATION_FAILED))
        {
            status = WPLRET_FAIL;
        }
        else
        {
            status = WPLRET_TIMEOUT;
        }
    }

    if (status == WPLRET_SUCCESS)
    {
        s_wplState = WPL_STARTED;
    }

    if (status != WPLRET_SUCCESS)
        return -1;

    return 0;
}

int WPL_Stop(void)
{
    wpl_ret_t status = WPLRET_SUCCESS;
    int ret;

    if (s_wplState != WPL_STARTED)
    {
        status = WPLRET_NOT_READY;
    }

    if (status == WPLRET_SUCCESS)
    {
        ret = wlan_stop();
        if (ret != WM_SUCCESS)
        {
            status = WPLRET_FAIL;
        }
    }

    if (status == WPLRET_SUCCESS)
    {
        s_wplState = WPL_INITIALIZED;
    }

    if (status != WPLRET_SUCCESS)
        return -1;

    return 0;
}

static int WPL_Start_AP(const struct device *dev,
			 struct wifi_connect_req_params *params)
{
    wpl_ret_t status = WPLRET_SUCCESS;
    int ret;
    uint32_t syncBit;
    interface_t *if_handle = (interface_t *)dev->data;

    if (if_handle->state.interface != WLAN_BSS_TYPE_UAP)
    {
        LOG_ERR("Wi-Fi not in uAP mode");
        return -EIO; 
    }

    if ((s_wplState != WPL_STARTED) || (s_wplUapActivated != false))
    {
        status = WPLRET_NOT_READY;
    }

    if (status == WPLRET_SUCCESS)
    {
        if ((params->ssid_length == 0) || (params->ssid_length > IEEEtypes_SSID_SIZE))
        {
            status = WPLRET_BAD_PARAM;
        }
    }

    if (status == WPLRET_SUCCESS)
    {
        wlan_remove_network(uap_network.name);

        wlan_initialize_uap_network(&uap_network);

        memcpy(uap_network.ssid, params->ssid, params->ssid_length);
        uap_network.channel          = params->channel;

        if (params->mfp == WIFI_MFP_REQUIRED)
        {
            uap_network.security.mfpc = true;
            uap_network.security.mfpr = true;
        }
        else if (params->mfp == WIFI_MFP_OPTIONAL)
        {
            uap_network.security.mfpc = true;
            uap_network.security.mfpr = false;
        }

        if (params->security == WIFI_SECURITY_TYPE_NONE)
        {
            uap_network.security.type = WLAN_SECURITY_NONE;
        }
        else if (params->security == WIFI_SECURITY_TYPE_PSK)
        {
            uap_network.security.type = WLAN_SECURITY_WPA2;
            uap_network.security.psk_len = params->psk_length;
            strncpy(uap_network.security.psk, params->psk, params->psk_length);
        }
#ifdef CONFIG_WPA_SUPP
        else if (params->security == WIFI_SECURITY_TYPE_PSK_SHA256)
        {
            uap_network.security.type = WLAN_SECURITY_WPA2_SHA256;
            uap_network.security.psk_len = params->psk_length;
            strncpy(uap_network.security.psk, params->psk, params->psk_length);
        }
#endif
        else if (params->security == WIFI_SECURITY_TYPE_SAE)
        {
            uap_network.security.type = WLAN_SECURITY_WPA3_SAE;
            uap_network.security.password_len = params->sae_password_length;
            strncpy(uap_network.security.password, params->sae_password, params->sae_password_length);
        }
        else
        {
            status = WPLRET_BAD_PARAM;
        }
    }

    if (status == WPLRET_SUCCESS)
    {
        ret = wlan_add_network(&uap_network);
        if (ret != WM_SUCCESS)
        {
            status = WPLRET_FAIL;
        }
    }

    if (status == WPLRET_SUCCESS)
    {
        k_event_clear(&s_wplSyncEvent, WPL_SYNC_UAP_START_GROUP);

        ret = wlan_start_network(uap_network.name);
        if (ret != WM_SUCCESS)
        {
            status = WPLRET_FAIL;
        }
        else
        {
            syncBit =
               k_event_wait(&s_wplSyncEvent, WPL_SYNC_UAP_START_GROUP, true, WPL_SYNC_TIMEOUT_MS);
            if (syncBit & EVENT_BIT(WLAN_REASON_UAP_SUCCESS))
            {
                status = WPLRET_SUCCESS;
            }
            else if (syncBit & EVENT_BIT(WLAN_REASON_UAP_START_FAILED))
            {
                status = WPLRET_FAIL;
            }
            else
            {
                status = WPLRET_TIMEOUT;
            }
        }

        if (status != WPLRET_SUCCESS)
        {
            wlan_remove_network(uap_network.name);
        }
    }

    if (status == WPLRET_SUCCESS)
    {
        ret = dhcp_server_start(net_get_uap_handle());
        if (ret != WM_SUCCESS)
        {
            wlan_stop_network(uap_network.name);
            wlan_remove_network(uap_network.name);
            status = WPLRET_FAIL;
        }
    }

    if (status == WPLRET_SUCCESS)
    {
        s_wplUapActivated = true;
    }

    if (status != WPLRET_SUCCESS)
    {
        LOG_ERR("Failed to enable Wi-Fi AP mode");
	return -EAGAIN;
    }

    return 0;
}

static int WPL_Stop_AP(const struct device *dev)
{
    wpl_ret_t status = WPLRET_SUCCESS;
    int ret;
    uint32_t syncBit;

    if ((s_wplState != WPL_STARTED) || (s_wplUapActivated != true))
    {
        status = WPLRET_NOT_READY;
    }

    if (status == WPLRET_SUCCESS)
    {
        dhcp_server_stop();

        k_event_clear(&s_wplSyncEvent, WPL_SYNC_UAP_START_GROUP);

        ret = wlan_stop_network(UAP_NETWORK_NAME);
        if (ret != WM_SUCCESS)
        {
            status = WPLRET_FAIL;
        }
        else
        {
            syncBit =
                k_event_wait(&s_wplSyncEvent, WPL_SYNC_UAP_STOP_GROUP, true, WPL_SYNC_TIMEOUT_MS);
            if (syncBit & EVENT_BIT(WLAN_REASON_UAP_STOPPED))
            {
                status = WPLRET_SUCCESS;
            }
            else if (syncBit & EVENT_BIT(WLAN_REASON_UAP_STOP_FAILED))
            {
                status = WPLRET_FAIL;
            }
            else
            {
                status = WPLRET_TIMEOUT;
            }
        }
    }

    if (status == WPLRET_SUCCESS)
    {
        ret = wlan_remove_network(UAP_NETWORK_NAME);
        if (ret != WM_SUCCESS)
        {
            status = WPLRET_FAIL;
        }
    }

    if (status == WPLRET_SUCCESS)
    {
        s_wplUapActivated = false;
    }

    if (status != WPLRET_SUCCESS)
    {
        LOG_ERR("Failed to disable Wi-Fi AP mode");
	return -EAGAIN;
    }

    return 0;
}

static int WLP_process_results(unsigned int count)
{
    struct wlan_scan_result scan_result = {0};
    struct wifi_scan_result res = { 0 };

    if (!count)
    {
	LOG_INF("No Wi-Fi AP found");
	goto out;
    }

    for (int i = 0; i < count; i++)
    {
        wlan_get_scan_result(i, &scan_result);

        memset(&res, 0, sizeof(struct wifi_scan_result));

        memcpy(res.mac, scan_result.bssid, WIFI_MAC_ADDR_LEN);
        res.mac_length = WIFI_MAC_ADDR_LEN;
	res.ssid_length = scan_result.ssid_len;
	strncpy(res.ssid, scan_result.ssid, scan_result.ssid_len);
	
        res.rssi = -scan_result.rssi;
        res.channel = scan_result.channel;
        res.band = scan_result.channel > 14 ? WIFI_FREQ_BAND_5_GHZ : WIFI_FREQ_BAND_2_4_GHZ; 

	res.security = WIFI_SECURITY_TYPE_NONE;

        if (scan_result.wpa2_entp)
        {
        }
        if (scan_result.wpa2)
        {
            res.security = WIFI_SECURITY_TYPE_PSK;
        }
#ifdef CONFIG_WPA_SUPP
        if (scan_result.wpa2_sha256)
        {
            res.security = WIFI_SECURITY_TYPE_PSK_SHA256;
        }
#endif
        if (scan_result.wpa3_sae)
        {
            res.security = WIFI_SECURITY_TYPE_SAE;
        }

	if (g_mlan.scan_cb)
        {
	    g_mlan.scan_cb(g_mlan.netif, 0, &res);

	    /* ensure notifications get delivered */
	    k_yield();
	}
    }

out:
    /* report end of scan event */
    g_mlan.scan_cb(g_mlan.netif, 0, NULL);
    g_mlan.scan_cb = NULL;

    k_event_set(&s_wplSyncEvent, EVENT_BIT(EVENT_SCAN_DONE));

    return WM_SUCCESS;
}

static int WPL_Scan(const struct device *dev, scan_result_cb_t cb)
{
    wpl_ret_t status = WPLRET_SUCCESS;
    int ret;
    uint32_t syncBit;
    interface_t *if_handle = (interface_t *)dev->data;

    if (if_handle->state.interface != WLAN_BSS_TYPE_STA)
    {
        LOG_ERR("Wi-Fi not in station mode");
        return -EIO; 
    }

    if (if_handle->scan_cb != NULL) {
        LOG_INF("Scan callback in progress");
	return -EINPROGRESS;
    }

    if_handle->scan_cb = cb;

    if (s_wplState != WPL_STARTED)
    {
        status = WPLRET_NOT_READY;
    }

    if (status == WPLRET_SUCCESS)
    {
        ret = wlan_scan(WLP_process_results);
        if (ret != WM_SUCCESS)
        {
            status = WPLRET_FAIL;
        }
    }

    if (status == WPLRET_SUCCESS)
    {
        syncBit = k_event_wait(&s_wplSyncEvent, WPL_SYNC_SCAN_GROUP, true, WPL_SYNC_TIMEOUT_MS);
        if (syncBit & EVENT_BIT(EVENT_SCAN_DONE))
        {
            status = WPLRET_SUCCESS;
        }
        else
        {
            status = WPLRET_TIMEOUT;
        }
    }

    if (status != WPLRET_SUCCESS)
    {
        LOG_ERR("Failed to start Wi-Fi scanning");
    	return -EAGAIN;
    }

    return 0;
}

static int WPL_Disconnect(const struct device *dev);

static int WPL_Connect(const struct device *dev,
			    struct wifi_connect_req_params *params)
{
    wpl_ret_t status = WPLRET_SUCCESS;
    int ret;
    uint32_t syncBit;
    interface_t *if_handle = (interface_t *)dev->data;

    if ((s_wplState != WPL_STARTED) || (s_wplStaConnected != false))
    {
        status = WPLRET_NOT_READY;
        wifi_mgmt_raise_connect_result_event(g_mlan.netif, -1);
        return -EALREADY;
    }

    if (if_handle->state.interface != WLAN_BSS_TYPE_STA)
    {
        LOG_ERR("Wi-Fi not in station mode");
	wifi_mgmt_raise_connect_result_event(g_mlan.netif, -1);
        return -EIO; 
    }

    if (status == WPLRET_SUCCESS)
    {
        if ((params->ssid_length == 0) || (params->ssid_length > IEEEtypes_SSID_SIZE))
        {
            status = WPLRET_BAD_PARAM;
        }
    }

    if (status == WPLRET_SUCCESS)
    {
        wlan_remove_network(sta_network.name);

        wlan_initialize_sta_network(&sta_network);

        memcpy(sta_network.ssid, params->ssid, params->ssid_length);
        sta_network.ssid_specific     = 1;

        sta_network.channel          = params->channel;

        if (params->mfp == WIFI_MFP_REQUIRED)
        {
            sta_network.security.mfpc = true;
            sta_network.security.mfpr = true;
        }
        else if (params->mfp == WIFI_MFP_OPTIONAL)
        {
            sta_network.security.mfpc = true;
            sta_network.security.mfpr = false;
        }

        if (params->security == WIFI_SECURITY_TYPE_NONE)
        {
            sta_network.security.type = WLAN_SECURITY_NONE;
        }
        else if (params->security == WIFI_SECURITY_TYPE_PSK)
        {
            sta_network.security.type = WLAN_SECURITY_WPA2;
            sta_network.security.psk_len = params->psk_length;
            strncpy(sta_network.security.psk, params->psk, params->psk_length);
        }
#ifdef CONFIG_WPA_SUPP
        else if (params->security == WIFI_SECURITY_TYPE_PSK_SHA256)
        {
            sta_network.security.type = WLAN_SECURITY_WPA2_SHA256;
            sta_network.security.psk_len = params->psk_length;
            strncpy(sta_network.security.psk, params->psk, params->psk_length);
        }
#endif
        else if (params->security == WIFI_SECURITY_TYPE_SAE)
        {
            sta_network.security.type = WLAN_SECURITY_WPA3_SAE;
            sta_network.security.password_len = params->sae_password_length;
            strncpy(sta_network.security.password, params->sae_password, params->sae_password_length);
        }
        else
        {
            status = WPLRET_BAD_PARAM;
        }
    }

    if (status == WPLRET_SUCCESS)
    {
        ret = wlan_add_network(&sta_network);
        if (ret != WM_SUCCESS)
        {
            status = WPLRET_FAIL;
        }
    }

    if (status == WPLRET_SUCCESS)
    {
        k_event_clear(&s_wplSyncEvent, WPL_SYNC_CONNECT_GROUP);

        ret = wlan_connect(sta_network.name);
        if (ret != WM_SUCCESS)
        {
            status = WPLRET_FAIL;
        }
    }

    if (status == WPLRET_SUCCESS)
    {
        syncBit = k_event_wait(&s_wplSyncEvent, WPL_SYNC_CONNECT_GROUP, true, WPL_SYNC_TIMEOUT_MS);
        if (syncBit & EVENT_BIT(WLAN_REASON_SUCCESS))
        {
            status = WPLRET_SUCCESS;
        }
        else if (syncBit & EVENT_BIT(WLAN_REASON_CONNECT_FAILED))
        {
            status = WPLRET_FAIL;
        }
        else if (syncBit & EVENT_BIT(WLAN_REASON_NETWORK_NOT_FOUND))
        {
            status = WPLRET_NOT_FOUND;
        }
        else if (syncBit & EVENT_BIT(WLAN_REASON_NETWORK_AUTH_FAILED))
        {
            status = WPLRET_AUTH_FAILED;
        }
        else if (syncBit & EVENT_BIT(WLAN_REASON_ADDRESS_FAILED))
        {
            status = WPLRET_ADDR_FAILED;
        }
        else
        {
            status = WPLRET_TIMEOUT;
        }

        if (status != WPLRET_SUCCESS)
        {
            /* Abort the next connection attempt */
            WPL_Disconnect(dev);
        }
    }

    if (status == WPLRET_SUCCESS)
    {
        s_wplStaConnected = true;
        wifi_mgmt_raise_connect_result_event(g_mlan.netif, 0);
    }

    if (status != WPLRET_SUCCESS)
    {
        LOG_ERR("Failed to connect to Wi-Fi access point");
	return -EAGAIN;
    }

    return 0;
}

static int WPL_Disconnect(const struct device *dev)
{
    wpl_ret_t status = WPLRET_SUCCESS;
    int ret;
    uint32_t syncBit;
    interface_t *if_handle = (interface_t *)dev->data;

    if (s_wplState != WPL_STARTED)
    {
        status = WPLRET_NOT_READY;
    }

    if (if_handle->state.interface != WLAN_BSS_TYPE_STA)
    {
        LOG_ERR("Wi-Fi not in station mode");
        return -EIO; 
    }

    enum wlan_connection_state connection_state = WLAN_DISCONNECTED;
    wlan_get_connection_state(&connection_state);
    if (connection_state == WLAN_DISCONNECTED)
    {
        s_wplStaConnected = false;
        wifi_mgmt_raise_disconnect_result_event(g_mlan.netif, -1);
        return WPLRET_SUCCESS;
    }

    if (status == WPLRET_SUCCESS)
    {
        k_event_clear(&s_wplSyncEvent, WPL_SYNC_DISCONNECT_GROUP);

        ret = wlan_disconnect();
        if (ret != WM_SUCCESS)
        {
            status = WPLRET_FAIL;
        }
    }

    if (status == WPLRET_SUCCESS)
    {
        syncBit = k_event_wait(&s_wplSyncEvent, WPL_SYNC_DISCONNECT_GROUP, true, WPL_SYNC_TIMEOUT_MS);
        if (syncBit & EVENT_BIT(WLAN_REASON_USER_DISCONNECT))
        {
            status = WPLRET_SUCCESS;
        }
        else
        {
            status = WPLRET_TIMEOUT;
        }
    }

    s_wplStaConnected = false;

    if (status != WPLRET_SUCCESS)
    {
        LOG_ERR("Failed to disconnect from AP");
        wifi_mgmt_raise_disconnect_result_event(g_mlan.netif, -1);
	return -EAGAIN;
    }

    wifi_mgmt_raise_disconnect_result_event(g_mlan.netif, 0);

    return 0;
}

int WPL_GetIP(char *ip, int client)
{
    wpl_ret_t status = WPLRET_SUCCESS;
    int ret;
    struct wlan_ip_config addr;

    if (ip == NULL)
    {
        status = WPLRET_FAIL;
    }

    if (status == WPLRET_SUCCESS)
    {
        if (client)
        {
            ret = wlan_get_address(&addr);
        }
        else
        {
            ret = wlan_get_uap_address(&addr);
        }

        if (ret == WM_SUCCESS)
        {
            net_inet_ntoa(addr.ipv4.address, ip);
        }
        else
        {
            status = WPLRET_FAIL;
        }
    }

    if (status != WPLRET_SUCCESS)
        return -1;

    return 0;
}

static inline enum wifi_security_type WPL_key_mgmt_to_zephyr(enum wlan_security_type type)
{
    switch(type) {
        case WLAN_SECURITY_NONE:
            return WIFI_SECURITY_TYPE_NONE;
        case WLAN_SECURITY_WPA2:
            return WIFI_SECURITY_TYPE_PSK;
#ifdef CONFIG_WPA_SUPP
        case WLAN_SECURITY_WPA2_SHA256:
            return WIFI_SECURITY_TYPE_PSK_SHA256;
#endif
        case WLAN_SECURITY_WPA3_SAE:
            return WIFI_SECURITY_TYPE_SAE;
        default:
            return WIFI_SECURITY_TYPE_UNKNOWN;
    }
}

static int WPL_Status(const struct device *dev,
			struct wifi_iface_status *status)
{
    enum wlan_connection_state connection_state = WLAN_DISCONNECTED;
    wlan_get_connection_state(&connection_state);
    struct wlan_network *network = (struct wlan_network *)os_mem_alloc(sizeof(struct wlan_network));
    if (!network)
    {
        LOG_ERR("Error: unable to malloc memory");
        return -1;
    }

    if (s_wplState != WPL_STARTED)
    {
        status->state = WIFI_STATE_INTERFACE_DISABLED; 
        return WPLRET_SUCCESS;
    }

    if (connection_state == WLAN_DISCONNECTED)
    {
        status->state = WIFI_STATE_DISCONNECTED;
    }
    else if (connection_state == WLAN_SCANNING)
    {
        status->state = WIFI_STATE_SCANNING;
    }
    else if (connection_state == WLAN_ASSOCIATING)
    {
        status->state = WIFI_STATE_ASSOCIATING;
    }
    else if (connection_state == WLAN_ASSOCIATED)
    {
        status->state = WIFI_STATE_ASSOCIATED;
    }
    else if (connection_state == WLAN_CONNECTED)
    {
        status->state = WIFI_STATE_COMPLETED;

        if (!wlan_get_current_network(network))
        {
            strncpy(status->ssid, network->ssid, strlen(network->ssid));
            status->ssid_len = strlen(network->ssid);

            memcpy(status->bssid, network->bssid, WIFI_MAC_ADDR_LEN);

            status->rssi = network->rssi;

            status->channel = network->channel;

            status->iface_mode = WIFI_MODE_INFRA;

            status->band = network->channel > 14 ? WIFI_FREQ_BAND_5_GHZ : WIFI_FREQ_BAND_2_4_GHZ; 
	    status->security = WPL_key_mgmt_to_zephyr(network->security.type);
	    status->mfp = network->security.mfpr ? WIFI_MFP_REQUIRED : network->security.mfpc ? WIFI_MFP_OPTIONAL : 0;
        }
    }

    return 0;
}


K_THREAD_STACK_DEFINE(net_wifi_init_stack, CONFIG_WIFI_INIT_STACK_SIZE);
struct k_thread net_wifi_thread;

extern void WL_MCI_WAKEUP0_DriverIRQHandler(void);

/* IW416 network init thread */
void net_wifi_init_thread(void *dev, void* arg2, void *arg3)
{
	int ret;

    IRQ_CONNECT(72, 1, WL_MCI_WAKEUP0_DriverIRQHandler, 0, 0);
    irq_enable(72);

	/* Initialize the wifi subsystem */
	ret = WPL_Init();
	if (ret) {
		LOG_ERR("wlan initialization failed");
		return;
	}
	ret = WPL_Start(LinkStatusChangeCallback);
	if (ret) {
		LOG_ERR("could not start wlan threads");
		return;
	}
}

static int wifi_net_init(const struct device *dev)
{
    return 0;
}

static int wifi_net_init_thread(const struct device *dev)
{
    g_mlan.state.interface = WLAN_BSS_TYPE_STA;
    g_uap.state.interface  = WLAN_BSS_TYPE_UAP;

    /* kickoff init thread to avoid stack overflow */
    k_thread_create(&net_wifi_thread, net_wifi_init_stack,
        K_THREAD_STACK_SIZEOF(net_wifi_init_stack),
        net_wifi_init_thread, (void *)dev, NULL, NULL,
        0, 0, K_NO_WAIT);

    return 0;
}

static void wifi_net_iface_init(struct net_if *iface)
{
    static int init_done = 0;
    const struct device *dev = net_if_get_device(iface);
    interface_t *intf = dev->data;

    intf->netif = iface;

    if (!init_done)
    {
        wifi_net_init_thread(dev);
        init_done = 1;
    }

    net_if_flag_set(iface, NET_IF_NO_AUTO_START);
}

extern int retry_attempts;

static int low_level_output(const struct device *dev, struct net_pkt *pkt)
{
    int ret;
    interface_t *if_handle = (interface_t *)dev->data;
    t_u8 interface   = if_handle->state.interface;
    t_u16 net_pkt_len = net_pkt_get_len(pkt);
    t_u32 pkt_len, outbuf_len;
    t_u8 *wmm_outbuf = NULL;
#ifdef CONFIG_WMM
    t_u8 *payload = net_pkt_data(pkt);
    t_u8 tid                      = 0;
    int retry                     = 0;
    t_u8 ra[MLAN_MAC_ADDR_LENGTH] = {0};
    bool is_tx_pause              = false;

    t_u32 pkt_prio = wifi_wmm_get_pkt_prio(payload, &tid);
    if (pkt_prio == -WM_FAIL)
    {
        return -ENOMEM;
    }

    if (interface > WLAN_BSS_TYPE_UAP)
    {
        wifi_wmm_drop_no_media(interface);
        return -ENOMEM;
    }

    if (wifi_tx_status == WIFI_DATA_BLOCK)
    {
        wifi_tx_block_cnt++;
        return 0;
    }

    wifi_wmm_da_to_ra(payload, ra);

    do
    {
        if (retry != 0)
        {
            send_wifi_driver_tx_data_event(interface);
            k_yield();
        }
        else
        {
            retry = retry_attempts;
        }

        wmm_outbuf = wifi_wmm_get_outbuf_enh(&outbuf_len, (mlan_wmm_ac_e)pkt_prio, interface, ra, &is_tx_pause);
        ret        = (wmm_outbuf == NULL) ? true : false;

        if (is_tx_pause == true)
        {
            wifi_wmm_drop_pause_drop(interface);
            return -ENOMEM;
        }

        retry--;
    } while (ret == true && retry > 0);

    if (ret == true)
    {
        wifi_wmm_drop_retried_drop(interface);
        return -ENOMEM;
    }
#else
    wmm_outbuf = wifi_get_outbuf((uint32_t *)(&outbuf_len));

    if (wmm_outbuf == NULL)
    {
        return -ENOMEM;
    }
#endif

    pkt_len =
#ifdef CONFIG_WMM
        sizeof(mlan_linked_list) +
#endif
        sizeof(TxPD) + INTF_HEADER_LEN;

    /* TODO: check if we can zero copy */

    assert(pkt_len + net_pkt_len <= outbuf_len);

    memset(wmm_outbuf, 0x00, pkt_len);

    if (net_pkt_read(pkt, wmm_outbuf + pkt_len, net_pkt_len))
        return -EIO;

    pkt_len += net_pkt_len;

    ret = wifi_low_level_output(interface, wmm_outbuf, pkt_len
#ifdef CONFIG_WMM
                                ,
                                pkt_prio, tid
#endif
    );

    if (ret == WM_SUCCESS)
    {
        ret = 0;
    }
    else if (ret == -WM_E_NOMEM)
    {
        LOG_ERR("Wifi Net NOMEM");
        ret = -ENOMEM;
    }
    else if (ret == -WM_E_BUSY)
    {
        LOG_ERR("Wifi Net Busy");
        ret = -ETIMEDOUT;
    }
    else
    { /* Do Nothing */
    }

    return ret;
}

/* Below struct is used for creating IGMP IPv4 multicast list */
typedef struct group_ip4_addr
{
    struct group_ip4_addr *next;
    uint32_t group_ip;
} group_ip4_addr_t;

/* Head of list that will contain IPv4 multicast IP's */
static group_ip4_addr_t *igmp_ip4_list;

/* Callback called by LwiP to add or delete an entry in the multicast filter table */
static int igmp_mac_filter(struct netif *netif, const struct in_addr *group, enum netif_mac_filter_action action)
{
    uint8_t mcast_mac[6];
    int result;
    int error;

    /* IPv4 to MAC conversion as per section 6.4 of rfc1112 */
    wifi_get_ipv4_multicast_mac(ntohl(group->s_addr), mcast_mac);
    group_ip4_addr_t *curr, *prev;

    switch (action)
    {
        case NET_IF_ADD_MAC_FILTER:
            /* LwIP takes care of duplicate IP addresses and it always send
             * unique IP address. Simply add IP to top of list*/
            curr = (group_ip4_addr_t *)os_mem_alloc(sizeof(group_ip4_addr_t));
            if (curr == NULL)
            {
                result = -WM_FAIL;
                goto done;
            }
            curr->group_ip = group->s_addr;
            curr->next     = igmp_ip4_list;
            igmp_ip4_list  = curr;
            /* Add multicast MAC filter */
            error = wifi_add_mcast_filter(mcast_mac);
            if (error == 0)
            {
                result = WM_SUCCESS;
            }
            else if (error == -WM_E_EXIST)
            {
                result = WM_SUCCESS;
            }
            else
            {
                /* In case of failure remove IP from list */
                curr          = igmp_ip4_list;
                igmp_ip4_list = curr->next;
                os_mem_free(curr);
                curr   = NULL;
                result = -WM_FAIL;
            }
            break;
        case NET_IF_DEL_MAC_FILTER:
            /* Remove multicast IP address from list */
            curr = igmp_ip4_list;
            prev = curr;
            while (curr != NULL)
            {
                if (curr->group_ip == group->s_addr)
                {
                    if (prev == curr)
                    {
                        igmp_ip4_list = curr->next;
                        os_mem_free(curr);
                    }
                    else
                    {
                        prev->next = curr->next;
                        os_mem_free(curr);
                    }
                    curr = NULL;
                    break;
                }
                prev = curr;
                curr = curr->next;
            }
            /* Check if other IP is mapped to same MAC */
            curr = igmp_ip4_list;
            while (curr != NULL)
            {
                /* If other IP is mapped to same MAC than skip Multicast MAC removal */
                if ((ntohl(curr->group_ip) & 0x7FFFFFU) == (ntohl(group->s_addr) & 0x7FFFFFU))
                {
                    result = WM_SUCCESS;
                    goto done;
                }
                curr = curr->next;
            }
            /* Remove Multicast MAC filter */
            error = wifi_remove_mcast_filter(mcast_mac);
            if (error == 0)
            {
                result = WM_SUCCESS;
            }
            else
            {
                result = -WM_FAIL;
            }
            break;
        default:
            result = -WM_FAIL;
            break;
    }
done:
    return result;
}

#ifdef CONFIG_IPV6
/* Below struct is used for creating IGMP IPv6 multicast list */
typedef struct group_ip6_addr
{
    struct group_ip6_addr *next;
    uint32_t group_ip;
} group_ip6_addr_t;

/* Head of list that will contain IPv6 multicast IP's */
static group_ip6_addr_t *mld_ip6_list;

/* Callback called by LwiP to add or delete an entry in the IPv6 multicast filter table */
static int mld_mac_filter(struct netif *netif, const struct in6_addr *group, enum netif_mac_filter_action action)
{
    uint8_t mcast_mac[6];
    int result;
    int error;

    /* IPv6 to MAC conversion as per section 7 of rfc2464 */
    wifi_get_ipv6_multicast_mac(ntohl(group->s6_addr32[3]), mcast_mac);
    group_ip6_addr_t *curr, *prev;

    switch (action)
    {
        case NET_IF_ADD_MAC_FILTER:
            /* LwIP takes care of duplicate IP addresses and it always send
             * unique IP address. Simply add IP to top of list*/
            curr = (group_ip6_addr_t *)os_mem_alloc(sizeof(group_ip6_addr_t));
            if (curr == NULL)
            {
                result = -WM_FAIL;
                goto done;
            }
            curr->group_ip = group->s6_addr32[3];
            curr->next     = mld_ip6_list;
            mld_ip6_list   = curr;
            /* Add multicast MAC filter */
            error = wifi_add_mcast_filter(mcast_mac);
            if (error == 0)
            {
                result = WM_SUCCESS;
            }
            else if (error == -WM_E_EXIST)
            {
                result = WM_SUCCESS;
            }
            else
            {
                /* In case of failure remove IP from list */
                curr         = mld_ip6_list;
                mld_ip6_list = mld_ip6_list->next;
                os_mem_free(curr);
                curr   = NULL;
                result = -WM_FAIL;
            }
            break;
        case NET_IF_DEL_MAC_FILTER:
            /* Remove multicast IP address from list */
            curr = mld_ip6_list;
            prev = curr;
            while (curr != NULL)
            {
                if (curr->group_ip == group->s6_addr32[3])
                {
                    if (prev == curr)
                    {
                        mld_ip6_list = curr->next;
                        os_mem_free(curr);
                    }
                    else
                    {
                        prev->next = curr->next;
                        os_mem_free(curr);
                    }
                    curr = NULL;
                    break;
                }
                prev = curr;
                curr = curr->next;
            }
            /* Check if other IP is mapped to same MAC */
            curr = mld_ip6_list;
            while (curr != NULL)
            {
                /* If other IP is mapped to same MAC than skip Multicast MAC removal */
                if ((ntohl(curr->group_ip) & 0xFFFFFF) == (ntohl(group->s6_addr32[3]) & 0xFFFFFF))
                {
                    result = WM_SUCCESS;
                    goto done;
                }
                curr = curr->next;
            }
            /* Remove Multicast MAC filter */
            error = wifi_remove_mcast_filter(mcast_mac);
            if (error == 0)
            {
                result = WM_SUCCESS;
            }
            else
            {
                result = -WM_FAIL;
            }
            break;
        default:
            result = -WM_FAIL;
            break;
    }
done:
    return result;
}
#endif /* #ifdef CONFIG_IPV6 */

void *net_get_sta_handle(void)
{
    return &g_mlan;
}

void *net_get_uap_handle(void)
{
    return &g_uap;
}

struct netif *net_get_sta_interface(void)
{
    return (struct netif *)g_mlan.netif;
}

struct netif *net_get_uap_interface(void)
{
    return (struct netif *)g_uap.netif;
}

void net_stop_dhcp_timer(void)
{
    (void)os_timer_deactivate((os_timer_t *)&dhcp_timer);
}

static void stop_cb(void *ctx)
{
    interface_t *if_handle = (interface_t *)net_get_mlan_handle();

    net_dhcpv4_stop(if_handle->netif);
    (void)net_if_down(if_handle->netif);
#ifndef CONFIG_ZEPHYR
    wm_netif_status_callback_ptr = NULL;
#endif
}

static void dhcp_timer_cb(os_timer_arg_t arg)
{
    stop_cb(NULL);

    (void)wlan_wlcmgr_send_msg(WIFI_EVENT_NET_DHCP_CONFIG, WIFI_EVENT_REASON_FAILURE, NULL);
}

void net_interface_up(void *intrfc_handle)
{
    net_if_up(((interface_t *)intrfc_handle)->netif);
}

void net_interface_down(void *intrfc_handle)
{
    net_if_down(((interface_t *)intrfc_handle)->netif);
}

void net_interface_dhcp_stop(void *intrfc_handle)
{
    net_dhcpv4_stop(((interface_t *)intrfc_handle)->netif);
#ifndef CONFIG_ZEPHYR
    wm_netif_status_callback_ptr = NULL;
#endif
}

static void ipv4_mcast_add(struct net_mgmt_event_callback *cb,
			 struct net_if *iface)
{
    igmp_mac_filter((struct netif *)iface, cb->info, NET_IF_ADD_MAC_FILTER);
}

static void ipv4_mcast_delete(struct net_mgmt_event_callback *cb,
			 struct net_if *iface)
{
    igmp_mac_filter((struct netif *)iface, cb->info, NET_IF_DEL_MAC_FILTER);
}

#ifdef CONFIG_IPV6
static void ipv6_mcast_add(struct net_mgmt_event_callback *cb,
			 struct net_if *iface)
{
    mld_mac_filter((struct netif *)iface, cb->info, NET_IF_ADD_MAC_FILTER);
}

static void ipv6_mcast_delete(struct net_mgmt_event_callback *cb,
			 struct net_if *iface)
{
    mld_mac_filter((struct netif *)iface, cb->info, NET_IF_DEL_MAC_FILTER);
}
#endif

static void wifi_net_event_handler(struct net_mgmt_event_callback *cb, uint32_t mgmt_event, struct net_if *iface)
{
    //const struct wifi_status *status = (const struct wifi_status *)cb->info;
    enum wifi_event_reason wifi_event_reason;

    switch (mgmt_event) {
        case NET_EVENT_IPV4_DHCP_BOUND:
            wifi_event_reason = WIFI_EVENT_REASON_SUCCESS;
            wlan_wlcmgr_send_msg(WIFI_EVENT_NET_DHCP_CONFIG, wifi_event_reason, NULL);
            break;
        case NET_EVENT_IPV4_MADDR_ADD:
            ipv4_mcast_add(cb, iface);
            break;
        case NET_EVENT_IPV4_MADDR_DEL:
            ipv4_mcast_delete(cb, iface);
            break;
#ifdef CONFIG_IPV6
        case NET_EVENT_IPV6_MADDR_ADD:
            ipv6_mcast_add(cb, iface);
            break;
        case NET_EVENT_IPV6_MADDR_DEL:
            ipv6_mcast_delete(cb, iface);
            break;
#endif
        default:
            net_d("Unhandled net event: %x", mgmt_event);
            break;
    }
}

int net_configure_address(struct wlan_ip_config *addr, void *intrfc_handle)
{
#ifndef CONFIG_ZEPHYR
#ifdef CONFIG_IPV6
    t_u8 i;
    ip_addr_t zero_addr = IPADDR6_INIT_HOST(0x0, 0x0, 0x0, 0x0);
#endif
#endif

    if (addr == NULL)
    {
        return -WM_E_INVAL;
    }
    if (intrfc_handle == NULL)
    {
        return -WM_E_INVAL;
    }

    interface_t *if_handle = (interface_t *)intrfc_handle;

#ifdef CONFIG_P2P
    net_d("configuring interface %s (with %s)", (if_handle == &g_mlan) ? "mlan" : (if_handle == &g_uap) ? "uap" : "wfd",
          (addr->ipv4.addr_type == ADDR_TYPE_DHCP) ? "DHCP client" : "Static IP");
#else
    net_d("configuring interface %s (with %s)", (if_handle == &g_mlan) ? "mlan" : "uap",
          (addr->ipv4.addr_type == ADDR_TYPE_DHCP) ? "DHCP client" : "Static IP");
#endif

    (void)net_if_down(if_handle->netif);

#ifndef CONFIG_ZEPHYR

    wm_netif_status_callback_ptr = NULL;

#ifdef CONFIG_IPV6
#ifdef RW610
    if (if_handle == &g_mlan || if_handle == &g_uap)
#else
    if (if_handle == &g_mlan)
#endif
    {
        LOCK_TCPIP_CORE();

        for (i = 0; i < CONFIG_MAX_IPV6_ADDRESSES; i++)
        {
            netif_ip6_addr_set(&if_handle->netif, i, ip_2_ip6(&zero_addr));
            netif_ip6_addr_set_state(&if_handle->netif, i, IP6_ADDR_INVALID);
        }

        netif_create_ip6_linklocal_address(&if_handle->netif, 1);

        UNLOCK_TCPIP_CORE();

        /* Explicitly call this function so that the linklocal address
         * gets updated even if the interface does not get any IPv6
         * address in its lifetime */
        if (if_handle == &g_mlan)
        {
            wm_netif_ipv6_status_callback(&if_handle->netif);
        }
    }
#endif
#endif

    if (if_handle == &g_mlan)
    {
        net_if_set_default(if_handle->netif);
    }

    switch (addr->ipv4.addr_type)
    {
        case ADDR_TYPE_STATIC:
            LOG_DBG("Debug set addr 0x%x", addr->ipv4.address);
            NET_IPV4_ADDR_U32(if_handle->ipaddr) = addr->ipv4.address;
            NET_IPV4_ADDR_U32(if_handle->nmask)  = addr->ipv4.netmask;
            NET_IPV4_ADDR_U32(if_handle->gw)     = addr->ipv4.gw;
            net_if_ipv4_addr_add(if_handle->netif, &if_handle->ipaddr.in_addr, NET_ADDR_MANUAL, 0);
            net_if_ipv4_set_gw(if_handle->netif, &if_handle->gw.in_addr);
            net_if_ipv4_set_netmask(if_handle->netif, &if_handle->nmask.in_addr);
            net_if_up(if_handle->netif);
            break;
        case ADDR_TYPE_DHCP:
            net_if_up(if_handle->netif);
            os_timer_activate(&dhcp_timer);
            net_dhcpv4_start(if_handle->netif);
            break;
        case ADDR_TYPE_LLA:
            /* For dhcp, instead of netifapi_netif_set_up, a
               netifapi_dhcp_start() call will be used */
            net_e("Not supported as of now...");
            break;
        default:
            net_d("Unexpected addr type");
            break;
    }
    /* Finally this should send the following event. */
    if ((if_handle == &g_mlan)
#ifdef CONFIG_P2P
        || ((if_handle == &g_wfd) && (netif_get_bss_type() == BSS_TYPE_STA))
#endif
    )
    {
        (void)wlan_wlcmgr_send_msg(WIFI_EVENT_NET_STA_ADDR_CONFIG, WIFI_EVENT_REASON_SUCCESS, NULL);

        /* XXX For DHCP, the above event will only indicate that the
         * DHCP address obtaining process has started. Once the DHCP
         * address has been obtained, another event,
         * WD_EVENT_NET_DHCP_CONFIG, should be sent to the wlcmgr.
         */
    }
    else if ((if_handle == &g_uap)
#ifdef CONFIG_P2P
             || ((if_handle == &g_wfd) && (netif_get_bss_type() == BSS_TYPE_UAP))
#endif
    )
    {
        (void)wlan_wlcmgr_send_msg(WIFI_EVENT_UAP_NET_ADDR_CONFIG, WIFI_EVENT_REASON_SUCCESS, NULL);
    }
    else
    { /* Do Nothing */
    }

    return WM_SUCCESS;
}

int net_get_if_addr(struct wlan_ip_config *addr, void *intrfc_handle)
{
    interface_t *if_handle = (interface_t *)intrfc_handle;
    struct net_if_ipv4 *ipv4 = if_handle->netif->config.ip.ipv4;

    addr->ipv4.address = NET_IPV4_ADDR_U32(ipv4->unicast[0].address);
    addr->ipv4.netmask = ipv4->netmask.s_addr;
    addr->ipv4.gw      = ipv4->gw.s_addr;

#if defined(CONFIG_DNS_RESOLVER)
    struct dns_resolve_context *ctx;

    /* DNS status */
    ctx = dns_resolve_get_default();
    if (ctx)
    {
        int i;

        for (i = 0; i < CONFIG_DNS_RESOLVER_MAX_SERVERS; i++)
        {
            if (ctx->servers[i].dns_server.sa_family == AF_INET)
            {
                if (i == 0)
                {
                    addr->ipv4.dns1 = net_sin(&ctx->servers[i].dns_server)->sin_addr.s_addr;
                }
                if (i == 1)
                {
                    addr->ipv4.dns2 = net_sin(&ctx->servers[i].dns_server)->sin_addr.s_addr;
                }
            }
        }
    }
#endif

    return WM_SUCCESS;
}

#ifdef CONFIG_IPV6
char *ipv6_addr_state_to_desc(unsigned char addr_state)
{
    if (addr_state == NET_ADDR_TENTATIVE)
    {
        return IPV6_ADDR_STATE_TENTATIVE;
    }
    else if (addr_state == NET_ADDR_PREFERRED)
    {
        return IPV6_ADDR_STATE_PREFERRED;
    }
    else if (addr_state == NET_ADDR_DEPRECATED)
    {
        return IPV6_ADDR_STATE_DEPRECATED;
    }
    else
    {
        return IPV6_ADDR_UNKNOWN;
    }
}

char *info = NULL;
char extra_info[NET_IPV6_ADDR_LEN];

char *ipv6_addr_addr_to_desc(struct ipv6_config *ipv6_conf)
{
    struct in6_addr ip6_addr;

    (void)memcpy((void *)&ip6_addr, (const void *)ipv6_conf->address, sizeof(ip6_addr));

    info = net_addr_ntop(AF_INET6, &ip6_addr, extra_info,
				     NET_IPV6_ADDR_LEN);

    return info;
}

char *ipv6_addr_type_to_desc(struct ipv6_config *ipv6_conf)
{
    struct in6_addr ip6_addr;

    (void)memcpy((void *)&ip6_addr, (const void *)ipv6_conf->address, sizeof(ip6_addr));

    if (net_ipv6_is_ll_addr(&ip6_addr))
    {
        return IPV6_ADDR_TYPE_LINKLOCAL;
    }
    else if (net_ipv6_is_global_addr(&ip6_addr))
    {
        return IPV6_ADDR_TYPE_GLOBAL;
    }
    else if (net_ipv6_is_ula_addr(&ip6_addr))
    {
        return IPV6_ADDR_TYPE_UNIQUELOCAL;
    }
    else if (net_ipv6_is_ll_addr(&ip6_addr))
    {
        return IPV6_ADDR_TYPE_SITELOCAL;
    }
    else
    {
        return IPV6_ADDR_UNKNOWN;
    }
}

int net_get_if_ipv6_addr(struct wlan_ip_config *addr, void *intrfc_handle)
{
    interface_t *if_handle = (interface_t *)intrfc_handle;
    int i;
    struct net_if_ipv6 *ipv6;
    struct net_if_addr *unicast;

    ipv6 = if_handle->netif->config.ip.ipv6;

    addr->ipv6_count = 0;

    for (i = 0; ipv6 && i < CONFIG_MAX_IPV6_ADDRESSES; i++)
    {
        unicast = &ipv6->unicast[i];

        if (!unicast->is_used)
        {
            continue;
        }

        (void)memcpy(addr->ipv6[i].address, &unicast->address.in6_addr, 16);
        addr->ipv6[i].addr_type = unicast->addr_type;
        addr->ipv6[i].addr_state = unicast->addr_state;
        addr->ipv6_count++;
    }
    /* TODO carry out more processing based on IPv6 fields in netif */
    return WM_SUCCESS;
}

int net_get_if_ipv6_pref_addr(struct wlan_ip_config *addr, void *intrfc_handle)
{
    int i, ret = 0;
    interface_t *if_handle = (interface_t *)intrfc_handle;
    struct net_if_ipv6 *ipv6;
    struct net_if_addr *unicast;
    //struct net_if_mcast_addr *mcast;

    ipv6 = if_handle->netif->config.ip.ipv6;

    addr->ipv6_count = 0;

    for (i = 0; ipv6 && i < CONFIG_MAX_IPV6_ADDRESSES; i++)
    {
        unicast = &ipv6->unicast[i];

        if (!unicast->is_used)
        {
            continue;
        }

        if (unicast->addr_state == NET_ADDR_PREFERRED)
        {
            (void)memcpy(addr->ipv6[ret++].address, &unicast->address.in6_addr, 16);
            addr->ipv6_count++;
        }
    }
    return ret;
}
#endif /* CONFIG_IPV6 */


int net_get_if_name(char *pif_name, void *intrfc_handle)
{
    interface_t *if_handle       = (interface_t *)intrfc_handle;
    const struct device *dev = NULL;
    dev = net_if_get_device((struct net_if *)if_handle->netif);
    strncpy(pif_name, dev->name, NETIF_NAMESIZE - 1);
    pif_name[NETIF_NAMESIZE - 1] = '\0';

    return WM_SUCCESS;
}

int net_get_if_ip_addr(uint32_t *ip, void *intrfc_handle)
{
    interface_t *if_handle = (interface_t *)intrfc_handle;
    struct net_if_ipv4 *ipv4 = if_handle->netif->config.ip.ipv4;

    *ip = NET_IPV4_ADDR_U32(ipv4->unicast[0].address);
    return WM_SUCCESS;
}

int net_get_if_ip_mask(uint32_t *nm, void *intrfc_handle)
{
    interface_t *if_handle = (interface_t *)intrfc_handle;
    struct net_if_ipv4 *ipv4 = if_handle->netif->config.ip.ipv4;

    *nm = ipv4->netmask.s_addr;
    return WM_SUCCESS;
}

void net_configure_dns(struct wlan_ip_config *ip, enum wlan_bss_role role)
{
    if (ip->ipv4.addr_type == ADDR_TYPE_STATIC)
    {
        if (role != WLAN_BSS_ROLE_UAP)
        {
            if (ip->ipv4.dns1 == 0U)
            {
                ip->ipv4.dns1 = ip->ipv4.gw;
            }
            if (ip->ipv4.dns2 == 0U)
            {
                ip->ipv4.dns2 = ip->ipv4.dns1;
            }
        }
        /* TODO: DNS server */
#if 0
        ip4_addr_t tmp;

        tmp.addr = ip->ipv4.dns1;
        dns_setserver(0, (ip_addr_t *)(void *)&tmp);
        tmp.addr = ip->ipv4.dns2;
        dns_setserver(1, (ip_addr_t *)(void *)&tmp);
#endif
    }

    /* DNS MAX Retries should be configured in lwip/dns.c to 3/4 */
    /* DNS Cache size of about 4 is sufficient */
}

void net_stat(void)
{
    //net_print_statistics();
}

static void setup_mgmt_events(void)
{
    net_mgmt_init_event_callback(&net_event_v4_cb, wifi_net_event_handler, MCASTV4_MASK | DHCPV4_MASK);

    net_mgmt_add_event_callback(&net_event_v4_cb);

#ifdef CONFIG_IPV6
    net_mgmt_init_event_callback(&net_event_v6_cb, wifi_net_event_handler, MCASTV6_MASK);

    net_mgmt_add_event_callback(&net_event_v6_cb);
#endif
}

int net_wlan_init(void)
{
    int ret;

    wifi_register_data_input_callback(&handle_data_packet);
    wifi_register_amsdu_data_input_callback(&handle_amsdu_data_packet);
    wifi_register_deliver_packet_above_callback(&handle_deliver_packet_above);
    wifi_register_wrapper_net_is_ip_or_ipv6_callback(&wrapper_net_is_ip_or_ipv6);

    if (!net_wlan_init_done)
    {
        /* init STA netif */
        ret = wlan_get_mac_address(g_mlan.state.ethaddr.addr);
        if (ret != 0)
        {
            net_e("could not get STA wifi mac addr");
            return ret;
        }

        net_if_set_link_addr(g_mlan.netif, g_mlan.state.ethaddr.addr, NET_MAC_ADDR_LEN, NET_LINK_ETHERNET);
        ethernet_init(g_mlan.netif);

        /* init uAP netif */
        ret = wlan_get_mac_address_uap(g_uap.state.ethaddr.addr);
        if (ret != 0)
        {
            net_e("could not get uAP wifi mac addr");
            return ret;
        }

        net_if_set_link_addr(g_uap.netif, g_uap.state.ethaddr.addr, NET_MAC_ADDR_LEN, NET_LINK_ETHERNET);
        ethernet_init(g_uap.netif);

        net_wlan_init_done = 1;
        net_d("Initialized TCP/IP networking stack");

        ret = os_timer_create(&dhcp_timer, "dhcp-timer", os_msec_to_ticks(DHCP_TIMEOUT), &dhcp_timer_cb, NULL,
                              OS_TIMER_ONE_SHOT, OS_TIMER_NO_ACTIVATE);
        if (ret != WM_SUCCESS)
        {
            net_e("Unable to start dhcp timer");
            return ret;
        }
    }

    setup_mgmt_events();

    LOG_DBG("Initialized TCP/IP networking stack");
    wlan_wlcmgr_send_msg(WIFI_EVENT_NET_INTERFACE_CONFIG, WIFI_EVENT_REASON_SUCCESS, NULL);
    return WM_SUCCESS;
}

void net_wlan_set_mac_address(unsigned char *sta_mac, unsigned char *uap_mac)
{
    (void)memcpy(g_mlan.state.ethaddr.addr, &sta_mac[0], MLAN_MAC_ADDR_LENGTH);
    (void)memcpy(g_uap.state.ethaddr.addr, &uap_mac[0], MLAN_MAC_ADDR_LENGTH);

    net_if_set_link_addr(g_mlan.netif, sta_mac, NET_MAC_ADDR_LEN, NET_LINK_ETHERNET);
    net_if_set_link_addr(g_uap.netif, uap_mac, NET_MAC_ADDR_LEN, NET_LINK_ETHERNET);
}

static int net_netif_deinit(struct net_if *netif)
{
#if 0
    int ret;
#ifdef CONFIG_IPV6
    if (netif->mld_mac_filter != NULL)
    {
        ip6_addr_t ip6_allnodes_ll;
        ip6_addr_set_allnodes_linklocal(&ip6_allnodes_ll);
        (void)netif->mld_mac_filter(netif, &ip6_allnodes_ll, NETIF_DEL_MAC_FILTER);
    }
#endif
    ret = netifapi_netif_remove(netif);

    if (ret != WM_SUCCESS)
    {
        net_e("Interface remove failed");
        return -WM_FAIL;
    }

    if (netif->state != NULL)
    {
#ifndef CONFIG_WPA_SUPP
        mem_free(netif->state);
#endif
        netif->state = NULL;
    }
#endif
    return WM_SUCCESS;
}

int net_wlan_deinit(void)
{
    int ret;

    if (net_wlan_init_done != 1)
    {
        return -WM_FAIL;
    }

    ret = net_netif_deinit(g_mlan.netif);
    if (ret != WM_SUCCESS)
    {
        net_e("MLAN interface deinit failed");
        return -WM_FAIL;
    }

    ret = net_netif_deinit(g_uap.netif);
    if (ret != WM_SUCCESS)
    {
        net_e("UAP interface deinit failed");
        return -WM_FAIL;
    }

    ret = os_timer_delete(&dhcp_timer);
    if (ret != WM_SUCCESS)
    {
        net_e("DHCP timer deletion failed");
        return -WM_FAIL;
    }

#ifndef CONFIG_ZEPHYR
    LOCK_TCPIP_CORE();
    netif_remove_ext_callback(&netif_ext_callback);
    UNLOCK_TCPIP_CORE();
    wm_netif_status_callback_ptr = NULL;
#endif

    net_wlan_init_done           = 0;

    LOG_DBG("DeInitialized TCP/IP networking stack");

    return WM_SUCCESS;
}

#ifdef CONFIG_NET_STATISTICS_WIFI
int z_wpa_supplicant_get_stats(const struct device *dev,
				struct net_stats_wifi *stats)
{
    PRINTF("%s\r\n", __func__);

    return 0;
}
#endif

static int z_wpa_supplicant_set_power_save(const struct device *dev,
				struct wifi_ps_params *params)
{
    PRINTF("%s\r\n", __func__);

    return 0;
}

static int z_wpa_supplicant_set_twt(const struct device *dev,
				struct wifi_twt_params *params)
{
    PRINTF("%s\r\n", __func__);

    return 0;
}

int z_wpa_supplicant_get_power_save_config(const struct device *dev,
				struct wifi_ps_config *config)
{
    PRINTF("%s\r\n", __func__);

    return 0;
}

int z_wpa_supplicant_reg_domain(const struct device *dev,
				struct wifi_reg_domain *reg_domain)
{
    PRINTF("%s\r\n", __func__);

    return 0;
}

static const struct net_wifi_mgmt_offload wifi_netif_apis = {
	.wifi_iface.iface_api.init = wifi_net_iface_init,
	.wifi_iface.send = low_level_output,
	.scan = WPL_Scan,
	.connect = WPL_Connect,
	.disconnect = WPL_Disconnect,
        .ap_enable = WPL_Start_AP,
        .ap_disable = WPL_Stop_AP,
	.iface_status = WPL_Status,
#ifdef CONFIG_NET_STATISTICS_WIFI
	.get_stats = z_wpa_supplicant_get_stats,
#endif
	.set_power_save = z_wpa_supplicant_set_power_save,
	.set_twt = z_wpa_supplicant_set_twt,
	.get_power_save_config = z_wpa_supplicant_get_power_save_config,
	.reg_domain = z_wpa_supplicant_reg_domain,
};


NET_DEVICE_INIT_INSTANCE(wifi_nxp_sta, "ml", 0, wifi_net_init, NULL, &g_mlan,
#ifdef CONFIG_WPA_SUPP
    &wpa_supp_ops,
#else
    NULL,
#endif
    CONFIG_ETH_INIT_PRIORITY, &wifi_netif_apis,
    ETHERNET_L2, NET_L2_GET_CTX_TYPE(ETHERNET_L2), NET_ETH_MTU);

NET_DEVICE_INIT_INSTANCE(wifi_nxp_uap, "ua", 1, wifi_net_init, NULL, &g_uap,
#ifdef CONFIG_WPA_SUPP
    &wpa_supp_ops,
#else
    NULL,
#endif
    CONFIG_ETH_INIT_PRIORITY, &wifi_netif_apis,
    ETHERNET_L2, NET_L2_GET_CTX_TYPE(ETHERNET_L2), NET_ETH_MTU);


const struct netif *net_if_get_binding(const char *ifname)
{
    struct netif *iface = NULL;
    const struct device *dev = NULL;

    dev = device_get_binding(ifname);
    if (!dev) {
        return NULL;
    }

    iface = (struct netif *)net_if_lookup_by_dev(dev);
    if (!iface) {
        return NULL;
    }

    return iface;
}

const struct freertos_wpa_supp_dev_ops *net_if_get_dev_config(struct netif* iface)
{
    const struct freertos_wpa_supp_dev_ops *dev_ops = NULL;
    const struct device *dev = NULL;

    dev = net_if_get_device((struct net_if *)iface);
    dev_ops = dev->config;

    return dev_ops;
}
