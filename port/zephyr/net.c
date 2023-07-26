/**
 * @file net.c
 * Shim layer between wifi driver connection manager and zephyr
 * ethernet L2 layer
 */

#include <zephyr/net/ethernet.h>
#include <zephyr/net/net_pkt.h>
#include <zephyr/net/net_if.h>
#include <zephyr/device.h>
#include <soc.h>
#include <ethernet/eth_stats.h>
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(wifi_nxp, CONFIG_WIFI_LOG_LEVEL);

#include "wlan_bt_fw.h"
#include "wlan.h"
#include "wifi.h"
#include <wm_os.h>
#include "netif_decl.h"
#include "wm_net.h"
#include "wifi_shell.h"
#ifdef CONFIG_WPA_SUPP
#include "wifi_nxp.h"

extern const rtos_wpa_supp_dev_ops wpa_supp_ops;
#else
static int wpa_supp_ops = 0;
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
} interface_t;

static struct net_mgmt_event_callback wifi_dhcp_cb;
#define DHCPV4_MASK (NET_EVENT_IPV4_DHCP_BOUND | NET_EVENT_IPV4_DHCP_STOP)

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

    if (net_pkt_write(pkt, payload, datalen) != 0) {
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

    if (!memcmp((t_u8 *)payload + SIZEOF_ETH_HDR, rfc1042_eth_hdr, sizeof(rfc1042_eth_hdr)))
    {
        struct eth_llc_hdr *ethllchdr = (struct eth_llc_hdr *)(void *)((t_u8 *)payload + SIZEOF_ETH_HDR);
        ethhdr->type                  = ethllchdr->type;
	net_pkt_skip(p, SIZEOF_ETH_LLC_HDR);
    }
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
    if (interface == MLAN_BSS_TYPE_STA)
    {
        process_data_packet(rcvdata, datalen);
    }
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
            PRINTF("app_cb: WLAN: authenticated to network\r\n");
            break;
        case WLAN_REASON_SUCCESS:
            net_eth_carrier_on(g_mlan.netif);
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
                    (void)PRINTF("IPv6 Address: %-13s:\t%s (%s)\r\n", ipv6_addr_type_to_desc(&addr.ipv6[i]),
                                 inet6_ntoa(addr.ipv6[i].address), ipv6_addr_state_to_desc(addr.ipv6[i].addr_state));
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

K_THREAD_STACK_DEFINE(net_wifi_init_stack, CONFIG_WIFI_INIT_STACK_SIZE);
struct k_thread net_wifi_thread;

extern void WL_MCI_WAKEUP0_DriverIRQHandler(void);

/* IW416 network init thread */
void net_wifi_init_thread(void *dev, void* arg2, void *arg3)
{
	int ret;
    LOG_ERR("Debug In %s", __func__);

    IRQ_CONNECT(72, 1, WL_MCI_WAKEUP0_DriverIRQHandler, 0, 0);
    irq_enable(72);

	/* Initialize the wifi subsystem */
	ret = wlan_init(wlan_fw_bin, wlan_fw_bin_len);
	if (ret) {
		LOG_ERR("wlan initialization failed");
		return;
	}
	ret = wlan_start(wlan_event_callback);
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
    LOG_ERR("Debug In %s", __func__);

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
    int ret;
    const struct device *dev = net_if_get_device(iface);
    interface_t *intf = dev->data;

    intf->netif = iface;

    LOG_ERR("Debug In %s", __func__);

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
        LOG_ERR("Wifi Net OOM");
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
#if 0
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
#if 0
    wm_netif_status_callback_ptr = NULL;
#endif
}

static void wifi_net_event_handler(struct net_mgmt_event_callback *cb, uint32_t mgmt_event, struct net_if *iface)
{
    const struct wifi_status *status = (const struct wifi_status *)cb->info;
    enum wifi_event_reason wifi_event_reason;

    switch (mgmt_event) {
        case NET_EVENT_IPV4_DHCP_BOUND:
            wifi_event_reason = WIFI_EVENT_REASON_SUCCESS;
            wlan_wlcmgr_send_msg(WIFI_EVENT_NET_DHCP_CONFIG, wifi_event_reason, NULL);
            break;
        default:
            break;
    }
}

int net_configure_address(struct wlan_ip_config *addr, void *intrfc_handle)
{
#ifdef CONFIG_IPV6
    t_u8 i;
    ip_addr_t zero_addr = IPADDR6_INIT_HOST(0x0, 0x0, 0x0, 0x0);
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
#if 0
    wm_netif_status_callback_ptr = NULL;
#endif

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

    if (if_handle == &g_mlan)
    {
        net_if_set_default(if_handle->netif);
    }

    switch (addr->ipv4.addr_type)
    {
        case ADDR_TYPE_STATIC:
            LOG_ERR("Debug set addr 0x%x", addr->ipv4.address);
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
            net_mgmt_init_event_callback(&wifi_dhcp_cb, wifi_net_event_handler, DHCPV4_MASK);
            net_mgmt_add_event_callback(&wifi_dhcp_cb);
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

    /* TODO: if need DNS server */
#if 0
    const ip_addr_t *tmp;

    tmp             = dns_getserver(0);
    addr->ipv4.dns1 = ip_2_ip4(tmp)->addr;
    tmp             = dns_getserver(1);
    addr->ipv4.dns2 = ip_2_ip4(tmp)->addr;
#endif
    return WM_SUCCESS;
}

#ifdef CONFIG_IPV6
int net_get_if_ipv6_addr(struct wlan_ip_config *addr, void *intrfc_handle)
{
    interface_t *if_handle = (interface_t *)intrfc_handle;
    int i;

    for (i = 0; i < CONFIG_MAX_IPV6_ADDRESSES; i++)
    {
        (void)memcpy(addr->ipv6[i].address, ip_2_ip6(&(if_handle->netif.ip6_addr[i]))->addr, 16);
        addr->ipv6[i].addr_state = if_handle->netif.ip6_addr_state[i];
    }
    /* TODO carry out more processing based on IPv6 fields in netif */
    return WM_SUCCESS;
}

int net_get_if_ipv6_pref_addr(struct wlan_ip_config *addr, void *intrfc_handle)
{
    int i, ret = 0;
    interface_t *if_handle = (interface_t *)intrfc_handle;

    for (i = 0; i < CONFIG_MAX_IPV6_ADDRESSES; i++)
    {
        if (if_handle->netif.ip6_addr_state[i] == IP6_ADDR_PREFERRED)
        {
            (void)memcpy(addr->ipv6[ret++].address, ip_2_ip6(&(if_handle->netif.ip6_addr[i]))->addr, 16);
        }
    }
    return ret;
}
#endif /* CONFIG_IPV6 */

/* TODO: DHCP server */
int dhcp_server_start(void *intrfc_handle)
{
    return 0;
}

void dhcp_server_stop(void)
{
}

#if 0
int net_get_if_name(char *pif_name, void *intrfc_handle)
{
    interface_t *if_handle       = (interface_t *)intrfc_handle;
    char if_name[NETIF_NAMESIZE] = {0};
    int ret;

    ret = netifapi_netif_index_to_name(if_handle->netif.num + 1, if_name);

    if (ret != WM_SUCCESS)
    {
        net_e("get interface name failed");
        return -WM_FAIL;
    }

    (void)strncpy(pif_name, if_name, NETIF_NAMESIZE);

    return WM_SUCCESS;
}

int net_get_if_ip_addr(uint32_t *ip, void *intrfc_handle)
{
    interface_t *if_handle = (interface_t *)intrfc_handle;

    *ip = ip_2_ip4(&(if_handle->netif.ip_addr))->addr;
    return WM_SUCCESS;
}

int net_get_if_ip_mask(uint32_t *nm, void *intrfc_handle)
{
    interface_t *if_handle = (interface_t *)intrfc_handle;

    *nm = ip_2_ip4(&(if_handle->netif.netmask))->addr;
    return WM_SUCCESS;
}
#endif /* DHCP server */

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

int net_wlan_init(void)
{
    int ret;

    LOG_ERR("Debug In %s", __func__);

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
            return;
        }

        net_if_set_link_addr(g_mlan.netif, g_mlan.state.ethaddr.addr, NET_MAC_ADDR_LEN, NET_LINK_ETHERNET);
        ethernet_init(g_mlan.netif);

        /* init uAP netif */
        ret = wlan_get_mac_address_uap(g_uap.state.ethaddr.addr);
        if (ret != 0)
        {
            net_e("could not get uAP wifi mac addr");
            return;
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

    LOG_ERR("Debug Initialized TCP/IP networking stack");
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

#if 0
    LOCK_TCPIP_CORE();
    netif_remove_ext_callback(&netif_ext_callback);
    UNLOCK_TCPIP_CORE();
    wm_netif_status_callback_ptr = NULL;
#endif

    net_wlan_init_done           = 0;

    LOG_ERR("DeInitialized TCP/IP networking stack");

    return WM_SUCCESS;
}

static const struct ethernet_api wifi_netif_apis = {
	.iface_api.init	= wifi_net_iface_init,
	.send =  low_level_output,
};

NET_DEVICE_INIT(wifi_nxp_sta, "WIFI_NXP_STA", wifi_net_init,
    NULL, &g_mlan, NULL, CONFIG_ETH_INIT_PRIORITY,
    &wifi_netif_apis, ETHERNET_L2, NET_L2_GET_CTX_TYPE(ETHERNET_L2),
    NET_ETH_MTU);

NET_DEVICE_INIT(wifi_nxp_uap, "WIFI_NXP_UAP", wifi_net_init,
    NULL, &g_uap, NULL, CONFIG_ETH_INIT_PRIORITY,
    &wifi_netif_apis, ETHERNET_L2, NET_L2_GET_CTX_TYPE(ETHERNET_L2),
    NET_ETH_MTU);
