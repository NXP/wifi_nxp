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

struct iw416_data {
	struct net_if *iface;
	uint8_t mac_addr[6U];
	struct ethernetif state;
	struct k_mutex tx_mutex;
};

struct iw416_data iw416_data;

typedef struct {
    struct net_if *netif;
    struct net_addr ipaddr;
    struct net_addr nmask;
    struct net_addr gw;
    struct ethernetif state;
} interface_t;

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
            lwiperr = net_recv_data(iw416_data.iface, p);
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

static struct net_pkt *gen_pkt_from_data(t_u8 *payload, t_u16 datalen)
{
    /* We allocate a network buffer */
    struct net_pkt *pkt = net_pkt_rx_alloc_with_buffer(iw416_data.iface, datalen,
    	AF_UNSPEC, 0, K_NO_WAIT);
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
    struct net_pkt *p = gen_pkt_from_data(payload, rxpd->rx_pkt_length);
    /* If there are no more buffers, we do nothing, so the data is
       lost. We have to go back and read the other ports */
    if (p == NULL)
    {
        return;
    }


    /* points to packet payload, which starts with an Ethernet header */
    struct net_eth_hdr *ethhdr = NET_ETH_HDR(p);

#ifdef CONFIG_FILTER_LOCALLY_ADMINISTERED_AND_SELF_MAC_ADDR
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
    struct net_pkt *p = gen_pkt_from_data(rcvdata, datalen);
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

int wlan_event_callback(enum wlan_event_reason reason, void *data)
{
    static int auth_fail = 0;

    printSeparator();
    printk("app_cb: WLAN: received event %d\n", reason);
    printSeparator();

    switch (reason)
    {
        case WLAN_REASON_INITIALIZED:
        	printk("app_cb: WLAN initialized\n");
        	break;
        case WLAN_REASON_INITIALIZATION_FAILED:
        	printk("app_cb: WLAN: initialization failed\n");
        	break;
        case WLAN_REASON_AUTH_SUCCESS:
        	printk("app_cb: WLAN: authenticated to network\n");
		/* Add network interface callbacks to wifi manager */
        //(void)wifi_register_data_input_callback(&handle_data_packet);
        //(void)wifi_register_amsdu_data_input_callback(&handle_amsdu_data_packet);
        //(void)wifi_register_deliver_packet_above_callback(&handle_deliver_packet_above);
        //(void)wifi_register_wrapper_net_is_ip_or_ipv6_callback(&wrapper_net_is_ip_or_ipv6);
        /* Mark the interface as up */
		net_if_up(iw416_data.iface);
		/* Notify the wlan manager that the TCP stack is ready */
 		wlan_wlcmgr_send_msg(WIFI_EVENT_NET_STA_ADDR_CONFIG,
			WIFI_EVENT_REASON_SUCCESS, NULL);
        	break;
        case WLAN_REASON_SUCCESS:
        	printk("app_cb: WLAN: connect succeeded\n");
		    /* Mark interface as up */
		    net_eth_carrier_on(iw416_data.iface);
        	break;
        case WLAN_REASON_CONNECT_FAILED:
        	printk("app_cb: WLAN: connect failed\n");
		    net_eth_carrier_off(iw416_data.iface);
        	break;
        case WLAN_REASON_NETWORK_NOT_FOUND:
        	printk("app_cb: WLAN: network not found\n");
		    net_eth_carrier_off(iw416_data.iface);
        	break;
        case WLAN_REASON_NETWORK_AUTH_FAILED:
        	printk("app_cb: WLAN: network authentication failed\n");
		    net_eth_carrier_off(iw416_data.iface);
        	break;
        case WLAN_REASON_ADDRESS_SUCCESS:
        	printk("network mgr: DHCP new lease\n");
        	break;
        case WLAN_REASON_ADDRESS_FAILED:
        	printk("app_cb: failed to obtain an IP address\n");
        	break;
        case WLAN_REASON_USER_DISCONNECT:
        	printk("app_cb: disconnected\n");
		    net_eth_carrier_off(iw416_data.iface);
        	auth_fail = 0;
        	break;
        case WLAN_REASON_LINK_LOST:
        	printk("app_cb: WLAN: link lost\n");
        	break;
        case WLAN_REASON_CHAN_SWITCH:
        	printk("app_cb: WLAN: channel switch\n");
        	break;
        case WLAN_REASON_UAP_SUCCESS:
        	printk("app_cb: WLAN: UAP Started\n");
        	break;
        case WLAN_REASON_UAP_CLIENT_ASSOC:
           	printk("app_cb: WLAN: UAP a Client Associated\n");
          	break;
        case WLAN_REASON_UAP_CLIENT_DISSOC:
        	printk("app_cb: WLAN: UAP a Client Dissociated\n");
        	break;
        case WLAN_REASON_UAP_STOPPED:
        	printk("app_cb: WLAN: UAP Stopped\n");
        	break;
        case WLAN_REASON_PS_ENTER:
        	printk("app_cb: WLAN: PS_ENTER\n");
        	break;
        case WLAN_REASON_PS_EXIT:
        	printk("app_cb: WLAN: PS EXIT\n");
        	break;
        default:
        	printk("app_cb: WLAN: Unknown Event: %d\n", reason);
    }
    return 0;
}

K_THREAD_STACK_DEFINE(net_wifi_init_stack, CONFIG_WIFI_INIT_STACK_SIZE);
struct k_thread net_wifi_thread;

extern void WL_MCI_WAKEUP0_DriverIRQHandler(void);

/* IW416 network init thread */
void net_wifi_init_thread(void *dev, void* arg2, void *arg3)
{
	const struct device *iw416_dev = dev;
	struct iw416_data *data = iw416_dev->data;
	wifi_mac_addr_t mac_addr;
	int ret;

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

volatile int g_debug_run_flag = 1;
int debug_cnt;
static int wifi_net_init(const struct device *dev)
{
    while (g_debug_run_flag != 0)
    {
        debug_cnt++;
    }
    g_debug_run_flag = 0;
    return 0;
}

static int wifi_net_init_thread(const struct device *dev)
{
    LOG_ERR("Debug In %s", __func__);

    g_mlan.state.interface = WLAN_BSS_TYPE_STA;
    g_uap.state.interface  = WLAN_BSS_TYPE_UAP;

    /* TODO: do we have to init in new thread? */
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
        wlan_shell_init();
        init_done = 1;
    }

    /* Don't start iface until wifi connects */
    net_if_flag_set(iface, NET_IF_NO_AUTO_START);

    /* Get the MAC address of the wifi device */
    if (intf->state.interface == WLAN_BSS_TYPE_STA)
    {
        ret = wlan_get_mac_address(intf->state.ethaddr.addr);
        if (ret != 0)
        {
            LOG_ERR("could not get STA wifi mac addr");
            return;
        }
    }
    else if (intf->state.interface == WLAN_BSS_TYPE_UAP)
    {
        ret = wlan_get_mac_address_uap(intf->state.ethaddr.addr);
        if (ret != 0)
        {
            LOG_ERR("could not get uAP wifi mac addr");
            return;
        }
    }
    else
    {
        LOG_ERR("unknown interface bss type %d", intf->state.interface);
        return;
    }

    net_if_set_link_addr(iface, intf->state.ethaddr.addr, NET_MAC_ADDR_LEN, NET_LINK_ETHERNET);
    ethernet_init(iface);

    LOG_ERR("wifi_net_iface_init complete %d", intf->state.interface);
}

static int low_level_output(const struct device *dev, struct net_pkt *pkt)
{
    int ret;
    uint32_t header_pkt_len, outbuf_len;
    uint16_t net_pkt_len = net_pkt_get_len(pkt);
    struct iw416_data *data = dev->data;
    struct ethernetif *ethernetif = &data->state;

    k_mutex_lock(&data->tx_mutex, K_FOREVER);
#ifdef CONFIG_WMM
    t_u8 tid;
    int retry         = retry_attempts;
    bool is_udp_frame = false;
    int pkt_prio      = wifi_wmm_get_pkt_prio(p->payload, &tid, &is_udp_frame);
    if (pkt_prio == -WM_FAIL)
    {
    	k_mutex_unlock(&data->tx_mutex);
        return -ENOMEM;
    }
    ret = is_wifi_wmm_queue_full(pkt_prio);
    while (ret == true && !is_udp_frame && retry > 0)
    {
        os_thread_sleep(os_msec_to_ticks(1));
        ret = is_wifi_wmm_queue_full(pkt_prio);
        retry--;
    }
    if (ret == true)
    {
    	k_mutex_unlock(&data->tx_mutex);
        return -ENOMEM;
    }
    uint8_t *outbuf = wifi_wmm_get_outbuf(&outbuf_len, pkt_prio);
#else
    uint8_t *outbuf = wifi_get_outbuf(&outbuf_len);
#endif
    if (outbuf == NULL)
    {
    	k_mutex_unlock(&data->tx_mutex);
        return -ENOMEM;
    }

    header_pkt_len = sizeof(TxPD) + INTF_HEADER_LEN;
    if ((header_pkt_len + net_pkt_len) > outbuf_len) {
	    while (true) {
		    printk("Panic: not enough storage in wifi outbuf\n");
		    k_msleep(3000);
	    }
    }
    (void)memset(outbuf, 0x00, header_pkt_len + net_pkt_len);

    if (net_pkt_read(pkt, outbuf + header_pkt_len, net_pkt_len)) {
    	k_mutex_unlock(&data->tx_mutex);
        return -EIO;
    }


    ret = wifi_low_level_output(ethernetif->interface, outbuf + header_pkt_len,
                                net_pkt_len
#ifdef CONFIG_WMM
                                ,
                                pkt_prio, tid
#endif
    );

    if (ret == -WM_E_NOMEM)
    {
	LOG_ERR("Wifi Net OOM");
        ret = -ENOMEM;
    }
    else if (ret == -WM_E_BUSY)
    {
	LOG_ERR("Wifi Net Busy");
        ret = -ETIMEDOUT;
    }
    else if (ret == WM_SUCCESS)
    {
        ret = 0;
    }
    else
    { /* Do Nothing */
    }

    k_mutex_unlock(&data->tx_mutex);
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
            /* TODO: DHCP */
#if 0
            /* Reset the address since we might be
               transitioning from static to DHCP */
            (void)memset(&if_handle->ipaddr, 0, sizeof(ip_addr_t));
            (void)memset(&if_handle->nmask, 0, sizeof(ip_addr_t));
            (void)memset(&if_handle->gw, 0, sizeof(ip_addr_t));
            (void)netifapi_netif_set_addr(&if_handle->netif, ip_2_ip4(&if_handle->ipaddr), ip_2_ip4(&if_handle->nmask),
                                          ip_2_ip4(&if_handle->gw));
            (void)netifapi_netif_set_up(&if_handle->netif);
            (void)os_timer_activate(&dhcp_timer);
            wm_netif_status_callback_ptr = wm_netif_status_callback;
            (void)netifapi_dhcp_start(&if_handle->netif);
#endif
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

    addr->ipv4.address = NET_IPV4_ADDR_U32(if_handle->ipaddr);
    addr->ipv4.netmask = NET_IPV4_ADDR_U32(if_handle->nmask);
    addr->ipv4.gw      = NET_IPV4_ADDR_U32(if_handle->gw);

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
void dhcp_server_stop()
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
#if 0
        net_ipv4stack_init();

        ip_2_ip4(&g_mlan.ipaddr)->addr = INADDR_ANY;
        ret = netifapi_netif_add(&g_mlan.netif, ip_2_ip4(&g_mlan.ipaddr), ip_2_ip4(&g_mlan.ipaddr),
                                 ip_2_ip4(&g_mlan.ipaddr), NULL, lwip_netif_init, tcpip_input);
        if (ret != 0)
        {
            net_e("MLAN interface add failed");
            return -WM_FAIL;
        }
#ifdef CONFIG_IPV6
        net_ipv6stack_init(&g_mlan.netif);
#endif /* CONFIG_IPV6 */

        ret = netifapi_netif_add(&g_uap.netif, ip_2_ip4(&g_uap.ipaddr), ip_2_ip4(&g_uap.ipaddr),
                                 ip_2_ip4(&g_uap.ipaddr), NULL, lwip_netif_uap_init, tcpip_input);
        if (ret != 0)
        {
            net_e("UAP interface add failed");
            return -WM_FAIL;
        }
#ifdef CONFIG_IPV6
        net_ipv6stack_init(&g_uap.netif);
#endif /* CONFIG_IPV6 */

#ifdef CONFIG_P2P
        g_wfd.ipaddr.addr = INADDR_ANY;
        ret               = netifapi_netif_add(&g_wfd.netif, ip_2_ip4(&g_wfd.ipaddr), ip_2_ip4(&g_wfd.ipaddr),
                                 ip_2_ip4(&g_wfd.ipaddr), NULL, lwip_netif_wfd_init, tcpip_input);
        if (ret)
        {
            net_e("P2P interface add failed\r\n");
            return -WM_FAIL;
        }
#endif

        LOCK_TCPIP_CORE();
        netif_add_ext_callback(&netif_ext_callback, netif_ext_status_callback);
        UNLOCK_TCPIP_CORE();

        net_wlan_init_done = 1;

        net_l("Initialized TCP/IP networking stack");
#endif
        ret = os_timer_create(&dhcp_timer, "dhcp-timer", os_msec_to_ticks(DHCP_TIMEOUT), &dhcp_timer_cb, NULL,
                              OS_TIMER_ONE_SHOT, OS_TIMER_NO_ACTIVATE);
        if (ret != WM_SUCCESS)
        {
            net_e("Unable to start dhcp timer");
            return ret;
        }
    }

    LOG_ERR("Initialized TCP/IP networking stack");
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
