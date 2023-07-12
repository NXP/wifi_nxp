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
LOG_MODULE_REGISTER(iw416_wifi, CONFIG_WIFI_LOG_LEVEL);

#include "wlan_bt_fw.h"
#include "wlan.h"
#include "wifi.h"
#include <wm_os.h>
#include "netif_decl.h"

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
        (void)wifi_register_data_input_callback(&handle_data_packet);
        (void)wifi_register_amsdu_data_input_callback(&handle_amsdu_data_packet);
        (void)wifi_register_deliver_packet_above_callback(&handle_deliver_packet_above);
        (void)wifi_register_wrapper_net_is_ip_or_ipv6_callback(&wrapper_net_is_ip_or_ipv6);
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


int iw416_init(const struct device *dev)
{
	return 0;
}

K_THREAD_STACK_DEFINE(iw416_init_stack, CONFIG_WIFI_INIT_STACK_SIZE);
struct k_thread iw416_thread;

extern void WL_MCI_WAKEUP0_DriverIRQHandler(void);
volatile int g_debug_run_flag = 1;
int debug_cnt;
/* IW416 network init thread */
void iw416_init_thread(void *dev, void* arg2, void *arg3)
{
	const struct device *iw416_dev = dev;
	struct iw416_data *data = iw416_dev->data;
	wifi_mac_addr_t mac_addr;
	int ret;
#if 0
    while (g_debug_run_flag != 0)
    {
        debug_cnt++;
    }
#endif
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
	/* Get the MAC address of the wifi device */
	ret = wifi_get_device_mac_addr(&mac_addr);
	if (ret) {
		LOG_ERR("could not get wifi mac addr");
		return;
	}
	memcpy(data->mac_addr, mac_addr.mac, 6U);
	net_if_set_link_addr(data->iface, data->mac_addr, 6, NET_LINK_ETHERNET);
	ethernet_init(data->iface);
	/* Signal to wifi subsystem that network config is done */
	wlan_wlcmgr_send_msg(WIFI_EVENT_NET_INTERFACE_CONFIG,
		WIFI_EVENT_REASON_SUCCESS, NULL);
	LOG_INF("wifi init thread complete");
}

static void iw416_iface_init(struct net_if *iface)
{
	const struct device *dev = net_if_get_device(iface);
	struct iw416_data *data = dev->data;

	data->iface = iface;
	data->state.interface = MLAN_BSS_TYPE_STA;
	data->state.ethaddr = (struct eth_addr *)data->mac_addr;
	k_mutex_init(&data->tx_mutex);

	/* Don't start iface until wifi connects */
	net_if_flag_set(iface, NET_IF_NO_AUTO_START);

	/* Kick off the init thread */
	k_thread_create(&iw416_thread, iw416_init_stack,
		K_THREAD_STACK_SIZEOF(iw416_init_stack),
		iw416_init_thread, (void *)dev, NULL, NULL,
		0, 0, K_NO_WAIT);
}

static int iw416_send(const struct device *dev, struct net_pkt *pkt)
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


static const struct ethernet_api iw416_apis = {
	.iface_api.init	= iw416_iface_init,
	.send =  iw416_send,
};

NET_DEVICE_INIT(iw416, "IW416", iw416_init,
	NULL, &iw416_data, NULL, CONFIG_ETH_INIT_PRIORITY,
	&iw416_apis, ETHERNET_L2, NET_L2_GET_CTX_TYPE(ETHERNET_L2),
	NET_ETH_MTU);
