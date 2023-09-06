/** @file main.c
 *
 *  @brief main file
 *
 *  Copyright 2020 NXP
 *  All rights reserved.
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 */

///////////////////////////////////////////////////////////////////////////////
//  Includes
///////////////////////////////////////////////////////////////////////////////

// SDK Included Files
#include "board.h"
#include "fsl_debug_console.h"
#include "wlan_bt_fw.h"
#include "wlan.h"
#include "wifi.h"
#include "wm_net.h"
#include <wm_os.h>
#include "dhcp-server.h"
#include "wifi_ping.h"
#include "app.h"
#include "fsl_usart_freertos.h"
#include "fsl_usart.h"
#include "lwiperf.h"
#include "lwip/tcpip.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define CONFIG_BRIDGE_STACK_SIZE 4096

#define IN_QUEUE_SIZE 4

#define BRIDGE_COMMAND_LEN         9
#define TLV_HEADER_LEN             3
#define BRIDGE_RESPONSE_LEN        9
#define BRIDGE_CMD_HEADER_LEN      4
#define BRIDGE_INBUF_SIZE          1383
#define BRIDGE_CONNECT_RES_TLV_LEN 48
#define SCAN_NETWORK_INFO_LEN      41
#define PING_INFO_LEN              9
#define IPERF_INFO_LEN             29

#define IPERF_TCP_TX 0x11
#define IPERF_TCP_RX 0x12
#define IPERF_UDP_TX 0x21
#define IPERF_UDP_RX 0x22
#define IPERF_ABORT  0x30

/*IPERF functions*/
#ifndef IPERF_UDP_CLIENT_RATE
#define IPERF_UDP_CLIENT_RATE (1 * 1024 * 1024) /* 1 Mbit/s */
#endif

#ifndef IPERF_CLIENT_AMOUNT
#define IPERF_CLIENT_AMOUNT (-1000) /* 10 seconds */
#endif

#define IPERF_UDP_DEFAULT_FACTOR 100

#define USART_INPUT_SIZE 1
#define USART_NVIC_PRIO  5

#define IPERF_REPORT_TYPE_LEN 12

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Variables
 ******************************************************************************/

static os_thread_t bridge_thread;
static os_thread_stack_define(bridge_stack, CONFIG_BRIDGE_STACK_SIZE);

const int TASK_MAIN_PRIO       = OS_PRIO_3;
const int TASK_MAIN_STACK_SIZE = 800;

portSTACK_TYPE *task_main_stack = NULL;
TaskHandle_t task_main_task_handler;

static os_thread_t UART_thread;
static os_thread_stack_define(UART_stack, 1024);

uint8_t b_background_buffer[32];
static usart_rtos_handle_t UR_handle;
struct _usart_handle b_u_handle;

struct rtos_usart_config USART_config = {
    .baudrate    = BOARD_DEBUG_UART_BAUDRATE,
    .parity      = kUSART_ParityDisabled,
    .stopbits    = kUSART_OneStopBit,
    .buffer      = b_background_buffer,
    .buffer_size = sizeof(b_background_buffer),
};

static os_queue_pool_define(queue_data, IN_QUEUE_SIZE);

static struct wlan_network sta_network;
static struct wlan_network uap_network;

static struct
{
    t_u8 *buf;

    os_queue_t input_queue;
    os_queue_pool_t in_queue_data;

} bridge;

/*Bridge command header*/
typedef MLAN_PACK_START struct bridge_command_header
{
    t_u16 cmd;
    t_u16 size;
    t_u8 seqnum;
    t_u8 bss;
    t_u16 result;
    t_u8 action;
} MLAN_PACK_END W_CMD, W_RES;

/*Bridge tlv header*/
typedef MLAN_PACK_START struct TLVTypeHeader_t
{
    t_u8 type;
    t_u16 size;
} MLAN_PACK_END TypeHeader_t;

/*Bridge ssid tlv*/
typedef MLAN_PACK_START struct SSID_ParaSet
{
    TypeHeader_t header;
    t_u8 ssid[1];
} MLAN_PACK_END SSID_tlv;

/*Bridge ping tlv*/
typedef MLAN_PACK_START struct PING_ParaSet
{
    TypeHeader_t header;
    t_u16 packet_count;
    t_u8 ping_ip[1];
} MLAN_PACK_END PING_tlv;

/*Bridge iperf tlv*/
typedef MLAN_PACK_START struct IPERF_ParaSet
{
    TypeHeader_t header;
    t_u16 time;
    t_u8 iperf_ip[1];
} MLAN_PACK_END IPERF_tlv;

/*Bridge response: ssid tlv*/
typedef MLAN_PACK_START struct SSID_RES
{
    TypeHeader_t header;
    t_u8 ip[16];
    t_u8 ssid[32];
} MLAN_PACK_END SSID_res_tlv;

/*Bridge response: scan network info*/
typedef MLAN_PACK_START struct SCAN_NETWORK_INFO
{
    t_u8 mac[6];
    t_u8 ssid[WLAN_NETWORK_NAME_MAX_LENGTH];
    t_u8 channel;
    t_u8 rssi;
    t_u8 security;
} MLAN_PACK_END scan_network_info;

/*Bridge response: scan tlv*/
typedef MLAN_PACK_START struct SCAN_RES
{
    TypeHeader_t header;
    t_u8 network_count;
    scan_network_info net_info[20];
} MLAN_PACK_END SCAN_res_tlv;

/*Bridge response: ping tlv*/
typedef MLAN_PACK_START struct PING_RES
{
    TypeHeader_t header;
    t_u8 status;
    t_u32 packet_transmit;
    t_u32 packet_received;
} MLAN_PACK_END PING_res_tlv;

/*Bridge response: iperf result info*/
typedef MLAN_PACK_START struct IPERF_INFO
{
    t_u8 role;
    t_u8 local_addr[4];
    t_u16 local_port;
    t_u8 remote_addr[4];
    t_u16 remote_port;
    t_u64 bytes_transferred;
    t_u32 ms_duration;
    t_u32 bandwidth_Mbitpsec;
} MLAN_PACK_END IPERF_info;

/*Bridge response: iperf tlv*/
typedef MLAN_PACK_START struct IPERF_RES
{
    TypeHeader_t header;
    IPERF_info iperf_info;
} MLAN_PACK_END IPERF_res_tlv;

static uint8_t CMD_buf[BRIDGE_INBUF_SIZE];
static uint8_t RES_buf[BRIDGE_INBUF_SIZE];
static int net_count = -1;
static scan_network_info scan_result_info[20];
static PING_res_tlv ping_info;
static IPERF_info iperf_info;
static int iperf_status = -1;
static int con_status   = -1;
static t_u8 con_ssid[32];
static t_u8 con_ip[16];

struct bridge_iperf_context
{
    bool server_mode;
    bool tcp;
    enum lwiperf_client_type client_type;
    void *iperf_session;
};

static struct bridge_iperf_context CTX;
static TimerHandle_t Timer = NULL;
static ip_addr_t Server_address;
static ip_addr_t Bind_address;
static bool Multicast;
#ifdef CONFIG_IPV6
static bool Ipv6;
#endif
/*******************************************************************************
 * Code
 ******************************************************************************/

static void *mem_cmd_buffer()
{
    return CMD_buf;
}

static int get_cmd_buffer(t_u8 **buff)
{
    *buff = mem_cmd_buffer();
    if (*buff == NULL)
        return -WM_FAIL;
    return WM_SUCCESS;
}

static int free_cmd_buffer(t_u8 **buff)
{
    *buff = NULL;
    return WM_SUCCESS;
}

static int submit_cmd_buffer(t_u8 **buff)
{
    int ret;

    ret = os_queue_send(&bridge.input_queue, (void *)buff, OS_WAIT_FOREVER);

    return ret;
}

static int iperf_amount                   = IPERF_CLIENT_AMOUNT;
static unsigned int Iperf_udp_rate_factor = IPERF_UDP_DEFAULT_FACTOR;

static uint8_t bridge_mcast_mac[6];
static bool bridge_mcast_mac_valid;

/*iperf functions*/
/** Prototype of a report function that is called when a session is finished. */
static void bridge_lwiperf_report(void *arg,
                                  enum lwiperf_report_type report_type,
                                  const ip_addr_t *local_addr,
                                  u16_t local_port,
                                  const ip_addr_t *remote_addr,
                                  u16_t remote_port,
                                  u64_t bytes_transferred,
                                  u32_t ms_duration,
                                  u32_t bandwidth_kbitpsec)
{
    if (report_type < IPERF_REPORT_TYPE_LEN)
    {
        iperf_status = 0;
        if (local_addr && remote_addr)
        {
            iperf_info.local_addr[0]      = ((u8_t *)local_addr)[0];
            iperf_info.local_addr[1]      = ((u8_t *)local_addr)[1];
            iperf_info.local_addr[2]      = ((u8_t *)local_addr)[2];
            iperf_info.local_addr[3]      = ((u8_t *)local_addr)[3];
            iperf_info.local_port         = local_port;
            iperf_info.remote_addr[0]     = ((u8_t *)remote_addr)[0];
            iperf_info.remote_addr[1]     = ((u8_t *)remote_addr)[1];
            iperf_info.remote_addr[2]     = ((u8_t *)remote_addr)[2];
            iperf_info.remote_addr[3]     = ((u8_t *)remote_addr)[3];
            iperf_info.remote_port        = remote_port;
            iperf_info.bytes_transferred  = bytes_transferred;
            iperf_info.ms_duration        = ms_duration;
            iperf_info.bandwidth_Mbitpsec = bandwidth_kbitpsec / 1000;
        }
        else
        {
            iperf_info.local_addr[0]      = 0;
            iperf_info.local_addr[1]      = 0;
            iperf_info.local_addr[2]      = 0;
            iperf_info.local_addr[3]      = 0;
            iperf_info.local_port         = local_port;
            iperf_info.remote_addr[0]     = 0;
            iperf_info.remote_addr[1]     = 0;
            iperf_info.remote_addr[2]     = 0;
            iperf_info.remote_addr[3]     = 0;
            iperf_info.remote_port        = remote_port;
            iperf_info.bytes_transferred  = bytes_transferred;
            iperf_info.ms_duration        = ms_duration;
            iperf_info.bandwidth_Mbitpsec = 0;
        }
    }
    else
    {
        iperf_status = -1;
    }
}

static void bridge_iperf_start(void *arg)
{
    struct bridge_iperf_context *ctx = (struct bridge_iperf_context *)arg;

    if (ctx->iperf_session != NULL)
    {
        lwiperf_abort(ctx->iperf_session);
        ctx->iperf_session = NULL;
    }

    if (!(ctx->tcp) && ctx->client_type == LWIPERF_DUAL)
    {
        /* Reducing udp Tx timer interval for rx to be served */
        xTimerChangePeriod(Timer, os_msec_to_ticks(2), 100);
    }
    else
    {
        /* Returning original timer settings of 1 ms interval*/
        xTimerChangePeriod(Timer, 1 / portTICK_PERIOD_MS, 100);
    }

    if (ctx->server_mode)
    {
        if (ctx->tcp)
        {
#ifdef CONFIG_IPV6
            if (Ipv6)
                ctx->iperf_session =
                    lwiperf_start_tcp_server(IP6_ADDR_ANY, LWIPERF_TCP_PORT_DEFAULT, bridge_lwiperf_report, NULL);
            else
#endif
                ctx->iperf_session =
                    lwiperf_start_tcp_server(IP_ADDR_ANY, LWIPERF_TCP_PORT_DEFAULT, bridge_lwiperf_report, 0);
        }
        else
        {
            if (Multicast)
            {
#ifdef CONFIG_IPV6
                wifi_get_ipv4_multicast_mac(ntohl(Bind_address.u_addr.ip4.addr), bridge_mcast_mac);
#else
                wifi_get_ipv4_multicast_mac(ntohl(Bind_address.addr), bridge_mcast_mac);
#endif
                if (wifi_add_mcast_filter(bridge_mcast_mac) != WM_SUCCESS)
                {
                    (void)PRINTF("IPERF session init failed\r\n");
                    lwiperf_abort(ctx->iperf_session);
                    ctx->iperf_session = NULL;
                    return;
                }
                bridge_mcast_mac_valid = true;
            }
#ifdef CONFIG_IPV6
            if (Ipv6)
                ctx->iperf_session =
                    lwiperf_start_udp_server(IP6_ADDR_ANY, LWIPERF_TCP_PORT_DEFAULT, bridge_lwiperf_report, NULL);
            else
#endif
                ctx->iperf_session =
                    lwiperf_start_udp_server(&Bind_address, LWIPERF_TCP_PORT_DEFAULT, bridge_lwiperf_report, 0);
        }
    }
    else
    {
        if (ctx->tcp)
        {
#ifdef CONFIG_IPV6
            if (Ipv6)
                ip6_addr_assign_zone(ip_2_ip6(&Server_address), IP6_UNICAST, netif_default);
#endif
            ctx->iperf_session = lwiperf_start_tcp_client(&Server_address, LWIPERF_TCP_PORT_DEFAULT, ctx->client_type,
                                                          iperf_amount, 0, LWIPERF_TOS_DEFAULT, bridge_lwiperf_report, 0);
        }
        else
        {
            if (IP_IS_V4(&Server_address) && ip_addr_ismulticast(&Server_address))
            {
#ifdef CONFIG_IPV6
                wifi_get_ipv4_multicast_mac(ntohl(Server_address.u_addr.ip4.addr), bridge_mcast_mac);
#else
                wifi_get_ipv4_multicast_mac(ntohl(Server_address.addr), bridge_mcast_mac);
#endif
                wifi_add_mcast_filter(bridge_mcast_mac);
                bridge_mcast_mac_valid = true;
            }
#ifdef CONFIG_IPV6
            if (Ipv6)
            {
                ctx->iperf_session = lwiperf_start_udp_client(
                    netif_ip_addr6(netif_default, 0), LWIPERF_TCP_PORT_DEFAULT, &Server_address,
                    LWIPERF_TCP_PORT_DEFAULT, ctx->client_type, iperf_amount, 0,
                    IPERF_UDP_CLIENT_RATE * Iperf_udp_rate_factor, 0, bridge_lwiperf_report, NULL);
            }
            else
            {
#endif
                ctx->iperf_session = lwiperf_start_udp_client(&Bind_address, LWIPERF_TCP_PORT_DEFAULT, &Server_address,
                                                              LWIPERF_TCP_PORT_DEFAULT, ctx->client_type, iperf_amount,
                                                              0, IPERF_UDP_CLIENT_RATE * Iperf_udp_rate_factor, 0,
                                                              bridge_lwiperf_report, NULL);
#ifdef CONFIG_IPV6
            }
#endif
        }
    }
}

static void bridge_iperf_abort(void *arg)
{
    struct bridge_iperf_context *test_ctx = (struct bridge_iperf_context *)arg;

    if (test_ctx->iperf_session != NULL)
    {
        lwiperf_abort(test_ctx->iperf_session);
        test_ctx->iperf_session = NULL;
    }

    (void)memset(&CTX, 0, sizeof(struct bridge_iperf_context));
}

static void bridge_poll_udp_client(void *arg)
{
    LWIP_UNUSED_ARG(arg);

    lwiperf_poll_udp_client();
}

static void Timer_poll_udp_client(TimerHandle_t timer)
{
    LWIP_UNUSED_ARG(timer);

    tcpip_try_callback(bridge_poll_udp_client, NULL);
}

static void IPERFAbort(void)
{
    iperf_info.role = IPERF_ABORT;
    bridge_iperf_abort((void *)&CTX);
}

static void iperf_TCPServer(void)
{
    CTX.server_mode = true;
    CTX.tcp         = true;
    CTX.client_type = LWIPERF_CLIENT;
    iperf_info.role = IPERF_TCP_RX;
    tcpip_callback(bridge_iperf_start, (void *)&CTX);
}

static void iperf_TCPClient(void)
{
    CTX.server_mode = false;
    CTX.tcp         = true;
    CTX.client_type = LWIPERF_CLIENT;
    iperf_info.role = IPERF_TCP_TX;
    tcpip_callback(bridge_iperf_start, (void *)&CTX);
}

static void iperf_UDPServer(void)
{
    CTX.server_mode = true;
    CTX.tcp         = false;
    CTX.client_type = LWIPERF_CLIENT;
    iperf_info.role = IPERF_UDP_RX;
    tcpip_callback(bridge_iperf_start, (void *)&CTX);
}

static void iperf_UDPClient(void)
{
    CTX.server_mode = false;
    CTX.tcp         = false;
    CTX.client_type = LWIPERF_CLIENT;
    iperf_info.role = IPERF_UDP_TX;
    tcpip_callback(bridge_iperf_start, (void *)&CTX);
}

int bridge_iperf_init()
{
    (void)memset(&CTX, 0, sizeof(struct bridge_iperf_context));

    if (Timer == NULL)
        Timer = xTimerCreate("UDP Poll Timer", 1 / portTICK_PERIOD_MS, pdTRUE, (void *)0, Timer_poll_udp_client);
    if (Timer == NULL)
    {
        while (true)
            ;
    }

    if (xTimerStart(Timer, 0) != pdPASS)
    {
        while (true)
            ;
    }

    return WM_SUCCESS;
}

/*scan fuctions*/
static int scan_cb(unsigned int count)
{
    struct wlan_scan_result scan_reslut;
    int i;
    int err;

    net_count = count;
    if (count > 20)
        net_count = 20;

    if (count == 0)
        return 0;

    for (i = 0; i < net_count; i++)
    {
        err = wlan_get_scan_result(i, &scan_reslut);
        if (err != WM_SUCCESS)
        {
            net_count = -1;
            return 0;
        }
        memcpy(scan_result_info[i].mac, scan_reslut.bssid, 6);
        memcpy(scan_result_info[i].ssid, scan_reslut.ssid, strlen(scan_reslut.ssid));
        scan_result_info[i].ssid[strlen(scan_reslut.ssid)] = '\0';
        scan_result_info[i].channel                        = scan_reslut.channel;
        scan_result_info[i].rssi                           = scan_reslut.rssi;

        if (scan_reslut.wep != 0U)
            scan_result_info[i].security = 0x01;
        if (scan_reslut.wpa && scan_reslut.wpa2)
            scan_result_info[i].security = 0x02;
        else
        {
            if (scan_reslut.wpa != 0U)
                scan_result_info[i].security = 0x03;
            if (scan_reslut.wpa2 != 0U)
                scan_result_info[i].security = 0x04;
            if (scan_reslut.wpa3_sae != 0U)
                scan_result_info[i].security = 0x05;
            if (scan_reslut.wpa2_entp != 0U)
                scan_result_info[i].security = 0x06;
        }
        if (!(scan_reslut.wep || scan_reslut.wpa || scan_reslut.wpa2 || scan_reslut.wpa3_sae || scan_reslut.wpa2_entp))
            scan_result_info[i].security = 0x07;
    }
    return 0;
}

/*bridge ping functions*/
static struct netif *bridge_get_netif_up()
{
    struct netif *netif = netif_list;
    for (; netif != NULL; netif = netif->next)
    {
        if (netif_is_up(netif))
        {
            return netif;
        }
    }
    return NULL;
}

static int bridge_addr_af(const ip_addr_t *addr)
{
#ifdef CONFIG_IPV6
    return (addr->type == IPADDR_TYPE_V4) ? AF_INET : AF_INET6;
#else
    return AF_INET;
#endif
}

static const ip_addr_t *bridge_get_src_addr(const ip_addr_t *dst)
{
    static ip_addr_t ret;
    const ip_addr_t *addr = NULL;
    struct netif *netif   = bridge_get_netif_up();

    if (netif == NULL)
    {
        return NULL;
    }

#ifdef CONFIG_IPV6
    switch (dst->type)
    {
        case IPADDR_TYPE_V4:
            addr = netif_ip_addr4(netif);
            memcpy(&ret.u_addr.ip4, &addr->u_addr.ip4, sizeof(ret.u_addr.ip4));
            break;
        case IPADDR_TYPE_V6:
            addr = ip6_select_source_address(netif, &addr->u_addr.ip6);
            memcpy(&ret.u_addr.ip6, &addr->u_addr.ip6, sizeof(ret.u_addr.ip6));
            break;
        default:
            return NULL;
    }

    ret.type = dst->type;
#else
    addr = netif_ip_addr4(netif);
    memcpy(&ret, addr, sizeof(ip_addr_t));
#endif
    return &ret;
}

/* Handle the ICMP echo response and extract required parameters */
static int bridge_ping_recv(int s, uint16_t seq_no, int *ttl)
{
    char buf[64];
    int fromlen = 0, len;
    struct sockaddr_in from;
    struct ip_hdr *iphdr;
    struct icmp_echo_hdr *iecho;

    while ((len = lwip_recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr *)&from, (socklen_t *)&fromlen)) > 0)
    {
        /* Received length should be greater than size of IP header and
         * size of ICMP header */
        if (len >= (int)(sizeof(struct ip_hdr) + sizeof(struct icmp_echo_hdr)))
        {
            iphdr = (struct ip_hdr *)buf;
            /* Calculate the offset of ICMP header */
            iecho = (struct icmp_echo_hdr *)(buf + (IPH_HL(iphdr) * 4));

            /* Verify that the echo response is for the echo request
             * we sent by checking PING_ID and sequence number */
            if ((iecho->id == PING_ID) && (iecho->seqno == htons(seq_no)))
            {
                /* Extract TTL and send back so that it can be
                 * displayed in ping statistics */
                *ttl = iphdr->_ttl;
                return WM_SUCCESS;
            }
        }
    }
    /* Either len < 0 or the echo response verification unsuccessful */
    return -WM_FAIL;
}

#ifdef CONFIG_IPV6
/* Handle the ICMP6 echo response and extract required parameters */
static int bridge_ping6_recv(int s, uint16_t seq_no, int *ttl)
{
    char buf[64];
    int fromlen = 0, len;
    struct sockaddr_in6 from;
    struct ip6_hdr *iphdr;
    struct icmp_echo_hdr *iecho;

    while ((len = lwip_recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr *)(void *)&from,
                                (socklen_t *)(void *)&fromlen)) > 0)
    {
        /* Received length should be greater than size of IP header and
         * size of ICMP header */
        if (len >= (int)(sizeof(struct ip6_hdr) + sizeof(struct icmp_echo_hdr)))
        {
            iphdr = (struct ip6_hdr *)(void *)buf;
            if (IP6H_NEXTH(iphdr) == IP6_NEXTH_ICMP6)
            {
                /* Calculate the offset of ICMP header */
                iecho = (struct icmp_echo_hdr *)(void *)(buf + sizeof(struct ip6_hdr));

                /* Verify that the echo response is for the echo request
                 * we sent by checking PING_ID, sequence number and ICMP type*/
                if ((iecho->id == PING_ID) && (iecho->seqno == htons(seq_no)) && (iecho->type == ICMP6_TYPE_EREP))
                {
                    /* Extract TTL and send back so that it can be
                     * displayed in ping statistics */
                    *ttl = IP6H_HOPLIM(iphdr);
                    return WM_SUCCESS;
                }
            }
        }
    }
    /* Either len < 0 or the echo response verification unsuccessful */
    return -WM_FAIL;
}
#endif

/* Prepare a ICMP echo request */
static void bridge_ping_prepare_echo(struct icmp_echo_hdr *iecho, const ip_addr_t *dest, uint16_t len, uint16_t seq_no)
{
    uint32_t i;
    uint32_t data_len = len - sizeof(struct icmp_echo_hdr);

#ifdef CONFIG_IPV6
    ICMPH_TYPE_SET(iecho, (dest->type == IPADDR_TYPE_V4) ? ICMP_ECHO : ICMP6_TYPE_EREQ);
#else
    ICMPH_TYPE_SET(iecho, ICMP_ECHO);
#endif
    ICMPH_CODE_SET(iecho, 0);
    iecho->chksum = 0;
    iecho->id     = PING_ID;
    iecho->seqno  = htons(seq_no);

    /* Fill the additional data buffer with some data */
    for (i = 0; i < data_len; i++)
    {
        ((char *)iecho)[sizeof(struct icmp_echo_hdr) + i] = (char)i;
    }
}

/* Send an ICMP echo request, receive its response and print its statistics and
 * result */
int bridge_ping(unsigned int count, unsigned short size, unsigned int r_timeout, ip_addr_t *addr)
{
    int i = 1, ret = WM_SUCCESS, s, recvd = 0;
    struct icmp_echo_hdr *iecho;
    unsigned int ping_time, ping_size;
    const ip_addr_t *ip_addr, *src_ip_addr;
    struct timeval timeout;

#ifdef CONFIG_IPV6
    struct netif *netif     = bridge_get_netif_up();
    const unsigned scope_id = netif_get_index(netif);
#endif

    /* Create a raw socket */
#ifdef CONFIG_IPV6
    s = socket(bridge_addr_af(addr), SOCK_RAW, (addr->type == IPADDR_TYPE_V4) ? IPPROTO_ICMP : IPPROTO_ICMPV6);
#else
    s = socket(bridge_addr_af(addr), SOCK_RAW, IPPROTO_ICMP);
#endif
    if (s < 0)
        return -WM_FAIL;
        /* Convert timeout to milliseconds */
#ifdef CONFIG_PALLADIUM_SUPPORT
    timeout.tv_sec  = 0;
    timeout.tv_usec = r_timeout * 10000;
#else
    timeout.tv_sec = r_timeout;
    timeout.tv_usec = 0;
#endif

    /* Set the socket timeout */
    ret = setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    if (ret < 0)
    {
        ret = -WM_FAIL;
        goto end;
    }

    /* Get the source IP address */
    src_ip_addr = bridge_get_src_addr(addr);

    /* Ping size is: size of ICMP header + size of payload */
    ping_size = sizeof(struct icmp_echo_hdr) + size;

    iecho = (struct icmp_echo_hdr *)os_mem_alloc(ping_size);
    if (!iecho)
    {
        ret = -WM_FAIL;
        goto end;
    }

    while (i <= count)
    {
        bridge_ping_prepare_echo(iecho, addr, (uint16_t)ping_size, i);
#ifdef CONFIG_IPV6
        if (addr->type == IPADDR_TYPE_V4)
#endif
        {
            struct sockaddr_in to;
            to.sin_len    = (u8_t)sizeof(to);
            to.sin_family = AF_INET;
            inet_addr_from_ip4addr(&to.sin_addr, ip_2_ip4(addr));

            iecho->chksum = inet_chksum(iecho, ping_size);

            /* Send the ICMP echo request */
            ret = lwip_sendto(s, iecho, ping_size, 0, (struct sockaddr *)(void *)&to, sizeof(to));
        }
#ifdef CONFIG_IPV6
        else
        {
            struct sockaddr_in6 to;
            to.sin6_len      = sizeof(to);
            to.sin6_family   = AF_INET6;
            to.sin6_scope_id = scope_id;

            inet6_addr_from_ip6addr(&to.sin6_addr, ip_2_ip6(addr));

            /* Send the ICMP6 echo request */
            ret = lwip_sendto(s, iecho, ping_size, 0, (struct sockaddr *)(void *)&to, sizeof(to));
        }
#endif

        /* Get the current ticks as the start time */
        ping_time = os_ticks_get();

        if (ret > 0)
        {
            int ttl = 0;
            /* Receive the ICMP echo response */
#ifdef CONFIG_IPV6
            if (addr->type == IPADDR_TYPE_V4)
#endif
                ret = bridge_ping_recv(s, (uint16_t)i, &ttl);
#ifdef CONFIG_IPV6
            else
                ret = bridge_ping6_recv(s, (uint16_t)i, &ttl);
#endif

            /* Calculate the round trip time */
            ping_time = os_ticks_get() - ping_time;

            if (ret == WM_SUCCESS)
            {
                /* Increment the receive counter */
                recvd++;
                /* To display successful ping stats, destination
                 * IP address is required */
                ip_addr = addr;
            }
            else
            {
                /* To display unsuccessful ping stats, source
                 * IP address is required */
                ip_addr = src_ip_addr;
            }
        }
        else
        {
            os_mem_free(iecho);
            ret = -WM_FAIL;
            goto end;
        }
        i++;
        os_thread_sleep(os_msec_to_ticks(PING_INTERVAL));
        ping_info.status = 0;
    }
    os_mem_free(iecho);
    ping_info.status          = 1;
    ping_info.packet_transmit = count;
    ping_info.packet_received = recvd;
end:
    close(s);
    return ret;
}

/*CMD handle functions*/

static int wlan_bridge_scan()
{
    if (wlan_scan(scan_cb) != 0)
        return -WM_FAIL;
    return WM_SUCCESS;
}

static int wlan_bridge_get_scan()
{
    W_RES *cmd_res  = (W_RES *)(RES_buf);
    cmd_res->cmd    = 0x01;
    cmd_res->size   = BRIDGE_COMMAND_LEN;
    cmd_res->seqnum = 0x00;
    cmd_res->bss    = 0x00;
    cmd_res->action = 0x00;
    cmd_res->result = 0x00;

    if (net_count == -1)
    {
        cmd_res->result = 0x01;
        return WM_SUCCESS;
    }
    SCAN_res_tlv *scan_res_tlv = (SCAN_res_tlv *)(RES_buf + BRIDGE_COMMAND_LEN);

    for (int i = 0; i < net_count; i++)
    {
        memcpy(scan_res_tlv->net_info[i].mac, scan_result_info[i].mac, 6);
        memcpy(scan_res_tlv->net_info[i].ssid, scan_result_info[i].ssid, strlen(scan_result_info[i].ssid));
        scan_res_tlv->net_info[i].ssid[strlen(scan_result_info[i].ssid)] = '\0';
        scan_res_tlv->net_info[i].channel                                = scan_result_info[i].channel;
        scan_res_tlv->net_info[i].rssi                                   = scan_result_info[i].rssi;
        scan_res_tlv->net_info[i].security                               = scan_result_info[i].security;
    }
    scan_res_tlv->network_count = net_count;
    scan_res_tlv->header.type   = 0x01;
    scan_res_tlv->header.size   = net_count * SCAN_NETWORK_INFO_LEN + 1;
    cmd_res->size += (TLV_HEADER_LEN + scan_res_tlv->header.size);

    return WM_SUCCESS;
}

static char name[] = "s1";
static int wlan_bridge_add(t_u8 *cmd)
{
    struct wlan_network network;
    (void)memset(&network, 0, sizeof(struct wlan_network));

    SSID_tlv *ssid_tlv = (SSID_tlv *)(cmd + BRIDGE_COMMAND_LEN);
    int len            = ssid_tlv->header.size;

    wlan_remove_network(name);

    (void)memcpy(network.name, name, 2);
    (void)memcpy(network.ssid, ssid_tlv->ssid, IEEEtypes_ADDRESS_SIZE >= len ? len : IEEEtypes_ADDRESS_SIZE);
    network.ip.ipv4.addr_type = ADDR_TYPE_DHCP;
    int ret                   = wlan_add_network(&network);
    return ret;
}

static int wlan_bridge_connect(t_u8 *cmd)
{
    int ret;
    ret = wlan_bridge_add(cmd);
    if (ret != WM_SUCCESS)
        return -WM_FAIL;
    ret = wlan_connect(name);

    return ret;
}

static int wlan_bridge_get_connect()
{
    W_RES *cmd_res  = (W_RES *)(RES_buf);
    cmd_res->cmd    = 0x02;
    cmd_res->size   = BRIDGE_COMMAND_LEN;
    cmd_res->seqnum = 0x00;
    cmd_res->bss    = 0x00;
    cmd_res->action = 0x00;
    cmd_res->result = 0x00;

    if (con_status != 0)
        cmd_res->result = 0x01;

    if (cmd_res->result == 0x00)
    {
        SSID_res_tlv *ssid_res_tlv = (SSID_res_tlv *)(RES_buf + BRIDGE_COMMAND_LEN);
        ssid_res_tlv->header.type  = 0x02;

        memcpy(ssid_res_tlv->ssid, con_ssid, strlen(con_ssid));
        ssid_res_tlv->ssid[strlen(con_ssid)] = '\0';
        memcpy(ssid_res_tlv->ip, con_ip, strlen(con_ip));
        ssid_res_tlv->ip[strlen(con_ip)] = 0;

        ssid_res_tlv->header.size = BRIDGE_CONNECT_RES_TLV_LEN;
        cmd_res->size += (TLV_HEADER_LEN + BRIDGE_CONNECT_RES_TLV_LEN);
    }
    return WM_SUCCESS;
}

static int wlan_bridge_disconnect()
{
    int ret = wlan_disconnect();
    return ret;
}

static int wlan_bridge_ping(t_u8 *cmd)
{
    PING_tlv *ping_tlv = (PING_tlv *)(cmd + BRIDGE_COMMAND_LEN);
    int len            = ping_tlv->header.size;
    ip_addr_t addr;
    char ip_addr[20];
    uint16_t size    = PING_DEFAULT_SIZE;
    uint32_t count   = 0;
    uint32_t timeout = PING_DEFAULT_TIMEOUT_SEC;

    if (ping_tlv->packet_count != 0)
        count |= (ping_tlv->packet_count);
    else
        count = PING_DEFAULT_COUNT;

    (void)memcpy(ip_addr, ping_tlv->ping_ip, len - 2);
    ip_addr[len - 2] = '\0';
    inet_aton(ip_addr, &addr);
#ifdef CONFIG_IPV6
    addr.type = IPADDR_TYPE_V4;
#endif
    int ret = bridge_ping(count, size, timeout, &addr);

    return ret;
}

static int wlan_bridge_get_ping()
{
    W_RES *cmd_res  = (W_RES *)(RES_buf);
    cmd_res->cmd    = 0x04;
    cmd_res->size   = BRIDGE_COMMAND_LEN;
    cmd_res->seqnum = 0x00;
    cmd_res->bss    = 0x00;
    cmd_res->action = 0x00;
    cmd_res->result = 0x00;
    if (ping_info.status == 0 || ping_info.status == 1)
    {
        PING_res_tlv *ping_res_tlv = (PING_res_tlv *)(RES_buf + BRIDGE_COMMAND_LEN);
        ping_res_tlv->header.type  = 0x04;
        ping_res_tlv->header.size  = PING_INFO_LEN;
        ping_res_tlv->status       = ping_info.status;
        if (ping_info.status == 1)
        {
            ping_res_tlv->packet_transmit = ping_info.packet_transmit;
            ping_res_tlv->packet_received = ping_info.packet_received;
        }
        cmd_res->size += (TLV_HEADER_LEN + ping_res_tlv->header.size);
        ping_info.status = -1;
    }
    else
    {
        cmd_res->result = 0x01;
    }

    return WM_SUCCESS;
}

static int wlan_bridge_iperf(t_u8 *cmd)
{
    int ret;
    iperf_amount = IPERF_CLIENT_AMOUNT;
    Multicast    = false;
#ifdef CONFIG_IPV6
    Ipv6                = false;
    Server_address.type = IPADDR_TYPE_V4;
#endif
    if (bridge_mcast_mac_valid)
    {
        ret = wifi_remove_mcast_filter(bridge_mcast_mac);
        if (ret != WM_SUCCESS)
            return ret;
        bridge_mcast_mac_valid = false;
    }
    Iperf_udp_rate_factor = IPERF_UDP_DEFAULT_FACTOR;

    IPERF_tlv *iperf_tlv = (IPERF_tlv *)(cmd + BRIDGE_COMMAND_LEN);
    if (iperf_tlv->header.type == 0x51)
    {
        iperf_TCPServer();
    }
    else if (iperf_tlv->header.type == 0x52 || iperf_tlv->header.type == 0x53 || iperf_tlv->header.type == 0x54)
    {
        int time = iperf_tlv->time;
        if (time != 0x0)
            iperf_amount = -100 * time;
        int len_ip = iperf_tlv->header.size - sizeof(iperf_tlv->time);
        char iperf_ip[128], ip[16];

        if (len_ip > 0)
        {
            /*get server ip address*/
            memcpy(iperf_ip, iperf_tlv->iperf_ip, len_ip);
            iperf_ip[len_ip] = '\0';
            // inet_aton(iperf_ip, ip_2_ip4(&server_address));
            inet_aton(iperf_ip, &Server_address);
            if (IP_IS_V4(&Server_address) == 0)
                return -WM_FAIL;
        }

        if (iperf_tlv->header.type == 0x53)
        {
            iperf_TCPClient();
        }
        else
        {
            struct wlan_ip_config addr;
            /*get own ip address*/
            wlan_get_address(&addr);
            net_inet_ntoa(addr.ipv4.address, ip);
            inet_aton(ip, &Bind_address);
            if (IP_IS_V4(&Bind_address) == 0)
            {
                return -WM_FAIL;
            }
            if (ip_addr_ismulticast(&Bind_address) != 0)
                Multicast = true;

            if (iperf_tlv->header.type == 0x52)
            {
                iperf_UDPServer();
            }
            else
            {
                iperf_UDPClient();
            }
        }
    }
    else
    {
        IPERFAbort();
    }
    return ret;
}

static int wlan_bridge_get_iperf()
{
    W_RES *cmd_res  = (W_RES *)(RES_buf);
    cmd_res->cmd    = 0x05;
    cmd_res->size   = BRIDGE_COMMAND_LEN;
    cmd_res->seqnum = 0x00;
    cmd_res->bss    = 0x00;
    cmd_res->action = 0x00;
    cmd_res->result = 0x00;

    if (iperf_status == 0)
    {
        IPERF_res_tlv *iperf_res_tlv   = (IPERF_res_tlv *)(RES_buf + BRIDGE_COMMAND_LEN);
        iperf_res_tlv->iperf_info.role = iperf_info.role;
        for (int i = 0; i < 4; i++)
        {
            iperf_res_tlv->iperf_info.local_addr[i]  = iperf_info.local_addr[i];
            iperf_res_tlv->iperf_info.remote_addr[i] = iperf_info.remote_addr[i];
        }
        iperf_res_tlv->iperf_info.local_port         = iperf_info.local_port;
        iperf_res_tlv->iperf_info.remote_port        = iperf_info.remote_port;
        iperf_res_tlv->iperf_info.bytes_transferred  = iperf_info.bytes_transferred;
        iperf_res_tlv->iperf_info.ms_duration        = iperf_info.ms_duration;
        iperf_res_tlv->iperf_info.bandwidth_Mbitpsec = iperf_info.bandwidth_Mbitpsec;
        iperf_res_tlv->header.type                   = 0x05;
        iperf_res_tlv->header.size                   = IPERF_INFO_LEN;
        cmd_res->size += (TLV_HEADER_LEN + iperf_res_tlv->header.size);
        if (iperf_info.role == IPERF_ABORT)
            iperf_status = -1;
    }
    else
        cmd_res->result = 0x01;

    return WM_SUCCESS;
}

/*get commands from upper Linux APP*/
static void bridge_get_input()
{
    int ret;
    if (bridge.buf == NULL)
    {
        ret = get_cmd_buffer(&bridge.buf);
        if (ret != WM_SUCCESS)
            return;
    }
    int len       = 0;
    int cmd_len   = 0;
    size_t rx_len = 0;
    while (len != BRIDGE_CMD_HEADER_LEN)
    {
        ret = USART_RTOS_Receive(&UR_handle, bridge.buf + len, BRIDGE_CMD_HEADER_LEN, &rx_len);
        len += rx_len;
    }

    cmd_len |= CMD_buf[3];
    cmd_len <<= 8;
    cmd_len |= CMD_buf[2];
    len    = 0;
    rx_len = 0;
    while (len != (cmd_len - BRIDGE_CMD_HEADER_LEN))
    {
        USART_RTOS_Receive(&UR_handle, bridge.buf + BRIDGE_CMD_HEADER_LEN + len, cmd_len - BRIDGE_CMD_HEADER_LEN - len,
                           &rx_len);
        len += rx_len;
    }

    ret = submit_cmd_buffer(&bridge.buf);
}

static void UART_task(void *pvParameters)
{
    USART_config.srcclk = BOARD_DEBUG_UART_CLK_FREQ;
    USART_config.base   = BOARD_DEBUG_UART;

    NVIC_SetPriority(BOARD_UART_IRQ, USART_NVIC_PRIO);

    if (USART_RTOS_Init(&UR_handle, &b_u_handle, &USART_config) != WM_SUCCESS)
    {
        vTaskSuspend(NULL);
    }
    /* Receive user input and send it back to terminal. */
    while (1)
    {
        bridge_get_input();
    }
}

/* This function processes commands*/
static int bridge_process_cmd(t_u8 *cmd)
{
    W_CMD *input_cmd = (W_CMD *)cmd;
    int ret          = WM_SUCCESS;
    if (input_cmd->cmd == 0x01)
    {
        if (input_cmd->action == 0x01)
        {
            ret = wlan_bridge_scan();
        }
        else
        {
            ret = wlan_bridge_get_scan();
        }
    }
    else if (input_cmd->cmd == 0x02)
    {
        if (input_cmd->action == 0x01)
        {
            ret = wlan_bridge_connect(cmd);
        }
        else
        {
            ret = wlan_bridge_get_connect();
        }
    }
    else if (input_cmd->cmd == 0x03 && input_cmd->action == 0x01)
    {
        ret = wlan_bridge_disconnect();

        W_RES *cmd_res  = (W_RES *)(RES_buf);
        cmd_res->cmd    = 0x03;
        cmd_res->size   = BRIDGE_COMMAND_LEN;
        cmd_res->seqnum = 0x00;
        cmd_res->bss    = 0x00;
        cmd_res->action = 0x00;
        cmd_res->result = 0x00;

        if (ret != WM_SUCCESS)
            cmd_res->result = 0x01;
    }
    else if (input_cmd->cmd == 0x04)
    {
        if (input_cmd->action == 0x01)
            ret = wlan_bridge_ping(cmd);
        else
        {
            ret = wlan_bridge_get_ping();
        }
    }
    else if (input_cmd->cmd == 0x05)
    {
        if (input_cmd->action == 0x01)
            ret = wlan_bridge_iperf(cmd);
        else
        {
            ret = wlan_bridge_get_iperf();
        }
    }
    else
    {
        ret = -WM_FAIL;
    }
    return ret;
}
/* This function processes commands and send response to UART*/
static void bridge_process_task(void *parameter)
{
    while (1)
    {
        int ret;
        uint8_t *data = NULL;

        data = NULL;
        ret  = os_queue_recv(&bridge.input_queue, &data, OS_WAIT_FOREVER);

        if (ret != WM_SUCCESS)
        {
            if (ret == WM_E_BADF)
            {
                (void)PRINTF("Error: CLI fatal queue error.\r\n");
                /* Special case fatal errors.  Shouldn't happen. If it does, end the thread.*/
                return;
            }
            continue;
        }
        if (data != NULL)
        {
            ret = bridge_process_cmd(data);
            if (ret == WM_SUCCESS)
            {
                W_RES *cmd_res = (W_RES *)(RES_buf);
                if (cmd_res->size >= BRIDGE_COMMAND_LEN)
                {
                    ret = USART_RTOS_Send(&UR_handle, RES_buf, cmd_res->size);
                }
                cmd_res->size = 0;
            }
        }
        free_cmd_buffer(&data);
    }
}

static int bridge_main()
{
    bridge.in_queue_data = queue_data;

    int ret;

    ret = os_thread_create(&bridge_thread, "bridge", bridge_process_task, 0, &bridge_stack, OS_PRIO_3);
    if (ret != WM_SUCCESS)
    {
        return -WM_FAIL;
    }

    ret = os_queue_create(&bridge.input_queue, "cmd_queue", sizeof(void *), &bridge.in_queue_data);
    if (ret != WM_SUCCESS)
    {
        return -WM_FAIL;
    }

    ret = os_thread_create(&UART_thread, "UART_task", UART_task, 0, &UART_stack, OS_PRIO_4);
    if (ret != WM_SUCCESS)
    {
        return -WM_FAIL;
    }

    return WM_SUCCESS;
}
/* Callback Function passed to WLAN Connection Manager. The callback function
 * gets called when there are WLAN Events that need to be handled by the
 * application.
 */
int wlan_event_callback(enum wlan_event_reason reason, void *data)
{
    int ret;
    static int auth_fail = 0;
    struct wlan_ip_config addr;
    char ip[16];

    switch (reason)
    {
        case WLAN_REASON_INITIALIZED:
            ret = bridge_iperf_init();
            if (ret != WM_SUCCESS)
            {
                return 0;
            }
            break;
        case WLAN_REASON_SUCCESS:
            ret = wlan_get_address(&addr);
            if (ret != WM_SUCCESS)
            {
                con_status = -1;
                return 0;
            }

            net_inet_ntoa(addr.ipv4.address, ip);

            ret = wlan_get_current_network(&sta_network);
            if (ret != WM_SUCCESS)
            {
                con_status = -1;
                return 0;
            }
            con_status = 0;
            memcpy(con_ssid, sta_network.ssid, strlen(sta_network.ssid));
            memcpy(con_ip, ip, strlen(ip));
            auth_fail = 0;
            break;
        case WLAN_REASON_NETWORK_AUTH_FAILED:
            auth_fail++;
            if (auth_fail >= 3)
            {
                wlan_disconnect();
                con_status = -1;
                auth_fail  = 0;
            }
            break;
        case WLAN_REASON_USER_DISCONNECT:
            con_status = -1;
            auth_fail  = 0;
            break;
        case WLAN_REASON_UAP_SUCCESS:
            ret = wlan_get_current_uap_network(&uap_network);

            if (ret != WM_SUCCESS)
            {
                return 0;
            }
            dhcp_server_start(net_get_uap_handle());
            break;
        case WLAN_REASON_UAP_STOPPED:
            dhcp_server_stop();
            break;
        default:
            PRINTF("app_cb: WLAN: Unknown Event: %d\r\n", reason);
    }
    return 0;
}

void task_main(void *param)
{
    int32_t result = 0;

    result = bridge_main();

    assert(WM_SUCCESS == result);

    PRINTF("Initialize WLAN Driver\r\n");

    /* Initialize WIFI Driver */
    result = wlan_init(wlan_fw_bin, wlan_fw_bin_len);

    assert(WM_SUCCESS == result);

    result = wlan_start(wlan_event_callback);

    assert(WM_SUCCESS == result);

    while (1)
    {
        /* wait for interface up */
        os_thread_sleep(os_msec_to_ticks(5000));
    }
}

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

int main(void)
{
    BaseType_t result = 0;
    (void)result;

    BOARD_InitHardware();

    result =
        xTaskCreate(task_main, "main", TASK_MAIN_STACK_SIZE, task_main_stack, TASK_MAIN_PRIO, &task_main_task_handler);
    assert(pdPASS == result);

    vTaskStartScheduler();
    for (;;)
        ;
}
