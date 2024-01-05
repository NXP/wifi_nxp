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
#include "pin_mux.h"
#include "serial_httpc.h"
#include "websockets.h"
#include "board.h"
#include "fsl_debug_console.h"
#include "wlan_bt_fw.h"
#include "wlan.h"
#include "wifi.h"
#include "wm_net.h"
#include <wm_os.h>
#include "dhcp-server.h"
#include "app.h"
#include "uap_prov.h"

#include "ncp_bridge_glue.h"
#include "app_notify.h"
#include "ncp_config.h"

#ifdef CONFIG_NCP_BRIDGE_DEBUG
#include "cli.h"
#endif
#include "crc.h"
#include "fsl_rtc.h"
#include "fsl_power.h"
#include "host_sleep.h"

#ifdef CONFIG_UART_BRIDGE
#include "fsl_usart_freertos.h"
#include "fsl_usart.h"
#elif defined(CONFIG_USB_BRIDGE)
#include "usb_slave_app.h"
#include "cdc_app.h"
#elif defined(CONFIG_SPI_BRIDGE)
#include "spi_slave_app.h"
#endif

#ifndef RW610
#include "wifi_bt_config.h"
#endif
#ifdef CONFIG_WIFI_USB_FILE_ACCESS
#include "usb_host_config.h"
#include "usb_host.h"
#include "usb_api.h"
#endif /* CONFIG_WIFI_USB_FILE_ACCESS */
#include "cli_utils.h"
#ifdef CONFIG_HOST_SLEEP
#include "host_sleep.h"
#endif

/*******************************************************************************
 * Definitions
 ******************************************************************************/
#ifdef CONFIG_UART_BRIDGE
/*! @brief The UART(FC0) to use for TLV command. */
#define PROTOCOL_UART_FRG_CLK \
    (&(const clock_frg_clk_config_t){0, kCLOCK_FrgMainClk, 255, 0}) /*!< Select FRG0 mux as frg_pll */
#define PROTOCOL_UART_CLK_ATTACH kFRG_to_FLEXCOMM0
#define PROTOCOL_UART_CLK_FREQ   CLOCK_GetFlexCommClkFreq(0)
#define PROTOCOL_UART            USART0
#define PROTOCOL_UART_IRQ        FLEXCOMM0_IRQn
#define PROTOCOL_UART_BAUDRATE   115200

#define USART_NVIC_PRIO 5

#define UART_BUF_SIZE 32
#endif

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Variables
 ******************************************************************************/
extern int network_services;

#ifdef RW610
extern const unsigned char *wlan_fw_bin;
extern const unsigned int wlan_fw_bin_len;
#endif

const int TASK_MAIN_PRIO       = OS_PRIO_3;
const int TASK_MAIN_STACK_SIZE = 800;

portSTACK_TYPE *task_main_stack = NULL;
TaskHandle_t task_main_task_handler;

os_semaphore_t bridge_lock;

os_thread_t ncp_bridge_thread;                         /* ncp bridge  task */
static os_thread_stack_define(ncp_bridge_stack, 4096); /* ncp bridge task stack*/

#ifdef CONFIG_UART_BRIDGE
uint8_t b_background_buffer[UART_BUF_SIZE];
static usart_rtos_handle_t uart_rtos_handle;
static usart_handle_t uart_handle;

struct rtos_usart_config protocol_usart_config = {
    .baudrate    = PROTOCOL_UART_BAUDRATE,
    .parity      = kUSART_ParityDisabled,
    .stopbits    = kUSART_OneStopBit,
    .buffer      = b_background_buffer,
    .buffer_size = sizeof(b_background_buffer),
};
#endif

static struct wlan_network sta_network;
static struct wlan_network uap_network;

uint16_t g_cmd_seqno = 0;

uint8_t cmd_buf[NCP_BRIDGE_INBUF_SIZE];
uint8_t res_buf[NCP_BRIDGE_INBUF_SIZE];

#ifndef CONFIG_CRC32_HW_ACCELERATE
static unsigned int crc32_table[256];
#endif
extern bool usart_suspend_flag;
extern power_cfg_t global_power_config;
os_mutex_t resp_buf_mutex;

#ifdef CONFIG_SPI_BRIDGE
extern os_semaphore_t spi_slave_sem;
#endif

uint32_t current_cmd = 0;
/*******************************************************************************
 * Code
 ******************************************************************************/

static void printSeparator(void)
{
    PRINTF("========================================\r\n");
}

/* check_command_complete() validates the command.
 * It checks for the crc of the command.
 */
static int check_command_complete(uint8_t *buf)
{
    NCP_BRIDGE_COMMAND *command;
    uint16_t msglen;
    uint32_t remote_checksum = 0, local_checksum = 0;

    command = (NCP_BRIDGE_COMMAND *)buf;
    /* check CRC */
    msglen          = command->size;
    remote_checksum = *(uint32_t *)(buf + msglen);

    local_checksum = ncp_bridge_get_crc32(buf, msglen);
    if (remote_checksum == local_checksum)
    {
        ncp_d("local checksum == remote checksum: 0x%02x", local_checksum);
        return WM_SUCCESS;
    }
    else
    {
        ncp_e("local checksum: 0x%02x != remote checksum: 0x%02x", local_checksum, remote_checksum);
        app_notify_event(APP_EVT_INVALID_CMD, APP_EVT_REASON_SUCCESS, NULL, 0);
#ifndef CONFIG_USB_BRIDGE
        memset(cmd_buf, 0, sizeof(cmd_buf));
#ifdef CONFIG_UART_BRIDGE
        memset(b_background_buffer, 0x0, sizeof(b_background_buffer));
        USART_TransferStartRingBuffer((&uart_rtos_handle)->base, (&uart_rtos_handle)->t_state,
                                      (&protocol_usart_config)->buffer, (&protocol_usart_config)->buffer_size);
#endif
#endif
        return -WM_FAIL;
    }
}

/* bridge_send_response() handles the response from the wifi driver.
 * This involves
 * 1) sending cmd response out to interface
 * 2) computation of the crc of the cmd resp
 * 3) reset cmd_buf & res_buf
 * 4) release bridge lock
 */
int bridge_send_response(uint8_t *pbuf)
{
    int ret                = WM_SUCCESS;
    uint32_t bridge_chksum = 0;
    uint16_t msglen = 0, index = 0;
    NCP_BRIDGE_COMMAND *res = (NCP_BRIDGE_COMMAND *)pbuf;
    uint16_t transfer_len   = 0;

#ifdef CONFIG_SPI_BRIDGE
    uint16_t sent_len  = 0;
    uint16_t block_len = 0;
#endif

    /* set cmd seqno */
    res->seqnum = g_cmd_seqno;

    /* calculate CRC. */
    msglen        = res->size;
    bridge_chksum = ncp_bridge_get_crc32(pbuf, msglen);
    index         = msglen;

    pbuf[index]     = bridge_chksum & 0xff;
    pbuf[index + 1] = (bridge_chksum & 0xff00) >> 8;
    pbuf[index + 2] = (bridge_chksum & 0xff0000) >> 16;
    pbuf[index + 3] = (bridge_chksum & 0xff000000) >> 24;
    transfer_len    = res->size + CHECKSUM_LEN;

    ncp_d("send checksum: 0x%02x", bridge_chksum);

    if (msglen >= NCP_BRIDGE_CMD_HEADER_LEN)
    {
        /* write response to host */
#ifdef CONFIG_UART_BRIDGE
        ret = USART_WriteBlocking(PROTOCOL_UART, pbuf, transfer_len);
#elif defined(CONFIG_SPI_BRIDGE)
        ret = ncp_bridge_spi_slave_transfer(pbuf, transfer_len, NCP_BRIDGE_SLAVE_TX, true);
#elif defined(CONFIG_USB_BRIDGE)
        ret = usb_no_copy_cmd_response(pbuf, transfer_len, NULL, OS_WAIT_FOREVER);
#endif
        if (ret != WM_SUCCESS)
        {
            ncp_e("failed to write response");
            ret = -WM_FAIL;
        }
    }
    else
    {
        ncp_e("command length is less than 12, cmd_len = %d", msglen);
        ret = -WM_FAIL;
    }

    if (res->msg_type != NCP_BRIDGE_MSG_TYPE_EVENT)
    {
        /* Reset cmd_buf */
        memset(cmd_buf, 0, sizeof(cmd_buf));
        /* Reset res_buf */
        // memset(res_buf, 0, sizeof(res_buf));

        os_semaphore_put(&bridge_lock);
        ncp_d("put bridge lock");
    }

    return ret;
}

static int handle_input(uint8_t *cmd)
{
    NCP_BRIDGE_COMMAND *input_cmd = (NCP_BRIDGE_COMMAND *)cmd;
    struct cmd_t *command         = NULL;
    int ret                       = WM_SUCCESS;

    uint32_t cmd_class    = GET_CMD_CLASS(input_cmd->cmd);
    uint32_t cmd_subclass = GET_CMD_SUBCLASS(input_cmd->cmd);
    uint32_t cmd_id       = GET_CMD_ID(input_cmd->cmd);
    void *cmd_tlv         = GET_CMD_TLV(input_cmd);

    command = lookup_class(cmd_class, cmd_subclass, cmd_id);
    if (NULL == command)
    {
        ncp_d("lookup_cmd failed\r\n");
        return -WM_FAIL;
    }
    current_cmd = command->cmd;
    ncp_d("got bridge command: <%s>", command->help);
    ret = command->handler(cmd_tlv);

    if (command->async == CMD_SYNC)
    {
        bridge_send_response(res_buf);
    }
    else
    {
        /* Wait for cmd to execute, then
         * 1) send cmd response
         * 2) reset cmd_buf & res_buf
         * 3) release bridge_lock */
#ifdef CONFIG_SPI_BRIDGE
        os_semaphore_get(&bridge_lock, OS_WAIT_FOREVER);
        os_semaphore_put(&bridge_lock);
#endif
    }

    return ret;
}

/* get TLV commands from BUS interface */
static void bridge_get_input()
{
    int total = 0;
#ifdef CONFIG_NCP_BRIDGE_DEBUG
    static int num = 0;
#endif
#ifndef CONFIG_USB_BRIDGE
    int ret;
    int len       = 0;
    int cmd_len   = 0;
    size_t rx_len = 0;
#ifdef CONFIG_SPI_BRIDGE
    int total_len = 0;
#endif

restart:
#ifdef CONFIG_UART_BRIDGE
    while (len != NCP_BRIDGE_CMD_HEADER_LEN)
    {
#ifdef CONFIG_HOST_SLEEP
        if (usart_suspend_flag)
        {
            os_thread_sleep(os_msec_to_ticks(1000));
            goto restart;
        }
#endif
        ret = USART_RTOS_Receive(&uart_rtos_handle, cmd_buf + len, NCP_BRIDGE_CMD_HEADER_LEN, &rx_len);
#ifdef CONFIG_HOST_SLEEP
        if (usart_suspend_flag)
            continue;
#endif
        len += rx_len;
        total += rx_len;
    }
#elif defined(CONFIG_SPI_BRIDGE)
    ret = ncp_bridge_spi_slave_transfer(cmd_buf + len, NCP_BRIDGE_CMD_HEADER_LEN, NCP_BRIDGE_SLAVE_RX, true);
    if (ret != WM_SUCCESS)
    {
        ncp_e("Failed to receive command header(%d)", ret);
        return;
    }
    total += NCP_BRIDGE_CMD_HEADER_LEN;
#endif
    /* Length of the packet is indicated by byte[4] & byte[5] of
     * the packet excluding checksum [4 bytes]
     */
    cmd_len = (cmd_buf[NCP_BRIDGE_CMD_SIZE_HIGH_BYTES] << 8) | cmd_buf[NCP_BRIDGE_CMD_SIZE_LOW_BYTES];
    len     = 0;
    rx_len  = 0;
    if (cmd_len < NCP_BRIDGE_CMD_HEADER_LEN || cmd_len > NCP_BRIDGE_INBUF_SIZE)
    {
        app_notify_event(APP_EVT_INVALID_CMD, APP_EVT_REASON_SUCCESS, NULL, 0);
        memset(cmd_buf, 0, sizeof(cmd_buf));
        total = 0;
#ifdef CONFIG_UART_BRIDGE
        memset(b_background_buffer, 0x0, sizeof(b_background_buffer));
        USART_TransferStartRingBuffer((&uart_rtos_handle)->base, (&uart_rtos_handle)->t_state,
                                      (&protocol_usart_config)->buffer, (&protocol_usart_config)->buffer_size);
#endif
        return;
    }
#ifdef CONFIG_UART_BRIDGE
    while (len != (cmd_len - NCP_BRIDGE_CMD_HEADER_LEN) + CHECKSUM_LEN)
    {
#ifdef CONFIG_HOST_SLEEP
        if (usart_suspend_flag)
        {
            os_thread_sleep(os_msec_to_ticks(1000));
            continue;
        }
#endif
        ret = USART_RTOS_Receive(&uart_rtos_handle, cmd_buf + NCP_BRIDGE_CMD_HEADER_LEN + len,
                                 cmd_len - NCP_BRIDGE_CMD_HEADER_LEN + CHECKSUM_LEN - len, &rx_len);
        len += rx_len;
        total += rx_len;
        if ((ret == kStatus_USART_RxRingBufferOverrun) || total >= sizeof(cmd_buf))
        {
            /* Notify about hardware buffer overrun, clear uart ring buffer and cmd buffer */
            memset(b_background_buffer, 0, sizeof(b_background_buffer));
            memset(cmd_buf, 0, sizeof(cmd_buf));
            total = 0;
            /* To Do: send overflow TLV command to peer*/
            ncp_e("overflow");
            return;
        }
    }
#elif defined(CONFIG_SPI_BRIDGE)
    total_len = cmd_len + CHECKSUM_LEN;
    ret = ncp_bridge_spi_slave_transfer(cmd_buf + total, total_len - NCP_BRIDGE_CMD_HEADER_LEN, NCP_BRIDGE_SLAVE_RX,
                                        false);
    if (ret != WM_SUCCESS)
        return;
#endif
#else
    os_event_notify_get(OS_WAIT_FOREVER);
#endif

    g_cmd_seqno = (cmd_buf[NCP_BRIDGE_CMD_SEQUENCE_HIGH_BYTES] << 8) | cmd_buf[NCP_BRIDGE_CMD_SEQUENCE_LOW_BYTES];

#ifdef CONFIG_NCP_BRIDGE_DEBUG
    printSeparator();
#endif
    ncp_d("=====[CMD: #%d, Length: %d]=====", num++, total);

    /* validate the command including checksum */
    if (check_command_complete(cmd_buf) == WM_SUCCESS)
    {
        /* Processes commands and send response to host*/
        ncp_d("taking bridge lock......");
        os_semaphore_get(&bridge_lock, OS_WAIT_FOREVER);
        ncp_d("got bridge lock");
        handle_input(cmd_buf);
    }
}

#ifdef CONFIG_UART_BRIDGE
int bridge_uart_reinit()
{
    /* Attach FRG0 clock to FLEXCOMM0 */
    CLOCK_SetFRGClock(PROTOCOL_UART_FRG_CLK);
    CLOCK_AttachClk(PROTOCOL_UART_CLK_ATTACH);
    return USART_RTOS_Init(&uart_rtos_handle, &uart_handle, &protocol_usart_config);
}

int bridge_uart_deinit()
{
    return USART_RTOS_Deinit(&uart_rtos_handle);
}

void bridge_uart_notify()
{
    xEventGroupSetBits(uart_rtos_handle.rxEvent, RTOS_USART_COMPLETE);
}
#endif

static void bridge_task(void *pvParameters)
{
#ifdef CONFIG_UART_BRIDGE
    /* Attach FRG0 clock to FLEXCOMM0 */
    CLOCK_SetFRGClock(PROTOCOL_UART_FRG_CLK);
    CLOCK_AttachClk(PROTOCOL_UART_CLK_ATTACH);

    ncp_bridge_get_uart_conf(&protocol_usart_config);

    protocol_usart_config.srcclk = PROTOCOL_UART_CLK_FREQ;
    protocol_usart_config.base   = PROTOCOL_UART;

    NVIC_SetPriority(PROTOCOL_UART_IRQ, USART_NVIC_PRIO);

    if (USART_RTOS_Init(&uart_rtos_handle, &uart_handle, &protocol_usart_config) != WM_SUCCESS)
    {
        ncp_e("failed to initialize protocol uart");
        vTaskSuspend(NULL);
    }
#elif defined(CONFIG_SPI_BRIDGE)
    int ret = 0;

    ret = ncp_bridge_init_spi_slave();
    if (ret)
    {
        ncp_e("Failed to initialize SPI slave");
        vTaskSuspend(NULL);
    }
#endif

#ifndef CONFIG_CRC32_HW_ACCELERATE
    /* Generate a table for a byte-wise 32-bit CRC calculation on the polynomial. */
    ncp_bridge_init_crc32();
#endif

    /* Receive peer TLV commands and send responses back to peer. */
    while (1)
    {
        bridge_get_input();
    }
}

static int bridge_init(void)
{
    int ret;

    ret = os_semaphore_create(&bridge_lock, "bridge_lock");
    if (ret != WM_SUCCESS)
    {
        ncp_e("failed to create bridge lock: %d", ret);
        return -WM_FAIL;
    }

    ret = os_thread_create(&ncp_bridge_thread, "bridge_task", bridge_task, 0, &ncp_bridge_stack, OS_PRIO_2);
    if (ret != WM_SUCCESS)
    {
        ncp_e("failed to create interface thread: %d", ret);
        return -WM_FAIL;
    }

    ret = app_notify_init();
    if (ret != WM_SUCCESS)
    {
        ncp_e("app notify failed to initialize: %d", ret);
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

    printSeparator();
    PRINTF("app_cb: WLAN: received event %d\r\n", reason);
    printSeparator();

    if (check_valid_status_for_uap_prov() && check_valid_event_for_uap_prov(reason))
    {
        send_msg_to_uap_prov(MSG_TYPE_EVT, reason, (int)data);
    }

    switch (reason)
    {
        case WLAN_REASON_INITIALIZED:
            PRINTF("app_cb: WLAN initialized\r\n");
            printSeparator();

#ifdef CONFIG_NCP_BRIDGE_DEBUG
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

#ifdef CONFIG_HOST_SLEEP
            ret = host_sleep_cli_init();
            if (ret != WM_SUCCESS)
            {
                PRINTF("Failed to initialize WLAN host sleep CLIs\r\n");
                return 0;
            }
            PRINTF("HOST SLEEP CLIs are initialized\r\n");
            printSeparator();
#endif

            ret = wlan_enhanced_cli_init();
            if (ret != WM_SUCCESS)
            {
                PRINTF("Failed to initialize WLAN CLIs\r\n");
                return 0;
            }
            PRINTF("ENHANCED WLAN CLIs are initialized\r\n");
            printSeparator();

            ret = dhcpd_cli_init();
            if (ret != WM_SUCCESS)
            {
                PRINTF("Failed to initialize DHCP Server CLI\r\n");
                return 0;
            }
#endif
            ret = uap_prov_cli_init();
            if (ret != WM_SUCCESS)
            {
                PRINTF("Failed to initialize UAP PROV CLI\r\n");
                return 0;
            }

            ret = ncp_bridge_mdns_init();
            if (ret != WM_SUCCESS)
            {
                (void)PRINTF("Failed to initialize mDNS\r\n");
                return 0;
            }
            (void)PRINTF("mDNS are initialized\r\n");
            printSeparator();
            break;
        case WLAN_REASON_INITIALIZATION_FAILED:
            PRINTF("app_cb: WLAN: initialization failed\r\n");
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
            for (i = 0; i < CONFIG_MAX_IPV6_ADDRESSES; i++)
            {
                if (ip6_addr_isvalid(addr.ipv6[i].addr_state))
                {
                    (void)PRINTF("IPv6 Address: %-13s:\t%s (%s)\r\n",
                                 ipv6_addr_type_to_desc((struct net_ipv6_config *)&addr.ipv6[i]),
                                 inet6_ntoa(addr.ipv6[i].address), ipv6_addr_state_to_desc(addr.ipv6[i].addr_state));
                }
            }
            (void)PRINTF("\r\n");
#endif
#ifdef MDNS_STA_INTERFACE
            if (!network_services)
            {
                ret = app_mdns_register_iface(net_get_sta_handle());
                if (ret != WM_SUCCESS)
                    (void)PRINTF("Error in registering mDNS STA interface\r\n");
                else
                {
                    (void)PRINTF("mDNS STA Interface successfully registered\r\n");
                    network_services = 1;
                }
            }
            else
            {
                app_mdns_resp_restart(net_get_sta_handle());
            }
#endif
            NCP_CMD_WLAN_CONN *conn_res = (NCP_CMD_WLAN_CONN *)os_mem_alloc(sizeof(NCP_CMD_WLAN_CONN));
            if (conn_res == NULL)
            {
                app_notify_event(APP_EVT_USER_CONNECT, APP_EVT_REASON_FAILURE, NULL, 0);
            }
            else
            {
                conn_res->ip = addr.ipv4.address;
                (void)memcpy(conn_res->ssid, sta_network.ssid, sizeof(sta_network.ssid));
                app_notify_event(APP_EVT_USER_CONNECT, APP_EVT_REASON_SUCCESS, conn_res, sizeof(NCP_CMD_WLAN_CONN));
            }
            auth_fail = 0;
            break;
        case WLAN_REASON_CONNECT_FAILED:
            PRINTF("app_cb: WLAN: connect failed\r\n");
            app_notify_event(APP_EVT_USER_CONNECT, APP_EVT_REASON_FAILURE, NULL, 0);
            break;
        case WLAN_REASON_NETWORK_NOT_FOUND:
            PRINTF("app_cb: WLAN: network not found\r\n");
            break;
        case WLAN_REASON_NETWORK_AUTH_FAILED:
            PRINTF("app_cb: WLAN: network authentication failed\r\n");
            auth_fail++;
            if (auth_fail >= 3)
            {
                PRINTF("Authentication Failed. Disconnecting ... \r\n");
                wlan_disconnect();
                auth_fail = 0;
            }
#ifdef MDNS_STA_INTERFACE
            ret = app_mdns_deregister_iface(net_get_sta_handle());
            if (ret != WM_SUCCESS)
                (void)PRINTF("Error in deregistering mDNS STA interface\r\n");
            else
                (void)PRINTF("mDNS STA Interface successfully deregistered\r\n");
#endif
            break;
        case WLAN_REASON_ADDRESS_SUCCESS:
            PRINTF("network mgr: DHCP new lease\r\n");
#ifdef MDNS_STA_INTERFACE
            app_mdns_resp_restart(net_get_sta_handle());
#endif
            break;
        case WLAN_REASON_ADDRESS_FAILED:
            PRINTF("app_cb: failed to obtain an IP address\r\n");
            break;
        case WLAN_REASON_USER_DISCONNECT:
            PRINTF("app_cb: disconnected\r\n");
#ifdef MDNS_STA_INTERFACE
            ret = app_mdns_deregister_iface(net_get_sta_handle());
            if (ret != WM_SUCCESS)
                (void)PRINTF("Error in deregistering mDNS STA interface\r\n");
            else
            {
                network_services = 0;
                (void)PRINTF("mDNS STA Interface successfully deregistered\r\n");
            }
#endif
            if (!data)
                app_notify_event(APP_EVT_USER_DISCONNECT, APP_EVT_REASON_SUCCESS, NULL, 0);
            else
                app_notify_event(APP_EVT_USER_DISCONNECT, (int)data ? APP_EVT_REASON_FAILURE : APP_EVT_REASON_SUCCESS,
                                 NULL, 0);
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
            NCP_CMD_NETWORK_START *start_res = (NCP_CMD_NETWORK_START *)os_mem_alloc(sizeof(NCP_CMD_NETWORK_START));
            (void)memcpy(start_res->ssid, uap_network.ssid, sizeof(uap_network.ssid));
            app_notify_event(APP_EVT_USER_START_NETWORK, APP_EVT_REASON_SUCCESS, start_res,
                             sizeof(NCP_CMD_NETWORK_START));

            ret = app_mdns_register_iface(net_get_uap_handle());
            if (ret != WM_SUCCESS)
                (void)PRINTF("Error in registering mDNS uAP interface\r\n");
            else
                (void)PRINTF("mDNS uAP Interface successfully registered\r\n");
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
        case WLAN_REASON_UAP_START_FAILED:
            PRINTF("app_cb: WLAN: UAP start failed\r\n");
            app_notify_event(APP_EVT_USER_START_NETWORK, APP_EVT_REASON_FAILURE, NULL, 0);
            break;
        case WLAN_REASON_UAP_STOP_FAILED:
            PRINTF("app_cb: WLAN: UAP stop failed\r\n");
            app_notify_event(APP_EVT_USER_STOP_NETWORK, APP_EVT_REASON_FAILURE, NULL, 0);
            break;
        case WLAN_REASON_UAP_STOPPED:
            PRINTF("app_cb: WLAN: UAP Stopped\r\n");
            printSeparator();
            PRINTF("Soft AP \"%s\" stopped successfully\r\n", uap_network.ssid);
            printSeparator();

            dhcp_server_stop();

            PRINTF("DHCP Server stopped successfully\r\n");
            printSeparator();
            app_notify_event(APP_EVT_USER_STOP_NETWORK, APP_EVT_REASON_SUCCESS, NULL, 0);

            ret = app_mdns_deregister_iface(net_get_uap_handle());
            if (ret != WM_SUCCESS)
                (void)PRINTF("Error in deregistering mDNS uAP interface\r\n");
            else
                (void)PRINTF("mDNS uAP Interface successfully deregistered\r\n");
            printSeparator();
            break;
        case WLAN_REASON_PS_ENTER:
            PRINTF("app_cb: WLAN: PS_ENTER\r\n");
            break;
        case WLAN_REASON_PS_EXIT:
            PRINTF("app_cb: WLAN: PS EXIT\r\n");
            break;
        case WLAN_REASON_WPS_SESSION_DONE:
            PRINTF("app_cb: WLAN: WPS session done\r\n");
            app_notify_event(APP_EVT_WPS_DONE, APP_EVT_REASON_SUCCESS, data, sizeof(struct wlan_network));
            break;
        default:
            PRINTF("app_cb: WLAN: Unknown Event: %d\r\n", reason);
    }
    return 0;
}

static void ncp_gpio_init()
{
    /* Define the init structure for the input switch pin */
    gpio_pin_config_t gpio_in_config = {
        kGPIO_DigitalInput,
        0,
    };
    gpio_pin_config_t gpio_out_config = {
        kGPIO_DigitalOutput,
        1,
    };

#ifndef CONFIG_SPI_BRIDGE
    GPIO_PortInit(GPIO, 0);
#endif
    GPIO_PinInit(GPIO, BOARD_SW4_GPIO_PORT, BOARD_SW4_GPIO_PIN, &gpio_in_config);
    /* Init output GPIO */
    GPIO_PinInit(GPIO, 0, 5, &gpio_out_config);
}

void task_main(void *param)
{
    int32_t result = 0;

#ifdef CONFIG_NCP_BRIDGE_DEBUG
    PRINTF("Initialize CLI\r\n");
    printSeparator();

    result = cli_init();

    assert(WM_SUCCESS == result);

#endif

    PRINTF("Initialize NCP config littlefs CLIs\r\n");
    printSeparator();
    result = ncp_config_init();
    assert(WM_SUCCESS == result);

    result = bridge_init();

    assert(WM_SUCCESS == result);

#ifdef CONFIG_USB_BRIDGE
    result = usb_device_task_init();
    assert(WM_SUCCESS == result);
    result = usb_slave_app_init();
    assert(WM_SUCCESS == result);
#endif

    printSeparator();
#ifdef CONFIG_HOST_SLEEP
    hostsleep_init();
    ncp_gpio_init();
#endif

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
#ifdef CONFIG_CRC32_HW_ACCELERATE
    hw_crc32_init();
#endif
    RTC_Init(RTC);

    printSeparator();
    PRINTF("wifi supplicant demo\r\n");
    printSeparator();

#ifdef CONFIG_WIFI_USB_FILE_ACCESS
    usb_init();
#endif
    sys_thread_new("main", task_main, NULL, TASK_MAIN_STACK_SIZE, TASK_MAIN_PRIO);

#if 0
    result =
        xTaskCreate(task_main, "main", TASK_MAIN_STACK_SIZE, task_main_stack, TASK_MAIN_PRIO, &task_main_task_handler);
    assert(pdPASS == result);
#endif

    vTaskStartScheduler();
    for (;;)
        ;
}
