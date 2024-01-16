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

#include "wm_utils.h"
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
#elif defined(CONFIG_SDIO_BRIDGE)
#include "fsl_adapter_sdu.h"
#endif
#include "ncp_bridge_cmd.h"

#if defined(MBEDTLS_NXP_SSSAPI)
#include "sssapi_mbedtls.h"
#elif defined(MBEDTLS_MCUX_CSS_API)
#include "platform_hw_ip.h"
#include "css_mbedtls.h"
#elif defined(MBEDTLS_MCUX_CSS_PKC_API)
#include "platform_hw_ip.h"
#include "css_pkc_mbedtls.h"
#elif defined(MBEDTLS_MCUX_ELS_PKC_API)
#include "platform_hw_ip.h"
#include "els_pkc_mbedtls.h"
#elif defined(MBEDTLS_MCUX_ELS_API)
#include "platform_hw_ip.h"
#include "els_mbedtls.h"
#else
#include "ksdk_mbedtls.h"
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

#define UART_BUF_SIZE               32
#define NCP_UART_SEND_FIFO_ATTEMPTS 1
#endif

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Variables
 ******************************************************************************/
extern int network_services;

const int TASK_MAIN_PRIO       = OS_PRIO_3;
const int TASK_MAIN_STACK_SIZE = 800;

portSTACK_TYPE *task_main_stack = NULL;
TaskHandle_t task_main_task_handler;

os_semaphore_t bridge_lock;

os_thread_t ncp_bridge_thread;                         /* ncp bridge task */
static os_thread_stack_define(ncp_bridge_stack, 8192); /* ncp bridge  task stack*/

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

#ifdef CONFIG_SPI_BRIDGE
extern os_semaphore_t spi_slave_sem;
#endif

uint32_t cmd_recv_drop  = 0;
uint32_t data_recv_drop = 0;
#define NCP_SDU_SEND_FIFO_ATTEMPTS 1
#ifdef CONFIG_SDIO_BRIDGE
status_t sdu_cmd_handler(uint8_t *data_addr, uint16_t data_len);
status_t sdu_data_handler(uint8_t *data_addr, uint16_t data_len);
status_t sdu_send_response(uint8_t *data_addr, uint16_t data_len);
#endif

#ifdef CONFIG_NCP_SOCKET_SEND_FIFO
static os_thread_t socket_send_cmd_thread;                  /* socket send task */
static os_thread_stack_define(socket_send_cmd_stack, 4096); /* socket send stack*/

os_queue_t socket_send_fifo_queue; /* app notify event queue */
static os_mutex_t socket_send_fifo_mutex;

static os_queue_pool_define(socket_send_queue_data, SOCKET_SEND_COMMAND_NUM * sizeof(socket_send_msg_t));

extern int wlan_bridge_socket_send(void *data);
extern int wlan_bridge_socket_sendto(void *data);
uint8_t socket_send_cmd_buf[SOCKET_SEND_COMMAND_NUM][NCP_BRIDGE_SEND_DATA_INBUF_SIZE];
int socket_send_fifo_recv_seq = 0;
int socket_send_fifo_num      = 0;
#endif

os_mutex_t resp_buf_mutex;
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
    local_checksum  = ncp_bridge_get_crc32(buf, msglen);
    if ((remote_checksum == local_checksum) && local_checksum != 0)
    {
        ncp_d("local checksum == remote checksum: 0x%02x", local_checksum);
        return WM_SUCCESS;
    }
    else
    {
        ncp_e("local checksum: 0x%02x != remote checksum: 0x%02x, msglen = %d\n", local_checksum, remote_checksum,
              msglen);
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

    os_mutex_get(&resp_buf_mutex, OS_WAIT_FOREVER);
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
#elif defined(CONFIG_SDIO_BRIDGE)
        ret = sdu_send_response(pbuf, transfer_len);
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
        /* Reset res_buf */
#ifndef CONFIG_USB_BRIDGE
        memset(res_buf, 0, sizeof(res_buf));
#endif
        os_semaphore_put(&bridge_lock);
        ncp_d("put bridge lock");
    }
    os_mutex_put(&resp_buf_mutex);
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

    if (command->handler)
        ret = command->handler(cmd_tlv);
    else
    {
        ncp_e("command handler is null");
        ret = -WM_FAIL;
    }
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
#elif defined(CONFIG_SDIO_BRIDGE)
    ret = SDU_RecvCmd();
    if (ret != WM_SUCCESS)
    {
        ncp_e("Failed to receive command header(%d)", ret);
        return;
    }
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
#ifdef CONFIG_NCP_SOCKET_SEND_FIFO
    int retry             = NCP_UART_SEND_FIFO_ATTEMPTS;
    uint16_t cmd_resp_len = 0;

    NCP_BRIDGE_COMMAND *input_cmd = (NCP_BRIDGE_COMMAND *)&cmd_buf[0];
    /*Dliver cmd data to socket_send_cmd_task directly, other cmds still deal with legacy data path*/
    if (input_cmd->cmd == NCP_BRIDGE_CMD_WLAN_SOCKET_SEND || input_cmd->cmd == NCP_BRIDGE_CMD_WLAN_SOCKET_SENDTO)
    {
        socket_send_msg_t msg;
        msg.send_type = input_cmd->cmd;
        // PRINTF("[%s-%d]: socket_send_fifo_recv_seq = %d\r\n", __func__, __LINE__, socket_send_fifo_recv_seq);
        memcpy(socket_send_cmd_buf[socket_send_fifo_recv_seq], (uint8_t *)input_cmd, cmd_len + CHECKSUM_LEN);

        while (retry > 0)
        {
            msg.data = &socket_send_cmd_buf[socket_send_fifo_recv_seq];
            ret      = os_queue_send(&socket_send_fifo_queue, &msg, OS_NO_WAIT);
            if (WM_SUCCESS == ret)
                break;
            taskYIELD();
            retry--;
        }

        if (WM_SUCCESS != ret)
        {
            data_recv_drop++;
            wlan_bridge_prepare_status(input_cmd->cmd, NCP_BRIDGE_CMD_RESULT_ERROR);
            bridge_send_response(res_buf);
        }

        os_mutex_get(&socket_send_fifo_mutex, OS_WAIT_FOREVER);
        socket_send_fifo_recv_seq++;
        socket_send_fifo_recv_seq = socket_send_fifo_recv_seq % SOCKET_SEND_COMMAND_NUM;
        os_mutex_put(&socket_send_fifo_mutex);
        return;
    }
#endif
#elif defined(CONFIG_SPI_BRIDGE)
    total_len = cmd_len + CHECKSUM_LEN;
    ret = ncp_bridge_spi_slave_transfer(cmd_buf + total, total_len - NCP_BRIDGE_CMD_HEADER_LEN, NCP_BRIDGE_SLAVE_RX,
                                        false);
    if (ret != WM_SUCCESS)
        return;
#elif defined(CONFIG_SDIO_BRIDGE)
    (void)len;
    (void)rx_len;
    total = cmd_len + CHECKSUM_LEN;
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

#ifdef CONFIG_SDIO_BRIDGE
status_t sdu_cmd_handler(uint8_t *data_addr, uint16_t data_len)
{
    assert(NULL != data_addr);
    assert(0 != data_len);

    // ncp_d("%s: data_addr=%p data_len=%d\r\n", __func__, data_addr, data_len);
    // dump_hex(data_addr, data_len);

    memset(cmd_buf, 0, sizeof(cmd_buf));
    memcpy(cmd_buf, data_addr, MIN(data_len, sizeof(cmd_buf)));

    return kStatus_Success;
}

status_t sdu_data_handler(uint8_t *data_addr, uint16_t data_len)
{
    int retry                     = NCP_SDU_SEND_FIFO_ATTEMPTS;
    uint16_t cmd_resp_len         = 0;
    NCP_BRIDGE_COMMAND *input_cmd = (NCP_BRIDGE_COMMAND *)data_addr;
    status_t stat                 = kStatus_Fail;
    int ret                       = WM_SUCCESS;

    assert(NULL != data_addr);
    assert(0 != data_len);

    // ncp_d("%s: data_addr=%p data_len=%d\r\n", __func__, data_addr, data_len);
    // dump_hex(data_addr, data_len);

    if ((input_cmd->cmd == NCP_BRIDGE_CMD_WLAN_SOCKET_SEND) || (input_cmd->cmd == NCP_BRIDGE_CMD_WLAN_SOCKET_SENDTO))
    {
        socket_send_msg_t msg;
        msg.send_type = input_cmd->cmd;

        // ncp_d("%s: DATA fifo_num=%d fifo_seq=%d\r\n", __func__,
        //                socket_send_fifo_num, socket_send_fifo_recv_seq);
        if (data_len > NCP_BRIDGE_SEND_DATA_INBUF_SIZE)
        {
            ncp_e("%s: data_len=%d exceed %d\r\n", __func__, data_len, NCP_BRIDGE_SEND_DATA_INBUF_SIZE);
            goto done;
        }

        if (socket_send_fifo_num >= SOCKET_SEND_COMMAND_NUM)
        {
            // vTaskDelay(os_msec_to_ticks(20));
            ncp_e("%s: drop data for socket_send_fifo_num=%d > %d\r\n", __func__, socket_send_fifo_num,
                  SOCKET_SEND_COMMAND_NUM);
            goto done;
        }

        memcpy(socket_send_cmd_buf[socket_send_fifo_recv_seq], (uint8_t *)input_cmd, data_len);
        while (retry > 0)
        {
            msg.data = &socket_send_cmd_buf[socket_send_fifo_recv_seq];
            ret      = os_queue_send(&socket_send_fifo_queue, &msg, OS_NO_WAIT);
            if (WM_SUCCESS == ret)
                break;
            vTaskDelay(os_msec_to_ticks(20));
            retry--;
        }
        if (WM_SUCCESS != ret)
        {
            goto done;
        }

        stat = kStatus_Success;
        os_mutex_get(&socket_send_fifo_mutex, OS_WAIT_FOREVER);
        socket_send_fifo_num++;
        socket_send_fifo_recv_seq = (socket_send_fifo_recv_seq + 1) % SOCKET_SEND_COMMAND_NUM;
        os_mutex_put(&socket_send_fifo_mutex);
    }

done:
    if (kStatus_Success != stat)
    {
        data_recv_drop++;
        wlan_bridge_prepare_status(input_cmd->cmd, NCP_BRIDGE_CMD_RESULT_ERROR);
        bridge_send_response(res_buf);
    }

    return stat;
}

status_t sdu_send_response(uint8_t *data_addr, uint16_t data_len)
{
    NCP_BRIDGE_COMMAND *res = (NCP_BRIDGE_COMMAND *)data_addr;
    status_t ret            = kStatus_Success;

    assert(NULL != data_addr);
    assert(0 != data_len);

    // ncp_d("%s: Enter %p %u", __FUNCTION__, data_addr, data_len);
    // dump_hex(data_addr, data_len);
    switch (res->msg_type)
    {
        case NCP_BRIDGE_MSG_TYPE_RESP:
            if ((res->cmd == NCP_BRIDGE_CMD_WLAN_SOCKET_SEND) || (res->cmd == NCP_BRIDGE_CMD_WLAN_SOCKET_SENDTO))
            {
                // ncp_d("%s: Send DATA %p %u", __FUNCTION__, data_addr, data_len);
                ret = SDU_Send(SDU_TYPE_FOR_READ_DATA, data_addr, data_len);
            }
            else
            {
                // ncp_d("%s: Send CMDRSP %p %u", __FUNCTION__, data_addr, data_len);
                ret = SDU_Send(SDU_TYPE_FOR_READ_CMD, data_addr, data_len);
            }
            break;
        case NCP_BRIDGE_MSG_TYPE_EVENT:
            // ncp_d("%s: Send EVENT %p %u", __FUNCTION__, data_addr, data_len);
            ret = SDU_Send(SDU_TYPE_FOR_READ_EVENT, data_addr, data_len);
            break;
        default:
            ncp_e("%s: invalid msg_type %d", __FUNCTION__, res->msg_type);
            ret = kStatus_Fail;
            break;
    }

    if (ret != kStatus_Success)
        ncp_e("%s: fail 0x%x", __FUNCTION__, ret);
    return ret;
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
#elif defined(CONFIG_SDIO_BRIDGE)
    status_t ret = 0;
    ret = SDU_Init();
    if (ret != kStatus_Success)
    {
        ncp_e("Failed to initialize SDIO");
        vTaskSuspend(NULL);
    }
    SDU_InstallCallback(SDU_TYPE_FOR_WRITE_CMD, sdu_cmd_handler);
    SDU_InstallCallback(SDU_TYPE_FOR_WRITE_DATA, sdu_data_handler);
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

#ifdef CONFIG_NCP_SOCKET_SEND_FIFO
static void socket_send_cmd_task(void *pvParameters)
{
    /* Receive peer TLV commands and send responses back to peer. */
    uint32_t cmd          = 0;
    uint16_t result       = NCP_BRIDGE_CMD_RESULT_OK;
    uint16_t seqnum       = 0;
    uint16_t cmd_resp_len = 0;

    socket_send_msg_t msg;
    while (1)
    {
        os_queue_recv(&socket_send_fifo_queue, &msg, OS_WAIT_FOREVER);

        NCP_BRIDGE_COMMAND *input_cmd = (NCP_BRIDGE_COMMAND *)msg.data;
        cmd                           = input_cmd->cmd;
        seqnum                        = input_cmd->seqnum;
        uint8_t *cmd_tlv              = GET_CMD_TLV(input_cmd);

        /* validate the command including checksum */
        if (check_command_complete((uint8_t *)input_cmd) == WM_SUCCESS)
        {
            if (msg.send_type == NCP_BRIDGE_CMD_WLAN_SOCKET_SEND)
                wlan_bridge_socket_send(cmd_tlv);
            else if (msg.send_type == NCP_BRIDGE_CMD_WLAN_SOCKET_SENDTO)
                wlan_bridge_socket_sendto(cmd_tlv);

            result = NCP_BRIDGE_CMD_RESULT_OK;
        }
        else
        {
            result = NCP_BRIDGE_CMD_RESULT_ERROR;
            /*
            PRINTF("************socket_send_cmd_task***************");
            dump_hex(input_cmd, input_cmd->size + 4);
            */
        }
        os_mutex_get(&socket_send_fifo_mutex, OS_WAIT_FOREVER);
        socket_send_fifo_num--;
        os_mutex_put(&socket_send_fifo_mutex);

#ifdef CONFIG_USB_BRIDGE
        cmd_resp_len = usb_prepare_socket_cmd_resp(cmd, result, seqnum);
        usb_cmd_response((uint8_t *)&res_buf[0], cmd_resp_len, NULL, OS_WAIT_FOREVER);
#else
        (void)seqnum;
        wlan_bridge_prepare_status(cmd, result);
        bridge_send_response(res_buf);
#endif
    }
}
#endif

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

#ifdef CONFIG_NCP_SOCKET_SEND_FIFO
    ret = os_queue_create(&socket_send_fifo_queue, "socket_send_fifo_queue", sizeof(socket_send_msg_t),
                          &socket_send_queue_data);
    if (ret != WM_SUCCESS)
    {
        ncp_e("failed to create socket_send_fifo_queue: %d", ret);
        return -WM_FAIL;
    }
    ret = os_mutex_create(&socket_send_fifo_mutex, "socket_send_fifo_mutex", OS_MUTEX_INHERIT);
    if (ret != WM_SUCCESS)
    {
        ncp_e("failed to create socket_send_fifo_mutex: %d", ret);
        return -WM_FAIL;
    }
    ret = os_thread_create(&socket_send_cmd_thread, "socket_send_cmd_task", socket_send_cmd_task, 0,
                           &socket_send_cmd_stack, OS_PRIO_2);
    if (ret != WM_SUCCESS)
    {
        ncp_e("failed to create socket_send_cmd_task thread: %d", ret);
        return -WM_FAIL;
    }
#endif
    ret = os_mutex_create(&resp_buf_mutex, "resp_buf_mutex", OS_MUTEX_INHERIT);
    if (ret != WM_SUCCESS)
    {
        ncp_e("failed to create resp_buf_mutex: %d", ret);
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
#ifndef CONFIG_NCP_BRIDGE_DEBUG
            (void)PRINTF("NCP device started successfully\r\n");
            (void)PRINTF("UART input disabled on NCP device side\r\n");
            (void)PRINTF("Please input commands on NCP host\r\n");
            printSeparator();
#endif
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
    (void)result;

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

    result = ncp_cmd_list_init();
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
    CRYPTO_InitHardware();
#ifdef CONFIG_CRC32_HW_ACCELERATE
    hw_crc32_init();
#endif
    RTC_Init(RTC);

    result =
        xTaskCreate(task_main, "main", TASK_MAIN_STACK_SIZE, task_main_stack, TASK_MAIN_PRIO, &task_main_task_handler);
    assert(pdPASS == result);

    vTaskStartScheduler();
    for (;;)
        ;
}
