/** @file usb_slave_app.c
 *
 *  @brief main file
 *
 *  Copyright 2023 NXP
 *  All rights reserved.
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 */
#include "wm_os.h"
#include "wlan.h"
#include "crc.h"
#include "usb_slave_app.h"
#include "ncp_bridge_glue.h"
#include "ncp_bridge_cmd.h"

#ifdef CONFIG_USB_BRIDGE

static os_thread_t usb_cmd_resp_thread;                  /* usb cmd resp task */
static os_thread_stack_define(usb_cmd_resp_stack, 4096); /* usb cmd resp task stack*/

extern usb_cdc_vcom_struct_t s_cdcVcom;
os_semaphore_t usb_pipe_seam;
uint8_t usb_scoket_cmd_resp_buf[USB_CMD_RESP_NUM][PER_SOCKET_RESP_BUFF_LEN];
int usb_scoket_cmd_resp_seq = 0;

static os_queue_t usb_cmd_resp_queue; /* app notify event queue */
static os_queue_pool_define(usb_cmd_resp_queue_data, USB_CMD_RESP_NUM * sizeof(usb_cmd_resp_msg_t));

uint32_t usb_recv_drop = 0;

void put_command_usb_pipe_sem(void)
{
    os_semaphore_put(&usb_pipe_seam);
}

uint16_t usb_prepare_socket_cmd_resp(uint32_t cmd, uint16_t result, uint16_t seqnum)
{
    uint32_t chksum   = 0;
    uint16_t index    = 0;
    uint16_t data_len = 0;

    NCPCmd_DS_COMMAND *cmd_res = ncp_bridge_get_response_buffer();
    cmd_res->header.cmd        = cmd;
    cmd_res->header.size       = NCP_BRIDGE_CMD_HEADER_LEN;
    cmd_res->header.result     = result;
    cmd_res->header.msg_type   = NCP_BRIDGE_MSG_TYPE_RESP;
    cmd_res->header.seqnum     = seqnum;

    /* calculate CRC. */
    chksum                                    = ncp_bridge_get_crc32((uint8_t *)cmd_res, cmd_res->header.size);
    index                                     = cmd_res->header.size;
    *(uint32_t *)((uint8_t *)cmd_res + index) = chksum;

    data_len = cmd_res->header.size + CHECKSUM_LEN;

    return data_len;
}

int usb_no_copy_cmd_response(uint8_t *data, uint16_t transfer_size, void (*callback)(), unsigned long wait)
{
    usb_cmd_resp_msg_t msg;

    msg.data        = data;
    msg.len         = transfer_size;
    msg.usb_send_cb = callback;

    return os_queue_send(&usb_cmd_resp_queue, &msg, wait);
}

int usb_cmd_response(uint8_t *data, uint16_t transfer_size, void (*callback)(), unsigned long wait)
{
    usb_cmd_resp_msg_t msg;

    if (transfer_size < PER_SOCKET_RESP_BUFF_LEN)
        memcpy(usb_scoket_cmd_resp_buf[usb_scoket_cmd_resp_seq], (uint8_t *)data, transfer_size);
    else
        return -WM_FAIL;

    msg.data        = &usb_scoket_cmd_resp_buf[usb_scoket_cmd_resp_seq];
    msg.len         = transfer_size;
    msg.usb_send_cb = callback;

    usb_scoket_cmd_resp_seq++;
    usb_scoket_cmd_resp_seq = usb_scoket_cmd_resp_seq % USB_CMD_RESP_NUM;

    return os_queue_send(&usb_cmd_resp_queue, &msg, wait);
}

#ifdef CONFIG_NCP_SOCKET_SEND_FIFO
extern os_queue_t socket_send_fifo_queue; /* app notify event queue */
extern uint8_t socket_send_cmd_buf[SOCKET_SEND_COMMAND_NUM][NCP_BRIDGE_SEND_DATA_INBUF_SIZE];
extern uint8_t res_buf[NCP_BRIDGE_INBUF_SIZE];
extern int socket_send_fifo_recv_seq;
#endif

extern uint8_t cmd_buf[NCP_BRIDGE_INBUF_SIZE];
extern os_thread_t ncp_bridge_thread;
void usb_save_recv_data(uint8_t *recv_data, uint32_t packet_len)
{
#ifdef CONFIG_NCP_SOCKET_SEND_FIFO
    uint32_t ret = 0;
#endif
    static uint32_t usb_transfer_len = 0;
    static uint32_t usb_rx_len       = 0;
    /*reset cmd_buf on first usb bulk received*/
    if (!usb_rx_len)
    {
        memset(cmd_buf, 0, sizeof(cmd_buf));
    }
    if (usb_rx_len < NCP_BRIDGE_CMD_HEADER_LEN)
    {
        memcpy((uint8_t *)&cmd_buf[0] + usb_rx_len, recv_data, packet_len);
        usb_rx_len += packet_len;

        if (usb_rx_len >= NCP_BRIDGE_CMD_HEADER_LEN)
        {
            usb_transfer_len =
                ((cmd_buf[NCP_BRIDGE_CMD_SIZE_HIGH_BYTES] << 8) | cmd_buf[NCP_BRIDGE_CMD_SIZE_LOW_BYTES]) +
                CHECKSUM_LEN;
        }
    }
    else
    {
        if ((packet_len < (sizeof(cmd_buf) - usb_rx_len)) && (usb_rx_len < usb_transfer_len))
        {
            memcpy((uint8_t *)&cmd_buf[0] + usb_rx_len, recv_data, packet_len);
            usb_rx_len += packet_len;
        }
        else
        {
            ncp_d("[%s] transfer warning. data_len : %d  \r\n", __func__, packet_len);
        }
    }

    if ((usb_rx_len >= usb_transfer_len) && (usb_transfer_len >= NCP_BRIDGE_CMD_HEADER_LEN))
    {
        ncp_d("recv data len: %d", usb_transfer_len);
#ifdef CONFIG_NCP_SOCKET_SEND_FIFO
        int retry             = NCP_SEND_FIFO_ATTEMPTS;
        uint16_t cmd_resp_len = 0;

        NCP_BRIDGE_COMMAND *input_cmd = (NCP_BRIDGE_COMMAND *)&cmd_buf[0];
        /*Dliver cmd data to socket_send_cmd_task directly, other cmds still deal with legacy data path*/
        if (input_cmd->cmd == NCP_BRIDGE_CMD_WLAN_SOCKET_SEND || input_cmd->cmd == NCP_BRIDGE_CMD_WLAN_SOCKET_SENDTO)
        {
            socket_send_msg_t msg;
            msg.send_type = input_cmd->cmd;
            ncp_d("[%s-%d]: socket_send_fifo_recv_seq = %d\r\n", __func__, __LINE__, socket_send_fifo_recv_seq);
            memcpy(socket_send_cmd_buf[socket_send_fifo_recv_seq], (uint8_t *)input_cmd, usb_transfer_len);

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
                usb_recv_drop++;
                cmd_resp_len =
                    usb_prepare_socket_cmd_resp(input_cmd->cmd, NCP_BRIDGE_CMD_RESULT_ERROR, input_cmd->seqnum);
                usb_cmd_response((uint8_t *)&res_buf[0], cmd_resp_len, NULL, OS_NO_WAIT);
            }

            socket_send_fifo_recv_seq++;
            socket_send_fifo_recv_seq = socket_send_fifo_recv_seq % SOCKET_SEND_COMMAND_NUM;
        }
        else
        {
            os_event_notify_put(ncp_bridge_thread);
        }
#else
        os_event_notify_put(ncp_bridge_thread);
#endif
        usb_rx_len       = 0;
        usb_transfer_len = 0;

        ncp_d("usb data recv success \r\n");
    }
}

int usb_send_data(uint8_t *data, uint16_t data_len)
{
    uint16_t packet_size        = 0;
    uint16_t remaining_data_len = data_len;
    ncp_d("usb transfer_size :%d!\r\n", data_len);

    while (remaining_data_len > 0)
    {
        packet_size = (remaining_data_len > NCP_BRIDGE_INBUF_SIZE) ? NCP_BRIDGE_INBUF_SIZE : remaining_data_len;

        USB_DeviceCdcAcmSend(s_cdcVcom.cdcAcmHandle, USB_CDC_VCOM_BULK_IN_ENDPOINT,
                             (uint8_t *)data + data_len - remaining_data_len, packet_size);

        os_semaphore_get(&usb_pipe_seam, OS_WAIT_FOREVER);

        remaining_data_len -= packet_size;
    }

    return WM_SUCCESS;
}

static void usb_cmd_resp_task(void *pvParameters)
{
    usb_cmd_resp_msg_t cmd_resp_msg;
    while (1)
    {
        os_queue_recv(&usb_cmd_resp_queue, &cmd_resp_msg, OS_WAIT_FOREVER);

        uint8_t *data = (uint8_t *)cmd_resp_msg.data;
        uint16_t len  = cmd_resp_msg.len;

        usb_send_data(data, len);

        if (NULL != cmd_resp_msg.usb_send_cb)
            cmd_resp_msg.usb_send_cb();
    }
}

int usb_slave_app_init()
{
    int ret = WM_SUCCESS;

    ret = os_queue_create(&usb_cmd_resp_queue, "usb_cmd_resp_queue", sizeof(usb_cmd_resp_msg_t),
                          &usb_cmd_resp_queue_data);
    if (ret != WM_SUCCESS)
    {
        ncp_e("failed to create usb_cmd_resp_queue: %d", ret);
        return -WM_FAIL;
    }
    ret = os_thread_create(&usb_cmd_resp_thread, "usb_cmd_resp_task", usb_cmd_resp_task, 0, &usb_cmd_resp_stack,
                           OS_PRIO_1);
    if (ret != WM_SUCCESS)
    {
        ncp_e("failed to create usb_cmd_resp_task: %d", ret);
        return -WM_FAIL;
    }

    ret = os_semaphore_create(&usb_pipe_seam, "usb_pipe_seam");
    if (ret != WM_SUCCESS)
    {
        ncp_e("failed to create usb_pipe_seam: %d", ret);
        return -WM_FAIL;
    }

    os_semaphore_get(&usb_pipe_seam, OS_WAIT_FOREVER);

    return WM_SUCCESS;
}
#endif
