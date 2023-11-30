/** @file usb_slave_app.h
 *
 *  @brief main file
 *
 *  Copyright 2023 NXP
 *  All rights reserved.
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef _USB_SLAVE_APP_H_
#define _USB_SLAVE_APP_H_
/*******************************************************************************
 * Definitions
 ******************************************************************************/
#include "usb_device_config.h"
#include "usb.h"
#include "usb_device.h"
#include "usb_device_class.h"
#include "usb_device_ch9.h"
#include "usb_device_descriptor.h"
#include "cdc_app.h"
#include "usb_device_config.h"
#include "usb_device_cdc_acm.h"

#define USB_CMD_RESP_NUM         16
#define PER_SOCKET_RESP_BUFF_LEN 1600

#define NCP_SEND_FIFO_ATTEMPTS 10

/* app notify event queue message */
typedef struct
{
    void *data;
    uint16_t len;
    /*Call this cb after usb send finished*/
    void (*usb_send_cb)();
} usb_cmd_resp_msg_t;

/*******************************************************************************
 * API
 ******************************************************************************/
void usb_save_recv_data(uint8_t *recv_data, uint32_t packet_len);
int usb_cmd_response(uint8_t *data, uint16_t transfer_size, void (*callback)(), unsigned long wait);
int usb_no_copy_cmd_response(uint8_t *data, uint16_t transfer_size, void (*callback)(), unsigned long wait);
int usb_slave_app_init();
void put_command_usb_pipe_sem(void);
#endif
