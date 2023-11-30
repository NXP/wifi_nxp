/**@file mcu_bridge_app.h
 *
 *  Copyright 2008-2023 NXP
 *
 *  Licensed under the LA_OPT_NXP_Software_License.txt (the "Agreement")
 *
 */

#ifndef _MCU_BRIDGE_APP_H_
#define _MCU_BRIDGE_APP_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "mcu_bridge_utils.h"

#define mcu_e(...) wmlog_e("mcu bridge", ##__VA_ARGS__)
#define mcu_w(...) wmlog_w("mcu bridge", ##__VA_ARGS__)

#ifdef CONFIG_MCU_BRIDGE_DEBUG
#define mcu_d(...) wmlog("mcu bridge", ##__VA_ARGS__)
#else
#define mcu_d(...)
#endif

#define MCU_BRIDGE_CMD_SIZE_BIT1     4
#define MCU_BRIDGE_CMD_SIZE_BIT2     5
#define MCU_BRIDGE_CMD_SEQUENCE_BIT1 6
#define MCU_BRIDGE_CMD_SEQUENCE_BIT2 7

#define CRC32_POLY 0x04c11db7

#define MCU_CHECKSUM_LEN 4

#define BRIDGE_MUTEX_INHERIT 1
#define TLV_CMD_BUF          200

int mcu_bridge_app_init();

int bridge_put_command_lock();

int bridge_get_uart_lock();

int string_equal(const char *s1, const char *s2);

int get_uint(const char *arg, unsigned int *dest, unsigned int len);

int check_command_complete(uint8_t *buf);

int mcu_get_command_resp_sem();

int mcu_put_command_resp_sem();

int mcu_get_command_lock();

int mcu_put_command_lock();

#endif /*_MCU_BRIDGE_APP_H_*/
