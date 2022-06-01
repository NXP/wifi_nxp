/** @file wifi-imu.h
 *
 *  @brief WLAN on IMU
 *
 *  Copyright 2008-2021 NXP
 *
 *  NXP CONFIDENTIAL
 *  The source code contained or described herein and all documents related to
 *  the source code ("Materials") are owned by NXP, its
 *  suppliers and/or its licensors. Title to the Materials remains with NXP,
 *  its suppliers and/or its licensors. The Materials contain
 *  trade secrets and proprietary and confidential information of NXP, its
 *  suppliers and/or its licensors. The Materials are protected by worldwide copyright
 *  and trade secret laws and treaty provisions. No part of the Materials may be
 *  used, copied, reproduced, modified, published, uploaded, posted,
 *  transmitted, distributed, or disclosed in any way without NXP's prior
 *  express written permission.
 *
 *  No license under any patent, copyright, trade secret or other intellectual
 *  property right is granted to or conferred upon you by disclosure or delivery
 *  of the Materials, either expressly, by implication, inducement, estoppel or
 *  otherwise. Any license under such intellectual property rights must be
 *  express and approved by NXP in writing.
 *
 */

#ifndef __WIFI_IMU_H__
#define __WIFI_IMU_H__

#include <wifi.h>
#include "fsl_power.h"
#include "firmware_dnld.h"

#define wifi_io_e(...) wmlog_e("wifi_io", ##__VA_ARGS__)
#define wifi_io_w(...) wmlog_w("wifi_io", ##__VA_ARGS__)

#ifdef CONFIG_WIFI_IO_DEBUG
#define wifi_io_d(...) wmlog("wifi_io", ##__VA_ARGS__)
#else
#define wifi_io_d(...)
#endif /* ! CONFIG_WIFI_IO_DEBUG */

#define wifi_io_info_e(...) wmlog_e("wpkt", ##__VA_ARGS__)
#define wifi_io_info_w(...) wmlog_w("wpkt", ##__VA_ARGS__)

#ifdef CONFIG_WIFI_IO_INFO_DUMP
#define wifi_io_info_d(...) wmlog("wpkt", ##__VA_ARGS__)
#else
#define wifi_io_info_d(...)
#endif

#define WLAN_MAGIC_NUM (('W' << 0) | ('L' << 8) | ('F' << 16) | ('W' << 24))

#ifndef CONFIG_11AX
#ifndef CONFIG_11AC
/* fixme: sizeof(HostCmd_DS_COMMAND) is 1132 bytes. So have kept this at
   the current size.
*/
#define WIFI_FW_CMDBUF_SIZE 1400U
#else
/* In 802.11ac sizeof(HostCmd_CMD_CHANNEL_TRPC_CONFIG) is 1572 bytes.
 */
#define WIFI_FW_CMDBUF_SIZE 1580U
#endif /* CONFIG_11AC */
#else
/* In 802.11ax sizeof(HostCmd_CMD_CHANNEL_TRPC_CONFIG) is 1884 bytes.
 */
#define WIFI_FW_CMDBUF_SIZE 1890U
#endif /* CONFIG_11AX */

#define WIFI_RESP_WAIT_TIME 10

#define WLAN_VALUE1 0x80002080

/*! @brief Data block count accessed in card */
#define DATA_BLOCK_COUNT (4U)
/*! @brief Data buffer size. */
#define DATA_BUFFER_SIZE (512 * DATA_BLOCK_COUNT)

/** Card Control Registers : Function 1 Block size 0 */
#define FN1_BLOCK_SIZE_0 0x110
/** Card Control Registers : Function 1 Block size 1 */
#define FN1_BLOCK_SIZE_1 0x111

/* Duplicated in wlan.c. keep in sync till we can be included directly */
typedef struct __nvram_backup_struct
{
    t_u32 ioport;
    t_u32 curr_wr_port;
    t_u32 curr_rd_port;
    t_u32 mp_end_port;
    t_u32 bss_num;
    t_u32 sta_mac_addr1;
    t_u32 sta_mac_addr2;
    t_u32 wifi_state;
} nvram_backup_t;

extern os_thread_t wifi_core_thread;
extern bool g_txrx_flag;
#ifdef WLAN_LOW_POWER_ENABLE
extern bool low_power_mode;
#endif
extern bool cal_data_valid;
extern bool mac_addr_valid;
#ifdef CONFIG_WIFI_TX_BUFF
extern uint16_t tx_buf_size;
#endif
extern bool txpwrlimit_data_valid;
extern uint8_t trpc_country;

mlan_status imu_wifi_init(enum wlan_type type, const uint8_t *fw_ram_start_addr, const size_t size);
void imu_wifi_deinit(void);
void imu_uninstall_callback(void);

/*
 * @internal
 *
 *
 */
int wlan_send_imu_cmd(t_u8 *buf);

/*
 * @internal
 *
 *
 */
int wifi_send_cmdbuffer(void);

/*
 * @internal
 *
 *
 */
HostCmd_DS_COMMAND *wifi_get_command_buffer(void);

mlan_status wlan_xmit_pkt(t_u32 txlen, t_u8 interface);
int raw_process_pkt_hdrs(void *pbuf, t_u32 payloadlen, t_u8 interface);
uint32_t wifi_get_device_value1();

uint8_t *wifi_get_imu_outbuf(uint32_t *outbuf_len);

#ifdef CONFIG_WIFI_FW_DEBUG
extern void wifi_dump_firmware_info();
#endif /* CONFIG_WIFI_FW_DEBUG */

#ifdef CONFIG_WMM
mlan_status wlan_xmit_wmm_pkt(t_u8 interface, t_u32 txlen, t_u8 *tx_buf);
mlan_status wlan_flush_wmm_pkt(int pkt_cnt);
#ifdef AMSDU_IN_AMPDU
uint8_t *wifi_get_amsdu_outbuf(uint32_t offset);
mlan_status wlan_xmit_wmm_amsdu_pkt(mlan_wmm_ac_e ac, t_u8 interface, t_u32 txlen, t_u8 *tx_buf, t_u8 amsdu_cnt);
#endif
#endif

void imu_wakeup_card();
#ifdef CONFIG_WIFI_TX_BUFF
int _wlan_return_all_tx_buf(imu_link_t link);
#endif
void mlan_disable_hs_wakeup_irq();
#endif /* __WIFI_SDIO_H__ */
