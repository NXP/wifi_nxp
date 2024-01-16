/* @file ncp_bridge_glue.h
 *
 *  @brief This file contains ncp bridge API functions definitions
 *
 *  Copyright 2008-2023 NXP
 *
 *  Licensed under the LA_OPT_NXP_Software_License.txt (the "Agreement")
 */

#ifndef __NCP_BRIDGE_GLUE_H__
#define __NCP_BRIDGE_GLUE_H__

#include <wmlog.h>

#include "ncp_bridge_cmd.h"
#include "mdns_service.h"

#define ncp_e(...) wmlog_e("NCP", ##__VA_ARGS__)
#define ncp_w(...) wmlog_w("NCP", ##__VA_ARGS__)

#ifdef CONFIG_NCP_BRIDGE_DEBUG
#define ncp_d(...) wmlog("NCP", ##__VA_ARGS__)
#else
#define ncp_d(...)
#endif

#define MDNS_PROTO_UDP "_udp"
#define MDNS_PROTO_TCP "_tcp"

#define MDNS_RRTYPE_A   "A"
#define MDNS_RRTYPE_PTR "PTR"

/* Names for the values of the `async' field of `struct cmd_t'.  */
#define CMD_SYNC  0
#define CMD_ASYNC 1

#define NCP_HASH_TABLE_SIZE  64
#define NCP_HASH_INVALID_KEY (uint8_t)(-1)

struct cmd_t
{
    uint32_t cmd;
    const char *help;
    int (*handler)(void *tlv);
    /* The field `async' is:
     *   CMD_SYNC     (or 0) if the command is executed synchronously,
     *   CMD_ASYNC    (or 1) if the command is executed asynchronously,
     */
    bool async;
};

struct cmd_subclass_t
{
    uint32_t cmd_subclass;
    struct cmd_t *cmd;
    /* Mapping of subclass list */
    uint8_t hash[NCP_HASH_TABLE_SIZE];
};

struct cmd_class_t
{
    uint32_t cmd_class;
    struct cmd_subclass_t *cmd_subclass;
    /* Length of subclass list */
    uint16_t subclass_len;
    /* Mapping of cmd list */
    uint8_t hash[NCP_HASH_TABLE_SIZE];
};

int wlan_bridge_prepare_status(uint32_t cmd, uint16_t result);

uint8_t *wlan_bridge_evt_status(uint32_t evt_id, void *msg);

int wlan_bridge_prepare_scan_result(NCP_CMD_SCAN_NETWORK_INFO *scan_res);

int wlan_bridge_prepare_connect_result(NCP_CMD_WLAN_CONN *conn_res);

int wlan_bridge_prepare_start_network_result(NCP_CMD_NETWORK_START *start_res);

int wlan_bridge_prepare_mac_address(void *mac_addr, uint8_t bss_type);

int wlan_bridge_prepare_mdns_result(mdns_result_ring_buffer_t *mdns_res);

uint8_t *wlan_bridge_prepare_mdns_resolve_result(ip_addr_t *ipaddr);

NCPCmd_DS_COMMAND *ncp_bridge_get_response_buffer();

int ncp_bridge_mdns_init(void);

int ncp_cmd_list_init(void);
int ncp_register_class(struct cmd_class_t *cmd_class);
struct cmd_t *lookup_class(uint32_t cmd_class, uint32_t cmd_subclass, uint32_t cmd_id);

void bridge_PostPowerSwitch(uint32_t mode, void *param);

#ifdef CONFIG_NCP_BRIDGE_DEBUG
void print_ncp_debug_time(void);
void add_ncp_debug_time_item(const char *func);
#endif

#ifdef CONFIG_SCHED_SWITCH_TRACE
extern int ncp_debug_task_switch_start;
void trace_task_switch(int in, const char *func_name);
void trace_task_switch_print();
#endif

#ifdef CONFIG_NCP_SOCKET_SEND_FIFO
#define SOCKET_SEND_COMMAND_NUM 64
/* app notify event queue message */
typedef struct
{
    uint32_t send_type;
    void *data;
} socket_send_msg_t;
#endif
#endif /* __NCP_BRIDGE_GLUE_H__ */
