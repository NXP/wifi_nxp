/** @file wifi-debug.h
 *
 *  @brief WLAN Debug Header
 *
 *  Copyright 2008-2021 NXP
 *
 *  Licensed under the LA_OPT_NXP_Software_License.txt (the "Agreement")
 *
 */

#ifndef __WIFI_DEBUG_H__
#define __WIFI_DEBUG_H__

#include <mlan_api.h>
#include <wmlog.h>

#define wscan_e(...) wmlog_e("wscan", ##__VA_ARGS__)
#define wscan_w(...) wmlog_w("wscan", ##__VA_ARGS__)
#ifdef CONFIG_WIFI_SCAN_DEBUG
#define wscan_d(...) wmlog("wscan", ##__VA_ARGS__)
#else
#define wscan_d(...)
#endif /* ! CONFIG_WIFI_SCAN_DEBUG */

#define wifi_e(...) wmlog_e("wifi", ##__VA_ARGS__)
#define wifi_w(...) wmlog_w("wifi", ##__VA_ARGS__)

#ifdef CONFIG_WIFI_FW_DEBUG
#define wifi_d(...) wmlog("wifi", ##__VA_ARGS__)
#else
#define wifi_d(...)
#endif /* ! CONFIG_WIFI_DEBUG */

#define ampdu_e(...) wmlog_e("ampdu", ##__VA_ARGS__)
#define ampdu_w(...) wmlog_w("ampdu", ##__VA_ARGS__)

#ifdef CONFIG_WIFI_AMPDU_DEBUG
#define ampdu_d(...) wmlog("ampdu", ##__VA_ARGS__)
#else
#define ampdu_d(...)
#endif /* ! CONFIG_WIFI_AMPDU_DEBUG */

#define w_tmr_e(...) wmlog_e("w_tmr", ##__VA_ARGS__)
#define w_tmr_w(...) wmlog_w("w_tmr", ##__VA_ARGS__)

#ifdef CONFIG_WIFI_TIMER_DEBUG
#define w_tmr_d(...) wmlog("w_tmr", ##__VA_ARGS__)
#else
#define w_tmr_d(...)
#endif /* CONFIG_WIFI_TIMER_DEBUG */

#define w_mem_e(...) wmlog_e("w_mem", ##__VA_ARGS__)
#define w_mem_w(...) wmlog_w("w_mem", ##__VA_ARGS__)

#ifdef CONFIG_WIFI_MEM_DEBUG
#define w_mem_d(...) wmlog("w_mem", ##__VA_ARGS__)
#else
#define w_mem_d(...)
#endif /* ! CONFIG_WIFI_MEM_DEBUG */

#define w_pkt_e(...) wmlog_e("w_pkt", ##__VA_ARGS__)
#define w_pkt_w(...) wmlog_w("w_pkt", ##__VA_ARGS__)

#ifdef CONFIG_WIFI_PKT_DEBUG
#define w_pkt_d(...) wmlog("w_pkt", ##__VA_ARGS__)
#else
#define w_pkt_d(...)
#endif /* ! CONFIG_WIFI_PKT_DEBUG */

#define wevt_e(...) wmlog_e("wevt", ##__VA_ARGS__)
#define wevt_w(...) wmlog_w("wevt", ##__VA_ARGS__)

#ifdef CONFIG_WIFI_EVENTS_DEBUG
#define wevt_d(...) wmlog("wevt", ##__VA_ARGS__)
#else
#define wevt_d(...)
#endif /* ! CONFIG_WIFI_EVENTS_DEBUG */

#define wcmdr_e(...) wmlog_e("wcmdr", ##__VA_ARGS__)
#define wcmdr_w(...) wmlog_w("wcmdr", ##__VA_ARGS__)

#ifdef CONFIG_WIFI_CMD_RESP_DEBUG
#define wcmdr_d(...) wmlog("wcmdr", ##__VA_ARGS__)
#else
#define wcmdr_d(...)
#endif /* ! CONFIG_WIFI_CMD_RESP_DEBUG */

#define wuap_e(...) wmlog_e("uap", ##__VA_ARGS__)
#define wuap_w(...) wmlog_w("uap", ##__VA_ARGS__)

#ifdef CONFIG_WIFI_UAP_DEBUG
#define wuap_d(...) wmlog("uap", ##__VA_ARGS__)
#else
#define wuap_d(...)
#endif /* ! CONFIG_WIFI_UAP_DEBUG */

void wifi_show_assoc_fail_reason(int status);

void dump_mac_addr(const char *msg, unsigned char *addr);
#ifdef DEBUG_11N_AGGR
void dump_packet_header(const HostCmd_DS_COMMAND *cmd);
void dump_addba_req_rsp_packet(const HostCmd_DS_COMMAND *cmd);
#endif
void dump_htcap_info(const MrvlIETypes_HTCap_t *htcap);
void dump_ht_info(const MrvlIETypes_HTInfo_t *htinfo);
#endif /* __WIFI_DEBUG_H__ */
