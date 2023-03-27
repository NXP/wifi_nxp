/** @file lwip_default_hooks.h
 *
 *  @brief This file provides lwip porting code
 *
 *  Copyright 2008-2022 NXP
 *
 *  Licensed under the LA_OPT_NXP_Software_License.txt (the "Agreement")
 */
#ifndef _LWIP_DEFAULT_HOOKS_H_
#define _LWIP_DEFAULT_HOOKS_H_
#ifdef CONFIG_CLOUD_KEEP_ALIVE
#include "lwip/priv/tcp_priv.h"
#include "lwip/tcp.h"
#include "lwip/pbuf.h"
#endif

struct netif *lwip_hook_ip4_route_src(const ip4_addr_t *src, const ip4_addr_t *dest);

#ifdef CONFIG_CLOUD_KEEP_ALIVE
u32_t *lwip_hook_tcp_out_add_tcpopts(struct pbuf *p, struct tcp_hdr *hdr, const struct tcp_pcb *pcb, u32_t *opts);
#endif

#endif
