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

struct netif* lwip_hook_ip4_route_src(const ip4_addr_t *src, const ip4_addr_t *dest);

#endif