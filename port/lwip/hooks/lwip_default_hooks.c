/** @file lwip_default_hook.c
 *
 *  @brief  This file provides lwip porting code
 *
 *  Copyright 2008-2022 NXP
 *
 *  Licensed under the LA_OPT_NXP_Software_License.txt (the "Agreement")
 *
 */
#include "lwip/tcpip.h"

struct netif* lwip_hook_ip4_route_src(const ip4_addr_t *src, const ip4_addr_t *dest)
{
	struct netif *netif = NULL;

	if (src == NULL)
	{
	    return NULL;
	}
	
    /* iterate through netifs */
    NETIF_FOREACH(netif)
    {
        /* is the netif up, does it have a link and a valid address? */ 
        if (netif_is_up(netif) && netif_is_link_up(netif) && !ip4_addr_isany_val(*netif_ip4_addr(netif)))
        {
            /*netif ip4 address matches bind_address*/
            if(ip4_addr_eq(src, netif_ip4_addr(netif)))
            {
                return netif;
            }
        }
    }

	return NULL;
}