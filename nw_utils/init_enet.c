/*
 * Copyright (c) 2016, Freescale Semiconductor, Inc.
 * Copyright 2016-2022 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef RW610
/*******************************************************************************
 * Includes
 ******************************************************************************/
/*${header:start}*/
#include "lwip/dhcp.h"
#include "lwip/ip_addr.h"
#include "lwip/netifapi.h"
#include "lwip/prot/dhcp.h"
#include "lwip/tcpip.h"
#include "lwip/sys.h"
#include "ethernetif.h"

#include "fsl_adapter_gpio.h"

#include "board.h"
#include "app.h"

#include "ethernetif.h"
#include <string.h>
#include <wm_os.h>
#include <wm_net.h>

#include "network_cfg.h"
#include "telnet_server.h"

#include "fsl_silicon_id.h"
#include "fsl_phy.h"
#include <cli.h>

/*${header:end}*/

/*******************************************************************************
 * Definitions
 ******************************************************************************/
/*${macro:start}*/
#ifndef EXAMPLE_NETIF_INIT_FN
/*! @brief Network interface initialization function. */
#define EXAMPLE_NETIF_INIT_FN ethernetif0_init
#endif /* EXAMPLE_NETIF_INIT_FN */
/*${macro:end}*/

/*******************************************************************************
 * Prototypes
 ******************************************************************************/
/*${prototype:start}*/
/*${prototype:end}*/

/*******************************************************************************
 * Variables
 ******************************************************************************/
/*${variable:start}*/
static phy_handle_t phyHandle;
static struct netif netif;

/*${variable:end}*/

/*******************************************************************************
 * Code
 ******************************************************************************/
/*${function:start}*/

void cmd_enet_info(int argc, char **argv)
{
    (void)PRINTF("\"%c%c%d\" : ", netif.name[0], netif.name[1], netif.num);
    if (netif_is_link_up(&netif) && netif_is_up(&netif))
    {
        (void)PRINTF("Connected\r\n");
        (void)PRINTF("\r\n\tIPv4 Address\r\n");
#ifdef IP_USE_DHCP
        (void)PRINTF("\taddress: DHCP");
#else
        (void)PRINTF("\taddress: Static");
#endif
        (void)PRINTF("\r\n\t\tIP:\t\t%s", ipaddr_ntoa(&netif.ip_addr));
        (void)PRINTF("\r\n\t\tgateway:\t%s", ipaddr_ntoa(&netif.gw));
        (void)PRINTF("\r\n\t\tnetmask:\t%s", ipaddr_ntoa(&netif.netmask));
        (void)PRINTF("\r\n");
#ifdef CONFIG_IPV6
        int i;
        char buf[128];
        // char *str;

        (void)PRINTF("\r\n\tIPv6 Addresses\r\n");
        for (i = 0; i < CONFIG_MAX_IPV6_ADDRESSES; i++)
        {
            if (ip6_addr_isvalid(netif_ip6_addr_state(&netif, i)))
            {
                memset(buf, 0x00, 128);

                // str = ip6addr_ntoa_r(ip_2_ip6(&netif.ip6_addr), buf, sizeof(buf));
                //(void)PRINTF("\t\t%s \r\n", str);
            }
        }
        (void)PRINTF("\r\n");
#endif
    }
    else
    {
        (void)PRINTF("Disconnected\r\n");
    }
}

static struct cli_command enet_cli[] = {
    {"enet-info", NULL, cmd_enet_info},
};

static int enet_cli_init(void)
{
    unsigned int i;
    for (i = 0; i < sizeof(enet_cli) / sizeof(struct cli_command); i++)
    {
        if (cli_register_command(&enet_cli[i]) != 0)
        {
            return -WM_FAIL;
        }
    }
    return WM_SUCCESS;
}

int initNetwork(void)
{
    ip4_addr_t netif_ipaddr, netif_netmask, netif_gw;
    ethernetif_config_t enet_config = {
        .phyHandle   = &phyHandle,
        .phyAddr     = EXAMPLE_PHY_ADDRESS,
        .phyOps      = EXAMPLE_PHY_OPS,
        .phyResource = EXAMPLE_PHY_RESOURCE,
        .srcClockHz  = EXAMPLE_CLOCK_FREQ,
#ifdef configMAC_ADDR
        .macAddress = configMAC_ADDR,
#endif
    };
    int ret = 0, retry = 0;

#ifdef IP_USE_DHCP
#ifndef configMAC_ADDR
    /* Set special address for each chip. */
    (void)SILICONID_ConvertToMacAddr(&enet_config.macAddress);
#endif

    IP4_ADDR(&netif_ipaddr, 0, 0, 0, 0);
    IP4_ADDR(&netif_netmask, 0, 0, 0, 0);
    IP4_ADDR(&netif_gw, 0, 0, 0, 0);
#else
    ip4addr_aton(IP_ADDR, &netif_ipaddr);
    ip4addr_aton(IP_MASK, &netif_netmask);
    ip4addr_aton(GW_ADDR, &netif_gw);
#endif

    netifapi_netif_add(&netif, &netif_ipaddr, &netif_netmask, &netif_gw, &enet_config, EXAMPLE_NETIF_INIT_FN,
                       tcpip_input);
    netifapi_netif_set_default(&netif);
    netifapi_netif_set_up(&netif);

    while ((ret = ethernetif_wait_linkup(&netif, 5000)) != ERR_OK)
    {
        PRINTF("PHY Auto-negotiation failed. Please check the cable connection and link partner setting.\r\n");
        if (retry == 5)
        {
            break;
        }
        retry++;
    }

    if (ret == ERR_OK)
    {
#ifdef IP_USE_DHCP
        PRINTF("Obtaining IP address from DHCP...\r\n");
        netifapi_dhcp_start(&netif);

        struct dhcp *dhcp;
        dhcp = netif_dhcp_data(&netif);

        while (dhcp->state != DHCP_STATE_BOUND)
        {
            vTaskDelay(100);
        }
#endif
        (void)ethernetif_wait_ipv4_valid(&netif, ETHERNETIF_WAIT_FOREVER);
        PRINTF("IPv4 Address: %s\r\n", ipaddr_ntoa(&netif.ip_addr));
        PRINTF("DHCP OK\r\n");

        enet_cli_init();

        // Initialize a socket Telnet server
        sys_thread_new("LwIP Telnet Server", SocketTelnetServer, NULL, 2048, 1);
    }
    return WM_SUCCESS;
}
/*${function:end}*/
#endif
