/*
 *  Copyright 2008-2023 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 *
 */

/*! \file wm_net_decl.h
 *  \brief Network Abstraction Declaration Layer
 *
 * This provides declarations related to the network layer.
 *
 *
 */

#ifndef _WM_NET_DECL_H_
#define _WM_NET_DECL_H_

#include <zephyr/kernel.h>
#include <zephyr/net/ethernet.h>
#include <zephyr/net/net_pkt.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/wifi_mgmt.h>

#define NETIF_NAMESIZE 6
#define NETIF_MAX_HWADDR_LEN 6

/* copy zephyr struct net if */
struct netif {
    /** The net_if_dev instance the net_if is related to */
	struct net_if_dev *if_dev;
#if defined(CONFIG_NET_STATISTICS_PER_INTERFACE)
	/** Network statistics related to this network interface */
	struct net_stats stats;
#endif /* CONFIG_NET_STATISTICS_PER_INTERFACE */

	/** Network interface instance configuration */
	struct net_if_config config;

#if defined(CONFIG_NET_POWER_MANAGEMENT)
	/** Keep track of packets pending in traffic queues. This is
	 * needed to avoid putting network device driver to sleep if
	 * there are packets waiting to be sent.
	 */
	int tx_pending;
#endif
};

/**
 * Helper struct to hold private data used to operate your ethernet interface.
 * Keeping the ethernet address of the MAC in this struct is not necessary
 * as it is already kept in the struct netif.
 * But this is only an example, anyway...
 */
struct ethernetif
{
    struct net_eth_addr ethaddr;
    /* Interface to bss type identification that tells the FW wherether
       the data is for STA for UAP */
    uint8_t interface;
    /* Add whatever per-interface state that is needed here. */
};

/** Address types to be used by the element net_ip_config.addr_type below
 */
enum net_address_types
{
    /** static IP address */
    NET_ADDR_TYPE_STATIC = 0,
    /** Dynamic  IP address*/
    NET_ADDR_TYPE_DHCP = 1,
    /** Link level address */
    NET_ADDR_TYPE_LLA = 2,
};

/** This data structure represents an IPv4 address */
struct net_ipv4_config
{
    /** Set to \ref ADDR_TYPE_DHCP to use DHCP to obtain the IP address or
     *  \ref ADDR_TYPE_STATIC to use a static IP. In case of static IP
     *  address ip, gw, netmask and dns members must be specified.  When
     *  using DHCP, the ip, gw, netmask and dns are overwritten by the
     *  values obtained from the DHCP server. They should be zeroed out if
     *  not used. */
    enum net_address_types addr_type;
    /** The system's IP address in network order. */
    unsigned address;
    /** The system's default gateway in network order. */
    unsigned gw;
    /** The system's subnet mask in network order. */
    unsigned netmask;
    /** The system's primary dns server in network order. */
    unsigned dns1;
    /** The system's secondary dns server in network order. */
    unsigned dns2;
};

#ifdef CONFIG_IPV6
/** This data structure represents an IPv6 address */
struct net_ipv6_config
{
    /** The system's IPv6 address in network order. */
    unsigned address[4];
    /** The address type: linklocal, site-local or global. */
    unsigned char addr_type;
    /** The state of IPv6 address (Tentative, Preferred, etc). */
    unsigned char addr_state;
};
#endif

/** Network IP configuration.
 *
 *  This data structure represents the network IP configuration
 *  for IPv4 as well as IPv6 addresses
 */
struct net_ip_config
{
#ifdef CONFIG_IPV6
    /** The network IPv6 address configuration that should be
     * associated with this interface. */
    struct net_ipv6_config ipv6[NET_IF_MAX_IPV6_ADDR];
    /** The network IPv6 valid addresses count */
    size_t ipv6_count;
#endif
    /** The network IPv4 address configuration that should be
     * associated with this interface. */
    struct net_ipv4_config ipv4;
};

#endif /* _WM_NET_DECL_H_ */
