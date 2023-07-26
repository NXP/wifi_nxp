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

#endif /* _WM_NET_DECL_H_ */