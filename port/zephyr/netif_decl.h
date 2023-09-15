/*
 *  Copyright 2008-2022 NXP
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

#include <mlan_api.h>
#include <wmlog.h>
#ifdef RW610
#include <wifi-imu.h>
#else
#include <wifi-sdio.h>
#endif
#include <wifi-internal.h>


/*------------------------------------------------------*/
/*
 * Packets of this type need o be handled
 * for WPS and Supplicant
 */
#define ETHTYPE_EAPOL 0x888EU /* EAPOL */


#define SIZEOF_ETH_LLC_HDR (8U)

/* Define those to better describe your network interface. */
#define IFNAME0 'm'
#define IFNAME1 'l'

/*
 * It was observed that Wi-Fi card does not wakeup
 * immediately after call to wlan_wakeup_card.
 * The code tries to wakeup the card by writing
 * in SDIO register.
 * It waits for 20 ms for AWAKE event from Wi-Fi card,
 * if AWAKE event is not generated or received  by MCU code
 * it returns error and does not send a packet out.
 * This is observed with  8801 Wi-Fi card.
 * So for 8801 based platforms the wait time is now 35 ms.
 */

#ifdef CONFIG_WiFi_878x
#define MAX_WAIT_TIME 20
#else
#define MAX_WAIT_TIME 35
#endif
#define MAX_INTERFACES_SUPPORTED 3U

/* The time to block waiting for input. */
#define emacBLOCK_TIME_WAITING_FOR_INPUT ((portTickType)100)
/*------------------------------------------------------*/
extern int wlan_get_mac_address(uint8_t *dest);
extern void wlan_wake_up_card(void);

#ifdef CONFIG_P2P
mlan_status wlan_send_gen_sdio_cmd(uint8_t *buf, uint32_t buflen);
#endif
#ifdef CONFIG_P2P
extern int wlan_get_wfd_mac_address(t_u8 *);
extern int wfd_bss_type;
#endif

#ifdef CONFIG_WPS2
void (*wps_rx_callback)(const t_u8 *buf, size_t len);
#endif

#ifdef CONFIG_WPA_SUPP
void (*l2_packet_rx_callback)(const struct pbuf *p);
#endif /* CONFIG_HOST_SUPP */

void wrapper_wlan_update_uap_rxrate_info(RxPD *rxpd);

int wrapper_wlan_handle_rx_packet(t_u16 datalen, RxPD *rxpd, void *p, void *payload);

int wrapper_wlan_handle_amsdu_rx_packet(const t_u8 *rcvdata, const t_u16 datalen);

#ifdef CONFIG_NET_MONITOR
void user_recv_monitor_data(const t_u8 *rcvdata);
#endif

/**
 * Helper struct to hold private data used to operate your ethernet interface.
 * Keeping the ethernet address of the MAC in this struct is not necessary
 * as it is already kept in the struct netif.
 * But this is only an example, anyway...
 */
struct ethernetif
{
    struct eth_addr *ethaddr;
    /* Interface to bss type identification that tells the FW wherether
       the data is for STA for UAP */
    t_u8 interface;
    /* Add whatever per-interface state that is needed here. */
};

/* This is an Token-Ring LLC structure */
struct eth_llc_hdr
{
    t_u8 dsap;      /* destination SAP */
    t_u8 ssap;      /* source SAP */
    t_u8 llc;       /* LLC control field */
    t_u8 protid[3]; /* protocol id */
    t_u16 type;     /* ether type field */
} __packed;


#define SIZEOF_ETH_LLC_HDR (8U)
#define SIZEOF_ETH_HDR (14U)
/*
 * Packets of this type need o be handled
 * for WPS and Supplicant
 */
#define ETHTYPE_EAPOL 0x888EU /* EAPOL */
