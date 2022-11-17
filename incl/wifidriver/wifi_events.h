/*
 *  Copyright 2008-2020 NXP
 *
 *  Licensed under the LA_OPT_NXP_Software_License.txt (the "Agreement")
 *
 */

/*! \file wifi_events.h
 * \brief Wi-Fi events
 */

#ifndef __WIFI_EVENTS_H__
#define __WIFI_EVENTS_H__

/** Wifi events */
enum wifi_event
{
    /** uAP Started */
    WIFI_EVENT_UAP_STARTED = 0,
    /** uAP Client Assoc */
    WIFI_EVENT_UAP_CLIENT_ASSOC,
    /** uAP Client De-authentication */
    WIFI_EVENT_UAP_CLIENT_DEAUTH,
    /** uAP Network Address Configuration */
    WIFI_EVENT_UAP_NET_ADDR_CONFIG,
    /** uAP Stopped */
    WIFI_EVENT_UAP_STOPPED,
    /** uAP Last */
    WIFI_EVENT_UAP_LAST,
    /* All the uAP related events need to be above and STA related events
     * below */
    /** Scan Result */
    WIFI_EVENT_SCAN_RESULT,
    /** Get hardware spec */
    WIFI_EVENT_GET_HW_SPEC,
    /** Association */
    WIFI_EVENT_ASSOCIATION,
    /** PMK */
    WIFI_EVENT_PMK,
    /** Authentication */
    WIFI_EVENT_AUTHENTICATION,
    /** Disassociation */
    WIFI_EVENT_DISASSOCIATION,
    /** De-authentication */
    WIFI_EVENT_DEAUTHENTICATION,
    /** Link Loss */
    WIFI_EVENT_LINK_LOSS,
    /* WiFi RSSI Low Event */
    WIFI_EVENT_RSSI_LOW,
    /* WiFi RSSI High Event */
    WIFI_EVENT_RSSI_HIGH,
    /* WiFi SRN Low Event */
    WIFI_EVENT_SNR_LOW,
    /* WiFi SNR High Event */
    WIFI_EVENT_SNR_HIGH,
    /* WiFi Max Fail Event */
    WIFI_EVENT_MAX_FAIL,
    /* WiFi Beacon miised Event */
    WIFI_EVENT_BEACON_MISSED,
    /* WiFi Data RSSI Low Event */
    WIFI_EVENT_DATA_RSSI_LOW,
    /* WiFi Data RSSI High Event */
    WIFI_EVENT_DATA_RSSI_HIGH,
    /* WiFi Data SNR Low Event */
    WIFI_EVENT_DATA_SNR_LOW,
    /* WiFi Data SNR High Event */
    WIFI_EVENT_DATA_SNR_HIGH,
    /* WiFi Link Quality Event */
    WIFI_EVENT_FW_LINK_QUALITY,
    /* WiFi Pre Beacon Lost Event */
    WIFI_EVENT_FW_PRE_BCN_LOST,
    /** Network station address configuration */
    WIFI_EVENT_NET_STA_ADDR_CONFIG,
    /** Network interface configuration */
    WIFI_EVENT_NET_INTERFACE_CONFIG,
    /** WEP configuration */
    WIFI_EVENT_WEP_CONFIG,
    /** STA MAC address configuration */
    WIFI_EVENT_STA_MAC_ADDR_CONFIG,
    /** UAP MAC address configuration */
    WIFI_EVENT_UAP_MAC_ADDR_CONFIG,
    /** Network DHCP configuration */
    WIFI_EVENT_NET_DHCP_CONFIG,
    /** Supplicant PMK */
    WIFI_EVENT_SUPPLICANT_PMK,
    /** Sleep */
    WIFI_EVENT_SLEEP,
    /** Awake */
    WIFI_EVENT_AWAKE,
    /** IEEE PS */
    WIFI_EVENT_IEEE_PS,
    /** Deep Sleep */
    WIFI_EVENT_DEEP_SLEEP,
    /** WNM ps */
    WIFI_EVENT_WNM_PS,
    /** PS Invalid */
    WIFI_EVENT_PS_INVALID,
    /** HS configuration */
    WIFI_EVENT_HS_CONFIG,
    /** Error Multicast */
    WIFI_EVENT_ERR_MULTICAST,
    /** error Unicast */
    WIFI_EVENT_ERR_UNICAST,
    /** 802.11K/11V neighbor report */
    WIFI_EVENT_NLIST_REPORT,
    /* Add Block Ack */
    /** 802.11N add block ack */
    WIFI_EVENT_11N_ADDBA,
    /** 802.11N block Ack stream timeout */
    WIFI_EVENT_11N_BA_STREAM_TIMEOUT,
    /** 802.11n Delete block add */
    WIFI_EVENT_11N_DELBA,
    /** 802.11n aggregation control */
    WIFI_EVENT_11N_AGGR_CTRL,
    /** Channel Switch Announcement */
    WIFI_EVENT_CHAN_SWITCH_ANN,
    /** Channel Switch */
    WIFI_EVENT_CHAN_SWITCH,
#ifdef CONFIG_IPV6
    /** IPv6 address state change */
    WIFI_EVENT_NET_IPV6_CONFIG,
#endif
#ifdef CONFIG_WLAN_BRIDGE
    /** Auto link switch network */
    WIFI_EVENT_AUTOLINK_NETWORK_SWITCHED,
#endif
#ifdef CONFIG_WIFI_FW_DEBUG
    /* WiFi FW Debug Info */
    WIFI_EVENT_FW_DEBUG_INFO,
#endif
#ifdef CONFIG_ROAMING
    /* Background Scan Report */
    WIFI_EVENT_BG_SCAN_REPORT,
    /* Background Scan Stop */
    WIFI_EVENT_BG_SCAN_STOPPED,
#endif
    /* Event to indicate RX Management Frame */
    WIFI_EVENT_MGMT_FRAME,
#ifdef CONFIG_CSI
    /* Recv csi data */
    WIFI_EVENT_CSI,
#endif
    /** Event to indicate end of Wi-Fi events */
    WIFI_EVENT_LAST,
    /* other events can be added after this, however this must
       be the last event in the wifi module */
};

/** WiFi Event Reason */
enum wifi_event_reason
{
    /** Success */
    WIFI_EVENT_REASON_SUCCESS,
    /** Timeout */
    WIFI_EVENT_REASON_TIMEOUT,
    /** Failure */
    WIFI_EVENT_REASON_FAILURE,
};

/** Network wireless BSS Type */
enum wlan_bss_type
{
    /** Station */
    WLAN_BSS_TYPE_STA = 0,
    /** uAP */
    WLAN_BSS_TYPE_UAP = 1,
#ifdef CONFIG_P2P
    /** WiFi Direct */
    WLAN_BSS_TYPE_WIFIDIRECT = 2,
#endif
    /** Any */
    WLAN_BSS_TYPE_ANY = 0xff,
};

/** Network wireless BSS Role */
enum wlan_bss_role
{
    /** Infrastructure network. The system will act as a station connected
     *  to an Access Point. */
    WLAN_BSS_ROLE_STA = 0,
    /** uAP (micro-AP) network.  The system will act as an uAP node to
     * which other Wireless clients can connect. */
    WLAN_BSS_ROLE_UAP = 1,
    /** Either Infrastructure network or micro-AP network */
    WLAN_BSS_ROLE_ANY = 0xff,
};

/** This enum defines various wakeup events
 * for which wakeup will occur */
enum wifi_wakeup_event_t
{
    /** Wakeup on broadcast  */
    WIFI_WAKE_ON_ALL_BROADCAST = 1,
    /** Wakeup on unicast  */
    WIFI_WAKE_ON_UNICAST = 1 << 1,
    /** Wakeup on MAC event  */
    WIFI_WAKE_ON_MAC_EVENT = 1 << 2,
    /** Wakeup on multicast  */
    WIFI_WAKE_ON_MULTICAST = 1 << 3,
    /** Wakeup on ARP broadcast  */
    WIFI_WAKE_ON_ARP_BROADCAST = 1 << 4,
    /** Wakeup on receiving a management frame  */
    WIFI_WAKE_ON_MGMT_FRAME = 1 << 6,
};

#endif /*__WIFI_EVENTS_H__*/
