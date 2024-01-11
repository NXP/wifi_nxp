/**@file ncp_mcu_host_command.h
 *
 *  Copyright 2008-2023 NXP
 *
 *  Licensed under the LA_OPT_NXP_Software_License.txt (the "Agreement")
 *
 */

#ifndef __NCP_MCU_HOST_COMMAND_H_
#define __NCP_MCU_HOST_COMMAND_H_

#ifdef __GNUC__
/** Structure packing begins */
#define MLAN_PACK_START
/** Structure packeing end */
#define MLAN_PACK_END __attribute__((packed))
#else /* !__GNUC__ */
#ifdef PRAGMA_PACK
/** Structure packing begins */
#define MLAN_PACK_START
/** Structure packeing end */
#define MLAN_PACK_END
#else /* !PRAGMA_PACK */
/** Structure packing begins */
#define MLAN_PACK_START __packed
/** Structure packing end */
#define MLAN_PACK_END
#endif /* PRAGMA_PACK */
#endif /* __GNUC__ */

/*Define macros which are used in ncp_bridge_cmd.h but not defined in mcu project.*/
#define MLAN_MAX_VER_STR_LEN         128
#define MLAN_MAC_ADDR_LENGTH         6
#define WLAN_NETWORK_NAME_MAX_LENGTH 32
#define IEEEtypes_SSID_SIZE          32
#define IDENTITY_MAX_LENGTH          64
#define MAX_NUM_CLIENTS              16
#define MAX_MONIT_MAC_FILTER_NUM     3
#define IEEEtypes_ADDRESS_SIZE       6
#define CSI_FILTER_MAX               16

/*Structures which are used by ncp_bridge_cmd.h but not defined in mcu project.*/
/** Station information structure */
typedef struct
{
    /** MAC address buffer */
    uint8_t mac[MLAN_MAC_ADDR_LENGTH];
    /**
     * Power management status
     * 0 = active (not in power save)
     * 1 = in power save status
     */
    uint8_t power_mgmt_status;
    /** RSSI: dBm */
    char rssi;
} wifi_sta_info_t;

typedef MLAN_PACK_START struct _wifi_csi_filter_t
{
    /** Source address of the packet to receive */
    uint8_t mac_addr[MLAN_MAC_ADDR_LENGTH];
    /** Pakcet type of the interested CSI */
    uint8_t pkt_type;
    /** Packet subtype of the interested CSI */
    uint8_t subtype;
    /** Other filter flags */
    uint8_t flags;
} MLAN_PACK_END wifi_csi_filter_t;
typedef MLAN_PACK_START struct _wifi_csi_config_params_t
{
    /** CSI enable flag. 1: enable, 2: disable */
    uint16_t csi_enable;
    /** Header ID*/
    uint32_t head_id;
    /** Tail ID */
    uint32_t tail_id;
    /** Number of CSI filters */
    uint8_t csi_filter_cnt;
    /** Chip ID */
    uint8_t chip_id;
    /** band config */
    uint8_t band_config;
    /** Channel num */
    uint8_t channel;
    /** Enable getting CSI data on special channel */
    uint8_t csi_monitor_enable;
    /** CSI data received in cfg channel with mac addr filter, not only RA is us or other*/
    uint8_t ra4us;
    /** CSI filters */
    wifi_csi_filter_t csi_filter[CSI_FILTER_MAX];
} MLAN_PACK_END wifi_csi_config_params_t;

typedef wifi_csi_config_params_t wlan_csi_config_params_t;

#include "ncp_bridge_cmd.h"

/*mcu macros*/
#define MAC2STR(a)              a[0], a[1], a[2], a[3], a[4], a[5]
#define NCP_HOST_IP_LENGTH      4
#define NCP_HOST_IP_VALID       255
#define NCP_HOST_MAX_AP_ENTRIES 30

/*NCP MCU Bridge CMD response state*/
/*MCU device enter low power mode*/
#define NCP_BRIDGE_CMD_RESULT_ENTER_SLEEP 0x0006
/*MCU device exit low power mode*/
#define NCP_BRIDGE_CMD_RESULT_EXIT_SLEEP 0x0007

#define ACTION_GET 0
#define ACTION_SET 1

#define NCP_WLAN_MAC_ADDR_LENGTH 6
#define MAX_MONIT_MAC_FILTER_NUM 3
enum wlan_monitor_opt
{
    MONITOR_FILTER_OPT_ADD_MAC = 0,
    MONITOR_FILTER_OPT_DELETE_MAC,
    MONITOR_FILTER_OPT_CLEAR_MAC,
    MONITOR_FILTER_OPT_DUMP,
};

enum wlan_csi_opt
{
    CSI_FILTER_OPT_ADD = 0,
    CSI_FILTER_OPT_DELETE,
    CSI_FILTER_OPT_CLEAR,
    CSI_FILTER_OPT_DUMP,
};

/** The space reserved for storing network names */
#define WLAN_NETWORK_NAME_MAX_LENGTH 32

#define WLAN_SSID_MAX_LENGTH 32

/** The operation could not be performed in the current system state. */
#define WLAN_ERROR_STATE 3

#define DNS_RRTYPE_A   1  /* a host address */
#define DNS_RRTYPE_PTR 12 /* a domain name pointer */

enum mdns_sd_proto
{
    DNSSD_PROTO_UDP = 0,
    DNSSD_PROTO_TCP = 1
};

#define MDNS_ADDRTYPE_IPV4 0
#define MDNS_ADDRTYPE_IPV6 1

typedef MLAN_PACK_START struct _BRIDGE_COMMAND
{
    /*bit0 ~ bit15 cmd id  bit16 ~ bit23 cmd subclass bit24 ~ bit31 cmd class*/
    uint32_t cmd;
    uint16_t size;
    uint16_t seqnum;
    uint16_t result;
    uint16_t msg_type;
} MLAN_PACK_END NCP_HOST_COMMAND, NCP_HOST_RESPONSE;

enum wlan_mef_type
{
    MEF_TYPE_DELETE = 0,
    MEF_TYPE_PING,
    MEF_TYPE_ARP,
    MEF_TYPE_MULTICAST,
    MEF_TYPE_IPV6_NS,
    MEF_TYPE_END,
};

#define MCU_DEVICE_STATUS_ACTIVE 1
#define MCU_DEVICE_STATUS_SLEEP  2

#ifdef CONFIG_NCP_WIFI_DTIM_PERIOD
#define WIFI_SUPPORT_11AX   (1 << 3)
#define WIFI_SUPPORT_11AC   (1 << 2)
#define WIFI_SUPPORT_11N    (1 << 1)
#define WIFI_SUPPORT_LEGACY (1 << 0)
#endif

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

enum wlan_security_type
{
    /** The network does not use security. */
    WLAN_SECURITY_NONE,
    /** The network uses WEP security with open key. */
    WLAN_SECURITY_WEP_OPEN,
    /** The network uses WEP security with shared key. */
    WLAN_SECURITY_WEP_SHARED,
    /** The network uses WPA security with PSK. */
    WLAN_SECURITY_WPA,
    /** The network uses WPA2 security with PSK. */
    WLAN_SECURITY_WPA2,
    /** The network uses WPA/WPA2 mixed security with PSK */
    WLAN_SECURITY_WPA_WPA2_MIXED,
#ifdef CONFIG_NCP_11R
    /** The network uses WPA2 security with PSK FT. */
    WLAN_SECURITY_WPA2_FT,
#endif
    /** The network uses WPA3 security with SAE. */
    WLAN_SECURITY_WPA3_SAE,
#ifdef CONFIG_NCP_WPA_SUPP
#ifdef CONFIG_NCP_11R
    /** The network uses WPA3 security with SAE FT. */
    WLAN_SECURITY_WPA3_FT_SAE,
#endif
#endif
    /** The network uses WPA2/WPA3 SAE mixed security with PSK. This security mode
     * is specific to uAP or SoftAP only */
    WLAN_SECURITY_WPA2_WPA3_SAE_MIXED,
#ifdef CONFIG_NCP_OWE
    /** The network uses OWE only security without Transition mode support. */
    WLAN_SECURITY_OWE_ONLY,
#endif
#if defined(CONFIG_NCP_WPA_SUPP_CRYPTO_ENTERPRISE) || defined(CONFIG_NCP_WPA2_ENTP)
    /** The network uses WPA2 Enterprise EAP-TLS security
     * The identity field in \ref wlan_network structure is used */
    WLAN_SECURITY_EAP_TLS,
#endif
#ifdef CONFIG_NCP_WPA_SUPP_CRYPTO_ENTERPRISE
#ifdef CONFIG_NCP_EAP_TLS
    /** The network uses WPA2 Enterprise EAP-TLS SHA256 security
     * The identity field in \ref wlan_network structure is used */
    WLAN_SECURITY_EAP_TLS_SHA256,
#ifdef CONFIG_NCP_11R
    /** The network uses WPA2 Enterprise EAP-TLS FT security
     * The identity field in \ref wlan_network structure is used */
    WLAN_SECURITY_EAP_TLS_FT,
    /** The network uses WPA2 Enterprise EAP-TLS FT SHA384 security
     * The identity field in \ref wlan_network structure is used */
    WLAN_SECURITY_EAP_TLS_FT_SHA384,
#endif
#endif
#ifdef CONFIG_NCP_EAP_TTLS
    /** The network uses WPA2 Enterprise EAP-TTLS security
     * The identity field in \ref wlan_network structure is used */
    WLAN_SECURITY_EAP_TTLS,
#ifdef CONFIG_NCP_EAP_MSCHAPV2
    /** The network uses WPA2 Enterprise EAP-TTLS-MSCHAPV2 security
     * The anonymous identity, identity and password fields in
     * \ref wlan_network structure are used */
    WLAN_SECURITY_EAP_TTLS_MSCHAPV2,
#endif
#endif
#endif
#if defined(CONFIG_NCP_WPA_SUPP_CRYPTO_ENTERPRISE) || defined(CONFIG_NCP_PEAP_MSCHAPV2) || defined(CONFIG_NCP_WPA2_ENTP)
    /** The network uses WPA2 Enterprise EAP-PEAP-MSCHAPV2 security
     * The anonymous identity, identity and password fields in
     * \ref wlan_network structure are used */
    WLAN_SECURITY_EAP_PEAP_MSCHAPV2,
#endif
#ifdef CONFIG_NCP_WPA_SUPP_CRYPTO_ENTERPRISE
#ifdef CONFIG_NCP_EAP_PEAP
#ifdef CONFIG_NCP_EAP_TLS
    /** The network uses WPA2 Enterprise EAP-PEAP-TLS security
     * The anonymous identity, identity and password fields in
     * \ref wlan_network structure are used */
    WLAN_SECURITY_EAP_PEAP_TLS,
#endif
#ifdef CONFIG_NCP_EAP_GTC
    /** The network uses WPA2 Enterprise EAP-PEAP-GTC security
     * The anonymous identity, identity and password fields in
     * \ref wlan_network structure are used */
    WLAN_SECURITY_EAP_PEAP_GTC,
#endif
#endif
#ifdef CONFIG_NCP_EAP_FAST
#ifdef CONFIG_NCP_EAP_MSCHAPV2
    /** The network uses WPA2 Enterprise EAP-FAST-MSCHAPV2 security
     * The anonymous identity, identity and password fields in
     * \ref wlan_network structure are used */
    WLAN_SECURITY_EAP_FAST_MSCHAPV2,
#endif
#ifdef CONFIG_NCP_EAP_GTC
    /** The network uses WPA2 Enterprise EAP-FAST-GTC security
     * The anonymous identity, identity and password fields in
     * \ref wlan_network structure are used */
    WLAN_SECURITY_EAP_FAST_GTC,
#endif
#endif
#ifdef CONFIG_NCP_EAP_SIM
    /** The network uses WPA2 Enterprise EAP-SIM security
     * The identity and password fields in
     * \ref wlan_network structure are used */
    WLAN_SECURITY_EAP_SIM,
#endif
#ifdef CONFIG_NCP_EAP_AKA
    /** The network uses WPA2 Enterprise EAP-AKA security
     * The identity and password fields in
     * \ref wlan_network structure are used */
    WLAN_SECURITY_EAP_AKA,
#endif
#ifdef CONFIG_NCP_EAP_AKA_PRIME
    /** The network uses WPA2 Enterprise EAP-AKA-PRIME security
     * The identity and password fields in
     * \ref wlan_network structure are used */
    WLAN_SECURITY_EAP_AKA_PRIME,
#endif
#endif
#ifdef CONFIG_NCP_WPA_SUPP_DPP
    /** The network uses DPP security with NAK(Net Access Key) */
    WLAN_SECURITY_DPP,
#endif
    /** The network can use any security method. This is often used when
     * the user only knows the name and passphrase but not the security
     * type.  */
    WLAN_SECURITY_WILDCARD,
};

enum
{
    /** static IP address */
    ADDR_TYPE_STATIC = 0,
    /** Dynamic  IP address*/
    ADDR_TYPE_DHCP = 1,
    /** Link level address */
    ADDR_TYPE_LLA = 2,
};

/*NCP Bridge BSSID tlv*/

#define NCP_WLAN_DEFAULT_RSSI_THRESHOLD 70
#define PING_INTERVAL                   1000
#define PING_DEFAULT_TIMEOUT_SEC        2
#define PING_DEFAULT_COUNT              10
#define PING_DEFAULT_SIZE               56
#define PING_MAX_SIZE                   65507

#define PING_ID 0xAFAF

#define IP_ADDR_LEN 16

MLAN_PACK_START struct icmp_echo_hdr
{
    uint8_t type;
    uint8_t code;
    uint16_t chksum;
    uint16_t id;
    uint16_t seqno;
} MLAN_PACK_END;

MLAN_PACK_START struct ip_hdr
{
    /* version / header length */
    uint8_t _v_hl;
    /* type of service */
    uint8_t _tos;
    /* total length */
    uint16_t _len;
    /* identification */
    uint16_t _id;
    /* fragment offset field */
    uint16_t _offset;
#define IP_RF      0x8000U /* reserved fragment flag */
#define IP_DF      0x4000U /* don't fragment flag */
#define IP_MF      0x2000U /* more fragments flag */
#define IP_OFFMASK 0x1fffU /* mask for fragmenting bits */
    /* time to live */
    uint8_t _ttl;
    /* protocol*/
    uint8_t _proto;
    /* checksum */
    uint16_t _chksum;
    /* source and destination IP addresses */
    in_addr_t src;
    in_addr_t dest;
} MLAN_PACK_END;

typedef MLAN_PACK_START struct _ping_msg_t
{
    uint16_t size;
    uint32_t count;
    uint32_t timeout;
    uint32_t handle;
    char ip_addr[IP_ADDR_LEN];
    uint32_t port;
} MLAN_PACK_END ping_msg_t;

typedef MLAN_PACK_START struct _ping_res
{
    int seq_no;
    int echo_resp;
    uint32_t time;
    uint32_t recvd;
    int ttl;
    char ip_addr[IP_ADDR_LEN];
    uint16_t size;
} MLAN_PACK_END ping_res_t;

#define NCP_IPERF_TCP_SERVER_PORT_DEFAULT 5001
#define NCP_IPERF_UDP_SERVER_PORT_DEFAULT NCP_IPERF_TCP_SERVER_PORT_DEFAULT + 2
#define NCP_IPERF_UDP_RATE                30 * 1024
#define NCP_IPERF_UDP_TIME                100
#define NCP_IPERF_PKG_COUNT               1000
#define NCP_IPERF_PER_TCP_PKG_SIZE        1448
#define NCP_IPERF_PER_UDP_PKG_SIZE        1472

#define IPERF_TCP_RECV_TIMEOUT 1000
#define IPERF_UDP_RECV_TIMEOUT 1000

enum ncp_iperf_item
{
    NCP_IPERF_TCP_TX,
    NCP_IPERF_TCP_RX,
    NCP_IPERF_UDP_TX,
    NCP_IPERF_UDP_RX,
    FALSE_ITEM,
};

typedef struct _iperf_set_t
{
    uint32_t iperf_type;
    uint32_t iperf_count;
    uint32_t iperf_udp_rate;
} iperf_set_t;

typedef MLAN_PACK_START struct _iperf_msg_t
{
    int16_t status[2];
    uint32_t count;
    uint32_t timeout;
    uint32_t handle;
    uint32_t port;
    uint16_t per_size;
    char ip_addr[IP_ADDR_LEN];
    iperf_set_t iperf_set;
} MLAN_PACK_END iperf_msg_t;

#define BRIDGE_MUTEX_INHERIT 1

/** Station Power save mode */
enum wlan_ps_mode
{
    /** Active mode */
    WLAN_ACTIVE = 0,
    /** IEEE power save mode */
    WLAN_IEEE,
    /** Deep sleep power save mode */
    WLAN_DEEP_SLEEP,
    WLAN_IEEE_DEEP_SLEEP,
    WLAN_WNM,
    WLAN_WNM_DEEP_SLEEP,
};

/** WLAN station/micro-AP/Wi-Fi Direct Connection/Status state */
enum wlan_connection_state
{
    /** The WLAN Connection Manager is not connected and no connection attempt
     *  is in progress.  It is possible to connect to a network or scan. */
    WLAN_DISCONNECTED,
    /** The WLAN Connection Manager is not connected but it is currently
     *  attempting to connect to a network.  It is not possible to scan at this
     *  time.  It is possible to connect to a different network. */
    WLAN_CONNECTING,
    /** The WLAN Connection Manager is not connected but associated. */
    WLAN_ASSOCIATED,
    /** The WLAN Connection Manager is connected.  It is possible to scan and
     *  connect to another network at this time.  Information about the current
     *  network configuration is available. */
    WLAN_CONNECTED,
    /** The WLAN Connection Manager has started uAP */
    WLAN_UAP_STARTED,
    /** The WLAN Connection Manager has stopped uAP */
    WLAN_UAP_STOPPED,
    /** The WLAN Connection Manager is not connected and network scan
     * is in progress. */
    WLAN_SCANNING,
    /** The WLAN Connection Manager is not connected and network association
     * is in progress. */
    WLAN_ASSOCIATING,
};

typedef MLAN_PACK_START struct _MCU_NCPCmd_DS_COMMAND
{
    /** Command Header : Command */
    NCP_HOST_COMMAND header;
    /** Command Body */
    union
    {
        /** Scan result*/
        NCP_CMD_SCAN_NETWORK_INFO scan_network_info;
        NCP_CMD_WPS_GEN_PIN wps_gen_pin_info;
        NCP_CMD_WPS_PIN wps_pin_cfg;
        /** RSSI information*/
        NCP_CMD_RSSI signal_rssi;
        /** Firmware version*/
        NCP_CMD_FW_VERSION fw_version;
        /** wlan connnection state */
        NCP_CMD_CONNECT_STAT conn_stat;
        /** Roaming configuration */
        NCP_CMD_ROAMING roaming;
        /** wlan multi MEF config */
        NCP_CMD_POWERMGMT_MEF mef_config;
        /** wlan deep sleep ps*/
        NCP_CMD_DEEP_SLEEP_PS wlan_deep_sleep_ps;
        /** wlan ieee ps*/
        NCP_CMD_IEEE_PS wlan_ieee_ps;
        NCP_CMD_POWERMGMT_UAPSD uapsd_cfg;
        NCP_CMD_POWERMGMT_QOSINFO qosinfo_cfg;
        NCP_CMD_POWERMGMT_SLEEP_PERIOD sleep_period_cfg;
        /** wlan wake config */
        NCP_CMD_POWERMGMT_WAKE_CFG wake_config;
        /** wlan wowlan config */
        NCP_CMD_POWERMGMT_WOWLAN_CFG wowlan_config;
        /** wlan mcu sleep config */
        NCP_CMD_POWERMGMT_MCU_SLEEP mcu_sleep_config;
        /** wlan suspend config */
        NCP_CMD_POWERMGMT_SUSPEND suspend_config;
        /** wlan host wakeup */
        NCP_CMD_POWERMGMT_WAKEUP_HOST host_wakeup_ctrl;
        /** wlan reset config **/
        WLAN_RESET_data reset_config;

        /** MAX client count*/
        NCP_CMD_CLIENT_CNT max_client_count;
        /** Antenna config*/
        NCP_CMD_ANTENNA_CFG antenna_cfg;

        NCP_CMD_11AX_CFG he_cfg;
        NCP_CMD_BTWT_CFG btwt_cfg;
        NCP_CMD_TWT_SETUP twt_setup;
        NCP_CMD_TWT_TEARDOWN twt_teardown;
        NCP_CMD_TWT_REPORT twt_report;
        NCP_CMD_11D_ENABLE wlan_11d_cfg;
        NCP_CMD_REGION_CODE region_cfg;

        /*socket command*/
        NCP_CMD_SOCKET_OPEN_CFG wlan_socket_open;
        NCP_CMD_SOCKET_CON_CFG wlan_socket_con;
        NCP_CMD_SOCKET_BIND_CFG wlan_socket_bind;
        NCP_CMD_SOCKET_CLOSE_CFG wlan_socket_close;
        NCP_CMD_SOCKET_LISTEN_CFG wlan_socket_listen;
        NCP_CMD_SOCKET_ACCEPT_CFG wlan_socket_accept;
        NCP_CMD_SOCKET_SEND_CFG wlan_socket_send;
        NCP_CMD_SOCKET_SENDTO_CFG wlan_socket_sendto;
        NCP_CMD_SOCKET_RECEIVE_CFG wlan_socket_receive;
        NCP_CMD_SOCKET_RECVFROM_CFG wlan_socket_recvfrom;

        /*http command*/
        NCP_CMD_HTTP_CON_CFG wlan_http_connect;
        NCP_CMD_HTTP_DISCON_CFG wlan_http_disconnect;
        NCP_CMD_HTTP_SETH_CFG wlan_http_seth;
        NCP_CMD_HTTP_UNSETH_CFG wlan_http_unseth;
        NCP_CMD_HTTP_REQ_CFG wlan_http_req;
        NCP_CMD_HTTP_REQ_RESP_CFG wlan_http_req_resp;
        NCP_CMD_HTTP_RECV_CFG wlan_http_recv;
        NCP_CMD_HTTP_UPG_CFG wlan_http_upg;
        NCP_CMD_WEBSOCKET_SEND_CFG wlan_websocket_send;
        NCP_CMD_WEBSOCKET_RECV_CFG wlan_websocket_recv;

        /*regulatory commands*/
        NCP_CMD_EU_VALIDATION eu_validation;
        NCP_CMD_ED_MAC ed_mac_mode;
#ifdef CONFIG_NCP_RF_TEST_MODE
        NCP_CMD_RF_TX_ANTENNA rf_tx_antenna;
        NCP_CMD_RF_RX_ANTENNA rf_rx_antenna;
        NCP_CMD_RF_BAND rf_band;
        NCP_CMD_RF_BANDWIDTH rf_bandwidth;
        NCP_CMD_RF_CHANNEL rf_channel;
        NCP_CMD_RF_RADIO_MODE rf_radio_mode;
        NCP_CMD_RF_TX_POWER rf_tx_power;
        NCP_CMD_RF_TX_CONT_MODE rf_tx_cont_mode;
        NCP_CMD_RF_TX_FRAME rf_tx_frame;
        NCP_CMD_RF_PER rf_per;
#endif

        /*Debug commands*/
        NCP_CMD_REGISTER_ACCESS register_access;
        /*Memory commands*/
        NCP_CMD_MEM_STAT mem_stat;

        /** System configuration */
        NCP_CMD_SYSTEM_CFG system_cfg;
        /** MAC address */
        NCP_CMD_MAC_ADDRESS mac_addr;
        /** Get MAC address */
        NCP_CMD_GET_MAC_ADDRESS get_mac_addr;
        /** wlan network info*/
        NCP_CMD_NETWORK_INFO network_info;
        /** wlan add network*/
        NCP_CMD_NETWORK_ADD network_add;
        /** wlan start network*/
        NCP_CMD_NETWORK_START network_start;
        /** wlan uap sta list*/
        NCP_CMD_NETWORK_UAP_STA_LIST uap_sta_list;
        NCP_CMD_DATE_TIME date_time;
        NCP_CMD_TEMPERATURE temperature;

        /** wlan connect*/
        NCP_CMD_WLAN_CONN wlan_connect;
        NCP_CMD_NET_MONITOR monitor_cfg;
        NCP_CMD_CSI csi_cfg;
        NCP_CMD_11K_CFG wlan_11k_cfg;
        NCP_CMD_NEIGHBOR_REQ neighbor_req;

        /** MBO **/
        NCP_CMD_MBO_ENABLE wlan_mbo_cfg;
        NCP_CMD_MBO_NONPREFER_CH mbo_nonprefer_ch_params;
        NCP_CMD_MBO_SET_CELL_CAPA wlan_mbo_set_cell_capa;
        NCP_CMD_MBO_SET_OCE wlan_mbo_set_oce;

        /** mdns query*/
        NCP_CMD_MDNS_QUERY mdns_query;
        /** mdns reuslt*/
        NCP_EVT_MDNS_RESULT mdns_result;
        /** mdns resolve*/
        NCP_EVT_MDNS_RESOLVE mdns_resolve;

        /** added network list*/
        NCP_CMD_NETWORK_LIST network_list;
        /** remove network*/
        NCP_CMD_NETWORK_REMOVE network_remove;
    } params;
} MLAN_PACK_END MCU_NCPCmd_DS_COMMAND;

/*Convert IP Adderss to hexadecimal*/
int strip_to_hex(int *number, int len);

/*Convert IP Adderss to hexadecimal*/
int IP_to_hex(char *IPstr, uint8_t *hex);

int wlan_scan_command(int argc, char **argv);

int wlan_connect_command(int argc, char **argv);

int wlan_disconnect_command(int argc, char **argv);

int wlan_start_wps_pbc_command(int argc, char **argv);

int wlan_process_wps_pbc_response(uint8_t *res);

int wlan_wps_generate_pin_command(int argc, char **argv);

int wlan_process_wps_generate_pin_response(uint8_t *res);

int wlan_start_wps_pin_command(int argc, char **argv);

int wlan_process_wps_pin_response(uint8_t *res);

int wlan_get_scan_res_command(int argc, char **argv);

int wlan_get_signal_command(int argc, char **argv);

int wlan_version_command(int argc, char **argv);

int wlan_stat_command(int argc, char **argv);

int wlan_multi_mef_command(int argc, char **argv);

int wlan_set_wmm_uapsd_command(int argc, char **argv);

int wlan_process_wmm_uapsd_response(uint8_t *res);

int wlan_wmm_uapsd_qosinfo_command(int argc, char **argv);

int wlan_process_uapsd_qosinfo_response(uint8_t *res);

int wlan_uapsd_sleep_period_command(int argc, char **argv);

int wlan_process_uapsd_sleep_period_response(uint8_t *res);

int wlan_wake_cfg_command(int argc, char **argv);

int wlan_wakeup_condition_command(int argc, char **argv);

int wlan_mcu_sleep_command(int argc, char **argv);

int wlan_suspend_command(int argc, char **argv);

int wlan_process_wlan_socket_open_response(uint8_t *res);

int wlan_process_wlan_socket_con_response(uint8_t *res);

int wlan_process_wlan_socket_bind_response(uint8_t *res);

int wlan_process_wlan_socket_close_response(uint8_t *res);

int wlan_process_wlan_socket_listen_response(uint8_t *res);

int wlan_process_wlan_socket_accept_response(uint8_t *res);

int wlan_process_wlan_socket_send_response(uint8_t *res);

int wlan_process_wlan_socket_sendto_response(uint8_t *res);

int wlan_process_wlan_socket_receive_response(uint8_t *res);

int wlan_process_wlan_socket_recvfrom_response(uint8_t *res);

int wlan_process_wlan_http_con_response(uint8_t *res);

int wlan_process_wlan_http_discon_response(uint8_t *res);

int wlan_process_wlan_http_req_response(uint8_t *res);

int wlan_process_wlan_http_recv_response(uint8_t *res);

int wlan_process_wlan_http_seth_response(uint8_t *res);

int wlan_process_wlan_http_unseth_response(uint8_t *res);

int wlan_process_wlan_websocket_upg_response(uint8_t *res);

int wlan_process_wlan_websocket_send_response(uint8_t *res);

int wlan_process_wlan_websocket_recv_response(uint8_t *res);

int ncp_set_command(int argc, char **argv);

int ncp_get_command(int argc, char **argv);

int wlan_set_max_clients_count_command(int argc, char **argv);

int wlan_set_antenna_cfg_command(int argc, char **argv);

int wlan_get_antenna_cfg_command(int argc, char **argv);

int wlan_deep_sleep_ps_command(int argc, char **argv);

int wlan_ieee_ps_command(int argc, char **argv);

int wlan_eu_validation_command(int argc, char **argv);

int wlan_ed_mac_mode_set_command(int argc, char **argv);

int wlan_ed_mac_mode_get_command(int argc, char **argv);

int wlan_set_mac_address_command(int argc, char **argv);

int wlan_get_mac_address_command(int argc, char **argv);

int wlan_register_access_command(int argc, char **argv);

#ifdef CONFIG_NCP_MEM_MONITOR_DEBUG
int wlan_memory_state_command(int argc, char **argv);
#endif

int wlan_info_command(int argc, char **argv);

int wlan_add_command(int argc, char **argv);

int wlan_start_network_command(int argc, char **argv);

int wlan_stop_network_command(int argc, char **argv);

int wlan_get_uap_sta_list_command(int argc, char **argv);

int ncp_ping_command(int argc, char **argv);

int wlan_list_command(int argc, char **argv);

int wlan_remove_command(int argc, char **argv);

int wlan_process_ncp_event(uint8_t *res);

int wlan_process_response(uint8_t *res);

int wlan_process_wlan_uap_prov_start_result_response(uint8_t *res);

int wlan_process_wlan_uap_prov_reset_result_response(uint8_t *res);

int wlan_process_discon_response(uint8_t *res);

int wlan_process_con_response(uint8_t *res);

int wlan_process_scan_response(uint8_t *res);

int wlan_process_ping_response(uint8_t *res);

int wlan_process_iperf_response(uint8_t *res);

int wlan_process_rssi_response(uint8_t *res);

int wlan_process_version_response(uint8_t *res);

int wlan_process_roaming_response(uint8_t *res);

int wlan_process_stat_response(uint8_t *res);

int wlan_process_multi_mef_response(uint8_t *res);

int wlan_process_wake_mode_response(uint8_t *res);

int wlan_process_wakeup_condition_response(uint8_t *res);

int wlan_process_mcu_sleep_response(uint8_t *res);

int wlan_process_suspend_response(uint8_t *res);

int wlan_process_sleep_status(uint8_t *res);

int wlan_set_11axcfg_command(int argc, char **argv);

int wlan_process_11axcfg_response(uint8_t *res);

int wlan_set_btwt_command(int argc, char **argv);

int wlan_process_btwt_response(uint8_t *res);

int wlan_twt_setup_command(int argc, char **argv);

int wlan_process_twt_setup_response(uint8_t *res);

int wlan_twt_teardown_command(int argc, char **argv);

int wlan_process_twt_teardown_response(uint8_t *res);

int wlan_get_twt_report_command(int argc, char **argv);

int wlan_process_twt_report_response(uint8_t *res);

int wlan_set_11d_enable_command(int argc, char **argv);

int wlan_process_11d_enable_response(uint8_t *res);

int wlan_region_code_command(int argc, char **argv);

int wlan_process_region_code_response(uint8_t *res);

int ncp_process_set_cfg_response(uint8_t *res);

int ncp_process_get_cfg_response(uint8_t *res);

int wlan_process_client_count_response(uint8_t *res);

int wlan_process_antenna_cfg_response(uint8_t *res);

int wlan_process_deep_sleep_ps_response(uint8_t *res);

int wlan_process_ieee_ps_response(uint8_t *res);

int wlan_process_eu_validation_response(uint8_t *res);

int wlan_process_ed_mac_response(uint8_t *res);

#ifdef CONFIG_NCP_RF_TEST_MODE
int wlan_set_rf_test_mode_command(int argc, char **argv);

int wlan_process_set_rf_test_mode_response(uint8_t *res);

int wlan_set_rf_tx_antenna_command(int argc, char **argv);

int wlan_process_set_rf_tx_antenna_response(uint8_t *res);

int wlan_get_rf_tx_antenna_command(int argc, char **argv);

int wlan_process_get_rf_tx_antenna_response(uint8_t *res);

int wlan_set_rf_rx_antenna_command(int argc, char **argv);

int wlan_process_set_rf_rx_antenna_response(uint8_t *res);

int wlan_get_rf_rx_antenna_command(int argc, char **argv);

int wlan_process_get_rf_rx_antenna_response(uint8_t *res);

int wlan_set_rf_band_command(int argc, char **argv);

int wlan_process_set_rf_band_response(uint8_t *res);

int wlan_get_rf_band_command(int argc, char **argv);

int wlan_process_get_rf_band_response(uint8_t *res);

int wlan_set_rf_bandwidth_command(int argc, char **argv);

int wlan_process_set_rf_bandwidth_response(uint8_t *res);

int wlan_get_rf_bandwidth_command(int argc, char **argv);

int wlan_process_get_rf_bandwidth_response(uint8_t *res);

int wlan_set_rf_channel_command(int argc, char **argv);

int wlan_process_set_rf_channel_response(uint8_t *res);

int wlan_get_rf_channel_command(int argc, char **argv);

int wlan_process_get_rf_channel_response(uint8_t *res);

int wlan_set_rf_radio_mode_command(int argc, char **argv);

int wlan_process_set_rf_radio_mode_response(uint8_t *res);

int wlan_get_rf_radio_mode_command(int argc, char **argv);

int wlan_process_get_rf_radio_mode_response(uint8_t *res);

int wlan_bridge_set_rf_tx_power_command(int argc, char **argv);

int wlan_process_set_rf_tx_power_response(uint8_t *res);

int wlan_bridge_set_rf_tx_cont_mode_command(int argc, char **argv);

int wlan_process_set_rf_tx_cont_mode_response(uint8_t *res);

int wlan_bridge_set_rf_tx_frame_command(int argc, char **argv);

int wlan_process_set_rf_tx_frame_response(uint8_t *res);

int wlan_bridge_set_rf_get_and_reset_rf_per_command(int argc, char **argv);

int wlan_process_set_rf_get_and_reset_rf_per_response(uint8_t *res);
#endif

int wlan_process_set_mac_address(uint8_t *res);

int wlan_process_get_mac_address(uint8_t *res);

int wlan_process_info(uint8_t *res);

int wlan_process_add_response(uint8_t *res);

int wlan_process_start_network_response(uint8_t *res);

int wlan_process_stop_network_response(uint8_t *res);

int wlan_process_get_uap_sta_list(uint8_t *res);

int wlan_process_register_access_response(uint8_t *res);

#ifdef CONFIG_NCP_MEM_MONITOR_DEBUG
int wlan_process_memory_state_response(uint8_t *res);
#endif

int wlan_set_time_command(int argc, char **argv);

int wlan_get_time_command(int argc, char **argv);

int wlan_process_time_response(uint8_t *res);

int wlan_get_temperature_command(int argc, char **argv);

int wlan_process_get_temperature_response(uint8_t *res);

int wlan_mdns_query_command(int argc, char **argv);

int wlan_process_mdns_query_response(uint8_t *res);

int wlan_process_mdns_query_result_event(uint8_t *res);

int wlan_process_mdns_resolve_domain_event(uint8_t *res);

int ncp_host_cli_command_init();

int wlan_process_monitor_response(uint8_t *res);

int wlan_process_csi_response(uint8_t *res);

int wlan_process_11k_cfg_response(uint8_t *res);

int wlan_process_neighbor_req_response(uint8_t *res);

int wlan_process_network_list_response(uint8_t *res);

int wlan_process_network_remove_response(uint8_t *res);

MCU_NCPCmd_DS_COMMAND *ncp_host_get_command_buffer();

int wlan_process_mbo_enable_response(uint8_t *res);

int wlan_process_mbo_nonprefer_ch_response(uint8_t *res);

int wlan_process_mbo_set_cell_capa_response(uint8_t *res);

int wlan_process_mbo_set_oce_response(uint8_t *res);

#endif /*__NCP_MCU_HOST_COMMAND_H_*/
