/**@file mcu_bridge_command.h
 *
 *  Copyright 2008-2023 NXP
 *
 *  Licensed under the LA_OPT_NXP_Software_License.txt (the "Agreement")
 *
 */

#ifndef __MCU_BRIDGE_COMMAND_H_
#define __MCU_BRIDGE_COMMAND_H_

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

#define NCP_BRIDGE_CMD_HEADER_LEN     sizeof(NCP_MCU_BRIDGE_COMMAND)
#define NCP_BRIDGE_TLV_HEADER_LEN     sizeof(TypeHeader_t)

#define MAC2STR(a)                a[0], a[1], a[2], a[3], a[4], a[5]
#define MCU_BRIDGE_IP_LENGTH      4
#define MCU_BRIDGE_IP_VALID       255
#define MCU_BRIDGE_MAX_AP_ENTRIES 30

/*NCP MCU Bridge command class*/
#define NCP_BRIDGE_CMD_WLAN   0x00000000
#define NCP_BRIDGE_CMD_BLE    0x01000000
#define NCP_BRIDGE_CMD_15D4   0x02000000
#define NCP_BRIDGE_CMD_MATTER 0x03000000
#define NCP_BRIDGE_CMD_SYSTEM 0x04000000

/*WLAN NCP MCU Bridge subclass*/
#define NCP_BRIDGE_CMD_WLAN_STA         0x00000000
#define NCP_BRIDGE_CMD_WLAN_BASIC       0x00010000
#define NCP_BRIDGE_CMD_WLAN_REGULATORY  0x00020000
#define NCP_BRIDGE_CMD_WLAN_POWERMGMT   0x00030000
#define NCP_BRIDGE_CMD_WLAN_DEBUG       0x00040000
#define NCP_BRIDGE_CMD_WLAN_OTHER       0x00050000
#define NCP_BRIDGE_CMD_WLAN_MEMORY      0x00060000
#define NCP_BRIDGE_CMD_WLAN_NETWORK     0x00070000
#define NCP_BRIDGE_CMD_WLAN_OFFLOAD     0x00080000
#define NCP_BRIDGE_CMD_WLAN_SOCKET      0x00090000
#define NCP_BRIDGE_CMD_WLAN_UAP         0x000a0000
#define NCP_BRIDGE_CMD_WLAN_HTTP        0x000b0000
#define NCP_BRIDGE_CMD_WLAN_COEX        0x000c0000
#define NCP_BRIDGE_CMD_WLAN_MATTER      0x000d0000
#define NCP_BRIDGE_CMD_WLAN_EDGE_LOCK   0x000e0000
#define NCP_BRIDGE_CMD_WLAN_ASYNC_EVENT 0x000f0000

/* System NCP Bridge subclass */
#define NCP_BRIDGE_CMD_SYSTEM_CONFIG   0x00000000

/*NCP MCU Bridge Message Type*/
#define NCP_BRIDGE_MSG_TYPE_CMD   0x0000
#define NCP_BRIDGE_MSG_TYPE_RESP  0x0001
#define NCP_BRIDGE_MSG_TYPE_EVENT 0x0002

/*NCP MCU Bridge CMD response state*/
/*General result code ok*/
#define NCP_BRIDGE_CMD_RESULT_OK 0x0000
/*General error*/
#define NCP_BRIDGE_CMD_RESULT_ERROR 0x0001
/*NCP Bridge Command is not valid*/
#define NCP_BRIDGE_CMD_RESULT_NOT_SUPPORT 0x0002
/*NCP Bridge Command is pending*/
#define NCP_BRIDGE_CMD_RESULT_PENDING 0x0003
/*System is busy*/
#define NCP_BRIDGE_CMD_RESULT_BUSY 0x0004
/*Data buffer is not big enough*/
#define NCP_BRIDGE_CMD_RESULT_PARTIAL_DATA 0x0005
/*MCU device enter low power mode*/
#define NCP_BRIDGE_CMD_RESULT_ENTER_SLEEP 0x0006
/*MCU device exit low power mode*/
#define NCP_BRIDGE_CMD_RESULT_EXIT_SLEEP 0x0007

/* The max size of the network list*/
#define NCP_BRIDGE_WLAN_KNOWN_NETWORKS 5

/*NCP MCU Bridge Command definitions*/
/*WLAN STA command*/
#define NCP_BRIDGE_CMD_WLAN_STA_SCAN    (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_STA | 0x00000001) /* wlan-scan */
#define NCP_BRIDGE_CMD_WLAN_STA_CONNECT (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_STA | 0x00000002) /* wlan-connect */
#define NCP_BRIDGE_CMD_WLAN_STA_DISCONNECT \
    (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_STA | 0x00000003) /* wlan-disconnect */
#define NCP_BRIDGE_CMD_WLAN_STA_VERSION \
    (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_STA | 0x00000004) /* wlan-version */
#define NCP_BRIDGE_CMD_WLAN_STA_SET_MAC \
    (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_STA | 0x00000005) /* wlan-set-mac */
#define NCP_BRIDGE_CMD_WLAN_STA_GET_MAC \
    (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_STA | 0x00000006) /* wlan-get-mac */
#define NCP_BRIDGE_CMD_WLAN_STA_CONNECT_STAT \
    (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_STA | 0x00000007) /* wlan-stat */
#define NCP_BRIDGE_CMD_WLAN_STA_ROAMING \
    (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_STA | 0x00000008) /* wlan-roaming */
#define NCP_BRIDGE_CMD_WLAN_STA_ANTENNA     (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_STA | 0x00000009) /** wlan-set-antenna / wlan-get-antenna*/

#define NCP_BRIDGE_CMD_WLAN_STA_SIGNAL      (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_STA | 0x00000012) /* wlan-get-signal */
#define NCP_BRIDGE_CMD_WLAN_STA_CSI         (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_STA | 0x00000020)
#define NCP_BRIDGE_CMD_WLAN_11K_CFG         (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_STA | 0x00000021)
#define NCP_BRIDGE_CMD_WLAN_NEIGHBOR_REQ    (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_STA | 0x00000022)

#define NCP_BRIDGE_CMD_WLAN_MBO_ENABLE       (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_STA | 0x00000023) /*wlan-mbo-enable*/
#define NCP_BRIDGE_CMD_WLAN_MBO_NONPREFER_CH (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_STA | 0x00000024) /*wlan-mbo-nonprefer-ch*/
#define NCP_BRIDGE_CMD_WLAN_MBO_SET_CELL_CAPA (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_STA | 0x00000025)/*wlan-mbo-set-cell-capa*/
#define NCP_BRIDGE_CMD_WLAN_MBO_SET_OCE       (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_STA | 0x00000026)/*wlan-mbo-set-oce*/

#define NCP_BRIDGE_CMD_WLAN_STA_WPS_PBC      (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_STA | 0x00000031) /* wlan-start-wps-pbc */
#define NCP_BRIDGE_CMD_WLAN_STA_GEN_WPS_PIN  (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_STA | 0x00000032) /* wlan-generate-wps-pin */
#define NCP_BRIDGE_CMD_WLAN_STA_WPS_PIN      (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_STA | 0x00000033) /* wlan-start-wps-pin */

/*WLAN Basic command*/
#define NCP_BRIDGE_CMD_WLAN_BASIC_WLAN_RESET (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_BASIC | 0x00000001)
#define NCP_BRIDGE_CMD_WLAN_BASIC_WLAN_UAP_PROV_START  (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_BASIC | 0x00000002)
#define NCP_BRIDGE_CMD_WLAN_BASIC_WLAN_UAP_PROV_RESET  (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_BASIC | 0x00000003)

/*WLAN Socket command*/
#define NCP_BRIDGE_CMD_WLAN_SOCKET_OPEN     (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_SOCKET | 0x00000001)
#define NCP_BRIDGE_CMD_WLAN_SOCKET_CON     (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_SOCKET | 0x00000002)
#define NCP_BRIDGE_CMD_WLAN_SOCKET_RECV     (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_SOCKET | 0x00000003)
#define NCP_BRIDGE_CMD_WLAN_SOCKET_SEND     (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_SOCKET | 0x00000004)
#define NCP_BRIDGE_CMD_WLAN_SOCKET_SENDTO   (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_SOCKET | 0x00000005)
#define NCP_BRIDGE_CMD_WLAN_SOCKET_BIND     (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_SOCKET | 0x00000006)
#define NCP_BRIDGE_CMD_WLAN_SOCKET_LISTEN   (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_SOCKET | 0x00000007)
#define NCP_BRIDGE_CMD_WLAN_SOCKET_ACCEPT   (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_SOCKET | 0x00000008)
#define NCP_BRIDGE_CMD_WLAN_SOCKET_CLOSE    (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_SOCKET | 0x00000009)
#define NCP_BRIDGE_CMD_WLAN_SOCKET_RECVFROM (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_SOCKET | 0x0000000a)

/*WLAN Http command*/
#define NCP_BRIDGE_CMD_WLAN_HTTP_CON         (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_HTTP | 0x00000001)
#define NCP_BRIDGE_CMD_WLAN_HTTP_DISCON      (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_HTTP | 0x00000002)
#define NCP_BRIDGE_CMD_WLAN_HTTP_REQ         (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_HTTP | 0x00000003)
#define NCP_BRIDGE_CMD_WLAN_HTTP_RECV        (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_HTTP | 0x00000004)
#define NCP_BRIDGE_CMD_WLAN_HTTP_SETH        (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_HTTP | 0x00000005)
#define NCP_BRIDGE_CMD_WLAN_HTTP_UNSETH      (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_HTTP | 0x00000006)
#define NCP_BRIDGE_CMD_WLAN_WEBSOCKET_UPG    (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_HTTP | 0x00000007)
#define NCP_BRIDGE_CMD_WLAN_WEBSOCKET_SEND   (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_HTTP | 0x00000008)
#define NCP_BRIDGE_CMD_WLAN_WEBSOCKET_RECV   (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_HTTP | 0x00000009)

/*WLAN Network command*/
#define NCP_BRIDGE_CMD_WLAN_NETWORK_INFO    (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_NETWORK | 0x00000001) /* wlan-info */
#define NCP_BRIDGE_CMD_WLAN_NETWORK_MONITOR     (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_NETWORK | 0x00000002) /* wlan-monitor */
#define NCP_BRIDGE_CMD_WLAN_NETWORK_ADD    (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_NETWORK | 0x00000003) /* wlan-add */
#define NCP_BRIDGE_CMD_WLAN_NETWORK_START   (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_NETWORK | 0x00000004) /* wlan-start-network */
#define NCP_BRIDGE_CMD_WLAN_NETWORK_STOP    (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_NETWORK | 0x00000005) /* wlan-stop-network */
#define NCP_BRIDGE_CMD_WLAN_NETWORK_GET_UAP_STA_LIST    (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_NETWORK | 0x00000006) /* wlan-get-uap-sta-list */
#define NCP_BRIDGE_CMD_WLAN_NETWORK_MDNS_QUERY  (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_NETWORK | 0x00000007) /* mdns-query */
#define NCP_BRIDGE_CMD_WLAN_NETWORK_LIST  (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_NETWORK | 0x00000008) /* wlan-list */
#define NCP_BRIDGE_CMD_WLAN_NETWORK_REMOVE  (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_NETWORK | 0x00000009) /* wlan-remove */

/*WLAN UAP command*/
#define NCP_BRIDGE_CMD_WLAN_UAP_MAX_CLIENT_CNT   (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_UAP | 0x00000001) /* wlan-set-max-clients-count */

/*WLAN Power Mgmt command*/
#define NCP_BRIDGE_CMD_WLAN_POWERMGMT_MEF \
    (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_POWERMGMT | 0x00000001) /* wlan-multi-mef */
#define NCP_BRIDGE_CMD_WLAN_POWERMGMT_DEEP_SLEEP_PS \
    (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_POWERMGMT | 0x00000002) /* wlan-deep-sleep-ps */
#define NCP_BRIDGE_CMD_WLAN_POWERMGMT_IEEE_PS \
    (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_POWERMGMT | 0x00000003) /* wlan-ieee-ps */
#define NCP_BRIDGE_CMD_WLAN_POWERMGMT_UAPSD \
    (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_POWERMGMT | 0x00000004) /* wlan-uapsd-enable */
#define NCP_BRIDGE_CMD_WLAN_POWERMGMT_QOSINFO \
    (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_POWERMGMT | 0x00000005) /* wlan-uapsd-qosinfo */
#define NCP_BRIDGE_CMD_WLAN_POWERMGMT_SLEEP_PERIOD \
    (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_POWERMGMT | 0x00000006) /* wlan-uapsd-sleep-period */
#define NCP_BRIDGE_CMD_WLAN_POWERMGMT_WAKE_MODE_CFG \
    (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_POWERMGMT | 0x00000007) /* wlan-wake-cfg */
#define NCP_BRIDGE_CMD_WLAN_POWERMGMT_WOWLAN_CFG \
    (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_POWERMGMT | 0x00000008) /* wlan-wowlan-cfg */
#define NCP_BRIDGE_CMD_WLAN_POWERMGMT_MCU_SLEEP \
    (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_POWERMGMT | 0x00000009) /* wlan-mcu-sleep-mode */
#define NCP_BRIDGE_CMD_WLAN_POWERMGMT_SUSPEND \
    (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_POWERMGMT | 0x0000000a) /* wlan-suspend */
#define NCP_BRIDGE_CMD_WLAN_POWERMGMT_WAKEUP_HOST \
    (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_POWERMGMT | 0x0000000b) /* wlan-wakeup-host */

/*WLAN Regulatory command*/
#define NCP_BRIDGE_CMD_WLAN_REGULATORY_EU_VALIDATION  (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_REGULATORY | 0x00000001)
#define NCP_BRIDGE_CMD_WLAN_REGULATORY_ED_MAC_MODE    (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_REGULATORY | 0x00000002)
#ifdef CONFIG_NCP_RF_TEST_MODE
#define NCP_BRIDGE_CMD_WLAN_REGULATORY_SET_RF_TEST_MODE      (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_REGULATORY | 0x00000003)
#define NCP_BRIDGE_CMD_WLAN_REGULATORY_SET_RF_TX_ANTENNA     (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_REGULATORY | 0x00000004)
#define NCP_BRIDGE_CMD_WLAN_REGULATORY_GET_RF_TX_ANTENNA     (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_REGULATORY | 0x00000005)
#define NCP_BRIDGE_CMD_WLAN_REGULATORY_SET_RF_RX_ANTENNA     (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_REGULATORY | 0x00000006)
#define NCP_BRIDGE_CMD_WLAN_REGULATORY_GET_RF_RX_ANTENNA     (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_REGULATORY | 0x00000007)
#define NCP_BRIDGE_CMD_WLAN_REGULATORY_SET_RF_BAND           (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_REGULATORY | 0x00000008)
#define NCP_BRIDGE_CMD_WLAN_REGULATORY_GET_RF_BAND           (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_REGULATORY | 0x00000009)
#define NCP_BRIDGE_CMD_WLAN_REGULATORY_SET_RF_BANDWIDTH      (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_REGULATORY | 0x0000000a)
#define NCP_BRIDGE_CMD_WLAN_REGULATORY_GET_RF_BANDWIDTH      (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_REGULATORY | 0x0000000b)
#define NCP_BRIDGE_CMD_WLAN_REGULATORY_SET_RF_CHANNEL        (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_REGULATORY | 0x0000000c)
#define NCP_BRIDGE_CMD_WLAN_REGULATORY_GET_RF_CHANNEL        (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_REGULATORY | 0x0000000d)
#define NCP_BRIDGE_CMD_WLAN_REGULATORY_SET_RF_RADIO_MODE     (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_REGULATORY | 0x0000000e)
#define NCP_BRIDGE_CMD_WLAN_REGULATORY_GET_RF_RADIO_MODE     (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_REGULATORY | 0x0000000f)
#define NCP_BRIDGE_CMD_WLAN_REGULATORY_SET_RF_TX_POWER       (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_REGULATORY | 0x00000010)
#define NCP_BRIDGE_CMD_WLAN_REGULATORY_SET_RF_TX_CONT_MODE   (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_REGULATORY | 0x00000011)
#define NCP_BRIDGE_CMD_WLAN_REGULATORY_SET_RF_TX_FRAME       (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_REGULATORY | 0x00000012)
#define NCP_BRIDGE_CMD_WLAN_REGULATORY_GET_AND_RESET_RF_PER  (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_REGULATORY | 0x00000013)
#endif

/* System Configure command */
#define NCP_BRIDGE_CMD_SYSTEM_CONFIG_SET  (NCP_BRIDGE_CMD_SYSTEM | NCP_BRIDGE_CMD_SYSTEM_CONFIG | 0x00000001) /* set-device-cfg */
#define NCP_BRIDGE_CMD_SYSTEM_CONFIG_GET  (NCP_BRIDGE_CMD_SYSTEM | NCP_BRIDGE_CMD_SYSTEM_CONFIG | 0x00000002) /* get-device-cfg */

/*WLAN Debug command*/
#define  NCP_BRIDGE_CMD_WLAN_DEBUG_REGISTER_ACCESS    (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_DEBUG | 0x00000001)

/*WLAN Memory command*/
#define NCP_BRIDGE_CMD_WLAN_MEMORY_HEAP_SIZE          (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_MEMORY | 0x00000001)

/*WLAN Other command */
#define NCP_BRIDGE_CMD_11AX_CFG       (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_OTHER | 0x00000001)
#define NCP_BRIDGE_CMD_BTWT_CFG       (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_OTHER | 0x00000002)
#define NCP_BRIDGE_CMD_TWT_SETUP      (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_OTHER | 0x00000003)
#define NCP_BRIDGE_CMD_TWT_TEARDOWN   (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_OTHER | 0x00000004)
#define NCP_BRIDGE_CMD_TWT_GET_REPORT (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_OTHER | 0x00000005)
#define NCP_BRIDGE_CMD_11D_ENABLE     (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_OTHER | 0x00000006)
#define NCP_BRIDGE_CMD_REGION_CODE    (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_OTHER | 0x00000007)
#define NCP_BRIDGE_CMD_DATE_TIME      (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_OTHER | 0x00000008)
#define NCP_BRIDGE_CMD_GET_TEMPERATUE (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_OTHER | 0x00000009)
#define NCP_BRIDGE_CMD_INVALID_CMD    (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_OTHER | 0x0000000a)

/*WLAN events*/
#define NCP_BRIDGE_EVENT_MCU_SLEEP_ENTER (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_ASYNC_EVENT | 0x00000001)
#define NCP_BRIDGE_EVENT_MCU_SLEEP_EXIT  (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_ASYNC_EVENT | 0x00000002)
#define NCP_BRIDGE_EVENT_MDNS_QUERY_RESULT (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_ASYNC_EVENT | 0x00000003)
#define NCP_BRIDGE_EVENT_MDNS_RESOLVE_DOMAIN (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_ASYNC_EVENT | 0x00000004)

/*NCP MCU BRIDGE TLV definitions*/
#define NCP_BRIDGE_CMD_NETWORK_SSID_TLV         0x0001
#define NCP_BRIDGE_CMD_NETWORK_BSSID_TLV        0x0002
#define NCP_BRIDGE_CMD_NETWORK_CHANNEL_TLV      0x0003
#define NCP_BRIDGE_CMD_NETWORK_IP_TLV           0x0004
#define NCP_BRIDGE_CMD_NETWORK_SECURITY_TLV     0x0005
#define NCP_BRIDGE_CMD_NETWORK_ROLE_TLV         0x0006
#define NCP_BRIDGE_CMD_NETWORK_DTIM_TLV         0x0007
#define NCP_BRIDGE_CMD_NETWORK_CAPA_TLV         0x0008
#define NCP_BRIDGE_CMD_NETWORK_ACSBAND_TLV      0x0009
#define NCP_BRIDGE_CMD_NETWORK_PMF_TLV          0x000A

#define NCP_BRIDGE_CMD_WLAN_HE_CAP_TLV 0x00FF

/* NCP Bridge MDNS Result TLV */
#define NCP_BRIDGE_CMD_NETWORK_MDNS_RESULT_PTR 0x0011
#define NCP_BRIDGE_CMD_NETWORK_MDNS_RESULT_SRV 0x0012
#define NCP_BRIDGE_CMD_NETWORK_MDNS_RESULT_TXT 0x0013
#define NCP_BRIDGE_CMD_NETWORK_MDNS_RESULT_IP_ADDR 0x0014

/*Set UAP max client count status*/
#define WLAN_SET_MAX_CLIENT_CNT_SUCCESS          0
#define WLAN_SET_MAX_CLIENT_CNT_FAIL             1
#define WLAN_SET_MAX_CLIENT_CNT_START            2
#define WLAN_SET_MAX_CLIENT_CNT_EXCEED           3

#define ACTION_GET   0
#define ACTION_SET   1

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

/* DNS field TYPE used for "Resource Records" */
#define DNS_RRTYPE_A     1   /* a host address */
#define DNS_RRTYPE_PTR   12  /* a domain name pointer */
#define DNS_RRTYPE_AAAA  28  /* IPv6 address */
#define DNS_RRTYPE_SRV   33  /* service location */
#define DNS_RRTYPE_ANY   255 /* any type */

enum mdns_sd_proto {
  DNSSD_PROTO_UDP = 0,
  DNSSD_PROTO_TCP = 1
};

#define MDNS_ADDRTYPE_IPV4      0
#define MDNS_ADDRTYPE_IPV6      1

typedef MLAN_PACK_START struct _BRIDGE_COMMAND
{
    /*bit0 ~ bit15 cmd id  bit16 ~ bit23 cmd subclass bit24 ~ bit31 cmd class*/
    uint32_t cmd;
    uint16_t size;
    uint16_t seqnum;
    uint16_t result;
    uint16_t msg_type;
} MLAN_PACK_END NCP_MCU_BRIDGE_COMMAND, NCP_MCU_BRIDGE_RESPONSE;

typedef MLAN_PACK_START struct TLVTypeHeader_t
{
    uint16_t type;
    uint16_t size;
} MLAN_PACK_END TypeHeader_t, NCP_MCU_BRIDGE_TLV_HEADER;

/** Scan Result */
typedef MLAN_PACK_START struct _wlan_bridge_scan_result
{
    /** The network SSID, represented as a NULL-terminated C string of 0 to 32
     *  characters.  If the network has a hidden SSID, this will be the empty
     *  string.
     */
    char ssid[33];
    /** SSID length */
    unsigned int ssid_len;
    /** The network BSSID, represented as a 6-byte array. */
    char bssid[6];
    /** The network channel. */
    unsigned int channel;

    /* network features */

    /** The network supports WMM.  This is set to 0 if the network does not
     *  support WMM or if the system does not have WMM support enabled. */
    unsigned wmm : 1;
#ifdef CONFIG_WPS2
    /** The network supports WPS.  This is set to 0 if the network does not
     *  support WPS or if the system does not have WPS support enabled. */
    unsigned wps : 1;
    /** WPS Type PBC/PIN */
    unsigned int wps_session;
#endif
    /** WPA2 Enterprise security */
    unsigned wpa2_entp : 1;
    /** The network uses WEP security. */
    unsigned wep : 1;
    /** The network uses WPA security. */
    unsigned wpa : 1;
    /** The network uses WPA2 security */
    unsigned wpa2 : 1;
    /** The network uses WPA3 SAE security */
    unsigned wpa3_sae : 1;

    /** The signal strength of the beacon */
    unsigned char rssi;
    /** The network SSID, represented as a NULL-terminated C string of 0 to 32
     *  characters.  If the network has a hidden SSID, this will be the empty
     *  string.
     */
    char trans_ssid[33];
    /** SSID length */
    unsigned int trans_ssid_len;
    /** The network BSSID, represented as a 6-byte array. */
    char trans_bssid[6];

    /** Beacon Period */
    uint16_t beacon_period;

    /** DTIM Period */
    uint8_t dtim_period;
} MLAN_PACK_END wlan_bridge_scan_result;

typedef MLAN_PACK_START struct _NCP_CMD_SCAN_NETWORK_INFO
{
    uint8_t res_cnt;
    wlan_bridge_scan_result res[MCU_BRIDGE_MAX_AP_ENTRIES];
} MLAN_PACK_END NCP_CMD_SCAN_NETWORK_INFO;

typedef MLAN_PACK_START struct _NCP_CMD_WPS_GEN_PIN
{
    uint32_t pin;
} MLAN_PACK_END NCP_CMD_WPS_GEN_PIN;

typedef MLAN_PACK_START struct _NCP_CMD_WPS_PIN
{
    uint32_t pin;
} MLAN_PACK_END NCP_CMD_WPS_PIN;

/** RSSI information */
typedef MLAN_PACK_START struct
{
    /** Data RSSI last */
    int16_t data_rssi_last;
    /** Data nf last */
    int16_t data_nf_last;
    /** Data RSSI average */
    int16_t data_rssi_avg;
    /** Data nf average */
    int16_t data_nf_avg;
    /** BCN SNR */
    int16_t bcn_snr_last;
    /** BCN SNR average */
    int16_t bcn_snr_avg;
    /** Data SNR last */
    int16_t data_snr_last;
    /** Data SNR average */
    int16_t data_snr_avg;
    /** BCN RSSI */
    int16_t bcn_rssi_last;
    /** BCN nf */
    int16_t bcn_nf_last;
    /** BCN RSSI average */
    int16_t bcn_rssi_avg;
    /** BCN nf average */
    int16_t bcn_nf_avg;
} MLAN_PACK_END wlan_mcu_bridge_rssi_info_t;

typedef MLAN_PACK_START struct _MCU_NCP_CMD_RSSI
{
    wlan_mcu_bridge_rssi_info_t rssi_info;
} MLAN_PACK_END MCU_NCP_CMD_RSSI;

typedef MLAN_PACK_START struct _NCP_CMD_FW_VERSION
{
    /** Driver version string */
    char driver_ver_str[16];
    /** Firmware version string */
    char fw_ver_str[128];
} MLAN_PACK_END NCP_CMD_FW_VERSION;

typedef MLAN_PACK_START struct _NCP_CMD_CONNECT_STAT
{
    uint8_t ps_mode;
    uint8_t uap_conn_stat;
    uint8_t sta_conn_stat;
} MLAN_PACK_END NCP_CMD_CONNECT_STAT;

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

typedef MLAN_PACK_START struct _power_cfg_t
{
    uint8_t enable;
    uint8_t wake_mode;
    uint8_t subscribe_evt;
    uint32_t wake_duration;
    uint8_t is_mef;
    uint32_t wake_up_conds;
    uint8_t is_manual;
    uint32_t rtc_timeout;
    uint8_t wakeup_host;
} MLAN_PACK_END power_cfg_t;

/* Host wakes up MCU through interface */
#define WAKE_MODE_UART 0x1
/* Host wakes up MCU through GPIO */
#define WAKE_MODE_GPIO 0x2

typedef MLAN_PACK_START struct _MCU_NCP_CMD_POWERMGMT_MEF
{
    int type;
    uint8_t action;
} MLAN_PACK_END MCU_NCP_CMD_POWERMGMT_MEF;

typedef MLAN_PACK_START struct _MCU_NCP_CMD_POWERMGMT_UAPSD
{
    int enable;
} MLAN_PACK_END MCU_NCP_CMD_POWERMGMT_UAPSD;

typedef MLAN_PACK_START struct _MCU_NCP_CMD_POWERMGMT_QOSINFO
{
    uint8_t qos_info;
    /* 0 - get, 1 - set */
    uint8_t action;
} MLAN_PACK_END MCU_NCP_CMD_POWERMGMT_QOSINFO;

typedef MLAN_PACK_START struct _MCU_NCP_CMD_POWERMGMT_SLEEP_PERIOD
{
    uint32_t period;
    /* 0 - get, 1 - set */
    uint8_t action;
} MLAN_PACK_END MCU_NCP_CMD_POWERMGMT_SLEEP_PERIOD;

typedef MLAN_PACK_START struct _MCU_NCP_CMD_POWERMGMT_WAKE_CFG
{
    uint8_t wake_mode;
    uint8_t subscribe_evt;
    uint32_t wake_duration;
} MLAN_PACK_END MCU_NCP_CMD_POWERMGMT_WAKE_CFG;

typedef MLAN_PACK_START struct _MCU_NCP_CMD_POWERMGMT_WOWLAN_CFG
{
    uint8_t is_mef;
    uint8_t wake_up_conds;
} MLAN_PACK_END MCU_NCP_CMD_POWERMGMT_WOWLAN_CFG;

typedef MLAN_PACK_START struct _MCU_NCP_CMD_POWERMGMT_MCU_SLEEP
{
    uint8_t enable;
    uint8_t is_manual;
    int rtc_timeout;
} MLAN_PACK_END MCU_NCP_CMD_POWERMGMT_MCU_SLEEP;

typedef MLAN_PACK_START struct _MCU_NCP_CMD_POWERMGMT_SUSPEND
{
    int mode;
} MLAN_PACK_END MCU_NCP_CMD_POWERMGMT_SUSPEND;

typedef MLAN_PACK_START struct _MCU_NCP_CMD_POWERMGMT_WAKEUP_HOST
{
    uint8_t enable;
} MLAN_PACK_END MCU_NCP_CMD_POWERMGMT_WAKEUP_HOST;

/*NCP Bridge HE CAPA tlv*/
typedef MLAN_PACK_START struct _HE_CAP_ParamSet_t
{
    /** 0xff: Extension Capability IE */
    TypeHeader_t header;
    /** 35: HE capability */
    uint8_t ext_id;
    /** he mac capability info */
    uint8_t he_mac_cap[6];
    /** he phy capability info */
    uint8_t he_phy_cap[11];
    /** he txrx mcs support for 80MHz */
    uint8_t he_txrx_mcs_support[4];
    /** val for txrx mcs 160Mhz or 80+80, and PPE thresholds */
    uint8_t val[28];
} MLAN_PACK_END HE_CAP_ParamSet_t;

typedef MLAN_PACK_START struct _NCP_CMD_11AX_CFG
{
    /** band, BIT0:2.4G, BIT1:5G, both set for 2.4G and 5G*/
    uint8_t band;
    HE_CAP_ParamSet_t he_cap_tlv;
} MLAN_PACK_END NCP_CMD_11AX_CFG;

typedef MLAN_PACK_START struct _NCP_CMD_BTWT_CFG
{
    /** only support 1: Set */
    uint16_t action;
    /** 0x125: Broadcast TWT AP config */
    uint16_t sub_id;
    /** range 64-255 */
    uint8_t nominal_wake;
    /** Max STA Support */
    uint8_t max_sta_support;
    uint16_t twt_mantissa;
    uint16_t twt_offset;
    uint8_t twt_exponent;
    uint8_t sp_gap;
} MLAN_PACK_END NCP_CMD_BTWT_CFG;

typedef MLAN_PACK_START struct _NCP_CMD_TWT_SETUP
{
    /** Implicit, 0: TWT session is explicit, 1: Session is implicit */
    uint8_t implicit;
    /** Announced, 0: Unannounced, 1: Announced TWT */
    uint8_t announced;
    /** Trigger Enabled, 0: Non-Trigger enabled, 1: Trigger enabled TWT */
    uint8_t trigger_enabled;
    /** TWT Information Disabled, 0: TWT info enabled, 1: TWT info disabled */
    uint8_t twt_info_disabled;
    /** Negotiation Type, 0: Individual TWT, 3: Broadcast TWT */
    uint8_t negotiation_type;
    /** TWT Wakeup Duration, time after which the TWT requesting STA can
     * transition to doze state */
    uint8_t twt_wakeup_duration;
    /** Flow Identifier. Range: [0-7]*/
    uint8_t flow_identifier;
    /** Hard Constraint, 0: FW can tweak the TWT setup parameters if it is
     *rejected by AP.
     ** 1: Firmware should not tweak any parameters. */
    uint8_t hard_constraint;
    /** TWT Exponent, Range: [0-63] */
    uint8_t twt_exponent;
    /** TWT Mantissa Range: [0-sizeof(UINT16)] */
    uint16_t twt_mantissa;
    /** TWT Request Type, 0: REQUEST_TWT, 1: SUGGEST_TWT*/
    uint8_t twt_request;
} MLAN_PACK_END NCP_CMD_TWT_SETUP;

typedef MLAN_PACK_START struct _NCP_CMD_TWT_TEARDOWN
{
    /** TWT Flow Identifier. Range: [0-7] */
    uint8_t flow_identifier;
    /** Negotiation Type. 0: Future Individual TWT SP start time, 1: Next
     * Wake TBTT time */
    uint8_t negotiation_type;
    /** Tear down all TWT. 1: To teardown all TWT, 0 otherwise */
    uint8_t teardown_all_twt;
} MLAN_PACK_END NCP_CMD_TWT_TEARDOWN;

typedef MLAN_PACK_START struct _IEEE_BTWT_ParamSet_t
{
    /*
     *  [Bit 0]     request
     *  [Bit 1-3]   setup_cmd
     *  [Bit 4]     trigger
     *  [Bit 5]     last_broadcast_parameter_set
     *  [Bit 6]     flow_type
     *  [Bit 7-9]   btwt_recommendation
     *  [Bit 10-14] wake_interval_exponent
     *  [Bit 15]    reserved
     */
    uint16_t request_type;
    uint16_t target_wake_time;
    uint8_t nominal_min_wake_duration;
    uint16_t wake_interval_mantissa;
    /*
     *  [Bit 0-2]   reserved
     *  [Bit 3-7]   btwt_id
     *  [Bit 8-15]  btwt_persistence
     */
    uint16_t twt_info;
} MLAN_PACK_END IEEE_BTWT_ParamSet_t;

typedef MLAN_PACK_START struct _NCP_CMD_TWT_REPORT
{
    /** TWT report type, 0: BTWT id */
    uint8_t type;
    /** TWT report length of value in data */
    uint8_t length;
    uint8_t reserve[2];
    /** TWT report payload for FW response to fill, 4 * 9bytes */
    IEEE_BTWT_ParamSet_t info[4];
} MLAN_PACK_END NCP_CMD_TWT_REPORT;

typedef MLAN_PACK_START struct _NCP_CMD_11D_ENABLE
{
    /** 0 - STA, 1 - UAP */
    uint32_t role;
    /** 0 - disable, 1 - enable */
    uint32_t state;
} MLAN_PACK_END NCP_CMD_11D_ENABLE;

typedef MLAN_PACK_START struct _NCP_CMD_REGION_CODE
{
    /** 0 - get, 1 - set */
    uint32_t action;
    /** region code, 0xaa for world wide safe, 0x10 for US FCC, etc */
    uint32_t region_code;
} MLAN_PACK_END NCP_CMD_REGION_CODE;

typedef MLAN_PACK_START struct _NCP_CMD_SYSTEM_CFG
{
    /* the name of system config file: sys, prov, wlan */
    char module_name[16];
    /* the name of entry */
    char variable_name[32];
    /* set value/returned result */
    char value[256];
} MLAN_PACK_END NCP_CMD_SYSTEM_CFG;

typedef MLAN_PACK_START struct _NCP_CMD_CLIENT_CNT
{
    uint16_t max_sta_count;
    uint8_t set_status;
    uint8_t support_count;
} MLAN_PACK_END NCP_CMD_CLIENT_CNT;

typedef MLAN_PACK_START struct _NCP_CMD_ANTENNA_CFG
{
    uint8_t action;
    uint32_t antenna_mode;
    uint16_t evaluate_time;
    uint16_t current_antenna;
} MLAN_PACK_END  NCP_CMD_ANTENNA_CFG;

typedef MLAN_PACK_START struct _NCP_CMD_REGISTER_ACCESS
{
    uint8_t action;
    uint8_t type;
    uint32_t offset;
    uint32_t value;
} MLAN_PACK_END NCP_CMD_REGISTER_ACCESS;

typedef MLAN_PACK_START struct _NCP_CMD_MEM_STAT
{
    uint32_t free_heap_size;
    uint32_t minimun_ever_free_heap_size;
} MLAN_PACK_END NCP_CMD_MEM_STAT;

typedef MLAN_PACK_START struct _MCU_NCP_CMD_DEEP_SLEEP_PS
{
    int enable;
} MLAN_PACK_END MCU_NCP_CMD_DEEP_SLEEP_PS;

typedef MLAN_PACK_START struct _MCU_NCP_CMD_IEEE_PS
{
    int enable;
} MLAN_PACK_END MCU_NCP_CMD_IEEE_PS;

typedef MLAN_PACK_START struct _NCP_CMD_EU_VALIDATION
{
    uint8_t option;
    uint8_t res_buf[4];
} MLAN_PACK_END NCP_CMD_EU_VALIDATION;

typedef MLAN_PACK_START struct _NCP_CMD_ED_MAC
{
    uint8_t action;
    uint16_t ed_ctrl_2g;
    uint16_t ed_offset_2g;
#ifdef CONFIG_5GHz_SUPPORT
    uint16_t ed_ctrl_5g;
    uint16_t ed_offset_5g;
#endif
} MLAN_PACK_END NCP_CMD_ED_MAC;

#ifdef CONFIG_NCP_RF_TEST_MODE
typedef MLAN_PACK_START struct _NCP_CMD_RF_TX_ANTENNA
{
    uint8_t ant;
} MLAN_PACK_END NCP_CMD_RF_TX_ANTENNA;

typedef MLAN_PACK_START struct _NCP_CMD_RF_RX_ANTENNA
{
    uint8_t ant;
} MLAN_PACK_END NCP_CMD_RF_RX_ANTENNA;

typedef MLAN_PACK_START struct _NCP_CMD_RF_BAND
{
    uint8_t band;
} MLAN_PACK_END NCP_CMD_RF_BAND;

typedef MLAN_PACK_START struct _NCP_CMD_RF_BANDWIDTH
{
    uint8_t bandwidth;
} MLAN_PACK_END NCP_CMD_RF_BANDWIDTH;

typedef MLAN_PACK_START struct _NCP_CMD_RF_CHANNEL
{
    uint8_t channel;
} MLAN_PACK_END NCP_CMD_RF_CHANNEL;

typedef MLAN_PACK_START struct _NCP_CMD_RF_RADIO_MODE
{
    uint8_t radio_mode;
} MLAN_PACK_END NCP_CMD_RF_RADIO_MODE;

typedef MLAN_PACK_START struct _NCP_CMD_RF_TX_POWER
{
    uint8_t power;
    uint8_t mod;
    uint8_t path_id;
} MLAN_PACK_END NCP_CMD_RF_TX_POWER;

typedef MLAN_PACK_START struct _NCP_CMD_RF_TX_CONT_MODE
{
    uint32_t enable_tx;
    uint32_t cw_mode;
    uint32_t payload_pattern;
    uint32_t cs_mode;
    uint32_t act_sub_ch;
    uint32_t tx_rate;
} MLAN_PACK_END NCP_CMD_RF_TX_CONT_MODE;

typedef MLAN_PACK_START struct _NCP_CMD_RF_TX_FRAME
{
    uint32_t enable;
    uint32_t data_rate;
    uint32_t frame_pattern;
    uint32_t frame_length;
    uint32_t adjust_burst_sifs;
    uint32_t burst_sifs_in_us;
    uint32_t short_preamble;
    uint32_t act_sub_ch;
    uint32_t short_gi;
    uint32_t adv_coding;
    uint32_t tx_bf;
    uint32_t gf_mode;
    uint32_t stbc;
    uint8_t bssid[NCP_WLAN_MAC_ADDR_LENGTH];
} MLAN_PACK_END NCP_CMD_RF_TX_FRAME;

typedef MLAN_PACK_START struct _NCP_CMD_RF_PER
{
    uint32_t rx_tot_pkt_count;
    uint32_t rx_mcast_bcast_count;
    uint32_t rx_pkt_fcs_error;
} MLAN_PACK_END NCP_CMD_RF_PER;
#endif

typedef MLAN_PACK_START struct _NCP_CMD_MAC_ADDRESS
{
    uint8_t mac_addr[NCP_WLAN_MAC_ADDR_LENGTH];
} MLAN_PACK_END NCP_CMD_MAC_ADDRESS;

typedef MLAN_PACK_START struct _NCP_CMD_GET_MAC_ADDRESS
{
    uint8_t uap_mac[NCP_WLAN_MAC_ADDR_LENGTH];
    uint8_t sta_mac[NCP_WLAN_MAC_ADDR_LENGTH];
} MLAN_PACK_END NCP_CMD_GET_MAC_ADDRESS;

#ifdef CONFIG_WIFI_CAPA
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
#ifdef CONFIG_WPA_SUPP
    /** The network uses WPA2 security with PSK SHA256. */
    WLAN_SECURITY_WPA2_SHA256,
#ifdef CONFIG_11R
    /** The network uses WPA2 security with PSK FT. */
    WLAN_SECURITY_WPA2_FT,
#endif
#else
    /** The network uses WPA2 security with PSK(SHA-1 and SHA-256).This security mode
     * is specific to uAP or SoftAP only */
    WLAN_SECURITY_WPA2_SHA256,
#endif
    /** The network uses WPA/WPA2 mixed security with PSK */
    WLAN_SECURITY_WPA_WPA2_MIXED,
#if defined(CONFIG_WPA_SUPP_CRYPTO_ENTERPRISE) || defined(CONFIG_WPA2_ENTP)
    /** The network uses WPA2 Enterprise EAP-TLS security
     * The identity field in \ref wlan_network structure is used */
    WLAN_SECURITY_EAP_TLS,
#endif
#ifdef CONFIG_WPA_SUPP_CRYPTO_ENTERPRISE
    /** The network uses WPA2 Enterprise EAP-TLS SHA256 security
     * The identity field in \ref wlan_network structure is used */
    WLAN_SECURITY_EAP_TLS_SHA256,
#ifdef CONFIG_11R
    /** The network uses WPA2 Enterprise EAP-TLS FT security
     * The identity field in \ref wlan_network structure is used */
    WLAN_SECURITY_EAP_TLS_FT,
    /** The network uses WPA2 Enterprise EAP-TLS FT SHA384 security
     * The identity field in \ref wlan_network structure is used */
    WLAN_SECURITY_EAP_TLS_FT_SHA384,
#endif
    /** The network uses WPA2 Enterprise EAP-TTLS security
     * The identity field in \ref wlan_network structure is used */
    WLAN_SECURITY_EAP_TTLS,
    /** The network uses WPA2 Enterprise TTLS-MSCHAPV2 security
     * The anonymous identity, identity and password fields in
     * \ref wlan_network structure are used */
    WLAN_SECURITY_EAP_TTLS_MSCHAPV2,
/** The network uses WPA2 Enterprise PEAP-MSCHAPV2 security
 * The anonymous identity, identity and password fields in
 * \ref wlan_network structure are used */
#endif
#if defined(CONFIG_WPA_SUPP_CRYPTO_ENTERPRISE) || defined(CONFIG_PEAP_MSCHAPV2) || defined(CONFIG_WPA2_ENTP)
    WLAN_SECURITY_EAP_PEAP_MSCHAPV2,
/** The network uses WPA2 Enterprise PEAP-MSCHAPV2 security
 * The anonymous identity, identity and password fields in
 * \ref wlan_network structure are used */
#endif
#ifdef CONFIG_WPA_SUPP_CRYPTO_ENTERPRISE
    WLAN_SECURITY_EAP_PEAP_TLS,
    /** The network uses WPA2 Enterprise PEAP-MSCHAPV2 security
     * The anonymous identity, identity and password fields in
     * \ref wlan_network structure are used */
    WLAN_SECURITY_EAP_PEAP_GTC,
    /** The network uses WPA2 Enterprise TTLS-MSCHAPV2 security
     * The anonymous identity, identity and password fields in
     * \ref wlan_network structure are used */
    WLAN_SECURITY_EAP_FAST_MSCHAPV2,
    /** The network uses WPA2 Enterprise PEAP-MSCHAPV2 security
     * The anonymous identity, identity and password fields in
     * \ref wlan_network structure are used */
    WLAN_SECURITY_EAP_FAST_GTC,
    /** The network uses WPA2 Enterprise SIM security
     * The identity and password fields in
     * \ref wlan_network structure are used */
    WLAN_SECURITY_EAP_SIM,
    /** The network uses WPA2 Enterprise SIM security
     * The identity and password fields in
     * \ref wlan_network structure are used */
    WLAN_SECURITY_EAP_AKA,
    /** The network uses WPA2 Enterprise SIM security
     * The identity and password fields in
     * \ref wlan_network structure are used */
    WLAN_SECURITY_EAP_AKA_PRIME,
    /** The network can use any eap security method. This is often used when
     * the user only knows the name, identity and password but not the security
     * type.  */
    WLAN_SECURITY_EAP_WILDCARD,
#endif
    /** The network can use any security method. This is often used when
     * the user only knows the name and passphrase but not the security
     * type.  */
    WLAN_SECURITY_WILDCARD,
    /** The network uses WPA3 security with SAE. Also set the PMF settings using
     * \ref wlan_set_pmfcfg API required for WPA3 SAE */
    WLAN_SECURITY_WPA3_SAE,
#ifdef CONFIG_WPA_SUPP
#ifdef CONFIG_11R
    /** The network uses WPA2 security with SAE FT. */
    WLAN_SECURITY_WPA3_SAE_FT,
#endif
#endif
    /** The network uses WPA2/WPA3 SAE mixed security with PSK. This security mode
     * is specific to uAP or SoftAP only */
    WLAN_SECURITY_WPA2_WPA3_SAE_MIXED,
#ifdef CONFIG_OWE
    /** The network uses OWE only security without Transition mode support. */
    WLAN_SECURITY_OWE_ONLY,
#endif
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

/*Bridge Wlan Socket Open*/
#define HTTP_PARA_LEN 16
#define SETH_NAME_LENGTH  64
#define SETH_VALUE_LENGTH 128
#define HTTP_URI_LEN 512
typedef MLAN_PACK_START struct _NCP_CMD_SOCKET_OPEN_CFG
{
    char socket_type[HTTP_PARA_LEN];
    char domain_type[HTTP_PARA_LEN];
    char procotol[HTTP_PARA_LEN];
    uint32_t opened_handle;
} MLAN_PACK_END NCP_CMD_SOCKET_OPEN_CFG;

/*Bridge Wlan Socket Connect*/
#define IP_ADDR_LEN 16
typedef MLAN_PACK_START struct _NCP_CMD_SOCKET_CON_CFG
{
    uint32_t handle;
    uint32_t port;
    char ip_addr[IP_ADDR_LEN];
} MLAN_PACK_END NCP_CMD_SOCKET_CON_CFG;

/*Bridge Wlan Socket Bind*/
typedef MLAN_PACK_START struct _NCP_CMD_SOCKET_BIND_CFG
{
    uint32_t handle;
    uint32_t port;
    char ip_addr[IP_ADDR_LEN];
} MLAN_PACK_END NCP_CMD_SOCKET_BIND_CFG;

/*Bridge Wlan Socket Close*/
typedef MLAN_PACK_START struct _NCP_CMD_SOCKET_CLOSE_CFG
{
    uint32_t handle;
} MLAN_PACK_END NCP_CMD_SOCKET_CLOSE_CFG;

/*Bridge Wlan Socket Listen*/
typedef MLAN_PACK_START struct _NCP_CMD_SOCKET_LISTEN_CFG
{
    uint32_t handle;
    uint32_t number;
} MLAN_PACK_END NCP_CMD_SOCKET_LISTEN_CFG;

/*Bridge Wlan Socket Accept*/
typedef MLAN_PACK_START struct _NCP_CMD_SOCKET_ACCEPT_CFG
{
    uint32_t handle;
    int accepted_handle;
} MLAN_PACK_END NCP_CMD_SOCKET_ACCEPT_CFG;

/*Bridge Wlan Socket Send*/
typedef MLAN_PACK_START struct _NCP_CMD_SOCKET_SEND_CFG
{
    uint32_t handle;
    uint32_t size;
    char send_data[1];
} MLAN_PACK_END NCP_CMD_SOCKET_SEND_CFG;

/*Bridge Wlan Socket Sendto*/
typedef MLAN_PACK_START struct _NCP_CMD_SOCKET_SENDTO_CFG
{
    uint32_t handle;
    uint32_t size;
    char ip_addr[IP_ADDR_LEN];
    uint32_t port;
    char send_data[1];
} MLAN_PACK_END NCP_CMD_SOCKET_SENDTO_CFG;

/*Bridge Wlan Socket Receive*/
typedef MLAN_PACK_START struct _NCP_CMD_SOCKET_RECEIVE_CFG
{
    uint32_t handle;
    uint32_t size;
    uint32_t timeout;
    char recv_data[1];
} MLAN_PACK_END NCP_CMD_SOCKET_RECEIVE_CFG;

/*Bridge Wlan Socket Recvfrom*/
typedef MLAN_PACK_START struct _NCP_CMD_SOCKET_RECVFROM_CFG
{
    uint32_t handle;
    uint32_t size;
    uint32_t timeout;
    char peer_ip[IP_ADDR_LEN];
    uint32_t peer_port;
    char recv_data[1];
} MLAN_PACK_END NCP_CMD_SOCKET_RECVFROM_CFG;

/*Bridge Wlan Http Connect*/
typedef MLAN_PACK_START struct _MPU_NCP_CMD_HTTP_CONNECT_CFG
{
    int opened_handle;
    char host[1];
} MLAN_PACK_END NCP_CMD_HTTP_CON_CFG;

/*Bridge Wlan Http Disconnect*/
typedef MLAN_PACK_START struct _MPU_NCP_CMD_HTTP_DISCONNECT_CFG
{
    uint32_t handle;
} MLAN_PACK_END NCP_CMD_HTTP_DISCON_CFG;

/*Bridge Wlan Http Seth*/
typedef MLAN_PACK_START struct _MPU_NCP_CMD_HTTP_SETH_CFG
{
    char name[SETH_NAME_LENGTH];
    char value[SETH_VALUE_LENGTH];
} MLAN_PACK_END NCP_CMD_HTTP_SETH_CFG;

/*Bridge Wlan Http Unseth*/
typedef MLAN_PACK_START struct _MPU_NCP_CMD_HTTP_UNSETH_CFG
{
    char name[SETH_NAME_LENGTH];
} MLAN_PACK_END NCP_CMD_HTTP_UNSETH_CFG;

/*Bridge Wlan Http Req*/
typedef MLAN_PACK_START struct _MPU_NCP_CMD_HTTP_REQ_CFG
{
    uint32_t handle;
    char method[HTTP_PARA_LEN];
    char uri[HTTP_URI_LEN];
    uint32_t req_size;
    char req_data[1];
} MLAN_PACK_END NCP_CMD_HTTP_REQ_CFG;

/*Bridge Wlan Http Recv Resp*/
typedef MLAN_PACK_START struct _MPU_NCP_CMD_HTTP_REQ_RESP_CFG
{
    uint32_t header_size;
    char recv_header[1];
} MLAN_PACK_END NCP_CMD_HTTP_REQ_RESP_CFG;

/*Bridge Wlan Http Recv*/
typedef MLAN_PACK_START struct _MPU_NCP_CMD_HTTP_RECV_CFG
{
    uint32_t handle;
    uint32_t size;
    uint32_t timeout;
    char recv_data[1];
} MLAN_PACK_END NCP_CMD_HTTP_RECV_CFG;

/*Bridge Wlan Http Upgrade*/
typedef MLAN_PACK_START struct _MPU_NCP_CMD_HTTP_UPG_CFG
{
    uint32_t handle;
    char     uri[HTTP_URI_LEN];
    char     protocol[HTTP_PARA_LEN];
} MLAN_PACK_END NCP_CMD_HTTP_UPG_CFG;

/*Bridge Wlan Socket Send*/
typedef MLAN_PACK_START struct _MPU_NCP_CMD_WEBSOCKET_SEND_CFG
{
    uint32_t handle;
    char type[HTTP_PARA_LEN];
    uint32_t size;
    char send_data[1];
} MLAN_PACK_END NCP_CMD_WEBSOCKET_SEND_CFG;


/*Bridge Wlan Websocket Receive*/
typedef MLAN_PACK_START struct _MPU_NCP_CMD_WEBSOCKET_RECV_CFG
{
    uint32_t handle;
    uint32_t size;
    uint32_t timeout;
    uint32_t fin;
    char recv_data[1];
} MLAN_PACK_END NCP_CMD_WEBSOCKET_RECV_CFG;

#ifdef CONFIG_IPV6
/** This data structure represents an IPv6 address */
typedef MLAN_PACK_START struct _wlan_bridge_ipv6_config
{
    /** The system's IPv6 address in network order. */
    unsigned address[4];
    /** The address type: linklocal, site-local or global. */
    unsigned char addr_type_str[16];
    /** The state of IPv6 address (Tentative, Preferred, etc). */
    unsigned char addr_state_str[32];
} MLAN_PACK_END wlan_bridge_ipv6_config;
#endif

/** This data structure represents an IPv4 address */
typedef MLAN_PACK_START struct _wlan_bridge_ipv4_config
{
    /** Set to \ref ADDR_TYPE_DHCP to use DHCP to obtain the IP address or
     *  \ref ADDR_TYPE_STATIC to use a static IP. In case of static IP
     *  address ip, gw, netmask and dns members must be specified.  When
     *  using DHCP, the ip, gw, netmask and dns are overwritten by the
     *  values obtained from the DHCP server. They should be zeroed out if
     *  not used. */
    uint32_t addr_type : 2;
    /** The system's IP address in network order. */
    uint32_t address;
    /** The system's default gateway in network order. */
    uint32_t gw;
    /** The system's subnet mask in network order. */
    uint32_t netmask;
    /** The system's primary dns server in network order. */
    uint32_t dns1;
    /** The system's secondary dns server in network order. */
    uint32_t dns2;
} MLAN_PACK_END wlan_bridge_ipv4_config;

/** WLAN Network Profile
 *  This data structure represents a WLAN network profile. It consists of an
 *  arbitrary name, WiFi configuration, and IP address configuration.
 */
typedef MLAN_PACK_START struct _wlan_bridge_network
{
    /** The name of this network profile. */
    char name[32];
    /** The network SSID, represented as a C string of up to 32 characters
     *  in length.
     *  If this profile is used in the micro-AP mode, this field is
     *  used as the SSID of the network.
     *  If this profile is used in the station mode, this field is
     *  used to identify the network. Set the first byte of the SSID to NULL
     *  (a 0-length string) to use only the BSSID to find the network.
     */
    char ssid[32 + 1];
    /** The network BSSID, represented as a 6-byte array.
     *  If this profile is used in the micro-AP mode, this field is
     *  ignored.
     *  If this profile is used in the station mode, this field is
     *  used to identify the network. Set all 6 bytes to 0 to use any BSSID,
     *  in which case only the SSID will be used to find the network.
     */
    char bssid[6];
    /** The channel for this network.
     *  If this profile is used in micro-AP mode, this field
     *  specifies the channel to start the micro-AP interface on. Set this
     *  to 0 for auto channel selection.
     *  If this profile is used in the station mode, this constrains the
     *  channel on which the network to connect should be present. Set this
     *  to 0 to allow the network to be found on any channel. */
    unsigned int channel;
    /** The ACS band if set channel to 0. **/
    uint16_t acs_band;
#ifdef CONFIG_SCAN_WITH_RSSIFILTER
    /** Rssi threshold */
    short rssi_threshold;
#endif
    /** BSS type */
    uint8_t type;
    /** The network wireless mode enum wlan_bss_role. Set this
     *  to specify what type of wireless network mode to use.
     *  This can either be \ref WLAN_BSS_ROLE_STA for use in
     *  the station mode, or it can be \ref WLAN_BSS_ROLE_UAP
     *  for use in the micro-AP mode.
     */
    uint8_t role;

    /** Type of network security to use specified by enum
     * wlan_security_type. */
    uint8_t security_type;

    uint8_t enable_11ax : 1;
    uint8_t enable_11ac : 1;
    uint8_t enable_11n : 1;

    /** The network IP address configuration. */
#ifdef CONFIG_IPV6
    /** The network IPv6 address configuration */
    wlan_bridge_ipv6_config ipv6[CONFIG_MAX_IPV6_ADDRESSES];
#endif
    /** The network IPv4 address configuration */
    wlan_bridge_ipv4_config ipv4;

    uint8_t is_sta_ipv4_connected;

#ifdef CONFIG_WPA2_ENTP
    char identity[64];
#endif

    /* Private Fields */
    /** If set to 1, the ssid field contains the specific SSID for this
     * network.*/
    unsigned ssid_specific : 1;
    /** If set to 1, the bssid field contains the specific BSSID for this
     *  network. */
    unsigned bssid_specific : 1;
    /** If set to 1, the channel field contains the specific channel for this
     * network. */
    unsigned channel_specific : 1;
    /** If set to 0, any security that matches is used. */
    unsigned security_specific : 1;
#ifdef CONFIG_WPS2
    /** This indicates this network is used as an internal network for
     * WPS */
    unsigned wps_specific : 1;
#endif
    /** Beacon period of associated BSS */
    uint16_t beacon_period;
    /** DTIM period of associated BSS */
    uint8_t dtim_period;
#ifdef CONFIG_WIFI_CAPA
    uint8_t wlan_capa;
#endif
} MLAN_PACK_END wlan_bridge_network;

typedef MLAN_PACK_START struct _NCP_CMD_NETWORK_INFO
{
    uint8_t uap_conn_stat;
    uint8_t sta_conn_stat;
    wlan_bridge_network uap_network;
    wlan_bridge_network sta_network;
} MLAN_PACK_END NCP_CMD_NETWORK_INFO;

typedef MLAN_PACK_START struct _NCP_CMD_NETWORK_LIST
{
    uint8_t count;
    wlan_bridge_network net_list[1];
} MLAN_PACK_END NCP_CMD_NETWORK_LIST;

typedef MLAN_PACK_START struct _NCP_CMD_NETWORK_REMOVE
{
    char name[WLAN_NETWORK_NAME_MAX_LENGTH + 1];
    int8_t remove_state;
} MLAN_PACK_END NCP_CMD_NETWORK_REMOVE;

typedef MLAN_PACK_START struct _SSID_ParamSet_t
{
    TypeHeader_t header;
    char ssid[32 + 1];
} MLAN_PACK_END SSID_ParamSet_t;

/*NCP Bridge BSSID tlv*/
typedef MLAN_PACK_START struct _BSSID_ParamSet_t
{
    TypeHeader_t header;
    char bssid[6];
} MLAN_PACK_END BSSID_ParamSet_t;

/*NCP Bridge bss role tlv*/
typedef MLAN_PACK_START struct _BSSRole_ParamSet_t
{
    TypeHeader_t header;
    uint8_t role;
} MLAN_PACK_END BSSRole_ParamSet_t;

/*NCP Bridge channel tlv*/
typedef MLAN_PACK_START struct _Channel_ParamSet_t
{
    TypeHeader_t header;
    uint8_t channel;
} MLAN_PACK_END Channel_ParamSet_t;

/*NCP Bridge acs_band tlv*/
typedef MLAN_PACK_START struct _ACSBand_ParamSet_t
{
    TypeHeader_t header;
    uint16_t acs_band;
} MLAN_PACK_END ACSBand_ParamSet_t;

/*NCP Bridge IP address tlv*/
typedef MLAN_PACK_START struct _IP_ParamSet_t
{
    TypeHeader_t header;
    uint8_t is_autoip;
    uint32_t address;
    uint32_t gateway;
    uint32_t netmask;
    uint32_t dns1;
    uint32_t dns2;
} MLAN_PACK_END IP_ParamSet_t;

/*NCP Bridge security tlv*/
typedef MLAN_PACK_START struct _Security_ParamSet_t
{
    TypeHeader_t header;
    uint8_t type;
    uint8_t password_len;
    char password[1];
} MLAN_PACK_END Security_ParamSet_t;

/*NCP Bridge PMF tlv*/
typedef MLAN_PACK_START struct _PMF_ParamSet_t
{
    TypeHeader_t header;
    uint8_t mfpc;
    uint8_t mfpr;
} MLAN_PACK_END PMF_ParamSet_t;

#ifdef CONFIG_WIFI_DTIM_PERIOD
/*NCP Bridge DTIM tlv*/
typedef MLAN_PACK_START struct _DTIM_ParamSet_t
{
    TypeHeader_t header;
    uint8_t dtim_period;
} MLAN_PACK_END DTIM_ParamSet_t;
#endif

#ifdef CONFIG_WIFI_CAPA
/*NCP Bridge CAPA tlv*/
typedef MLAN_PACK_START struct _CAPA_ParamSet_t
{
    TypeHeader_t header;
    uint8_t capa;
} MLAN_PACK_END CAPA_ParamSet_t;
#endif

typedef MLAN_PACK_START struct _NCP_CMD_NETWORK_ADD
{
    char name[32];
    /** Length of TLVs sent in command starting at tlvBuffer */
    uint32_t tlv_buf_len;
    /**
     * SSID TLV, SSID_ParamSet_t
     * BSSID TLV, BSSID_ParamSet_t
     * BSS role TLV, BSSRole_ParamSet_t
     * Channel TLV, Channel_ParamSet_t
     * ACS band TLV, ACSBand_ParamSet_t
     * IP address TLV, IP_ParamSet_t
     * Security TLV, Security_ParamSet_t
     * DTIM period TLV, DTIM_ParamSet_t
     * CAPA TLV, CAPA_ParamSet_t
     */
    uint8_t tlv_buf[1];
} MLAN_PACK_END NCP_CMD_NETWORK_ADD;

typedef MLAN_PACK_START struct _NCP_CMD_NETWORK_START
{
    char name[32];
    char ssid[32 + 1];
} MLAN_PACK_END NCP_CMD_NETWORK_START;

/** Station information structure */
typedef MLAN_PACK_START struct _wlan_bridge_sta_info
{
    /** MAC address buffer */
    uint8_t mac[6];
    /**
     * Power management status
     * 0 = active (not in power save)
     * 1 = in power save status
     */
    uint8_t power_mgmt_status;
    /** RSSI: dBm */
    signed char rssi;
} MLAN_PACK_END wlan_bridge_sta_info;

typedef MLAN_PACK_START struct _NCP_CMD_NETWORK_UAP_STA_LIST
{
    /** station count */
    uint16_t sta_count;
    /** station list */
    wlan_bridge_sta_info info[16];
} MLAN_PACK_END NCP_CMD_NETWORK_UAP_STA_LIST;

typedef MLAN_PACK_START struct _wlan_date_time_t
{
    uint32_t action;
    uint16_t year;  /*!< Range from 1970 to 2099.*/
    uint8_t month;  /*!< Range from 1 to 12.*/
    uint8_t day;    /*!< Range from 1 to 31 (depending on month).*/
    uint8_t hour;   /*!< Range from 0 to 23.*/
    uint8_t minute; /*!< Range from 0 to 59.*/
    uint8_t second; /*!< Range from 0 to 59.*/
} MLAN_PACK_END wlan_date_time_t;

typedef MLAN_PACK_START struct _NCP_CMD_DATE_TIME
{
    uint32_t action;
    wlan_date_time_t date_time;
} MLAN_PACK_END NCP_CMD_DATE_TIME;

typedef MLAN_PACK_START struct _NCP_CMD_TEMPERATURE
{
    uint32_t temp;
} MLAN_PACK_END NCP_CMD_TEMPERATURE;

typedef MLAN_PACK_START struct _NCP_CMD_WLAN_CONN
{
    char name[32];
    uint32_t ip;
    char ssid[32 + 1];
} MLAN_PACK_END NCP_CMD_WLAN_CONN;

#define NCP_WLAN_DEFAULT_RSSI_THRESHOLD 70

typedef MLAN_PACK_START struct _NCP_CMD_ROAMING
{
    uint32_t enable;
    uint8_t rssi_threshold;
} MLAN_PACK_END NCP_CMD_ROAMING;

#define PING_INTERVAL 1000
#define PING_DEFAULT_TIMEOUT_SEC 2
#define PING_DEFAULT_COUNT       10
#define PING_DEFAULT_SIZE        56
#define PING_MAX_SIZE            65507

#define PING_ID 0xAFAF

#define IP_ADDR_LEN 16

MLAN_PACK_START struct icmp_echo_hdr {
    uint8_t type;
    uint8_t code;
    uint16_t chksum;
    uint16_t id;
    uint16_t seqno;
} MLAN_PACK_END;

MLAN_PACK_START struct ip_hdr {
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
#define IP_RF 0x8000U        /* reserved fragment flag */
#define IP_DF 0x4000U        /* don't fragment flag */
#define IP_MF 0x2000U        /* more fragments flag */
#define IP_OFFMASK 0x1fffU   /* mask for fragmenting bits */
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

typedef MLAN_PACK_START struct _iperf_msg_t
{
    uint16_t size;
    uint32_t count;
    uint32_t timeout;
    uint32_t handle;
    char ip_addr[IP_ADDR_LEN];
    uint32_t port;
    char status[2];
} MLAN_PACK_END iperf_msg_t;


/** Network monitor structure */
typedef MLAN_PACK_START struct _wlan_bridge_net_monitor_para
{
    /** Action */
    uint16_t action;
    /** Monitor activity */
    uint16_t monitor_activity;
    /** Filter flags */
    uint16_t filter_flags;
    /** Channel scan parameter : Radio type */
    uint8_t radio_type;
    /** Channel number */
    uint8_t chan_number;
    /** mac num of filter*/
    uint8_t filter_num;
    /** Source address of the packet to receive */
    uint8_t mac_addr[MAX_MONIT_MAC_FILTER_NUM][NCP_WLAN_MAC_ADDR_LENGTH];
} MLAN_PACK_END wlan_bridge_net_monitor_para;

typedef MLAN_PACK_START struct _MCU_NCP_CMD_NET_MONITOR
{
    wlan_bridge_net_monitor_para monitor_para;
} MLAN_PACK_END MCU_NCP_CMD_NET_MONITOR;

#define CSI_FILTER_MAX 16
/** Structure of CSI filters */
typedef MLAN_PACK_START struct _wlan_csi_filter_t
{
    /** Source address of the packet to receive */
    uint8_t mac_addr[NCP_WLAN_MAC_ADDR_LENGTH];
    /** Pakcet type of the interested CSI */
    uint8_t pkt_type;
    /* Packet subtype of the interested CSI */
    uint8_t subtype;
    /* Other filter flags */
    uint8_t flags;
} MLAN_PACK_END wlan_csi_filter_t;

/** Structure of CSI parameters */
typedef MLAN_PACK_START struct _wlan_csi_config_params_t
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
    wlan_csi_filter_t csi_filter[CSI_FILTER_MAX];
} MLAN_PACK_END wlan_csi_config_params_t;

typedef MLAN_PACK_START struct _MCU_NCP_CMD_CSI
{
    wlan_csi_config_params_t csi_para;
} MLAN_PACK_END MCU_NCP_CMD_CSI;

typedef MLAN_PACK_START struct _MCU_NCP_CMD_11K_CFG
{
    int enable;
} MLAN_PACK_END MCU_NCP_CMD_11K_CFG;

typedef MLAN_PACK_START struct _MCU_NCP_CMD_NEIGHBOR_REQ
{
    SSID_ParamSet_t ssid_tlv;
} MLAN_PACK_END MCU_NCP_CMD_NEIGHBOR_REQ;

typedef MLAN_PACK_START struct _QUERY_PTR_CFG
{
    /** Type of service, like '_http' */
    char service[63 + 1];
    /** Protocol, TCP or UDP */
    uint16_t proto;
} MLAN_PACK_END QUERY_PTR_CFG;

typedef MLAN_PACK_START struct _QUERY_A_CFG
{
    /** Domain name, like 'wifi-http.local' */
    char name[63 + 1];
} MLAN_PACK_END QUERY_A_CFG;

typedef MLAN_PACK_START struct _NCP_CMD_MDNS_QUERY
{
    /** Query type (PTR, SRV, A, AAAA...) */
    uint8_t qtype;
    union
    {
        QUERY_PTR_CFG ptr_cfg;
        QUERY_A_CFG a_cfg;
    } Q;
} MLAN_PACK_END NCP_CMD_MDNS_QUERY;

/*NCP Bridge PTR RR tlv*/
typedef MLAN_PACK_START struct _PTR_ParamSet_t
{
    TypeHeader_t header;
    /* instance name */
    char instance_name[63 + 1];
    /* service type */
    char service_type[63 + 1];
    /* srevice protocol */
    char proto[8];
} MLAN_PACK_END PTR_ParamSet_t;

/*NCP Bridge SRV RR tlv*/
typedef MLAN_PACK_START struct _SRV_ParamSet_t
{
    TypeHeader_t header;
    /* host name */
    char host_name[63 + 1];
    /* service port */
    uint16_t port;
    /* target name */
    char target[63 + 1];
} MLAN_PACK_END SRV_ParamSet_t;

/*NCP Bridge TXT RR tlv*/
typedef MLAN_PACK_START struct _TXT_ParamSet_t
{
    TypeHeader_t header;
    /* txt value len */
    uint8_t txt_len;
    /* txt string */
    char txt[63 + 1];
} MLAN_PACK_END TXT_ParamSet_t;

/*NCP Bridge A&AAAA RR tlv*/
typedef MLAN_PACK_START struct _IP_ADDR_ParamSet_t
{
    TypeHeader_t header;
    uint8_t addr_type;
    /* ip address */
    union {
        uint32_t ip_v4;
        uint32_t ip_v6[4];
    } ip;
} MLAN_PACK_END IP_ADDR_ParamSet_t;

typedef MLAN_PACK_START struct _NCP_EVT_MDNS_RESULT
{
    /* time to live */
    uint32_t ttl;
    /** Length of TLVs sent in command starting at tlvBuffer */
    uint32_t tlv_buf_len;
    /**
     *  PTR, PTR_ParamSet_t
     *  SRV, SRV_ParamSet_t
     *  TXT, TXT_ParamSet_t
     *  A&AAAA, IP_ADDR_ParamSet_t
     */
    uint8_t tlv_buf[1];
} MLAN_PACK_END NCP_EVT_MDNS_RESULT;

typedef MLAN_PACK_START struct _NCP_EVT_MDNS_RESOLVE
{
    uint8_t ip_type;
    union {
      uint32_t ip6_addr[4];
      uint32_t ip4_addr;
    } u_addr;
} MLAN_PACK_END NCP_EVT_MDNS_RESOLVE;

typedef MLAN_PACK_START struct _MCU_NCP_CMD_MBO_CFG
{
    int enable;
} MLAN_PACK_END MCU_NCP_CMD_MBO_CFG;

typedef MLAN_PACK_START struct _MBO_NONPREFER_CH
{
    uint8_t ch0;
    uint8_t ch1;
    uint8_t preference0;
    uint8_t preference1;
} MLAN_PACK_END MBO_NONPREFER_CH;

typedef MLAN_PACK_START struct _MBO_NONPREFER_CH_SUPP
{
    char mbo_nonprefer_ch_params[32];
} MLAN_PACK_END MBO_NONPREFER_CH_SUPP;

typedef MLAN_PACK_START struct _MCU_NCP_CMD_MBO_NONPREFER_CH
{
    union{
        MBO_NONPREFER_CH mbo_nonprefer_ch_cfg;
        MBO_NONPREFER_CH_SUPP mbo_nonprefer_ch_supp_cfg;
    } NONPREFER_CH_CFG;
} MLAN_PACK_END MCU_NCP_CMD_MBO_NONPREFER_CH;

typedef MLAN_PACK_START struct _MCU_NCP_CMD_MBO_SET_CELL_CAPA
{
    uint8_t cell_capa;
} MLAN_PACK_END MCU_NCP_CMD_MBO_SET_CELL_CAPA;

typedef MLAN_PACK_START struct _MCU_NCP_CMD_MBO_SET_OCE
{
    uint8_t oce;
} MLAN_PACK_END MCU_NCP_CMD_MBO_SET_OCE;

typedef MLAN_PACK_START struct _MCU_NCPCmd_DS_COMMAND
{
    /** Command Header : Command */
    NCP_MCU_BRIDGE_COMMAND header;
    /** Command Body */
    union
    {
        /** Scan result*/
        NCP_CMD_SCAN_NETWORK_INFO scan_network_info;
        NCP_CMD_WPS_GEN_PIN wps_gen_pin_info;
        NCP_CMD_WPS_PIN wps_pin_cfg;
        /** RSSI information*/
        MCU_NCP_CMD_RSSI signal_rssi;
        /** Firmware version*/
        NCP_CMD_FW_VERSION fw_version;
        /** wlan connnection state */
        NCP_CMD_CONNECT_STAT conn_stat;
        /** Roaming configuration */
        NCP_CMD_ROAMING roaming;
        /** wlan multi MEF config */
        MCU_NCP_CMD_POWERMGMT_MEF mef_config;
        /** wlan deep sleep ps*/
        MCU_NCP_CMD_DEEP_SLEEP_PS wlan_deep_sleep_ps;
        /** wlan ieee ps*/
        MCU_NCP_CMD_IEEE_PS wlan_ieee_ps;
        MCU_NCP_CMD_POWERMGMT_UAPSD uapsd_cfg;
        MCU_NCP_CMD_POWERMGMT_QOSINFO qosinfo_cfg;
        MCU_NCP_CMD_POWERMGMT_SLEEP_PERIOD sleep_period_cfg;
        /** wlan wake config */
        MCU_NCP_CMD_POWERMGMT_WAKE_CFG wake_config;
        /** wlan wowlan config */
        MCU_NCP_CMD_POWERMGMT_WOWLAN_CFG wowlan_config;
        /** wlan mcu sleep config */
        MCU_NCP_CMD_POWERMGMT_MCU_SLEEP mcu_sleep_config;
        /** wlan suspend config */
        MCU_NCP_CMD_POWERMGMT_SUSPEND suspend_config;
        /** wlan host wakeup */
        MCU_NCP_CMD_POWERMGMT_WAKEUP_HOST host_wakeup_ctrl;

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
        MCU_NCP_CMD_NET_MONITOR monitor_cfg;
        MCU_NCP_CMD_CSI csi_cfg;
        MCU_NCP_CMD_11K_CFG wlan_11k_cfg;
        MCU_NCP_CMD_NEIGHBOR_REQ neighbor_req;

        /** MBO **/
        MCU_NCP_CMD_MBO_CFG wlan_mbo_cfg;
        MCU_NCP_CMD_MBO_NONPREFER_CH mbo_nonprefer_ch_params;
        MCU_NCP_CMD_MBO_SET_CELL_CAPA wlan_mbo_set_cell_capa;
        MCU_NCP_CMD_MBO_SET_OCE wlan_mbo_set_oce;

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

#ifdef CONFIG_MEM_MONITOR_DEBUG
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

#ifdef CONFIG_MEM_MONITOR_DEBUG
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

int mcu_bridge_cli_command_init();

int wlan_process_monitor_response(uint8_t *res);

int wlan_process_csi_response(uint8_t *res);

int wlan_process_11k_cfg_response(uint8_t *res);

int wlan_process_neighbor_req_response(uint8_t *res);

int wlan_process_network_list_response(uint8_t *res);

int wlan_process_network_remove_response(uint8_t *res);

MCU_NCPCmd_DS_COMMAND *ncp_mcu_bridge_get_command_buffer();

int wlan_process_mbo_enable_response(uint8_t *res);

int wlan_process_mbo_nonprefer_ch_response(uint8_t *res);

int wlan_process_mbo_set_cell_capa_response(uint8_t *res);

int wlan_process_mbo_set_oce_response(uint8_t *res);

#endif /*__MCU_BRIDGE_COMMAND_H_*/
