
#ifndef __MPU_BRIDGE_COMMAND_H__
#define __MPU_BRIDGE_COMMAND_H__
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/times.h>
#include "mpu_bridge_wifi_config.h"

#define NCP_BRIDGE_CMD_HEADER_LEN sizeof(NCP_BRIDGE_COMMAND)
#define NCP_BRIDGE_TLV_HEADER_LEN sizeof(NCP_BRIDGE_TLV_HEADER)

#define MACSTR                    "%02X:%02X:%02X:%02X:%02X:%02X "
#define MAC2STR(a)                a[0], a[1], a[2], a[3], a[4], a[5]
#define NCP_BRIDGE_MAX_AP_ENTRIES 30
#define NCP_BRIDGE_IP_LENGTH      4
#define NCP_BRIDGE_IP_VALID       255

#define WLAN_NETWORK_NAME_MAX_LENGTH    32
#define IEEEtypes_SSID_SIZE             32
#define IEEEtypes_ADDRESS_SIZE          6
#define NCP_BRIDGE_WLAN_KNOWN_NETWORKS  5
#define MAX_NUM_CLIENTS                 16
#define MODULE_NAME_MAX_LEN             16
#define VAR_NAME_MAX_LEN                32
#define CONFIG_VALUE_MAX_LEN            256


#define NCP_BRIDGE_CMD_WLAN 0x00000000
#define NCP_BRIDGE_CMD_BLE    0x01000000
#define NCP_BRIDGE_CMD_15D4   0x02000000
#define NCP_BRIDGE_CMD_MATTER 0x03000000
#define NCP_BRIDGE_CMD_SYSTEM 0x04000000

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

/*NCP MPU Bridge Command definitions*/
/*WLAN STA command*/
#define NCP_BRIDGE_CMD_WLAN_STA_SCAN \
    (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_STA | 0x00000001) /* wlan-scan */
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
#define NCP_BRIDGE_CMD_WLAN_STA_ANTENNA       (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_STA | 0x00000009)  /* wlan-set-antenna / wlan-get-antenna*/
#define NCP_BRIDGE_CMD_WLAN_STA_SIGNAL \
    (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_STA | 0x00000012) /* wlan-get-signal */
#define NCP_BRIDGE_CMD_WLAN_STA_CSI          (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_STA | 0x00000020)
#define NCP_BRIDGE_CMD_WLAN_STA_11K_CFG      (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_STA | 0x00000021)
#define NCP_BRIDGE_CMD_WLAN_STA_NEIGHBOR_REQ (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_STA | 0x00000022)

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
#define NCP_BRIDGE_CMD_WLAN_NETWORK_MONITOR (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_NETWORK | 0x00000002)
#define NCP_BRIDGE_CMD_WLAN_NETWORK_ADD     (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_NETWORK | 0x00000003) /* wlan-add */
#define NCP_BRIDGE_CMD_WLAN_NETWORK_START   (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_NETWORK | 0x00000004) /* wlan-start-network */
#define NCP_BRIDGE_CMD_WLAN_NETWORK_STOP    (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_NETWORK | 0x00000005) /* wlan-stop-network */
#define NCP_BRIDGE_CMD_WLAN_NETWORK_GET_UAP_STA_LIST    (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_NETWORK | 0x00000006) /* wlan-get-uap-sta-list */
#define NCP_BRIDGE_CMD_WLAN_NETWORK_MDNS_QUERY  (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_NETWORK | 0x00000007) /* mdns-query */
#define NCP_BRIDGE_CMD_WLAN_NETWORK_LIST  (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_NETWORK | 0x00000008) /* wlan-list */
#define NCP_BRIDGE_CMD_WLAN_NETWORK_REMOVE  (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_NETWORK | 0x00000009) /* wlan-remove */

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

/*WLAN Debug command*/
#define  NCP_BRIDGE_CMD_WLAN_DEBUG_REGISTER_ACCESS    (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_DEBUG | 0x00000001)

/*WLAN Memory command*/
#define NCP_BRIDGE_CMD_WLAN_MEMORY_HEAP_SIZE          (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_MEMORY | 0x00000001)

/*WLAN UAP command*/
#define NCP_BRIDGE_CMD_WLAN_UAP_MAX_CLIENT_CNT   (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_UAP | 0x00000001) /* wlan-set-max-clients-count */

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

/*WLAN events*/
#define NCP_BRIDGE_EVENT_MCU_SLEEP_ENTER (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_ASYNC_EVENT | 0x00000001)
#define NCP_BRIDGE_EVENT_MCU_SLEEP_EXIT  (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_ASYNC_EVENT | 0x00000002)
#define NCP_BRIDGE_EVENT_MDNS_QUERY_RESULT (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_ASYNC_EVENT | 0x00000003)
#define NCP_BRIDGE_EVENT_MDNS_RESOLVE_DOMAIN (NCP_BRIDGE_CMD_WLAN | NCP_BRIDGE_CMD_WLAN_ASYNC_EVENT | 0x00000004)

#define NCP_BRIDGE_CMD_RESULT_OK 0x0000

/*General error*/
#define NCP_BRIDGE_CMD_RESULT_ERROR 0x0001
/*MCU device enter low power mode*/
#define NCP_BRIDGE_CMD_RESULT_ENTER_SLEEP 0x0006
/*MCU device exit low power mode*/
#define NCP_BRIDGE_CMD_RESULT_EXIT_SLEEP 0x0007

/* The max size of the network list*/
#define NCP_BRIDGE_WLAN_KNOWN_NETWORKS 5

#define NCP_BRIDGE_MSG_TYPE_CMD   0x0000
#define NCP_BRIDGE_MSG_TYPE_RESP  0x0001
#define NCP_BRIDGE_MSG_TYPE_EVENT 0x0002

/*NCP MPU BRIDGE TLV definitions*/
#define NCP_BRIDGE_CMD_NETWORK_SSID_TLV     0x0001
#define NCP_BRIDGE_CMD_NETWORK_BSSID_TLV    0x0002
#define NCP_BRIDGE_CMD_NETWORK_CHANNEL_TLV  0x0003
#define NCP_BRIDGE_CMD_NETWORK_IP_TLV       0x0004
#define NCP_BRIDGE_CMD_NETWORK_SECURITY_TLV 0x0005
#define NCP_BRIDGE_CMD_NETWORK_ROLE_TLV     0x0006
#define NCP_BRIDGE_CMD_NETWORK_DTIM_TLV     0x0007
#define NCP_BRIDGE_CMD_NETWORK_CAPA_TLV     0x0008
#define NCP_BRIDGE_CMD_NETWORK_ACSBAND_TLV  0x0009
#define NCP_BRIDGE_CMD_NETWORK_PMF_TLV      0x000A

#define NCP_BRIDGE_CMD_WLAN_HE_CAP_TLV 0x00FF

/* NCP MPU BRIDGE MDNS Result TLV */
#define NCP_BRIDGE_CMD_NETWORK_MDNS_RESULT_PTR 0x0011
#define NCP_BRIDGE_CMD_NETWORK_MDNS_RESULT_SRV 0x0012
#define NCP_BRIDGE_CMD_NETWORK_MDNS_RESULT_TXT 0x0013
#define NCP_BRIDGE_CMD_NETWORK_MDNS_RESULT_IP_ADDR 0x0014

#define NCP_WLAN_MAC_ADDR_LENGTH 6
#define MAX_MONIT_MAC_FILTER_NUM 3

#define FOLD_U32T(u)          ((uint32_t)(((u) >> 16) + ((u)&0x0000ffffUL)))
#define SWAP_BYTES_IN_WORD(w) (((w)&0xff) << 8) | (((w)&0xff00) >> 8)

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

enum wlan_mef_type
{
    MEF_TYPE_DELETE = 0,
    MEF_TYPE_PING,
    MEF_TYPE_ARP,
    MEF_TYPE_MULTICAST,
    MEF_TYPE_IPV6_NS,
    MEF_TYPE_END,
};

#define NCP_WLAN_DEFAULT_RSSI_THRESHOLD 70

/** The space reserved for storing network names */
#define WLAN_NETWORK_NAME_MAX_LENGTH 32

#define WLAN_SSID_MAX_LENGTH 32

/* Min WPA2 passphrase can be upto 8 ASCII chars */
#define WLAN_PSK_MIN_LENGTH 8
/* Max WPA2 passphrase can be upto 63 ASCII chars or 64 hexadecimal digits*/
#define WLAN_PSK_MAX_LENGTH 65
/* Min WPA3 password can be upto 8 ASCII chars */
#define WLAN_PASSWORD_MIN_LENGTH 8
/* Max WPA3 password can be upto 255 ASCII chars */
#define WLAN_PASSWORD_MAX_LENGTH 255
/* Max WPA2 Enterprise identity can be upto 64 characters */
#define IDENTITY_MAX_LENGTH 64
/* Max WPA2 Enterprise password can be upto 64 unicode characters */
#define PASSWORD_MAX_LENGTH 64

/** The operation could not be performed in the current system state. */
#define WLAN_ERROR_STATE 3

#define MOD_ERROR_START(x) (x << 12 | 0)
/* Globally unique success code */
#define WM_SUCCESS 0

/*Set UAP max client count status*/
#define WLAN_SET_MAX_CLIENT_CNT_SUCCESS          0
#define WLAN_SET_MAX_CLIENT_CNT_FAIL             1
#define WLAN_SET_MAX_CLIENT_CNT_START            2
#define WLAN_SET_MAX_CLIENT_CNT_EXCEED           3

#define ACTION_GET   0
#define ACTION_SET   1

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

enum wm_errno
{
    /* First Generic Error codes */
    WM_GEN_E_BASE = MOD_ERROR_START(0),
    WM_FAIL,     /* 1 */
    WM_E_PERM,   /* 2: Operation not permitted */
    WM_E_NOENT,  /* 3: No such file or directory */
    WM_E_SRCH,   /* 4: No such process */
    WM_E_INTR,   /* 5: Interrupted system call */
    WM_E_IO,     /* 6: I/O error */
    WM_E_NXIO,   /* 7: No such device or address */
    WM_E_2BIG,   /* 8: Argument list too long */
    WM_E_NOEXEC, /* 9: Exec format error */
    WM_E_BADF,   /* 10: Bad file number */
    WM_E_CHILD,  /* 11: No child processes */
    WM_E_AGAIN,  /* 12: Try again */
    WM_E_NOMEM,  /* 13: Out of memory */
    WM_E_ACCES,  /* 14: Permission denied */
    WM_E_FAULT,  /* 15: Bad address */
    WM_E_NOTBLK, /* 16: Block device required */
    WM_E_BUSY,   /* 17: Device or resource busy */
    WM_E_EXIST,  /* 18: File exists */
    WM_E_XDEV,   /* 19: Cross-device link */
    WM_E_NODEV,  /* 20: No such device */
    WM_E_NOTDIR, /* 21: Not a directory */
    WM_E_ISDIR,  /* 22: Is a directory */
    WM_E_INVAL,  /* 23: Invalid argument */
    WM_E_NFILE,  /* 24: File table overflow */
    WM_E_MFILE,  /* 25: Too many open files */
    WM_E_NOTTY,  /* 26: Not a typewriter */
    WM_E_TXTBSY, /* 27: Text file busy */
    WM_E_FBIG,   /* 28: File too large */
    WM_E_NOSPC,  /* 29: No space left on device */
    WM_E_SPIPE,  /* 30: Illegal seek */
    WM_E_ROFS,   /* 31: Read-only file system */
    WM_E_MLINK,  /* 32: Too many links */
    WM_E_PIPE,   /* 33: Broken pipe */
    WM_E_DOM,    /* 34: Math argument out of domain of func */
    WM_E_RANGE,  /* 35: Math result not representable */

    /* WMSDK generic error codes */
    WM_E_CRC,     /* 36: Error in CRC check */
    WM_E_UNINIT,  /* 37: Module is not yet initialized */
    WM_E_TIMEOUT, /* 38: Timeout occurred during operation */

    /* Defined for Hostcmd specific API*/
    WM_E_INBIG,   /* 39: Input buffer too big */
    WM_E_INSMALL, /* 40: A finer version for WM_E_INVAL, where it clearly specifies that input is much smaller than
                     minimum requirement */
    WM_E_OUTBIG,  /* 41: Data output exceeds the size provided */
};

#pragma pack(1) // unalign

typedef struct _NCP_CMD_WLAN_RESET_CFG
{
    int option;
} NCP_CMD_WLAN_RESET_CFG;

/** Scan Result */
typedef struct _wlan_bridge_scan_result
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
} wlan_bridge_scan_result;

typedef struct BRIDGE_COMMAND
{
    /*bit0 ~ bit15 cmd id  bit16 ~ bit23 cmd subclass bit24 ~ bit31 cmd class*/
    uint32_t cmd;
    uint16_t size;
    uint16_t seqnum;
    uint16_t result;
    uint16_t msg_type;
} NCP_BRIDGE_COMMAND, NCP_BRIDGE_RESPONSE;

typedef struct TLVTypeHeader_t
{
    uint16_t type;
    uint16_t size;
} TypeHeader_t, NCP_BRIDGE_TLV_HEADER;

typedef struct _NCP_CMD_SCAN_NETWORK_INFO
{
    uint8_t res_cnt;
    wlan_bridge_scan_result res[NCP_BRIDGE_MAX_AP_ENTRIES];
} NCP_CMD_SCAN_NETWORK_INFO;

typedef struct _NCP_CMD_FW_VERSION
{
    /** Driver version string */
    char driver_ver_str[16];
    /** Firmware version string */
    char fw_ver_str[128];
} NCP_CMD_FW_VERSION;

typedef struct _NCP_CMD_MAC_ADDRESS
{
    uint8_t mac_addr[NCP_WLAN_MAC_ADDR_LENGTH];
} NCP_CMD_MAC_ADDRESS;

typedef struct _NCP_CMD_GET_MAC_ADDRESS
{
    uint8_t uap_mac[NCP_WLAN_MAC_ADDR_LENGTH];
    uint8_t sta_mac[NCP_WLAN_MAC_ADDR_LENGTH];
} NCP_CMD_GET_MAC_ADDRESS;

typedef struct _NCP_CMD_CONNECT_STAT
{
    uint8_t ps_mode;
    uint8_t uap_conn_stat;
    uint8_t sta_conn_stat;
} NCP_CMD_CONNECT_STAT;

typedef struct _NCP_CMD_ROAMING
{
    uint32_t enable;
    uint8_t rssi_threshold;
} NCP_CMD_ROAMING;

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

/** Network security types*/
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
#ifdef CONFIG_11R
    /** The network uses WPA2 security with PSK FT. */
    WLAN_SECURITY_WPA2_FT,
#endif
    /** The network uses WPA3 security with SAE. */
    WLAN_SECURITY_WPA3_SAE,
#ifdef CONFIG_WPA_SUPP
#ifdef CONFIG_11R
    /** The network uses WPA3 security with SAE FT. */
    WLAN_SECURITY_WPA3_FT_SAE,
#endif
#endif
    /** The network uses WPA2/WPA3 SAE mixed security with PSK. This security mode
     * is specific to uAP or SoftAP only */
    WLAN_SECURITY_WPA2_WPA3_SAE_MIXED,
#ifdef CONFIG_OWE
    /** The network uses OWE only security without Transition mode support. */
    WLAN_SECURITY_OWE_ONLY,
#endif
#if defined(CONFIG_WPA_SUPP_CRYPTO_ENTERPRISE) || defined(CONFIG_WPA2_ENTP)
    /** The network uses WPA2 Enterprise EAP-TLS security
     * The identity field in \ref wlan_network structure is used */
    WLAN_SECURITY_EAP_TLS,
#endif
#ifdef CONFIG_WPA_SUPP_CRYPTO_ENTERPRISE
#ifdef CONFIG_EAP_TLS
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
#endif
#ifdef CONFIG_EAP_TTLS
    /** The network uses WPA2 Enterprise EAP-TTLS security
     * The identity field in \ref wlan_network structure is used */
    WLAN_SECURITY_EAP_TTLS,
#ifdef CONFIG_EAP_MSCHAPV2
    /** The network uses WPA2 Enterprise EAP-TTLS-MSCHAPV2 security
     * The anonymous identity, identity and password fields in
     * \ref wlan_network structure are used */
    WLAN_SECURITY_EAP_TTLS_MSCHAPV2,
#endif
#endif
#endif
#if defined(CONFIG_WPA_SUPP_CRYPTO_ENTERPRISE) || defined(CONFIG_PEAP_MSCHAPV2) || defined(CONFIG_WPA2_ENTP)
    /** The network uses WPA2 Enterprise EAP-PEAP-MSCHAPV2 security
     * The anonymous identity, identity and password fields in
     * \ref wlan_network structure are used */
    WLAN_SECURITY_EAP_PEAP_MSCHAPV2,
#endif
#ifdef CONFIG_WPA_SUPP_CRYPTO_ENTERPRISE
#ifdef CONFIG_EAP_PEAP
#ifdef CONFIG_EAP_TLS
    /** The network uses WPA2 Enterprise EAP-PEAP-TLS security
     * The anonymous identity, identity and password fields in
     * \ref wlan_network structure are used */
    WLAN_SECURITY_EAP_PEAP_TLS,
#endif
#ifdef CONFIG_EAP_GTC
    /** The network uses WPA2 Enterprise EAP-PEAP-GTC security
     * The anonymous identity, identity and password fields in
     * \ref wlan_network structure are used */
    WLAN_SECURITY_EAP_PEAP_GTC,
#endif
#endif
#ifdef CONFIG_EAP_FAST
#ifdef CONFIG_EAP_MSCHAPV2
    /** The network uses WPA2 Enterprise EAP-FAST-MSCHAPV2 security
     * The anonymous identity, identity and password fields in
     * \ref wlan_network structure are used */
    WLAN_SECURITY_EAP_FAST_MSCHAPV2,
#endif
#ifdef CONFIG_EAP_GTC
    /** The network uses WPA2 Enterprise EAP-FAST-GTC security
     * The anonymous identity, identity and password fields in
     * \ref wlan_network structure are used */
    WLAN_SECURITY_EAP_FAST_GTC,
#endif
#endif
#ifdef CONFIG_EAP_SIM
    /** The network uses WPA2 Enterprise EAP-SIM security
     * The identity and password fields in
     * \ref wlan_network structure are used */
    WLAN_SECURITY_EAP_SIM,
#endif
#ifdef CONFIG_EAP_AKA
    /** The network uses WPA2 Enterprise EAP-AKA security
     * The identity and password fields in
     * \ref wlan_network structure are used */
    WLAN_SECURITY_EAP_AKA,
#endif
#ifdef CONFIG_EAP_AKA_PRIME
    /** The network uses WPA2 Enterprise EAP-AKA-PRIME security
     * The identity and password fields in
     * \ref wlan_network structure are used */
    WLAN_SECURITY_EAP_AKA_PRIME,
#endif
#endif
#ifdef CONFIG_WPA_SUPP_DPP
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

#ifdef CONFIG_IPV6
/** This data structure represents an IPv6 address */
typedef struct _wlan_bridge_ipv6_config
{
    /** The system's IPv6 address in network order. */
    unsigned address[4];
    /** The address type: linklocal, site-local or global. */
    unsigned char addr_type_str[16];
    /** The state of IPv6 address (Tentative, Preferred, etc). */
    unsigned char addr_state_str[32];
} wlan_bridge_ipv6_config;
#endif

/** This data structure represents an IPv4 address */
typedef struct _wlan_bridge_ipv4_config
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
} wlan_bridge_ipv4_config;

/** WLAN Network Profile
 *  This data structure represents a WLAN network profile. It consists of an
 *  arbitrary name, WiFi configuration, and IP address configuration.
 */
typedef struct _wlan_bridge_network
{
    /** The name of this network profile. */
    char name[WLAN_NETWORK_NAME_MAX_LENGTH + 1];
    /** The network SSID, represented as a C string of up to 32 characters
     *  in length.
     *  If this profile is used in the micro-AP mode, this field is
     *  used as the SSID of the network.
     *  If this profile is used in the station mode, this field is
     *  used to identify the network. Set the first byte of the SSID to NULL
     *  (a 0-length string) to use only the BSSID to find the network.
     */
    char ssid[IEEEtypes_SSID_SIZE + 1];
    /** The network BSSID, represented as a 6-byte array.
     *  If this profile is used in the micro-AP mode, this field is
     *  ignored.
     *  If this profile is used in the station mode, this field is
     *  used to identify the network. Set all 6 bytes to 0 to use any BSSID,
     *  in which case only the SSID will be used to find the network.
     */
    char bssid[IEEEtypes_ADDRESS_SIZE];
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
    /** Rssi threshold */
    short rssi_threshold;
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
    /** The network IPv6 address configuration */
    wlan_bridge_ipv6_config ipv6[CONFIG_MAX_IPV6_ADDRESSES];
    /** The network IPv4 address configuration */
    wlan_bridge_ipv4_config ipv4;

    uint8_t is_sta_ipv4_connected;

    char identity[IDENTITY_MAX_LENGTH];

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
    /** This indicates this network is used as an internal network for
     * WPS */
    unsigned wps_specific : 1;
    /** Beacon period of associated BSS */
    uint16_t beacon_period;
    /** DTIM period of associated BSS */
    uint8_t dtim_period;
    uint8_t wlan_capa;
} wlan_bridge_network;

typedef struct _NCP_CMD_NETWORK_INFO
{
    uint8_t uap_conn_stat;
    uint8_t sta_conn_stat;
    wlan_bridge_network uap_network;
    wlan_bridge_network sta_network;
} NCP_CMD_NETWORK_INFO;

typedef struct _NCP_CMD_NETWORK_LIST
{
    uint8_t count;
    wlan_bridge_network net_list[NCP_BRIDGE_WLAN_KNOWN_NETWORKS];
} NCP_CMD_NETWORK_LIST;

typedef struct _NCP_CMD_NETWORK_REMOVE
{
    uint8_t name[WLAN_NETWORK_NAME_MAX_LENGTH];
    int8_t remove_state;
} NCP_CMD_NETWORK_REMOVE;

/*NCP Bridge SSID tlv*/
typedef struct _SSID_ParamSet_t
{
    TypeHeader_t header;
    char ssid[IEEEtypes_SSID_SIZE + 1];
} SSID_ParamSet_t;

/*NCP Bridge BSSID tlv*/
typedef struct _BSSID_ParamSet_t
{
    TypeHeader_t header;
    char bssid[IEEEtypes_ADDRESS_SIZE];
} BSSID_ParamSet_t;

/*NCP Bridge bss role tlv*/
typedef struct _BSSRole_ParamSet_t
{
    TypeHeader_t header;
    uint8_t role;
} BSSRole_ParamSet_t;

/*NCP Bridge channel tlv*/
typedef struct _Channel_ParamSet_t
{
    TypeHeader_t header;
    uint8_t channel;
} Channel_ParamSet_t;

/*NCP Bridge acs_band tlv*/
typedef struct _ACSBand_ParamSet_t
{
    TypeHeader_t header;
    uint16_t acs_band;
} ACSBand_ParamSet_t;

/*NCP Bridge IP address tlv*/
typedef struct _IP_ParamSet_t
{
    TypeHeader_t header;
    uint8_t is_autoip;
    uint32_t address;
    uint32_t gateway;
    uint32_t netmask;
    uint32_t dns1;
    uint32_t dns2;
} IP_ParamSet_t;

/*NCP Bridge security tlv*/
typedef struct _Security_ParamSet_t
{
    TypeHeader_t header;
    uint8_t type;
    uint8_t password_len;
    char password[1];
} Security_ParamSet_t;

/*NCP Bridge PMF tlv*/
typedef struct _PMF_ParamSet_t
{
    TypeHeader_t header;
    uint8_t mfpc;
    uint8_t mfpr;
} PMF_ParamSet_t;

#ifdef CONFIG_WIFI_DTIM_PERIOD
/*NCP Bridge DTIM tlv*/
typedef struct _DTIM_ParamSet_t
{
    TypeHeader_t header;
    uint8_t dtim_period;
} DTIM_ParamSet_t;
#endif

#ifdef CONFIG_WIFI_CAPA
/*NCP Bridge CAPA tlv*/
typedef struct _CAPA_ParamSet_t
{
    TypeHeader_t header;
    uint8_t capa;
} CAPA_ParamSet_t;
#endif

typedef struct _NCP_CMD_NETWORK_ADD
{
    char name[WLAN_NETWORK_NAME_MAX_LENGTH];
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
} NCP_CMD_NETWORK_ADD;

typedef struct _NCP_CMD_NETWORK_START
{
    char name[32];
    char ssid[32 + 1];
} NCP_CMD_NETWORK_START;

/** Station information structure */
typedef struct _wlan_bridge_sta_info
{
    /** MAC address buffer */
    uint8_t mac[IEEEtypes_ADDRESS_SIZE];
    /**
     * Power management status
     * 0 = active (not in power save)
     * 1 = in power save status
     */
    uint8_t power_mgmt_status;
    /** RSSI: dBm */
    signed char rssi;
} wlan_bridge_sta_info;

typedef struct _NCP_CMD_NETWORK_UAP_STA_LIST
{
    /** station count */
    uint16_t sta_count;
    /** station list */
    wlan_bridge_sta_info info[MAX_NUM_CLIENTS];
} NCP_CMD_NETWORK_UAP_STA_LIST;

/*Bridge Wlan Socket Open*/
#define HTTP_PARA_LEN 16
#define SETH_NAME_LENGTH  64
#define SETH_VALUE_LENGTH 128
#define HTTP_URI_LEN 512
typedef struct _NCP_CMD_SOCKET_OPEN_CFG
{
    char socket_type[HTTP_PARA_LEN];
    char domain_type[HTTP_PARA_LEN];
    char protocol[HTTP_PARA_LEN];
    uint32_t opened_handle;
} NCP_CMD_SOCKET_OPEN_CFG;

/*Bridge Wlan Socket Connect*/
#define IP_ADDR_LEN 16
typedef struct _NCP_CMD_SOCKET_CON_CFG
{
    uint32_t handle;
    uint32_t port;
    char ip_addr[IP_ADDR_LEN];
} NCP_CMD_SOCKET_CON_CFG;

/*Bridge Wlan Socket Bind*/
typedef struct _NCP_CMD_SOCKET_BIND_CFG
{
    uint32_t handle;
    uint32_t port;
    char ip_addr[IP_ADDR_LEN];
} NCP_CMD_SOCKET_BIND_CFG;

/*Bridge Wlan Socket Close*/
typedef struct _NCP_CMD_SOCKET_CLOSE_CFG
{
    uint32_t handle;
} NCP_CMD_SOCKET_CLOSE_CFG;

/*Bridge Wlan Socket Listen*/
typedef struct _NCP_CMD_SOCKET_LISTEN_CFG
{
    uint32_t handle;
    uint32_t number;
} NCP_CMD_SOCKET_LISTEN_CFG;

/*Bridge Wlan Socket Accept*/
typedef struct _NCP_CMD_SOCKET_ACCEPT_CFG
{
    uint32_t handle;
    int accepted_handle;
} NCP_CMD_SOCKET_ACCEPT_CFG;

/*Bridge Wlan Socket Send*/
typedef struct _NCP_CMD_SOCKET_SEND_CFG
{
    uint32_t handle;
    uint32_t size;
    char send_data[1];
} NCP_CMD_SOCKET_SEND_CFG;

/*Bridge Wlan Socket Sendto*/
typedef struct _NCP_CMD_SOCKET_SENDTO_CFG
{
    uint32_t handle;
    uint32_t size;
    char ip_addr[IP_ADDR_LEN];
    uint32_t port;
    char send_data[1];
} NCP_CMD_SOCKET_SENDTO_CFG;

/*Bridge Wlan Socket Receive*/
typedef struct _NCP_CMD_SOCKET_RECEIVE_CFG
{
    uint32_t handle;
    uint32_t size;
    uint32_t timeout;
    char recv_data[1];
} NCP_CMD_SOCKET_RECEIVE_CFG;

/*Bridge Wlan Socket Recvfrom*/
typedef struct _NCP_CMD_SOCKET_RECVFROM_CFG
{
    uint32_t handle;
    uint32_t size;
    uint32_t timeout;
    char peer_ip[IP_ADDR_LEN];
    uint32_t peer_port;
    char recv_data[1];
} NCP_CMD_SOCKET_RECVFROM_CFG;

/*Bridge Wlan Http Connect*/
typedef struct _MPU_NCP_CMD_HTTP_CONNECT_CFG
{
    int opened_handle;
    char host[1];
} NCP_CMD_HTTP_CON_CFG;

/*Bridge Wlan Http Disconnect*/
typedef struct _MPU_NCP_CMD_HTTP_DISCONNECT_CFG
{
    uint32_t handle;
} NCP_CMD_HTTP_DISCON_CFG;

/*Bridge Wlan Http Seth*/
typedef struct _MPU_NCP_CMD_HTTP_SETH_CFG
{
    char name[SETH_NAME_LENGTH];
    char value[SETH_VALUE_LENGTH];
} NCP_CMD_HTTP_SETH_CFG;

/*Bridge Wlan Http Unseth*/
typedef struct _MPU_NCP_CMD_HTTP_UNSETH_CFG
{
    char name[SETH_NAME_LENGTH];
} NCP_CMD_HTTP_UNSETH_CFG;

/*Bridge Wlan Http Req*/
typedef struct _MPU_NCP_CMD_HTTP_REQ_CFG
{
    uint32_t handle;
    char method[HTTP_PARA_LEN];
    char uri[HTTP_URI_LEN];
    uint32_t req_size;
    char req_data[1];
} NCP_CMD_HTTP_REQ_CFG;

/*Bridge Wlan Http Recv Resp*/
typedef struct _MPU_NCP_CMD_HTTP_REQ_RESP_CFG
{
    uint32_t header_size;
    char recv_header[1];
} NCP_CMD_HTTP_REQ_RESP_CFG;

/*Bridge Wlan Http Recv*/
typedef struct _MPU_NCP_CMD_HTTP_RECV_CFG
{
    uint32_t handle;
    uint32_t size;
    uint32_t timeout;
    char recv_data[1];
} NCP_CMD_HTTP_RECV_CFG;

/*Bridge Wlan Http Upgrade*/
typedef struct _MPU_NCP_CMD_HTTP_UPG_CFG
{
    uint32_t handle;
    char     uri[HTTP_URI_LEN];
    char     protocol[HTTP_PARA_LEN];
} NCP_CMD_HTTP_UPG_CFG;

/*Bridge Wlan Socket Send*/
typedef struct _MPU_NCP_CMD_WEBSOCKET_SEND_CFG
{
    uint32_t handle;
    char type[HTTP_PARA_LEN];
    uint32_t size;
    char send_data[1];
} NCP_CMD_WEBSOCKET_SEND_CFG;


/*Bridge Wlan Websocket Receive*/
typedef struct _MPU_NCP_CMD_WEBSOCKET_RECV_CFG
{
    uint32_t handle;
    uint32_t size;
    uint32_t timeout;
	uint32_t fin;
    char recv_data[1];
} NCP_CMD_WEBSOCKET_RECV_CFG;

/** Network monitor structure */
typedef struct
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
} wlan_bridge_net_monitor_para;

typedef struct _NCP_CMD_NET_MONITOR
{
    wlan_bridge_net_monitor_para monitor_para;
} NCP_CMD_NET_MONITOR;

typedef struct _NCP_CMD_REGISTER_ACCESS
{
    uint8_t action;
    uint8_t type;
    uint32_t offset;
    uint32_t value;
} NCP_CMD_REGISTER_ACCESS;

typedef struct _NCP_CMD_MEM_STAT
{
    uint32_t free_heap_size;
    uint32_t minimun_ever_free_heap_size;
} NCP_CMD_MEM_STAT;

#define CSI_FILTER_MAX 16
/** Structure of CSI filters */
typedef struct _wlan_csi_filter_t
{
    /** Source address of the packet to receive */
    uint8_t mac_addr[NCP_WLAN_MAC_ADDR_LENGTH];
    /** Pakcet type of the interested CSI */
    uint8_t pkt_type;
    /* Packet subtype of the interested CSI */
    uint8_t subtype;
    /* Other filter flags */
    uint8_t flags;
} wlan_csi_filter_t;

/** Structure of CSI parameters */
typedef struct _wlan_csi_config_params_t
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
} wlan_csi_config_params_t;

typedef struct _NCP_CMD_CSI
{
    wlan_csi_config_params_t csi_para;
} NCP_CMD_CSI;

typedef struct _NCP_CMD_11K_CFG
{
    int enable;
} NCP_CMD_11K_CFG;

typedef struct _NCP_CMD_NEIGHBOR_REQ
{
    SSID_ParamSet_t ssid_tlv;
} NCP_CMD_NEIGHBOR_REQ;

/** RSSI information */
typedef struct
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
} wlan_bridge_rssi_info_t;

typedef struct _NCP_CMD_RSSI
{
    wlan_bridge_rssi_info_t rssi_info;
} NCP_CMD_RSSI;

#define MPU_DEVICE_STATUS_ACTIVE 1
#define MPU_DEVICE_STATUS_SLEEP  2

/* Host wakes up MCU through interface */
#define WAKE_MODE_UART 0x1

typedef struct _NCP_CMD_POWERMGMT_MEF
{
    int type;
    uint8_t action;
} NCP_CMD_POWERMGMT_MEF;

typedef struct _NCP_CMD_POWERMGMT_UAPSD
{
    int enable;
} NCP_CMD_POWERMGMT_UAPSD;

typedef struct _NCP_CMD_POWERMGMT_QOSINFO
{
    uint8_t qos_info;
    /* 0 - get, 1 - set */
    uint8_t action;
} NCP_CMD_POWERMGMT_QOSINFO;

typedef struct _NCP_CMD_POWERMGMT_SLEEP_PERIOD
{
    uint32_t period;
    /* 0 - get, 1 - set */
    uint8_t action;
} NCP_CMD_POWERMGMT_SLEEP_PERIOD;

typedef struct _power_cfg_t
{
    uint8_t enable;
    uint8_t wake_mode;
    uint8_t subscribe_evt;
    uint32_t wake_duration;
    uint8_t is_mef;
    uint32_t wake_up_conds;
    uint8_t is_manual;
    uint32_t rtc_timeout;
} power_cfg_t;

typedef struct _NCP_CMD_POWERMGMT_WAKE_CFG
{
    uint8_t wake_mode;
    uint8_t subscribe_evt;
    uint32_t wake_duration;
} NCP_CMD_POWERMGMT_WAKE_CFG;

typedef struct _NCP_CMD_POWERMGMT_WOWLAN_CFG
{
    uint8_t is_mef;
    uint8_t wake_up_conds;
} NCP_CMD_POWERMGMT_WOWLAN_CFG;

typedef struct _NCP_CMD_POWERMGMT_MCU_SLEEP
{
    uint8_t enable;
    uint8_t is_manual;
    int rtc_timeout;
} NCP_CMD_POWERMGMT_MCU_SLEEP;

typedef struct _NCP_CMD_POWERMGMT_SUSPEND
{
    int mode;
} NCP_CMD_POWERMGMT_SUSPEND;

/*NCP Bridge HE CAPA tlv*/
typedef struct _HE_CAP_ParamSet_t
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
} HE_CAP_ParamSet_t;

typedef struct _NCP_CMD_11AX_CFG
{
    /** band, BIT0:2.4G, BIT1:5G, both set for 2.4G and 5G*/
    uint8_t band;
    HE_CAP_ParamSet_t he_cap_tlv;
} NCP_CMD_11AX_CFG;

typedef struct _NCP_CMD_BTWT_CFG
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
} NCP_CMD_BTWT_CFG;

typedef struct _NCP_CMD_TWT_SETUP
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
} NCP_CMD_TWT_SETUP;

typedef struct _NCP_CMD_TWT_TEARDOWN
{
    /** TWT Flow Identifier. Range: [0-7] */
    uint8_t flow_identifier;
    /** Negotiation Type. 0: Future Individual TWT SP start time, 1: Next
     * Wake TBTT time */
    uint8_t negotiation_type;
    /** Tear down all TWT. 1: To teardown all TWT, 0 otherwise */
    uint8_t teardown_all_twt;
} NCP_CMD_TWT_TEARDOWN;

typedef struct _IEEE_BTWT_ParamSet_t
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
} IEEE_BTWT_ParamSet_t;

typedef struct _NCP_CMD_TWT_REPORT
{
    /** TWT report type, 0: BTWT id */
    uint8_t type;
    /** TWT report length of value in data */
    uint8_t length;
    uint8_t reserve[2];
    /** TWT report payload for FW response to fill, 4 * 9bytes */
    IEEE_BTWT_ParamSet_t info[4];
} NCP_CMD_TWT_REPORT;

typedef struct _NCP_CMD_11D_ENABLE
{
    /** 0 - STA, 1 - UAP */
    uint32_t role;
    /** 0 - disable, 1 - enable */
    uint32_t state;
} NCP_CMD_11D_ENABLE;

typedef struct _NCP_CMD_REGION_CODE
{
    /** 0 - get, 1 - set */
    uint32_t action;
    /** region code, 0xaa for world wide safe, 0x10 for US FCC, etc */
    uint32_t region_code;
} NCP_CMD_REGION_CODE;

typedef struct _NCP_CMD_SYSTEM_CFG
{
    /* the name of system config file: sys, prov, wlan */
    char module_name[MODULE_NAME_MAX_LEN];
    /* the name of entry */
    char variable_name[VAR_NAME_MAX_LEN];
    /* set value/returned result */
    char value[CONFIG_VALUE_MAX_LEN];
} NCP_CMD_SYSTEM_CFG;

typedef struct _NCP_CMD_CLIENT_CNT
{
    uint16_t max_sta_count;
    uint8_t set_status;
    uint8_t support_count;
} NCP_CMD_CLIENT_CNT;

typedef struct _NCP_CMD_ANTENNA_CFG
{
    uint8_t action;
    uint32_t antenna_mode;
    uint16_t evaluate_time;
    uint8_t evaluate_mode;
    uint16_t current_antenna;
} NCP_CMD_ANTENNA_CFG;

typedef struct _NCP_CMD_WPS_GEN_PIN
{
    uint32_t pin;
} NCP_CMD_WPS_GEN_PIN;

typedef struct _NCP_CMD_WPS_PIN
{
    uint32_t pin;
} NCP_CMD_WPS_PIN;

typedef struct _NCP_CMD_DEEP_SLEEP_PS
{
    int enable;
} NCP_CMD_DEEP_SLEEP_PS;

typedef struct _NCP_CMD_IEEE_PS
{
    int enable;
} NCP_CMD_IEEE_PS;

typedef struct _NCP_CMD_EU_VALIDATION
{
    uint8_t option;
    uint8_t res_buf[4];
} NCP_CMD_EU_VALIDATION;

typedef struct _NCP_CMD_ED_MAC
{
    uint8_t action;
    uint16_t ed_ctrl_2g;
    uint16_t ed_offset_2g;
#ifdef CONFIG_5GHz_SUPPORT
    uint16_t ed_ctrl_5g;
    uint16_t ed_offset_5g;
#endif
} NCP_CMD_ED_MAC;

typedef struct _NCP_CMD_RF_TX_ANTENNA
{
    uint8_t ant;
} NCP_CMD_RF_TX_ANTENNA;

typedef struct _NCP_CMD_RF_RX_ANTENNA
{
    uint8_t ant;
} NCP_CMD_RF_RX_ANTENNA;

typedef struct _NCP_CMD_RF_BAND
{
    uint8_t band;
} NCP_CMD_RF_BAND;

typedef struct _NCP_CMD_RF_BANDWIDTH
{
    uint8_t bandwidth;
} NCP_CMD_RF_BANDWIDTH;

typedef struct _NCP_CMD_RF_CHANNEL
{
    uint8_t channel;
} NCP_CMD_RF_CHANNEL;

typedef struct _NCP_CMD_RF_RADIO_MODE
{
    uint8_t radio_mode;
} NCP_CMD_RF_RADIO_MODE;

typedef struct _NCP_CMD_RF_TX_POWER
{
    uint8_t power;
    uint8_t mod;
    uint8_t path_id;
} NCP_CMD_RF_TX_POWER;

typedef struct _NCP_CMD_RF_TX_CONT_MODE
{
    uint32_t enable_tx;
    uint32_t cw_mode;
    uint32_t payload_pattern;
    uint32_t cs_mode;
    uint32_t act_sub_ch;
    uint32_t tx_rate;
} NCP_CMD_RF_TX_CONT_MODE;

typedef struct _NCP_CMD_RF_TX_FRAME
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
} NCP_CMD_RF_TX_FRAME;

typedef struct _NCP_CMD_RF_PER
{
    uint32_t rx_tot_pkt_count;
    uint32_t rx_mcast_bcast_count;
    uint32_t rx_pkt_fcs_error;
} NCP_CMD_RF_PER;

typedef struct _wlan_date_time_t
{
    uint32_t action;
    uint16_t year;  /*!< Range from 1970 to 2099.*/
    uint8_t month;  /*!< Range from 1 to 12.*/
    uint8_t day;    /*!< Range from 1 to 31 (depending on month).*/
    uint8_t hour;   /*!< Range from 0 to 23.*/
    uint8_t minute; /*!< Range from 0 to 59.*/
    uint8_t second; /*!< Range from 0 to 59.*/
} wlan_date_time_t;

typedef struct _NCP_CMD_DATE_TIME
{
    uint32_t action;
    wlan_date_time_t date_time;
} NCP_CMD_DATE_TIME;

typedef struct _NCP_CMD_TEMPERATURE
{
    uint32_t temp;
} NCP_CMD_TEMPERATURE;

typedef struct _NCP_CMD_WLAN_CONN
{
    char name[WLAN_NETWORK_NAME_MAX_LENGTH];
    uint32_t ip;
    char ssid[IEEEtypes_SSID_SIZE + 1];
} NCP_CMD_WLAN_CONN;

typedef struct _QUERY_PTR_CFG
{
    /** Type of service, like '_http' */
    char service[63 + 1];
    /** Protocol, TCP or UDP */
    uint16_t proto;
} QUERY_PTR_CFG;

typedef struct _QUERY_A_CFG
{
    /** Domain name, like 'wifi-http.local' */
    char name[63 + 1];
} QUERY_A_CFG;

typedef struct _NCP_CMD_MDNS_QUERY
{
    /** Query type (PTR, SRV, A, AAAA...) */
    uint8_t qtype;
    union
    {
        QUERY_PTR_CFG ptr_cfg;
        QUERY_A_CFG a_cfg;
    } Q;
} NCP_CMD_MDNS_QUERY;

/*NCP Bridge PTR RR tlv*/
typedef struct _PTR_ParamSet_t
{
    TypeHeader_t header;
    /* instance name */
    char instance_name[63 + 1];
    /* service type */
    char service_type[63 + 1];
    /* srevice protocol */
    char proto[8];
} PTR_ParamSet_t;

/*NCP Bridge SRV RR tlv*/
typedef struct _SRV_ParamSet_t
{
    TypeHeader_t header;
    /* host name */
    char host_name[63 + 1];
    /* service port */
    uint16_t port;
    /* target name */
    char target[63 + 1];
} SRV_ParamSet_t;

/*NCP Bridge TXT RR tlv*/
typedef struct _TXT_ParamSet_t
{
    TypeHeader_t header;
    /* txt value len */
    uint8_t txt_len;
    /* txt string */
    char txt[63 + 1];
} TXT_ParamSet_t;

/*NCP Bridge A&AAAA RR tlv*/
typedef struct _IP_ADDR_ParamSet_t
{
    TypeHeader_t header;
    uint8_t addr_type;
    /* ip address */
    union {
        uint32_t ip_v4;
        uint32_t ip_v6[4];
    } ip;
} IP_ADDR_ParamSet_t;

typedef struct _NCP_EVT_MDNS_RESULT
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
} NCP_EVT_MDNS_RESULT;

typedef struct _NCP_EVT_MDNS_RESOLVE
{
    uint8_t ip_type;
    union {
      uint32_t ip6_addr[4];
      uint32_t ip4_addr;
    } u_addr;
} NCP_EVT_MDNS_RESOLVE;

#define PING_INTERVAL 1000
#define PING_DEFAULT_TIMEOUT_SEC 2
#define PING_DEFAULT_COUNT       10
#define PING_DEFAULT_SIZE        56
#define PING_MAX_SIZE            65507
#define PING_ID 0xAFAF
#define IP_ADDR_LEN 16

struct icmp_echo_hdr {
    uint8_t type;
    uint8_t code;
    uint16_t chksum;
    uint16_t id;
    uint16_t seqno;
};

typedef uint32_t in_addr_t;

struct ip_hdr {
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
};

typedef struct _ping_msg_t
{
    uint16_t size;
    uint32_t count;
    uint32_t timeout;
    uint32_t handle;
    char ip_addr[IP_ADDR_LEN];
    uint32_t port;
} ping_msg_t;

typedef struct _ping_time_t
{
    uint32_t secs;
    uint32_t usecs;
} ping_time_t;

typedef struct _ping_res
{
    int seq_no;
    int echo_resp;
    ping_time_t time;
    uint32_t recvd;
    int ttl;
    char ip_addr[IP_ADDR_LEN];
    uint16_t size;
} ping_res_t;

/**
 * @brief This function prepares ncp iperf command
 *
 * @return Status returned
 */

#define NCP_IPERF_TCP_SERVER_PORT_DEFAULT 5001
#define NCP_IPERF_UDP_SERVER_PORT_DEFAULT NCP_IPERF_TCP_SERVER_PORT_DEFAULT + 2
#define NCP_IPERF_UDP_RATE           30
#define NCP_IPERF_UDP_TIME           10
#define NCP_IPERF_PKG_COUNT          10000
#define NCP_IPERF_PER_TCP_PKG_SIZE   1448
#define NCP_IPERF_PER_UDP_PKG_SIZE   1472

#define IPERF_TCP_RECV_TIMEOUT           1000
#define IPERF_UDP_RECV_TIMEOUT           50
#define NCP_IPERF_END_TOKEN_SIZE     11
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
    uint32_t iperf_udp_time;
} iperf_set_t;

typedef struct _iperf_msg_t
{
    int16_t status[2];
    uint32_t count;
    uint32_t timeout;
    uint32_t handle;
    uint32_t port;
    uint16_t per_size;
    char ip_addr[IP_ADDR_LEN];
    iperf_set_t iperf_set;
} iperf_msg_t;

typedef struct _NCPCmd_DS_COMMAND
{
    /** Command Header : Command */
    NCP_BRIDGE_COMMAND header;
    /** Command Body */
    union
    {
        /** Scan result*/
        NCP_CMD_SCAN_NETWORK_INFO scan_network_info;
        /** Firmware version*/
        NCP_CMD_FW_VERSION firmware_version;
        /** MAC address */
        NCP_CMD_MAC_ADDRESS mac_addr;
        /** Get MAC address */
        NCP_CMD_GET_MAC_ADDRESS get_mac_addr;
        /** wlan connnection state */
        NCP_CMD_CONNECT_STAT conn_stat;
        /** Roaming configuration */
        NCP_CMD_ROAMING roaming;
        /** wlan network info*/
        NCP_CMD_NETWORK_INFO network_info;
        NCP_CMD_NET_MONITOR monitor_cfg;
        /** wlan add network*/
        NCP_CMD_NETWORK_ADD network_add;
        /** wlan start network*/
        NCP_CMD_NETWORK_START network_start;
        /** wlan uap sta list*/
        NCP_CMD_NETWORK_UAP_STA_LIST uap_sta_list;
        NCP_CMD_CSI csi_cfg;
        NCP_CMD_11K_CFG wlan_11k_cfg;
        NCP_CMD_NEIGHBOR_REQ neighbor_req;
        /** RSSI Information*/
        NCP_CMD_RSSI signal_rssi;
        /** MAX client count*/
        NCP_CMD_CLIENT_CNT max_client_count;
        /** Antenna config*/
        NCP_CMD_ANTENNA_CFG antenna_cfg;
        NCP_CMD_WPS_GEN_PIN wps_gen_pin_info;
        NCP_CMD_WPS_PIN wps_pin_cfg;

        NCP_CMD_WLAN_RESET_CFG wlan_reset_cfg;
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

        /*power mgmt command*/
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

        NCP_CMD_11AX_CFG he_cfg;
        NCP_CMD_BTWT_CFG btwt_cfg;
        NCP_CMD_TWT_SETUP twt_setup;
        NCP_CMD_TWT_TEARDOWN twt_teardown;
        NCP_CMD_TWT_REPORT twt_report;
        NCP_CMD_11D_ENABLE wlan_11d_cfg;
        NCP_CMD_REGION_CODE region_cfg;

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

        NCP_CMD_DATE_TIME date_time;
        NCP_CMD_TEMPERATURE temperature;

        /** wlan connect*/
        NCP_CMD_WLAN_CONN wlan_connect;
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
} NCPCmd_DS_COMMAND;

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

extern int cli_optind;
extern char *cli_optarg;
static inline int cli_getopt(int argc, char **argv, const char *fmt)
{
    char *opt, *c;

    if (cli_optind == argc)
        return -1;
    cli_optarg = NULL;
    opt        = argv[cli_optind];
    if (opt[0] != '-')
        return -1;
    if (opt[0] == 0 || opt[1] == 0)
        return '?';
    cli_optind++;
    c = strchr(fmt, opt[1]);
    if (c == NULL)
        return opt[1];
    if (c[1] == ':')
    {
        if (cli_optind < argc)
            cli_optarg = argv[cli_optind++];
    }
    return c[0];
}

static inline uint16_t inet_chksum(const void *dataptr, int len)
{
    const uint8_t *pb = (const uint8_t *)dataptr;
    const uint16_t *ps;
    uint16_t t   = 0;
    uint32_t sum = 0;
    int odd      = ((uintptr_t)pb & 1);

    /* Get aligned to u16_t */
    if (odd && len > 0)
    {
        ((uint8_t *)&t)[1] = *pb++;
        len--;
    }

    /* Add the bulk of the data */
    ps = (const uint16_t *)(const void *)pb;
    while (len > 1)
    {
        sum += *ps++;
        len -= 2;
    }

    /* Consume left-over byte, if any */
    if (len > 0)
    {
        ((uint8_t *)&t)[0] = *(const uint8_t *)ps;
    }

    /* Add end bytes */
    sum += t;

    /* Fold 32-bit sum to 16 bits
       calling this twice is probably faster than if statements... */
    sum = FOLD_U32T(sum);
    sum = FOLD_U32T(sum);

    /* Swap if alignment was odd */
    if (odd)
    {
        sum = SWAP_BYTES_IN_WORD(sum);
    }

    return (uint16_t)(~(unsigned int)(uint16_t)sum);
}

int gettimeofday();

static inline int ping_time_now(ping_time_t *time)
{
    struct timeval tv;
    int result;
    result = gettimeofday(&tv, NULL);
    time->secs = tv.tv_sec;
    time->usecs = tv.tv_usec;
    return result;
}

/* ping_time_compare
 *
 * Compare two timestamps
 *
 * Returns -1 if time1 is earlier, 1 if time1 is later,
 * or 0 if the timestamps are equal.
 */
static inline int ping_time_compare(ping_time_t *time1, ping_time_t *time2)
{
    if (time1->secs < time2->secs)
        return -1;
    if (time1->secs > time2->secs)
        return 1;
    if (time1->usecs < time2->usecs)
        return -1;
    if (time1->usecs > time2->usecs)
        return 1;
    return 0;
}

/* ping_time_diff
 *
 * Calculates the time from time2 to time1, assuming time1 is later than time2.
 * The diff will always be positive, so the return value should be checked
 * to determine if time1 was earlier than time2.
 *
 * Returns 1 if the time1 is less than or equal to time2, otherwise 0.
 */
static inline int ping_time_diff(ping_time_t *time1, ping_time_t *time2, ping_time_t *diff)
{
    int past = 0;
    int cmp = 0;

    cmp = ping_time_compare(time1, time2);
    if (cmp == 0) {
        diff->secs = 0;
        diff->usecs = 0;
        past = 1;
    }
    else if (cmp == 1) {
        diff->secs = time1->secs - time2->secs;
        diff->usecs = time1->usecs;
        if (diff->usecs < time2->usecs) {
            diff->secs --;
            diff->usecs += 1000000;
        }
        diff->usecs = diff->usecs - time2->usecs;
    } else {
        diff->secs = time2->secs - time1->secs;
        diff->usecs = time2->usecs;
        if (diff->usecs < time1->usecs) {
            diff->secs --;
            diff->usecs += 1000000;
        }
        diff->usecs = diff->usecs - time1->usecs;
        past = 1;
    }

    return past;
}

static inline uint64_t ping_time_in_msecs(ping_time_t *time)
{
    return time->secs * 1000 + time->usecs / 1000;
}

#pragma pack()

/*Convert IP Adderss to hexadecimal*/
int strip_to_hex(int *number, int len);

/*Dump buffer in hex format on console*/
void dump_hex(const void *data, unsigned len);

/*Convert IP Adderss to hexadecimal*/
int IP_to_hex(char *IPstr, uint8_t *hex);

/*Prase command*/
int string_to_command(char *strcom);

int wlan_scan_command(int argc, char **argv);

int wlan_connect_command(int argc, char **argv);

int wlan_disconnect_command(int argc, char **argv);

int wlan_start_wps_pbc_command(int argc, char **argv);

int wlan_process_wps_pbc_response(uint8_t *res);

int wlan_wps_generate_pin_command(int argc, char **argv);

int wlan_process_wps_generate_pin_response(uint8_t *res);

int wlan_start_wps_pin_command(int argc, char **argv);

int wlan_process_wps_pin_response(uint8_t *res);

int wlan_start_network_command(int argc, char **argv);

int wlan_stop_network_command(int argc, char **argv);

int wlan_get_uap_sta_list_command(int argc, char **argv);

int wlan_version_command(int argc, char **argv);

int wlan_set_mac_address_command(int argc, char **argv);

int wlan_get_mac_address_command(int argc, char **argv);

int wlan_stat_command(int argc, char **argv);

int wlan_roaming_command(int argc, char **argv);

int wlan_info_command(int argc, char **argv);

int wlan_get_signal_command(int argc, char **argv);

int wlan_multi_mef_command(int argc, char **argv);

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

int wlan_register_access_command(int argc, char **argv);

#ifdef CONFIG_MEM_MONITOR_DEBUG
int wlan_memory_state_command(int argc, char **argv);
#endif

int wlan_list_command(int argc, char **argv);

int wlan_remove_command(int argc, char **argv);

int wlan_process_ncp_event(uint8_t *res);

int wlan_process_response(uint8_t *res);

int wlan_process_discon_response(uint8_t *res);

int wlan_process_con_response(uint8_t *res);

void print_security_mode(uint8_t sec);

int wlan_process_scan_response(uint8_t *res);

int wlan_process_ping_response(uint8_t *res);

int wlan_process_version_response(uint8_t *res);

int wlan_process_monitor_response(uint8_t *res);

int wlan_process_csi_response(uint8_t *res);

int wlan_process_11k_cfg_response(uint8_t *res);

int wlan_process_neighbor_req_response(uint8_t *res);

int wlan_process_rssi_response(uint8_t *res);

int wlan_process_set_mac_address(uint8_t *res);

int wlan_process_get_mac_address(uint8_t *res);

int wlan_process_stat(uint8_t *res);

int wlan_process_info(uint8_t *res);

int wlan_process_wlan_reset_result_response(uint8_t *res);

int wlan_process_wlan_uap_prov_start_result_response(uint8_t *res);

int wlan_process_wlan_uap_prov_reset_result_response(uint8_t *res);

int wlan_process_roaming(uint8_t *res);

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

int wlan_process_add_response(uint8_t *res);

int wlan_process_start_network_response(uint8_t *res);

int wlan_process_stop_network_response(uint8_t *res);

int wlan_process_get_uap_sta_list(uint8_t *res);

int ncp_process_set_cfg_response(uint8_t *res);

int ncp_process_get_cfg_response(uint8_t *res);

int wlan_process_multi_mef_response(uint8_t *res);

int wlan_set_wmm_uapsd_command(int argc, char **argv);

int wlan_process_wmm_uapsd_response(uint8_t *res);

int wlan_wmm_uapsd_qosinfo_command(int argc, char **argv);

int wlan_process_uapsd_qosinfo_response(uint8_t *res);

int wlan_uapsd_sleep_period_command(int argc, char **argv);

int wlan_process_uapsd_sleep_period_response(uint8_t *res);

int wlan_wake_cfg_command(int argc, char **argv);

int wlan_process_wake_mode_response(uint8_t *res);

int wlan_wowlan_cfg_command(int argc, char **argv);

int wlan_process_wakeup_condition_response(uint8_t *res);

int wlan_mcu_sleep_command(int argc, char **argv);

int wlan_process_mcu_sleep_response(uint8_t *res);

int wlan_suspend_command(int argc, char **argv);

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

int wlan_process_network_list_response(uint8_t *res);

int wlan_process_network_remove_response(uint8_t *res);

NCPCmd_DS_COMMAND *ncp_mpu_bridge_get_command_buffer();

void clear_mpu_bridge_command_buffer();

int mpu_bridge_init_cli_commands();

int ncp_ping_command(int argc, char **argv);

#endif /*__MPU_BRIDGE_COMMAND_H__*/
