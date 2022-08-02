/*
 *  Copyright 2008-2022 NXP
 *
 *  Licensed under the LA_OPT_NXP_Software_License.txt (the "Agreement")
 *
 */

/*! \file wifi-decl.h
 * \brief Wifi structure declarations
 */

#ifndef __WIFI_DECL_H__
#define __WIFI_DECL_H__

#include <stdint.h>
#include <stdbool.h>
#include <wm_utils.h>
#include <mlan_decl.h>
#include <mlan_ioctl.h>
#include <wifi_events.h>

/* fixme: remove these after complete integration with mlan */
#define MLAN_MAC_ADDR_LENGTH (6U)
/** Version string buffer length */
#define MLAN_MAX_VER_STR_LEN 128

#define PMK_BIN_LEN 32
#define PMK_HEX_LEN 64

#define MOD_GROUPS 7

#ifdef CONFIG_OWE
/** The open AP in OWE transmition Mode */
#define OWE_TRANS_MODE_OPEN 1U
/** The security AP in OWE trsnsition Mode */
#define OWE_TRANS_MODE_OWE 2U
#endif

#if 0
/** channel_field.flags */
#define CHANNEL_FLAGS_TURBO                   0x0010
#define CHANNEL_FLAGS_CCK                     0x0020
#define CHANNEL_FLAGS_OFDM                    0x0040
#define CHANNEL_FLAGS_2GHZ                    0x0080
#define CHANNEL_FLAGS_5GHZ                    0x0100
#define CHANNEL_FLAGS_ONLY_PASSIVSCAN_ALLOW   0x0200
#define CHANNEL_FLAGS_DYNAMIC_CCK_OFDM        0x0400
#define CHANNEL_FLAGS_GFSK                    0x0800
PACK_START struct channel_field {
    t_u16 frequency;
    t_u16 flags;
} PACK_END;

/** mcs_field.known */
#define MCS_KNOWN_BANDWIDTH                   0x01
#define MCS_KNOWN_MCS_INDEX_KNOWN             0x02
#define MCS_KNOWN_GUARD_INTERVAL              0x04
#define MCS_KNOWN_HT_FORMAT                   0x08
#define MCS_KNOWN_FEC_TYPE                    0x10
#define MCS_KNOWN_STBC_KNOWN                  0x20
#define MCS_KNOWN_NESS_KNOWN                  0x40
#define MCS_KNOWN_NESS_DATA                   0x80
/** bandwidth */
#define RX_BW_20                              0
#define RX_BW_40                              1
#define RX_BW_20L                             2
#define RX_BW_20U                             3
/** mcs_field.flags
The flags field is any combination of the following:
0x03    bandwidth - 0: 20, 1: 40, 2: 20L, 3: 20U
0x04    guard interval - 0: long GI, 1: short GI
0x08    HT format - 0: mixed, 1: greenfield
0x10    FEC type - 0: BCC, 1: LDPC
0x60    Number of STBC streams
0x80    Ness - bit 0 (LSB) of Number of extension spatial streams */
PACK_START struct mcs_field {
    t_u8 known;
    t_u8 flags;
    t_u8 mcs;
} PACK_END;

/** radiotap_body.flags */
#define RADIOTAP_FLAGS_DURING_CFG             0x01
#define RADIOTAP_FLAGS_SHORT_PREAMBLE         0x02
#define RADIOTAP_FLAGS_WEP_ENCRYPTION         0x04
#define RADIOTAP_FLAGS_WITH_FRAGMENT          0x08
#define RADIOTAP_FLAGS_INCLUDE_FCS            0x10
#define RADIOTAP_FLAGS_PAD_BTW_HEADER_PAYLOAD 0x20
#define RADIOTAP_FLAGS_FAILED_FCS_CHECK       0x40
#define RADIOTAP_FLAGS_USE_SGI_HT             0x80
PACK_START struct radiotap_body {
    t_u64 timestamp;
    t_u8 flags;
    t_u8 rate;
    struct channel_field channel;
    t_s8 antenna_signal;
    t_s8 antenna_noise;
    t_u8 antenna;
    struct mcs_field mcs;
} PACK_END;

typedef PACK_START struct _radiotap_header {
    struct ieee80211_radiotap_header hdr;
    struct radiotap_body body;
} PACK_END radiotap_header_t;
#endif

/** Station information structure */
typedef struct
{
    /** MAC address buffer */
    t_u8 mac[MLAN_MAC_ADDR_LENGTH];
    /**
     * Power management status
     * 0 = active (not in power save)
     * 1 = in power save status
     */
    t_u8 power_mgmt_status;
    /** RSSI: dBm */
    t_s8 rssi;
} wifi_sta_info_t;

/** Channel list structure */
typedef PACK_START struct _wifi_scan_chan_list_t
{
    /** Number of channels */
    uint8_t num_of_chan;
    /** Channel number */
    uint8_t chan_number[MLAN_MAX_CHANNEL];
} PACK_END wifi_scan_chan_list_t;

/**
 *  Note: This is variable length structure. The size of array mac_list is
 *  equal to count. The caller of the API which returns this structure does
 *  not need to separately free the array mac_list. It only needs to free
 *  the sta_list_t object after use.
 */
typedef struct
{
    /** Count */
    int count;
    /*
     * Variable length array. Max size is MAX_NUM_CLIENTS.
     */
    /* wifi_sta_info_t *list; */
} wifi_sta_list_t;

/** BSS type : STA */
#define BSS_TYPE_STA 0U
/** BSS type : UAP */
#define BSS_TYPE_UAP 1U

#define UAP_DEFAULT_CHANNEL 0

enum wifi_bss_security
{
    WIFI_SECURITY_NONE = 0,
    WIFI_SECURITY_WEP_STATIC,
    WIFI_SECURITY_WEP_DYNAMIC,
    WIFI_SECURITY_WPA,
    WIFI_SECURITY_WPA2,
};

enum wifi_bss_features
{
    WIFI_BSS_FEATURE_WMM = 0,
    WIFI_BSS_FEATURE_WPS = 1,
};

struct wifi_message
{
    uint16_t event;
    enum wifi_event_reason reason;
    void *data;
};

#ifdef CONFIG_P2P
struct wifi_wfd_event
{
    bool peer_event;
    bool action_frame;
    void *data;
};
#endif

/* Wlan Cipher structure */
typedef struct
{
    /** 1 bit value can be set for wep40 */
    uint8_t wep40 : 1;
    /** 1 bit value can be set for wep104 */
    uint8_t wep104 : 1;
    /** 1 bit value can be set for tkip */
    uint8_t tkip : 1;
    /** 1 bit valuecan be set for ccmp */
    uint8_t ccmp : 1;
    /** 4 bits are reserved */
    uint8_t rsvd : 4;
} _Cipher_t;

/* Security mode structure */
typedef struct
{
    /** No security */
    uint16_t noRsn : 1;
    /** WEP static */
    uint16_t wepStatic : 1;
    /** WEP dynamic */
    uint16_t wepDynamic : 1;
    /** WPA */
    uint16_t wpa : 1;
    /** WPA none */
    uint16_t wpaNone : 1;
    /** WPA 2 */
    uint16_t wpa2 : 1;
    /** OWE */
    uint16_t owe : 1;
    /** WPA 3 SAE */
    uint16_t wpa3_sae : 1;
    /** Reserved 10 bits */
    uint16_t rsvd : 10;
} _SecurityMode_t;

/* TODO: clean up the parts brought over from the Host SME BSSDescriptor_t,
 * remove ifdefs, consolidate security info */

/** MLAN Maximum SSID Length */
#define MLAN_MAX_SSID_LENGTH (32U)
/** MLAN Maximum PASSPHRASE Length */
#define MLAN_MAX_PASS_LENGTH (64)

/** Scan result information */
struct wifi_scan_result
{
    uint8_t bssid[MLAN_MAC_ADDR_LENGTH]; /*!< BSSID array */
    bool is_ibss_bit_set;                /*!< Is bssid set? */

    uint8_t ssid[MLAN_MAX_SSID_LENGTH]; /*!< ssid array */
    int ssid_len;                       /*!< SSID length */
    uint8_t Channel;                    /*!< Channel associated to the BSSID */
    uint8_t RSSI;                       /*!< Received signal strength */
    uint16_t beacon_period;             /*!< Beacon period */
    uint8_t dtim_period;                /*!< DTIM period */
    _SecurityMode_t WPA_WPA2_WEP;       /*!< Security mode info */
    _Cipher_t wpa_mcstCipher;           /*!< WPA multicast cipher */
    _Cipher_t wpa_ucstCipher;           /*!< WPA unicast cipher */
    _Cipher_t rsn_mcstCipher;           /*!< No security multicast cipher */
    _Cipher_t rsn_ucstCipher;           /*!< No security unicast cipher */
    bool is_pmf_required;               /*!< Is pmf required flag */

    /*!<
     **  WPA_WPA2 = 0 => Security not enabled
     **  = 1 => WPA mode
     **  = 2 => WPA2 mode
     **  = 3 => WEP mode
     */
    bool phtcap_ie_present;  /*!< PHT CAP IE present info */
    bool phtinfo_ie_present; /*!< PHT INFO IE present info */

    bool wmm_ie_present; /*!< WMM IE present info */
    uint8_t band;        /*!< Band info */

    bool wps_IE_exist;                         /*!< WPS IE exist info */
    uint16_t wps_session;                      /*!< WPS session */
    bool wpa2_entp_IE_exist;                   /*!< WPA2 enterprise IE exist info */
    uint8_t trans_mode;                        /*!< Trans mode */
    uint8_t trans_bssid[MLAN_MAC_ADDR_LENGTH]; /*!< Trans bssid array */
    uint8_t trans_ssid[MLAN_MAX_SSID_LENGTH];  /*!< Trans ssid array */
    int trans_ssid_len;                        /*!< Trans bssid length */
};

/** MAC address */
typedef struct
{
    /** Mac address array */
    char mac[MLAN_MAC_ADDR_LENGTH];
} wifi_mac_addr_t;

/** Firmware version */
typedef struct
{
    /** Firmware version string */
    char version_str[MLAN_MAX_VER_STR_LEN];
} wifi_fw_version_t;

/** Extended Firmware version */
typedef struct
{
    /** ID for extended version select */
    uint8_t version_str_sel;
    /** Firmware version string */
    char version_str[MLAN_MAX_VER_STR_LEN];
} wifi_fw_version_ext_t;

enum wlan_type
{
    WLAN_TYPE_NORMAL = 0,
    WLAN_TYPE_WIFI_CALIB,
    WLAN_TYPE_FCC_CERTIFICATION,
};

/** Tx power levels */
typedef struct
{
    /** Current power level */
    uint16_t current_level;
    /** Maximum power level */
    uint8_t max_power;
    /** Minimum power level */
    uint8_t min_power;

} wifi_tx_power_t;

/** Rf channel */
typedef struct
{
    /** Current channel */
    uint16_t current_channel;
    /** RF Type */
    uint16_t rf_type;
} wifi_rf_channel_t;

/** Remain on channel info structure */
typedef struct
{
    /** Remove */
    uint16_t remove;
    /** Current status */
    uint8_t status;
    /** band configuration */
    uint8_t bandcfg;
    /** Channel */
    uint8_t channel;
    /** Remain on channel period */
    uint32_t remain_period;
} wifi_remain_on_channel_t;

/** Data structure for cmd txratecfg */
typedef PACK_START struct _wifi_rate_cfg_t
{
    /** LG rate: 0, HT rate: 1, VHT rate: 2 */
    mlan_rate_format rate_format;
    /** Rate/MCS index (0xFF: auto) */
    t_u32 rate_index;
    /** Rate rate */
    t_u32 rate;
#ifdef CONFIG_11AC
    /** NSS */
    t_u32 nss;
#endif
} PACK_END wifi_rate_cfg_t;

/** Data structure for cmd get data rate */
typedef PACK_START struct _wifi_data_rate_t
{
    /** Tx data rate */
    t_u32 tx_data_rate;
    /** Rx data rate */
    t_u32 rx_data_rate;

    /** Tx channel bandwidth */
    t_u32 tx_ht_bw;
    /** Tx guard interval */
    t_u32 tx_ht_gi;
    /** Rx channel bandwidth */
    t_u32 rx_ht_bw;
    /** Rx guard interval */
    t_u32 rx_ht_gi;

#ifndef SD8801
    /** MCS index */
    t_u32 tx_mcs_index;
    /** MCS index */
    t_u32 rx_mcs_index;
#ifdef CONFIG_11AC
    /** NSS */
    t_u32 tx_nss;
    /** NSS */
    t_u32 rx_nss;
#endif
    /** LG rate: 0, HT rate: 1, VHT rate: 2 */
    mlan_rate_format tx_rate_format;
    /** LG rate: 0, HT rate: 1, VHT rate: 2 */
    mlan_rate_format rx_rate_format;
#endif
} PACK_END wifi_data_rate_t;

enum wifi_ds_command_type
{
    WIFI_DS_RATE_CFG      = 0,
    WIFI_DS_GET_DATA_RATE = 1,
};

/** Type definition of wifi_ds_rate */
typedef PACK_START struct _wifi_ds_rate
{
    /** Sub-command */
    enum wifi_ds_command_type sub_command;
    /** Rate configuration parameter */
    union
    {
        /** Rate configuration for MLAN_OID_RATE_CFG */
        wifi_rate_cfg_t rate_cfg;
        /** Data rate for MLAN_OID_GET_DATA_RATE */
        wifi_data_rate_t data_rate;
    } param;
} PACK_END wifi_ds_rate;

/** Type definition of wifi_ed_mac_ctrl_t */
typedef PACK_START struct _wifi_ed_mac_ctrl_t
{
    /** ED CTRL 2G */
    t_u16 ed_ctrl_2g;
    /** ED Offset 2G */
    t_s16 ed_offset_2g;
#ifdef CONFIG_5GHz_SUPPORT
    /** ED CTRL 5G */
    t_u16 ed_ctrl_5g;
    /** ED Offset 5G */
    t_s16 ed_offset_5g;
#endif
} PACK_END wifi_ed_mac_ctrl_t;

/** Type definition of wifi_bandcfg_t */
typedef PACK_START struct _wifi_bandcfg_t
{
    /** Infra band */
    mlan_band_def config_bands;
    /** fw supported band */
    mlan_band_def fw_bands;
} PACK_END wifi_bandcfg_t;

#ifdef SD8801
/** Type definition of wifi_ext_coex_config_t */
typedef PACK_START struct _wifi_ext_coex_config_t
{
    /** Enable or disable external coexistence */
    t_u8 Enabled;
    /** Ignore the priority of the external radio request */
    t_u8 IgnorePriority;
    /** Default priority when the priority of the external radio
request is ignored */
    t_u8 DefaultPriority;
    /** Input request GPIO pin for EXT_RADIO_REQ signal */
    t_u8 EXT_RADIO_REQ_ip_gpio_num;
    /** Input request GPIO polarity for EXT_RADIO_REQ signal */
    t_u8 EXT_RADIO_REQ_ip_gpio_polarity;
    /** Input priority GPIO pin for EXT_RADIO_PRI signal */
    t_u8 EXT_RADIO_PRI_ip_gpio_num;
    /** Input priority GPIO polarity for EXT_RADIO_PRI signal */
    t_u8 EXT_RADIO_PRI_ip_gpio_polarity;
    /** Output grant GPIO pin for WLAN_GRANT signal */
    t_u8 WLAN_GRANT_op_gpio_num;
    /** Output grant GPIO polarity of WLAN_GRANT */
    t_u8 WLAN_GRANT_op_gpio_polarity;
    /** Reserved Bytes */
    t_u16 reserved_1;
    /** Reserved Bytes */
    t_u16 reserved_2;
} PACK_END wifi_ext_coex_config_t;

/** Type definition of wifi_ext_coex_stats_t */
typedef PACK_START struct _wifi_ext_coex_stats_t
{
    /** External Radio Request count */
    t_u16 ext_radio_req_count;
    /** External Radio Priority count */
    t_u16 ext_radio_pri_count;
    /** WLAN GRANT count */
    t_u16 wlan_grant_count;
} PACK_END wifi_ext_coex_stats_t;
#endif

/** Type definition of wifi_antcfg_t */
typedef PACK_START struct _wifi_antcfg_t
{
    /** Antenna Mode */
    t_u32 ant_mode;
    /** Evaluate Time */
    t_u16 evaluate_time;
} PACK_END wifi_antcfg_t;

/** CW_MODE_CTRL structure */
typedef PACK_START struct _wifi_cw_mode_ctrl_t
{
    /** Mode of Operation 0:Disable 1: Tx Continuous Packet 2 : Tx
 Continuous Wave */
    t_u8 mode;
    /** channel */
    t_u8 channel;
    /** channel info */
    t_u8 chanInfo;
    /** Tx Power level in dBm */
    t_u16 txPower;
    /** Packet Length */
    t_u16 pktLength;
    /** bit rate info */
    t_u32 rateInfo;
} PACK_END wifi_cw_mode_ctrl_t;

/** TBTT offset structure */
typedef struct
{
    /** Min TBTT offset */
    t_u32 min_tbtt_offset;
    /** Max TBTT offset */
    t_u32 max_tbtt_offset;
    /** AVG TBTT offset */
    t_u32 avg_tbtt_offset;
} wifi_tbtt_offset_t;

#define BIT(n)                           (1 << n)
#define WOWLAN_MAX_PATTERN_LEN           20
#define WOWLAN_MAX_OFFSET_LEN            50
#define MAX_NUM_FILTERS                  10
#define MEF_MODE_HOST_SLEEP              (1 << 0)
#define MEF_MODE_NON_HOST_SLEEP          (1 << 1)
#define MEF_ACTION_WAKE                  (1 << 0)
#define MEF_ACTION_ALLOW                 (1 << 1)
#define MEF_ACTION_ALLOW_AND_WAKEUP_HOST 3
#define MEF_AUTO_ARP                     0x10
#define MEF_AUTO_PING                    0x20
#define MEF_NS_RESP                      0x40
#define MEF_MAGIC_PKT                    0x80
#define CRITERIA_BROADCAST               BIT(0)
#define CRITERIA_UNICAST                 BIT(1)
#define CRITERIA_MULTICAST               BIT(3)

#define MAX_NUM_ENTRIES  8
#define MAX_NUM_BYTE_SEQ 6
#define MAX_NUM_MASK_SEQ 6

#define OPERAND_DNUM     1
#define OPERAND_BYTE_SEQ 2

#define MAX_OPERAND  0x40
#define TYPE_BYTE_EQ (MAX_OPERAND + 1)
#define TYPE_DNUM_EQ (MAX_OPERAND + 2)
#define TYPE_BIT_EQ  (MAX_OPERAND + 3)

#define RPN_TYPE_AND (MAX_OPERAND + 4)
#define RPN_TYPE_OR  (MAX_OPERAND + 5)

#define ICMP_OF_IP_PROTOCOL 0x01
#define TCP_OF_IP_PROTOCOL  0x06
#define UDP_OF_IP_PROTOCOL  0x11

#define IPV4_PKT_OFFSET      20
#define IP_PROTOCOL_OFFSET   31
#define PORT_PROTOCOL_OFFSET 44

#define FILLING_TYPE      MBIT(0)
#define FILLING_PATTERN   MBIT(1)
#define FILLING_OFFSET    MBIT(2)
#define FILLING_NUM_BYTES MBIT(3)
#define FILLING_REPEAT    MBIT(4)
#define FILLING_BYTE_SEQ  MBIT(5)
#define FILLING_MASK_SEQ  MBIT(6)

/** Type definition of filter_item
 *  support three match methods:
 *  <1>Byte comparison type=0x41
 *  <2>Decimal comparison type=0x42
 *  <3>Bit comparison type=0x43
 */
typedef struct _wifi_mef_filter_t
{
    /** BYTE 0X41; Decimal 0X42; Bit 0x43*/
    t_u16 type;
    /** value*/
    t_u32 pattern;
    /** offset*/
    t_u16 offset;
    /** number of bytes*/
    t_u16 num_bytes;
    /** repeat*/
    t_u16 repeat;
    /** byte number*/
    t_u8 num_byte_seq;
    /** array*/
    t_u8 byte_seq[MAX_NUM_BYTE_SEQ];
    /** mask numbers*/
    t_u8 num_mask_seq;
    /** array*/
    t_u8 mask_seq[MAX_NUM_MASK_SEQ];
} wifi_mef_filter_t;

/** MEF entry struct */
typedef struct _wifi_mef_entry_t
{
    /** mode: bit0--hostsleep mode; bit1--non hostsleep mode */
    t_u8 mode;
    /** action: 0--discard and not wake host;
                1--discard and wake host;
                3--allow and wake host;*/
    t_u8 action;
    /** filter number */
    t_u8 filter_num;
    /** filter array*/
    wifi_mef_filter_t filter_item[MAX_NUM_FILTERS];
    /** rpn array*/
    t_u8 rpn[MAX_NUM_FILTERS];
} wifi_mef_entry_t;

/** Wifi filter config struct */
typedef struct _wifi_flt_cfg
{
    /** Filter Criteria */
    t_u32 criteria;
    /** Number of entries */
    t_u16 nentries;
    /** MEF entry*/
    wifi_mef_entry_t mef_entry;
} wifi_flt_cfg_t;

/* User defined pattern struct */
typedef struct
{
    /** pattern offset of received pattern */
    t_u8 pkt_offset;
    /** pattern length */
    t_u8 pattern_len;
    /** wowlan pattern */
    t_u8 pattern[WOWLAN_MAX_PATTERN_LEN];
    /** mask */
    t_u8 mask[6];
} wifi_wowlan_pattern_t;

/* Wowlan Pattern config struct */
typedef struct
{
    /** Enable user defined pattern*/
    t_u8 enable;
    /** number of patterns******/
    t_u8 n_patterns;
    /** user define pattern*/
    wifi_wowlan_pattern_t patterns[MAX_NUM_FILTERS];
} wifi_wowlan_ptn_cfg_t;

/** TCP keep alive information */
typedef struct
{
    /** Enable keep alive */
    t_u8 enable;
    /** Reset */
    t_u8 reset;
    /** Keep alive timeout */
    t_u32 timeout;
    /** Keep alive interval */
    t_u16 interval;
    /** Maximum keep alives */
    t_u16 max_keep_alives;
    /** Destination MAC address */
    t_u8 dst_mac[MLAN_MAC_ADDR_LENGTH];
    /** Destination IP */
    t_u32 dst_ip;
    /** Destination TCP port */
    t_u16 dst_tcp_port;
    /** Source TCP port */
    t_u16 src_tcp_port;
    /** Sequence number */
    t_u32 seq_no;
} wifi_tcp_keep_alive_t;

/** TCP nat keep alive information */
typedef struct
{
    /** Keep alive interval */
    t_u16 interval;
    /** Destination MAC address */
    t_u8 dst_mac[MLAN_MAC_ADDR_LENGTH];
    /** Destination IP */
    t_u32 dst_ip;
    /** Destination port */
    t_u16 dst_port;
} wifi_nat_keep_alive_t;

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
} wifi_rssi_info_t;

/**
 * Data structure for subband set
 *
 * For uAP 11d support
 */
typedef struct
{
    /** First channel */
    t_u8 first_chan;
    /** Number of channels */
    t_u8 no_of_chan;
    /** Maximum Tx power in dBm */
    t_u8 max_tx_pwr;

} wifi_sub_band_set_t;

/**
 * Data structure for domain parameters
 *
 * This structure is accepted by wlan_uap_set_domain_params() API. This
 * information is used to generate the country info IE.
 */
typedef struct
{
    /** Country code */
    t_u8 country_code[COUNTRY_CODE_LEN];
    /** subbands count */
    t_u8 no_of_sub_band;
    /** Set of subbands of no_of_sub_band number of elements */
    wifi_sub_band_set_t sub_band[1];
} wifi_domain_param_t;

/**
 * Data structure for Channel attributes
 *
 */
typedef PACK_START struct
{
    /** Channel Number */
    t_u8 chan_num;
    /** Channel frequency for this channel */
    t_u16 chan_freq;
    /** Passice Scan or RADAR Detect*/
    bool passive_scan_or_radar_detect;
} PACK_END wifi_chan_info_t;

/**
 * Data structure for Channel List Config
 *
 */
typedef PACK_START struct
{
    /** Number of Channels */
    t_u8 num_chans;
    /** Channel Info */
    wifi_chan_info_t chan_info[54];
} PACK_END wifi_chanlist_t;

/** Wifi subband enum */
typedef enum
{
    /** Subband 2.4 GHz */
    SubBand_2_4_GHz = 0x00,
    /** Subband 5 GHz 0 */
    SubBand_5_GHz_0 = 0x10,
    /** Subband 5 GHz 1 */
    SubBand_5_GHz_1 = 0x11,
    /** Subband 5 GHz 2 */
    SubBand_5_GHz_2 = 0x12,
    /** Subband 5 GHz 3 */
    SubBand_5_GHz_3 = 0x13,
} wifi_SubBand_t;

/**
 * Data structure for Channel descriptor
 *
 * Set CFG data for Tx power limitation
 *
 * start_freq: Starting Frequency of the band for this channel\n
 *                  2407, 2414 or 2400 for 2.4 GHz\n
 *                  5000\n
 *                  4000\n
 * chan_width: Channel Width\n
 *                  20\n
 * chan_num  : Channel Number\n
 *
 */
typedef PACK_START struct
{
    /** Starting frequency of the band for this channel */
    t_u16 start_freq;
    /** Channel width */
    t_u8 chan_width;
    /** Channel Number */
    t_u8 chan_num;
} PACK_END wifi_channel_desc_t;

/**
 * Data structure for Modulation Group
 *
 * mod_group : ModulationGroup\n
 *                  0: CCK (1,2,5.5,11 Mbps)\n
 *                  1: OFDM (6,9,12,18 Mbps)\n
 *                  2: OFDM (24,36 Mbps)\n
 *                  3: OFDM (48,54 Mbps)\n
 *                  4: HT20 (0,1,2)\n
 *                  5: HT20 (3,4)\n
 *                  6: HT20 (5,6,7)\n
 *                  7: HT40 (0,1,2)\n
 *                  8: HT40 (3,4)\n
 *                  9: HT40 (5,6,7)\n
 *                  10: HT2_20 (8,9,10)\n
 *                  11: HT2_20 (11,12)\n
 *                  12: HT2_20 (13,14,15)\n
 *tx_power   : Power Limit in dBm\n
 *
 */
typedef PACK_START struct
{
    /** Modulation group */
    t_u8 mod_group;
    /** Tx Power */
    t_u8 tx_power;
} PACK_END wifi_txpwrlimit_entry_t;

/**
 * Data structure for TRPC config
 *
 * For TRPC support
 */
typedef PACK_START struct
{
    /** Number of modulation groups */
    t_u8 num_mod_grps;
    /** Chnannel descriptor */
    wifi_channel_desc_t chan_desc;
    /** Channel Modulation groups */
#ifdef CONFIG_11AX
    wifi_txpwrlimit_entry_t txpwrlimit_entry[20];
#elif defined(CONFIG_11AC)
    wifi_txpwrlimit_entry_t txpwrlimit_entry[16];
#else
    wifi_txpwrlimit_entry_t txpwrlimit_entry[10];
#endif /* CONFIG_11AX */
} PACK_END wifi_txpwrlimit_config_t;

/**
 * Data structure for Channel TRPC config
 *
 * For TRPC support
 */
typedef PACK_START struct
{
    /** SubBand */
    wifi_SubBand_t subband;
    /** Number of Channels */
    t_u8 num_chans;
    /** TRPC config */
    wifi_txpwrlimit_config_t txpwrlimit_config[40];
} PACK_END wifi_txpwrlimit_t;

#ifdef CONFIG_WLAN_BRIDGE
/**
 * Data structure for Bridge Autolink Configuration
 */
typedef struct
{
    /** Auto Link Periodical scan interval */
    uint32_t scan_timer_interval;
    /** The condition triggers Auto Link periodical scan
     *  0: trigger scan when current link is not good
     *  1: trigger scan by host setting(always periodical scan)
     */
    uint8_t scan_timer_condition;
    /** Auto Link periodical scan channel list:
     *  0: only scan with previous In-STA associated channel
     *  1: 2.4G all channels
     */
    uint8_t scan_channel_list;
} wifi_autolink_cfg_t;

/**
 * Data structure for Bridge Configuration
 */
#define ENABLE_AUTOLINK_BIT 1
#define HIDDEN_SSID_BIT     2
typedef struct
{
    /** Bit 0: Enable/Disable bridge mode,
     *  Bit 1: Enable/Disable auto link,
     *  Bit 2: Enable/Disable hidden ssid
     */
    uint8_t enable;
    /** Auto Link */
    bool auto_link;
    /** Hideen Bridge SSID */
    bool hidden_ssid;
    /** EX-AP SSID Length */
    uint8_t ex_ap_ssid_len;
    /** EX-AP SSID */
    char ex_ap_ssid[MLAN_MAX_SSID_LENGTH];
    /** EX-AP Passphrase length */
    uint8_t ex_ap_pass_len;
    /** EX-AP Passphrase */
    char ex_ap_pass[MLAN_MAX_PASS_LENGTH];
    /** Bridge SSID Length */
    uint8_t bridge_ssid_len;
    /** Bridge SSID */
    char bridge_ssid[MLAN_MAX_SSID_LENGTH];
    /** Bridge Passphrase length */
    uint8_t bridge_pass_len;
    /** Bridge Passphrase */
    char bridge_pass[MLAN_MAX_PASS_LENGTH];
    /**auto link configuration*/
    wifi_autolink_cfg_t autolink;
} wifi_bridge_cfg_t;
#endif

#ifndef CONFIG_MLAN_WMSDK

/** Network monitor structure */
typedef struct
{
    /** Monitor activity */
    uint16_t monitor_activity;
    /** Filter flags */
    uint16_t filter_flags;
    uint8_t radio_type;
    /** Channel number */
    uint8_t chan_number;
} wifi_net_monitor_t;

/** Beacon information structure */
typedef PACK_START struct
{
    /** Frame control flags */
    uint8_t frame_ctrl_flags;
    uint16_t duration;
    /** Destination MAC address */
    char dest[MLAN_MAC_ADDR_LENGTH];
    /** Source MAC address */
    char src[MLAN_MAC_ADDR_LENGTH];
    /** BSSID */
    char bssid[MLAN_MAC_ADDR_LENGTH];
    uint16_t seq_frag_num;
    /** Timestamp */
    uint8_t timestamp[8];
    uint16_t beacon_interval;
    uint16_t cap_info;
    uint8_t ssid_element_id;
    /** SSID Length */
    uint8_t ssid_len;
    /* SSID */
    char ssid[MLAN_MAX_SSID_LENGTH];
} PACK_END wifi_beacon_info_t;

/** Wifi data information */
typedef PACK_START struct
{
    /** Frame control flags */
    uint8_t frame_ctrl_flags;
    uint16_t duration;
    char bssid[MLAN_MAC_ADDR_LENGTH];
    /** Source MAC address */
    char src[MLAN_MAC_ADDR_LENGTH];
    /** Destination MAC address */
    char dest[MLAN_MAC_ADDR_LENGTH];
    uint16_t seq_frag_num;
    /** QOS control */
    uint16_t qos_ctrl;
} PACK_END wifi_data_info_t;

/** Wifi frame types */
typedef enum
{
    /** Assoc request frame */
    ASSOC_REQ_FRAME = 0x00,
    /** Assoc response frame */
    ASSOC_RESP_FRAME = 0x10,
    /** ReAssoc request frame */
    REASSOC_REQ_FRAME = 0x20,
    /** ReAssoc response frame */
    REASSOC_RESP_FRAME = 0x30,
    /** Probe request frame */
    PROBE_REQ_FRAME = 0x40,
    /** Probe response frame */
    PROBE_RESP_FRAME = 0x50,
    /** BEACON frame */
    BEACON_FRAME = 0x80,
    /** Dis assoc frame */
    DISASSOC_FRAME = 0xA0,
    /** Auth frame */
    AUTH_FRAME = 0xB0,
    /** Deauth frame */
    DEAUTH_FRAME = 0xC0,
    /** Action frame */
    ACTION_FRAME = 0xD0,
    /** Data frame */
    DATA_FRAME = 0x08,
    /** QOS frame */
    QOS_DATA_FRAME = 0x88,
} wifi_frame_type_t;

typedef PACK_START struct
{
    wifi_frame_type_t frame_type;
    union
    {
        wifi_beacon_info_t beacon_info;
        wifi_data_info_t data_info;
    } frame_data;
} PACK_END wifi_frame_t;
#endif

typedef struct
{
    uint8_t mfpc;
    uint8_t mfpr;
} wifi_pmf_params_t;

#ifndef CONFIG_MLAN_WMSDK
/** mix rate information structure */
typedef PACK_START struct _mix_rate_info
{
    /**  bit0: LGI: gi=0, SGI: gi= 1 */
    /**  bit1-2: 20M: bw=0, 40M: bw=1, 80M: bw=2, 160M: bw=3  */
    /**  bit3-4: LG: format=0, HT: format=1, VHT: format=2 */
    /**  bit5: LDPC: 0-not support,  1-support */
    /**  bit6-7:reserved */
    t_u8 rate_info;
    /** MCS index */
    t_u8 mcs_index;
    /** bitrate, in 500Kbps */
    t_u16 bitrate;
} PACK_END mix_rate_info, *pmix_rate_info;

/** rxpd extra information structure */
typedef PACK_START struct _rxpd_extra_info
{
    /** flags */
    t_u8 flags;
    /** channel.flags */
    t_u16 channel_flags;
    /** mcs.known */
    t_u8 mcs_known;
    /** mcs.flags */
    t_u8 mcs_flags;
} PACK_END rxpd_extra_info, *prxpd_extra_info;
#endif

/** Channel scan parameters */
typedef struct
{
    /** channel number */
    t_u8 chan_number;
    /** minimum scan time */
    t_u16 min_scan_time;
    /** maximum scan time */
    t_u16 max_scan_time;
} wifi_chan_scan_param_set_t;

/** Channel list parameter set */
typedef struct
{
    /** number of channels */
    t_u8 no_of_channels;
    /** channel scan array */
    wifi_chan_scan_param_set_t chan_scan_param[1];
} wifi_chan_list_param_set_t;

#ifndef CONFIG_MLAN_WMSDK
/** 802_11_header packet */
typedef PACK_START struct _wifi_mgmt_frame_t
{
    /** Packet Length */
    t_u16 frm_len;
    /** Frame Type */
    wifi_frame_type_t frame_type;
    /** Frame Control flags */
    t_u8 frame_ctrl_flags;
    /** Duration ID */
    t_u16 duration_id;
    /** Address 1 */
    t_u8 addr1[MLAN_MAC_ADDR_LENGTH];
    /** Address 2 */
    t_u8 addr2[MLAN_MAC_ADDR_LENGTH];
    /** Address 3 */
    t_u8 addr3[MLAN_MAC_ADDR_LENGTH];
    /** Sequence Control */
    t_u16 seq_ctl;
    /** Address 4 */
    t_u8 addr4[MLAN_MAC_ADDR_LENGTH];
    /** Frame payload */
    t_u8 payload[0];
} PACK_END wifi_mgmt_frame_t;
#endif

/** Calibration Data */
typedef PACK_START struct _wifi_cal_data_t
{
    /** Calibration data length */
    t_u16 data_len;
    /** Calibration data */
    t_u8 *data;
} PACK_END wifi_cal_data_t;

/** Auto reconnect structure */
typedef PACK_START struct _wifi_auto_reconnect_config_t
{
    /** Reconnect counter */
    t_u8 reconnect_counter;
    /** Reconnect interval */
    t_u8 reconnect_interval;
    /** Flags */
    t_u16 flags;
} PACK_END wifi_auto_reconnect_config_t;

/** Scan channel list */
typedef PACK_START struct _wifi_scan_channel_list_t
{
    /** Channel numder */
    t_u8 chan_number;
    /** Scan type Active = 1, Passive = 2 */
    mlan_scan_type scan_type;
    /** Scan time */
    t_u16 scan_time;
} PACK_END wifi_scan_channel_list_t;

/* Configuration for wireless scanning */
#define MAX_CHANNEL_LIST 5
#ifdef CONFIG_COMBO_SCAN
#define MAX_NUM_SSID 2
#endif
/** V2 scan parameters */
typedef PACK_START struct _wifi_scan_params_v2_t
{
    /** BSSID to scan */
    t_u8 bssid[MLAN_MAC_ADDR_LENGTH];
    /** SSID to scan */
#ifdef CONFIG_COMBO_SCAN
    char ssid[MAX_NUM_SSID][MLAN_MAX_SSID_LENGTH + 1];
#else
    char ssid[MLAN_MAX_SSID_LENGTH + 1];
#endif
    /** Number of channels */
    t_u8 num_channels;
    /** Channel list with channel information */
    wifi_scan_channel_list_t chan_list[MAX_CHANNEL_LIST];
    /** Number of probes */
    t_u8 num_probes;
#ifdef CONFIG_SCAN_WITH_RSSIFILTER
    /** Threshold of rssi */
    t_s16 rssi_threshold;
#endif
    /** Callback to be called when scan is completed */
    int (*cb)(unsigned int count);
} PACK_END wifi_scan_params_v2_t;

#ifdef CONFIG_RF_TEST_MODE
/** Configuration for Manufacturing generic command */
typedef PACK_START struct _wifi_mfg_cmd_generic_cfg
{
    /** MFG command code */
    t_u32 mfg_cmd;
    /** Action */
    t_u16 action;
    /** Device ID */
    t_u16 device_id;
    /** MFG Error code */
    t_u32 error;
    /** value 1 */
    t_u32 data1;
    /** value 2 */
    t_u32 data2;
    /** value 3 */
    t_u32 data3;
} PACK_END wifi_mfg_cmd_generic_cfg_t;

/** Configuration for Manufacturing command Tx Frame */
typedef PACK_START struct _wifi_mfg_cmd_tx_frame
{
    /** MFG command code */
    t_u32 mfg_cmd;
    /** Action */
    t_u16 action;
    /** Device ID */
    t_u16 device_id;
    /** MFG Error code */
    t_u32 error;
    /** enable */
    t_u32 enable;
    /** data_rate */
    t_u32 data_rate;
    /** frame pattern */
    t_u32 frame_pattern;
    /** frame length */
    t_u32 frame_length;
    /** BSSID */
    t_u8 bssid[MLAN_MAC_ADDR_LENGTH];
    /** Adjust burst sifs */
    t_u16 adjust_burst_sifs;
    /** Burst sifs in us*/
    t_u32 burst_sifs_in_us;
    /** short preamble */
    t_u32 short_preamble;
    /** active sub channel */
    t_u32 act_sub_ch;
    /** short GI */
    t_u32 short_gi;
    /** Adv coding */
    t_u32 adv_coding;
    /** Tx beamforming */
    t_u32 tx_bf;
    /** HT Greenfield Mode*/
    t_u32 gf_mode;
    /** STBC */
    t_u32 stbc;
    /** power id */
    t_u32 rsvd[2];
} PACK_END wifi_mfg_cmd_tx_frame_t;

/** Configuration for Manufacturing command Tx Continuous */
typedef PACK_START struct _wifi_mfg_cmd_tx_cont
{
    /** MFG command code */
    t_u32 mfg_cmd;
    /** Action */
    t_u16 action;
    /** Device ID */
    t_u16 device_id;
    /** MFG Error code */
    t_u32 error;
    /** enable Tx*/
    t_u32 enable_tx;
    /** Continuous Wave mode */
    t_u32 cw_mode;
    /** payload pattern */
    t_u32 payload_pattern;
    /** CS Mode */
    t_u32 cs_mode;
    /** active sub channel */
    t_u32 act_sub_ch;
    /** Tx rate */
    t_u32 tx_rate;
    /** power id */
    t_u32 rsvd;
} PACK_END wifi_mfg_cmd_tx_cont_t;
#endif

#endif /* __WIFI_DECL_H__ */