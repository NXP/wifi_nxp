# Wi-Fi Driver API Reference Manual — FreeRTOS

> **OS:** FreeRTOS  
> **Source file:** `wlan.h`  
> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612

---

## Main Page

### Introduction

NXP wireless SoCs require a combination of firmware binary image
streamed into the radio subsystem, and driver source code compiled onto
the application MCU. The radio driver source code provides APIs that
enable a developer to send and receive packets over the radio interfaces
by communicating with the firmware images that are streamed into the
radio subsystems on start-up.

#### Developer Documentation

This manual provides developer reference documentation for Wi-Fi driver
and Wi-Fi Connection Manager. Refer to the source code for additional
information.

> **Note:** The File Documentation provides documentation for all the APIs
> available in the Wi-Fi driver and connection manager.

#### Supported SoC Summary

| SoC | Band | Max Channel Width | Wi-Fi Generation |
|-----|------|-------------------|-----------------|
| IW416 | 2.4/5 GHz | 20/40 MHz | Wi-Fi 4 (802.11n) |
| W8987 | 2.4/5 GHz | 20/40/80 MHz | Wi-Fi 5 (802.11ac) |
| RW610 | 2.4/5 GHz | 20 MHz | Wi-Fi 6 (802.11ax) |
| IW610 | 2.4/5 GHz | 20 MHz | Wi-Fi 6 (802.11ax) |
| IW612 | 2.4/5 GHz | 20/40/80 MHz | Wi-Fi 6 (802.11ax) |

#### Abbreviations and Acronyms

| Abbreviation | Description |
|---|---|
| ACS | auto channel selection |
| AID | association ID |
| AMI | Ambient Motion Index |
| AMPDU | aggregate medium access control protocol data unit |
| AP | Access Point |
| ARP | address resolution protocol |
| BSS | basic service set |
| BSSID | basic service set ID |
| BTM | BSS transition management |
| CA | Certificate Authority |
| CCK | complementary code keying |
| CLI | command line input |
| CSI | channel state information |
| CW | continuous wave |
| DH | Diffie Hellman |
| DPP | Device Provisioning Protocol |
| DTIM | delivery traffic indication map |
| EAP | Extensible Authentication Protocol |
| EAP TLS | Extensible Authentication Protocol Transport Layer Security |
| FCS | frame check sequence |
| FTM | Fine Timing Measurement |
| GI | guard interval |
| HE | 802.11ax high efficiency |
| HT | 802.11n high throughput |
| HTC | high throughput control |
| LDPC | low density parity check |
| MBO | multi band operation |
| MEF | memory efficient filtering |
| MFPC | Management Frame Protection Capable |
| MFPR | Management frame protection required |
| MIMO | multiple input multiple output |
| NAN | Neighbor Awareness Networking |
| NSS | N*N MIMO spatial stream |
| OBSS | overlapping basic service set |
| OWE | opportunistic wireless encryption |
| P2P | Peer to Peer |
| PBC | push button configuration |
| PEAP | Protected Extensible Authentication Protocol |
| PMF | protected management frame |
| PMK | pairwise master key |
| PMKSA | pairwise master key security association |
| PS | power save |
| QoS | quality of service |
| RSSI | received signal strength indicator |
| RTS | request to send |
| SAE | Simultaneous Authentication of Equals |
| SSID | service set ID |
| STBC | space time block code |
| TBTT | target beacon transmission time |
| TIM | Traffic Indication Map |
| TSF | timing synchronization function |
| TWT | Target Wake Time |
| UAPSD | unscheduled automatic power save delivery |
| VHT | 802.11ac very high throughput |
| WLCMGR | Wi-Fi command manager |
| WLS | Wireless Location Service |
| WPS | Wi-Fi Protected Setup |

---

## File Index

### File List

Here is a list of all documented files with brief descriptions:

| File | Description |
|------|-------------|
| `wlan.h` | This file provides Wi-Fi APIs for the application |

---

<div class="toc-block">
<h2>Table of Contents</h2>
<ul>
  <li><a href="#data-structures">Data Structures</a></li>
  <li><a href="#macros">Macros</a></li>
  <li><a href="#functions">Functions</a>
    <ul>
    <li><a href="#initialization-lifecycle">Initialization & Lifecycle</a></li>
    <li><a href="#connection-management">Connection Management</a></li>
    <li><a href="#network-management">Network Management</a></li>
    <li><a href="#network-status">Network Status</a></li>
    <li><a href="#scan">Scan</a></li>
    <li><a href="#uap-micro-access-point">UAP (Micro Access Point)</a></li>
    <li><a href="#power-management">Power Management</a></li>
    <li><a href="#host-sleep">Host Sleep</a></li>
    <li><a href="#tx-power-rate-control">TX Power & Rate Control</a></li>
    <li><a href="#antenna-configuration">Antenna Configuration</a></li>
    <li><a href="#channel-band-configuration">Channel & Band Configuration</a></li>
    <li><a href="#80211ax-wi-fi-6">802.11ax (Wi-Fi 6)</a></li>
    <li><a href="#80211ac-wi-fi-5">802.11ac (Wi-Fi 5)</a></li>
    <li><a href="#80211n-wi-fi-4">802.11n (Wi-Fi 4)</a></li>
    <li><a href="#ampdu-aggregation">AMPDU & Aggregation</a></li>
    <li><a href="#wmm-qos">WMM / QoS</a></li>
    <li><a href="#roaming-80211krv">Roaming (802.11k/r/v)</a></li>
    <li><a href="#twt-target-wake-time">TWT (Target Wake Time)</a></li>
    <li><a href="#wps">WPS</a></li>
    <li><a href="#dpp-device-provisioning-protocol">DPP (Device Provisioning Protocol)</a></li>
    <li><a href="#wi-fi-direct-p2p">Wi-Fi Direct (P2P)</a></li>
    <li><a href="#nan-neighbor-awareness-networking">NAN (Neighbor Awareness Networking)</a></li>
    <li><a href="#csi-channel-state-information">CSI (Channel State Information)</a></li>
    <li><a href="#ftm-80211az-ranging">FTM / 802.11az Ranging</a></li>
    <li><a href="#mbo-multi-band-operation">MBO (Multi-Band Operation)</a></li>
    <li><a href="#mef-management-entity-filter">MEF (Management Entity Filter)</a></li>
    <li><a href="#network-monitor">Network Monitor</a></li>
    <li><a href="#ed-mac-control">ED MAC Control</a></li>
    <li><a href="#rf-phy-configuration">RF & PHY Configuration</a></li>
    <li><a href="#event-subscription">Event Subscription</a></li>
    <li><a href="#management-frame">Management Frame</a></li>
    <li><a href="#security-crypto">Security & Crypto</a></li>
    <li><a href="#auto-reconnect">Auto Reconnect</a></li>
    <li><a href="#wowlan-wake-on-wlan">WoWLAN (Wake on WLAN)</a></li>
    <li><a href="#cloud-keep-alive">Cloud Keep-Alive</a></li>
    <li><a href="#sta-filter-management">STA & Filter Management</a></li>
    <li><a href="#statistics-diagnostics">Statistics & Diagnostics</a></li>
    <li><a href="#mac-address">MAC Address</a></li>
    <li><a href="#country-region">Country / Region</a></li>
    <li><a href="#calibration">Calibration</a></li>
    <li><a href="#register-access">Register Access</a></li>
    <li><a href="#utility-miscellaneous">Utility & Miscellaneous</a></li>
    </ul>
  </li>
</ul>
</div>

---

## Data Structures

| Struct | Supported SoCs |
|--------|---------------|
| `ftm_11mc_nego_cfg_t` | IW612 |
| `ipv4_config` | All |
| `ipv6_config` | All |
| `ranging_11az_cfg_t` | IW612 |
| `rx_pkt_he_rate_info` | All |
| `rx_pkt_ht_rate_info` | All |
| `rx_pkt_rate_info` | All |
| `rx_pkt_vht_rate_info` | All |
| `tx_ampdu_prot_mode_para` | RW610 |
| `tx_pkt_he_rate_info` | All |
| `tx_pkt_ht_rate_info` | All |
| `tx_pkt_rate_info` | All |
| `tx_pkt_vht_rate_info` | All |
| `wifi_scan_params_t` | All |
| `wlan_cipher` | All |
| `wlan_ieeeps_config` | All |
| `wlan_ip_config` | All |
| `wlan_nan_publish_params_t` | RW610 |
| `wlan_nan_subscribe_params_t` | RW610 |
| `wlan_network` | All |
| `wlan_network_security` | All |
| `wlan_scan_result` | All |

---

### Data Structure Documentation

#### ftm_11mc_nego_cfg_t Struct Reference


**Data Fields**


-   t_u8 burst_exponent

-   t_u8 burst_duration

-   t_u8 min_delta_FTM

-   t_u8 is_ASAP

-   t_u8 per_burst_FTM

-   t_u8 channel_spacing

-   t_u16 burst_period


**Detailed Description**


Structure of FTM_SESSION_CFG TLV data


**Field Documentation**



**t_u8 ftm_11mc_nego_cfg_t::burst_exponent**


Indicates how many burst instances are requested for the FTM session


**t_u8 ftm_11mc_nego_cfg_t::burst_duration**


Indicates the duration of a burst instance


**t_u8 ftm_11mc_nego_cfg_t::min_delta_FTM**


Minimum time between consecutive FTM frames


**t_u8 ftm_11mc_nego_cfg_t::is_ASAP**


ASAP/non-ASAP casel


**t_u8 ftm_11mc_nego_cfg_t::per_burst_FTM**


Number of FTMs per burst


**t_u8 ftm_11mc_nego_cfg_t::channel_spacing**


FTM channel spacing: HT20/HT40/VHT80/\...


**t_u16 ftm_11mc_nego_cfg_t::burst_period**


Indicates the interval between two consecutive burst instances


**The documentation for this struct was generated from the following file:**


-   wlan.h

> **Supported SoCs:** IW612


---

#### ipv4_config Struct Reference


**Data Fields**


-   enum address_types addr_type

-   unsigned address

-   unsigned gw

-   unsigned netmask

-   unsigned dns1

-   unsigned dns2


**Detailed Description**


This data structure represents an IPv4 address


**Field Documentation**



**enum address_types ipv4_config::addr_type**


Set to ADDR_TYPE_DHCP to use DHCP to obtain the IP address or set to ADDR_TYPE_STATIC to use a static IP. In case of static IP address ip, gw, netmask and dns members should be specified. When using DHCP, the ip, gw, netmask and dns are overwritten by the values obtained from the DHCP server. They should be zeroed out if not used.


**unsigned ipv4_config::address**


The system\'s IP address in network order.


**unsigned ipv4_config::gw**


The system\'s default gateway in network order.


**unsigned ipv4_config::netmask**


The system\'s subnet mask in network order.


**unsigned ipv4_config::dns1**


The system\'s primary dns server in network order.


**unsigned ipv4_config::dns2**


The system\'s secondary dns server in network order.


**The documentation for this struct was generated from the following file:**


-   wlan.h

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

#### ipv6_config Struct Reference


**Data Fields**


-   unsigned address \[4\]

-   unsigned char addr_type

-   uint8_t addr_state


**Detailed Description**


This data structure represents an IPv6 address


**Field Documentation**



**unsigned ipv6_config::address\[4\]**


The system\'s IPv6 address in network order.


**unsigned char ipv6_config::addr_type**


The address type: linklocal, site-local or global.


**uint8_t ipv6_config::addr_state**


The state of IPv6 address (Tentative, Preferred, etc.).


**The documentation for this struct was generated from the following file:**


-   wlan.h

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

#### ranging_11az_cfg_t Struct Reference


**Data Fields**


-   t_u8 format_bw

-   t_u8 max_i2r_sts_upto80

-   t_u8 max_r2i_sts_upto80

-   t_u8 az_measurement_freq

-   t_u8 az_number_of_measurements

-   t_u8 i2r_lmr_feedback

-   t_u8 civic_req

-   t_u8 lci_req


**Detailed Description**


Structure of FTM_SESSION_CFG_NTB_RANGING / FTM_SESSION_CFG_TB_RANGING TLV data


**Field Documentation**



**t_u8 ranging_11az_cfg_t::format_bw**


Indicates the channel BW for session 0: HE20, 1: HE40, 2: HE80, 3: HE80+80, 4: HE160, 5:HE160_SRF


**t_u8 ranging_11az_cfg_t::max_i2r_sts_upto80**


Indicates for bandwidths less than or equal to 80 MHz the maximum number of space-time streams to be used in DL/UL NDP frames in the session


**t_u8 ranging_11az_cfg_t::max_r2i_sts_upto80**


Indicates for bandwidths less than or equal to 80 MHz the maximum number of space-time streams to be used in DL/UL NDP frames in the session


**t_u8 ranging_11az_cfg_t::az_measurement_freq**


Specify measurement freq in Hz to calculate measurement interval


**t_u8 ranging_11az_cfg_t::az_number_of_measurements**


Indicates the number of measurements to be done for session


**t_u8 ranging_11az_cfg_t::i2r_lmr_feedback**


Initator lmr feedback


**t_u8 ranging_11az_cfg_t::civic_req**


Include location civic request (Expect location civic from responder)


**t_u8 ranging_11az_cfg_t::lci_req**


Include LCI request (Expect LCI info from responder)


**The documentation for this struct was generated from the following file:**


-   wlan.h

> **Supported SoCs:** IW612


---

#### rx_pkt_he_rate_info Struct Reference


**Data Fields**


-   t_u32 hemcs_rxcnt \[12\]

-   t_u32 hestbcrate_rxcnt \[12\]


**Detailed Description**


Sum of RX packets for HE (802.11ax high efficiency) rate.


**Field Documentation**



**t_u32 rx_pkt_he_rate_info::hemcs_rxcnt\[12\]**


Sum of RX packets for HE rate. The array index represents MSC0\~MCS11, the following array indexes have the same effect.


**t_u32 rx_pkt_he_rate_info::hestbcrate_rxcnt\[12\]**


Sum of RX STBC (space time block code) packets for HE rate.


**The documentation for this struct was generated from the following file:**


-   wlan.h

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

#### rx_pkt_ht_rate_info Struct Reference


**Data Fields**


-   t_u32 htmcs_rxcnt \[16\]

-   t_u32 htsgi_rxcnt \[16\]

-   t_u32 htstbcrate_rxcnt \[16\]


**Detailed Description**


Sum of RX packets for HT (802.11n high throughput) rate.


**Field Documentation**



**t_u32 rx_pkt_ht_rate_info::htmcs_rxcnt\[16\]**


Sum of RX packets for HT rate. The array index represents MSC0\~MCS15, the following array indexes have the same effect.


**t_u32 rx_pkt_ht_rate_info::htsgi_rxcnt\[16\]**


Sum of TX short GI (guard interval) packets for HT rate.


**t_u32 rx_pkt_ht_rate_info::htstbcrate_rxcnt\[16\]**


Sum of TX STBC (space time block code) packets for HT rate.


**The documentation for this struct was generated from the following file:**


-   wlan.h

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

#### rx_pkt_rate_info Struct Reference


**Data Fields**


-   t_u32 nss_rxcnt \[2\]

-   t_u32 nsts_rxcnt

-   t_u32 bandwidth_rxcnt \[3\]

-   t_u32 preamble_rxcnt \[6\]

-   t_u32 ldpc_txbfcnt \[2\]

-   t_s32 rssi_value \[2\]

-   t_s32 rssi_chain0 \[4\]

-   t_s32 rssi_chain1 \[4\]


**Detailed Description**


Sum of RX packets.


**Field Documentation**



**t_u32 rx_pkt_rate_info::nss_rxcnt\[2\]**


Sum of RX NSS (N\*N MIMO spatial stream) packets. nss_txcnt\[0\] is for NSS 1, nss_txcnt\[1\] is for NSS 2.


**t_u32 rx_pkt_rate_info::nsts_rxcnt**


Sum of received packets for all STBC rates.


**t_u32 rx_pkt_rate_info::bandwidth_rxcnt\[3\]**


Sum of received packets for three bandwidth types. bandwidth_rxcnt\[0\] is for 20MHz, bandwidth_rxcnt\[1\] is for 40MHz, bandwidth_rxcnt\[2\] is for 80MHz.


**t_u32 rx_pkt_rate_info::preamble_rxcnt\[6\]**


Sum of received packets for four preamble format types. preamble_txcnt\[0\] is for preamble format 0, preamble_txcnt\[1\] is for preamble format 1, preamble_txcnt\[2\] is for preamble format 2, preamble_txcnt\[3\] is for preamble format 3, preamble_txcnt\[4\] and preamble_txcnt\[5\] are as reserved.


**t_u32 rx_pkt_rate_info::ldpc_txbfcnt\[2\]**


Sum of packets for TX LDPC packets.


**t_s32 rx_pkt_rate_info::rssi_value\[2\]**


Average RSSI


**t_s32 rx_pkt_rate_info::rssi_chain0\[4\]**


RSSI value of path A


**t_s32 rx_pkt_rate_info::rssi_chain1\[4\]**


RSSI value of path B


**The documentation for this struct was generated from the following file:**


-   wlan.h

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

#### rx_pkt_vht_rate_info Struct Reference


**Data Fields**


-   t_u32 vhtmcs_rxcnt \[10\]

-   t_u32 vhtsgi_rxcnt \[10\]

-   t_u32 vhtstbcrate_rxcnt \[10\]


**Detailed Description**


Sum of RX packets for VHT (802.11ac very high throughput) rate.


**Field Documentation**



**t_u32 rx_pkt_vht_rate_info::vhtmcs_rxcnt\[10\]**


Sum of RX packets for VHT rate. The array index represents MSC0\~MCS9, the following array indexes have the same effect.


**t_u32 rx_pkt_vht_rate_info::vhtsgi_rxcnt\[10\]**


Sum of RX short GI (guard interval) packets for VHT rate.


**t_u32 rx_pkt_vht_rate_info::vhtstbcrate_rxcnt\[10\]**


Sum of RX STBC (space time block code) packets for VHT rate.


**The documentation for this struct was generated from the following file:**


-   wlan.h

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

## tx_ampdu_prot_mode_para Struct Reference

### Data Fields

  - > int mode

### Detailed Description

Set protection mode for the transmit AMPDU packet

### Field Documentation

#### int tx_ampdu_prot_mode_para::mode

mode, 0: set RTS/CTS mode, 1: set CTS to self mode, 2: disable
protection mode, 3: set dynamic RTS/CTS mode.

#### The documentation for this struct was generated from the following file:

  - > wlan.h

####

> **Supported SoCs:** RW610


---

#### tx_pkt_he_rate_info Struct Reference


**Data Fields**


-   t_u32 hemcs_txcnt \[12\]

-   t_u32 hestbcrate_txcnt \[12\]


**Detailed Description**


Sum of TX packets for HE (802.11ax high efficiency) rate.


**Field Documentation**



**t_u32 tx_pkt_he_rate_info::hemcs_txcnt\[12\]**


Sum of TX packets for HE rate. The array index represents MSC0\~MCS11, the following array indexes have the same effect.


**t_u32 tx_pkt_he_rate_info::hestbcrate_txcnt\[12\]**


Sum of TX STBC (space time block code) packets for HE rate.


**The documentation for this struct was generated from the following file:**


-   wlan.h

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

#### tx_pkt_ht_rate_info Struct Reference


**Data Fields**


-   t_u32 htmcs_txcnt \[16\]

-   t_u32 htsgi_txcnt \[16\]

-   t_u32 htstbcrate_txcnt \[16\]


**Detailed Description**


Sum of TX packets for HT (802.11n high throughput) rate.


**Field Documentation**



**t_u32 tx_pkt_ht_rate_info::htmcs_txcnt\[16\]**


Sum of TX packets for HT rate. The array index represents MSC0\~MCS15, the following array indexes have the same effect.


**t_u32 tx_pkt_ht_rate_info::htsgi_txcnt\[16\]**


Sum of TX short GI (guard interval) packets for HT rate.


**t_u32 tx_pkt_ht_rate_info::htstbcrate_txcnt\[16\]**


Sum of TX STBC (space time block code) packets for HT rate.


**The documentation for this struct was generated from the following file:**


-   wlan.h

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

#### tx_pkt_rate_info Struct Reference


**Data Fields**


-   t_u32 nss_txcnt \[2\]

-   t_u32 bandwidth_txcnt \[3\]

-   t_u32 preamble_txcnt \[4\]

-   t_u32 ldpc_txcnt

-   t_u32 rts_txcnt

-   t_s32 ack_RSSI


**Detailed Description**


Sum of TX packets.


**Field Documentation**



**t_u32 tx_pkt_rate_info::nss_txcnt\[2\]**


Sum of TX NSS (N\*N MIMO spatial stream) packets. nss_txcnt\[0\] is for NSS 1, nss_txcnt\[1\] is for NSS 2.


**t_u32 tx_pkt_rate_info::bandwidth_txcnt\[3\]**


Sum of TX packets for three bandwidths. bandwidth_txcnt\[0\] is for 20MHz, bandwidth_txcnt\[1\] is for 40MHz, bandwidth_txcnt\[2\] is for 80MHz.


**t_u32 tx_pkt_rate_info::preamble_txcnt\[4\]**


Sum of RX packets for four preamble format types. preamble_txcnt\[0\] is for preamble format 0, preamble_txcnt\[1\] is for preamble format 1, preamble_txcnt\[2\] is for preamble format 2, preamble_txcnt\[3\] is for preamble format 3,


**t_u32 tx_pkt_rate_info::ldpc_txcnt**


Sum of TX LDPC (low density parity check) packets.


**t_u32 tx_pkt_rate_info::rts_txcnt**


Sum of TX RTS (request to send) packets


**t_s32 tx_pkt_rate_info::ack_RSSI**


RSSI of ACK packet


**The documentation for this struct was generated from the following file:**


-   wlan.h

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

#### tx_pkt_vht_rate_info Struct Reference


**Data Fields**


-   t_u32 vhtmcs_txcnt \[10\]

-   t_u32 vhtsgi_txcnt \[10\]

-   t_u32 vhtstbcrate_txcnt \[10\]


**Detailed Description**


Sum of TX packets for VHT (802.11ac very high throughput) rate.


**Field Documentation**



**t_u32 tx_pkt_vht_rate_info::vhtmcs_txcnt\[10\]**


Sum of TX packets for VHT rate. The array index represents MSC0\~MCS9, the following array indexes have the same effect.


**t_u32 tx_pkt_vht_rate_info::vhtsgi_txcnt\[10\]**


Sum of TX short GI packets for HT mode.


**t_u32 tx_pkt_vht_rate_info::vhtstbcrate_txcnt\[10\]**


Sum of TX STBC (space time block code) packets for VHT mode.


**The documentation for this struct was generated from the following file:**


-   wlan.h

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

#### wifi_scan_params_t Struct Reference


**Data Fields**


-   uint8_t \* bssid

-   char \* ssid

-   int channel \[MAX_CHANNEL_LIST\]

-   IEEEtypes_Bss_t bss_type

-   int scan_duration

-   int split_scan_delay


**Detailed Description**


This structure is used to configure Wi-Fi scan parameters


**Field Documentation**



**uint8_t\* wifi_scan_params_t::bssid**


BSSID (basic service set ID)


**char\* wifi_scan_params_t::ssid**


SSID (service set ID)


**int wifi_scan_params_t::channel\[MAX_CHANNEL_LIST\]**


Channel list


**IEEEtypes_Bss_t wifi_scan_params_t::bss_type**


BSS (basic service set) type. 1: Infrastructure BSS, 2: Indenpent BSS.


**int wifi_scan_params_t::scan_duration**


Time for scan duration


**int wifi_scan_params_t::split_scan_delay**


split scan delay


**The documentation for this struct was generated from the following file:**


-   wlan.h

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

#### wlan_cipher Struct Reference


**Data Fields**


-   uint16_t none: 1

-   uint16_t wep40: 1

-   uint16_t wep104: 1

-   uint16_t tkip: 1

-   uint16_t ccmp: 1

-   uint16_t aes_128_cmac: 1

-   uint16_t gcmp: 1

-   uint16_t sms4: 1

-   uint16_t gcmp_256: 1

-   uint16_t ccmp_256: 1

-   uint16_t rsvd: 1

-   uint16_t bip_gmac_128: 1

-   uint16_t bip_gmac_256: 1

-   uint16_t bip_cmac_256: 1

-   uint16_t gtk_not_used: 1

-   uint16_t rsvd2: 2


**Detailed Description**


Wi-Fi cipher structure


**Field Documentation**



**uint16_t wlan_cipher::none**


1 bit value can be set for none


**uint16_t wlan_cipher::wep40**


1 bit value can be set for wep40


**uint16_t wlan_cipher::wep104**


1 bit value can be set for wep104


**uint16_t wlan_cipher::tkip**


1 bit value can be set for tkip


**uint16_t wlan_cipher::ccmp**


1 bit value can be set for ccmp


**uint16_t wlan_cipher::aes_128_cmac**


1 bit value can be set for aes 128 cmac


**uint16_t wlan_cipher::gcmp**


1 bit value can be set for gcmp


**uint16_t wlan_cipher::sms4**


1 bit value can be set for sms4


**uint16_t wlan_cipher::gcmp_256**


1 bit value can be set for gcmp 256


**uint16_t wlan_cipher::ccmp_256**


1 bit value can be set for ccmp 256


**uint16_t wlan_cipher::rsvd**


1 bit is reserved


**uint16_t wlan_cipher::bip_gmac_128**


1 bit value can be set for bip gmac 128


**uint16_t wlan_cipher::bip_gmac_256**


1 bit value can be set for bip gmac 256


**uint16_t wlan_cipher::bip_cmac_256**


1 bit value can be set for bip cmac 256


**uint16_t wlan_cipher::gtk_not_used**


1 bit value can be set for gtk not used


**uint16_t wlan_cipher::rsvd2**


4 bits are reserved


**The documentation for this struct was generated from the following file:**


-   wlan.h

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

#### wlan_ieeeps_config Struct Reference


**Data Fields**


-   t_u32 ps_null_interval

-   t_u32 multiple_dtim_interval

-   t_u32 listen_interval

-   t_u32 adhoc_awake_period

-   t_u32 bcn_miss_timeout

-   t_s32 delay_to_ps

-   t_u32 ps_mode


**Detailed Description**


This structure is for IEEE PS (power save) configuration


**Field Documentation**



**t_u32 wlan_ieeeps_config::ps_null_interval**


The interval that STA sends null packet


**t_u32 wlan_ieeeps_config::multiple_dtim_interval**


The count of listen interval


**t_u32 wlan_ieeeps_config::listen_interval**


Periodic interval that STA listens to AP beacons


**t_u32 wlan_ieeeps_config::adhoc_awake_period**


Periodic awake period for adhoc networks


**t_u32 wlan_ieeeps_config::bcn_miss_timeout**


Beacon miss timeout in milliseconds


**t_s32 wlan_ieeeps_config::delay_to_ps**


The delay of enabling IEEE-PS in milliseconds


**t_u32 wlan_ieeeps_config::ps_mode**


PS mode, 1: PS-auto mode, 2: PS-poll mode, 3: PS-null mode.


**The documentation for this struct was generated from the following file:**


-   wlan.h

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

#### wlan_ip_config Struct Reference


**Data Fields**


-   struct ipv6_config ipv6 \[CONFIG_MAX_IPV6_ADDRESSES\]

-   size_t ipv6_count

-   struct ipv4_config ipv4


**Detailed Description**


Network IP configuration.

This data structure represents the network IP configuration for IPv4 as well as IPv6 addresses


**Field Documentation**



**struct ipv6_config wlan_ip_config::ipv6\[CONFIG_MAX_IPV6_ADDRESSES\]**


The network IPv6 address configuration that should be associated with this interface.


**size_t wlan_ip_config::ipv6_count**


The network IPv6 valid addresses count


**struct ipv4_config wlan_ip_config::ipv4**


The network IPv4 address configuration that should be associated with this interface.


**The documentation for this struct was generated from the following file:**


-   wlan.h

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

## wlan_nan_publish_params_t Struct Reference

### Data Fields

  - > char \* **service_name**

  - > unsigned int **ttl**

  - > unsigned int **freq**

  - > char \* **freq_list**

  - > nan_service_protocol_type_t **srv_proto_type**

  - > char \* **ssi**

### Detailed Description

This structure is used to configure wlan nan publish parameters

The documentation for this struct was generated from the following file:

  - > wlan.h

> **Supported SoCs:** RW610


---

## wlan_nan_subscribe_params_t Struct Reference

### Data Fields

  - > char \* **service_name**

  - > bool **active**

  - > unsigned int **ttl**

  - > unsigned int **freq**

  - > nan_service_protocol_type_t **srv_proto_type**

  - > char \* **ssi**

### Detailed Description

This structure is used to configure wlan nan subscribe parameters

The documentation for this struct was generated from the following file:

  - > wlan.h

> **Supported SoCs:** RW610


---

#### wlan_network Struct Reference


**Data Fields**


-   int id

-   int wps_network

-   int unspecified_network

-   char name \[WLAN_NETWORK_NAME_MAX_LENGTH+1\]

-   char ssid \[IEEEtypes_SSID_SIZE+1\]

-   char bssid \[IEEEtypes_ADDRESS_SIZE\]

-   unsigned int channel

-   uint8_t sec_channel_offset

-   uint16_t acs_band

-   uint8_t chan_list \[WLAN_NETWORK_CHAN_LIST_MAX\]

-   uint8_t chan_list_len

-   int rssi

-   enum wlan_select_policy select_policy

-   int priority

-   unsigned short ht_capab

-   unsigned char he_oper_chwidth

-   enum wlan_bss_type type

-   enum wlan_bss_role role

-   struct wlan_network_security security

-   struct wlan_ip_config ip

-   unsigned ssid_specific: 1

-   unsigned bssid_specific: 1

-   unsigned channel_specific: 1

-   unsigned security_specific: 1

-   unsigned priority_specific: 1

-   unsigned dot11n: 1

-   unsigned dot11ax: 1

-   uint16_t mdid

-   unsigned ft_1x: 1

-   unsigned ft_psk: 1

-   unsigned ft_sae: 1

-   uint16_t beacon_period

-   uint8_t dtim_period

-   uint8_t btm_mode

-   bool bss_transition_supported

-   bool neighbor_report_supported

-   bool **twt_capab**


**Detailed Description**


Wi-Fi network profile

This data structure represents a Wi-Fi network profile. It consists of an arbitrary name, Wi-Fi configuration, and IP address configuration.

Every network profile is associated with one of the two interfaces. The network profile can be used for the station interface (i.e. to connect to an Access Point) by setting the role field to WLAN_BSS_ROLE_STA. The network profile can be used for the uAP interface (i.e. to start a network of our own.) by setting the mode field to WLAN_BSS_ROLE_UAP.

If the mode field is WLAN_BSS_ROLE_STA, either of the SSID or BSSID fields are used to identify the network, while the other members like channel and security settings characterize the network.

If the mode field is WLAN_BSS_ROLE_UAP, the SSID, channel and security fields are used to define the network to be started.

In both the above cases, the address field is used to determine the type of address assignment to be used for this interface.


**Field Documentation**



**int wlan_network::id**


Identifier for network profile


**int wlan_network::wps_network**


WPS network flag.


**int wlan_network::unspecified_network**


Unspecified network flag.


**char wlan_network::name\[WLAN_NETWORK_NAME_MAX_LENGTH+1\]**


The name of this network profile. Each network profile that is added to the Wi-Fi connection manager should have a unique name.


**char wlan_network::ssid\[IEEEtypes_SSID_SIZE+1\]**


The network SSID, represented as a C string of up to 32 characters in length. If this profile is used in the uAP mode, this field is used as the SSID of the network. If this profile is used in the station mode, this field is used to identify the network. Set the first byte of the SSID to NULL (a 0-length string) to use only the BSSID to find the network.


**char wlan_network::bssid\[IEEEtypes_ADDRESS_SIZE\]**


The network BSSID, represented as a 6-byte array. If this profile is used in the uAP mode, this field is ignored. If this profile is used in the station mode, this field is used to identify the network. Set all 6 bytes to 0 to use any BSSID, in which case only the SSID is used to find the network.


**unsigned int wlan_network::channel**


The channel for this network.

If this profile is used in uAP mode, this field specifies the channel to start the uAP interface on. Set this to 0 for auto channel selection.

If this profile is used in the station mode, this constrains the channel on which the network to connect should be present. Set this to 0 to allow the network to be found on any channel.


**uint8_t wlan_network::sec_channel_offset**


The secondary channel offset


**uint16_t wlan_network::acs_band**


The ACS (auto channel selection) band if set channel to 0.


**uint8_t wlan_network::chan_list\[WLAN_NETWORK_CHAN_LIST_MAX\]**


Array of channel list to scan or NULL for all

This is a array of channels to include in scan requests when searching for this network. This can be used to speed up scanning when the network is known to not use all possible channels.


**uint8_t wlan_network::chan_list_len**


Number of channels in the channel list


**int wlan_network::rssi**


RSSI (received signal strength indicator) value.


**enum wlan_select_policy wlan_network::select_policy**


Network selection policy


**int wlan_network::priority**


Priority group


**unsigned short wlan_network::ht_capab**


HT capabilities info field within HT capabilities information element


**unsigned char wlan_network::he_oper_chwidth**


HE bandwidth


**enum wlan_bss_type wlan_network::type**


BSS type


**enum wlan_bss_role wlan_network::role**


The network Wi-Fi mode enum wlan_bss_role. Set this to specify what type of Wi-Fi network mode to use. This can either be WLAN_BSS_ROLE_STA for use in the station mode, or it can be WLAN_BSS_ROLE_UAP for use in the uAP mode.


**struct wlan_network_security wlan_network::security**


The network security configuration specified by struct wlan_network_security for the network.


**struct wlan_ip_config wlan_network::ip**


The network IP address configuration specified by struct wlan_ip_config that should be associated with this interface.


**unsigned wlan_network::ssid_specific**


If set to 1, the ssid field contains the specific SSID for this network. the Wi-Fi connection manager can only connect to networks with matching SSID matches. If set to 0, the ssid field contents are not used when deciding whether to connect to a network or not. The BSSID field is used instead and any network with matching BSSID matches is accepted.

This field can be set to 1 if the network is added with the SSID specified (not an empty string), otherwise it is set to 0.


**unsigned wlan_network::bssid_specific**


If set to 1, the bssid field contains the specific BSSID for this network. The Wi-Fi connection manager cannot connect to any other network with the same SSID unless the BSSID matches. If set to 0, the Wi-Fi connection manager can connect to any network whose SSID matches.

This field set to 1 if the network is added with the BSSID specified (not set to all zeroes), otherwise it is set to 0.


**unsigned wlan_network::channel_specific**


If set to 1, the channel field contains the specific channel for this network. The Wi-Fi connection manager cannot look for this network on any other channel. If set to 0, the Wi-Fi connection manager can look for this network on any available channel.

This field is set to 1 if the network is added with the channel specified (not set to 0), otherwise it is set to 0.


**unsigned wlan_network::security_specific**


If set to 0, any security that matches is used. This field is internally set when the security type parameter above is set to WLAN_SECURITY_WILDCARD.


**unsigned wlan_network::priority_specific**


If set to 1, the priority field contains the specific priority for this network. This field can be used to change the order in which wpa_supplicant goes through the networks when selecting a BSS. If set to 0, all networks will get same priority group (0).

This field is set to 1 if the network is added with the priority specified (not set to 0), otherwise it is set to 0.


**unsigned wlan_network::dot11n**


The network supports 802.11N.


**unsigned wlan_network::dot11ax**


The network supports 802.11AX.


**uint16_t wlan_network::mdid**


Mobility Domain ID


**unsigned wlan_network::ft_1x**


The network uses FT 802.1x security


**unsigned wlan_network::ft_psk**


The network uses FT PSK security


**unsigned wlan_network::ft_sae**


The network uses FT SAE security


**uint16_t wlan_network::beacon_period**


Beacon period of associated BSS


**uint8_t wlan_network::dtim_period**


DTIM period of associated BSS


**uint8_t wlan_network::btm_mode**


BTM mode


**bool wlan_network::bss_transition_supported**


BSS transition support


**bool wlan_network::neighbor_report_supported**


Neighbor report support


**The documentation for this struct was generated from the following file:**


-   wlan.h

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

#### wlan_network_security Struct Reference


**Data Fields**


-   enum wlan_security_type type

-   int key_mgmt

-   struct wlan_cipher mcstCipher

-   struct wlan_cipher ucstCipher

-   unsigned pkc: 1

-   int group_cipher

-   int pairwise_cipher

-   int group_mgmt_cipher

-   bool is_pmf_required

-   char psk \[WLAN_PSK_MAX_LENGTH\]

-   uint8_t psk_len

-   char password \[WLAN_PASSWORD_MAX_LENGTH+1\]

-   size_t password_len

-   char \* sae_groups

-   uint8_t pwe_derivation

-   uint8_t transition_disable

-   char pmk \[WLAN_PMK_LENGTH\]

-   bool pmk_valid

-   int8_t mfpc

-   int8_t mfpr

-   unsigned wpa3_ent: 1

-   unsigned wpa3_sb: 1

-   unsigned wpa3_sb_192: 1

-   unsigned eap_ver: 1

-   char identity \[IDENTITY_MAX_LENGTH\]

-   char anonymous_identity \[IDENTITY_MAX_LENGTH\]

-   char eap_password \[PASSWORD_MAX_LENGTH\]

-   unsigned char \* ca_cert_data

-   size_t ca_cert_len

-   unsigned char \* client_cert_data

-   size_t client_cert_len

-   unsigned char \* client_key_data

-   size_t client_key_len

-   char client_key_passwd \[PASSWORD_MAX_LENGTH\]

-   char ca_cert_hash \[HASH_MAX_LENGTH\]

-   char domain_match \[DOMAIN_MATCH_MAX_LENGTH\]

-   char domain_suffix_match \[DOMAIN_MATCH_MAX_LENGTH\]

-   unsigned char \* ca_cert2_data

-   size_t ca_cert2_len

-   unsigned char \* client_cert2_data

-   size_t client_cert2_len

-   unsigned char \* client_key2_data

-   size_t client_key2_len

-   char client_key2_passwd \[PASSWORD_MAX_LENGTH\]

-   unsigned char \* **dpp_connector**

-   unsigned char \* **dpp_c_sign_key**

-   unsigned char \* **dpp_net_access_key**


**Detailed Description**


Network security configuration


**Field Documentation**



**enum wlan_security_type wlan_network_security::type**


Type of network security to use. Specified by enum wlan_security_type.


**int wlan_network_security::key_mgmt**


Key management type


**struct wlan_cipher wlan_network_security::mcstCipher**


Type of network security Group Cipher suite


**struct wlan_cipher wlan_network_security::ucstCipher**


Type of network security Pairwise Cipher suite


**unsigned wlan_network_security::pkc**


Proactive key caching


**int wlan_network_security::group_cipher**


Type of network security Group Cipher suite


**int wlan_network_security::pairwise_cipher**


Type of network security Pairwise Cipher suite


**int wlan_network_security::group_mgmt_cipher**


Type of network security Pairwise Cipher suite


**bool wlan_network_security::is_pmf_required**


Is PMF (protected management frame) required


**char wlan_network_security::psk\[WLAN_PSK_MAX_LENGTH\]**


Pre-shared key (network password). For WEP networks this is a hex byte sequence of length psk_len, for WPA and WPA2 networks this is an ASCII pass-phrase of length psk_len. This field is ignored for networks with no security.


**uint8_t wlan_network_security::psk_len**


Length of the WEP key or WPA/WPA2 pass phrase, WLAN_PSK_MIN_LENGTH to WLAN_PSK_MAX_LENGTH. Ignored for networks with no security.


**char wlan_network_security::password\[WLAN_PASSWORD_MAX_LENGTH+1\]**


WPA3 SAE password, for WPA3 SAE networks this is an ASCII password of length password_len. This field is ignored for networks with no security.


**size_t wlan_network_security::password_len**


Length of the WPA3 SAE Password, WLAN_PASSWORD_MIN_LENGTH to WLAN_PASSWORD_MAX_LENGTH. Ignored for networks with no security.


**char\* wlan_network_security::sae_groups**


Preference list of enabled groups for SAE. By default (if this parameter is not set), the mandatory group 19 (ECC group defined over a 256-bit prime order field) is preferred, but other groups are also enabled. If this parameter is set, the groups is tried in the indicated order.


**uint8_t wlan_network_security::pwe_derivation**


SAE (Simultaneous Authentication of Equals) mechanism for PWE (Password Element) derivation


**uint8_t wlan_network_security::transition_disable**


Transition Disable indication


**char wlan_network_security::pmk\[WLAN_PMK_LENGTH\]**


PMK (pairwise master key). When pmk_valid is set, this is the PMK calculated from the PSK for WPA/PSK networks. If pmk_valid is not set, this field is ignored. When adding networks with wlan_add_network, users can initialize PMK and set pmk_valid in lieu of setting the psk. After successfully connecting to a WPA/PSK network, users can call wlan_get_current_network to inspect pmk_valid and pmk. Thus, the pmk value can be populated in subsequent calls to wlan_add_network. This saves the CPU time required to otherwise calculate the PMK.


**bool wlan_network_security::pmk_valid**


Flag reporting whether PMK is valid or not.


**int8_t wlan_network_security::mfpc**


Management frame protection capable (MFPC)


**int8_t wlan_network_security::mfpr**


Management frame protection required (MFPR)


**unsigned wlan_network_security::wpa3_ent**


WPA3 Enterprise mode


**unsigned wlan_network_security::wpa3_sb**


WPA3 Enterprise Suite B mode


**unsigned wlan_network_security::wpa3_sb_192**


WPA3 Enterprise Suite B 192 mode


**unsigned wlan_network_security::eap_ver**


EAP (Extensible Authentication Protocol) version


**char wlan_network_security::identity\[IDENTITY_MAX_LENGTH\]**


Identity string for EAP


**char wlan_network_security::anonymous_identity\[IDENTITY_MAX_LENGTH\]**


Anonymous identity string for EAP


**char wlan_network_security::eap_password\[PASSWORD_MAX_LENGTH\]**


Password string for EAP.


**unsigned char\* wlan_network_security::ca_cert_data**


CA (Certificate Authority) certification blob (Binary Large Object) in PEM (Base64 ASCII)/DER (binary) format


**size_t wlan_network_security::ca_cert_len**


CA (Certificate Authority) certification blob (Binary Large Object) length


**unsigned char\* wlan_network_security::client_cert_data**


Client certification blob (Binary Large Object) in PEM (Base64 ASCII)/DER (binary) format


**size_t wlan_network_security::client_cert_len**


Client certification blob (Binary Large Object) length


**unsigned char\* wlan_network_security::client_key_data**


Client key blob (Binary Large Object)


**size_t wlan_network_security::client_key_len**


Client key blob (Binary Large Object) length


**char wlan_network_security::client_key_passwd\[PASSWORD_MAX_LENGTH\]**


Client key password


**char wlan_network_security::ca_cert_hash\[HASH_MAX_LENGTH\]**


CA certification HASH


**char wlan_network_security::domain_match\[DOMAIN_MATCH_MAX_LENGTH\]**


Domain


**char wlan_network_security::domain_suffix_match\[DOMAIN_MATCH_MAX_LENGTH\]**


Domain Suffix


**unsigned char\* wlan_network_security::ca_cert2_data**


CA (Certificate Authority) certification blob (Binary Large Object) in PEM (Base64 ASCII)/DER (binary) format for phase two


**size_t wlan_network_security::ca_cert2_len**


CA (Certificate Authority) certification blob (Binary Large Object) length for phase two


**unsigned char\* wlan_network_security::client_cert2_data**


Client certification blob (Binary Large Object) in PEM (Base64 ASCII)/DER (binary) format for phase two


**size_t wlan_network_security::client_cert2_len**


Client certification blob (Binary Large Object) length for phase two


**unsigned char\* wlan_network_security::client_key2_data**


Client key blob (Binary Large Object) for phase two


**size_t wlan_network_security::client_key2_len**


Client key blob (Binary Large Object) length for phase two


**char wlan_network_security::client_key2_passwd\[PASSWORD_MAX_LENGTH\]**


Client key password for phase two


**The documentation for this struct was generated from the following file:**


-   wlan.h

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

#### wlan_scan_result Struct Reference


**Data Fields**


-   char ssid \[WLAN_NETWORK_NAME_MAX_LENGTH+1\]

-   unsigned int ssid_len

-   char bssid \[IEEEtypes_ADDRESS_SIZE\]

-   unsigned int channel

-   enum wlan_bss_type type

-   enum wlan_bss_role role

-   unsigned dot11n: 1

-   unsigned dot11ax: 1

-   unsigned wmm: 1

-   unsigned wps: 1

-   unsigned int wps_session

-   unsigned wep: 1

-   unsigned wpa: 1

-   unsigned wpa2: 1

-   unsigned wpa2_sha256: 1

-   unsigned wpa3_sae: 1

-   unsigned wpa2_entp: 1

-   unsigned wpa3_entp: 1

-   unsigned wpa3_1x_sha256: 1

-   unsigned wpa3_1x_sha384: 1

-   unsigned ft_1x: 1

-   unsigned ft_1x_sha384: 1

-   unsigned ft_psk: 1

-   unsigned ft_sae: 1

-   unsigned char rssi

-   char trans_ssid \[WLAN_NETWORK_NAME_MAX_LENGTH+1\]

-   unsigned int trans_ssid_len

-   char trans_bssid \[IEEEtypes_ADDRESS_SIZE\]

-   uint16_t beacon_period

-   uint8_t dtim_period

-   t_u8 ap_mfpc

-   t_u8 ap_mfpr

-   t_u8 ap_pwe

-   bool neighbor_report_supported

-   bool bss_transition_supported


**Detailed Description**


Scan result


**Field Documentation**



**char wlan_scan_result::ssid\[WLAN_NETWORK_NAME_MAX_LENGTH+1\]**


The network SSID, represented as a NULL-terminated C string of 0 to 32 characters. If the network has a hidden SSID, this can be the empty string.


**unsigned int wlan_scan_result::ssid_len**


SSID length


**char wlan_scan_result::bssid\[IEEEtypes_ADDRESS_SIZE\]**


The network BSSID, represented as a 6-byte array.


**unsigned int wlan_scan_result::channel**


The network channel.


**enum wlan_bss_type wlan_scan_result::type**


The Wi-Fi network type.


**enum wlan_bss_role wlan_scan_result::role**


The Wi-Fi network mode.


**unsigned wlan_scan_result::dot11n**


The network supports 802.11N. This is set to 0 if the network does not support 802.11N or if the system does not have 802.11N support enabled.


**unsigned wlan_scan_result::dot11ax**


The network supports 802.11AX. This is set to 0 if the network does not support 802.11AX or if the system does not have 802.11AX support enabled.


**unsigned wlan_scan_result::wmm**


The network supports WMM. This is set to 0 if the network does not support WMM or if the system does not have WMM support enabled.


**unsigned wlan_scan_result::wps**


The network supports WPS. This is set to 0 if the network does not support WPS or if the system does not have WPS support enabled.


**unsigned int wlan_scan_result::wps_session**


WPS Type WPS_SESSION_PBC/ WPS_SESSION_PIN


**unsigned wlan_scan_result::wep**


The network uses WEP security.


**unsigned wlan_scan_result::wpa**


The network uses WPA security.


**unsigned wlan_scan_result::wpa2**


The network uses WPA2 security


**unsigned wlan_scan_result::wpa2_sha256**


The network uses WPA2 SHA256 security


**unsigned wlan_scan_result::wpa3_sae**


The network uses WPA3 SAE security


**unsigned wlan_scan_result::wpa2_entp**


The network uses WPA2 Enterprise security


**unsigned wlan_scan_result::wpa3_entp**


The network uses WPA3 Enterprise security


**unsigned wlan_scan_result::wpa3_1x_sha256**


The network uses WPA3 Enterprise SHA256 security


**unsigned wlan_scan_result::wpa3_1x_sha384**


The network uses WPA3 Enterprise SHA384 security


**unsigned wlan_scan_result::ft_1x**


The network uses FT 802.1x security


**unsigned wlan_scan_result::ft_1x_sha384**


The network uses FT 892.1x SHA384 security


**unsigned wlan_scan_result::ft_psk**


The network uses FT PSK security


**unsigned wlan_scan_result::ft_sae**


The network uses FT SAE security


**unsigned char wlan_scan_result::rssi**


The signal strength of the beacon


**char wlan_scan_result::trans_ssid\[WLAN_NETWORK_NAME_MAX_LENGTH+1\]**


The network SSID, represented as a NULL-terminated C string of 0 to 32 characters. If the network has a hidden SSID, this should be the empty string.


**unsigned int wlan_scan_result::trans_ssid_len**


SSID length


**char wlan_scan_result::trans_bssid\[IEEEtypes_ADDRESS_SIZE\]**


The network BSSID, represented as a 6-byte array.


**uint16_t wlan_scan_result::beacon_period**


Beacon period


**uint8_t wlan_scan_result::dtim_period**


DTIM (delivery traffic indication map) period


**t_u8 wlan_scan_result::ap_mfpc**


MFPC (Management Frame Protection Capable) bit of AP (Access Point)


**t_u8 wlan_scan_result::ap_mfpr**


MFPR (Management Frame Protection Required) bit of AP (Access Point)


**t_u8 wlan_scan_result::ap_pwe**


PWE (Password Element) bit of AP (Access Point)


**bool wlan_scan_result::neighbor_report_supported**


Neighbor report support


**bool wlan_scan_result::bss_transition_supported**


bss transition support


**The documentation for this struct was generated from the following file:**


-   wlan.h**File Documentation**


**wlan.h File Reference**


This file provides Wi-Fi APIs for the application.


**Function Documentation**


> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

## Macros

| Macro | Supported SoCs |
|-------|---------------|
| `ACTION_GET` | IW416, W8987, IW610, IW612 |
| `ACTION_SET` | IW416, W8987, IW610, IW612 |
| `A_ID_MAX_LENGTH` | IW416, W8987, IW610, IW612 |
| `DOMAIN_MATCH_MAX_LENGTH` | IW416, W8987, IW610, IW612 |
| `HASH_MAX_LENGTH` | IW416, W8987, IW610, IW612 |
| `IDENTITY_MAX_LENGTH` | IW416, W8987, IW610, IW612 |
| `IEEEtypes_ADDRESS_SIZE` | IW416, W8987, IW610, IW612 |
| `IEEEtypes_SSID_SIZE` | IW416, W8987, IW610, IW612 |
| `MAX_CHANNEL_LIST` | IW416, W8987, IW610, IW612 |
| `MAX_USERS` | IW416, W8987, IW610, IW612 |
| `PAC_OPAQUE_ENCR_KEY_MAX_LENGTH` | IW416, W8987, IW610, IW612 |
| `PASSWORD_MAX_LENGTH` | IW416, W8987, IW610, IW612 |
| `UNSPEC_WPS_NETWORK` | IW416, W8987, IW610, IW612 |
| `WLAN_ERROR_ACTION` | IW416, W8987, IW610, IW612 |
| `WLAN_ERROR_NOMEM` | IW416, W8987, IW610, IW612 |
| `WLAN_ERROR_NONE` | IW416, W8987, IW610, IW612 |
| `WLAN_ERROR_NOT_SUPPORTED` | IW416, W8987, IW610, IW612 |
| `WLAN_ERROR_PARAM` | IW416, W8987, IW610, IW612 |
| `WLAN_ERROR_PS_ACTION` | IW416, W8987, IW610, IW612 |
| `WLAN_ERROR_STATE` | IW416, W8987, IW610, IW612 |
| `WLAN_KEY_MGMT_FT` | IW416, W8987, IW610, IW612 |
| `WLAN_MGMT_ACTION` | IW416, W8987, IW610, IW612 |
| `WLAN_NETWORK_CHAN_LIST_MAX` | IW416, W8987, IW610, IW612 |
| `WLAN_NETWORK_NAME_MAX_LENGTH` | IW416, W8987, IW610, IW612 |
| `WLAN_NETWORK_NAME_MIN_LENGTH` | IW416, W8987, IW610, IW612 |
| `WLAN_PASSWORD_MAX_LENGTH` | IW416, W8987, IW610, IW612 |
| `WLAN_PASSWORD_MIN_LENGTH` | IW416, W8987, IW610, IW612 |
| `WLAN_PMK_LENGTH` | IW416, W8987, IW610, IW612 |
| `WLAN_PSK_MAX_LENGTH` | IW416, W8987, IW610, IW612 |
| `WLAN_PSK_MIN_LENGTH` | IW416, W8987, IW610, IW612 |
| `WLAN_RECONNECT_LIMIT` | IW416, W8987, IW610, IW612 |
| `WLAN_RESCAN_LIMIT` | IW416, W8987, IW610, IW612 |

---

### Macro Documentation

#### #define ACTION_GET  (0U)

Action GET

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

#### #define ACTION_SET  (1)

Action SET

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

#### #define A_ID_MAX_LENGTH  33U

Maximum length of A-ID, A-ID indicates the identity of the authority that issues PACs.

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

#### #define DOMAIN_MATCH_MAX_LENGTH  64U

Maximum length of domain match

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

#### #define HASH_MAX_LENGTH  40U

Maximum length of CA certification hash

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

#### #define IDENTITY_MAX_LENGTH  64U

Maximum enterprise identity can be up to 64 characters

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

#### #define IEEEtypes_ADDRESS_SIZE  6

MAC Address length

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

#### #define IEEEtypes_SSID_SIZE  32U

Maximum SSID length

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

#### #define MAX_CHANNEL_LIST  6

Configuration for Wi-Fi scan

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

#### #define MAX_USERS  8U

Maximum identities for EAP server users

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

#### #define PAC_OPAQUE_ENCR_KEY_MAX_LENGTH  33U

Maximum length of encryption key for EAP-FAST PAC-Opaque values.

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

#### #define PASSWORD_MAX_LENGTH  128U

Maximum enterprise password can be up to 128 characters

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

#### #define UNSPEC_WPS_NETWORK  MBIT(0)

When the temporary network is of type WPS, bit 0 is 1.


**Typedef Documentation**



**typedef wifi_scan_channel_list_t wlan_scan_channel_list_t**


Configuration for Wi-Fi scan channel list from wifi_scan_channel_list_t


**typedef wifi_scan_params_v2_t wlan_scan_params_v2_t**


Configuration for Wi-Fi scan parameters v2 from wifi_scan_params_v2_t


**typedef wifi_cal_data_t wlan_cal_data_t**


Configuration for Wi-Fi calibration data from wifi_cal_data_t


**typedef wifi_auto_reconnect_config_t wlan_auto_reconnect_config_t**


Configuration for auto reconnect configuration from wifi_auto_reconnect_config_t


**typedef wifi_flt_cfg_t wlan_flt_cfg_t**


Configuration for memory efficient filters in Wi-Fi firmware from wifi_flt_cfg_t


**typedef wifi_wowlan_ptn_cfg_t wlan_wowlan_ptn_cfg_t**


Configuration for wowlan pattern parameters from wifi_wowlan_ptn_cfg_t


**typedef wifi_tcp_keep_alive_t wlan_tcp_keep_alive_t**


Configuration for TCP keep alive parameters from wifi_tcp_keep_alive_t


**typedef wifi_cloud_keep_alive_t wlan_cloud_keep_alive_t**


Configuration for cloud keep alive parameters from wifi_cloud_keep_alive_t


**typedef wifi_ds_rate wlan_ds_rate**


Configuration for TX rate and get data rate from wifi_ds_rate


**typedef wifi_ed_mac_ctrl_t wlan_ed_mac_ctrl_t**


Configuration for ED MAC Control parameters from wifi_ed_mac_ctrl_t


**typedef wifi_set_band_config_t wlan_bandcfg_t**


Configuration for band from wifi_set_band_config_t


**typedef wifi_cw_mode_ctrl_t wlan_cw_mode_ctrl_t**


Configuration for CW mode parameters from wifi_cw_mode_ctrl_t


**typedef wifi_chanlist_t wlan_chanlist_t**


Configuration for channel list from wifi_chanlist_t


**typedef wifi_txpwrlimit_t wlan_txpwrlimit_t**


Configuration for TX power Limit from wifi_txpwrlimit_t


**typedef wifi_rutxpwrlimit_t wlan_rutxpwrlimit_t**


Configuration for RU TX power limit from wifi_rutxpwrlimit_t


**typedef wifi_11ax_config_t wlan_11ax_config_t**


Configuration for 802.11ax capabilities wifi_11ax_config_t


**typedef wifi_twt_setup_config_t wlan_twt_setup_config_t**


Configuration for TWT setup wifi_twt_setup_config_t


**typedef wifi_twt_teardown_config_t wlan_twt_teardown_config_t**


Configuration for TWT teardown wifi_twt_teardown_config_t


**typedef wifi_btwt_config_t wlan_btwt_config_t**


Configuration for Broadcast TWT Setup wifi_btwt_config_t


**typedef wifi_twt_report_t wlan_twt_report_t**


Configuration for TWT Report wifi_twt_report_t


**typedef wifi_twt_information_t wlan_twt_information_t**


Configuration for TWT Information wifi_twt_information_t


**typedef wifi_csi_config_params_t wlan_csi_config_params_t**


Configuration for CSI config params from wifi_csi_config_params_t


**typedef wifi_indrst_cfg_t wlan_indrst_cfg_t**


Configuration for GPIO independent reset wifi_indrst_cfg_t


**typedef txrate_setting wlan_txrate_setting**


Configuration for TX rate setting from txrate_setting


**Enumeration Type Documentation**



**enum wm_wlan_errno**


Enum for Wi-Fi errors


**Enumerator:**


  --------------------------- ----------------------------------------- ------------------------- -------------------------------------- ------------------------------ -------------------------- ---------------------------- ------------------------------- ----------------------------------- ------------------------------
  WLAN_ERROR_FW_DNLD_FAILED   The firmware download operation failed.   WLAN_ERROR_FW_NOT_READY   The firmware ready register not set.   WLAN_ERROR_CARD_NOT_DETECTED   The Wi-Fi SoC not found.   WLAN_ERROR_FW_NOT_DETECTED   The Wi-Fi Firmware not found.   WLAN_BSSID_NOT_FOUND_IN_SCAN_LIST   BSSID not found in scan list

  --------------------------- ----------------------------------------- ------------------------- -------------------------------------- ------------------------------ -------------------------- ---------------------------- ------------------------------- ----------------------------------- ------------------------------


**enum wlan_event_reason**


Wi-Fi connection manager event reason


**Enumerator:**


  --------------------- ------------------------------------------------------------------------------------------------------------------------------------------- -------------------------- ------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ------------------------------- -------------------------------------------------------------------------------------------------------------------------------------------------------------- --------------------------------- ---------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------- ------------------------------ ---------------------------- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ----------------------- ------------------------------------------------------------------------ ------------------------- ----------------------------------------------------------------------------------------------------- ---------------------------- ----------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------- --------------------------------------------------------------------------------------------------------------------------------------------------------------------- ------------------------- ----------------------------------------------------------------------------------------------------------------------------------- ----------------------------------- ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- --------------------- -------------------------------------------------------- ---------------------- --------------------------------------------------------- ---------------------- ----------------------------------------------------------- --------------------- --------------------------------------------------------------- ------------------------- ------------------------------------------------------------------- ------------------------------ ---------------------------------------------- ----------------------------- ---------------------------------------------------------------------- ------------------------------- -------------------------------------------- ------------------------------ ------------------------------------------------------ ----------------------------- ----------------------------------------------------- ------------------------- ---------------------------------------------- ---------------------- --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  WLAN_REASON_SUCCESS   The Wi-Fi connection manager has successfully connected to a network and is now in the WLAN_CONNECTED state.   WLAN_REASON_AUTH_SUCCESS   The Wi-Fi connection manager has successfully authenticated to a network and is now in the WLAN_ASSOCIATED state.   WLAN_REASON_CONNECT_FAILED   The Wi-Fi connection manager failed to connect before actual connection attempt with AP due to incorrect Wi-Fi network profile. or the Wi-Fi connection manager failed to reconnect to previously connected network and it is now in the WLAN_DISCONNECTED state.   WLAN_REASON_NETWORK_NOT_FOUND   The Wi-Fi connection manager could not find the network that it was connecting to and it is now in the WLAN_DISCONNECTED state.   WLAN_REASON_NETWORK_AUTH_FAILED   The Wi-Fi connection manager failed to authenticate with the network and is now in the WLAN_DISCONNECTED state.   WLAN_REASON_ADDRESS_SUCCESS   DHCP lease has been renewed.   WLAN_REASON_ADDRESS_FAILED   The Wi-Fi connection manager failed to obtain an IP address or TCP stack configuration has failed or the IP address configuration was lost due to a DHCP error. The system is now in the WLAN_DISCONNECTED state.   WLAN_REASON_LINK_LOST   The Wi-Fi connection manager has lost the link to the current network.   WLAN_REASON_CHAN_SWITCH   The Wi-Fi connection manager has received the channel switch announcement from the current network.   WLAN_REASON_WPS_DISCONNECT   The Wi-Fi connection manager has disconnected from the WPS network (or has canceled a connection attempt) by request and is now in the WLAN_DISCONNECTED state.   WLAN_REASON_USER_DISCONNECT   The Wi-Fi connection manager has disconnected from the current network (or has canceled a connection attempt) by request and is now in the WLAN_DISCONNECTED state.   WLAN_REASON_INITIALIZED   The Wi-Fi connection manager is initialized and is ready for use. That is, it\'s now possible to scan or to connect to a network.   WLAN_REASON_INITIALIZATION_FAILED   The Wi-Fi connection manager has failed to initialize and is therefore not running. It is not possible to scan or to connect to a network. The Wi-Fi connection manager should be stopped and started again via wlan_stop() and wlan_start() respectively.   WLAN_REASON_FW_HANG   The Wi-Fi connection manager has entered in hang mode.   WLAN_REASON_FW_RESET   The Wi-Fi connection manager has reset fw successfully.   WLAN_REASON_PS_ENTER   The Wi-Fi connection manager has entered power save mode.   WLAN_REASON_PS_EXIT   The Wi-Fi connection manager has exited from power save mode.   WLAN_REASON_UAP_SUCCESS   The Wi-Fi connection manager has started uAP (micro access point)   WLAN_REASON_UAP_CLIENT_ASSOC   A Wi-Fi client has joined uAP\'s BSS network   WLAN_REASON_UAP_CLIENT_CONN   A Wi-Fi client has authenticated and connected to uAP\'s BSS network   WLAN_REASON_UAP_CLIENT_DISSOC   A Wi-Fi client has left uAP\'s BSS network   WLAN_REASON_UAP_START_FAILED   The Wi-Fi connection manager has failed to start uAP   WLAN_REASON_UAP_STOP_FAILED   The Wi-Fi connection manager has failed to stop uAP   WLAN_REASON_UAP_STOPPED   The Wi-Fi connection manager has stopped uAP   WLAN_REASON_RSSI_LOW   The Wi-Fi connection manager has received subscribed RSSI low event on station interface as per configured threshold and frequency. If CONFIG_11K, CONFIG_11V, CONFIG_11R or CONFIG_ROAMING enabled then RSSI low event is processed internally.

  --------------------- ------------------------------------------------------------------------------------------------------------------------------------------- -------------------------- ------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ------------------------------- -------------------------------------------------------------------------------------------------------------------------------------------------------------- --------------------------------- ---------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------- ------------------------------ ---------------------------- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ----------------------- ------------------------------------------------------------------------ ------------------------- ----------------------------------------------------------------------------------------------------- ---------------------------- ----------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------------------- --------------------------------------------------------------------------------------------------------------------------------------------------------------------- ------------------------- ----------------------------------------------------------------------------------------------------------------------------------- ----------------------------------- ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- --------------------- -------------------------------------------------------- ---------------------- --------------------------------------------------------- ---------------------- ----------------------------------------------------------- --------------------- --------------------------------------------------------------- ------------------------- ------------------------------------------------------------------- ------------------------------ ---------------------------------------------- ----------------------------- ---------------------------------------------------------------------- ------------------------------- -------------------------------------------- ------------------------------ ------------------------------------------------------ ----------------------------- ----------------------------------------------------- ------------------------- ---------------------------------------------- ---------------------- --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


**enum wlan_wakeup_event_t**


Wakeup event bitmap


**Enumerator:**


  ----------------------- --------------------- ----------------- ------------------- ------------------- --------------------- ------------------- --------------------- ----------------------- ------------------------- -------------------- ----------------------------------------
  WAKE_ON_ALL_BROADCAST   Wakeup on broadcast   WAKE_ON_UNICAST   Wakeup on unicast   WAKE_ON_MAC_EVENT   Wakeup on MAC event   WAKE_ON_MULTICAST   Wakeup on multicast   WAKE_ON_ARP_BROADCAST   Wakeup on ARP broadcast   WAKE_ON_MGMT_FRAME   Wakeup on receiving a management frame

  ----------------------- --------------------- ----------------- ------------------- ------------------- --------------------- ------------------- --------------------- ----------------------- ------------------------- -------------------- ----------------------------------------


**enum wlan_connection_state**


Wi-Fi station/uAP/Wi-Fi direct connection/status state


**Enumerator:**


  ------------------- ----------------------------------------------------------------------------------------------------------------------------------------- ----------------- -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------- --------------------------------------------------------------- -------------------- ------------------------------------------------------------------ ---------------- ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ------------------ ---------------------------------------------- ------------------ ---------------------------------------------- --------------- -------------------------------------------------------------------------------- ------------------ ---------------------------------------------------------------------------------------
  WLAN_DISCONNECTED   The Wi-Fi connection manager is not connected and no connection attempt is in progress. It is possible to connect to a network or scan.   WLAN_CONNECTING   The Wi-Fi connection manager is not connected but it is currently attempting to connect to a network. It is not possible to scan at this time. It is possible to connect to a different network.   WLAN_ASSOCIATED   The Wi-Fi connection manager is not connected but associated.   WLAN_AUTHENTICATED   The Wi-Fi connection manager is not connected but authenticated.   WLAN_CONNECTED   The Wi-Fi connection manager is connected. It is possible to scan and connect to another network at this time. Information about the current network configuration is available.   WLAN_UAP_STARTED   The Wi-Fi connection manager has started uAP   WLAN_UAP_STOPPED   The Wi-Fi connection manager has stopped uAP   WLAN_SCANNING   The Wi-Fi connection manager is not connected and network scan is in progress.   WLAN_ASSOCIATING   The Wi-Fi connection manager is not connected and network association is in progress.

  ------------------- ----------------------------------------------------------------------------------------------------------------------------------------- ----------------- -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ----------------- --------------------------------------------------------------- -------------------- ------------------------------------------------------------------ ---------------- ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ------------------ ---------------------------------------------- ------------------ ---------------------------------------------- --------------- -------------------------------------------------------------------------------- ------------------ ---------------------------------------------------------------------------------------


**enum wlan_ps_mode**


Station power save mode


**Enumerator:**


  ------------- ------------- ----------- ---------------------- ----------------- ---------------------------- ---------------------- -------------------------------------
  WLAN_ACTIVE   Active mode   WLAN_IEEE   IEEE power save mode   WLAN_DEEP_SLEEP   Deep sleep power save mode   WLAN_IEEE_DEEP_SLEEP   IEEE and deep sleep power save mode

  ------------- ------------- ----------- ---------------------- ----------------- ---------------------------- ---------------------- -------------------------------------


**enum wlan_security_type**


Network security types


**Enumerator:**


  -------------------- ------------------------------------ ------------------------ ---------------------------------------------- -------------------------- ------------------------------------------------ ------------------- ----------------------------------------- -------------------- ------------------------------------------ ------------------------------ --------------------------------------------------- ----------------------- --------------------------------------------- ------------------------ ------------------------------------------ --------------------------- --------------------------------------------- -------------------------------- ----------------------------------------------------------- ----------------------------------- --------------------------------------------------------- ----------------------- ------------------------------------------------------------------------------------------------------------------------------------- --------------------------------- ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ------------------- -------------------------------------------------------- ------------------------ -----------------------------------------------------------------------------------------------------------------------------------------
  WLAN_SECURITY_NONE   The network does not use security.   WLAN_SECURITY_WEP_OPEN   The network uses WEP security with open key.   WLAN_SECURITY_WEP_SHARED   The network uses WEP security with shared key.   WLAN_SECURITY_WPA   The network uses WPA security with PSK.   WLAN_SECURITY_WPA2   The network uses WPA2 security with PSK.   WLAN_SECURITY_WPA_WPA2_MIXED   The network uses WPA/WPA2 mixed security with PSK   WLAN_SECURITY_WPA2_FT   The network uses WPA2 security with PSK FT.   WLAN_SECURITY_WPA3_SAE   The network uses WPA3 security with SAE.   WLAN_SECURITY_WPA3_FT_SAE   The network uses WPA3 security with SAE FT.   WLAN_SECURITY_WPA3_SAE_EXT_KEY   The network uses WPA3 security with new SAE AKM suite 24.   WLAN_SECURITY_WPA2_WPA3_SAE_MIXED   The network uses WPA2/WPA3 SAE mixed security with PSK.   WLAN_SECURITY_EAP_TLS   The network uses WPA2 Enterprise EAP-TLS security The identity field in wlan_network structure is used   WLAN_SECURITY_EAP_PEAP_MSCHAPV2   The network uses WPA2 Enterprise EAP-PEAP-MSCHAPV2 security. The anonymous identity, identity and password fields in wlan_network structure are used   WLAN_SECURITY_DPP   The network uses DPP security with NAK(Net Access Key)   WLAN_SECURITY_WILDCARD   The network can use any security method. This is often used when the user only knows the name and passphrase but not the security type.

  -------------------- ------------------------------------ ------------------------ ---------------------------------------------- -------------------------- ------------------------------------------------ ------------------- ----------------------------------------- -------------------- ------------------------------------------ ------------------------------ --------------------------------------------------- ----------------------- --------------------------------------------- ------------------------ ------------------------------------------ --------------------------- --------------------------------------------- -------------------------------- ----------------------------------------------------------- ----------------------------------- --------------------------------------------------------- ----------------------- ------------------------------------------------------------------------------------------------------------------------------------- --------------------------------- ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ------------------- -------------------------------------------------------- ------------------------ -----------------------------------------------------------------------------------------------------------------------------------------


**enum address_types**


Address types to be used by the element wlan_ip_config.addr_type below


**Enumerator:**


  ------------------ ------------------- ---------------- -------------------- --------------- -------------------- ----------------------- --------------------------------
  ADDR_TYPE_STATIC   Static IP address   ADDR_TYPE_DHCP   Dynamic IP address   ADDR_TYPE_LLA   Link level address   ADDR_TYPE_BRIDGE_MODE   For Bridge Mode, no IP address

  ------------------ ------------------- ---------------- -------------------- --------------- -------------------- ----------------------- --------------------------------


**enum wlan_select_policy**


WLAN selection policy configuration


**enum wlan_frequency_bands**



**Enumerator:**


  ------------------------ -------------- ---------------------- ------------ --------------------- ----------- ------------------------ ------------------------
  WLAN_FREQ_BAND_2_4_GHZ   2.4 GHz band   WLAN_FREQ_BAND_5_GHZ   5 GHz band   WLAN_FREQ_BAND_BOTH   All bands   WLAN_FREQ_BAND_UNKNOWN   Invalid frequency band

  ------------------------ -------------- ---------------------- ------------ --------------------- ----------- ------------------------ ------------------------


**Index**


> **Supported SoCs:** IW416, W8987, IW610, IW612


---

#### #define WLAN_ERROR_ACTION  4

The operation failed due to an internal error.

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

#### #define WLAN_ERROR_NOMEM  2

The operation could not be performed because there is not enough memory.

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

#### #define WLAN_ERROR_NONE  0

Error codes The operation was successful.

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

#### #define WLAN_ERROR_NOT_SUPPORTED  6

The requested feature is not supported

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

#### #define WLAN_ERROR_PARAM  1

The operation failed due to an error with one or more parameters.

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

#### #define WLAN_ERROR_PS_ACTION  5

The operation to change power state could not be performed

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

#### #define WLAN_ERROR_STATE  3

The operation could not be performed in the current system state.

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

#### #define WLAN_KEY_MGMT_FT

**Value:**`    (WLAN_KEY_MGMT_FT_PSK | WLAN_KEY_MGMT_FT_IEEE8021X | WLAN_KEY_MGMT_FT_IEEE8021X_SHA384 | WLAN_KEY_MGMT_FT_SAE | ``\`

         WLAN_KEY_MGMT_FT_FILS_SHA256 | WLAN_KEY_MGMT_FT_FILS_SHA384)

Fast BSS Transition(11r) key management

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

#### #define WLAN_MGMT_ACTION  MBIT(13)

BITMAP for Action frame

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

#### #define WLAN_NETWORK_CHAN_LIST_MAX  14U

Maximum number of channels storable in a network\'s scan channel list

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

#### #define WLAN_NETWORK_NAME_MAX_LENGTH  32U

Maximum length for network names, see wlan_network

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

#### #define WLAN_NETWORK_NAME_MIN_LENGTH  1U

Minimum length for network names, see wlan_network.

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

#### #define WLAN_PASSWORD_MAX_LENGTH  255U

Maximum WPA3 password can be up to 255 ASCII chars

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

#### #define WLAN_PASSWORD_MIN_LENGTH  8U

Minimum WPA3 password can be up to 8 ASCII chars

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

#### #define WLAN_PMK_LENGTH  32

Length of a pairwise master key (PMK). It\'s always 256 bits (32 Bytes)

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

#### #define WLAN_PSK_MAX_LENGTH  65U

Maximum WPA2 passphrase can be up to 63 ASCII chars or 64 hexadecimal digits + 1 \'\\0\' char

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

#### #define WLAN_PSK_MIN_LENGTH  8U

Minimum WPA2 passphrase can be up to 8 ASCII chars

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

#### #define WLAN_RECONNECT_LIMIT  CONFIG_MAX_RECONNECT_LIMIT

The number of times that the Wi-Fi connection manager attempts a reconnection with the network before giving up.

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

#### #define WLAN_RESCAN_LIMIT  CONFIG_MAX_RESCAN_LIMIT

The number of times that the Wi-Fi connection manager look for a network before giving up.

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

## Functions

#### Initialization & Lifecycle

| Function | Supported SoCs |
|----------|---------------|
| `wlan_basic_cli_deinit` | All |
| `wlan_basic_cli_init` | All |
| `wlan_cli_deinit` | All |
| `wlan_cli_init` | All |
| `wlan_deinit` | All |
| `wlan_destroy_all_tasks` | All |
| `wlan_enhanced_cli_deinit` | All |
| `wlan_enhanced_cli_init` | All |
| `wlan_init` | All |
| `wlan_reset` | All |
| `wlan_start` | All |
| `wlan_stop` | All |
| `wlan_wfa_basic_cli_deinit` | All |
| `wlan_wfa_basic_cli_init` | All |

##### int wlan_basic_cli_deinit (void )

Unregister basic Wi-Fi CLI commands

This function unregisters basic Wi-Fi CLI commands like showing version information, MAC address.


**Note**


This function gets called by wlan_cli_deinit(), hence only one function out of these two functions should be called in the application.


**Returns**


WLAN_ERROR_NONE if the CLI commands were unregistered

WLAN_ERROR_ACTION if they were not unregistered (for example if this function was called while the CLI commands were not registered or were already unregistered).

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_basic_cli_init (void )

Register basic Wi-Fi CLI (command line input) commands

This function registers basic Wi-Fi CLI commands like showing version information, MAC address.


**Note**


This function can only be called by the application after wlan_init() called.

This function gets called by wlan_cli_init(), hence only one function out of these two functions should be called in the application.


**Returns**


WLAN_ERROR_NONE if the CLI commands were registered

WLAN_ERROR_ACTION if they were not registered (for example if this function was called while the CLI commands were already registered).

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_cli_deinit (void )

Unregister Wi-Fi CLI commands.

Try to unregister the Wi-Fi CLI commands with the CLI subsystem. This function is available for the application for use.


**Note**


This function can only be called by the application after wlan_init() called.

This function internally calls wlan_basic_cli_deinit(), hence only one function out of these two functions should be called in the application.


**Returns**


WM_SUCCESS if the CLI commands were unregistered or

-WM_FAIL if they were not (for example if this function was called while the CLI commands were already unregistered).

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_cli_init (void )

Register Wi-Fi CLI (command line input) commands.

Try to register the Wi-Fi CLI commands with the CLI subsystem. This function is available for the application for use.


**Note**


This function can only be called by the application after wlan_init() called.

This function internally calls wlan_basic_cli_init(), hence only one function out of these two functions should be called in the application.


**Returns**


WM_SUCCESS if the CLI commands were registered or

-WM_FAIL if they were not (for example if this function was called while the CLI commands were already registered).

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### void wlan_deinit (int *action*)

Deinitialize the Wi-Fi driver, send a shutdown command to the Wi-Fi firmware and delete the Wi-Fi driver thread.


**Parameters**


  ----------------------- ----------------------- -----------------------------------------------------------------
  in                      *action*                Additional action to be taken with deinit. Should input 0 here.

  ----------------------- ----------------------- -----------------------------------------------------------------

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### void wlan_destroy_all_tasks (void )

This API destroys all tasks.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_enhanced_cli_deinit (void )

Unregister Wi-Fi enhanced CLI commands.

Unregister the Wi-Fi enhanced CLI commands like set or get tx-power, tx-datarate, tx-modulation etc. with the CLI subsystem.


**Note**


This function can only be called by the application after wlan_init() called.


**Returns**


WM_SUCCESS if the CLI commands were unregistered or

-WM_FAIL if they were not unregistered.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_enhanced_cli_init (void )

Register Wi-Fi enhanced CLI commands.

Register the Wi-Fi enhanced CLI commands like set or get tx-power, tx-datarate, tx-modulation etc. with the CLI subsystem.


**Note**


This function can only be called by the application after wlan_init() called.


**Returns**


WM_SUCCESS if the CLI commands were registered or

-WM_FAIL if they were not (for example if this function was called while the CLI commands were already registered).

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_init (const uint8_t \* *fw_start_addr*, const size_t *size*)

Initialize the Wi-Fi driver and create the Wi-Fi driver thread.


**Parameters**


  ----------------------- ----------------------- --------------------------------------
  in                      *fw_start_addr*         Start address of the Wi-Fi firmware.

  in                      *size*                  Size of the Wi-Fi firmware.
  ----------------------- ----------------------- --------------------------------------


**Returns**


WM_SUCCESS if the Wi-Fi connection manager service has initialized successfully.

Negative value if initialization failed.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### void wlan_reset (cli_reset_option *ResetOption*)

Reset the driver.


**Parameters**


  ----------------------- ----------------------- -----------------------------------------------------------------------
  in                      *ResetOption*           Option including enable, disable or reset Wi-Fi driver can be chosen.

  ----------------------- ----------------------- -----------------------------------------------------------------------

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_start (int(\*)(enum wlan_event_reason reason, void \*data) *cb*)

Start the Wi-Fi connection manager service.

This function starts the Wi-Fi connection manager.


**Note**


The status of the Wi-Fi connection manager is notified asynchronously through the callback, *cb* , with a WLAN_REASON_INITIALIZED event (if initialization succeeded) or WLAN_REASON_INITIALIZATION_FAILED (if initialization failed). If the Wi-Fi connection manager fails to initialize, the caller should stop Wi-Fi connection manager via wlan_stop() and try wlan_start() again.


**Parameters**


  ----------------------- ----------------------- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  in                      *cb*                    A pointer to a callback function that handles Wi-Fi events. All further WLCMGR events can be notified in this callback. Refer to enum wlan_event_reason for the various events for which this callback is called.

  ----------------------- ----------------------- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


**Returns**


WM_SUCCESS if the Wi-Fi connection manager service has started successfully.

-WM_E_INVAL if the *cb* pointer is NULL.

-WM_FAIL if an internal error occurred.

WLAN_ERROR_STATE if the Wi-Fi connection manager is already running.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_stop (void )

Stop the Wi-Fi connection manager service.

This function stops the Wi-Fi connection manager, causing the station interface to disconnect from the currently connected network and stop the uAP interface.


**Returns**


WM_SUCCESS if the Wi-Fi connection manager service has been stopped successfully.

WLAN_ERROR_STATE if the Wi-Fi connection manager was not running.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_wfa_basic_cli_deinit (void )

Unregister WFA basic Wi-Fi CLI (command line input) commands

This function unregisters basic Wi-Fi CLI commands like showing version information, MAC address.


**Note**


This function can only be called by the application after wlan_init() called.


**Returns**


WLAN_ERROR_NONE if the CLI commands were unregistered or

WLAN_ERROR_ACTION if they were not unregistered

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_wfa_basic_cli_init (void )

Register WFA basic Wi-Fi CLI (command line input) commands

This function registers basic Wi-Fi CLI commands like showing version information, MAC address.


**Note**


This function can only be called by the application after wlan_init() called.


**Returns**


WLAN_ERROR_NONE if the CLI commands were registered or

WLAN_ERROR_ACTION if they were not registered (for example if this function was called while the CLI commands were already registered).

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---


#### Connection Management

| Function | Supported SoCs |
|----------|---------------|
| `is_sta_associated` | All |
| `is_sta_connected` | All |
| `is_sta_ipv4_connected` | All |
| `is_sta_ipv6_connected` | All |
| `wlan_connect` | All |
| `wlan_connect_opt` | All |
| `wlan_disconnect` | All |
| `wlan_get_connection_state` | All |
| `wlan_is_started` | All |
| `wlan_reassociate` | All |
| `wlan_wlcmgr_send_msg` | All |

##### bool is_sta_associated (void )

Retrieve the status information of the station interface.


**Returns**


TRUE if station interface is in or above the WLAN_ASSOCIATED state.

FALSE otherwise.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### bool is_sta_connected (void )

Retrieve the status information of the station interface.


**Returns**


TRUE if station interface is in WLAN_CONNECTED state.

FALSE otherwise.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### bool is_sta_ipv4_connected (void )

Retrieve the status information of the ipv4 network of the station interface.


**Returns**


TRUE if ipv4 network of the station interface is in WLAN_CONNECTED state.

FALSE otherwise.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### bool is_sta_ipv6_connected (void )

Retrieve the status information of the ipv6 network of the station interface.


**Returns**


TRUE if ipv6 network of the station interface is in WLAN_CONNECTED state.

FALSE otherwise.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_connect (char \* *name*)

Connect to a Wi-Fi network (access point).

When this function is called, Wi-Fi connection manager starts connection attempts to the network specified by *name* . The connection result can be notified asynchronously to the WLCMGR callback when the connection process has completed.

When connecting to a network, the event refers to the connection attempt to that network.

Calling this function when the station interface is in the WLAN_DISCONNECTED state should, if successful, cause the interface to transition into the WLAN_CONNECTING state. If the connection attempt succeeds, the station interface should transition to the WLAN_CONNECTED state, otherwise it should return to the WLAN_DISCONNECTED state. If this function is called while the station interface is in the WLAN_CONNECTING or WLAN_CONNECTED state, the Wi-Fi connection manager should first cancel its connection attempt or disconnect from the network, respectively, and generate an event with reason WLAN_REASON_USER_DISCONNECT. This should be followed by a second event that reports the result of the new connection attempt.

If the connection attempt was successful the WLCMGR callback is notified with the event WLAN_REASON_SUCCESS, while if the connection attempt fails then either of the events, WLAN_REASON_NETWORK_NOT_FOUND, WLAN_REASON_NETWORK_AUTH_FAILED, WLAN_REASON_CONNECT_FAILED or WLAN_REASON_ADDRESS_FAILED are reported as appropriate.


**Parameters**


  ----------------------- ----------------------- ---------------------------------------------------------------------------
  in                      *name*                  A pointer to a string representing the name of the network to connect to.

  ----------------------- ----------------------- ---------------------------------------------------------------------------


**Returns**


WM_SUCCESS if a connection attempt was started successfully

WLAN_ERROR_STATE if the Wi-Fi connection manager was not running.

-WM_E_INVAL if there are no known networks to connect to or the network specified by *name* is not in the list of known networks or network *name* is NULL.

-WM_FAIL if an internal error has occurred.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_connect_opt (char \* *name*, bool *skip_dfs*)

Connect to a Wi-Fi network (access point) with options.

When this function is called, the Wi-Fi connection manager starts connection attempts to the network specified by *name* . The connection result should be notified asynchronously to the WLCMGR callback when the connection process has completed.

When connecting to a network, the event refers to the connection attempt to that network.

Calling this function when the station interface is in the WLAN_DISCONNECTED state should, if successful, cause the interface to transition into the WLAN_CONNECTING state. If the connection attempt succeeds, the station interface should transition to the WLAN_CONNECTED state, otherwise it should return to the WLAN_DISCONNECTED state. If this function is called while the station interface is in the WLAN_CONNECTING or WLAN_CONNECTED state, the Wi-Fi connection manager should first cancel its connection attempt or disconnect from the network, respectively, and generate an event with reason WLAN_REASON_USER_DISCONNECT. This should be followed by a second event that reports the result of the new connection attempt.

If the connection attempt was successful the WLCMGR callback is notified with the event WLAN_REASON_SUCCESS, while if the connection attempt fails then either of the events, WLAN_REASON_NETWORK_NOT_FOUND, WLAN_REASON_NETWORK_AUTH_FAILED, WLAN_REASON_CONNECT_FAILED or WLAN_REASON_ADDRESS_FAILED are reported as appropriate.


**Parameters**


  ----------------------- ----------------------- ---------------------------------------------------------------------------
  in                      *name*                  A pointer to a string representing the name of the network to connect to.

  in                      *skip_dfs*              Option to skip DFS channel when doing scan.
  ----------------------- ----------------------- ---------------------------------------------------------------------------


**Returns**


WM_SUCCESS if a connection attempt was started successfully

WLAN_ERROR_STATE if the Wi-Fi connection manager was not running.

-WM_E_INVAL if there are no known networks to connect to or the network specified by *name* is not in the list of known networks or network *name* is NULL.

-WM_FAIL if an internal error has occurred.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_disconnect (void )

Disconnect from the current Wi-Fi network (access point).

When this function is called, the Wi-Fi connection manager attempts to disconnect the station interface from its currently connected network (or cancel an in-progress connection attempt) and return to the WLAN_DISCONNECTED state. Calling this function has no effect if the station interface is already disconnected.


**Note**


This is an asynchronous function and successful disconnection should be notified using the WLAN_REASON_USER_DISCONNECT.


**Returns**


WM_SUCCESS if successful

WLAN_ERROR_STATE otherwise

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_get_connection_state (enum wlan_connection_state \* *state*)

Retrieve the connection state of the station interface.

This function retrieves the connection state of the station interface, which is one of WLAN_DISCONNECTED, WLAN_CONNECTING, WLAN_ASSOCIATED or WLAN_CONNECTED.


**Parameters**


  ----------------------- ----------------------- --------------------------------------------------------------------------------------------------------------------------
  out                     *state*                 A pointer to the wlan_connection_state where the current connection state should be copied.

  ----------------------- ----------------------- --------------------------------------------------------------------------------------------------------------------------


**Returns**


WM_SUCCESS if successful.

-WM_E_INVAL if *state* is NULL

WLAN_ERROR_STATE if the Wi-Fi connection manager was not running.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_is_started (void )

Retrieve the status information of if Wi-Fi started.


**Returns**


TRUE if Wi-Fi network is started.

FALSE if not started.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_reassociate (void )

Reassociate to a Wi-Fi network (access point).

When this function is called, the Wi-Fi connection manager starts reassociation attempts using same SSID as currently connected network . The connection result should be notified asynchronously to the WLCMGR callback when the connection process has completed.

When connecting to a network, the event refers to the connection attempt to that network.

Calling this function when the station interface is in the WLAN_DISCONNECTED state should have no effect.

Calling this function when the station interface is in the WLAN_CONNECTED state should, if successful, cause the interface to reassociate to another network (access point).

If the connection attempt was successful the WLCMGR (Wi-Fi command manager) callback is notified with the event WLAN_REASON_SUCCESS, while if the connection attempt fails then either of the events, WLAN_REASON_NETWORK_AUTH_FAILED, WLAN_REASON_CONNECT_FAILED or WLAN_REASON_ADDRESS_FAILED are reported as appropriate.


**Returns**


WM_SUCCESS if a reassociation attempt was started successfully

WLAN_ERROR_STATE if the Wi-Fi connection manager was not running. or Wi-Fi connection manager was not in WLAN_CONNECTED state.

-WM_E_INVAL if there are no known networks to connect to

-WM_FAIL if an internal error has occurred.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_wlcmgr_send_msg (enum wlan_bss_type *bss_type*, enum wifi_event *event*, enum wifi_event_reason *reason*, void \* *data*)

Send message to Wi-Fi connection manager thread.


**Parameters**


  ----------------------- ----------------------- -------------------------------------------------
  in                      *event*                 An event from wifi_event.

  in                      *reason*                A reason code.

  in                      *data*                  A pointer to data buffer associated with event.
  ----------------------- ----------------------- -------------------------------------------------


**Returns**


WM_SUCCESS if successful.

-WM_FAIL if failed.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---


#### Network Management

| Function | Supported SoCs |
|----------|---------------|
| `wlan_add_network` | All |
| `wlan_get_network` | All |
| `wlan_get_network_byname` | All |
| `wlan_get_network_count` | All |
| `wlan_initialize_sta_network` | All |
| `wlan_remove_all_network_profiles` | All |
| `wlan_remove_all_networks` | All |
| `wlan_remove_network` | All |

##### int wlan_add_network (struct wlan_network \* *network*)

Add a network profile to the list of known networks.

This function copies the contents of *network* to the list of known networks in the Wi-Fi connection manager. The network\'s \'name\' field is unique and between WLAN_NETWORK_NAME_MIN_LENGTH and WLAN_NETWORK_NAME_MAX_LENGTH characters. The network must specify at least an SSID or BSSID. the Wi-Fi connection manager can store up to WLAN_MAX_KNOWN_NETWORKS networks.


**Note**


Profiles for the station interface may be added only when the station interface is in the WLAN_DISCONNECTED or WLAN_CONNECTED state.

This API can be used to add profiles for station or uAP interfaces.

Set mfpc and mfpr to -1 for default configurations.


**Parameters**


  ----------------------- ----------------------- -----------------------------------------------------------------------------------------------------------------------------------------------------------
  in                      *network*               A pointer to the wlan_network that can be copied to the list of known networks in the Wi-Fi connection manager successfully.

  ----------------------- ----------------------- -----------------------------------------------------------------------------------------------------------------------------------------------------------


**Returns**


WM_SUCCESS if the contents pointed to by *network* have been added to the Wi-Fi connection manager.

-WM_E_INVAL if *network* is NULL or the network name is not unique or the network name length is not valid or network security is WLAN_SECURITY_WPA3_SAE but Management Frame Protection Capable is not enabled. in wlan_network_security field. if network security type is WLAN_SECURITY_WPA or WLAN_SECURITY_WPA2 or WLAN_SECURITY_WPA_WPA2_MIXED, but the passphrase length is less than 8 or greater than 63, or the psk length equal to 64 but not hexadecimal digits. if network security type is WLAN_SECURITY_WPA3_SAE, but the password length is less than 8 or greater than 255. if network security type is WLAN_SECURITY_WEP_OPEN or WLAN_SECURITY_WEP_SHARED.

-WM_E_NOMEM if there was no room to add the network.

WLAN_ERROR_STATE if the Wi-Fi connection manager was running and not in the WLAN_DISCONNECTED, WLAN_ASSOCIATED or WLAN_CONNECTED state.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_get_network (unsigned int *index*, struct wlan_network \* *network*)

Retrieve the information about a known network using *index* .

This function retrieves the contents of a network at *index* in the list of known networks maintained by the Wi-Fi connection manager and copies it to the location pointed to by *network* .


**Note**


wlan_get_network_count() can be used to retrieve the number of known networks. wlan_get_network() can be used to retrieve information about networks at *index* 0 to one minus the number of networks.

This function can be called regardless of whether the Wi-Fi connection manager is running or not. Calls to this function are synchronous.


**Parameters**


  ----------------------- ----------------------- --------------------------------------------------------------------------------------------------------------------------------------
  in                      *index*                 The index of the network to retrieve.

  out                     *network*               A pointer to the wlan_network where the network configuration for the network at *index* can be copied.
  ----------------------- ----------------------- --------------------------------------------------------------------------------------------------------------------------------------


**Returns**


WM_SUCCESS if successful.

-WM_E_INVAL if *network* is NULL or *index* is out of range.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_get_network_byname (char \* *name*, struct wlan_network \* *network*)

Retrieve information about a known network using *name* .

This function retrieves the contents of a named network in the list of known networks maintained by the Wi-Fi connection manager and copies it to the location pointed to by *network* .


**Note**


This function can be called regardless of whether the Wi-Fi Connection Manager is running or not. Calls to this function are synchronous.


**Parameters**


  ----------------------- ----------------------- ----------------------------------------------------------------------------------------------------------------------------------------------------
  in                      *name*                  The name of the network to retrieve.

  out                     *network*               A pointer to the wlan_network where the network configuration for the network having name as *name* should be copied.
  ----------------------- ----------------------- ----------------------------------------------------------------------------------------------------------------------------------------------------


**Returns**


WM_SUCCESS if successful.

-WM_E_INVAL if *network* is NULL or *name* is NULL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_get_network_count (unsigned int \* *count*)

Retrieve the number of networks known to the Wi-Fi connection manager.

This function retrieves the number of known networks in the list maintained by the Wi-Fi connection manager and copies it to *count* .


**Note**


This function can be called regardless of whether the Wi-Fi Connection Manager is running or not. Calls to this function are synchronous.


**Parameters**


  ----------------------- ----------------------- ---------------------------------------------------------------------------------
  out                     *count*                 A pointer to the memory location where the number of networks should be copied.

  ----------------------- ----------------------- ---------------------------------------------------------------------------------


**Returns**


WM_SUCCESS if successful.

-WM_E_INVAL if *count* is NULL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### void wlan_initialize_sta_network (struct wlan_network \* *net*)

Initialize the station network information.

This API initializes a station network with default configurations. The network ssid, passphrase is initialized to NULL. Channel is set to auto.


**Parameters**


  ----------------------- ----------------------- --------------------------------------------
  out                     *net*                   Pointer to the initialized station network

  ----------------------- ----------------------- --------------------------------------------

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_remove_all_network_profiles (void )

Stop and remove all Wi-Fi network profiles.


**Returns**


WM_SUCCESS if successful otherwise return -WM_E_INVAL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_remove_all_networks (void )

Stop and remove all Wi-Fi network (access point).


**Returns**


WM_SUCCESS if successful.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_remove_network (const char \* *name*)

Remove a network profile from the list of known networks.

This function removes a network (identified by its name) from the WLAN Connection Manager, disconnecting from that network if connected.


**Note**


This function is asynchronous if it is called while the WLAN Connection Manager is running and connected to the network to be removed. In that case, the Wi-Fi connection manager can disconnect from the network and generate an event with reason WLAN_REASON_USER_DISCONNECT. This function is synchronous otherwise.

This API can be used to remove profiles for station or uAP interfaces. Station network can not be removed if it is in WLAN_CONNECTED state and uAP network can not be removed if it is in WLAN_UAP_STARTED state.


**Parameters**


  ----------------------- ----------------------- -------------------------------------------------------------------------
  in                      *name*                  A pointer to the string representing the name of the network to remove.

  ----------------------- ----------------------- -------------------------------------------------------------------------


**Returns**


WM_SUCCESS if the network named *name* was removed from the Wi-Fi connection manager successfully. Otherwise, the network is not removed.

WLAN_ERROR_STATE if the Wi-Fi connection manager was running and the station interface was not in the WLAN_DISCONNECTED state.

-WM_E_INVAL if *name* is NULL or the network was not found in the list of known networks.

-WM_FAIL if an internal error occurred while trying to disconnect from the network specified for removal.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---


#### Network Status

| Function | Supported SoCs |
|----------|---------------|
| `wlan_get_address` | All |
| `wlan_get_current_bssid` | All |
| `wlan_get_current_network` | All |
| `wlan_get_current_network_bssid` | All |
| `wlan_get_current_network_ssid` | All |

##### int wlan_get_address (struct wlan_ip_config \* *addr*)

Retrieve the IP address configuration of the station interface.

This function retrieves the IP address configuration of the station interface and copies it to the memory location pointed to by *addr* .


**Note**


This function may only be called when the station interface is in the WLAN_CONNECTED state.


**Parameters**


  ----------------------- ----------------------- ---------------------------------------------------------------
  out                     *addr*                  A pointer to the wlan_ip_config.

  ----------------------- ----------------------- ---------------------------------------------------------------


**Returns**


WM_SUCCESS if successful.

-WM_E_INVAL if *addr* is NULL.

WLAN_ERROR_STATE if the Wi-Fi connection manager was not running or was not in the WLAN_CONNECTED state.

-WM_FAIL if an internal error occurred when retrieving IP address information from the TCP stack.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_get_current_bssid (uint8_t \* *bssid*)

Use this API to get the BSSID of associated BSS when in station mode.


**Parameters**


  ----------------------- ----------------------- -----------------------------------------------------------
  out                     *bssid*                 A pointer to array(char, length is 6) to store the BSSID.

  ----------------------- ----------------------- -----------------------------------------------------------


**Returns**


WM_SUCCESS if operation is successful.

-WM_FAIL if command fails.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_get_current_network (struct wlan_network \* *network*)

Retrieve the current network configuration of the station interface.

This function retrieves the current network configuration of the station interface when the station interface is in the WLAN_CONNECTED state.


**Parameters**


  ----------------------- ----------------------- -------------------------------------------------------------
  out                     *network*               A pointer to the wlan_network.

  ----------------------- ----------------------- -------------------------------------------------------------


**Returns**


WM_SUCCESS if successful.

-WM_E_INVAL if *network* is NULL.

WLAN_ERROR_STATE if the Wi-Fi connection manager was not running or not in the WLAN_CONNECTED state.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_get_current_network_bssid (char \* *bssid*)

Retrieve the current network bssid of the station interface.

This function retrieves the current network bssid of the station interface when the station interface is in the WLAN_CONNECTED state.


**Parameters**


  ----------------------- ----------------------- --------------------------------------------------------------
  out                     *bssid*                 A pointer to the bssid char string without NULL termination.

  ----------------------- ----------------------- --------------------------------------------------------------


**Returns**


WM_SUCCESS if successful.

-WM_E_INVAL if *bssid* is NULL.

WLAN_ERROR_STATE if the Wi-Fi connection manager was not running or not in the WLAN_CONNECTED state.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_get_current_network_ssid (char \* *ssid*)

Retrieve the current network ssid of the station interface.

This function retrieves the current network ssid of the station interface when the station interface is in the WLAN_CONNECTED state.


**Parameters**


  ----------------------- ----------------------- ---------------------------------------------------------------------------------------------------------------
  out                     *ssid*                  A pointer to the ssid char string with NULL termination. Maximum length is 32 (not include NULL termination).

  ----------------------- ----------------------- ---------------------------------------------------------------------------------------------------------------


**Returns**


WM_SUCCESS if successful.

-WM_E_INVAL if *ssid* is NULL.

WLAN_ERROR_STATE if the Wi-Fi connection manager was not running or not in the WLAN_CONNECTED state.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---


#### Scan

| Function | Supported SoCs |
|----------|---------------|
| `get_scan_params` | All |
| `set_scan_params` | All |
| `verify_scan_channel_value` | All |
| `verify_scan_duration_value` | All |
| `verify_split_scan_delay` | All |
| `wlan_get_scan_result` | All |
| `wlan_scan` | All |
| `wlan_scan_with_opt` | All |
| `wlan_select_cur_network_by_scan_res` | IW416, W8987, IW610, IW612 |
| `wlan_set_scan_interval` | All |

##### int get_scan_params (struct wifi_scan_params_t \* *wifi_scan_params*)

Get the scan parameters.


**Parameters**


  ----------------------- ----------------------- -----------------------------------------
  out                     *wifi_scan_params*      Wi-Fi scan parameter structure pointer.

  ----------------------- ----------------------- -----------------------------------------


**Returns**


WM_SUCCESS.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int set_scan_params (struct wifi_scan_params_t \* *wifi_scan_params*)

Set the scan parameters.


**Parameters**


  ----------------------- ----------------------- -----------------------------------------
  in                      *wifi_scan_params*      Wi-Fi scan parameter structure pointer.

  ----------------------- ----------------------- -----------------------------------------


**Returns**


0 if Wi-Fi scan parameters are set successfully, else return -1.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int verify_scan_channel_value (int *channel*)

Check whether the scan channel is valid or not.


**Parameters**


  ----------------------- ----------------------- -----------------------
  in                      *channel*               the scan channel

  ----------------------- ----------------------- -----------------------


**Returns**


0 if the channel is valid, else return -1.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int verify_scan_duration_value (int *scan_duration*)

Check whether the scan duration is valid or not.


**Parameters**


  ----------------------- ----------------------- -----------------------
  in                      *scan_duration*         scan duration time

  ----------------------- ----------------------- -----------------------


**Returns**


0 if the time is valid, else return -1.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int verify_split_scan_delay (int *delay*)

Check whether the scan delay time is valid or not.


**Parameters**


  ----------------------- ----------------------- -----------------------
  in                      *delay*                 the scan delay time.

  ----------------------- ----------------------- -----------------------


**Returns**


0 if the time is valid, else return -1.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_get_scan_result (unsigned int *index*, struct wlan_scan_result \* *res*)

Retrieve a scan result.

This function can be called to retrieve scan results when the Wi-Fi connection manager has finished scanning. It is called from within the scan result callback (see wlan_scan()) as scan results are valid only in that context. The callback argument \'count\' provides the number of scan results that can be retrieved and wlan_get_scan_result() can be used to retrieve scan results at *index* 0 through that number.


**Note**


This function may only be called in the context of the scan results callback.

Calls to this function are synchronous.


**Parameters**


  ----------------------- ----------------------- --------------------------------------------------------------------------------------------------------------------
  in                      *index*                 The scan result to retrieve.

  out                     *res*                   A pointer to the wlan_scan_result where the scan result information should be copied.
  ----------------------- ----------------------- --------------------------------------------------------------------------------------------------------------------


**Returns**


WM_SUCCESS if successful.

-WM_E_INVAL if *res* is NULL

WLAN_ERROR_STATE if the Wi-Fi connection manager was not running

-WM_FAIL if the scan result at *index* could not be retrieved (that is, *index* is out of range).

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_scan (int(\*)(unsigned int count) *cb*)

Scan for Wi-Fi networks.

When this function is called, the Wi-Fi connection manager starts scan for Wi-Fi networks. On completion of the scan the Wi-Fi connection manager can call the specified callback function *cb* . The callback function should then retrieve the scan results by using the wlan_get_scan_result() function.


**Note**


This function may only be called when the station interface is in the WLAN_DISCONNECTED or WLAN_CONNECTED state. scan is disabled in the WLAN_CONNECTING state.

This function should block until it can issue a scan request if called while another scan is in progress.


**Parameters**


  ----------------------- ----------------------- -------------------------------------------------------------------------------------------------
  in                      *cb*                    A pointer to the function that should be called to handle scan results when they are available.

  ----------------------- ----------------------- -------------------------------------------------------------------------------------------------


**Returns**


WM_SUCCESS if successful.

-WM_E_NOMEM if failed to allocated memory for wlan_scan_params_v2_t structure.

-WM_E_INVAL if *cb* scan result callback function pointer is NULL.

WLAN_ERROR_STATE if the Wi-Fi connection manager was not running or not in the WLAN_DISCONNECTED or WLAN_CONNECTED states.

-WM_FAIL if an internal error has occurred and the system is unable to scan.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_scan_with_opt (wlan_scan_params_v2_t *t_wlan_scan_param*)

Scan for Wi-Fi networks using options provided.

When this function is called, the Wi-Fi connection manager starts scanning for Wi-Fi networks. On completion of the scan the Wi-Fi connection manager should call the specified callback function *t_wlan_scan_param.cb* . The callback function should then retrieve the scan results by using the wlan_get_scan_result() function.


**Note**


This function may only be called when the station interface is in the WLAN_DISCONNECTED or WLAN_CONNECTED state. scan is disabled in the WLAN_CONNECTING state.

This function can block until it issues a scan request if called while another scan is in progress.


**Parameters**


  ----------------------- ----------------------- -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  in                      *t_wlan_scan_param*     A wlan_scan_params_v2_t structure holding a pointer to function that should be called to handle scan results when they are available, SSID of a Wi-Fi network, BSSID of a Wi-Fi network, number of channels with scan type information and number of probes.

  ----------------------- ----------------------- -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


**Returns**


WM_SUCCESS if successful.

-WM_E_NOMEM if failed to allocated memory for wlan_scan_params_v2_t structure.

-WM_E_INVAL if *cb* scan result callback function pointer is NULL.

WLAN_ERROR_STATE if the Wi-Fi connection manager was not running or not in the WLAN_DISCONNECTED or WLAN_CONNECTED states.

-WM_FAIL if an internal error has occurred and the system is unable to scan.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_select_cur_network_by_scan_res (unsigned int *scan_index*)

Select (synchronize) current network index according to a scan table entry.

This API searches configured wlan.networks\[\] for an entry that matches the given scan table index, and sets wlan.cur_network_idx accordingly.


**Parameters**


  ----------------------- ----------------------- --------------------------------------
  in                      *scan_index*            Index into the driver\'s scan table.

  ----------------------- ----------------------- --------------------------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

##### int wlan_set_scan_interval (int *scan_int*)

Set wpa supplicant scan interval in seconds


**Parameters**


  ----------------------- ----------------------- --------------------------
  in                      *scan_int*              Scan interval in seconds

  ----------------------- ----------------------- --------------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---


#### UAP (Micro Access Point)

| Function | Supported SoCs |
|----------|---------------|
| `is_uap_started` | All |
| `wlan_get_current_uap_network` | All |
| `wlan_get_current_uap_network_ssid` | All |
| `wlan_get_uap_address` | All |
| `wlan_get_uap_channel` | All |
| `wlan_get_uap_connection_state` | All |
| `wlan_get_uap_ed_mac_mode` | All |
| `wlan_get_uap_max_clients` | All |
| `wlan_get_uap_supported_max_clients` | All |
| `wlan_initialize_uap_network` | All |
| `wlan_set_uap_ed_mac_mode` | All |
| `wlan_set_uap_mac_addr` | All |
| `wlan_set_uap_max_clients` | All |
| `wlan_start_network` | All |
| `wlan_stop_network` | All |
| `wlan_uap_ampdu_rx_disable` | All |
| `wlan_uap_ampdu_rx_enable` | All |
| `wlan_uap_ampdu_tx_disable` | All |
| `wlan_uap_ampdu_tx_enable` | All |
| `wlan_uap_ctrl_deauth` | All |
| `wlan_uap_disconnect_sta` | RW610 |
| `wlan_uap_get_bandwidth` | All |
| `wlan_uap_get_log` | RW610 |
| `wlan_uap_get_pmfcfg` | All |
| `wlan_uap_set_bandwidth` | All |
| `wlan_uap_set_beacon_period` | All |
| `wlan_uap_set_ecsa` | All |
| `wlan_uap_set_ecsa_cfg` | RW610 |
| `wlan_uap_set_hidden_ssid` | All |
| `wlan_uap_set_htcapinfo` | All |
| `wlan_uap_set_httxcfg` | All |
| `wlan_uap_set_scan_chan_list` | All |

##### bool is_uap_started (void )

Retrieve the status information of the uAP interface.


**Returns**


TRUE if uAP interface is in WLAN_UAP_STARTED state.

FALSE otherwise.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_get_current_uap_network (struct wlan_network \* *network*)

Retrieve the current network configuration of the uAP interface.

This function retrieves the current network configuration of the uAP interface when the uAP interface is in the WLAN_UAP_STARTED state.


**Parameters**


  ----------------------- ----------------------- -------------------------------------------------------------
  out                     *network*               A pointer to the wlan_network.

  ----------------------- ----------------------- -------------------------------------------------------------


**Returns**


WM_SUCCESS if successful.

-WM_E_INVAL if *network* is NULL.

WLAN_ERROR_STATE if the Wi-Fi connection manager was not running or not in the WLAN_UAP_STARTED state.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_get_current_uap_network_ssid (char \* *ssid*)

Retrieve the current network ssid of the uAP interface.

This function retrieves the current network ssid of the uAP interface when the uAP interface is in the WLAN_UAP_STARTED state.


**Parameters**


  ----------------------- ----------------------- ---------------------------------------------------------------------------------------------------------------
  out                     *ssid*                  A pointer to the ssid char string with NULL termination. Maximum length is 32 (not include NULL termination).

  ----------------------- ----------------------- ---------------------------------------------------------------------------------------------------------------


**Returns**


WM_SUCCESS if successful.

-WM_E_INVAL if *ssid* is NULL.

WLAN_ERROR_STATE if the Wi-Fi connection manager was not running or not in the WLAN_UAP_STARTED state.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_get_uap_address (struct wlan_ip_config \* *addr*)

Retrieve the IP address of the uAP interface.

This function retrieves the current IP address configuration of the uAP and copies it to the memory location pointed to by *addr* .


**Note**


This function may only be called when the uAP interface is in the WLAN_UAP_STARTED state.


**Parameters**


  ----------------------- ----------------------- ---------------------------------------------------------------
  out                     *addr*                  A pointer to the wlan_ip_config.

  ----------------------- ----------------------- ---------------------------------------------------------------


**Returns**


WM_SUCCESS if successful.

-WM_E_INVAL if *addr* is NULL.

WLAN_ERROR_STATE if the Wi-Fi connection manager was not running or the uAP interface was not in the WLAN_UAP_STARTED state.

-WM_FAIL if an internal error occurred when retrieving IP address information from the TCP stack.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_get_uap_channel (int \* *channel*)

Retrieve the channel of the uAP interface.

This function retrieves the channel number of the uAP and copies it to the memory location pointed to by *channel* .


**Note**


This function may only be called when the uAP interface is in the WLAN_UAP_STARTED state.


**Parameters**


  ----------------------- ----------------------- ---------------------------------------------------
  out                     *channel*               A pointer to variable that stores channel number.

  ----------------------- ----------------------- ---------------------------------------------------


**Returns**


WM_SUCCESS if successful.

-WM_E_INVAL if *channel* is NULL.

-WM_FAIL if an internal error has occurred.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_get_uap_connection_state (enum wlan_connection_state \* *state*)

Retrieve the connection state of the uAP interface.

This function retrieves the connection state of the uAP interface, which is one of WLAN_UAP_STARTED, or WLAN_UAP_STOPPED.


**Parameters**


  ----------------------- ----------------------- --------------------------------------------------------------------------------------------------------------------------
  out                     *state*                 A pointer to the wlan_connection_state where the current connection state should be copied.

  ----------------------- ----------------------- --------------------------------------------------------------------------------------------------------------------------


**Returns**


WM_SUCCESS if successful.

-WM_E_INVAL if *state* is NULL

WLAN_ERROR_STATE if the Wi-Fi connection manager was not running.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_get_uap_ed_mac_mode (wlan_ed_mac_ctrl_t \* *wlan_ed_mac_ctrl*)

This API can be used to get current ED MAC MODE configuration for uAP.


**Parameters**


  ----------------------- ----------------------- ----------------------------------------------------------------------------------------------------------
  out                     *wlan_ed_mac_ctrl*      A pointer to wlan_ed_mac_ctrl_t with parameters mentioned in above set API.

  ----------------------- ----------------------- ----------------------------------------------------------------------------------------------------------


**Returns**


WM_SUCCESS if the call was successful.

-WM_FAIL if failed.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_get_uap_max_clients (unsigned int \* *max_sta_num*)

Get current maximum number of the stations that can be allowed to connect to the uAP.


**Parameters**


  ----------------------- ----------------------- --------------------------------------------------------------------------------------------------------
  out                     *max_sta_num*           A pointer to variable where current maximum number of the stations of the uAP interface can be stored.

  ----------------------- ----------------------- --------------------------------------------------------------------------------------------------------


**Returns**


WM_SUCCESS if successful.

-WM_FAIL if unsuccessful.


**Note**


Get operation is allowed in any uAP state.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### unsigned int wlan_get_uap_supported_max_clients (void )

Get maximum number of the stations Wi-Fi firmware supported that can be allowed to connect to the uAP.


**Returns**


Maximum number of the stations Wi-Fi firmware supported that can be allowed to connect to the uAP.


**Note**


Get operation is allowed in any uAP state.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### void wlan_initialize_uap_network (struct wlan_network \* *net*)

Initialize the uAP network information.

This API initializes a uAP network with default configurations. The network ssid, passphrase is initialized to NULL. Channel is set to auto. The IP Address of the uAP interface is 192.168.10.1/255.255.255.0. The network name is set to \'uap-network\'.


**Parameters**


  ----------------------- ----------------------- ----------------------------------------
  out                     *net*                   Pointer to the initialized uAP network

  ----------------------- ----------------------- ----------------------------------------

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_set_uap_ed_mac_mode (wlan_ed_mac_ctrl_t *wlan_ed_mac_ctrl*)

Configure Energy Detect MAC mode for the uAP in the Wi-Fi firmware.


**Note**


When ED MAC mode is enabled, the Wi-Fi Firmware can behave in the following way:

When the background noise had reached the Energy Detect threshold or above, the Wi-Fi chipset/module should hold data transmission until the condition is removed. The 2.4GHz and 5GHz bands are configured separately.


**Parameters**


  ----------------------- ----------------------- --------------------------------------------------------------------------------------------------------------------------------
  in                      *wlan_ed_mac_ctrl*      Struct with following parameters ed_ctrl_2g 0 - disable EU adaptivity for 2.4GHz band 1 - enable EU adaptivity for 2.4GHz band

  ----------------------- ----------------------- --------------------------------------------------------------------------------------------------------------------------------

ed_offset_2g 0 - Default energy detect threshold (Default: 0x9) offset value range: 0x80 to 0x7F


**Note**


If 5GH enabled then add following parameters

      ed_ctrl_5g          0  - disable EU adaptivity for 5GHz band
                          1  - enable EU adaptivity for 5GHz band
      ed_offset_5g        0  - Default energy detect threshold(Default: 0xC)
                          offset value range: 0x80 to 0x7F


**Returns**


WM_SUCCESS if the call was successful.

-WM_FAIL if failed.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_set_uap_mac_addr (uint8_t \* *mac*)

Set the Wi-Fi MAC address for the uAP in the Wi-Fi firmware.

This function can be used to set the Wi-Fi MAC address for the uAP in the firmware. Should be called after Wi-Fi initialization done. It sets the uAP MAC address only.


**Parameters**


  ----------------------- ----------------------- -------------------------------------------------------------------------------------------------------
  in                      *MAC*                   The MAC Address in 6 bytes array format like uint8_t mac\[\] = { 0x00, 0x50, 0x43, 0x21, 0x19, 0x6E};

  ----------------------- ----------------------- -------------------------------------------------------------------------------------------------------


**Returns**


WM_SUCCESS if the call was successful.

-WM_FAIL if failed.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_set_uap_max_clients (unsigned int *max_sta_num*)

Set maximum number of the stations that can be allowed to connect to the uAP.


**Parameters**


  ----------------------- ----------------------- -------------------------------------
  in                      *max_sta_num*           Number of maximum stations for uAP.

  ----------------------- ----------------------- -------------------------------------


**Returns**


WM_SUCCESS if successful.

-WM_FAIL if unsuccessful.


**Note**


Set operation in not allowed in WLAN_UAP_STARTED state.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_start_network (const char \* *name*)

Start a Wi-Fi network (access point).

When this function is called, the Wi-Fi connection manager starts the network specified by *name* . The network with the specified *name* is first added using wlan_add_network and is a uAP network with a valid SSID.


**Note**


The WLCMGR callback is asynchronously notified of the status. On success, the event WLAN_REASON_UAP_SUCCESS is reported, while on failure, the event WLAN_REASON_UAP_START_FAILED is reported.


**Parameters**


  ----------------------- ----------------------- -------------------------------------------------------------------------
  in                      *name*                  A pointer to string representing the name of the network to connect to.

  ----------------------- ----------------------- -------------------------------------------------------------------------


**Returns**


WM_SUCCESS if successful.

WLAN_ERROR_STATE if in power save state or uAP already running.

-WM_E_INVAL if *name* was NULL or the network *name* was not found or it not have a specified SSID.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_stop_network (const char \* *name*)

Stop a Wi-Fi network (access point).

When this function is called, the Wi-Fi connection manager stops the network specified by *name* . The specified network is a valid uAP network that has already been started.


**Note**


The WLCMGR callback is asynchronously notified of the status. On success, the event WLAN_REASON_UAP_STOPPED is reported, while on failure, the event WLAN_REASON_UAP_STOP_FAILED is reported.


**Parameters**


  ----------------------- ----------------------- ---------------------------------------------------------------------
  in                      *name*                  A pointer to a string representing the name of the network to stop.

  ----------------------- ----------------------- ---------------------------------------------------------------------


**Returns**


WM_SUCCESS if successful.

WLAN_ERROR_STATE if uAP is in power save state.

-WM_E_INVAL if *name* was NULL or the network *name* was not found or that the network *name* is not a uAP network or it is a uAP network but does not have a specified SSID.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### void wlan_uap_ampdu_rx_disable (void )

This API can be used to disable AMPDU support when uAP is a receiver.


**Note**


By default the uAP AMPDU TX support is enabled if configuration option CONFIG_UAP_AMPDU_RX is defined 1.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### void wlan_uap_ampdu_rx_enable (void )

This API can be used to enable AMPDU support when uAP is a receiver.


**Note**


By default the uAP AMPDU TX support is enabled if configuration option CONFIG_UAP_AMPDU_RX is defined 1.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### void wlan_uap_ampdu_tx_disable (void )

This API can be used to disable AMPDU support when uAP is a transmitter.


**Note**


By default the uAP AMPDU TX support is enabled if configuration option CONFIG_UAP_AMPDU_TX is defined 1.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### void wlan_uap_ampdu_tx_enable (void )

This API can be used to enable AMPDU support when uAP is a transmitter.


**Note**


By default the uAP AMPDU TX support is enabled if configuration option CONFIG_UAP_AMPDU_TX is defined 1.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### void wlan_uap_ctrl_deauth (const bool *enable*)

API to control the deauthentication during uAP channel switch.


**Parameters**


  ----------------------- ----------------------- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  in                      *enable*                0 -- Wi-Fi firmware can use default behavior, send deauth packet when uAP move to another channel. 1 -- Wi-Fi firmware cannot send deauth packet when uAP move to another channel.

  ----------------------- ----------------------- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


**Note**


Call this API before calling uAP start API.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_uap_disconnect_sta (uint8_t \* *sta_addr*)

Disconnect to STA which is connected with internal uAP.

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>sta_addr</em></td>
<td>STA MAC address</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610


---

##### int wlan_uap_get_bandwidth (uint8_t \* *bandwidth*)

API to get the bandwidth of the uAP


**Parameters**


  ----------------------- ----------------------- --------------------------------------------------
  out                     *bandwidth*             Wi-Fi AP bandwidth 1: 20 MHz 2: 40 MHz 3: 80 MHz

  ----------------------- ----------------------- --------------------------------------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

-WM_FAIL if command fails.


**Note**


Call this API before calling uAP start API.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_uap_get_log (wlan_pkt_stats_t \* *stats*)

Use this API to get the various statistics of the uAP from Wi-Fi
firmware.

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>stats</em></td>
<td><p>A pointer to structure where stats collected from Wi-Fi firmware can be copied.</p>
<p>Explore the elements of the wlan_pkt_stats_t strucutre for more information on stats.</p></td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if operation is successful.

\-WM_FAIL if command fails.

> **Supported SoCs:** RW610


---

##### int wlan_uap_get_pmfcfg (uint8_t \* *mfpc*, uint8_t \* *mfpr*)

Use this API to get the set management frame protection parameters for uAP.


**Parameters**


  ----------------------- ----------------------- --------------------------------------------------------------------------------------------------------------------------------
  out                     *mfpc*                  Management frame protection capable (MFPC) 1: management frame protection capable. 0: management frame protection not capable.

  out                     *mfpr*                  Management frame protection required (MFPR) 1: management frame protection required. 0: management frame protection optional.
  ----------------------- ----------------------- --------------------------------------------------------------------------------------------------------------------------------


**Returns**


WM_SUCCESS if operation is successful.

-WM_FAIL if command fails.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_uap_set_bandwidth (const uint8_t *bandwidth*)

API to set the bandwidth of the uAP


**Parameters**


+-----------------------+-----------------------+-------------------------------+
| in                    | *bandwidth*           | Wi-Fi AP bandwidth            |
|                       |                       |                               |
|                       |                       | 1: 20 MHz 2: 40 MHz 3: 80 MHz |
+-----------------------+-----------------------+-------------------------------+


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

-WM_FAIL if command fails.


**Note**


Not applicable to 20MHZ only chip sets (Redfinch, SD8801)

Call this API before calling uAP start API.

Default bandwidth setting is 40 MHz.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### void wlan_uap_set_beacon_period (const uint16_t *beacon_period*)

API to set the beacon period of the uAP


**Parameters**


  ----------------------- ----------------------- ------------------------------------------------
  in                      *beacon_period*         Beacon period in TU (1 TU = 1024 microseconds)

  ----------------------- ----------------------- ------------------------------------------------


**Note**


Call this API before calling uAP start API.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### void wlan_uap_set_ecsa (void )

API to enable channel switch announcement functionality on uAP.


**Note**


Call this API before calling uAP start API. Also note that 802.11n should be enabled on uAP. The channel switch announcement IE is transmitted in 7 beacons before the channel switch, during a station connection attempt on a different channel with Ex-AP.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_uap_set_ecsa_cfg (t_u8 *block_tx*, t_u8 *oper_class*, t_u8 *channel*, t_u8 *switch_count*, t_u8 *band_width*)

Send the ecsa configuration parameter to FW.

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>block_tx</em></td>
<td>0 – no need to block traffic,1 – need block traffic.</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>oper_class</em></td>
<td>Operating class according to IEEE std802.11 spec, refer to Annex E, when 0 is used, automatically get operclass through band_width and channel.</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>channel</em></td>
<td>The channel can switch to.</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>switch_count</em></td>
<td>Channel switch time to send ECSA ie, unit is 110ms.</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>band_width</em></td>
<td>Channel width switch to(optional), only for 5G channels. Depends on the hardware capabilities, when the hardware does not support, it can automatically downgrade. Redfinch support 20M. 0 – 20MHZ, 1 – 40M above, 3 – 40M below, 4 – 80M, 5 – 160M</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610


---

##### int wlan_uap_set_hidden_ssid (const t_u8 *hidden_ssid*)

API to control SSID broadcast capability of the uAP

This API enables/disables the SSID broadcast feature (also known as the hidden SSID feature). When broadcast SSID is enabled, the AP responds to probe requests from client stations that contain null SSID. When broadcast SSID is disabled, the AP does not respond to probe requests that contain null SSID and generates beacons that contain null SSID.


**Parameters**


  ----------------------- ----------------------- --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  in                      *hidden_ssid*           Hidden SSID control hidden_ssid=0: broadcast SSID in beacons. hidden_ssid=1: send empty SSID (length=0) in beacon. hidden_ssid=2: clear SSID (ACSII 0), but keep the original length

  ----------------------- ----------------------- --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

-WM_FAIL if command fails.


**Note**


Call this API before calling uAP start API.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### void wlan_uap_set_htcapinfo (const uint16_t *ht_cap_info*)

API to set the HT capability information of the uAP.


**Parameters**


+-----------------------+-----------------------+-----------------------------------------------------+
| in                    | *ht_cap_info*         | \- This is a bitmap and should be used as following |
|                       |                       |                                                     |
|                       |                       | Bit 15: L Sig TxOP protection - reserved, set to 0  |
|                       |                       |                                                     |
|                       |                       | Bit 14: 40 MHz intolerant - reserved, set to 0      |
|                       |                       |                                                     |
|                       |                       | Bit 13: PSMP - reserved, set to 0                   |
|                       |                       |                                                     |
|                       |                       | Bit 12: DSSS Cck40MHz mode                          |
|                       |                       |                                                     |
|                       |                       | Bit 11: Maximal A-MSDU size - reserved, set to 0    |
|                       |                       |                                                     |
|                       |                       | Bit 10: Delayed BA - reserved, set to 0             |
|                       |                       |                                                     |
|                       |                       | Bits 9:8: RX STBC - reserved, set to 0              |
|                       |                       |                                                     |
|                       |                       | Bit 7: TX STBC - reserved, set to 0                 |
|                       |                       |                                                     |
|                       |                       | Bit 6: Short GI 40 MHz                              |
|                       |                       |                                                     |
|                       |                       | Bit 5: Short GI 20 MHz                              |
|                       |                       |                                                     |
|                       |                       | Bit 4: GF preamble                                  |
|                       |                       |                                                     |
|                       |                       | Bits 3:2: MIMO power save - reserved, set to 0      |
|                       |                       |                                                     |
|                       |                       | Bit 1: SuppChanWidth - set to 0 for 2.4 GHz band    |
|                       |                       |                                                     |
|                       |                       | Bit 0: LDPC coding - reserved, set to 0             |
+-----------------------+-----------------------+-----------------------------------------------------+


**Note**


Call this API before calling uAP start API.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### void wlan_uap_set_httxcfg (unsigned short *httxcfg*)

This API can be used to configure various 802.11n specific configuration for transmit (such as short GI, channel bandwidth and green field support) for uAP interface.


**Parameters**


+-----------------------+-----------------------+------------------------------------------------------------------------+
| in                    | *httxcfg*             | This is a bitmap and should be used as following                       |
|                       |                       |                                                                        |
|                       |                       | Bit 15-8: Reserved set to 0                                            |
|                       |                       |                                                                        |
|                       |                       | Bit 7: STBC Enable/Disable                                             |
|                       |                       |                                                                        |
|                       |                       | Bit 6: Short GI in 40 Mhz Enable/Disable                               |
|                       |                       |                                                                        |
|                       |                       | Bit 5: Short GI in 20 Mhz Enable/Disable                               |
|                       |                       |                                                                        |
|                       |                       | Bit 4: Green field Enable/Disable                                      |
|                       |                       |                                                                        |
|                       |                       | Bit 3-2: Reserved set to 1                                             |
|                       |                       |                                                                        |
|                       |                       | Bit 1: 20/40 Mhz enable disable.                                       |
|                       |                       |                                                                        |
|                       |                       | Bit 0: LDPC Enable/Disable                                             |
|                       |                       |                                                                        |
|                       |                       | When Bit 1 is set then firmware could transmit in 20Mhz or 40Mhz based |
|                       |                       |                                                                        |
|                       |                       | on rate adaptation. When this bit is reset then firmware can only      |
|                       |                       |                                                                        |
|                       |                       | transmit in 20Mhz.                                                     |
+-----------------------+-----------------------+------------------------------------------------------------------------+


**Note**


Call this API before calling uAP start API.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### void wlan_uap_set_scan_chan_list (wifi_scan_chan_list_t *scan_chan_list*)

Set number of channels and channel number used during automatic channel selection of the uAP.


**Parameters**


  ----------------------- ----------------------- -----------------------------------------------------------------
  in                      *scan_chan_list*        A structure holding the number of channels and channel numbers.

  ----------------------- ----------------------- -----------------------------------------------------------------


**Note**


Call this API before uAP start API in order to set the user defined channels, otherwise it can have no effect. There is no need to call this API every time before uAP start, if once set same channel configuration can get used in all upcoming uAP start call. If user wish to change the channels at run time then it make sense to call this API before every uAP start API.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---


#### Power Management

| Function | Supported SoCs |
|----------|---------------|
| `wlan_configure_delay_to_ps` | All |
| `wlan_configure_idle_time` | All |
| `wlan_configure_listen_interval` | All |
| `wlan_configure_null_pkt_interval` | All |
| `wlan_deepsleepps_off` | All |
| `wlan_deepsleepps_on` | All |
| `wlan_get_delay_to_ps` | All |
| `wlan_get_idle_time` | All |
| `wlan_get_listen_interval` | All |
| `wlan_get_ps_mode` | All |
| `wlan_get_ps_mode_cfg` | All |
| `wlan_ieeeps_off` | All |
| `wlan_ieeeps_on` | All |
| `wlan_is_power_save_enabled` | All |
| `wlan_set_ieeeps_cfg` | All |
| `wlan_set_ips` | RW610 |
| `wlan_set_ps_cfg` | All |
| `wlan_sleep_period` | RW610 |

##### void wlan_configure_delay_to_ps (unsigned int *timeout_ms*)

Set timeout configuration before Wi-Fi power save mode.


**Parameters**


  ----------------------- ----------------------- -------------------------------
  in                      *timeout_ms*            timout time, in milliseconds.

  ----------------------- ----------------------- -------------------------------

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### void wlan_configure_idle_time (unsigned int *timeout_ms*)

Set timeout value before Wi-Fi enter deep sleep mode.

param \[in\] timeout_ms: timout time, in milliseconds.


**Note**


The minimum value of timeout_ms is 10.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### void wlan_configure_listen_interval (int *listen_interval*)

Configure listening interval of IEEE power save mode.


**Note**


**Delivery traffic indication message (DTIM)** : It is a concept in 802.11 It is a time duration after which AP can send out buffered BROADCAST / MULTICAST data and stations connected to the AP should wakeup to take this broadcast / multicast data.

**Traffic Indication Map (TIM)** : It is a bitmap which the AP sends with each beacon. The bitmap has one bit each for a station connected to AP.

Each station is recognized by an association ID (AID). If AP has buffered data for a station, it will set corresponding bit of bitmap in TIM based on AID. Ideally AP does not buffer any unicast data it just sends unicast data to the station on every beacon when station is not sleeping.

When broadcast data / multicast data is to be send AP sets bit 0 of TIM indicating broadcast / multicast.

The occurrence of DTIM is defined by AP.

Each beacon has a number indicating period at which DTIM occurs.

The number is expressed in terms of number of beacons.

This period is called DTIM Period / DTIM interval.

For example:

If AP has DTIM period = 3 the stations connected to AP have to wake up (if they are sleeping) to receive broadcast /multicast data on every third beacon.

Generic:

When DTIM period is X AP buffers broadcast data / multicast data for X beacons. Then it transmits the data no matter whether station is awake or not.

Listen interval:

This is time interval on station side which indicates when station can be awake to listen i.e. accept data.

Long listen interval:

It comes into picture when station sleeps (IEEE PS) and it does not want to wake up on every DTIM So station is not worried about broadcast data/multicast data in this case.

This should be a design decision what should be chosen Firmware suggests values which are about 3 times DTIM at the max to gain optimal usage and reliability.

In the IEEE power save mode, the Wi-Fi firmware goes to sleep and periodically wakes up to check if the AP has any pending packets for it. A longer listen interval implies that the Wi-Fi SoC stays in power save for a longer duration at the cost of additional delays while receiving data. Note that choosing incorrect value for listen interval causes poor response from device during data transfer. Actual listen interval selected by firmware is equal to closest DTIM.

For example:

AP beacon period : 100 ms

AP DTIM period : 2

Application request value: 500ms

Actual listen interval = 400ms (This is the closest DTIM). Actual listen interval set should be a multiple of DTIM closest to but lower than the value provided by the application.

This API can be called before/after association. The configured listen interval can be used in subsequent association attempt.


**Parameters**


+-----------------------+-----------------------+----------------------------------+
| in                    | *listen_interval*     | Listen interval as below         |
|                       |                       |                                  |
|                       |                       | 0 : Unchanged,                   |
|                       |                       |                                  |
|                       |                       | -1 : Disable,                    |
|                       |                       |                                  |
|                       |                       | 1-49: Value in beacon intervals, |
|                       |                       |                                  |
|                       |                       | \>= 50: Value in TUs             |
+-----------------------+-----------------------+----------------------------------+

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### void wlan_configure_null_pkt_interval (int *time_in_secs*)

Configure NULL packet interval of IEEE power save mode.


**Note**


In IEEE PS (power save), station sends a NULL packet to AP to indicate that the station is alive and maintain connection with the AP. If null packet is not sent some APs may disconnect station which might lead to a loss of connectivity. The time is specified in seconds. Default value is 30 seconds.

This API should be called before configuring IEEE Power save.


**Parameters**


  ----------------------- ----------------------- ---------------------------------------------------------------------------------------------------------------
  in                      *time_in_secs*          -1 Disables null packet transmission, 0 Null packet interval is unchanged, n Null packet interval in seconds.

  ----------------------- ----------------------- ---------------------------------------------------------------------------------------------------------------

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_deepsleepps_off (void )

Turn off deep sleep power save mode.


**Note**


deep sleep power save mode only applies when STA disconnected. It could be enabled/disabled when STA connected or disconnected, but only take effect when STA disconnected.


**Returns**


WM_SUCCESS if the call was successful.

-WM_FAIL otherwise.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_deepsleepps_on (void )

Turn on deep sleep power save mode.


**Note**


deep sleep power save mode only applies when STA disconnected. It could be enabled/disabled when STA connected or disconnected, but only take effect when STA disconnected.


**Returns**


WM_SUCCESS if the call was successful.

-WM_FAIL otherwise.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### unsigned int wlan_get_delay_to_ps (void )

Get delay time for Wi-Fi power save mode.


**Returns**


delay time value.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### unsigned int wlan_get_idle_time (void )

Get timeout value of deep sleep mode, in milliseconds.


**Returns**


idle time value.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### unsigned short wlan_get_listen_interval (void )

Get listen interval .


**Returns**


listen interval value.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_get_ps_mode (enum wlan_ps_mode \* *ps_mode*)

Get station interface power save mode.


**Parameters**


  ----------------------- ----------------------- ------------------------------------------------------------------------------------------------------------------
  out                     *ps_mode*               A pointer to wlan_ps_mode where station interface power save mode should be stored.

  ----------------------- ----------------------- ------------------------------------------------------------------------------------------------------------------


**Returns**


WM_SUCCESS if successful.

-WM_E_INVAL if *ps_mode* was NULL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_get_ps_mode_cfg (uint8_t \* *ps_mode_cfg*)

Get station interface power save configuration.


**Parameters**


  ----------------------- ----------------------- ------------------------------------------------------------------
  out                     *ps_mode_cfg*           A pointer to variable that stores power save mode configuration.

  ----------------------- ----------------------- ------------------------------------------------------------------


**Returns**


WM_SUCCESS if successful.

-WM_E_INVAL if *ps_mode_cfg* was NULL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_ieeeps_off (void )

Turn off IEEE power save mode.


**Note**


IEEE power save mode applies only when STA has connected to an AP. It could be enabled/disabled when STA connected or disconnected, but only take effect when STA has connected to an AP.


**Returns**


WM_SUCCESS if the call was successful.

-WM_FAIL otherwise.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_ieeeps_on (unsigned int *wakeup_conditions*)

Enable IEEE power save with host sleep configuration

When enabled, Wi-Fi SoC is opportunistically put into IEEE power save mode. Before putting the Wi-Fi SoC in power save this also sets the host sleep configuration on the SoC as specified. This makes the SoC generate a wakeup for the processor if any of the wakeup conditions are met.


**Parameters**


  ----------------------- ----------------------- ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  in                      *wakeup_conditions*     conditions to wake the host. This should be a logical OR of the conditions in wlan_wakeup_event_t. Typically devices would want to wake up on WAKE_ON_ALL_BROADCAST, WAKE_ON_UNICAST, WAKE_ON_MAC_EVENT. WAKE_ON_MULTICAST, WAKE_ON_ARP_BROADCAST, WAKE_ON_MGMT_FRAME

  ----------------------- ----------------------- ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


**Note**


IEEE power save mode applies only when STA has connected to an AP. It could be enabled/disabled when STA connected or disconnected, but only take effect when STA has connected to an AP.


**Returns**


WM_SUCCESS if the call was successful.

-WM_FAIL otherwise.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### bool wlan_is_power_save_enabled (void )

Check whether Wi-Fi power save is enabled or not.


**Returns**


TRUE if Wi-Fi power save is enabled, else return FALSE.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_set_ieeeps_cfg (struct wlan_ieeeps_config \* *ps_cfg*)

Set configuration parameters of IEEE power save mode.


**Parameters**


  ----------------------- ----------------------- --------------------------------------------------------
  in                      *ps_cfg*                Power save configuration includes multiple parameters.

  ----------------------- ----------------------- --------------------------------------------------------


**Returns**


WM_SUCCESS if the call was successful.

-WM_FAIL if failed.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_set_ips (int *option*)

Config IEEE power save mode (IPS). If the option is 1, the IPS
hardware listens to beacon frames after Wi-Fi CPU enters power save
mode. When there is work needed to done by Wi-Fi CPU, Wi-Fi CPU can be
woken up by ips hardware.

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>option</em></td>
<td>0/1 disable/enable ips</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610


---

##### void wlan_set_ps_cfg (t_u16 *multiple_dtims*, t_u16 *bcn_miss_timeout*, t_u16 *local_listen_interval*, t_u16 *adhoc_wake_period*, t_u16 *mode*, t_u16 *delay_to_ps*)

Set multiple dtim for next wakeup RX beacon time


**Parameters**


  ----------------------- ------------------------- ----------------------------------------------------------------------------------------------------------
  in                      *multiple_dtims*          num dtims, range \[1,20\]

  in                      *bcn_miss_timeout*        becaon miss interval

  in                      *local_listen_interval*   local listen interval

  in                      *adhoc_wake_period*       adhoc awake period

  in                      *mode*                    mode - (0x01 - firmware to automatically choose PS_POLL or NULL mode, 0x02 - PS_POLL, 0x03 - NULL mode )

  in                      *delay_to_ps*             Delay to PS in milliseconds
  ----------------------- ------------------------- ----------------------------------------------------------------------------------------------------------

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_sleep_period (unsigned int \* *sleep_period*, t_u8 *action*)

Set/get UAPSD sleep period in the Wi-Fi firmware.

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in,out</td>
<td><em>sleep_period</em></td>
<td>UAPSD sleep period. Unit is ms.</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>action</em></td>
<td>Set/get action.</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if the call was successful.

\-WM_FAIL if failed.

##### t_u8 wlan_is_wmm_uapsd_enabled (void )

Check whether UAPSD is enabled or not.

###### Returns

true if UAPSD is enabled.

false if UAPSD is disabled.

> **Supported SoCs:** RW610


---


#### Host Sleep

| Function | Supported SoCs |
|----------|---------------|
| `wlan_cancel_host_sleep` | All |
| `wlan_clear_host_sleep_config` | All |
| `wlan_config_host_sleep` | All |
| `wlan_get_wakeup_reason` | All |
| `wlan_hs_post_cfg` | All |
| `wlan_hs_pre_cfg` | All |
| `wlan_hs_send_event` | IW416, W8987, IW610, IW612 |

##### void wlan_cancel_host_sleep (void )

Cancel host sleep. This function is called to cancel the host sleep in the firmware.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### void wlan_clear_host_sleep_config (void )

Clear host sleep configurations in driver. This function clears all the host sleep related configures in driver.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### void wlan_config_host_sleep (bool *is_manual*, t_u8 *is_periodic*)

Host sleep configuration. This function may be called to configure host sleep in firmware.


**Parameters**


  ----------------------- ----------------------- --------------------------------------------------------------------------------
  in                      *is_manual*             Flag to indicate host enter low power mode with power manager or by command.

  in                      *is_periodic*           Flag to indicate host enter low power periodically or once with power manager.
  ----------------------- ----------------------- --------------------------------------------------------------------------------

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_get_wakeup_reason (uint16_t \* *hs_wakeup_reason*)

Use this API to get host sleep wakeup reason from Wi-Fi firmware after waking up from host sleep by Wi-Fi.


**Parameters**


  ----------------------------------- -----------------------------------
  out                                 *hs_wakeup_reason*

  ----------------------------------- -----------------------------------

1\. Non-maskable event matched 6: Non-maskable condition matched (EAPoL rekey) 7: Magic pattern matched Others: reserved. (set to 0)

  -----------------------------------------------------------------------

  -----------------------------------------------------------------------


**Returns**


WM_SUCCESS if operation is successful.

-WM_FAIL if command fails.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### void wlan_hs_post_cfg (void )

Use this API to get and print the reason of waking up from host sleep

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### void wlan_hs_pre_cfg (void )

Use this API to set configuration before going to host sleep

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### status_t wlan_hs_send_event (int *id*, void \* *data*)

This function sends host sleep events to mon_thread


**Parameters**


  ----------------------- ----------------------- -----------------------
  in                      *id*                    Event ID.

  in                      *data*                  Pointer to event msg.
  ----------------------- ----------------------- -----------------------


**Returns**


kStatus_Success if successful else return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, IW610, IW612


---


#### TX Power & Rate Control

| Function | Supported SoCs |
|----------|---------------|
| `wlan_get_data_rate` | All |
| `wlan_get_sta_tx_power` | All |
| `wlan_get_txpwrlimit` | All |
| `wlan_get_txratecfg` | All |
| `wlan_set_frag` | RW610 |
| `wlan_set_htcapinfo` | All |
| `wlan_set_httxcfg` | All |
| `wlan_set_region_power_cfg` | RW610 |
| `wlan_set_rg_power_cfg` | RW610 |
| `wlan_set_rts` | RW610 |
| `wlan_set_ru_power_cfg` | RW610 |
| `wlan_set_sta_tx_power` | All |
| `wlan_set_txpwrlimit` | All |
| `wlan_set_txratecfg` | All |
| `wlan_set_txrx_histogram` | All |
| `wlan_set_uap_frag` | RW610 |
| `wlan_set_uap_rts` | RW610 |
| `wlan_set_wwsm_txpwrlimit` | All |

##### int wlan_get_data_rate (wlan_ds_rate \* *ds_rate*, mlan_bss_type *bss_type*)

Use this API to get the current TX and RX rates along with bandwidth and guard interval information if rate is 802.11n.


**Parameters**


  ----------------------- ----------------------- ---------------------------------------------------------------------------------------------------------------
  in                      *ds_rate*               A pointer to structure which has tx, RX rate information along with bandwidth and guard interval information.

  in                      *bss_type*              0: STA, 1: uAP
  ----------------------- ----------------------- ---------------------------------------------------------------------------------------------------------------


**Note**


If rate is greater than 11 then it is 802.11n rate and from 12 MCS0 rate starts. The bandwidth mapping is like value 0 is for 20MHz, 1 is 40MHz, 2 is for 80MHz. The guard interval value zero means Long otherwise Short.


**Returns**


WM_SUCCESS if operation is successful.

-WM_FAIL if command fails.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_get_sta_tx_power (t_u32 \* *power_level*)

Get station transmit power


**Parameters**


  ----------------------- ----------------------- -----------------------------------
  out                     *power_level*           Transmit power level (unit: dBm).

  ----------------------- ----------------------- -----------------------------------


**Returns**


WM_SUCCESS if successful.

-WM_FAIL if unsuccessful.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_get_txpwrlimit (wifi_SubBand_t *subband*, wifi_txpwrlimit_t \* *txpwrlimit*)

Get the TRPC (transient receptor potential canonical) channel configuration.


**Parameters**


+-----------------------+-----------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------+
| in                    | *subband*             | Where subband is:                                                                                                                                     |
|                       |                       |                                                                                                                                                       |
|                       |                       | 0x00 2G subband (2.4G: channel 1-14)                                                                                                                  |
|                       |                       |                                                                                                                                                       |
|                       |                       | 0x10 5G subband0 (5G: channel 36,40,44,48,                                                                                                            |
|                       |                       |                                                                                                                                                       |
|                       |                       | 52,56,60,64)                                                                                                                                          |
|                       |                       |                                                                                                                                                       |
|                       |                       | 0x11 5G subband1 (5G: channel 100,104,108,112,                                                                                                        |
|                       |                       |                                                                                                                                                       |
|                       |                       | 116,120,124,128,                                                                                                                                      |
|                       |                       |                                                                                                                                                       |
|                       |                       | 132,136,140,144)                                                                                                                                      |
|                       |                       |                                                                                                                                                       |
|                       |                       | 0x12 5G subband2 (5G: channel 149,153,157,161,165,172)                                                                                                |
|                       |                       |                                                                                                                                                       |
|                       |                       | 0x13 5G subband3 (5G: channel 183,184,185,187,188,                                                                                                    |
|                       |                       |                                                                                                                                                       |
|                       |                       | 189, 192,196;                                                                                                                                         |
|                       |                       |                                                                                                                                                       |
|                       |                       | 5G: channel 7,8,11,12,16,34)                                                                                                                          |
+-----------------------+-----------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------+
| out                   | *txpwrlimit*          | A pointer to wlan_txpwrlimit_t TX power Limit configuration structure where Wi-Fi firmware configuration can get copied. |
+-----------------------+-----------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------+


**Returns**


WM_SUCCESS on success, error otherwise.


**Note**


application can use print_txpwrlimit API to print the content of the txpwrlimit structure.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_get_txratecfg (wlan_ds_rate \* *ds_rate*, mlan_bss_type *bss_type*)

Use this API to get the transmit data rate.


**Parameters**


  ----------------------- ----------------------- ---------------------------------------------------------------------------------------------------
  in                      *ds_rate*               A pointer to wlan_ds_rate where TX Rate configuration can be stored.

  in                      *bss_type*              0: STA, 1: uAP
  ----------------------- ----------------------- ---------------------------------------------------------------------------------------------------


**Returns**


WM_SUCCESS if successful.

-WM_FAIL if unsuccessful.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_set_frag (int *frag*)

Set the fragment threshold of STA in Wi-Fi firmware. If the size of
packet exceeds the fragment threshold, the packet is divided into
fragments. For example, if the fragment threshold is set to 300, a
ping packet of size 1300 is divided into 5 fragments.

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>frag</em></td>
<td>The value of fragment threshold configuration.</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610


---

##### int wlan_set_htcapinfo (unsigned int *htcapinfo*)

Use this API to configure some of parameters in HT capability information IE (such as short GI, channel bandwidth, and green field support)


**Parameters**


+-----------------------+-----------------------+-----------------------------------------------------------+
| in                    | *htcapinfo*           | This is a bitmap and should be used as following          |
|                       |                       |                                                           |
|                       |                       | Bit 29: Green field Enable/Disable                        |
|                       |                       |                                                           |
|                       |                       | Bit 26: RX STBC Support Enable/Disable. (As we support    |
|                       |                       |                                                           |
|                       |                       | single spatial stream only 1 bit is used for RX STBC)     |
|                       |                       |                                                           |
|                       |                       | Bit 25: TX STBC support Enable/Disable.                   |
|                       |                       |                                                           |
|                       |                       | Bit 24: Short GI in 40 Mhz Enable/Disable                 |
|                       |                       |                                                           |
|                       |                       | Bit 23: Short GI in 20 Mhz Enable/Disable                 |
|                       |                       |                                                           |
|                       |                       | Bit 22: RX LDPC Enable/Disable                            |
|                       |                       |                                                           |
|                       |                       | Bit 17: 20/40 Mhz enable disable.                         |
|                       |                       |                                                           |
|                       |                       | Bit 8: Enable/Disable 40Mhz intolerant bit in HT capinfo. |
|                       |                       |                                                           |
|                       |                       | 0 can reset this bit and 1 can set this bit in            |
|                       |                       |                                                           |
|                       |                       | htcapinfo attached in association request.                |
|                       |                       |                                                           |
|                       |                       | All others are reserved and should be set to 0.           |
+-----------------------+-----------------------+-----------------------------------------------------------+


**Returns**


WM_SUCCESS if successful.

-WM_FAIL if unsuccessful.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_set_httxcfg (unsigned short *httxcfg*)

Use this API to configure various 802.11n specific configuration for transmit (such as short GI, channel bandwidth and green field support)


**Parameters**


+-----------------------+-----------------------+------------------------------------------------------------------------+
| in                    | *httxcfg*             | This is a bitmap and should be used as following                       |
|                       |                       |                                                                        |
|                       |                       | Bit 15-10: Reserved set to 0                                           |
|                       |                       |                                                                        |
|                       |                       | Bit 9-8: RX STBC set to 0x01                                           |
|                       |                       |                                                                        |
|                       |                       | BIT9 BIT8 Description                                                  |
|                       |                       |                                                                        |
|                       |                       | 0 0 No spatial streams                                                 |
|                       |                       |                                                                        |
|                       |                       | 0 1 One spatial stream supported                                       |
|                       |                       |                                                                        |
|                       |                       | 1 0 Reserved                                                           |
|                       |                       |                                                                        |
|                       |                       | 1 1 Reserved                                                           |
|                       |                       |                                                                        |
|                       |                       | Bit 7: STBC Enable/Disable                                             |
|                       |                       |                                                                        |
|                       |                       | Bit 6: Short GI in 40 Mhz Enable/Disable                               |
|                       |                       |                                                                        |
|                       |                       | Bit 5: Short GI in 20 Mhz Enable/Disable                               |
|                       |                       |                                                                        |
|                       |                       | Bit 4: Green field Enable/Disable                                      |
|                       |                       |                                                                        |
|                       |                       | Bit 3-2: Reserved set to 1                                             |
|                       |                       |                                                                        |
|                       |                       | Bit 1: 20/40 Mhz enable disable.                                       |
|                       |                       |                                                                        |
|                       |                       | Bit 0: LDPC Enable/Disable                                             |
|                       |                       |                                                                        |
|                       |                       | When Bit 1 is set then firmware could transmit in 20Mhz or 40Mhz based |
|                       |                       |                                                                        |
|                       |                       | on rate adaptation. When this bit is reset then firmware can only      |
|                       |                       |                                                                        |
|                       |                       | transmit in 20Mhz.                                                     |
+-----------------------+-----------------------+------------------------------------------------------------------------+


**Returns**


WM_SUCCESS if successful.

-WM_FAIL if unsuccessful.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_set_region_power_cfg (const t_u8 \* *data*, t_u16 *len*)

Set the compressed (use LZW algorithm) TX power limit configuration.

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>data</em></td>
<td>A pointer to TX power limit configuration.</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>len</em></td>
<td>Length of TX power limit configuration.</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS on success, error otherwise.

> **Supported SoCs:** RW610


---

##### int wlan_set_rg_power_cfg (t_u16 *region_code*)

Set TX power table according to region code

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>region_code</em></td>
<td>region code</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610


---

##### int wlan_set_rts (int *rts*)

Set the RTS(Request to Send) threshold of STA in Wi-Fi firmware.

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>rts</em></td>
<td>the value of rts threshold configuration.</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610


---

##### int wlan_set_ru_power_cfg (t_u16 *region_code*)

set ru tx power table

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>region_code</em></td>
<td>region code</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if successful otherwise failure.

> **Supported SoCs:** RW610


---

##### int wlan_set_sta_tx_power (t_u32 *power_level*)

Set station transmit power


**Parameters**


  ----------------------- ----------------------- -----------------------------------
  in                      *power_level*           Transmit power level (unit: dBm).

  ----------------------- ----------------------- -----------------------------------


**Returns**


WM_SUCCESS if successful.

-WM_FAIL if unsuccessful.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_set_txpwrlimit (wlan_txpwrlimit_t \* *txpwrlimit*)

Set the TRPC (transient receptor potential canonical) channel configuration.


**Parameters**


  ----------------------- ----------------------- -------------------------------------------------------------------------------------------
  in                      *txpwrlimit*            A pointer to wlan_txpwrlimit_t TX power limit configuration.

  ----------------------- ----------------------- -------------------------------------------------------------------------------------------


**Returns**


WM_SUCCESS on success, error otherwise.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_set_txratecfg (wlan_ds_rate *ds_rate*, mlan_bss_type *bss_type*)

Use this API to set the transmit data rate.


**Note**


The data rate can be set only after association.


**Parameters**


+-----------------------+-----------------------+---------------------------------------------------------------------------------------------------------------------------+
| in                    | *ds_rate*             | struct contains following fields sub_command It should be WIFI_DS_RATE_CFG and rate_cfg should have following parameters. |
|                       |                       |                                                                                                                           |
|                       |                       | rate_format - This parameter specifies the data rate format used in this command                                          |
|                       |                       |                                                                                                                           |
|                       |                       | 0: LG                                                                                                                     |
|                       |                       |                                                                                                                           |
|                       |                       | 1: HT                                                                                                                     |
|                       |                       |                                                                                                                           |
|                       |                       | 2: VHT                                                                                                                    |
|                       |                       |                                                                                                                           |
|                       |                       | 0xff: Auto                                                                                                                |
|                       |                       |                                                                                                                           |
|                       |                       | index - This parameter specifies the rate or MCS index                                                                    |
|                       |                       |                                                                                                                           |
|                       |                       | If rate_format is 0 (LG),                                                                                                 |
|                       |                       |                                                                                                                           |
|                       |                       | 0 1 Mbps                                                                                                                  |
|                       |                       |                                                                                                                           |
|                       |                       | 1 2 Mbps                                                                                                                  |
|                       |                       |                                                                                                                           |
|                       |                       | 2 5.5 Mbps                                                                                                                |
|                       |                       |                                                                                                                           |
|                       |                       | 3 11 Mbps                                                                                                                 |
|                       |                       |                                                                                                                           |
|                       |                       | 4 6 Mbps                                                                                                                  |
|                       |                       |                                                                                                                           |
|                       |                       | 5 9 Mbps                                                                                                                  |
|                       |                       |                                                                                                                           |
|                       |                       | 6 12 Mbps                                                                                                                 |
|                       |                       |                                                                                                                           |
|                       |                       | 7 18 Mbps                                                                                                                 |
|                       |                       |                                                                                                                           |
|                       |                       | 8 24 Mbps                                                                                                                 |
|                       |                       |                                                                                                                           |
|                       |                       | 9 36 Mbps                                                                                                                 |
|                       |                       |                                                                                                                           |
|                       |                       | 10 48 Mbps                                                                                                                |
|                       |                       |                                                                                                                           |
|                       |                       | 11 54 Mbps                                                                                                                |
|                       |                       |                                                                                                                           |
|                       |                       | If rate_format is 1 (HT),                                                                                                 |
|                       |                       |                                                                                                                           |
|                       |                       | 0 MCS0                                                                                                                    |
|                       |                       |                                                                                                                           |
|                       |                       | 1 MCS1                                                                                                                    |
|                       |                       |                                                                                                                           |
|                       |                       | 2 MCS2                                                                                                                    |
|                       |                       |                                                                                                                           |
|                       |                       | 3 MCS3                                                                                                                    |
|                       |                       |                                                                                                                           |
|                       |                       | 4 MCS4                                                                                                                    |
|                       |                       |                                                                                                                           |
|                       |                       | 5 MCS5                                                                                                                    |
|                       |                       |                                                                                                                           |
|                       |                       | 6 MCS6                                                                                                                    |
|                       |                       |                                                                                                                           |
|                       |                       | 7 MCS7                                                                                                                    |
|                       |                       |                                                                                                                           |
|                       |                       | If STREAM_2X2                                                                                                             |
|                       |                       |                                                                                                                           |
|                       |                       | 8 MCS8                                                                                                                    |
|                       |                       |                                                                                                                           |
|                       |                       | 9 MCS9                                                                                                                    |
|                       |                       |                                                                                                                           |
|                       |                       | 10 MCS10                                                                                                                  |
|                       |                       |                                                                                                                           |
|                       |                       | 11 MCS11                                                                                                                  |
|                       |                       |                                                                                                                           |
|                       |                       | 12 MCS12                                                                                                                  |
|                       |                       |                                                                                                                           |
|                       |                       | 13 MCS13                                                                                                                  |
|                       |                       |                                                                                                                           |
|                       |                       | 14 MCS14                                                                                                                  |
|                       |                       |                                                                                                                           |
|                       |                       | 15 MCS15                                                                                                                  |
|                       |                       |                                                                                                                           |
|                       |                       | If rate_format is 2 (VHT),                                                                                                |
|                       |                       |                                                                                                                           |
|                       |                       | 0 MCS0                                                                                                                    |
|                       |                       |                                                                                                                           |
|                       |                       | 1 MCS1                                                                                                                    |
|                       |                       |                                                                                                                           |
|                       |                       | 2 MCS2                                                                                                                    |
|                       |                       |                                                                                                                           |
|                       |                       | 3 MCS3                                                                                                                    |
|                       |                       |                                                                                                                           |
|                       |                       | 4 MCS4                                                                                                                    |
|                       |                       |                                                                                                                           |
|                       |                       | 5 MCS5                                                                                                                    |
|                       |                       |                                                                                                                           |
|                       |                       | 6 MCS6                                                                                                                    |
|                       |                       |                                                                                                                           |
|                       |                       | 7 MCS7                                                                                                                    |
|                       |                       |                                                                                                                           |
|                       |                       | 8 MCS8                                                                                                                    |
|                       |                       |                                                                                                                           |
|                       |                       | 9 MCS9                                                                                                                    |
|                       |                       |                                                                                                                           |
|                       |                       | nss - This parameter specifies the NSS.                                                                                   |
|                       |                       |                                                                                                                           |
|                       |                       | It is valid only for VHT                                                                                                  |
|                       |                       |                                                                                                                           |
|                       |                       | If rate_format is 2 (VHT),                                                                                                |
|                       |                       |                                                                                                                           |
|                       |                       | 1 NSS1                                                                                                                    |
|                       |                       |                                                                                                                           |
|                       |                       | 2 NSS2                                                                                                                    |
+-----------------------+-----------------------+---------------------------------------------------------------------------------------------------------------------------+
| in                    | *bss_type*            | 0: STA, 1: uAP                                                                                                            |
+-----------------------+-----------------------+---------------------------------------------------------------------------------------------------------------------------+


**Returns**


WM_SUCCESS if successful.

-WM_FAIL if unsuccessful.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_set_txrx_histogram (int *bss_type*, struct wlan_txrx_histogram_info \* *txrx_histogram*, t_u8 \* *data*)

Set TX RX histogram config. This function can be called to set TX RX histogram config.


**Parameters**


  ----------------------- ----------------------- -----------------------------------------------------------------------------
  in                      *bss_type*              0: STA, 1: uAP

  in                      *txrx_histogram*        User configured parameters of TX RX histogram. including enable and action.

  out                     *data*                  TX RX histogram data from FW.
  ----------------------- ----------------------- -----------------------------------------------------------------------------


**Returns**


WM_SUCCESS if the call was successful.

-WM_FAIL if failed.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_set_uap_frag (int *frag*)

Set the fragment threshold of the uAP in Wi-Fi firmware. If the size
of packet exceeds the fragment threshold, the packet is divided into
fragments. For example, if the fragment threshold is set to 300, a
ping packet of size 1300 is divided into 5 fragments.

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>frag</em></td>
<td>the value of fragment threshold configuration.</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610


---

##### int wlan_set_uap_rts (int *rts*)

Set the RTS(Request to Send) threshold of the uAP in Wi-Fi firmware.

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>rts</em></td>
<td>the value of rts threshold configuration.</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610


---

##### int wlan_set_wwsm_txpwrlimit (void )

Set worldwide safe mode TX power limits. Set TX power limit and ru TX power limit according to the region code. TX power limit: rg_power_cfg_info ru TX power limit: ru_power_cfg_info


**Returns**


WM_SUCCESS if successful.

-WM_FAIL if unsuccessful.


**const char \* wlan_get_wlan_region_code (void )**


Get Wi-Fi region code from TX power config


**Returns**


Wi-Fi region code in string format.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---


#### Antenna Configuration

| Function | Supported SoCs |
|----------|---------------|
| `wlan_dual_ant_duty_cycle` | RW610 |
| `wlan_get_antcfg` | All |
| `wlan_set_antcfg` | All |
| `wlan_single_ant_duty_cycle` | RW610 |

##### int wlan_dual_ant_duty_cycle (t_u16 *enable*, t_u16 *nbTime*, t_u16 *wlanTime*, t_u16 *wlanBlockTime*)

Set dual antenna duty cycle.

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>enable</em></td>
<td><p>enable/disable single duty cycle</p>
<p>0: Disable</p>
<p>1: enable</p></td>
</tr>
<tr class="even">
<td>in</td>
<td><em>nbTime</em></td>
<td>time in units 1ms, no more than wlanTime</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>wlanTime</em></td>
<td>time in unit 1ms, total duty cycle time</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>wlanBlockTime</em></td>
<td>time in unit 1ms</td>
</tr>
</tbody>
</table>

###### Note

nbTime, wlanTime and wlanBlockTime should not equal to each other

###### Returns

WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610


---

##### int wlan_get_antcfg (uint32_t \* *ant*, uint16_t \* *evaluate_time*, uint16_t \* *current_antenna*)

This API can be used to get the mode of TX/RX antenna. If SAD (software antenna diversity) is enabled, this API can also be used to get SAD antenna evaluate time interval(antenna mode is antenna diversitywhen set SAD evaluate time interval).


**Parameters**


  ----------------------- ----------------------- --------------------------------------------------------------------------------------------------------------------------------------------
  out                     *ant*                   pointer to antenna variable. antenna variable: 1 : TX/RX antenna 1 2 : TX/RX antenna 2 0xFFFF: TX/RX antenna diversity

  out                     *evaluate_time*         pointer to evaluate_time variable for SAD.

  out                     *current_antenna*       pointer to current antenna. evaluate_mode: 0: PCB Ant + Ext Ant0 1: Ext Ant0 + Ext Ant1 2: PCB Ant + Ext Ant1 0xFF: Default divisity mode.
  ----------------------- ----------------------- --------------------------------------------------------------------------------------------------------------------------------------------


**Returns**


WM_SUCCESS if successful.

WLAN_ERROR_STATE if unsuccessful.


**char \* wlan_get_firmware_version_ext (void )**


Get the Wi-Fi firmware version extension string.


**Note**


This API does not allocate memory for pointer. It just returns pointer of WLCMGR internal static buffer. So no need to free the pointer by caller.


**Returns**


Wi-Fi firmware version extension string pointer stored in WLCMGR

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_set_antcfg (uint32_t *ant*, uint16_t *evaluate_time*)

This API can be used to set the mode of TX/RX antenna. If SAD (software antenna diversity) is enabled, this API can also be used to set SAD antenna evaluate time interval(antenna mode is antenna diversitywhen set SAD evaluate time interval).


**Parameters**


  ----------------------- ----------------------- ------------------------------------------------------------------------------------------------------------------------------------------------
  in                      *ant*                   Antenna valid values are 1, 2 and 0xFFFF 1 : TX/RX antenna 1 2 : TX/RX antenna 2 0xFFFF: TX/RX antenna diversity (Refer to hardware schematic)

  in                      *evaluate_time*         SAD evaluate time interval (unit: milliseconds), default value is 6s(0x1770).
  ----------------------- ----------------------- ------------------------------------------------------------------------------------------------------------------------------------------------


**Returns**


WM_SUCCESS if successful.

WLAN_ERROR_STATE if unsuccessful.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_single_ant_duty_cycle (t_u16 *enable*, t_u16 *nbTime*, t_u16 *wlanTime*)

Set single antenna: duty cycle.

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>enable</em></td>
<td><p>enable/disable single duty cycle</p>
<p>0: Disable</p>
<p>1: enable</p></td>
</tr>
<tr class="even">
<td>in</td>
<td><em>nbTime</em></td>
<td>time in unit 1ms, no more than wlanTime</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>wlanTime</em></td>
<td>time in unit 1ms, total duty cycle time</td>
</tr>
</tbody>
</table>

###### Note

wlanTime should not equal to wlanTime-nbTime

###### Returns

WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610


---


#### Channel & Band Configuration

| Function | Supported SoCs |
|----------|---------------|
| `wlan_get_bandcfg` | All |
| `wlan_get_chanlist` | All |
| `wlan_get_current_channel` | IW416, W8987, IW610, IW612 |
| `wlan_set_bandcfg` | All |
| `wlan_set_chanlist` | All |
| `wlan_set_chanlist_and_txpwrlimit` | All |
| `wlan_set_network_chanlist` | IW416, W8987, IW610, IW612 |
| `wlan_set_scan_channel_gap` | RW610 |

##### int wlan_get_bandcfg (wlan_bandcfg_t \* *bandcfg*)

Get band configuration.


**Parameters**


  ----------------------- ----------------------- -----------------------
  out                     *bandcfg*               band configuration

  ----------------------- ----------------------- -----------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_get_chanlist (wlan_chanlist_t \* *chanlist*)

Get the channel list configuration.


**Parameters**


  ----------------------- ----------------------- ----------------------------------------------------------
  out                     *chanlist*              A pointer to wlan_chanlist_t channel list configuration.

  ----------------------- ----------------------- ----------------------------------------------------------


**Returns**


WM_SUCCESS on success, error otherwise.


**Note**


The wlan_chanlist_t struct allocates memory for a maximum of 54. channels.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### uint8_t wlan_get_current_channel (void )

Use this API to get the channel number of associated BSS.


**Returns**


channel number if operation is successful.

0 if command fails.

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

##### int wlan_set_bandcfg (wlan_bandcfg_t \* *bandcfg*)

Set band configuration.


**Parameters**


  ----------------------- ----------------------- -----------------------
  in                      *bandcfg*               band configuration

  ----------------------- ----------------------- -----------------------


**Note**


11AC or 11AX only mode is not supported. Supported modes are:

legacy (B + G + A)

11N only

11N + 11AC

11N + 11AX

11N + 11AC + 11AX

B,G and A modes are enabled by default and are not configurable.


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_set_chanlist (wlan_chanlist_t \* *chanlist*)

Set the channel list configuration wlan_chanlist_t.


**Parameters**


  ----------------------- ----------------------- ---------------------------------------------------------------------------------------
  in                      *chanlist*              A pointer to wlan_chanlist_t channel list configuration.

  ----------------------- ----------------------- ---------------------------------------------------------------------------------------


**Returns**


WM_SUCCESS on success, error otherwise.


**Note**


If region enforcement flag is enabled in the OTP then this API should not take effect.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_set_chanlist_and_txpwrlimit (wlan_chanlist_t \* *chanlist*, wlan_txpwrlimit_t \* *txpwrlimit*)

Set the TRPC (transient receptor potential canonical) channel list and TX power limit configuration.


**Parameters**


  ----------------------- ----------------------- -------------------------------------------------------------------------------------------
  in                      *chanlist*              A poiner to wlan_chanlist_t channel List configuration.

  in                      *txpwrlimit*            A pointer to wlan_txpwrlimit_t TX power limit configuration.
  ----------------------- ----------------------- -------------------------------------------------------------------------------------------


**Returns**


WM_SUCCESS on success, error otherwise.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_set_network_chanlist (char \* *name*, const uint8_t \* *chan_list*, uint8_t *num_chans*, enum wlan_frequency_bands *freq_band*)

Set channel list for a network.

Note: when both `chan_list` and `freq_band` are provided, the channel list takes precedence. The frequency band parameter will be ignored.


**Parameters**


  ----------------------- ----------------------- -------------------------------------------------------------
  in                      *name*                  A pointer to a string representing the name of the network.

  in                      *chan_list*             A pointer to the channel list

  in                      *num_chans*             Number of channels in the channel list

  in                      *freq_band*             Frequency band for the channels (e.g., 2.4GHz, 5GHz)
  ----------------------- ----------------------- -------------------------------------------------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.


**Macro Documentation**


> **Supported SoCs:** IW416, W8987, IW610, IW612


---

##### void wlan_set_scan_channel_gap (unsigned *scan_chan_gap*)

Set scan channel gap.

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>scan_chan_gap</em></td>
<td>Time gap to be used between two consecutive channels scan.</td>
</tr>
</tbody>
</table>

> **Supported SoCs:** RW610


---


#### 802.11ax (Wi-Fi 6)

| Function | Supported SoCs |
|----------|---------------|
| `wlan_11ax_allowed` | RW610, IW610, IW612 |
| `wlan_enable_disable_htc` | RW610, IW610, IW612 |
| `wlan_get_11ax_rutxpowerlimit_legacy` | RW610, IW610, IW612 |
| `wlan_set_11ax_cfg` | RW610, IW610, IW612 |
| `wlan_set_11ax_rutxpowerlimit` | RW610, IW610, IW612 |
| `wlan_set_11ax_rutxpowerlimit_legacy` | RW610, IW610, IW612 |
| `wlan_set_11ax_tol_time` | RW610, IW610, IW612 |
| `wlan_set_11ax_tx_omi` | RW610, IW610, IW612 |

##### int wlan_11ax_allowed (struct wlan_network \* *network*)

Check if 802.11ax is allowed in capability.


**Parameters**


  ----------------------- ----------------------- ------------------------------------------------------------
  in                      *network*               A pointer to the wlan_network

  ----------------------- ----------------------- ------------------------------------------------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610, IW610, IW612


---

##### int wlan_enable_disable_htc (uint8_t *option*)

This function is used to enable/disable HTC (high throughput control).


**Parameters**


  ----------------------- ----------------------- -----------------------------
  in                      *option*                1 =\> Enable; 0 =\> Disable

  ----------------------- ----------------------- -----------------------------


**Returns**


WM_SUCCESS if operation is successful, otherwise return -WM_FAIL

> **Supported SoCs:** RW610, IW610, IW612


---

##### int wlan_get_11ax_rutxpowerlimit_legacy (wlan_rutxpwrlimit_t \* *ru_pwr_cfg*)

Use this API to get the RU TX power limit by channel based approach.


**Parameters**


  ----------------------- ----------------------- -------------------------------------------------------
  out                     *ru_pwr_cfg*            802.11ax rutxpwr of channels to be get from firmware.

  ----------------------- ----------------------- -------------------------------------------------------


**Returns**


WM_SUCCESS if operation is successful.

-WM_FAIL if command fails.

> **Supported SoCs:** RW610, IW610, IW612


---

##### int wlan_set_11ax_cfg (wlan_11ax_config_t \* *ax_config*)

Set 802.11ax configuration parameters


**Parameters**


  ----------------------- ----------------------- -----------------------------------------------------------
  in                      *ax_config*             802.11ax configuration parameters to be sent to firmware.

  ----------------------- ----------------------- -----------------------------------------------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.


**wlan_11ax_config_t \* wlan_get_11ax_cfg (void )**


Get default 802.11ax configuration parameters


**Returns**


802.11ax configuration parameters default array.

> **Supported SoCs:** RW610, IW610, IW612


---

##### int wlan_set_11ax_rutxpowerlimit (const void \* *rutx_pwr_cfg*, uint32_t *rutx_pwr_cfg_len*)

Use this API to set the RU TX power limit.


**Parameters**


  ----------------------- ----------------------- ----------------------------------------------------------------------------------------------
  in                      *rutx_pwr_cfg*          802.11ax rutxpwr of sub-bands to be sent to firmware. refer to rutxpowerlimit_cfg_set_WW\[\]

  in                      *rutx_pwr_cfg_len*      Size of rutx_pwr_cfg buffer.
  ----------------------- ----------------------- ----------------------------------------------------------------------------------------------


**Returns**


WM_SUCCESS if operation is successful.

-WM_FAIL if command fails.

> **Supported SoCs:** RW610, IW610, IW612


---

##### int wlan_set_11ax_rutxpowerlimit_legacy (const wlan_rutxpwrlimit_t \* *ru_pwr_cfg*)

Use this API to set the RU TX power limit by channel based approach.


**Parameters**


  ----------------------- ----------------------- ------------------------------------------------------
  in                      *ru_pwr_cfg*            802.11ax rutxpwr of channels to be sent to firmware.

  ----------------------- ----------------------- ------------------------------------------------------


**Returns**


WM_SUCCESS if operation is successful.

-WM_FAIL if command fails.

> **Supported SoCs:** RW610, IW610, IW612


---

##### int wlan_set_11ax_tol_time (const t_u32 *tol_time*)

Set 802.11ax OBSS (overlapping basic service set) narrow bandwidth RU (resource unit) tolerance time In uplink transmission, AP sends a trigger frame to all the stations that can be involved in the upcoming transmission, and then these stations transmit Trigger-based(TB) PPDU in response to the trigger frame. If STA connects to AP which channel is set to 100,STA doesn\'t support 26 tones RU. The API should be called when station is in disconnected state.


**Parameters**


  ----------------------- ----------------------- -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  in                      *tol_time*              Valid range \[1\...3600\] tolerance time is in unit of seconds. STA periodically check AP\'s beacon for ext cap bit79 (OBSS Narrow bandwidth RU in ofdma tolerance support) and set 20 tone RU tolerance time if ext cap bit79 is not set

  ----------------------- ----------------------- -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610, IW610, IW612


---

##### int wlan_set_11ax_tx_omi (const t_u8 *interface*, const t_u16 *tx_omi*, const t_u8 *tx_option*, const t_u8 *num_data_pkts*)

Use this API to set the set 802.11ax TX OMI (operating mode indication).


**Parameters**


  ----------------------- ----------------------- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  in                      *interface*             Interface type STA or uAP. 0: STA 1: uAP

  in                      *tx_omi*                value to be sent to firmware

  in                      *tx_option*             value to be sent to firmware 1: send OMI (operating mode indication) in QoS (quality of service) data.

  in                      *num_data_pkts*         value to be sent to firmware num_data_pkts is applied only if OMI is sent in QoS data frame. It specifies the number of consecutive data frames containing the OMI. Minimum value is 1 Maximum value is 16
  ----------------------- ----------------------- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


**Returns**


WM_SUCCESS if operation is successful.

-WM_FAIL if command fails.

> **Supported SoCs:** RW610, IW610, IW612


---


#### 802.11ac (Wi-Fi 5)

| Function | Supported SoCs |
|----------|---------------|
| `wlan_11ac_allowed` | W8987, RW610 |

##### int wlan_11ac_allowed (struct wlan_network \* *network*)

Check if 802.11ac is allowed in capability.

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>network</em></td>
<td>A pointer to the wlan_network</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** W8987, RW610


---


#### 802.11n (Wi-Fi 4)

| Function | Supported SoCs |
|----------|---------------|
| `wlan_11n_allowed` | All |

##### int wlan_11n_allowed (struct wlan_network \* *network*)

Check if 802.11n is allowed in capability.


**Parameters**


  ----------------------- ----------------------- ------------------------------------------------------------
  in                      *network*               A pointer to the wlan_network

  ----------------------- ----------------------- ------------------------------------------------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---


#### AMPDU & Aggregation

| Function | Supported SoCs |
|----------|---------------|
| `wlan_sta_ampdu_rx_disable` | All |
| `wlan_sta_ampdu_rx_enable` | All |
| `wlan_sta_ampdu_tx_disable` | All |
| `wlan_sta_ampdu_tx_enable` | All |
| `wlan_tx_ampdu_prot_mode` | RW610 |

##### void wlan_sta_ampdu_rx_disable (void )

This API can be used to disable AMPDU support when station is a receiver.


**Note**


By default the station AMPDU RX support is enabled if configuration option CONFIG_STA_AMPDU_RX is defined 1.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### void wlan_sta_ampdu_rx_enable (void )

This API can be used to enable AMPDU support when station is a receiver.


**Note**


By default the station AMPDU RX support is enabled if configuration option CONFIG_STA_AMPDU_RX is defined 1.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### void wlan_sta_ampdu_tx_disable (void )

This API can be used to disable AMPDU support when station is a transmitter.


**Note**


By default the station AMPDU TX support is enabled if configuration option CONFIG_STA_AMPDU_TX is defined 1.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### void wlan_sta_ampdu_tx_enable (void )

This API can be used to enable AMPDU support when station is a transmitter.


**Note**


By default the station AMPDU TX support is enabled if configuration option CONFIG_STA_AMPDU_TX is defined 1.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_tx_ampdu_prot_mode (tx_ampdu_prot_mode_para \* *prot_mode*, t_u16 *action*)

Set/Get TX AMPDU protect mode.

###### Parameters

<table>
<tbody>
<tr class="odd">
<td></td>
<td><em>[in/out]</em></td>
<td>prot_mode: TX AMPDU protect mode tx_ampdu_prot_mode_para</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>action</em></td>
<td>Command action 0: get TX AMPDU protect mode 1: set TX AMPDU protect mode</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610


---


#### WMM / QoS

| Function | Supported SoCs |
|----------|---------------|
| `wlan_set_wmm_uapsd` | RW610 |
| `wlan_wmm_uapsd_qosinfo` | RW610 |

##### int wlan_set_wmm_uapsd (t_u8 *uapsd_enable*)

Enable/Disable the UAPSD in the Wi-Fi firmware.

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>uapsd_enable</em></td>
<td>Enable/Disable UAPSD.</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if the call was successful.

\-WM_FAIL if failed.

> **Supported SoCs:** RW610


---

##### int wlan_wmm_uapsd_qosinfo (t_u8 \* *qos_info*, t_u8 *action*)

Set the QOS info of the UAPSD (unscheduled automatic power save
delivery) in the Wi-Fi firmware.

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in,out</td>
<td><em>qos_info</em></td>
<td>UAPSD (unscheduled automatic power save delivery) QOS info.</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>action</em></td>
<td>Set/get action.</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if the call was successful.

\-WM_FAIL if failed.

> **Supported SoCs:** RW610


---


#### Roaming (802.11k/r/v)

| Function | Supported SoCs |
|----------|---------------|
| `wlan_get_host_11k_status` | All |
| `wlan_get_roaming_status` | All |
| `wlan_host_11k_cfg` | All |
| `wlan_host_11k_neighbor_req` | All |
| `wlan_host_11v_bss_trans_query` | All |
| `wlan_set_roaming` | All |

##### bool wlan_get_host_11k_status (void )

Get enable/disable host 802.11k feature flag.


**Returns**


TRUE if 802.11k is enabled, return FALSE if 802.11k is disabled.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_get_roaming_status (void )

Get the roaming status.


**Returns**


1 if roaming is enabled.

0 if roaming is disbled.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_host_11k_cfg (int *enable_11k*)

Enable/Disable host 802.11k feature.


**Parameters**


  ----------------------- ----------------------- ----------------------------------------------------------------------------
  in                      *enable_11k*            the value of 802.11k configuration. 0: disable host 11k 1: enable host 11k

  ----------------------- ----------------------- ----------------------------------------------------------------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_host_11k_neighbor_req (const char \* *ssid*)

Host send neighbor report request.


**Parameters**


  ----------------------- ----------------------- ------------------------------
  in                      *ssid*                  The SSID for neighbor report

  ----------------------- ----------------------- ------------------------------


**Note**


ssid parameter is optional, pass NULL pointer to ignore SSID input if not specify SSID


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_host_11v_bss_trans_query (t_u8 *query_reason*)

Host send BSS transition management query. STA sends BTM (BSS transition management) query, and the AP supporting 11V will response BTM request, the AP will parse neighbor report in the BTM request and response the BTM response to AP to indicate the receive status.


**Parameters**


  ----------------------- ----------------------- -------------------------------------------------------------------------------------------------------------------------------------------------------------------
  in                      *query_reason*          \[0..16\] IEEE 802.11v BTM (BSS transition management) Query reasons. Refer to IEEE Std 802.11v-2011 - Table 7-43x-Transition and Transition Query reasons table.

  ----------------------- ----------------------- -------------------------------------------------------------------------------------------------------------------------------------------------------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_set_roaming (const int *enable*, const uint8_t *rssi_low_threshold*)

Set soft roaming config.

This function can be used to enable/disable soft roaming by specifying the RSSI threshold.


**Note**


**RSSI Threshold setting for soft roaming** : The provided RSSI low threshold value is used to subscribe RSSI low event from the firmware. On reception of this event, the background scan is started in the firmware with the same RSSI threshold to find out APs with a better signal strength than the RSSI threshold.

If an AP with better signal strength is found, the reassociation is triggered. Otherwise the background scan is started again until the scan count reaches BG_SCAN_LIMIT.

If still AP is not found then Wi-Fi connection manager sends WLAN_REASON_BGSCAN_NETWORK_NOT_FOUND event to application. In this case, if application again wants to use soft roaming then it can call this API again or use wlan_set_rssi_low_threshold API to set RSSI low threshold again.


**Parameters**


  ----------------------- ----------------------- --------------------------
  in                      *enable*                Enable/Disable roaming.

  in                      *rssi_low_threshold*    RSSI low threshold value
  ----------------------- ----------------------- --------------------------


**Returns**


WM_SUCCESS if the call was successful.

-WM_FAIL if failed.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---


#### TWT (Target Wake Time)

| Function | Supported SoCs |
|----------|---------------|
| `wlan_get_btwt_cfg` | RW610, IW610, IW612 |
| `wlan_get_twt_report` | RW610, IW610, IW612 |
| `wlan_set_btwt_cfg` | RW610, IW610, IW612 |
| `wlan_set_twt_setup_cfg` | RW610, IW610, IW612 |
| `wlan_set_twt_teardown_cfg` | RW610, IW610, IW612 |
| `wlan_twt_information` | RW610, IW610, IW612 |

##### int wlan_get_btwt_cfg (wlan_btwt_config_t \* *btwt_cfg*)

Get broadcast TWT (target wake time) configuration parameters


**Parameters**


  ----------------------- ----------------------- -------------------------------------------------------
  in                      *btwt_cfg*              Broadcast TWT Setup parameters to be sent to Firmware

  ----------------------- ----------------------- -------------------------------------------------------


**Returns**


WM_SUCCESS if successful otherwise failure.

> **Supported SoCs:** RW610, IW610, IW612


---

##### int wlan_get_twt_report (wlan_twt_report_t \* *twt_report*)

Get TWT report


**Parameters**


  ----------------------- ----------------------- -----------------------
  out                     *twt_report*            TWT report parameter.

  ----------------------- ----------------------- -----------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610, IW610, IW612


---

##### int wlan_set_btwt_cfg (wlan_btwt_config_t \* *btwt_cfg*)

Set broadcast TWT (target wake time) configuration parameters


**Parameters**


  ----------------------- ----------------------- -------------------------------------------------------
  in                      *btwt_cfg*              Broadcast TWT Setup parameters to be sent to Firmware

  ----------------------- ----------------------- -------------------------------------------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610, IW610, IW612


---

##### int wlan_set_twt_setup_cfg (const wlan_twt_setup_config_t \* *twt_setup*)

Set TWT setup configuration parameters


**Parameters**


  ----------------------- ----------------------- ----------------------------------------------
  in                      *twt_setup*             TWT setup parameters to be sent to firmware.

  ----------------------- ----------------------- ----------------------------------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.


**wlan_twt_setup_config_t \* wlan_get_twt_setup_cfg (void )**


Get TWT setup configuration parameters


**Returns**


TWT setup parameters default array.

> **Supported SoCs:** RW610, IW610, IW612


---

##### int wlan_set_twt_teardown_cfg (const wlan_twt_teardown_config_t \* *teardown_config*)

Set TWT teardown configuration parameters


**Parameters**


  ----------------------- ----------------------- -------------------------------------------
  in                      *teardown_config*       TWT teardown parameters sent to firmware.

  ----------------------- ----------------------- -------------------------------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.


**wlan_twt_teardown_config_t \* wlan_get_twt_teardown_cfg (void )**


Get TWT teardown configuration parameters


**Returns**


TWT Teardown parameters default array

> **Supported SoCs:** RW610, IW610, IW612


---

##### int wlan_twt_information (wlan_twt_information_t \* *twt_information*)

Twt information


**Parameters**


  ----------------------- ----------------------- -----------------------
  out                     *twt_information*       TWT information.

  ----------------------- ----------------------- -----------------------


**Returns**


WM_SUCCESS if successful otherwise failure.

> **Supported SoCs:** RW610, IW610, IW612


---


#### WPS

| Function | Supported SoCs |
|----------|---------------|
| `wlan_start_ap_wps_pbc` | RW610 |
| `wlan_start_ap_wps_pin` | RW610 |
| `wlan_start_wps_pbc` | All |
| `wlan_start_wps_pin` | All |
| `wlan_wps_ap_cancel` | RW610 |
| `wlan_wps_cancel` | All |
| `wlan_wps_generate_pin` | All |

##### int wlan_start_ap_wps_pbc (void )

Start WPS PBC session.

This function starts AP WPS PBC session.

###### Returns

WM_SUCCESS if successful

\-WM_FAIL if invalid pin entered.

> **Supported SoCs:** RW610


---

##### int wlan_start_ap_wps_pin (const char \* *pin*)

Start WPS pin session.

This function starts AP WPS pin session.

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>pin</em></td>
<td>Pin for WPS session.</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if the pin entered is valid.

\-WM_FAIL if invalid pin entered.

> **Supported SoCs:** RW610


---

##### int wlan_start_wps_pbc (const struct netif \* *netif*)

Start WPS PBC (push button configuration) session.

This function starts WPS PBC (push button configuration) session.


**Parameters**


  ----------------------- ----------------------- -----------------------------------------
  in                      *netif*                 Pointer to network interface structure.

  ----------------------- ----------------------- -----------------------------------------


**Returns**


WM_SUCCESS if successful

-WM_FAIL if invalid pin entered.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_start_wps_pin (const struct netif \* *netif*, const char \* *pin*)

Start WPS pin session.

This function starts WPS pin session.


**Parameters**


  ----------------------- ----------------------- -----------------------------------------
  in                      *netif*                 Pointer to network interface structure.

  in                      *pin*                   Pin for WPS session.
  ----------------------- ----------------------- -----------------------------------------


**Returns**


WM_SUCCESS if the pin entered is valid.

-WM_FAIL if invalid pin entered.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_wps_ap_cancel (void )

Cancel AP's WPS session.

This function cancels ongoing WPS session.

###### Returns

WM_SUCCESS if successful

\-WM_FAIL if invalid pin entered.

> **Supported SoCs:** RW610


---

##### int wlan_wps_cancel (void )

Cancel WPS session.

This function cancels ongoing WPS session.


**Returns**


WM_SUCCESS if successful

-WM_FAIL if invalid pin entered.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### void wlan_wps_generate_pin (uint32_t \* *pin*)

This function generate pin for WPS pin session.


**Parameters**


  ----------------------- ----------------------- ---------------------------------------
  in                      *pin*                   A pointer to WPS pin to be generated.

  ----------------------- ----------------------- ---------------------------------------

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---


#### DPP (Device Provisioning Protocol)

| Function | Supported SoCs |
|----------|---------------|
| `wlan_dpp_auth_init` | All |
| `wlan_dpp_bootstrap_gen` | All |
| `wlan_dpp_bootstrap_get_uri` | RW610 |
| `wlan_dpp_chirp` | All |
| `wlan_dpp_configurator_add` | All |
| `wlan_dpp_configurator_params` | All |
| `wlan_dpp_configurator_sign` | All |
| `wlan_dpp_listen` | All |
| `wlan_dpp_mud_url` | All |
| `wlan_dpp_pkex_add` | All |
| `wlan_dpp_qr_code` | All |
| `wlan_dpp_reconfig` | All |
| `wlan_dpp_stop_listen` | All |

##### int wlan_dpp_auth_init (int *is_ap*, const char \* *cmd*)

Send provisioning auth request to responder.

This function send Auth request to responder by qr-code-id.


**Parameters**


  ----------------------- ----------------------- ----------------------------------------------------------------
  in                      *is_ap*                 0 is STA, 1 is uAP.

  in                      *cmd*                   \" peer=\<qr-code-id\> conf=\<sta-dpp/ap-dpp/sta-psk\> \....\"
  ----------------------- ----------------------- ----------------------------------------------------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_dpp_bootstrap_gen (int *is_ap*, const char \* *cmd*)

Generate QR code.

This function generates QR code and return bootstrap-id


**Parameters**


  ----------------------- ----------------------- ------------------------------------------------------------------------------------
  in                      *is_ap*                 0 is STA, 1 is uAP.

  in                      *cmd*                   \"type=qrcode mac=\<mac-address-of-device\> chan=\<operating-class/channel\>\...\"
  ----------------------- ----------------------- ------------------------------------------------------------------------------------


**Returns**


bootstrap-id if successful otherwise return -WM_FAIL.


**const char \* wlan_dpp_bootstrap_get_uri (int *is_ap*, unsigned int *id*)**


Get QR code by bootstrap-id.

This function gets QR code string by bootstrap-id


**Parameters**


  ----------------------- ----------------------- -----------------------
  in                      *is_ap*                 0 is STA, 1 is uAP.

  in                      *id*                    bootstrap-id
  ----------------------- ----------------------- -----------------------


**Returns**


QR code string if successful otherwise NULL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### const char\* wlan_dpp_bootstrap_get_uri (int *is_ap*, unsigned int *id*)

Get QR code by bootstrap-id.

This function gets QR code string by bootstrap-id

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>is_ap</em></td>
<td>0 is STA, 1 is uAP.</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>id</em></td>
<td>bootstrap-id</td>
</tr>
</tbody>
</table>

###### Returns

QR code string if successful otherwise NULL.

> **Supported SoCs:** RW610


---

##### int wlan_dpp_chirp (int *is_ap*, const char \* *cmd*)

sends DPP presence announcement.

Send DPP presence announcement from responder. After the Initiator enters the QRcode URI provided by the Responder, the Responder sends the presence announcement to trigger Auth Request from Initiator.


**Parameters**


  ----------------------- ----------------------- -----------------------------------------------
  in                      *is_ap*                 0 is STA, 1 is uAP.

  in                      *cmd*                   \"own=\<bootstrap id\> listen=\<freq\> \...\"
  ----------------------- ----------------------- -----------------------------------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_dpp_configurator_add (int *is_ap*, const char \* *cmd*)

Add a DPP (device provisioning protocol) configurator.

If this device is DPP configurator, add it to get configurator ID.


**Parameters**


  ----------------------- ----------------------- -----------------------
  in                      *is_ap*                 0 is STA, 1 is uAP.

  in                      *cmd*                   \"curve=P-256\"
  ----------------------- ----------------------- -----------------------


**Returns**


configurator ID if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### void wlan_dpp_configurator_params (int *is_ap*, const char \* *cmd*)

Set DPP (device provisioning protocol) configurator parameter

set DPP configurator params. for example:\" conf=\<sta-dpp/ap-dpp\> ssid=\<hex ssid\> configurator=conf_id\" #space character exists between \" & conf word.@param \[in\] is_ap: 0 is STA, 1 is uAP.@param \[in\] cmd: \" conf=\<sta-dpp/ap-dpp/sta-psk\> ssid=\<hex ssid\> configurator=conf_id\...\"


**Returns**


void

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_dpp_configurator_sign (int *is_ap*, const char \* *cmd*)

Configurator configures itself as an Enrollee AP/STA.

Wi-Fi_CERTIFIED_Easy_Connect_Test_Plan_v3.0.pdf 5.3.8 & 5.3.9 Configurator configures itself as an Enrollee AP/STA

for example:\" conf=\<sta-dpp/ap-dpp\> ssid=\<hex ssid\> configurator=conf_id\" #space character exists between \" & conf word.@param \[in\] is_ap: 0 is STA, 1 is uAP@param \[in\] cmd: \" conf=\<sta-dpp/ap-dpp/sta-psk\> ssid=\<hex ssid\> configurator=conf_id\...\"


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_dpp_listen (int *is_ap*, const char \* *cmd*)

Make device listen to DPP request.

Responder generates QR code and listening on its operating channel to wait Auth request.


**Parameters**


  ----------------------- ----------------------- -----------------------
  in                      *is_ap*                 0 is STA, 1 is uAP.

  in                      *cmd*                   \"\<frequency\>\"
  ----------------------- ----------------------- -----------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### void wlan_dpp_mud_url (int *is_ap*, const char \* *cmd*)

MUD URL for enrollee\'s DPP configuration request (optional)

Wi-Fi_CERTIFIED_Easy_Connect_Test_Plan_v3.0.pdf 5.1.23 STAUT sends the MUD URL


**Parameters**


  ----------------------- ----------------------- -----------------------------
  in                      *is_ap*                 0 is STA, 1 is uAP.

  in                      *cmd*                   \"https://example.com/mud\"
  ----------------------- ----------------------- -----------------------------


**Returns**


void

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_dpp_pkex_add (int *is_ap*, const char \* *cmd*)

Set bootstrapping through PKEX (Public Key Exchange).

Support in-band bootstrapping through PKEX


**Parameters**


  ----------------------- ----------------------- ----------------------------------------------------------------
  in                      *is_ap*                 0 is STA, 1 is uAP.

  in                      *cmd*                   \"own=\<bootstrap_id\> identifier=\<string\> code=\<string\>\"
  ----------------------- ----------------------- ----------------------------------------------------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_dpp_qr_code (int *is_ap*, char \* *uri*)

Enter the QR code in the DPP device.

This function set the QR code and return qr-code-id.


**Parameters**


  ----------------------- ----------------------- -----------------------------------
  in                      *is_ap*                 0 is STA, 1 is uAP

  in                      *uri*                   QR code provided by other device.
  ----------------------- ----------------------- -----------------------------------


**Returns**


qr-code-id if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_dpp_reconfig (const char \* *cmd*)

DPP reconfig.

DPP reconfig and make a new DPP connection.


**Parameters**


  ----------------------- ----------------------- -------------------------
  in                      *cmd*                   \"\<network id\> \...\"

  ----------------------- ----------------------- -------------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_dpp_stop_listen (int *is_ap*)

DPP stop listen.

Stop dpp listen and clear listen frequency


**Parameters**


  ----------------------- ----------------------- -----------------------
  in                      *is_ap*                 0 is STA, 1 is uAP.

  ----------------------- ----------------------- -----------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---


#### Wi-Fi Direct (P2P)

| Function | Supported SoCs |
|----------|---------------|
| `wlan_p2p_cancel` | All |
| `wlan_p2p_connect` | All |
| `wlan_p2p_find` | All |
| `wlan_p2p_get_passphrase` | All |
| `wlan_p2p_group_add` | All |
| `wlan_p2p_group_remove` | All |
| `wlan_p2p_invite` | All |
| `wlan_p2p_list_network` | All |
| `wlan_p2p_listen` | All |
| `wlan_p2p_peer` | All |
| `wlan_p2p_peers` | All |
| `wlan_p2p_prov_disc` | All |
| `wlan_p2p_remove_client` | All |
| `wlan_p2p_serv_disc_req` | All |
| `wlan_p2p_serv_disc_resp` | All |
| `wlan_p2p_servvice_add` | All |
| `wlan_p2p_set_listen_channel` | All |
| `wlan_p2p_status` | All |
| `wlan_p2p_stop_find` | All |

##### int wlan_p2p_cancel (void )

Cancel ongoing P2P operations.

This function cancels any active P2P operations, including discovery, connection attempts, or group formation. It resets the P2P state to idle, making it possible to start a new operation afterward.


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_p2p_connect (char \* *cmd*)

Initiate a P2P connection.

After identifying a target P2P device using the discovery process, this function begins the connection sequence. It negotiates connection parameters (often involving WPS configuration) and starts the group formation process.


**Parameters**


  ----------------------- ----------------------- -------------------------------------------------------------------
  in                      *cmd*                   Connection parameters (e.g. Peer device address, WPS method etc).

  ----------------------- ----------------------- -------------------------------------------------------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_p2p_find (const char \* *cmd*)

Initiate P2P discovery.

This function triggers the P2P discovery process by instructing wpa_supplicant to scan for available P2P devices. Optional arguments (such as scan timeout, scan type, or device filters) can be used to tailor the search behavior. Use this function when you want to start discovering nearby P2P devices for later connection or service discovery.


**Parameters**


  ----------------------- ----------------------- ----------------------------------------------------------
  in                      *cmd*                   Optional parameters for discovery (e.g., timeout, type).

  ----------------------- ----------------------- ----------------------------------------------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_p2p_get_passphrase (void )

Retrieve the group passphrase.

Once a P2P group has been established, this function prints the WPA-PSK passphrase that secures the group. Client devices can use this passphrase to connect to the group.


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_p2p_group_add (char \* *cmd*)

Create a new P2P group.

This function requests the creation of a new P2P group (i.e., starting a group owner instance) in wpa_supplicant. It configures the group parameters, including the SSID and security settings, so that client devices can join.


**Parameters**


  ----------------------- ----------------------- ---------------------------------
  in                      *cmd*                   Group configuration parameters.

  ----------------------- ----------------------- ---------------------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_p2p_group_remove (char \* *cmd*)

Tear down an existing P2P group.

This function ends an active P2P group by terminating the group owner instance and disconnecting all associated clients. It performs necessary resource cleanup and notifies clients that the group has been disbanded.


**Parameters**


  ----------------------- ----------------------- ------------------------
  in                      *cmd*                   The wfd interface name

  ----------------------- ----------------------- ------------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_p2p_invite (char \* *cmd*)

Issue a group invitation.

This function sends an invitation request to a target P2P device, inviting it to join an existing P2P group. The invitation bypasses the standard negotiation procedure by directly inviting a device.


**Parameters**


  ----------------------- ----------------------- ---------------------------------------------------------------
  in                      *cmd*                   Invitation parameters (e.g. Peer address, Group address etc).

  ----------------------- ----------------------- ---------------------------------------------------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_p2p_list_network (char \* *buf*, size_t *buflen*, int \* *reslen*)

Retrieves configured networks on a P2P interface.

This function sends a generic wpa_cli command (given by list_network cmd) to obtain configured networks in P2P interface.

The data is returned in tabular form:

network id / ssid / bssid / flags

where: network id -- numeric ID assigned by wpa_supplicant ssid -- the network SSID bssid -- the currently selected BSSID (or "any") flags -- status flags (e.g., "\[CURRENT\]")


**Parameters**


  ----------------------- ----------------------- -------------------------------------------------------------------------------------------------
  out                     *buf*                   Pointer to the buffer that will receive the detailed information.

  in                      *buflen*                The total size of the buf in bytes.

  out                     *reslen*                Pointer to an integer where the actual length (in bytes) of data written to buf will be stored.
  ----------------------- ----------------------- -------------------------------------------------------------------------------------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_p2p_listen (const char \* *cmd*)

Initiates P2P listen mode.

This function sends a generic command to wpa_wpa_supplicant to initiate P2P listen mode.


**Parameters**


  ----------------------- ----------------------- ------------------------------------------------
  in                      *cmd*                   Optional parameters for listen (e.g. timeout).

  ----------------------- ----------------------- ------------------------------------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_p2p_peer (char \* *cmd*, char \* *peer_info_buf*, int *peer_info_buf_size*, int \* *peer_info_len*)

Retrieves detailed information for a specified P2P peer.

This function sends a generic wpa_cli command (given by p2p_peer cmd) to obtain detailed information about a specific P2P peer. The resulting output is stored in the buffer provided by peer_info_buf, and the length of the retrieved information is returned via peer_info_len.


**Parameters**


  ----------------------- ----------------------- ----------------------------------------------------------------------------------------------------------------------------------------------------------
  in                      *cmd*                   A generic command string passed to wpa_cli. It should include the necessary parameters (e.g., \"p2p_peer \<peer_address\>\") to specify the target peer.

  out                     *peer_info_buf*         Pointer to the buffer that will receive the detailed peer information.

  in                      *peer_info_buf_size*    The total size of the `peer_info_buf` in bytes.

  out                     *peer_info_len*         Pointer to an integer where the actual length (in bytes) of data written to `peer_info_buf` will be stored.
  ----------------------- ----------------------- ----------------------------------------------------------------------------------------------------------------------------------------------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_p2p_peers (char \* *peers_buf*, int *peer_buf_size*, int \* *peers_buf_len*)

Retrieves the list of available P2P peers.

This function executes the equivalent of the wpa_cli \'p2p_peers\' command. It fills the provided `peers_buf` with peer information and sets peers_buf_len to reflect the number of bytes written to the buffer.


**Parameters**


  ----------------------- ----------------------- ---------------------------------------------------------------------------------------------------------
  out                     *peers_buf*             Pointer to the buffer that will receive the list of peer addresses or identifiers.

  in                      *peer_buf_size*         The total size of the peers_buf in bytes.

  out                     *peers_buf_len*         Pointer to an integer where the actual length (in bytes) of data written to `peers_buf` will be stored.
  ----------------------- ----------------------- ---------------------------------------------------------------------------------------------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_p2p_prov_disc (char \* *cmd*)

Initiate provisioning discovery.

This command starts the provisioning discovery phase, which is used to determine the optimal method (e.g., PIN or PBC) for configuring a new P2P connection as part of the WPS process.


**Parameters**


  ----------------------- ----------------------- --------------------------------------------------------------------------
  in                      *cmd*                   Povisioning discovery parameters (e.g. device_addr, config_methods etc).

  ----------------------- ----------------------- --------------------------------------------------------------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_p2p_remove_client (char \* *cmd*)

Remove a client from the P2P group.

When a P2P group owner needs to disconnect a client, this function removes the specified client from the group. It ensures that the client's association with the group is terminated, and cleans up related state.


**Parameters**


  ----------------------- ----------------------- ------------------------------------------
  in                      *cmd*                   The address of the client to be removed.

  ----------------------- ----------------------- ------------------------------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_p2p_serv_disc_req (char \* *cmd*)

Send a service discovery request.

A device can use this function to query a discovered P2P peer for details about available services. The request typically includes the type of service or specific query parameters, and the peer is expected to respond with matching service information.


**Parameters**


  ----------------------- ----------------------- ---------------------------------------
  in                      *cmd*                   Service discovery request parameters.

  ----------------------- ----------------------- ---------------------------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_p2p_serv_disc_resp (char \* *cmd*)

Send a service discovery response.

This function is used by a P2P device to respond to a service discovery request. It sends detailed information about the services that are available, enabling the requesting peer to decide if the advertised service meets its requirements.


**Parameters**


  ----------------------- ----------------------- ----------------------------------------
  in                      *cmd*                   Service discovery response parameters.

  ----------------------- ----------------------- ----------------------------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_p2p_servvice_add (char \* *cmd*)

Advertise a service.

This function adds a service advertisement to the device's P2P service discovery framework. It allows the device to broadcast information about services (e.g., file sharing, printing) that may be available to peers.


**Parameters**


  ----------------------- ----------------------- --------------------------------------------------------
  in                      *cmd*                   A string or binary blob representing the service data.

  ----------------------- ----------------------- --------------------------------------------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_p2p_set_listen_channel (t_u8 *channel*, t_u8 *op_class*)

Set P2P Listen channel.

This command is mainly meant for testing purposes and changing the Listen channel during normal operations can result in protocol failures.


**Parameters**


  ----------------------- ----------------------- ----------------------------------------
  in                      *channel*               Channel to listen on.

  in                      *op_class*              Operating class of for listen channel.
  ----------------------- ----------------------- ----------------------------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_p2p_status (char \* *buf*, size_t *buflen*, int \* *reslen*)

Retrieves detailed information for a P2P interface.

This function sends a generic wpa_cli command (given by status cmd) to obtain detailed information about a P2P interface. The resulting output is stored in the buffer provided by buf, and the length of the retrieved information is returned via reslen.


**Parameters**


  ----------------------- ----------------------- -------------------------------------------------------------------------------------------------
  out                     *buf*                   Pointer to the buffer that will receive the detailed information.

  in                      *buflen*                The total size of the buf in bytes.

  out                     *reslen*                Pointer to an integer where the actual length (in bytes) of data written to buf will be stored.
  ----------------------- ----------------------- -------------------------------------------------------------------------------------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_p2p_stop_find (void )

Stop the P2P discovery process.

This command stops an ongoing P2P discovery process initiated by a previous call to wlan_p2p_find. It frees up radio resources and halts further scanning.


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---


#### NAN (Neighbor Awareness Networking)

| Function | Supported SoCs |
|----------|---------------|
| `wlan_nan_cancel_publish` | RW610 |
| `wlan_nan_cancel_subscribe` | RW610 |
| `wlan_nan_publish` | RW610 |
| `wlan_nan_subscribe` | RW610 |
| `wlan_nan_transmit` | RW610 |
| `wlan_nan_update_publish` | RW610 |

##### int wlan_nan_cancel_publish (int *publish_id*)

Cancel NAN USD publish.

This function cancel publish.

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>publish_id</em></td>
<td>publish id to cancel</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610


---

##### int wlan_nan_cancel_subscribe (int *subscribe_id*)

Cancel NAN USD subscribe.

This function cancel subscribe.

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>subscribe_id</em></td>
<td>subscribe id to cancel</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610


---

##### int wlan_nan_publish (wlan_nan_publish_params_t \* *nan_publish*)

Initiate NAN USD publisher.

This function start publish.

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>nan_publish</em></td>
<td>A pointer to wlan_nan_publish_params_t to store nan publish parameters.</td>
</tr>
</tbody>
</table>

###### Returns

publish id if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610


---

##### int wlan_nan_subscribe (wlan_nan_subscribe_params_t \* *nan_subscribe*)

Initiate NAN USD subscriber.

This function start subscribe.

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>nan_subscribe</em></td>
<td>A pointer to wlan_nan_subscribe_params_t to store nan subscribe parameters.</td>
</tr>
</tbody>
</table>

###### Returns

subscribe id if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610


---

##### int wlan_nan_transmit (int *own_id*, int *peer_id*, uint8_t \* *peer_mac*, char \* *ssi_tx*)

Initiate NAN USD subscriber.

This function start subscribe.

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>own_id</em></td>
<td>own publish id or subscribe id</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>peer_id</em></td>
<td>peer's id</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>peer_mac</em></td>
<td>peer's MAC address</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>ssi_tx</em></td>
<td>service specific information (hexdump)</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610


---

##### int wlan_nan_update_publish (int *publish_id*, char \* *ssi_update*)

Update NAN USD publish.

This function update publish.

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>publish_id</em></td>
<td>publish id to update</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>ssi</em></td>
<td>service specific information (hexdump)</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610


---


#### CSI (Channel State Information)

| Function | Supported SoCs |
|----------|---------------|
| `wlan_csi_cfg` | RW610, IW610, IW612 |
| `wlan_register_csi_user_callback` | RW610, IW610, IW612 |
| `wlan_reset_csi_filter_data` | RW610, IW610, IW612 |
| `wlan_set_csi_cfg_param_default` | RW610, IW610, IW612 |
| `wlan_unregister_csi_user_callback` | RW610, IW610, IW612 |

##### int wlan_csi_cfg (wlan_csi_config_params_t \* *csi_params*)

Send the CSI configuration parameter to firmware.


**Parameters**


  ----------------------- ----------------------- -----------------------------
  in                      *csi_params*            CSI configuration parameter

  ----------------------- ----------------------- -----------------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610, IW610, IW612


---

##### int wlan_register_csi_user_callback (int(\*)(void \*buffer, size_t len) *csi_data_recv_callback*)

This function registers callback which are used to deliver CSI (channel state information) data to user.


**Parameters**


  ----------------------------------- -----------------------------------
  in                                  *csi_data_recv_callback*

  ----------------------------------- -----------------------------------

         Memory layout of buffer:
         size(byte)                         items
         2                                  buffer len[bit 0:12]
         2                                  CSI signature, 0xABCD fixed
         4                                  User defined HeaderID
         2                                  Packet info
         2                                  Frame control field for the received packet
         8                                  Timestamp when packet received
         6                                  Received packet destination MAC Address
         6                                  Received packet source MAC address
         1                                  RSSI for antenna A
         1                                  RSSI for antenna B
         1                                  Noise floor for antenna A
         1                                  Noise floor for antenna B
         1                                  RX signal strength above noise floor
         1                                  Channel
         2                                  user defined chip ID
         4                                  Reserved
         4                                  CSI data length in DWORDs
                                            CSI data

  -----------------------------------------------------------------------

  -----------------------------------------------------------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610, IW610, IW612


---

##### void wlan_reset_csi_filter_data (void )

This function reset Wi-Fi CSI filter data.

> **Supported SoCs:** RW610, IW610, IW612


---

##### int wlan_set_csi_cfg_param_default (wlan_csi_config_params_t \* *in_csi_cfg*)

This function set CSI default configuration data.


**Parameters**


  ----------------------- ----------------------- -------------------------------------------
  in                      *in_csi_cfg*            CSI default configuration data to be set.

  ----------------------- ----------------------- -------------------------------------------


**Returns**


if successful return 1 else return 0.

> **Supported SoCs:** RW610, IW610, IW612


---

##### int wlan_unregister_csi_user_callback (void )

This function unregisters callback which are used to deliver CSI data to user.


**Returns**


WM_SUCCESS if successful


**wlan_csi_config_params_t \* wlan_get_csi_cfg_param_default (void )**


This function get CSI default configuration data.


**Returns**


CSI data pointer.

> **Supported SoCs:** RW610, IW610, IW612


---


#### FTM / 802.11az Ranging

| Function | Supported SoCs |
|----------|---------------|
| `wlan_ftm_cfg` | IW612 |
| `wlan_ftm_start_stop` | IW612 |

##### int wlan_ftm_cfg (const t_u8 *protocol*, ranging_11az_cfg_t \* *ftm_ranging_cfg*)

Config FTM protocol.


**Parameters**


  ----------------------- ----------------------- -------------------------------------------
  in                      *protocol*              0: Dot11mc, 1: Dot11az_ntb, 2: Dot11az_tb

  in                      *ftm_ranging_cfg*       FTM ranging config.
  ----------------------- ----------------------- -------------------------------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW612


---

##### int wlan_ftm_start_stop (const t_u16 *action*, const t_u8 *loop_cnt*, const t_u8 \* *mac*, const t_u8 *channel*)

Start or stop FTM (Wi-Fi fine time measurement) based on the command from CLI.


**Parameters**


  ----------------------- ----------------------- -----------------------------------------------------------------------------------
  in                      *action*                1: start FTM 2: stop FTM.

  in                      *loop_cnt*              number of FTM sessions to run repeatedly (default:1, 0: non-stop, n\>1: n times).

  in                      *MAC*                   MAC address of the peer with whom FTM session is required.

  in                      *channel*               Channel on which FTM is started.
  ----------------------- ----------------------- -----------------------------------------------------------------------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW612


---


#### MBO (Multi-Band Operation)

| Function | Supported SoCs |
|----------|---------------|
| `wlan_mbo_peferch_cfg` | RW610 |
| `wlan_mbo_set_cell_capa` | RW610 |
| `wlan_mbo_set_oce` | RW610 |

##### int wlan_mbo_peferch_cfg (const char \* *non_pref_chan*)

Multi band operation (MBO) non-preferred channels

A space delimited list of non-preferred channels where each channel is
a colon delimited list of values.

Format:

non_pref_chan=oper_class:chan:preference:reason Example:

non_pref_chan=81:5:10:2 81:1:0:2 81:9:0:2

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>non_pref_chan</em></td>
<td>list of non-preferred channels.</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610


---

##### int wlan_mbo_set_cell_capa (t_u8 *cell_capa*)

MBO set cellular data capabilities

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>cell_capa</em></td>
<td>1 = Cellular data connection available 2 = Cellular data connection not available 3 = Not cellular capable (default)</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610


---

##### int wlan_mbo_set_oce (t_u8 *oce*)

Optimized connectivity experience (OCE)

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>oce</em></td>
<td>Enable OCE features 1 = Enable OCE in non-AP STA mode (default; disabled if the driver does not indicate support for OCE in STA mode). 2 = Enable OCE in STA-CFON mode.</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610


---


#### MEF (Management Entity Filter)

| Function | Supported SoCs |
|----------|---------------|
| `wlan_config_mef` | RW610 |
| `wlan_mef_set_auto_arp` | RW610 |
| `wlan_mef_set_auto_ping` | RW610 |
| `wlan_mef_set_multicast` | RW610 |

##### int wlan_config_mef (int *type*, t_u8 *mef_action*)

This function set/delete MEF entries configuration.

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>type</em></td>
<td>MEF type: MEF_TYPE_DELETE, MEF_TYPE_AUTO_PING, MEF_TYPE_AUTO_ARP</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>mef_action</em></td>
<td>To be 0–discard and not wake host, 1–discard and wake host 3–allow and wake host.</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if the call was successful.

\-WM_FAIL if failed.

> **Supported SoCs:** RW610


---

##### int wlan_mef_set_auto_arp (t_u8 *mef_action*)

This function set auto ARP configuration.

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>mef_action</em></td>
<td>To be 0–discard and not wake host, 1–discard and wake host, 3–allow and wake host.</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610


---

##### int wlan_mef_set_auto_ping (t_u8 *mef_action*)

This function set auto ping configuration.

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>mef_action</em></td>
<td><p>To be</p>
<p>0–discard ping packet and not wake host</p>
<p>1–discard ping packet and wake host</p>
<p>3–allow ping packet and wake host.</p></td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610


---

##### int wlan_mef_set_multicast (t_u8 *mef_action*)

This function set multicast packet as low power wake up condition.

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>mef_action</em></td>
<td><p>To be</p>
<p>0–discard multicast packet and not wake host</p>
<p>1–discard multicast packet and wake host</p>
<p>3–allow multicast packet and wake host.</p></td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610


---


#### Network Monitor

| Function | Supported SoCs |
|----------|---------------|
| `wlan_deregister_net_monitor_user_callback` | RW610, IW610 |
| `wlan_net_monitor_cfg` | RW610, IW610 |
| `wlan_register_monitor_user_callback` | RW610, IW610 |

##### void wlan_deregister_net_monitor_user_callback (void )

This function deregisters monitor callback.

> **Supported SoCs:** RW610, IW610


---

##### int wlan_net_monitor_cfg (wlan_net_monitor_t \* *monitor*)

Send the network monitor configuration parameter to firmware.


**Parameters**


  ----------------------- ----------------------- ---------------------------------
  in                      *monitor*               Monitor configuration parameter

  ----------------------- ----------------------- ---------------------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610, IW610


---

##### void wlan_register_monitor_user_callback (int(\*)(void \*buffer, t_u16 data_len) *monitor_data_recv_callback*)

This function registers callback which are used to deliver monitor data to user.


**Parameters**


  ----------------------- ------------------------------ -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  in                      *monitor_data_recv_callback*   Callback to deliver monitor data and data length to user. Memory layout of buffer: offset(byte) items 0 rssi 1 802.11 MAC header 1 + \'size of 802.11 MAC header\' frame body

  ----------------------- ------------------------------ -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

> **Supported SoCs:** RW610, IW610


---


#### ED MAC Control

| Function | Supported SoCs |
|----------|---------------|
| `wlan_get_ed_mac_mode` | All |
| `wlan_set_ed_mac_mode` | All |

##### int wlan_get_ed_mac_mode (wlan_ed_mac_ctrl_t \* *wlan_ed_mac_ctrl*)

This API can be used to get current ED MAC MODE configuration for station.


**Parameters**


  ----------------------- ----------------------- ----------------------------------------------------------------------------------------------------------
  out                     *wlan_ed_mac_ctrl*      A pointer to wlan_ed_mac_ctrl_t with parameters mentioned in above set API.

  ----------------------- ----------------------- ----------------------------------------------------------------------------------------------------------


**Returns**


WM_SUCCESS if the call was successful.

-WM_FAIL if failed.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_set_ed_mac_mode (wlan_ed_mac_ctrl_t *wlan_ed_mac_ctrl*)

Configure Energy Detect MAC mode for the station in the Wi-Fi Firmware.


**Note**


When ED MAC mode is enabled, the Wi-Fi Firmware can behave in the following way:

When the background noise had reached the Energy Detect threshold or above, the Wi-Fi chipset/module should hold the data transmission until the condition is removed. The 2.4GHz and 5GHz bands are configured separately.


**Parameters**


  ----------------------- ----------------------- --------------------------------------------------------------------------------------------------------------------------------
  in                      *wlan_ed_mac_ctrl*      Struct with following parameters ed_ctrl_2g 0 - disable EU adaptivity for 2.4GHz band 1 - enable EU adaptivity for 2.4GHz band

  ----------------------- ----------------------- --------------------------------------------------------------------------------------------------------------------------------

ed_offset_2g 0 - Default Energy Detect threshold (Default: 0x9) offset value range: 0x80 to 0x7F


**Note**


If 5GH enabled then add following parameters

      ed_ctrl_5g          0  - disable EU adaptivity for 5GHz band
                          1  - enable EU adaptivity for 5GHz band
      ed_offset_5g        0  - Default Energy Detect threshold(Default: 0xC)
                          offset value range: 0x80 to 0x7F


**Returns**


WM_SUCCESS if the call was successful.

-WM_FAIL if failed.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---


#### RF & PHY Configuration

| Function | Supported SoCs |
|----------|---------------|
| `wlan_auto_null_tx` | RW610 |
| `wlan_external_coex_pta_cfg` | RW610 |
| `wlan_get_mmsf` | RW610 |
| `wlan_get_rx_abort_cfg_ext` | RW610 |
| `wlan_get_tsp_cfg` | RW610 |
| `wlan_set_ami_cfg` | RW610, IW610, IW612 |
| `wlan_set_clocksync_cfg` | RW610 |
| `wlan_set_get_cck_desense_cfg` | RW610 |
| `wlan_set_get_rx_abort_cfg` | RW610 |
| `wlan_set_mmsf` | RW610 |
| `wlan_set_rx_abort_cfg_ext` | RW610 |
| `wlan_set_tsp_cfg` | RW610 |
| `wlan_start_stop_ami` | RW610, IW610, IW612 |

##### int wlan_auto_null_tx (wlan_auto_null_tx_t \* *auto_null_tx*, mlan_bss_type *bss_type*)

Start/Stop auto TX null. Call this API to auto transmit and one shot
quality of service data packets to get the CSI after STA connected one
AP or uAP was connected with external STA.

###### Note

STA cannot send auto NULL data if not connected AP, not support auto
TX without connecting AP. uAP cannot send auto NULL data if is not
connected, not support auto tx without connecting with external STA.

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>auto_null_tx</em></td>
<td>auto null RX information</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>bss_type</em></td>
<td>0: station; 1: uAP</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610


---

##### int wlan_external_coex_pta_cfg (ext_coex_pta_cfg *coex_pta_config*)

Set external coex PTA (packet traffic arbitration) parameters.

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>coex_pta_config</em></td>
<td>ext_coex_pta_cfg</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610


---

##### int wlan_get_mmsf (t_u8 \* *enable*, t_u8 \* *Density*, t_u8 \* *MMSF*)

Get 802.11ax AMPDU density configuration.

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>enable</em></td>
<td>0 - Disbale MMSF; 1 - Enable MMSF</td>
</tr>
<tr class="even">
<td>out</td>
<td><em>Density</em></td>
<td>AMPDU Density value.</td>
</tr>
<tr class="odd">
<td>out</td>
<td><em>MMSF</em></td>
<td>AMPDU MMSF value. Default value is 0x6.</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610


---

##### int wlan_get_rx_abort_cfg_ext (struct wlan_rx_abort_cfg_ext \* *cfg*)

Get the dynamic RX abort configuration from firmware.

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>cfg</em></td>
<td>A pointer to information buffer</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610


---

##### int wlan_get_tsp_cfg (t_u16 \* *enable*, t_u32 \* *back_off*, t_u32 \* *highThreshold*, t_u32 \* *lowThreshold*, t_u32 \* *dutycycstep*, t_u32 \* *dutycycmin*, int \* *highthrtemp*, int \* *lowthrtemp*, int \* *currCAUTemp*, int \* *currRFUTemp*)

Get TSP (thermal safeguard protection) configuration. TSP algorithm
monitors PA Tj and primarily backs off data throughput.

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>enable</em></td>
<td>Enable/Disable TSP algorithm</td>
</tr>
<tr class="even">
<td>out</td>
<td><em>back_off</em></td>
<td>Power back off [0...20]dB</td>
</tr>
<tr class="odd">
<td>out</td>
<td><em>highThreshold</em></td>
<td>High threshold [0...300]°C</td>
</tr>
<tr class="even">
<td>out</td>
<td><em>lowThreshold</em></td>
<td>Low threshold [0...300]°C High Threshold is Greater than low threshold.</td>
</tr>
<tr class="odd">
<td>out</td>
<td><em>dutycycstep</em></td>
<td>Duty cycle step(percentage)</td>
</tr>
<tr class="even">
<td>out</td>
<td><em>dutycycmin</em></td>
<td>Duty cycle min(percentage)</td>
</tr>
<tr class="odd">
<td>out</td>
<td><em>highthrtemp</em></td>
<td>High throttle threshold temperature(celsius)</td>
</tr>
<tr class="even">
<td>out</td>
<td><em>lowthrtemp</em></td>
<td>Low throttle threshold temperature(celsius)</td>
</tr>
<tr class="odd">
<td>out</td>
<td><em>currCAUTemp</em></td>
<td>CAU TSEN temperature</td>
</tr>
<tr class="even">
<td>out</td>
<td><em>currRFUTemp</em></td>
<td>RFU temperature</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610


---

##### void wlan_set_ami_cfg (wlan_csi_proc_cfg \* *cfg*)

This function set Ambient Motion Index configuration.


**Parameters**


  ----------------------- ----------------------- --------------------------------------
  in                      *cfg*                   Ambient Motion Index configuration..

  ----------------------- ----------------------- --------------------------------------

> **Supported SoCs:** RW610, IW610, IW612


---

##### int wlan_set_clocksync_cfg (const wlan_clock_sync_gpio_tsf_t \* *tsf_latch*)

Set clock sync GPIO based TSF (time synchronization function).

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>tsf_latch</em></td>
<td>Clock sync TSF latch parameters to be sent to firmware</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610


---

##### int wlan_set_get_cck_desense_cfg (struct wlan_cck_desense_cfg \* *cfg*, t_u16 *action*)

Set/Get CCK (complementary code keying) desense configuration to/from
firmware.

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in,out</td>
<td><em>cfg</em></td>
<td>A pointer to information buffer</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>action</em></td>
<td>get or set.</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610


---

##### int wlan_set_get_rx_abort_cfg (struct wlan_rx_abort_cfg \* *cfg*, t_u16 *action*)

Set/Get RX abort configuration to/from firmware.

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in,out</td>
<td><em>cfg</em></td>
<td>A pointer to information buffer</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>action</em></td>
<td>Command action: get or set</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610


---

##### int wlan_set_mmsf (const t_u8 *enable*, const t_u8 *Density*, const t_u8 *MMSF*)

Set 802.11ax AMPDU (aggregate medium access control (MAC) protocol
data unit) density configuration.

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>enable</em></td>
<td>0 - Disbale MMSF; 1 - Enable MMSF</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>Density</em></td>
<td>AMPDU density value. Default value is 0x30.</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>MMSF</em></td>
<td>AMPDU MMSF value. Default value is 0x6.</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610


---

##### int wlan_set_rx_abort_cfg_ext (const struct wlan_rx_abort_cfg_ext \* *cfg*)

Set the dynamic RX abort configuration to firmware.

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>cfg</em></td>
<td>A pointer to information buffer</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610


---

##### int wlan_set_tsp_cfg (t_u16 *enable*, t_u32 *back_off*, t_u32 *highThreshold*, t_u32 *lowThreshold*, t_u32 *dutycycstep*, t_u32 *dutycycmin*, int *highthrtemp*, int *lowthrtemp*)

Set TSP (thermal safeguard protection) configuration. TSP algorithm
monitors and primarily backs off data throughput.

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>enable</em></td>
<td>Enable/Disable tsp algorithm</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>back_off</em></td>
<td>Power back off [0...20]dB</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>highThreshold</em></td>
<td>High threshold [0...300]Celsius</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>lowThreshold</em></td>
<td>Low threshold [0...300]Celsius High threshold is greater than low threshold.</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>dutycycstep</em></td>
<td>Duty cycle step(percentage)</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>dutycycmin</em></td>
<td>Duty cycle min(percentage)</td>
</tr>
<tr class="odd">
<td>out</td>
<td><em>highthrtemp</em></td>
<td>High throttle threshold temperature (celsius)</td>
</tr>
<tr class="even">
<td>out</td>
<td><em>lowthrtemp</em></td>
<td>Low throttle threshold temperature (celsius)</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610


---

##### void wlan_start_stop_ami (uint8_t *start*)

Use this API to start or stop caculate Ambient Motion Index.


**Parameters**


  ----------------------- ----------------------- -----------------------------
  in                      *start*                 start/stop 1: start 0: stop

  ----------------------- ----------------------- -----------------------------

> **Supported SoCs:** RW610, IW610, IW612


---


#### Event Subscription

| Function | Supported SoCs |
|----------|---------------|
| `wlan_clear_subscribe_event` | RW610 |
| `wlan_get_subscribe_event` | RW610 |
| `wlan_set_subscribe_event` | RW610 |
| `wlan_set_threshold_link_quality` | RW610 |
| `wlan_subscribe_rssi_low_event` | All |

##### int wlan_clear_subscribe_event (unsigned int *event_id*)

cancel the subscribe event to firmware

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>event_id</em></td>
<td>event id to clear as per sub_event_id</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610


---

##### int wlan_get_subscribe_event (wlan_ds_subscribe_evt \* *sub_evt*)

Get all subscribed events from Wi-Fi firmware along with threshold
value and report frequency.

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>sub_evt</em></td>
<td>A pointer to wlan_ds_subscribe_evt to store the events data.</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if set successfully, otherwise return failure.

> **Supported SoCs:** RW610


---

##### int wlan_set_subscribe_event (unsigned int *event_id*, unsigned int *thresh_value*, unsigned int *freq*)

Subscribe specified event from the Wi-Fi firmware. Wi-Fi firmware
report the registered event to driver upon configured report
conditions are met.

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>event_id</em></td>
<td>event to register as per sub_event_id except for EVENT_SUB_LINK_QUALITY</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>thresh_value</em></td>
<td>the RSSI threshold value (dBm)</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>freq</em></td>
<td>event frequency 0–report once, 1–report every time happened, N – report only happened &gt; N consecutive times.</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if set successfully, otherwise return failure.

> **Supported SoCs:** RW610


---

##### int wlan_set_threshold_link_quality (unsigned int *evend_id*, unsigned int *link_snr*, unsigned int *link_snr_freq*, unsigned int *link_rate*, unsigned int *link_rate_freq*, unsigned int *link_tx_latency*, unsigned int *link_tx_lantency_freq*)

subscribe link quality event

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>event_id</em></td>
<td>event id to set, EVENT_SUB_LINK_QUALITY</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>link_snr</em></td>
<td>link quality snr value</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>link_snr_freq</em></td>
<td>link quality snr freq</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>link_rate</em></td>
<td>link quality rate</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>link_rate_freq</em></td>
<td>link quality rate freq</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>link_tx_latency</em></td>
<td>link quality write latency</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>link_tx_lantency_freq</em></td>
<td>link quality write latency freq</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610


---

##### void wlan_subscribe_rssi_low_event (void )

Subscribe RSSI low event in firmware if roaming is enabled.


**Parameters**


  ----------------------- ----------------------- -----------------------
  in                      *void*                  

  ----------------------- ----------------------- -----------------------


**Returns**


void

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---


#### Management Frame

| Function | Supported SoCs |
|----------|---------------|
| `wlan_clear_mgmt_ie` | All |
| `wlan_get_mgmt_ie` | All |
| `wlan_mgmtframe_tx_cfg` | RW610, IW610 |
| `wlan_remain_on_channel` | All |
| `wlan_rx_mgmt_indication` | All |
| `wlan_set_sta_mac_filter` | RW610 |

##### int wlan_clear_mgmt_ie (enum wlan_bss_type *bss_type*, IEEEtypes_ElementId_t *index*, int *mgmt_bitmap_index*)

Clear management IE for given BSS type (interface) and index.


**Parameters**


  ----------------------- ----------------------- --------------------------
  in                      *bss_type*              0: STA, 1: uAP

  in                      *index*                 IE index.

  in                      *mgmt_bitmap_index*     management bitmap index.
  ----------------------- ----------------------- --------------------------


**Returns**


WM_SUCCESS if successful.

-WM_FAIL if unsuccessful.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_get_mgmt_ie (enum wlan_bss_type *bss_type*, IEEEtypes_ElementId_t *index*, void \* *buf*, unsigned int \* *buf_len*)

Get Management IE for given BSS type (interface) and index.


**Parameters**


  ----------------------- ----------------------- ------------------------------------
  in                      *bss_type*              0: STA, 1: uAP

  in                      *index*                 IE index.

  out                     *buf*                   Buffer to store requested IE data.

  out                     *buf_len*               Length of IE data.
  ----------------------- ----------------------- ------------------------------------


**Returns**


WM_SUCCESS if successful.

-WM_FAIL if unsuccessful.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_mgmtframe_tx_cfg (wlan_host_tx_frame_params_t \* *mgmtframe*)

Send the mgmt/data frame config parameter and payload to FW.


**Parameters**


  ----------------------- ----------------------- --------------------------
  in                      *mgmtframe*             Frame header and payload

  ----------------------- ----------------------- --------------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610, IW610


---

##### int wlan_remain_on_channel (const enum wlan_bss_type *bss_type*, const bool *status*, const uint8_t *channel*, const uint32_t *duration*)

This API is used to set/cancel the remain on channel configuration.


**Note**


When status is false, channel and duration parameters are ignored.


**Parameters**


  ----------------------- ----------------------- ---------------------------------------------------------------------------------------------------
  in                      *bss_type*              The interface to set channel bss_type 0: STA, 1: uAP

  in                      *status*                false : Cancel the remain on channel configuration true : Set the remain on channel configuration

  in                      *channel*               The channel to configure

  in                      *duration*              The duration for which to remain on channel in milliseconds.
  ----------------------- ----------------------- ---------------------------------------------------------------------------------------------------


**Returns**


WM_SUCCESS on success or error code.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_rx_mgmt_indication (const enum wlan_bss_type *bss_type*, const uint32_t *mgmt_subtype_mask*, int(\*)(const enum wlan_bss_type bss_type, const wlan_mgmt_frame_t \*frame, const size_t len) *rx_mgmt_callback*)

This API can be used to start/stop the management frame forwarded to host through data path.


**Parameters**


  ----------------------- ----------------------- --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  in                      *bss_type*              The interface from which management frame needs to be collected 0: STA, 1: uAP

  in                      *mgmt_subtype_mask*     Management Subtype Mask If Bit X is set in mask, it means that IEEE Management Frame SubType X is to be filtered and passed through to host. Bit Description \[31:14\] Reserved \[13\] Action frame \[12:9\] Reserved \[8\] Beacon \[7:6\] Reserved \[5\] Probe response \[4\] Probe request \[3\] Reassociation response \[2\] Reassociation request \[1\] Association response \[0\] Association request Support multiple bits set. 0 = stop forward frame 1 = start forward frame

  in                      *rx_mgmt_callback*      The receive callback where the received management frames are passed.
  ----------------------- ----------------------- --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


**Returns**


WM_SUCCESS if operation is successful.

-WM_FAIL if command fails.


**Note**


Pass management subtype mask all zero to disable all the management frame forward to host.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_set_sta_mac_filter (int *filter_mode*, int *mac_count*, unsigned char \* *mac_addr*)

Set the STA MAC filter in Wi-Fi firmware. Apply for uAP mode only.
When STA MAC filter enabled, wlan firmware blocks all the packets from
station with MAC address in black list and not blocks packets from
station with MAC address in white list.

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>filter_mode</em></td>
<td>Channel filter mode (disable/white/black list)</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>mac_count</em></td>
<td>The count of MAC list</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>mac_addr</em></td>
<td>The pointer to MAC address list</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610


---


#### Security & Crypto

| Function | Supported SoCs |
|----------|---------------|
| `wlan_free_entp_cert_files` | All |
| `wlan_get_entp_cert_files` | IW416, W8987, IW610, IW612 |
| `wlan_get_pmfcfg` | All |
| `wlan_pmksa_flush` | All |
| `wlan_pmksa_list` | All |
| `wlan_set_crypto_AES_CCMP_decrypt` | All |
| `wlan_set_crypto_AES_CCMP_encrypt` | All |
| `wlan_set_crypto_AES_ECB_decrypt` | All |
| `wlan_set_crypto_AES_ECB_encrypt` | All |
| `wlan_set_crypto_AES_GCMP_decrypt` | All |
| `wlan_set_crypto_AES_GCMP_encrypt` | All |
| `wlan_set_crypto_AES_WRAP_decrypt` | All |
| `wlan_set_crypto_AES_WRAP_encrypt` | All |
| `wlan_set_crypto_RC4_decrypt` | All |
| `wlan_set_crypto_RC4_encrypt` | All |
| `wlan_set_entp_cert_files` | All |
| `wlan_set_okc` | All |
| `wlan_set_reassoc_control` | All |

##### void wlan_free_entp_cert_files (void )

This function free the temporary memory of enterprise certificate data After add new enterprise network profile, the certificate data has been parsed by mbedtls into another data, which can be freed.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### t_u32 wlan_get_entp_cert_files (int *cert_type*, t_u8 \*\* *data*)

This function get enterprise certificate data from \"wlan\" global structure


**Parameters**


  ----------------------- ----------------------- ----------------------------------------------------------------------------------------------------------------------
  in                      *cert_type*             certificate file type: 1 -- FILE_TYPE_ENTP_CA_CERT, 2 -- FILE_TYPE_ENTP_CLIENT_CERT, 3 -- FILE_TYPE_ENTP_CLIENT_KEY.

  out                     *data*                  raw data of the enterprise certificate file
  ----------------------- ----------------------- ----------------------------------------------------------------------------------------------------------------------


**Returns**


size of raw data

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

##### int wlan_get_pmfcfg (uint8_t \* *mfpc*, uint8_t \* *mfpr*)

Use this API to get the management frame protection parameters for sta.


**Parameters**


  ----------------------- ----------------------- ------------------------------------------------------------------------------------------------------------------------------
  out                     *mfpc*                  Management frame protection capable (MFPC) 1: Management frame protection capable 0: Management frame protection not capable

  out                     *mfpr*                  Management frame protection required (MFPR) 1: Management frame protection required 0: Management frame protection optional
  ----------------------- ----------------------- ------------------------------------------------------------------------------------------------------------------------------


**Returns**


WM_SUCCESS if operation is successful.

-WM_FAIL if command fails.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_pmksa_flush (void )

Flush PTKSA cache entries


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_pmksa_list (char \* *buf*, size_t *buflen*)

Dump text list of entries in PMKSA (pairwise master key security association) cache.


**Parameters**


  ----------------------- ----------------------- --------------------------------------
  out                     *buf*                   Buffer to save PMKSA cache text list

  in                      *buflen*                length of the buffer
  ----------------------- ----------------------- --------------------------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_set_crypto_AES_CCMP_decrypt (const t_u8 \* *Key*, const t_u16 *KeyLength*, const t_u8 \* *AAD*, const t_u16 *AADLength*, const t_u8 \* *Nonce*, const t_u16 *NonceLength*, t_u8 \* *Data*, t_u16 \* *DataLength*)

Set crypto AES_CCMP algorithm decrypt command parameters.


**Parameters**


  ----------------------- ----------------------- ----------------------------------------
  in                      *Key*                   key

  in                      *KeyLength*             The key length is 16/32.

  in                      *AAD*                   AAD

  in                      *AADLength*             The maximum AAD length is 30.

  in                      *Nonce*                 Nonce

  in                      *NonceLength*           The nonce length valid range \[7,13\].

  in                      *Data*                  Data

  in                      *DataLength*            The maximum data length is 80.
  ----------------------- ----------------------- ----------------------------------------


**Returns**


WM_SUCCESS if successful.

-WM_E_PERM if not supported.

-WM_FAIL if failure.


**Note**


If the function returns WM_SUCCESS, the data in the memory pointed to by data is overwritten by the decrypted data. The value of DataLength is updated to the decrypted data length. The decrypted data is 8 bytes (when key length is 16) or 16 bytes (when key length is 32) less than the original data.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_set_crypto_AES_CCMP_encrypt (const t_u8 \* *Key*, const t_u16 *KeyLength*, const t_u8 \* *AAD*, const t_u16 *AADLength*, const t_u8 \* *Nonce*, const t_u16 *NonceLength*, t_u8 \* *Data*, t_u16 \* *DataLength*)

Set crypto AES_CCMP (counter mode with cipher block chaining message authentication code protocol) algorithm encrypt command parameters.


**Parameters**


  ----------------------- ----------------------- ----------------------------------------
  in                      *Key*                   key

  in                      *KeyLength*             The key length is 16/32.

  in                      *AAD*                   AAD

  in                      *AADLength*             The maximum AAD length is 30.

  in                      *Nonce*                 Nonce

  in                      *NonceLength*           The nonce length valid range \[7,13\].

  in                      *Data*                  Data

  in                      *DataLength*            The maximum data length is 80.
  ----------------------- ----------------------- ----------------------------------------


**Returns**


WM_SUCCESS if successful.

-WM_E_PERM if not supported.

-WM_FAIL if failure.


**Note**


If the function returns WM_SUCCESS, the data in the memory pointed to by data is overwritten by the encrypted data. The value of DataLength is updated to the encrypted data length. The encrypted data is 8 bytes (when key length is 16) or 16 bytes (when key length is 32) more than the original data. Therefore, the address pointed to by Data needs to reserve enough space.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_set_crypto_AES_ECB_decrypt (const t_u8 \* *Key*, const t_u16 *KeyLength*, const t_u8 \* *KeyIV*, const t_u16 *KeyIVLength*, t_u8 \* *Data*, t_u16 \* *DataLength*)

Set crypto AES_ECB (advanced encryption standard, electronic codebook) algorithm decrypt command parameters.


**Parameters**


  ----------------------- ----------------------- --------------------------------------------------------------------
  in                      *Key*                   key

  in                      *KeyLength*             The key length is 16/24/32.

  in                      *KeyIV*                 KeyIV should point to a 8 bytes array with any value in the array.

  in                      *KeyIVLength*           The keyIV length is 8.

  in                      *Data*                  Data

  in                      *DataLength*            The data length is 16.
  ----------------------- ----------------------- --------------------------------------------------------------------


**Returns**


WM_SUCCESS if successful.

-WM_E_PERM if not supported.

-WM_FAIL if failure.


**Note**


If the function returns WM_SUCCESS, the data in the memory pointed to by data is overwritten by the decrypted data. The value of DataLength is updated to the decrypted data length. The length of the decrypted data is the same as the origin DataLength.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_set_crypto_AES_ECB_encrypt (const t_u8 \* *Key*, const t_u16 *KeyLength*, const t_u8 \* *KeyIV*, const t_u16 *KeyIVLength*, t_u8 \* *Data*, t_u16 \* *DataLength*)

Set crypto AES_ECB (advanced encryption standard, electronic codebook) algorithm encrypt command parameters.


**Parameters**


  ----------------------- ----------------------- --------------------------------------------------------------------
  in                      *Key*                   key

  in                      *KeyLength*             The key length is 16/24/32.

  in                      *KeyIV*                 KeyIV should point to a 8 bytes array with any value in the array.

  in                      *KeyIVLength*           The keyIV length is 8.

  in                      *Data*                  Data

  in                      *DataLength*            The data length is 16.
  ----------------------- ----------------------- --------------------------------------------------------------------


**Returns**


WM_SUCCESS if successful.

-WM_E_PERM if not supported.

-WM_FAIL if failure.


**Note**


If the function returns WM_SUCCESS, the data in the memory pointed to by data is overwritten by the encrypted data. The value of DataLength is updated to the encrypted data length. The length of the encrypted data is the same as the origin DataLength.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_set_crypto_AES_GCMP_decrypt (const t_u8 \* *Key*, const t_u16 *KeyLength*, const t_u8 \* *AAD*, const t_u16 *AADLength*, const t_u8 \* *Nonce*, const t_u16 *NonceLength*, t_u8 \* *Data*, t_u16 \* *DataLength*)

Set crypto AES_CCMP algorithm decrypt command parameters.


**Parameters**


  ----------------------- ----------------------- ----------------------------------------
  in                      *Key*                   key

  in                      *KeyLength*             The key length is 16/32.

  in                      *AAD*                   AAD

  in                      *AADLength*             The maximum AAD length is 30.

  in                      *Nonce*                 Nonce

  in                      *NonceLength*           The nonce length valid range \[7,13\].

  in                      *Data*                  Data

  in                      *DataLength*            The maximum data length is 80.
  ----------------------- ----------------------- ----------------------------------------


**Returns**


WM_SUCCESS if successful.

-WM_E_PERM if not supported.

-WM_FAIL if failure.


**Note**


If the function returns WM_SUCCESS, the data in the memory pointed to by data is overwritten by the decrypted data. The value of DataLength is updated to the decrypted data length. The decrypted data is 16 bytes less than the original data.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_set_crypto_AES_GCMP_encrypt (const t_u8 \* *Key*, const t_u16 *KeyLength*, const t_u8 \* *AAD*, const t_u16 *AADLength*, const t_u8 \* *Nonce*, const t_u16 *NonceLength*, t_u8 \* *Data*, t_u16 \* *DataLength*)

Set crypto AES_GCMP (galois/counter mode with AES-GMAC) algorithm encrypt command parameters.


**Parameters**


  ----------------------- ----------------------- ----------------------------------------
  in                      *Key*                   key

  in                      *KeyLength*             The key length is 16/32.

  in                      *AAD*                   AAD

  in                      *AADLength*             The maximum AAD length is 30.

  in                      *Nonce*                 Nonce

  in                      *NonceLength*           The nonce length valid range \[7,13\].

  in                      *Data*                  Data

  in                      *DataLength*            The maximum data length is 80.
  ----------------------- ----------------------- ----------------------------------------


**Returns**


WM_SUCCESS if successful.

-WM_E_PERM if not supported.

-WM_FAIL if failure.


**Note**


If the function returns WM_SUCCESS, the data in the memory pointed to by data is overwritten by the encrypted data. The value of DataLength is updated to the encrypted data length. The encrypted data is 16 bytes more than the original data. Therefore, the address pointed to by Data needs to reserve enough space.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_set_crypto_AES_WRAP_decrypt (const t_u8 \* *Key*, const t_u16 *KeyLength*, const t_u8 \* *KeyIV*, const t_u16 *KeyIVLength*, t_u8 \* *Data*, t_u16 \* *DataLength*)

Set crypto AES_WRAP algorithm decrypt command parameters.


**Parameters**


  ----------------------- ----------------------- -----------------------------------------
  in                      *Key*                   key

  in                      *KeyLength*             The key length is 16/24/32.

  in                      *KeyIV*                 KeyIV

  in                      *KeyIVLength*           The keyIV length is 8.

  in                      *Data*                  Data

  in                      *DataLength*            The data length valid range \[8,1016\].
  ----------------------- ----------------------- -----------------------------------------


**Returns**


WM_SUCCESS if successful.

-WM_E_PERM if not supported.

-WM_FAIL if failure.


**Note**


If the function returns WM_SUCCESS, the data in the memory pointed to by data is overwritten by the decrypted data. The value of DataLength is updated to the decrypted data length. The decrypted data is 8 bytes less than the original data.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_set_crypto_AES_WRAP_encrypt (const t_u8 \* *Key*, const t_u16 *KeyLength*, const t_u8 \* *KeyIV*, const t_u16 *KeyIVLength*, t_u8 \* *Data*, t_u16 \* *DataLength*)

Set crypto AES_WRAP (advanced encryption standard wrap) algorithm encrypt command parameters.


**Parameters**


  ----------------------- ----------------------- -----------------------------------------
  in                      *Key*                   key

  in                      *KeyLength*             The key length is 16/24/32.

  in                      *KeyIV*                 KeyIV

  in                      *KeyIVLength*           The keyIV length is 8.

  in                      *Data*                  Data

  in                      *DataLength*            The data length valid range \[8,1016\].
  ----------------------- ----------------------- -----------------------------------------


**Returns**


WM_SUCCESS if successful.

-WM_E_PERM if not supported.

-WM_FAIL if failure.


**Note**


If the function returns WM_SUCCESS, the data in the memory pointed to by data is overwritten by the encrypted data. The value of DataLength is updated to the encrypted data length. The encrypted data is 8 bytes more than the original data. Therefore, the address pointed to by Data needs to reserve enough space.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_set_crypto_RC4_decrypt (const t_u8 \* *Key*, const t_u16 *KeyLength*, const t_u8 \* *KeyIV*, const t_u16 *KeyIVLength*, t_u8 \* *Data*, t_u16 \* *DataLength*)

Set crypto RC4 (rivest cipher 4) algorithm decrypt command parameters.


**Parameters**


  ----------------------- ----------------------- ----------------------------------------------------
  in                      *Key*                   key

  in                      *KeyLength*             The KeyLength + KeyIVLength valid range \[1,256\].

  in                      *KeyIV*                 KeyIV

  in                      *KeyIVLength*           The KeyLength + KeyIVLength valid range \[1,256\].

  in                      *Data*                  Data

  in                      *DataLength*            The maximum data length is 1200.
  ----------------------- ----------------------- ----------------------------------------------------


**Returns**


WM_SUCCESS if successful.

-WM_E_PERM if not supported.

-WM_FAIL if failure.


**Note**


If the function returns WM_SUCCESS, the data in the memory pointed to by data is overwritten by the decrypted data. The value of DataLength is updated to the decrypted data length. The length of the decrypted data is the same as the origin DataLength.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_set_crypto_RC4_encrypt (const t_u8 \* *Key*, const t_u16 *KeyLength*, const t_u8 \* *KeyIV*, const t_u16 *KeyIVLength*, t_u8 \* *Data*, t_u16 \* *DataLength*)

Set crypto RC4 (rivest cipher 4) algorithm encrypt command parameters.


**Parameters**


  ----------------------- ----------------------- ----------------------------------------------------
  in                      *Key*                   key

  in                      *KeyLength*             The KeyLength + KeyIVLength valid range \[1,256\].

  in                      *KeyIV*                 KeyIV

  in                      *KeyIVLength*           The KeyLength + KeyIVLength valid range \[1,256\].

  in                      *Data*                  Data

  in                      *DataLength*            The maximum data length is 1200.
  ----------------------- ----------------------- ----------------------------------------------------


**Returns**


WM_SUCCESS if successful.

-WM_E_PERM if not supported.

-WM_FAIL if failure.


**Note**


If the function returns WM_SUCCESS, the data in the memory pointed to by data is overwritten by the encrypted data. The value of DataLength is updated to the encrypted data length. The length of the encrypted data is the same as the origin DataLength.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_set_entp_cert_files (int *cert_type*, t_u8 \* *data*, t_u32 *data_len*)

This function specifies the enterprise certificate file This function is used before adding network profile. It can store certificate data in \"wlan\" global structure.


**Parameters**


  ----------------------- ----------------------- ----------------------------------------------------------------------------------------------------------------------
  in                      *cert_type*             certificate file type: 1 -- FILE_TYPE_ENTP_CA_CERT, 2 -- FILE_TYPE_ENTP_CLIENT_CERT, 3 -- FILE_TYPE_ENTP_CLIENT_KEY.

  in                      *data*                  raw data of the enterprise certificate file

  in                      *data_len*              length of the enterprise certificate file
  ----------------------- ----------------------- ----------------------------------------------------------------------------------------------------------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_set_okc (t_u8 *okc*)

Opportunistic key caching (also known as proactive key caching) default This parameter can be used to set the default behavior for the proactive_key_caching parameter. By default, OKC is disabled unless enabled with the global okc=1 parameter or with the per-network pkc(proactive_key_caching)=1 parameter. With okc=1, OKC is enabled by default, but can be disabled with per-network pkc(proactive_key_caching)=0 parameter.


**Parameters**


  ----------------------- ----------------------- ----------------------------------
  in                      *okc*                   Enable opportunistic key caching

  ----------------------- ----------------------- ----------------------------------

0 = Disable OKC (default) 1 = Enable OKC


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### void wlan_set_reassoc_control (bool *reassoc_control*)

Set reassociation control in Wi-Fi connection manager. When reassociation control enabled, Wi-Fi connection manager attempts reconnection with the network for WLAN_RECONNECT_LIMIT times before giving up.


**Note**


Reassociation is enabled by default in the Wi-Fi connection manager.


**Parameters**


  ----------------------- ----------------------- ------------------------------
  in                      *reassoc_control*       Reassociation enable/disable

  ----------------------- ----------------------- ------------------------------

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---


#### Auto Reconnect

| Function | Supported SoCs |
|----------|---------------|
| `wlan_auto_reconnect_disable` | IW416, W8987, IW610, IW612 |
| `wlan_auto_reconnect_enable` | IW416, W8987, IW610, IW612 |
| `wlan_get_auto_reconnect_config` | IW416, W8987, IW610, IW612 |

##### int wlan_auto_reconnect_disable (void )

Disable auto reconnect feature in Wi-Fi firmware.


**Returns**


WM_SUCCESS if operation is successful.

-WM_FAIL if command fails.

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

##### int wlan_auto_reconnect_enable (wlan_auto_reconnect_config_t *auto_reconnect_config*)

Enable auto reconnect feature in Wi-Fi firmware.


**Parameters**


  ----------------------------------- -----------------------------------
  in                                  *auto_reconnect_config*

  ----------------------------------- -----------------------------------

1\. reconnect counter(0x1-0xff) - The number of times the Wi-Fi firmware retries connection attempt with AP. The value 0xff means retry forever. (default 0xff).

2\. reconnect interval(0x0-0xff) - Time gap in seconds between each connection attempt (default 10).

3\. flags - Bit 0: Set to 1: Firmware should report link-loss to host if AP rejects authentication/association while reconnecting. Set to 0: Default behavior: Firmware does not report link-loss to host on AP rejection and continues internally. Bit 1-15: Reserved.

  -----------------------------------------------------------------------

  -----------------------------------------------------------------------


**Returns**


WM_SUCCESS if operation is successful.

-WM_FAIL if command fails.

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

##### int wlan_get_auto_reconnect_config (wlan_auto_reconnect_config_t \* *auto_reconnect_config*)

Get auto reconnect configuration from Wi-Fi firmware.


**Parameters**


  ----------------------- ------------------------- ----------------------------------------------------------------------------------------
  out                     *auto_reconnect_config*   auto reconnect configuration structure where response from Wi-Fi firmware gets stored.

  ----------------------- ------------------------- ----------------------------------------------------------------------------------------


**Returns**


WM_SUCCESS if operation is successful.

-WM_E_INVAL if auto_reconnect_config is not valid.

-WM_FAIL if command fails.

> **Supported SoCs:** IW416, W8987, IW610, IW612


---


#### WoWLAN (Wake on WLAN)

| Function | Supported SoCs |
|----------|---------------|
| `wlan_set_ipv6_ns_mef` | RW610 |
| `wlan_tcp_keep_alive` | All |
| `wlan_wowlan_cfg_ptn_match` | RW610 |
| `wlan_wowlan_config` | All |

##### int wlan_set_ipv6_ns_mef (t_u8 *mef_action*)

Use this API to enable IPv6 neighbor solicitation offload in Wi-Fi
firmware.

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>mef_action</em></td>
<td>0–discard and not wake host, 1–discard and wake host 3–allow and wake host.</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if operation is successful.

\-WM_FAIL if command fails.

> **Supported SoCs:** RW610


---

##### int wlan_tcp_keep_alive (wlan_tcp_keep_alive_t \* *keep_alive*)

Use this API to configure the TCP keep alive parameters in Wi-Fi firmware. wlan_tcp_keep_alive_t provides the parameters which are available for configuration.


**Note**


To reset current TCP keep alive configuration, just set the reset member of wlan_tcp_keep_alive_t with value 1, all other parameters are ignored in this case.

This API is called after successful connection and before putting Wi-Fi SoC in IEEE power save mode.


**Parameters**


  ----------------------- ----------------------- -----------------------------------------------------------------
  in                      *keep_alive*            A pointer to wlan_tcp_keep_alive_t

  ----------------------- ----------------------- -----------------------------------------------------------------


**Returns**


WM_SUCCESS if operation is successful.

-WM_FAIL if command fails.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_wowlan_cfg_ptn_match (enum wlan_bss_type *bss_type*, wlan_wowlan_ptn_cfg_t \* *ptn_cfg*)

Use this API to enable WOWLAN (wake-on-wireless-LAN) on magic packet
RX in Wi-Fi firmware

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>bss_type</em></td>
<td>0–for bss type as sta, 1–for bss type as uap</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>ptn_cfg</em></td>
<td>A pointer to wlan_wowlan_ptn_cfg_t containing wake on Wi-Fi pattern configuration</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if operation is successful.

\-WM_FAIL if command fails

> **Supported SoCs:** RW610


---

##### int wlan_wowlan_config (t_u32 *wake_up_conds*)

Wowlan configuration. This function may be called to configure host sleep in firmware.


**Parameters**


  ----------------------- ----------------------- -------------------------------
  in                      *wake_up_conds*         Bit map of default condition.

  ----------------------- ----------------------- -------------------------------


**Returns**


WM_SUCCESS if the call was successful.

-WM_FAIL if failed.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---


#### Cloud Keep-Alive

| Function | Supported SoCs |
|----------|---------------|
| `wlan_cloud_keep_alive_enabled` | IW416, W8987, IW610, IW612 |
| `wlan_save_cloud_keep_alive_params` | IW416, W8987, IW610, IW612 |
| `wlan_start_cloud_keep_alive` | IW416, W8987, IW610, IW612 |
| `wlan_stop_cloud_keep_alive` | IW416, W8987, IW610, IW612 |

##### int wlan_cloud_keep_alive_enabled (t_u32 *dst_ip*, t_u16 *dst_port*)

Get cloud keep alive status for given destination ip and port


**Parameters**


  ----------------------- ----------------------- ------------------------
  in                      *dst_ip*                Destination ip address

  in                      *dst_port*              Destination port
  ----------------------- ----------------------- ------------------------


**Returns**


1 if enabled otherwise 0.

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

##### int wlan_save_cloud_keep_alive_params (wlan_cloud_keep_alive_t \* *cloud_keep_alive*, t_u16 *src_port*, t_u16 *dst_port*, t_u32 *seq_number*, t_u32 *ack_number*, t_u8 *enable*)

Save start cloud keep alive parameters


**Parameters**


  ----------------------- ----------------------- ------------------------------
  in                      *cloud_keep_alive*      cloud keep alive information

  in                      *src_port*              Source port

  in                      *dst_port*              Destination port

  in                      *seq_number*            Sequence number

  in                      *ack_number*            Acknowledgement number

  in                      *enable*                Enable
  ----------------------- ----------------------- ------------------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

##### int wlan_start_cloud_keep_alive (void )

Start cloud keep alive


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

##### int wlan_stop_cloud_keep_alive (wlan_cloud_keep_alive_t \* *cloud_keep_alive*)

Stop cloud keep alive


**Parameters**


  ----------------------- ----------------------- ------------------------------
  in                      *cloud_keep_alive*      cloud keep alive information

  ----------------------- ----------------------- ------------------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, IW610, IW612


---


#### STA & Filter Management

| Function | Supported SoCs |
|----------|---------------|
| `wlan_set_multicast` | All |
| `wlan_set_packet_filters` | All |
| `wlan_sta_inactivityto` | RW610 |

##### int wlan_set_multicast (t_u8 *mef_action*)

This function set multicast MEF (memory efficient filtering) entry


**Parameters**


  ----------------------- ----------------------- --------------------------------------------------------------------------------------
  in                      *mef_action*            To be 0--discard and not wake host, 1--discard and wake host 3--allow and wake host.

  ----------------------- ----------------------- --------------------------------------------------------------------------------------


**Returns**


WM_SUCCESS if the call was successful.

-WM_FAIL if failed.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_set_packet_filters (wlan_flt_cfg_t \* *flt_cfg*)

Use this API to set packet filters in Wi-Fi firmware.


**Parameters**


  ----------------------- ----------------------- --------------------------------------------------------------------------------------------------------
  in                      *flt_cfg*               A pointer to structure which holds the the packet filters wlan_flt_cfg_t.

  ----------------------- ----------------------- --------------------------------------------------------------------------------------------------------


**Note**


For example:

MEF Configuration command

mefcfg={

Criteria: bit0-broadcast, bit1-unicast, bit3-multicast

Criteria=2 Unicast frames are received during host sleep mode

NumEntries=1 Number of activated MEF entries

mef_entry_0: example filters to match TCP destination port 80 send by 192.168.0.88 pkt or magic pkt.

mef_entry_0={

mode: bit0--hostsleep mode, bit1--non hostsleep mode

mode=1 HostSleep mode

action: 0--discard and not wake host, 1--discard and wake host 3--allow and wake host

action=3 Allow and Wake host

filter_num=3 Number of filter

RPN only support \"&&\" and \"\|\|\" operators, space cannot be removed between operators.

RPN=Filter_0 && Filter_1 \|\| Filter_2

Byte comparison filter\'s type is 0x41, decimal comparison filter\'s type is 0x42,

Bit comparison filter\'s type is 0x43

Filter_0 is decimal comparison filter, it always with type=0x42

Decimal filter always has type, pattern, offset, numbyte 4 field

Filter_0 matches RX packet with TCP destination port 80

Filter_0={

type=0x42 decimal comparison filter

pattern=80 80 is the decimal constant to be compared

offset=44 44 is the byte offset of the field in RX pkt to be compare

numbyte=2 2 is the number of bytes of the field

}

Filter_1 is Byte comparison filter, it always with type=0x41

Byte filter always has type, byte, repeat, offset 4 filed

Filter_1 matches RX packet send by IP address 192.168.0.88

Filter_1={

type=0x41 Byte comparison filter

repeat=1 1 copies of \'c0:a8:00:58\'

byte=c0:a8:00:58 \'c0:a8:00:58\' is the byte sequence constant with each byte

in hex format, with \':\' as delimiter between two byte.

offset=34 34 is the byte offset of the equal length field of rx\'d pkt.

}

Filter_2 is Magic packet, it can look for 16 contiguous copies of \'00:50:43:20:01:02\' from

the RX pkt\'s offset 14

Filter_2={

type=0x41 Byte comparison filter

repeat=16 16 copies of \'00:50:43:20:01:02\'

byte=00:50:43:20:01:02 \# \'00:50:43:20:01:02\' is the byte sequence constant

offset=14 14 is the byte offset of the equal length field of rx\'d pkt.

}

}

}

Above filters can be set by filling values in following way in wlan_flt_cfg_t structure.

wlan_flt_cfg_t flt_cfg;

uint8_t byte_seq1\[\] = {0xc0, 0xa8, 0x00, 0x58};

uint8_t byte_seq2\[\] = {0x00, 0x50, 0x43, 0x20, 0x01, 0x02};

memset(&flt_cfg, 0, sizeof(wlan_flt_cfg_t));

flt_cfg.criteria = 2;

flt_cfg.nentries = 1;

flt_cfg.mef_entry.mode = 1;

flt_cfg.mef_entry.action = 3;

flt_cfg.mef_entry.filter_num = 3;

flt_cfg.mef_entry.filter_item\[0\].type = TYPE_DNUM_EQ;

flt_cfg.mef_entry.filter_item\[0\].pattern = 80;

flt_cfg.mef_entry.filter_item\[0\].offset = 44;

flt_cfg.mef_entry.filter_item\[0\].num_bytes = 2;

flt_cfg.mef_entry.filter_item\[1\].type = TYPE_BYTE_EQ;

flt_cfg.mef_entry.filter_item\[1\].repeat = 1;

flt_cfg.mef_entry.filter_item\[1\].offset = 34;

flt_cfg.mef_entry.filter_item\[1\].num_byte_seq = 4;

memcpy(flt_cfg.mef_entry.filter_item\[1\].byte_seq, byte_seq1, 4);

flt_cfg.mef_entry.rpn\[1\] = RPN_TYPE_AND;

flt_cfg.mef_entry.filter_item\[2\].type = TYPE_BYTE_EQ;

flt_cfg.mef_entry.filter_item\[2\].repeat = 16;

flt_cfg.mef_entry.filter_item\[2\].offset = 14;

flt_cfg.mef_entry.filter_item\[2\].num_byte_seq = 6;

memcpy(flt_cfg.mef_entry.filter_item\[2\].byte_seq, byte_seq2, 6);

flt_cfg.mef_entry.rpn\[2\] = RPN_TYPE_OR;


**Returns**


WM_SUCCESS if operation is successful.

-WM_FAIL if command fails.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_sta_inactivityto (wlan_inactivity_to_t \* *inac_to*, t_u16 *action*)

Get/Set inactivity timeout extend

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>inac_to</em></td>
<td>wlan_inactivity_to_t</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>action</em></td>
<td><p>0: get</p>
<p>1: set</p></td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if successful otherwise return -WM_FAIL.

##### t_u16 wlan_get_status_code (enum wlan_event_reason *reason*)

Get 802.11 Status Code.

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>reason</em></td>
<td>wlcmgr event reason</td>
</tr>
</tbody>
</table>

###### Returns

status code defined in IEEE 802.11-2020 standard.

##### int32_t wlan_get_temperature (void )

Get board temperature.

###### Returns

board temperature.

> **Supported SoCs:** RW610


---


#### Statistics & Diagnostics

| Function | Supported SoCs |
|----------|---------------|
| `wlan_channel_load` | RW610 |
| `wlan_get_average_signal_strength` | All |
| `wlan_get_channel_load` | RW610 |
| `wlan_get_current_nf` | All |
| `wlan_get_current_rssi` | All |
| `wlan_get_current_signal_strength` | All |
| `wlan_get_firmware_version_ext` | RW610 |
| `wlan_get_log` | RW610 |
| `wlan_get_signal_info` | RW610 |
| `wlan_get_stats` | RW610 |
| `wlan_reset_stats` | RW610 |
| `wlan_version_extended` | All |

##### int wlan_channel_load (wlan_802_11_chan_load_t \* *chan_load*)

Set Wi-Fi channel load info.

> **Supported SoCs:** RW610


---

##### int wlan_get_average_signal_strength (short \* *rssi*, int \* *snr*)

Get average RSSI and signal to noise ratio (average value of the former 8 packets) from Wi-Fi firmware.


**Parameters**


  ----------------------- ----------------------- ---------------------------------------------
  out                     *RSSI*                  A pointer to variable to store current RSSI

  out                     *snr*                   A pointer to variable to store current SNR.
  ----------------------- ----------------------- ---------------------------------------------


**Returns**


WM_SUCCESS if successful.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_get_channel_load (wlan_802_11_chan_load_t \* *chan_load*)

Get Wi-Fi channel load info.

> **Supported SoCs:** RW610


---

##### int wlan_get_current_nf (void )

Get the current noise floor.


**Returns**


The noise floor value

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_get_current_rssi (short \* *rssi*)

Get the current RSSI value.


**Parameters**


  ----------------------- ----------------------- ----------------------------------------------------------------------
  out                     *rssi*                  pointer to get the current RSSI (Received Signal Strength Indicator)

  ----------------------- ----------------------- ----------------------------------------------------------------------


**Returns**


WM_SUCCESS.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_get_current_signal_strength (short \* *rssi*, int \* *snr*)

Get current RSSI and signal to noise ratio from Wi-Fi firmware.


**Parameters**


  ----------------------- ----------------------- ---------------------------------------------
  out                     *RSSI*                  A pointer to variable to store current RSSI

  out                     *snr*                   A pointer to variable to store current SNR.
  ----------------------- ----------------------- ---------------------------------------------


**Returns**


WM_SUCCESS if successful.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### char\* wlan_get_firmware_version_ext (void )

Get the Wi-Fi firmware version extension string.

###### Note

This API does not allocate memory for pointer. It just returns pointer
of WLCMGR internal static buffer. So no need to free the pointer by
caller.

###### Returns

Wi-Fi firmware version extension string pointer stored in WLCMGR

> **Supported SoCs:** RW610


---

##### int wlan_get_log (wlan_pkt_stats_t \* *stats*)

Use this API to get the various statistics of STA from Wi-Fi firmware

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>stats</em></td>
<td><p>A pointer to structure where stats collected from Wi-Fi firmware can be copied.</p>
<p>Explore the elements of the wlan_pkt_stats_t strucutre for more information on stats.</p></td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if operation is successful.

\-WM_FAIL if command fails.

> **Supported SoCs:** RW610


---

##### int wlan_get_signal_info (wlan_rssi_info_t \* *signal*)

Get RSSI information.

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>signal</em></td>
<td>RSSI information get report buffer</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610


---

##### int wlan_get_stats (wlan_stats_t \* *stats*, enum wlan_bss_type *bss_type*)

Use this API to get the various statistics of STA/uAP from Wi-Fi
driver

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>stats</em></td>
<td><p>A pointer to structure where stats collected from Wi-Fi driver can be copied.</p>
<p>Explore the elements of the wlan_stats_t strucutre for more information on stats.</p></td>
</tr>
<tr class="even">
<td>in</td>
<td><em>bss_type</em></td>
<td>0: STA, 1: uAP</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if operation is successful.

\-WM_FAIL if command fails.

> **Supported SoCs:** RW610


---

##### int wlan_reset_stats (enum wlan_bss_type *bss_type*)

Use this API to reset the various statistics of STA/uAP from Wi-Fi
driver

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>bss_type</em></td>
<td>0: STA, 1: uAP</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if operation is successful.

\-WM_FAIL if command fails.

> **Supported SoCs:** RW610


---

##### void wlan_version_extended (void )

Use this API to print Wi-Fi driver and firmware extended version on console.


**Note**


Call this API when SDK_DEBUGCONSOLE not set to DEBUGCONSOLE_DISABLE.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---


#### MAC Address

| Function | Supported SoCs |
|----------|---------------|
| `wlan_get_mac_address` | All |
| `wlan_get_mac_address_uap` | All |
| `wlan_get_wfd_mac_address` | All |
| `wlan_set_mac_addr` | All |
| `wlan_set_sta_mac_addr` | All |

##### int wlan_get_mac_address (unsigned char \* *dest*)

Retrieve the Wi-Fi MAC address of the station interface.

This function copies the MAC address of the Wi-Fi station interface to the 6-byte array pointed to by *dest* . In the event of an error, nothing is copied to *dest* .


**Parameters**


  ----------------------- ----------------------- ---------------------------------------------------------------------
  out                     *dest*                  A pointer to a 6-byte array where the MAC address should be copied.

  ----------------------- ----------------------- ---------------------------------------------------------------------


**Returns**


WM_SUCCESS if the MAC address was copied.

-WM_E_INVAL if *dest* is NULL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_get_mac_address_uap (uint8_t \* *dest*)

Retrieve the Wi-Fi MAC address of the uAP interface.

This function copies the MAC address of the Wi-Fi uAP interface to the 6-byte array pointed to by *dest* . In the event of an error, nothing is copied to *dest* .


**Parameters**


  ----------------------- ----------------------- ------------------------------------------------------------------
  out                     *dest*                  A pointer to a 6-byte array where the MAC address can be copied.

  ----------------------- ----------------------- ------------------------------------------------------------------


**Returns**


WM_SUCCESS if the MAC address was copied.

-WM_E_INVAL if *dest* is NULL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_get_wfd_mac_address (unsigned char \* *dest*)

Retrieve the wireless MAC address of wfd interface.

This function copies the MAC address of the wireless interface to the 6-byte array pointed to by *dest* . In the event of an error, nothing is copied to *dest* .


**Parameters**


  ----------------------- ----------------------- -------------------------------------------------------------------
  out                     *dest*                  A pointer to a 6-byte array where the MAC address will be copied.

  ----------------------- ----------------------- -------------------------------------------------------------------


**Returns**


WM_SUCCESS if the MAC address was copied.

-WM_E_INVAL if *dest* is NULL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_set_mac_addr (uint8_t \* *mac*)

Set the Wi-Fi MAC Address in the Wi-Fi firmware.

This function can be used to set Wi-Fi MAC Address in firmware. When called after Wi-Fi initialization done, the incoming MAC is treated as the STA MAC address directly. And mac\[4\] plus 1, the modified MAC is used as the uAP MAC address.


**Parameters**


  ----------------------- ----------------------- -------------------------------------------------------------------------------------------------------
  in                      *MAC*                   The MAC Address in 6 bytes array format like uint8_t mac\[\] = { 0x00, 0x50, 0x43, 0x21, 0x19, 0x6E};

  ----------------------- ----------------------- -------------------------------------------------------------------------------------------------------


**Returns**


WM_SUCCESS if the call was successful.

-WM_FAIL if failed.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_set_sta_mac_addr (uint8_t \* *mac*)

Set the Wi-Fi MAC address for the STA in the Wi-Fi firmware.

This function can be used to set the Wi-Fi MAC address for the station in the firmware. Should be called after Wi-Fi initialization done. It sets the station MAC address only.


**Parameters**


  ----------------------- ----------------------- ------------------------------------------------------------------------------------------------------
  in                      *MAC*                   The MAC Address in 6 byte array format like uint8_t mac\[\] = { 0x00, 0x50, 0x43, 0x21, 0x19, 0x6E};

  ----------------------- ----------------------- ------------------------------------------------------------------------------------------------------


**Returns**


WM_SUCCESS if the call was successful.

-WM_FAIL if failed.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---


#### Country / Region

| Function | Supported SoCs |
|----------|---------------|
| `wlan_get_11d_enable_status` | All |
| `wlan_set_11d_state` | All |
| `wlan_set_country_code` | All |
| `wlan_set_country_ie_ignore` | All |

##### bool wlan_get_11d_enable_status (void )

Get current status of 802.11d support.


**Returns**


true if 802.11d support is enabled by application.

false if not enabled.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_set_11d_state (int *bss_type*, int *state*)

Set STA/uAP 802.11d feature Enable/Disable.


**Parameters**


  ----------------------- ----------------------- -----------------------
  in                      *bss_type*              0: STA, 1: uAP

  in                      *state*                 0: disable, 1: enable
  ----------------------- ----------------------- -----------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_set_country_code (const char \* *alpha2*)

Set country code


**Note**


This API should be called after Wi-Fi is initialized but before starting uAP interface.


**Parameters**


  ----------------------- ----------------------- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  in                      *alpha2*                country code in 3 octets string, 2 octets country code and 1 octet environment 2 octets country code supported: WW : World Wide Safe US : US FCC CA : IC Canada SG : Singapore EU : ETSI AU : Australia KR : Republic Of Korea FR : France JP : Japan CN : China

  ----------------------- ----------------------- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

For the third octet, STA is always 0. for uAP environment: All environments of the current frequency band and country (default) alpha2\[2\]=0x20 Outdoor environment only alpha2\[2\]=0x4f Indoor environment only alpha2\[2\]=0x49 Noncountry entity (country_code=XX) alpha\[2\]=0x58 IEEE 802.11 standard Annex E table indication: 0x01 .. 0x1f Annex E, Table E-4 (Global operating classes) alpha\[2\]=0x04


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_set_country_ie_ignore (uint8_t \* *ignore*)

Set ignore region code.


**Parameters**


  ----------------------- ----------------------- -----------------------------
  in                      *ignore*                0: don\'t ignore, 1: ignore

  ----------------------- ----------------------- -----------------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---


#### Calibration

| Function | Supported SoCs |
|----------|---------------|
| `wlan_get_cal_data` | All |
| `wlan_get_otp_user_data` | All |
| `wlan_set_cal_data` | All |

##### int wlan_get_cal_data (wlan_cal_data_t \* *cal_data*)

Get calibration data from Wi-Fi firmware.


**Parameters**


  ----------------------- ----------------------- -------------------------------------------------------------------------------------------------
  out                     *cal_data*              Pointer to calibration data structure where calibration data and it\'s length should be stored.

  ----------------------- ----------------------- -------------------------------------------------------------------------------------------------


**Returns**


WM_SUCCESS if calibration data read operation is successful.

-WM_E_INVAL if cal_data is not valid.

-WM_FAIL if command fails.


**Note**


The user of this API should free the allocated buffer for calibration data.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_get_otp_user_data (uint8_t \* *buf*, uint16_t *len*)

Get user data from OTP (one-time pramming) memory


**Parameters**


  ----------------------- ----------------------- -----------------------------------------------
  out                     *buf*                   Pointer to buffer where data should be stored

  out                     *len*                   Number of bytes to read
  ----------------------- ----------------------- -----------------------------------------------


**Returns**


WM_SUCCESS if user data read operation is successful.

-WM_E_INVAL if buf is not valid or of insufficient size.

-WM_FAIL if user data field is not present or command fails.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### void wlan_set_cal_data (const uint8_t \* *cal_data*, const unsigned int *cal_data_size*)

Set the Wi-Fi calibration data in the Wi-Fi firmware.

This function can be used to set the Wi-Fi calibration data in the firmware. This should be call before wlan_init() function.


**Parameters**


  ----------------------- ----------------------- ----------------------------------
  in                      *cal_data*              The calibration data buffer

  in                      *cal_data_size*         Size of calibration data buffer.
  ----------------------- ----------------------- ----------------------------------

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---


#### Register Access

| Function | Supported SoCs |
|----------|---------------|
| `wlan_reg_access` | RW610 |

##### int wlan_reg_access (wifi_reg_t *type*, uint16_t *action*, uint32_t *offset*, uint32_t \* *value*)

This function reads/writes adapter registers value.

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>type</em></td>
<td>Register type: 1 – MAC, 2 – BBP, 3 – RF.</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>action</em></td>
<td>0 – read, 1 – write</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>offset</em></td>
<td>Specifies the offset location that is to be read/write.</td>
</tr>
<tr class="even">
<td>in,out</td>
<td><em>value</em></td>
<td>Value if specified, stand for write action, then that value can be written to that offset in the specified register. Value should be specified in hexadecimal. Otherwise, it stands for read action, the value is updated with read value.</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610


---


#### Utility & Miscellaneous

| Function | Supported SoCs |
|----------|---------------|
| `wlan_ft_roam` | All |
| `wlan_get_beacon_period` | IW416, W8987, IW610, IW612 |
| `wlan_get_board_type` | IW416, W8987, IW610, IW612 |
| `wlan_get_current_wfd_network` | IW416, W8987, IW610, IW612 |
| `wlan_get_current_wfd_network_ssid` | IW416, W8987, IW610, IW612 |
| `wlan_get_dtim_period` | IW416, W8987, IW610, IW612 |
| `wlan_get_region_code` | All |
| `wlan_get_status_code` | IW416, W8987, IW610, IW612 |
| `wlan_get_tsf` | All |
| `wlan_get_tsf_info` | RW610 |
| `wlan_independent_reset` | IW416, W8987, IW610, IW612 |
| `wlan_send_hostcmd` | IW416, W8987, IW610, IW612 |
| `wlan_set_indrst_cfg` | IW416, W8987, IW610, IW612 |
| `wlan_set_mgmt_ie` | All |
| `wlan_set_region_code` | All |
| `wlan_set_sta_reconnect_in_hang` | IW416, W8987, IW610, IW612 |
| `wlan_set_uap_restart_in_hang` | IW416, W8987, IW610, IW612 |
| `wlan_string_dup` | RW610 |

##### int wlan_ft_roam (const t_u8 \* *bssid*, const t_u8 *channel*)

Start FT roaming : This API is used to initiate fast BSS transition based roaming.


**Parameters**


  ----------------------- ----------------------- -----------------------
  in                      *bssid*                 BSSID of AP to roam

  in                      *channel*               Channel of AP to roam
  ----------------------- ----------------------- -----------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### uint16_t wlan_get_beacon_period (void )

Use this API to get the beacon period of associated BSS from the cached state information.


**Returns**


beacon_period if operation is successful.

0 if command fails.

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

##### uint32_t wlan_get_board_type (void )

Get board type.


**Returns**


board type. 0x02: RW610_PACKAGE_TYPE_BGA 0xFF: others

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

##### int wlan_get_current_wfd_network (struct wlan_network \* *network*)

Retrieve the current network configuration of the WFD interface.

This function retrieves the current network configuration of the WFD interface when the WFD interface is in the WLAN_UAP_STARTED state.


**Parameters**


  ----------------------- ----------------------- -------------------------------------------------------------
  out                     *network*               A pointer to the wlan_network.

  ----------------------- ----------------------- -------------------------------------------------------------


**Returns**


WM_SUCCESS if successful.

-WM_E_INVAL if *network* is NULL.

WLAN_ERROR_STATE if the Wi-Fi connection manager was not running or not in the WLAN_UAP_STARTED state.

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

##### int wlan_get_current_wfd_network_ssid (char \* *ssid*)

Retrieve the current network ssid of the WFD interface.

This function retrieves the current network ssid of the WFD interface when the WFD interface is in the WLAN_UAP_STARTED state.


**Parameters**


  ----------------------- ----------------------- ---------------------------------------------------------------------------------------------------------------
  out                     *ssid*                  A pointer to the ssid char string with NULL termination. Maximum length is 32 (not include NULL termination).

  ----------------------- ----------------------- ---------------------------------------------------------------------------------------------------------------


**Returns**


WM_SUCCESS if successful.

-WM_E_INVAL if *ssid* is NULL.

WLAN_ERROR_STATE if the Wi-Fi connection manager was not running or not in the WLAN_UAP_STARTED state.

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

##### uint8_t wlan_get_dtim_period (void )

Use this API to get the dtim period of associated BSS. When this API called, the radio sends a probe request to the AP for this information.


**Returns**


dtim_period if operation is successful.

0 if DTIM IE is not found in AP\'s Probe response.


**Note**


This API should not be called from Wi-Fi event handler registered by application during wlan_start.

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

##### int wlan_get_region_code (unsigned int \* *region_code*)

Get region code.


**Parameters**


  ----------------------- ----------------------- -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  out                     *region_code*           pointer The value: 0x00: World Wide Safe 0x10: US FCC 0x20: IC Canada 0x10: Singapore 0x30: ETSI 0x30: Australia 0x30: Republic Of Korea 0x32: France 0xFF: Japan 0x50: China

  ----------------------- ----------------------- -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### t_u16 wlan_get_status_code (enum wlan_event_reason *reason*)

Get 802.11 Status Code.


**Parameters**


  ----------------------- ----------------------- -----------------------
  in                      *reason*                wlcmgr event reason

  ----------------------- ----------------------- -----------------------


**Returns**


status code defined in IEEE 802.11-2020 standard.


**char \* wlan_string_dup (const char \* *s*)**


Allocate memory for a string and copy the string to the allocated memory


**Parameters**


  ----------------------- ----------------------- --------------------------
  in                      *s*                     the source/target string

  ----------------------- ----------------------- --------------------------


**Returns**


new string if successful, otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

##### int wlan_get_tsf (uint32_t \* *tsf_high*, uint32_t \* *tsf_low*)

Use this API to get the TSF (timing synchronization function) from Wi-Fi firmware.


**Parameters**


  ----------------------- ----------------------- -------------------------------------
  in                      *tsf_high*              Pointer to store TSF higher 32bits.

  in                      *tsf_low*               Pointer to store TSF lower 32bits.
  ----------------------- ----------------------- -------------------------------------


**Returns**


WM_SUCCESS if operation is successful.

-WM_FAIL if command fails.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_get_tsf_info (wlan_tsf_info_t \* *tsf_info*)

Get TSF info from firmware using GPIO latch.

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>tsf_info</em></td>
<td>TSF info parameter received from firmware</td>
</tr>
</tbody>
</table>

###### Returns

WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** RW610


---

##### int wlan_independent_reset (void )

Test independent firmware reset

This function can either send command that can cause timeout in firmware or send GPIO pulse that can cause out of band reset in firmware as per configuration int earlier wlan_set_indrst_cfg API.


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

##### int wlan_send_hostcmd (const void \* *cmd_buf*, uint32_t *cmd_buf_len*, void \* *host_resp_buf*, uint32_t *resp_buf_len*, uint32_t \* *reqd_resp_len*)

This function sends the host command to firmware and copies back response to caller provided buffer in case of success response from firmware is not parsed by this function but just copied back to the caller buffer.


**Parameters**


  ----------------------- ----------------------- -------------------------------------------------------------------------------------------------------------
  in                      *cmd_buf*               Buffer containing the host command with header

  in                      *cmd_buf_len*           length of valid bytes in cmd_buf

  out                     *host_resp_buf*         Caller provided buffer, in case of success command response is copied to this buffer can be same as cmd_buf

  in                      *resp_buf_len*          resp_buf\'s allocated length

  out                     *reqd_resp_len*         length of valid bytes in response buffer if successful otherwise invalid.
  ----------------------- ----------------------- -------------------------------------------------------------------------------------------------------------


**Returns**


WM_SUCCESS in case of success.

WM_E_INBIG in case cmd_buf_len is bigger than the commands that can be handled by driver.

WM_E_INSMALL in case cmd_buf_len is smaller than the minimum length. Minimum length is at least the length of command header. see Note for same.

WM_E_OUTBIG in case the resp_buf_len is not sufficient to copy response from firmware. reqd_resp_len is updated with the response size.

WM_E_INVAL in case cmd_buf_len and resp_buf_len have invalid values.

WM_E_NOMEM in case cmd_buf, resp_buf and reqd_resp_len are NULL


**Note**


Brief on the command Header: Start 8 bytes of cmd_buf should have these values set. Firmware would update resp_buf with these 8 bytes at the start.

2 bytes : Command.

2 bytes : Size.

2 bytes : Sequence number.

2 bytes : Result.

Rest of buffer length is Command/Response Body.

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

##### int wlan_set_indrst_cfg (const wifi_indrst_cfg_t \* *indrst_cfg*)

Set GPIO independent reset configuration


**Parameters**


  ----------------------- ----------------------- -------------------------------------------------------------
  in                      *indrst_cfg*            GPIO independent reset configuration to be sent to firmware

  ----------------------- ----------------------- -------------------------------------------------------------


**Returns**


WM_SUCCESS if successful otherwise return -WM_FAIL.

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

##### int wlan_set_mgmt_ie (enum wlan_bss_type *bss_type*, IEEEtypes_ElementId_t *id*, void \* *buf*, unsigned int *buf_len*)

Set management IE for given BSS type (interface) and index.


**Parameters**


  ----------------------- ----------------------- ----------------------------
  in                      *bss_type*              0: STA, 1: uAP

  in                      *id*                    Type/ID of Management IE.

  in                      *buf*                   Buffer containing IE data.

  in                      *buf_len*               Length of IE data.
  ----------------------- ----------------------- ----------------------------


**Returns**


Management IE index if successful.

-WM_FAIL if unsuccessful.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### int wlan_set_region_code (unsigned int *region_code*)

Set region code.


**Parameters**


  ----------------------- ----------------------- ------------------------
  in                      *region_code*           region code to be set.

  ----------------------- ----------------------- ------------------------


**Returns**


WM_SUCCESS if successful otherwise fail.

> **Supported SoCs:** IW416, W8987, RW610, IW610, IW612


---

##### void wlan_set_sta_reconnect_in_hang (bool *flag*)

Set flag for reconnection in hang

This function sets the flag to reconnect to the same network before hang


**Parameters**


  ----------------------- ----------------------- -----------------------
  in                      *flag*                  set/reset flag

  ----------------------- ----------------------- -----------------------

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

##### void wlan_set_uap_restart_in_hang (bool *flag*)

Set flag to restart uap in hang

This function sets the flag to start the uap network with same settings before hang


**Parameters**


  ----------------------- ----------------------- -----------------------
  in                      *flag*                  set/reset flag

  ----------------------- ----------------------- -----------------------

> **Supported SoCs:** IW416, W8987, IW610, IW612


---

##### char\* wlan_string_dup (const char \* *s*)

Allocate memory for a string and copy the string to the allocated
memory

###### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>s</em></td>
<td>the source/target string</td>
</tr>
</tbody>
</table>

###### Returns

new string if successful, otherwise return -WM_FAIL.

##### uint32_t wlan_get_board_type (void )

Get board type.

###### Returns

board type. 0x02: RW610_PACKAGE_TYPE_BGA 0xFF: others

> **Supported SoCs:** RW610


---

