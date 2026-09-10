# Wi-Fi Driver API Reference Manual — FreeRTOS

> **OS:** FreeRTOS
> **Source file:** `wlan.h`
> **Supported SoCs:** IW416, RW612, IW610, IW612

---

## Main Page

### Introduction

NXP wireless SoCs require a combination of firmware binary image streamed into the radio
subsystem, and driver source code compiled onto the application MCU. The radio driver source
code provides APIs that enable a developer to send and receive packets over the radio interfaces
by communicating with the firmware images that are streamed into the radio subsystems on start-up.

This manual provides developer reference documentation for Wi-Fi driver and Wi-Fi Connection
Manager. Refer to the source code for additional information.

#### Supported SoC Summary

| SoC | Band | Max Channel Width | Wi-Fi Generation |
|-----|------|-------------------|-----------------|
| IW416 | 2.4/5 GHz | 20/40 MHz | Wi-Fi 4 (802.11n) |
| W8987 | 2.4/5 GHz | 20/40/80 MHz | Wi-Fi 5 (802.11ac) |
| RW612 | 2.4/5 GHz | 20 MHz | Wi-Fi 6 (802.11ax) |
| IW610 | 2.4/5 GHz | 20 MHz | Wi-Fi 6 (802.11ax) |
| IW612 | 2.4/5 GHz | 20/40/80 MHz | Wi-Fi 6 (802.11ax) |

#### Abbreviations and Acronyms

| Abbreviation | Description |
|---|---|
| ACS | Auto channel selection |
| AID | Association ID |
| AMI | Ambient motion index |
| AMPDU | Aggregate medium access control protocol data unit |
| AP | Access point |
| ARP | Address resolution protocol |
| BSS | Basic service set |
| BSSID | Basic service set ID |
| BTM | BSS transition management |
| CA | Certificate authority |
| CCK | Complementary code keying |
| CLI | Command line input |
| CSI | Channel state information |
| CW | Continuous wave |
| DH | Diffie-Hellman |
| DPP | Device provisioning protocol |
| DTIM | Delivery traffic indication map |
| EAP | Extensible authentication protocol |
| EAP TLS | Extensible authentication protocol transport layer security |
| FCS | Frame check sequence |
| FTM | Fine timing measurement |
| GI | Guard interval |
| HE | 802.11ax high efficiency |
| HT | 802.11n high throughput |
| HTC | High throughput control |
| LDPC | Low density parity check |
| MBO | Multi band operation |
| MEF | Memory efficient filtering |
| MFPC | Management frame protection capable |
| MFPR | Management frame protection required |
| MIMO | Multiple input multiple output |
| NAN | Neighbor awareness networking |
| NSS | N*N MIMO spatial stream |
| OBSS | Overlapping basic service set |
| OCE | Optimized connectivity experience |
| OMI | Operating mode indication |
| OWE | Opportunistic wireless encryption |
| P2P | Peer to peer |
| PBC | Push button configuration |
| PEAP | Protected extensible authentication protocol |
| PMF | Protected management frame |
| PMK | Pairwise master key |
| PMKSA | Pairwise master key security association |
| PS | Power-save |
| PTA | Packet traffic arbitration |
| PWE | Password element |
| QoS | Quality of service |
| RSSI | Received signal strength indicator |
| RTS | Request to send |
| SAD | Software antenna diversity |
| SAE | Simultaneous authentication of equals |
| SSID | Service set ID |
| STBC | Space time block code |
| TBTT | Target beacon transmission time |
| TIM | Traffic indication map |
| TSF | Timing synchronization function |
| TSP | Thermal safeguard protection |
| TWT | Target wake time |
| UAPSD | Unscheduled automatic Power-save delivery |
| VHT | 802.11ac very high throughput |
| WLCMGR | Wi-Fi connection manager |
| WLS | Wireless location service |
| WPS | Wi-Fi protected setup |

---

## File Index

| File | Description |
|------|-------------|
| `wlan.h` | This file provides Wi-Fi APIs for the application |

---

<div class="toc-block">
<h2>Table of Contents</h2>
<ul>
  <li><a href="#datastructures">Data Structures</a></li>
  <li><a href="#enumerations">Enumerations</a></li>
  <li><a href="#macros">Macros</a></li>
  <li><a href="#functions">Functions</a>
    <ul>
    <li><a href="#initializationlifecycle">Initialization & Lifecycle</a></li>
    <li><a href="#connectionmanagement">Connection Management</a></li>
    <li><a href="#networkmanagement">Network Management</a></li>
    <li><a href="#networkstatus">Network Status</a></li>
    <li><a href="#scan">Scan</a></li>
    <li><a href="#uapmicroaccesspoint">UAP (Micro Access Point)</a></li>
    <li><a href="#powermanagement">Power Management</a></li>
    <li><a href="#hostsleep">Host Sleep</a></li>
    <li><a href="#txpowerratecontrol">TX Power & Rate Control</a></li>
    <li><a href="#antennaconfiguration">Antenna Configuration</a></li>
    <li><a href="#channelbandconfiguration">Channel & Band Configuration</a></li>
    <li><a href="#80211axwifi6">802.11ax (Wi-Fi 6)</a></li>
    <li><a href="#80211acwifi5">802.11ac (Wi-Fi 5)</a></li>
    <li><a href="#80211nwifi4">802.11n (Wi-Fi 4)</a></li>
    <li><a href="#ampduaggregation">AMPDU & Aggregation</a></li>
    <li><a href="#wmmqos">WMM / QoS</a></li>
    <li><a href="#roaming80211krv">Roaming (802.11k/r/v)</a></li>
    <li><a href="#twttargetwaketime">TWT (Target Wake Time)</a></li>
    <li><a href="#wps">WPS</a></li>
    <li><a href="#dppdeviceprovisioningprotocol">DPP (Device Provisioning Protocol)</a></li>
    <li><a href="#wifidirectp2p">Wi-Fi Direct (P2P)</a></li>
    <li><a href="#nanneighborawarenessnetworking">NAN (Neighbor Awareness Networking)</a></li>
    <li><a href="#csichannelstateinformation">CSI (Channel State Information)</a></li>
    <li><a href="#ftm80211azranging">FTM / 802.11az Ranging</a></li>
    <li><a href="#mbomultibandoperation">MBO (Multi-Band Operation)</a></li>
    <li><a href="#mefmanagemententityfilter">MEF (Management Entity Filter)</a></li>
    <li><a href="#networkmonitor">Network Monitor</a></li>
    <li><a href="#edmaccontrol">ED MAC Control</a></li>
    <li><a href="#rfphyconfiguration">RF & PHY Configuration</a></li>
    <li><a href="#eventsubscription">Event Subscription</a></li>
    <li><a href="#managementframe">Management Frame</a></li>
    <li><a href="#securitycrypto">Security & Crypto</a></li>
    <li><a href="#wowlanwakeonwlan">WoWLAN (Wake on WLAN)</a></li>
    <li><a href="#cloudkeepalive">Cloud Keep-Alive</a></li>
    <li><a href="#stafiltermanagement">STA & Filter Management</a></li>
    <li><a href="#statisticsdiagnostics">Statistics & Diagnostics</a></li>
    <li><a href="#macaddress">MAC Address</a></li>
    <li><a href="#countryregion">Country / Region</a></li>
    <li><a href="#calibration">Calibration</a></li>
    <li><a href="#registeraccess">Register Access</a></li>
    <li><a href="#utilitymiscellaneous">Utility & Miscellaneous</a></li>
    </ul>
  </li>
</ul>
</div>

---

<a id="datastructures"></a>
## Data Structures

| Struct | Supported SoCs |
|--------|---------------|
| [`_Event_Radar_Detected_Info`](#eventradardetectedinfo) | All |
| [`ext_coex_pta_cfg`](#extcoexptacfg) | RW612 |
| [`ftm_11mc_nego_cfg_t`](#ftm11mcnegocfgt) | IW612 |
| [`ipv4_config`](#ipv4config) | All |
| [`ipv6_config`](#ipv6config) | All |
| [`location_cfg_info_t`](#locationcfginfot) | IW612 |
| [`location_civic_rep_t`](#locationcivicrept) | IW612 |
| [`ranging_11az_cfg_t`](#ranging11azcfgt) | IW612 |
| [`rx_pkt_he_rate_info`](#rxpktherateinfo) | All |
| [`rx_pkt_ht_rate_info`](#rxpkthtrateinfo) | All |
| [`rx_pkt_rate_info`](#rxpktrateinfo) | All |
| [`rx_pkt_vht_rate_info`](#rxpktvhtrateinfo) | All |
| [`tx_ampdu_prot_mode_para`](#txampduprotmodepara) | RW612, IW610 |
| [`tx_pkt_he_rate_info`](#txpktherateinfo) | All |
| [`tx_pkt_ht_rate_info`](#txpkthtrateinfo) | All |
| [`tx_pkt_rate_info`](#txpktrateinfo) | All |
| [`tx_pkt_vht_rate_info`](#txpktvhtrateinfo) | All |
| [`wifi_scan_params_t`](#wifiscanparamst) | All |
| [`wlan_cck_desense_cfg`](#wlancckdesensecfg) | RW612, IW610 |
| [`wlan_cipher`](#wlancipher) | All |
| [`wlan_csi_proc_cfg`](#wlancsiproccfg) | RW612 |
| [`wlan_diag`](#wlandiag) | All |
| [`wlan_ieeeps_config`](#wlanieeepsconfig) | All |
| [`wlan_ip_config`](#wlanipconfig) | All |
| [`wlan_message`](#wlanmessage) | All |
| [`wlan_nan_publish_params_t`](#wlannanpublishparamst) | RW612 |
| [`wlan_nan_subscribe_params_t`](#wlannansubscribeparamst) | RW612 |
| [`wlan_network`](#wlannetwork) | All |
| [`wlan_network_security`](#wlannetworksecurity) | All |
| [`wlan_rx_abort_cfg`](#wlanrxabortcfg) | RW612, IW610 |
| [`wlan_rx_abort_cfg_ext`](#wlanrxabortcfgext) | RW612, IW610 |
| [`wlan_scan_result`](#wlanscanresult) | All |
| [`wlan_tx_pert_info`](#wlantxpertinfo) | RW612 |
| [`wlan_txrx_histogram_info`](#wlantxrxhistograminfo) | All |

---

### Data Structure Documentation

<a id="eventradardetectedinfo"></a>
### `_Event_Radar_Detected_Info`

| Field | Type | Description |
|-------|------|-------------|
| `detect_count` | `t_u32` | Radar detection count. |
| `reg_domain` | `t_u8` | Regulatory domain: 1=fcc, 2=etsi, 3=mic. |
| `main_det_type` | `t_u8` | Main detection type: 0=none, 1=pw(chirp), 2=pri(radar). |
| `pw_chirp_type` | `t_u16` | Pulse width chirp type. |
| `pw_chirp_idx` | `t_u8` | Pulse width chirp index. |
| `pw_value` | `t_u8` | Pulse width value. |
| `pri_radar_type` | `t_u8` | Primary radar type. |
| `pri_binCnt` | `t_u8` | Primary radar binary counter count. |
| `binCounter` | `t_u8` | Binary counter array. |
| `numDfsRecords` | `t_u8` | Number of DFS records. |
| `dfsRecordHdrs` | `t_u8` | DFS record header array. |
| `reallyPassed` | `t_u32` | Actual elapsed time in milliseconds. |

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="extcoexptacfg"></a>
### `ext_coex_pta_cfg`

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | `t_u8` | Enable: 0x01, Disable: 0x00. |
| `ext_WifiBtArb` | `t_u8` | Enable extended Wi-Fi and Bluetooth LE arbitration: 0x01, Disable: 0x00. |
| `polGrantPin` | `t_u8` | Active high: 0x00, Active low: 0x01. |
| `enable_PriPtaInt` | `t_u8` | Enable PriPtaInt: 0x01, Disable PriPtaInt: 0x00. |
| `enable_StatusFromPta` | `t_u8` | State input disable: 0x00, State info is from state pin: 0x01, State info is sampled on priority pin: 0x02. |
| `setPriSampTiming` | `t_u16` | Timing to sample Priority bit. |
| `setStateInfoSampTiming` | `t_u16` | Timing to sample TX/RX info. |
| `extRadioTrafficPrio` | `t_u8` | Enable external traffic TX/RX Priority: 0x01, Disable: 0x00. |
| `extCoexHwIntWci2` | `t_u8` | Enable wci-2 interface: 0x01, Disable wci-2 interface: 0x00. |

External coexistence PTA (Packet Traffic Arbitration) configuration

---

> **Supported SoCs:** RW612

---

<a id="ftm11mcnegocfgt"></a>
### `ftm_11mc_nego_cfg_t`

| Field | Type | Description |
|-------|------|-------------|
| `burst_exponent` | `t_u8` | Indicates how many burst instances are requested for the FTM session. |
| `burst_duration` | `t_u8` | Indicates the duration of a burst instance. |
| `min_delta_FTM` | `t_u8` | Minimum time between consecutive FTM frames. |
| `is_ASAP` | `t_u8` | ASAP/non-ASAP case. |
| `per_burst_FTM` | `t_u8` | Number of FTMs per burst. |
| `channel_spacing` | `t_u8` | FTM channel spacing: HT20/HT40/VHT80/... |
| `burst_period` | `t_u16` | Indicates the interval between two consecutive burst instances. |

Structure of FTM_SESSION_CFG TLV data

---

> **Supported SoCs:** IW612

---

<a id="ipv4config"></a>
### `ipv4_config`

| Field | Type | Description |
|-------|------|-------------|
| `addr_type` | `enum address_types` | Set to ADDR_TYPE_DHCP to use DHCP to obtain the IP address or set to ADDR_TYPE_STATIC to use a static IP. In case of static IP address ip, gw, netmask and dns members should be specified. When using DHCP, the ip, gw, netmask and dns are overwritten by the values obtained from the DHCP server. They should be zeroed out if not used. |
| `address` | `unsigned` | The IP address of the system in network order. |
| `gw` | `unsigned` | The default gateway of the system in network order. |
| `netmask` | `unsigned` | The subnet mask of the system in network order. |
| `dns1` | `unsigned` | The primary DNS server of the system in network order. |
| `dns2` | `unsigned` | The secondary DNS server of the system in network order. |

This data structure represents an IPv4 address

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="ipv6config"></a>
### `ipv6_config`

| Field | Type | Description |
|-------|------|-------------|
| `address` | `unsigned` | The IPv6 address of the system in network order. |
| `addr_type` | `unsigned char` | The address type: linklocal, site-local or global. |
| `addr_state` | `uint8_t` | The state of IPv6 address (Tentative, Preferred, and so on). |

This data structure represents an IPv6 address

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="locationcfginfot"></a>
### `location_cfg_info_t`

| Field | Type | Description |
|-------|------|-------------|
| `lat_unc` | `t_u8` | Known latitude uncertainty. |
| `long_unc` | `t_u8` | Known longitude uncertainty. |
| `alt_unc` | `t_u8` | Known altitude uncertainty. |
| `lci_req` | `t_u8` | Include LCI request (expect LCI information from the responder). |
| `longitude` | `double` | Known longitude. |
| `latitude` | `double` | Known latitude. |
| `altitude` | `double` | Known altitude. |

LCI (Location configuration information) data for 802.11az ranging

---

> **Supported SoCs:** IW612

---

<a id="locationcivicrept"></a>
### `location_civic_rep_t`

| Field | Type | Description |
|-------|------|-------------|
| `civic_location_type` | `t_u8` | Civic location type. |
| `civic_address_type` | `t_u8` | Civic address type. |
| `civic_address_length` | `t_u8` | Civic address length. |
| `civic_req` | `t_u8` | Include an LCI request (Expect LCI info from the responder). |
| `country_code` | `t_u16` | Country code. |

Civic location report for 802.11az ranging

---

> **Supported SoCs:** IW612

---

<a id="ranging11azcfgt"></a>
### `ranging_11az_cfg_t`

| Field | Type | Description |
|-------|------|-------------|
| `format_bw` | `t_u8` | Indicates the channel BW for the session. <br>• 0: HE20. <br>• 1: HE40. <br>• 2: HE80. <br>• 3: HE80+80. <br>• 4: HE160. <br>• 5: HE160_SRF. |
| `max_i2r_sts_upto80` | `t_u8` | Indicates for bandwidths less than or equal to 80 MHz the maximum number of space-time streams to be used in DL/UL NDP frames in the session. |
| `max_r2i_sts_upto80` | `t_u8` | Indicates for bandwidths less than or equal to 80 MHz the maximum number of space-time streams to be used in DL/UL NDP frames in the session. |
| `az_measurement_freq` | `t_u8` | Specifies the measurement frequency in Hz to calculate the measurement interval. |
| `az_number_of_measurements` | `t_u8` | Indicates the number of measurements to be done for the session. |
| `i2r_lmr_feedback` | `t_u8` | Initiator lmr feedback. |
| `civic_req` | `t_u8` | Include location civic request (Expect location civic from responder). |
| `lci_req` | `t_u8` | Include an LCI request (Expect LCI info from the responder). |

Structure of FTM_SESSION_CFG_NTB_RANGING/FTM_SESSION_CFG_TB_RANGING TLV data

---

> **Supported SoCs:** IW612

---

<a id="rxpktherateinfo"></a>
### `rx_pkt_he_rate_info`

| Field | Type | Description |
|-------|------|-------------|
| `hemcs_rxcnt` | `t_u32` | Sum of RX packets for HE rate. The array index represents MCS0~MCS11, the following array indexes have the same effect. |
| `hestbcrate_rxcnt` | `t_u32` | Sum of RX STBC (space time block code) packets for HE rate. |

Sum of RX packets for HE (802.11ax high efficiency) rate

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="rxpkthtrateinfo"></a>
### `rx_pkt_ht_rate_info`

| Field | Type | Description |
|-------|------|-------------|
| `htmcs_rxcnt` | `t_u32` | Sum of RX packets for HT rate. The array index represents MCS0~MCS15, the following array indexes have the same effect. |
| `htsgi_rxcnt` | `t_u32` | Sum of TX short GI (guard interval) packets for HT rate. |
| `htstbcrate_rxcnt` | `t_u32` | Sum of TX STBC (space time block code) packets for HT rate. |

Sum of RX packets for HT (802.11n high throughput) rate

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="rxpktrateinfo"></a>
### `rx_pkt_rate_info`

| Field | Type | Description |
|-------|------|-------------|
| `nss_rxcnt` | `t_u32` | Sum of RX NSS (N*N MIMO spatial stream) packets. nss_txcnt[0] is for NSS 1, nss_txcnt[1] is for NSS 2. |
| `nsts_rxcnt` | `t_u32` | Sum of received packets for all STBC rates. |
| `bandwidth_rxcnt` | `t_u32` | Sum of received packets for three bandwidth types. bandwidth_rxcnt[0] is for 20 MHz, bandwidth_rxcnt[1] is for 40 MHz, bandwidth_rxcnt[2] is for 80 MHz. |
| `preamble_rxcnt` | `t_u32` | Sum of received packets for four preamble format types. preamble_txcnt[0] is for preamble format 0, preamble_txcnt[1] is for preamble format 1, preamble_txcnt[2] is for preamble format 2, preamble_txcnt[3] is for preamble format 3, preamble_txcnt[4] and preamble_txcnt[5] are as reserved. |
| `ldpc_txbfcnt` | `t_u32` | Sum of packets for TX LDPC packets. |
| `rssi_value` | `t_s32` | Average RSSI. |
| `rssi_chain0` | `t_s32` | RSSI value of path A. |
| `rssi_chain1` | `t_s32` | RSSI value of path B. |

Sum of RX packets

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="rxpktvhtrateinfo"></a>
### `rx_pkt_vht_rate_info`

| Field | Type | Description |
|-------|------|-------------|
| `vhtmcs_rxcnt` | `t_u32` | Sum of RX packets for VHT rate. The array index represents MCS0~MCS9, the following array indexes have the same effect. |
| `vhtsgi_rxcnt` | `t_u32` | Sum of RX short GI (guard interval) packets for VHT rate. |
| `vhtstbcrate_rxcnt` | `t_u32` | Sum of RX STBC (space time block code) packets for VHT rate. |

Sum of RX packets for VHT (802.11ac very high throughput) rate

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="txampduprotmodepara"></a>
### `tx_ampdu_prot_mode_para`

| Field | Type | Description |
|-------|------|-------------|
| `mode` | `int` | TX AMPDU protection mode. <br>• 0: Set RTS/CTS mode. <br>• 1: Set CTS to self mode. <br>• 2: Disable protection mode. <br>• 3: Set dynamic RTS/CTS mode. |

Set the protection mode for the transmit AMPDU packet

---

> **Supported SoCs:** RW612, IW610

---

<a id="txpktherateinfo"></a>
### `tx_pkt_he_rate_info`

| Field | Type | Description |
|-------|------|-------------|
| `hemcs_txcnt` | `t_u32` | Sum of TX packets for HE rate. The array index represents MCS0~MCS11, the following array indexes have the same effect. |
| `hestbcrate_txcnt` | `t_u32` | Sum of TX STBC (space time block code) packets for HE rate. |

Sum of TX packets for HE (802.11ax high efficiency) rate

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="txpkthtrateinfo"></a>
### `tx_pkt_ht_rate_info`

| Field | Type | Description |
|-------|------|-------------|
| `htmcs_txcnt` | `t_u32` | Sum of TX packets for HT rate. The array index represents MCS0~MCS15, the following array indexes have the same effect. |
| `htsgi_txcnt` | `t_u32` | Sum of TX short GI (guard interval) packets for HT rate. |
| `htstbcrate_txcnt` | `t_u32` | Sum of TX STBC (space time block code) packets for HT rate. |

Sum of TX packets for HT (802.11n high throughput) rate

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="txpktrateinfo"></a>
### `tx_pkt_rate_info`

| Field | Type | Description |
|-------|------|-------------|
| `nss_txcnt` | `t_u32` | Sum of TX NSS (N*N MIMO spatial stream) packets. nss_txcnt[0] is for NSS 1, nss_txcnt[1] is for NSS 2. |
| `bandwidth_txcnt` | `t_u32` | Sum of TX packets for three bandwidths. bandwidth_txcnt[0] is for 20 MHz, bandwidth_txcnt[1] is for 40 MHz, bandwidth_txcnt[2] is for 80 MHz. |
| `preamble_txcnt` | `t_u32` | Sum of RX packets for four preamble format types. preamble_txcnt[0] is for preamble format 0, preamble_txcnt[1] is for preamble format 1, preamble_txcnt[2] is for preamble format 2, preamble_txcnt[3] is for preamble format 3,. |
| `ldpc_txcnt` | `t_u32` | Sum of TX LDPC (low-density parity check) packets. |
| `rts_txcnt` | `t_u32` | Sum of TX RTS (request to send) packets. |
| `ack_RSSI` | `t_s32` | RSSI of ACK packet. |

Sum of TX packets

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="txpktvhtrateinfo"></a>
### `tx_pkt_vht_rate_info`

| Field | Type | Description |
|-------|------|-------------|
| `vhtmcs_txcnt` | `t_u32` | Sum of TX packets for VHT rate. The array index represents MCS0~MCS9, the following array indexes have the same effect. |
| `vhtsgi_txcnt` | `t_u32` | Sum of TX short GI packets for HT mode. |
| `vhtstbcrate_txcnt` | `t_u32` | Sum of TX STBC (space time block code) packets for VHT mode. |

Sum of TX packets for VHT (802.11ac very high throughput) rate

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wifiscanparamst"></a>
### `wifi_scan_params_t`

| Field | Type | Description |
|-------|------|-------------|
| `bssid` | `uint8_t *` | BSSID (basic service set ID). |
| `ssid` | `char *` | SSID (service set ID). |
| `channel` | `int` | Channel list. |
| `bss_type` | `IEEEtypes_Bss_t` | BSS (basic service set) type. <br>• 1: Infrastructure BSS. <br>• 2: Independent BSS. |
| `scan_duration` | `int` | Time for scan duration. |
| `split_scan_delay` | `int` | Split scan delay. |

This structure is used to configure Wi-Fi scan parameters

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlancckdesensecfg"></a>
### `wlan_cck_desense_cfg`

| Field | Type | Description |
|-------|------|-------------|
| `mode` | `t_u16` | CCK (complementary code keying) desense mode. <br>• 0: Disable. <br>• 1: Normal. <br>• 2: Dynamic. |
| `margin` | `int` | Specifies the RSSI margin. |
| `ceil_thresh` | `int` | Specifies ceil RSSI threshold. |
| `num_on_intervals` | `int` | CCK (complementary code keying) desense "on" interval count. |
| `num_off_intervals` | `int` | CCK desense "off" interval count. |

CCK (Complementary Code Keying) desensitization configuration

---

> **Supported SoCs:** RW612, IW610

---

<a id="wlancipher"></a>
### `wlan_cipher`

| Field | Type | Description |
|-------|------|-------------|
| `none` | `uint16_t` | 1 bit value can be set for none. |
| `wep40` | `uint16_t` | 1 bit value can be set for wep40. |
| `wep104` | `uint16_t` | 1 bit value can be set for wep104. |
| `tkip` | `uint16_t` | 1 bit value can be set for tkip. |
| `ccmp` | `uint16_t` | 1 bit value can be set for ccmp. |
| `aes_128_cmac` | `uint16_t` | 1 bit value can be set for aes 128 cmac. |
| `gcmp` | `uint16_t` | 1 bit value can be set for gcmp. |
| `sms4` | `uint16_t` | 1 bit value can be set for sms4. |
| `gcmp_256` | `uint16_t` | 1 bit value can be set for gcmp 256. |
| `ccmp_256` | `uint16_t` | 1 bit value can be set for ccmp 256. |
| `rsvd` | `uint16_t` | 1 bit is reserved. |
| `bip_gmac_128` | `uint16_t` | 1 bit value can be set for bip gmac 128. |
| `bip_gmac_256` | `uint16_t` | 1 bit value can be set for bip gmac 256. |
| `bip_cmac_256` | `uint16_t` | 1 bit value can be set for bip cmac 256. |
| `gtk_not_used` | `uint16_t` | 1 bit value can be set for gtk not used. |
| `rsvd2` | `uint16_t` | 4 bits are reserved. |

Wi-Fi cipher structure

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlancsiproccfg"></a>
### `wlan_csi_proc_cfg`

| Field | Type | Description |
|-------|------|-------------|
| `peer_mac` | `uint8_t` | Peer mac address. |
| `num_csi` | `uint8_t` | Number of CSI to process. |
| `packet_bandwidth` | `uint8_t` | CSI bandwidth: 20/40/80. |
| `packet_format` | `uint8_t` | CSI format: legacy/HT/VHT/HE. |
| `reference_update` | `uint8_t` | Reference Update. |

CSI (Channel state information) ambient motion index processing configuration

---

> **Supported SoCs:** RW612

---

<a id="wlandiag"></a>
### `wlan_diag`

| Field | Type | Description |
|-------|------|-------------|
| `hw_exception_count` | `uint32_t` | Number of hardware exceptions detected by the Wi-Fi driver; reserved, always 0. |
| `disconnection_count` | `uint32_t` | Number of disconnection events since driver initialization. |
| `disconnection_dur_sec` | `uint32_t` | Duration in seconds that the Wi-Fi interface has been in a disconnected state. |

Wi-Fi diagnostic statistics

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanieeepsconfig"></a>
### `wlan_ieeeps_config`

| Field | Type | Description |
|-------|------|-------------|
| `ps_null_interval` | `t_u32` | The interval that STA sends a null packet. |
| `multiple_dtim_interval` | `t_u32` | The count of listen interval. |
| `listen_interval` | `t_u32` | Periodic interval that STA listens to AP beacons. |
| `adhoc_awake_period` | `t_u32` | Periodic awake period for adhoc networks. |
| `bcn_miss_timeout` | `t_u32` | Beacon miss timeout in milliseconds. |
| `delay_to_ps` | `t_s32` | The delay of enabling IEEE-PS in milliseconds. |
| `ps_mode` | `t_u32` | PS mode <br>• 1: PS-auto mode. <br>• 2: PS-poll mode. <br>• 3: PS-null mode. |

This structure is for IEEE PS (Power-save) configuration

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanipconfig"></a>
### `wlan_ip_config`

| Field | Type | Description |
|-------|------|-------------|
| `ipv6` | `struct ipv6_config` | The network IPv6 address configuration that must be associated with this interface. |
| `ipv6_count` | `size_t` | The network IPv6 valid addresses count. |
| `ipv4` | `struct ipv4_config` | The network IPv4 address configuration that must be associated with this interface. |

Network IP configuration.
This data structure represents the network IP configuration for IPv4 as well as IPv6 addresses

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanmessage"></a>
### `wlan_message`

| Field | Type | Description |
|-------|------|-------------|
| `id` | `t_u16` | Message ID used to identify the message type. |
| `data` | `void *` | Message data pointer pointing to the data buffer associated with the message. |

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlannanpublishparamst"></a>
### `wlan_nan_publish_params_t`

| Field | Type | Description |
|-------|------|-------------|
| `service_name` | `char *` | Service name for NAN. |
| `ttl` | `unsigned int` | Time to live (in seconds); 0 = one TX only. |
| `freq` | `unsigned int` | Default frequency (defaultPublishChannel). |
| `freq_list` | `char *` | Multi-channel frequencies. |
| `srv_proto_type` | `nan_service_protocol_type_t` | NAN service protocol type. |
| `ssi` | `char *` | Service specific information (hexdump). |

This structure is used to configure wlan nan publish parameters

---

> **Supported SoCs:** RW612

---

<a id="wlannansubscribeparamst"></a>
### `wlan_nan_subscribe_params_t`

| Field | Type | Description |
|-------|------|-------------|
| `service_name` | `char *` | Service name for NAN. |
| `active` | `bool` | Subscribe type: true = active subscribe, false = passive subscribe. |
| `ttl` | `unsigned int` | Time to live (in seconds); 0 = until first result. |
| `freq` | `unsigned int` | Selected frequency. |
| `srv_proto_type` | `nan_service_protocol_type_t` | NAN service protocol type. |
| `ssi` | `char *` | Service specific information (hexdump). |

This structure is used to configure wlan nan subscribe parameters

---

> **Supported SoCs:** RW612

---

<a id="wlannetwork"></a>
### `wlan_network`

| Field | Type | Description |
|-------|------|-------------|
| `id` | `int` | Identifier for network profile. |
| `wps_network` | `int` | WPS network flag. |
| `unspecified_network` | `int` | Unspecified network flag. |
| `name` | `char` | The name of this network profile. Each network profile that is added to the Wi-Fi connection manager must have a unique name. |
| `ssid` | `char` | The network SSID, represented as a C string of up to 32 characters in length. If this profile is used in the uAP mode, this field is used as the SSID of the network. If this profile is used in the station mode, this field is used to identify the network. Sets the first byte of the SSID to NULL (a 0-length string) to use only the BSSID to find the network. |
| `bssid` | `char` | The network BSSID, represented as a 6-byte array. If this profile is used in the uAP mode, this field is ignored. If this profile is used in the station mode, this field is used to identify the network. Sets all 6 bytes to 0 to use any BSSID, in which case only the SSID is used to find the network. |
| `channel` | `unsigned int` | The channel for this network. |
| `sec_channel_offset` | `uint8_t` | The secondary channel offset *. |
| `acs_band` | `uint16_t` | The ACS (auto channel selection) band if channel is set to 0. |
| `chan_list` | `uint8_t` | Array of channel list to scan or NULL for all. |
| `chan_list_len` | `uint8_t` | Number of channels in the channel list. |
| `rssi` | `int` | RSSI (received signal strength indicator) value. |
| `rssi_threshold` | `short` | Specifies RSSI threshold (dBm) for scan. |
| `select_policy` | `enum wlan_select_policy` | Network selection policy. |
| `priority` | `int` | Priority group. |
| `ssid_protection` | `bool` | SSID protection enabled flag. |
| `ht_capab` | `unsigned short` | HT capabilities info field within HT capabilities information element. |
| `vht_capab` | `unsigned int` | VHT capabilities info field within VHT capabilities information element. |
| `vht_oper_chwidth` | `unsigned char` | VHT bandwidth. |
| `he_oper_chwidth` | `unsigned char` | HE bandwidth. |
| `type` | `enum wlan_bss_type` | BSS type. |
| `role` | `enum wlan_bss_role` | The network Wi-Fi mode enum wlan_bss_role. Set this to specify what type of Wi-Fi network mode to use. This can either be WLAN_BSS_ROLE_STA for use in the station mode, or it can be WLAN_BSS_ROLE_UAP for use in the uAP mode. |
| `security` | `struct wlan_network_security` | The network security configuration specified by struct wlan_network_security for the network. |
| `ip` | `struct wlan_ip_config` | The network IP address configuration specified by struct wlan_ip_config that must be associated with this interface. |
| `ssid_specific` | `unsigned` | If set to 1, the ssid field contains the specific SSID for this network. the Wi-Fi connection manager can only connect to networks with matching SSID matches. If set to 0, the ssid field contents are not used when deciding whether to connect to a network or not. The BSSID field is used instead and any network with matching BSSID matches is accepted. |
| `trans_ssid_specific` | `unsigned` | If set to 1, the ssid field contains the transitional SSID for this network. |
| `bssid_specific` | `unsigned` | If set to 1, the bssid field contains the specific BSSID for this network. The Wi-Fi connection manager cannot connect to any other network with the same SSID unless the BSSID matches. If set to 0, the Wi-Fi connection manager can connect to any network whose SSID matches. |
| `channel_specific` | `unsigned` | If set to 1, the channel field contains the specific channel for this network. The Wi-Fi connection manager cannot look for this network on any other channel. If set to 0, the Wi-Fi connection manager can look for this network on any available channel. |
| `security_specific` | `unsigned` | If set to 0, any security that matches is used. This field is internally set when the security type parameter above is set to WLAN_SECURITY_WILDCARD. |
| `priority_specific` | `unsigned` | If set to 1, the priority field contains the specific priority for this network. This field can be used to change the order in which wpa_supplicant goes through the networks when selecting a BSS. If set to 0, all networks will get same priority group (0). |
| `ssid_protect_specific` | `unsigned` | If set to 1, the SSID protection of 4-way handshake will be enabled. |
| `dot11n` | `unsigned` | The network supports 802.11n. |
| `dot11ac` | `unsigned` | The network supports 802.11ac. |
| `dot11ax` | `unsigned` | The network supports 802.11ax. |
| `__pad0__` | `unsigned` |  |
| `ft_1x` | `unsigned` | The network uses FT 802.1x security. |
| `ft_psk` | `unsigned` | The network uses FT PSK security. |
| `ft_sae` | `unsigned` | The network uses FT SAE security. |
| `reserved5` | `unsigned` | Reserved. |
| `mdid` | `uint16_t` | Mobility Domain ID. |
| `owe_trans_mode` | `unsigned int` | OWE (opportunistic wireless encryption) Transition mode. |
| `trans_ssid` | `char` | The network transitional SSID, represented as a C string of up to 32 characters in length. |
| `trans_ssid_len` | `unsigned int` | Transitional SSID length. |
| `beacon_period` | `uint16_t` | Beacon period of associated BSS. |
| `dtim_period` | `uint8_t` | DTIM period of associated BSS. |
| `btm_mode` | `uint8_t` | BTM mode. |
| `bss_transition_supported` | `bool` | BSS transition support. |
| `neighbor_report_supported` | `bool` | Neighbor report support. |
| `twt_capab` | `bool` | TWT (Target Wake Time) capability flag indicating whether the associated BSS supports TWT. |

Wi-Fi network profile
This data structure represents a Wi-Fi network profile. It consists of an arbitrary name, Wi-Fi configuration, and IP address configuration.
Every network profile is associated with one of the two interfaces. The network profile can be used for the station interface (i.e. to connect to an Access Point) by setting the role field to WLAN_BSS_ROLE_STA. The network profile can be used for the uAP interface (that is, to start its own network) by setting the mode field to WLAN_BSS_ROLE_UAP.
If the mode field is WLAN_BSS_ROLE_STA, either of the SSID or BSSID fields are used to identify the network, while the other members like channel and security settings characterize the network.
If the mode field is WLAN_BSS_ROLE_UAP, the SSID, channel, and security fields are used to define the network to be started.
In both the above cases, the address field is used to determine the type of address assignment to be used for this interface.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlannetworksecurity"></a>
### `wlan_network_security`

| Field | Type | Description |
|-------|------|-------------|
| `type` | `enum wlan_security_type` | Type of network security to use. Specified by the enum wlan_security_type. |
| `key_mgmt` | `int` | Key management type. |
| `mcstCipher` | `struct wlan_cipher` | Type of network security Group Cipher suite. |
| `ucstCipher` | `struct wlan_cipher` | Type of network security Pairwise Cipher suite. |
| `pkc` | `unsigned` | Proactive key caching. |
| `group_cipher` | `int` | Type of network security Group Cipher suite. |
| `pairwise_cipher` | `int` | Type of network security Pairwise Cipher suite. |
| `group_mgmt_cipher` | `int` | Type of network security Pairwise Cipher suite. |
| `is_pmf_required` | `bool` | Use when PMF (protected management frame) is required. |
| `psk` | `char` | Pre-shared key (network password). For WEP networks this is a hex byte sequence of length psk_len, for WPA and WPA2 networks this is an ASCII pass-phrase of length psk_len. This field is ignored for networks with no security. |
| `psk_len` | `uint8_t` | Length of the WEP key or WPA/WPA2 pass phrase, WLAN_PSK_MIN_LENGTH to WLAN_PSK_MAX_LENGTH. Ignored for networks with no security. |
| `password` | `char` | WPA3 SAE password, for WPA3 SAE networks this is an ASCII password of length password_len. This field is ignored for networks with no security. |
| `password_len` | `size_t` | Length of the WPA3 SAE Password, WLAN_PASSWORD_MIN_LENGTH to WLAN_PASSWORD_MAX_LENGTH. Ignored for networks with no security. |
| `sae_groups` | `char *` | Preference list of enabled groups for SAE. By default (if this parameter is not set), the mandatory group 19 (ECC group defined over a 256-bit prime order field) is preferred, but other groups are also enabled. If this parameter is set, the groups are tried in the indicated order. |
| `pwe_derivation` | `uint8_t` | SAE (Simultaneous authentication of equals) mechanism for PWE (Password Element) derivation. |
| `transition_disable` | `uint8_t` | Transition Disable indication. |
| `owe_groups` | `char *` | OWE Groups. |
| `pmk` | `char` | PMK (pairwise master key). When pmk_valid is set, this is the PMK calculated from the PSK for WPA/PSK networks. If pmk_valid is not set, this field is ignored. When adding networks with wlan_add_network, users can initialize PMK and set pmk_valid instead of setting the psk. After successfully connecting to a WPA/PSK network, users can call wlan_get_current_network to inspect pmk_valid and pmk. Therefore, the pmk value can be populated in subsequent calls to wlan_add_network. This saves the CPU time required to otherwise calculate the PMK. |
| `pmk_valid` | `bool` | Flag reports whether PMK is valid or not. |
| `mfpc` | `int8_t` | Management frame protection capable (MFPC). |
| `mfpr` | `int8_t` | Management frame protection required (MFPR). |
| `wpa3_ent` | `unsigned` | WPA3 Enterprise mode. |
| `wpa3_sb` | `unsigned` | WPA3 Enterprise Suite B mode. |
| `wpa3_sb_192` | `unsigned` | WPA3 Enterprise Suite B 192 mode. |
| `eap_ver` | `unsigned` | EAP (Extensible Authentication Protocol) version. |
| `peap_label` | `unsigned` | PEAP (Protected Extensible Authentication Protocol) label. |
| `eap_crypto_binding` | `uint8_t` | crypto_binding option can be used to control WLAN_SECURITY_EAP_PEAP_MSCHAPV2, WLAN_SECURITY_EAP_PEAP_TLS and WLAN_SECURITY_EAP_PEAP_GTC version 0 cryptobinding behavior: 0 = do not use cryptobinding (default) 1 = use cryptobinding if the server supports it 2 = require cryptobinding. |
| `eap_result_ind` | `unsigned` | eap_result_ind=1 can be used to enable WLAN_SECURITY_EAP_SIM, WLAN_SECURITY_EAP_AKA and WLAN_SECURITY_EAP_AKA_PRIME to use protected result indication. |
| `tls_cipher` | `unsigned char` | Cipher for EAP TLS (Extensible Authentication Protocol Transport Layer Security). |
| `identity` | `char` | Identity string for EAP. |
| `anonymous_identity` | `char` | Anonymous identity string for EAP. |
| `eap_password` | `char` | Password string for the EAP. |
| `verify_peer_cert` | `bool` | whether verify peer with CA or not false: not verify, true: verify. |
| `ca_cert_data` | `unsigned char *` | CA (certificate authority) certification blob (binary large object) in PEM (Base64 ASCII)/DER (binary) format. |
| `ca_cert_len` | `size_t` | CA (certificate authority) certification blob (binary large object) length. |
| `client_cert_data` | `unsigned char *` | Client certification blob (Binary Large Object) in PEM (Base64 ASCII)/DER (binary) format. |
| `client_cert_len` | `size_t` | Client certification blob (Binary Large Object) length. |
| `client_key_data` | `unsigned char *` | Client key blob (Binary Large Object). |
| `client_key_len` | `size_t` | Client key blob (Binary Large Object) length. |
| `client_key_passwd` | `char` | Client key password. |
| `ca_cert_hash` | `char` | CA certification Hash. |
| `domain_match` | `char` | Domain. |
| `domain_suffix_match` | `char` | Domain Suffix. |
| `ca_cert2_data` | `unsigned char *` | CA (certificate authority) certification blob (binary large object) in PEM (Base64 ASCII)/DER (binary) format for phase two. |
| `ca_cert2_len` | `size_t` | CA (certificate authority) certification blob (binary large object) length for phase two. |
| `client_cert2_data` | `unsigned char *` | Client certification blob (Binary Large Object) in PEM (Base64 ASCII)/DER (binary) format for phase two. |
| `client_cert2_len` | `size_t` | Client certification blob (Binary Large Object) length for phase two. |
| `client_key2_data` | `unsigned char *` | Client key blob (Binary Large Object) for phase two. |
| `client_key2_len` | `size_t` | Client key blob (Binary Large Object) length for phase two. |
| `client_key2_passwd` | `char` | Client key password for phase two. |
| `dh_data` | `unsigned char *` | DH (Diffie Hellman) parameters blob (Binary Large Object). |
| `dh_len` | `size_t` | DH (Diffie Hellman) parameters blob (Binary Large Object) length. |
| `server_cert_data` | `unsigned char *` | Server certification blob (Binary Large Object) in PEM (Base64 ASCII)/DER (binary) format. |
| `server_cert_len` | `size_t` | Server certification blob (Binary Large Object) length. |
| `server_key_data` | `unsigned char *` | Server key blob (Binary Large Object). |
| `server_key_len` | `size_t` | Server key blob (Binary Large Object) length. |
| `server_key_passwd` | `char` | Server key password. |
| `nusers` | `size_t` | Number of EAP users. |
| `identities` | `char` | User Identities. |
| `passwords` | `char` | User Passwords. |
| `pac_opaque_encr_key` | `char` | Encryption key for EAP-FAST PAC-Opaque values. |
| `a_id` | `char` | EAP-FAST authority identity (A-ID). |
| `fast_prov` | `uint8_t` | EAP-FAST provisioning modes: 0 = provisioning disabled 1 = only anonymous provisioning allowed 2 = only authenticated provisioning allowed 3 = both provisioning modes allowed (default). |
| `dpp_connector` | `unsigned char *` | DPP (device provisioning protocol) connector for DPP network access credentials. |
| `dpp_c_sign_key` | `unsigned char *` | DPP configurator sign key used to verify DPP configuration objects. |
| `dpp_net_access_key` | `unsigned char *` | DPP network access key used for DPP network connection authentication. |

Network security configuration

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanrxabortcfg"></a>
### `wlan_rx_abort_cfg`

| Field | Type | Description |
|-------|------|-------------|
| `enable` | `t_u8` | Enable/Disable RX abort configuration. |
| `rssi_threshold` | `int` | RX weak RSSI threshold. |

RX abort configuration for weak signal rejection

---

> **Supported SoCs:** RW612, IW610

---

<a id="wlanrxabortcfgext"></a>
### `wlan_rx_abort_cfg_ext`

| Field | Type | Description |
|-------|------|-------------|
| `enable` | `int` | Enables or disables dyn RX abort on weak packet RSSI. |
| `rssi_margin` | `int` | Specifies the RSSI margin. |
| `ceil_rssi_threshold` | `int` | Specifies ceil RSSI threshold. |
| `floor_rssi_threshold` | `int` | Specifies floor RSSI threshold. |
| `current_dynamic_rssi_threshold` | `int` | Current dynamic RSSI threshold. |
| `rssi_default_config` | `int` | RSSI config: default or user-configured. |
| `edmac_enable` | `int` | EDMAC status. |

Extended dynamic RX abort configuration

---

> **Supported SoCs:** RW612, IW610

---

<a id="wlanscanresult"></a>
### `wlan_scan_result`

| Field | Type | Description |
|-------|------|-------------|
| `ssid` | `char` | The network SSID, represented as a NULL-terminated C string of 0 to 32 characters. If the network has a hidden SSID, this can be the empty string. |
| `ssid_len` | `unsigned int` | SSID length. |
| `bssid` | `char` | The network BSSID, represented as a 6-byte array. |
| `channel` | `unsigned int` | The network channel. |
| `type` | `enum wlan_bss_type` | The Wi-Fi network type. |
| `role` | `enum wlan_bss_role` | The Wi-Fi network mode. |
| `__pad0__` | `unsigned` |  |
| `dot11n` | `unsigned` | The network supports 802.11n. This is set to 0 if the network does not support 802.11n or if the system does not have 802.11n support enabled. |
| `dot11ac` | `unsigned` | The network supports 802.11ac. This is set to 0 if the network does not support 802.11ac or if the system does not have 802.11ac support enabled. |
| `dot11ax` | `unsigned` | The network supports 802.11ax. This is set to 0 if the network does not support 802.11ax or if the system does not have 802.11ax support enabled. |
| `wmm` | `unsigned` | The network supports WMM. This is set to 0 if the network does not support WMM or if the system does not have WMM support enabled. |
| `wps` | `unsigned` | The network supports WPS. This is set to 0 if the network does not support WPS or if the system does not have WPS support enabled. |
| `wep` | `unsigned` | The network uses WEP security. |
| `wpa` | `unsigned` | The network uses WPA security. |
| `wpa2` | `unsigned` | The network uses WPA2 security. |
| `wpa2_sha256` | `unsigned` | The network uses WPA2 SHA256 security. |
| `owe` | `unsigned` | The network uses OWE security. |
| `wpa3_sae` | `unsigned` | The network uses WPA3 SAE security. |
| `wpa2_entp` | `unsigned` | The network uses WPA2 Enterprise security. |
| `wpa3_entp` | `unsigned` | The network uses WPA3 Enterprise security. |
| `wpa3_1x_sha256` | `unsigned` | The network uses WPA3 Enterprise SHA256 security. |
| `wpa3_1x_sha384` | `unsigned` | The network uses WPA3 Enterprise SHA384 security. |
| `ft_1x` | `unsigned` | The network uses FT 802.1x security. |
| `ft_1x_sha384` | `unsigned` | The network uses FT 892.1x SHA384 security. |
| `ft_psk` | `unsigned` | The network uses FT PSK security. |
| `ft_sae` | `unsigned` | The network uses FT SAE security. |
| `__pad1__` | `unsigned` |  |
| `wps_session` | `unsigned int` | WPS Type WPS_SESSION_PBC/ WPS_SESSION_PIN. |
| `rssi` | `unsigned char` | The signal strength of the beacon. |
| `trans_ssid` | `char` | The network SSID, represented as a NULL-terminated C string of 0 to 32 characters. If the network has a hidden SSID, this must be the empty string. |
| `trans_ssid_len` | `unsigned int` | SSID length. |
| `trans_bssid` | `char` | The network BSSID, represented as a 6-byte array. |
| `beacon_period` | `uint16_t` | Beacon period. |
| `dtim_period` | `uint8_t` | DTIM (delivery traffic indication map) period. |
| `ap_mfpc` | `t_u8` | MFPC (Management Frame Protection Capable) bit of AP (Access Point). |
| `ap_mfpr` | `t_u8` | MFPR (Management Frame Protection Required) bit of AP (Access Point). |
| `ap_pwe` | `t_u8` | PWE (Password Element) bit of AP (Access Point). |
| `neighbor_report_supported` | `bool` | Neighbor report support. |
| `bss_transition_supported` | `bool` | Bss transition support. |

Scan result

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlantxpertinfo"></a>
### `wlan_tx_pert_info`

| Field | Type | Description |
|-------|------|-------------|
| `tx_pert_check` | `t_u8` | Enable/Disable TX per tracking. |
| `tx_pert_check_peroid` | `t_u8` | Check period (unit sec). |
| `tx_pert_check_ratio` | `t_u8` | (Fail TX packet)/(Total TX packet) ratio (unit 10%) default: 5. |
| `tx_pert_check_num` | `t_u16` | A watermark of check number (default 5). |

TX PER tracking structure Driver sets TX per tracking statistic to firmware. Firmware can check TX packet error rate periodically and report per to host if per is high.

---

> **Supported SoCs:** RW612

---

<a id="wlantxrxhistograminfo"></a>
### `wlan_txrx_histogram_info`

| Field | Type | Description |
|-------|------|-------------|
| `enable` | `t_u8` | Enables or disables. |
| `action` | `t_u16` | Choose to get TX, RX or both. |

TX/RX packet rate histogram information

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="enumerations"></a>
## Enumerations

| Enum | Supported SoCs |
|------|---------------|
| [`Chan2Offset_e`](#chan2offsete) | All |
| [`ChanBand_e`](#chanbande) | All |
| [`ChanWidth_e`](#chanwidthe) | All |
| [`IEEEtypes_Bss_t`](#ieeetypesbsst) | All |
| [`ScanMode_e`](#scanmodee) | All |
| [`_ENH_PS_MODES`](#enhpsmodes) | All |
| [`_Host_Sleep_Action`](#hostsleepaction) | All |
| [`address_types`](#addresstypes) | All |
| [`cli_reset_option`](#cliresetoption) | All |
| [`eap_tls_cipher_type`](#eaptlsciphertype) | RW612, IW610 |
| [`nan_service_protocol_type_t`](#nanserviceprotocoltypet) | RW612 |
| [`sub_event_id`](#subeventid) | RW612, IW610 |
| [`wlan_connection_state`](#wlanconnectionstate) | All |
| [`wlan_csi_opt`](#wlancsiopt) | RW612, IW610 |
| [`wlan_event_reason`](#wlaneventreason) | All |
| [`wlan_frequency_bands`](#wlanfrequencybands) | All |
| [`wlan_hostsleep_state`](#wlanhostsleepstate) | RW612, IW610 |
| [`wlan_mef_type`](#wlanmeftype) | RW612, IW610 |
| [`wlan_mon_task_event`](#wlanmontaskevent) | All |
| [`wlan_monitor_opt`](#wlanmonitoropt) | All |
| [`wlan_ps_mode`](#wlanpsmode) | All |
| [`wlan_ps_state`](#wlanpsstate) | All |
| [`wlan_security_type`](#wlansecuritytype) | All |
| [`wlan_select_policy`](#wlanselectpolicy) | All |
| [`wlan_wakeup_event_t`](#wlanwakeupeventt) | All |
| [`wm_wlan_errno`](#wmwlanerrno) | All |

---

### Enumeration Documentation

<a id="chan2offsete"></a>
### `Chan2Offset_e`

| Value | Description |
|-------|-------------|
| `SECONDARY_CHAN_NONE` | No secondary channel |
| `SECONDARY_CHAN_ABOVE` | Secondary channel is above the primary channel |
| `SECONDARY_CHAN_BELOW` | The secondary channel is below the primary channel |

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="chanbande"></a>
### `ChanBand_e`

| Value | Description |
|-------|-------------|
| `Band_2_4_GHz` | 2.4 GHz band |
| `Band_5_GHz` | 5 GHz band |
| `Band_4_GHz` | 4 GHz band |

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="chanwidthe"></a>
### `ChanWidth_e`

| Value | Description |
|-------|-------------|
| `ChanWidth_20_MHz` | 20 MHz channel bandwidth |
| `ChanWidth_10_MHz` | 10 MHz channel bandwidth |
| `ChanWidth_40_MHz` | 40 MHz channel bandwidth |
| `ChanWidth_80_MHz` | 80 MHz channel bandwidth |

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="ieeetypesbsst"></a>
### `IEEEtypes_Bss_t`

| Value | Description |
|-------|-------------|
| `BSS_INFRASTRUCTURE` | Infrastructure BSS mode (STA connects to AP) |
| `BSS_INDEPENDENT` | Independent BSS mode (IBSS/Ad-hoc) |
| `BSS_ANY` | Any BSS type |

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="scanmodee"></a>
### `ScanMode_e`

| Value | Description |
|-------|-------------|
| `MANUAL_MODE` | Manual channel selection mode |
| `ACS_MODE` | Auto channel selection (ACS) mode |

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="enhpsmodes"></a>
### `_ENH_PS_MODES`

| Value | Description |
|-------|-------------|
| `GET_PS` | Get the current Power-save mode |
| `SLEEP_CONFIRM` | Sleep confirm command |
| `EXT_PS_PARAM` | Extended Power-save parameters |
| `DIS_AUTO_PS` | Disable auto Power-save mode |
| `EN_AUTO_PS` | Enable auto Power-save mode |

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="hostsleepaction"></a>
### `_Host_Sleep_Action`

| Value | Description |
|-------|-------------|
| `HS_CONFIGURE` | Configure host sleep parameters |
| `HS_ACTIVATE` | Activate the host sleep mode |

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="addresstypes"></a>
### `address_types`

| Value | Description |
|-------|-------------|
| `ADDR_TYPE_STATIC` | Static IP address |
| `ADDR_TYPE_DHCP` | Dynamic IP address |
| `ADDR_TYPE_LLA` | Link level address |
| `ADDR_TYPE_BRIDGE_MODE` | For Bridge Mode, no IP address |

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="cliresetoption"></a>
### `cli_reset_option`

| Value | Description |
|-------|-------------|
| `CLI_DISABLE_WIFI` | Disables the Wi-Fi driver |
| `CLI_ENABLE_WIFI` | Enables the Wi-Fi driver |
| `CLI_RESET_WIFI` | Reset the Wi-Fi driver |

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="eaptlsciphertype"></a>
### `eap_tls_cipher_type`

| Value | Description |
|-------|-------------|
| `EAP_TLS_NONE` | No EAP TLS cipher suite |
| `EAP_TLS_ECC_P384` | EAP TLS with ECDH and ECDSA with p384. |
| `EAP_TLS_RSA_3K` | EAP TLS with ECDH and RSA with > 3K |

---

> **Supported SoCs:** RW612, IW610

---

<a id="nanserviceprotocoltypet"></a>
### `nan_service_protocol_type_t`

| Value | Description |
|-------|-------------|
| `NAN_SERVICE_PROTO_BONJOUR` | Bonjour service discovery protocol |
| `NAN_SERVICE_PROTO_GENERIC` | Generic service protocol |
| `NAN_SERVICE_PROTO_CSA_MATTER` | CSA Matter protocol |

---

> **Supported SoCs:** RW612

---

<a id="subeventid"></a>
### `sub_event_id`

| Value | Description |
|-------|-------------|
| `EVENT_SUB_RSSI_LOW` | Event ID for subscribe event RSSI low |
| `EVENT_SUB_RSSI_HIGH` | Event ID for subscribe event RSSI high |
| `EVENT_SUB_SNR_LOW` | Event ID for subscribe event snr low |
| `EVENT_SUB_SNR_HIGH` | Event ID for subscribe event snr high |
| `EVENT_SUB_MAX_FAIL` | Event ID for subscribe event max fail |
| `EVENT_SUB_BEACON_MISSED` | Event ID for subscribe event beacon missed |
| `EVENT_SUB_DATA_RSSI_LOW` | Event ID for subscribe event data RSSI low |
| `EVENT_SUB_DATA_RSSI_HIGH` | Event ID for subscribe event data RSSI high |
| `EVENT_SUB_DATA_SNR_LOW` | Event ID for subscribe event data snr low |
| `EVENT_SUB_DATA_SNR_HIGH` | Event ID for subscribe event data snr high |
| `EVENT_SUB_LINK_QUALITY` | Event ID for subscribe event link quality |
| `EVENT_SUB_PRE_BEACON_LOST` | Event ID for subscribe event pre_beacon_lost |
| `MAX_EVENT_ID` | Fail event ID |

---

> **Supported SoCs:** RW612, IW610

---

<a id="wlanconnectionstate"></a>
### `wlan_connection_state`

| Value | Description |
|-------|-------------|
| `WLAN_DISCONNECTED` | The Wi-Fi connection manager is not connected and no connection attempt is in progress. It is possible to connect to a network or scan. |
| `WLAN_CONNECTING` | The Wi-Fi connection manager is not connected but it is currently attempting to connect to a network. It is not possible to scan at this time. It is possible to connect to a different network. |
| `WLAN_ASSOCIATED` | The Wi-Fi connection manager is not connected but associated |
| `WLAN_AUTHENTICATED` | The Wi-Fi connection manager is not connected but authenticated |
| `WLAN_CONNECTED` | The Wi-Fi connection manager is connected. It is possible to scan and connect to another network at this time. Information about the current network configuration is available. |
| `WLAN_UAP_STARTED` | The Wi-Fi connection manager has started uAP |
| `WLAN_UAP_STOPPED` | The Wi-Fi connection manager has stopped uAP |
| `WLAN_SCANNING` | The Wi-Fi connection manager is not connected and network scan is in progress. |
| `WLAN_ASSOCIATING` | The Wi-Fi connection manager is not connected and network association is in progress. |

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlancsiopt"></a>
### `wlan_csi_opt`

| Value | Description |
|-------|-------------|
| `CSI_FILTER_OPT_ADD` | Add a CSI filter entry |
| `CSI_FILTER_OPT_DELETE` | Delete a CSI filter entry |
| `CSI_FILTER_OPT_CLEAR` | Clear all CSI filter entries |
| `CSI_FILTER_OPT_DUMP` | Dump all CSI filter entries |

---

> **Supported SoCs:** RW612, IW610

---

<a id="wlaneventreason"></a>
### `wlan_event_reason`

| Value | Description |
|-------|-------------|
| `WLAN_REASON_SUCCESS` | The Wi-Fi connection manager has successfully connected to a network and is now in the WLAN_CONNECTED state. |
| `WLAN_REASON_AUTH_SUCCESS` | The Wi-Fi connection manager has successfully authenticated to a network and is now in the WLAN_ASSOCIATED state. |
| `WLAN_REASON_CONNECT_FAILED` | The Wi-Fi connection manager failed to connect before actual connection attempt with AP due to incorrect Wi-Fi network profile. or the Wi-Fi connection manager failed to reconnect to previously connected network and it is now in the WLAN_DISCONNECTED state. |
| `WLAN_REASON_NETWORK_NOT_FOUND` | The Wi-Fi connection manager could not find the network that it was connecting to and it is now in the WLAN_DISCONNECTED state. |
| `WLAN_REASON_BGSCAN_NETWORK_NOT_FOUND` | The Wi-Fi connection manager could not find the network in background scan during roam attempt that it was connecting to and it is now in the WLAN_CONNECTED state with previous AP. |
| `WLAN_REASON_NETWORK_AUTH_FAILED` | The Wi-Fi connection manager failed to authenticate with the network and is now in the WLAN_DISCONNECTED state. |
| `WLAN_REASON_ADDRESS_SUCCESS` | DHCP lease has been renewed |
| `WLAN_REASON_ADDRESS_FAILED` | The Wi-Fi connection manager failed to obtain an IP address or TCP stack configuration has failed or the IP address configuration was lost due to a DHCP error. The system is now in the WLAN_DISCONNECTED state. |
| `WLAN_REASON_LINK_LOST` | The Wi-Fi connection manager has lost the link to the current network |
| `WLAN_REASON_CHAN_SWITCH` | The Wi-Fi connection manager has received the channel switch announcement from the current network. |
| `WLAN_REASON_WPS_DISCONNECT` | The Wi-Fi connection manager has disconnected from the WPS network (or has canceled a connection attempt) by request and is now in the WLAN_DISCONNECTED state. |
| `WLAN_REASON_USER_DISCONNECT` | The Wi-Fi connection manager has disconnected from the current network (or has canceled a connection attempt) by request and is now in the WLAN_DISCONNECTED state. |
| `WLAN_REASON_INITIALIZED` | The Wi-Fi connection manager is initialized and is ready for use. That is, it's now possible to scan or to connect to a network. |
| `WLAN_REASON_INITIALIZATION_FAILED` | The Wi-Fi connection manager has failed to initialize and is therefore not running. It is not possible to scan or to connect to a network. The Wi-Fi connection manager must be stopped and started again via wlan_stop() and wlan_start() respectively. |
| `WLAN_REASON_FW_HANG` | The Wi-Fi connection manager has entered in hang mode |
| `WLAN_REASON_FW_RESET` | The Wi-Fi connection manager has reset fw successfully |
| `WLAN_REASON_PS_ENTER` | The Wi-Fi connection manager has entered Power-save mode |
| `WLAN_REASON_PS_EXIT` | The Wi-Fi connection manager has exited from Power-save mode |
| `WLAN_REASON_UAP_SUCCESS` | The Wi-Fi connection manager has started uAP (micro access point) |
| `WLAN_REASON_UAP_CLIENT_ASSOC` | A Wi-Fi client has joined the uAP BSS network |
| `WLAN_REASON_UAP_CLIENT_CONN` | A Wi-Fi client has authenticated and connected to the uAP BSS network |
| `WLAN_REASON_UAP_CLIENT_DISSOC` | A Wi-Fi client has left the uAP BSS network |
| `WLAN_REASON_UAP_START_FAILED` | The Wi-Fi connection manager has failed to start uAP |
| `WLAN_REASON_UAP_STOP_FAILED` | The Wi-Fi connection manager has failed to stop uAP |
| `WLAN_REASON_UAP_STOPPED` | The Wi-Fi connection manager has stopped uAP |
| `WLAN_REASON_RSSI_LOW` | The Wi-Fi connection manager has received subscribed RSSI low event on station interface as per configured threshold and frequency. If CONFIG_11K, CONFIG_11V, CONFIG_11R or CONFIG_ROAMING enabled then RSSI low event is processed internally. |
| `WLAN_REASON_RSSI_HIGH` | The Wi-Fi connection manager has received subscribed RSSI high event on station interface as per configured threshold and frequency. |
| `WLAN_REASON_SNR_LOW` | The Wi-Fi connection manager has received subscribed SNR low event on station interface as per configured threshold and frequency. |
| `WLAN_REASON_SNR_HIGH` | The Wi-Fi connection manager has received subscribed SNR high event on station interface as per configured threshold and frequency. |
| `WLAN_REASON_MAX_FAIL` | The Wi-Fi connection manager has received subscribed maximum fail event on station interface as per configured threshold and frequency. |
| `WLAN_REASON_BEACON_MISSED` | The Wi-Fi connection manager has received subscribed beacon missed fail event on station interface as per configured threshold and frequency. |
| `WLAN_REASON_DATA_RSSI_LOW` | The Wi-Fi connection manager has received subscribed data RSSI low event on station interface as per configured threshold and frequency. |
| `WLAN_REASON_DATA_RSSI_HIGH` | The Wi-Fi connection manager has received subscribed data RSSI high event on station interface as per configured threshold and frequency. |
| `WLAN_REASON_DATA_SNR_LOW` | The Wi-Fi connection manager has received subscribed data SNR low event on station interface as per configured threshold and frequency. |
| `WLAN_REASON_DATA_SNR_HIGH` | The Wi-Fi connection manager has received subscribed data SNR high event on station interface as per configured threshold and frequency. |
| `WLAN_REASON_LINK_QUALITY` | The Wi-Fi connection manager has received subscribed link quality event on station interface as per configured link_snr threshold and frequency, link_rate threshold and frequency, link_tx_latency threshold and frequency |
| `WLAN_REASON_PRE_BEACON_LOST` | The Wi-Fi connection manager has received subscribed pre beacon lost event on station interface as per configured threshold and frequency. |
| `WLAN_REASON_SCAN_DONE` | Scan is done |
| `WLAN_REASON_WPS_SESSION_DONE` | WPS session is done |

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanfrequencybands"></a>
### `wlan_frequency_bands`

| Value | Description |
|-------|-------------|
| `WLAN_FREQ_BAND_2_4_GHZ` | 2.4 GHz band |
| `WLAN_FREQ_BAND_5_GHZ` | 5 GHz band |
| `WLAN_FREQ_BAND_BOTH` | All bands |
| `WLAN_FREQ_BAND_UNKNOWN` | Invalid frequency band |

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanhostsleepstate"></a>
### `wlan_hostsleep_state`

| Value | Description |
|-------|-------------|
| `HOST_SLEEP_DISABLE` | Host sleep feature disabled |
| `HOST_SLEEP_ONESHOT` | Host sleep one-shot mode, automatically disabled after triggering once |
| `HOST_SLEEP_PERIODIC` | Host sleep periodic mode, enters sleep periodically |

---

> **Supported SoCs:** RW612, IW610

---

<a id="wlanmeftype"></a>
### `wlan_mef_type`

| Value | Description |
|-------|-------------|
| `MEF_TYPE_DELETE` | Delete MEF entry |
| `MEF_TYPE_PING` | Ping (ICMP echo request) filter |
| `MEF_TYPE_ARP` | ARP (Address Resolution Protocol) filter |
| `MEF_TYPE_MULTICAST` | Multicast filter |
| `MEF_TYPE_IPV6_NS` | IPv6 Neighbor Solicitation filter |
| `MEF_TYPE_END` | End of MEF type list |

---

> **Supported SoCs:** RW612, IW610

---

<a id="wlanmontaskevent"></a>
### `wlan_mon_task_event`

| Value | Description |
|-------|-------------|
| `HOST_SLEEP_HANDSHAKE` | Host sleep handshake event |
| `HOST_SLEEP_EXIT` | Host sleep exit event |
| `HOST_SLEEP_UART_NOTIFY` | Host sleep UART notify event |
| `HOST_SLEEP_HS_SKIP` | Host sleep handshake skip event |
| `WIFI_RECOVERY_REQ` | Wi-Fi recovery request event |

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanmonitoropt"></a>
### `wlan_monitor_opt`

| Value | Description |
|-------|-------------|
| `MONITOR_FILTER_OPT_ADD_MAC` | Add a MAC address to the monitor filter list |
| `MONITOR_FILTER_OPT_DELETE_MAC` | Delete a MAC address from the monitor filter list |
| `MONITOR_FILTER_OPT_CLEAR_MAC` | Clear all MAC addresses from the monitor filter list |
| `MONITOR_FILTER_OPT_DUMP` | Dump all MAC addresses in the monitor filter list |

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanpsmode"></a>
### `wlan_ps_mode`

| Value | Description |
|-------|-------------|
| `WLAN_ACTIVE` | Active mode |
| `WLAN_IEEE` | IEEE Power-save mode |
| `WLAN_DEEP_SLEEP` | Deep sleep Power-save mode |
| `WLAN_IEEE_DEEP_SLEEP` | IEEE and deep sleep Power-save mode |

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanpsstate"></a>
### `wlan_ps_state`

| Value | Description |
|-------|-------------|
| `PS_STATE_AWAKE` | Awake state, Wi-Fi is in normal operating mode |
| `PS_STATE_PRE_SLEEP` | Pre-sleep state, preparing to enter sleep |
| `PS_STATE_SLEEP_CFM` | Sleep confirm state, waiting for firmware to confirm sleep entry |
| `PS_STATE_SLEEP` | Sleep state, Wi-Fi is in low power sleep mode |

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansecuritytype"></a>
### `wlan_security_type`

| Value | Description |
|-------|-------------|
| `WLAN_SECURITY_NONE` | The network does not use security |
| `WLAN_SECURITY_WEP_OPEN` | The network uses WEP security with open key |
| `WLAN_SECURITY_WEP_SHARED` | The network uses WEP security with shared key |
| `WLAN_SECURITY_WPA` | The network uses WPA security with PSK |
| `WLAN_SECURITY_WPA2` | The network uses WPA2 security with PSK |
| `WLAN_SECURITY_WPA_WPA2_MIXED` | The network uses WPA/WPA2 mixed security with PSK |
| `WLAN_SECURITY_WPA2_FT` | The network uses WPA2 security with PSK FT |
| `WLAN_SECURITY_WPA3_SAE` | The network uses WPA3 security with SAE |
| `WLAN_SECURITY_WPA3_FT_SAE` | The network uses WPA3 security with SAE FT |
| `WLAN_SECURITY_WPA3_SAE_EXT_KEY` | The network uses WPA3 security with new SAE AKM suite 24. |
| `WLAN_SECURITY_WPA2_WPA3_SAE_MIXED` | The network uses WPA2/WPA3 SAE mixed security with PSK |
| `WLAN_SECURITY_OWE_ONLY` | The network uses OWE only security without Transition mode support |
| `WLAN_SECURITY_EAP_TLS` | The network uses WPA2 Enterprise EAP-TLS security The identity field in the wlan_network structure is used |
| `WLAN_SECURITY_EAP_TLS_SHA256` | The network uses WPA2 Enterprise EAP-TLS SHA256 security. The identity field in the wlan_network structure is used |
| `WLAN_SECURITY_EAP_TLS_FT` | The network uses WPA2 Enterprise EAP-TLS FT security. The identity field in the wlan_network structure is used |
| `WLAN_SECURITY_EAP_TLS_FT_SHA384` | The network uses WPA2 Enterprise EAP-TLS FT SHA384 security The identity field in the wlan_network structure is used |
| `WLAN_SECURITY_EAP_TTLS` | The network uses WPA2 Enterprise EAP-TTLS security. The identity field in the wlan_network structure is used |
| `WLAN_SECURITY_EAP_TTLS_MSCHAPV2` | The network uses WPA2 Enterprise EAP-TTLS-MSCHAPV2 security. The anonymous identity, identity and password fields in the wlan_network structure are used |
| `WLAN_SECURITY_EAP_PEAP_MSCHAPV2` | The network uses WPA2 Enterprise EAP-PEAP-MSCHAPV2 security. The anonymous identity, identity and password fields in the wlan_network structure are used |
| `WLAN_SECURITY_EAP_PEAP_TLS` | The network uses WPA2 Enterprise EAP-PEAP-TLS security. The anonymous identity, identity and password fields in the wlan_network structure are used |
| `WLAN_SECURITY_EAP_PEAP_GTC` | The network uses WPA2 Enterprise EAP-PEAP-GTC security. The anonymous identity, identity and password fields in the wlan_network structure are used |
| `WLAN_SECURITY_EAP_FAST_MSCHAPV2` | The network uses WPA2 Enterprise EAP-FAST-MSCHAPV2 security. The anonymous identity, identity and password fields in the wlan_network structure are used |
| `WLAN_SECURITY_EAP_FAST_GTC` | The network uses WPA2 Enterprise EAP-FAST-GTC security The anonymous identity, identity and password fields in the wlan_network structure are used |
| `WLAN_SECURITY_EAP_SIM` | The network uses WPA2 Enterprise EAP-SIM security The identity and password fields in the wlan_network structure are used |
| `WLAN_SECURITY_EAP_AKA` | The network uses WPA2 Enterprise EAP-AKA security The identity and password fields in the wlan_network structure are used |
| `WLAN_SECURITY_EAP_AKA_PRIME` | The network uses WPA2 Enterprise EAP-AKA-PRIME security The identity and password fields in the wlan_network structure are used |
| `WLAN_SECURITY_DPP` | The network uses DPP security with NAK(Net Access Key) |
| `WLAN_SECURITY_WILDCARD` | The network can use any security method. This security method is often used when the user only knows the name and passphrase but not the security type. |

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanselectpolicy"></a>
### `wlan_select_policy`

| Value | Description |
|-------|-------------|
| `WLAN_SELECT_POLICY_MANUAL` | Manual network selection: user selects the network explicitly |
| `WLAN_SELECT_POLICY_AUTO` | Automatic network selection: driver selects the best network automatically |

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanwakeupeventt"></a>
### `wlan_wakeup_event_t`

| Value | Description |
|-------|-------------|
| `WAKE_ON_ALL_BROADCAST` | Wake-up on broadcast |
| `WAKE_ON_UNICAST` | Wake-up on unicast |
| `WAKE_ON_MAC_EVENT` | Wake-up on MAC event |
| `WAKE_ON_MULTICAST` | Wake-up on multicast |
| `WAKE_ON_ARP_BROADCAST` | Wake-up on ARP broadcast |
| `WAKE_ON_MGMT_FRAME` | Wake-up on receiving a management frame |

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wmwlanerrno"></a>
### `wm_wlan_errno`

| Value | Description |
|-------|-------------|
| `WM_E_WLAN_ERRNO_BASE` |  |
| `WLAN_ERROR_FW_DNLD_FAILED` | The firmware download operation failed |
| `WLAN_ERROR_FW_NOT_READY` | The firmware ready register not set |
| `WLAN_ERROR_CARD_NOT_DETECTED` | The Wi-Fi SoC not found |
| `WLAN_ERROR_FW_NOT_DETECTED` | The Wi-Fi Firmware is not found |
| `WLAN_BSSID_NOT_FOUND_IN_SCAN_LIST` | BSSID not found in scan list |

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="macros"></a>
## Macros

| Macro | Value | Supported SoCs |
|-------|-------|---------------|
| [`ACTION_GET`](#actionget) | `(0U)` | All |
| [`ACTION_SET`](#actionset) | `(1)` | All |
| [`ARG_UNUSED`](#argunused) | `(void)(x)` | All |
| [`AZ_MEASUREMENT_FREQ`](#azmeasurementfreq) | `4 /* in 0.1 Hz increments */` | IW612 |
| [`AZ_NUMBER_OF_MEASUREMENTS`](#aznumberofmeasurements) | `6` | IW612 |
| [`A_ID_MAX_LENGTH`](#aidmaxlength) | `33U` | All |
| [`BIN_COUNTER_LEN`](#bincounterlen) | `(7)` | All |
| [`BURST_DURATION`](#burstduration) | `11` | IW612 |
| [`BURST_EXP`](#burstexp) | `3` | IW612 |
| [`BURST_PERIOD`](#burstperiod) | `10` | IW612 |
| [`BW`](#bw) | `13 /* RW610 only allows 20M bandwidth */` | IW612 |
| [`CARD_WAKEUP_GPIO_PIN`](#cardwakeupgpiopin) | `13` | All |
| [`CCK_DESENSE_MODE_DISABLED`](#cckdesensemodedisabled) | `0` | RW612, IW610 |
| [`CCK_DESENSE_MODE_DYNAMIC`](#cckdesensemodedynamic) | `1` | RW612, IW610 |
| [`CCK_DESENSE_MODE_DYN_ENH`](#cckdesensemodedynenh) | `2` | RW612, IW610 |
| [`CIVIC_ADDRESS_TYPE`](#civicaddresstype) | `22` | IW612 |
| [`CIVIC_COUNTRY_CODE`](#civiccountrycode) | `0 /* US */` | IW612 |
| [`CIVIC_LOCATION`](#civiclocation) | `1` | IW612 |
| [`CIVIC_LOCATION_TYPE`](#civiclocationtype) | `1` | IW612 |
| [`CIVIC_REQUEST`](#civicrequest) | `1` | IW612 |
| [`COEX_PTA_FEATURE_DISABLE`](#coexptafeaturedisable) | `0` | RW612 |
| [`COEX_PTA_FEATURE_ENABLE`](#coexptafeatureenable) | `1` | RW612 |
| [`DFS_REC_HDR_LEN`](#dfsrechdrlen) | `(8)` | All |
| [`DFS_REC_HDR_NUM`](#dfsrechdrnum) | `(10)` | All |
| [`DISABLE_TX_RX_HISTOGRAM`](#disabletxrxhistogram) | `0x00` | All |
| [`DOMAIN_MATCH_MAX_LENGTH`](#domainmatchmaxlength) | `64U` | All |
| [`ENABLE_TX_RX_HISTOGRAM`](#enabletxrxhistogram) | `0x01` | All |
| [`EU_CRYPTO_AAD_MAX_LENGTH`](#eucryptoaadmaxlength) | `32U` | All |
| [`EU_CRYPTO_DATA_MAX_LENGTH`](#eucryptodatamaxlength) | `1300U` | All |
| [`EU_CRYPTO_KEYIV_MAX_LENGTH`](#eucryptokeyivmaxlength) | `32U` | All |
| [`EU_CRYPTO_KEY_MAX_LENGTH`](#eucryptokeymaxlength) | `32U` | All |
| [`EU_CRYPTO_NONCE_MAX_LENGTH`](#eucryptononcemaxlength) | `14U` | All |
| [`EXT_COEX_PTA_INTERFACE`](#extcoexptainterface) | `5` | RW612 |
| [`EXT_COEX_WCI2_GPIO_INTERFACE`](#extcoexwci2gpiointerface) | `7` | RW612 |
| [`EXT_COEX_WCI2_INTERFACE`](#extcoexwci2interface) | `6` | RW612 |
| [`FILE_TYPE_ENTP_CA_CERT`](#filetypeentpcacert) | `1` | RW612, IW610 |
| [`FILE_TYPE_ENTP_CA_CERT2`](#filetypeentpcacert2) | `4` | RW612, IW610 |
| [`FILE_TYPE_ENTP_CLIENT_CERT`](#filetypeentpclientcert) | `2` | RW612, IW610 |
| [`FILE_TYPE_ENTP_CLIENT_CERT2`](#filetypeentpclientcert2) | `5` | RW612, IW610 |
| [`FILE_TYPE_ENTP_CLIENT_KEY`](#filetypeentpclientkey) | `3` | RW612, IW610 |
| [`FILE_TYPE_ENTP_CLIENT_KEY2`](#filetypeentpclientkey2) | `6` | RW612, IW610 |
| [`FILE_TYPE_ENTP_DH_PARAMS`](#filetypeentpdhparams) | `10` | RW612, IW610 |
| [`FILE_TYPE_ENTP_SERVER_CERT`](#filetypeentpservercert) | `8` | RW612, IW610 |
| [`FILE_TYPE_ENTP_SERVER_KEY`](#filetypeentpserverkey) | `9` | RW612, IW610 |
| [`FILE_TYPE_NONE`](#filetypenone) | `0` | RW612, IW610 |
| [`FLAG_RX_HISTOGRAM`](#flagrxhistogram) | `0x02` | All |
| [`FLAG_TX_HISTOGRAM`](#flagtxhistogram) | `0x01` | All |
| [`FORMAT_BW`](#formatbw) | `2 /* RW610 only allows 20M bandwidth */` | IW612 |
| [`FOR_RANGING`](#forranging) | `0` | IW612 |
| [`FTM_ACTION_START`](#ftmactionstart) | `1` | IW612 |
| [`FTM_ACTION_STOP`](#ftmactionstop) | `2` | IW612 |
| [`FTM_PER_BURST`](#ftmperburst) | `5` | IW612 |
| [`GET_TX_RX_HISTOGRAM`](#gettxrxhistogram) | `0x02` | All |
| [`HASH_MAX_LENGTH`](#hashmaxlength) | `40U` | All |
| [`HOST_WAKEUP_GPIO_PIN`](#hostwakeupgpiopin) | `12` | All |
| [`I2R_LMR_FEEDBACK`](#i2rlmrfeedback) | `0 /* allow RSTA to request I2R reporting */` | IW612 |
| [`IDENTITY_MAX_LENGTH`](#identitymaxlength) | `64U` | All |
| [`IEEEtypes_ADDRESS_SIZE`](#ieeetypesaddresssize) | `6` | All |
| [`IEEEtypes_SSID_SIZE`](#ieeetypesssidsize) | `32U` | All |
| [`IS_ASAP`](#isasap) | `1` | IW612 |
| [`LCI_ALTITUDE`](#lcialtitude) | `11.2` | IW612 |
| [`LCI_ALTITUDE_UNCERTAINITY`](#lcialtitudeuncertainity) | `15` | IW612 |
| [`LCI_LATITIUDE`](#lcilatitiude) | `-33.8570095` | IW612 |
| [`LCI_LATITUDE_UNCERTAINITY`](#lcilatitudeuncertainity) | `18` | IW612 |
| [`LCI_LONGITUDE`](#lcilongitude) | `151.2152005` | IW612 |
| [`LCI_LONGITUDE_UNCERTAINITY`](#lcilongitudeuncertainity) | `18` | IW612 |
| [`LCI_REQUEST`](#lcirequest) | `1` | IW612 |
| [`MAX_CHANNEL_LIST`](#maxchannellist) | `6` | All |
| [`MAX_I2R_STS_UPTO80`](#maxi2rstsupto80) | `0 /* RW610 only allows to send 1 N_STS*/` | IW612 |
| [`MAX_R2I_STS_UPTO80`](#maxr2istsupto80) | `0` | IW612 |
| [`MAX_SAMP_TIMING`](#maxsamptiming) | `200` | RW612 |
| [`MAX_USERS`](#maxusers) | `8U` | All |
| [`MIN_DELTA`](#mindelta) | `60` | IW612 |
| [`MIN_SAMP_TIMING`](#minsamptiming) | `20` | RW612 |
| [`NUM_CHAN_BAND_ENUMS`](#numchanbandenums) | `3` | All |
| [`PAC_OPAQUE_ENCR_KEY_MAX_LENGTH`](#pacopaqueencrkeymaxlength) | `33U` | All |
| [`PASSWORD_MAX_LENGTH`](#passwordmaxlength) | `128U` | All |
| [`POL_GRANT_PIN_HIGH`](#polgrantpinhigh) | `0` | RW612 |
| [`POL_GRANT_PIN_LOW`](#polgrantpinlow) | `1` | RW612 |
| [`PROTO_DOT11AZ_NTB`](#protodot11azntb) | `1` | IW612 |
| [`PROTO_DOT11AZ_TB`](#protodot11aztb) | `2` | IW612 |
| [`PROTO_DOT11MC`](#protodot11mc) | `0` | IW612 |
| [`SAMPLE_TIMING_VALUE`](#sampletimingvalue) | `100` | RW612 |
| [`STATE_INPUT_DISABLE`](#stateinputdisable) | `0` | RW612 |
| [`STATE_PRIORITY_PIN`](#stateprioritypin) | `2` | RW612 |
| [`STATE_PTA_PIN`](#stateptapin) | `1` | RW612 |
| [`TX_AMPDU_CTS_2_SELF`](#txampducts2self) | `1` | RW612, IW610 |
| [`TX_AMPDU_DISABLE_PROTECTION`](#txampdudisableprotection) | `2` | RW612, IW610 |
| [`TX_AMPDU_DYNAMIC_RTS_CTS`](#txampdudynamicrtscts) | `3` | RW612, IW610 |
| [`TX_AMPDU_RTS_CTS`](#txampdurtscts) | `0` | RW612, IW610 |
| [`UNSPEC_WPS_NETWORK`](#unspecwpsnetwork) | `MBIT(0)` | All |
| [`WLAN_11D_SCAN_LIMIT`](#wlan11dscanlimit) | `3U` | All |
| [`WLAN_AMPDU_DENSITY`](#wlanampdudensity) | `0x30` | RW612, IW610 |
| [`WLAN_AMPDU_MMSF`](#wlanampdummsf) | `0x6` | RW612, IW610 |
| [`WLAN_BANDCFG_11AC`](#wlanbandcfg11ac) | `MBIT(1)` | RW612, IW610, IW612 |
| [`WLAN_BANDCFG_11AX`](#wlanbandcfg11ax) | `MBIT(2)` | RW612, IW610, IW612 |
| [`WLAN_BANDCFG_11N`](#wlanbandcfg11n) | `MBIT(0)` | All |
| [`WLAN_CIPHER_AES_128_CMAC`](#wlancipheraes128cmac) | `MBIT(5)` | All |
| [`WLAN_CIPHER_BIP_CMAC_256`](#wlancipherbipcmac256) | `MBIT(13)` | All |
| [`WLAN_CIPHER_BIP_GMAC_128`](#wlancipherbipgmac128) | `MBIT(11)` | All |
| [`WLAN_CIPHER_BIP_GMAC_256`](#wlancipherbipgmac256) | `MBIT(12)` | All |
| [`WLAN_CIPHER_CCMP`](#wlancipherccmp) | `MBIT(4)` | All |
| [`WLAN_CIPHER_CCMP_256`](#wlancipherccmp256) | `MBIT(9)` | All |
| [`WLAN_CIPHER_GCMP`](#wlanciphergcmp) | `MBIT(6)` | All |
| [`WLAN_CIPHER_GCMP_256`](#wlanciphergcmp256) | `MBIT(8)` | All |
| [`WLAN_CIPHER_GTK_NOT_USED`](#wlanciphergtknotused) | `MBIT(14)` | All |
| [`WLAN_CIPHER_NONE`](#wlanciphernone) | `MBIT(0)` | All |
| [`WLAN_CIPHER_SMS4`](#wlanciphersms4) | `MBIT(7)` | All |
| [`WLAN_CIPHER_TKIP`](#wlanciphertkip) | `MBIT(3)` | All |
| [`WLAN_CIPHER_WEP104`](#wlancipherwep104) | `MBIT(2)` | All |
| [`WLAN_CIPHER_WEP40`](#wlancipherwep40) | `MBIT(1)` | All |
| [`WLAN_ERROR_ACTION`](#wlanerroraction) | `4` | All |
| [`WLAN_ERROR_NOMEM`](#wlanerrornomem) | `2` | All |
| [`WLAN_ERROR_NONE`](#wlanerrornone) | `0` | All |
| [`WLAN_ERROR_NOT_SUPPORTED`](#wlanerrornotsupported) | `6` | All |
| [`WLAN_ERROR_PARAM`](#wlanerrorparam) | `1` | All |
| [`WLAN_ERROR_PS_ACTION`](#wlanerrorpsaction) | `5` | All |
| [`WLAN_ERROR_STATE`](#wlanerrorstate) | `3` | All |
| [`WLAN_HOSTSLEEP_FAIL`](#wlanhostsleepfail) | `3` | RW612, IW610 |
| [`WLAN_HOSTSLEEP_IN_PROCESS`](#wlanhostsleepinprocess) | `2` | RW612, IW610 |
| [`WLAN_HOSTSLEEP_SUCCESS`](#wlanhostsleepsuccess) | `1` | RW612, IW610 |
| [`WLAN_KEY_MGMT_CCKM`](#wlankeymgmtcckm) | `MBIT(14)` | All |
| [`WLAN_KEY_MGMT_DPP`](#wlankeymgmtdpp) | `MBIT(23)` | All |
| [`WLAN_KEY_MGMT_FILS_SHA256`](#wlankeymgmtfilssha256) | `MBIT(18)` | All |
| [`WLAN_KEY_MGMT_FILS_SHA384`](#wlankeymgmtfilssha384) | `MBIT(19)` | All |
| [`WLAN_KEY_MGMT_FT`](#wlankeymgmtft) | `(WLAN_KEY_MGMT_FT_PSK | WLAN_KEY_MGMT_FT_IEEE8021X | WLAN_KEY_MGMT_FT_IEEE8021X_SHA384 | WLAN_KEY_MGMT_FT_SAE | \
     WLAN_KEY_MGMT_FT_FILS_SHA256 | WLAN_KEY_MGMT_FT_FILS_SHA384)` | All |
| [`WLAN_KEY_MGMT_FT_FILS_SHA256`](#wlankeymgmtftfilssha256) | `MBIT(20)` | All |
| [`WLAN_KEY_MGMT_FT_FILS_SHA384`](#wlankeymgmtftfilssha384) | `MBIT(21)` | All |
| [`WLAN_KEY_MGMT_FT_IEEE8021X`](#wlankeymgmtftieee8021x) | `MBIT(5)` | All |
| [`WLAN_KEY_MGMT_FT_IEEE8021X_SHA384`](#wlankeymgmtftieee8021xsha384) | `MBIT(24)` | All |
| [`WLAN_KEY_MGMT_FT_PSK`](#wlankeymgmtftpsk) | `MBIT(6)` | All |
| [`WLAN_KEY_MGMT_FT_SAE`](#wlankeymgmtftsae) | `MBIT(11)` | All |
| [`WLAN_KEY_MGMT_IEEE8021X`](#wlankeymgmtieee8021x) | `MBIT(0)` | All |
| [`WLAN_KEY_MGMT_IEEE8021X_NO_WPA`](#wlankeymgmtieee8021xnowpa) | `MBIT(3)` | All |
| [`WLAN_KEY_MGMT_IEEE8021X_SHA256`](#wlankeymgmtieee8021xsha256) | `MBIT(7)` | All |
| [`WLAN_KEY_MGMT_IEEE8021X_SUITE_B`](#wlankeymgmtieee8021xsuiteb) | `MBIT(16)` | All |
| [`WLAN_KEY_MGMT_IEEE8021X_SUITE_B_192`](#wlankeymgmtieee8021xsuiteb192) | `MBIT(17)` | All |
| [`WLAN_KEY_MGMT_NONE`](#wlankeymgmtnone) | `MBIT(2)` | All |
| [`WLAN_KEY_MGMT_OSEN`](#wlankeymgmtosen) | `MBIT(15)` | All |
| [`WLAN_KEY_MGMT_OWE`](#wlankeymgmtowe) | `MBIT(22)` | All |
| [`WLAN_KEY_MGMT_PASN`](#wlankeymgmtpasn) | `MBIT(25)` | All |
| [`WLAN_KEY_MGMT_PSK`](#wlankeymgmtpsk) | `MBIT(1)` | All |
| [`WLAN_KEY_MGMT_PSK_SHA256`](#wlankeymgmtpsksha256) | `MBIT(8)` | All |
| [`WLAN_KEY_MGMT_SAE`](#wlankeymgmtsae) | `MBIT(10)` | All |
| [`WLAN_KEY_MGMT_SAE_EXT_KEY`](#wlankeymgmtsaeextkey) | `MBIT(26)` | All |
| [`WLAN_KEY_MGMT_WAPI_CERT`](#wlankeymgmtwapicert) | `MBIT(13)` | All |
| [`WLAN_KEY_MGMT_WAPI_PSK`](#wlankeymgmtwapipsk) | `MBIT(12)` | All |
| [`WLAN_KEY_MGMT_WPA_NONE`](#wlankeymgmtwpanone) | `MBIT(4)` | All |
| [`WLAN_KEY_MGMT_WPS`](#wlankeymgmtwps) | `MBIT(9)` | All |
| [`WLAN_MAC_ADDR_LENGTH`](#wlanmacaddrlength) | `6` | All |
| [`WLAN_MAX_KNOWN_NETWORKS`](#wlanmaxknownnetworks) | `CONFIG_WLAN_KNOWN_NETWORKS` | All |
| [`WLAN_MAX_STA_FILTER_NUM`](#wlanmaxstafilternum) | `16` | All |
| [`WLAN_MGMT_ACTION`](#wlanmgmtaction) | `MBIT(13)` | All |
| [`WLAN_MGMT_AUTH`](#wlanmgmtauth) | `MBIT(11)` | All |
| [`WLAN_MGMT_DEAUTH`](#wlanmgmtdeauth) | `MBIT(12)` | All |
| [`WLAN_MGMT_DIASSOC`](#wlanmgmtdiassoc) | `MBIT(10)` | All |
| [`WLAN_MGMT_PROBE_RQST`](#wlanmgmtproberqst) | `MBIT(4)` | All |
| [`WLAN_NETWORK_CHAN_LIST_MAX`](#wlannetworkchanlistmax) | `50U` | All |
| [`WLAN_NETWORK_NAME_MAX_LENGTH`](#wlannetworknamemaxlength) | `32U` | All |
| [`WLAN_NETWORK_NAME_MIN_LENGTH`](#wlannetworknameminlength) | `1U` | All |
| [`WLAN_PASSWORD_MAX_LENGTH`](#wlanpasswordmaxlength) | `255U` | All |
| [`WLAN_PASSWORD_MIN_LENGTH`](#wlanpasswordminlength) | `8U` | All |
| [`WLAN_PMK_LENGTH`](#wlanpmklength) | `32` | All |
| [`WLAN_PSK_MAX_LENGTH`](#wlanpskmaxlength) | `64U` | All |
| [`WLAN_PSK_MIN_LENGTH`](#wlanpskminlength) | `8U` | All |
| [`WLAN_REASON_CODE_PREV_AUTH_NOT_VALID`](#wlanreasoncodeprevauthnotvalid) | `2U` | All |
| [`WLAN_RECONNECT_LIMIT`](#wlanreconnectlimit) | `CONFIG_MAX_RECONNECT_LIMIT` | All |
| [`WLAN_RESCAN_LIMIT`](#wlanrescanlimit) | `CONFIG_MAX_RESCAN_LIMIT` | All |
| [`WLAN_STATS_GET`](#wlanstatsget) | `(priv->x)` | All |
| [`WLAN_STATS_INC`](#wlanstatsinc) | `(++(priv->x))` | All |
| [`WMM_UAPSD_QOS_INFO`](#wmmuapsdqosinfo) | `0x0F` | All |
| [`WMM_UAPSD_SLEEP_PERIOD`](#wmmuapsdsleepperiod) | `20` | All |
| [`Z_INFO`](#zinfo) | `0` | IW612 |
| [`wlcm_d`](#wlcmd) | `` | All |

---

### Macro Documentation

<a id="actionget"></a>
### `ACTION_GET`

**Value:** `(0U)`

Action GET

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="actionset"></a>
### `ACTION_SET`

**Value:** `(1)`

Action SET

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="argunused"></a>
### `ARG_UNUSED`

**Value:** `(void)(x)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="azmeasurementfreq"></a>
### `AZ_MEASUREMENT_FREQ`

**Value:** `4 /* in 0.1 Hz increments */`

> **Supported SoCs:** IW612

---

<a id="aznumberofmeasurements"></a>
### `AZ_NUMBER_OF_MEASUREMENTS`

**Value:** `6`

> **Supported SoCs:** IW612

---

<a id="aidmaxlength"></a>
### `A_ID_MAX_LENGTH`

**Value:** `33U`

Maximum length of the A-ID. The A-ID indicates the identity of the authority that issues PACs

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="bincounterlen"></a>
### `BIN_COUNTER_LEN`

**Value:** `(7)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="burstduration"></a>
### `BURST_DURATION`

**Value:** `11`

> **Supported SoCs:** IW612

---

<a id="burstexp"></a>
### `BURST_EXP`

**Value:** `3`

> **Supported SoCs:** IW612

---

<a id="burstperiod"></a>
### `BURST_PERIOD`

**Value:** `10`

> **Supported SoCs:** IW612

---

<a id="bw"></a>
### `BW`

**Value:** `13 /* RW610 only allows 20M bandwidth */`

> **Supported SoCs:** IW612

---

<a id="cardwakeupgpiopin"></a>
### `CARD_WAKEUP_GPIO_PIN`

**Value:** `13`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="cckdesensemodedisabled"></a>
### `CCK_DESENSE_MODE_DISABLED`

**Value:** `0`

> **Supported SoCs:** RW612, IW610

---

<a id="cckdesensemodedynamic"></a>
### `CCK_DESENSE_MODE_DYNAMIC`

**Value:** `1`

> **Supported SoCs:** RW612, IW610

---

<a id="cckdesensemodedynenh"></a>
### `CCK_DESENSE_MODE_DYN_ENH`

**Value:** `2`

> **Supported SoCs:** RW612, IW610

---

<a id="civicaddresstype"></a>
### `CIVIC_ADDRESS_TYPE`

**Value:** `22`

> **Supported SoCs:** IW612

---

<a id="civiccountrycode"></a>
### `CIVIC_COUNTRY_CODE`

**Value:** `0 /* US */`

> **Supported SoCs:** IW612

---

<a id="civiclocation"></a>
### `CIVIC_LOCATION`

**Value:** `1`

> **Supported SoCs:** IW612

---

<a id="civiclocationtype"></a>
### `CIVIC_LOCATION_TYPE`

**Value:** `1`

> **Supported SoCs:** IW612

---

<a id="civicrequest"></a>
### `CIVIC_REQUEST`

**Value:** `1`

> **Supported SoCs:** IW612

---

<a id="coexptafeaturedisable"></a>
### `COEX_PTA_FEATURE_DISABLE`

**Value:** `0`

> **Supported SoCs:** RW612

---

<a id="coexptafeatureenable"></a>
### `COEX_PTA_FEATURE_ENABLE`

**Value:** `1`

> **Supported SoCs:** RW612

---

<a id="dfsrechdrlen"></a>
### `DFS_REC_HDR_LEN`

**Value:** `(8)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="dfsrechdrnum"></a>
### `DFS_REC_HDR_NUM`

**Value:** `(10)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="disabletxrxhistogram"></a>
### `DISABLE_TX_RX_HISTOGRAM`

**Value:** `0x00`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="domainmatchmaxlength"></a>
### `DOMAIN_MATCH_MAX_LENGTH`

**Value:** `64U`

Maximum length of domain match

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="enabletxrxhistogram"></a>
### `ENABLE_TX_RX_HISTOGRAM`

**Value:** `0x01`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="eucryptoaadmaxlength"></a>
### `EU_CRYPTO_AAD_MAX_LENGTH`

**Value:** `32U`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="eucryptodatamaxlength"></a>
### `EU_CRYPTO_DATA_MAX_LENGTH`

**Value:** `1300U`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="eucryptokeyivmaxlength"></a>
### `EU_CRYPTO_KEYIV_MAX_LENGTH`

**Value:** `32U`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="eucryptokeymaxlength"></a>
### `EU_CRYPTO_KEY_MAX_LENGTH`

**Value:** `32U`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="eucryptononcemaxlength"></a>
### `EU_CRYPTO_NONCE_MAX_LENGTH`

**Value:** `14U`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="extcoexptainterface"></a>
### `EXT_COEX_PTA_INTERFACE`

**Value:** `5`

> **Supported SoCs:** RW612

---

<a id="extcoexwci2gpiointerface"></a>
### `EXT_COEX_WCI2_GPIO_INTERFACE`

**Value:** `7`

> **Supported SoCs:** RW612

---

<a id="extcoexwci2interface"></a>
### `EXT_COEX_WCI2_INTERFACE`

**Value:** `6`

> **Supported SoCs:** RW612

---

<a id="filetypeentpcacert"></a>
### `FILE_TYPE_ENTP_CA_CERT`

**Value:** `1`

> **Supported SoCs:** RW612, IW610

---

<a id="filetypeentpcacert2"></a>
### `FILE_TYPE_ENTP_CA_CERT2`

**Value:** `4`

> **Supported SoCs:** RW612, IW610

---

<a id="filetypeentpclientcert"></a>
### `FILE_TYPE_ENTP_CLIENT_CERT`

**Value:** `2`

> **Supported SoCs:** RW612, IW610

---

<a id="filetypeentpclientcert2"></a>
### `FILE_TYPE_ENTP_CLIENT_CERT2`

**Value:** `5`

> **Supported SoCs:** RW612, IW610

---

<a id="filetypeentpclientkey"></a>
### `FILE_TYPE_ENTP_CLIENT_KEY`

**Value:** `3`

> **Supported SoCs:** RW612, IW610

---

<a id="filetypeentpclientkey2"></a>
### `FILE_TYPE_ENTP_CLIENT_KEY2`

**Value:** `6`

> **Supported SoCs:** RW612, IW610

---

<a id="filetypeentpdhparams"></a>
### `FILE_TYPE_ENTP_DH_PARAMS`

**Value:** `10`

> **Supported SoCs:** RW612, IW610

---

<a id="filetypeentpservercert"></a>
### `FILE_TYPE_ENTP_SERVER_CERT`

**Value:** `8`

> **Supported SoCs:** RW612, IW610

---

<a id="filetypeentpserverkey"></a>
### `FILE_TYPE_ENTP_SERVER_KEY`

**Value:** `9`

> **Supported SoCs:** RW612, IW610

---

<a id="filetypenone"></a>
### `FILE_TYPE_NONE`

**Value:** `0`

> **Supported SoCs:** RW612, IW610

---

<a id="flagrxhistogram"></a>
### `FLAG_RX_HISTOGRAM`

**Value:** `0x02`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="flagtxhistogram"></a>
### `FLAG_TX_HISTOGRAM`

**Value:** `0x01`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="formatbw"></a>
### `FORMAT_BW`

**Value:** `2 /* RW610 only allows 20M bandwidth */`

> **Supported SoCs:** IW612

---

<a id="forranging"></a>
### `FOR_RANGING`

**Value:** `0`

> **Supported SoCs:** IW612

---

<a id="ftmactionstart"></a>
### `FTM_ACTION_START`

**Value:** `1`

> **Supported SoCs:** IW612

---

<a id="ftmactionstop"></a>
### `FTM_ACTION_STOP`

**Value:** `2`

> **Supported SoCs:** IW612

---

<a id="ftmperburst"></a>
### `FTM_PER_BURST`

**Value:** `5`

> **Supported SoCs:** IW612

---

<a id="gettxrxhistogram"></a>
### `GET_TX_RX_HISTOGRAM`

**Value:** `0x02`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="hashmaxlength"></a>
### `HASH_MAX_LENGTH`

**Value:** `40U`

Maximum length of CA certification hash

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="hostwakeupgpiopin"></a>
### `HOST_WAKEUP_GPIO_PIN`

**Value:** `12`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="i2rlmrfeedback"></a>
### `I2R_LMR_FEEDBACK`

**Value:** `0 /* allow RSTA to request I2R reporting */`

> **Supported SoCs:** IW612

---

<a id="identitymaxlength"></a>
### `IDENTITY_MAX_LENGTH`

**Value:** `64U`

An enterprise identity can be up to 64 characters

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="ieeetypesaddresssize"></a>
### `IEEEtypes_ADDRESS_SIZE`

**Value:** `6`

MAC Address length

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="ieeetypesssidsize"></a>
### `IEEEtypes_SSID_SIZE`

**Value:** `32U`

Maximum SSID length

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="isasap"></a>
### `IS_ASAP`

**Value:** `1`

> **Supported SoCs:** IW612

---

<a id="lcialtitude"></a>
### `LCI_ALTITUDE`

**Value:** `11.2`

> **Supported SoCs:** IW612

---

<a id="lcialtitudeuncertainity"></a>
### `LCI_ALTITUDE_UNCERTAINITY`

**Value:** `15`

> **Supported SoCs:** IW612

---

<a id="lcilatitiude"></a>
### `LCI_LATITIUDE`

**Value:** `-33.8570095`

> **Supported SoCs:** IW612

---

<a id="lcilatitudeuncertainity"></a>
### `LCI_LATITUDE_UNCERTAINITY`

**Value:** `18`

> **Supported SoCs:** IW612

---

<a id="lcilongitude"></a>
### `LCI_LONGITUDE`

**Value:** `151.2152005`

> **Supported SoCs:** IW612

---

<a id="lcilongitudeuncertainity"></a>
### `LCI_LONGITUDE_UNCERTAINITY`

**Value:** `18`

> **Supported SoCs:** IW612

---

<a id="lcirequest"></a>
### `LCI_REQUEST`

**Value:** `1`

> **Supported SoCs:** IW612

---

<a id="maxchannellist"></a>
### `MAX_CHANNEL_LIST`

**Value:** `6`

Configuration for Wi-Fi scan

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="maxi2rstsupto80"></a>
### `MAX_I2R_STS_UPTO80`

**Value:** `0 /* RW610 only allows to send 1 N_STS*/`

> **Supported SoCs:** IW612

---

<a id="maxr2istsupto80"></a>
### `MAX_R2I_STS_UPTO80`

**Value:** `0`

> **Supported SoCs:** IW612

---

<a id="maxsamptiming"></a>
### `MAX_SAMP_TIMING`

**Value:** `200`

> **Supported SoCs:** RW612

---

<a id="maxusers"></a>
### `MAX_USERS`

**Value:** `8U`

Maximum identities for EAP server users

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="mindelta"></a>
### `MIN_DELTA`

**Value:** `60`

> **Supported SoCs:** IW612

---

<a id="minsamptiming"></a>
### `MIN_SAMP_TIMING`

**Value:** `20`

> **Supported SoCs:** RW612

---

<a id="numchanbandenums"></a>
### `NUM_CHAN_BAND_ENUMS`

**Value:** `3`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="pacopaqueencrkeymaxlength"></a>
### `PAC_OPAQUE_ENCR_KEY_MAX_LENGTH`

**Value:** `33U`

Maximum length of encryption key for EAP-FAST PAC-Opaque values

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="passwordmaxlength"></a>
### `PASSWORD_MAX_LENGTH`

**Value:** `128U`

An enterprise password can be up to 128 characters

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="polgrantpinhigh"></a>
### `POL_GRANT_PIN_HIGH`

**Value:** `0`

> **Supported SoCs:** RW612

---

<a id="polgrantpinlow"></a>
### `POL_GRANT_PIN_LOW`

**Value:** `1`

> **Supported SoCs:** RW612

---

<a id="protodot11azntb"></a>
### `PROTO_DOT11AZ_NTB`

**Value:** `1`

> **Supported SoCs:** IW612

---

<a id="protodot11aztb"></a>
### `PROTO_DOT11AZ_TB`

**Value:** `2`

> **Supported SoCs:** IW612

---

<a id="protodot11mc"></a>
### `PROTO_DOT11MC`

**Value:** `0`

> **Supported SoCs:** IW612

---

<a id="sampletimingvalue"></a>
### `SAMPLE_TIMING_VALUE`

**Value:** `100`

> **Supported SoCs:** RW612

---

<a id="stateinputdisable"></a>
### `STATE_INPUT_DISABLE`

**Value:** `0`

> **Supported SoCs:** RW612

---

<a id="stateprioritypin"></a>
### `STATE_PRIORITY_PIN`

**Value:** `2`

> **Supported SoCs:** RW612

---

<a id="stateptapin"></a>
### `STATE_PTA_PIN`

**Value:** `1`

> **Supported SoCs:** RW612

---

<a id="txampducts2self"></a>
### `TX_AMPDU_CTS_2_SELF`

**Value:** `1`

> **Supported SoCs:** RW612, IW610

---

<a id="txampdudisableprotection"></a>
### `TX_AMPDU_DISABLE_PROTECTION`

**Value:** `2`

> **Supported SoCs:** RW612, IW610

---

<a id="txampdudynamicrtscts"></a>
### `TX_AMPDU_DYNAMIC_RTS_CTS`

**Value:** `3`

> **Supported SoCs:** RW612, IW610

---

<a id="txampdurtscts"></a>
### `TX_AMPDU_RTS_CTS`

**Value:** `0`

> **Supported SoCs:** RW612, IW610

---

<a id="unspecwpsnetwork"></a>
### `UNSPEC_WPS_NETWORK`

**Value:** `MBIT(0)`

When the temporary network is of type WPS, bit 0 is 1.

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlan11dscanlimit"></a>
### `WLAN_11D_SCAN_LIMIT`

**Value:** `3U`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanampdudensity"></a>
### `WLAN_AMPDU_DENSITY`

**Value:** `0x30`

> **Supported SoCs:** RW612, IW610

---

<a id="wlanampdummsf"></a>
### `WLAN_AMPDU_MMSF`

**Value:** `0x6`

> **Supported SoCs:** RW612, IW610

---

<a id="wlanbandcfg11ac"></a>
### `WLAN_BANDCFG_11AC`

**Value:** `MBIT(1)`

> **Supported SoCs:** RW612, IW610, IW612

---

<a id="wlanbandcfg11ax"></a>
### `WLAN_BANDCFG_11AX`

**Value:** `MBIT(2)`

> **Supported SoCs:** RW612, IW610, IW612

---

<a id="wlanbandcfg11n"></a>
### `WLAN_BANDCFG_11N`

**Value:** `MBIT(0)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlancipheraes128cmac"></a>
### `WLAN_CIPHER_AES_128_CMAC`

**Value:** `MBIT(5)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlancipherbipcmac256"></a>
### `WLAN_CIPHER_BIP_CMAC_256`

**Value:** `MBIT(13)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlancipherbipgmac128"></a>
### `WLAN_CIPHER_BIP_GMAC_128`

**Value:** `MBIT(11)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlancipherbipgmac256"></a>
### `WLAN_CIPHER_BIP_GMAC_256`

**Value:** `MBIT(12)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlancipherccmp"></a>
### `WLAN_CIPHER_CCMP`

**Value:** `MBIT(4)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlancipherccmp256"></a>
### `WLAN_CIPHER_CCMP_256`

**Value:** `MBIT(9)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanciphergcmp"></a>
### `WLAN_CIPHER_GCMP`

**Value:** `MBIT(6)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanciphergcmp256"></a>
### `WLAN_CIPHER_GCMP_256`

**Value:** `MBIT(8)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanciphergtknotused"></a>
### `WLAN_CIPHER_GTK_NOT_USED`

**Value:** `MBIT(14)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanciphernone"></a>
### `WLAN_CIPHER_NONE`

**Value:** `MBIT(0)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanciphersms4"></a>
### `WLAN_CIPHER_SMS4`

**Value:** `MBIT(7)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanciphertkip"></a>
### `WLAN_CIPHER_TKIP`

**Value:** `MBIT(3)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlancipherwep104"></a>
### `WLAN_CIPHER_WEP104`

**Value:** `MBIT(2)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlancipherwep40"></a>
### `WLAN_CIPHER_WEP40`

**Value:** `MBIT(1)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanerroraction"></a>
### `WLAN_ERROR_ACTION`

**Value:** `4`

The operation failed due to an internal error

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanerrornomem"></a>
### `WLAN_ERROR_NOMEM`

**Value:** `2`

The operation could not be performed because there is not enough memory

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanerrornone"></a>
### `WLAN_ERROR_NONE`

**Value:** `0`

Error codes The operation was successful

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanerrornotsupported"></a>
### `WLAN_ERROR_NOT_SUPPORTED`

**Value:** `6`

The requested feature is not supported

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanerrorparam"></a>
### `WLAN_ERROR_PARAM`

**Value:** `1`

The operation failed due to an error with one or more parameters

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanerrorpsaction"></a>
### `WLAN_ERROR_PS_ACTION`

**Value:** `5`

The operation to change the power state could not be performed

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanerrorstate"></a>
### `WLAN_ERROR_STATE`

**Value:** `3`

The operation could not be performed in the current system state

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanhostsleepfail"></a>
### `WLAN_HOSTSLEEP_FAIL`

**Value:** `3`

> **Supported SoCs:** RW612, IW610

---

<a id="wlanhostsleepinprocess"></a>
### `WLAN_HOSTSLEEP_IN_PROCESS`

**Value:** `2`

> **Supported SoCs:** RW612, IW610

---

<a id="wlanhostsleepsuccess"></a>
### `WLAN_HOSTSLEEP_SUCCESS`

**Value:** `1`

> **Supported SoCs:** RW612, IW610

---

<a id="wlankeymgmtcckm"></a>
### `WLAN_KEY_MGMT_CCKM`

**Value:** `MBIT(14)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlankeymgmtdpp"></a>
### `WLAN_KEY_MGMT_DPP`

**Value:** `MBIT(23)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlankeymgmtfilssha256"></a>
### `WLAN_KEY_MGMT_FILS_SHA256`

**Value:** `MBIT(18)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlankeymgmtfilssha384"></a>
### `WLAN_KEY_MGMT_FILS_SHA384`

**Value:** `MBIT(19)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlankeymgmtft"></a>
### `WLAN_KEY_MGMT_FT`

**Value:** `(WLAN_KEY_MGMT_FT_PSK | WLAN_KEY_MGMT_FT_IEEE8021X | WLAN_KEY_MGMT_FT_IEEE8021X_SHA384 | WLAN_KEY_MGMT_FT_SAE | \
     WLAN_KEY_MGMT_FT_FILS_SHA256 | WLAN_KEY_MGMT_FT_FILS_SHA384)`

Fast BSS Transition(11r) key management

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlankeymgmtftfilssha256"></a>
### `WLAN_KEY_MGMT_FT_FILS_SHA256`

**Value:** `MBIT(20)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlankeymgmtftfilssha384"></a>
### `WLAN_KEY_MGMT_FT_FILS_SHA384`

**Value:** `MBIT(21)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlankeymgmtftieee8021x"></a>
### `WLAN_KEY_MGMT_FT_IEEE8021X`

**Value:** `MBIT(5)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlankeymgmtftieee8021xsha384"></a>
### `WLAN_KEY_MGMT_FT_IEEE8021X_SHA384`

**Value:** `MBIT(24)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlankeymgmtftpsk"></a>
### `WLAN_KEY_MGMT_FT_PSK`

**Value:** `MBIT(6)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlankeymgmtftsae"></a>
### `WLAN_KEY_MGMT_FT_SAE`

**Value:** `MBIT(11)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlankeymgmtieee8021x"></a>
### `WLAN_KEY_MGMT_IEEE8021X`

**Value:** `MBIT(0)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlankeymgmtieee8021xnowpa"></a>
### `WLAN_KEY_MGMT_IEEE8021X_NO_WPA`

**Value:** `MBIT(3)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlankeymgmtieee8021xsha256"></a>
### `WLAN_KEY_MGMT_IEEE8021X_SHA256`

**Value:** `MBIT(7)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlankeymgmtieee8021xsuiteb"></a>
### `WLAN_KEY_MGMT_IEEE8021X_SUITE_B`

**Value:** `MBIT(16)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlankeymgmtieee8021xsuiteb192"></a>
### `WLAN_KEY_MGMT_IEEE8021X_SUITE_B_192`

**Value:** `MBIT(17)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlankeymgmtnone"></a>
### `WLAN_KEY_MGMT_NONE`

**Value:** `MBIT(2)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlankeymgmtosen"></a>
### `WLAN_KEY_MGMT_OSEN`

**Value:** `MBIT(15)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlankeymgmtowe"></a>
### `WLAN_KEY_MGMT_OWE`

**Value:** `MBIT(22)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlankeymgmtpasn"></a>
### `WLAN_KEY_MGMT_PASN`

**Value:** `MBIT(25)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlankeymgmtpsk"></a>
### `WLAN_KEY_MGMT_PSK`

**Value:** `MBIT(1)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlankeymgmtpsksha256"></a>
### `WLAN_KEY_MGMT_PSK_SHA256`

**Value:** `MBIT(8)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlankeymgmtsae"></a>
### `WLAN_KEY_MGMT_SAE`

**Value:** `MBIT(10)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlankeymgmtsaeextkey"></a>
### `WLAN_KEY_MGMT_SAE_EXT_KEY`

**Value:** `MBIT(26)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlankeymgmtwapicert"></a>
### `WLAN_KEY_MGMT_WAPI_CERT`

**Value:** `MBIT(13)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlankeymgmtwapipsk"></a>
### `WLAN_KEY_MGMT_WAPI_PSK`

**Value:** `MBIT(12)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlankeymgmtwpanone"></a>
### `WLAN_KEY_MGMT_WPA_NONE`

**Value:** `MBIT(4)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlankeymgmtwps"></a>
### `WLAN_KEY_MGMT_WPS`

**Value:** `MBIT(9)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanmacaddrlength"></a>
### `WLAN_MAC_ADDR_LENGTH`

**Value:** `6`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanmaxknownnetworks"></a>
### `WLAN_MAX_KNOWN_NETWORKS`

**Value:** `CONFIG_WLAN_KNOWN_NETWORKS`

The size of the list of known networks maintained by the Wi-Fi connection manager

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanmaxstafilternum"></a>
### `WLAN_MAX_STA_FILTER_NUM`

**Value:** `16`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanmgmtaction"></a>
### `WLAN_MGMT_ACTION`

**Value:** `MBIT(13)`

Bitmap for Action frame

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanmgmtauth"></a>
### `WLAN_MGMT_AUTH`

**Value:** `MBIT(11)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanmgmtdeauth"></a>
### `WLAN_MGMT_DEAUTH`

**Value:** `MBIT(12)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanmgmtdiassoc"></a>
### `WLAN_MGMT_DIASSOC`

**Value:** `MBIT(10)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanmgmtproberqst"></a>
### `WLAN_MGMT_PROBE_RQST`

**Value:** `MBIT(4)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlannetworkchanlistmax"></a>
### `WLAN_NETWORK_CHAN_LIST_MAX`

**Value:** `50U`

Maximum number of channels storable in a scan channel list of a network

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlannetworknamemaxlength"></a>
### `WLAN_NETWORK_NAME_MAX_LENGTH`

**Value:** `32U`

Maximum length for network names. See wlan_network.

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlannetworknameminlength"></a>
### `WLAN_NETWORK_NAME_MIN_LENGTH`

**Value:** `1U`

Minimum length for network names, see wlan_network.

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanpasswordmaxlength"></a>
### `WLAN_PASSWORD_MAX_LENGTH`

**Value:** `255U`

A WPA3 password can be up to 255 ASCII characters

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanpasswordminlength"></a>
### `WLAN_PASSWORD_MIN_LENGTH`

**Value:** `8U`

A WPA3 password must be at least 8 ASCII characters

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanpmklength"></a>
### `WLAN_PMK_LENGTH`

**Value:** `32`

Length of a pairwise master key (PMK). It's always 256 bits (32 Bytes)

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanpskmaxlength"></a>
### `WLAN_PSK_MAX_LENGTH`

**Value:** `64U`

Maximum WPA2 passphrase can be up to 63 ASCII chars + 1 '\0' char

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanpskminlength"></a>
### `WLAN_PSK_MIN_LENGTH`

**Value:** `8U`

A WPA2 passphrase must be at least 8 ASCII characters

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanreasoncodeprevauthnotvalid"></a>
### `WLAN_REASON_CODE_PREV_AUTH_NOT_VALID`

**Value:** `2U`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanreconnectlimit"></a>
### `WLAN_RECONNECT_LIMIT`

**Value:** `CONFIG_MAX_RECONNECT_LIMIT`

The number of times that the Wi-Fi connection manager attempts a reconnection with the network before giving up.

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanrescanlimit"></a>
### `WLAN_RESCAN_LIMIT`

**Value:** `CONFIG_MAX_RESCAN_LIMIT`

The number of times that the Wi-Fi connection manager looks for a network before giving up.

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanstatsget"></a>
### `WLAN_STATS_GET`

**Value:** `(priv->x)`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanstatsinc"></a>
### `WLAN_STATS_INC`

**Value:** `(++(priv->x))`

Wi-Fi statistics

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wmmuapsdqosinfo"></a>
### `WMM_UAPSD_QOS_INFO`

**Value:** `0x0F`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wmmuapsdsleepperiod"></a>
### `WMM_UAPSD_SLEEP_PERIOD`

**Value:** `20`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="zinfo"></a>
### `Z_INFO`

**Value:** `0`

> **Supported SoCs:** IW612

---

<a id="wlcmd"></a>
### `wlcm_d`

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="functions"></a>
## Functions

<a id="initializationlifecycle"></a>
### Initialization & Lifecycle

| Function | Supported SoCs |
|----------|---------------|
| [`wlan_basic_cli_deinit`](#wlanbasicclideinit) | All |
| [`wlan_basic_cli_init`](#wlanbasiccliinit) | All |
| [`wlan_cli_deinit`](#wlanclideinit) | All |
| [`wlan_cli_init`](#wlancliinit) | All |
| [`wlan_deinit`](#wlandeinit) | All |
| [`wlan_destroy_all_tasks`](#wlandestroyalltasks) | All |
| [`wlan_enhanced_cli_deinit`](#wlanenhancedclideinit) | All |
| [`wlan_enhanced_cli_init`](#wlanenhancedcliinit) | All |
| [`wlan_init`](#wlaninit) | All |
| [`wlan_reset`](#wlanreset) | All |
| [`wlan_start`](#wlanstart) | All |
| [`wlan_stop`](#wlanstop) | All |
| [`wlan_wfa_basic_cli_deinit`](#wlanwfabasicclideinit) | All |
| [`wlan_wfa_basic_cli_init`](#wlanwfabasiccliinit) | All |

<a id="wlanbasicclideinit"></a>
### `wlan_basic_cli_deinit`

```c
int wlan_basic_cli_deinit (void **)
```

Unregister basic Wi-Fi CLI commands.

**Returns**

- WLAN_ERROR_NONE if the CLI commands were unregistered.
- WLAN_ERROR_ACTION if they were not unregistered (for example. if this function was called while the CLI commands were not registered or were already unregistered).

> **Note**: This function gets called by wlan_cli_deinit(), hence only one function out of these two functions should be called in the application.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanbasiccliinit"></a>
### `wlan_basic_cli_init`

```c
int wlan_basic_cli_init (void **)
```

Registers basic Wi-Fi CLI (command line input) commands.

**Returns**

- WLAN_ERROR_NONE if the CLI commands were registered.
- WLAN_ERROR_ACTION if they were not registered (for example. if this function was called while the CLI commands were already registered).

> **Note**: This function can only be called by the application after wlan_init() called.

> **Note**: This function gets called by wlan_cli_init(), hence only one function out of these two functions should be called in the application.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanclideinit"></a>
### `wlan_cli_deinit`

```c
int wlan_cli_deinit (void **)
```

Unregister Wi-Fi CLI commands.

**Returns**

- WM_SUCCESS if the CLI commands were unregistered or.
- -WM_FAIL if they were not (for example if this function was called while the CLI commands were already unregistered).

> **Note**: This function can only be called by the application after wlan_init() called.

> **Note**: This function internally calls wlan_basic_cli_deinit(), hence only one function out of these two functions should be called in the application.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlancliinit"></a>
### `wlan_cli_init`

```c
int wlan_cli_init (void **)
```

Registers Wi-Fi CLI (command line input) commands.

**Returns**

- WM_SUCCESS if the CLI commands were registered or.
- -WM_FAIL if they were not (for example if this function was called while the CLI commands were already registered).

> **Note**: This function can only be called by the application after wlan_init() called.

> **Note**: This function internally calls wlan_basic_cli_init(), hence only one function out of these two functions should be called in the application.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlandeinit"></a>
### `wlan_deinit`

```c
void wlan_deinit (int *action*)
```

Deinitialize the Wi-Fi driver, send a shutdown command to the Wi-Fi firmware and delete the Wi-Fi driver thread.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `action` | in | Additional action to be taken with deinit. Should input 0 here. |

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlandestroyalltasks"></a>
### `wlan_destroy_all_tasks`

```c
void wlan_destroy_all_tasks (void **)
```

This API destroys all tasks.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanenhancedclideinit"></a>
### `wlan_enhanced_cli_deinit`

```c
int wlan_enhanced_cli_deinit (void **)
```

Unregister Wi-Fi enhanced CLI commands.

**Returns**

- WM_SUCCESS if the CLI commands were unregistered or.
- -WM_FAIL if they were not unregistered.

> **Note**: This function can only be called by the application after wlan_init() called.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanenhancedcliinit"></a>
### `wlan_enhanced_cli_init`

```c
int wlan_enhanced_cli_init (void **)
```

Registers Wi-Fi enhanced CLI commands.

**Returns**

- WM_SUCCESS if the CLI commands were registered or.
- -WM_FAIL if they were not (for example if this function was called while the CLI commands were already registered).

> **Note**: This function can only be called by the application after wlan_init() called.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlaninit"></a>
### `wlan_init`

```c
int wlan_init (const uint8_t * *fw_start_addr*, const size_t *size*)
```

Initialize the Wi-Fi driver and create the Wi-Fi driver thread.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `fw_start_addr` | in | Start address of the Wi-Fi firmware. |
| `size` | in | Size of the Wi-Fi firmware. |

**Returns**

- WM_SUCCESS if the Wi-Fi connection manager service has initialized successfully.
- Negative value if initialization failed.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanreset"></a>
### `wlan_reset`

```c
void wlan_reset (cli_reset_option *ResetOption*)
```

Resets the driver.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `ResetOption` | in | Option including enable, disable or reset Wi-Fi driver can be chosen. |

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanstart"></a>
### `wlan_start`

```c
int wlan_start (int(*)(enum wlan_event_reason reason, void *data) *cb*)
```

Starts the Wi-Fi connection manager service.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `cb` | in | A pointer to a callback function that handles Wi-Fi events. All. further WLCMGR events can be notified in this callback. Refer to enum wlan_event_reason for the various events for which this callback is called. |

**Returns**

- WM_SUCCESS if the Wi-Fi connection manager service has started successfully.
- -WM_E_INVAL if the cb pointer is NULL.
- -WM_FAIL if an internal error occurred.
- WLAN_ERROR_STATE if the Wi-Fi connection manager is already running.

> **Note**: The status of the Wi-Fi connection manager is notified asynchronously through the callback, cb, with a WLAN_REASON_INITIALIZED event (if initialization succeeded) or WLAN_REASON_INITIALIZATION_FAILED (if initialization failed). If the Wi-Fi connection manager fails to initialize, the caller should stop Wi-Fi connection manager via wlan_stop() and try wlan_start() again.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanstop"></a>
### `wlan_stop`

```c
int wlan_stop (void **)
```

Stops the Wi-Fi connection manager service.

**Returns**

- WM_SUCCESS if the Wi-Fi connection manager service has been stopped successfully.
- WLAN_ERROR_STATE if the Wi-Fi connection manager was not running.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanwfabasicclideinit"></a>
### `wlan_wfa_basic_cli_deinit`

```c
int wlan_wfa_basic_cli_deinit (void **)
```

Unregister WFA basic Wi-Fi CLI (command line input) commands.

**Returns**

- WLAN_ERROR_NONE if the CLI commands were unregistered or.
- WLAN_ERROR_ACTION if they were not unregistered.

> **Note**: This function can only be called by the application after wlan_init() called.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanwfabasiccliinit"></a>
### `wlan_wfa_basic_cli_init`

```c
int wlan_wfa_basic_cli_init (void **)
```

Registers WFA basic Wi-Fi CLI (command line input) commands.

**Returns**

- WLAN_ERROR_NONE if the CLI commands were registered or.
- WLAN_ERROR_ACTION if they were not registered (for example if this function was called while the CLI commands were already registered).

> **Note**: This function can only be called by the application after wlan_init() called.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---


<a id="connectionmanagement"></a>
### Connection Management

| Function | Supported SoCs |
|----------|---------------|
| [`is_sta_associated`](#isstaassociated) | All |
| [`is_sta_connected`](#isstaconnected) | All |
| [`is_sta_ipv4_connected`](#isstaipv4connected) | All |
| [`is_sta_ipv6_connected`](#isstaipv6connected) | All |
| [`wlan_connect`](#wlanconnect) | All |
| [`wlan_connect_opt`](#wlanconnectopt) | All |
| [`wlan_disconnect`](#wlandisconnect) | All |
| [`wlan_get_connection_state`](#wlangetconnectionstate) | All |
| [`wlan_is_started`](#wlanisstarted) | All |
| [`wlan_reassociate`](#wlanreassociate) | All |
| [`wlan_wlcmgr_send_msg`](#wlanwlcmgrsendmsg) | All |

<a id="isstaassociated"></a>
### `is_sta_associated`

```c
bool is_sta_associated (void **)
```

Retrieves the status information of the station interface.

**Returns**

- TRUE if station interface is in or above the WLAN_ASSOCIATED state.
- FALSE otherwise.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="isstaconnected"></a>
### `is_sta_connected`

```c
bool is_sta_connected (void **)
```

Retrieves the status information of the station interface.

**Returns**

- TRUE if station interface is in WLAN_CONNECTED state.
- FALSE otherwise.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="isstaipv4connected"></a>
### `is_sta_ipv4_connected`

```c
bool is_sta_ipv4_connected (void **)
```

Retrieves the status information of the IPv4 network of the station interface.

**Returns**

- TRUE if ipv4 network of the station interface is in WLAN_CONNECTED state.
- FALSE otherwise.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="isstaipv6connected"></a>
### `is_sta_ipv6_connected`

```c
bool is_sta_ipv6_connected (void **)
```

Retrieves the status information of the IPv6 network of the station interface.

**Returns**

- TRUE if ipv6 network of the station interface is in WLAN_CONNECTED state.
- FALSE otherwise.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanconnect"></a>
### `wlan_connect`

```c
int wlan_connect (char * *name*)
```

Connect to a Wi-Fi network (access point).

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `name` | in | A pointer to a string representing the name of the network to connect to. |

**Returns**

- WM_SUCCESS if a connection attempt was started successfully.
- WLAN_ERROR_STATE if the Wi-Fi connection manager was not running.
- -WM_E_INVAL if there are no known networks to connect to or the network specified by name is not in the list of known networks or network name is NULL.
- -WM_FAIL if an internal error has occurred.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanconnectopt"></a>
### `wlan_connect_opt`

```c
int wlan_connect_opt (char * *name*, bool *skip_dfs*)
```

Connect to a Wi-Fi network (access point) with options.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `name` | in | A pointer to a string representing the name of the network to connect to. |
| `skip_dfs` | in | Option to skip DFS channel when doing scan. |

**Returns**

- WM_SUCCESS if a connection attempt was started successfully.
- WLAN_ERROR_STATE if the Wi-Fi connection manager was not running.
- -WM_E_INVAL if there are no known networks to connect to or the network specified by name is not in the list of known networks or network name is NULL.
- -WM_FAIL if an internal error has occurred.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlandisconnect"></a>
### `wlan_disconnect`

```c
int wlan_disconnect (void **)
```

Disconnects from the current Wi-Fi network (access point).

**Returns**

- WM_SUCCESS if successful.
- WLAN_ERROR_STATE otherwise.

> **Note**: This is an asynchronous function and successful disconnection should be notified using the WLAN_REASON_USER_DISCONNECT.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetconnectionstate"></a>
### `wlan_get_connection_state`

```c
int wlan_get_connection_state (enum wlan_connection_state * *state*)
```

Retrieves the connection state of the station interface.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `state` | out | A pointer to the wlan_connection_state where the current connection state must be copied. |

**Returns**

- WM_SUCCESS if successful.
- -WM_E_INVAL if state is NULL.
- WLAN_ERROR_STATE if the Wi-Fi connection manager was not running.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanisstarted"></a>
### `wlan_is_started`

```c
int wlan_is_started (void **)
```

Retrieves the status information of if Wi-Fi started.

**Returns**

- TRUE if Wi-Fi network is started.
- FALSE if not started.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanreassociate"></a>
### `wlan_reassociate`

```c
int wlan_reassociate (void **)
```

Reassociates with a Wi-Fi network (access point).

**Returns**

- WM_SUCCESS if a reassociation attempt was started successfully.
- WLAN_ERROR_STATE if the Wi-Fi connection manager was not running. or Wi-Fi connection manager was not in WLAN_CONNECTED state.
- -WM_E_INVAL if there are no known networks to connect to.
- -WM_FAIL if an internal error has occurred.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanwlcmgrsendmsg"></a>
### `wlan_wlcmgr_send_msg`

```c
int wlan_wlcmgr_send_msg (enum wlan_bss_type *bss_type*, enum wifi_event *event*, enum wifi_event_reason *reason*, void * *data*)
```

Sends message to Wi-Fi connection manager thread.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `bss_type` | in |  |
| `event` | in | An event from wifi_event. |
| `reason` | in | A reason code. |
| `data` | in | A pointer to data buffer associated with event. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---


<a id="networkmanagement"></a>
### Network Management

| Function | Supported SoCs |
|----------|---------------|
| [`wlan_add_network`](#wlanaddnetwork) | All |
| [`wlan_get_network`](#wlangetnetwork) | All |
| [`wlan_get_network_byname`](#wlangetnetworkbyname) | All |
| [`wlan_get_network_count`](#wlangetnetworkcount) | All |
| [`wlan_initialize_sta_network`](#wlaninitializestanetwork) | All |
| [`wlan_remove_all_network_profiles`](#wlanremoveallnetworkprofiles) | All |
| [`wlan_remove_all_networks`](#wlanremoveallnetworks) | All |
| [`wlan_remove_network`](#wlanremovenetwork) | All |

<a id="wlanaddnetwork"></a>
### `wlan_add_network`

```c
int wlan_add_network (struct wlan_network * *network*)
```

Adds a network profile to the list of known networks.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `network` | in | A pointer to the wlan_network that can be copied to the list of known networks in the Wi-Fi connection manager successfully. |

**Returns**

- WM_SUCCESS if the contents pointed to by network have been added to the Wi-Fi connection manager.
- -WM_E_INVAL if network is NULL or the network name is not unique or the network name length is not valid or network security is WLAN_SECURITY_WPA3_SAE but Management Frame Protection Capable is not enabled. in wlan_network_security field. if network security type is. WLAN_SECURITY_WPA or WLAN_SECURITY_WPA2 or WLAN_SECURITY_WPA_WPA2_MIXED, but the passphrase length is less than 8 or greater than 63, or the psk length equal to 64 but not hexadecimal digits. if network security type is WLAN_SECURITY_WPA3_SAE, but the password length is less than 8 or greater than 255. if network security type is WLAN_SECURITY_WEP_OPEN or WLAN_SECURITY_WEP_SHARED.
- -WM_E_NOMEM if there was no room to add the network.
- WLAN_ERROR_STATE if the Wi-Fi connection manager was running and not in the WLAN_DISCONNECTED, WLAN_ASSOCIATED or WLAN_CONNECTED state.

> **Note**: Profiles for the station interface may be added only when the station interface is in the WLAN_DISCONNECTED or WLAN_CONNECTED state.

> **Note**: This API can be used to add profiles for station or uAP interfaces.

> **Note**: Set mfpc and mfpr to -1 for default configurations.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetnetwork"></a>
### `wlan_get_network`

```c
int wlan_get_network (unsigned int *index*, struct wlan_network * *network*)
```

Retrieves the information about a known network using index.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `index` | in | The index of the network to retrieve. |
| `network` | out | A pointer to the wlan_network where the network configuration for the network at index can be copied. |

**Returns**

- WM_SUCCESS if successful.
- -WM_E_INVAL if network is NULL or index is out of range.

> **Note**: wlan_get_network_count() can be used to retrieve the number of known networks. wlan_get_network() can be used to retrieve information about networks at index 0 to one minus the number of networks.

> **Note**: This function can be called regardless of whether the Wi-Fi connection manager is running or not. Calls to this function are synchronous.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetnetworkbyname"></a>
### `wlan_get_network_byname`

```c
int wlan_get_network_byname (char * *name*, struct wlan_network * *network*)
```

Retrieves information about a known network using name.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `name` | in | The name of the network to retrieve. |
| `network` | out | A pointer to the wlan_network where the network configuration for the network having name as name must be copied. |

**Returns**

- WM_SUCCESS if successful.
- -WM_E_INVAL if network is NULL or name is NULL.

> **Note**: This function can be called regardless of whether the Wi-Fi Connection Manager is running or not. Calls to this function are synchronous.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetnetworkcount"></a>
### `wlan_get_network_count`

```c
int wlan_get_network_count (unsigned int * *count*)
```

Retrieves the number of networks known to the Wi-Fi connection manager.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `count` | out | A pointer to the memory location where the number of networks must be copied. |

**Returns**

- WM_SUCCESS if successful.
- -WM_E_INVAL if count is NULL.

> **Note**: This function can be called regardless of whether the Wi-Fi Connection Manager is running or not. Calls to this function are synchronous.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlaninitializestanetwork"></a>
### `wlan_initialize_sta_network`

```c
void wlan_initialize_sta_network (struct wlan_network * *net*)
```

Initialize the station network information.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `net` | out | Pointer to the initialized station network. |

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanremoveallnetworkprofiles"></a>
### `wlan_remove_all_network_profiles`

```c
int wlan_remove_all_network_profiles (void **)
```

Stops and removes all Wi-Fi network profiles.

**Returns**

WM_SUCCESS if successful otherwise return -WM_E_INVAL.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanremoveallnetworks"></a>
### `wlan_remove_all_networks`

```c
int wlan_remove_all_networks (void **)
```

Stops and removes all Wi-Fi network (access point).

**Returns**

WM_SUCCESS if successful.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanremovenetwork"></a>
### `wlan_remove_network`

```c
int wlan_remove_network (const char * *name*)
```

Removes a network profile from the list of known networks.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `name` | in | A pointer to the string representing the name of the network to remove. |

**Returns**

- WM_SUCCESS if the network named name was removed from the Wi-Fi connection manager successfully. Otherwise, the network is not removed.
- WLAN_ERROR_STATE if the Wi-Fi connection manager was running and the station interface was not in the WLAN_DISCONNECTED state.
- -WM_E_INVAL if name is NULL or the network was not found in the list of known networks.
- -WM_FAIL if an internal error occurred while trying to disconnect from the network specified for removal.

> **Note**: This function is asynchronous if it is called while the WLAN Connection Manager is running and connected to the network to be removed. In that case, the Wi-Fi connection manager can disconnect from the network and generate an event with reason WLAN_REASON_USER_DISCONNECT. This function is synchronous otherwise.

> **Note**: This API can be used to remove profiles for station or uAP interfaces. Station network can not be removed if it is in WLAN_CONNECTED state and uAP network can not be removed if it is in WLAN_UAP_STARTED state.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---


<a id="networkstatus"></a>
### Network Status

| Function | Supported SoCs |
|----------|---------------|
| [`wlan_get_address`](#wlangetaddress) | All |
| [`wlan_get_current_bssid`](#wlangetcurrentbssid) | All |
| [`wlan_get_current_network`](#wlangetcurrentnetwork) | All |
| [`wlan_get_current_network_bssid`](#wlangetcurrentnetworkbssid) | All |
| [`wlan_get_current_network_ssid`](#wlangetcurrentnetworkssid) | All |

<a id="wlangetaddress"></a>
### `wlan_get_address`

```c
int wlan_get_address (struct wlan_ip_config * *addr*)
```

Retrieves the IP address configuration of the station interface.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `addr` | out | A pointer to the wlan_ip_config. |

**Returns**

- WM_SUCCESS if successful.
- -WM_E_INVAL if addr is NULL.
- WLAN_ERROR_STATE if the Wi-Fi connection manager was not running or was not in the WLAN_CONNECTED state.
- -WM_FAIL if an internal error occurred when retrieving IP address information from the TCP stack.

> **Note**: This function may only be called when the station interface is in the WLAN_CONNECTED state.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetcurrentbssid"></a>
### `wlan_get_current_bssid`

```c
int wlan_get_current_bssid (uint8_t * *bssid*)
```

Use this API to get the BSSID of associated BSS when in station mode.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `bssid` | out | A pointer to array(char, length is 6) to store the BSSID. |

**Returns**

- WM_SUCCESS if operation is successful.
- -WM_FAIL if command fails.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetcurrentnetwork"></a>
### `wlan_get_current_network`

```c
int wlan_get_current_network (struct wlan_network * *network*)
```

Retrieves the current network configuration of the station interface.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `network` | out | A pointer to the wlan_network. |

**Returns**

- WM_SUCCESS if successful.
- -WM_E_INVAL if network is NULL.
- WLAN_ERROR_STATE if the Wi-Fi connection manager was not running or not in the WLAN_CONNECTED state.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetcurrentnetworkbssid"></a>
### `wlan_get_current_network_bssid`

```c
int wlan_get_current_network_bssid (char * *bssid*)
```

Retrieves the current network BSSID of the station interface.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `bssid` | out | A pointer to the bssid char string without NULL termination. |

**Returns**

- WM_SUCCESS if successful.
- -WM_E_INVAL if bssid is NULL.
- WLAN_ERROR_STATE if the Wi-Fi connection manager was not running or not in the WLAN_CONNECTED state.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetcurrentnetworkssid"></a>
### `wlan_get_current_network_ssid`

```c
int wlan_get_current_network_ssid (char * *ssid*)
```

Retrieves the current network SSID of the station interface.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `ssid` | out | A pointer to the ssid char string with NULL termination. The maximum length is 32 (not include NULL termination). |

**Returns**

- WM_SUCCESS if successful.
- -WM_E_INVAL if ssid is NULL.
- WLAN_ERROR_STATE if the Wi-Fi connection manager was not running or not in the WLAN_CONNECTED state.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---


<a id="scan"></a>
### Scan

| Function | Supported SoCs |
|----------|---------------|
| [`get_scan_params`](#getscanparams) | All |
| [`set_scan_params`](#setscanparams) | All |
| [`verify_scan_channel_value`](#verifyscanchannelvalue) | All |
| [`verify_scan_duration_value`](#verifyscandurationvalue) | All |
| [`verify_split_scan_delay`](#verifysplitscandelay) | All |
| [`wlan_get_scan_result`](#wlangetscanresult) | All |
| [`wlan_scan`](#wlanscan) | All |
| [`wlan_scan_with_opt`](#wlanscanwithopt) | All |
| [`wlan_select_cur_network_by_scan_res`](#wlanselectcurnetworkbyscanres) | All |
| [`wlan_set_scan_interval`](#wlansetscaninterval) | All |

<a id="getscanparams"></a>
### `get_scan_params`

```c
int get_scan_params (struct wifi_scan_params_t * *wifi_scan_params*)
```

Gets the scan parameters.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `wifi_scan_params` | out | Wi-Fi scan parameter structure pointer. |

**Returns**

WM_SUCCESS.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="setscanparams"></a>
### `set_scan_params`

```c
int set_scan_params (struct wifi_scan_params_t * *wifi_scan_params*)
```

Sets the scan parameters.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `wifi_scan_params` | in | Wi-Fi scan parameter structure pointer. |

**Returns**

0 if Wi-Fi scan parameters are set successfully, else return -1.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="verifyscanchannelvalue"></a>
### `verify_scan_channel_value`

```c
int verify_scan_channel_value (int *channel*)
```

Checks whether the scan channel is valid or not.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `channel` | in | the scan channel. |

**Returns**

0 if the channel is valid, else return -1.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="verifyscandurationvalue"></a>
### `verify_scan_duration_value`

```c
int verify_scan_duration_value (int *scan_duration*)
```

Checks whether the scan duration is valid or not.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `scan_duration` | in | scan duration time. |

**Returns**

0 if the time is valid, else return -1.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="verifysplitscandelay"></a>
### `verify_split_scan_delay`

```c
int verify_split_scan_delay (int *delay*)
```

Checks whether the scan delay time is valid or not.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `delay` | in | the scan delay time. |

**Returns**

0 if the time is valid, else return -1.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetscanresult"></a>
### `wlan_get_scan_result`

```c
int wlan_get_scan_result (unsigned int *index*, struct wlan_scan_result * *res*)
```

Retrieves a scan result.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `index` | in | The scan result to retrieve. |
| `res` | out | A pointer to the wlan_scan_result where the scan result information must be copied. |

**Returns**

- WM_SUCCESS if successful.
- -WM_E_INVAL if res is NULL.
- WLAN_ERROR_STATE if the Wi-Fi connection manager was not running.
- -WM_FAIL if the scan result at index could not be retrieved (that is, index is out of range).

> **Note**: This function may only be called in the context of the scan results callback.

> **Note**: Calls to this function are synchronous.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanscan"></a>
### `wlan_scan`

```c
int wlan_scan (int(*)(unsigned int count) *cb*)
```

Scan for Wi-Fi networks.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `cb` | in | A pointer to the function that should be called to handle scan results when they are available. |

**Returns**

- WM_SUCCESS if successful.
- -WM_E_NOMEM if failed to allocated memory for wlan_scan_params_v2_t structure.
- -WM_E_INVAL if cb scan result callback function pointer is NULL.
- WLAN_ERROR_STATE if the Wi-Fi connection manager was not running or not in the WLAN_DISCONNECTED or WLAN_CONNECTED states.
- -WM_FAIL if an internal error has occurred and the system is unable to scan.

> **Note**: This function may only be called when the station interface is in the WLAN_DISCONNECTED or WLAN_CONNECTED state. scan is disabled in the WLAN_CONNECTING state.

> **Note**: This function should block until it can issue a scan request if called while another scan is in progress.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanscanwithopt"></a>
### `wlan_scan_with_opt`

```c
int wlan_scan_with_opt (wlan_scan_params_v2_t *t_wlan_scan_param*)
```

Scan for Wi-Fi networks using options provided.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `t_wlan_scan_param` | in | A wlan_scan_params_v2_t structure holding a pointer to a function that must be called to handle scan results when they are available, SSID of a Wi-Fi network, BSSID of a Wi-Fi network, number of channels with scan type information and number of probes. |

**Returns**

- WM_SUCCESS if successful.
- -WM_E_NOMEM if failed to allocated memory for wlan_scan_params_v2_t structure.
- -WM_E_INVAL if cb scan result callback function pointer is NULL.
- WLAN_ERROR_STATE if the Wi-Fi connection manager was not running or not in the WLAN_DISCONNECTED or WLAN_CONNECTED states.
- -WM_FAIL if an internal error has occurred and the system is unable to scan.

> **Note**: This function may only be called when the station interface is in the WLAN_DISCONNECTED or WLAN_CONNECTED state. scan is disabled in the WLAN_CONNECTING state.

> **Note**: This function can block until it issues a scan request if called while another scan is in progress.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanselectcurnetworkbyscanres"></a>
### `wlan_select_cur_network_by_scan_res`

```c
int wlan_select_cur_network_by_scan_res (unsigned int *scan_index*)
```

Select (synchronize) current network index according to a scan table entry.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `scan_index` | in | Index into the driver's scan table. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetscaninterval"></a>
### `wlan_set_scan_interval`

```c
int wlan_set_scan_interval (int *scan_int*)
```

Sets the wpa_supplicant scan interval in seconds.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `scan_int` | in | Scan interval in seconds. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---


<a id="uapmicroaccesspoint"></a>
### UAP (Micro Access Point)

| Function | Supported SoCs |
|----------|---------------|
| [`is_uap_started`](#isuapstarted) | All |
| [`wlan_get_current_uap_network`](#wlangetcurrentuapnetwork) | All |
| [`wlan_get_current_uap_network_ssid`](#wlangetcurrentuapnetworkssid) | All |
| [`wlan_get_uap_address`](#wlangetuapaddress) | All |
| [`wlan_get_uap_channel`](#wlangetuapchannel) | All |
| [`wlan_get_uap_connection_state`](#wlangetuapconnectionstate) | All |
| [`wlan_get_uap_ed_mac_mode`](#wlangetuapedmacmode) | All |
| [`wlan_get_uap_max_clients`](#wlangetuapmaxclients) | All |
| [`wlan_get_uap_supported_max_clients`](#wlangetuapsupportedmaxclients) | All |
| [`wlan_initialize_uap_network`](#wlaninitializeuapnetwork) | All |
| [`wlan_set_uap_ed_mac_mode`](#wlansetuapedmacmode) | All |
| [`wlan_set_uap_mac_addr`](#wlansetuapmacaddr) | All |
| [`wlan_set_uap_max_clients`](#wlansetuapmaxclients) | All |
| [`wlan_start_network`](#wlanstartnetwork) | All |
| [`wlan_stop_network`](#wlanstopnetwork) | All |
| [`wlan_uap_ctrl_deauth`](#wlanuapctrldeauth) | All |
| [`wlan_uap_disconnect_sta`](#wlanuapdisconnectsta) | All |
| [`wlan_uap_get_bandwidth`](#wlanuapgetbandwidth) | All |
| [`wlan_uap_get_beacon_period`](#wlanuapgetbeaconperiod) | All |
| [`wlan_uap_get_log`](#wlanuapgetlog) | All |
| [`wlan_uap_get_pmfcfg`](#wlanuapgetpmfcfg) | All |
| [`wlan_uap_set_bandwidth`](#wlanuapsetbandwidth) | All |
| [`wlan_uap_set_beacon_period`](#wlanuapsetbeaconperiod) | All |
| [`wlan_uap_set_ecsa`](#wlanuapsetecsa) | All |
| [`wlan_uap_set_ecsa_cfg`](#wlanuapsetecsacfg) | All |
| [`wlan_uap_set_hidden_ssid`](#wlanuapsethiddenssid) | All |
| [`wlan_uap_set_htcapinfo`](#wlanuapsethtcapinfo) | All |
| [`wlan_uap_set_httxcfg`](#wlanuapsethttxcfg) | All |
| [`wlan_uap_set_scan_chan_list`](#wlanuapsetscanchanlist) | All |

<a id="isuapstarted"></a>
### `is_uap_started`

```c
bool is_uap_started (void **)
```

Retrieves the status information of the uAP interface.

**Returns**

- TRUE if uAP interface is in WLAN_UAP_STARTED state.
- FALSE otherwise.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetcurrentuapnetwork"></a>
### `wlan_get_current_uap_network`

```c
int wlan_get_current_uap_network (struct wlan_network * *network*)
```

Retrieves the current network configuration of the uAP interface.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `network` | out | A pointer to the wlan_network. |

**Returns**

- WM_SUCCESS if successful.
- -WM_E_INVAL if network is NULL.
- WLAN_ERROR_STATE if the Wi-Fi connection manager was not running or not in the WLAN_UAP_STARTED state.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetcurrentuapnetworkssid"></a>
### `wlan_get_current_uap_network_ssid`

```c
int wlan_get_current_uap_network_ssid (char * *ssid*)
```

Retrieves the current network ssid of the uAP interface.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `ssid` | out | A pointer to the ssid char string with NULL termination. The maximum length is 32 (not include NULL termination). |

**Returns**

- WM_SUCCESS if successful.
- -WM_E_INVAL if ssid is NULL.
- WLAN_ERROR_STATE if the Wi-Fi connection manager was not running or not in the WLAN_UAP_STARTED state.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetuapaddress"></a>
### `wlan_get_uap_address`

```c
int wlan_get_uap_address (struct wlan_ip_config * *addr*)
```

Retrieves the IP address of the uAP interface.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `addr` | out | A pointer to the wlan_ip_config. |

**Returns**

- WM_SUCCESS if successful.
- -WM_E_INVAL if addr is NULL.
- WLAN_ERROR_STATE if the Wi-Fi connection manager was not running or the uAP interface was not in the WLAN_UAP_STARTED state.
- -WM_FAIL if an internal error occurred when retrieving IP address information from the TCP stack.

> **Note**: This function may only be called when the uAP interface is in the WLAN_UAP_STARTED state.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetuapchannel"></a>
### `wlan_get_uap_channel`

```c
int wlan_get_uap_channel (int * *channel*)
```

Retrieves the channel of the uAP interface.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `channel` | out | A pointer to variable that stores channel number. |

**Returns**

- WM_SUCCESS if successful.
- -WM_E_INVAL if channel is NULL.
- -WM_FAIL if an internal error has occurred.

> **Note**: This function may only be called when the uAP interface is in the WLAN_UAP_STARTED state.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetuapconnectionstate"></a>
### `wlan_get_uap_connection_state`

```c
int wlan_get_uap_connection_state (enum wlan_connection_state * *state*)
```

Retrieves the connection state of the uAP interface.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `state` | out | A pointer to the wlan_connection_state where the current connection state must be copied. |

**Returns**

- WM_SUCCESS if successful.
- -WM_E_INVAL if state is NULL.
- WLAN_ERROR_STATE if the Wi-Fi connection manager was not running.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetuapedmacmode"></a>
### `wlan_get_uap_ed_mac_mode`

```c
int wlan_get_uap_ed_mac_mode (wlan_ed_mac_ctrl_t * *wlan_ed_mac_ctrl*)
```

This API can be used to get the current ED MAC mode configuration for the uAP.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `wlan_ed_mac_ctrl` | out | A pointer to wlan_ed_mac_ctrl_t as described in the corresponding set API. |

**Returns**

- WM_SUCCESS if the call was successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetuapmaxclients"></a>
### `wlan_get_uap_max_clients`

```c
int wlan_get_uap_max_clients (unsigned int * *max_sta_num*)
```

Gets the current maximum number of stations that can be allowed to connect to the uAP.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `max_sta_num` | out | A pointer to variable where current maximum number of the stations of the uAP interface can be stored. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if unsuccessful.

> **Note**: Get operation is allowed in any uAP state.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetuapsupportedmaxclients"></a>
### `wlan_get_uap_supported_max_clients`

```c
unsigned int wlan_get_uap_supported_max_clients (void **)
```

Gets the maximum number of stations the Wi-Fi firmware supports that are allowed to connect to the uAP.

**Returns**

Maximum number of stations supported by the Wi-Fi firmware that can connect to the uAP.

> **Note**: Get operation is allowed in any uAP state.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlaninitializeuapnetwork"></a>
### `wlan_initialize_uap_network`

```c
void wlan_initialize_uap_network (struct wlan_network * *net*)
```

Initialize the uAP network information.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `net` | out | Pointer to the initialized uAP network. |

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetuapedmacmode"></a>
### `wlan_set_uap_ed_mac_mode`

```c
int wlan_set_uap_ed_mac_mode (wlan_ed_mac_ctrl_t *wlan_ed_mac_ctrl*)
```

Configures Energy Detect MAC mode for the uAP in the Wi-Fi firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `wlan_ed_mac_ctrl` | in | Struct with the following fields: ed_ctrl_2g = <br>• 0: Disable EU adaptivity for 2.4 GHz band. ed_ctrl_2g =. <br>• 1: Enable EU adaptivity for 2.4 GHz band. ed_offset_2g =. <br>• 0: Default Energy Detect threshold (0x9). ed_offset_2g = other: Offset value in range 0x80 to 0x7F. |

**Returns**

- WM_SUCCESS if the call was successful.
- -WM_FAIL if failed.

> **Note**: When ED MAC mode is enabled, the Wi-Fi Firmware can behave in the following way:

> **Note**: If 5 GHz is enabled, the following fields also apply:     - ed_ctrl_5g = 0: Disable EU adaptivity for 5 GHz band.
    - ed_ctrl_5g = 1: Enable EU adaptivity for 5 GHz band.
    - ed_offset_5g = 0: Default Energy Detect threshold (0xC).
    - ed_offset_5g = other: Offset value in range 0x80 to 0x7F.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetuapmacaddr"></a>
### `wlan_set_uap_mac_addr`

```c
int wlan_set_uap_mac_addr (uint8_t * *mac*)
```

Sets the Wi-Fi MAC address for the uAP in the Wi-Fi firmware.

**Returns**

- WM_SUCCESS if the call was successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetuapmaxclients"></a>
### `wlan_set_uap_max_clients`

```c
int wlan_set_uap_max_clients (unsigned int *max_sta_num*)
```

Sets the maximum number of stations that can be allowed to connect to the uAP.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `max_sta_num` | in | Number of maximum stations for uAP. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if unsuccessful.

> **Note**: Set operation in not allowed in WLAN_UAP_STARTED state.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanstartnetwork"></a>
### `wlan_start_network`

```c
int wlan_start_network (const char * *name*)
```

Starts a Wi-Fi network (access point).

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `name` | in | A pointer to string representing the name of the network to connect to. |

**Returns**

- WM_SUCCESS if successful.
- WLAN_ERROR_STATE if in Power-save state or uAP already running.
- -WM_E_INVAL if name was NULL or the network name was not found or it not have a specified SSID.

> **Note**: The WLCMGR callback is asynchronously notified of the status. On success, the event WLAN_REASON_UAP_SUCCESS is reported, while on failure, the event WLAN_REASON_UAP_START_FAILED is reported.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanstopnetwork"></a>
### `wlan_stop_network`

```c
int wlan_stop_network (const char * *name*)
```

Stops a Wi-Fi network (access point).

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `name` | in | A pointer to a string representing the name of the network to stop. |

**Returns**

- WM_SUCCESS if successful.
- WLAN_ERROR_STATE if uAP is in Power-save state.
- -WM_E_INVAL if name was NULL or the network name was not found or that the network name is not a uAP network or it is a uAP network but does not have a specified SSID.

> **Note**: The WLCMGR callback is asynchronously notified of the status. On success, the event WLAN_REASON_UAP_STOPPED is reported, while on failure, the event WLAN_REASON_UAP_STOP_FAILED is reported.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanuapctrldeauth"></a>
### `wlan_uap_ctrl_deauth`

```c
void wlan_uap_ctrl_deauth (const bool *enable*)
```

API to control the deauthentication during uAP channel switch.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `enable` | in | 0  Wi-Fi firmware can use default behavior, send deauth packet when uAP moves to another channel. 1: Wi-Fi firmware cannot send deauth packet. when uAP moves to another channel. |

> **Note**: Call this API before calling uAP start API.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanuapdisconnectsta"></a>
### `wlan_uap_disconnect_sta`

```c
int wlan_uap_disconnect_sta (uint8_t * *sta_addr*)
```

Disconnects to STA which is connected with internal uAP.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `sta_addr` | in | STA MAC address. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanuapgetbandwidth"></a>
### `wlan_uap_get_bandwidth`

```c
int wlan_uap_get_bandwidth (uint8_t * *bandwidth*)
```

API to get the bandwidth of the uAP.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `bandwidth` | out | Wi-Fi AP bandwidth <br>• 1: 20 MHz. <br>• 2: 40 MHz. <br>• 3: 80 MHz. |

**Returns**

- WM_SUCCESS if successful otherwise return -WM_FAIL.
- -WM_FAIL if command fails.

> **Note**: Call this API before calling uAP start API.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanuapgetbeaconperiod"></a>
### `wlan_uap_get_beacon_period`

```c
int wlan_uap_get_beacon_period (void)
```

API to get the beacon period of the uAP.

**Returns**

- beacon_period: Beacon period in TU (1 TU = 1024 microseconds).

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanuapgetlog"></a>
### `wlan_uap_get_log`

```c
int wlan_uap_get_log (wlan_pkt_stats_t * *stats*)
```

Use this API to get the various statistics of the uAP from Wi-Fi firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `stats` | out | A pointer to structure where stats collected from Wi-Fi firmware can be copied.  Explore the elements of the wlan_pkt_stats_t structure for more information on stats. |

**Returns**

- WM_SUCCESS if operation is successful.
- -WM_FAIL if command fails.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanuapgetpmfcfg"></a>
### `wlan_uap_get_pmfcfg`

```c
int wlan_uap_get_pmfcfg (uint8_t * *mfpc*, uint8_t * *mfpr*)
```

Use this API to get the set management frame protection parameters for uAP.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `mfpc` | out | Management frame protection capable (MFPC) <br>• 0: Management frame protection not capable. <br>• 1: Management frame protection capable. |
| `mfpr` | out | Management frame protection required (MFPR) <br>• 0: Management frame protection optional. <br>• 1: Management frame protection required. |

**Returns**

- WM_SUCCESS if operation is successful.
- -WM_FAIL if command fails.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanuapsetbandwidth"></a>
### `wlan_uap_set_bandwidth`

```c
int wlan_uap_set_bandwidth (const uint8_t *bandwidth*)
```

API to set the bandwidth of the uAP.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `bandwidth` | in | Wi-Fi AP bandwidth <br>• 1: 20 MHz. <br>• 2: 40 MHz. <br>• 3: 80 MHz. |

**Returns**

- WM_SUCCESS if successful otherwise return -WM_FAIL.
- -WM_FAIL if command fails.

> **Note**: Not applicable to 20MHZ only chip sets (Redfinch, SD8801)

> **Note**: Call this API before calling uAP start API.

> **Note**: Default bandwidth setting is 40 MHz.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanuapsetbeaconperiod"></a>
### `wlan_uap_set_beacon_period`

```c
void wlan_uap_set_beacon_period (const uint16_t *beacon_period*)
```

API to set the beacon period of the uAP.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `beacon_period` | in | Beacon period in TU (1 TU = 1024 microseconds) |

> **Note**: Call this API before calling uAP start API.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanuapsetecsa"></a>
### `wlan_uap_set_ecsa`

```c
void wlan_uap_set_ecsa (void **)
```

API to enable the channel switch announcement functionality on uAP.

> **Note**: Call this API before calling uAP start API. Also note that 802.11n should be enabled on uAP. The channel switch announcement IE is transmitted in 7 beacons before the channel switch, during a station connection attempt on a different channel with Ex-AP.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanuapsetecsacfg"></a>
### `wlan_uap_set_ecsa_cfg`

```c
int wlan_uap_set_ecsa_cfg (t_u8 *block_tx*, t_u8 *oper_class*, t_u8 *channel*, t_u8 *switch_count*, t_u8 *band_width*)
```

Sends the ecsa configuration parameter to FW.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `block_tx` | in | 0  no need to block traffic,1  need block traffic. |
| `oper_class` | in | Operating class according to IEEE std802.11 spec, refer to Annex E, when 0 is used, automatically get the operclass through bandwidth and channel. |
| `channel` | in | The channel can switch to. |
| `switch_count` | in | Channel switch time to send ECSA ie, unit is 110ms. |
| `band_width` | in | Channel width switch to(optional), only for 5G channels. Depends on the hardware capabilities, when the hardware does not support, it can automatically downgrade. Redfinch support 20M. 0  20MHZ, 1  40M above, 3  40M below, 4  80M, 5  160M |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanuapsethiddenssid"></a>
### `wlan_uap_set_hidden_ssid`

```c
int wlan_uap_set_hidden_ssid (const t_u8 *hidden_ssid*)
```

API to control the SSID broadcast capability of the uAP.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `hidden_ssid` | in | Hidden SSID control hidden_ssid=0: broadcast SSID in beacons. hidden_ssid=1: send empty SSID (length=0) in beacon. hidden_ssid=2: clear SSID (ASCII 0), but keep the original length |

**Returns**

- WM_SUCCESS if successful otherwise return -WM_FAIL.
- -WM_FAIL if command fails.

> **Note**: Call this API before calling uAP start API.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanuapsethtcapinfo"></a>
### `wlan_uap_set_htcapinfo`

```c
void wlan_uap_set_htcapinfo (const uint16_t *ht_cap_info*)
```

API to set the HT capability information of the uAP.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `ht_cap_info` | in | - This is a bitmap and should be used as following  Bit, 15: L Sig TxOP protection - reserved, set to 0   Bit, 14: 40 MHz intolerant - reserved, set to 0   Bit, 13: PSMP - reserved, set to 0   Bit <br>• 12: DSSS Cck40 MHz mode  Bit. <br>• 6: Short GI 40 MHz  Bit. <br>• 5: Short GI 20 MHz  Bit. <br>• 4: GF preamble  Bits. <br>• 1: SuppChanWidth - set to 0 for 2.4 GHz band   Bit. |

> **Note**: Call this API before calling uAP start API.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanuapsethttxcfg"></a>
### `wlan_uap_set_httxcfg`

```c
void wlan_uap_set_httxcfg (unsigned short *httxcfg*)
```

This API can be used to configure various 802.11n specific configuration for transmit (such as short GI, channel bandwidth and green field support) for uAP interface.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `httxcfg` | in | This is a bitmap and should be used as following  Bit 15 <br>• -8: Reserved set to 0  Bit. <br>• 7: STBC Enable/Disable  Bit. <br>• 6: Short GI in 40 Mhz Enable/Disable  Bit. <br>• 5: Short GI in 20 Mhz Enable/Disable  Bit. <br>• 4: Green field Enable/Disable  Bit 3-2: Reserved set to 1  Bit. <br>• 1: 20/40 Mhz enable disable.  Bit. <br>• 0: LDPC Enable/Disable  When Bit 1 is set then firmware could transmit in 20Mhz or 40Mhz based  on rate adaptation. When this bit is reset then firmware can only  transmit in 20Mhz. |

> **Note**: Call this API before calling uAP start API.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanuapsetscanchanlist"></a>
### `wlan_uap_set_scan_chan_list`

```c
void wlan_uap_set_scan_chan_list (wifi_scan_chan_list_t *scan_chan_list*)
```

Sets the number of channels and channel number used during automatic channel selection of the uAP.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `scan_chan_list` | in | A structure holding the number of channels and channel numbers. |

> **Note**: Call this API before uAP start API in order to set the user defined channels, otherwise it can have no effect. There is no need to call this API every time before uAP start, if once set same channel configuration can get used in all upcoming uAP start call. If user wish to change the channels at run time then it make sense to call this API before every uAP start API.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---


<a id="powermanagement"></a>
### Power Management

| Function | Supported SoCs |
|----------|---------------|
| [`wlan_configure_delay_to_ps`](#wlanconfiguredelaytops) | All |
| [`wlan_configure_idle_time`](#wlanconfigureidletime) | All |
| [`wlan_configure_listen_interval`](#wlanconfigurelisteninterval) | All |
| [`wlan_configure_null_pkt_interval`](#wlanconfigurenullpktinterval) | All |
| [`wlan_deepsleepps_off`](#wlandeepsleeppsoff) | All |
| [`wlan_deepsleepps_on`](#wlandeepsleeppson) | All |
| [`wlan_get_delay_to_ps`](#wlangetdelaytops) | All |
| [`wlan_get_idle_time`](#wlangetidletime) | All |
| [`wlan_get_listen_interval`](#wlangetlisteninterval) | All |
| [`wlan_get_ps_mode`](#wlangetpsmode) | All |
| [`wlan_get_ps_mode_cfg`](#wlangetpsmodecfg) | All |
| [`wlan_ieeeps_off`](#wlanieeepsoff) | All |
| [`wlan_ieeeps_on`](#wlanieeepson) | All |
| [`wlan_is_power_save_enabled`](#wlanispowersaveenabled) | All |
| [`wlan_set_ieeeps_cfg`](#wlansetieeepscfg) | All |
| [`wlan_set_ips`](#wlansetips) | RW612, IW610 |
| [`wlan_set_ps_cfg`](#wlansetpscfg) | All |
| [`wlan_sleep_period`](#wlansleepperiod) | All |

<a id="wlanconfiguredelaytops"></a>
### `wlan_configure_delay_to_ps`

```c
void wlan_configure_delay_to_ps (unsigned int *timeout_ms*)
```

Sets timeout configuration before Wi-Fi Power-save mode.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `timeout_ms` | in | timeout time, in milliseconds. |

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanconfigureidletime"></a>
### `wlan_configure_idle_time`

```c
void wlan_configure_idle_time (unsigned int *timeout_ms*)
```

Sets timeout value before Wi-Fi enter deep sleep mode.

> **Note**: The minimum value of timeout_ms is 10.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanconfigurelisteninterval"></a>
### `wlan_configure_listen_interval`

```c
void wlan_configure_listen_interval (int *listen_interval*)
```

Configures listening interval of IEEE Power-save mode.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `listen_interval` | in | Listen interval as below <br>• 0: Unchanged. <br>• -1: Disable. 1-49: Value in beacon intervals. >=. <br>• 50: Value in TUs. |

> **Note**: Delivery traffic indication message (DTIM): It is a concept in 802.11 It is a time duration after which AP can send out buffered BROADCAST / MULTICAST data and stations connected to the AP should wakeup to take this broadcast / multicast data.

> **Note**: Traffic Indication Map (TIM): It is a bitmap which the AP sends with each beacon. The bitmap has one bit each for a station connected to AP.

> **Note**: Each station is recognized by an association ID (AID). If AP has buffered data for a station, it will set corresponding bit of bitmap in TIM based on AID. Ideally AP does not buffer any unicast data it just sends unicast data to the station on every beacon when station is not sleeping.
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
In the IEEE Power-save mode, the Wi-Fi firmware goes to sleep and periodically wakes up to check if the AP has any pending packets for it. A longer listen interval implies that the Wi-Fi SoC stays in Power-save for a longer duration at the cost of additional delays while receiving data. Note that choosing incorrect value for listen interval causes poor response from device during data transfer. Actual listen interval selected by firmware is equal to closest DTIM.
For example:
 AP beacon period : 100 ms
 AP DTIM period : 2
 Application request value: 500ms
 Actual listen interval = 400ms (This is the closest DTIM). Actual listen interval set should be a multiple of DTIM closest to but lower than the value provided by the application.

> **Note**: This API can be called before/after association. The configured listen interval can be used in subsequent association attempt.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanconfigurenullpktinterval"></a>
### `wlan_configure_null_pkt_interval`

```c
void wlan_configure_null_pkt_interval (unsigned int *time_in_secs*)
```

Configures NULL packet interval of IEEE Power-save mode.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `time_in_secs` | in | -1 Disables null packet transmission, 0: Null packet interval is unchanged. n Null packet interval in seconds. |

> **Note**: In IEEE PS (Power-save), station sends a NULL packet to AP to indicate that the station is alive and maintain connection with the AP. If null packet is not sent some APs may disconnect station which might lead to a loss of connectivity. The time is specified in seconds. Default value is 30 seconds.

> **Note**: This API should be called before configuring IEEE Power-save.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlandeepsleeppsoff"></a>
### `wlan_deepsleepps_off`

```c
int wlan_deepsleepps_off (void **)
```

Turns off deep sleep Power-save mode.

**Returns**

- WM_SUCCESS if the call was successful.
- -WM_FAIL otherwise.

> **Note**: deep sleep Power-save mode only applies when STA disconnected. It could be enabled/disabled when STA connected or disconnected, but only take effect when STA disconnected.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlandeepsleeppson"></a>
### `wlan_deepsleepps_on`

```c
int wlan_deepsleepps_on (void **)
```

Turns on deep sleep Power-save mode.

**Returns**

- WM_SUCCESS if the call was successful.
- -WM_FAIL otherwise.

> **Note**: deep sleep Power-save mode only applies when STA disconnected. It could be enabled/disabled when STA connected or disconnected, but only take effect when STA disconnected.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetdelaytops"></a>
### `wlan_get_delay_to_ps`

```c
unsigned int wlan_get_delay_to_ps (void **)
```

Gets delay time for Wi-Fi Power-save mode.

**Returns**

delay time value.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetidletime"></a>
### `wlan_get_idle_time`

```c
unsigned int wlan_get_idle_time (void **)
```

Gets timeout value of deep sleep mode, in milliseconds.

**Returns**

idle time value.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetlisteninterval"></a>
### `wlan_get_listen_interval`

```c
unsigned short wlan_get_listen_interval (void **)
```

Gets listen interval.

**Returns**

Listen interval value in beacon intervals.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetpsmode"></a>
### `wlan_get_ps_mode`

```c
int wlan_get_ps_mode (enum wlan_ps_mode * *ps_mode*)
```

Gets station interface Power-save mode.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `ps_mode` | out | A pointer to wlan_ps_mode where station interface Power-save mode must be stored. |

**Returns**

- WM_SUCCESS if successful.
- -WM_E_INVAL if ps_mode was NULL.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetpsmodecfg"></a>
### `wlan_get_ps_mode_cfg`

```c
int wlan_get_ps_mode_cfg (uint8_t * *ps_mode_cfg*)
```

Gets station interface Power-save configuration.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `ps_mode_cfg` | out | A pointer to variable that stores Power-save mode configuration. |

**Returns**

- WM_SUCCESS if successful.
- -WM_E_INVAL if ps_mode_cfg was NULL.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanieeepsoff"></a>
### `wlan_ieeeps_off`

```c
int wlan_ieeeps_off (void **)
```

Turns off IEEE Power-save mode.

**Returns**

- WM_SUCCESS if the call was successful.
- -WM_FAIL otherwise.

> **Note**: IEEE Power-save mode applies only when STA has connected to an AP. It could be enabled/disabled when STA connected or disconnected, but only take effect when STA has connected to an AP.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanieeepson"></a>
### `wlan_ieeeps_on`

```c
int wlan_ieeeps_on (unsigned int *wakeup_conditions*)
```

Enables IEEE Power-save with host sleep configuration.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `wakeup_conditions` | in | conditions to wake the host. This should be a logical OR of the conditions in wlan_wakeup_event_t. Typically devices would want to wake up on. WAKE_ON_ALL_BROADCAST, WAKE_ON_UNICAST, WAKE_ON_MAC_EVENT. WAKE_ON_MULTICAST, WAKE_ON_ARP_BROADCAST, WAKE_ON_MGMT_FRAME |

**Returns**

- WM_SUCCESS if the call was successful.
- -WM_FAIL otherwise.

> **Note**: IEEE Power-save mode applies only when STA has connected to an AP. It could be enabled/disabled when STA connected or disconnected, but only take effect when STA has connected to an AP.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanispowersaveenabled"></a>
### `wlan_is_power_save_enabled`

```c
bool wlan_is_power_save_enabled (void **)
```

Checks whether Wi-Fi Power-save is enabled or not.

**Returns**

TRUE if Wi-Fi Power-save is enabled, else return FALSE.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetieeepscfg"></a>
### `wlan_set_ieeeps_cfg`

```c
int wlan_set_ieeeps_cfg (struct wlan_ieeeps_config * *ps_cfg*)
```

Sets configuration parameters of IEEE Power-save mode.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `ps_cfg` | in | Power-save configuration includes multiple parameters. |

**Returns**

- WM_SUCCESS if the call was successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetips"></a>
### `wlan_set_ips`

```c
int wlan_set_ips (int *option*)
```

Config IEEE Power-save mode (IPS). If the option is 1, the IPS hardware listens to beacon frames after Wi-Fi CPU enters Power-save mode. When there is work needed to done by Wi-Fi CPU, Wi-Fi CPU can be woken up by ips hardware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `option` | in | 0/1 disable/enable ips. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612, IW610

---

<a id="wlansetpscfg"></a>
### `wlan_set_ps_cfg`

```c
void wlan_set_ps_cfg (t_u16 *multiple_dtims*, t_u16 *bcn_miss_timeout*, t_u16 *local_listen_interval*, t_u16 *adhoc_wake_period*, t_u16 *mode*, t_u16 *delay_to_ps*)
```

Sets the multiple DTIM for the next wakeup RX beacon time.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `multiple_dtims` | in | num dtims, range [1,20] |
| `bcn_miss_timeout` | in | beacon miss interval. |
| `local_listen_interval` | in | local listen interval. |
| `adhoc_wake_period` | in | adhoc awake period. |
| `mode` | in | mode - ( <br>• 0x01: Firmware automatically chooses PS_POLL or NULL mode. <br>• 0x02: PS_POLL mode. <br>• 0x03: NULL mode. |
| `delay_to_ps` | in | Delay to PS in milliseconds. |

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansleepperiod"></a>
### `wlan_sleep_period`

```c
int wlan_sleep_period (unsigned int * *sleep_period*, t_u8 *action*)
```

Gets or sets the UAPSD sleep period in the Wi-Fi firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `sleep_period` | inout | UAPSD sleep period. Unit is ms. |
| `action` | in | Set/get action. |

**Returns**

- WM_SUCCESS if the call was successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---


<a id="hostsleep"></a>
### Host Sleep

| Function | Supported SoCs |
|----------|---------------|
| [`wlan_cancel_host_sleep`](#wlancancelhostsleep) | RW612, IW610 |
| [`wlan_clear_host_sleep_config`](#wlanclearhostsleepconfig) | RW612, IW610 |
| [`wlan_config_host_sleep`](#wlanconfighostsleep) | RW612, IW610 |
| [`wlan_get_wakeup_reason`](#wlangetwakeupreason) | RW612, IW610 |
| [`wlan_hs_post_cfg`](#wlanhspostcfg) | RW612, IW610 |
| [`wlan_hs_pre_cfg`](#wlanhsprecfg) | RW612, IW610 |
| [`wlan_hs_send_event`](#wlanhssendevent) | RW612, IW610 |

<a id="wlancancelhostsleep"></a>
### `wlan_cancel_host_sleep`

```c
void wlan_cancel_host_sleep (void **)
```

Cancel host sleep. This function is called to cancel the host sleep in the firmware.

---

> **Supported SoCs:** RW612, IW610

---

<a id="wlanclearhostsleepconfig"></a>
### `wlan_clear_host_sleep_config`

```c
void wlan_clear_host_sleep_config (void **)
```

Clears host sleep configurations in the driver. This function clears all the host sleep related configures in driver.

---

> **Supported SoCs:** RW612, IW610

---

<a id="wlanconfighostsleep"></a>
### `wlan_config_host_sleep`

```c
void wlan_config_host_sleep (bool *is_manual*, t_u8 *is_periodic*)
```

Host sleep configuration. This function may be called to configure host sleep in firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `is_manual` | in | Flag to indicate host enter low power mode with power manager or by command. |
| `is_periodic` | in | Flag to indicate host enter low power periodically or once with power manager. |

---

> **Supported SoCs:** RW612, IW610

---

<a id="wlangetwakeupreason"></a>
### `wlan_get_wakeup_reason`

```c
int wlan_get_wakeup_reason (uint16_t * *hs_wakeup_reason*)
```

Use this API to get host sleep wakeup reason from Wi-Fi firmware after waking up from host sleep by Wi-Fi.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `hs_wakeup_reason` | out | wakeupReason: <br>• 0: Unknown. <br>• 1: Broadcast data matched. <br>• 2: Multicast data matched. <br>• 3: Unicast data matched. <br>• 4: Maskable event matched. <br>• 5: Non-maskable event matched. <br>• 6: Non-maskable condition matched (EAPoL rekey). <br>• 7: Magic pattern matched. Others: Reserved (set to 0). |

**Returns**

- WM_SUCCESS if operation is successful.
- -WM_FAIL if command fails.

---

> **Supported SoCs:** RW612, IW610

---

<a id="wlanhspostcfg"></a>
### `wlan_hs_post_cfg`

```c
void wlan_hs_post_cfg (void **)
```

Use this API to get and print the reason for waking up from host sleep.

---

> **Supported SoCs:** RW612, IW610

---

<a id="wlanhsprecfg"></a>
### `wlan_hs_pre_cfg`

```c
void wlan_hs_pre_cfg (void **)
```

Use this API to set the configuration before going to host sleep.

---

> **Supported SoCs:** RW612, IW610

---

<a id="wlanhssendevent"></a>
### `wlan_hs_send_event`

```c
status_t wlan_hs_send_event (int *id*, void * *data*)
```

This function sends host sleep events to mon_thread.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `id` | in | Event ID. |
| `data` | in | Pointer to event msg. |

**Returns**

kStatus_Success if successful else return -WM_FAIL.

---

> **Supported SoCs:** RW612, IW610

---


<a id="txpowerratecontrol"></a>
### TX Power & Rate Control

| Function | Supported SoCs |
|----------|---------------|
| [`wlan_get_data_rate`](#wlangetdatarate) | All |
| [`wlan_get_sta_tx_power`](#wlangetstatxpower) | All |
| [`wlan_get_txpwrlimit`](#wlangettxpwrlimit) | All |
| [`wlan_get_txratecfg`](#wlangettxratecfg) | All |
| [`wlan_set_frag`](#wlansetfrag) | All |
| [`wlan_set_htcapinfo`](#wlansethtcapinfo) | All |
| [`wlan_set_httxcfg`](#wlansethttxcfg) | All |
| [`wlan_set_region_power_cfg`](#wlansetregionpowercfg) | RW612, IW610, IW612 |
| [`wlan_set_rg_power_cfg`](#wlansetrgpowercfg) | RW612, IW610, IW612 |
| [`wlan_set_rts`](#wlansetrts) | All |
| [`wlan_set_ru_power_cfg`](#wlansetrupowercfg) | RW612, IW610, IW612 |
| [`wlan_set_sta_tx_power`](#wlansetstatxpower) | All |
| [`wlan_set_tx_pert`](#wlansettxpert) | RW612 |
| [`wlan_set_txpwrlimit`](#wlansettxpwrlimit) | All |
| [`wlan_set_txratecfg`](#wlansettxratecfg) | All |
| [`wlan_set_txrx_histogram`](#wlansettxrxhistogram) | All |
| [`wlan_set_uap_frag`](#wlansetuapfrag) | All |
| [`wlan_set_uap_rts`](#wlansetuaprts) | All |
| [`wlan_set_wwsm_txpwrlimit`](#wlansetwwsmtxpwrlimit) | All |

<a id="wlangetdatarate"></a>
### `wlan_get_data_rate`

```c
int wlan_get_data_rate (wlan_ds_rate * *ds_rate*, mlan_bss_type *bss_type*)
```

Use this API to get the current TX and RX rates along with bandwidth and guard interval information if the rate is 802.11n.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `ds_rate` | in | A pointer to structure which has tx, RX rate information along with bandwidth and guard interval information. |
| `bss_type` | in | 0: STA, 1: uAP. |

**Returns**

- WM_SUCCESS if operation is successful.
- -WM_FAIL if command fails.

> **Note**: If rate is greater than 11 then it is 802.11n rate and from 12 MCS0 rate starts. The bandwidth mapping is like value 0 is for 20 MHz, 1 is 40 MHz, 2 is for 80 MHz. The guard interval value zero means Long otherwise Short.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetstatxpower"></a>
### `wlan_get_sta_tx_power`

```c
int wlan_get_sta_tx_power (t_u32 * *power_level*)
```

Gets the station transmit power.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `power_level` | out | Transmit power level (unit: dBm). |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if unsuccessful.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangettxpwrlimit"></a>
### `wlan_get_txpwrlimit`

```c
int wlan_get_txpwrlimit (wifi_SubBand_t *subband*, wifi_txpwrlimit_t * *txpwrlimit*)
```

Gets the TRPC (transient receptor potential canonical) channel configuration.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `subband` | in | Where subband is: <br>• 0x00: 2G subband (2.4G: channel 1-14). <br>• 0x10: 5G subband0 (5G: channel 36. <br>• 0x11: 5G subband1 (5G: channel 100. <br>• 0x12: 5G subband2 (5G: channel 149. <br>• 0x13: 5G subband3 (5G: channel 183. |
| `txpwrlimit` | out | A pointer to wlan_txpwrlimit_t TX power limit configuration structure where Wi-Fi firmware configuration can be copied. |

**Returns**

WM_SUCCESS on success, error otherwise.

> **Note**: application can use print_txpwrlimit API to print the content of the txpwrlimit structure.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangettxratecfg"></a>
### `wlan_get_txratecfg`

```c
int wlan_get_txratecfg (wlan_ds_rate * *ds_rate*, mlan_bss_type *bss_type*)
```

Use this API to get the transmit data rate.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `ds_rate` | in | A pointer to wlan_ds_rate where TX Rate configuration can be stored. |
| `bss_type` | in | 0: STA, 1: uAP. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if unsuccessful.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetfrag"></a>
### `wlan_set_frag`

```c
int wlan_set_frag (int *frag*)
```

Sets the fragment threshold of STA in Wi-Fi firmware. If the size of packet exceeds the fragment threshold, the packet is divided into fragments. For example, if the fragment threshold is set to 300, a ping packet of size 1300 is divided into 5 fragments.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `frag` | in | The value of fragment threshold configuration. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansethtcapinfo"></a>
### `wlan_set_htcapinfo`

```c
int wlan_set_htcapinfo (unsigned int *htcapinfo*)
```

Use this API to configure some of the parameters in HT capability information IE (such as short GI, channel bandwidth, and green field support).

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `htcapinfo` | in | This is a bitmap and should be used as following  Bit <br>• 29: Green field Enable/Disable  Bit. <br>• 26: RX STBC Support Enable/Disable. (As we support  single spatial stream only 1 bit is used for RX STBC)  Bit. <br>• 25: TX STBC support Enable/Disable.  Bit. <br>• 24: Short GI in 40 Mhz Enable/Disable  Bit. <br>• 23: Short GI in 20 Mhz Enable/Disable  Bit. <br>• 22: RX LDPC Enable/Disable  Bit. <br>• 17: 20/40 Mhz enable disable.  Bit. <br>• 8: Enable/Disable 40 MHz intolerant bit in HT capinfo (0 resets this bit. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if unsuccessful.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansethttxcfg"></a>
### `wlan_set_httxcfg`

```c
int wlan_set_httxcfg (unsigned short *httxcfg*)
```

Use this API to configure various 802.11n specific configuration for transmit (such as short GI, channel bandwidth and green field support).

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `httxcfg` | in | This is a bitmap and should be used as following  Bit 15 <br>• -10: Reserved set to 0  Bit 9-8: RX STBC set to 0x01.  0b00: No spatial streams.  0b01: One spatial stream supported.  0b10: Reserved.  0b11: Reserved.  Bit. <br>• 7: STBC Enable/Disable  Bit. <br>• 6: Short GI in 40 Mhz Enable/Disable  Bit. <br>• 5: Short GI in 20 Mhz Enable/Disable  Bit. <br>• 4: Green field Enable/Disable  Bit 3-2: Reserved set to 1  Bit. <br>• 1: 20/40 Mhz enable disable.  Bit. <br>• 0: LDPC Enable/Disable  When Bit 1 is set then firmware could transmit in 20Mhz or 40Mhz based  on rate adaptation. When this bit is reset then firmware can only  transmit in 20Mhz. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if unsuccessful.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetregionpowercfg"></a>
### `wlan_set_region_power_cfg`

```c
int wlan_set_region_power_cfg (const t_u8 * *data*, t_u16 *len*)
```

Sets the compressed (use LZW algorithm) TX power limit configuration.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `data` | in | A pointer to TX power limit configuration. |
| `len` | in | Length of TX power limit configuration. |

**Returns**

WM_SUCCESS on success, error otherwise.

---

> **Supported SoCs:** RW612, IW610, IW612

---

<a id="wlansetrgpowercfg"></a>
### `wlan_set_rg_power_cfg`

```c
int wlan_set_rg_power_cfg (t_u16 *region_code*)
```

Sets the TX power table according to the region code.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `region_code` | in | region code. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612, IW610, IW612

---

<a id="wlansetrts"></a>
### `wlan_set_rts`

```c
int wlan_set_rts (int *rts*)
```

Sets the RTS(Request to Send) threshold of STA in Wi-Fi firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `rts` | in | the value of rts threshold configuration. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetrupowercfg"></a>
### `wlan_set_ru_power_cfg`

```c
int wlan_set_ru_power_cfg (t_u16 *region_code*)
```

Sets the resource unit TX power table.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `region_code` | in | region code. |

**Returns**

WM_SUCCESS if successful otherwise failure.

---

> **Supported SoCs:** RW612, IW610, IW612

---

<a id="wlansetstatxpower"></a>
### `wlan_set_sta_tx_power`

```c
int wlan_set_sta_tx_power (t_u32 *power_level*)
```

Sets the station transmit power.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `power_level` | in | Transmit power level (unit: dBm). |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if unsuccessful.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansettxpert"></a>
### `wlan_set_tx_pert`

```c
void wlan_set_tx_pert (struct wlan_tx_pert_info * *tx_pert*, mlan_bss_type *bss_type*)
```

Sets the TX per tracking config. This function can be called to set TX per tracking in firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `tx_pert` | in | User configured parameters of TX per tracking period, ratio and number of TX packets. |
| `bss_type` | in | BSS type for STA or uAP. |

**Returns**

- WM_SUCCESS if the call was successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612

---

<a id="wlansettxpwrlimit"></a>
### `wlan_set_txpwrlimit`

```c
int wlan_set_txpwrlimit (wlan_txpwrlimit_t * *txpwrlimit*)
```

Sets the TRPC (transient receptor potential canonical) channel configuration.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `txpwrlimit` | in | A pointer to wlan_txpwrlimit_t TX power limit configuration. |

**Returns**

WM_SUCCESS on success, error otherwise.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansettxratecfg"></a>
### `wlan_set_txratecfg`

```c
int wlan_set_txratecfg (wlan_ds_rate *ds_rate*, mlan_bss_type *bss_type*)
```

Use this API to set the transmit data rate.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `ds_rate` | in | struct contains following fields sub_command It should be WIFI_DS_RATE_CFG and rate_cfg should have following parameters.  rate_format - This parameter specifies the data rate format used in this command <br>• 0: LG (legacy). <br>• 1: HT. <br>• 2: VHT. <br>• 0: 1 Mbps. <br>• 1: 2 Mbps. <br>• 2: 5.5 Mbps. <br>• 3: 11 Mbps. <br>• 4: 6 Mbps. <br>• 5: 9 Mbps. <br>• 6: 12 Mbps. <br>• 7: 18 Mbps. <br>• 8: 24 Mbps. <br>• 9: 36 Mbps. <br>• 10: 48 Mbps. <br>• 0: MCS0. <br>• 1: MCS1. <br>• 2: MCS2. <br>• 3: MCS3. <br>• 4: MCS4. <br>• 5: MCS5. <br>• 6: MCS6. <br>• 7: MCS7. If STREAM_2X2:. <br>• 8: MCS8. <br>• 9: MCS9. <br>• 10: MCS10. <br>• 11: MCS11. <br>• 12: MCS12. <br>• 13: MCS13. <br>• 14: MCS14. <br>• 0: MCS0. <br>• 1: MCS1. <br>• 2: MCS2. <br>• 3: MCS3. <br>• 4: MCS4. <br>• 5: MCS5. <br>• 6: MCS6. <br>• 7: MCS7. <br>• 8: MCS8. <br>• 1: NSS1. <br>• 2: NSS2. |
| `bss_type` | in | 0: STA, 1: uAP. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if unsuccessful.

> **Note**: The data rate can be set only after association.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansettxrxhistogram"></a>
### `wlan_set_txrx_histogram`

```c
int wlan_set_txrx_histogram (int *bss_type*, struct wlan_txrx_histogram_info * *txrx_histogram*, t_u8 * *data*)
```

Sets the TX RX histogram config. This function can be called to set TX RX histogram config.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `bss_type` | in | 0: STA, 1: uAP. |
| `txrx_histogram` | in | User configured parameters of TX RX histogram. including enable and action. |
| `data` | out | TX RX histogram data from FW. |

**Returns**

- WM_SUCCESS if the call was successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetuapfrag"></a>
### `wlan_set_uap_frag`

```c
int wlan_set_uap_frag (int *frag*)
```

Sets the fragment threshold of the uAP in Wi-Fi firmware. If the size of packet exceeds the fragment threshold, the packet is divided into fragments. For example, if the fragment threshold is set to 300, a ping packet of size 1300 is divided into 5 fragments.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `frag` | in | the value of fragment threshold configuration. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetuaprts"></a>
### `wlan_set_uap_rts`

```c
int wlan_set_uap_rts (int *rts*)
```

Sets the RTS(Request to Send) threshold of the uAP in Wi-Fi firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `rts` | in | the value of rts threshold configuration. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetwwsmtxpwrlimit"></a>
### `wlan_set_wwsm_txpwrlimit`

```c
int wlan_set_wwsm_txpwrlimit (void **)
```

Sets worldwide safe mode TX power limits. Set TX power limit and ru TX power limit according to the region code. TX power limit: rg_power_cfg_info ru TX power limit: ru_power_cfg_info.

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if unsuccessful.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---


<a id="antennaconfiguration"></a>
### Antenna Configuration

| Function | Supported SoCs |
|----------|---------------|
| [`wlan_dual_ant_duty_cycle`](#wlandualantdutycycle) | RW612, IW610 |
| [`wlan_get_antcfg`](#wlangetantcfg) | All |
| [`wlan_get_ext_ant_gain`](#wlangetextantgain) | All |
| [`wlan_set_antcfg`](#wlansetantcfg) | All |
| [`wlan_set_ext_ant_gain`](#wlansetextantgain) | All |
| [`wlan_single_ant_duty_cycle`](#wlansingleantdutycycle) | RW612, IW610 |

<a id="wlandualantdutycycle"></a>
### `wlan_dual_ant_duty_cycle`

```c
int wlan_dual_ant_duty_cycle (t_u16 *enable*, t_u16 *nbTime*, t_u16 *wlanTime*, t_u16 *wlanBlockTime*)
```

Sets dual antenna duty cycle.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `enable` | in | enable/disable single duty cycle <br>• 0: Disable. <br>• 1: Enable. |
| `nbTime` | in | time in units 1ms, no more than wlanTime. |
| `wlanTime` | in | time in unit 1ms, total duty cycle time. |
| `wlanBlockTime` | in | time in unit 1ms. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

> **Note**: nbTime, wlanTime and wlanBlockTime should not equal to each other

---

> **Supported SoCs:** RW612, IW610

---

<a id="wlangetantcfg"></a>
### `wlan_get_antcfg`

```c
int wlan_get_antcfg (uint32_t * *ant*, uint16_t * *evaluate_time*, uint8_t * *evaluate_mode*, uint16_t * *current_antenna*)
```

This API can be used to get the mode of TX/RX antenna. If SAD (software antenna diversity) is enabled, this API can also be used to get SAD antenna evaluate time interval(antenna mode is antenna diversity when set SAD evaluate time interval).

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `ant` | out | pointer to antenna variable. antenna variable: <br>• 1: TX/RX antenna 1. <br>• 2: TX/RX antenna 2. <br>• 0xFFFF: TX/RX antenna diversity. |
| `evaluate_time` | out | pointer to evaluate_time variable for SAD. |
| `evaluate_mode` | in |  |
| `current_antenna` | out | pointer to current antenna. |

**Returns**

- WM_SUCCESS if successful.
- WLAN_ERROR_STATE if unsuccessful.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetextantgain"></a>
### `wlan_get_ext_ant_gain`

```c
int wlan_get_ext_ant_gain (const uint8_t *band*, const uint8_t *channel*, int8_t * *net_ant_gain*)
```

Gets computed net antenna gain for a given band and channel.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `band` | in | Band index (0=2.4 GHz, 1=5 GHz). |
| `channel` | in | Channel number within the specified band. |
| `net_ant_gain` | out | Pointer to store the computed net gain in dB (int8_t). |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetantcfg"></a>
### `wlan_set_antcfg`

```c
int wlan_set_antcfg (uint32_t *ant*, uint16_t *evaluate_time*, uint8_t *evaluate_mode*)
```

This API can be used to set the mode of TX/RX antenna. If SAD (software antenna diversity) is enabled, this API can also be used to set SAD antenna evaluate time interval(antenna mode is antenna diversity when set SAD evaluate time interval).

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `ant` | in | Antenna valid values are <br>• 1: TX/RX antenna 1. <br>• 2: TX/RX antenna 2. <br>• 0xFFFF: TX/RX antenna diversity. |
| `evaluate_time` | in | SAD evaluate time interval, default value is 6s(0x1770). |
| `evaluate_mode` | in | <br>• 0: PCB Ant + Ext Ant0. <br>• 1: Ext Ant0 + Ext Ant1. <br>• 2: PCB Ant + Ext Ant1. <br>• 0xFF: Default diversity mode. |

**Returns**

- WM_SUCCESS if successful.
- WLAN_ERROR_STATE if unsuccessful.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetextantgain"></a>
### `wlan_set_ext_ant_gain`

```c
int wlan_set_ext_ant_gain (const int8_t * *ext_ant_gain*, const uint8_t *num_subbands*)
```

Sets external antenna gain for all sub-bands.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `ext_ant_gain` | in | Pointer to array of per-sub-band gains in dB (int8_t). Array size must match firmware MAX_SUBBAND. |
| `num_subbands` | in | Number of sub-bands (must be <= WIFI_EXT_ANT_GAIN_MAX_SUBBAND). |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansingleantdutycycle"></a>
### `wlan_single_ant_duty_cycle`

```c
int wlan_single_ant_duty_cycle (t_u16 *enable*, t_u16 *nbTime*, t_u16 *wlanTime*)
```

Sets single antenna: duty cycle.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `enable` | in | enable/disable single duty cycle <br>• 0: Disable. <br>• 1: Enable. |
| `nbTime` | in | time in unit 1ms, no more than wlanTime. |
| `wlanTime` | in | time in unit 1ms, total duty cycle time. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

> **Note**: wlanTime should not equal to wlanTime-nbTime

---

> **Supported SoCs:** RW612, IW610

---


<a id="channelbandconfiguration"></a>
### Channel & Band Configuration

| Function | Supported SoCs |
|----------|---------------|
| [`wlan_get_bandcfg`](#wlangetbandcfg) | All |
| [`wlan_get_chanlist`](#wlangetchanlist) | All |
| [`wlan_get_current_channel`](#wlangetcurrentchannel) | All |
| [`wlan_set_bandcfg`](#wlansetbandcfg) | All |
| [`wlan_set_chanlist`](#wlansetchanlist) | All |
| [`wlan_set_chanlist_and_txpwrlimit`](#wlansetchanlistandtxpwrlimit) | All |
| [`wlan_set_network_chanlist`](#wlansetnetworkchanlist) | All |
| [`wlan_set_scan_channel_gap`](#wlansetscanchannelgap) | All |

<a id="wlangetbandcfg"></a>
### `wlan_get_bandcfg`

```c
int wlan_get_bandcfg (wlan_bandcfg_t * *bandcfg*)
```

Gets the band configuration.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `bandcfg` | out | band configuration. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetchanlist"></a>
### `wlan_get_chanlist`

```c
int wlan_get_chanlist (wlan_chanlist_t * *chanlist*)
```

Gets the channel list configuration.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `chanlist` | out | A pointer to wlan_chanlist_t channel list configuration. |

**Returns**

WM_SUCCESS on success, error otherwise.

> **Note**: The wlan_chanlist_t struct allocates memory for a maximum of 54. channels.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetcurrentchannel"></a>
### `wlan_get_current_channel`

```c
uint8_t wlan_get_current_channel (void **)
```

Use this API to get the channel number of associated BSS.

**Returns**

- channel number if operation is successful.
- 0 if command fails.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetbandcfg"></a>
### `wlan_set_bandcfg`

```c
int wlan_set_bandcfg (wlan_bandcfg_t * *bandcfg*)
```

Sets the band configuration.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `bandcfg` | in | band configuration. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

> **Note**: 11AC or 11AX only mode is not supported. Supported modes are:
 legacy (B + G + A)
 11N only
 11N + 11AC
 11N + 11AX
 11N + 11AC + 11AX

> **Note**: B, G and A modes are enabled by default and are not configurable.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetchanlist"></a>
### `wlan_set_chanlist`

```c
int wlan_set_chanlist (wlan_chanlist_t * *chanlist*)
```

Sets the channel list configuration.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `chanlist` | in | A pointer to wlan_chanlist_t channel list configuration. |

**Returns**

WM_SUCCESS on success, error otherwise.

> **Note**: If region enforcement flag is enabled in the OTP then this API should not take effect.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetchanlistandtxpwrlimit"></a>
### `wlan_set_chanlist_and_txpwrlimit`

```c
int wlan_set_chanlist_and_txpwrlimit (wlan_chanlist_t * *chanlist*, wlan_txpwrlimit_t * *txpwrlimit*)
```

Sets the channel list and TX power limit configuration.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `chanlist` | in | A pointer to wlan_chanlist_t channel List configuration. |
| `txpwrlimit` | in | A pointer to wlan_txpwrlimit_t TX power limit configuration. |

**Returns**

WM_SUCCESS on success, error otherwise.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetnetworkchanlist"></a>
### `wlan_set_network_chanlist`

```c
int wlan_set_network_chanlist (char * *name*, const uint8_t * *chan_list*, uint8_t *num_chans*, enum wlan_frequency_bands *freq_band*)
```

Sets the channel list for a network.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `name` | in | A pointer to a string representing the name of the network. |
| `chan_list` | in | A pointer to the channel list. |
| `num_chans` | in | Number of channels in the channel list. |
| `freq_band` | in | Frequency band for the channels (e.g., 2.4 GHz, 5 GHz). |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetscanchannelgap"></a>
### `wlan_set_scan_channel_gap`

```c
void wlan_set_scan_channel_gap (unsigned *scan_chan_gap*)
```

Sets the scan channel gap.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `scan_chan_gap` | in | Time gap to be used between two consecutive channels scan. |

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---


<a id="80211axwifi6"></a>
### 802.11ax (Wi-Fi 6)

| Function | Supported SoCs |
|----------|---------------|
| [`wlan_11ax_allowed`](#wlan11axallowed) | RW612, IW610, IW612 |
| [`wlan_enable_disable_htc`](#wlanenabledisablehtc) | RW612, IW610, IW612 |
| [`wlan_get_11ax_cfg`](#wlanget11axcfg) | RW612, IW610, IW612 |
| [`wlan_get_11ax_rutxpowerlimit_legacy`](#wlanget11axrutxpowerlimitlegacy) | RW612, IW610, IW612 |
| [`wlan_set_11ax_cfg`](#wlanset11axcfg) | RW612, IW610, IW612 |
| [`wlan_set_11ax_rutxpowerlimit`](#wlanset11axrutxpowerlimit) | RW612, IW610, IW612 |
| [`wlan_set_11ax_rutxpowerlimit_legacy`](#wlanset11axrutxpowerlimitlegacy) | RW612, IW610, IW612 |
| [`wlan_set_11ax_tol_time`](#wlanset11axtoltime) | RW612, IW610, IW612 |
| [`wlan_set_11ax_tx_omi`](#wlanset11axtxomi) | RW612, IW610, IW612 |

<a id="wlan11axallowed"></a>
### `wlan_11ax_allowed`

```c
int wlan_11ax_allowed (struct wlan_network * *network*)
```

Checks if 802.11ax is allowed in capability.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `network` | in | A pointer to the wlan_network. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612, IW610, IW612

---

<a id="wlanenabledisablehtc"></a>
### `wlan_enable_disable_htc`

```c
int wlan_enable_disable_htc (uint8_t *option*)
```

This function is used to enable/disable HTC (high throughput control).

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `option` | in | 1 => Enable; 0 => Disable. |

**Returns**

WM_SUCCESS if operation is successful, otherwise return -WM_FAIL.

---

> **Supported SoCs:** RW612, IW610, IW612

---

<a id="wlanget11axcfg"></a>
### `wlan_get_11ax_cfg`

```c
wlan_11ax_config_t * wlan_get_11ax_cfg (void **)
```

Gets default 802.11ax configuration parameters.

**Returns**

802.11ax configuration parameters default array.

---

> **Supported SoCs:** RW612, IW610, IW612

---

<a id="wlanget11axrutxpowerlimitlegacy"></a>
### `wlan_get_11ax_rutxpowerlimit_legacy`

```c
int wlan_get_11ax_rutxpowerlimit_legacy (wlan_rutxpwrlimit_t * *ru_pwr_cfg*)
```

Use this API to get the resource unit TX power limit by a channel-based approach.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `ru_pwr_cfg` | out | 802.11ax rutxpwr of channels to be get from firmware. |

**Returns**

- WM_SUCCESS if operation is successful.
- -WM_FAIL if command fails.

---

> **Supported SoCs:** RW612, IW610, IW612

---

<a id="wlanset11axcfg"></a>
### `wlan_set_11ax_cfg`

```c
int wlan_set_11ax_cfg (wlan_11ax_config_t * *ax_config*)
```

Sets 802.11ax configuration parameters.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `ax_config` | in | 802.11ax configuration parameters to be sent to firmware. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612, IW610, IW612

---

<a id="wlanset11axrutxpowerlimit"></a>
### `wlan_set_11ax_rutxpowerlimit`

```c
int wlan_set_11ax_rutxpowerlimit (const void * *rutx_pwr_cfg*, uint32_t *rutx_pwr_cfg_len*)
```

Use this API to set the resource unit TX power limit.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `rutx_pwr_cfg` | in | 802.11ax rutxpwr of sub-bands to be sent to firmware. refer to rutxpowerlimit_cfg_set_WW[] |
| `rutx_pwr_cfg_len` | in | Size of rutx_pwr_cfg buffer. |

**Returns**

- WM_SUCCESS if operation is successful.
- -WM_FAIL if command fails.

---

> **Supported SoCs:** RW612, IW610, IW612

---

<a id="wlanset11axrutxpowerlimitlegacy"></a>
### `wlan_set_11ax_rutxpowerlimit_legacy`

```c
int wlan_set_11ax_rutxpowerlimit_legacy (const wlan_rutxpwrlimit_t * *ru_pwr_cfg*)
```

Use this API to set the resource unit TX power limit by a channel-based approach.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `ru_pwr_cfg` | in | 802.11ax rutxpwr of channels to be sent to firmware. |

**Returns**

- WM_SUCCESS if operation is successful.
- -WM_FAIL if command fails.

---

> **Supported SoCs:** RW612, IW610, IW612

---

<a id="wlanset11axtoltime"></a>
### `wlan_set_11ax_tol_time`

```c
int wlan_set_11ax_tol_time (const t_u32 *tol_time*)
```

Sets 802.11ax OBSS (overlapping basic service set) narrow bandwidth RU (resource unit) tolerance time In uplink transmission, AP sends a trigger frame to all the stations that can be involved in the upcoming transmission, and then these stations transmit Trigger-based(TB) PPDU in response to the trigger frame. If STA connects to AP which channel is set to 100, STA doesn't support 26 tones RU. The API should be called when station is in disconnected state.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `tol_time` | in | Valid range [1...3600] tolerance time is in unit of seconds. STA periodically checks AP's beacon for ext cap bit79 (OBSS Narrow bandwidth RU in OFDMA tolerance support) and sets 20-tone RU tolerance time if ext cap bit79 is not set. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612, IW610, IW612

---

<a id="wlanset11axtxomi"></a>
### `wlan_set_11ax_tx_omi`

```c
int wlan_set_11ax_tx_omi (const t_u8 *interface*, const t_u16 *tx_omi*, const t_u8 *tx_option*, const t_u8 *num_data_pkts*)
```

Use this API to set the set 802.11ax TX OMI (operating mode indication).

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `interface` | in | Interface type STA or uAP. <br>• 0: STA. <br>• 1: uAP. |
| `tx_omi` | in | value to be sent to firmware. |
| `tx_option` | in | value to be sent to firmware 1: Send OMI (operating mode indication) in QoS (quality of service) data. |
| `num_data_pkts` | in | value to be sent to firmware num_data_pkts is applied only if OMI is sent in QoS data frame. It specifies the number of consecutive data frames containing the OMI. Minimum value is 1 Maximum value is 16. |

**Returns**

- WM_SUCCESS if operation is successful.
- -WM_FAIL if command fails.

---

> **Supported SoCs:** RW612, IW610, IW612

---


<a id="80211acwifi5"></a>
### 802.11ac (Wi-Fi 5)

| Function | Supported SoCs |
|----------|---------------|
| [`wlan_11ac_allowed`](#wlan11acallowed) | RW612, IW610, IW612 |

<a id="wlan11acallowed"></a>
### `wlan_11ac_allowed`

```c
int wlan_11ac_allowed (struct wlan_network * *network*)
```

Checks if 802.11ac is allowed in capability.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `network` | in | A pointer to the wlan_network. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612, IW610, IW612

---


<a id="80211nwifi4"></a>
### 802.11n (Wi-Fi 4)

| Function | Supported SoCs |
|----------|---------------|
| [`wlan_11n_allowed`](#wlan11nallowed) | All |

<a id="wlan11nallowed"></a>
### `wlan_11n_allowed`

```c
int wlan_11n_allowed (struct wlan_network * *network*)
```

Checks if 802.11n is allowed in capability.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `network` | in | A pointer to the wlan_network. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---


<a id="ampduaggregation"></a>
### AMPDU & Aggregation

| Function | Supported SoCs |
|----------|---------------|
| [`wlan_tx_ampdu_prot_mode`](#wlantxampduprotmode) | RW612, IW610 |

<a id="wlantxampduprotmode"></a>
### `wlan_tx_ampdu_prot_mode`

```c
int wlan_tx_ampdu_prot_mode (tx_ampdu_prot_mode_para * *prot_mode*, t_u16 *action*)
```

Gets or sets the TX AMPDU protect mode.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `prot_mode` | inout | TX AMPDU protect mode. tx_ampdu_prot_mode_para |
| `action` | in | Command action <br>• 0: Get TX AMPDU protect mode. <br>• 1: Set TX AMPDU protect mode. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612, IW610

---


<a id="wmmqos"></a>
### WMM / QoS

| Function | Supported SoCs |
|----------|---------------|
| [`wlan_set_wmm_uapsd`](#wlansetwmmuapsd) | All |
| [`wlan_wmm_tx_stats_dump`](#wlanwmmtxstatsdump) | All |
| [`wlan_wmm_uapsd_qosinfo`](#wlanwmmuapsdqosinfo) | All |

<a id="wlansetwmmuapsd"></a>
### `wlan_set_wmm_uapsd`

```c
int wlan_set_wmm_uapsd (t_u8 *uapsd_enable*)
```

Enables or disables the UAPSD in the Wi-Fi firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `uapsd_enable` | in | Enable/Disable UAPSD. |

**Returns**

- WM_SUCCESS if the call was successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanwmmtxstatsdump"></a>
### `wlan_wmm_tx_stats_dump`

```c
void wlan_wmm_tx_stats_dump (int *bss_type*)
```

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanwmmuapsdqosinfo"></a>
### `wlan_wmm_uapsd_qosinfo`

```c
int wlan_wmm_uapsd_qosinfo (t_u8 * *qos_info*, t_u8 *action*)
```

Sets the QOS info of the UAPSD (unscheduled automatic Power-save delivery) in the Wi-Fi firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `qos_info` | inout | UAPSD (unscheduled automatic Power-save delivery) QOS info. |
| `action` | in | Set/get action. |

**Returns**

- WM_SUCCESS if the call was successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---


<a id="roaming80211krv"></a>
### Roaming (802.11k/r/v)

| Function | Supported SoCs |
|----------|---------------|
| [`wlan_ft_roam`](#wlanftroam) | All |
| [`wlan_get_host_11k_status`](#wlangethost11kstatus) | All |
| [`wlan_get_roaming_status`](#wlangetroamingstatus) | All |
| [`wlan_host_11k_cfg`](#wlanhost11kcfg) | All |
| [`wlan_host_11k_neighbor_req`](#wlanhost11kneighborreq) | All |
| [`wlan_host_11v_bss_trans_query`](#wlanhost11vbsstransquery) | All |
| [`wlan_set_roaming`](#wlansetroaming) | All |

<a id="wlanftroam"></a>
### `wlan_ft_roam`

```c
int wlan_ft_roam (const t_u8 * *bssid*, const t_u8 *channel*)
```

Starts FT roaming. This API is used to initiate fast BSS transition-based roaming.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `bssid` | in | BSSID of AP to roam. |
| `channel` | in | Channel of AP to roam. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangethost11kstatus"></a>
### `wlan_get_host_11k_status`

```c
bool wlan_get_host_11k_status (void **)
```

Gets the enable/disable host 802.11k feature flag.

**Returns**

TRUE if 802.11k is enabled, return FALSE if 802.11k is disabled.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetroamingstatus"></a>
### `wlan_get_roaming_status`

```c
int wlan_get_roaming_status (void **)
```

Gets the roaming status.

**Returns**

- 1 if roaming is enabled.
- 0 if roaming is disabled.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanhost11kcfg"></a>
### `wlan_host_11k_cfg`

```c
int wlan_host_11k_cfg (int *enable_11k*)
```

Enables or disables the host 802.11k feature.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `enable_11k` | in | the value of 8 <br>• 0: Disable host 802.11k. <br>• 1: Enable host 802.11k. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanhost11kneighborreq"></a>
### `wlan_host_11k_neighbor_req`

```c
int wlan_host_11k_neighbor_req (const char * *ssid*)
```

Host sends a neighbor report request.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `ssid` | in | The SSID for neighbor report. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

> **Note**: ssid parameter is optional, pass NULL pointer to ignore SSID input if not specify SSID

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanhost11vbsstransquery"></a>
### `wlan_host_11v_bss_trans_query`

```c
int wlan_host_11v_bss_trans_query (t_u8 *query_reason*)
```

Host sends a BSS transition management query. STA sends BTM (BSS transition management) query, and the AP supporting 11V will response BTM request, the AP will parse neighbor report in the BTM request and response the BTM response to AP to indicate the receive status.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `query_reason` | in | [0..16] IEEE 802.11v BTM (BSS transition management) Query reasons. Refer to IEEE Std 802.11v-2011 - Table 7-43x-Transition and Transition Query reasons table. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetroaming"></a>
### `wlan_set_roaming`

```c
int wlan_set_roaming (const uint8_t *bitmap*, const uint8_t *rssi_low_threshold*, const uint8_t *snr_low_threshold*)
```

Sets soft roaming config.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `bitmap` | in | Roaming event bitmap (0=disable, bit0=RSSI_LOW, bit1=SNR_LOW) |
| `rssi_low_threshold` | in | RSSI low threshold value. |
| `snr_low_threshold` | in | SNR low threshold value. |

**Returns**

- WM_SUCCESS if the call was successful.
- -WM_FAIL if failed.

> **Note**: RSSI Threshold setting for soft roaming: The provided RSSI low threshold value is used to subscribe RSSI low event from the firmware. On reception of this event, the background scan is started in the firmware with the same RSSI threshold to find out APs with a better signal strength than the RSSI threshold.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---


<a id="twttargetwaketime"></a>
### TWT (Target Wake Time)

| Function | Supported SoCs |
|----------|---------------|
| [`wlan_get_btwt_cfg`](#wlangetbtwtcfg) | RW612, IW610, IW612 |
| [`wlan_get_twt_report`](#wlangettwtreport) | RW612, IW610, IW612 |
| [`wlan_get_twt_setup_cfg`](#wlangettwtsetupcfg) | RW612, IW610, IW612 |
| [`wlan_get_twt_teardown_cfg`](#wlangettwtteardowncfg) | RW612, IW610, IW612 |
| [`wlan_set_btwt_cfg`](#wlansetbtwtcfg) | RW612, IW610, IW612 |
| [`wlan_set_twt_setup_cfg`](#wlansettwtsetupcfg) | RW612, IW610, IW612 |
| [`wlan_set_twt_teardown_cfg`](#wlansettwtteardowncfg) | RW612, IW610, IW612 |
| [`wlan_twt_information`](#wlantwtinformation) | RW612, IW610, IW612 |

<a id="wlangetbtwtcfg"></a>
### `wlan_get_btwt_cfg`

```c
int wlan_get_btwt_cfg (wlan_btwt_config_t * *btwt_cfg*)
```

Gets broadcast TWT (target wake time) configuration parameters.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `btwt_cfg` | in | Broadcast TWT Setup parameters to be sent to Firmware. |

**Returns**

WM_SUCCESS if successful otherwise failure.

---

> **Supported SoCs:** RW612, IW610, IW612

---

<a id="wlangettwtreport"></a>
### `wlan_get_twt_report`

```c
int wlan_get_twt_report (wlan_twt_report_t * *twt_report*)
```

Gets TWT report.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `twt_report` | out | TWT report parameter. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612, IW610, IW612

---

<a id="wlangettwtsetupcfg"></a>
### `wlan_get_twt_setup_cfg`

```c
wlan_twt_setup_config_t * wlan_get_twt_setup_cfg (void **)
```

Gets TWT setup configuration parameters.

**Returns**

TWT setup parameters default array.

---

> **Supported SoCs:** RW612, IW610, IW612

---

<a id="wlangettwtteardowncfg"></a>
### `wlan_get_twt_teardown_cfg`

```c
wlan_twt_teardown_config_t * wlan_get_twt_teardown_cfg (void **)
```

Gets TWT teardown configuration parameters.

**Returns**

TWT Teardown parameters default array.

---

> **Supported SoCs:** RW612, IW610, IW612

---

<a id="wlansetbtwtcfg"></a>
### `wlan_set_btwt_cfg`

```c
int wlan_set_btwt_cfg (wlan_btwt_config_t * *btwt_cfg*)
```

Sets broadcast TWT (target wake time) configuration parameters.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `btwt_cfg` | in | Broadcast TWT Setup parameters to be sent to Firmware. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612, IW610, IW612

---

<a id="wlansettwtsetupcfg"></a>
### `wlan_set_twt_setup_cfg`

```c
int wlan_set_twt_setup_cfg (const wlan_twt_setup_config_t * *twt_setup*)
```

Sets TWT setup configuration parameters.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `twt_setup` | in | TWT setup parameters to be sent to firmware. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612, IW610, IW612

---

<a id="wlansettwtteardowncfg"></a>
### `wlan_set_twt_teardown_cfg`

```c
int wlan_set_twt_teardown_cfg (const wlan_twt_teardown_config_t * *teardown_config*)
```

Sets TWT teardown configuration parameters.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `teardown_config` | in | TWT teardown parameters sent to firmware. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612, IW610, IW612

---

<a id="wlantwtinformation"></a>
### `wlan_twt_information`

```c
int wlan_twt_information (wlan_twt_information_t * *twt_information*)
```

Twt information.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `twt_information` | out | TWT information. |

**Returns**

WM_SUCCESS if successful otherwise failure.

---

> **Supported SoCs:** RW612, IW610, IW612

---


<a id="wps"></a>
### WPS

| Function | Supported SoCs |
|----------|---------------|
| [`wlan_start_ap_wps_pbc`](#wlanstartapwpspbc) | All |
| [`wlan_start_ap_wps_pin`](#wlanstartapwpspin) | All |
| [`wlan_start_wps_pbc`](#wlanstartwpspbc) | All |
| [`wlan_start_wps_pin`](#wlanstartwpspin) | All |
| [`wlan_wps_ap_cancel`](#wlanwpsapcancel) | All |
| [`wlan_wps_cancel`](#wlanwpscancel) | All |
| [`wlan_wps_generate_pin`](#wlanwpsgeneratepin) | All |

<a id="wlanstartapwpspbc"></a>
### `wlan_start_ap_wps_pbc`

```c
int wlan_start_ap_wps_pbc (void **)
```

Starts WPS PBC session.

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if unsuccessful.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanstartapwpspin"></a>
### `wlan_start_ap_wps_pin`

```c
int wlan_start_ap_wps_pin (const char * *pin*)
```

Starts WPS pin session.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `pin` | in | Pin for WPS session. |

**Returns**

- WM_SUCCESS if the pin entered is valid.
- -WM_FAIL if invalid pin entered.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanstartwpspbc"></a>
### `wlan_start_wps_pbc`

```c
int wlan_start_wps_pbc (const struct netif * *netif*)
```

Starts WPS PBC (push button configuration) session.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `netif` | in | Pointer to network interface structure. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if unsuccessful.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanstartwpspin"></a>
### `wlan_start_wps_pin`

```c
int wlan_start_wps_pin (const struct netif * *netif*, const char * *pin*)
```

Starts WPS pin session.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `netif` | in | Pointer to network interface structure. |
| `pin` | in | Pin for WPS session. |

**Returns**

- WM_SUCCESS if the pin entered is valid.
- -WM_FAIL if invalid pin entered.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanwpsapcancel"></a>
### `wlan_wps_ap_cancel`

```c
int wlan_wps_ap_cancel (void **)
```

Cancel AP's WPS session.

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if unsuccessful.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanwpscancel"></a>
### `wlan_wps_cancel`

```c
int wlan_wps_cancel (void **)
```

Cancel WPS session.

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if unsuccessful.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanwpsgeneratepin"></a>
### `wlan_wps_generate_pin`

```c
void wlan_wps_generate_pin (uint32_t * *pin*)
```

This function generates a pin for WPS pin session.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `pin` | out | A pointer to a variable where the generated WPS pin will be stored. |

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---


<a id="dppdeviceprovisioningprotocol"></a>
### DPP (Device Provisioning Protocol)

| Function | Supported SoCs |
|----------|---------------|
| [`wlan_dpp_auth_init`](#wlandppauthinit) | RW612 |
| [`wlan_dpp_bootstrap_gen`](#wlandppbootstrapgen) | RW612 |
| [`wlan_dpp_bootstrap_get_uri`](#wlandppbootstrapgeturi) | RW612 |
| [`wlan_dpp_chirp`](#wlandppchirp) | RW612 |
| [`wlan_dpp_configurator_add`](#wlandppconfiguratoradd) | RW612 |
| [`wlan_dpp_configurator_params`](#wlandppconfiguratorparams) | RW612 |
| [`wlan_dpp_configurator_sign`](#wlandppconfiguratorsign) | RW612 |
| [`wlan_dpp_listen`](#wlandpplisten) | RW612 |
| [`wlan_dpp_mud_url`](#wlandppmudurl) | RW612 |
| [`wlan_dpp_pkex_add`](#wlandpppkexadd) | RW612 |
| [`wlan_dpp_qr_code`](#wlandppqrcode) | RW612 |
| [`wlan_dpp_reconfig`](#wlandppreconfig) | RW612 |
| [`wlan_dpp_stop_listen`](#wlandppstoplisten) | RW612 |

<a id="wlandppauthinit"></a>
### `wlan_dpp_auth_init`

```c
int wlan_dpp_auth_init (int *is_ap*, const char * *cmd*)
```

Sends provisioning auth request to responder.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `is_ap` | in | 0 is STA, 1 is uAP. |
| `cmd` | in | " peer=<qr-code-id> conf=<sta-dpp/ap-dpp/sta-psk> ....". |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612

---

<a id="wlandppbootstrapgen"></a>
### `wlan_dpp_bootstrap_gen`

```c
int wlan_dpp_bootstrap_gen (int *is_ap*, const char * *cmd*)
```

Generates QR code.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `is_ap` | in | 0 is STA, 1 is uAP. |
| `cmd` | in | "type=qrcode mac=<mac-address-of-device> chan=<operating-class/channel>...". |

**Returns**

bootstrap-id if successful otherwise return -WM_FAIL.

---

> **Supported SoCs:** RW612

---

<a id="wlandppbootstrapgeturi"></a>
### `wlan_dpp_bootstrap_get_uri`

```c
const char * wlan_dpp_bootstrap_get_uri (int *is_ap*, unsigned int *id*)
```

Gets QR code by bootstrap-id.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `is_ap` | in | 0 is STA, 1 is uAP. |
| `id` | in | bootstrap-id. |

**Returns**

QR code string if successful otherwise NULL.

---

> **Supported SoCs:** RW612

---

<a id="wlandppchirp"></a>
### `wlan_dpp_chirp`

```c
int wlan_dpp_chirp (int *is_ap*, const char * *cmd*)
```

sends DPP presence announcement.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `is_ap` | in | 0 is STA, 1 is uAP. |
| `cmd` | in | "own=<bootstrap id> listen=<freq> ...". |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612

---

<a id="wlandppconfiguratoradd"></a>
### `wlan_dpp_configurator_add`

```c
int wlan_dpp_configurator_add (int *is_ap*, const char * *cmd*)
```

Adds a DPP (device provisioning protocol) configurator.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `is_ap` | in | 0 is STA, 1 is uAP. |
| `cmd` | in | "curve=P-256". |

**Returns**

configurator ID if successful otherwise return -WM_FAIL.

---

> **Supported SoCs:** RW612

---

<a id="wlandppconfiguratorparams"></a>
### `wlan_dpp_configurator_params`

```c
void wlan_dpp_configurator_params (int *is_ap*, const char * *cmd*)
```

Sets DPP (device provisioning protocol) configurator parameter.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `is_ap` | in | 0 is STA, 1 is uAP. |
| `cmd` | in | " conf=<sta-dpp/ap-dpp/sta-psk> ssid=<hex ssid> configurator=conf_id...". |

**Returns**

void.

---

> **Supported SoCs:** RW612

---

<a id="wlandppconfiguratorsign"></a>
### `wlan_dpp_configurator_sign`

```c
int wlan_dpp_configurator_sign (int *is_ap*, const char * *cmd*)
```

Configurator configures itself as an Enrollee AP/STA.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `is_ap` | in | 0 is STA, 1 is uAP. |
| `cmd` | in | " conf=<sta-dpp/ap-dpp/sta-psk> ssid=<hex ssid> configurator=conf_id...". |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612

---

<a id="wlandpplisten"></a>
### `wlan_dpp_listen`

```c
int wlan_dpp_listen (int *is_ap*, const char * *cmd*)
```

Make device listen to DPP request.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `is_ap` | in | 0 is STA, 1 is uAP. |
| `cmd` | in | "<frequency>". |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612

---

<a id="wlandppmudurl"></a>
### `wlan_dpp_mud_url`

```c
void wlan_dpp_mud_url (int *is_ap*, const char * *cmd*)
```

MUD URL for enrollee's DPP configuration request (optional).

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `is_ap` | in | 0 is STA, 1 is uAP. |
| `cmd` | in | "https://example.com/mud". |

**Returns**

void.

---

> **Supported SoCs:** RW612

---

<a id="wlandpppkexadd"></a>
### `wlan_dpp_pkex_add`

```c
int wlan_dpp_pkex_add (int *is_ap*, const char * *cmd*)
```

Sets bootstrapping through PKEX (Public Key Exchange).

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `is_ap` | in | 0 is STA, 1 is uAP. |
| `cmd` | in | "own=<bootstrap_id> identifier=<string> code=<string>". |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612

---

<a id="wlandppqrcode"></a>
### `wlan_dpp_qr_code`

```c
int wlan_dpp_qr_code (int *is_ap*, char * *uri*)
```

Enter the QR code in the DPP device.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `is_ap` | in | 0 is STA, 1 is uAP. |
| `uri` | in | QR code provided by other device. |

**Returns**

qr-code-id if successful otherwise return -WM_FAIL.

---

> **Supported SoCs:** RW612

---

<a id="wlandppreconfig"></a>
### `wlan_dpp_reconfig`

```c
int wlan_dpp_reconfig (const char * *cmd*)
```

DPP reconfig.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `cmd` | in | "<network id> ...". |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612

---

<a id="wlandppstoplisten"></a>
### `wlan_dpp_stop_listen`

```c
int wlan_dpp_stop_listen (int *is_ap*)
```

DPP stop listen.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `is_ap` | in | 0 is STA, 1 is uAP. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612

---


<a id="wifidirectp2p"></a>
### Wi-Fi Direct (P2P)

| Function | Supported SoCs |
|----------|---------------|
| [`wlan_p2p_cancel`](#wlanp2pcancel) | RW612 |
| [`wlan_p2p_connect`](#wlanp2pconnect) | RW612 |
| [`wlan_p2p_find`](#wlanp2pfind) | RW612 |
| [`wlan_p2p_get_passphrase`](#wlanp2pgetpassphrase) | RW612 |
| [`wlan_p2p_group_add`](#wlanp2pgroupadd) | RW612 |
| [`wlan_p2p_group_remove`](#wlanp2pgroupremove) | RW612 |
| [`wlan_p2p_invite`](#wlanp2pinvite) | RW612 |
| [`wlan_p2p_list_network`](#wlanp2plistnetwork) | RW612 |
| [`wlan_p2p_listen`](#wlanp2plisten) | RW612 |
| [`wlan_p2p_peer`](#wlanp2ppeer) | RW612 |
| [`wlan_p2p_peers`](#wlanp2ppeers) | RW612 |
| [`wlan_p2p_prov_disc`](#wlanp2pprovdisc) | RW612 |
| [`wlan_p2p_remove_client`](#wlanp2premoveclient) | RW612 |
| [`wlan_p2p_serv_disc_req`](#wlanp2pservdiscreq) | RW612 |
| [`wlan_p2p_serv_disc_resp`](#wlanp2pservdiscresp) | RW612 |
| [`wlan_p2p_servvice_add`](#wlanp2pservviceadd) | RW612 |
| [`wlan_p2p_set_listen_channel`](#wlanp2psetlistenchannel) | RW612 |
| [`wlan_p2p_status`](#wlanp2pstatus) | RW612 |
| [`wlan_p2p_stop_find`](#wlanp2pstopfind) | RW612 |

<a id="wlanp2pcancel"></a>
### `wlan_p2p_cancel`

```c
int wlan_p2p_cancel (void **)
```

Cancel ongoing P2P operations.

**Returns**

WM_SUCCESS if successful otherwise return -WM_FAIL.

---

> **Supported SoCs:** RW612

---

<a id="wlanp2pconnect"></a>
### `wlan_p2p_connect`

```c
int wlan_p2p_connect (char * *cmd*)
```

Initiate a P2P connection.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `cmd` | in | Connection parameters (e.g. Peer device address, WPS method etc). |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612

---

<a id="wlanp2pfind"></a>
### `wlan_p2p_find`

```c
int wlan_p2p_find (const char * *cmd*)
```

Initiate P2P discovery.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `cmd` | in | Optional parameters for discovery (e.g., timeout, type). |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612

---

<a id="wlanp2pgetpassphrase"></a>
### `wlan_p2p_get_passphrase`

```c
int wlan_p2p_get_passphrase (void **)
```

Retrieves the group passphrase.

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612

---

<a id="wlanp2pgroupadd"></a>
### `wlan_p2p_group_add`

```c
int wlan_p2p_group_add (char * *cmd*)
```

Create a new P2P group.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `cmd` | in | Group configuration parameters. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612

---

<a id="wlanp2pgroupremove"></a>
### `wlan_p2p_group_remove`

```c
int wlan_p2p_group_remove (char * *cmd*)
```

Tear down an existing P2P group.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `cmd` | in | The wfd interface name. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612

---

<a id="wlanp2pinvite"></a>
### `wlan_p2p_invite`

```c
int wlan_p2p_invite (char * *cmd*)
```

Issue a group invitation.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `cmd` | in | Invitation parameters (e.g. Peer address, Group address etc). |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612

---

<a id="wlanp2plistnetwork"></a>
### `wlan_p2p_list_network`

```c
int wlan_p2p_list_network (char * *buf*, size_t *buflen*, int * *reslen*)
```

Retrieves configured networks on a P2P interface.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `buf` | out | Pointer to the buffer that will receive the detailed information. |
| `buflen` | in | The total size of the buf in bytes. |
| `reslen` | out | Pointer to an integer where the actual length (in bytes) of data written to buf will be stored. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612

---

<a id="wlanp2plisten"></a>
### `wlan_p2p_listen`

```c
int wlan_p2p_listen (const char * *cmd*)
```

Initiates P2P listen mode.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `cmd` | in | Optional parameters for listen (e.g. timeout). |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612

---

<a id="wlanp2ppeer"></a>
### `wlan_p2p_peer`

```c
int wlan_p2p_peer (char * *cmd*, char * *peer_info_buf*, int *peer_info_buf_size*, int * *peer_info_len*)
```

Retrieves detailed information for a specified P2P peer.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `cmd` | in | A generic command string passed to wpa_cli. It should include the necessary parameters (e.g., "p2p_peer <peer_address>") to specify the target peer. |
| `peer_info_buf` | out | Pointer to the buffer that will receive the detailed peer information. |
| `peer_info_buf_size` | in | The total size of the peer_info_buf in bytes. |
| `peer_info_len` | out | Pointer to an integer where the actual length (in bytes) of data written to peer_info_buf will be stored. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612

---

<a id="wlanp2ppeers"></a>
### `wlan_p2p_peers`

```c
int wlan_p2p_peers (char * *peers_buf*, int *peer_buf_size*, int * *peers_buf_len*)
```

Retrieves the list of available P2P peers.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `peers_buf` | out | Pointer to the buffer that will receive the list of peer addresses or identifiers. |
| `peer_buf_size` | in | The total size of the peers_buf in bytes. |
| `peers_buf_len` | out | Pointer to an integer where the actual length (in bytes) of data written to peers_buf will be stored. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612

---

<a id="wlanp2pprovdisc"></a>
### `wlan_p2p_prov_disc`

```c
int wlan_p2p_prov_disc (char * *cmd*)
```

Initiate provisioning discovery.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `cmd` | in | Povisioning discovery parameters (e.g. device_addr, config_methods etc). |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612

---

<a id="wlanp2premoveclient"></a>
### `wlan_p2p_remove_client`

```c
int wlan_p2p_remove_client (char * *cmd*)
```

Removes a client from the P2P group.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `cmd` | in | The address of the client to be removed. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612

---

<a id="wlanp2pservdiscreq"></a>
### `wlan_p2p_serv_disc_req`

```c
int wlan_p2p_serv_disc_req (char * *cmd*)
```

Sends a service discovery request.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `cmd` | in | Service discovery request parameters. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612

---

<a id="wlanp2pservdiscresp"></a>
### `wlan_p2p_serv_disc_resp`

```c
int wlan_p2p_serv_disc_resp (char * *cmd*)
```

Sends a service discovery response.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `cmd` | in | Service discovery response parameters. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612

---

<a id="wlanp2pservviceadd"></a>
### `wlan_p2p_servvice_add`

```c
int wlan_p2p_servvice_add (char * *cmd*)
```

Advertise a service.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `cmd` | in | A string or binary blob representing the service data. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612

---

<a id="wlanp2psetlistenchannel"></a>
### `wlan_p2p_set_listen_channel`

```c
int wlan_p2p_set_listen_channel (t_u8 *channel*, t_u8 *op_class*)
```

Sets P2P Listen channel.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `channel` | in | Channel to listen on. |
| `op_class` | in | Operating class of for listen channel. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612

---

<a id="wlanp2pstatus"></a>
### `wlan_p2p_status`

```c
int wlan_p2p_status (char * *buf*, size_t *buflen*, int * *reslen*)
```

Retrieves detailed information for a P2P interface.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `buf` | out | Pointer to the buffer that will receive the detailed information. |
| `buflen` | in | The total size of the buf in bytes. |
| `reslen` | out | Pointer to an integer where the actual length (in bytes) of data written to buf will be stored. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612

---

<a id="wlanp2pstopfind"></a>
### `wlan_p2p_stop_find`

```c
int wlan_p2p_stop_find (void **)
```

Stops the P2P discovery process.

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612

---


<a id="nanneighborawarenessnetworking"></a>
### NAN (Neighbor Awareness Networking)

| Function | Supported SoCs |
|----------|---------------|
| [`wlan_nan_cancel_publish`](#wlannancancelpublish) | RW612 |
| [`wlan_nan_cancel_subscribe`](#wlannancancelsubscribe) | RW612 |
| [`wlan_nan_publish`](#wlannanpublish) | RW612 |
| [`wlan_nan_subscribe`](#wlannansubscribe) | RW612 |
| [`wlan_nan_transmit`](#wlannantransmit) | RW612 |
| [`wlan_nan_update_publish`](#wlannanupdatepublish) | RW612 |

<a id="wlannancancelpublish"></a>
### `wlan_nan_cancel_publish`

```c
int wlan_nan_cancel_publish (int *publish_id*)
```

Cancel NAN USD publish.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `publish_id` | in | publish id to cancel. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612

---

<a id="wlannancancelsubscribe"></a>
### `wlan_nan_cancel_subscribe`

```c
int wlan_nan_cancel_subscribe (int *subscribe_id*)
```

Cancel NAN USD subscribe.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `subscribe_id` | in | subscribe id to cancel. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612

---

<a id="wlannanpublish"></a>
### `wlan_nan_publish`

```c
int wlan_nan_publish (wlan_nan_publish_params_t * *nan_publish*)
```

Initiate NAN USD publisher.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `nan_publish` | in | A pointer to wlan_nan_publish_params_t to store nan publish parameters. |

**Returns**

publish id if successful otherwise return -WM_FAIL.

---

> **Supported SoCs:** RW612

---

<a id="wlannansubscribe"></a>
### `wlan_nan_subscribe`

```c
int wlan_nan_subscribe (wlan_nan_subscribe_params_t * *nan_subscribe*)
```

Initiate NAN USD subscriber.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `nan_subscribe` | in | A pointer to wlan_nan_subscribe_params_t to store nan subscribe parameters. |

**Returns**

subscribe id if successful otherwise return -WM_FAIL.

---

> **Supported SoCs:** RW612

---

<a id="wlannantransmit"></a>
### `wlan_nan_transmit`

```c
int wlan_nan_transmit (int *own_id*, int *peer_id*, uint8_t * *peer_mac*, char * *ssi_tx*)
```

Initiate NAN USD subscriber.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `own_id` | in | own publish id or subscribe id |
| `peer_id` | in | peer's id |
| `peer_mac` | in | peer's MAC address |
| `ssi_tx` | in | service specific information (hexdump) |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612

---

<a id="wlannanupdatepublish"></a>
### `wlan_nan_update_publish`

```c
int wlan_nan_update_publish (int *publish_id*, char * *ssi_update*)
```

Update NAN USD publish.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `publish_id` | in | Publish session ID to update. |
| `ssi_update` | in | Updated service specific information string (hexdump). |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612

---


<a id="csichannelstateinformation"></a>
### CSI (Channel State Information)

| Function | Supported SoCs |
|----------|---------------|
| [`wlan_csi_cfg`](#wlancsicfg) | RW612, IW610 |
| [`wlan_get_csi_cfg_param_default`](#wlangetcsicfgparamdefault) | RW612, IW610 |
| [`wlan_register_csi_user_callback`](#wlanregistercsiusercallback) | RW612, IW610 |
| [`wlan_reset_csi_filter_data`](#wlanresetcsifilterdata) | RW612, IW610 |
| [`wlan_set_csi_cfg_param_default`](#wlansetcsicfgparamdefault) | RW612, IW610 |
| [`wlan_unregister_csi_user_callback`](#wlanunregistercsiusercallback) | RW612, IW610 |

<a id="wlancsicfg"></a>
### `wlan_csi_cfg`

```c
int wlan_csi_cfg (wlan_csi_config_params_t * *csi_params*)
```

Sends the CSI configuration parameter to the firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `csi_params` | in | CSI configuration parameter |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612, IW610

---

<a id="wlangetcsicfgparamdefault"></a>
### `wlan_get_csi_cfg_param_default`

```c
wlan_csi_config_params_t * wlan_get_csi_cfg_param_default (void **)
```

This function gets CSI default configuration data.

**Returns**

CSI data pointer.

---

> **Supported SoCs:** RW612, IW610

---

<a id="wlanregistercsiusercallback"></a>
### `wlan_register_csi_user_callback`

```c
int wlan_register_csi_user_callback (int(*)(void *buffer, size_t len) *csi_data_recv_callback*)
```

This function registers callback which are used to deliver CSI (channel state information) data to user.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `csi_data_recv_callback` | in | Callback to deliver CSI data and max data length is 768 bytes. Process data as soon as possible in callback, or else shall block there. Type of callback return value is int.      Memory layout of buffer:      size(byte)                         items     Memory layout of buffer (size in bytes: item):     - <br>• 2: Buffer length [bit. <br>• 0: 12].     -. <br>• 2: CSI signature. <br>• 4: User defined HeaderID.     -. <br>• 2: Packet info.     -. <br>• 2: Frame control field for the received packet.     -. <br>• 8: Timestamp when packet received.     -. <br>• 6: Received packet destination MAC Address.     -. <br>• 6: Received packet source MAC address.     -. <br>• 1: RSSI for antenna A.     -. <br>• 1: RSSI for antenna B.     -. <br>• 1: Noise floor for antenna A.     -. <br>• 1: Noise floor for antenna B.     -. <br>• 1: RX signal strength above noise floor.     -. <br>• 1: Channel.     -. <br>• 2: User defined chip ID.     -. <br>• 4: Reserved.     -. <br>• 4: CSI data length in DWORDs.                                         CSI data. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612, IW610

---

<a id="wlanresetcsifilterdata"></a>
### `wlan_reset_csi_filter_data`

```c
void wlan_reset_csi_filter_data (void **)
```

This function resets Wi-Fi CSI filter data.

---

> **Supported SoCs:** RW612, IW610

---

<a id="wlansetcsicfgparamdefault"></a>
### `wlan_set_csi_cfg_param_default`

```c
int wlan_set_csi_cfg_param_default (wlan_csi_config_params_t * *in_csi_cfg*)
```

This function sets CSI default configuration data.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `in_csi_cfg` | in | CSI default configuration data to be set. |

**Returns**

if successful return 1 else return 0.

---

> **Supported SoCs:** RW612, IW610

---

<a id="wlanunregistercsiusercallback"></a>
### `wlan_unregister_csi_user_callback`

```c
int wlan_unregister_csi_user_callback (void **)
```

This function unregisters callback, which are used to deliver CSI data to the user.

**Returns**

WM_SUCCESS if successful.

---

> **Supported SoCs:** RW612, IW610

---


<a id="ftm80211azranging"></a>
### FTM / 802.11az Ranging

| Function | Supported SoCs |
|----------|---------------|
| [`wlan_ftm_11mc_cfg`](#wlanftm11mccfg) | IW612 |
| [`wlan_ftm_cfg`](#wlanftmcfg) | IW612 |
| [`wlan_ftm_civic_cfg`](#wlanftmciviccfg) | IW612 |
| [`wlan_ftm_location_cfg`](#wlanftmlocationcfg) | IW612 |
| [`wlan_ftm_start_stop`](#wlanftmstartstop) | IW612 |

<a id="wlanftm11mccfg"></a>
### `wlan_ftm_11mc_cfg`

```c
int wlan_ftm_11mc_cfg (ftm_11mc_nego_cfg_t * *ftm_11mc_nego_cfg*)
```

---

> **Supported SoCs:** IW612

---

<a id="wlanftmcfg"></a>
### `wlan_ftm_cfg`

```c
int wlan_ftm_cfg (const t_u8 *protocol*, ranging_11az_cfg_t * *ftm_ranging_cfg*)
```

Configures the FTM protocol.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `protocol` | in | 0: Dot11mc, 1: Dot11az_ntb, 2: Dot11az_tb. |
| `ftm_ranging_cfg` | in | FTM ranging config. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** IW612

---

<a id="wlanftmciviccfg"></a>
### `wlan_ftm_civic_cfg`

```c
int wlan_ftm_civic_cfg (location_civic_rep_t * *ftm_civic_cfg*)
```

---

> **Supported SoCs:** IW612

---

<a id="wlanftmlocationcfg"></a>
### `wlan_ftm_location_cfg`

```c
int wlan_ftm_location_cfg (location_cfg_info_t * *ftm_location_cfg*)
```

---

> **Supported SoCs:** IW612

---

<a id="wlanftmstartstop"></a>
### `wlan_ftm_start_stop`

```c
int wlan_ftm_start_stop (const t_u16 *action*, const t_u8 *loop_cnt*, const t_u8 * *mac*, const t_u8 *channel*)
```

Starts or stops FTM (Wi-Fi fine time measurement) based on the command from CLI.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `action` | in | <br>• 1: start FTM. <br>• 2: stop FTM. |
| `loop_cnt` | in |  |
| `mac` | in |  |
| `channel` | in |  |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** IW612

---


<a id="mbomultibandoperation"></a>
### MBO (Multi-Band Operation)

| Function | Supported SoCs |
|----------|---------------|
| [`wlan_mbo_peferch_cfg`](#wlanmbopeferchcfg) | RW612, IW610, IW612 |
| [`wlan_mbo_set_cell_capa`](#wlanmbosetcellcapa) | RW612, IW610, IW612 |
| [`wlan_mbo_set_oce`](#wlanmbosetoce) | RW612, IW610, IW612 |

<a id="wlanmbopeferchcfg"></a>
### `wlan_mbo_peferch_cfg`

```c
int wlan_mbo_peferch_cfg (const char * *non_pref_chan*)
```

Multi band operation (MBO) non-preferred channels.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `non_pref_chan` | in | list of non-preferred channels. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612, IW610, IW612

---

<a id="wlanmbosetcellcapa"></a>
### `wlan_mbo_set_cell_capa`

```c
int wlan_mbo_set_cell_capa (t_u8 *cell_capa*)
```

MBO set cellular data capabilities.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `cell_capa` | in | 1 = Cellular data connection available. 2 = Cellular data connection not available 3 = Not cellular capable (default) |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612, IW610, IW612

---

<a id="wlanmbosetoce"></a>
### `wlan_mbo_set_oce`

```c
int wlan_mbo_set_oce (t_u8 *oce*)
```

Optimized connectivity experience (OCE).

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `oce` | in | Enable OCE features. 1 = Enable OCE in non-AP STA mode (default; disabled if the driver does not indicate support for OCE in STA mode). 2 = Enable OCE in STA-CFON mode. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612, IW610, IW612

---


<a id="mefmanagemententityfilter"></a>
### MEF (Management Entity Filter)

| Function | Supported SoCs |
|----------|---------------|
| [`wlan_config_mef`](#wlanconfigmef) | RW612, IW610 |
| [`wlan_mef_set_auto_arp`](#wlanmefsetautoarp) | RW612, IW610 |
| [`wlan_mef_set_auto_ping`](#wlanmefsetautoping) | RW612, IW610 |
| [`wlan_mef_set_multicast`](#wlanmefsetmulticast) | RW612, IW610 |

<a id="wlanconfigmef"></a>
### `wlan_config_mef`

```c
int wlan_config_mef (int *type*, t_u8 *mef_action*)
```

This function sets/deletes MEF entries configuration.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `type` | in | MEF type: MEF_TYPE_DELETE, MEF_TYPE_AUTO_PING, MEF_TYPE_AUTO_ARP. |
| `mef_action` | in | To be 0discard and not wake host, 1discard and wake host 3allow and wake host. |

**Returns**

- WM_SUCCESS if the call was successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612, IW610

---

<a id="wlanmefsetautoarp"></a>
### `wlan_mef_set_auto_arp`

```c
int wlan_mef_set_auto_arp (t_u8 *mef_action*)
```

This function sets auto ARP configuration.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `mef_action` | in | To be 0discard and not wake host, 1discard and wake host, 3allow and wake host. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612, IW610

---

<a id="wlanmefsetautoping"></a>
### `wlan_mef_set_auto_ping`

```c
int wlan_mef_set_auto_ping (t_u8 *mef_action*)
```

This function sets auto ping configuration.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `mef_action` | in | To be <br>• 0: Discard ping packet and not wake host. <br>• 1: Discard ping packet and wake host. <br>• 3: Allow ping packet and wake host. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612, IW610

---

<a id="wlanmefsetmulticast"></a>
### `wlan_mef_set_multicast`

```c
int wlan_mef_set_multicast (t_u8 *mef_action*)
```

This function sets multicast packet as low power wake up condition.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `mef_action` | in | To be <br>• 0: Discard multicast packet and not wake host. <br>• 1: Discard multicast packet and wake host. <br>• 3: Allow multicast packet and wake host. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612, IW610

---


<a id="networkmonitor"></a>
### Network Monitor

| Function | Supported SoCs |
|----------|---------------|
| [`wlan_deregister_net_monitor_user_callback`](#wlanderegisternetmonitorusercallback) | RW612, IW610 |
| [`wlan_net_monitor_cfg`](#wlannetmonitorcfg) | RW612, IW610 |
| [`wlan_register_monitor_user_callback`](#wlanregistermonitorusercallback) | RW612, IW610 |

<a id="wlanderegisternetmonitorusercallback"></a>
### `wlan_deregister_net_monitor_user_callback`

```c
void wlan_deregister_net_monitor_user_callback (void **)
```

This function deregisters the monitor callback.

---

> **Supported SoCs:** RW612, IW610

---

<a id="wlannetmonitorcfg"></a>
### `wlan_net_monitor_cfg`

```c
int wlan_net_monitor_cfg (wlan_net_monitor_t * *monitor*)
```

Sends the network monitor configuration parameter to the firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `monitor` | in | Monitor configuration parameter |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612, IW610

---

<a id="wlanregistermonitorusercallback"></a>
### `wlan_register_monitor_user_callback`

```c
void wlan_register_monitor_user_callback (int(*)(void *buffer, t_u16 data_len) *monitor_data_recv_callback*)
```

This function registers callback, which are used to deliver monitor data to the user.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `monitor_data_recv_callback` | in | Callback to deliver monitor data and data length to user. Memory layout of buffer: offset(byte) items Memory layout of buffer (offset in bytes: item): <br>• 0: RSSI. <br>• 1: 802.11 MAC header. 1 + size of 802.11 MAC header: Frame body. |

---

> **Supported SoCs:** RW612, IW610

---


<a id="edmaccontrol"></a>
### ED MAC Control

| Function | Supported SoCs |
|----------|---------------|
| [`wlan_get_ed_mac_mode`](#wlangetedmacmode) | All |
| [`wlan_set_ed_mac_mode`](#wlansetedmacmode) | All |

<a id="wlangetedmacmode"></a>
### `wlan_get_ed_mac_mode`

```c
int wlan_get_ed_mac_mode (wlan_ed_mac_ctrl_t * *wlan_ed_mac_ctrl*)
```

This API can be used to get the current ED MAC mode configuration for the station.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `wlan_ed_mac_ctrl` | out | A pointer to wlan_ed_mac_ctrl_t as described in the corresponding set API. |

**Returns**

- WM_SUCCESS if the call was successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetedmacmode"></a>
### `wlan_set_ed_mac_mode`

```c
int wlan_set_ed_mac_mode (wlan_ed_mac_ctrl_t *wlan_ed_mac_ctrl*)
```

Configures Energy Detect MAC mode for the station in the Wi-Fi Firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `wlan_ed_mac_ctrl` | in | Struct with following parameters ed_ctrl_2g = <br>• 0: Disable EU adaptivity for 2.4 GHz band. ed_ctrl_2g =. <br>• 1: Enable EU adaptivity for 2.4 GHz band. ed_offset_2g =. <br>• 0: Default Energy Detect threshold (0x9). ed_offset_2g = other: Offset value in range 0x80 to 0x7F. |

**Returns**

- WM_SUCCESS if the call was successful.
- -WM_FAIL if failed.

> **Note**: When ED MAC mode is enabled, the Wi-Fi Firmware can behave in the following way:

> **Note**: If 5 GHz is enabled, the following fields also apply:     - ed_ctrl_5g = 0: Disable EU adaptivity for 5 GHz band.
    - ed_ctrl_5g = 1: Enable EU adaptivity for 5 GHz band.
    - ed_offset_5g = 0: Default Energy Detect threshold (0xC).
    - ed_offset_5g = other: Offset value in range 0x80 to 0x7F.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---


<a id="rfphyconfiguration"></a>
### RF & PHY Configuration

| Function | Supported SoCs |
|----------|---------------|
| [`wlan_auto_null_tx`](#wlanautonulltx) | RW612, IW610 |
| [`wlan_external_coex_pta_cfg`](#wlanexternalcoexptacfg) | RW612 |
| [`wlan_get_mmsf`](#wlangetmmsf) | RW612, IW610 |
| [`wlan_get_rx_abort_cfg_ext`](#wlangetrxabortcfgext) | RW612, IW610 |
| [`wlan_get_tsp_cfg`](#wlangettspcfg) | RW612, IW610 |
| [`wlan_set_ami_cfg`](#wlansetamicfg) | RW612 |
| [`wlan_set_clocksync_cfg`](#wlansetclocksynccfg) | RW612, IW610 |
| [`wlan_set_get_cck_desense_cfg`](#wlansetgetcckdesensecfg) | RW612, IW610 |
| [`wlan_set_get_rx_abort_cfg`](#wlansetgetrxabortcfg) | RW612, IW610 |
| [`wlan_set_mmsf`](#wlansetmmsf) | RW612, IW610 |
| [`wlan_set_rx_abort_cfg_ext`](#wlansetrxabortcfgext) | RW612, IW610 |
| [`wlan_set_tsp_cfg`](#wlansettspcfg) | RW612, IW610 |
| [`wlan_start_stop_ami`](#wlanstartstopami) | RW612 |

<a id="wlanautonulltx"></a>
### `wlan_auto_null_tx`

```c
int wlan_auto_null_tx (wlan_auto_null_tx_t * *auto_null_tx*, mlan_bss_type *bss_type*)
```

Start/Stop auto TX null. Call this API to auto transmit and one shot quality of service data packets to get the CSI after STA connected one AP or uAP was connected with external STA.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `auto_null_tx` | in | auto null RX information. |
| `bss_type` | in | <br>• 0: station;. <br>• 1: uAP. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

> **Note**: STA cannot send auto NULL data if not connected AP, not support auto TX without connecting AP. uAP cannot send auto NULL data if is not connected, not support auto tx without connecting with external STA.

---

> **Supported SoCs:** RW612, IW610

---

<a id="wlanexternalcoexptacfg"></a>
### `wlan_external_coex_pta_cfg`

```c
int wlan_external_coex_pta_cfg (ext_coex_pta_cfg *coex_pta_config*)
```

Sets the external coex PTA (packet traffic arbitration) parameters.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `coex_pta_config` | in | ext_coex_pta_cfg. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612

---

<a id="wlangetmmsf"></a>
### `wlan_get_mmsf`

```c
int wlan_get_mmsf (t_u8 * *enable*, t_u8 * *Density*, t_u8 * *MMSF*)
```

Gets 802.11ax AMPDU density configuration.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `enable` | out | 0 - Disable MMSF; 1 - Enable MMSF. |
| `Density` | out | AMPDU Density value. |
| `MMSF` | out | AMPDU MMSF value. Default value is 0x6. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612, IW610

---

<a id="wlangetrxabortcfgext"></a>
### `wlan_get_rx_abort_cfg_ext`

```c
int wlan_get_rx_abort_cfg_ext (struct wlan_rx_abort_cfg_ext * *cfg*)
```

Gets the dynamic RX abort configuration from the firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `cfg` | out | A pointer to information buffer. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612, IW610

---

<a id="wlangettspcfg"></a>
### `wlan_get_tsp_cfg`

```c
int wlan_get_tsp_cfg (t_u16 * *enable*, t_u32 * *back_off*, t_u32 * *highThreshold*, t_u32 * *lowThreshold*, t_u32 * *dutycycstep*, t_u32 * *dutycycmin*, int * *highthrtemp*, int * *lowthrtemp*, t_u32 * *throttledutycycle*, t_u32 * *rftemppollcnt*, int * *currCAUTemp*, int * *currRFUTemp*)
```

Gets the TSP (thermal safeguard protection) configuration. TSP algorithm monitors PA Tj and primarily backs off data throughput.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `enable` | out | Enable/Disable TSP algorithm. |
| `back_off` | out | Power back off [0...20]dB. |
| `highThreshold` | out | High threshold [0...300]°C. |
| `lowThreshold` | out | Low threshold [0...300]°C High Threshold is Greater than low threshold. |
| `dutycycstep` | out | Duty cycle step(percentage) |
| `dutycycmin` | out | Duty cycle min(percentage) |
| `highthrtemp` | out | High throttle threshold temperature(celsius) |
| `lowthrtemp` | out | Low throttle threshold temperature(celsius) |
| `throttledutycycle` | out | Throttled duty cycle [3...100] (percentage) |
| `rftemppollcnt` | out | RFU temperature poll/averaging count [1...100] (number of samples per average) |
| `currCAUTemp` | out | CAU TSEN temperature. |
| `currRFUTemp` | out | RFU temperature. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612, IW610

---

<a id="wlansetamicfg"></a>
### `wlan_set_ami_cfg`

```c
void wlan_set_ami_cfg (wlan_csi_proc_cfg * *cfg*)
```

This function sets Ambient Motion Index configuration.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `cfg` | in | Ambient Motion Index configuration. |

---

> **Supported SoCs:** RW612

---

<a id="wlansetclocksynccfg"></a>
### `wlan_set_clocksync_cfg`

```c
int wlan_set_clocksync_cfg (const wlan_clock_sync_gpio_tsf_t * *tsf_latch*)
```

Sets clock sync GPIO based TSF (time synchronization function).

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `tsf_latch` | in | Clock sync TSF latch parameters to be sent to firmware. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612, IW610

---

<a id="wlansetgetcckdesensecfg"></a>
### `wlan_set_get_cck_desense_cfg`

```c
int wlan_set_get_cck_desense_cfg (struct wlan_cck_desense_cfg * *cfg*, t_u16 *action*)
```

Gets or sets the CCK (complementary code keying) desense configuration to/from firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `cfg` | inout | A pointer to information buffer. |
| `action` | in | get or set. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612, IW610

---

<a id="wlansetgetrxabortcfg"></a>
### `wlan_set_get_rx_abort_cfg`

```c
int wlan_set_get_rx_abort_cfg (struct wlan_rx_abort_cfg * *cfg*, t_u16 *action*)
```

Gets or sets the RX abort configuration to or from the firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `cfg` | inout | A pointer to information buffer. |
| `action` | in | Command action: get or set. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612, IW610

---

<a id="wlansetmmsf"></a>
### `wlan_set_mmsf`

```c
int wlan_set_mmsf (const t_u8 *enable*, const t_u8 *Density*, const t_u8 *MMSF*)
```

Sets 802.11ax AMPDU (aggregate medium access control (MAC) protocol data unit) density configuration.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `enable` | in | 0 - Disable MMSF; 1 - Enable MMSF. |
| `Density` | in | AMPDU density value. Default value is 0x30. |
| `MMSF` | in | AMPDU MMSF value. Default value is 0x6. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612, IW610

---

<a id="wlansetrxabortcfgext"></a>
### `wlan_set_rx_abort_cfg_ext`

```c
int wlan_set_rx_abort_cfg_ext (const struct wlan_rx_abort_cfg_ext * *cfg*)
```

Sets the dynamic RX abort configuration to the firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `cfg` | in | A pointer to information buffer. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612, IW610

---

<a id="wlansettspcfg"></a>
### `wlan_set_tsp_cfg`

```c
int wlan_set_tsp_cfg (t_u16 *enable*, t_u32 *back_off*, t_u32 *highThreshold*, t_u32 *lowThreshold*, t_u32 *dutycycstep*, t_u32 *dutycycmin*, int *highthrtemp*, int *lowthrtemp*, t_u32 *rftemppollcnt*)
```

Sets the TSP (thermal safeguard protection) configuration. TSP algorithm monitors and primarily backs off data throughput.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `enable` | in | Enable/Disable tsp algorithm. |
| `back_off` | in | Power back off [0...20]dB. |
| `highThreshold` | in | High threshold [0...300]Celsius. |
| `lowThreshold` | in | Low threshold [0...300]Celsius High threshold is greater than low threshold. |
| `dutycycstep` | in | Duty cycle step(percentage) |
| `dutycycmin` | in | Duty cycle min(percentage) |
| `highthrtemp` | out | High throttle threshold temperature (celsius) |
| `lowthrtemp` | out | Low throttle threshold temperature (celsius) |
| `rftemppollcnt` | in | RFU temperature poll/averaging count [1...100] (number of samples per average) |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612, IW610

---

<a id="wlanstartstopami"></a>
### `wlan_start_stop_ami`

```c
void wlan_start_stop_ami (uint8_t *start*)
```

Use this API to start or stop calculate Ambient Motion Index.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `start` | in | start/stop <br>• 0: Stop. <br>• 1: Start. |

---

> **Supported SoCs:** RW612

---


<a id="eventsubscription"></a>
### Event Subscription

| Function | Supported SoCs |
|----------|---------------|
| [`wlan_clear_subscribe_event`](#wlanclearsubscribeevent) | RW612, IW610 |
| [`wlan_get_subscribe_event`](#wlangetsubscribeevent) | RW612, IW610 |
| [`wlan_set_subscribe_event`](#wlansetsubscribeevent) | RW612, IW610 |
| [`wlan_set_threshold_link_quality`](#wlansetthresholdlinkquality) | RW612, IW610 |

<a id="wlanclearsubscribeevent"></a>
### `wlan_clear_subscribe_event`

```c
int wlan_clear_subscribe_event (unsigned int *event_id*)
```

Cancel the subscribe event to firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `event_id` | in | event id to clear as per sub_event_id. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612, IW610

---

<a id="wlangetsubscribeevent"></a>
### `wlan_get_subscribe_event`

```c
int wlan_get_subscribe_event (wlan_ds_subscribe_evt * *sub_evt*)
```

Gets all subscribed events from Wi-Fi firmware along with threshold value and report frequency.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `sub_evt` | out | A pointer to wlan_ds_subscribe_evt to store the events data. |

**Returns**

WM_SUCCESS if set successfully, otherwise return failure.

---

> **Supported SoCs:** RW612, IW610

---

<a id="wlansetsubscribeevent"></a>
### `wlan_set_subscribe_event`

```c
int wlan_set_subscribe_event (unsigned int *event_id*, unsigned int *thresh_value*, unsigned int *freq*)
```

Subscribe specified event from the Wi-Fi firmware. Wi-Fi firmware report the registered event to driver upon configured report conditions are met.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `event_id` | in | event to register as per sub_event_id except for EVENT_SUB_LINK_QUALITY. |
| `thresh_value` | in | the RSSI threshold value (dBm) |
| `freq` | in | event frequency 0report once, 1report every time happened, N  report only happened > N consecutive times. |

**Returns**

WM_SUCCESS if set successfully, otherwise return failure.

---

> **Supported SoCs:** RW612, IW610

---

<a id="wlansetthresholdlinkquality"></a>
### `wlan_set_threshold_link_quality`

```c
int wlan_set_threshold_link_quality (unsigned int *event_id*, unsigned int *link_snr*, unsigned int *link_snr_freq*, unsigned int *link_rate*, unsigned int *link_rate_freq*, unsigned int *link_tx_latency*, unsigned int *link_tx_latency_freq*)
```

Subscribe link quality event.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `event_id` | in |  |
| `link_snr` | in | link quality snr value. |
| `link_snr_freq` | in | link quality snr freq. |
| `link_rate` | in | link quality rate. |
| `link_rate_freq` | in | link quality rate freq. |
| `link_tx_latency` | in | link quality write latency. |
| `link_tx_latency_freq` | in | link quality write latency freq. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612, IW610

---


<a id="managementframe"></a>
### Management Frame

| Function | Supported SoCs |
|----------|---------------|
| [`wlan_remain_on_channel`](#wlanremainonchannel) | All |
| [`wlan_rx_mgmt_indication`](#wlanrxmgmtindication) | All |
| [`wlan_set_sta_mac_filter`](#wlansetstamacfilter) | All |

<a id="wlanremainonchannel"></a>
### `wlan_remain_on_channel`

```c
int wlan_remain_on_channel (const enum wlan_bss_type *bss_type*, const bool *status*, const uint8_t *channel*, const uint32_t *duration*)
```

This API is used to set/cancel the remain on channel configuration.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `bss_type` | in | The interface to set channel bss_type 0: STA, 1: uAP. |
| `status` | in | false : Cancel the remain on channel configuration true : Set the remain on channel configuration. |
| `channel` | in | The channel to configure. |
| `duration` | in | The duration for which to remain on the channel in milliseconds. |

**Returns**

WM_SUCCESS on success or error code.

> **Note**: When status is false, channel and duration parameters are ignored.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanrxmgmtindication"></a>
### `wlan_rx_mgmt_indication`

```c
int wlan_rx_mgmt_indication (const enum wlan_bss_type *bss_type*, const uint32_t *mgmt_subtype_mask*, int(*)(const enum wlan_bss_type bss_type, const wlan_mgmt_frame_t *frame, const size_t len) *rx_mgmt_callback*)
```

This API can be used to start/stop the management frame forwarded to host through data path.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `bss_type` | in | The interface from which management frame needs to be collected 0: STA, 1: uAP. |
| `mgmt_subtype_mask` | in | Management Subtype Mask If Bit X is set in mask, it means that IEEE Management Frame SubType X is to be filtered and passed through to host. Bit Description [ <br>• 31: 14] Reserved [13] Action frame [12:9] Reserved [8] Beacon [7:6] Reserved [5] Probe response [4] Probe request [3] Reassociation response [2] Reassociation request [1] Association response [0] Association request Support multiple bits set. <br>• 0: Stop forwarding frames. <br>• 1: Start forwarding frames. |
| `rx_mgmt_callback` | in | The receive callback where the received management frames are passed. |

**Returns**

- WM_SUCCESS if operation is successful.
- -WM_FAIL if command fails.

> **Note**: Pass management subtype mask all zero to disable all the management frame forward to host.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetstamacfilter"></a>
### `wlan_set_sta_mac_filter`

```c
int wlan_set_sta_mac_filter (int *filter_mode*, int *mac_count*, unsigned char * *mac_addr*)
```

Sets the STA MAC filter in Wi-Fi firmware. Apply for uAP mode only. When STA MAC filter enabled, wlan firmware blocks all the packets from station with MAC address in black list and not blocks packets from station with MAC address in white list.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `filter_mode` | in | Channel filter mode (disable/white/black list) |
| `mac_count` | in | The count of MAC list. |
| `mac_addr` | in | The pointer to MAC address list. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---


<a id="securitycrypto"></a>
### Security & Crypto

| Function | Supported SoCs |
|----------|---------------|
| [`wlan_free_entp_cert_files`](#wlanfreeentpcertfiles) | RW612, IW610 |
| [`wlan_get_entp_cert_files`](#wlangetentpcertfiles) | RW612, IW610 |
| [`wlan_get_pmfcfg`](#wlangetpmfcfg) | All |
| [`wlan_pmksa_flush`](#wlanpmksaflush) | All |
| [`wlan_pmksa_list`](#wlanpmksalist) | All |
| [`wlan_set_crypto_AES_CCMP_decrypt`](#wlansetcryptoaesccmpdecrypt) | All |
| [`wlan_set_crypto_AES_CCMP_encrypt`](#wlansetcryptoaesccmpencrypt) | All |
| [`wlan_set_crypto_AES_ECB_decrypt`](#wlansetcryptoaesecbdecrypt) | All |
| [`wlan_set_crypto_AES_ECB_encrypt`](#wlansetcryptoaesecbencrypt) | All |
| [`wlan_set_crypto_AES_GCMP_decrypt`](#wlansetcryptoaesgcmpdecrypt) | All |
| [`wlan_set_crypto_AES_GCMP_encrypt`](#wlansetcryptoaesgcmpencrypt) | All |
| [`wlan_set_crypto_AES_WRAP_decrypt`](#wlansetcryptoaeswrapdecrypt) | All |
| [`wlan_set_crypto_AES_WRAP_encrypt`](#wlansetcryptoaeswrapencrypt) | All |
| [`wlan_set_crypto_RC4_decrypt`](#wlansetcryptorc4decrypt) | All |
| [`wlan_set_crypto_RC4_encrypt`](#wlansetcryptorc4encrypt) | All |
| [`wlan_set_entp_cert_files`](#wlansetentpcertfiles) | RW612, IW610 |
| [`wlan_set_okc`](#wlansetokc) | All |
| [`wlan_set_reassoc_control`](#wlansetreassoccontrol) | All |

<a id="wlanfreeentpcertfiles"></a>
### `wlan_free_entp_cert_files`

```c
void wlan_free_entp_cert_files (void **)
```

This function frees the temporary memory of enterprise certificate data After add new enterprise network profile, the certificate data has been parsed by mbedtls into another data, which can be freed.

---

> **Supported SoCs:** RW612, IW610

---

<a id="wlangetentpcertfiles"></a>
### `wlan_get_entp_cert_files`

```c
t_u32 wlan_get_entp_cert_files (int *cert_type*, t_u8 ** *data*)
```

This function gets enterprise certificate data from "wlan" global structure.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `cert_type` | in | certificate file type: <br>• 1: FILE_TYPE_ENTP_CA_CERT. <br>• 2: FILE_TYPE_ENTP_CLIENT_CERT. <br>• 3: FILE_TYPE_ENTP_CLIENT_KEY. |
| `data` | out | raw data of the enterprise certificate file. |

**Returns**

size of raw data.

---

> **Supported SoCs:** RW612, IW610

---

<a id="wlangetpmfcfg"></a>
### `wlan_get_pmfcfg`

```c
int wlan_get_pmfcfg (uint8_t * *mfpc*, uint8_t * *mfpr*)
```

Use this API to get the management frame protection parameters for sta.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `mfpc` | out | Management frame protection capable (MFPC) <br>• 0: Management frame protection not capable. <br>• 1: Management frame protection capable. |
| `mfpr` | out | Management frame protection required (MFPR) <br>• 0: Management frame protection optional. <br>• 1: Management frame protection required. |

**Returns**

- WM_SUCCESS if operation is successful.
- -WM_FAIL if command fails.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanpmksaflush"></a>
### `wlan_pmksa_flush`

```c
int wlan_pmksa_flush (void **)
```

Flush PTKSA cache entries.

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanpmksalist"></a>
### `wlan_pmksa_list`

```c
int wlan_pmksa_list (char * *buf*, size_t *buflen*)
```

Dumps the text list of entries in the PMKSA (pairwise master key security association) cache.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `buf` | out | Buffer to save PMKSA cache text list. |
| `buflen` | in | length of the buffer. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetcryptoaesccmpdecrypt"></a>
### `wlan_set_crypto_AES_CCMP_decrypt`

```c
int wlan_set_crypto_AES_CCMP_decrypt (const t_u8 * *Key*, const t_u16 *KeyLength*, const t_u8 * *AAD*, const t_u16 *AADLength*, const t_u8 * *Nonce*, const t_u16 *NonceLength*, t_u8 * *Data*, t_u16 * *DataLength*)
```

Sets crypto AES_GCMP algorithm decrypt command parameters.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `Key` | in | key. |
| `KeyLength` | in | The key length is 16/32. |
| `AAD` | in | AAD. |
| `AADLength` | in | The maximum AAD length is 30. |
| `Nonce` | in | Nonce. |
| `NonceLength` | in | The nonce length valid range [7,13]. |
| `Data` | in | Data. |
| `DataLength` | in | The maximum data length is 80. |

**Returns**

- WM_SUCCESS if successful.
- -WM_E_PERM if not supported.
- -WM_FAIL if failed.

> **Note**: If the function returns WM_SUCCESS, the data in the memory pointed to by data is overwritten by the decrypted data. The value of DataLength is updated to the decrypted data length. The decrypted data is 8 bytes (when key length is 16) or 16 bytes (when key length is 32) less than the original data.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetcryptoaesccmpencrypt"></a>
### `wlan_set_crypto_AES_CCMP_encrypt`

```c
int wlan_set_crypto_AES_CCMP_encrypt (const t_u8 * *Key*, const t_u16 *KeyLength*, const t_u8 * *AAD*, const t_u16 *AADLength*, const t_u8 * *Nonce*, const t_u16 *NonceLength*, t_u8 * *Data*, t_u16 * *DataLength*)
```

Sets crypto AES_CCMP (counter mode with cipher block chaining message authentication code protocol) algorithm encrypt command parameters.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `Key` | in | key. |
| `KeyLength` | in | The key length is 16/32. |
| `AAD` | in | AAD. |
| `AADLength` | in | The maximum AAD length is 30. |
| `Nonce` | in | Nonce. |
| `NonceLength` | in | The nonce length valid range [7,13]. |
| `Data` | in | Data. |
| `DataLength` | in | The maximum data length is 80. |

**Returns**

- WM_SUCCESS if successful.
- -WM_E_PERM if not supported.
- -WM_FAIL if failed.

> **Note**: If the function returns WM_SUCCESS, the data in the memory pointed to by data is overwritten by the encrypted data. The value of DataLength is updated to the encrypted data length. The encrypted data is 8 bytes (when key length is 16) or 16 bytes (when key length is 32) more than the original data. Therefore, the address pointed to by Data needs to reserve enough space.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetcryptoaesecbdecrypt"></a>
### `wlan_set_crypto_AES_ECB_decrypt`

```c
int wlan_set_crypto_AES_ECB_decrypt (const t_u8 * *Key*, const t_u16 *KeyLength*, const t_u8 * *KeyIV*, const t_u16 *KeyIVLength*, t_u8 * *Data*, t_u16 * *DataLength*)
```

Sets crypto AES_ECB (advanced encryption standard, electronic codebook) algorithm decrypt command parameters.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `Key` | in | key. |
| `KeyLength` | in | The key length is 16/24/32. |
| `KeyIV` | in | KeyIV should point to a 8 bytes array with any value in the array. |
| `KeyIVLength` | in | The keyIV length is 8. |
| `Data` | in | Data. |
| `DataLength` | in | The data length is 16. |

**Returns**

- WM_SUCCESS if successful.
- -WM_E_PERM if not supported.
- -WM_FAIL if failed.

> **Note**: If the function returns WM_SUCCESS, the data in the memory pointed to by data is overwritten by the decrypted data. The value of DataLength is updated to the decrypted data length. The length of the decrypted data is the same as the origin DataLength.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetcryptoaesecbencrypt"></a>
### `wlan_set_crypto_AES_ECB_encrypt`

```c
int wlan_set_crypto_AES_ECB_encrypt (const t_u8 * *Key*, const t_u16 *KeyLength*, const t_u8 * *KeyIV*, const t_u16 *KeyIVLength*, t_u8 * *Data*, t_u16 * *DataLength*)
```

Sets crypto AES_ECB (advanced encryption standard, electronic codebook) algorithm encrypt command parameters.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `Key` | in | key. |
| `KeyLength` | in | The key length is 16/24/32. |
| `KeyIV` | in | KeyIV should point to a 8 bytes array with any value in the array. |
| `KeyIVLength` | in | The keyIV length is 8. |
| `Data` | in | Data. |
| `DataLength` | in | The data length is 16. |

**Returns**

- WM_SUCCESS if successful.
- -WM_E_PERM if not supported.
- -WM_FAIL if failed.

> **Note**: If the function returns WM_SUCCESS, the data in the memory pointed to by data is overwritten by the encrypted data. The value of DataLength is updated to the encrypted data length. The length of the encrypted data is the same as the origin DataLength.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetcryptoaesgcmpdecrypt"></a>
### `wlan_set_crypto_AES_GCMP_decrypt`

```c
int wlan_set_crypto_AES_GCMP_decrypt (const t_u8 * *Key*, const t_u16 *KeyLength*, const t_u8 * *AAD*, const t_u16 *AADLength*, const t_u8 * *Nonce*, const t_u16 *NonceLength*, t_u8 * *Data*, t_u16 * *DataLength*)
```

Sets crypto AES_GCMP algorithm decrypt command parameters.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `Key` | in | key. |
| `KeyLength` | in | The key length is 16/32. |
| `AAD` | in | AAD. |
| `AADLength` | in | The maximum AAD length is 30. |
| `Nonce` | in | Nonce. |
| `NonceLength` | in | The nonce length valid range [7,13]. |
| `Data` | in | Data. |
| `DataLength` | in | The maximum data length is 80. |

**Returns**

- WM_SUCCESS if successful.
- -WM_E_PERM if not supported.
- -WM_FAIL if failed.

> **Note**: If the function returns WM_SUCCESS, the data in the memory pointed to by data is overwritten by the decrypted data. The value of DataLength is updated to the decrypted data length. The decrypted data is 16 bytes less than the original data.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetcryptoaesgcmpencrypt"></a>
### `wlan_set_crypto_AES_GCMP_encrypt`

```c
int wlan_set_crypto_AES_GCMP_encrypt (const t_u8 * *Key*, const t_u16 *KeyLength*, const t_u8 * *AAD*, const t_u16 *AADLength*, const t_u8 * *Nonce*, const t_u16 *NonceLength*, t_u8 * *Data*, t_u16 * *DataLength*)
```

Sets crypto AES_GCMP (galois/counter mode with AES-GMAC) algorithm encrypt command parameters.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `Key` | in | key. |
| `KeyLength` | in | The key length is 16/32. |
| `AAD` | in | AAD. |
| `AADLength` | in | The maximum AAD length is 30. |
| `Nonce` | in | Nonce. |
| `NonceLength` | in | The nonce length valid range [7,13]. |
| `Data` | in | Data. |
| `DataLength` | in | The maximum data length is 80. |

**Returns**

- WM_SUCCESS if successful.
- -WM_E_PERM if not supported.
- -WM_FAIL if failed.

> **Note**: If the function returns WM_SUCCESS, the data in the memory pointed to by data is overwritten by the encrypted data. The value of DataLength is updated to the encrypted data length. The encrypted data is 16 bytes more than the original data. Therefore, the address pointed to by Data needs to reserve enough space.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetcryptoaeswrapdecrypt"></a>
### `wlan_set_crypto_AES_WRAP_decrypt`

```c
int wlan_set_crypto_AES_WRAP_decrypt (const t_u8 * *Key*, const t_u16 *KeyLength*, const t_u8 * *KeyIV*, const t_u16 *KeyIVLength*, t_u8 * *Data*, t_u16 * *DataLength*)
```

Sets crypto AES_WRAP algorithm decrypt command parameters.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `Key` | in | key. |
| `KeyLength` | in | The key length is 16/24/32. |
| `KeyIV` | in | KeyIV. |
| `KeyIVLength` | in | The keyIV length is 8. |
| `Data` | in | Data. |
| `DataLength` | in | The data length valid range [8,1016]. |

**Returns**

- WM_SUCCESS if successful.
- -WM_E_PERM if not supported.
- -WM_FAIL if failed.

> **Note**: If the function returns WM_SUCCESS, the data in the memory pointed to by data is overwritten by the decrypted data. The value of DataLength is updated to the decrypted data length. The decrypted data is 8 bytes less than the original data.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetcryptoaeswrapencrypt"></a>
### `wlan_set_crypto_AES_WRAP_encrypt`

```c
int wlan_set_crypto_AES_WRAP_encrypt (const t_u8 * *Key*, const t_u16 *KeyLength*, const t_u8 * *KeyIV*, const t_u16 *KeyIVLength*, t_u8 * *Data*, t_u16 * *DataLength*)
```

Sets crypto AES_WRAP (advanced encryption standard wrap) algorithm encrypt command parameters.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `Key` | in | key. |
| `KeyLength` | in | The key length is 16/24/32. |
| `KeyIV` | in | KeyIV. |
| `KeyIVLength` | in | The keyIV length is 8. |
| `Data` | in | Data. |
| `DataLength` | in | The data length valid range [8,1016]. |

**Returns**

- WM_SUCCESS if successful.
- -WM_E_PERM if not supported.
- -WM_FAIL if failed.

> **Note**: If the function returns WM_SUCCESS, the data in the memory pointed to by data is overwritten by the encrypted data. The value of DataLength is updated to the encrypted data length. The encrypted data is 8 bytes more than the original data. Therefore, the address pointed to by Data needs to reserve enough space.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetcryptorc4decrypt"></a>
### `wlan_set_crypto_RC4_decrypt`

```c
int wlan_set_crypto_RC4_decrypt (const t_u8 * *Key*, const t_u16 *KeyLength*, const t_u8 * *KeyIV*, const t_u16 *KeyIVLength*, t_u8 * *Data*, t_u16 * *DataLength*)
```

Sets crypto RC4 (rivest cipher 4) algorithm decrypt command parameters.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `Key` | in | key. |
| `KeyLength` | in | The KeyLength + KeyIVLength valid range [1,256]. |
| `KeyIV` | in | KeyIV. |
| `KeyIVLength` | in | The KeyLength + KeyIVLength valid range [1,256]. |
| `Data` | in | Data. |
| `DataLength` | in | The maximum data length is 1200. |

**Returns**

- WM_SUCCESS if successful.
- -WM_E_PERM if not supported.
- -WM_FAIL if failed.

> **Note**: If the function returns WM_SUCCESS, the data in the memory pointed to by data is overwritten by the decrypted data. The value of DataLength is updated to the decrypted data length. The length of the decrypted data is the same as the origin DataLength.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetcryptorc4encrypt"></a>
### `wlan_set_crypto_RC4_encrypt`

```c
int wlan_set_crypto_RC4_encrypt (const t_u8 * *Key*, const t_u16 *KeyLength*, const t_u8 * *KeyIV*, const t_u16 *KeyIVLength*, t_u8 * *Data*, t_u16 * *DataLength*)
```

Sets crypto RC4 (rivest cipher 4) algorithm encrypt command parameters.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `Key` | in | key. |
| `KeyLength` | in | The KeyLength + KeyIVLength valid range [1,256]. |
| `KeyIV` | in | KeyIV. |
| `KeyIVLength` | in | The KeyLength + KeyIVLength valid range [1,256]. |
| `Data` | in | Data. |
| `DataLength` | in | The maximum data length is 1200. |

**Returns**

- WM_SUCCESS if successful.
- -WM_E_PERM if not supported.
- -WM_FAIL if failed.

> **Note**: If the function returns WM_SUCCESS, the data in the memory pointed to by data is overwritten by the encrypted data. The value of DataLength is updated to the encrypted data length. The length of the encrypted data is the same as the origin DataLength.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetentpcertfiles"></a>
### `wlan_set_entp_cert_files`

```c
int wlan_set_entp_cert_files (int *cert_type*, t_u8 * *data*, t_u32 *data_len*)
```

This function specifies the enterprise certificate file This function is used before adding network profile. It can store certificate data in "wlan" global structure.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `cert_type` | in | certificate file type: <br>• 1: FILE_TYPE_ENTP_CA_CERT. <br>• 2: FILE_TYPE_ENTP_CLIENT_CERT. <br>• 3: FILE_TYPE_ENTP_CLIENT_KEY. |
| `data` | in | raw data of the enterprise certificate file. |
| `data_len` | in | length of the enterprise certificate file. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612, IW610

---

<a id="wlansetokc"></a>
### `wlan_set_okc`

```c
int wlan_set_okc (t_u8 *okc*)
```

Opportunistic key caching (also known as proactive key caching) default This parameter can be used to set the default behavior for the proactive_key_caching parameter. By default, OKC is disabled unless enabled with the global okc=1 parameter or with the per-network pkc(proactive_key_caching)=1 parameter. With okc=1, OKC is enabled by default, but can be disabled with per-network pkc(proactive_key_caching)=0 parameter.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `okc` | in | Enable opportunistic key caching. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetreassoccontrol"></a>
### `wlan_set_reassoc_control`

```c
void wlan_set_reassoc_control (bool *reassoc_control*)
```

Sets the reassociation control in the Wi-Fi connection manager. When reassociation control enabled, Wi-Fi connection manager attempts reconnection with the network for WLAN_RECONNECT_LIMIT times before giving up.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `reassoc_control` | in | Reassociation enable/disable. |

> **Note**: Reassociation is enabled by default in the Wi-Fi connection manager.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---


<a id="wowlanwakeonwlan"></a>
### WoWLAN (Wake on WLAN)

| Function | Supported SoCs |
|----------|---------------|
| [`wlan_set_ipv6_ns_mef`](#wlansetipv6nsmef) | RW612, IW610 |
| [`wlan_tcp_keep_alive`](#wlantcpkeepalive) | All |
| [`wlan_wowlan_cfg_ptn_match`](#wlanwowlancfgptnmatch) | RW612, IW610 |
| [`wlan_wowlan_config`](#wlanwowlanconfig) | RW612, IW610 |

<a id="wlansetipv6nsmef"></a>
### `wlan_set_ipv6_ns_mef`

```c
int wlan_set_ipv6_ns_mef (t_u8 *mef_action*)
```

Use this API to enable the IPv6 neighbor solicitation offload in Wi-Fi firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `mef_action` | in | 0discard and not wake host, 1discard and wake host 3allow and wake host. |

**Returns**

- WM_SUCCESS if operation is successful.
- -WM_FAIL if command fails.

---

> **Supported SoCs:** RW612, IW610

---

<a id="wlantcpkeepalive"></a>
### `wlan_tcp_keep_alive`

```c
int wlan_tcp_keep_alive (wlan_tcp_keep_alive_t * *keep_alive*)
```

Use this API to configure the TCP keep alive parameters in Wi-Fi firmware. wlan_tcp_keep_alive_t provides the parameters which are available for configuration.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `keep_alive` | in | A pointer to wlan_tcp_keep_alive_t. |

**Returns**

- WM_SUCCESS if operation is successful.
- -WM_FAIL if command fails.

> **Note**: To reset current TCP keep alive configuration, just set the reset member of wlan_tcp_keep_alive_t with value 1, all other parameters are ignored in this case.

> **Note**: This API is called after successful connection and before putting Wi-Fi SoC in IEEE Power-save mode.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanwowlancfgptnmatch"></a>
### `wlan_wowlan_cfg_ptn_match`

```c
int wlan_wowlan_cfg_ptn_match (enum wlan_bss_type *bss_type*, wlan_wowlan_ptn_cfg_t * *ptn_cfg*)
```

Use this API to enable the WOWLAN (wake-on-wireless-LAN) on magic packet RX in Wi-Fi firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `bss_type` | in | 0for bss type as sta, 1for bss type as uap. |
| `ptn_cfg` | in | A pointer to wlan_wowlan_ptn_cfg_t containing wake on Wi-Fi pattern configuration. |

**Returns**

- WM_SUCCESS if operation is successful.
- -WM_FAIL if command fails

---

> **Supported SoCs:** RW612, IW610

---

<a id="wlanwowlanconfig"></a>
### `wlan_wowlan_config`

```c
int wlan_wowlan_config (uint8_t *is_mef*, t_u32 *wake_up_conds*)
```

Wowlan (wake on wireless LAN) configuration. This function may be called to configure host sleep in firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `is_mef` | in | Flag to indicate use MEF (memory efficient filtering) condition or not. |
| `wake_up_conds` | in | Bitmap of default condition. |

**Returns**

- WM_SUCCESS if the call was successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612, IW610

---


<a id="cloudkeepalive"></a>
### Cloud Keep-Alive

| Function | Supported SoCs |
|----------|---------------|
| [`wlan_cloud_keep_alive_enabled`](#wlancloudkeepaliveenabled) | IW416, IW610, IW612 |

<a id="wlancloudkeepaliveenabled"></a>
### `wlan_cloud_keep_alive_enabled`

```c
int wlan_cloud_keep_alive_enabled (t_u32 *dst_ip*, t_u16 *dst_port*)
```

Gets cloud keep alive status for given destination ip and port.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `dst_ip` | in | Destination ip address. |
| `dst_port` | in | Destination port. |

**Returns**

1 if enabled otherwise 0.

---

> **Supported SoCs:** IW416, IW610, IW612

---


<a id="stafiltermanagement"></a>
### STA & Filter Management

| Function | Supported SoCs |
|----------|---------------|
| [`wlan_set_multicast`](#wlansetmulticast) | RW612, IW610 |
| [`wlan_set_packet_filters`](#wlansetpacketfilters) | All |
| [`wlan_sta_inactivityto`](#wlanstainactivityto) | RW612, IW610 |

<a id="wlansetmulticast"></a>
### `wlan_set_multicast`

```c
int wlan_set_multicast (t_u8 *mef_action*)
```

This function sets multicast MEF (memory efficient filtering) entry.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `mef_action` | in | To be 0discard and not wake host, 1discard and wake host 3allow and wake host. |

**Returns**

- WM_SUCCESS if the call was successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612, IW610

---

<a id="wlansetpacketfilters"></a>
### `wlan_set_packet_filters`

```c
int wlan_set_packet_filters (wlan_flt_cfg_t * *flt_cfg*)
```

Use this API to set packet filters in Wi-Fi firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `flt_cfg` | in | A pointer to structure which holds the the packet filters wlan_flt_cfg_t. |

**Returns**

- WM_SUCCESS if operation is successful.
- -WM_FAIL if command fails.

> **Note**: For example:
 MEF Configuration command
 mefcfg={
 Criteria: bit0-broadcast, bit1-unicast, bit3-multicast
 Criteria=2 Unicast frames are received during host sleep mode
 NumEntries=1 Number of activated MEF entries
 mef_entry_0: example filters to match TCP destination port 80 send by 192.168.0.88 pkt or magic pkt.
 mef_entry_0={
 mode: bit0hostsleep mode, bit1non hostsleep mode
 mode=1 HostSleep mode
 action: 0discard and not wake host, 1discard and wake host 3allow and wake host
 action=3 Allow and Wake host
 filter_num=3 Number of filter
 RPN only support "&&" and "||" operators, space cannot be removed between operators.
 RPN=Filter_0 && Filter_1 || Filter_2
 Byte comparison filter's type is 0x41, decimal comparison filter's type is 0x42,
 Bit comparison filter's type is 0x43
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
 repeat=1 1 copies of 'c0:a8:00:58'
 byte=c0:a8:00:58 'c0:a8:00:58' is the byte sequence constant with each byte
 in hex format, with ':' as delimiter between two byte.
 offset=34 34 is the byte offset of the equal length field of rx'd pkt.
 }
 Filter_2 is Magic packet, it can look for 16 contiguous copies of '00:50:43:20:01:02' from
 the RX pkt's offset 14
 Filter_2={
 type=0x41 Byte comparison filter
 repeat=16 16 copies of '00:50:43:20:01:02'
 byte=00:50:43:20:01:02 # '00:50:43:20:01:02' is the byte sequence constant
 offset=14 14 is the byte offset of the equal length field of rx'd pkt.
 }
 }
 }
 Above filters can be set by filling values in following way in wlan_flt_cfg_t structure.
 wlan_flt_cfg_t flt_cfg;
 uint8_t byte_seq1[] = {0xc0, 0xa8, 0x00, 0x58};
 uint8_t byte_seq2[] = {0x00, 0x50, 0x43, 0x20, 0x01, 0x02};

 memset(&flt_cfg, 0, sizeof(wlan_flt_cfg_t));

 flt_cfg.criteria = 2;
 flt_cfg.nentries = 1;

 flt_cfg.mef_entry.mode = 1;
 flt_cfg.mef_entry.action = 3;

 flt_cfg.mef_entry.filter_num = 3;

 flt_cfg.mef_entry.filter_item[0].type = TYPE_DNUM_EQ;
 flt_cfg.mef_entry.filter_item[0].pattern = 80;
 flt_cfg.mef_entry.filter_item[0].offset = 44;
 flt_cfg.mef_entry.filter_item[0].num_bytes = 2;

 flt_cfg.mef_entry.filter_item[1].type = TYPE_BYTE_EQ;
 flt_cfg.mef_entry.filter_item[1].repeat = 1;
 flt_cfg.mef_entry.filter_item[1].offset = 34;
 flt_cfg.mef_entry.filter_item[1].num_byte_seq = 4;
 memcpy(flt_cfg.mef_entry.filter_item[1].byte_seq, byte_seq1, 4);
 flt_cfg.mef_entry.rpn[1] = RPN_TYPE_AND;

 flt_cfg.mef_entry.filter_item[2].type = TYPE_BYTE_EQ;
 flt_cfg.mef_entry.filter_item[2].repeat = 16;
 flt_cfg.mef_entry.filter_item[2].offset = 14;
 flt_cfg.mef_entry.filter_item[2].num_byte_seq = 6;
 memcpy(flt_cfg.mef_entry.filter_item[2].byte_seq, byte_seq2, 6);
 flt_cfg.mef_entry.rpn[2] = RPN_TYPE_OR;

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanstainactivityto"></a>
### `wlan_sta_inactivityto`

```c
int wlan_sta_inactivityto (wlan_inactivity_to_t * *inac_to*, t_u16 *action*)
```

Gets or sets the inactivity timeout extend.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `inac_to` | in | wlan_inactivity_to_t. |
| `action` | in | <br>• 0: Get. <br>• 1: Set. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612, IW610

---


<a id="statisticsdiagnostics"></a>
### Statistics & Diagnostics

| Function | Supported SoCs |
|----------|---------------|
| [`wlan_channel_load`](#wlanchannelload) | All |
| [`wlan_get_average_signal_strength`](#wlangetaveragesignalstrength) | All |
| [`wlan_get_channel_load`](#wlangetchannelload) | All |
| [`wlan_get_current_nf`](#wlangetcurrentnf) | All |
| [`wlan_get_current_rssi`](#wlangetcurrentrssi) | All |
| [`wlan_get_current_signal_strength`](#wlangetcurrentsignalstrength) | All |
| [`wlan_get_firmware_version_ext`](#wlangetfirmwareversionext) | All |
| [`wlan_get_log`](#wlangetlog) | All |
| [`wlan_get_signal_info`](#wlangetsignalinfo) | All |
| [`wlan_get_stats`](#wlangetstats) | All |
| [`wlan_reset_stats`](#wlanresetstats) | All |
| [`wlan_version_extended`](#wlanversionextended) | All |

<a id="wlanchannelload"></a>
### `wlan_channel_load`

```c
int wlan_channel_load (wlan_802_11_chan_load_t * *chan_load*)
```

Sets the Wi-Fi channel load information.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetaveragesignalstrength"></a>
### `wlan_get_average_signal_strength`

```c
int wlan_get_average_signal_strength (short * *rssi*, int * *snr*)
```

Gets the average RSSI and signal to noise ratio (average value of the former 8 packets) from Wi-Fi firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `rssi` | out | A pointer to a variable to store the average RSSI (Received Signal Strength Indicator) in dBm. |
| `snr` | out | A pointer to a variable to store the average SNR (Signal to Noise Ratio) in dB. |

**Returns**

WM_SUCCESS if successful.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetchannelload"></a>
### `wlan_get_channel_load`

```c
int wlan_get_channel_load (wlan_802_11_chan_load_t * *chan_load*)
```

Gets the Wi-Fi channel load info.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `chan_load` | out | Pointer to channel load info structure to be filled. |

**Returns**

WM_SUCCESS if successful. Returns -WM_FAIL otherwise.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetcurrentnf"></a>
### `wlan_get_current_nf`

```c
int wlan_get_current_nf (void **)
```

Gets the current noise floor.

**Returns**

The noise floor value.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetcurrentrssi"></a>
### `wlan_get_current_rssi`

```c
int wlan_get_current_rssi (short * *rssi*)
```

Gets the current RSSI value.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `rssi` | out | pointer to get the current RSSI (Received Signal Strength Indicator) |

**Returns**

WM_SUCCESS.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetcurrentsignalstrength"></a>
### `wlan_get_current_signal_strength`

```c
int wlan_get_current_signal_strength (short * *rssi*, int * *snr*)
```

Gets the current RSSI and signal to noise ratio from Wi-Fi firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `rssi` | out | A pointer to a variable to store the current RSSI (Received Signal Strength Indicator) in dBm. |
| `snr` | out | A pointer to a variable to store the current SNR (Signal to Noise Ratio) in dB. |

**Returns**

WM_SUCCESS if successful.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetfirmwareversionext"></a>
### `wlan_get_firmware_version_ext`

```c
char * wlan_get_firmware_version_ext (void **)
```

Gets the Wi-Fi firmware version extension string.

**Returns**

Wi-Fi firmware version extension string pointer stored in WLCMGR.

> **Note**: This API does not allocate memory for pointer. It just returns pointer of WLCMGR internal static buffer. So no need to free the pointer by caller.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetlog"></a>
### `wlan_get_log`

```c
int wlan_get_log (wlan_pkt_stats_t * *stats*)
```

Use this API to get the various statistics of STA from Wi-Fi firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `stats` | out | A pointer to structure where stats collected from Wi-Fi firmware can be copied.  Explore the elements of the wlan_pkt_stats_t structure for more information on stats. |

**Returns**

- WM_SUCCESS if operation is successful.
- -WM_FAIL if command fails.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetsignalinfo"></a>
### `wlan_get_signal_info`

```c
int wlan_get_signal_info (wlan_rssi_info_t * *signal*)
```

Gets RSSI information.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `signal` | out | RSSI information get report buffer. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetstats"></a>
### `wlan_get_stats`

```c
int wlan_get_stats (wlan_stats_t * *stats*, enum wlan_bss_type *bss_type*)
```

Use this API to get the various statistics of STA/uAP from Wi-Fi driver.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `stats` | out | A pointer to structure where stats collected from Wi-Fi driver can be copied.  Explore the elements of the wlan_stats_t structure for more information on stats. |
| `bss_type` | in | 0: STA, 1: uAP. |

**Returns**

- WM_SUCCESS if operation is successful.
- -WM_FAIL if command fails.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanresetstats"></a>
### `wlan_reset_stats`

```c
int wlan_reset_stats (enum wlan_bss_type *bss_type*)
```

Use this API to reset the various statistics of STA/uAP from Wi-Fi driver.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `bss_type` | in | 0: STA, 1: uAP. |

**Returns**

- WM_SUCCESS if operation is successful.
- -WM_FAIL if command fails.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanversionextended"></a>
### `wlan_version_extended`

```c
void wlan_version_extended (void **)
```

Use this API to print Wi-Fi driver and firmware extended version on the console.

> **Note**: Call this API when SDK_DEBUGCONSOLE not set to DEBUGCONSOLE_DISABLE.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---


<a id="macaddress"></a>
### MAC Address

| Function | Supported SoCs |
|----------|---------------|
| [`wlan_get_mac_address`](#wlangetmacaddress) | All |
| [`wlan_get_mac_address_uap`](#wlangetmacaddressuap) | All |
| [`wlan_get_wfd_mac_address`](#wlangetwfdmacaddress) | RW612 |
| [`wlan_set_mac_addr`](#wlansetmacaddr) | All |
| [`wlan_set_sta_mac_addr`](#wlansetstamacaddr) | All |

<a id="wlangetmacaddress"></a>
### `wlan_get_mac_address`

```c
int wlan_get_mac_address (unsigned char * *dest*)
```

Retrieves the Wi-Fi MAC address of the station interface.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `dest` | out | A pointer to a 6-byte array where the MAC address should be copied. |

**Returns**

- WM_SUCCESS if the MAC address was copied.
- -WM_E_INVAL if dest is NULL.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetmacaddressuap"></a>
### `wlan_get_mac_address_uap`

```c
int wlan_get_mac_address_uap (uint8_t * *dest*)
```

Retrieves the Wi-Fi MAC address of the uAP interface.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `dest` | out | A pointer to a 6-byte array where the MAC address can be copied. |

**Returns**

- WM_SUCCESS if the MAC address was copied.
- -WM_E_INVAL if dest is NULL.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetwfdmacaddress"></a>
### `wlan_get_wfd_mac_address`

```c
int wlan_get_wfd_mac_address (unsigned char * *dest*)
```

Retrieves the wireless MAC address of wfd interface.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `dest` | out | A pointer to a 6-byte array where the MAC address will be copied. |

**Returns**

- WM_SUCCESS if the MAC address was copied.
- -WM_E_INVAL if dest is NULL.

---

> **Supported SoCs:** RW612

---

<a id="wlansetmacaddr"></a>
### `wlan_set_mac_addr`

```c
int wlan_set_mac_addr (uint8_t * *mac*)
```

Sets the Wi-Fi MAC Address in the Wi-Fi firmware.

**Returns**

- WM_SUCCESS if the call was successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetstamacaddr"></a>
### `wlan_set_sta_mac_addr`

```c
int wlan_set_sta_mac_addr (uint8_t * *mac*)
```

Sets the Wi-Fi MAC address for the STA in the Wi-Fi firmware.

**Returns**

- WM_SUCCESS if the call was successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---


<a id="countryregion"></a>
### Country / Region

| Function | Supported SoCs |
|----------|---------------|
| [`wlan_get_11d_enable_status`](#wlanget11denablestatus) | All |
| [`wlan_get_country_code`](#wlangetcountrycode) | All |
| [`wlan_set_11d_state`](#wlanset11dstate) | All |
| [`wlan_set_country_code`](#wlansetcountrycode) | All |
| [`wlan_set_country_ie_ignore`](#wlansetcountryieignore) | All |

<a id="wlanget11denablestatus"></a>
### `wlan_get_11d_enable_status`

```c
bool wlan_get_11d_enable_status (void **)
```

Gets the current status of 802.11d support.

**Returns**

- true if 802.11d support is enabled by application.
- false if not enabled.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetcountrycode"></a>
### `wlan_get_country_code`

```c
int wlan_get_country_code (char * *alpha2*)
```

Gets current country code.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `alpha2` | out | Buffer to store the 2-character country code. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanset11dstate"></a>
### `wlan_set_11d_state`

```c
int wlan_set_11d_state (int *bss_type*, int *state*)
```

Sets STA/uAP 802.11d feature Enable/Disable.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `bss_type` | in | 0: STA, 1: uAP. |
| `state` | in | 0: disable, 1: enable. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetcountrycode"></a>
### `wlan_set_country_code`

```c
int wlan_set_country_code (const char * *alpha2*)
```

Sets the country code.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `alpha2` | in | country code in 3 octets string, 2 octets country code and 1 octet environment Supported 2-octet country codes: WW: World Wide Safe. US: US FCC. CA: IC Canada. SG: Singapore. EU: ETSI. AU: Australia. KR: Republic of Korea. FR: France. JP: Japan. CN: China. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

> **Note**: This API should be called after Wi-Fi is initialized but before starting uAP interface.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetcountryieignore"></a>
### `wlan_set_country_ie_ignore`

```c
int wlan_set_country_ie_ignore (uint8_t * *ignore*)
```

Sets ignore region code.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `ignore` | in | 0: don't ignore, 1: ignore. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---


<a id="calibration"></a>
### Calibration

| Function | Supported SoCs |
|----------|---------------|
| [`wlan_get_cal_data`](#wlangetcaldata) | All |
| [`wlan_get_otp_user_data`](#wlangetotpuserdata) | All |
| [`wlan_set_cal_data`](#wlansetcaldata) | All |

<a id="wlangetcaldata"></a>
### `wlan_get_cal_data`

```c
int wlan_get_cal_data (wlan_cal_data_t * *cal_data*)
```

Gets the calibration data from Wi-Fi firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `cal_data` | out | Pointer to calibration data structure where calibration data and it's length should be stored. |

**Returns**

- WM_SUCCESS if calibration data read operation is successful.
- -WM_E_INVAL if cal_data is not valid.
- -WM_FAIL if command fails.

> **Note**: The user of this API should free the allocated buffer for calibration data.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetotpuserdata"></a>
### `wlan_get_otp_user_data`

```c
int wlan_get_otp_user_data (uint8_t * *buf*, uint16_t *len*)
```

Gets the user data from OTP (one-time programming) memory.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `buf` | out | Pointer to buffer where data should be stored. |
| `len` | out | Number of bytes to read. |

**Returns**

- WM_SUCCESS if user data read operation is successful.
- -WM_E_INVAL if buf is not valid or of insufficient size.
- -WM_FAIL if user data field is not present or command fails.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetcaldata"></a>
### `wlan_set_cal_data`

```c
void wlan_set_cal_data (const uint8_t * *cal_data*, const unsigned int *cal_data_size*)
```

Sets the Wi-Fi calibration data in the Wi-Fi firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `cal_data` | in | The calibration data buffer. |
| `cal_data_size` | in | Size of calibration data buffer. |

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---


<a id="registeraccess"></a>
### Register Access

| Function | Supported SoCs |
|----------|---------------|
| [`wlan_reg_access`](#wlanregaccess) | RW612 |

<a id="wlanregaccess"></a>
### `wlan_reg_access`

```c
int wlan_reg_access (wifi_reg_t *type*, uint16_t *action*, uint32_t *offset*, uint32_t * *value*)
```

This function reads/writes adapter registers value.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `type` | in | Register type: 1  MAC, 2  BBP, 3  RF. |
| `action` | in | 0  read, 1  write |
| `offset` | in | Specifies the offset location that is to be read/write. |
| `value` | inout | Value if specified, stand for write action, then that value can be written to that offset in the specified register. Value should be specified in hexadecimal. Otherwise, it stands for read action, the value is updated with read value. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612

---


<a id="utilitymiscellaneous"></a>
### Utility & Miscellaneous

| Function | Supported SoCs |
|----------|---------------|
| [`is_ep_valid_security`](#isepvalidsecurity) | RW612, IW610 |
| [`is_valid_security`](#isvalidsecurity) | All |
| [`print_mac`](#printmac) | All |
| [`wlan_cfg_rf_he_tb_tx`](#wlancfgrfhetbtx) | All |
| [`wlan_event_callback`](#wlaneventcallback) | All |
| [`wlan_get_beacon_period`](#wlangetbeaconperiod) | All |
| [`wlan_get_board_type`](#wlangetboardtype) | All |
| [`wlan_get_current_wfd_network`](#wlangetcurrentwfdnetwork) | RW612 |
| [`wlan_get_current_wfd_network_ssid`](#wlangetcurrentwfdnetworkssid) | RW612 |
| [`wlan_get_diag`](#wlangetdiag) | All |
| [`wlan_get_dtim_period`](#wlangetdtimperiod) | All |
| [`wlan_get_indrst_cfg`](#wlangetindrstcfg) | IW416, IW610, IW612 |
| [`wlan_get_region_code`](#wlangetregioncode) | All |
| [`wlan_get_rf_band`](#wlangetrfband) | All |
| [`wlan_get_rf_bandwidth`](#wlangetrfbandwidth) | All |
| [`wlan_get_rf_channel`](#wlangetrfchannel) | All |
| [`wlan_get_rf_otp_cal_data`](#wlangetrfotpcaldata) | All |
| [`wlan_get_rf_otp_mac_addr`](#wlangetrfotpmacaddr) | All |
| [`wlan_get_rf_per`](#wlangetrfper) | All |
| [`wlan_get_rf_radio_mode`](#wlangetrfradiomode) | All |
| [`wlan_get_rf_rx_antenna`](#wlangetrfrxantenna) | All |
| [`wlan_get_rf_tx_antenna`](#wlangetrftxantenna) | All |
| [`wlan_get_rf_xtal`](#wlangetrfxtal) | All |
| [`wlan_get_scan_raw_frame`](#wlangetscanrawframe) | All |
| [`wlan_get_status_code`](#wlangetstatuscode) | All |
| [`wlan_get_temperature`](#wlangettemperature) | RW612 |
| [`wlan_get_tsf`](#wlangettsf) | All |
| [`wlan_get_tsf_info`](#wlangettsfinfo) | RW612, IW610 |
| [`wlan_get_turbo_mode`](#wlangetturbomode) | All |
| [`wlan_get_uap_turbo_mode`](#wlangetuapturbomode) | All |
| [`wlan_get_wlan_region_code`](#wlangetwlanregioncode) | IW416, IW610, IW612 |
| [`wlan_host_set_sta_mac_filter`](#wlanhostsetstamacfilter) | All |
| [`wlan_init_nb`](#wlaninitnb) | IW416 |
| [`wlan_is_wmm_uapsd_enabled`](#wlaniswmmuapsdenabled) | All |
| [`wlan_nb_task_cleanup`](#wlannbtaskcleanup) | IW416 |
| [`wlan_recovery_test`](#wlanrecoverytest) | RW612 |
| [`wlan_register_fw_dump_cb`](#wlanregisterfwdumpcb) | IW610, IW612 |
| [`wlan_register_uap_prov_deinit_cb`](#wlanregisteruapprovdeinitcb) | RW612 |
| [`wlan_rf_disable_11ax`](#wlanrfdisable11ax) | All |
| [`wlan_rf_trigger_frame_cfg`](#wlanrftriggerframecfg) | All |
| [`wlan_send_hostcmd`](#wlansendhostcmd) | IW416, IW610, IW612 |
| [`wlan_set_indrst_cfg`](#wlansetindrstcfg) | IW416, IW610, IW612 |
| [`wlan_set_network_ip_byname`](#wlansetnetworkipbyname) | All |
| [`wlan_set_region_code`](#wlansetregioncode) | All |
| [`wlan_set_rf_band`](#wlansetrfband) | All |
| [`wlan_set_rf_bandwidth`](#wlansetrfbandwidth) | All |
| [`wlan_set_rf_channel`](#wlansetrfchannel) | All |
| [`wlan_set_rf_otp_cal_data`](#wlansetrfotpcaldata) | All |
| [`wlan_set_rf_otp_mac_addr`](#wlansetrfotpmacaddr) | All |
| [`wlan_set_rf_radio_mode`](#wlansetrfradiomode) | All |
| [`wlan_set_rf_rx_antenna`](#wlansetrfrxantenna) | All |
| [`wlan_set_rf_rx_mac_filter`](#wlansetrfrxmacfilter) | All |
| [`wlan_set_rf_test_mode`](#wlansetrftestmode) | All |
| [`wlan_set_rf_tx_antenna`](#wlansetrftxantenna) | All |
| [`wlan_set_rf_tx_cont_mode`](#wlansetrftxcontmode) | All |
| [`wlan_set_rf_tx_frame`](#wlansetrftxframe) | All |
| [`wlan_set_rf_tx_power`](#wlansetrftxpower) | All |
| [`wlan_set_rf_xtal`](#wlansetrfxtal) | All |
| [`wlan_set_rssi_threshold`](#wlansetrssithreshold) | All |
| [`wlan_set_turbo_mode`](#wlansetturbomode) | All |
| [`wlan_set_uap_turbo_mode`](#wlansetuapturbomode) | All |
| [`wlan_stop_all_networks`](#wlanstopallnetworks) | RW612 |
| [`wlan_string_dup`](#wlanstringdup) | All |
| [`wlan_test_mode_cli_deinit`](#wlantestmodeclideinit) | All |
| [`wlan_test_mode_cli_init`](#wlantestmodecliinit) | All |
| [`wlan_unassoc_ftm_cfg`](#wlanunassocftmcfg) | IW612 |
| [`wlan_unset_rf_test_mode`](#wlanunsetrftestmode) | All |

<a id="isepvalidsecurity"></a>
### `is_ep_valid_security`

```c
int is_ep_valid_security (int *security*)
```

---

> **Supported SoCs:** RW612, IW610

---

<a id="isvalidsecurity"></a>
### `is_valid_security`

```c
int is_valid_security (int *security*)
```

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="printmac"></a>
### `print_mac`

```c
void print_mac (const char * *mac*)
```

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlancfgrfhetbtx"></a>
### `wlan_cfg_rf_he_tb_tx`

```c
int wlan_cfg_rf_he_tb_tx (uint16_t *enable*, uint16_t *qnum*, uint16_t *aid*, uint16_t *axq_mu_timer*, int16_t *tx_power*)
```

Sets the RF HE TB TX in Wi-Fi firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `enable` | in | Enable/Disable trigger response mode. |
| `qnum` | in | AXQ to be used for the trigger response frame. |
| `aid` | in | AID of the peer to which response is to be generated. |
| `axq_mu_timer` | in | MU timer for the AXQ on which response is sent. |
| `tx_power` | in | TxPwr to be configured for the response. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

> **Note**: call wlan_set_rf_test_mode API before using this API.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlaneventcallback"></a>
### `wlan_event_callback`

```c
int wlan_event_callback (enum wlan_event_reason *reason*, void * *data*)
```

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetbeaconperiod"></a>
### `wlan_get_beacon_period`

```c
uint16_t wlan_get_beacon_period (void **)
```

Use this API to get the beacon period of associated BSS from the cached state information.

**Returns**

- beacon_period if operation is successful.
- 0 if command fails.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetboardtype"></a>
### `wlan_get_board_type`

```c
uint32_t wlan_get_board_type (void **)
```

Gets the board type.

**Returns**

board type.
0x02: RW610_PACKAGE_TYPE_BGA.
0xFF: Others.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetcurrentwfdnetwork"></a>
### `wlan_get_current_wfd_network`

```c
int wlan_get_current_wfd_network (struct wlan_network * *network*)
```

Retrieves the current network configuration of the WFD interface.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `network` | out | A pointer to the wlan_network. |

**Returns**

- WM_SUCCESS if successful.
- -WM_E_INVAL if network is NULL.
- WLAN_ERROR_STATE if the Wi-Fi connection manager was not running or not in the WLAN_UAP_STARTED state.

---

> **Supported SoCs:** RW612

---

<a id="wlangetcurrentwfdnetworkssid"></a>
### `wlan_get_current_wfd_network_ssid`

```c
int wlan_get_current_wfd_network_ssid (char * *ssid*)
```

Retrieves the current network ssid of the WFD interface.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `ssid` | out | A pointer to the ssid char string with NULL termination. The maximum length is 32 (not include NULL termination). |

**Returns**

- WM_SUCCESS if successful.
- -WM_E_INVAL if ssid is NULL.
- WLAN_ERROR_STATE if the Wi-Fi connection manager was not running or not in the WLAN_UAP_STARTED state.

---

> **Supported SoCs:** RW612

---

<a id="wlangetdiag"></a>
### `wlan_get_diag`

```c
int wlan_get_diag (struct wlan_diag * *diag*)
```

Gets the Wi-Fi diagnostic statistics.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `diag` | out | Pointer to wlan_diag to store the result. |

**Returns**

- WM_SUCCESS if successful.
- -WM_E_INVAL if a NULL pointer is passed.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetdtimperiod"></a>
### `wlan_get_dtim_period`

```c
uint8_t wlan_get_dtim_period (void **)
```

Use this API to get the DTIM period of associated BSS. When this API called, the radio sends a probe request to the AP for this information.

**Returns**

- dtim_period if operation is successful.
- 0 if DTIM IE is not found in AP's Probe response.

> **Note**: This API should not be called from Wi-Fi event handler registered by application during wlan_start.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetindrstcfg"></a>
### `wlan_get_indrst_cfg`

```c
int wlan_get_indrst_cfg (wifi_indrst_cfg_t * *indrst_cfg*)
```

---

> **Supported SoCs:** IW416, IW610, IW612

---

<a id="wlangetregioncode"></a>
### `wlan_get_region_code`

```c
int wlan_get_region_code (unsigned int * *region_code*)
```

Gets region code.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `region_code` | out | pointer The value: <br>• 0x00: World Wide Safe. <br>• 0x10: US FCC / Singapore. <br>• 0x20: IC Canada. <br>• 0x30: ETSI / Australia / Republic of Korea. <br>• 0x32: France. <br>• 0x50: China. <br>• 0xFF: Japan. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetrfband"></a>
### `wlan_get_rf_band`

```c
int wlan_get_rf_band (uint8_t * *band*)
```

Gets the RF band from Wi-Fi firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `band` | out | A Pointer to a variable where RF band is to be stored. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

> **Note**: call wlan_set_rf_test_mode API before using this API.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetrfbandwidth"></a>
### `wlan_get_rf_bandwidth`

```c
int wlan_get_rf_bandwidth (uint8_t * *bandwidth*)
```

Gets the RF bandwidth from Wi-Fi firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `bandwidth` | out | A Pointer to a variable where bandwidth to get. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

> **Note**: call wlan_set_rf_test_mode API before using this API.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetrfchannel"></a>
### `wlan_get_rf_channel`

```c
int wlan_get_rf_channel (uint8_t * *channel*)
```

Gets the RF channel from Wi-Fi firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `channel` | out | A pointer to a variable where channel number to get. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

> **Note**: call wlan_set_rf_test_mode API before using this API.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetrfotpcaldata"></a>
### `wlan_get_rf_otp_cal_data`

```c
int wlan_get_rf_otp_cal_data (uint8_t * *cal_data*)
```

Gets the RF OTP calculate data from Wi-Fi firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `cal_data` | out | A pointer to a variable where OTP calculate data is to be stored. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

> **Note**: call wlan_set_rf_test_mode API before using this API.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetrfotpmacaddr"></a>
### `wlan_get_rf_otp_mac_addr`

```c
int wlan_get_rf_otp_mac_addr (uint8_t * *mac*)
```

Gets the RF OTP MAC address from Wi-Fi firmware.

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

> **Note**: call wlan_set_rf_test_mode API before using this API.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetrfper"></a>
### `wlan_get_rf_per`

```c
int wlan_get_rf_per (uint32_t * *rx_tot_pkt_count*, uint32_t * *rx_mcast_bcast_count*, uint32_t * *rx_pkt_fcs_error*)
```

Gets the RF RX total packet and multicast/broadcast packet count.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `rx_tot_pkt_count` | out | A Pointer to a variable where RX total packet count to get. |
| `rx_mcast_bcast_count` | out | A Pointer to a variable where RX total multicast/broadcast packet count to get. |
| `rx_pkt_fcs_error` | out | A Pointer to a variable where RX total packet count with FCS (frame check sequence) error to get. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

> **Note**: call wlan_set_rf_test_mode API before using this API.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetrfradiomode"></a>
### `wlan_get_rf_radio_mode`

```c
int wlan_get_rf_radio_mode (uint8_t * *mode*)
```

Gets the RF radio mode from Wi-Fi firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `mode` | out | A pointer to a variable where radio mode number to get. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

> **Note**: call wlan_set_rf_test_mode API before using this API.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetrfrxantenna"></a>
### `wlan_get_rf_rx_antenna`

```c
int wlan_get_rf_rx_antenna (uint8_t * *antenna*)
```

Gets the RF RX antenna from Wi-Fi firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `antenna` | out | A Pointer to a variable where RX antenna is to be stored. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

> **Note**: call wlan_set_rf_test_mode API before using this API.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetrftxantenna"></a>
### `wlan_get_rf_tx_antenna`

```c
int wlan_get_rf_tx_antenna (uint8_t * *antenna*)
```

Gets the RF TX antenna from Wi-Fi firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `antenna` | out | A Pointer to a variable where TX antenna is to be stored. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

> **Note**: call wlan_set_rf_test_mode API before using this API.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetrfxtal"></a>
### `wlan_get_rf_xtal`

```c
int wlan_get_rf_xtal (uint8_t * *extension*, uint8_t * *xtal_cal*)
```

Gets the RF crystal calibration from Wi-Fi firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `extension` | out | A Pointer to a variable indicate RF xtal from internal or external crystal. |
| `xtal_cal` | out | A Pointer to a variable where RF crystal calibration is to be stored. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

> **Note**: call wlan_set_rf_test_mode API before using this API.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetscanrawframe"></a>
### `wlan_get_scan_raw_frame`

```c
int wlan_get_scan_raw_frame (unsigned int *index*, uint8_t * *buf*, size_t *buf_len*, size_t * *frame_len*, uint32_t * *freq*, int8_t * *rssi*)
```

Gets a reconstructed raw 802.11 beacon frame for a scan result entry. The frame includes MAC header (24B) + fixed fields (12B) + IEs.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `index` | in | Index into scan table |
| `buf` | out | Buffer to write frame into |
| `buf_len` | in | Size of buffer |
| `frame_len` | out | Actual total frame length (may exceed buf_len) |
| `freq` | out | Frequency in MHz |
| `rssi` | out | RSSI in dBm (negative value) |

**Returns**

WM_SUCCESS on success or error code.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetstatuscode"></a>
### `wlan_get_status_code`

```c
t_u16 wlan_get_status_code (enum wlan_event_reason *reason*)
```

Gets 802.11 Status Code.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `reason` | in | wlcmgr event reason. |

**Returns**

status code defined in IEEE 802.11-2020 standard.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangettemperature"></a>
### `wlan_get_temperature`

```c
int32_t wlan_get_temperature (void **)
```

Gets the board temperature.

**Returns**

Board temperature in degrees Celsius.

---

> **Supported SoCs:** RW612

---

<a id="wlangettsf"></a>
### `wlan_get_tsf`

```c
int wlan_get_tsf (uint32_t * *tsf_high*, uint32_t * *tsf_low*)
```

Use this API to get the TSF (timing synchronization function) from Wi-Fi firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `tsf_high` | in | Pointer to store TSF higher 32bits. |
| `tsf_low` | in | Pointer to store TSF lower 32bits. |

**Returns**

- WM_SUCCESS if operation is successful.
- -WM_FAIL if command fails.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangettsfinfo"></a>
### `wlan_get_tsf_info`

```c
int wlan_get_tsf_info (wlan_tsf_info_t * *tsf_info*)
```

Gets TSF info from firmware using GPIO latch.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `tsf_info` | out | TSF info parameter received from firmware. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** RW612, IW610

---

<a id="wlangetturbomode"></a>
### `wlan_get_turbo_mode`

```c
int wlan_get_turbo_mode (t_u8 * *mode*)
```

Gets the turbo mode.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `mode` | out | turbo mode <br>• 0: Disable turbo mode. <br>• 1: Turbo mode 1. <br>• 2: Turbo mode 2. <br>• 3: Turbo mode 3. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetuapturbomode"></a>
### `wlan_get_uap_turbo_mode`

```c
int wlan_get_uap_turbo_mode (t_u8 * *mode*)
```

Gets the uAP turbo mode.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `mode` | out | turbo mode <br>• 0: Disable turbo mode. <br>• 1: Turbo mode 1. <br>• 2: Turbo mode 2. <br>• 3: Turbo mode 3. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlangetwlanregioncode"></a>
### `wlan_get_wlan_region_code`

```c
const char * wlan_get_wlan_region_code (void **)
```

Gets the Wi-Fi region code from TX power config.

**Returns**

Wi-Fi region code in string format.

---

> **Supported SoCs:** IW416, IW610, IW612

---

<a id="wlanhostsetstamacfilter"></a>
### `wlan_host_set_sta_mac_filter`

```c
int wlan_host_set_sta_mac_filter (int *filter_mode*, int *mac_count*, unsigned char * *mac_addr*)
```

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlaninitnb"></a>
### `wlan_init_nb`

```c
int wlan_init_nb (const uint8_t * *fw_start_addr*, const size_t *size*, int(*)(enum wlan_event_reason reason, void *data) *cb*)
```

Initialize Wi-Fi driver and create the Wi-Fi driver thread in non blocking mode. This API creates a new thread and performs wlan_init and wlan_start API calls internally.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `fw_start_addr` | in | Start address of the Wi-Fi firmware. |
| `size` | in | Size of the Wi-Fi firmware. |
| `cb` | in | A pointer to a callback function that handles Wi-Fi events. All. further WLCMGR events can be notified in this callback. Refer to enum wlan_event_reason for the various events for which this callback is called. |

**Returns**

- WM_SUCCESS if the Wi-Fi connection manager service has initialized successfully.
- Negative value if initialization failed.

---

> **Supported SoCs:** IW416

---

<a id="wlaniswmmuapsdenabled"></a>
### `wlan_is_wmm_uapsd_enabled`

```c
t_u8 wlan_is_wmm_uapsd_enabled (void **)
```

Checks whether UAPSD is enabled or not.

**Returns**

- true if UAPSD is enabled.
- false if UAPSD is disabled.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlannbtaskcleanup"></a>
### `wlan_nb_task_cleanup`

```c
void wlan_nb_task_cleanup (void **)
```

Wait for the task created by wlan_init_nb() to complete and destroy it. Call this from the application task after wlan_init_nb().

---

> **Supported SoCs:** IW416

---

<a id="wlanrecoverytest"></a>
### `wlan_recovery_test`

```c
int wlan_recovery_test (void **)
```

---

> **Supported SoCs:** RW612

---

<a id="wlanregisterfwdumpcb"></a>
### `wlan_register_fw_dump_cb`

```c
void wlan_register_fw_dump_cb (void(*)(void) *wlan_usb_init_cb*, int(*)() *wlan_usb_mount_cb*, int(*)(char *test_file_name) *wlan_usb_file_open_cb*, int(*)(uint8_t *data, size_t data_len) *wlan_usb_file_write_cb*, int(*)() *wlan_usb_file_close_cb*)
```

This function registers callbacks which are used to generate firmware dump on USB device.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `wlan_usb_init_cb` | in | Callback to initialize usb device. |
| `wlan_usb_mount_cb` | in | Callback to mount usb device. |
| `wlan_usb_file_open_cb` | in | Callback to open file on usb device for firmware dump. |
| `wlan_usb_file_write_cb` | in | Callback to write firmware dump data to opened file. |
| `wlan_usb_file_close_cb` | in | Callback to close firmware dump file. |

---

> **Supported SoCs:** IW610, IW612

---

<a id="wlanregisteruapprovdeinitcb"></a>
### `wlan_register_uap_prov_deinit_cb`

```c
void wlan_register_uap_prov_deinit_cb (int(*)(void) *cb*)
```

UAP provisioning deinit callback function.

---

> **Supported SoCs:** RW612

---

<a id="wlanrfdisable11ax"></a>
### `wlan_rf_disable_11ax`

```c
int wlan_rf_disable_11ax (void **)
```

Disables the RF 11AX in Wi-Fi firmware.

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

> **Note**: call wlan_set_rf_test_mode API before using this API.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanrftriggerframecfg"></a>
### `wlan_rf_trigger_frame_cfg`

```c
int wlan_rf_trigger_frame_cfg (uint32_t *Enable_tx*, uint32_t *Standalone_hetb*, uint8_t *FRAME_CTRL_TYPE*, uint8_t *FRAME_CTRL_SUBTYPE*, uint16_t *FRAME_DURATION*, uint64_t *TriggerType*, uint64_t *UlLen*, uint64_t *MoreTF*, uint64_t *CSRequired*, uint64_t *UlBw*, uint64_t *LTFType*, uint64_t *LTFMode*, uint64_t *LTFSymbol*, uint64_t *UlSTBC*, uint64_t *LdpcESS*, uint64_t *ApTxPwr*, uint64_t *PreFecPadFct*, uint64_t *PeDisambig*, uint64_t *SpatialReuse*, uint64_t *Doppler*, uint64_t *HeSig2*, uint32_t *AID12*, uint32_t *RUAllocReg*, uint32_t *RUAlloc*, uint32_t *UlCodingType*, uint32_t *UlMCS*, uint32_t *UlDCM*, uint32_t *SSAlloc*, uint8_t *UlTargetRSSI*, uint8_t *MPDU_MU_SF*, uint8_t *TID_AL*, uint8_t *AC_PL*, uint8_t *Pref_AC*)
```

Sets the RF Trigger Frame Config in Wi-Fi firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `Enable_tx` | in | Enable or Disable trigger frame transmission. |
| `Standalone_hetb` | in | Enable or Disable Standalone HE TB support. |
| `FRAME_CTRL_TYPE` | in | Frame control type. |
| `FRAME_CTRL_SUBTYPE` | in | Frame control subtype. |
| `FRAME_DURATION` | in | Max Duration time. |
| `TriggerType` | in | Identifies the Trigger frame variant and its encoding. |
| `UlLen` | in | Indicates the value of the L-SIG LENGTH field of the solicited HE TB PPDU. |
| `MoreTF` | in | Indicates whether a subsequent Trigger frame is scheduled for transmission or not. |
| `CSRequired` | in | Required to use ED to sense the medium and to consider the medium state and the NAV in. determining whether to respond or not. |
| `UlBw` | in | Indicates the bandwidth in the HE-SIG-A field of the HE TB PPDU. |
| `LTFType` | in | Indicates the LTF type of the HE TB PPDU response. |
| `LTFMode` | in | Indicates the LTF mode for an HE TB PPDU. |
| `LTFSymbol` | in | Indicates the number of LTF symbols present in the HE TB PPDU. |
| `UlSTBC` | in | Indicates the status of STBC encoding for the solicited HE TB PPDUs. |
| `LdpcESS` | in | Indicates the status of the LDPC extra symbol segment. |
| `ApTxPwr` | in | Indicates the AP's combined transmit power at the transmit antenna connector of all the antennas. used to transmit the triggering PPDU. |
| `PreFecPadFct` | in | Indicates the pre-FEC padding factor. |
| `PeDisambig` | in | Indicates PE disambiguity. |
| `SpatialReuse` | in | Carries the values to be included in the Spatial Reuse. fields in the HE-SIG-A field of the solicited HE TB PPDUs. |
| `Doppler` | in | Indicate that a midamble is present in the HE TB PPDU. |
| `HeSig2` | in | Carries the value to be included in the Reserved field in the HE-SIG-A2 subfield of. the solicited HE TB PPDUs. |
| `AID12` | in | If set to 0 allocates one or more contiguous RA-RUs for associated STAs. |
| `RUAllocReg` | in | RUAllocReg. |
| `RUAlloc` | in | Identifies the size and the location of the RU. |
| `UlCodingType` | in | Indicates the code type of the solicited HE TB PPDU. |
| `UlMCS` | in | Indicates the HE-MCS of the solicited HE TB PPDU. |
| `UlDCM` | in | Indicates DCM of the solicited HE TB PPDU. |
| `SSAlloc` | in | Indicates the spatial streams of the solicited HE TB PPDU. |
| `UlTargetRSSI` | in | Indicates the expected receive signal power. |
| `MPDU_MU_SF` | in | Used for calculating the value by which the minimum MPDU start spacing is multiplied. |
| `TID_AL` | in | Indicates the MPDUs allowed in an A-MPDU carried in the HE TB PPDU and the maximum number of TIDs. that can be aggregated by the STA in the A-MPDU. |
| `AC_PL` | in | Reserved. |
| `Pref_AC` | in | Indicates the lowest AC that is recommended for aggregation of MPDUs in the A-MPDU contained in. the HE TB PPDU sent as a response to the trigger frame. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

> **Note**: call wlan_set_rf_test_mode API before using this API.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansendhostcmd"></a>
### `wlan_send_hostcmd`

```c
int wlan_send_hostcmd (const void * *cmd_buf*, uint32_t *cmd_buf_len*, void * *host_resp_buf*, uint32_t *resp_buf_len*, uint32_t * *reqd_resp_len*)
```

This function sends the host command to firmware and copies back response to caller provided buffer in case of success response from firmware is not parsed by this function but just copied back to the caller buffer.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `cmd_buf` | in | Buffer containing the host command with header. |
| `cmd_buf_len` | in | length of valid bytes in cmd_buf. |
| `host_resp_buf` | out | Caller provided buffer, in case of success command response is copied to this. buffer can be same as cmd_buf |
| `resp_buf_len` | in | resp_buf's allocated length. |
| `reqd_resp_len` | out | length of valid bytes in response buffer if successful otherwise invalid. |

**Returns**

- WM_SUCCESS in case of success.
- WM_E_INBIG in case cmd_buf_len is bigger than the commands that can be handled by driver.
- WM_E_INSMALL in case cmd_buf_len is smaller than the minimum length. Minimum length is at least. the length of command header. see Note for same.
- WM_E_OUTBIG in case the. resp_buf_len is not sufficient to copy response from firmware. reqd_resp_len is updated with the response size.
- WM_E_INVAL in case cmd_buf_len and resp_buf_len have invalid values.
- WM_E_NOMEM in case cmd_buf, resp_buf and reqd_resp_len are NULL.

> **Note**: Brief on the command Header: Start 8 bytes of cmd_buf should have these values set. Firmware would update resp_buf with these 8 bytes at the start.

2 bytes: Command.
2 bytes: Size.
2 bytes: Sequence number.
2 bytes: Result. Rest of buffer length is Command/Response Body.

---

> **Supported SoCs:** IW416, IW610, IW612

---

<a id="wlansetindrstcfg"></a>
### `wlan_set_indrst_cfg`

```c
int wlan_set_indrst_cfg (const wifi_indrst_cfg_t * *indrst_cfg*)
```

Sets the GPIO-independent reset configuration.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `indrst_cfg` | in | GPIO independent reset configuration to be sent to firmware. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** IW416, IW610, IW612

---

<a id="wlansetnetworkipbyname"></a>
### `wlan_set_network_ip_byname`

```c
int wlan_set_network_ip_byname (char * *name*, struct wlan_ip_config * *ip*)
```

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetregioncode"></a>
### `wlan_set_region_code`

```c
int wlan_set_region_code (unsigned int *region_code*)
```

Sets region code.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `region_code` | in | region code to be set. |

**Returns**

WM_SUCCESS if successful otherwise fail.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetrfband"></a>
### `wlan_set_rf_band`

```c
int wlan_set_rf_band (const uint8_t *band*)
```

Sets the RF band in Wi-Fi firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `band` | in | The bandwidth to be set in Wi-Fi firmware. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

> **Note**: call wlan_set_rf_test_mode API before using this API.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetrfbandwidth"></a>
### `wlan_set_rf_bandwidth`

```c
int wlan_set_rf_bandwidth (const uint8_t *bandwidth*)
```

Sets the RF bandwidth in Wi-Fi firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `bandwidth` | in | The bandwidth to be set in Wi-Fi firmware. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

> **Note**: call wlan_set_rf_test_mode API before using this API.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetrfchannel"></a>
### `wlan_set_rf_channel`

```c
int wlan_set_rf_channel (const uint8_t *channel*)
```

Sets the RF channel in Wi-Fi firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `channel` | in | The channel number to be set in Wi-Fi firmware. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

> **Note**: call wlan_set_rf_test_mode API before using this API.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetrfotpcaldata"></a>
### `wlan_set_rf_otp_cal_data`

```c
int wlan_set_rf_otp_cal_data (const uint8_t * *cal_data*, uint32_t *cal_data_len*)
```

Sets the RF OTP calculate data in Wi-Fi firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `cal_data` | in | A Pointer to a variable where OTP calculate data is to be stored. |
| `cal_data_len` | in | The length of OTP calculate data. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

> **Note**: call wlan_set_rf_test_mode API before using this API.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetrfotpmacaddr"></a>
### `wlan_set_rf_otp_mac_addr`

```c
int wlan_set_rf_otp_mac_addr (uint8_t * *mac*)
```

Sets the RF OTP (one-time password) MAC address in Wi-Fi firmware.

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

> **Note**: call wlan_set_rf_test_mode API before using this API.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetrfradiomode"></a>
### `wlan_set_rf_radio_mode`

```c
int wlan_set_rf_radio_mode (const uint8_t *mode*)
```

Sets the RF radio mode in Wi-Fi firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `mode` | in | The radio mode number to be set in Wi-Fi firmware. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

> **Note**: call wlan_set_rf_test_mode API before using this API.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetrfrxantenna"></a>
### `wlan_set_rf_rx_antenna`

```c
int wlan_set_rf_rx_antenna (const uint8_t *antenna*)
```

Sets the RF RX antenna in Wi-Fi firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `antenna` | in | The RX antenna to be set in Wi-Fi firmware. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

> **Note**: call wlan_set_rf_test_mode API before using this API.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetrfrxmacfilter"></a>
### `wlan_set_rf_rx_mac_filter`

```c
int wlan_set_rf_rx_mac_filter (uint8_t * *addr*)
```

Adds RX peer mac filter.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `addr` | in | only receive packets from this mac address. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

> **Note**: call wlan_set_rf_test_mode API before using this API.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetrftestmode"></a>
### `wlan_set_rf_test_mode`

```c
int wlan_set_rf_test_mode (void **)
```

Sets the RF test mode in Wi-Fi firmware.

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetrftxantenna"></a>
### `wlan_set_rf_tx_antenna`

```c
int wlan_set_rf_tx_antenna (const uint8_t *antenna*)
```

Sets the RF TX antenna in Wi-Fi firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `antenna` | in | The TX antenna to be set in Wi-Fi firmware. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

> **Note**: call wlan_set_rf_test_mode API before using this API.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetrftxcontmode"></a>
### `wlan_set_rf_tx_cont_mode`

```c
int wlan_set_rf_tx_cont_mode (const uint32_t *enable_tx*, const uint32_t *cw_mode*, const uint32_t *payload_pattern*, const uint32_t *cs_mode*, const uint32_t *act_sub_ch*, const uint32_t *tx_rate*)
```

Sets the RF TX continuous mode in Wi-Fi firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `enable_tx` | in | Enable TX. |
| `cw_mode` | in | Set CW (continuous wave) mode. |
| `payload_pattern` | in | Set payload pattern. |
| `cs_mode` | in | Set CS mode. |
| `act_sub_ch` | in | Active subchannel. |
| `tx_rate` | in | Set TX rate. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

> **Note**: call wlan_set_rf_test_mode API before using this API.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetrftxframe"></a>
### `wlan_set_rf_tx_frame`

```c
int wlan_set_rf_tx_frame (const uint32_t *enable*, const uint32_t *data_rate*, const uint32_t *frame_pattern*, const uint32_t *frame_length*, const uint16_t *adjust_burst_sifs*, const uint32_t *burst_sifs_in_us*, const uint32_t *short_preamble*, const uint32_t *act_sub_ch*, const uint32_t *short_gi*, const uint32_t *adv_coding*, const uint32_t *tx_bf*, const uint32_t *gf_mode*, const uint32_t *stbc*, const uint8_t * *bssid*, const uint32_t *signal_bw*, const uint32_t *NumPkt*, const uint32_t *MaxPE*, const uint32_t *BeamChange*, const uint32_t *Dcm*, const uint32_t *Doppler*, const uint32_t *MidP*, const uint32_t *QNum*)
```

Sets the RF TX Frame in Wi-Fi firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `enable` | in | Enable/Disable RF TX Frame. |
| `data_rate` | in | Rate index corresponding to legacy/HT/VHT rates. |
| `frame_pattern` | in | Payload pattern. |
| `frame_length` | in | Payload length. |
| `adjust_burst_sifs` | in | Enable/Disable adjust burst SIFS3 Gap. |
| `burst_sifs_in_us` | in | Burst SIFS in us. |
| `short_preamble` | in | Enable/Disable short preamble. |
| `act_sub_ch` | in | Enable/Disable active sub channel. |
| `short_gi` | in | Short guard interval. |
| `adv_coding` | in | Enable/Disable adv coding. |
| `tx_bf` | in | Enable/Disable beamforming. |
| `gf_mode` | in | Enable/Disable green field mode. |
| `stbc` | in | Enable/Disable STBC. |
| `bssid` | in | BSSID. |
| `signal_bw` | in | Signal BW. |
| `NumPkt` | in | Number of packets. |
| `MaxPE` | in | Max pkt extension. |
| `BeamChange` | in | Beam change. |
| `Dcm` | in | DCM enable. |
| `Doppler` | in | Doppler enable. |
| `MidP` | in | Midamble periodicity. |
| `QNum` | in | Tx queue num that holds the trigger-based response pkts. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

> **Note**: call wlan_set_rf_test_mode API before using this API.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetrftxpower"></a>
### `wlan_set_rf_tx_power`

```c
int wlan_set_rf_tx_power (const uint32_t *power*, const uint8_t *mod*, const uint8_t *path_id*)
```

Sets the RF RX power in Wi-Fi firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `power` | in | The RF RX power to be set in Wi-Fi firmware. For RW610, transmit output power level control range is -10 dBm to 22 dBm as per the data sheet. |
| `mod` | in | The modulation to be set in Wi-Fi firmware. |
| `path_id` | in | The Path ID to be set in Wi-Fi firmware. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

> **Note**: call wlan_set_rf_test_mode API before using this API.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetrfxtal"></a>
### `wlan_set_rf_xtal`

```c
int wlan_set_rf_xtal (const uint8_t *xtal_cal*)
```

Sets the RF crystal calibration in Wi-Fi firmware.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `xtal_cal` | in | The crystal calibration offset to be set in Wi-Fi firmware, range [0,255]. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

> **Note**: call wlan_set_rf_test_mode API before using this API.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetrssithreshold"></a>
### `wlan_set_rssi_threshold`

```c
int wlan_set_rssi_threshold (int *rssithr*)
```

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetturbomode"></a>
### `wlan_set_turbo_mode`

```c
int wlan_set_turbo_mode (t_u8 *mode*)
```

Sets the turbo mode.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `mode` | in | turbo mode <br>• 0: Disable turbo mode. <br>• 1: Turbo mode 1. <br>• 2: Turbo mode 2. <br>• 3: Turbo mode 3. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlansetuapturbomode"></a>
### `wlan_set_uap_turbo_mode`

```c
int wlan_set_uap_turbo_mode (t_u8 *mode*)
```

Sets the uAP turbo mode.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `mode` | in | turbo mode <br>• 0: Disable turbo mode. <br>• 1: Turbo mode 1. <br>• 2: Turbo mode 2. <br>• 3: Turbo mode 3. |

**Returns**

- WM_SUCCESS if successful.
- -WM_FAIL if failed.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanstopallnetworks"></a>
### `wlan_stop_all_networks`

```c
int wlan_stop_all_networks (void **)
```

Stops all Wi-Fi network.

**Returns**

WM_SUCCESS if successful.

---

> **Supported SoCs:** RW612

---

<a id="wlanstringdup"></a>
### `wlan_string_dup`

```c
char * wlan_string_dup (const char * *s*)
```

Allocate memory for a string and copy the string to the allocated memory.

**Parameters**

| Parameter | In/Out | Description |
|-----------|--------|-------------|
| `s` | in | the source/target string. |

**Returns**

new string if successful, otherwise return -WM_FAIL.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlantestmodeclideinit"></a>
### `wlan_test_mode_cli_deinit`

```c
int wlan_test_mode_cli_deinit (void **)
```

Unregister Wi-Fi test mode CLI commands.

**Returns**

- WM_SUCCESS if the CLI commands were unregistered or.
- -WM_FAIL if they were not unregistered.

> **Note**: This function can only be called by the application after wlan_init() called.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlantestmodecliinit"></a>
### `wlan_test_mode_cli_init`

```c
int wlan_test_mode_cli_init (void **)
```

Registers Wi-Fi test mode CLI commands.

**Returns**

- WM_SUCCESS if the CLI commands were registered or.
- -WM_FAIL if they were not (for example if this function was called while the CLI commands were already registered).

> **Note**: This function can only be called by the application after wlan_init() called.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612

---

<a id="wlanunassocftmcfg"></a>
### `wlan_unassoc_ftm_cfg`

```c
int wlan_unassoc_ftm_cfg (const t_u16 *action*, const t_u16 *config*)
```

---

> **Supported SoCs:** IW612

---

<a id="wlanunsetrftestmode"></a>
### `wlan_unset_rf_test_mode`

```c
int wlan_unset_rf_test_mode (void **)
```

Unsets the RF test mode in Wi-Fi firmware.

**Returns**

WM_SUCCESS if successful.

---

> **Supported SoCs:** IW416, RW612, IW610, IW612
