# Table of Contents

# Main Page

## Introduction

NXP wireless SoCs require a combination of firmware binary image
streamed into the radio subsystem, and driver source code compiled onto
the application MCU. The radio driver source code provides APIs that
enable a developer to send and receive packets over the radio interfaces
by communicating with the firmware images that are streamed into the
radio subsystems on start-up.

### Developer Documentation

This manual provides developer reference documentation for Wi-Fi driver
and Wi-Fi Connection Manager. Refer to the source code for additional
information.

##### Note

> The File Documentation provides documentation for all the APIs that
> are available in Wi-Fi driver and connection manager.

### Abbreviations and acronyms

<table>
<tbody>
<tr class="odd">
<td>Abbreviation</td>
<td>Description</td>
</tr>
<tr class="even">
<td>ACS</td>
<td>auto channel selection</td>
</tr>
<tr class="odd">
<td>AID</td>
<td>association ID</td>
</tr>
<tr class="even">
<td>AMPDU</td>
<td>aggregate medium access control protocol data unit</td>
</tr>
<tr class="odd">
<td>AP</td>
<td>Access Point</td>
</tr>
<tr class="even">
<td>ARP</td>
<td>address resolution protocol</td>
</tr>
<tr class="odd">
<td>BSS</td>
<td>basic service set</td>
</tr>
<tr class="even">
<td>BSSID</td>
<td>basic servivce set ID</td>
</tr>
<tr class="odd">
<td>BTM</td>
<td>BSS transition management</td>
</tr>
<tr class="even">
<td>CA</td>
<td>Certificate Authority</td>
</tr>
<tr class="odd">
<td>CCK</td>
<td>complementary code keying</td>
</tr>
<tr class="even">
<td>CLI</td>
<td>command line input</td>
</tr>
<tr class="odd">
<td>CSI</td>
<td>channel state information</td>
</tr>
<tr class="even">
<td>CW</td>
<td>continuous wave</td>
</tr>
<tr class="odd">
<td>DH</td>
<td>Diffie Hellman</td>
</tr>
<tr class="even">
<td>DPP</td>
<td>device provisioning protocol</td>
</tr>
<tr class="odd">
<td>DTIM</td>
<td>delivery traffic indication map</td>
</tr>
<tr class="even">
<td>EAP</td>
<td>Extensible Authentication Protocol</td>
</tr>
<tr class="odd">
<td>EAP TLS</td>
<td>Extensible Authentication Protocol Transport Layer Security</td>
</tr>
<tr class="even">
<td>FCS</td>
<td>frame check sequence</td>
</tr>
<tr class="odd">
<td>FTM</td>
<td>fine timing measurement</td>
</tr>
<tr class="even">
<td>GI</td>
<td>guard interval</td>
</tr>
<tr class="odd">
<td>HE</td>
<td>802.11ax high efficiency</td>
</tr>
<tr class="even">
<td>HT</td>
<td>802.11n high throughput</td>
</tr>
<tr class="odd">
<td>HTC</td>
<td>high throughput control</td>
</tr>
<tr class="even">
<td>LDPC</td>
<td>low density parity check</td>
</tr>
<tr class="odd">
<td>MBO</td>
<td>multi band operation</td>
</tr>
<tr class="even">
<td>MEF</td>
<td>memory efficient filtering</td>
</tr>
<tr class="odd">
<td>MFPC</td>
<td>Management Frame Protection Capable</td>
</tr>
<tr class="even">
<td>MFPR</td>
<td>Management frame protection required</td>
</tr>
<tr class="odd">
<td>NSS</td>
<td>N*N MIMO spatial stream</td>
</tr>
<tr class="even">
<td>OBSS</td>
<td>overlapping basic service set</td>
</tr>
<tr class="odd">
<td>OCE</td>
<td>Optimized connectivity experience</td>
</tr>
<tr class="even">
<td>OMI</td>
<td>operating mode indication</td>
</tr>
<tr class="odd">
<td>OWE</td>
<td>opportunistic wireless encryption</td>
</tr>
<tr class="even">
<td>PBC</td>
<td>push button configuration</td>
</tr>
<tr class="odd">
<td>PEAP</td>
<td>Protected Extensible Authentication Protocol</td>
</tr>
<tr class="even">
<td>PKEX</td>
<td>Public Key Exchange</td>
</tr>
<tr class="odd">
<td>PMF</td>
<td>protected management frame</td>
</tr>
<tr class="even">
<td>PMK</td>
<td>pairwise master key</td>
</tr>
<tr class="odd">
<td>PMKSA</td>
<td>pairwise master key security association</td>
</tr>
<tr class="even">
<td>PS</td>
<td>power save</td>
</tr>
<tr class="odd">
<td>PTA</td>
<td>packet traffic arbitration</td>
</tr>
<tr class="even">
<td>PWE</td>
<td>Password Element</td>
</tr>
<tr class="odd">
<td>QoS</td>
<td>quality of service</td>
</tr>
<tr class="even">
<td>RSSI</td>
<td>received signal strength indicator</td>
</tr>
<tr class="odd">
<td>RTS</td>
<td>request to send</td>
</tr>
<tr class="even">
<td>SAD</td>
<td>software antenna diversity</td>
</tr>
<tr class="odd">
<td>SAE</td>
<td>Simultaneous Authentication of Equals</td>
</tr>
<tr class="even">
<td>SSID</td>
<td>service set ID</td>
</tr>
<tr class="odd">
<td>STBC</td>
<td>space time block code</td>
</tr>
<tr class="even">
<td>TBTT</td>
<td>target beacon transmission time</td>
</tr>
<tr class="odd">
<td>TIM</td>
<td>Traffic Indication Map</td>
</tr>
<tr class="even">
<td>TRPC</td>
<td>transient receptor potential canonical</td>
</tr>
<tr class="odd">
<td>TSF</td>
<td>timing synchronization function</td>
</tr>
<tr class="even">
<td>TSP</td>
<td>thermal safeguard protection</td>
</tr>
<tr class="odd">
<td>TWT</td>
<td>target wake time</td>
</tr>
<tr class="even">
<td>UAPSD</td>
<td>unscheduled automatic power save delivery</td>
</tr>
<tr class="odd">
<td>VHT</td>
<td>802.11ac very high throughput</td>
</tr>
<tr class="even">
<td>WLCMGR</td>
<td>Wi-Fi command manager</td>
</tr>
</tbody>
</table>

# Data Structure Index

## Data Structures

Here are the data structures with brief descriptions:

**ipv4\_config**

**ipv6\_config**

**rx\_pkt\_he\_rate\_info**

**rx\_pkt\_ht\_rate\_info**

**rx\_pkt\_rate\_info**

**rx\_pkt\_vht\_rate\_info**

**tx\_ampdu\_prot\_mode\_para**

**tx\_pkt\_he\_rate\_info**

**tx\_pkt\_ht\_rate\_info**

**tx\_pkt\_rate\_info**

**tx\_pkt\_vht\_rate\_info**

**wifi\_scan\_params\_t**

**wlan\_cipher**

**wlan\_ieeeps\_config**

**wlan\_ip\_config**

**wlan\_network**

**wlan\_network\_security**

**wlan\_scan\_result**

# File Index

## File List

Here is a list of all documented files with brief descriptions:

**wlan.h (This file provides Wi-Fi APIs for the application )**

# Data Structure Documentation

## ipv4\_config Struct Reference

### Data Fields

enum address\_types addr\_type

unsigned address

unsigned gw

unsigned netmask

unsigned dns1

unsigned dns2

### Detailed Description

This data structure represents an IPv4 address

### Field Documentation

#### enum address\_types ipv4\_config::addr\_type

> Set to ADDR\_TYPE\_DHCP to use DHCP to obtain the IP address or set to
> ADDR\_TYPE\_STATIC to use a static IP. In case of static IP address
> ip, gw, netmask and dns members should be specified. When using DHCP,
> the ip, gw, netmask and dns are overwritten by the values obtained
> from the DHCP server. They should be zeroed out if not used.

#### unsigned ipv4\_config::address

> The system's IP address in network order.

#### unsigned ipv4\_config::gw

> The system's default gateway in network order.

#### unsigned ipv4\_config::netmask

> The system's subnet mask in network order.

#### unsigned ipv4\_config::dns1

> The system's primary dns server in network order.

#### unsigned ipv4\_config::dns2

> The system's secondary dns server in network order.

#### The documentation for this struct was generated from the following file:

wlan.h

#### 

## ipv6\_config Struct Reference

### Data Fields

unsigned address \[4\]

unsigned char addr\_type

unsigned char addr\_state

### Detailed Description

This data structure represents an IPv6 address

### Field Documentation

#### unsigned ipv6\_config::address\[4\]

> The system's IPv6 address in network order.

#### unsigned char ipv6\_config::addr\_type

> The address type: linklocal, site-local or global.

#### unsigned char ipv6\_config::addr\_state

> The state of IPv6 address (Tentative, Preferred, etc.).

#### The documentation for this struct was generated from the following file:

wlan.h

#### 

## rx\_pkt\_he\_rate\_info Struct Reference

### Data Fields

t\_u32 hemcs\_rxcnt \[12\]

t\_u32 hestbcrate\_rxcnt \[12\]

### Detailed Description

Sum of RX packets for HE (802.11ax high efficiency) rate.

### Field Documentation

#### t\_u32 rx\_pkt\_he\_rate\_info::hemcs\_rxcnt\[12\]

> Sum of RX packets for HE rate. The array index represents MSC0\~MCS11,
> the following array indexes have the same effect.

#### t\_u32 rx\_pkt\_he\_rate\_info::hestbcrate\_rxcnt\[12\]

> Sum of RX STBC (space time block code) packets for HE rate.

#### The documentation for this struct was generated from the following file:

wlan.h

#### 

## rx\_pkt\_ht\_rate\_info Struct Reference

### Data Fields

t\_u32 htmcs\_rxcnt \[16\]

t\_u32 htsgi\_rxcnt \[16\]

t\_u32 htstbcrate\_rxcnt \[16\]

### Detailed Description

Sum of RX packets for HT (802.11n high throughput) rate.

### Field Documentation

#### t\_u32 rx\_pkt\_ht\_rate\_info::htmcs\_rxcnt\[16\]

> Sum of RX packets for HT rate. The array index represents MSC0\~MCS15,
> the following array indexes have the same effect.

#### t\_u32 rx\_pkt\_ht\_rate\_info::htsgi\_rxcnt\[16\]

> Sum of TX short GI (guard interval) packets for HT rate.

#### t\_u32 rx\_pkt\_ht\_rate\_info::htstbcrate\_rxcnt\[16\]

> Sum of TX STBC (space time block code) packets for HT rate.

#### The documentation for this struct was generated from the following file:

wlan.h

#### 

## rx\_pkt\_rate\_info Struct Reference

### Data Fields

t\_u32 nss\_rxcnt \[2\]

t\_u32 nsts\_rxcnt

t\_u32 bandwidth\_rxcnt \[3\]

t\_u32 preamble\_rxcnt \[6\]

t\_u32 ldpc\_txbfcnt \[2\]

t\_s32 rssi\_value \[2\]

t\_s32 rssi\_chain0 \[4\]

t\_s32 rssi\_chain1 \[4\]

### Detailed Description

Sum of RX packets.

### Field Documentation

#### t\_u32 rx\_pkt\_rate\_info::nss\_rxcnt\[2\]

> Sum of RX NSS (N\*N MIMO spatial stream) packets. nss\_txcnt\[0\] is
> for NSS 1, nss\_txcnt\[1\] is for NSS 2.

#### t\_u32 rx\_pkt\_rate\_info::nsts\_rxcnt

> Sum of received packets for all STBC rates.

#### t\_u32 rx\_pkt\_rate\_info::bandwidth\_rxcnt\[3\]

> Sum of received packets for three bandwidth types.
> bandwidth\_rxcnt\[0\] is for 20MHz, bandwidth\_rxcnt\[1\] is for
> 40MHz, bandwidth\_rxcnt\[2\] is for 80MHz.

#### t\_u32 rx\_pkt\_rate\_info::preamble\_rxcnt\[6\]

> Sum of received packets for four preamble format types.
> preamble\_txcnt\[0\] is for preamble format 0, preamble\_txcnt\[1\] is
> for preamble format 1, preamble\_txcnt\[2\] is for preamble format 2,
> preamble\_txcnt\[3\] is for preamble format 3, preamble\_txcnt\[4\]
> and preamble\_txcnt\[5\] are as reserved.

#### t\_u32 rx\_pkt\_rate\_info::ldpc\_txbfcnt\[2\]

> Sum of packets for TX LDPC packets.

#### t\_s32 rx\_pkt\_rate\_info::rssi\_value\[2\]

> Average RSSI

#### t\_s32 rx\_pkt\_rate\_info::rssi\_chain0\[4\]

> RSSI value of path A

#### t\_s32 rx\_pkt\_rate\_info::rssi\_chain1\[4\]

> RSSI value of path B

#### The documentation for this struct was generated from the following file:

wlan.h

#### 

## rx\_pkt\_vht\_rate\_info Struct Reference

### Data Fields

t\_u32 vhtmcs\_rxcnt \[10\]

t\_u32 vhtsgi\_rxcnt \[10\]

t\_u32 vhtstbcrate\_rxcnt \[10\]

### Detailed Description

Sum of RX packets for VHT (802.11ac very high throughput) rate.

### Field Documentation

#### t\_u32 rx\_pkt\_vht\_rate\_info::vhtmcs\_rxcnt\[10\]

> Sum of RX packets for VHT rate. The array index represents MSC0\~MCS9,
> the following array indexes have the same effect.

#### t\_u32 rx\_pkt\_vht\_rate\_info::vhtsgi\_rxcnt\[10\]

> Sum of RX short GI (guard interval) packets for VHT rate.

#### t\_u32 rx\_pkt\_vht\_rate\_info::vhtstbcrate\_rxcnt\[10\]

> Sum of RX STBC (space time block code) packets for VHT rate.

#### The documentation for this struct was generated from the following file:

wlan.h

#### 

## tx\_ampdu\_prot\_mode\_para Struct Reference

### Data Fields

int mode

### Detailed Description

Set protection mode for the transmit AMPDU packet

### Field Documentation

#### int tx\_ampdu\_prot\_mode\_para::mode

> mode, 0: set RTS/CTS mode, 1: set CTS to self mode, 2: disable
> protection mode, 3: set dynamic RTS/CTS mode.

#### The documentation for this struct was generated from the following file:

wlan.h

#### 

## tx\_pkt\_he\_rate\_info Struct Reference

### Data Fields

t\_u32 hemcs\_txcnt \[12\]

t\_u32 hestbcrate\_txcnt \[12\]

### Detailed Description

Sum of TX packets for HE (802.11ax high efficiency) rate.

### Field Documentation

#### t\_u32 tx\_pkt\_he\_rate\_info::hemcs\_txcnt\[12\]

> Sum of TX packets for HE rate. The array index represents MSC0\~MCS11,
> the following array indexes have the same effect.

#### t\_u32 tx\_pkt\_he\_rate\_info::hestbcrate\_txcnt\[12\]

> Sum of TX STBC (space time block code) packets for HE rate.

#### The documentation for this struct was generated from the following file:

wlan.h

#### 

## tx\_pkt\_ht\_rate\_info Struct Reference

### Data Fields

t\_u32 htmcs\_txcnt \[16\]

t\_u32 htsgi\_txcnt \[16\]

t\_u32 htstbcrate\_txcnt \[16\]

### Detailed Description

Sum of TX packets for HT (802.11n high throughput) rate.

### Field Documentation

#### t\_u32 tx\_pkt\_ht\_rate\_info::htmcs\_txcnt\[16\]

> Sum of TX packets for HT rate. The array index represents MSC0\~MCS15,
> the following array indexes have the same effect.

#### t\_u32 tx\_pkt\_ht\_rate\_info::htsgi\_txcnt\[16\]

> Sum of TX short GI (guard interval) packets for HT rate.

#### t\_u32 tx\_pkt\_ht\_rate\_info::htstbcrate\_txcnt\[16\]

> Sum of TX STBC (space time block code) packets for HT rate.

#### The documentation for this struct was generated from the following file:

wlan.h

#### 

## tx\_pkt\_rate\_info Struct Reference

### Data Fields

t\_u32 nss\_txcnt \[2\]

t\_u32 bandwidth\_txcnt \[3\]

t\_u32 preamble\_txcnt \[4\]

t\_u32 ldpc\_txcnt

t\_u32 rts\_txcnt

t\_s32 ack\_RSSI

### Detailed Description

Sum of TX packets.

### Field Documentation

#### t\_u32 tx\_pkt\_rate\_info::nss\_txcnt\[2\]

> Sum of TX NSS (N\*N MIMO spatial stream) packets. nss\_txcnt\[0\] is
> for NSS 1, nss\_txcnt\[1\] is for NSS 2.

#### t\_u32 tx\_pkt\_rate\_info::bandwidth\_txcnt\[3\]

> Sum of TX packets for three bandwidths. bandwidth\_txcnt\[0\] is for
> 20MHz, bandwidth\_txcnt\[1\] is for 40MHz, bandwidth\_txcnt\[2\] is
> for 80MHz.

#### t\_u32 tx\_pkt\_rate\_info::preamble\_txcnt\[4\]

> Sum of RX packets for four preamble format types. preamble\_txcnt\[0\]
> is for preamble format 0, preamble\_txcnt\[1\] is for preamble format
> 1, preamble\_txcnt\[2\] is for preamble format 2, preamble\_txcnt\[3\]
> is for preamble format 3,

#### t\_u32 tx\_pkt\_rate\_info::ldpc\_txcnt

> Sum of TX LDPC (low density parity check) packets.

#### t\_u32 tx\_pkt\_rate\_info::rts\_txcnt

> Sum of TX RTS (request to send) packets

#### t\_s32 tx\_pkt\_rate\_info::ack\_RSSI

> RSSI of ACK packet

#### The documentation for this struct was generated from the following file:

wlan.h

#### 

## tx\_pkt\_vht\_rate\_info Struct Reference

### Data Fields

t\_u32 vhtmcs\_txcnt \[10\]

t\_u32 vhtsgi\_txcnt \[10\]

t\_u32 vhtstbcrate\_txcnt \[10\]

### Detailed Description

Sum of TX packets for VHT (802.11ac very high throughput) rate.

### Field Documentation

#### t\_u32 tx\_pkt\_vht\_rate\_info::vhtmcs\_txcnt\[10\]

> Sum of TX packets for VHT rate. The array index represents MSC0\~MCS9,
> the following array indexes have the same effect.

#### t\_u32 tx\_pkt\_vht\_rate\_info::vhtsgi\_txcnt\[10\]

> Sum of TX short GI packets for HT mode.

#### t\_u32 tx\_pkt\_vht\_rate\_info::vhtstbcrate\_txcnt\[10\]

> Sum of TX STBC (space time block code) packets for VHT mode.

#### The documentation for this struct was generated from the following file:

wlan.h

#### 

## wifi\_scan\_params\_t Struct Reference

### Data Fields

uint8\_t \* bssid

char \* ssid

int channel \[MAX\_CHANNEL\_LIST\]

IEEEtypes\_Bss\_t bss\_type

int scan\_duration

int split\_scan\_delay

### Detailed Description

This structure is used to configure Wi-Fi scan parameters

### Field Documentation

#### uint8\_t\* wifi\_scan\_params\_t::bssid

> BSSID (basic service set ID)

#### char\* wifi\_scan\_params\_t::ssid

> SSID (service set ID)

#### int wifi\_scan\_params\_t::channel\[MAX\_CHANNEL\_LIST\]

> Channel list

#### IEEEtypes\_Bss\_t wifi\_scan\_params\_t::bss\_type

> BSS (basic service set) type. 1: Infrastructure BSS, 2: Indenpent BSS.

#### int wifi\_scan\_params\_t::scan\_duration

> Time for scan duration

#### int wifi\_scan\_params\_t::split\_scan\_delay

> split scan delay

#### The documentation for this struct was generated from the following file:

wlan.h

#### 

## wlan\_cipher Struct Reference

### Data Fields

uint16\_t none: 1

uint16\_t wep40: 1

uint16\_t wep104: 1

uint16\_t tkip: 1

uint16\_t ccmp: 1

uint16\_t aes\_128\_cmac: 1

uint16\_t gcmp: 1

uint16\_t sms4: 1

uint16\_t gcmp\_256: 1

uint16\_t ccmp\_256: 1

uint16\_t rsvd: 1

uint16\_t bip\_gmac\_128: 1

uint16\_t bip\_gmac\_256: 1

uint16\_t bip\_cmac\_256: 1

uint16\_t gtk\_not\_used: 1

uint16\_t rsvd2: 2

### Detailed Description

Wi-Fi cipher structure

### Field Documentation

#### uint16\_t wlan\_cipher::none

> 1 bit value can be set for none

#### uint16\_t wlan\_cipher::wep40

> 1 bit value can be set for wep40

#### uint16\_t wlan\_cipher::wep104

> 1 bit value can be set for wep104

#### uint16\_t wlan\_cipher::tkip

> 1 bit value can be set for tkip

#### uint16\_t wlan\_cipher::ccmp

> 1 bit value can be set for ccmp

#### uint16\_t wlan\_cipher::aes\_128\_cmac

> 1 bit value can be set for aes 128 cmac

#### uint16\_t wlan\_cipher::gcmp

> 1 bit value can be set for gcmp

#### uint16\_t wlan\_cipher::sms4

> 1 bit value can be set for sms4

#### uint16\_t wlan\_cipher::gcmp\_256

> 1 bit value can be set for gcmp 256

#### uint16\_t wlan\_cipher::ccmp\_256

> 1 bit value can be set for ccmp 256

#### uint16\_t wlan\_cipher::rsvd

> 1 bit is reserved

#### uint16\_t wlan\_cipher::bip\_gmac\_128

> 1 bit value can be set for bip gmac 128

#### uint16\_t wlan\_cipher::bip\_gmac\_256

> 1 bit value can be set for bip gmac 256

#### uint16\_t wlan\_cipher::bip\_cmac\_256

> 1 bit value can be set for bip cmac 256

#### uint16\_t wlan\_cipher::gtk\_not\_used

> 1 bit value can be set for gtk not used

#### uint16\_t wlan\_cipher::rsvd2

> 4 bits are reserved

#### The documentation for this struct was generated from the following file:

wlan.h

#### 

## wlan\_ieeeps\_config Struct Reference

### Data Fields

t\_u32 ps\_null\_interval

t\_u32 multiple\_dtim\_interval

t\_u32 listen\_interval

t\_u32 adhoc\_awake\_period

t\_u32 bcn\_miss\_timeout

t\_s32 delay\_to\_ps

t\_u32 ps\_mode

### Detailed Description

This structure is for IEEE PS (power save) configuration

### Field Documentation

#### t\_u32 wlan\_ieeeps\_config::ps\_null\_interval

> The interval that STA sends null packet

#### t\_u32 wlan\_ieeeps\_config::multiple\_dtim\_interval

> The count of listen interval

#### t\_u32 wlan\_ieeeps\_config::listen\_interval

> Periodic interval that STA listens to AP beacons

#### t\_u32 wlan\_ieeeps\_config::adhoc\_awake\_period

> Periodic awake period for adhoc networks

#### t\_u32 wlan\_ieeeps\_config::bcn\_miss\_timeout

> Beacon miss timeout in milliseconds

#### t\_s32 wlan\_ieeeps\_config::delay\_to\_ps

> The delay of enabling IEEE-PS in milliseconds

#### t\_u32 wlan\_ieeeps\_config::ps\_mode

> PS mode, 1: PS-auto mode, 2: PS-poll mode, 3: PS-null mode.

#### The documentation for this struct was generated from the following file:

wlan.h

#### 

## wlan\_ip\_config Struct Reference

### Data Fields

struct ipv6\_config ipv6 \[CONFIG\_MAX\_IPV6\_ADDRESSES\]

size\_t ipv6\_count

struct ipv4\_config ipv4

### Detailed Description

Network IP configuration.

This data structure represents the network IP configuration for IPv4 as
well as IPv6 addresses

### Field Documentation

#### struct ipv6\_config wlan\_ip\_config::ipv6\[CONFIG\_MAX\_IPV6\_ADDRESSES\]

> The network IPv6 address configuration that should be associated with
> this interface.

#### size\_t wlan\_ip\_config::ipv6\_count

> The network IPv6 valid addresses count

#### struct ipv4\_config wlan\_ip\_config::ipv4

> The network IPv4 address configuration that should be associated with
> this interface.

#### The documentation for this struct was generated from the following file:

wlan.h

#### 

## wlan\_network Struct Reference

### Data Fields

int id

int wps\_network

char name \[WLAN\_NETWORK\_NAME\_MAX\_LENGTH+1\]

char ssid \[IEEEtypes\_SSID\_SIZE+1\]

char bssid \[IEEEtypes\_ADDRESS\_SIZE\]

unsigned int channel

uint8\_t sec\_channel\_offset

uint16\_t acs\_band

int rssi

short rssi\_threshold

unsigned short ht\_capab

unsigned int vht\_capab

unsigned char vht\_oper\_chwidth

unsigned char he\_oper\_chwidth

enum wlan\_bss\_type type

enum wlan\_bss\_role role

struct wlan\_network\_security security

struct wlan\_ip\_config ip

unsigned ssid\_specific: 1

unsigned trans\_ssid\_specific: 1

unsigned bssid\_specific: 1

unsigned channel\_specific: 1

unsigned security\_specific: 1

unsigned dot11n: 1

unsigned dot11ac: 1

unsigned dot11ax: 1

uint16\_t mdid

unsigned ft\_1x: 1

unsigned ft\_psk: 1

unsigned ft\_sae: 1

unsigned int owe\_trans\_mode

char trans\_ssid \[IEEEtypes\_SSID\_SIZE+1\]

unsigned int trans\_ssid\_len

uint16\_t beacon\_period

uint8\_t dtim\_period

uint8\_t wlan\_capa

uint8\_t btm\_mode

bool bss\_transition\_supported

bool neighbor\_report\_supported

### Detailed Description

Wi-Fi network profile

This data structure represents a Wi-Fi network profile. It consists of
an arbitrary name, Wi-Fi configuration, and IP address configuration.

Every network profile is associated with one of the two interfaces. The
network profile can be used for the station interface (i.e. to connect
to an Access Point) by setting the role field to WLAN\_BSS\_ROLE\_STA.
The network profile can be used for the uAP interface (i.e. to start a
network of our own.) by setting the mode field to WLAN\_BSS\_ROLE\_UAP.

If the mode field is WLAN\_BSS\_ROLE\_STA, either of the SSID or BSSID
fields are used to identify the network, while the other members like
channel and security settings characterize the network.

If the mode field is WLAN\_BSS\_ROLE\_UAP, the SSID, channel and
security fields are used to define the network to be started.

In both the above cases, the address field is used to determine the type
of address assignment to be used for this interface.

### Field Documentation

#### int wlan\_network::id

> Identifier for network profile

#### int wlan\_network::wps\_network

> WPS network flag.

#### char wlan\_network::name\[WLAN\_NETWORK\_NAME\_MAX\_LENGTH+1\]

> The name of this network profile. Each network profile that is added
> to the Wi-Fi connection manager should have a unique name.

#### char wlan\_network::ssid\[IEEEtypes\_SSID\_SIZE+1\]

> The network SSID, represented as a C string of up to 32 characters in
> length. If this profile is used in the uAP mode, this field is used as
> the SSID of the network. If this profile is used in the station mode,
> this field is used to identify the network. Set the first byte of the
> SSID to NULL (a 0-length string) to use only the BSSID to find the
> network.

#### char wlan\_network::bssid\[IEEEtypes\_ADDRESS\_SIZE\]

> The network BSSID, represented as a 6-byte array. If this profile is
> used in the uAP mode, this field is ignored. If this profile is used
> in the station mode, this field is used to identify the network. Set
> all 6 bytes to 0 to use any BSSID, in which case only the SSID is used
> to find the network.

#### unsigned int wlan\_network::channel

> The channel for this network.
> 
> If this profile is used in uAP mode, this field specifies the channel
> to start the uAP interface on. Set this to 0 for auto channel
> selection.
> 
> If this profile is used in the station mode, this constrains the
> channel on which the network to connect should be present. Set this to
> 0 to allow the network to be found on any channel.

#### uint8\_t wlan\_network::sec\_channel\_offset

> The secondary channel offset

#### uint16\_t wlan\_network::acs\_band

> The ACS (auto channel selection) band if set channel to 0.

#### int wlan\_network::rssi

> RSSI (received signal strength indicator) value.

#### short wlan\_network::rssi\_threshold

> Specify RSSI threshold (dBm) for scan

#### unsigned short wlan\_network::ht\_capab

> HT capabilities info field within HT capabilities information element

#### unsigned int wlan\_network::vht\_capab

> VHT capabilities info field within VHT capabilities information
> element

#### unsigned char wlan\_network::vht\_oper\_chwidth

> VHT bandwidth

#### unsigned char wlan\_network::he\_oper\_chwidth

> HE bandwidth

#### enum wlan\_bss\_type wlan\_network::type

> BSS type

#### enum wlan\_bss\_role wlan\_network::role

> The network Wi-Fi mode enum wlan\_bss\_role. Set this to specify what
> type of Wi-Fi network mode to use. This can either be
> WLAN\_BSS\_ROLE\_STA for use in the station mode, or it can be
> WLAN\_BSS\_ROLE\_UAP for use in the uAP mode.

#### struct wlan\_network\_security wlan\_network::security

> The network security configuration specified by struct
> wlan\_network\_security for the network.

#### struct wlan\_ip\_config wlan\_network::ip

> The network IP address configuration specified by struct
> wlan\_ip\_config that should be associated with this interface.

#### unsigned wlan\_network::ssid\_specific

> If set to 1, the ssid field contains the specific SSID for this
> network. the Wi-Fi connection manager can only connect to networks
> with matching SSID matches. If set to 0, the ssid field contents are
> not used when deciding whether to connect to a network or not. The
> BSSID field is used instead and any network with matching BSSID
> matches is accepted.
> 
> This field can be set to 1 if the network is added with the SSID
> specified (not an empty string), otherwise it is set to 0.

#### unsigned wlan\_network::trans\_ssid\_specific

> If set to 1, the ssid field contains the transitional SSID for this
> network.

#### unsigned wlan\_network::bssid\_specific

> If set to 1, the bssid field contains the specific BSSID for this
> network. The Wi-Fi connection manager cannot connect to any other
> network with the same SSID unless the BSSID matches. If set to 0, the
> Wi-Fi connection manager can connect to any network whose SSID
> matches.
> 
> This field set to 1 if the network is added with the BSSID specified
> (not set to all zeroes), otherwise it is set to 0.

#### unsigned wlan\_network::channel\_specific

> If set to 1, the channel field contains the specific channel for this
> network. The Wi-Fi connection manager cannot look for this network on
> any other channel. If set to 0, the Wi-Fi connection manager can look
> for this network on any available channel.
> 
> This field is set to 1 if the network is added with the channel
> specified (not set to 0), otherwise it is set to 0.

#### unsigned wlan\_network::security\_specific

> If set to 0, any security that matches is used. This field is
> internally set when the security type parameter above is set to
> WLAN\_SECURITY\_WILDCARD.

#### unsigned wlan\_network::dot11n

> The network supports 802.11N.

#### unsigned wlan\_network::dot11ac

> The network supports 802.11AC.

#### unsigned wlan\_network::dot11ax

> The network supports 802.11AX.

#### uint16\_t wlan\_network::mdid

> Mobility Domain ID

#### unsigned wlan\_network::ft\_1x

> The network uses FT 802.1x security

#### unsigned wlan\_network::ft\_psk

> The network uses FT PSK security

#### unsigned wlan\_network::ft\_sae

> The network uses FT SAE security

#### unsigned int wlan\_network::owe\_trans\_mode

> OWE (opportunistic wireless encryption) Transition mode

#### char wlan\_network::trans\_ssid\[IEEEtypes\_SSID\_SIZE+1\]

> The network transitional SSID, represented as a C string of up to 32
> characters in length.

#### unsigned int wlan\_network::trans\_ssid\_len

> Transitional SSID length

#### uint16\_t wlan\_network::beacon\_period

> Beacon period of associated BSS

#### uint8\_t wlan\_network::dtim\_period

> DTIM period of associated BSS

#### uint8\_t wlan\_network::wlan\_capa

> Wi-Fi capabilities of the uAP network 802.11n, 802.11ac or/and
> 802.11ax

#### uint8\_t wlan\_network::btm\_mode

> BTM mode

#### bool wlan\_network::bss\_transition\_supported

> BSS transition support

#### bool wlan\_network::neighbor\_report\_supported

> Neighbor report support

#### The documentation for this struct was generated from the following file:

wlan.h

#### 

## wlan\_network\_security Struct Reference

### Data Fields

enum wlan\_security\_type type

int key\_mgmt

struct wlan\_cipher mcstCipher

struct wlan\_cipher ucstCipher

unsigned pkc: 1

int group\_cipher

int pairwise\_cipher

int group\_mgmt\_cipher

bool is\_pmf\_required

char psk \[WLAN\_PSK\_MAX\_LENGTH\]

uint8\_t psk\_len

char password \[WLAN\_PASSWORD\_MAX\_LENGTH+1\]

size\_t password\_len

char \* sae\_groups

uint8\_t pwe\_derivation

uint8\_t transition\_disable

char \* owe\_groups

char pmk \[WLAN\_PMK\_LENGTH\]

bool pmk\_valid

int8\_t mfpc

int8\_t mfpr

unsigned wpa3\_sb: 1

unsigned wpa3\_sb\_192: 1

unsigned eap\_ver: 1

unsigned peap\_label: 1

uint8\_t eap\_crypto\_binding

unsigned eap\_result\_ind: 1

unsigned char tls\_cipher

char identity \[IDENTITY\_MAX\_LENGTH\]

char anonymous\_identity \[IDENTITY\_MAX\_LENGTH\]

char eap\_password \[PASSWORD\_MAX\_LENGTH\]

bool verify\_peer

unsigned char \* ca\_cert\_data

size\_t ca\_cert\_len

unsigned char \* client\_cert\_data

size\_t client\_cert\_len

unsigned char \* client\_key\_data

size\_t client\_key\_len

char client\_key\_passwd \[PASSWORD\_MAX\_LENGTH\]

char ca\_cert\_hash \[HASH\_MAX\_LENGTH\]

char domain\_match \[DOMAIN\_MATCH\_MAX\_LENGTH\]

char domain\_suffix\_match \[DOMAIN\_MATCH\_MAX\_LENGTH\]

unsigned char \* ca\_cert2\_data

size\_t ca\_cert2\_len

unsigned char \* client\_cert2\_data

size\_t client\_cert2\_len

unsigned char \* client\_key2\_data

size\_t client\_key2\_len

char client\_key2\_passwd \[PASSWORD\_MAX\_LENGTH\]

unsigned char \* **dpp\_connector**

unsigned char \* **dpp\_c\_sign\_key**

unsigned char \* **dpp\_net\_access\_key**

### Detailed Description

Network security configuration

### Field Documentation

#### enum wlan\_security\_type wlan\_network\_security::type

> Type of network security to use. Specified by enum
> wlan\_security\_type.

#### int wlan\_network\_security::key\_mgmt

> Key management type

#### struct wlan\_cipher wlan\_network\_security::mcstCipher

> Type of network security Group Cipher suite

#### struct wlan\_cipher wlan\_network\_security::ucstCipher

> Type of network security Pairwise Cipher suite

#### unsigned wlan\_network\_security::pkc

> Proactive key caching

#### int wlan\_network\_security::group\_cipher

> Type of network security Group Cipher suite

#### int wlan\_network\_security::pairwise\_cipher

> Type of network security Pairwise Cipher suite

#### int wlan\_network\_security::group\_mgmt\_cipher

> Type of network security Pairwise Cipher suite

#### bool wlan\_network\_security::is\_pmf\_required

> Is PMF (protected management frame) required

#### char wlan\_network\_security::psk\[WLAN\_PSK\_MAX\_LENGTH\]

> Pre-shared key (network password). For WEP networks this is a hex byte
> sequence of length psk\_len, for WPA and WPA2 networks this is an
> ASCII pass-phrase of length psk\_len. This field is ignored for
> networks with no security.

#### uint8\_t wlan\_network\_security::psk\_len

> Length of the WEP key or WPA/WPA2 pass phrase, WLAN\_PSK\_MIN\_LENGTH
> to WLAN\_PSK\_MAX\_LENGTH. Ignored for networks with no security.

#### char wlan\_network\_security::password\[WLAN\_PASSWORD\_MAX\_LENGTH+1\]

> WPA3 SAE password, for WPA3 SAE networks this is an ASCII password of
> length password\_len. This field is ignored for networks with no
> security.

#### size\_t wlan\_network\_security::password\_len

> Length of the WPA3 SAE Password, WLAN\_PASSWORD\_MIN\_LENGTH to
> WLAN\_PASSWORD\_MAX\_LENGTH. Ignored for networks with no security.

#### char\* wlan\_network\_security::sae\_groups

> Preference list of enabled groups for SAE. By default (if this
> parameter is not set), the mandatory group 19 (ECC group defined over
> a 256-bit prime order field) is preferred, but other groups are also
> enabled. If this parameter is set, the groups is tried in the
> indicated order.

#### uint8\_t wlan\_network\_security::pwe\_derivation

> SAE (Simultaneous Authentication of Equals) mechanism for PWE
> (Password Element) derivation

#### uint8\_t wlan\_network\_security::transition\_disable

> Transition Disable indication

#### char\* wlan\_network\_security::owe\_groups

> OWE Groups

#### char wlan\_network\_security::pmk\[WLAN\_PMK\_LENGTH\]

> PMK (pairwise master key). When pmk\_valid is set, this is the PMK
> calculated from the PSK for WPA/PSK networks. If pmk\_valid is not
> set, this field is ignored. When adding networks with
> wlan\_add\_network, users can initialize PMK and set pmk\_valid in
> lieu of setting the psk. After successfully connecting to a WPA/PSK
> network, users can call wlan\_get\_current\_network to inspect
> pmk\_valid and pmk. Thus, the pmk value can be populated in subsequent
> calls to wlan\_add\_network. This saves the CPU time required to
> otherwise calculate the PMK.

#### bool wlan\_network\_security::pmk\_valid

> Flag reporting whether PMK is valid or not.

#### int8\_t wlan\_network\_security::mfpc

> Management frame protection capable (MFPC)

#### int8\_t wlan\_network\_security::mfpr

> Management frame protection required (MFPR)

#### unsigned wlan\_network\_security::wpa3\_sb

> WPA3 Enterprise mode

#### unsigned wlan\_network\_security::wpa3\_sb\_192

> WPA3 Enterprise Suite B 192 mode

#### unsigned wlan\_network\_security::eap\_ver

> EAP (Extensible Authentication Protocol) version

#### unsigned wlan\_network\_security::peap\_label

> PEAP (Protected Extensible Authentication Protocol) label

#### uint8\_t wlan\_network\_security::eap\_crypto\_binding

> crypto\_binding option can be used to control
> WLAN\_SECURITY\_EAP\_PEAP\_MSCHAPV2, WLAN\_SECURITY\_EAP\_PEAP\_TLS
> and WLAN\_SECURITY\_EAP\_PEAP\_GTC version 0 cryptobinding behavior: 0
> = do not use cryptobinding (default) 1 = use cryptobinding if server
> supports it 2 = require cryptobinding

#### unsigned wlan\_network\_security::eap\_result\_ind

> eap\_result\_ind=1 can be used to enable WLAN\_SECURITY\_EAP\_SIM,
> WLAN\_SECURITY\_EAP\_AKA and WLAN\_SECURITY\_EAP\_AKA\_PRIME to use
> protected result indication.

#### unsigned char wlan\_network\_security::tls\_cipher

> Cipher for EAP TLS (Extensible Authentication Protocol Transport Layer
> Security)

#### char wlan\_network\_security::identity\[IDENTITY\_MAX\_LENGTH\]

> Identity string for EAP

#### char wlan\_network\_security::anonymous\_identity\[IDENTITY\_MAX\_LENGTH\]

> Anonymous identity string for EAP

#### char wlan\_network\_security::eap\_password\[PASSWORD\_MAX\_LENGTH\]

> Password string for EAP.

#### bool wlan\_network\_security::verify\_peer

> whether verify peer with CA or not 0: not verify, 1: verify.

#### unsigned char\* wlan\_network\_security::ca\_cert\_data

> CA (Certificate Authority) certification blob (Binary Large Object) in
> PEM (Base64 ASCII)/DER (binary) format

#### size\_t wlan\_network\_security::ca\_cert\_len

> CA (Certificate Authority) certification blob (Binary Large Object)
> length

#### unsigned char\* wlan\_network\_security::client\_cert\_data

> Client certification blob (Binary Large Object) in PEM (Base64
> ASCII)/DER (binary) format

#### size\_t wlan\_network\_security::client\_cert\_len

> Client certification blob (Binary Large Object) length

#### unsigned char\* wlan\_network\_security::client\_key\_data

> Client key blob (Binary Large Object)

#### size\_t wlan\_network\_security::client\_key\_len

> Client key blob (Binary Large Object) length

#### char wlan\_network\_security::client\_key\_passwd\[PASSWORD\_MAX\_LENGTH\]

> Client key password

#### char wlan\_network\_security::ca\_cert\_hash\[HASH\_MAX\_LENGTH\]

> CA certification HASH

#### char wlan\_network\_security::domain\_match\[DOMAIN\_MATCH\_MAX\_LENGTH\]

> Domain

#### char wlan\_network\_security::domain\_suffix\_match\[DOMAIN\_MATCH\_MAX\_LENGTH\]

> Domain Suffix

#### unsigned char\* wlan\_network\_security::ca\_cert2\_data

> CA (Certificate Authority) certification blob (Binary Large Object) in
> PEM (Base64 ASCII)/DER (binary) format for phase two

#### size\_t wlan\_network\_security::ca\_cert2\_len

> CA (Certificate Authority) certification blob (Binary Large Object)
> length for phase two

#### unsigned char\* wlan\_network\_security::client\_cert2\_data

> Client certification blob (Binary Large Object) in PEM (Base64
> ASCII)/DER (binary) format for phase two

#### size\_t wlan\_network\_security::client\_cert2\_len

> Client certification blob (Binary Large Object) length for phase two

#### unsigned char\* wlan\_network\_security::client\_key2\_data

> Client key blob (Binary Large Object) for phase two

#### size\_t wlan\_network\_security::client\_key2\_len

> Client key blob (Binary Large Object) length for phase two

#### char wlan\_network\_security::client\_key2\_passwd\[PASSWORD\_MAX\_LENGTH\]

> Client key password for phase two

#### The documentation for this struct was generated from the following file:

wlan.h

#### 

## wlan\_scan\_result Struct Reference

### Data Fields

char ssid \[WLAN\_NETWORK\_NAME\_MAX\_LENGTH+1\]

unsigned int ssid\_len

char bssid \[IEEEtypes\_ADDRESS\_SIZE\]

unsigned int channel

enum wlan\_bss\_type type

enum wlan\_bss\_role role

unsigned dot11n: 1

unsigned dot11ac: 1

unsigned dot11ax: 1

unsigned wmm: 1

unsigned wps: 1

unsigned int wps\_session

unsigned wep: 1

unsigned wpa: 1

unsigned wpa2: 1

unsigned wpa2\_sha256: 1

unsigned owe: 1

unsigned wpa3\_sae: 1

unsigned wpa2\_entp: 1

unsigned wpa2\_entp\_sha256: 1

unsigned wpa3\_1x\_sha256: 1

unsigned wpa3\_1x\_sha384: 1

unsigned ft\_1x: 1

unsigned ft\_1x\_sha384: 1

unsigned ft\_psk: 1

unsigned ft\_sae: 1

unsigned char rssi

char trans\_ssid \[WLAN\_NETWORK\_NAME\_MAX\_LENGTH+1\]

unsigned int trans\_ssid\_len

char trans\_bssid \[IEEEtypes\_ADDRESS\_SIZE\]

uint16\_t beacon\_period

uint8\_t dtim\_period

t\_u8 ap\_mfpc

t\_u8 ap\_mfpr

t\_u8 ap\_pwe

bool neighbor\_report\_supported

bool bss\_transition\_supported

### Detailed Description

Scan result

### Field Documentation

#### char wlan\_scan\_result::ssid\[WLAN\_NETWORK\_NAME\_MAX\_LENGTH+1\]

> The network SSID, represented as a NULL-terminated C string of 0 to 32
> characters. If the network has a hidden SSID, this can be the empty
> string.

#### unsigned int wlan\_scan\_result::ssid\_len

> SSID length

#### char wlan\_scan\_result::bssid\[IEEEtypes\_ADDRESS\_SIZE\]

> The network BSSID, represented as a 6-byte array.

#### unsigned int wlan\_scan\_result::channel

> The network channel.

#### enum wlan\_bss\_type wlan\_scan\_result::type

> The Wi-Fi network type.

#### enum wlan\_bss\_role wlan\_scan\_result::role

> The Wi-Fi network mode.

#### unsigned wlan\_scan\_result::dot11n

> The network supports 802.11N. This is set to 0 if the network does not
> support 802.11N or if the system does not have 802.11N support
> enabled.

#### unsigned wlan\_scan\_result::dot11ac

> The network supports 802.11AC. This is set to 0 if the network does
> not support 802.11AC or if the system does not have 802.11AC support
> enabled.

#### unsigned wlan\_scan\_result::dot11ax

> The network supports 802.11AX. This is set to 0 if the network does
> not support 802.11AX or if the system does not have 802.11AX support
> enabled.

#### unsigned wlan\_scan\_result::wmm

> The network supports WMM. This is set to 0 if the network does not
> support WMM or if the system does not have WMM support enabled.

#### unsigned wlan\_scan\_result::wps

> The network supports WPS. This is set to 0 if the network does not
> support WPS or if the system does not have WPS support enabled.

#### unsigned int wlan\_scan\_result::wps\_session

> WPS Type WPS\_SESSION\_PBC/ WPS\_SESSION\_PIN

#### unsigned wlan\_scan\_result::wep

> The network uses WEP security.

#### unsigned wlan\_scan\_result::wpa

> The network uses WPA security.

#### unsigned wlan\_scan\_result::wpa2

> The network uses WPA2 security

#### unsigned wlan\_scan\_result::wpa2\_sha256

> The network uses WPA2 SHA256 security

#### unsigned wlan\_scan\_result::owe

> The network uses OWE security

#### unsigned wlan\_scan\_result::wpa3\_sae

> The network uses WPA3 SAE security

#### unsigned wlan\_scan\_result::wpa2\_entp

> The network uses WPA2 Enterprise security

#### unsigned wlan\_scan\_result::wpa2\_entp\_sha256

> The network uses WPA2 Enterprise SHA256 security

#### unsigned wlan\_scan\_result::wpa3\_1x\_sha256

> The network uses WPA3 Enterprise SHA256 security

#### unsigned wlan\_scan\_result::wpa3\_1x\_sha384

> The network uses WPA3 Enterprise SHA384 security

#### unsigned wlan\_scan\_result::ft\_1x

> The network uses FT 802.1x security

#### unsigned wlan\_scan\_result::ft\_1x\_sha384

> The network uses FT 892.1x SHA384 security

#### unsigned wlan\_scan\_result::ft\_psk

> The network uses FT PSK security

#### unsigned wlan\_scan\_result::ft\_sae

> The network uses FT SAE security

#### unsigned char wlan\_scan\_result::rssi

> The signal strength of the beacon

#### char wlan\_scan\_result::trans\_ssid\[WLAN\_NETWORK\_NAME\_MAX\_LENGTH+1\]

> The network SSID, represented as a NULL-terminated C string of 0 to 32
> characters. If the network has a hidden SSID, this should be the empty
> string.

#### unsigned int wlan\_scan\_result::trans\_ssid\_len

> SSID length

#### char wlan\_scan\_result::trans\_bssid\[IEEEtypes\_ADDRESS\_SIZE\]

> The network BSSID, represented as a 6-byte array.

#### uint16\_t wlan\_scan\_result::beacon\_period

> Beacon period

#### uint8\_t wlan\_scan\_result::dtim\_period

> DTIM (delivery traffic indication map) period

#### t\_u8 wlan\_scan\_result::ap\_mfpc

> MFPC (Management Frame Protection Capable) bit of AP (Access Point)

#### t\_u8 wlan\_scan\_result::ap\_mfpr

> MFPR (Management Frame Protection Required) bit of AP (Access Point)

#### t\_u8 wlan\_scan\_result::ap\_pwe

> PWE (Password Element) bit of AP (Access Point)

#### bool wlan\_scan\_result::neighbor\_report\_supported

> Neighbor report support

#### bool wlan\_scan\_result::bss\_transition\_supported

> bss transition support

#### The documentation for this struct was generated from the following file:

wlan.h

# File Documentation

## wlan.h File Reference

This file provides Wi-Fi APIs for the application.

### Function Documentation

#### int verify\_scan\_duration\_value (int *scan\_duration*)

> Check whether the scan duration is valid or not.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>scan_duration</em></td>
<td>scan duration time</td>
</tr>
</tbody>
</table>

##### Returns

> 0 if the time is valid, else return -1.

#### int verify\_scan\_channel\_value (int *channel*)

> Check whether the scan channel is valid or not.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>channel</em></td>
<td>the scan channel</td>
</tr>
</tbody>
</table>

##### Returns

> 0 if the channel is valid, else return -1.

#### int verify\_split\_scan\_delay (int *delay*)

> Check whether the scan delay time is valid or not.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>delay</em></td>
<td>the scan delay time.</td>
</tr>
</tbody>
</table>

##### Returns

> 0 if the time is valid, else return -1.

#### int set\_scan\_params (struct wifi\_scan\_params\_t \* *wifi\_scan\_params*)

> Set the scan parameters.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>wifi_scan_params</em></td>
<td>Wi-Fi scan parameter structure pointer.</td>
</tr>
</tbody>
</table>

##### Returns

> 0 if Wi-Fi scan parameters are set successfully, else return -1.

#### int get\_scan\_params (struct wifi\_scan\_params\_t \* *wifi\_scan\_params*)

> Get the scan parameters.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>wifi_scan_params</em></td>
<td>Wi-Fi scan parameter structure pointer.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS.

#### int wlan\_get\_current\_rssi (short \* *rssi*)

> Get the current RSSI value.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>rssi</em></td>
<td>pointer to get the current RSSI (Received Signal Strength Indicator)</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS.

#### int wlan\_get\_current\_nf (void )

> Get the current noise floor.

##### Returns

> The noise floor value

#### int wlan\_init (const uint8\_t \* *fw\_start\_addr*, const size\_t *size*)

> Initialize the Wi-Fi driver and create the Wi-Fi driver thread.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>fw_start_addr</em></td>
<td>Start address of the Wi-Fi firmware.</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>size</em></td>
<td>Size of the Wi-Fi firmware.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if the Wi-Fi connection manager service has initialized
> successfully.
> 
> Negative value if initialization failed.

#### int wlan\_start (int(\*)(enum wlan\_event\_reason reason, void \*data) *cb*)

> Start the Wi-Fi connection manager service.
> 
> This function starts the Wi-Fi connection manager.

##### Note

> The status of the Wi-Fi connection manager is notified asynchronously
> through the callback, *cb* , with a WLAN\_REASON\_INITIALIZED event
> (if initialization succeeded) or WLAN\_REASON\_INITIALIZATION\_FAILED
> (if initialization failed). If the Wi-Fi connection manager fails to
> initialize, the caller should stop Wi-Fi connection manager via
> wlan\_stop() and try wlan\_start() again.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>cb</em></td>
<td>A pointer to a callback function that handles Wi-Fi events. All further WLCMGR events can be notified in this callback. Refer to enum wlan_event_reason for the various events for which this callback is called.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if the Wi-Fi connection manager service has started
> successfully.
> 
> \-WM\_E\_INVAL if the *cb* pointer is NULL.
> 
> \-WM\_FAIL if an internal error occurred.
> 
> WLAN\_ERROR\_STATE if the Wi-Fi connection manager is already running.

#### int wlan\_stop (void )

> Stop the Wi-Fi connection manager service.
> 
> This function stops the Wi-Fi connection manager, causing the station
> interface to disconnect from the currently connected network and stop
> the uAP interface.

##### Returns

> WM\_SUCCESS if the Wi-Fi connection manager service has been stopped
> successfully.
> 
> WLAN\_ERROR\_STATE if the Wi-Fi connection manager was not running.

#### void wlan\_deinit (int *action*)

> Deinitialize the Wi-Fi driver, send a shutdown command to the Wi-Fi
> firmware and delete the Wi-Fi driver thread.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>action</em></td>
<td>Additional action to be taken with deinit. Should input 0 here.</td>
</tr>
</tbody>
</table>

#### int wlan\_remove\_all\_network\_profiles (void )

> Stop and remove all Wi-Fi network profiles.

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_E\_INVAL.

#### void wlan\_reset (cli\_reset\_option *ResetOption*)

> Reset the driver.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>ResetOption</em></td>
<td>Option including enable, disable or reset Wi-Fi driver can be chosen.</td>
</tr>
</tbody>
</table>

#### int wlan\_remove\_all\_networks (void )

> Stop and remove all Wi-Fi network (access point).

##### Returns

> WM\_SUCCESS if successful.

#### void wlan\_destroy\_all\_tasks (void )

> This API destroys all tasks.

#### int wlan\_is\_started (void )

> Retrieve the status information of if Wi-Fi started.

##### Returns

> TRUE if Wi-Fi network is started.
> 
> FALSE if not started.

#### int wlan\_set\_get\_rx\_abort\_cfg (struct wlan\_rx\_abort\_cfg \* *cfg*, t\_u16 *action*)

> Set/Get RX abort configuration to/from firmware.

##### Parameters

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

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_set\_rx\_abort\_cfg\_ext (const struct wlan\_rx\_abort\_cfg\_ext \* *cfg*)

> Set the dynamic RX abort configuration to firmware.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>cfg</em></td>
<td>A pointer to information buffer</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_get\_rx\_abort\_cfg\_ext (struct wlan\_rx\_abort\_cfg\_ext \* *cfg*)

> Get the dynamic RX abort configuration from firmware.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>cfg</em></td>
<td>A pointer to information buffer</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_set\_get\_cck\_desense\_cfg (struct wlan\_cck\_desense\_cfg \* *cfg*, t\_u16 *action*)

> Set/Get CCK (complementary code keying) desense configuration to/from
> firmware.

##### Parameters

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

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### void wlan\_initialize\_uap\_network (struct wlan\_network \* *net*)

> Initialize the uAP network information.
> 
> This API initializes a uAP network with default configurations. The
> network ssid, passphrase is initialized to NULL. Channel is set to
> auto. The IP Address of the uAP interface is
> 192.168.10.1/255.255.255.0. The network name is set to 'uap-network'.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>net</em></td>
<td>Pointer to the initialized uAP network</td>
</tr>
</tbody>
</table>

#### void wlan\_initialize\_sta\_network (struct wlan\_network \* *net*)

> Initialize the station network information.
> 
> This API initializes a station network with default configurations.
> The network ssid, passphrase is initialized to NULL. Channel is set to
> auto.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>net</em></td>
<td>Pointer to the initialized station network</td>
</tr>
</tbody>
</table>

#### int wlan\_add\_network (struct wlan\_network \* *network*)

> Add a network profile to the list of known networks.
> 
> This function copies the contents of *network* to the list of known
> networks in the Wi-Fi connection manager. The network's 'name' field
> is unique and between WLAN\_NETWORK\_NAME\_MIN\_LENGTH and
> WLAN\_NETWORK\_NAME\_MAX\_LENGTH characters. The network must specify
> at least an SSID or BSSID. the Wi-Fi connection manager can store up
> to WLAN\_MAX\_KNOWN\_NETWORKS networks.

##### Note

> Profiles for the station interface may be added only when the station
> interface is in the WLAN\_DISCONNECTED or WLAN\_CONNECTED state.
> 
> This API can be used to add profiles for station or uAP interfaces.
> 
> Set mfpc and mfpr to -1 for default configurations.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>network</em></td>
<td>A pointer to the wlan_network that can be copied to the list of known networks in the Wi-Fi connection manager successfully.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if the contents pointed to by *network* have been added to
> the Wi-Fi connection manager.
> 
> \-WM\_E\_INVAL if *network* is NULL or the network name is not unique
> or the network name length is not valid or network security is
> WLAN\_SECURITY\_WPA3\_SAE but Management Frame Protection Capable is
> not enabled. in wlan\_network\_security field. if network security
> type is WLAN\_SECURITY\_WPA or WLAN\_SECURITY\_WPA2 or
> WLAN\_SECURITY\_WPA\_WPA2\_MIXED, but the passphrase length is less
> than 8 or greater than 63, or the psk length equal to 64 but not
> hexadecimal digits. if network security type is
> WLAN\_SECURITY\_WPA3\_SAE, but the password length is less than 8 or
> greater than 255. if network security type is
> WLAN\_SECURITY\_WEP\_OPEN or WLAN\_SECURITY\_WEP\_SHARED.
> 
> \-WM\_E\_NOMEM if there was no room to add the network.
> 
> WLAN\_ERROR\_STATE if the Wi-Fi connection manager was running and not
> in the WLAN\_DISCONNECTED, WLAN\_ASSOCIATED or WLAN\_CONNECTED state.

#### int wlan\_remove\_network (const char \* *name*)

> Remove a network profile from the list of known networks.
> 
> This function removes a network (identified by its name) from the WLAN
> Connection Manager, disconnecting from that network if connected.

##### Note

> This function is asynchronous if it is called while the WLAN
> Connection Manager is running and connected to the network to be
> removed. In that case, the Wi-Fi connection manager can disconnect
> from the network and generate an event with reason
> WLAN\_REASON\_USER\_DISCONNECT. This function is synchronous
> otherwise.
> 
> This API can be used to remove profiles for station or uAP interfaces.
> Station network can not be removed if it is in WLAN\_CONNECTED state
> and uAP network can not be removed if it is in WLAN\_UAP\_STARTED
> state.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>name</em></td>
<td>A pointer to the string representing the name of the network to remove.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if the network named *name* was removed from the Wi-Fi
> connection manager successfully. Otherwise, the network is not
> removed.
> 
> WLAN\_ERROR\_STATE if the Wi-Fi connection manager was running and the
> station interface was not in the WLAN\_DISCONNECTED state.
> 
> \-WM\_E\_INVAL if *name* is NULL or the network was not found in the
> list of known networks.
> 
> \-WM\_FAIL if an internal error occurred while trying to disconnect
> from the network specified for removal.

#### int wlan\_connect (char \* *name*)

> Connect to a Wi-Fi network (access point).
> 
> When this function is called, Wi-Fi connection manager starts
> connection attempts to the network specified by *name* . The
> connection result can be notified asynchronously to the WLCMGR
> callback when the connection process has completed.
> 
> When connecting to a network, the event refers to the connection
> attempt to that network.
> 
> Calling this function when the station interface is in the
> WLAN\_DISCONNECTED state should, if successful, cause the interface to
> transition into the WLAN\_CONNECTING state. If the connection attempt
> succeeds, the station interface should transition to the
> WLAN\_CONNECTED state, otherwise it should return to the
> WLAN\_DISCONNECTED state. If this function is called while the station
> interface is in the WLAN\_CONNECTING or WLAN\_CONNECTED state, the
> Wi-Fi connection manager should first cancel its connection attempt or
> disconnect from the network, respectively, and generate an event with
> reason WLAN\_REASON\_USER\_DISCONNECT. This should be followed by a
> second event that reports the result of the new connection attempt.
> 
> If the connection attempt was successful the WLCMGR callback is
> notified with the event WLAN\_REASON\_SUCCESS, while if the connection
> attempt fails then either of the events,
> WLAN\_REASON\_NETWORK\_NOT\_FOUND,
> WLAN\_REASON\_NETWORK\_AUTH\_FAILED, WLAN\_REASON\_CONNECT\_FAILED or
> WLAN\_REASON\_ADDRESS\_FAILED are reported as appropriate.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>name</em></td>
<td>A pointer to a string representing the name of the network to connect to.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if a connection attempt was started successfully
> 
> WLAN\_ERROR\_STATE if the Wi-Fi connection manager was not running.
> 
> \-WM\_E\_INVAL if there are no known networks to connect to or the
> network specified by *name* is not in the list of known networks or
> network *name* is NULL.
> 
> \-WM\_FAIL if an internal error has occurred.

#### int wlan\_connect\_opt (char \* *name*, bool *skip\_dfs*)

> Connect to a Wi-Fi network (access point) with options.
> 
> When this function is called, the Wi-Fi connection manager starts
> connection attempts to the network specified by *name* . The
> connection result should be notified asynchronously to the WLCMGR
> callback when the connection process has completed.
> 
> When connecting to a network, the event refers to the connection
> attempt to that network.
> 
> Calling this function when the station interface is in the
> WLAN\_DISCONNECTED state should, if successful, cause the interface to
> transition into the WLAN\_CONNECTING state. If the connection attempt
> succeeds, the station interface should transition to the
> WLAN\_CONNECTED state, otherwise it should return to the
> WLAN\_DISCONNECTED state. If this function is called while the station
> interface is in the WLAN\_CONNECTING or WLAN\_CONNECTED state, the
> Wi-Fi connection manager should first cancel its connection attempt or
> disconnect from the network, respectively, and generate an event with
> reason WLAN\_REASON\_USER\_DISCONNECT. This should be followed by a
> second event that reports the result of the new connection attempt.
> 
> If the connection attempt was successful the WLCMGR callback is
> notified with the event WLAN\_REASON\_SUCCESS, while if the connection
> attempt fails then either of the events,
> WLAN\_REASON\_NETWORK\_NOT\_FOUND,
> WLAN\_REASON\_NETWORK\_AUTH\_FAILED, WLAN\_REASON\_CONNECT\_FAILED or
> WLAN\_REASON\_ADDRESS\_FAILED are reported as appropriate.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>name</em></td>
<td>A pointer to a string representing the name of the network to connect to.</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>skip_dfs</em></td>
<td>Option to skip DFS channel when doing scan.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if a connection attempt was started successfully
> 
> WLAN\_ERROR\_STATE if the Wi-Fi connection manager was not running.
> 
> \-WM\_E\_INVAL if there are no known networks to connect to or the
> network specified by *name* is not in the list of known networks or
> network *name* is NULL.
> 
> \-WM\_FAIL if an internal error has occurred.

#### int wlan\_reassociate (void )

> Reassociate to a Wi-Fi network (access point).
> 
> When this function is called, the Wi-Fi connection manager starts
> reassociation attempts using same SSID as currently connected network
> . The connection result should be notified asynchronously to the
> WLCMGR callback when the connection process has completed.
> 
> When connecting to a network, the event refers to the connection
> attempt to that network.
> 
> Calling this function when the station interface is in the
> WLAN\_DISCONNECTED state should have no effect.
> 
> Calling this function when the station interface is in the
> WLAN\_CONNECTED state should, if successful, cause the interface to
> reassociate to another network (access point).
> 
> If the connection attempt was successful the WLCMGR (Wi-Fi command
> manager) callback is notified with the event WLAN\_REASON\_SUCCESS,
> while if the connection attempt fails then either of the events,
> WLAN\_REASON\_NETWORK\_AUTH\_FAILED, WLAN\_REASON\_CONNECT\_FAILED or
> WLAN\_REASON\_ADDRESS\_FAILED are reported as appropriate.

##### Returns

> WM\_SUCCESS if a reassociation attempt was started successfully
> 
> WLAN\_ERROR\_STATE if the Wi-Fi connection manager was not running. or
> Wi-Fi connection manager was not in WLAN\_CONNECTED state.
> 
> \-WM\_E\_INVAL if there are no known networks to connect to
> 
> \-WM\_FAIL if an internal error has occurred.

#### int wlan\_disconnect (void )

> Disconnect from the current Wi-Fi network (access point).
> 
> When this function is called, the Wi-Fi connection manager attempts to
> disconnect the station interface from its currently connected network
> (or cancel an in-progress connection attempt) and return to the
> WLAN\_DISCONNECTED state. Calling this function has no effect if the
> station interface is already disconnected.

##### Note

> This is an asynchronous function and successful disconnection should
> be notified using the WLAN\_REASON\_USER\_DISCONNECT.

##### Returns

> WM\_SUCCESS if successful
> 
> WLAN\_ERROR\_STATE otherwise

#### int wlan\_start\_network (const char \* *name*)

> Start a Wi-Fi network (access point).
> 
> When this function is called, the Wi-Fi connection manager starts the
> network specified by *name* . The network with the specified *name* is
> first added using wlan\_add\_network and is a uAP network with a valid
> SSID.

##### Note

> The WLCMGR callback is asynchronously notified of the status. On
> success, the event WLAN\_REASON\_UAP\_SUCCESS is reported, while on
> failure, the event WLAN\_REASON\_UAP\_START\_FAILED is reported.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>name</em></td>
<td>A pointer to string representing the name of the network to connect to.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful.
> 
> WLAN\_ERROR\_STATE if in power save state or uAP already running.
> 
> \-WM\_E\_INVAL if *name* was NULL or the network *name* was not found
> or it not have a specified SSID.

#### int wlan\_stop\_network (const char \* *name*)

> Stop a Wi-Fi network (access point).
> 
> When this function is called, the Wi-Fi connection manager stops the
> network specified by *name* . The specified network is a valid uAP
> network that has already been started.

##### Note

> The WLCMGR callback is asynchronously notified of the status. On
> success, the event WLAN\_REASON\_UAP\_STOPPED is reported, while on
> failure, the event WLAN\_REASON\_UAP\_STOP\_FAILED is reported.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>name</em></td>
<td>A pointer to a string representing the name of the network to stop.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful.
> 
> WLAN\_ERROR\_STATE if uAP is in power save state.
> 
> \-WM\_E\_INVAL if *name* was NULL or the network *name* was not found
> or that the network *name* is not a uAP network or it is a uAP network
> but does not have a specified SSID.

#### int wlan\_get\_mac\_address (uint8\_t \* *dest*)

> Retrieve the Wi-Fi MAC address of the station interface.
> 
> This function copies the MAC address of the Wi-Fi station interface to
> the 6-byte array pointed to by *dest* . In the event of an error,
> nothing is copied to *dest* .

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>dest</em></td>
<td>A pointer to a 6-byte array where the MAC address should be copied.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if the MAC address was copied.
> 
> \-WM\_E\_INVAL if *dest* is NULL.

#### int wlan\_get\_mac\_address\_uap (uint8\_t \* *dest*)

> Retrieve the Wi-Fi MAC address of the uAP interface.
> 
> This function copies the MAC address of the Wi-Fi uAP interface to the
> 6-byte array pointed to by *dest* . In the event of an error, nothing
> is copied to *dest* .

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>dest</em></td>
<td>A pointer to a 6-byte array where the MAC address can be copied.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if the MAC address was copied.
> 
> \-WM\_E\_INVAL if *dest* is NULL.

#### int wlan\_get\_address (struct wlan\_ip\_config \* *addr*)

> Retrieve the IP address configuration of the station interface.
> 
> This function retrieves the IP address configuration of the station
> interface and copies it to the memory location pointed to by *addr* .

##### Note

> This function may only be called when the station interface is in the
> WLAN\_CONNECTED state.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>addr</em></td>
<td>A pointer to the wlan_ip_config.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful.
> 
> \-WM\_E\_INVAL if *addr* is NULL.
> 
> WLAN\_ERROR\_STATE if the Wi-Fi connection manager was not running or
> was not in the WLAN\_CONNECTED state.
> 
> \-WM\_FAIL if an internal error occurred when retrieving IP address
> information from the TCP stack.

#### int wlan\_get\_uap\_address (struct wlan\_ip\_config \* *addr*)

> Retrieve the IP address of the uAP interface.
> 
> This function retrieves the current IP address configuration of the
> uAP and copies it to the memory location pointed to by *addr* .

##### Note

> This function may only be called when the uAP interface is in the
> WLAN\_UAP\_STARTED state.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>addr</em></td>
<td>A pointer to the wlan_ip_config.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful.
> 
> \-WM\_E\_INVAL if *addr* is NULL.
> 
> WLAN\_ERROR\_STATE if the Wi-Fi connection manager was not running or
> the uAP interface was not in the WLAN\_UAP\_STARTED state.
> 
> \-WM\_FAIL if an internal error occurred when retrieving IP address
> information from the TCP stack.

#### int wlan\_get\_uap\_channel (int \* *channel*)

> Retrieve the channel of the uAP interface.
> 
> This function retrieves the channel number of the uAP and copies it to
> the memory location pointed to by *channel* .

##### Note

> This function may only be called when the uAP interface is in the
> WLAN\_UAP\_STARTED state.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>channel</em></td>
<td>A pointer to variable that stores channel number.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful.
> 
> \-WM\_E\_INVAL if *channel* is NULL.
> 
> \-WM\_FAIL if an internal error has occurred.

#### int wlan\_get\_current\_network (struct wlan\_network \* *network*)

> Retrieve the current network configuration of the station interface.
> 
> This function retrieves the current network configuration of the
> station interface when the station interface is in the WLAN\_CONNECTED
> state.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>network</em></td>
<td>A pointer to the wlan_network.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful.
> 
> \-WM\_E\_INVAL if *network* is NULL.
> 
> WLAN\_ERROR\_STATE if the Wi-Fi connection manager was not running or
> not in the WLAN\_CONNECTED state.

#### int wlan\_get\_current\_network\_ssid (char \* *ssid*)

> Retrieve the current network ssid of the station interface.
> 
> This function retrieves the current network ssid of the station
> interface when the station interface is in the WLAN\_CONNECTED state.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>ssid</em></td>
<td>A pointer to the ssid char string with NULL termination. Maximum length is 32 (not include NULL termination).</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful.
> 
> \-WM\_E\_INVAL if *ssid* is NULL.
> 
> WLAN\_ERROR\_STATE if the Wi-Fi connection manager was not running or
> not in the WLAN\_CONNECTED state.

#### int wlan\_get\_current\_network\_bssid (char \* *bssid*)

> Retrieve the current network bssid of the station interface.
> 
> This function retrieves the current network bssid of the station
> interface when the station interface is in the WLAN\_CONNECTED state.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>bssid</em></td>
<td>A pointer to the bssid char string without NULL termination.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful.
> 
> \-WM\_E\_INVAL if *bssid* is NULL.
> 
> WLAN\_ERROR\_STATE if the Wi-Fi connection manager was not running or
> not in the WLAN\_CONNECTED state.

#### int wlan\_get\_current\_uap\_network (struct wlan\_network \* *network*)

> Retrieve the current network configuration of the uAP interface.
> 
> This function retrieves the current network configuration of the uAP
> interface when the uAP interface is in the WLAN\_UAP\_STARTED state.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>network</em></td>
<td>A pointer to the wlan_network.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful.
> 
> \-WM\_E\_INVAL if *network* is NULL.
> 
> WLAN\_ERROR\_STATE if the Wi-Fi connection manager was not running or
> not in the WLAN\_UAP\_STARTED state.

#### int wlan\_get\_current\_uap\_network\_ssid (char \* *ssid*)

> Retrieve the current network ssid of the uAP interface.
> 
> This function retrieves the current network ssid of the uAP interface
> when the uAP interface is in the WLAN\_UAP\_STARTED state.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>ssid</em></td>
<td>A pointer to the ssid char string with NULL termination. Maximum length is 32 (not include NULL termination).</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful.
> 
> \-WM\_E\_INVAL if *ssid* is NULL.
> 
> WLAN\_ERROR\_STATE if the Wi-Fi connection manager was not running or
> not in the WLAN\_UAP\_STARTED state.

#### bool is\_uap\_started (void )

> Retrieve the status information of the uAP interface.

##### Returns

> TRUE if uAP interface is in WLAN\_UAP\_STARTED state.
> 
> FALSE otherwise.

#### bool is\_sta\_associated (void )

> Retrieve the status information of the station interface.

##### Returns

> TRUE if station interface is in or above the WLAN\_ASSOCIATED state.
> 
> FALSE otherwise.

#### bool is\_sta\_connected (void )

> Retrieve the status information of the station interface.

##### Returns

> TRUE if station interface is in WLAN\_CONNECTED state.
> 
> FALSE otherwise.

#### bool is\_sta\_ipv4\_connected (void )

> Retrieve the status information of the ipv4 network of the station
> interface.

##### Returns

> TRUE if ipv4 network of the station interface is in WLAN\_CONNECTED
> state.
> 
> FALSE otherwise.

#### bool is\_sta\_ipv6\_connected (void )

> Retrieve the status information of the ipv6 network of the station
> interface.

##### Returns

> TRUE if ipv6 network of the station interface is in WLAN\_CONNECTED
> state.
> 
> FALSE otherwise.

#### int wlan\_get\_network (unsigned int *index*, struct wlan\_network \* *network*)

> Retrieve the information about a known network using *index* .
> 
> This function retrieves the contents of a network at *index* in the
> list of known networks maintained by the Wi-Fi connection manager and
> copies it to the location pointed to by *network* .

##### Note

> wlan\_get\_network\_count() can be used to retrieve the number of
> known networks. wlan\_get\_network() can be used to retrieve
> information about networks at *index* 0 to one minus the number of
> networks.
> 
> This function can be called regardless of whether the Wi-Fi connection
> manager is running or not. Calls to this function are synchronous.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>index</em></td>
<td>The index of the network to retrieve.</td>
</tr>
<tr class="even">
<td>out</td>
<td><em>network</em></td>
<td>A pointer to the wlan_network where the network configuration for the network at <em>index</em> can be copied.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful.
> 
> \-WM\_E\_INVAL if *network* is NULL or *index* is out of range.

#### int wlan\_get\_network\_byname (char \* *name*, struct wlan\_network \* *network*)

> Retrieve information about a known network using *name* .
> 
> This function retrieves the contents of a named network in the list of
> known networks maintained by the Wi-Fi connection manager and copies
> it to the location pointed to by *network* .

##### Note

> This function can be called regardless of whether the Wi-Fi Connection
> Manager is running or not. Calls to this function are synchronous.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>name</em></td>
<td>The name of the network to retrieve.</td>
</tr>
<tr class="even">
<td>out</td>
<td><em>network</em></td>
<td>A pointer to the wlan_network where the network configuration for the network having name as <em>name</em> should be copied.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful.
> 
> \-WM\_E\_INVAL if *network* is NULL or *name* is NULL.

#### int wlan\_get\_network\_count (unsigned int \* *count*)

> Retrieve the number of networks known to the Wi-Fi connection manager.
> 
> This function retrieves the number of known networks in the list
> maintained by the Wi-Fi connection manager and copies it to *count* .

##### Note

> This function can be called regardless of whether the Wi-Fi Connection
> Manager is running or not. Calls to this function are synchronous.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>count</em></td>
<td>A pointer to the memory location where the number of networks should be copied.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful.
> 
> \-WM\_E\_INVAL if *count* is NULL.

#### int wlan\_get\_connection\_state (enum wlan\_connection\_state \* *state*)

> Retrieve the connection state of the station interface.
> 
> This function retrieves the connection state of the station interface,
> which is one of WLAN\_DISCONNECTED, WLAN\_CONNECTING, WLAN\_ASSOCIATED
> or WLAN\_CONNECTED.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>state</em></td>
<td>A pointer to the wlan_connection_state where the current connection state should be copied.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful.
> 
> \-WM\_E\_INVAL if *state* is NULL
> 
> WLAN\_ERROR\_STATE if the Wi-Fi connection manager was not running.

#### int wlan\_get\_uap\_connection\_state (enum wlan\_connection\_state \* *state*)

> Retrieve the connection state of the uAP interface.
> 
> This function retrieves the connection state of the uAP interface,
> which is one of WLAN\_UAP\_STARTED, or WLAN\_UAP\_STOPPED.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>state</em></td>
<td>A pointer to the wlan_connection_state where the current connection state should be copied.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful.
> 
> \-WM\_E\_INVAL if *state* is NULL
> 
> WLAN\_ERROR\_STATE if the Wi-Fi connection manager was not running.

#### int wlan\_scan (int(\*)(unsigned int count) *cb*)

> Scan for Wi-Fi networks.
> 
> When this function is called, the Wi-Fi connection manager starts scan
> for Wi-Fi networks. On completion of the scan the Wi-Fi connection
> manager can call the specified callback function *cb* . The callback
> function should then retrieve the scan results by using the
> wlan\_get\_scan\_result() function.

##### Note

> This function may only be called when the station interface is in the
> WLAN\_DISCONNECTED or WLAN\_CONNECTED state. scan is disabled in the
> WLAN\_CONNECTING state.
> 
> This function should block until it can issue a scan request if called
> while another scan is in progress.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>cb</em></td>
<td>A pointer to the function that should be called to handle scan results when they are available.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful.
> 
> \-WM\_E\_NOMEM if failed to allocated memory for
> wlan\_scan\_params\_v2\_t structure.
> 
> \-WM\_E\_INVAL if *cb* scan result callback function pointer is NULL.
> 
> WLAN\_ERROR\_STATE if the Wi-Fi connection manager was not running or
> not in the WLAN\_DISCONNECTED or WLAN\_CONNECTED states.
> 
> \-WM\_FAIL if an internal error has occurred and the system is unable
> to scan.

#### int wlan\_scan\_with\_opt (wlan\_scan\_params\_v2\_t *t\_wlan\_scan\_param*)

> Scan for Wi-Fi networks using options provided.
> 
> When this function is called, the Wi-Fi connection manager starts
> scanning for Wi-Fi networks. On completion of the scan the Wi-Fi
> connection manager should call the specified callback function
> *t\_wlan\_scan\_param.cb* . The callback function should then retrieve
> the scan results by using the wlan\_get\_scan\_result() function.

##### Note

> This function may only be called when the station interface is in the
> WLAN\_DISCONNECTED or WLAN\_CONNECTED state. scan is disabled in the
> WLAN\_CONNECTING state.
> 
> This function can block until it issues a scan request if called while
> another scan is in progress.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>t_wlan_scan_param</em></td>
<td>A wlan_scan_params_v2_t structure holding a pointer to function that should be called to handle scan results when they are available, SSID of a Wi-Fi network, BSSID of a Wi-Fi network, number of channels with scan type information and number of probes.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful.
> 
> \-WM\_E\_NOMEM if failed to allocated memory for
> wlan\_scan\_params\_v2\_t structure.
> 
> \-WM\_E\_INVAL if *cb* scan result callback function pointer is NULL.
> 
> WLAN\_ERROR\_STATE if the Wi-Fi connection manager was not running or
> not in the WLAN\_DISCONNECTED or WLAN\_CONNECTED states.
> 
> \-WM\_FAIL if an internal error has occurred and the system is unable
> to scan.

#### int wlan\_get\_scan\_result (unsigned int *index*, struct wlan\_scan\_result \* *res*)

> Retrieve a scan result.
> 
> This function can be called to retrieve scan results when the Wi-Fi
> connection manager has finished scanning. It is called from within the
> scan result callback (see wlan\_scan()) as scan results are valid only
> in that context. The callback argument 'count' provides the number of
> scan results that can be retrieved and wlan\_get\_scan\_result() can
> be used to retrieve scan results at *index* 0 through that number.

##### Note

> This function may only be called in the context of the scan results
> callback.
> 
> Calls to this function are synchronous.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>index</em></td>
<td>The scan result to retrieve.</td>
</tr>
<tr class="even">
<td>out</td>
<td><em>res</em></td>
<td>A pointer to the wlan_scan_result where the scan result information should be copied.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful.
> 
> \-WM\_E\_INVAL if *res* is NULL
> 
> WLAN\_ERROR\_STATE if the Wi-Fi connection manager was not running
> 
> \-WM\_FAIL if the scan result at *index* could not be retrieved (that
> is, *index* is out of range).

#### int wlan\_set\_ed\_mac\_mode (wlan\_ed\_mac\_ctrl\_t *wlan\_ed\_mac\_ctrl*)

> Configure Energy Detect MAC mode for the station in the Wi-Fi
> Firmware.

##### Note

> When ED MAC mode is enabled, the Wi-Fi Firmware can behave in the
> following way:
> 
> When the background noise had reached the Energy Detect threshold or
> above, the Wi-Fi chipset/module should hold the data transmission
> until the condition is removed. The 2.4GHz and 5GHz bands are
> configured separately.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>wlan_ed_mac_ctrl</em></td>
<td>Struct with following parameters ed_ctrl_2g 0 - disable EU adaptivity for 2.4GHz band 1 - enable EU adaptivity for 2.4GHz band</td>
</tr>
</tbody>
</table>

> ed\_offset\_2g 0 - Default Energy Detect threshold (Default: 0x9)
> offset value range: 0x80 to 0x7F

##### Note

> If 5GH enabled then add following parameters

ed\_ctrl\_5g 0 - disable EU adaptivity for 5GHz band

1 - enable EU adaptivity for 5GHz band

ed\_offset\_5g 0 - Default Energy Detect threshold(Default: 0xC)

offset value range: 0x80 to 0x7F

##### Returns

> WM\_SUCCESS if the call was successful.
> 
> \-WM\_FAIL if failed.

#### int wlan\_set\_uap\_ed\_mac\_mode (wlan\_ed\_mac\_ctrl\_t *wlan\_ed\_mac\_ctrl*)

> Configure Energy Detect MAC mode for the uAP in the Wi-Fi firmware.

##### Note

> When ED MAC mode is enabled, the Wi-Fi Firmware can behave in the
> following way:
> 
> When the background noise had reached the Energy Detect threshold or
> above, the Wi-Fi chipset/module should hold data transmission until
> the condition is removed. The 2.4GHz and 5GHz bands are configured
> separately.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>wlan_ed_mac_ctrl</em></td>
<td>Struct with following parameters ed_ctrl_2g 0 - disable EU adaptivity for 2.4GHz band 1 - enable EU adaptivity for 2.4GHz band</td>
</tr>
</tbody>
</table>

> ed\_offset\_2g 0 - Default energy detect threshold (Default: 0x9)
> offset value range: 0x80 to 0x7F

##### Note

> If 5GH enabled then add following parameters

ed\_ctrl\_5g 0 - disable EU adaptivity for 5GHz band

1 - enable EU adaptivity for 5GHz band

ed\_offset\_5g 0 - Default energy detect threshold(Default: 0xC)

offset value range: 0x80 to 0x7F

##### Returns

> WM\_SUCCESS if the call was successful.
> 
> \-WM\_FAIL if failed.

#### int wlan\_get\_ed\_mac\_mode (wlan\_ed\_mac\_ctrl\_t \* *wlan\_ed\_mac\_ctrl*)

> This API can be used to get current ED MAC MODE configuration for
> station.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>wlan_ed_mac_ctrl</em></td>
<td>A pointer to wlan_ed_mac_ctrl_t with parameters mentioned in above set API.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if the call was successful.
> 
> \-WM\_FAIL if failed.

#### int wlan\_get\_uap\_ed\_mac\_mode (wlan\_ed\_mac\_ctrl\_t \* *wlan\_ed\_mac\_ctrl*)

> This API can be used to get current ED MAC MODE configuration for uAP.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>wlan_ed_mac_ctrl</em></td>
<td>A pointer to wlan_ed_mac_ctrl_t with parameters mentioned in above set API.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if the call was successful.
> 
> \-WM\_FAIL if failed.

#### void wlan\_set\_cal\_data (const uint8\_t \* *cal\_data*, const unsigned int *cal\_data\_size*)

> Set the Wi-Fi calibration data in the Wi-Fi firmware.
> 
> This function can be used to set the Wi-Fi calibration data in the
> firmware. This should be call before wlan\_init() function.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>cal_data</em></td>
<td>The calibration data buffer</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>cal_data_size</em></td>
<td>Size of calibration data buffer.</td>
</tr>
</tbody>
</table>

#### int wlan\_set\_mac\_addr (uint8\_t \* *mac*)

> Set the Wi-Fi MAC Address in the Wi-Fi firmware.
> 
> This function can be used to set Wi-Fi MAC Address in firmware. When
> called after Wi-Fi initialization done, the incoming MAC is treated as
> the STA MAC address directly. And mac\[4\] plus 1, the modified MAC is
> used as the uAP MAC address.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>MAC</em></td>
<td>The MAC Address in 6 bytes array format like uint8_t mac[] = { 0x00, 0x50, 0x43, 0x21, 0x19, 0x6E};</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if the call was successful.
> 
> \-WM\_FAIL if failed.

#### int wlan\_set\_sta\_mac\_addr (uint8\_t \* *mac*)

> Set the Wi-Fi MAC address for the STA in the Wi-Fi firmware.
> 
> This function can be used to set the Wi-Fi MAC address for the station
> in the firmware. Should be called after Wi-Fi initialization done. It
> sets the station MAC address only.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>MAC</em></td>
<td>The MAC Address in 6 byte array format like uint8_t mac[] = { 0x00, 0x50, 0x43, 0x21, 0x19, 0x6E};</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if the call was successful.
> 
> \-WM\_FAIL if failed.

#### int wlan\_set\_uap\_mac\_addr (uint8\_t \* *mac*)

> Set the Wi-Fi MAC address for the uAP in the Wi-Fi firmware.
> 
> This function can be used to set the Wi-Fi MAC address for the uAP in
> the firmware. Should be called after Wi-Fi initialization done. It
> sets the uAP MAC address only.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>MAC</em></td>
<td>The MAC Address in 6 bytes array format like uint8_t mac[] = { 0x00, 0x50, 0x43, 0x21, 0x19, 0x6E};</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if the call was successful.
> 
> \-WM\_FAIL if failed.

#### int wlan\_wmm\_uapsd\_qosinfo (t\_u8 \* *qos\_info*, t\_u8 *action*)

> Set the QOS info of the UAPSD (unscheduled automatic power save
> delivery) in the Wi-Fi firmware.

##### Parameters

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

##### Returns

> WM\_SUCCESS if the call was successful.
> 
> \-WM\_FAIL if failed.

#### int wlan\_set\_wmm\_uapsd (t\_u8 *uapsd\_enable*)

> Enable/Disable the UAPSD in the Wi-Fi firmware.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>uapsd_enable</em></td>
<td>Enable/Disable UAPSD.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if the call was successful.
> 
> \-WM\_FAIL if failed.

#### int wlan\_sleep\_period (unsigned int \* *sleep\_period*, t\_u8 *action*)

> Set/get UAPSD sleep period in the Wi-Fi firmware.

##### Parameters

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

##### Returns

> WM\_SUCCESS if the call was successful.
> 
> \-WM\_FAIL if failed.

#### t\_u8 wlan\_is\_wmm\_uapsd\_enabled (void )

> Check whether UAPSD is enabled or not.

##### Returns

> true if UAPSD is enabled.
> 
> false if UAPSD is disabled.

#### void wlan\_set\_txrx\_histogram (struct wlan\_txrx\_histogram\_info \* *txrx\_histogram*, t\_u8 \* *data*)

> Set TX RX histogram config. This function can be called to set TX RX
> histogram config.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>txrx_histogram</em></td>
<td>User configured parameters of TX RX histogram. including enable and action.</td>
</tr>
<tr class="even">
<td>out</td>
<td><em>data</em></td>
<td>TX RX histogram data from FW.</td>
</tr>
</tbody>
</table>

#### int wlan\_set\_roaming (const int *enable*, const uint8\_t *rssi\_low\_threshold*)

> Set soft roaming config.
> 
> This function can be used to enable/disable soft roaming by specifying
> the RSSI threshold.

##### Note

> **RSSI Threshold setting for soft roaming** : The provided RSSI low
> threshold value is used to subscribe RSSI low event from the firmware.
> On reception of this event, the background scan is started in the
> firmware with the same RSSI threshold to find out APs with a better
> signal strength than the RSSI threshold.
> 
> If an AP with better signal strength is found, the reassociation is
> triggered. Otherwise the background scan is started again until the
> scan count reaches BG\_SCAN\_LIMIT.
> 
> If still AP is not found then Wi-Fi connection manager sends
> WLAN\_REASON\_BGSCAN\_NETWORK\_NOT\_FOUND event to application. In
> this case, if application again wants to use soft roaming then it can
> call this API again or use wlan\_set\_rssi\_low\_threshold API to set
> RSSI low threshold again.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>enable</em></td>
<td>Enable/Disable roaming.</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>rssi_low_threshold</em></td>
<td>RSSI low threshold value</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if the call was successful.
> 
> \-WM\_FAIL if failed.

#### int wlan\_get\_roaming\_status (void )

> Get the roaming status.

##### Returns

> 1 if roaming is enabled.
> 
> 0 if roaming is disbled.

#### int wlan\_wowlan\_config (uint8\_t *is\_mef*, t\_u32 *wake\_up\_conds*)

> Wowlan (wake on wireless LAN) configuration. This function may be
> called to configure host sleep in firmware.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>is_mef</em></td>
<td>Flag to indicate use MEF (memory efficient filtering) condition or not.</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>wake_up_conds</em></td>
<td>Bit map of default condition.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if the call was successful.
> 
> \-WM\_FAIL if failed.

#### void wlan\_config\_host\_sleep (bool *is\_manual*, t\_u8 *is\_periodic*)

> Host sleep configuration. This function may be called to configure
> host sleep in firmware.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>is_manual</em></td>
<td>Flag to indicate host enter low power mode with power manager or by command.</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>is_periodic</em></td>
<td>Flag to indicate host enter low power periodically or once with power manager.</td>
</tr>
</tbody>
</table>

#### status\_t wlan\_hs\_send\_event (int *id*, void \* *data*)

> This function sends host sleep events to mon\_thread

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>id</em></td>
<td>Event ID.</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>data</em></td>
<td>Pointer to event msg.</td>
</tr>
</tbody>
</table>

##### Returns

> kStatus\_Success if successful else return -WM\_FAIL.

#### void wlan\_cancel\_host\_sleep (void )

> Cancel host sleep. This function is called to cancel the host sleep in
> the firmware.

#### void wlan\_clear\_host\_sleep\_config (void )

> Clear host sleep configurations in driver. This function clears all
> the host sleep related configures in driver.

#### int wlan\_set\_multicast (t\_u8 *mef\_action*)

> This function set multicast MEF (memory efficient filtering) entry

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>mef_action</em></td>
<td>To be 0–discard and not wake host, 1–discard and wake host 3–allow and wake host.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if the call was successful.
> 
> \-WM\_FAIL if failed.

#### int wlan\_set\_ieeeps\_cfg (struct wlan\_ieeeps\_config \* *ps\_cfg*)

> Set configuration parameters of IEEE power save mode.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>ps_cfg</em></td>
<td>Power save configuration includes multiple parameters.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if the call was successful.
> 
> \-WM\_FAIL if failed.

#### void wlan\_configure\_listen\_interval (int *listen\_interval*)

> Configure listening interval of IEEE power save mode.

##### Note

> **Delivery traffic indication message (DTIM)** : It is a concept in
> 802.11 It is a time duration after which AP can send out buffered
> BROADCAST / MULTICAST data and stations connected to the AP should
> wakeup to take this broadcast / multicast data.
> 
> **Traffic Indication Map (TIM)** : It is a bitmap which the AP sends
> with each beacon. The bitmap has one bit each for a station connected
> to AP.
> 
> Each station is recognized by an association ID (AID). If AP has
> buffered data for a station, it will set corresponding bit of bitmap
> in TIM based on AID. Ideally AP does not buffer any unicast data it
> just sends unicast data to the station on every beacon when station is
> not sleeping.
> 
> When broadcast data / multicast data is to be send AP sets bit 0 of
> TIM indicating broadcast / multicast.
> 
> The occurrence of DTIM is defined by AP.
> 
> Each beacon has a number indicating period at which DTIM occurs.
> 
> The number is expressed in terms of number of beacons.
> 
> This period is called DTIM Period / DTIM interval.
> 
> For example:
> 
> If AP has DTIM period = 3 the stations connected to AP have to wake up
> (if they are sleeping) to receive broadcast /multicast data on every
> third beacon.
> 
> Generic:
> 
> When DTIM period is X AP buffers broadcast data / multicast data for X
> beacons. Then it transmits the data no matter whether station is awake
> or not.
> 
> Listen interval:
> 
> This is time interval on station side which indicates when station can
> be awake to listen i.e. accept data.
> 
> Long listen interval:
> 
> It comes into picture when station sleeps (IEEE PS) and it does not
> want to wake up on every DTIM So station is not worried about
> broadcast data/multicast data in this case.
> 
> This should be a design decision what should be chosen Firmware
> suggests values which are about 3 times DTIM at the max to gain
> optimal usage and reliability.
> 
> In the IEEE power save mode, the Wi-Fi firmware goes to sleep and
> periodically wakes up to check if the AP has any pending packets for
> it. A longer listen interval implies that the Wi-Fi SoC stays in power
> save for a longer duration at the cost of additional delays while
> receiving data. Note that choosing incorrect value for listen interval
> causes poor response from device during data transfer. Actual listen
> interval selected by firmware is equal to closest DTIM.
> 
> For example:
> 
> AP beacon period : 100 ms
> 
> AP DTIM period : 2
> 
> Application request value: 500ms
> 
> Actual listen interval = 400ms (This is the closest DTIM). Actual
> listen interval set should be a multiple of DTIM closest to but lower
> than the value provided by the application.
> 
> This API can be called before/after association. The configured listen
> interval can be used in subsequent association attempt.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>listen_interval</em></td>
<td><p>Listen interval as below</p>
<p>0 : Unchanged,</p>
<p>-1 : Disable,</p>
<p>1-49: Value in beacon intervals,</p>
<p>&gt;= 50: Value in TUs</p></td>
</tr>
</tbody>
</table>

#### void wlan\_configure\_delay\_to\_ps (unsigned int *timeout\_ms*)

> Set timeout configuration before Wi-Fi power save mode.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>timeout_ms</em></td>
<td>timout time, in milliseconds.</td>
</tr>
</tbody>
</table>

#### void wlan\_configure\_idle\_time (unsigned int *timeout\_ms*)

> Set timeout value before Wi-Fi enter deep sleep mode.
> 
> param \[in\] timeout\_ms: timout time, in milliseconds.

##### Note

> The minimum value of timeout\_ms is 100.

#### unsigned int wlan\_get\_idle\_time (void )

> Get timeout value of deep sleep mode, in milliseconds.

##### Returns

> idle time value.

#### unsigned short wlan\_get\_listen\_interval (void )

> Get listen interval .

##### Returns

> listen interval value.

#### unsigned int wlan\_get\_delay\_to\_ps (void )

> Get delay time for Wi-Fi power save mode.

##### Returns

> delay time value.

#### bool wlan\_is\_power\_save\_enabled (void )

> Check whether Wi-Fi power save is enabled or not.

##### Returns

> TRUE if Wi-Fi power save is enabled, else return FALSE.

#### void wlan\_configure\_null\_pkt\_interval (int *time\_in\_secs*)

> Configure NULL packet interval of IEEE power save mode.

##### Note

> In IEEE PS (power save), station sends a NULL packet to AP to indicate
> that the station is alive and maintain connection with the AP. If null
> packet is not sent some APs may disconnect station which might lead to
> a loss of connectivity. The time is specified in seconds. Default
> value is 30 seconds.
> 
> This API should be called before configuring IEEE Power save.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>time_in_secs</em></td>
<td>-1 Disables null packet transmission, 0 Null packet interval is unchanged, n Null packet interval in seconds.</td>
</tr>
</tbody>
</table>

#### int wlan\_set\_antcfg (uint32\_t *ant*, uint16\_t *evaluate\_time*, uint8\_t *evaluate\_mode*)

> This API can be used to set the mode of TX/RX antenna. If SAD
> (software antenna diversity) is enabled, this API can also be used to
> set SAD antenna evaluate time interval(antenna mode is antenna
> diversity when set SAD evaluate time interval).

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>ant</em></td>
<td>Antenna valid values are 1, 2 and 0xFFFF 1 : TX/RX antenna 1 2 : TX/RX antenna 2 0xFFFF: TX/RX antenna diversity</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>evaluate_time</em></td>
<td>SAD evaluate time interval, default value is 6s(0x1770).</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>evaluate_mode</em></td>
<td>0: PCB Ant + Ext Ant0 1: Ext Ant0 + Ext Ant1 2: PCB Ant + Ext Ant1 0xFF: Default divisity mode.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful.
> 
> WLAN\_ERROR\_STATE if unsuccessful.

#### int wlan\_get\_antcfg (uint32\_t \* *ant*, uint16\_t \* *evaluate\_time*, uint8\_t \* *evaluate\_mode*, uint16\_t \* *current\_antenna*)

> This API can be used to get the mode of TX/RX antenna. If SAD
> (software antenna diversity) is enabled, this API can also be used to
> get SAD antenna evaluate time interval(antenna mode is antenna
> diversity when set SAD evaluate time interval).

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>ant</em></td>
<td>pointer to antenna variable. antenna variable: 1 : TX/RX antenna 1 2 : TX/RX antenna 2 0xFFFF: TX/RX antenna diversity</td>
</tr>
<tr class="even">
<td>out</td>
<td><em>evaluate_time</em></td>
<td>pointer to evaluate_time variable for SAD.</td>
</tr>
<tr class="odd">
<td>out</td>
<td><em>current_mode</em></td>
<td>pointer to evaluate_mode. evaluate_mode: 0: PCB Ant + Ext Ant0 1: Ext Ant0 + Ext Ant1 2: PCB Ant + Ext Ant1 0xFF: Default divisity mode.</td>
</tr>
<tr class="even">
<td>out</td>
<td><em>current_antenna</em></td>
<td>pointer to current antenna.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful.
> 
> WLAN\_ERROR\_STATE if unsuccessful.

#### char\* wlan\_get\_firmware\_version\_ext (void )

> Get the Wi-Fi firmware version extension string.

##### Note

> This API does not allocate memory for pointer. It just returns pointer
> of WLCMGR internal static buffer. So no need to free the pointer by
> caller.

##### Returns

> Wi-Fi firmware version extension string pointer stored in WLCMGR

#### void wlan\_version\_extended (void )

> Use this API to print Wi-Fi driver and firmware extended version on
> console.

##### Note

> Call this API when SDK\_DEBUGCONSOLE not set to DEBUGCONSOLE\_DISABLE.

#### int wlan\_get\_tsf (uint32\_t \* *tsf\_high*, uint32\_t \* *tsf\_low*)

> Use this API to get the TSF (timing synchronization function) from
> Wi-Fi firmware.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>tsf_high</em></td>
<td>Pointer to store TSF higher 32bits.</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>tsf_low</em></td>
<td>Pointer to store TSF lower 32bits.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if operation is successful.
> 
> \-WM\_FAIL if command fails.

#### int wlan\_ieeeps\_on (unsigned int *wakeup\_conditions*)

> Enable IEEE power save with host sleep configuration
> 
> When enabled, Wi-Fi SoC is opportunistically put into IEEE power save
> mode. Before putting the Wi-Fi SoC in power save this also sets the
> host sleep configuration on the SoC as specified. This makes the SoC
> generate a wakeup for the processor if any of the wakeup conditions
> are met.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>wakeup_conditions</em></td>
<td>conditions to wake the host. This should be a logical OR of the conditions in wlan_wakeup_event_t. Typically devices would want to wake up on WAKE_ON_ALL_BROADCAST, WAKE_ON_UNICAST, WAKE_ON_MAC_EVENT. WAKE_ON_MULTICAST, WAKE_ON_ARP_BROADCAST, WAKE_ON_MGMT_FRAME</td>
</tr>
</tbody>
</table>

##### Note

> IEEE power save mode applies only when STA has connected to an AP. It
> could be enabled/disabled when STA connected or disconnected, but only
> take effect when STA has connected to an AP.

##### Returns

> WM\_SUCCESS if the call was successful.
> 
> \-WM\_FAIL otherwise.

#### int wlan\_ieeeps\_off (void )

> Turn off IEEE power save mode.

##### Note

> IEEE power save mode applies only when STA has connected to an AP. It
> could be enabled/disabled when STA connected or disconnected, but only
> take effect when STA has connected to an AP.

##### Returns

> WM\_SUCCESS if the call was successful.
> 
> \-WM\_FAIL otherwise.

#### int wlan\_deepsleepps\_on (void )

> Turn on deep sleep power save mode.

##### Note

> deep sleep power save mode only applies when STA disconnected. It
> could be enabled/disabled when STA connected or disconnected, but only
> take effect when STA disconnected.

##### Returns

> WM\_SUCCESS if the call was successful.
> 
> \-WM\_FAIL otherwise.

#### int wlan\_deepsleepps\_off (void )

> Turn off deep sleep power save mode.

##### Note

> deep sleep power save mode only applies when STA disconnected. It
> could be enabled/disabled when STA connected or disconnected, but only
> take effect when STA disconnected.

##### Returns

> WM\_SUCCESS if the call was successful.
> 
> \-WM\_FAIL otherwise.

#### int wlan\_tcp\_keep\_alive (wlan\_tcp\_keep\_alive\_t \* *keep\_alive*)

> Use this API to configure the TCP keep alive parameters in Wi-Fi
> firmware. wlan\_tcp\_keep\_alive\_t provides the parameters which are
> available for configuration.

##### Note

> To reset current TCP keep alive configuration, just set the reset
> member of wlan\_tcp\_keep\_alive\_t with value 1, all other parameters
> are ignored in this case.
> 
> This API is called after successful connection and before putting
> Wi-Fi SoC in IEEE power save mode.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>keep_alive</em></td>
<td>A pointer to wlan_tcp_keep_alive_t</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if operation is successful.
> 
> \-WM\_FAIL if command fails.

#### uint16\_t wlan\_get\_beacon\_period (void )

> Use this API to get the beacon period of associated BSS from the
> cached state information.

##### Returns

> beacon\_period if operation is successful.
> 
> 0 if command fails.

#### uint8\_t wlan\_get\_dtim\_period (void )

> Use this API to get the dtim period of associated BSS. When this API
> called, the radio sends a probe request to the AP for this
> information.

##### Returns

> dtim\_period if operation is successful.
> 
> 0 if DTIM IE is not found in AP's Probe response.

##### Note

> This API should not be called from Wi-Fi event handler registered by
> application during wlan\_start.

#### int wlan\_get\_data\_rate (wlan\_ds\_rate \* *ds\_rate*, mlan\_bss\_type *bss\_type*)

> Use this API to get the current TX and RX rates along with bandwidth
> and guard interval information if rate is 802.11n.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>ds_rate</em></td>
<td>A pointer to structure which has tx, RX rate information along with bandwidth and guard interval information.</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>bss_type</em></td>
<td>0: STA, 1: uAP</td>
</tr>
</tbody>
</table>

##### Note

> If rate is greater than 11 then it is 802.11n rate and from 12 MCS0
> rate starts. The bandwidth mapping is like value 0 is for 20MHz, 1 is
> 40MHz, 2 is for 80MHz. The guard interval value zero means Long
> otherwise Short.

##### Returns

> WM\_SUCCESS if operation is successful.
> 
> \-WM\_FAIL if command fails.

#### int wlan\_get\_pmfcfg (uint8\_t \* *mfpc*, uint8\_t \* *mfpr*)

> Use this API to get the management frame protection parameters for
> sta.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>mfpc</em></td>
<td>Management frame protection capable (MFPC) 1: Management frame protection capable 0: Management frame protection not capable</td>
</tr>
<tr class="even">
<td>out</td>
<td><em>mfpr</em></td>
<td>Management frame protection required (MFPR) 1: Management frame protection required 0: Management frame protection optional</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if operation is successful.
> 
> \-WM\_FAIL if command fails.

#### int wlan\_uap\_get\_pmfcfg (uint8\_t \* *mfpc*, uint8\_t \* *mfpr*)

> Use this API to get the set management frame protection parameters for
> uAP.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>mfpc</em></td>
<td>Management frame protection capable (MFPC) 1: management frame protection capable. 0: management frame protection not capable.</td>
</tr>
<tr class="even">
<td>out</td>
<td><em>mfpr</em></td>
<td>Management frame protection required (MFPR) 1: management frame protection required. 0: management frame protection optional.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if operation is successful.
> 
> \-WM\_FAIL if command fails.

#### int wlan\_set\_packet\_filters (wlan\_flt\_cfg\_t \* *flt\_cfg*)

> Use this API to set packet filters in Wi-Fi firmware.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>flt_cfg</em></td>
<td>A pointer to structure which holds the the packet filters wlan_flt_cfg_t.</td>
</tr>
</tbody>
</table>

##### Note

> For example:
> 
> MEF Configuration command
> 
> mefcfg={
> 
> Criteria: bit0-broadcast, bit1-unicast, bit3-multicast
> 
> Criteria=2 Unicast frames are received during host sleep mode
> 
> NumEntries=1 Number of activated MEF entries
> 
> mef\_entry\_0: example filters to match TCP destination port 80 send
> by 192.168.0.88 pkt or magic pkt.
> 
> mef\_entry\_0={
> 
> mode: bit0–hostsleep mode, bit1–non hostsleep mode
> 
> mode=1 HostSleep mode
> 
> action: 0–discard and not wake host, 1–discard and wake host 3–allow
> and wake host
> 
> action=3 Allow and Wake host
> 
> filter\_num=3 Number of filter
> 
> RPN only support "&&" and "||" operators, space cannot be removed
> between operators.
> 
> RPN=Filter\_0 && Filter\_1 || Filter\_2
> 
> Byte comparison filter's type is 0x41, decimal comparison filter's
> type is 0x42,
> 
> Bit comparison filter's type is 0x43
> 
> Filter\_0 is decimal comparison filter, it always with type=0x42
> 
> Decimal filter always has type, pattern, offset, numbyte 4 field
> 
> Filter\_0 matches RX packet with TCP destination port 80
> 
> Filter\_0={
> 
> type=0x42 decimal comparison filter
> 
> pattern=80 80 is the decimal constant to be compared
> 
> offset=44 44 is the byte offset of the field in RX pkt to be compare
> 
> numbyte=2 2 is the number of bytes of the field
> 
> }
> 
> Filter\_1 is Byte comparison filter, it always with type=0x41
> 
> Byte filter always has type, byte, repeat, offset 4 filed
> 
> Filter\_1 matches RX packet send by IP address 192.168.0.88
> 
> Filter\_1={
> 
> type=0x41 Byte comparison filter
> 
> repeat=1 1 copies of 'c0:a8:00:58'
> 
> byte=c0:a8:00:58 'c0:a8:00:58' is the byte sequence constant with each
> byte
> 
> in hex format, with ':' as delimiter between two byte.
> 
> offset=34 34 is the byte offset of the equal length field of rx'd pkt.
> 
> }
> 
> Filter\_2 is Magic packet, it can look for 16 contiguous copies of
> '00:50:43:20:01:02' from
> 
> the RX pkt's offset 14
> 
> Filter\_2={
> 
> type=0x41 Byte comparison filter
> 
> repeat=16 16 copies of '00:50:43:20:01:02'
> 
> byte=00:50:43:20:01:02 \# '00:50:43:20:01:02' is the byte sequence
> constant
> 
> offset=14 14 is the byte offset of the equal length field of rx'd pkt.
> 
> }
> 
> }
> 
> }
> 
> Above filters can be set by filling values in following way in
> wlan\_flt\_cfg\_t structure.
> 
> wlan\_flt\_cfg\_t flt\_cfg;
> 
> uint8\_t byte\_seq1\[\] = {0xc0, 0xa8, 0x00, 0x58};
> 
> uint8\_t byte\_seq2\[\] = {0x00, 0x50, 0x43, 0x20, 0x01, 0x02};
> 
> memset(\&flt\_cfg, 0, sizeof(wlan\_flt\_cfg\_t));
> 
> flt\_cfg.criteria = 2;
> 
> flt\_cfg.nentries = 1;
> 
> flt\_cfg.mef\_entry.mode = 1;
> 
> flt\_cfg.mef\_entry.action = 3;
> 
> flt\_cfg.mef\_entry.filter\_num = 3;
> 
> flt\_cfg.mef\_entry.filter\_item\[0\].type = TYPE\_DNUM\_EQ;
> 
> flt\_cfg.mef\_entry.filter\_item\[0\].pattern = 80;
> 
> flt\_cfg.mef\_entry.filter\_item\[0\].offset = 44;
> 
> flt\_cfg.mef\_entry.filter\_item\[0\].num\_bytes = 2;
> 
> flt\_cfg.mef\_entry.filter\_item\[1\].type = TYPE\_BYTE\_EQ;
> 
> flt\_cfg.mef\_entry.filter\_item\[1\].repeat = 1;
> 
> flt\_cfg.mef\_entry.filter\_item\[1\].offset = 34;
> 
> flt\_cfg.mef\_entry.filter\_item\[1\].num\_byte\_seq = 4;
> 
> memcpy(flt\_cfg.mef\_entry.filter\_item\[1\].byte\_seq, byte\_seq1,
> 4);
> 
> flt\_cfg.mef\_entry.rpn\[1\] = RPN\_TYPE\_AND;
> 
> flt\_cfg.mef\_entry.filter\_item\[2\].type = TYPE\_BYTE\_EQ;
> 
> flt\_cfg.mef\_entry.filter\_item\[2\].repeat = 16;
> 
> flt\_cfg.mef\_entry.filter\_item\[2\].offset = 14;
> 
> flt\_cfg.mef\_entry.filter\_item\[2\].num\_byte\_seq = 6;
> 
> memcpy(flt\_cfg.mef\_entry.filter\_item\[2\].byte\_seq, byte\_seq2,
> 6);
> 
> flt\_cfg.mef\_entry.rpn\[2\] = RPN\_TYPE\_OR;

##### Returns

> WM\_SUCCESS if operation is successful.
> 
> \-WM\_FAIL if command fails.

#### int wlan\_set\_auto\_arp (void )

> Use this API to enable ARP (address resolution protocol) offload in
> Wi-Fi firmware

##### Returns

> WM\_SUCCESS if operation is successful.
> 
> \-WM\_FAIL if command fails.

#### int wlan\_wowlan\_cfg\_ptn\_match (wlan\_wowlan\_ptn\_cfg\_t \* *ptn\_cfg*)

> Use this API to enable WOWLAN (wake-on-wireless-LAN) on magic packet
> RX in Wi-Fi firmware

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>ptn_cfg</em></td>
<td>A pointer to wlan_wowlan_ptn_cfg_t containing wake on Wi-Fi pattern configuration</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if operation is successful.
> 
> \-WM\_FAIL if command fails

#### int wlan\_set\_ipv6\_ns\_offload (void )

> Use this API to enable NS offload in Wi-Fi firmware.

##### Returns

> WM\_SUCCESS if operation is successful.
> 
> \-WM\_FAIL if command fails.

#### void wlan\_hs\_pre\_cfg (void )

> Use this API to set configuration before going to host sleep

#### void wlan\_hs\_post\_cfg (void )

> Use this API to get and print the reason of waking up from host sleep

#### int wlan\_send\_host\_sleep (uint32\_t *wakeup\_condition*)

> Use this API to configure host sleep parameters in Wi-Fi firmware.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>wakeup_condition</em></td>
<td>bit 0: WAKE_ON_ALL_BROADCAST bit 1: WAKE_ON_UNICAST bit 2: WAKE_ON_MAC_EVENT bit 3: WAKE_ON_MULTICAST bit 4: WAKE_ON_ARP_BROADCAST bit 6: WAKE_ON_MGMT_FRAME All bit 0 discard and not wakeup host</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if operation is successful.
> 
> \-WM\_FAIL if command fails.

#### int wlan\_get\_wakeup\_reason (uint16\_t \* *hs\_wakeup\_reason*)

> Use this API to get host sleep wakeup reason from Wi-Fi firmware after
> waking up from host sleep by Wi-Fi.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>hs_wakeup_reason</em></td>
<td>wakeupReason: 0: unknown 1: Broadcast data matched 2: Multicast data matched 3: Unicast data matched 4: Maskable event matched</td>
</tr>
</tbody>
</table>

1\. Non-maskable event matched 6: Non-maskable condition matched (EAPoL
rekey) 7: Magic pattern matched Others: reserved. (set to 0)

<table>
<tbody>
<tr class="odd">
<td></td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if operation is successful.
> 
> \-WM\_FAIL if command fails.

#### int wlan\_get\_current\_bssid (uint8\_t \* *bssid*)

> Use this API to get the BSSID of associated BSS when in station mode.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>bssid</em></td>
<td>A pointer to array(char, length is 6) to store the BSSID.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if operation is successful.
> 
> \-WM\_FAIL if command fails.

#### uint8\_t wlan\_get\_current\_channel (void )

> Use this API to get the channel number of associated BSS.

##### Returns

> channel number if operation is successful.
> 
> 0 if command fails.

#### int wlan\_get\_log (wlan\_pkt\_stats\_t \* *stats*)

> Use this API to get the various statistics of STA from Wi-Fi firmware

##### Parameters

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

##### Returns

> WM\_SUCCESS if operation is successful.
> 
> \-WM\_FAIL if command fails.

#### int wlan\_uap\_get\_log (wlan\_pkt\_stats\_t \* *stats*)

> Use this API to get the various statistics of the uAP from Wi-Fi
> firmware.

##### Parameters

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

##### Returns

> WM\_SUCCESS if operation is successful.
> 
> \-WM\_FAIL if command fails.

#### int wlan\_get\_ps\_mode (enum wlan\_ps\_mode \* *ps\_mode*)

> Get station interface power save mode.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>ps_mode</em></td>
<td>A pointer to wlan_ps_mode where station interface power save mode should be stored.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful.
> 
> \-WM\_E\_INVAL if *ps\_mode* was NULL.

#### int wlan\_get\_ps\_mode\_cfg (uint8\_t \* *ps\_mode\_cfg*)

> Get station interface power save configuration.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>ps_mode_cfg</em></td>
<td>A pointer to variable that stores power save mode configuration.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful.
> 
> \-WM\_E\_INVAL if *ps\_mode\_cfg* was NULL.

#### int wlan\_wlcmgr\_send\_msg (enum wifi\_event *event*, enum wifi\_event\_reason *reason*, void \* *data*)

> Send message to Wi-Fi connection manager thread.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>event</em></td>
<td>An event from wifi_event.</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>reason</em></td>
<td>A reason code.</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>data</em></td>
<td>A pointer to data buffer associated with event.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful.
> 
> \-WM\_FAIL if failed.

#### int wlan\_wfa\_basic\_cli\_init (void )

> Register WFA basic Wi-Fi CLI (command line input) commands
> 
> This function registers basic Wi-Fi CLI commands like showing version
> information, MAC address.

##### Note

> This function can only be called by the application after wlan\_init()
> called.

##### Returns

> WLAN\_ERROR\_NONE if the CLI commands were registered or
> 
> WLAN\_ERROR\_ACTION if they were not registered (for example if this
> function was called while the CLI commands were already registered).

#### int wlan\_wfa\_basic\_cli\_deinit (void )

> Unregister WFA basic Wi-Fi CLI (command line input) commands
> 
> This function unregisters basic Wi-Fi CLI commands like showing
> version information, MAC address.

##### Note

> This function can only be called by the application after wlan\_init()
> called.

##### Returns

> WLAN\_ERROR\_NONE if the CLI commands were unregistered or
> 
> WLAN\_ERROR\_ACTION if they were not unregistered

#### int wlan\_basic\_cli\_init (void )

> Register basic Wi-Fi CLI (command line input) commands
> 
> This function registers basic Wi-Fi CLI commands like showing version
> information, MAC address.

##### Note

> This function can only be called by the application after wlan\_init()
> called.
> 
> This function gets called by wlan\_cli\_init(), hence only one
> function out of these two functions should be called in the
> application.

##### Returns

> WLAN\_ERROR\_NONE if the CLI commands were registered
> 
> WLAN\_ERROR\_ACTION if they were not registered (for example if this
> function was called while the CLI commands were already registered).

#### int wlan\_basic\_cli\_deinit (void )

> Unregister basic Wi-Fi CLI commands
> 
> This function unregisters basic Wi-Fi CLI commands like showing
> version information, MAC address.

##### Note

> This function gets called by wlan\_cli\_deinit(), hence only one
> function out of these two functions should be called in the
> application.

##### Returns

> WLAN\_ERROR\_NONE if the CLI commands were unregistered
> 
> WLAN\_ERROR\_ACTION if they were not unregistered (for example if this
> function was called while the CLI commands were not registered or were
> already unregistered).

#### int wlan\_cli\_init (void )

> Register Wi-Fi CLI (command line input) commands.
> 
> Try to register the Wi-Fi CLI commands with the CLI subsystem. This
> function is available for the application for use.

##### Note

> This function can only be called by the application after wlan\_init()
> called.
> 
> This function internally calls wlan\_basic\_cli\_init(), hence only
> one function out of these two functions should be called in the
> application.

##### Returns

> WM\_SUCCESS if the CLI commands were registered or
> 
> \-WM\_FAIL if they were not (for example if this function was called
> while the CLI commands were already registered).

#### int wlan\_cli\_deinit (void )

> Unregister Wi-Fi CLI commands.
> 
> Try to unregister the Wi-Fi CLI commands with the CLI subsystem. This
> function is available for the application for use.

##### Note

> This function can only be called by the application after wlan\_init()
> called.
> 
> This function internally calls wlan\_basic\_cli\_deinit(), hence only
> one function out of these two functions should be called in the
> application.

##### Returns

> WM\_SUCCESS if the CLI commands were unregistered or
> 
> \-WM\_FAIL if they were not (for example if this function was called
> while the CLI commands were already unregistered).

#### int wlan\_enhanced\_cli\_init (void )

> Register Wi-Fi enhanced CLI commands.
> 
> Register the Wi-Fi enhanced CLI commands like set or get tx-power,
> tx-datarate, tx-modulation etc. with the CLI subsystem.

##### Note

> This function can only be called by the application after wlan\_init()
> called.

##### Returns

> WM\_SUCCESS if the CLI commands were registered or
> 
> \-WM\_FAIL if they were not (for example if this function was called
> while the CLI commands were already registered).

#### int wlan\_enhanced\_cli\_deinit (void )

> Unregister Wi-Fi enhanced CLI commands.
> 
> Unregister the Wi-Fi enhanced CLI commands like set or get tx-power,
> tx-datarate, tx-modulation etc. with the CLI subsystem.

##### Note

> This function can only be called by the application after wlan\_init()
> called.

##### Returns

> WM\_SUCCESS if the CLI commands were unregistered or
> 
> \-WM\_FAIL if they were not unregistered.

#### unsigned int wlan\_get\_uap\_supported\_max\_clients (void )

> Get maximum number of the stations Wi-Fi firmware supported that can
> be allowed to connect to the uAP.

##### Returns

> Maximum number of the stations Wi-Fi firmware supported that can be
> allowed to connect to the uAP.

##### Note

> Get operation is allowed in any uAP state.

#### int wlan\_get\_uap\_max\_clients (unsigned int \* *max\_sta\_num*)

> Get current maximum number of the stations that can be allowed to
> connect to the uAP.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>max_sta_num</em></td>
<td>A pointer to variable where current maximum number of the stations of the uAP interface can be stored.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful.
> 
> \-WM\_FAIL if unsuccessful.

##### Note

> Get operation is allowed in any uAP state.

#### int wlan\_set\_uap\_max\_clients (unsigned int *max\_sta\_num*)

> Set maximum number of the stations that can be allowed to connect to
> the uAP.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>max_sta_num</em></td>
<td>Number of maximum stations for uAP.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful.
> 
> \-WM\_FAIL if unsuccessful.

##### Note

> Set operation in not allowed in WLAN\_UAP\_STARTED state.

#### int wlan\_set\_htcapinfo (unsigned int *htcapinfo*)

> Use this API to configure some of parameters in HT capability
> information IE (such as short GI, channel bandwidth, and green field
> support)

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>htcapinfo</em></td>
<td><p>This is a bitmap and should be used as following</p>
<p>Bit 29: Green field Enable/Disable</p>
<p>Bit 26: RX STBC Support Enable/Disable. (As we support</p>
<p>single spatial stream only 1 bit is used for RX STBC)</p>
<p>Bit 25: TX STBC support Enable/Disable.</p>
<p>Bit 24: Short GI in 40 Mhz Enable/Disable</p>
<p>Bit 23: Short GI in 20 Mhz Enable/Disable</p>
<p>Bit 22: RX LDPC Enable/Disable</p>
<p>Bit 17: 20/40 Mhz enable disable.</p>
<p>Bit 8: Enable/Disable 40Mhz intolerant bit in HT capinfo.</p>
<p>0 can reset this bit and 1 can set this bit in</p>
<p>htcapinfo attached in association request.</p>
<p>All others are reserved and should be set to 0.</p></td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful.
> 
> \-WM\_FAIL if unsuccessful.

#### int wlan\_set\_httxcfg (unsigned short *httxcfg*)

> Use this API to configure various 802.11n specific configuration for
> transmit (such as short GI, channel bandwidth and green field support)

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>httxcfg</em></td>
<td><p>This is a bitmap and should be used as following</p>
<p>Bit 15-10: Reserved set to 0</p>
<p>Bit 9-8: RX STBC set to 0x01</p>
<p>BIT9 BIT8 Description</p>
<p>0 0 No spatial streams</p>
<p>0 1 One spatial stream supported</p>
<p>1 0 Reserved</p>
<p>1 1 Reserved</p>
<p>Bit 7: STBC Enable/Disable</p>
<p>Bit 6: Short GI in 40 Mhz Enable/Disable</p>
<p>Bit 5: Short GI in 20 Mhz Enable/Disable</p>
<p>Bit 4: Green field Enable/Disable</p>
<p>Bit 3-2: Reserved set to 1</p>
<p>Bit 1: 20/40 Mhz enable disable.</p>
<p>Bit 0: LDPC Enable/Disable</p>
<p>When Bit 1 is set then firmware could transmit in 20Mhz or 40Mhz based</p>
<p>on rate adaptation. When this bit is reset then firmware can only</p>
<p>transmit in 20Mhz.</p></td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful.
> 
> \-WM\_FAIL if unsuccessful.

#### int wlan\_set\_txratecfg (wlan\_ds\_rate *ds\_rate*, mlan\_bss\_type *bss\_type*)

> Use this API to set the transmit data rate.

##### Note

> The data rate can be set only after association.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>ds_rate</em></td>
<td><p>struct contains following fields sub_command It should be WIFI_DS_RATE_CFG and rate_cfg should have following parameters.</p>
<p>rate_format - This parameter specifies the data rate format used in this command</p>
<p>0: LG</p>
<p>1: HT</p>
<p>2: VHT</p>
<p>0xff: Auto</p>
<p>index - This parameter specifies the rate or MCS index</p>
<p>If rate_format is 0 (LG),</p>
<p>0 1 Mbps</p>
<p>1 2 Mbps</p>
<p>2 5.5 Mbps</p>
<p>3 11 Mbps</p>
<p>4 6 Mbps</p>
<p>5 9 Mbps</p>
<p>6 12 Mbps</p>
<p>7 18 Mbps</p>
<p>8 24 Mbps</p>
<p>9 36 Mbps</p>
<p>10 48 Mbps</p>
<p>11 54 Mbps</p>
<p>If rate_format is 1 (HT),</p>
<p>0 MCS0</p>
<p>1 MCS1</p>
<p>2 MCS2</p>
<p>3 MCS3</p>
<p>4 MCS4</p>
<p>5 MCS5</p>
<p>6 MCS6</p>
<p>7 MCS7</p>
<p>If STREAM_2X2</p>
<p>8 MCS8</p>
<p>9 MCS9</p>
<p>10 MCS10</p>
<p>11 MCS11</p>
<p>12 MCS12</p>
<p>13 MCS13</p>
<p>14 MCS14</p>
<p>15 MCS15</p>
<p>If rate_format is 2 (VHT),</p>
<p>0 MCS0</p>
<p>1 MCS1</p>
<p>2 MCS2</p>
<p>3 MCS3</p>
<p>4 MCS4</p>
<p>5 MCS5</p>
<p>6 MCS6</p>
<p>7 MCS7</p>
<p>8 MCS8</p>
<p>9 MCS9</p>
<p>nss - This parameter specifies the NSS.</p>
<p>It is valid only for VHT</p>
<p>If rate_format is 2 (VHT),</p>
<p>1 NSS1</p>
<p>2 NSS2</p></td>
</tr>
<tr class="even">
<td>in</td>
<td><em>bss_type</em></td>
<td>0: STA, 1: uAP</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful.
> 
> \-WM\_FAIL if unsuccessful.

#### int wlan\_get\_txratecfg (wlan\_ds\_rate \* *ds\_rate*, mlan\_bss\_type *bss\_type*)

> Use this API to get the transmit data rate.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>ds_rate</em></td>
<td>A pointer to wlan_ds_rate where TX Rate configuration can be stored.</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>bss_type</em></td>
<td>0: STA, 1: uAP</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful.
> 
> \-WM\_FAIL if unsuccessful.

#### int wlan\_get\_sta\_tx\_power (t\_u32 \* *power\_level*)

> Get station transmit power

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>power_level</em></td>
<td>Transmit power level (unit: dBm).</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful.
> 
> \-WM\_FAIL if unsuccessful.

#### int wlan\_set\_sta\_tx\_power (t\_u32 *power\_level*)

> Set station transmit power

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>power_level</em></td>
<td>Transmit power level (unit: dBm).</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful.
> 
> \-WM\_FAIL if unsuccessful.

#### int wlan\_set\_wwsm\_txpwrlimit (void )

> Set worldwide safe mode TX power limits. Set TX power limit and ru TX
> power limit according to the region code. TX power limit:
> rg\_power\_cfg\_rw610 ru TX power limit: ru\_power\_cfg\_rw610

##### Returns

> WM\_SUCCESS if successful.
> 
> \-WM\_FAIL if unsuccessful.

#### int wlan\_get\_mgmt\_ie (enum wlan\_bss\_type *bss\_type*, IEEEtypes\_ElementId\_t *index*, void \* *buf*, unsigned int \* *buf\_len*)

> Get Management IE for given BSS type (interface) and index.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>bss_type</em></td>
<td>0: STA, 1: uAP</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>index</em></td>
<td>IE index.</td>
</tr>
<tr class="odd">
<td>out</td>
<td><em>buf</em></td>
<td>Buffer to store requested IE data.</td>
</tr>
<tr class="even">
<td>out</td>
<td><em>buf_len</em></td>
<td>Length of IE data.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful.
> 
> \-WM\_FAIL if unsuccessful.

#### int wlan\_set\_mgmt\_ie (enum wlan\_bss\_type *bss\_type*, IEEEtypes\_ElementId\_t *id*, void \* *buf*, unsigned int *buf\_len*)

> Set management IE for given BSS type (interface) and index.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>bss_type</em></td>
<td>0: STA, 1: uAP</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>id</em></td>
<td>Type/ID of Management IE.</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>buf</em></td>
<td>Buffer containing IE data.</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>buf_len</em></td>
<td>Length of IE data.</td>
</tr>
</tbody>
</table>

##### Returns

> Management IE index if successful.
> 
> \-WM\_FAIL if unsuccessful.

#### int wlan\_clear\_mgmt\_ie (enum wlan\_bss\_type *bss\_type*, IEEEtypes\_ElementId\_t *index*, int *mgmt\_bitmap\_index*)

> Clear management IE for given BSS type (interface) and index.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>bss_type</em></td>
<td>0: STA, 1: uAP</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>index</em></td>
<td>IE index.</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>mgmt_bitmap_index</em></td>
<td>management bitmap index.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful.
> 
> \-WM\_FAIL if unsuccessful.

#### bool wlan\_get\_11d\_enable\_status (void )

> Get current status of 802.11d support.

##### Returns

> true if 802.11d support is enabled by application.
> 
> false if not enabled.

#### int wlan\_get\_current\_signal\_strength (short \* *rssi*, int \* *snr*)

> Get current RSSI and signal to noise ratio from Wi-Fi firmware.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>RSSI</em></td>
<td>A pointer to variable to store current RSSI</td>
</tr>
<tr class="even">
<td>out</td>
<td><em>snr</em></td>
<td>A pointer to variable to store current SNR.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful.

#### int wlan\_get\_average\_signal\_strength (short \* *rssi*, int \* *snr*)

> Get average RSSI and signal to noise ratio (average value of the
> former 8 packets) from Wi-Fi firmware.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>RSSI</em></td>
<td>A pointer to variable to store current RSSI</td>
</tr>
<tr class="even">
<td>out</td>
<td><em>snr</em></td>
<td>A pointer to variable to store current SNR.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful.

#### int wlan\_remain\_on\_channel (const enum wlan\_bss\_type *bss\_type*, const bool *status*, const uint8\_t *channel*, const uint32\_t *duration*)

> This API is used to set/cancel the remain on channel configuration.

##### Note

> When status is false, channel and duration parameters are ignored.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>bss_type</em></td>
<td>The interface to set channel bss_type 0: STA, 1: uAP</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>status</em></td>
<td>false : Cancel the remain on channel configuration true : Set the remain on channel configuration</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>channel</em></td>
<td>The channel to configure</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>duration</em></td>
<td>The duration for which to remain on channel in milliseconds.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS on success or error code.

#### int wlan\_get\_otp\_user\_data (uint8\_t \* *buf*, uint16\_t *len*)

> Get user data from OTP (one-time pramming) memory

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>buf</em></td>
<td>Pointer to buffer where data should be stored</td>
</tr>
<tr class="even">
<td>out</td>
<td><em>len</em></td>
<td>Number of bytes to read</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if user data read operation is successful.
> 
> \-WM\_E\_INVAL if buf is not valid or of insufficient size.
> 
> \-WM\_FAIL if user data field is not present or command fails.

#### int wlan\_get\_cal\_data (wlan\_cal\_data\_t \* *cal\_data*)

> Get calibration data from Wi-Fi firmware.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>cal_data</em></td>
<td>Pointer to calibration data structure where calibration data and it's length should be stored.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if calibration data read operation is successful.
> 
> \-WM\_E\_INVAL if cal\_data is not valid.
> 
> \-WM\_FAIL if command fails.

##### Note

> The user of this API should free the allocated buffer for calibration
> data.

#### int wlan\_set\_region\_power\_cfg (const t\_u8 \* *data*, t\_u16 *len*)

> Set the compressed (use LZW algorithm) TX power limit configuration.

##### Parameters

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

##### Returns

> WM\_SUCCESS on success, error otherwise.

#### int wlan\_set\_chanlist\_and\_txpwrlimit (wlan\_chanlist\_t \* *chanlist*, wlan\_txpwrlimit\_t \* *txpwrlimit*)

> Set the TRPC (transient receptor potential canonical) channel list and
> TX power limit configuration.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>chanlist</em></td>
<td>A poiner to wlan_chanlist_t channel List configuration.</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>txpwrlimit</em></td>
<td>A pointer to wlan_txpwrlimit_t TX power limit configuration.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS on success, error otherwise.

#### int wlan\_set\_chanlist (wlan\_chanlist\_t \* *chanlist*)

> Set the channel list configuration wlan\_chanlist\_t.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>chanlist</em></td>
<td>A pointer to wlan_chanlist_t channel list configuration.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS on success, error otherwise.

##### Note

> If region enforcement flag is enabled in the OTP then this API should
> not take effect.

#### int wlan\_get\_chanlist (wlan\_chanlist\_t \* *chanlist*)

> Get the channel list configuration.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>chanlist</em></td>
<td>A pointer to wlan_chanlist_t channel list configuration.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS on success, error otherwise.

##### Note

> The wlan\_chanlist\_t struct allocates memory for a maximum of 54.
> channels.

#### int wlan\_set\_txpwrlimit (wlan\_txpwrlimit\_t \* *txpwrlimit*)

> Set the TRPC (transient receptor potential canonical) channel
> configuration.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>txpwrlimit</em></td>
<td>A pointer to wlan_txpwrlimit_t TX power limit configuration.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS on success, error otherwise.

#### int wlan\_get\_txpwrlimit (wifi\_SubBand\_t *subband*, wifi\_txpwrlimit\_t \* *txpwrlimit*)

> Get the TRPC (transient receptor potential canonical) channel
> configuration.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>subband</em></td>
<td><p>Where subband is:</p>
<p>0x00 2G subband (2.4G: channel 1-14)</p>
<p>0x10 5G subband0 (5G: channel 36,40,44,48,</p>
<p>52,56,60,64)</p>
<p>0x11 5G subband1 (5G: channel 100,104,108,112,</p>
<p>116,120,124,128,</p>
<p>132,136,140,144)</p>
<p>0x12 5G subband2 (5G: channel 149,153,157,161,165,172)</p>
<p>0x13 5G subband3 (5G: channel 183,184,185,187,188,</p>
<p>189, 192,196;</p>
<p>5G: channel 7,8,11,12,16,34)</p></td>
</tr>
<tr class="even">
<td>out</td>
<td><em>txpwrlimit</em></td>
<td>A pointer to wlan_txpwrlimit_t TX power Limit configuration structure where Wi-Fi firmware configuration can get copied.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS on success, error otherwise.

##### Note

> application can use print\_txpwrlimit API to print the content of the
> txpwrlimit structure.

#### void wlan\_set\_reassoc\_control (bool *reassoc\_control*)

> Set reassociation control in Wi-Fi connection manager. When
> reassociation control enabled, Wi-Fi connection manager attempts
> reconnection with the network for WLAN\_RECONNECT\_LIMIT times before
> giving up.

##### Note

> Reassociation is enabled by default in the Wi-Fi connection manager.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>reassoc_control</em></td>
<td>Reassociation enable/disable</td>
</tr>
</tbody>
</table>

#### void wlan\_uap\_set\_beacon\_period (const uint16\_t *beacon\_period*)

> API to set the beacon period of the uAP

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>beacon_period</em></td>
<td>Beacon period in TU (1 TU = 1024 microseconds)</td>
</tr>
</tbody>
</table>

##### Note

> Call this API before calling uAP start API.

#### int wlan\_uap\_set\_bandwidth (const uint8\_t *bandwidth*)

> API to set the bandwidth of the uAP

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>bandwidth</em></td>
<td><p>Wi-Fi AP bandwidth</p>
<p>1: 20 MHz 2: 40 MHz 3: 80 MHz</p></td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.
> 
> \-WM\_FAIL if command fails.

##### Note

> Not applicable to 20MHZ only chip sets (Redfinch, SD8801)
> 
> Call this API before calling uAP start API.
> 
> Default bandwidth setting is 40 MHz.

#### int wlan\_uap\_get\_bandwidth (uint8\_t \* *bandwidth*)

> API to get the bandwidth of the uAP

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>bandwidth</em></td>
<td>Wi-Fi AP bandwidth 1: 20 MHz 2: 40 MHz 3: 80 MHz</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.
> 
> \-WM\_FAIL if command fails.

##### Note

> Call this API before calling uAP start API.

#### int wlan\_uap\_set\_hidden\_ssid (const t\_u8 *hidden\_ssid*)

> API to control SSID broadcast capability of the uAP
> 
> This API enables/disables the SSID broadcast feature (also known as
> the hidden SSID feature). When broadcast SSID is enabled, the AP
> responds to probe requests from client stations that contain null
> SSID. When broadcast SSID is disabled, the AP does not respond to
> probe requests that contain null SSID and generates beacons that
> contain null SSID.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>hidden_ssid</em></td>
<td>Hidden SSID control hidden_ssid=0: broadcast SSID in beacons. hidden_ssid=1: send empty SSID (length=0) in beacon. hidden_ssid=2: clear SSID (ACSII 0), but keep the original length</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.
> 
> \-WM\_FAIL if command fails.

##### Note

> Call this API before calling uAP start API.

#### void wlan\_uap\_ctrl\_deauth (const bool *enable*)

> API to control the deauthentication during uAP channel switch.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>enable</em></td>
<td>0 – Wi-Fi firmware can use default behavior, send deauth packet when uAP move to another channel. 1 – Wi-Fi firmware cannot send deauth packet when uAP move to another channel.</td>
</tr>
</tbody>
</table>

##### Note

> Call this API before calling uAP start API.

#### void wlan\_uap\_set\_ecsa (void )

> API to enable channel switch announcement functionality on uAP.

##### Note

> Call this API before calling uAP start API. Also note that 802.11n
> should be enabled on uAP. The channel switch announcement IE is
> transmitted in 7 beacons before the channel switch, during a station
> connection attempt on a different channel with Ex-AP.

#### void wlan\_uap\_set\_htcapinfo (const uint16\_t *ht\_cap\_info*)

> API to set the HT capability information of the uAP.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>ht_cap_info</em></td>
<td><p>- This is a bitmap and should be used as following</p>
<p>Bit 15: L Sig TxOP protection - reserved, set to 0</p>
<p>Bit 14: 40 MHz intolerant - reserved, set to 0</p>
<p>Bit 13: PSMP - reserved, set to 0</p>
<p>Bit 12: DSSS Cck40MHz mode</p>
<p>Bit 11: Maximal A-MSDU size - reserved, set to 0</p>
<p>Bit 10: Delayed BA - reserved, set to 0</p>
<p>Bits 9:8: RX STBC - reserved, set to 0</p>
<p>Bit 7: TX STBC - reserved, set to 0</p>
<p>Bit 6: Short GI 40 MHz</p>
<p>Bit 5: Short GI 20 MHz</p>
<p>Bit 4: GF preamble</p>
<p>Bits 3:2: MIMO power save - reserved, set to 0</p>
<p>Bit 1: SuppChanWidth - set to 0 for 2.4 GHz band</p>
<p>Bit 0: LDPC coding - reserved, set to 0</p></td>
</tr>
</tbody>
</table>

##### Note

> Call this API before calling uAP start API.

#### void wlan\_uap\_set\_httxcfg (unsigned short *httxcfg*)

> This API can be used to configure various 802.11n specific
> configuration for transmit (such as short GI, channel bandwidth and
> green field support) for uAP interface.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>httxcfg</em></td>
<td><p>This is a bitmap and should be used as following</p>
<p>Bit 15-8: Reserved set to 0</p>
<p>Bit 7: STBC Enable/Disable</p>
<p>Bit 6: Short GI in 40 Mhz Enable/Disable</p>
<p>Bit 5: Short GI in 20 Mhz Enable/Disable</p>
<p>Bit 4: Green field Enable/Disable</p>
<p>Bit 3-2: Reserved set to 1</p>
<p>Bit 1: 20/40 Mhz enable disable.</p>
<p>Bit 0: LDPC Enable/Disable</p>
<p>When Bit 1 is set then firmware could transmit in 20Mhz or 40Mhz based</p>
<p>on rate adaptation. When this bit is reset then firmware can only</p>
<p>transmit in 20Mhz.</p></td>
</tr>
</tbody>
</table>

##### Note

> Call this API before calling uAP start API.

#### void wlan\_sta\_ampdu\_tx\_enable (void )

> This API can be used to enable AMPDU support when station is a
> transmitter.

##### Note

> By default the station AMPDU TX support is enabled if configuration
> option CONFIG\_STA\_AMPDU\_TX is defined 1.

#### void wlan\_sta\_ampdu\_tx\_disable (void )

> This API can be used to disable AMPDU support when station is a
> transmitter.

##### Note

> By default the station AMPDU TX support is enabled if configuration
> option CONFIG\_STA\_AMPDU\_TX is defined 1.

#### void wlan\_sta\_ampdu\_rx\_enable (void )

> This API can be used to enable AMPDU support when station is a
> receiver.

##### Note

> By default the station AMPDU RX support is enabled if configuration
> option CONFIG\_STA\_AMPDU\_RX is defined 1.

#### void wlan\_sta\_ampdu\_rx\_disable (void )

> This API can be used to disable AMPDU support when station is a
> receiver.

##### Note

> By default the station AMPDU RX support is enabled if configuration
> option CONFIG\_STA\_AMPDU\_RX is defined 1.

#### void wlan\_uap\_ampdu\_tx\_enable (void )

> This API can be used to enable AMPDU support when uAP is a
> transmitter.

##### Note

> By default the uAP AMPDU TX support is enabled if configuration option
> CONFIG\_UAP\_AMPDU\_TX is defined 1.

#### void wlan\_uap\_ampdu\_tx\_disable (void )

> This API can be used to disable AMPDU support when uAP is a
> transmitter.

##### Note

> By default the uAP AMPDU TX support is enabled if configuration option
> CONFIG\_UAP\_AMPDU\_TX is defined 1.

#### void wlan\_uap\_ampdu\_rx\_enable (void )

> This API can be used to enable AMPDU support when uAP is a receiver.

##### Note

> By default the uAP AMPDU TX support is enabled if configuration option
> CONFIG\_UAP\_AMPDU\_RX is defined 1.

#### void wlan\_uap\_ampdu\_rx\_disable (void )

> This API can be used to disable AMPDU support when uAP is a receiver.

##### Note

> By default the uAP AMPDU TX support is enabled if configuration option
> CONFIG\_UAP\_AMPDU\_RX is defined 1.

#### void wlan\_uap\_set\_scan\_chan\_list (wifi\_scan\_chan\_list\_t *scan\_chan\_list*)

> Set number of channels and channel number used during automatic
> channel selection of the uAP.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>scan_chan_list</em></td>
<td>A structure holding the number of channels and channel numbers.</td>
</tr>
</tbody>
</table>

##### Note

> Call this API before uAP start API in order to set the user defined
> channels, otherwise it can have no effect. There is no need to call
> this API every time before uAP start, if once set same channel
> configuration can get used in all upcoming uAP start call. If user
> wish to change the channels at run time then it make sense to call
> this API before every uAP start API.

#### int wlan\_set\_rts (int *rts*)

> Set the RTS(Request to Send) threshold of STA in Wi-Fi firmware.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>rts</em></td>
<td>the value of rts threshold configuration.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_set\_uap\_rts (int *rts*)

> Set the RTS(Request to Send) threshold of the uAP in Wi-Fi firmware.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>rts</em></td>
<td>the value of rts threshold configuration.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_set\_frag (int *frag*)

> Set the fragment threshold of STA in Wi-Fi firmware. If the size of
> packet exceeds the fragment threshold, the packet is divided into
> fragments. For example, if the fragment threshold is set to 300, a
> ping packet of size 1300 is divided into 5 fragments.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>frag</em></td>
<td>The value of fragment threshold configuration.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_set\_uap\_frag (int *frag*)

> Set the fragment threshold of the uAP in Wi-Fi firmware. If the size
> of packet exceeds the fragment threshold, the packet is divided into
> fragments. For example, if the fragment threshold is set to 300, a
> ping packet of size 1300 is divided into 5 fragments.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>frag</em></td>
<td>the value of fragment threshold configuration.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_set\_sta\_mac\_filter (int *filter\_mode*, int *mac\_count*, unsigned char \* *mac\_addr*)

> Set the STA MAC filter in Wi-Fi firmware. Apply for uAP mode only.
> When STA MAC filter enabled, wlan firmware blocks all the packets from
> station with MAC address in black list and not blocks packets from
> station with MAC address in white list.

##### Parameters

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

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_set\_crypto\_RC4\_encrypt (const t\_u8 \* *Key*, const t\_u16 *KeyLength*, const t\_u8 \* *KeyIV*, const t\_u16 *KeyIVLength*, t\_u8 \* *Data*, t\_u16 \* *DataLength*)

> Set crypto RC4 (rivest cipher 4) algorithm encrypt command parameters.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>Key</em></td>
<td>key</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>KeyLength</em></td>
<td>The KeyLength + KeyIVLength valid range [1,256].</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>KeyIV</em></td>
<td>KeyIV</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>KeyIVLength</em></td>
<td>The KeyLength + KeyIVLength valid range [1,256].</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>Data</em></td>
<td>Data</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>DataLength</em></td>
<td>The maximum data length is 1200.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful.
> 
> \-WM\_E\_PERM if not supported.
> 
> \-WM\_FAIL if failure.

##### Note

> If the function returns WM\_SUCCESS, the data in the memory pointed to
> by data is overwritten by the encrypted data. The value of DataLength
> is updated to the encrypted data length. The length of the encrypted
> data is the same as the origin DataLength.

#### int wlan\_set\_crypto\_RC4\_decrypt (const t\_u8 \* *Key*, const t\_u16 *KeyLength*, const t\_u8 \* *KeyIV*, const t\_u16 *KeyIVLength*, t\_u8 \* *Data*, t\_u16 \* *DataLength*)

> Set crypto RC4 (rivest cipher 4) algorithm decrypt command parameters.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>Key</em></td>
<td>key</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>KeyLength</em></td>
<td>The KeyLength + KeyIVLength valid range [1,256].</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>KeyIV</em></td>
<td>KeyIV</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>KeyIVLength</em></td>
<td>The KeyLength + KeyIVLength valid range [1,256].</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>Data</em></td>
<td>Data</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>DataLength</em></td>
<td>The maximum data length is 1200.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful.
> 
> \-WM\_E\_PERM if not supported.
> 
> \-WM\_FAIL if failure.

##### Note

> If the function returns WM\_SUCCESS, the data in the memory pointed to
> by data is overwritten by the decrypted data. The value of DataLength
> is updated to the decrypted data length. The length of the decrypted
> data is the same as the origin DataLength.

#### int wlan\_set\_crypto\_AES\_ECB\_encrypt (const t\_u8 \* *Key*, const t\_u16 *KeyLength*, const t\_u8 \* *KeyIV*, const t\_u16 *KeyIVLength*, t\_u8 \* *Data*, t\_u16 \* *DataLength*)

> Set crypto AES\_ECB (advanced encryption standard, electronic
> codebook) algorithm encrypt command parameters.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>Key</em></td>
<td>key</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>KeyLength</em></td>
<td>The key length is 16/24/32.</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>KeyIV</em></td>
<td>KeyIV should point to a 8 bytes array with any value in the array.</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>KeyIVLength</em></td>
<td>The keyIV length is 8.</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>Data</em></td>
<td>Data</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>DataLength</em></td>
<td>The data length is 16.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful.
> 
> \-WM\_E\_PERM if not supported.
> 
> \-WM\_FAIL if failure.

##### Note

> If the function returns WM\_SUCCESS, the data in the memory pointed to
> by data is overwritten by the encrypted data. The value of DataLength
> is updated to the encrypted data length. The length of the encrypted
> data is the same as the origin DataLength.

#### int wlan\_set\_crypto\_AES\_ECB\_decrypt (const t\_u8 \* *Key*, const t\_u16 *KeyLength*, const t\_u8 \* *KeyIV*, const t\_u16 *KeyIVLength*, t\_u8 \* *Data*, t\_u16 \* *DataLength*)

> Set crypto AES\_ECB (advanced encryption standard, electronic
> codebook) algorithm decrypt command parameters.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>Key</em></td>
<td>key</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>KeyLength</em></td>
<td>The key length is 16/24/32.</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>KeyIV</em></td>
<td>KeyIV should point to a 8 bytes array with any value in the array.</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>KeyIVLength</em></td>
<td>The keyIV length is 8.</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>Data</em></td>
<td>Data</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>DataLength</em></td>
<td>The data length is 16.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful.
> 
> \-WM\_E\_PERM if not supported.
> 
> \-WM\_FAIL if failure.

##### Note

> If the function returns WM\_SUCCESS, the data in the memory pointed to
> by data is overwritten by the decrypted data. The value of DataLength
> is updated to the decrypted data length. The length of the decrypted
> data is the same as the origin DataLength.

#### int wlan\_set\_crypto\_AES\_WRAP\_encrypt (const t\_u8 \* *Key*, const t\_u16 *KeyLength*, const t\_u8 \* *KeyIV*, const t\_u16 *KeyIVLength*, t\_u8 \* *Data*, t\_u16 \* *DataLength*)

> Set crypto AES\_WRAP (advanced encryption standard wrap) algorithm
> encrypt command parameters.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>Key</em></td>
<td>key</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>KeyLength</em></td>
<td>The key length is 16/24/32.</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>KeyIV</em></td>
<td>KeyIV</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>KeyIVLength</em></td>
<td>The keyIV length is 8.</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>Data</em></td>
<td>Data</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>DataLength</em></td>
<td>The data length valid range [8,1016].</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful.
> 
> \-WM\_E\_PERM if not supported.
> 
> \-WM\_FAIL if failure.

##### Note

> If the function returns WM\_SUCCESS, the data in the memory pointed to
> by data is overwritten by the encrypted data. The value of DataLength
> is updated to the encrypted data length. The encrypted data is 8 bytes
> more than the original data. Therefore, the address pointed to by Data
> needs to reserve enough space.

#### int wlan\_set\_crypto\_AES\_WRAP\_decrypt (const t\_u8 \* *Key*, const t\_u16 *KeyLength*, const t\_u8 \* *KeyIV*, const t\_u16 *KeyIVLength*, t\_u8 \* *Data*, t\_u16 \* *DataLength*)

> Set crypto AES\_WRAP algorithm decrypt command parameters.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>Key</em></td>
<td>key</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>KeyLength</em></td>
<td>The key length is 16/24/32.</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>KeyIV</em></td>
<td>KeyIV</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>KeyIVLength</em></td>
<td>The keyIV length is 8.</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>Data</em></td>
<td>Data</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>DataLength</em></td>
<td>The data length valid range [8,1016].</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful.
> 
> \-WM\_E\_PERM if not supported.
> 
> \-WM\_FAIL if failure.

##### Note

> If the function returns WM\_SUCCESS, the data in the memory pointed to
> by data is overwritten by the decrypted data. The value of DataLength
> is updated to the decrypted data length. The decrypted data is 8 bytes
> less than the original data.

#### int wlan\_set\_crypto\_AES\_CCMP\_encrypt (const t\_u8 \* *Key*, const t\_u16 *KeyLength*, const t\_u8 \* *AAD*, const t\_u16 *AADLength*, const t\_u8 \* *Nonce*, const t\_u16 *NonceLength*, t\_u8 \* *Data*, t\_u16 \* *DataLength*)

> Set crypto AES\_CCMP (counter mode with cipher block chaining message
> authentication code protocol) algorithm encrypt command parameters.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>Key</em></td>
<td>key</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>KeyLength</em></td>
<td>The key length is 16/32.</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>AAD</em></td>
<td>AAD</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>AADLength</em></td>
<td>The maximum AAD length is 30.</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>Nonce</em></td>
<td>Nonce</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>NonceLength</em></td>
<td>The nonce length valid range [7,13].</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>Data</em></td>
<td>Data</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>DataLength</em></td>
<td>The maximum data length is 80.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful.
> 
> \-WM\_E\_PERM if not supported.
> 
> \-WM\_FAIL if failure.

##### Note

> If the function returns WM\_SUCCESS, the data in the memory pointed to
> by data is overwritten by the encrypted data. The value of DataLength
> is updated to the encrypted data length. The encrypted data is 8 bytes
> (when key length is 16) or 16 bytes (when key length is 32) more than
> the original data. Therefore, the address pointed to by Data needs to
> reserve enough space.

#### int wlan\_set\_crypto\_AES\_CCMP\_decrypt (const t\_u8 \* *Key*, const t\_u16 *KeyLength*, const t\_u8 \* *AAD*, const t\_u16 *AADLength*, const t\_u8 \* *Nonce*, const t\_u16 *NonceLength*, t\_u8 \* *Data*, t\_u16 \* *DataLength*)

> Set crypto AES\_CCMP algorithm decrypt command parameters.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>Key</em></td>
<td>key</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>KeyLength</em></td>
<td>The key length is 16/32.</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>AAD</em></td>
<td>AAD</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>AADLength</em></td>
<td>The maximum AAD length is 30.</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>Nonce</em></td>
<td>Nonce</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>NonceLength</em></td>
<td>The nonce length valid range [7,13].</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>Data</em></td>
<td>Data</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>DataLength</em></td>
<td>The maximum data length is 80.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful.
> 
> \-WM\_E\_PERM if not supported.
> 
> \-WM\_FAIL if failure.

##### Note

> If the function returns WM\_SUCCESS, the data in the memory pointed to
> by data is overwritten by the decrypted data. The value of DataLength
> is updated to the decrypted data length. The decrypted data is 8 bytes
> (when key length is 16) or 16 bytes (when key length is 32) less than
> the original data.

#### int wlan\_set\_crypto\_AES\_GCMP\_encrypt (const t\_u8 \* *Key*, const t\_u16 *KeyLength*, const t\_u8 \* *AAD*, const t\_u16 *AADLength*, const t\_u8 \* *Nonce*, const t\_u16 *NonceLength*, t\_u8 \* *Data*, t\_u16 \* *DataLength*)

> Set crypto AES\_GCMP (galois/counter mode with AES-GMAC) algorithm
> encrypt command parameters.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>Key</em></td>
<td>key</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>KeyLength</em></td>
<td>The key length is 16/32.</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>AAD</em></td>
<td>AAD</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>AADLength</em></td>
<td>The maximum AAD length is 30.</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>Nonce</em></td>
<td>Nonce</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>NonceLength</em></td>
<td>The nonce length valid range [7,13].</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>Data</em></td>
<td>Data</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>DataLength</em></td>
<td>The maximum data length is 80.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful.
> 
> \-WM\_E\_PERM if not supported.
> 
> \-WM\_FAIL if failure.

##### Note

> If the function returns WM\_SUCCESS, the data in the memory pointed to
> by data is overwritten by the encrypted data. The value of DataLength
> is updated to the encrypted data length. The encrypted data is 16
> bytes more than the original data. Therefore, the address pointed to
> by Data needs to reserve enough space.

#### int wlan\_set\_crypto\_AES\_GCMP\_decrypt (const t\_u8 \* *Key*, const t\_u16 *KeyLength*, const t\_u8 \* *AAD*, const t\_u16 *AADLength*, const t\_u8 \* *Nonce*, const t\_u16 *NonceLength*, t\_u8 \* *Data*, t\_u16 \* *DataLength*)

> Set crypto AES\_CCMP algorithm decrypt command parameters.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>Key</em></td>
<td>key</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>KeyLength</em></td>
<td>The key length is 16/32.</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>AAD</em></td>
<td>AAD</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>AADLength</em></td>
<td>The maximum AAD length is 30.</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>Nonce</em></td>
<td>Nonce</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>NonceLength</em></td>
<td>The nonce length valid range [7,13].</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>Data</em></td>
<td>Data</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>DataLength</em></td>
<td>The maximum data length is 80.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful.
> 
> \-WM\_E\_PERM if not supported.
> 
> \-WM\_FAIL if failure.

##### Note

> If the function returns WM\_SUCCESS, the data in the memory pointed to
> by data is overwritten by the decrypted data. The value of DataLength
> is updated to the decrypted data length. The decrypted data is 16
> bytes less than the original data.

#### int wlan\_enable\_disable\_htc (uint8\_t *option*)

> This function is used to enable/disable HTC (high throughput control).

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>option</em></td>
<td>1 =&gt; Enable; 0 =&gt; Disable</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if operation is successful, otherwise return -WM\_FAIL

#### int wlan\_set\_11ax\_tx\_omi (const t\_u8 *interface*, const t\_u16 *tx\_omi*, const t\_u8 *tx\_option*, const t\_u8 *num\_data\_pkts*)

> Use this API to set the set 802.11ax TX OMI (operating mode
> indication).

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>interface</em></td>
<td>Interface type STA or uAP. 0: STA 1: uAP</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>tx_omi</em></td>
<td>value to be sent to firmware</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>tx_option</em></td>
<td>value to be sent to firmware 1: send OMI (operating mode indication) in QoS (quality of service) data.</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>num_data_pkts</em></td>
<td>value to be sent to firmware num_data_pkts is applied only if OMI is sent in QoS data frame. It specifies the number of consecutive data frames containing the OMI. Minimum value is 1 Maximum value is 16</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if operation is successful.
> 
> \-WM\_FAIL if command fails.

#### int wlan\_set\_11ax\_tol\_time (const t\_u32 *tol\_time*)

> Set 802.11ax OBSS (overlapping basic service set) narrow bandwidth RU
> (resource unit) tolerance time In uplink transmission, AP sends a
> trigger frame to all the stations that can be involved in the upcoming
> transmission, and then these stations transmit Trigger-based(TB) PPDU
> in response to the trigger frame. If STA connects to AP which channel
> is set to 100,STA doesn't support 26 tones RU. The API should be
> called when station is in disconnected state.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>tol_time</em></td>
<td>Valid range [1...3600] tolerance time is in unit of seconds. STA periodically check AP's beacon for ext cap bit79 (OBSS Narrow bandwidth RU in ofdma tolerance support) and set 20 tone RU tolerance time if ext cap bit79 is not set</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_set\_11ax\_rutxpowerlimit (const void \* *rutx\_pwr\_cfg*, uint32\_t *rutx\_pwr\_cfg\_len*)

> Use this API to set the RU TX power limit.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>rutx_pwr_cfg</em></td>
<td>802.11ax rutxpwr of sub-bands to be sent to firmware. refer to rutxpowerlimit_cfg_set_WW[]</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>rutx_pwr_cfg_len</em></td>
<td>Size of rutx_pwr_cfg buffer.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if operation is successful.
> 
> \-WM\_FAIL if command fails.

#### int wlan\_set\_11ax\_rutxpowerlimit\_legacy (const wlan\_rutxpwrlimit\_t \* *ru\_pwr\_cfg*)

> Use this API to set the RU TX power limit by channel based approach.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>ru_pwr_cfg</em></td>
<td>802.11ax rutxpwr of channels to be sent to firmware.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if operation is successful.
> 
> \-WM\_FAIL if command fails.

#### int wlan\_get\_11ax\_rutxpowerlimit\_legacy (wlan\_rutxpwrlimit\_t \* *ru\_pwr\_cfg*)

> Use this API to get the RU TX power limit by channel based approach.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>ru_pwr_cfg</em></td>
<td>802.11ax rutxpwr of channels to be get from firmware.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if operation is successful.
> 
> \-WM\_FAIL if command fails.

#### int wlan\_set\_11ax\_cfg (wlan\_11ax\_config\_t \* *ax\_config*)

> Set 802.11ax configuration parameters

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>ax_config</em></td>
<td>802.11ax configuration parameters to be sent to firmware.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### wlan\_11ax\_config\_t\* wlan\_get\_11ax\_cfg (void )

> Get default 802.11ax configuration parameters

##### Returns

> 802.11ax configuration parameters default array.

#### int wlan\_set\_btwt\_cfg (const wlan\_btwt\_config\_t \* *btwt\_config*)

> Set broadcast TWT (target wake time) configuration parameters

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>btwt_config</em></td>
<td>Broadcast TWT setup parameters to be sent to firmware.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### wlan\_btwt\_config\_t\* wlan\_get\_btwt\_cfg (void )

> Get broadcast TWT configuration parameters

##### Returns

> Broadcast TWT setup parameters default configuration array.

#### int wlan\_set\_twt\_setup\_cfg (const wlan\_twt\_setup\_config\_t \* *twt\_setup*)

> Set TWT setup configuration parameters

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>twt_setup</em></td>
<td>TWT setup parameters to be sent to firmware.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### wlan\_twt\_setup\_config\_t\* wlan\_get\_twt\_setup\_cfg (void )

> Get TWT setup configuration parameters

##### Returns

> TWT setup parameters default array.

#### int wlan\_set\_twt\_teardown\_cfg (const wlan\_twt\_teardown\_config\_t \* *teardown\_config*)

> Set TWT teardown configuration parameters

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>teardown_config</em></td>
<td>TWT teardown parameters sent to firmware.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### wlan\_twt\_teardown\_config\_t\* wlan\_get\_twt\_teardown\_cfg (void )

> Get TWT teardown configuration parameters

##### Returns

> TWT Teardown parameters default array

#### int wlan\_get\_twt\_report (wlan\_twt\_report\_t \* *twt\_report*)

> Get TWT report

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>twt_report</em></td>
<td>TWT report parameter.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_set\_mmsf (const t\_u8 *enable*, const t\_u8 *Density*, const t\_u8 *MMSF*)

> Set 802.11ax AMPDU (aggregate medium access control (MAC) protocol
> data unit) density configuration.

##### Parameters

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

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_get\_mmsf (t\_u8 \* *enable*, t\_u8 \* *Density*, t\_u8 \* *MMSF*)

> Get 802.11ax AMPDU density configuration.

##### Parameters

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

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_set\_clocksync\_cfg (const wlan\_clock\_sync\_gpio\_tsf\_t \* *tsf\_latch*)

> Set clock sync GPIO based TSF (time synchronization function).

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>tsf_latch</em></td>
<td>Clock sync TSF latch parameters to be sent to firmware</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_get\_tsf\_info (wlan\_tsf\_info\_t \* *tsf\_info*)

> Get TSF info from firmware using GPIO latch.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>tsf_info</em></td>
<td>TSF info parameter received from firmware</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_ft\_roam (const t\_u8 \* *bssid*, const t\_u8 *channel*)

> Start FT roaming : This API is used to initiate fast BSS transition
> based roaming.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>bssid</em></td>
<td>BSSID of AP to roam</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>channel</em></td>
<td>Channel of AP to roam</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_rx\_mgmt\_indication (const enum wlan\_bss\_type *bss\_type*, const uint32\_t *mgmt\_subtype\_mask*, int(\*)(const enum wlan\_bss\_type bss\_type, const wlan\_mgmt\_frame\_t \*frame, const size\_t len) *rx\_mgmt\_callback*)

> This API can be used to start/stop the management frame forwarded to
> host through data path.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>bss_type</em></td>
<td>The interface from which management frame needs to be collected 0: STA, 1: uAP</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>mgmt_subtype_mask</em></td>
<td>Management Subtype Mask If Bit X is set in mask, it means that IEEE Management Frame SubType X is to be filtered and passed through to host. Bit Description [31:14] Reserved [13] Action frame [12:9] Reserved [8] Beacon [7:6] Reserved [5] Probe response [4] Probe request [3] Reassociation response [2] Reassociation request [1] Association response [0] Association request Support multiple bits set. 0 = stop forward frame 1 = start forward frame</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>rx_mgmt_callback</em></td>
<td>The receive callback where the received management frames are passed.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if operation is successful.
> 
> \-WM\_FAIL if command fails.

##### Note

> Pass management subtype mask all zero to disable all the management
> frame forward to host.

#### void wlan\_set\_scan\_channel\_gap (unsigned *scan\_chan\_gap*)

> Set scan channel gap.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>scan_chan_gap</em></td>
<td>Time gap to be used between two consecutive channels scan.</td>
</tr>
</tbody>
</table>

#### int wlan\_host\_11k\_cfg (int *enable\_11k*)

> Enable/Disable host 802.11k feature.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>enable_11k</em></td>
<td>the value of 802.11k configuration. 0: disable host 11k 1: enable host 11k</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### bool wlan\_get\_host\_11k\_status (void )

> Get enable/disable host 802.11k feature flag.

##### Returns

> TRUE if 802.11k is enabled, return FALSE if 802.11k is disabled.

#### int wlan\_host\_11k\_neighbor\_req (const char \* *ssid*)

> Host send neighbor report request.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>ssid</em></td>
<td>The SSID for neighbor report</td>
</tr>
</tbody>
</table>

##### Note

> ssid parameter is optional, pass NULL pointer to ignore SSID input if
> not specify SSID

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_host\_11v\_bss\_trans\_query (t\_u8 *query\_reason*)

> Host send BSS transition management query. STA sends BTM (BSS
> transition management) query, and the AP supporting 11V will response
> BTM request, the AP will parse neighbor report in the BTM request and
> response the BTM response to AP to indicate the receive status.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>query_reason</em></td>
<td>[0..16] IEEE 802.11v BTM (BSS transition management) Query reasons. Refer to IEEE Std 802.11v-2011 - Table 7-43x-Transition and Transition Query reasons table.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_set\_okc (t\_u8 *okc*)

> Opportunistic key caching (also known as proactive key caching)
> default This parameter can be used to set the default behavior for the
> proactive\_key\_caching parameter. By default, OKC is disabled unless
> enabled with the global okc=1 parameter or with the per-network
> pkc(proactive\_key\_caching)=1 parameter. With okc=1, OKC is enabled
> by default, but can be disabled with per-network
> pkc(proactive\_key\_caching)=0 parameter.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>okc</em></td>
<td>Enable opportunistic key caching</td>
</tr>
</tbody>
</table>

> 0 = Disable OKC (default) 1 = Enable OKC

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_pmksa\_list (char \* *buf*, size\_t *buflen*)

> Dump text list of entries in PMKSA (pairwise master key security
> association) cache.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>buf</em></td>
<td>Buffer to save PMKSA cache text list</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>buflen</em></td>
<td>length of the buffer</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_pmksa\_flush (void )

> Flush PTKSA cache entries

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_set\_scan\_interval (int *scan\_int*)

> Set wpa supplicant scan interval in seconds

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>scan_int</em></td>
<td>Scan interval in seconds</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_uap\_set\_ecsa\_cfg (t\_u8 *block\_tx*, t\_u8 *oper\_class*, t\_u8 *channel*, t\_u8 *switch\_count*, t\_u8 *band\_width*)

> Send the ecsa configuration parameter to FW.

##### Parameters

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

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_set\_subscribe\_event (unsigned int *event\_id*, unsigned int *thresh\_value*, unsigned int *freq*)

> Subscribe specified event from the Wi-Fi firmware. Wi-Fi firmware
> report the registered event to driver upon configured report
> conditions are met.

##### Parameters

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

##### Returns

> WM\_SUCCESS if set successfully, otherwise return failure.

#### int wlan\_get\_subscribe\_event (wlan\_ds\_subscribe\_evt \* *sub\_evt*)

> Get all subscribed events from Wi-Fi firmware along with threshold
> value and report frequency.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>sub_evt</em></td>
<td>A pointer to wlan_ds_subscribe_evt to store the events data.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if set successfully, otherwise return failure.

#### int wlan\_clear\_subscribe\_event (unsigned int *event\_id*)

> cancel the subscribe event to firmware

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>event_id</em></td>
<td>event id to clear as per sub_event_id</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_set\_threshold\_link\_quality (unsigned int *evend\_id*, unsigned int *link\_snr*, unsigned int *link\_snr\_freq*, unsigned int *link\_rate*, unsigned int *link\_rate\_freq*, unsigned int *link\_tx\_latency*, unsigned int *link\_tx\_lantency\_freq*)

> subscribe link quality event

##### Parameters

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

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_get\_tsp\_cfg (t\_u16 \* *enable*, t\_u32 \* *back\_off*, t\_u32 \* *highThreshold*, t\_u32 \* *lowThreshold*, t\_u32 \* *dutycycstep*, t\_u32 \* *dutycycmin*, int \* *highthrtemp*, int \* *lowthrtemp*, int \* *currCAUTemp*, int \* *currRFUTemp*)

> Get TSP (thermal safeguard protection) configuration. TSP algorithm
> monitors PA Tj and primarily backs off data throughput.

##### Parameters

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

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_set\_tsp\_cfg (t\_u16 *enable*, t\_u32 *back\_off*, t\_u32 *highThreshold*, t\_u32 *lowThreshold*, t\_u32 *dutycycstep*, t\_u32 *dutycycmin*, int *highthrtemp*, int *lowthrtemp*)

> Set TSP (thermal safeguard protection) configuration. TSP algorithm
> monitors and primarily backs off data throughput.

##### Parameters

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

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_reg\_access (wifi\_reg\_t *type*, uint16\_t *action*, uint32\_t *offset*, uint32\_t \* *value*)

> This function reads/writes adapter registers value.

##### Parameters

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

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_tx\_ampdu\_prot\_mode (tx\_ampdu\_prot\_mode\_para \* *prot\_mode*, t\_u16 *action*)

> Set/Get TX AMPDU protect mode.

##### Parameters

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

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_mef\_set\_auto\_arp (t\_u8 *mef\_action*)

> This function set auto ARP configuration.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>mef_action</em></td>
<td>To be 0–discard and not wake host, 1–discard and wake host, 3–allow and wake host.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_mef\_set\_auto\_ping (t\_u8 *mef\_action*)

> This function set auto ping configuration.

##### Parameters

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

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_config\_mef (int *type*, t\_u8 *mef\_action*)

> This function set/delete MEF entries configuration.

##### Parameters

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

##### Returns

> WM\_SUCCESS if the call was successful.
> 
> \-WM\_FAIL if failed.

#### int wlan\_set\_ipv6\_ns\_mef (t\_u8 *mef\_action*)

> Use this API to enable IPv6 neighbor solicitation offload in Wi-Fi
> firmware.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>mef_action</em></td>
<td>0–discard and not wake host, 1–discard and wake host 3–allow and wake host.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if operation is successful.
> 
> \-WM\_FAIL if command fails.

#### int wlan\_csi\_cfg (wlan\_csi\_config\_params\_t \* *csi\_params*)

> Send the CSI configuration parameter to firmware.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>csi_params</em></td>
<td>CSI configuration parameter</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_register\_csi\_user\_callback (int(\*)(void \*buffer, size\_t len) *csi\_data\_recv\_callback*)

> This function registers callback which are used to deliver CSI
> (channel state information) data to user.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>csi_data_recv_callback</em></td>
<td>Callback to deliver CSI data and max data length is 768 bytes. Process data as soon as possible in callback, or else shall block there. Type of callback return value is int.</td>
</tr>
</tbody>
</table>

Memory layout of buffer:

size(byte) items

2 buffer len\[bit 0:12\]

2 CSI signature, 0xABCD fixed

4 User defined HeaderID

2 Packet info

2 Frame control field for the received packet

8 Timestamp when packet received

6 Received packet destination MAC Address

6 Received packet source MAC address

1 RSSI for antenna A

1 RSSI for antenna B

1 Noise floor for antenna A

1 Noise floor for antenna B

1 RX signal strength above noise floor

1 Channel

2 user defined chip ID

4 Reserved

4 CSI data length in DWORDs

CSI data

<table>
<tbody>
<tr class="odd">
<td></td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_unregister\_csi\_user\_callback (void )

> This function unregisters callback which are used to deliver CSI data
> to user.

##### Returns

> WM\_SUCCESS if successful

#### wlan\_csi\_config\_params\_t\* wlan\_get\_csi\_cfg\_param\_default (void )

> This function get CSI default configuration data.

##### Returns

> CSI data pointer.

#### int wlan\_set\_csi\_cfg\_param\_default (wlan\_csi\_config\_params\_t \* *in\_csi\_cfg*)

> This function set CSI default configuration data.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>in_csi_cfg</em></td>
<td>CSI default configuration data to be set.</td>
</tr>
</tbody>
</table>

##### Returns

> if successful return 1 else return 0.

#### void wlan\_reset\_csi\_filter\_data (void )

> This function reset Wi-Fi CSI filter data.

#### void wlan\_set\_rssi\_low\_threshold (uint8\_t *threshold*)

> Use this API to set the RSSI threshold value for low RSSI event
> subscription. When RSSI falls below this threshold firmware can
> generate the low RSSI event to driver. This low RSSI event is used
> when either of CONFIG\_11R, CONFIG\_11K, CONFIG\_11V or
> CONFIG\_ROAMING is enabled.

##### Note

> By default RSSI low threshold is set at -70 dbm.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>threshold</em></td>
<td>Threshold RSSI value to be set</td>
</tr>
</tbody>
</table>

#### void wlan\_wps\_generate\_pin (uint32\_t \* *pin*)

> This function generate pin for WPS pin session.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>pin</em></td>
<td>A pointer to WPS pin to be generated.</td>
</tr>
</tbody>
</table>

#### int wlan\_start\_wps\_pin (const char \* *pin*)

> Start WPS pin session.
> 
> This function starts WPS pin session.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>pin</em></td>
<td>Pin for WPS session.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if the pin entered is valid.
> 
> \-WM\_FAIL if invalid pin entered.

#### int wlan\_start\_wps\_pbc (void )

> Start WPS PBC (push button configuration) session.
> 
> This function starts WPS PBC (push button configuration) session.

##### Returns

> WM\_SUCCESS if successful
> 
> \-WM\_FAIL if invalid pin entered.

#### int wlan\_wps\_cancel (void )

> Cancel WPS session.
> 
> This function cancels ongoing WPS session.

##### Returns

> WM\_SUCCESS if successful
> 
> \-WM\_FAIL if invalid pin entered.

#### int wlan\_set\_entp\_cert\_files (int *cert\_type*, t\_u8 \* *data*, t\_u32 *data\_len*)

> This function specifies the enterprise certificate file This function
> is used before adding network profile. It can store certificate data
> in "wlan" global structure.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>cert_type</em></td>
<td>certificate file type: 1 – FILE_TYPE_ENTP_CA_CERT, 2 – FILE_TYPE_ENTP_CLIENT_CERT, 3 – FILE_TYPE_ENTP_CLIENT_KEY.</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>data</em></td>
<td>raw data of the enterprise certificate file</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>data_len</em></td>
<td>length of the enterprise certificate file</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### t\_u32 wlan\_get\_entp\_cert\_files (int *cert\_type*, t\_u8 \*\* *data*)

> This function get enterprise certificate data from "wlan" global
> structure

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>cert_type</em></td>
<td>certificate file type: 1 – FILE_TYPE_ENTP_CA_CERT, 2 – FILE_TYPE_ENTP_CLIENT_CERT, 3 – FILE_TYPE_ENTP_CLIENT_KEY.</td>
</tr>
<tr class="even">
<td>out</td>
<td><em>data</em></td>
<td>raw data of the enterprise certificate file</td>
</tr>
</tbody>
</table>

##### Returns

> size of raw data

#### void wlan\_free\_entp\_cert\_files (void )

> This function free the temporary memory of enterprise certificate data
> After add new enterprise network profile, the certificate data has
> been parsed by mbedtls into another data, which can be freed.

#### int wlan\_net\_monitor\_cfg (wlan\_net\_monitor\_t \* *monitor*)

> Send the network monitor configuration parameter to firmware.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>monitor</em></td>
<td>Monitor configuration parameter</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### void wlan\_register\_monitor\_user\_callback (int(\*)(void \*buffer, t\_u16 data\_len) *monitor\_data\_recv\_callback*)

> This function registers callback which are used to deliver monitor
> data to user.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>monitor_data_recv_callback</em></td>
<td>Callback to deliver monitor data and data length to user. Memory layout of buffer: offset(byte) items 0 rssi 1 802.11 MAC header 1 + 'size of 802.11 MAC header' frame body</td>
</tr>
</tbody>
</table>

#### void wlan\_deregister\_net\_monitor\_user\_callback (void )

> This function deregisters monitor callback.

#### uint8\_t wlan\_check\_11n\_capa (unsigned int *channel*)

> Check if Wi-Fi hardware support 802.11n for on 2.4G or 5G bands.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>channel</em></td>
<td>Channel number.</td>
</tr>
</tbody>
</table>

##### Returns

> true if 802.11n is supported or false if not.

#### uint8\_t wlan\_check\_11ac\_capa (unsigned int *channel*)

> Check if Wi-Fi hardware support 802.11ac for on 2.4G or 5G bands.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>channel</em></td>
<td>Channel number.</td>
</tr>
</tbody>
</table>

##### Returns

> true if 802.11ac is supported or false if not.

#### uint8\_t wlan\_check\_11ax\_capa (unsigned int *channel*)

> Check if Wi-Fi hardware support 802.11ax for on 2.4G or 5G bands.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>channel</em></td>
<td>Channel number.</td>
</tr>
</tbody>
</table>

##### Returns

> true if 802.11ax is supported or false if not.

#### int wlan\_set\_ips (int *option*)

> Config IEEE power save mode (IPS). If the option is 1, the IPS
> hardware listens to beacon frames after Wi-Fi CPU enters power save
> mode. When there is work needed to done by Wi-Fi CPU, Wi-Fi CPU can be
> woken up by ips hardware.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>option</em></td>
<td>0/1 disable/enable ips</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_get\_signal\_info (wlan\_rssi\_info\_t \* *signal*)

> Get RSSI information.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>signal</em></td>
<td>RSSI information get report buffer</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_set\_bandcfg (wlan\_bandcfg\_t \* *bandcfg*)

> Set band configuration.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>bandcfg</em></td>
<td>band configuration</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_get\_bandcfg (wlan\_bandcfg\_t \* *bandcfg*)

> Get band configuration.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>bandcfg</em></td>
<td>band configuration</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_set\_rg\_power\_cfg (t\_u16 *region\_code*)

> Set TX power table according to region code

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>region_code</em></td>
<td>region code</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_set\_ru\_power\_cfg (t\_u16 *region\_code*)

> set ru tx power table

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>region_code</em></td>
<td>region code</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise failure.

#### void wlan\_set\_ps\_cfg (t\_u16 *multiple\_dtims*, t\_u16 *bcn\_miss\_timeout*, t\_u16 *local\_listen\_interval*, t\_u16 *adhoc\_wake\_period*, t\_u16 *mode*, t\_u16 *delay\_to\_ps*)

> Set multiple dtim for next wakeup RX beacon time

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>multiple_dtims</em></td>
<td>num dtims, range [1,20]</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>bcn_miss_timeout</em></td>
<td>becaon miss interval</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>local_listen_interval</em></td>
<td>local listen interval</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>adhoc_wake_period</em></td>
<td>adhoc awake period</td>
</tr>
<tr class="odd">
<td>in</td>
<td><em>mode</em></td>
<td>mode - (0x01 - firmware to automatically choose PS_POLL or NULL mode, 0x02 - PS_POLL, 0x03 - NULL mode )</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>delay_to_ps</em></td>
<td>Delay to PS in milliseconds</td>
</tr>
</tbody>
</table>

#### int wlan\_set\_country\_code (const char \* *alpha2*)

> Set country code

##### Note

> This API should be called after Wi-Fi is initialized but before
> starting uAP interface.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>alpha2</em></td>
<td>country code in 3 octets string, 2 octets country code and 1 octet environment 2 octets country code supported: WW : World Wide Safe US : US FCC CA : IC Canada SG : Singapore EU : ETSI AU : Australia KR : Republic Of Korea FR : France JP : Japan CN : China</td>
</tr>
</tbody>
</table>

> For the third octet, STA is always 0. for uAP environment: All
> environments of the current frequency band and country (default)
> alpha2\[2\]=0x20 Outdoor environment only alpha2\[2\]=0x4f Indoor
> environment only alpha2\[2\]=0x49 Noncountry entity (country\_code=XX)
> alpha\[2\]=0x58 IEEE 802.11 standard Annex E table indication: 0x01 ..
> 0x1f Annex E, Table E-4 (Global operating classes) alpha\[2\]=0x04

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_set\_country\_ie\_ignore (uint8\_t \* *ignore*)

> Set ignore region code.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>ignore</em></td>
<td>0: don't ignore, 1: ignore</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_set\_region\_code (unsigned int *region\_code*)

> Set region code.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>region_code</em></td>
<td>region code to be set.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise fail.

#### int wlan\_get\_region\_code (unsigned int \* *region\_code*)

> Get region code.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>out</td>
<td><em>region_code</em></td>
<td>pointer The value: 0x00: World Wide Safe 0x10: US FCC 0x20: IC Canada 0x10: Singapore 0x30: ETSI 0x30: Australia 0x30: Republic Of Korea 0x32: France 0xFF: Japan 0x50: China</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_set\_11d\_state (int *bss\_type*, int *state*)

> Set STA/uAP 802.11d feature Enable/Disable.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>bss_type</em></td>
<td>0: STA, 1: uAP</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>state</em></td>
<td>0: disable, 1: enable</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_single\_ant\_duty\_cycle (t\_u16 *enable*, t\_u16 *nbTime*, t\_u16 *wlanTime*)

> Set single antenna: duty cycle.

##### Parameters

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

##### Note

> wlanTime should not equal to wlanTime-nbTime

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_dual\_ant\_duty\_cycle (t\_u16 *enable*, t\_u16 *nbTime*, t\_u16 *wlanTime*, t\_u16 *wlanBlockTime*)

> Set dual antenna duty cycle.

##### Parameters

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

##### Note

> nbTime, wlanTime and wlanBlockTime should not equal to each other

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_external\_coex\_pta\_cfg (ext\_coex\_pta\_cfg *coex\_pta\_config*)

> Set external coex PTA (packet traffic arbitration) parameters.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>coex_pta_config</em></td>
<td>ext_coex_pta_cfg</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_dpp\_configurator\_add (int *is\_ap*, const char \* *cmd*)

> Add a DPP (device provisioning protocol) configurator.
> 
> If this device is DPP configurator, add it to get configurator ID.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>is_ap</em></td>
<td>0 is STA, 1 is uAP.</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>cmd</em></td>
<td>"curve=P-256"</td>
</tr>
</tbody>
</table>

##### Returns

> configurator ID if successful otherwise return -WM\_FAIL.

#### void wlan\_dpp\_configurator\_params (int *is\_ap*, const char \* *cmd*)

> Set DPP (device provisioning protocol) configurator parameter
> 
> set DPP configurator params. for example:" conf=\<sta-dpp/ap-dpp\>
> ssid=\<hex ssid\> configurator=conf\_id" \#space character exists
> between " & conf word.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>is_ap</em></td>
<td>0 is STA, 1 is uAP.</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>cmd</em></td>
<td>" conf=&lt;sta-dpp/ap-dpp/sta-psk&gt; ssid=&lt;hex ssid&gt; configurator=conf_id..."</td>
</tr>
</tbody>
</table>

##### Returns

> void

#### void wlan\_dpp\_mud\_url (int *is\_ap*, const char \* *cmd*)

> MUD URL for enrollee's DPP configuration request (optional)
> 
> Wi-Fi\_CERTIFIED\_Easy\_Connect\_Test\_Plan\_v3.0.pdf 5.1.23 STAUT
> sends the MUD URL

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>is_ap</em></td>
<td>0 is STA, 1 is uAP.</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>cmd</em></td>
<td>"https://example.com/mud"</td>
</tr>
</tbody>
</table>

##### Returns

> void

#### int wlan\_dpp\_bootstrap\_gen (int *is\_ap*, const char \* *cmd*)

> Generate QR code.
> 
> This function generates QR code and return bootstrap-id

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>is_ap</em></td>
<td>0 is STA, 1 is uAP.</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>cmd</em></td>
<td>"type=qrcode mac=&lt;mac-address-of-device&gt; chan=&lt;operating-class/channel&gt;..."</td>
</tr>
</tbody>
</table>

##### Returns

> bootstrap-id if successful otherwise return -WM\_FAIL.

#### const char\* wlan\_dpp\_bootstrap\_get\_uri (int *is\_ap*, unsigned int *id*)

> Get QR code by bootstrap-id.
> 
> This function gets QR code string by bootstrap-id

##### Parameters

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

##### Returns

> QR code string if successful otherwise NULL.

#### int wlan\_dpp\_qr\_code (int *is\_ap*, char \* *uri*)

> Enter the QR code in the DPP device.
> 
> This function set the QR code and return qr-code-id.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>is_ap</em></td>
<td>0 is STA, 1 is uAP</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>uri</em></td>
<td>QR code provided by other device.</td>
</tr>
</tbody>
</table>

##### Returns

> qr-code-id if successful otherwise return -WM\_FAIL.

#### int wlan\_dpp\_auth\_init (int *is\_ap*, const char \* *cmd*)

> Send provisioning auth request to responder.
> 
> This function send Auth request to responder by qr-code-id.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>is_ap</em></td>
<td>0 is STA, 1 is uAP.</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>cmd</em></td>
<td>" peer=&lt;qr-code-id&gt; conf=&lt;sta-dpp/ap-dpp/sta-psk&gt; ...."</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_dpp\_listen (int *is\_ap*, const char \* *cmd*)

> Make device listen to DPP request.
> 
> Responder generates QR code and listening on its operating channel to
> wait Auth request.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>is_ap</em></td>
<td>0 is STA, 1 is uAP.</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>cmd</em></td>
<td>"&lt;frequency&gt;"</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_dpp\_stop\_listen (int *is\_ap*)

> DPP stop listen.
> 
> Stop dpp listen and clear listen frequency

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>is_ap</em></td>
<td>0 is STA, 1 is uAP.</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_dpp\_pkex\_add (int *is\_ap*, const char \* *cmd*)

> Set bootstrapping through PKEX (Public Key Exchange).
> 
> Support in-band bootstrapping through PKEX

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>is_ap</em></td>
<td>0 is STA, 1 is uAP.</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>cmd</em></td>
<td>"own=&lt;bootstrap_id&gt; identifier=&lt;string&gt; code=&lt;string&gt;"</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_dpp\_chirp (int *is\_ap*, const char \* *cmd*)

> sends DPP presence announcement.
> 
> Send DPP presence announcement from responder. After the Initiator
> enters the QRcode URI provided by the Responder, the Responder sends
> the presence announcement to trigger Auth Request from Initiator.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>is_ap</em></td>
<td>0 is STA, 1 is uAP.</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>cmd</em></td>
<td>"own=&lt;bootstrap id&gt; listen=&lt;freq&gt; ..."</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_dpp\_reconfig (const char \* *cmd*)

> DPP reconfig.
> 
> DPP reconfig and make a new DPP connection.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>cmd</em></td>
<td>"&lt;network id&gt; ..."</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_dpp\_configurator\_sign (int *is\_ap*, const char \* *cmd*)

> Configurator configures itself as an Enrollee AP/STA.
> 
> Wi-Fi\_CERTIFIED\_Easy\_Connect\_Test\_Plan\_v3.0.pdf 5.3.8 & 5.3.9
> Configurator configures itself as an Enrollee AP/STA
> 
> for example:" conf=\<sta-dpp/ap-dpp\> ssid=\<hex ssid\>
> configurator=conf\_id" \#space character exists between " & conf word.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>is_ap</em></td>
<td>0 is STA, 1 is uAP</td>
</tr>
<tr class="even">
<td>in</td>
<td><em>cmd</em></td>
<td>" conf=&lt;sta-dpp/ap-dpp/sta-psk&gt; ssid=&lt;hex ssid&gt; configurator=conf_id..."</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_sta\_inactivityto (wlan\_inactivity\_to\_t \* *inac\_to*, t\_u16 *action*)

> Get/Set inactivity timeout extend

##### Parameters

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

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### t\_u16 wlan\_get\_status\_code (enum wlan\_event\_reason *reason*)

> Get 802.11 Status Code.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>reason</em></td>
<td>wlcmgr event reason</td>
</tr>
</tbody>
</table>

##### Returns

> status code defined in IEEE 802.11-2020 standard.

#### int32\_t wlan\_get\_temperature (void )

> Get board temperature.

##### Returns

> board temperature.

#### int wlan\_auto\_null\_tx (wlan\_auto\_null\_tx\_t \* *auto\_null\_tx*, mlan\_bss\_type *bss\_type*)

> Start/Stop auto TX null. Call this API to auto transmit and one shot
> quality of service data packets to get the CSI after STA connected one
> AP or uAP was connected with external STA.

##### Note

> STA cannot send auto NULL data if not connected AP, not support auto
> TX without connecting AP. uAP cannot send auto NULL data if is not
> connected, not support auto tx without connecting with external STA.

##### Parameters

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

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### char\* wlan\_string\_dup (const char \* *s*)

> Allocate memory for a string and copy the string to the allocated
> memory

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>s</em></td>
<td>the source/target string</td>
</tr>
</tbody>
</table>

##### Returns

> new string if successful, otherwise return -WM\_FAIL.

#### uint32\_t wlan\_get\_board\_type (void )

> Get board type.

##### Returns

> board type. 0x02: RW610\_PACKAGE\_TYPE\_BGA 0xFF: others

#### int wlan\_uap\_disconnect\_sta (uint8\_t \* *sta\_addr*)

> Disconnect to STA which is connected with internal uAP.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>sta_addr</em></td>
<td>STA MAC address</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_11n\_allowed (struct wlan\_network \* *network*)

> Check if 802.11n is allowed in capability.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>network</em></td>
<td>A pointer to the wlan_network</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_11ac\_allowed (struct wlan\_network \* *network*)

> Check if 802.11ac is allowed in capability.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>network</em></td>
<td>A pointer to the wlan_network</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_11ax\_allowed (struct wlan\_network \* *network*)

> Check if 802.11ax is allowed in capability.

##### Parameters

<table>
<tbody>
<tr class="odd">
<td>in</td>
<td><em>network</em></td>
<td>A pointer to the wlan_network</td>
</tr>
</tbody>
</table>

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

### Macro Documentation

#### \#define ACTION\_GET  (0U)

> Action GET

#### \#define ACTION\_SET  (1)

> Action SET

#### \#define IEEEtypes\_SSID\_SIZE  32U

> Maximum SSID length

#### \#define IEEEtypes\_ADDRESS\_SIZE  6

> MAC Address length

#### \#define WLAN\_RESCAN\_LIMIT  CONFIG\_MAX\_RESCAN\_LIMIT

> The number of times that the Wi-Fi connection manager look for a
> network before giving up.

#### \#define WLAN\_RECONNECT\_LIMIT  5U

> The number of times that the Wi-Fi connection manager attempts a
> reconnection with the network before giving up.

#### \#define WLAN\_NETWORK\_NAME\_MIN\_LENGTH  1U

> Minimum length for network names, see wlan\_network.

#### \#define WLAN\_NETWORK\_NAME\_MAX\_LENGTH  32U

> Maximum length for network names, see wlan\_network

#### \#define WLAN\_PSK\_MIN\_LENGTH  8U

> Minimum WPA2 passphrase can be up to 8 ASCII chars

#### \#define WLAN\_PSK\_MAX\_LENGTH  65U

> Maximum WPA2 passphrase can be up to 63 ASCII chars or 64 hexadecimal
> digits + 1 '\\0' char

#### \#define WLAN\_PASSWORD\_MIN\_LENGTH  8U

> Minimum WPA3 password can be up to 8 ASCII chars

#### \#define WLAN\_PASSWORD\_MAX\_LENGTH  255U

> Maximum WPA3 password can be up to 255 ASCII chars

#### \#define IDENTITY\_MAX\_LENGTH  64U

> Maximum enterprise identity can be up to 64 characters

#### \#define PASSWORD\_MAX\_LENGTH  128U

> Maximum enterprise password can be up to 128 characters

#### \#define MAX\_USERS  8U

> Maximum identities for EAP server users

#### \#define PAC\_OPAQUE\_ENCR\_KEY\_MAX\_LENGTH  33U

> Maximum length of encryption key for EAP-FAST PAC-Opaque values.

#### \#define A\_ID\_MAX\_LENGTH  33U

> Maximum length of A-ID, A-ID indicates the identity of the authority
> that issues PACs.

#### \#define HASH\_MAX\_LENGTH  40U

> Maximum length of CA certification hash

#### \#define DOMAIN\_MATCH\_MAX\_LENGTH  64U

> Maximum length of domain match

#### \#define WLAN\_MAX\_KNOWN\_NETWORKS  CONFIG\_WLAN\_KNOWN\_NETWORKS

> The size of the list of known networks maintained by the Wi-Fi
> connection manager

#### \#define WLAN\_PMK\_LENGTH  32

> Length of a pairwise master key (PMK). It's always 256 bits (32 Bytes)

#### \#define WLAN\_ERROR\_NONE  0

> Error codes The operation was successful.

#### \#define WLAN\_ERROR\_PARAM  1

> The operation failed due to an error with one or more parameters.

#### \#define WLAN\_ERROR\_NOMEM  2

> The operation could not be performed because there is not enough
> memory.

#### \#define WLAN\_ERROR\_STATE  3

> The operation could not be performed in the current system state.

#### \#define WLAN\_ERROR\_ACTION  4

> The operation failed due to an internal error.

#### \#define WLAN\_ERROR\_PS\_ACTION  5

> The operation to change power state could not be performed

#### \#define WLAN\_ERROR\_NOT\_SUPPORTED  6

> The requested feature is not supported

#### \#define WLAN\_MGMT\_ACTION  MBIT(13)

> BITMAP for Action frame

#### \#define WLAN\_KEY\_MGMT\_FT

**Value:** (WLAN\_KEY\_MGMT\_FT\_PSK | WLAN\_KEY\_MGMT\_FT\_IEEE8021X |
WLAN\_KEY\_MGMT\_FT\_IEEE8021X\_SHA384 | WLAN\_KEY\_MGMT\_FT\_SAE | \\

WLAN\_KEY\_MGMT\_FT\_FILS\_SHA256 | WLAN\_KEY\_MGMT\_FT\_FILS\_SHA384)

> Fast BSS Transition(11r) key management

#### \#define MAX\_CHANNEL\_LIST  6

> Configuration for Wi-Fi scan

### Typedef Documentation

#### typedef wifi\_pkt\_stats\_t wlan\_pkt\_stats\_t

> Wi-Fi firmware stat from wifi\_pkt\_stats\_t

#### typedef wifi\_scan\_channel\_list\_t wlan\_scan\_channel\_list\_t

> Configuration for Wi-Fi scan channel list from
> wifi\_scan\_channel\_list\_t

#### typedef wifi\_scan\_params\_v2\_t wlan\_scan\_params\_v2\_t

> Configuration for Wi-Fi scan parameters v2 from
> wifi\_scan\_params\_v2\_t

#### typedef wifi\_cal\_data\_t wlan\_cal\_data\_t

> Configuration for Wi-Fi calibration data from wifi\_cal\_data\_t

#### typedef wifi\_flt\_cfg\_t wlan\_flt\_cfg\_t

> Configuration for memory efficient filters in Wi-Fi firmware from
> wifi\_flt\_cfg\_t

#### typedef wifi\_wowlan\_ptn\_cfg\_t wlan\_wowlan\_ptn\_cfg\_t

> Configuration for wowlan pattern parameters from
> wifi\_wowlan\_ptn\_cfg\_t

#### typedef wifi\_tcp\_keep\_alive\_t wlan\_tcp\_keep\_alive\_t

> Configuration for TCP keep alive parameters from
> wifi\_tcp\_keep\_alive\_t

#### typedef wifi\_ds\_rate wlan\_ds\_rate

> Configuration for TX rate and get data rate from wifi\_ds\_rate

#### typedef wifi\_ed\_mac\_ctrl\_t wlan\_ed\_mac\_ctrl\_t

> Configuration for ED MAC Control parameters from
> wifi\_ed\_mac\_ctrl\_t

#### typedef wifi\_bandcfg\_t wlan\_bandcfg\_t

> Configuration for band from wifi\_bandcfg\_t

#### typedef wifi\_cw\_mode\_ctrl\_t wlan\_cw\_mode\_ctrl\_t

> Configuration for CW mode parameters from wifi\_cw\_mode\_ctrl\_t

#### typedef wifi\_chanlist\_t wlan\_chanlist\_t

> Configuration for channel list from wifi\_chanlist\_t

#### typedef wifi\_txpwrlimit\_t wlan\_txpwrlimit\_t

> Configuration for TX power Limit from wifi\_txpwrlimit\_t

#### typedef wifi\_rutxpwrlimit\_t wlan\_rutxpwrlimit\_t

> Configuration for RU TX power limit from wifi\_rutxpwrlimit\_t

#### typedef wifi\_11ax\_config\_t wlan\_11ax\_config\_t

> Configuration for 802.11ax capabilities wifi\_11ax\_config\_t

#### typedef wifi\_twt\_setup\_config\_t wlan\_twt\_setup\_config\_t

> Configuration for TWT setup wifi\_twt\_setup\_config\_t

#### typedef wifi\_twt\_teardown\_config\_t wlan\_twt\_teardown\_config\_t

> Configuration for TWT teardown wifi\_twt\_teardown\_config\_t

#### typedef wifi\_btwt\_config\_t wlan\_btwt\_config\_t

> Configuration for Broadcast TWT setup wifi\_btwt\_config\_t

#### typedef wifi\_twt\_report\_t wlan\_twt\_report\_t

> Configuration for TWT report wifi\_twt\_report\_t

#### typedef wifi\_clock\_sync\_gpio\_tsf\_t wlan\_clock\_sync\_gpio\_tsf\_t

> Configuration for clock sync GPIO TSF latch
> wifi\_clock\_sync\_gpio\_tsf\_t

#### typedef wifi\_tsf\_info\_t wlan\_tsf\_info\_t

> Configuration for TSF info wifi\_tsf\_info\_t

#### typedef wifi\_csi\_config\_params\_t wlan\_csi\_config\_params\_t

> Configuration for CSI config params from wifi\_csi\_config\_params\_t

#### typedef wifi\_net\_monitor\_t wlan\_net\_monitor\_t

> Configuration for net monitor from wifi\_net\_monitor\_t

#### typedef txrate\_setting wlan\_txrate\_setting

> Configuration for TX rate setting from txrate\_setting

#### typedef wifi\_rssi\_info\_t wlan\_rssi\_info\_t

> Configuration for RSSI information wifi\_rssi\_info\_t

#### typedef wifi\_ds\_subscribe\_evt wlan\_ds\_subscribe\_evt

> Configuration for subscribe events from wlan\_ds\_subscribe\_evt

#### typedef wifi\_auto\_null\_tx\_t wlan\_auto\_null\_tx\_t

> Configuration for auto null TX parameters from wifi\_auto\_null\_tx\_t

### Enumeration Type Documentation

#### enum wm\_wlan\_errno

> Enum for Wi-Fi errors

##### Enumerator:

<table>
<tbody>
<tr class="odd">
<td>WLAN_ERROR_FW_DNLD_FAILED</td>
<td>The firmware download operation failed.</td>
</tr>
<tr class="even">
<td>WLAN_ERROR_FW_NOT_READY</td>
<td>The firmware ready register not set.</td>
</tr>
<tr class="odd">
<td>WLAN_ERROR_CARD_NOT_DETECTED</td>
<td>The Wi-Fi SoC not found.</td>
</tr>
<tr class="even">
<td>WLAN_ERROR_FW_NOT_DETECTED</td>
<td>The Wi-Fi Firmware not found.</td>
</tr>
<tr class="odd">
<td>WLAN_BSSID_NOT_FOUND_IN_SCAN_LIST</td>
<td>BSSID not found in scan list</td>
</tr>
</tbody>
</table>

#### enum wlan\_event\_reason

> Wi-Fi connection manager event reason

##### Enumerator:

<table>
<tbody>
<tr class="odd">
<td>WLAN_REASON_SUCCESS</td>
<td>The Wi-Fi connection manager has successfully connected to a network and is now in the WLAN_CONNECTED state.</td>
</tr>
<tr class="even">
<td>WLAN_REASON_AUTH_SUCCESS</td>
<td>The Wi-Fi connection manager has successfully authenticated to a network and is now in the WLAN_ASSOCIATED state.</td>
</tr>
<tr class="odd">
<td>WLAN_REASON_CONNECT_FAILED</td>
<td>The Wi-Fi connection manager failed to connect before actual connection attempt with AP due to incorrect Wi-Fi network profile. or the Wi-Fi connection manager failed to reconnect to previously connected network and it is now in the WLAN_DISCONNECTED state.</td>
</tr>
<tr class="even">
<td>WLAN_REASON_NETWORK_NOT_FOUND</td>
<td>The Wi-Fi connection manager could not find the network that it was connecting to and it is now in the WLAN_DISCONNECTED state.</td>
</tr>
<tr class="odd">
<td>WLAN_REASON_BGSCAN_NETWORK_NOT_FOUND</td>
<td>The Wi-Fi connection manager could not find the network in background scan during roam attempt that it was connecting to and it is now in the WLAN_CONNECTED state with previous AP.</td>
</tr>
<tr class="even">
<td>WLAN_REASON_NETWORK_AUTH_FAILED</td>
<td>The Wi-Fi connection manager failed to authenticate with the network and is now in the WLAN_DISCONNECTED state.</td>
</tr>
<tr class="odd">
<td>WLAN_REASON_ADDRESS_SUCCESS</td>
<td>DHCP lease has been renewed.</td>
</tr>
<tr class="even">
<td>WLAN_REASON_ADDRESS_FAILED</td>
<td>The Wi-Fi connection manager failed to obtain an IP address or TCP stack configuration has failed or the IP address configuration was lost due to a DHCP error. The system is now in the WLAN_DISCONNECTED state.</td>
</tr>
<tr class="odd">
<td>WLAN_REASON_LINK_LOST</td>
<td>The Wi-Fi connection manager has lost the link to the current network.</td>
</tr>
<tr class="even">
<td>WLAN_REASON_CHAN_SWITCH</td>
<td>The Wi-Fi connection manager has received the channel switch announcement from the current network.</td>
</tr>
<tr class="odd">
<td>WLAN_REASON_WPS_DISCONNECT</td>
<td>The Wi-Fi connection manager has disconnected from the WPS network (or has canceled a connection attempt) by request and is now in the WLAN_DISCONNECTED state.</td>
</tr>
<tr class="even">
<td>WLAN_REASON_USER_DISCONNECT</td>
<td>The Wi-Fi connection manager has disconnected from the current network (or has canceled a connection attempt) by request and is now in the WLAN_DISCONNECTED state.</td>
</tr>
<tr class="odd">
<td>WLAN_REASON_INITIALIZED</td>
<td>The Wi-Fi connection manager is initialized and is ready for use. That is, it's now possible to scan or to connect to a network.</td>
</tr>
<tr class="even">
<td>WLAN_REASON_INITIALIZATION_FAILED</td>
<td>The Wi-Fi connection manager has failed to initialize and is therefore not running. It is not possible to scan or to connect to a network. The Wi-Fi connection manager should be stopped and started again via wlan_stop() and wlan_start() respectively.</td>
</tr>
<tr class="odd">
<td>WLAN_REASON_FW_HANG</td>
<td>The Wi-Fi connection manager has entered in hang mode.</td>
</tr>
<tr class="even">
<td>WLAN_REASON_FW_RESET</td>
<td>The Wi-Fi connection manager has reset fw successfully.</td>
</tr>
<tr class="odd">
<td>WLAN_REASON_PS_ENTER</td>
<td>The Wi-Fi connection manager has entered power save mode.</td>
</tr>
<tr class="even">
<td>WLAN_REASON_PS_EXIT</td>
<td>The Wi-Fi connection manager has exited from power save mode.</td>
</tr>
<tr class="odd">
<td>WLAN_REASON_UAP_SUCCESS</td>
<td>The Wi-Fi connection manager has started uAP (micro access point)</td>
</tr>
<tr class="even">
<td>WLAN_REASON_UAP_CLIENT_ASSOC</td>
<td>A Wi-Fi client has joined uAP's BSS network</td>
</tr>
<tr class="odd">
<td>WLAN_REASON_UAP_CLIENT_CONN</td>
<td>A Wi-Fi client has authenticated and connected to uAP's BSS network</td>
</tr>
<tr class="even">
<td>WLAN_REASON_UAP_CLIENT_DISSOC</td>
<td>A Wi-Fi client has left uAP's BSS network</td>
</tr>
<tr class="odd">
<td>WLAN_REASON_UAP_START_FAILED</td>
<td>The Wi-Fi connection manager has failed to start uAP</td>
</tr>
<tr class="even">
<td>WLAN_REASON_UAP_STOP_FAILED</td>
<td>The Wi-Fi connection manager has failed to stop uAP</td>
</tr>
<tr class="odd">
<td>WLAN_REASON_UAP_STOPPED</td>
<td>The Wi-Fi connection manager has stopped uAP</td>
</tr>
<tr class="even">
<td>WLAN_REASON_RSSI_LOW</td>
<td>The Wi-Fi connection manager has received subscribed RSSI low event on station interface as per configured threshold and frequency. If CONFIG_11K, CONFIG_11V, CONFIG_11R or CONFIG_ROAMING enabled then RSSI low event is processed internally.</td>
</tr>
<tr class="odd">
<td>WLAN_REASON_RSSI_HIGH</td>
<td>The Wi-Fi connection manager has received subscribed RSSI high event on station interface as per configured threshold and frequency.</td>
</tr>
<tr class="even">
<td>WLAN_REASON_SNR_LOW</td>
<td>The Wi-Fi connection manager has received subscribed SNR low event on station interface as per configured threshold and frequency.</td>
</tr>
<tr class="odd">
<td>WLAN_REASON_SNR_HIGH</td>
<td>The Wi-Fi connection manager has received subscribed SNR high event on station interface as per configured threshold and frequency.</td>
</tr>
<tr class="even">
<td>WLAN_REASON_MAX_FAIL</td>
<td>The Wi-Fi connection manager has received subscribed maximum fail event on station interface as per configured threshold and frequency.</td>
</tr>
<tr class="odd">
<td>WLAN_REASON_BEACON_MISSED</td>
<td>The Wi-Fi connection manager has received subscribed beacon missed fail event on station interface as per configured threshold and frequency.</td>
</tr>
<tr class="even">
<td>WLAN_REASON_DATA_RSSI_LOW</td>
<td>The Wi-Fi connection manager has received subscribed data RSSI low event on station interface as per configured threshold and frequency.</td>
</tr>
<tr class="odd">
<td>WLAN_REASON_DATA_RSSI_HIGH</td>
<td>The Wi-Fi connection manager has received subscribed data RSSI high event on station interface as per configured threshold and frequency.</td>
</tr>
<tr class="even">
<td>WLAN_REASON_DATA_SNR_LOW</td>
<td>The Wi-Fi connection manager has received subscribed data SNR low event on station interface as per configured threshold and frequency.</td>
</tr>
<tr class="odd">
<td>WLAN_REASON_DATA_SNR_HIGH</td>
<td>The Wi-Fi connection manager has received subscribed data SNR high event on station interface as per configured threshold and frequency.</td>
</tr>
<tr class="even">
<td>WLAN_REASON_LINK_QUALITY</td>
<td>The Wi-Fi connection manager has received subscribed link quality event on station interface as per configured link_snr threshold and frequency, link_rate threshold and frequency, link_tx_latency threshold and frequency</td>
</tr>
<tr class="odd">
<td>WLAN_REASON_PRE_BEACON_LOST</td>
<td>The Wi-Fi connection manager has received subscribed pre beacon lost event on station interface as per configured threshold and frequency.</td>
</tr>
</tbody>
</table>

#### enum wlan\_wakeup\_event\_t

> Wakeup event bitmap

##### Enumerator:

<table>
<tbody>
<tr class="odd">
<td>WAKE_ON_ALL_BROADCAST</td>
<td>Wakeup on broadcast</td>
</tr>
<tr class="even">
<td>WAKE_ON_UNICAST</td>
<td>Wakeup on unicast</td>
</tr>
<tr class="odd">
<td>WAKE_ON_MAC_EVENT</td>
<td>Wakeup on MAC event</td>
</tr>
<tr class="even">
<td>WAKE_ON_MULTICAST</td>
<td>Wakeup on multicast</td>
</tr>
<tr class="odd">
<td>WAKE_ON_ARP_BROADCAST</td>
<td>Wakeup on ARP broadcast</td>
</tr>
<tr class="even">
<td>WAKE_ON_MGMT_FRAME</td>
<td>Wakeup on receiving a management frame</td>
</tr>
</tbody>
</table>

#### enum wlan\_connection\_state

> Wi-Fi station/uAP/Wi-Fi direct connection/status state

##### Enumerator:

<table>
<tbody>
<tr class="odd">
<td>WLAN_DISCONNECTED</td>
<td>The Wi-Fi connection manager is not connected and no connection attempt is in progress. It is possible to connect to a network or scan.</td>
</tr>
<tr class="even">
<td>WLAN_CONNECTING</td>
<td>The Wi-Fi connection manager is not connected but it is currently attempting to connect to a network. It is not possible to scan at this time. It is possible to connect to a different network.</td>
</tr>
<tr class="odd">
<td>WLAN_ASSOCIATED</td>
<td>The Wi-Fi connection manager is not connected but associated.</td>
</tr>
<tr class="even">
<td>WLAN_AUTHENTICATED</td>
<td>The Wi-Fi connection manager is not connected but authenticated.</td>
</tr>
<tr class="odd">
<td>WLAN_CONNECTED</td>
<td>The Wi-Fi connection manager is connected. It is possible to scan and connect to another network at this time. Information about the current network configuration is available.</td>
</tr>
<tr class="even">
<td>WLAN_UAP_STARTED</td>
<td>The Wi-Fi connection manager has started uAP</td>
</tr>
<tr class="odd">
<td>WLAN_UAP_STOPPED</td>
<td>The Wi-Fi connection manager has stopped uAP</td>
</tr>
<tr class="even">
<td>WLAN_SCANNING</td>
<td>The Wi-Fi connection manager is not connected and network scan is in progress.</td>
</tr>
<tr class="odd">
<td>WLAN_ASSOCIATING</td>
<td>The Wi-Fi connection manager is not connected and network association is in progress.</td>
</tr>
</tbody>
</table>

#### enum wlan\_ps\_mode

> Station power save mode

##### Enumerator:

<table>
<tbody>
<tr class="odd">
<td>WLAN_ACTIVE</td>
<td>Active mode</td>
</tr>
<tr class="even">
<td>WLAN_IEEE</td>
<td>IEEE power save mode</td>
</tr>
<tr class="odd">
<td>WLAN_DEEP_SLEEP</td>
<td>Deep sleep power save mode</td>
</tr>
<tr class="even">
<td>WLAN_IEEE_DEEP_SLEEP</td>
<td>IEEE and deep sleep power save mode</td>
</tr>
<tr class="odd">
<td>WLAN_WNM</td>
<td>WNM power save mode</td>
</tr>
<tr class="even">
<td>WLAN_WNM_DEEP_SLEEP</td>
<td>WNM and Deep sleep power save mode</td>
</tr>
</tbody>
</table>

#### enum wlan\_security\_type

> Network security types

##### Enumerator:

<table>
<tbody>
<tr class="odd">
<td>WLAN_SECURITY_NONE</td>
<td>The network does not use security.</td>
</tr>
<tr class="even">
<td>WLAN_SECURITY_WEP_OPEN</td>
<td>The network uses WEP security with open key.</td>
</tr>
<tr class="odd">
<td>WLAN_SECURITY_WEP_SHARED</td>
<td>The network uses WEP security with shared key.</td>
</tr>
<tr class="even">
<td>WLAN_SECURITY_WPA</td>
<td>The network uses WPA security with PSK.</td>
</tr>
<tr class="odd">
<td>WLAN_SECURITY_WPA2</td>
<td>The network uses WPA2 security with PSK.</td>
</tr>
<tr class="even">
<td>WLAN_SECURITY_WPA_WPA2_MIXED</td>
<td>The network uses WPA/WPA2 mixed security with PSK</td>
</tr>
<tr class="odd">
<td>WLAN_SECURITY_WPA2_FT</td>
<td>The network uses WPA2 security with PSK FT.</td>
</tr>
<tr class="even">
<td>WLAN_SECURITY_WPA3_SAE</td>
<td>The network uses WPA3 security with SAE.</td>
</tr>
<tr class="odd">
<td>WLAN_SECURITY_WPA3_FT_SAE</td>
<td>The network uses WPA3 security with SAE FT.</td>
</tr>
<tr class="even">
<td>WLAN_SECURITY_WPA3_SAE_EXT_KEY</td>
<td>The network uses WPA3 security with new SAE AKM suite 24.</td>
</tr>
<tr class="odd">
<td>WLAN_SECURITY_WPA2_WPA3_SAE_MIXED</td>
<td>The network uses WPA2/WPA3 SAE mixed security with PSK.</td>
</tr>
<tr class="even">
<td>WLAN_SECURITY_OWE_ONLY</td>
<td>The network uses OWE only security without Transition mode support.</td>
</tr>
<tr class="odd">
<td>WLAN_SECURITY_EAP_TLS</td>
<td>The network uses WPA2 Enterprise EAP-TLS security The identity field in wlan_network structure is used</td>
</tr>
<tr class="even">
<td>WLAN_SECURITY_EAP_TLS_SHA256</td>
<td>The network uses WPA2 Enterprise EAP-TLS SHA256 security. The identity field in wlan_network structure is used</td>
</tr>
<tr class="odd">
<td>WLAN_SECURITY_EAP_TLS_FT</td>
<td>The network uses WPA2 Enterprise EAP-TLS FT security. The identity field in wlan_network structure is used</td>
</tr>
<tr class="even">
<td>WLAN_SECURITY_EAP_TLS_FT_SHA384</td>
<td>The network uses WPA2 Enterprise EAP-TLS FT SHA384 security The identity field in wlan_network structure is used</td>
</tr>
<tr class="odd">
<td>WLAN_SECURITY_EAP_TTLS</td>
<td>The network uses WPA2 Enterprise EAP-TTLS security. The identity field in wlan_network structure is used</td>
</tr>
<tr class="even">
<td>WLAN_SECURITY_EAP_TTLS_MSCHAPV2</td>
<td>The network uses WPA2 Enterprise EAP-TTLS-MSCHAPV2 security. The anonymous identity, identity and password fields in wlan_network structure are used</td>
</tr>
<tr class="odd">
<td>WLAN_SECURITY_EAP_PEAP_MSCHAPV2</td>
<td>The network uses WPA2 Enterprise EAP-PEAP-MSCHAPV2 security. The anonymous identity, identity and password fields in wlan_network structure are used</td>
</tr>
<tr class="even">
<td>WLAN_SECURITY_EAP_PEAP_TLS</td>
<td>The network uses WPA2 Enterprise EAP-PEAP-TLS security. The anonymous identity, identity and password fields in wlan_network structure are used</td>
</tr>
<tr class="odd">
<td>WLAN_SECURITY_EAP_PEAP_GTC</td>
<td>The network uses WPA2 Enterprise EAP-PEAP-GTC security. The anonymous identity, identity and password fields in wlan_network structure are used</td>
</tr>
<tr class="even">
<td>WLAN_SECURITY_EAP_FAST_MSCHAPV2</td>
<td>The network uses WPA2 Enterprise EAP-FAST-MSCHAPV2 security. The anonymous identity, identity and password fields in wlan_network structure are used</td>
</tr>
<tr class="odd">
<td>WLAN_SECURITY_EAP_FAST_GTC</td>
<td>The network uses WPA2 Enterprise EAP-FAST-GTC security The anonymous identity, identity and password fields in wlan_network structure are used</td>
</tr>
<tr class="even">
<td>WLAN_SECURITY_EAP_SIM</td>
<td>The network uses WPA2 Enterprise EAP-SIM security The identity and password fields in wlan_network structure are used</td>
</tr>
<tr class="odd">
<td>WLAN_SECURITY_EAP_AKA</td>
<td>The network uses WPA2 Enterprise EAP-AKA security The identity and password fields in wlan_network structure are used</td>
</tr>
<tr class="even">
<td>WLAN_SECURITY_EAP_AKA_PRIME</td>
<td>The network uses WPA2 Enterprise EAP-AKA-PRIME security The identity and password fields in wlan_network structure are used</td>
</tr>
<tr class="odd">
<td>WLAN_SECURITY_DPP</td>
<td>The network uses DPP security with NAK(Net Access Key)</td>
</tr>
<tr class="even">
<td>WLAN_SECURITY_WILDCARD</td>
<td>The network can use any security method. This is often used when the user only knows the name and passphrase but not the security type.</td>
</tr>
</tbody>
</table>

#### enum eap\_tls\_cipher\_type

> EAP TLS Cipher types

##### Enumerator:

<table>
<tbody>
<tr class="odd">
<td>EAP_TLS_ECC_P384</td>
<td>EAP TLS with ECDH &amp; ECDSA with p384</td>
</tr>
<tr class="even">
<td>EAP_TLS_RSA_3K</td>
<td>EAP TLS with ECDH &amp; RSA with &gt; 3K</td>
</tr>
</tbody>
</table>

#### enum address\_types

> Address types to be used by the element wlan\_ip\_config.addr\_type
> below

##### Enumerator:

<table>
<tbody>
<tr class="odd">
<td>ADDR_TYPE_STATIC</td>
<td>Static IP address</td>
</tr>
<tr class="even">
<td>ADDR_TYPE_DHCP</td>
<td>Dynamic IP address</td>
</tr>
<tr class="odd">
<td>ADDR_TYPE_LLA</td>
<td>Link level address</td>
</tr>
<tr class="even">
<td>ADDR_TYPE_BRIDGE_MODE</td>
<td>For Bridge Mode, no IP address</td>
</tr>
</tbody>
</table>

#### enum sub\_event\_id

> Type enum definition of subscribe event

##### Enumerator:

<table>
<tbody>
<tr class="odd">
<td>EVENT_SUB_RSSI_LOW</td>
<td>Event Id for subscribe event RSSI low</td>
</tr>
<tr class="even">
<td>EVENT_SUB_RSSI_HIGH</td>
<td>Event Id for subscribe event RSSI high</td>
</tr>
<tr class="odd">
<td>EVENT_SUB_SNR_LOW</td>
<td>Event Id for subscribe event snr low</td>
</tr>
<tr class="even">
<td>EVENT_SUB_SNR_HIGH</td>
<td>Event Id for subscribe event snr high</td>
</tr>
<tr class="odd">
<td>EVENT_SUB_MAX_FAIL</td>
<td>Event Id for subscribe event max fail</td>
</tr>
<tr class="even">
<td>EVENT_SUB_BEACON_MISSED</td>
<td>Event Id for subscribe event beacon missed</td>
</tr>
<tr class="odd">
<td>EVENT_SUB_DATA_RSSI_LOW</td>
<td>Event Id for subscribe event data RSSI low</td>
</tr>
<tr class="even">
<td>EVENT_SUB_DATA_RSSI_HIGH</td>
<td>Event Id for subscribe event data RSSI high</td>
</tr>
<tr class="odd">
<td>EVENT_SUB_DATA_SNR_LOW</td>
<td>Event Id for subscribe event data snr low</td>
</tr>
<tr class="even">
<td>EVENT_SUB_DATA_SNR_HIGH</td>
<td>Event Id for subscribe event data snr high</td>
</tr>
<tr class="odd">
<td>EVENT_SUB_LINK_QUALITY</td>
<td>Event Id for subscribe event link quality</td>
</tr>
<tr class="even">
<td>EVENT_SUB_PRE_BEACON_LOST</td>
<td>Event Id for subscribe event pre_beacon_lost</td>
</tr>
<tr class="odd">
<td>MAX_EVENT_ID</td>
<td>Fail event id</td>
</tr>
</tbody>
</table>

# Index

INDEX
