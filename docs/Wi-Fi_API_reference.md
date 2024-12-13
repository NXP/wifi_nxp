Table of contents

Main Page
=========

Introduction
------------

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
>
> Abbreviations and acronyms
>
> ACS auto channel selection
>
> AID association ID
>
> AMPDU aggregate medium access control protocol data unit
>
> AP Access Point
>
> ARP address resolution protocol
>
> BSS basic service set
>
> BSSID basic servivce set ID
>
> BTM BSS transition management
>
> CA Certificate Authority
>
> CCK complementary code keying
>
> CLI command line input
>
> CSI channel state information
>
> CW continuous wave
>
> DH Diffie Hellman
>
> DPP device provisioning protocol
>
> DTIM delivery traffic indication map
>
> EAP Extensible Authentication Protocol
>
> EAP TLS Extensible Authentication Protocol Transport Layer Security
>
> FCS frame check sequence
>
> FTM fine timing measurement
>
> GI guard interval
>
> HE 802.11ax high efficiency
>
> HT 802.11n high throughput
>
> HTC high throughput control
>
> LDPC low density parity check
>
> MBO multi band operation
>
> MEF memory efficient filtering
>
> MFPC Management Frame Protection Capable
>
> MFPR Management frame protection required
>
> NSS N\*N MIMO spatial stream
>
> OBSS overlapping basic service set
>
> OCE Optimized connectivity experience
>
> OMI operating mode indication
>
> OWE opportunistic wireless encryption
>
> PBC push button configuration
>
> PEAP Protected Extensible Authentication Protocol
>
> PKEX Public Key Exchange
>
> PMF protected management frame
>
> PMK pairwise master key
>
> PMKSA pairwise master key security association
>
> PS power save
>
> PTA packet traffic arbitration
>
> PWE Password Element
>
> QoS quality of service
>
> RSSI received signal strength indicator
>
> RTS request to send
>
> SAD software antenna diversity
>
> SAE Simultaneous Authentication of Equals
>
> SSID service set ID
>
> STBC space time block code
>
> TBTT target beacon transmission time
>
> TIM Traffic Indication Map
>
> TRPC transient receptor potential canonical
>
> TSF timing synchronization function
>
> TSP thermal safeguard protection
>
> TWT target wake time
>
> UAPSD unscheduled automatic power save delivery
>
> VHT 802.11ac very high throughput
>
> WLCMGR Wi-Fi command manager

Data Structure Index
====================

Data Structures
---------------

Here are the data structures with brief descriptions:

**ipv4\_config** 

**wifi\_scan\_params\_t** 

**wlan\_cipher** 

**wlan\_ieeeps\_config** 

**wlan\_ip\_config** 

**wlan\_network** 

**wlan\_network\_security** 

**wlan\_scan\_result** 

File Index
==========

File List
---------

Here is a list of all documented files with brief descriptions:

**wlan.h (This file provides Wi-Fi APIs for the application )** 

Data Structure Documentation
============================

ipv4\_config Struct Reference
-----------------------------

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

wifi\_scan\_params\_t Struct Reference
--------------------------------------

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

wlan\_cipher Struct Reference
-----------------------------

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

wlan\_ieeeps\_config Struct Reference
-------------------------------------

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

wlan\_ip\_config Struct Reference
---------------------------------

### Data Fields

struct ipv4\_config ipv4

### Detailed Description

Network IP configuration.

This data structure represents the network IP configuration for IPv4 as
well as IPv6 addresses

### Field Documentation

#### struct ipv4\_config wlan\_ip\_config::ipv4

> The network IPv4 address configuration that should be associated with
> this interface.

#### The documentation for this struct was generated from the following file:

wlan.h

#### 

wlan\_network Struct Reference
------------------------------

### Data Fields

char name \[WLAN\_NETWORK\_NAME\_MAX\_LENGTH+1\]

char ssid \[IEEEtypes\_SSID\_SIZE+1\]

char bssid \[IEEEtypes\_ADDRESS\_SIZE\]

unsigned int channel

uint8\_t sec\_channel\_offset

uint16\_t acs\_band

int rssi

enum wlan\_bss\_type type

enum wlan\_bss\_role role

struct wlan\_network\_security security

struct wlan\_ip\_config ip

unsigned ssid\_specific: 1

unsigned bssid\_specific: 1

unsigned channel\_specific: 1

unsigned security\_specific: 1

unsigned dot11n: 1

uint16\_t beacon\_period

uint8\_t dtim\_period

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

#### uint16\_t wlan\_network::beacon\_period

> Beacon period of associated BSS

#### uint8\_t wlan\_network::dtim\_period

> DTIM period of associated BSS

#### The documentation for this struct was generated from the following file:

wlan.h

#### 

wlan\_network\_security Struct Reference
----------------------------------------

### Data Fields

enum wlan\_security\_type type

int key\_mgmt

struct wlan\_cipher mcstCipher

struct wlan\_cipher ucstCipher

bool is\_pmf\_required

char psk \[WLAN\_PSK\_MAX\_LENGTH\]

uint8\_t psk\_len

char password \[WLAN\_PASSWORD\_MAX\_LENGTH+1\]

size\_t password\_len

char \* sae\_groups

uint8\_t pwe\_derivation

uint8\_t transition\_disable

char pmk \[WLAN\_PMK\_LENGTH\]

bool pmk\_valid

int8\_t mfpc

int8\_t mfpr

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

#### The documentation for this struct was generated from the following file:

wlan.h

#### 

wlan\_scan\_result Struct Reference
-----------------------------------

### Data Fields

char ssid \[WLAN\_NETWORK\_NAME\_MAX\_LENGTH+1\]

unsigned int ssid\_len

char bssid \[IEEEtypes\_ADDRESS\_SIZE\]

unsigned int channel

enum wlan\_bss\_type type

enum wlan\_bss\_role role

unsigned dot11n: 1

unsigned wmm: 1

unsigned wep: 1

unsigned wpa: 1

unsigned wpa2: 1

unsigned wpa2\_sha256: 1

unsigned wpa3\_sae: 1

unsigned wpa2\_entp: 1

unsigned wpa2\_entp\_sha256: 1

unsigned wpa3\_1x\_sha256: 1

unsigned wpa3\_1x\_sha384: 1

unsigned char rssi

char trans\_ssid \[WLAN\_NETWORK\_NAME\_MAX\_LENGTH+1\]

unsigned int trans\_ssid\_len

char trans\_bssid \[IEEEtypes\_ADDRESS\_SIZE\]

uint16\_t beacon\_period

uint8\_t dtim\_period

t\_u8 ap\_mfpc

t\_u8 ap\_mfpr

t\_u8 ap\_pwe

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

#### unsigned wlan\_scan\_result::wmm

> The network supports WMM. This is set to 0 if the network does not
> support WMM or if the system does not have WMM support enabled.

#### unsigned wlan\_scan\_result::wep

> The network uses WEP security.

#### unsigned wlan\_scan\_result::wpa

> The network uses WPA security.

#### unsigned wlan\_scan\_result::wpa2

> The network uses WPA2 security

#### unsigned wlan\_scan\_result::wpa2\_sha256

> The network uses WPA2 SHA256 security

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

#### The documentation for this struct was generated from the following file:

wlan.h

File Documentation
==================

wlan.h File Reference
---------------------

This file provides Wi-Fi APIs for the application.

### Function Documentation

#### int verify\_scan\_duration\_value (int *scan\_duration*)

> Check whether the scan duration is valid or not.

##### Parameters

  ---- ------------------ --------------------
  in   *scan\_duration*   scan duration time
  ---- ------------------ --------------------

##### Returns

> 0 if the time is valid, else return -1.

#### int verify\_scan\_channel\_value (int *channel*)

> Check whether the scan channel is valid or not.

##### Parameters

  ---- ----------- ------------------
  in   *channel*   the scan channel
  ---- ----------- ------------------

##### Returns

> 0 if the channel is valid, else return -1.

#### int verify\_split\_scan\_delay (int *delay*)

> Check whether the scan delay time is valid or not.

##### Parameters

  ---- --------- ----------------------
  in   *delay*   the scan delay time.
  ---- --------- ----------------------

##### Returns

> 0 if the time is valid, else return -1.

#### int set\_scan\_params (struct wifi\_scan\_params\_t \* *wifi\_scan\_params*)

> Set the scan parameters.

##### Parameters

  ---- ---------------------- -----------------------------------------
  in   *wifi\_scan\_params*   Wi-Fi scan parameter structure pointer.
  ---- ---------------------- -----------------------------------------

##### Returns

> 0 if Wi-Fi scan parameters are set successfully, else return -1.

#### int get\_scan\_params (struct wifi\_scan\_params\_t \* *wifi\_scan\_params*)

> Get the scan parameters.

##### Parameters

  ----- ---------------------- -----------------------------------------
  out   *wifi\_scan\_params*   Wi-Fi scan parameter structure pointer.
  ----- ---------------------- -----------------------------------------

##### Returns

> WM\_SUCCESS.

#### int wlan\_get\_current\_rssi (short \* *rssi*)

> Get the current RSSI value.

##### Parameters

  ----- -------- ----------------------------------------------------------------------
  out   *rssi*   pointer to get the current RSSI (Received Signal Strength Indicator)
  ----- -------- ----------------------------------------------------------------------

##### Returns

> WM\_SUCCESS.

#### int wlan\_get\_current\_nf (void )

> Get the current noise floor.

##### Returns

> The noise floor value

#### int wlan\_init (const uint8\_t \* *fw\_start\_addr*, const size\_t *size*)

> Initialize the Wi-Fi driver and create the Wi-Fi driver thread.

##### Parameters

  ---- ------------------- --------------------------------------
  in   *fw\_start\_addr*   Start address of the Wi-Fi firmware.
  in   *size*              Size of the Wi-Fi firmware.
  ---- ------------------- --------------------------------------

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

  ---- ------ ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  in   *cb*   A pointer to a callback function that handles Wi-Fi events. All further WLCMGR events can be notified in this callback. Refer to enum wlan\_event\_reason for the various events for which this callback is called.
  ---- ------ ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

##### Returns

> WM\_SUCCESS if the Wi-Fi connection manager service has started
> successfully.
>
> -WM\_E\_INVAL if the *cb* pointer is NULL.
>
> -WM\_FAIL if an internal error occurred.
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

  ---- ---------- -----------------------------------------------------------------
  in   *action*   Additional action to be taken with deinit. Should input 0 here.
  ---- ---------- -----------------------------------------------------------------

#### int wlan\_remove\_all\_network\_profiles (void )

> Stop and remove all Wi-Fi network profiles.

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_E\_INVAL.

#### void wlan\_reset (cli\_reset\_option *ResetOption*)

> Reset the driver.

##### Parameters

  ---- --------------- -----------------------------------------------------------------------
  in   *ResetOption*   Option including enable, disable or reset Wi-Fi driver can be chosen.
  ---- --------------- -----------------------------------------------------------------------

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

#### void wlan\_initialize\_uap\_network (struct wlan\_network \* *net*)

> Initialize the uAP network information.
>
> This API initializes a uAP network with default configurations. The
> network ssid, passphrase is initialized to NULL. Channel is set to
> auto. The IP Address of the uAP interface is
> 192.168.10.1/255.255.255.0. The network name is set to
> \'uap-network\'.

##### Parameters

  ----- ------- ----------------------------------------
  out   *net*   Pointer to the initialized uAP network
  ----- ------- ----------------------------------------

#### void wlan\_initialize\_sta\_network (struct wlan\_network \* *net*)

> Initialize the station network information.
>
> This API initializes a station network with default configurations.
> The network ssid, passphrase is initialized to NULL. Channel is set to
> auto.

##### Parameters

  ----- ------- --------------------------------------------
  out   *net*   Pointer to the initialized station network
  ----- ------- --------------------------------------------

#### int wlan\_add\_network (struct wlan\_network \* *network*)

> Add a network profile to the list of known networks.
>
> This function copies the contents of *network* to the list of known
> networks in the Wi-Fi connection manager. The network\'s \'name\'
> field is unique and between WLAN\_NETWORK\_NAME\_MIN\_LENGTH and
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

  ---- ----------- -------------------------------------------------------------------------------------------------------------------------------
  in   *network*   A pointer to the wlan\_network that can be copied to the list of known networks in the Wi-Fi connection manager successfully.
  ---- ----------- -------------------------------------------------------------------------------------------------------------------------------

##### Returns

> WM\_SUCCESS if the contents pointed to by *network* have been added to
> the Wi-Fi connection manager.
>
> -WM\_E\_INVAL if *network* is NULL or the network name is not unique
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
> -WM\_E\_NOMEM if there was no room to add the network.
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

  ---- -------- -------------------------------------------------------------------------
  in   *name*   A pointer to the string representing the name of the network to remove.
  ---- -------- -------------------------------------------------------------------------

##### Returns

> WM\_SUCCESS if the network named *name* was removed from the Wi-Fi
> connection manager successfully. Otherwise, the network is not
> removed.
>
> WLAN\_ERROR\_STATE if the Wi-Fi connection manager was running and the
> station interface was not in the WLAN\_DISCONNECTED state.
>
> -WM\_E\_INVAL if *name* is NULL or the network was not found in the
> list of known networks.
>
> -WM\_FAIL if an internal error occurred while trying to disconnect
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

  ---- -------- ---------------------------------------------------------------------------
  in   *name*   A pointer to a string representing the name of the network to connect to.
  ---- -------- ---------------------------------------------------------------------------

##### Returns

> WM\_SUCCESS if a connection attempt was started successfully
>
> WLAN\_ERROR\_STATE if the Wi-Fi connection manager was not running.
>
> -WM\_E\_INVAL if there are no known networks to connect to or the
> network specified by *name* is not in the list of known networks or
> network *name* is NULL.
>
> -WM\_FAIL if an internal error has occurred.

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

  ---- ------------- ---------------------------------------------------------------------------
  in   *name*        A pointer to a string representing the name of the network to connect to.
  in   *skip\_dfs*   Option to skip DFS channel when doing scan.
  ---- ------------- ---------------------------------------------------------------------------

##### Returns

> WM\_SUCCESS if a connection attempt was started successfully
>
> WLAN\_ERROR\_STATE if the Wi-Fi connection manager was not running.
>
> -WM\_E\_INVAL if there are no known networks to connect to or the
> network specified by *name* is not in the list of known networks or
> network *name* is NULL.
>
> -WM\_FAIL if an internal error has occurred.

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
> -WM\_E\_INVAL if there are no known networks to connect to
>
> -WM\_FAIL if an internal error has occurred.

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

  ---- -------- -------------------------------------------------------------------------
  in   *name*   A pointer to string representing the name of the network to connect to.
  ---- -------- -------------------------------------------------------------------------

##### Returns

> WM\_SUCCESS if successful.
>
> WLAN\_ERROR\_STATE if in power save state or uAP already running.
>
> -WM\_E\_INVAL if *name* was NULL or the network *name* was not found
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

  ---- -------- ---------------------------------------------------------------------
  in   *name*   A pointer to a string representing the name of the network to stop.
  ---- -------- ---------------------------------------------------------------------

##### Returns

> WM\_SUCCESS if successful.
>
> WLAN\_ERROR\_STATE if uAP is in power save state.
>
> -WM\_E\_INVAL if *name* was NULL or the network *name* was not found
> or that the network *name* is not a uAP network or it is a uAP network
> but does not have a specified SSID.

#### int wlan\_get\_mac\_address (uint8\_t \* *dest*)

> Retrieve the Wi-Fi MAC address of the station interface.
>
> This function copies the MAC address of the Wi-Fi station interface to
> the 6-byte array pointed to by *dest* . In the event of an error,
> nothing is copied to *dest* .

##### Parameters

  ----- -------- ---------------------------------------------------------------------
  out   *dest*   A pointer to a 6-byte array where the MAC address should be copied.
  ----- -------- ---------------------------------------------------------------------

##### Returns

> WM\_SUCCESS if the MAC address was copied.
>
> -WM\_E\_INVAL if *dest* is NULL.

#### int wlan\_get\_mac\_address\_uap (uint8\_t \* *dest*)

> Retrieve the Wi-Fi MAC address of the uAP interface.
>
> This function copies the MAC address of the Wi-Fi uAP interface to the
> 6-byte array pointed to by *dest* . In the event of an error, nothing
> is copied to *dest* .

##### Parameters

  ----- -------- ------------------------------------------------------------------
  out   *dest*   A pointer to a 6-byte array where the MAC address can be copied.
  ----- -------- ------------------------------------------------------------------

##### Returns

> WM\_SUCCESS if the MAC address was copied.
>
> -WM\_E\_INVAL if *dest* is NULL.

#### int wlan\_get\_address (struct wlan\_ip\_config \* *addr*)

> Retrieve the IP address configuration of the station interface.
>
> This function retrieves the IP address configuration of the station
> interface and copies it to the memory location pointed to by *addr* .

##### Note

> This function may only be called when the station interface is in the
> WLAN\_CONNECTED state.

##### Parameters

  ----- -------- ------------------------------------
  out   *addr*   A pointer to the wlan\_ip\_config.
  ----- -------- ------------------------------------

##### Returns

> WM\_SUCCESS if successful.
>
> -WM\_E\_INVAL if *addr* is NULL.
>
> WLAN\_ERROR\_STATE if the Wi-Fi connection manager was not running or
> was not in the WLAN\_CONNECTED state.
>
> -WM\_FAIL if an internal error occurred when retrieving IP address
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

  ----- -------- ------------------------------------
  out   *addr*   A pointer to the wlan\_ip\_config.
  ----- -------- ------------------------------------

##### Returns

> WM\_SUCCESS if successful.
>
> -WM\_E\_INVAL if *addr* is NULL.
>
> WLAN\_ERROR\_STATE if the Wi-Fi connection manager was not running or
> the uAP interface was not in the WLAN\_UAP\_STARTED state.
>
> -WM\_FAIL if an internal error occurred when retrieving IP address
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

  ----- ----------- ---------------------------------------------------
  out   *channel*   A pointer to variable that stores channel number.
  ----- ----------- ---------------------------------------------------

##### Returns

> WM\_SUCCESS if successful.
>
> -WM\_E\_INVAL if *channel* is NULL.
>
> -WM\_FAIL if an internal error has occurred.

#### int wlan\_get\_current\_network (struct wlan\_network \* *network*)

> Retrieve the current network configuration of the station interface.
>
> This function retrieves the current network configuration of the
> station interface when the station interface is in the WLAN\_CONNECTED
> state.

##### Parameters

  ----- ----------- ---------------------------------
  out   *network*   A pointer to the wlan\_network.
  ----- ----------- ---------------------------------

##### Returns

> WM\_SUCCESS if successful.
>
> -WM\_E\_INVAL if *network* is NULL.
>
> WLAN\_ERROR\_STATE if the Wi-Fi connection manager was not running or
> not in the WLAN\_CONNECTED state.

#### int wlan\_get\_current\_network\_ssid (char \* *ssid*)

> Retrieve the current network ssid of the station interface.
>
> This function retrieves the current network ssid of the station
> interface when the station interface is in the WLAN\_CONNECTED state.

##### Parameters

  ----- -------- ---------------------------------------------------------------------------------------------------------------
  out   *ssid*   A pointer to the ssid char string with NULL termination. Maximum length is 32 (not include NULL termination).
  ----- -------- ---------------------------------------------------------------------------------------------------------------

##### Returns

> WM\_SUCCESS if successful.
>
> -WM\_E\_INVAL if *ssid* is NULL.
>
> WLAN\_ERROR\_STATE if the Wi-Fi connection manager was not running or
> not in the WLAN\_CONNECTED state.

#### int wlan\_get\_current\_network\_bssid (char \* *bssid*)

> Retrieve the current network bssid of the station interface.
>
> This function retrieves the current network bssid of the station
> interface when the station interface is in the WLAN\_CONNECTED state.

##### Parameters

  ----- --------- --------------------------------------------------------------
  out   *bssid*   A pointer to the bssid char string without NULL termination.
  ----- --------- --------------------------------------------------------------

##### Returns

> WM\_SUCCESS if successful.
>
> -WM\_E\_INVAL if *bssid* is NULL.
>
> WLAN\_ERROR\_STATE if the Wi-Fi connection manager was not running or
> not in the WLAN\_CONNECTED state.

#### int wlan\_get\_current\_uap\_network (struct wlan\_network \* *network*)

> Retrieve the current network configuration of the uAP interface.
>
> This function retrieves the current network configuration of the uAP
> interface when the uAP interface is in the WLAN\_UAP\_STARTED state.

##### Parameters

  ----- ----------- ---------------------------------
  out   *network*   A pointer to the wlan\_network.
  ----- ----------- ---------------------------------

##### Returns

> WM\_SUCCESS if successful.
>
> -WM\_E\_INVAL if *network* is NULL.
>
> WLAN\_ERROR\_STATE if the Wi-Fi connection manager was not running or
> not in the WLAN\_UAP\_STARTED state.

#### int wlan\_get\_current\_uap\_network\_ssid (char \* *ssid*)

> Retrieve the current network ssid of the uAP interface.
>
> This function retrieves the current network ssid of the uAP interface
> when the uAP interface is in the WLAN\_UAP\_STARTED state.

##### Parameters

  ----- -------- ---------------------------------------------------------------------------------------------------------------
  out   *ssid*   A pointer to the ssid char string with NULL termination. Maximum length is 32 (not include NULL termination).
  ----- -------- ---------------------------------------------------------------------------------------------------------------

##### Returns

> WM\_SUCCESS if successful.
>
> -WM\_E\_INVAL if *ssid* is NULL.
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

  ----- ----------- ----------------------------------------------------------------------------------------------------------
  in    *index*     The index of the network to retrieve.
  out   *network*   A pointer to the wlan\_network where the network configuration for the network at *index* can be copied.
  ----- ----------- ----------------------------------------------------------------------------------------------------------

##### Returns

> WM\_SUCCESS if successful.
>
> -WM\_E\_INVAL if *network* is NULL or *index* is out of range.

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

  ----- ----------- ------------------------------------------------------------------------------------------------------------------------
  in    *name*      The name of the network to retrieve.
  out   *network*   A pointer to the wlan\_network where the network configuration for the network having name as *name* should be copied.
  ----- ----------- ------------------------------------------------------------------------------------------------------------------------

##### Returns

> WM\_SUCCESS if successful.
>
> -WM\_E\_INVAL if *network* is NULL or *name* is NULL.

#### int wlan\_get\_network\_count (unsigned int \* *count*)

> Retrieve the number of networks known to the Wi-Fi connection manager.
>
> This function retrieves the number of known networks in the list
> maintained by the Wi-Fi connection manager and copies it to *count* .

##### Note

> This function can be called regardless of whether the Wi-Fi Connection
> Manager is running or not. Calls to this function are synchronous.

##### Parameters

  ----- --------- ---------------------------------------------------------------------------------
  out   *count*   A pointer to the memory location where the number of networks should be copied.
  ----- --------- ---------------------------------------------------------------------------------

##### Returns

> WM\_SUCCESS if successful.
>
> -WM\_E\_INVAL if *count* is NULL.

#### int wlan\_get\_connection\_state (enum wlan\_connection\_state \* *state*)

> Retrieve the connection state of the station interface.
>
> This function retrieves the connection state of the station interface,
> which is one of WLAN\_DISCONNECTED, WLAN\_CONNECTING, WLAN\_ASSOCIATED
> or WLAN\_CONNECTED.

##### Parameters

  ----- --------- -----------------------------------------------------------------------------------------------
  out   *state*   A pointer to the wlan\_connection\_state where the current connection state should be copied.
  ----- --------- -----------------------------------------------------------------------------------------------

##### Returns

> WM\_SUCCESS if successful.
>
> -WM\_E\_INVAL if *state* is NULL
>
> WLAN\_ERROR\_STATE if the Wi-Fi connection manager was not running.

#### int wlan\_get\_uap\_connection\_state (enum wlan\_connection\_state \* *state*)

> Retrieve the connection state of the uAP interface.
>
> This function retrieves the connection state of the uAP interface,
> which is one of WLAN\_UAP\_STARTED, or WLAN\_UAP\_STOPPED.

##### Parameters

  ----- --------- -----------------------------------------------------------------------------------------------
  out   *state*   A pointer to the wlan\_connection\_state where the current connection state should be copied.
  ----- --------- -----------------------------------------------------------------------------------------------

##### Returns

> WM\_SUCCESS if successful.
>
> -WM\_E\_INVAL if *state* is NULL
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

  ---- ------ -------------------------------------------------------------------------------------------------
  in   *cb*   A pointer to the function that should be called to handle scan results when they are available.
  ---- ------ -------------------------------------------------------------------------------------------------

##### Returns

> WM\_SUCCESS if successful.
>
> -WM\_E\_NOMEM if failed to allocated memory for
> wlan\_scan\_params\_v2\_t structure.
>
> -WM\_E\_INVAL if *cb* scan result callback function pointer is NULL.
>
> WLAN\_ERROR\_STATE if the Wi-Fi connection manager was not running or
> not in the WLAN\_DISCONNECTED or WLAN\_CONNECTED states.
>
> -WM\_FAIL if an internal error has occurred and the system is unable
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

  ---- ------------------------ ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  in   *t\_wlan\_scan\_param*   A wlan\_scan\_params\_v2\_t structure holding a pointer to function that should be called to handle scan results when they are available, SSID of a Wi-Fi network, BSSID of a Wi-Fi network, number of channels with scan type information and number of probes.
  ---- ------------------------ ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

##### Returns

> WM\_SUCCESS if successful.
>
> -WM\_E\_NOMEM if failed to allocated memory for
> wlan\_scan\_params\_v2\_t structure.
>
> -WM\_E\_INVAL if *cb* scan result callback function pointer is NULL.
>
> WLAN\_ERROR\_STATE if the Wi-Fi connection manager was not running or
> not in the WLAN\_DISCONNECTED or WLAN\_CONNECTED states.
>
> -WM\_FAIL if an internal error has occurred and the system is unable
> to scan.

#### int wlan\_get\_scan\_result (unsigned int *index*, struct wlan\_scan\_result \* *res*)

> Retrieve a scan result.
>
> This function can be called to retrieve scan results when the Wi-Fi
> connection manager has finished scanning. It is called from within the
> scan result callback (see wlan\_scan()) as scan results are valid only
> in that context. The callback argument \'count\' provides the number
> of scan results that can be retrieved and wlan\_get\_scan\_result()
> can be used to retrieve scan results at *index* 0 through that number.

##### Note

> This function may only be called in the context of the scan results
> callback.
>
> Calls to this function are synchronous.

##### Parameters

  ----- --------- -----------------------------------------------------------------------------------------
  in    *index*   The scan result to retrieve.
  out   *res*     A pointer to the wlan\_scan\_result where the scan result information should be copied.
  ----- --------- -----------------------------------------------------------------------------------------

##### Returns

> WM\_SUCCESS if successful.
>
> -WM\_E\_INVAL if *res* is NULL
>
> WLAN\_ERROR\_STATE if the Wi-Fi connection manager was not running
>
> -WM\_FAIL if the scan result at *index* could not be retrieved (that
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

  ---- ----------------------- ----------------------------------------------------------------------------------------------------------------------------------
  in   *wlan\_ed\_mac\_ctrl*   Struct with following parameters ed\_ctrl\_2g 0 - disable EU adaptivity for 2.4GHz band 1 - enable EU adaptivity for 2.4GHz band
  ---- ----------------------- ----------------------------------------------------------------------------------------------------------------------------------

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
> -WM\_FAIL if failed.

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

  ---- ----------------------- ----------------------------------------------------------------------------------------------------------------------------------
  in   *wlan\_ed\_mac\_ctrl*   Struct with following parameters ed\_ctrl\_2g 0 - disable EU adaptivity for 2.4GHz band 1 - enable EU adaptivity for 2.4GHz band
  ---- ----------------------- ----------------------------------------------------------------------------------------------------------------------------------

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
> -WM\_FAIL if failed.

#### int wlan\_get\_ed\_mac\_mode (wlan\_ed\_mac\_ctrl\_t \* *wlan\_ed\_mac\_ctrl*)

> This API can be used to get current ED MAC MODE configuration for
> station.

##### Parameters

  ----- ----------------------- ---------------------------------------------------------------------------------
  out   *wlan\_ed\_mac\_ctrl*   A pointer to wlan\_ed\_mac\_ctrl\_t with parameters mentioned in above set API.
  ----- ----------------------- ---------------------------------------------------------------------------------

##### Returns

> WM\_SUCCESS if the call was successful.
>
> -WM\_FAIL if failed.

#### int wlan\_get\_uap\_ed\_mac\_mode (wlan\_ed\_mac\_ctrl\_t \* *wlan\_ed\_mac\_ctrl*)

> This API can be used to get current ED MAC MODE configuration for uAP.

##### Parameters

  ----- ----------------------- ---------------------------------------------------------------------------------
  out   *wlan\_ed\_mac\_ctrl*   A pointer to wlan\_ed\_mac\_ctrl\_t with parameters mentioned in above set API.
  ----- ----------------------- ---------------------------------------------------------------------------------

##### Returns

> WM\_SUCCESS if the call was successful.
>
> -WM\_FAIL if failed.

#### void wlan\_set\_cal\_data (const uint8\_t \* *cal\_data*, const unsigned int *cal\_data\_size*)

> Set the Wi-Fi calibration data in the Wi-Fi firmware.
>
> This function can be used to set the Wi-Fi calibration data in the
> firmware. This should be call before wlan\_init() function.

##### Parameters

  ---- ------------------- ----------------------------------
  in   *cal\_data*         The calibration data buffer
  in   *cal\_data\_size*   Size of calibration data buffer.
  ---- ------------------- ----------------------------------

#### int wlan\_set\_mac\_addr (uint8\_t \* *mac*)

> Set the Wi-Fi MAC Address in the Wi-Fi firmware.
>
> This function can be used to set Wi-Fi MAC Address in firmware. When
> called after Wi-Fi initialization done, the incoming MAC is treated as
> the STA MAC address directly. And mac\[4\] plus 1, the modified MAC is
> used as the uAP MAC address.

##### Parameters

  ---- ------- --------------------------------------------------------------------------------------------------------
  in   *MAC*   The MAC Address in 6 bytes array format like uint8\_t mac\[\] = { 0x00, 0x50, 0x43, 0x21, 0x19, 0x6E};
  ---- ------- --------------------------------------------------------------------------------------------------------

##### Returns

> WM\_SUCCESS if the call was successful.
>
> -WM\_FAIL if failed.

#### int wlan\_set\_sta\_mac\_addr (uint8\_t \* *mac*)

> Set the Wi-Fi MAC address for the STA in the Wi-Fi firmware.
>
> This function can be used to set the Wi-Fi MAC address for the station
> in the firmware. Should be called after Wi-Fi initialization done. It
> sets the station MAC address only.

##### Parameters

  ---- ------- -------------------------------------------------------------------------------------------------------
  in   *MAC*   The MAC Address in 6 byte array format like uint8\_t mac\[\] = { 0x00, 0x50, 0x43, 0x21, 0x19, 0x6E};
  ---- ------- -------------------------------------------------------------------------------------------------------

##### Returns

> WM\_SUCCESS if the call was successful.
>
> -WM\_FAIL if failed.

#### int wlan\_set\_uap\_mac\_addr (uint8\_t \* *mac*)

> Set the Wi-Fi MAC address for the uAP in the Wi-Fi firmware.
>
> This function can be used to set the Wi-Fi MAC address for the uAP in
> the firmware. Should be called after Wi-Fi initialization done. It
> sets the uAP MAC address only.

##### Parameters

  ---- ------- --------------------------------------------------------------------------------------------------------
  in   *MAC*   The MAC Address in 6 bytes array format like uint8\_t mac\[\] = { 0x00, 0x50, 0x43, 0x21, 0x19, 0x6E};
  ---- ------- --------------------------------------------------------------------------------------------------------

##### Returns

> WM\_SUCCESS if the call was successful.
>
> -WM\_FAIL if failed.

#### int wlan\_set\_ieeeps\_cfg (struct wlan\_ieeeps\_config \* *ps\_cfg*)

> Set configuration parameters of IEEE power save mode.

##### Parameters

  ---- ----------- --------------------------------------------------------
  in   *ps\_cfg*   Power save configuration includes multiple parameters.
  ---- ----------- --------------------------------------------------------

##### Returns

> WM\_SUCCESS if the call was successful.
>
> -WM\_FAIL if failed.

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

+----+--------------------+----------------------------------+
| in | *listen\_interval* | Listen interval as below         |
|    |                    |                                  |
|    |                    | 0 : Unchanged,                   |
|    |                    |                                  |
|    |                    | -1 : Disable,                    |
|    |                    |                                  |
|    |                    | 1-49: Value in beacon intervals, |
|    |                    |                                  |
|    |                    | \>= 50: Value in TUs             |
+----+--------------------+----------------------------------+

#### void wlan\_configure\_delay\_to\_ps (unsigned int *timeout\_ms*)

> Set timeout configuration before Wi-Fi power save mode.

##### Parameters

  ---- --------------- -------------------------------
  in   *timeout\_ms*   timout time, in milliseconds.
  ---- --------------- -------------------------------

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

  ---- ------------------ ---------------------------------------------------------------------------------------------------------------
  in   *time\_in\_secs*   -1 Disables null packet transmission, 0 Null packet interval is unchanged, n Null packet interval in seconds.
  ---- ------------------ ---------------------------------------------------------------------------------------------------------------

#### int wlan\_set\_antcfg (uint32\_t *ant*, uint16\_t *evaluate\_time*)

> This API can be used to set the mode of TX/RX antenna. If SAD
> (software antenna diversity) is enabled, this API can also be used to
> set SAD antenna evaluate time interval(antenna mode is antenna
> diversity when set SAD evaluate time interval).

##### Parameters

  ---- ------------------ ------------------------------------------------------------------------------------------------------------------------------------------------
  in   *ant*              Antenna valid values are 1, 2 and 0xFFFF 1 : TX/RX antenna 1 2 : TX/RX antenna 2 0xFFFF: TX/RX antenna diversity (Refer to hardware schematic)
  in   *evaluate\_time*   SAD evaluate time interval (unit: milliseconds), default value is 6s(0x1770).
  ---- ------------------ ------------------------------------------------------------------------------------------------------------------------------------------------

##### Returns

> WM\_SUCCESS if successful.
>
> WLAN\_ERROR\_STATE if unsuccessful.

#### int wlan\_get\_antcfg (uint32\_t \* *ant*, uint16\_t \* *evaluate\_time*, uint16\_t \* *current\_antenna*)

> This API can be used to get the mode of TX/RX antenna. If SAD
> (software antenna diversity) is enabled, this API can also be used to
> get SAD antenna evaluate time interval(antenna mode is antenna
> diversity when set SAD evaluate time interval).

##### Parameters

  ----- -------------------- ---------------------------------------------------------------------------------------------------------------------------------------------
  out   *ant*                pointer to antenna variable. antenna variable: 1 : TX/RX antenna 1 2 : TX/RX antenna 2 0xFFFF: TX/RX antenna diversity
  out   *evaluate\_time*     pointer to evaluate\_time variable for SAD.
  out   *current\_antenna*   pointer to current antenna. evaluate\_mode: 0: PCB Ant + Ext Ant0 1: Ext Ant0 + Ext Ant1 2: PCB Ant + Ext Ant1 0xFF: Default divisity mode.
  ----- -------------------- ---------------------------------------------------------------------------------------------------------------------------------------------

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

  ---- ------------- -------------------------------------
  in   *tsf\_high*   Pointer to store TSF higher 32bits.
  in   *tsf\_low*    Pointer to store TSF lower 32bits.
  ---- ------------- -------------------------------------

##### Returns

> WM\_SUCCESS if operation is successful.
>
> -WM\_FAIL if command fails.

#### int wlan\_ieeeps\_on (unsigned int *wakeup\_conditions*)

> Enable IEEE power save with host sleep configuration
>
> When enabled, Wi-Fi SoC is opportunistically put into IEEE power save
> mode. Before putting the Wi-Fi SoC in power save this also sets the
> host sleep configuration on the SoC as specified. This makes the SoC
> generate a wakeup for the processor if any of the wakeup conditions
> are met.

##### Parameters

  ---- ---------------------- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  in   *wakeup\_conditions*   conditions to wake the host. This should be a logical OR of the conditions in wlan\_wakeup\_event\_t. Typically devices would want to wake up on WAKE\_ON\_ALL\_BROADCAST, WAKE\_ON\_UNICAST, WAKE\_ON\_MAC\_EVENT. WAKE\_ON\_MULTICAST, WAKE\_ON\_ARP\_BROADCAST, WAKE\_ON\_MGMT\_FRAME
  ---- ---------------------- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

##### Note

> IEEE power save mode applies only when STA has connected to an AP. It
> could be enabled/disabled when STA connected or disconnected, but only
> take effect when STA has connected to an AP.

##### Returns

> WM\_SUCCESS if the call was successful.
>
> -WM\_FAIL otherwise.

#### int wlan\_ieeeps\_off (void )

> Turn off IEEE power save mode.

##### Note

> IEEE power save mode applies only when STA has connected to an AP. It
> could be enabled/disabled when STA connected or disconnected, but only
> take effect when STA has connected to an AP.

##### Returns

> WM\_SUCCESS if the call was successful.
>
> -WM\_FAIL otherwise.

#### int wlan\_deepsleepps\_on (void )

> Turn on deep sleep power save mode.

##### Note

> deep sleep power save mode only applies when STA disconnected. It
> could be enabled/disabled when STA connected or disconnected, but only
> take effect when STA disconnected.

##### Returns

> WM\_SUCCESS if the call was successful.
>
> -WM\_FAIL otherwise.

#### int wlan\_deepsleepps\_off (void )

> Turn off deep sleep power save mode.

##### Note

> deep sleep power save mode only applies when STA disconnected. It
> could be enabled/disabled when STA connected or disconnected, but only
> take effect when STA disconnected.

##### Returns

> WM\_SUCCESS if the call was successful.
>
> -WM\_FAIL otherwise.

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

  ---- --------------- ----------------------------------------
  in   *keep\_alive*   A pointer to wlan\_tcp\_keep\_alive\_t
  ---- --------------- ----------------------------------------

##### Returns

> WM\_SUCCESS if operation is successful.
>
> -WM\_FAIL if command fails.

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
> 0 if DTIM IE is not found in AP\'s Probe response.

##### Note

> This API should not be called from Wi-Fi event handler registered by
> application during wlan\_start.

#### int wlan\_get\_data\_rate (wlan\_ds\_rate \* *ds\_rate*, mlan\_bss\_type *bss\_type*)

> Use this API to get the current TX and RX rates along with bandwidth
> and guard interval information if rate is 802.11n.

##### Parameters

  ---- ------------- ---------------------------------------------------------------------------------------------------------------
  in   *ds\_rate*    A pointer to structure which has tx, RX rate information along with bandwidth and guard interval information.
  in   *bss\_type*   0: STA, 1: uAP
  ---- ------------- ---------------------------------------------------------------------------------------------------------------

##### Note

> If rate is greater than 11 then it is 802.11n rate and from 12 MCS0
> rate starts. The bandwidth mapping is like value 0 is for 20MHz, 1 is
> 40MHz, 2 is for 80MHz. The guard interval value zero means Long
> otherwise Short.

##### Returns

> WM\_SUCCESS if operation is successful.
>
> -WM\_FAIL if command fails.

#### int wlan\_get\_pmfcfg (uint8\_t \* *mfpc*, uint8\_t \* *mfpr*)

> Use this API to get the management frame protection parameters for
> sta.

##### Parameters

  ----- -------- ------------------------------------------------------------------------------------------------------------------------------
  out   *mfpc*   Management frame protection capable (MFPC) 1: Management frame protection capable 0: Management frame protection not capable
  out   *mfpr*   Management frame protection required (MFPR) 1: Management frame protection required 0: Management frame protection optional
  ----- -------- ------------------------------------------------------------------------------------------------------------------------------

##### Returns

> WM\_SUCCESS if operation is successful.
>
> -WM\_FAIL if command fails.

#### int wlan\_uap\_get\_pmfcfg (uint8\_t \* *mfpc*, uint8\_t \* *mfpr*)

> Use this API to get the set management frame protection parameters for
> uAP.

##### Parameters

  ----- -------- --------------------------------------------------------------------------------------------------------------------------------
  out   *mfpc*   Management frame protection capable (MFPC) 1: management frame protection capable. 0: management frame protection not capable.
  out   *mfpr*   Management frame protection required (MFPR) 1: management frame protection required. 0: management frame protection optional.
  ----- -------- --------------------------------------------------------------------------------------------------------------------------------

##### Returns

> WM\_SUCCESS if operation is successful.
>
> -WM\_FAIL if command fails.

#### int wlan\_set\_packet\_filters (wlan\_flt\_cfg\_t \* *flt\_cfg*)

> Use this API to set packet filters in Wi-Fi firmware.

##### Parameters

  ---- ------------ ------------------------------------------------------------------------------
  in   *flt\_cfg*   A pointer to structure which holds the the packet filters wlan\_flt\_cfg\_t.
  ---- ------------ ------------------------------------------------------------------------------

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
> mode: bit0--hostsleep mode, bit1--non hostsleep mode
>
> mode=1 HostSleep mode
>
> action: 0--discard and not wake host, 1--discard and wake host
> 3--allow and wake host
>
> action=3 Allow and Wake host
>
> filter\_num=3 Number of filter
>
> RPN only support \"&&\" and \"\|\|\" operators, space cannot be
> removed between operators.
>
> RPN=Filter\_0 && Filter\_1 \|\| Filter\_2
>
> Byte comparison filter\'s type is 0x41, decimal comparison filter\'s
> type is 0x42,
>
> Bit comparison filter\'s type is 0x43
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
> repeat=1 1 copies of \'c0:a8:00:58\'
>
> byte=c0:a8:00:58 \'c0:a8:00:58\' is the byte sequence constant with
> each byte
>
> in hex format, with \':\' as delimiter between two byte.
>
> offset=34 34 is the byte offset of the equal length field of rx\'d
> pkt.
>
> }
>
> Filter\_2 is Magic packet, it can look for 16 contiguous copies of
> \'00:50:43:20:01:02\' from
>
> the RX pkt\'s offset 14
>
> Filter\_2={
>
> type=0x41 Byte comparison filter
>
> repeat=16 16 copies of \'00:50:43:20:01:02\'
>
> byte=00:50:43:20:01:02 \# \'00:50:43:20:01:02\' is the byte sequence
> constant
>
> offset=14 14 is the byte offset of the equal length field of rx\'d
> pkt.
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
> memset(&flt\_cfg, 0, sizeof(wlan\_flt\_cfg\_t));
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
> -WM\_FAIL if command fails.

#### int wlan\_set\_auto\_arp (void )

> Use this API to enable ARP (address resolution protocol) offload in
> Wi-Fi firmware

##### Returns

> WM\_SUCCESS if operation is successful.
>
> -WM\_FAIL if command fails.

#### int wlan\_wowlan\_cfg\_ptn\_match (wlan\_wowlan\_ptn\_cfg\_t \* *ptn\_cfg*)

> Use this API to enable WOWLAN (wake-on-wireless-LAN) on magic packet
> RX in Wi-Fi firmware

##### Parameters

  ---- ------------ ---------------------------------------------------------------------------------------
  in   *ptn\_cfg*   A pointer to wlan\_wowlan\_ptn\_cfg\_t containing wake on Wi-Fi pattern configuration
  ---- ------------ ---------------------------------------------------------------------------------------

##### Returns

> WM\_SUCCESS if operation is successful.
>
> -WM\_FAIL if command fails

#### int wlan\_set\_ipv6\_ns\_offload (void )

> Use this API to enable NS offload in Wi-Fi firmware.

##### Returns

> WM\_SUCCESS if operation is successful.
>
> -WM\_FAIL if command fails.

#### int wlan\_get\_current\_bssid (uint8\_t \* *bssid*)

> Use this API to get the BSSID of associated BSS when in station mode.

##### Parameters

  ----- --------- -----------------------------------------------------------
  out   *bssid*   A pointer to array(char, length is 6) to store the BSSID.
  ----- --------- -----------------------------------------------------------

##### Returns

> WM\_SUCCESS if operation is successful.
>
> -WM\_FAIL if command fails.

#### uint8\_t wlan\_get\_current\_channel (void )

> Use this API to get the channel number of associated BSS.

##### Returns

> channel number if operation is successful.
>
> 0 if command fails.

#### int wlan\_get\_ps\_mode (enum wlan\_ps\_mode \* *ps\_mode*)

> Get station interface power save mode.

##### Parameters

  ----- ------------ ---------------------------------------------------------------------------------------
  out   *ps\_mode*   A pointer to wlan\_ps\_mode where station interface power save mode should be stored.
  ----- ------------ ---------------------------------------------------------------------------------------

##### Returns

> WM\_SUCCESS if successful.
>
> -WM\_E\_INVAL if *ps\_mode* was NULL.

#### int wlan\_wlcmgr\_send\_msg (enum wifi\_event *event*, enum wifi\_event\_reason *reason*, void \* *data*)

> Send message to Wi-Fi connection manager thread.

##### Parameters

  ---- ---------- -------------------------------------------------
  in   *event*    An event from wifi\_event.
  in   *reason*   A reason code.
  in   *data*     A pointer to data buffer associated with event.
  ---- ---------- -------------------------------------------------

##### Returns

> WM\_SUCCESS if successful.
>
> -WM\_FAIL if failed.

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
> -WM\_FAIL if they were not (for example if this function was called
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
> -WM\_FAIL if they were not (for example if this function was called
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
> -WM\_FAIL if they were not (for example if this function was called
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
> -WM\_FAIL if they were not unregistered.

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

  ----- ----------------- --------------------------------------------------------------------------------------------------------
  out   *max\_sta\_num*   A pointer to variable where current maximum number of the stations of the uAP interface can be stored.
  ----- ----------------- --------------------------------------------------------------------------------------------------------

##### Returns

> WM\_SUCCESS if successful.
>
> -WM\_FAIL if unsuccessful.

##### Note

> Get operation is allowed in any uAP state.

#### int wlan\_set\_uap\_max\_clients (unsigned int *max\_sta\_num*)

> Set maximum number of the stations that can be allowed to connect to
> the uAP.

##### Parameters

  ---- ----------------- -------------------------------------
  in   *max\_sta\_num*   Number of maximum stations for uAP.
  ---- ----------------- -------------------------------------

##### Returns

> WM\_SUCCESS if successful.
>
> -WM\_FAIL if unsuccessful.

##### Note

> Set operation in not allowed in WLAN\_UAP\_STARTED state.

#### int wlan\_set\_htcapinfo (unsigned int *htcapinfo*)

> Use this API to configure some of parameters in HT capability
> information IE (such as short GI, channel bandwidth, and green field
> support)

##### Parameters

+----+-------------+-----------------------------------------------------------+
| in | *htcapinfo* | This is a bitmap and should be used as following          |
|    |             |                                                           |
|    |             | Bit 29: Green field Enable/Disable                        |
|    |             |                                                           |
|    |             | Bit 26: RX STBC Support Enable/Disable. (As we support    |
|    |             |                                                           |
|    |             | single spatial stream only 1 bit is used for RX STBC)     |
|    |             |                                                           |
|    |             | Bit 25: TX STBC support Enable/Disable.                   |
|    |             |                                                           |
|    |             | Bit 24: Short GI in 40 Mhz Enable/Disable                 |
|    |             |                                                           |
|    |             | Bit 23: Short GI in 20 Mhz Enable/Disable                 |
|    |             |                                                           |
|    |             | Bit 22: RX LDPC Enable/Disable                            |
|    |             |                                                           |
|    |             | Bit 17: 20/40 Mhz enable disable.                         |
|    |             |                                                           |
|    |             | Bit 8: Enable/Disable 40Mhz intolerant bit in HT capinfo. |
|    |             |                                                           |
|    |             | 0 can reset this bit and 1 can set this bit in            |
|    |             |                                                           |
|    |             | htcapinfo attached in association request.                |
|    |             |                                                           |
|    |             | All others are reserved and should be set to 0.           |
+----+-------------+-----------------------------------------------------------+

##### Returns

> WM\_SUCCESS if successful.
>
> -WM\_FAIL if unsuccessful.

#### int wlan\_set\_httxcfg (unsigned short *httxcfg*)

> Use this API to configure various 802.11n specific configuration for
> transmit (such as short GI, channel bandwidth and green field support)

##### Parameters

+----+-----------+---------------------------------------------------+
| in | *httxcfg* | This is a bitmap and should be used as following  |
|    |           |                                                   |
|    |           | Bit 15-10: Reserved set to 0                      |
|    |           |                                                   |
|    |           | Bit 9-8: RX STBC set to 0x01                      |
|    |           |                                                   |
|    |           | BIT9 BIT8 Description                             |
|    |           |                                                   |
|    |           | 0 0 No spatial streams                            |
|    |           |                                                   |
|    |           | 0 1 One spatial stream supported                  |
|    |           |                                                   |
|    |           | 1 0 Reserved                                      |
|    |           |                                                   |
|    |           | 1 1 Reserved                                      |
|    |           |                                                   |
|    |           | Bit 7: STBC Enable/Disable                        |
|    |           |                                                   |
|    |           | Bit 6: Short GI in 40 Mhz Enable/Disable          |
|    |           |                                                   |
|    |           | Bit 5: Short GI in 20 Mhz Enable/Disable          |
|    |           |                                                   |
|    |           | Bit 4: Green field Enable/Disable                 |
|    |           |                                                   |
|    |           | Bit 3-2: Reserved set to 1                        |
|    |           |                                                   |
|    |           | Bit 1: 20/40 Mhz enable disable.                  |
|    |           |                                                   |
|    |           | Bit 0: LDPC Enable/Disable                        |
|    |           |                                                   |
|    |           | When Bit 1 is set then firmware could transmit in |
|    |           | 20Mhz or 40Mhz based                              |
|    |           |                                                   |
|    |           | on rate adaptation. When this bit is reset then   |
|    |           | firmware can only                                 |
|    |           |                                                   |
|    |           | transmit in 20Mhz.                                |
+----+-----------+---------------------------------------------------+

##### Returns

> WM\_SUCCESS if successful.
>
> -WM\_FAIL if unsuccessful.

#### int wlan\_set\_txratecfg (wlan\_ds\_rate *ds\_rate*, mlan\_bss\_type *bss\_type*)

> Use this API to set the transmit data rate.

##### Note

> The data rate can be set only after association.

##### Parameters

+----+-------------+-------------------------------------------------+
| in | *ds\_rate*  | struct contains following fields sub\_command   |
|    |             | It should be WIFI\_DS\_RATE\_CFG and rate\_cfg  |
|    |             | should have following parameters.               |
|    |             |                                                 |
|    |             | rate\_format - This parameter specifies the     |
|    |             | data rate format used in this command           |
|    |             |                                                 |
|    |             | 0: LG                                           |
|    |             |                                                 |
|    |             | 1: HT                                           |
|    |             |                                                 |
|    |             | 2: VHT                                          |
|    |             |                                                 |
|    |             | 0xff: Auto                                      |
|    |             |                                                 |
|    |             | index - This parameter specifies the rate or    |
|    |             | MCS index                                       |
|    |             |                                                 |
|    |             | If rate\_format is 0 (LG),                      |
|    |             |                                                 |
|    |             | 0 1 Mbps                                        |
|    |             |                                                 |
|    |             | 1 2 Mbps                                        |
|    |             |                                                 |
|    |             | 2 5.5 Mbps                                      |
|    |             |                                                 |
|    |             | 3 11 Mbps                                       |
|    |             |                                                 |
|    |             | 4 6 Mbps                                        |
|    |             |                                                 |
|    |             | 5 9 Mbps                                        |
|    |             |                                                 |
|    |             | 6 12 Mbps                                       |
|    |             |                                                 |
|    |             | 7 18 Mbps                                       |
|    |             |                                                 |
|    |             | 8 24 Mbps                                       |
|    |             |                                                 |
|    |             | 9 36 Mbps                                       |
|    |             |                                                 |
|    |             | 10 48 Mbps                                      |
|    |             |                                                 |
|    |             | 11 54 Mbps                                      |
|    |             |                                                 |
|    |             | If rate\_format is 1 (HT),                      |
|    |             |                                                 |
|    |             | 0 MCS0                                          |
|    |             |                                                 |
|    |             | 1 MCS1                                          |
|    |             |                                                 |
|    |             | 2 MCS2                                          |
|    |             |                                                 |
|    |             | 3 MCS3                                          |
|    |             |                                                 |
|    |             | 4 MCS4                                          |
|    |             |                                                 |
|    |             | 5 MCS5                                          |
|    |             |                                                 |
|    |             | 6 MCS6                                          |
|    |             |                                                 |
|    |             | 7 MCS7                                          |
|    |             |                                                 |
|    |             | If STREAM\_2X2                                  |
|    |             |                                                 |
|    |             | 8 MCS8                                          |
|    |             |                                                 |
|    |             | 9 MCS9                                          |
|    |             |                                                 |
|    |             | 10 MCS10                                        |
|    |             |                                                 |
|    |             | 11 MCS11                                        |
|    |             |                                                 |
|    |             | 12 MCS12                                        |
|    |             |                                                 |
|    |             | 13 MCS13                                        |
|    |             |                                                 |
|    |             | 14 MCS14                                        |
|    |             |                                                 |
|    |             | 15 MCS15                                        |
|    |             |                                                 |
|    |             | If rate\_format is 2 (VHT),                     |
|    |             |                                                 |
|    |             | 0 MCS0                                          |
|    |             |                                                 |
|    |             | 1 MCS1                                          |
|    |             |                                                 |
|    |             | 2 MCS2                                          |
|    |             |                                                 |
|    |             | 3 MCS3                                          |
|    |             |                                                 |
|    |             | 4 MCS4                                          |
|    |             |                                                 |
|    |             | 5 MCS5                                          |
|    |             |                                                 |
|    |             | 6 MCS6                                          |
|    |             |                                                 |
|    |             | 7 MCS7                                          |
|    |             |                                                 |
|    |             | 8 MCS8                                          |
|    |             |                                                 |
|    |             | 9 MCS9                                          |
|    |             |                                                 |
|    |             | nss - This parameter specifies the NSS.         |
|    |             |                                                 |
|    |             | It is valid only for VHT                        |
|    |             |                                                 |
|    |             | If rate\_format is 2 (VHT),                     |
|    |             |                                                 |
|    |             | 1 NSS1                                          |
|    |             |                                                 |
|    |             | 2 NSS2                                          |
+----+-------------+-------------------------------------------------+
| in | *bss\_type* | 0: STA, 1: uAP                                  |
+----+-------------+-------------------------------------------------+

##### Returns

> WM\_SUCCESS if successful.
>
> -WM\_FAIL if unsuccessful.

#### int wlan\_get\_txratecfg (wlan\_ds\_rate \* *ds\_rate*, mlan\_bss\_type *bss\_type*)

> Use this API to get the transmit data rate.

##### Parameters

  ---- ------------- ------------------------------------------------------------------------
  in   *ds\_rate*    A pointer to wlan\_ds\_rate where TX Rate configuration can be stored.
  in   *bss\_type*   0: STA, 1: uAP
  ---- ------------- ------------------------------------------------------------------------

##### Returns

> WM\_SUCCESS if successful.
>
> -WM\_FAIL if unsuccessful.

#### int wlan\_get\_sta\_tx\_power (t\_u32 \* *power\_level*)

> Get station transmit power

##### Parameters

  ----- ---------------- -----------------------------------
  out   *power\_level*   Transmit power level (unit: dBm).
  ----- ---------------- -----------------------------------

##### Returns

> WM\_SUCCESS if successful.
>
> -WM\_FAIL if unsuccessful.

#### int wlan\_set\_sta\_tx\_power (t\_u32 *power\_level*)

> Set station transmit power

##### Parameters

  ---- ---------------- -----------------------------------
  in   *power\_level*   Transmit power level (unit: dBm).
  ---- ---------------- -----------------------------------

##### Returns

> WM\_SUCCESS if successful.
>
> -WM\_FAIL if unsuccessful.

#### int wlan\_set\_wwsm\_txpwrlimit (void )

> Set worldwide safe mode TX power limits. Set TX power limit and ru TX
> power limit according to the region code. TX power limit:
> rg\_power\_cfg\_rw610 ru TX power limit: ru\_power\_cfg\_rw610

##### Returns

> WM\_SUCCESS if successful.
>
> -WM\_FAIL if unsuccessful.

#### const char\* wlan\_get\_wlan\_region\_code (void )

> Get Wi-Fi region code from TX power config

##### Returns

> Wi-Fi region code in string format.

#### int wlan\_get\_mgmt\_ie (enum wlan\_bss\_type *bss\_type*, IEEEtypes\_ElementId\_t *index*, void \* *buf*, unsigned int \* *buf\_len*)

> Get Management IE for given BSS type (interface) and index.

##### Parameters

  ----- ------------- ------------------------------------
  in    *bss\_type*   0: STA, 1: uAP
  in    *index*       IE index.
  out   *buf*         Buffer to store requested IE data.
  out   *buf\_len*    Length of IE data.
  ----- ------------- ------------------------------------

##### Returns

> WM\_SUCCESS if successful.
>
> -WM\_FAIL if unsuccessful.

#### int wlan\_set\_mgmt\_ie (enum wlan\_bss\_type *bss\_type*, IEEEtypes\_ElementId\_t *id*, void \* *buf*, unsigned int *buf\_len*)

> Set management IE for given BSS type (interface) and index.

##### Parameters

  ---- ------------- ----------------------------
  in   *bss\_type*   0: STA, 1: uAP
  in   *id*          Type/ID of Management IE.
  in   *buf*         Buffer containing IE data.
  in   *buf\_len*    Length of IE data.
  ---- ------------- ----------------------------

##### Returns

> Management IE index if successful.
>
> -WM\_FAIL if unsuccessful.

#### int wlan\_clear\_mgmt\_ie (enum wlan\_bss\_type *bss\_type*, IEEEtypes\_ElementId\_t *index*, int *mgmt\_bitmap\_index*)

> Clear management IE for given BSS type (interface) and index.

##### Parameters

  ---- ----------------------- --------------------------
  in   *bss\_type*             0: STA, 1: uAP
  in   *index*                 IE index.
  in   *mgmt\_bitmap\_index*   management bitmap index.
  ---- ----------------------- --------------------------

##### Returns

> WM\_SUCCESS if successful.
>
> -WM\_FAIL if unsuccessful.

#### bool wlan\_get\_11d\_enable\_status (void )

> Get current status of 802.11d support.

##### Returns

> true if 802.11d support is enabled by application.
>
> false if not enabled.

#### int wlan\_get\_current\_signal\_strength (short \* *rssi*, int \* *snr*)

> Get current RSSI and signal to noise ratio from Wi-Fi firmware.

##### Parameters

  ----- -------- ---------------------------------------------
  out   *RSSI*   A pointer to variable to store current RSSI
  out   *snr*    A pointer to variable to store current SNR.
  ----- -------- ---------------------------------------------

##### Returns

> WM\_SUCCESS if successful.

#### int wlan\_get\_average\_signal\_strength (short \* *rssi*, int \* *snr*)

> Get average RSSI and signal to noise ratio (average value of the
> former 8 packets) from Wi-Fi firmware.

##### Parameters

  ----- -------- ---------------------------------------------
  out   *RSSI*   A pointer to variable to store current RSSI
  out   *snr*    A pointer to variable to store current SNR.
  ----- -------- ---------------------------------------------

##### Returns

> WM\_SUCCESS if successful.

#### int wlan\_remain\_on\_channel (const enum wlan\_bss\_type *bss\_type*, const bool *status*, const uint8\_t *channel*, const uint32\_t *duration*)

> This API is used to set/cancel the remain on channel configuration.

##### Note

> When status is false, channel and duration parameters are ignored.

##### Parameters

  ---- ------------- ---------------------------------------------------------------------------------------------------
  in   *bss\_type*   The interface to set channel bss\_type 0: STA, 1: uAP
  in   *status*      false : Cancel the remain on channel configuration true : Set the remain on channel configuration
  in   *channel*     The channel to configure
  in   *duration*    The duration for which to remain on channel in milliseconds.
  ---- ------------- ---------------------------------------------------------------------------------------------------

##### Returns

> WM\_SUCCESS on success or error code.

#### int wlan\_get\_otp\_user\_data (uint8\_t \* *buf*, uint16\_t *len*)

> Get user data from OTP (one-time pramming) memory

##### Parameters

  ----- ------- -----------------------------------------------
  out   *buf*   Pointer to buffer where data should be stored
  out   *len*   Number of bytes to read
  ----- ------- -----------------------------------------------

##### Returns

> WM\_SUCCESS if user data read operation is successful.
>
> -WM\_E\_INVAL if buf is not valid or of insufficient size.
>
> -WM\_FAIL if user data field is not present or command fails.

#### int wlan\_get\_cal\_data (wlan\_cal\_data\_t \* *cal\_data*)

> Get calibration data from Wi-Fi firmware.

##### Parameters

  ----- ------------- -------------------------------------------------------------------------------------------------
  out   *cal\_data*   Pointer to calibration data structure where calibration data and it\'s length should be stored.
  ----- ------------- -------------------------------------------------------------------------------------------------

##### Returns

> WM\_SUCCESS if calibration data read operation is successful.
>
> -WM\_E\_INVAL if cal\_data is not valid.
>
> -WM\_FAIL if command fails.

##### Note

> The user of this API should free the allocated buffer for calibration
> data.

#### int wlan\_set\_chanlist\_and\_txpwrlimit (wlan\_chanlist\_t \* *chanlist*, wlan\_txpwrlimit\_t \* *txpwrlimit*)

> Set the TRPC (transient receptor potential canonical) channel list and
> TX power limit configuration.

##### Parameters

  ---- -------------- ----------------------------------------------------------------
  in   *chanlist*     A poiner to wlan\_chanlist\_t channel List configuration.
  in   *txpwrlimit*   A pointer to wlan\_txpwrlimit\_t TX power limit configuration.
  ---- -------------- ----------------------------------------------------------------

##### Returns

> WM\_SUCCESS on success, error otherwise.

#### int wlan\_set\_chanlist (wlan\_chanlist\_t \* *chanlist*)

> Set the channel list configuration wlan\_chanlist\_t.

##### Parameters

  ---- ------------ ------------------------------------------------------------
  in   *chanlist*   A pointer to wlan\_chanlist\_t channel list configuration.
  ---- ------------ ------------------------------------------------------------

##### Returns

> WM\_SUCCESS on success, error otherwise.

##### Note

> If region enforcement flag is enabled in the OTP then this API should
> not take effect.

#### int wlan\_get\_chanlist (wlan\_chanlist\_t \* *chanlist*)

> Get the channel list configuration.

##### Parameters

  ----- ------------ ------------------------------------------------------------
  out   *chanlist*   A pointer to wlan\_chanlist\_t channel list configuration.
  ----- ------------ ------------------------------------------------------------

##### Returns

> WM\_SUCCESS on success, error otherwise.

##### Note

> The wlan\_chanlist\_t struct allocates memory for a maximum of 54.
> channels.

#### int wlan\_set\_txpwrlimit (wlan\_txpwrlimit\_t \* *txpwrlimit*)

> Set the TRPC (transient receptor potential canonical) channel
> configuration.

##### Parameters

  ---- -------------- ----------------------------------------------------------------
  in   *txpwrlimit*   A pointer to wlan\_txpwrlimit\_t TX power limit configuration.
  ---- -------------- ----------------------------------------------------------------

##### Returns

> WM\_SUCCESS on success, error otherwise.

#### int wlan\_get\_txpwrlimit (wifi\_SubBand\_t *subband*, wifi\_txpwrlimit\_t \* *txpwrlimit*)

> Get the TRPC (transient receptor potential canonical) channel
> configuration.

##### Parameters

+-----+--------------+-----------------------------------------------+
| in  | *subband*    | Where subband is:                             |
|     |              |                                               |
|     |              | 0x00 2G subband (2.4G: channel 1-14)          |
|     |              |                                               |
|     |              | 0x10 5G subband0 (5G: channel 36,40,44,48,    |
|     |              |                                               |
|     |              | 52,56,60,64)                                  |
|     |              |                                               |
|     |              | 0x11 5G subband1 (5G: channel                 |
|     |              | 100,104,108,112,                              |
|     |              |                                               |
|     |              | 116,120,124,128,                              |
|     |              |                                               |
|     |              | 132,136,140,144)                              |
|     |              |                                               |
|     |              | 0x12 5G subband2 (5G: channel                 |
|     |              | 149,153,157,161,165,172)                      |
|     |              |                                               |
|     |              | 0x13 5G subband3 (5G: channel                 |
|     |              | 183,184,185,187,188,                          |
|     |              |                                               |
|     |              | 189, 192,196;                                 |
|     |              |                                               |
|     |              | 5G: channel 7,8,11,12,16,34)                  |
+-----+--------------+-----------------------------------------------+
| out | *txpwrlimit* | A pointer to wlan\_txpwrlimit\_t TX power     |
|     |              | Limit configuration structure where Wi-Fi     |
|     |              | firmware configuration can get copied.        |
+-----+--------------+-----------------------------------------------+

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

  ---- -------------------- ------------------------------
  in   *reassoc\_control*   Reassociation enable/disable
  ---- -------------------- ------------------------------

#### void wlan\_uap\_set\_beacon\_period (const uint16\_t *beacon\_period*)

> API to set the beacon period of the uAP

##### Parameters

  ---- ------------------ ------------------------------------------------
  in   *beacon\_period*   Beacon period in TU (1 TU = 1024 microseconds)
  ---- ------------------ ------------------------------------------------

##### Note

> Call this API before calling uAP start API.

#### int wlan\_uap\_set\_bandwidth (const uint8\_t *bandwidth*)

> API to set the bandwidth of the uAP

##### Parameters

+----+-------------+-------------------------------+
| in | *bandwidth* | Wi-Fi AP bandwidth            |
|    |             |                               |
|    |             | 1: 20 MHz 2: 40 MHz 3: 80 MHz |
+----+-------------+-------------------------------+

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.
>
> -WM\_FAIL if command fails.

##### Note

> Not applicable to 20MHZ only chip sets (Redfinch, SD8801)
>
> Call this API before calling uAP start API.
>
> Default bandwidth setting is 40 MHz.

#### int wlan\_uap\_get\_bandwidth (uint8\_t \* *bandwidth*)

> API to get the bandwidth of the uAP

##### Parameters

  ----- ------------- --------------------------------------------------
  out   *bandwidth*   Wi-Fi AP bandwidth 1: 20 MHz 2: 40 MHz 3: 80 MHz
  ----- ------------- --------------------------------------------------

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.
>
> -WM\_FAIL if command fails.

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

  ---- ---------------- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  in   *hidden\_ssid*   Hidden SSID control hidden\_ssid=0: broadcast SSID in beacons. hidden\_ssid=1: send empty SSID (length=0) in beacon. hidden\_ssid=2: clear SSID (ACSII 0), but keep the original length
  ---- ---------------- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.
>
> -WM\_FAIL if command fails.

##### Note

> Call this API before calling uAP start API.

#### void wlan\_uap\_ctrl\_deauth (const bool *enable*)

> API to control the deauthentication during uAP channel switch.

##### Parameters

  ---- ---------- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  in   *enable*   0 -- Wi-Fi firmware can use default behavior, send deauth packet when uAP move to another channel. 1 -- Wi-Fi firmware cannot send deauth packet when uAP move to another channel.
  ---- ---------- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

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

+----+-----------------+-----------------------------------------------------+
| in | *ht\_cap\_info* | \- This is a bitmap and should be used as following |
|    |                 |                                                     |
|    |                 | Bit 15: L Sig TxOP protection - reserved, set to 0  |
|    |                 |                                                     |
|    |                 | Bit 14: 40 MHz intolerant - reserved, set to 0      |
|    |                 |                                                     |
|    |                 | Bit 13: PSMP - reserved, set to 0                   |
|    |                 |                                                     |
|    |                 | Bit 12: DSSS Cck40MHz mode                          |
|    |                 |                                                     |
|    |                 | Bit 11: Maximal A-MSDU size - reserved, set to 0    |
|    |                 |                                                     |
|    |                 | Bit 10: Delayed BA - reserved, set to 0             |
|    |                 |                                                     |
|    |                 | Bits 9:8: RX STBC - reserved, set to 0              |
|    |                 |                                                     |
|    |                 | Bit 7: TX STBC - reserved, set to 0                 |
|    |                 |                                                     |
|    |                 | Bit 6: Short GI 40 MHz                              |
|    |                 |                                                     |
|    |                 | Bit 5: Short GI 20 MHz                              |
|    |                 |                                                     |
|    |                 | Bit 4: GF preamble                                  |
|    |                 |                                                     |
|    |                 | Bits 3:2: MIMO power save - reserved, set to 0      |
|    |                 |                                                     |
|    |                 | Bit 1: SuppChanWidth - set to 0 for 2.4 GHz band    |
|    |                 |                                                     |
|    |                 | Bit 0: LDPC coding - reserved, set to 0             |
+----+-----------------+-----------------------------------------------------+

##### Note

> Call this API before calling uAP start API.

#### void wlan\_uap\_set\_httxcfg (unsigned short *httxcfg*)

> This API can be used to configure various 802.11n specific
> configuration for transmit (such as short GI, channel bandwidth and
> green field support) for uAP interface.

##### Parameters

+----+-----------+---------------------------------------------------+
| in | *httxcfg* | This is a bitmap and should be used as following  |
|    |           |                                                   |
|    |           | Bit 15-8: Reserved set to 0                       |
|    |           |                                                   |
|    |           | Bit 7: STBC Enable/Disable                        |
|    |           |                                                   |
|    |           | Bit 6: Short GI in 40 Mhz Enable/Disable          |
|    |           |                                                   |
|    |           | Bit 5: Short GI in 20 Mhz Enable/Disable          |
|    |           |                                                   |
|    |           | Bit 4: Green field Enable/Disable                 |
|    |           |                                                   |
|    |           | Bit 3-2: Reserved set to 1                        |
|    |           |                                                   |
|    |           | Bit 1: 20/40 Mhz enable disable.                  |
|    |           |                                                   |
|    |           | Bit 0: LDPC Enable/Disable                        |
|    |           |                                                   |
|    |           | When Bit 1 is set then firmware could transmit in |
|    |           | 20Mhz or 40Mhz based                              |
|    |           |                                                   |
|    |           | on rate adaptation. When this bit is reset then   |
|    |           | firmware can only                                 |
|    |           |                                                   |
|    |           | transmit in 20Mhz.                                |
+----+-----------+---------------------------------------------------+

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

  ---- -------------------- -----------------------------------------------------------------
  in   *scan\_chan\_list*   A structure holding the number of channels and channel numbers.
  ---- -------------------- -----------------------------------------------------------------

##### Note

> Call this API before uAP start API in order to set the user defined
> channels, otherwise it can have no effect. There is no need to call
> this API every time before uAP start, if once set same channel
> configuration can get used in all upcoming uAP start call. If user
> wish to change the channels at run time then it make sense to call
> this API before every uAP start API.

#### int wlan\_send\_hostcmd (const void \* *cmd\_buf*, uint32\_t *cmd\_buf\_len*, void \* *host\_resp\_buf*, uint32\_t *resp\_buf\_len*, uint32\_t \* *reqd\_resp\_len*)

> This function sends the host command to firmware and copies back
> response to caller provided buffer in case of success response from
> firmware is not parsed by this function but just copied back to the
> caller buffer.

##### Parameters

  ----- ------------------- --------------------------------------------------------------------------------------------------------------
  in    *cmd\_buf*          Buffer containing the host command with header
  in    *cmd\_buf\_len*     length of valid bytes in cmd\_buf
  out   *host\_resp\_buf*   Caller provided buffer, in case of success command response is copied to this buffer can be same as cmd\_buf
  in    *resp\_buf\_len*    resp\_buf\'s allocated length
  out   *reqd\_resp\_len*   length of valid bytes in response buffer if successful otherwise invalid.
  ----- ------------------- --------------------------------------------------------------------------------------------------------------

##### Returns

> WM\_SUCCESS in case of success.
>
> WM\_E\_INBIG in case cmd\_buf\_len is bigger than the commands that
> can be handled by driver.
>
> WM\_E\_INSMALL in case cmd\_buf\_len is smaller than the minimum
> length. Minimum length is at least the length of command header. see
> Note for same.
>
> WM\_E\_OUTBIG in case the resp\_buf\_len is not sufficient to copy
> response from firmware. reqd\_resp\_len is updated with the response
> size.
>
> WM\_E\_INVAL in case cmd\_buf\_len and resp\_buf\_len have invalid
> values.
>
> WM\_E\_NOMEM in case cmd\_buf, resp\_buf and reqd\_resp\_len are NULL

##### Note

> Brief on the command Header: Start 8 bytes of cmd\_buf should have
> these values set. Firmware would update resp\_buf with these 8 bytes
> at the start.
>
> 2 bytes : Command.
>
> 2 bytes : Size.
>
> 2 bytes : Sequence number.
>
> 2 bytes : Result.
>
> Rest of buffer length is Command/Response Body.

#### int wlan\_rx\_mgmt\_indication (const enum wlan\_bss\_type *bss\_type*, const uint32\_t *mgmt\_subtype\_mask*, int(\*)(const enum wlan\_bss\_type bss\_type, const wlan\_mgmt\_frame\_t \*frame, const size\_t len) *rx\_mgmt\_callback*)

> This API can be used to start/stop the management frame forwarded to
> host through data path.

##### Parameters

  ---- ----------------------- --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  in   *bss\_type*             The interface from which management frame needs to be collected 0: STA, 1: uAP
  in   *mgmt\_subtype\_mask*   Management Subtype Mask If Bit X is set in mask, it means that IEEE Management Frame SubType X is to be filtered and passed through to host. Bit Description \[31:14\] Reserved \[13\] Action frame \[12:9\] Reserved \[8\] Beacon \[7:6\] Reserved \[5\] Probe response \[4\] Probe request \[3\] Reassociation response \[2\] Reassociation request \[1\] Association response \[0\] Association request Support multiple bits set. 0 = stop forward frame 1 = start forward frame
  in   *rx\_mgmt\_callback*    The receive callback where the received management frames are passed.
  ---- ----------------------- --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

##### Returns

> WM\_SUCCESS if operation is successful.
>
> -WM\_FAIL if command fails.

##### Note

> Pass management subtype mask all zero to disable all the management
> frame forward to host.

#### int wlan\_set\_bandcfg (wlan\_bandcfg\_t \* *bandcfg*)

> Set band configuration.

##### Parameters

  ---- ----------- --------------------
  in   *bandcfg*   band configuration
  ---- ----------- --------------------

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_get\_bandcfg (wlan\_bandcfg\_t \* *bandcfg*)

> Get band configuration.

##### Parameters

  ----- ----------- --------------------
  out   *bandcfg*   band configuration
  ----- ----------- --------------------

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### void wlan\_set\_ps\_cfg (t\_u16 *multiple\_dtims*, t\_u16 *bcn\_miss\_timeout*, t\_u16 *local\_listen\_interval*, t\_u16 *adhoc\_wake\_period*, t\_u16 *mode*, t\_u16 *delay\_to\_ps*)

> Set multiple dtim for next wakeup RX beacon time

##### Parameters

  ---- --------------------------- ------------------------------------------------------------------------------------------------------------
  in   *multiple\_dtims*           num dtims, range \[1,20\]
  in   *bcn\_miss\_timeout*        becaon miss interval
  in   *local\_listen\_interval*   local listen interval
  in   *adhoc\_wake\_period*       adhoc awake period
  in   *mode*                      mode - (0x01 - firmware to automatically choose PS\_POLL or NULL mode, 0x02 - PS\_POLL, 0x03 - NULL mode )
  in   *delay\_to\_ps*             Delay to PS in milliseconds
  ---- --------------------------- ------------------------------------------------------------------------------------------------------------

#### int wlan\_set\_country\_code (const char \* *alpha2*)

> Set country code

##### Note

> This API should be called after Wi-Fi is initialized but before
> starting uAP interface.

##### Parameters

  ---- ---------- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  in   *alpha2*   country code in 3 octets string, 2 octets country code and 1 octet environment 2 octets country code supported: WW : World Wide Safe US : US FCC CA : IC Canada SG : Singapore EU : ETSI AU : Australia KR : Republic Of Korea FR : France JP : Japan CN : China
  ---- ---------- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

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

  ---- ---------- -----------------------------
  in   *ignore*   0: don\'t ignore, 1: ignore
  ---- ---------- -----------------------------

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_set\_region\_code (unsigned int *region\_code*)

> Set region code.

##### Parameters

  ---- ---------------- ------------------------
  in   *region\_code*   region code to be set.
  ---- ---------------- ------------------------

##### Returns

> WM\_SUCCESS if successful otherwise fail.

#### int wlan\_get\_region\_code (unsigned int \* *region\_code*)

> Get region code.

##### Parameters

  ----- ---------------- -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  out   *region\_code*   pointer The value: 0x00: World Wide Safe 0x10: US FCC 0x20: IC Canada 0x10: Singapore 0x30: ETSI 0x30: Australia 0x30: Republic Of Korea 0x32: France 0xFF: Japan 0x50: China
  ----- ---------------- -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### int wlan\_set\_11d\_state (int *bss\_type*, int *state*)

> Set STA/uAP 802.11d feature Enable/Disable.

##### Parameters

  ---- ------------- -----------------------
  in   *bss\_type*   0: STA, 1: uAP
  in   *state*       0: disable, 1: enable
  ---- ------------- -----------------------

##### Returns

> WM\_SUCCESS if successful otherwise return -WM\_FAIL.

#### t\_u16 wlan\_get\_status\_code (enum wlan\_event\_reason *reason*)

> Get 802.11 Status Code.

##### Parameters

  ---- ---------- ---------------------
  in   *reason*   wlcmgr event reason
  ---- ---------- ---------------------

##### Returns

> status code defined in IEEE 802.11-2020 standard.

#### char\* wlan\_string\_dup (const char \* *s*)

> Allocate memory for a string and copy the string to the allocated
> memory

##### Parameters

  ---- ----- --------------------------
  in   *s*   the source/target string
  ---- ----- --------------------------

##### Returns

> new string if successful, otherwise return -WM\_FAIL.

#### uint32\_t wlan\_get\_board\_type (void )

> Get board type.

##### Returns

> board type. 0x02: RW610\_PACKAGE\_TYPE\_BGA 0xFF: others

#### int wlan\_11n\_allowed (struct wlan\_network \* *network*)

> Check if 802.11n is allowed in capability.

##### Parameters

  ---- ----------- --------------------------------
  in   *network*   A pointer to the wlan\_network
  ---- ----------- --------------------------------

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

#### \#define WLAN\_RESCAN\_LIMIT  5U

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
> digits + 1 \'\\0\' char

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

> Length of a pairwise master key (PMK). It\'s always 256 bits (32
> Bytes)

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

**Value:** (WLAN\_KEY\_MGMT\_FT\_PSK \| WLAN\_KEY\_MGMT\_FT\_IEEE8021X
\| WLAN\_KEY\_MGMT\_FT\_IEEE8021X\_SHA384 \| WLAN\_KEY\_MGMT\_FT\_SAE \|
\\

WLAN\_KEY\_MGMT\_FT\_FILS\_SHA256 \| WLAN\_KEY\_MGMT\_FT\_FILS\_SHA384)

> Fast BSS Transition(11r) key management

#### \#define MAX\_CHANNEL\_LIST  6

> Configuration for Wi-Fi scan

### Typedef Documentation

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

### Enumeration Type Documentation

#### enum wm\_wlan\_errno

> Enum for Wi-Fi errors

##### Enumerator:

  ----------------------------------------- -----------------------------------------
  WLAN\_ERROR\_FW\_DNLD\_FAILED             The firmware download operation failed.
  WLAN\_ERROR\_FW\_NOT\_READY               The firmware ready register not set.
  WLAN\_ERROR\_CARD\_NOT\_DETECTED          The Wi-Fi SoC not found.
  WLAN\_ERROR\_FW\_NOT\_DETECTED            The Wi-Fi Firmware not found.
  WLAN\_BSSID\_NOT\_FOUND\_IN\_SCAN\_LIST   BSSID not found in scan list
  ----------------------------------------- -----------------------------------------

#### enum wlan\_event\_reason

> Wi-Fi connection manager event reason

##### Enumerator:

  -------------------------------------- --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  WLAN\_REASON\_SUCCESS                  The Wi-Fi connection manager has successfully connected to a network and is now in the WLAN\_CONNECTED state.
  WLAN\_REASON\_AUTH\_SUCCESS            The Wi-Fi connection manager has successfully authenticated to a network and is now in the WLAN\_ASSOCIATED state.
  WLAN\_REASON\_CONNECT\_FAILED          The Wi-Fi connection manager failed to connect before actual connection attempt with AP due to incorrect Wi-Fi network profile. or the Wi-Fi connection manager failed to reconnect to previously connected network and it is now in the WLAN\_DISCONNECTED state.
  WLAN\_REASON\_NETWORK\_NOT\_FOUND      The Wi-Fi connection manager could not find the network that it was connecting to and it is now in the WLAN\_DISCONNECTED state.
  WLAN\_REASON\_NETWORK\_AUTH\_FAILED    The Wi-Fi connection manager failed to authenticate with the network and is now in the WLAN\_DISCONNECTED state.
  WLAN\_REASON\_ADDRESS\_SUCCESS         DHCP lease has been renewed.
  WLAN\_REASON\_ADDRESS\_FAILED          The Wi-Fi connection manager failed to obtain an IP address or TCP stack configuration has failed or the IP address configuration was lost due to a DHCP error. The system is now in the WLAN\_DISCONNECTED state.
  WLAN\_REASON\_LINK\_LOST               The Wi-Fi connection manager has lost the link to the current network.
  WLAN\_REASON\_CHAN\_SWITCH             The Wi-Fi connection manager has received the channel switch announcement from the current network.
  WLAN\_REASON\_WPS\_DISCONNECT          The Wi-Fi connection manager has disconnected from the WPS network (or has canceled a connection attempt) by request and is now in the WLAN\_DISCONNECTED state.
  WLAN\_REASON\_USER\_DISCONNECT         The Wi-Fi connection manager has disconnected from the current network (or has canceled a connection attempt) by request and is now in the WLAN\_DISCONNECTED state.
  WLAN\_REASON\_INITIALIZED              The Wi-Fi connection manager is initialized and is ready for use. That is, it\'s now possible to scan or to connect to a network.
  WLAN\_REASON\_INITIALIZATION\_FAILED   The Wi-Fi connection manager has failed to initialize and is therefore not running. It is not possible to scan or to connect to a network. The Wi-Fi connection manager should be stopped and started again via wlan\_stop() and wlan\_start() respectively.
  WLAN\_REASON\_FW\_HANG                 The Wi-Fi connection manager has entered in hang mode.
  WLAN\_REASON\_FW\_RESET                The Wi-Fi connection manager has reset fw successfully.
  WLAN\_REASON\_PS\_ENTER                The Wi-Fi connection manager has entered power save mode.
  WLAN\_REASON\_PS\_EXIT                 The Wi-Fi connection manager has exited from power save mode.
  WLAN\_REASON\_UAP\_SUCCESS             The Wi-Fi connection manager has started uAP (micro access point)
  WLAN\_REASON\_UAP\_CLIENT\_ASSOC       A Wi-Fi client has joined uAP\'s BSS network
  WLAN\_REASON\_UAP\_CLIENT\_CONN        A Wi-Fi client has authenticated and connected to uAP\'s BSS network
  WLAN\_REASON\_UAP\_CLIENT\_DISSOC      A Wi-Fi client has left uAP\'s BSS network
  WLAN\_REASON\_UAP\_START\_FAILED       The Wi-Fi connection manager has failed to start uAP
  WLAN\_REASON\_UAP\_STOP\_FAILED        The Wi-Fi connection manager has failed to stop uAP
  WLAN\_REASON\_UAP\_STOPPED             The Wi-Fi connection manager has stopped uAP
  WLAN\_REASON\_RSSI\_LOW                The Wi-Fi connection manager has received subscribed RSSI low event on station interface as per configured threshold and frequency. If CONFIG\_11K, CONFIG\_11V, CONFIG\_11R or CONFIG\_ROAMING enabled then RSSI low event is processed internally.
  -------------------------------------- --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

#### enum wlan\_wakeup\_event\_t

> Wakeup event bitmap

##### Enumerator:

  -------------------------- ----------------------------------------
  WAKE\_ON\_ALL\_BROADCAST   Wakeup on broadcast
  WAKE\_ON\_UNICAST          Wakeup on unicast
  WAKE\_ON\_MAC\_EVENT       Wakeup on MAC event
  WAKE\_ON\_MULTICAST        Wakeup on multicast
  WAKE\_ON\_ARP\_BROADCAST   Wakeup on ARP broadcast
  WAKE\_ON\_MGMT\_FRAME      Wakeup on receiving a management frame
  -------------------------- ----------------------------------------

#### enum wlan\_connection\_state

> Wi-Fi station/uAP/Wi-Fi direct connection/status state

##### Enumerator:

  --------------------- --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  WLAN\_DISCONNECTED    The Wi-Fi connection manager is not connected and no connection attempt is in progress. It is possible to connect to a network or scan.
  WLAN\_CONNECTING      The Wi-Fi connection manager is not connected but it is currently attempting to connect to a network. It is not possible to scan at this time. It is possible to connect to a different network.
  WLAN\_ASSOCIATED      The Wi-Fi connection manager is not connected but associated.
  WLAN\_AUTHENTICATED   The Wi-Fi connection manager is not connected but authenticated.
  WLAN\_CONNECTED       The Wi-Fi connection manager is connected. It is possible to scan and connect to another network at this time. Information about the current network configuration is available.
  WLAN\_UAP\_STARTED    The Wi-Fi connection manager has started uAP
  WLAN\_UAP\_STOPPED    The Wi-Fi connection manager has stopped uAP
  WLAN\_SCANNING        The Wi-Fi connection manager is not connected and network scan is in progress.
  WLAN\_ASSOCIATING     The Wi-Fi connection manager is not connected and network association is in progress.
  --------------------- --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

#### enum wlan\_ps\_mode

> Station power save mode

##### Enumerator:

  ------------------------- -------------------------------------
  WLAN\_ACTIVE              Active mode
  WLAN\_IEEE                IEEE power save mode
  WLAN\_DEEP\_SLEEP         Deep sleep power save mode
  WLAN\_IEEE\_DEEP\_SLEEP   IEEE and deep sleep power save mode
  ------------------------- -------------------------------------

#### enum wlan\_security\_type

> Network security types

##### Enumerator:

  ---------------------------------------- -----------------------------------------------------------------------------------------------------------------------------------------
  WLAN\_SECURITY\_NONE                     The network does not use security.
  WLAN\_SECURITY\_WEP\_OPEN                The network uses WEP security with open key.
  WLAN\_SECURITY\_WEP\_SHARED              The network uses WEP security with shared key.
  WLAN\_SECURITY\_WPA                      The network uses WPA security with PSK.
  WLAN\_SECURITY\_WPA2                     The network uses WPA2 security with PSK.
  WLAN\_SECURITY\_WPA\_WPA2\_MIXED         The network uses WPA/WPA2 mixed security with PSK
  WLAN\_SECURITY\_WPA3\_SAE                The network uses WPA3 security with SAE.
  WLAN\_SECURITY\_WPA3\_SAE\_EXT\_KEY      The network uses WPA3 security with new SAE AKM suite 24.
  WLAN\_SECURITY\_WPA2\_WPA3\_SAE\_MIXED   The network uses WPA2/WPA3 SAE mixed security with PSK.
  WLAN\_SECURITY\_WILDCARD                 The network can use any security method. This is often used when the user only knows the name and passphrase but not the security type.
  ---------------------------------------- -----------------------------------------------------------------------------------------------------------------------------------------

#### enum address\_types

> Address types to be used by the element wlan\_ip\_config.addr\_type
> below

##### Enumerator:

  -------------------------- --------------------------------
  ADDR\_TYPE\_STATIC         Static IP address
  ADDR\_TYPE\_DHCP           Dynamic IP address
  ADDR\_TYPE\_LLA            Link level address
  ADDR\_TYPE\_BRIDGE\_MODE   For Bridge Mode, no IP address
  -------------------------- --------------------------------

Index
=====

INDEX
