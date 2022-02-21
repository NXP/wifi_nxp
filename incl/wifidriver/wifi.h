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

/** @file wifi.h
 *
 * @brief This file contains interface to wifi driver
 */

#ifndef __WIFI_H__
#define __WIFI_H__

#ifndef CONFIG_WIFI_INTERNAL
#define CONFIG_WIFI_INTERNAL 1
#endif

#ifdef CONFIG_WIFI_INTERNAL
#define CONFIG_11N             1
#define STA_SUPPORT            1
#define UAP_SUPPORT            1
#define WPA                    1
#define KEY_MATERIAL_WEP       1
#define KEY_PARAM_SET_V2       1
#define ENABLE_802_11W         1
#define OTP_CHANINFO           1
#define CONFIG_STA_AMPDU_RX    1
#define CONFIG_STA_AMPDU_TX    1
#define CONFIG_ENABLE_AMSDU_RX 1
#define CONFIG_UAP_AMPDU_TX    1
#define CONFIG_UAP_AMPDU_RX    1
#endif

#include <wifi-decl.h>
#include <wifi_events.h>
#include <wm_os.h>
#include <wmerrno.h>

#define BANDWIDTH_20MHZ 1U
#define BANDWIDTH_40MHZ 2U
extern int16_t g_bcn_nf_last;
extern uint8_t g_rssi;
extern uint16_t g_data_nf_last;
extern uint16_t g_data_snr_last;

/** WiFi Error Code */
enum
{
    WM_E_WIFI_ERRNO_START = MOD_ERROR_START(MOD_WIFI),
    /** The Firmware download operation failed. */
    WIFI_ERROR_FW_DNLD_FAILED,
    /** The Firmware ready register not set. */
    WIFI_ERROR_FW_NOT_READY,
    /** The WiFi card not found. */
    WIFI_ERROR_CARD_NOT_DETECTED,
    /** The WiFi Firmware not found. */
    WIFI_ERROR_FW_NOT_DETECTED,
#ifdef CONFIG_XZ_DECOMPRESSION
    /** The WiFi Firmware XZ decompression failed. */
    WIFI_ERROR_FW_XZ_FAILED,
#endif
};

typedef enum
{
    MGMT_RSN_IE              = 48,
    MGMT_VENDOR_SPECIFIC_221 = 221,
    MGMT_WPA_IE              = MGMT_VENDOR_SPECIFIC_221,
    MGMT_WPS_IE              = MGMT_VENDOR_SPECIFIC_221,
} IEEEtypes_ElementId_t;

/** 802.11d country codes */
typedef PACK_START enum {
    /** World Wide Safe Mode */
    COUNTRY_WW = 1,
    /** US FCC */
    COUNTRY_US,
    /** IC Canada */
    COUNTRY_CA,
    /** Singapore */
    COUNTRY_SG,
    /** ETSI */
    COUNTRY_EU,
    /** Australia */
    COUNTRY_AU,
    /** Republic Of Korea */
    COUNTRY_KR,
    /** France */
    COUNTRY_FR,
    /** Japan */
    COUNTRY_JP,
    /** China */
    COUNTRY_CN,
} PACK_END country_code_t;

/**
 * Initialize Wi-Fi driver module.
 *
 * Performs SDIO init, downloads Wi-Fi Firmware, creates Wi-Fi Driver
 * and command response processor thread.
 *
 * Also creates mutex, and semaphores used in command and data synchronizations.
 *
 * \param[in] fw_ram_start_addr address of stored Wi-Fi Firmware.
 * \param[in] size Size of Wi-Fi Firmware.
 *
 * \return WM_SUCCESS on success or -WM_FAIL on error.
 *
 */
int wifi_init(const uint8_t *fw_ram_start_addr, const size_t size);

/**
 * Initialize Wi-Fi driver module for FCC Certification.
 *
 * Performs SDIO init, downloads Wi-Fi Firmware, creates Wi-Fi Driver
 * and command response processor thread.
 *
 * Also creates mutex, and semaphores used in command and data synchronizations.
 *
 * \param[in] fw_ram_start_addr address of stored Manufacturing Wi-Fi Firmware.
 * \param[in] size Size of Manufacturing Wi-Fi Firmware.
 *
 * \return WM_SUCCESS on success or -WM_FAIL on error.
 *
 */
int wifi_init_fcc(const uint8_t *fw_ram_start_addr, const size_t size);

/**
 * Deinitialize Wi-Fi driver module.
 *
 * Performs SDIO deinit, send shutdown command to Wi-Fi Firmware, deletes
 * Wi-Fi Driver and command processor thread.
 *
 * Also deletes mutex and semaphores used in command and data synchronizations.
 *
 */
void wifi_deinit(void);

/**
 * Register Data callback function with Wi-Fi Driver to receive
 * DATA from SDIO.
 *
 * This callback function is used to send data received from Wi-Fi
 * firmware to the networking stack.
 *
 * @param[in] data_intput_callback Function that needs to be called
 *
 * @return WM_SUCCESS
 */
int wifi_register_data_input_callback(void (*data_intput_callback)(const uint8_t interface,
                                                                   const uint8_t *buffer,
                                                                   const uint16_t len));

/** Deregister Data callback function from Wi-Fi Driver */
void wifi_deregister_data_input_callback(void);

/**
 * Register Data callback function with Wi-Fi Driver to receive
 * processed AMSDU DATA from Wi-Fi driver.
 *
 * This callback function is used to send data received from Wi-Fi
 * firmware to the networking stack.
 *
 * @param[in] amsdu_data_intput_callback Function that needs to be called
 *
 * @return WM_SUCESS
 *
 */
int wifi_register_amsdu_data_input_callback(void (*amsdu_data_intput_callback)(uint8_t interface,
                                                                               uint8_t *buffer,
                                                                               uint16_t len));

/** Deregister Data callback function from Wi-Fi Driver */
void wifi_deregister_amsdu_data_input_callback(void);

int wifi_register_deliver_packet_above_callback(void (*deliver_packet_above_callback)(uint8_t interface,
                                                                                      void *lwip_pbuf));

void wifi_deregister_deliver_packet_above_callback(void);

int wifi_register_wrapper_net_is_ip_or_ipv6_callback(bool (*wrapper_net_is_ip_or_ipv6_callback)(const t_u8 *buffer));

void wifi_deregister_wrapper_net_is_ip_or_ipv6_callback(void);

/**
 * Wi-Fi Driver low level output function.
 *
 * Data received from upper layer is passed to Wi-Fi Driver for transmission.
 *
 * \param[in] interface Interface on which DATA frame will be transmitted.
 *  0 for Station interface, 1 for uAP interface and 2 for Wi-Fi
 *  Direct interface.
 * \param[in] buffer A pointer pointing to DATA frame.
 * \param[in] len Length of DATA frame.
 *
 * \return WM_SUCCESS on success or -WM_E_NOMEM if memory is not available
 *  or -WM_E_BUSY if SDIO is busy.
 *
 */
int wifi_low_level_output(const uint8_t interface,
                          const uint8_t *buffer,
                          const uint16_t len
#ifdef CONFIG_WMM
                          ,
                          uint8_t pkt_prio,
                          uint8_t tid
#endif
);

/**
 * API to enable packet retries at wifi driver level.
 *
 * This API sets retry count which will be used by wifi driver to retry packet
 * transmission in case there was failure in earlier attempt. Failure may
 * happen due to SDIO write port un-availability or other failures in SDIO
 * write operation.
 *
 * \note Default value of retry count is zero.
 *
 * \param[in] count No of retry attempts.
 *
 */
void wifi_set_packet_retry_count(const int count);

/**
 * This API can be used to enable AMPDU support on the go
 * when station is a transmitter.
 */
void wifi_sta_ampdu_tx_enable(void);

/**
 * This API can be used to disable AMPDU support on the go
 * when station is a transmitter.
 */
void wifi_sta_ampdu_tx_disable(void);

/**
 * This API can be used to enable AMPDU support on the go
 * when station is a receiver.
 */
void wifi_sta_ampdu_rx_enable(void);

/**
 * This API can be used to disable AMPDU support on the go
 * when station is a receiver.
 */
void wifi_sta_ampdu_rx_disable(void);

/**
 * Get the device MAC address
 *
 * @param[out] mac_addr Mac address
 *
 * @return WM_SUCESS
 */
int wifi_get_device_mac_addr(wifi_mac_addr_t *mac_addr);

/**
 * Get the cached string representation of the wlan firmware extended version.
 *
 * @param[in] fw_ver_ext Firmware Version Extended
 *
 * @return WM_SUCCESS
 */
int wifi_get_device_firmware_version_ext(wifi_fw_version_ext_t *fw_ver_ext);

/**
 * Get the timestamp of the last command sent to the firmware
 *
 * @return Timestamp in millisec of the last command sent
 */
unsigned wifi_get_last_cmd_sent_ms(void);

uint32_t wifi_get_value1(void);

uint8_t *wifi_get_outbuf(uint32_t *outbuf_len);

/**
 * This will update the last command sent variable value to current
 * time. This is used for power management.
 */
void wifi_update_last_cmd_sent_ms(void);

/**
 * Register an event queue with the wifi driver to receive events
 *
 * The list of events which can be received from the wifi driver are
 * enumerated in the file wifi_events.h
 *
 * @param[in] event_queue The queue to which wifi driver will post events.
 *
 * @note Only one queue can be registered. If the registered queue needs to
 * be changed unregister the earlier queue first.
 *
 * @return Standard SDK return codes
 */
int wifi_register_event_queue(os_queue_t *event_queue);

/**
 * Unregister an event queue from the wifi driver.
 *
 * @param[in] event_queue The queue to which was registered earlier with
 * the wifi driver.
 *
 * @return Standard SDK return codes
 */
int wifi_unregister_event_queue(os_queue_t *event_queue);

/** Get scan list
 *
 * @param[in] index Index
 * @param[out] desc Descriptor of type \ref wifi_scan_result
 *
 * @return WM_SUCCESS on success or error code.
 *
 */
int wifi_get_scan_result(unsigned int index, struct wifi_scan_result **desc);

/**
 * Get the count of elements in the scan list
 *
 * @param[in,out] count Pointer to a variable which will hold the count after
 * this call returns
 *
 * @warning The count returned by this function is the current count of the
 * elements. A scan command given to the driver or some other background
 * event may change this count in the wifi driver. Thus when the API
 * \ref wifi_get_scan_result is used to get individual elements of the scan
 * list, do not assume that it will return exactly 'count' number of
 * elements. Your application should not consider such situations as a
 * major event.
 *
 * @return Standard SDK return codes.
 */
int wifi_get_scan_result_count(unsigned *count);

/**
 * Returns the current STA list connected to our uAP
 *
 * This function gets its information after querying the firmware. It will
 * block till the response is received from firmware or a timeout.
 *
 * @param[in, out] list After this call returns this points to the
 * structure \ref wifi_sta_list_t allocated by the callee. This is variable
 * length structure and depends on count variable inside it. <b> The caller
 * needs to free this buffer after use.</b>. If this function is unable to
 * get the sta list, the value of list parameter will be NULL
 *
 * \note The caller needs to explicitly free the buffer returned by this
 * function.
 *
 * @return void
 */
int wifi_uap_bss_sta_list(wifi_sta_list_t **list);

#ifdef WLAN_LOW_POWER_ENABLE
void wifi_enable_low_pwr_mode();
#endif

/** Set wifi calibration data in firmware.
 *
 * This function may be used to set wifi calibration data in firmware.
 *
 * @param[in] cdata The calibration data
 * @param[in] clen Length of calibration data
 *
 */
void wifi_set_cal_data(uint8_t *cdata, unsigned int clen);

/** Set wifi MAC address in firmware at load time.
 *
 * This function may be used to set wifi MAC address in firmware.
 *
 * @param[in] mac The new MAC Address
 *
 */
void wifi_set_mac_addr(uint8_t *mac);

/** Set wifi MAC address in firmware at run time.
 *
 * This function may be used to set wifi MAC address in firmware.
 *
 * @param[in] mac The new MAC Address
 *
 */
void _wifi_set_mac_addr(uint8_t *mac);

#ifdef CONFIG_P2P
int wifi_register_wfd_event_queue(os_queue_t *event_queue);
int wifi_unregister_wfd_event_queue(os_queue_t *event_queue);
void wifi_wfd_event(bool peer_event, bool action_frame, void *data);
int wifi_wfd_start(char *ssid, int security, char *passphrase, int channel);
int wifi_wfd_stop(void);

/**
 * Returns the current STA list connected to our WFD
 *
 * This function gets its information after querying the firmware. It will
 * block till the response is received from firmware or a timeout.
 *
 * @param[in, out] list After this call returns this points to the
 * structure \ref sta_list_t allocated by the callee. This is variable
 * length structure and depends on count variable inside it. <b> The caller
 * needs to free this buffer after use.</b>. If this function is unable to
 * get the sta list, the value of list parameter will be NULL
 *
 * \note The caller needs to explicitly free the buffer returned by this
 * function.
 *
 * @return void
 */
int wifi_wfd_bss_sta_list(sta_list_t **list);

int wifi_get_wfd_mac_address(void);
int wifi_wfd_ps_inactivity_sleep_enter(unsigned int ctrl_bitmap,
                                       unsigned int inactivity_to,
                                       unsigned int min_sleep,
                                       unsigned int max_sleep,
                                       unsigned int min_awake,
                                       unsigned int max_awake);

int wifi_wfd_ps_inactivity_sleep_exit();
int wifidirectapcmd_sys_config();
void wifidirectcmd_config();
#endif

int wifi_get_wpa_ie_in_assoc(uint8_t *wpa_ie);

/** Add Multicast Filter by MAC Address
 *
 * Multicast filters should be registered with the WiFi driver for IP-level
 * multicast addresses to work. This API allows for registration of such filters
 * with the WiFi driver.
 *
 * If multicast-mapped MAC address is 00:12:23:34:45:56 then pass mac_addr as
 * below:
 * mac_add[0] = 0x00
 * mac_add[1] = 0x12
 * mac_add[2] = 0x23
 * mac_add[3] = 0x34
 * mac_add[4] = 0x45
 * mac_add[5] = 0x56
 *
 * \param[in] mac_addr multicast mapped MAC address
 *
 * \return 0 on Success or else Error
 */
int wifi_add_mcast_filter(uint8_t *mac_addr);

/** Remove Multicast Filter by MAC Address
 *
 * This function removes multicast filters for the given multicast-mapped
 * MAC address. If multicast-mapped MAC address is 00:12:23:34:45:56
 * then pass mac_addr as below:
 * mac_add[0] = 0x00
 * mac_add[1] = 0x12
 * mac_add[2] = 0x23
 * mac_add[3] = 0x34
 * mac_add[4] = 0x45
 * mac_add[5] = 0x56
 *
 * \param[in] mac_addr multicast mapped MAC address
 *
 * \return  0 on Success or else Error
 */
int wifi_remove_mcast_filter(uint8_t *mac_addr);

/** Get Multicast Mapped Mac address from IPv4
 *
 * This function will generate Multicast Mapped MAC address from IPv4
 * Multicast Mapped MAC address will be in following format:
 * 1) Higher 24-bits filled with IANA Multicast OUI (01-00-5E)
 * 2) 24th bit set as Zero
 * 3) Lower 23-bits filled with IP address (ignoring higher 9bits).
 *
 * \param[in] ipaddr ipaddress(input)
 * \param[in] mac_addr multicast mapped MAC address(output)
 *
 * \return  void
 */
void wifi_get_ipv4_multicast_mac(uint32_t ipaddr, uint8_t *mac_addr);

#ifdef CONFIG_IPV6
/** Get Multicast Mapped Mac address from IPv6 address
 *
 * This function will generate Multicast Mapped MAC address from IPv6 address.
 * Multicast Mapped MAC address will be in following format:
 * 1) Higher 16-bits filled with IANA Multicast OUI (33-33)
 * 2) Lower 32-bits filled with last 4 bytes of IPv6 address
 *
 * \param[in] ipaddr last 4 bytes of IPv6 address
 * \param[in] mac_addr multicast mapped MAC address
 *
 * \return void
 */
void wifi_get_ipv6_multicast_mac(uint32_t ipaddr, uint8_t *mac_addr);
#endif /* CONFIG_IPV6 */

#ifdef STREAM_2X2
int wifi_set_11n_cfg(uint16_t httxcfg);
int wifi_set_11ac_cfg(uint32_t vhtcap, uint16_t tx_mcs_map, uint16_t rx_mcs_map);
#endif

#ifdef STREAM_2X2
int wifi_set_antenna(t_u8 tx_antenna, t_u8 rx_antenna);
#else
int wifi_set_antenna(t_u32 ant_mode, t_u16 evaluate_time);
int wifi_get_antenna(t_u32 *ant_mode, t_u16 *evaluate_time);
#endif

void wifi_process_hs_cfg_resp(t_u8 *cmd_res_buffer);
enum wifi_event_reason wifi_process_ps_enh_response(t_u8 *cmd_res_buffer, t_u16 *ps_event, t_u16 *action);

int wifi_uap_rates_getset(uint8_t action, char *rates, uint8_t num_rates);
int wifi_uap_sta_ageout_timer_getset(uint8_t action, uint32_t *sta_ageout_timer);
int wifi_uap_ps_sta_ageout_timer_getset(uint8_t action, uint32_t *sta_ageout_timer);
typedef enum
{
    REG_MAC = 1,
    REG_BBP,
    REG_RF
} wifi_reg_t;

int wifi_mem_access(uint16_t action, uint32_t addr, uint32_t *value);
/*
 * This function is supposed to be called after scan is complete from wlc
 * manager.
 */
void wifi_scan_process_results(void);

/**
 * Get the wifi region code
 *
 * This function will return one of the following values in the region_code
 * variable.\n
 * 0x10 : US FCC\n
 * 0x20 : CANADA\n
 * 0x30 : EU\n
 * 0x32 : FRANCE\n
 * 0x40 : JAPAN\n
 * 0x41 : JAPAN\n
 * 0x50 : China\n
 * 0xfe : JAPAN\n
 * 0xff : Special\n
 *
 * @param[out] region_code Region Code
 *
 * @return Standard WMSDK return codes.
 */
int wifi_get_region_code(t_u32 *region_code);

/**
 * Set the wifi region code.
 *
 * This function takes one of the values from the following array.\n
 * 0x10 : US FCC\n
 * 0x20 : CANADA\n
 * 0x30 : EU\n
 * 0x32 : FRANCE\n
 * 0x40 : JAPAN\n
 * 0x41 : JAPAN\n
 * 0x50 : China\n
 * 0xfe : JAPAN\n
 * 0xff : Special\n
 *
 * @param[in] region_code Region Code
 *
 * @return Standard WMSDK return codes.
 */
int wifi_set_region_code(t_u32 region_code);

/**
 * Get the uAP channel number
 *
 *
 * @param[in] channel Pointer to channel number. Will be initialized by
 * callee
 * @return Standard WMSDK return code
 */
int wifi_get_uap_channel(int *channel);

/**
 * Sets the domain parameters for the uAP.
 *
 * @note This API only saves the domain params inside the driver internal
 * structures. The actual application of the params will happen only during
 * starting phase of uAP. So, if the uAP is already started then the
 * configuration will not apply till uAP re-start.
 *
 * To use this API you will need to fill up the structure
 * \ref wifi_domain_param_t with correct parameters.
 *
 * E.g. Programming for US country code\n
 * <CODE>
 *	wifi_sub_band_set_t sb = {
 *		.first_chan = 1,
 *		.no_of_chan= 11,
 *		.max_tx_pwr = 30,
 *	};
 *
 *	wifi_domain_param_t *dp = os_mem_alloc(sizeof(wifi_domain_param_t) +
 *					       sizeof(wifi_sub_band_set_t));
 *
 *	(void)memcpy(dp->country_code, "US\0", COUNTRY_CODE_LEN);
 *	dp->no_of_sub_band = 1;
 *	(void)memcpy(dp->sub_band, &sb, sizeof(wifi_sub_band_set_t));
 *
 *	wmprintf("wifi uap set domain params\n\r");
 *	wifi_uap_set_domain_params(dp);
 *	os_mem_free(dp);
 * </CODE>
 *
 * @return WM_SUCCESS on success or error code.
 *
 */
int wifi_enable_11d_support(void);
int wifi_set_domain_params(wifi_domain_param_t *dp);
int wifi_set_country(int country);
int wifi_uap_set_country(int country);
int wifi_get_country(void);
#ifdef OTP_CHANINFO
int wifi_get_fw_region_and_cfp_tables();
#endif
int wifi_set_htcapinfo(unsigned int htcapinfo);
int wifi_set_httxcfg(unsigned short httxcfg);
int wifi_uap_set_httxcfg(unsigned short httxcfg);
int wifi_get_tx_power(t_u32 *power_level);
int wifi_set_tx_power(t_u32 power_level);
int wrapper_wlan_cmd_get_hw_spec(void);
/* fixme: These need to be removed later after complete mlan integration */
void set_event_chanswann(void);
void clear_event_chanswann(void);
int wifi_send_hs_cfg_cmd(mlan_bss_type interface, t_u32 ipv4_addr, t_u16 action, t_u32 conditions);
bool wrapper_wlan_11d_support_is_enabled(void);
void wrapper_wlan_11d_clear_parsedtable(void);
void wrapper_clear_media_connected_event(void);
int wifi_uap_ps_inactivity_sleep_exit(mlan_bss_type type);
int wifi_enter_ieee_power_save(void);
int wifi_exit_ieee_power_save(void);
int wifi_enter_deepsleep_power_save(void);
int wifi_exit_deepsleep_power_save(void);
void send_sleep_confirm_command(mlan_bss_type interface);
void wifi_configure_listen_interval(int listen_interval);
void wifi_configure_null_pkt_interval(unsigned int null_pkt_interval);
int wrapper_wifi_assoc(const unsigned char *bssid, int wlan_security, bool is_wpa_tkip, unsigned int owe_trans_mode);
#ifdef CONFIG_WIFI_UAP_WORKAROUND_STICKY_TIM
void wifi_uap_enable_sticky_bit(const uint8_t *mac_addr);
#endif /* CONFIG_WIFI_UAP_WORKAROUND_STICKY_TIM */
bool wifi_get_xfer_pending(void);
void wifi_set_xfer_pending(bool xfer_val);
int wrapper_wlan_cmd_11n_ba_stream_timeout(void *saved_event_buff);

int wifi_set_txratecfg(wifi_ds_rate ds_rate);
int wifi_get_txratecfg(wifi_ds_rate *ds_rate);
void wifi_wake_up_card(uint32_t *resp);

#ifdef CONFIG_WPA2_ENTP
void wifi_scan_enable_wpa2_enterprise_ap_only();
#endif

#ifndef CONFIG_MLAN_WMSDK
int wifi_auto_reconnect_enable(wifi_auto_reconnect_config_t auto_reconnect_config);

int wifi_auto_reconnect_disable();

int wifi_get_auto_reconnect_config(wifi_auto_reconnect_config_t *auto_reconnect_config);
#endif

int wrapper_wlan_11d_enable(void);

int wrapper_wlan_cmd_11n_addba_rspgen(void *saved_event_buff);

int wrapper_wlan_cmd_11n_delba_rspgen(void *saved_event_buff);

int wrapper_wlan_ecsa_enable(void);

int wifi_uap_start(int type,
                   char *ssid,
                   uint8_t *mac_addr,
                   int security,
                   char *passphrase,
                   char *password,
                   int channel,
                   wifi_scan_chan_list_t scan_chan_list,
                   bool mfpc,
                   bool mfpr);

#ifdef CONFIG_WMM
int wrapper_wlan_sta_ampdu_enable(t_u8 tid);
#else
int wrapper_wlan_sta_ampdu_enable(void);
#endif

int wrapper_wlan_upa_ampdu_enable(uint8_t *addr);

#ifdef CONFIG_WLAN_BRIDGE
/** Enable Bridge mode in WLAN firmware.
 *
 * \param[in] auto_link, Whether enable auto link for in-sta of bridge mode.
 * \param[in] hidden_ssid, Whether enable hidden_ssid for in-AP of bridge mode.
 * \param[in] cfg, Bridge configuration structure holding enable, auto_link,
 *	      hidden_ssid, EX-AP SSID, Passphrase, Bridge SSID and Passphrase.
 *
 * \return WM_SUCCESS if operation is successful.
 * \return -WM_FAIL if operation is failed.
 */
int wifi_enable_bridge_mode(wifi_bridge_cfg_t *cfg);

/** Disable Bridge mode in WLAN firmware.
 *
 * \return WM_SUCCESS if operation is successful.
 * \return -WM_FAIL if operation is failed.
 */
int wifi_disable_bridge_mode();

/** Get Bridge configuration from WLAN firmware.
 *
 * \param[out] cfg Bridge configuration structure where EX-AP SSID,
 *             Passphrase, Bridge SSID and Passphrase will get copied.
 *
 * \return WM_SUCCESS if operation is successful.
 * \return -WM_FAIL if operation is failed.
 */
int wifi_get_bridge_mode_config(wifi_bridge_cfg_t *cfg);

/**
 * Reconfigure TX buffer size during bridge mode operation.
 *
 * \param[in] buf_size Buffer size to configure.
 *
 * \return WM_SUCCESS if operation is successful.
 * \return -WM_FAIL is operation is failed.
 */
int wifi_config_bridge_tx_buf(uint16_t buf_size);
#endif

#ifdef CONFIG_WIFI_GET_LOG
/** WiFi Statistics counter */
typedef PACK_START struct
{
    /** Multicast transmitted frame count */
    t_u32 mcast_tx_frame;
    /** Failure count */
    t_u32 failed;
    /** Retry count */
    t_u32 retry;
    /** Multi entry count */
    t_u32 multi_retry;
    /** Duplicate frame count */
    t_u32 frame_dup;
    /** RTS success count */
    t_u32 rts_success;
    /** RTS failure count */
    t_u32 rts_failure;
    /** Ack failure count */
    t_u32 ack_failure;
    /** Rx fragmentation count */
    t_u32 rx_frag;
    /** Multicast Tx frame count */
    t_u32 mcast_rx_frame;
    /** FCS error count */
    t_u32 fcs_error;
    /** Tx frame count */
    t_u32 tx_frame;
    /** WEP ICV error count */
    t_u32 wep_icv_error[4];
    /** beacon recv count */
    t_u32 bcn_rcv_cnt;
    /** beacon miss count */
    t_u32 bcn_miss_cnt;
    /** received amsdu count*/
    t_u32 amsdu_rx_cnt;
    /** received msdu count in amsdu*/
    t_u32 msdu_in_rx_amsdu_cnt;
    /** tx amsdu count*/
    t_u32 amsdu_tx_cnt;
    /** tx msdu count in amsdu*/
    t_u32 msdu_in_tx_amsdu_cnt;
    /** Tx frag count */
    t_u32 tx_frag_cnt;
    /** Qos Tx frag count */
    t_u32 qos_tx_frag_cnt[8];
    /** Qos failed count */
    t_u32 qos_failed_cnt[8];
    /** Qos retry count */
    t_u32 qos_retry_cnt[8];
    /** Qos multi retry count */
    t_u32 qos_multi_retry_cnt[8];
    /** Qos frame dup count */
    t_u32 qos_frm_dup_cnt[8];
    /** Qos rts success count */
    t_u32 qos_rts_suc_cnt[8];
    /** Qos rts failure count */
    t_u32 qos_rts_failure_cnt[8];
    /** Qos ack failure count */
    t_u32 qos_ack_failure_cnt[8];
    /** Qos Rx frag count */
    t_u32 qos_rx_frag_cnt[8];
    /** Qos Tx frame count */
    t_u32 qos_tx_frm_cnt[8];
    /** Qos discarded frame count */
    t_u32 qos_discarded_frm_cnt[8];
    /** Qos mpdus Rx count */
    t_u32 qos_mpdus_rx_cnt[8];
    /** Qos retry rx count */
    t_u32 qos_retries_rx_cnt[8];
    /** CMACICV errors count */
    t_u32 cmacicv_errors;
    /** CMAC replays count */
    t_u32 cmac_replays;
    /** mgmt CCMP replays count */
    t_u32 mgmt_ccmp_replays;
    /** TKIP ICV errors count */
    t_u32 tkipicv_errors;
    /** TKIP replays count */
    t_u32 tkip_replays;
    /** CCMP decrypt errors count */
    t_u32 ccmp_decrypt_errors;
    /** CCMP replays count */
    t_u32 ccmp_replays;
    /** Tx amsdu count */
    t_u32 tx_amsdu_cnt;
    /** failed amsdu count */
    t_u32 failed_amsdu_cnt;
    /** retry amsdu count */
    t_u32 retry_amsdu_cnt;
    /** multi-retry amsdu count */
    t_u32 multi_retry_amsdu_cnt;
    /** Tx octets in amsdu count */
    t_u64 tx_octets_in_amsdu_cnt;
    /** amsdu ack failure count */
    t_u32 amsdu_ack_failure_cnt;
    /** Rx amsdu count */
    t_u32 rx_amsdu_cnt;
    /** Rx octets in amsdu count */
    t_u64 rx_octets_in_amsdu_cnt;
    /** Tx ampdu count */
    t_u32 tx_ampdu_cnt;
    /** tx mpdus in ampdu count */
    t_u32 tx_mpdus_in_ampdu_cnt;
    /** tx octets in ampdu count */
    t_u64 tx_octets_in_ampdu_cnt;
    /** ampdu Rx count */
    t_u32 ampdu_rx_cnt;
    /** mpdu in Rx ampdu count */
    t_u32 mpdu_in_rx_ampdu_cnt;
    /** Rx octets ampdu count */
    t_u64 rx_octets_in_ampdu_cnt;
    /** ampdu delimiter CRC error count */
    t_u32 ampdu_delimiter_crc_error_cnt;
    /** Rx Stuck Related Info*/
    /** Rx Stuck Issue count */
    t_u32 rx_stuck_issue_cnt[2];
    /** Rx Stuck Recovery count */
    t_u32 rx_stuck_recovery_cnt;
    /** Rx Stuck TSF */
    t_u64 rx_stuck_tsf[2];
    /** Tx Watchdog Recovery Related Info */
    /** Tx Watchdog Recovery count */
    t_u32 tx_watchdog_recovery_cnt;
    /** Tx Watchdog TSF */
    t_u64 tx_watchdog_tsf[2];
    /** Channel Switch Related Info */
    /** Channel Switch Announcement Sent */
    t_u32 channel_switch_ann_sent;
    /** Channel Switch State */
    t_u32 channel_switch_state;
    /** Register Class */
    t_u32 reg_class;
    /** Channel Number */
    t_u32 channel_number;
    /** Channel Switch Mode */
    t_u32 channel_switch_mode;
    /** Reset Rx Mac Recovery Count */
    t_u32 rx_reset_mac_recovery_cnt;
    /** ISR2 Not Done Count*/
    t_u32 rx_Isr2_NotDone_Cnt;
    /** GDMA Abort Count */
    t_u32 gdma_abort_cnt;
    /** Rx Reset MAC Count */
    t_u32 g_reset_rx_mac_cnt;
    // Ownership error counters
    /*Error Ownership error count*/
    t_u32 dwCtlErrCnt;
    /*Control Ownership error count*/
    t_u32 dwBcnErrCnt;
    /*Control Ownership error count*/
    t_u32 dwMgtErrCnt;
    /*Control Ownership error count*/
    t_u32 dwDatErrCnt;
    /*BIGTK MME good count*/
    t_u32 bigtk_mmeGoodCnt;
    /*BIGTK Replay error count*/
    t_u32 bigtk_replayErrCnt;
    /*BIGTK MIC error count*/
    t_u32 bigtk_micErrCnt;
    /*BIGTK MME not included count*/
    t_u32 bigtk_mmeNotFoundCnt;
} PACK_END wifi_pkt_stats_t;

int wifi_get_log(wifi_pkt_stats_t *stats, mlan_bss_type bss_type);
#endif

void handle_cdint(int error);

int wifi_set_packet_filters(wifi_flt_cfg_t *flt_cfg);

int wifi_uap_stop(int type);
int wifi_uap_set_bandwidth(const t_u8 bandwidth);

#ifndef CONFIG_MLAN_WMSDK
int wifi_get_tbtt_offset(wifi_tbtt_offset_t *tbtt_offset);
#endif

#ifdef CONFIG_WIFI_RTS_THRESHOLD
int wifi_set_rts(int rts, mlan_bss_type bss_type);
#endif

#ifdef CONFIG_WIFI_FRAG_THRESHOLD
int wifi_set_frag(int frag, mlan_bss_type bss_type);
#endif

#ifdef CONFIG_UAP_STA_MAC_ADDR_FILTER
int wifi_set_sta_mac_filter(int filter_mode, int mac_count, unsigned char *mac_addr);
#endif

int wifi_set_auto_arp(t_u32 *ipv4_addr);

int wifi_tcp_keep_alive(wifi_tcp_keep_alive_t *keep_alive, t_u8 *src_mac, t_u32 src_ip);

#ifndef CONFIG_MLAN_WMSDK
int wifi_nat_keep_alive(wifi_nat_keep_alive_t *keep_alive, t_u8 *src_mac, t_u32 src_ip, t_u16 src_port);
#endif

int wifi_raw_packet_send(const t_u8 *packet, t_u32 length);

int wifi_raw_packet_recv(t_u8 **data, t_u32 *pkt_type);

#ifdef CONFIG_11AX
int wifi_set_11ax_tx_omi(const t_u16 tx_omi);
#endif

#ifdef CONFIG_RF_TEST_MODE

int wifi_set_rf_test_mode(void);

int wifi_set_rf_channel(const uint8_t channel);

int wifi_get_rf_channel(uint8_t *channel);

int wifi_set_rf_band(const uint8_t band);

int wifi_get_rf_band(uint8_t *band);

int wifi_set_rf_bandwidth(const uint8_t bandwidth);

int wifi_get_rf_bandwidth(uint8_t *bandwidth);

int wifi_get_rf_per(uint32_t *rx_tot_pkt_count, uint32_t *rx_mcast_bcast_count, uint32_t *rx_pkt_fcs_error);

int wifi_set_rf_tx_cont_mode(const uint32_t enable_tx,
                             const uint32_t cw_mode,
                             const uint32_t payload_pattern,
                             const uint32_t cs_mode,
                             const uint32_t act_sub_ch,
                             const uint32_t tx_rate);

int wifi_set_rf_tx_antenna(const uint8_t antenna);

int wifi_get_rf_tx_antenna(uint8_t *antenna);

int wifi_set_rf_rx_antenna(const uint8_t antenna);

int wifi_get_rf_rx_antenna(uint8_t *antenna);

int wifi_set_rf_tx_power(const uint8_t power, const uint8_t mod, const uint8_t path_id);

int wifi_set_rf_tx_frame(const uint32_t enable,
                         const uint32_t data_rate,
                         const uint32_t frame_pattern,
                         const uint32_t frame_length,
                         const uint32_t adjust_burst_sifs,
                         const uint32_t burst_sifs_in_us,
                         const uint32_t short_preamble,
                         const uint32_t act_sub_ch,
                         const uint32_t short_gi,
                         const uint32_t adv_coding,
                         const uint32_t tx_bf,
                         const uint32_t gf_mode,
                         const uint32_t stbc,
                         const uint32_t *bssid);
#endif
#ifdef CONFIG_WIFI_FW_DEBUG
/** This function registers callbacks which are used to generate FW Dump on USB
 * device.
 *
 * \param[in] wifi_usb_mount_cb Callback to mount usb device.
 * \param[in] wifi_usb_file_open_cb Callback to open file on usb device for FW dump.
 * \param[in] wifi_usb_file_write_cb Callback to write FW dump data to opened file.
 * \param[in] wifi_usb_file_close_cb Callback to close FW dump file.
 *
 * \return void
 */
void wifi_register_fw_dump_cb(int (*wifi_usb_mount_cb)(),
                              int (*wifi_usb_file_open_cb)(char *test_file_name),
                              int (*wifi_usb_file_write_cb)(uint8_t *data, size_t data_len),
                              int (*wifi_usb_file_close_cb)());
#endif
#ifdef CONFIG_WMM
#define BK_MAX_BUF 4
#define BE_MAX_BUF 4
#define VI_MAX_BUF 4
#define VO_MAX_BUF 4

bool is_wifi_wmm_queue_full(mlan_wmm_ac_e queue);

int wifi_wmm_get_pkt_prio(t_u8 *buf, t_u8 *tid, bool *is_udp_frame);

uint8_t *wifi_wmm_get_outbuf(uint32_t *outbuf_len, mlan_wmm_ac_e queue);
#endif
wifi_domain_param_t *get_11d_domain_params(int country, wifi_sub_band_set_t *sub_band, t_u8 nr_sb);
#endif
