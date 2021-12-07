#ifndef _WIFI_CONFIG_INTERNAL_H_
#define _WIFI_CONFIG_INTERNAL_H_

#define CONFIG_MLAN_WMSDK      1
#define CONFIG_11N             1
#define INCLUDE_FROM_MLAN      1
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

#if defined(IW61x)
#define CONFIG_EXT_SCAN_SUPPORT 1
#endif /* IW61x */

#if defined(SD8801)
#define WLAN_LOW_POWER_ENABLE 1
#endif /* SD8801 */

#define CONFIG_DEBUG_BUILD  1
#define CONFIG_DEBUG_OUTPUT 1

#endif /* _WIFI_CONFIG_INTERNAL_H_ */
