/*
 *  Copyright 2008-2022 NXP
 *
 *  Licensed under the LA_OPT_NXP_Software_License.txt (the "Agreement")
 *
 */

/*! \file wlan_11d.h
 * \brief WLAN module 11d API
 */

#ifndef __WLAN_11D_H__
#define __WLAN_11D_H__

#include <wifi.h>

/** wlan_11d Wi-Fi Region Configuration
 * By default, the SDK builds applications that are compliant with the
 * US region configuration. This implies that the module obeys the
 * US regulations for Wi-Fi transmissions on certified frequency bands. The
 * SDK provides mechanism for configuring various region codes in the
 * applications.
 * This can be performed in one of the following two ways:
 *
 * I) Specifying Country Code
 *
 * In this method of configuration, the application defines up-front
 * what is the country code that the device is going to be deployed in.
 * Once configured the Wi-Fi firmware obeys the configured
 * countries regulations. This configuration can be set by making a call to the
 * wlan_set_country() API. This API should be called after WLAN is initialized
 * but before starting uAP or making any connection attempts on station
 * interface.
 *
 * For example:
 * wlan_set_country(COUNTRY_CN);
 *
 * II) Using 802.11D
 *
 * \note The FCC does not allow the use of 802.11D in the US starting Jan 1,
 * 2015.
 * In this method of configuration, the Wi-Fi driver of the SDK will
 * scan for Access Points in the vicinity and  accordingly configure
 * itself to operate in the available frequency bands. This configuration can
 * be set by making a call to the wlan_enable_11d() API. This API should be
 * called after WLAN is initialized but before starting uAP or making any
 * connection attempts on station interface.
 *
 * For example:
 * wlan_enable_11d();
 *
 * @{
 */

/** Enable 11D support in WLAN Driver.
 *
 * \note This API should be called after WLAN is initialized
 * but before starting uAP or making any connection attempts on station
 * interface.
 *
 * \note Either this function or wlan_set_country() should be used
 * at a time. If both functions are called in the application, then WLAN
 * Driver properties will be set as per the wlan_set_country() function.
 *
 * \return -WM_FAIL if operation was failed.
 * \return WM_SUCCESS if operation was successful.
 */
static inline int wlan_enable_11d(void)
{
    return wifi_enable_11d_support();
}

/** Get country code from WLAN Driver.
 *
 * \note This API should be called after WLAN is initialized
 * but before starting uAP or making any connection attempts on station
 * interface.
 *
 * \return Country code. Refer to \ref country_code_t.
 *
 */
static inline country_code_t wlan_get_country(void)
{
    return wifi_get_country();
}

/** Set country code in WLAN Driver.
 *
 * \note This API should be called after WLAN is initialized
 * but before starting uAP interface.
 *
 * \note Either this function or wlan_enable_11d() should be used
 * at a time. If both functions are called in the application, then WLAN
 * Driver properties will be set as per the wlan_uap_set_country() function.
 *
 * \param[in] country Country code. Refer to \ref country_code_t.
 * \param[in] country3 The third octet of the Country String
 * This parameter is used to set the third octet of the country string.
 * All environments of the current frequency band and country (default)
 * country3=0x20
 * Outdoor environment only
 * country3=0x4f
 * Indoor environment only
 * country3=0x49
 * Noncountry entity (country_code=XX)
 * country3=0x58
 * IEEE 802.11 standard Annex E table indication: 0x01 .. 0x1f
 * Annex E, Table E-4 (Global operating classes)
 * country3=0x04
 *
 * \return -WM_FAIL if operation was failed.
 * \return WM_SUCCESS if operation was successful.
 */
static inline int wlan_uap_set_country(country_code_t country
#ifdef CONFIG_WPA_SUPP
#ifdef CONFIG_WPA_SUPP_AP
                                       ,
                                       unsigned char country3
#endif
#endif
)
{
#ifdef CONFIG_WPA_SUPP
#ifdef CONFIG_WPA_SUPP_AP
    struct netif *netif = net_get_uap_interface();

    char *country_str = wifi_get_country_str(country);
    int ret;

    if ((country3 != 0x4f) && (country3 != 0x49) && (country3 != 0x58) && (country3 != 0x04))
    {
        country3 = 0x20;
    }

    ret = freertos_supp_set_ap_country(netif, country_str, country3);

    if (ret != WM_SUCCESS)
    {
        return -WM_FAIL;
    }
#endif
#endif

    return wifi_uap_set_country(country);
}

/** Set country code in WLAN Driver.
 *
 * \note This API should be called after WLAN is initialized
 * but before making any connection attempts on station
 * interface.
 *
 * \note Either this function or wlan_enable_11d() should be used
 * at a time. If both functions are called in the application, then WLAN
 * Driver properties will be set as per the wlan_set_country() function.
 *
 * \param[in] country Country code. Refer to \ref country_code_t.
 *
 * \return -WM_FAIL if operation was failed.
 * \return WM_SUCCESS if operation was successful.
 */
static inline int wlan_set_country(country_code_t country)
{
    return wifi_set_country(country);
}

/**  wlan_11d_custom Custom Wi-Fi Region Configuration

   Ideally applications should use either wlan_enable_11d() or
   wlan_set_country() APIs to have standard 802.11d functionality as
   per regulations of Wi-Fi transmissions on certified frequency bands.

   But If application wants to configure custom 802.11d configurations
   then wlan_set_domain_params API can be used for that.

   If applications just want to set a particular region then
   wlan_set_region_code() API can be used for the purpose.

   Supported region code values are given in mlan_11d.c file.

   Sets the domain parameters for the uAP.

 @note This API should be called after WLAN is initialized
 but before starting uAP

   To use this API you will need to fill up the structure
   \ref wifi_domain_param_t with correct parameters.

   @note This API should be called after WLAN is initialized
   but before making any connection attempts on station interface.

   The below section lists all the arrays that can be passed individually
   or in combination to the API wlan_set_domain_params(). These are
   the sub band sets to be part of the Country Info IE in the uAP beacon.
   One of them is to be selected according to your region. Please have a look
   at the example given in the documentation below for reference.

   Supported Country Codes:
   "US" : USA,
   "CA" : Canada,
   "SG" : Singapore,
   "EU" : Europe,
   "AU" : Australia,
   "KR" : Republic of Korea,
   "CN" : China,
   "FR" : France,
   "JP" : Japan

\code

Region : US(US) or Canada(CA) or Singapore(SG) 2.4 GHz
wifi_sub_band_set_t subband_US_CA_SG_2_4_GHz[] = {
 {1, 11, 20}
};

Region: Europe(EU), Australia(AU), Republic of Korea(KR),
China(CN) 2.4 GHz
wifi_sub_band_set_t subband_EU_AU_KR_CN_2_4GHz[] = {
 {1, 13, 20}
};

Region: France(FR) 2.4 GHz
wifi_sub_band_set_t subband_FR_2_4GHz[] = {
 {1, 9, 20},
 {10, 4, 10}
};

Region: Japan(JP) 2.4 GHz
wifi_sub_band_set_t subband_JP_2_4GHz[] = {
 {1, 14, 20},
};

Region: Constrained 2.4 Ghz
wifi_sub_band_set_t subband_CS_2_4GHz[] = {
 {1, 9, 20},
 {10, 2, 10}
};

Region: US(US) or Singapore(SG) 5 GHz
wifi_sub_band_set_t subband_US_SG_5GHz[] = {
 {36, 1, 20},
 {40, 1, 20},
 {44, 1, 20},
 {48, 1, 20},
 {52, 1, 20},
 {56, 1, 20},
 {60, 1, 20},
 {64, 1, 20},
 {100, 1, 20},
 {104, 1, 20},
 {108, 1, 20},
 {112, 1, 20},
 {116, 1, 20},
 {120, 1, 20},
 {124, 1, 20},
 {128, 1, 20},
 {132, 1, 20},
 {136, 1, 20},
 {140, 1, 20},
 {149, 1, 20},
 {153, 1, 20},
 {157, 1, 20},
 {161, 1, 20},
 {165, 1, 20}
};

Region: Canada(CA) 5 GHz
wifi_sub_band_set_t subband_CA_5GHz[] = {
 {36, 1, 20},
 {40, 1, 20},
 {44, 1, 20},
 {48, 1, 20},
 {52, 1, 20},
 {56, 1, 20},
 {60, 1, 20},
 {64, 1, 20},
 {100, 1, 20},
 {104, 1, 20},
 {108, 1, 20},
 {112, 1, 20},
 {116, 1, 20},
 {132, 1, 20},
 {136, 1, 20},
 {140, 1, 20},
 {149, 1, 20},
 {153, 1, 20},
 {157, 1, 20},
 {161, 1, 20},
 {165, 1, 20}
};

Region: Europe/ETSI(EU), Australia(AU), Republic of Korea(KR) 5 GHz
wifi_sub_band_set_t subband_EU_AU_KR_5GHz[] = {
 {36, 1, 20},
 {40, 1, 20},
 {44, 1, 20},
 {48, 1, 20},
 {52, 1, 20},
 {56, 1, 20},
 {60, 1, 20},
 {64, 1, 20},
 {100, 1, 20},
 {104, 1, 20},
 {108, 1, 20},
 {112, 1, 20},
 {116, 1, 20},
 {120, 1, 20},
 {124, 1, 20},
 {128, 1, 20},
 {132, 1, 20},
 {136, 1, 20},
 {140, 1, 20}
};

Region: China(CN) 5 GHz
wifi_sub_band_set_t subband_CN_5GHz[] = {
 {149, 1, 33},
 {153, 1, 33},
 {157, 1, 33},
 {161, 1, 33},
 {165, 1, 33},
};

Region: France(FR) 5 GHz
wifi_sub_band_set_t subband_FR_5GHz[] = {
 {36, 1, 20},
 {40, 1, 20},
 {44, 1, 20},
 {48, 1, 20},
 {52, 1, 20},
 {56, 1, 20},
 {60, 1, 20},
 {64, 1, 20},
 {100, 1, 20},
 {104, 1, 20},
 {108, 1, 20},
 {112, 1, 20},
 {116, 1, 20},
 {120, 1, 20},
 {124, 1, 20},
 {128, 1, 20},
 {132, 1, 20},
 {136, 1, 20},
 {140, 1, 20},
 {149, 1, 20},
 {153, 1, 20},
 {157, 1, 20},
 {161, 1, 20},
 {165, 1, 20}
};

Region: Japan(JP) 5 GHz
wifi_sub_band_set_t subband_JP_5_GHz[] = {
 {8, 1, 23},
 {12, 1, 23},
 {16, 1, 23},
 {36, 1, 23},
 {40, 1, 23},
 {44, 1, 23},
 {48, 1, 23},
 {52, 1, 23},
 {56, 1, 23},
 {60, 1, 23},
 {64, 1, 23},
 {100, 1, 23},
 {104, 1, 23},
 {108, 1, 23},
 {112, 1, 23},
 {116, 1, 23},
 {120, 1, 23},
 {124, 1, 23},
 {128, 1, 23},
 {132, 1, 23},
 {136, 1, 23},
 {140, 1, 23}
};

\code
 // We will be using the KR 2.4 and 5 GHz bands for this example

 int nr_sb = (sizeof(subband_EU_AU_KR_CN_2_4GHz)
   + sizeof(subband_EU_AU_KR_5GHz))
   / sizeof(wifi_sub_band_set_t);

 // We already have space for first sub band info entry in
 // wifi_domain_param_t
 wifi_domain_param_t *dp = os_mem_alloc(sizeof(wifi_domain_param_t) +
   (sizeof(wifi_sub_band_set_t) * (nr_sb - 1)));

 // COUNTRY_CODE_LEN is 3. Add extra ' ' as country code is 2 characters
 (void)memcpy(dp->country_code, "KR ", COUNTRY_CODE_LEN);

 dp->no_of_sub_band = nr_sb;
 (void)memcpy(&dp->sub_band[0], &subband_EU_AU_KR_CN_2_4GHz[0],
   1 * sizeof(wifi_sub_band_set_t));
 (void)memcpy(&dp->sub_band[1], &subband_EU_AU_KR_5GHz,
   (nr_sb - 1) * sizeof(wifi_sub_band_set_t));

 wlan_set_domain_params(dp);
 os_mem_free(dp);
\endcode

\param[in] dp The wifi domain parameters

\return -WM_E_INVAL if invalid parameters were passed.
\return WM_SUCCESS if operation was successful.
*/
static inline int wlan_set_domain_params(wifi_domain_param_t *dp)
{
    return wifi_set_domain_params(dp);
}

/**
 Set 11D region code.

\param[in] region_code 11D region code to set.

\return -WM_FAIL if operation was failed.
\return WM_SUCCESS if operation was successful.
 */
static inline int wlan_set_region_code(uint32_t region_code)
{
    return wifi_set_region_code(region_code);
}

/**
 Get country string from country code

 This function converts country index to country string

\param[in] country Country index

\return Country string
 */
const uint8_t *wlan_11d_country_index_2_string(int country);

/** @} */

#endif /* __WLAN_11D_H__ */
