#Description: NXP Wi-Fi driver; user_visible: False
include_guard(GLOBAL)
message("middleware_wifi_wifidriver component is included.")

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/wifidriver/mlan_11ac.c
    ${CMAKE_CURRENT_LIST_DIR}/wifidriver/mlan_11ax.c
    ${CMAKE_CURRENT_LIST_DIR}/wifidriver/mlan_11d.c
    ${CMAKE_CURRENT_LIST_DIR}/wifidriver/mlan_11h.c
    ${CMAKE_CURRENT_LIST_DIR}/wifidriver/mlan_11n.c
    ${CMAKE_CURRENT_LIST_DIR}/wifidriver/mlan_11n_aggr.c
    ${CMAKE_CURRENT_LIST_DIR}/wifidriver/mlan_11n_rxreorder.c
    ${CMAKE_CURRENT_LIST_DIR}/wifidriver/mlan_11v.c
    ${CMAKE_CURRENT_LIST_DIR}/wifidriver/mlan_action.c
    ${CMAKE_CURRENT_LIST_DIR}/wifidriver/mlan_11k.c
    ${CMAKE_CURRENT_LIST_DIR}/wifidriver/mlan_mbo.c
    ${CMAKE_CURRENT_LIST_DIR}/wifidriver/mlan_api.c
    ${CMAKE_CURRENT_LIST_DIR}/wifidriver/mlan_cfp.c
    ${CMAKE_CURRENT_LIST_DIR}/wifidriver/mlan_cmdevt.c
    ${CMAKE_CURRENT_LIST_DIR}/wifidriver/mlan_glue.c
    ${CMAKE_CURRENT_LIST_DIR}/wifidriver/mlan_init.c
    ${CMAKE_CURRENT_LIST_DIR}/wifidriver/mlan_join.c
    ${CMAKE_CURRENT_LIST_DIR}/wifidriver/mlan_misc.c
    ${CMAKE_CURRENT_LIST_DIR}/wifidriver/mlan_scan.c
    ${CMAKE_CURRENT_LIST_DIR}/wifidriver/mlan_shim.c
    ${CMAKE_CURRENT_LIST_DIR}/wifidriver/mlan_sta_cmd.c
    ${CMAKE_CURRENT_LIST_DIR}/wifidriver/mlan_sta_cmdresp.c
    ${CMAKE_CURRENT_LIST_DIR}/wifidriver/mlan_sta_event.c
    ${CMAKE_CURRENT_LIST_DIR}/wifidriver/mlan_sta_ioctl.c
    ${CMAKE_CURRENT_LIST_DIR}/wifidriver/mlan_sta_rx.c
    ${CMAKE_CURRENT_LIST_DIR}/wifidriver/mlan_txrx.c
    ${CMAKE_CURRENT_LIST_DIR}/wifidriver/mlan_uap_cmdevent.c
    ${CMAKE_CURRENT_LIST_DIR}/wifidriver/mlan_uap_ioctl.c
    ${CMAKE_CURRENT_LIST_DIR}/wifidriver/mlan_wmm.c
    ${CMAKE_CURRENT_LIST_DIR}/wifidriver/wifi-debug.c
    ${CMAKE_CURRENT_LIST_DIR}/wifidriver/wifi-mem.c
    ${CMAKE_CURRENT_LIST_DIR}/wifidriver/wifi-uap.c
    ${CMAKE_CURRENT_LIST_DIR}/wifidriver/wifi.c
    ${CMAKE_CURRENT_LIST_DIR}/wifidriver/wifi_pwrmgr.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/incl
    ${CMAKE_CURRENT_LIST_DIR}/incl/port/os
    ${CMAKE_CURRENT_LIST_DIR}/incl/wifidriver
    ${CMAKE_CURRENT_LIST_DIR}/incl/wlcmgr
    ${CMAKE_CURRENT_LIST_DIR}/wifi_bt_firmware
    ${CMAKE_CURRENT_LIST_DIR}/wifidriver
    ${CMAKE_CURRENT_LIST_DIR}/wifidriver/incl
)

if(${MCUX_DEVICE} STREQUAL "MIMXRT1166_cm7")
    include(middleware_wifi_fwdnld_MIMXRT1166_cm7)
endif()
if(${MCUX_DEVICE} STREQUAL "MIMXRT1052")
    include(middleware_wifi_fwdnld_MIMXRT1052)
endif()
if(${MCUX_DEVICE} STREQUAL "MIMXRT1064")
    include(middleware_wifi_fwdnld_MIMXRT1064)
endif()
if(${MCUX_DEVICE} STREQUAL "MIMXRT1021")
    include(middleware_wifi_fwdnld_MIMXRT1021)
endif()
if(${MCUX_DEVICE} STREQUAL "MIMXRT1062")
    include(middleware_wifi_fwdnld_MIMXRT1062)
endif()
if(${MCUX_DEVICE} STREQUAL "MIMXRT1042")
    include(middleware_wifi_fwdnld_MIMXRT1042)
endif()
if(${MCUX_DEVICE} STREQUAL "MIMXRT1176_cm7")
    include(middleware_wifi_fwdnld_MIMXRT1176_cm7)
endif()
if(${MCUX_DEVICE} STREQUAL "MIMXRT685S_cm33")
    include(middleware_wifi_fwdnld_MIMXRT685S_cm33)
endif()
if(${MCUX_DEVICE} STREQUAL "MIMXRT595S_cm33")
    include(middleware_wifi_fwdnld_MIMXRT595S_cm33)
endif()
if(${MCUX_DEVICE} STREQUAL "MIMXRT1166_cm4")
    include(middleware_wifi_fwdnld_MIMXRT1166_cm4)
endif()

include(middleware_wifi_fwdnld)
include(utility_debug_console)
include(middleware_wifi_sdio)
