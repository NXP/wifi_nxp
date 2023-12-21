#Description: NXP Wi-Fi WPS; user_visible: True
include_guard(GLOBAL)
message("middleware_wifi_wps component is included.")

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/wps/wps_eapol.c
    ${CMAKE_CURRENT_LIST_DIR}/wps/wps_l2.c
    ${CMAKE_CURRENT_LIST_DIR}/wps/wps_main.c
    ${CMAKE_CURRENT_LIST_DIR}/wps/wps_mem.c
    ${CMAKE_CURRENT_LIST_DIR}/wps/wps_msg.c
    ${CMAKE_CURRENT_LIST_DIR}/wps/wps_os.c
    ${CMAKE_CURRENT_LIST_DIR}/wps/wps_start.c
    ${CMAKE_CURRENT_LIST_DIR}/wps/wps_state.c
    ${CMAKE_CURRENT_LIST_DIR}/wps/wps_wlan.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/incl/wps
    ${CMAKE_CURRENT_LIST_DIR}/wps
)


include(middleware_wifi_dpp)
include(middleware_wifi_RW612)
