#Description: NXP Wi-Fi; user_visible: True
include_guard(GLOBAL)
message("middleware_wifi component is included.")

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/dhcpd/dhcp-server-main.c
    ${CMAKE_CURRENT_LIST_DIR}/dhcpd/dhcp-server.c
    ${CMAKE_CURRENT_LIST_DIR}/dhcpd/dns-server.c
    ${CMAKE_CURRENT_LIST_DIR}/port/lwip/net.c
    ${CMAKE_CURRENT_LIST_DIR}/port/lwip/wifi_netif.c
    ${CMAKE_CURRENT_LIST_DIR}/wlcmgr/wlan.c
    ${CMAKE_CURRENT_LIST_DIR}/wlcmgr/wlan_txpwrlimit_cfg.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/dhcpd
    ${CMAKE_CURRENT_LIST_DIR}/incl
    ${CMAKE_CURRENT_LIST_DIR}/incl/port/lwip
    ${CMAKE_CURRENT_LIST_DIR}/port/lwip
)


include(middleware_lwip)
include(middleware_wifi_wifidriver)
