#Description: NXP Wi-Fi SDIO; user_visible: True
include_guard(GLOBAL)
message("middleware_wifi_sdio-2 component is included.")

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/wifidriver/mlan_sdio.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/incl/wifidriver
    ${CMAKE_CURRENT_LIST_DIR}/wifidriver
)


include(middleware_sdmmc_sdio)
