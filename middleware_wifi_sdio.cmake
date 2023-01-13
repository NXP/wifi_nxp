#Description: NXP Wi-Fi SDIO; user_visible: False
include_guard(GLOBAL)
message("middleware_wifi_sdio component is included.")

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/wifidriver/wifi-sdio.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
)


include(middleware_wifi_sdio-2)
