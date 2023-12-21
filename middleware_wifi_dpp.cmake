#Description: NXP Wi-Fi DPP; user_visible: True
include_guard(GLOBAL)
message("middleware_wifi_dpp component is included.")

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/dpp
    ${CMAKE_CURRENT_LIST_DIR}/dpp/incl
    ${CMAKE_CURRENT_LIST_DIR}/incl/dpp
)


include(middleware_wifi_jsmn)
include(middleware_wifi_wmcrypto)
include(middleware_wifi_wmtime)
