#Description: NXP Wi-Fi WMTIME; user_visible: True
include_guard(GLOBAL)
message("middleware_wifi_wmtime component is included.")

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/wmtime/wmtime.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/wmtime
)


