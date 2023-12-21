#Description: NXP Wi-Fi IMU; user_visible: False
include_guard(GLOBAL)
message("middleware_wifi_imu component is included.")

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/wifidriver/wifi-imu.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/wifidriver
)


include(component_wireless_imu_adapter)
include(component_osa_free_rtos_RW612)
