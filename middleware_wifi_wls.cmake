#Description: NXP Wi-Fi WLS; user_visible: True
include_guard(GLOBAL)
message("middleware_wifi_wls component is included.")

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/wls/range_kalman.c
    ${CMAKE_CURRENT_LIST_DIR}/wls/wls_api.c
    ${CMAKE_CURRENT_LIST_DIR}/wls/wls_processing.c
    ${CMAKE_CURRENT_LIST_DIR}/wls/wls_QR_algorithm.c
    ${CMAKE_CURRENT_LIST_DIR}/wls/wls_radix4Fft.c
    ${CMAKE_CURRENT_LIST_DIR}/wls/wls_subspace_processing.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/wls
)


include(middleware_wifi_RW612)
