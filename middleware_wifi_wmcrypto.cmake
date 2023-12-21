#Description: NXP Wi-Fi WMCRYPTO; user_visible: True
include_guard(GLOBAL)
message("middleware_wifi_wmcrypto component is included.")

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/wmcrypto/wmcrypto.c
    ${CMAKE_CURRENT_LIST_DIR}/wmcrypto/wmcrypto_mem.c
    ${CMAKE_CURRENT_LIST_DIR}/wmcrypto/wm_mbedtls_entropy.c
    ${CMAKE_CURRENT_LIST_DIR}/wmcrypto/wm_mbedtls_mem.c
    ${CMAKE_CURRENT_LIST_DIR}/wmcrypto/wm_mbedtls_net.c
    ${CMAKE_CURRENT_LIST_DIR}/wmcrypto/wm_mbedtls_helper_api.c
    ${CMAKE_CURRENT_LIST_DIR}/wmcrypto/wm_utils.c
    ${CMAKE_CURRENT_LIST_DIR}/wmcrypto/aescrypto/aes-siv.c
    ${CMAKE_CURRENT_LIST_DIR}/wmcrypto/aescrypto/aes-ctr.c
    ${CMAKE_CURRENT_LIST_DIR}/wmcrypto/aescrypto/aes-omac1.c
    ${CMAKE_CURRENT_LIST_DIR}/wmcrypto/aescrypto/aes-wrap.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/incl/wmcrypto
    ${CMAKE_CURRENT_LIST_DIR}/wmcrypto
    ${CMAKE_CURRENT_LIST_DIR}/wmcrypto/aescrypto
    ${CMAKE_CURRENT_LIST_DIR}/wmcrypto/hkdf-sha512
)


