#Description: NXP Wi-Fi Ncp_Bridge_Supp WMCRYPTO; user_visible: True
include_guard(GLOBAL)
message("middleware_ncp_bridge_supp_wmcrypto component is included.")

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/wmcrypto/wmcrypto_mem.c
    ${CMAKE_CURRENT_LIST_DIR}/wmcrypto/wm_mbedtls_entropy.c
    ${CMAKE_CURRENT_LIST_DIR}/wmcrypto/wm_mbedtls_mem.c
    ${CMAKE_CURRENT_LIST_DIR}/wmcrypto/wm_mbedtls_net.c
    ${CMAKE_CURRENT_LIST_DIR}/wmcrypto/wm_mbedtls_helper_api.c
    ${CMAKE_CURRENT_LIST_DIR}/wmcrypto/wm_utils.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/incl/wmcrypto
    ${CMAKE_CURRENT_LIST_DIR}/wmcrypto
    ${CMAKE_CURRENT_LIST_DIR}/wmcrypto/aescrypto
    ${CMAKE_CURRENT_LIST_DIR}/wmcrypto/hkdf-sha512
)


