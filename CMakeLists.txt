# SPDX-License-Identifier: Apache-2.0
# Copyright 2022 NXP

# define part number for this driver
zephyr_compile_definitions_ifdef(CONFIG_SD8987
    SD8987
    WIFI_BT_TX_PWR_LIMITS="wlan_txpwrlimit_cfg_WW.h"
)

zephyr_compile_definitions_ifdef(CONFIG_SD8978
    SD8978
    WIFI_BT_TX_PWR_LIMITS="wlan_txpwrlimit_cfg_WW.h"
)

zephyr_compile_definitions_ifdef(CONFIG_IW61x
    IW61x
    WIFI_BT_TX_PWR_LIMITS="wlan_txpwrlimit_cfg_WW.h"
)

zephyr_compile_definitions_ifdef(CONFIG_RW610
    RW610
    WIFI_BT_TX_PWR_LIMITS="wlan_txpwrlimit_cfg_WW_rw610.h"
)

zephyr_include_directories(
    incl
    incl/wifidriver
    incl/wlcmgr
    incl/port/os
    incl/port/zephyr
    wifidriver
    wifidriver/incl
    wifi_bt_firmware
    cli
)

# OS abstraction layer source
zephyr_library_sources(port/os/os_zephyr.c)
# net stack abstraction layer source
zephyr_library_sources(port/zephyr/net.c)

file(GLOB WIFI_SRC ./wifidriver/*.c)
list(FILTER WIFI_SRC EXCLUDE REGEX ".*sdio.c$")
list(FILTER WIFI_SRC EXCLUDE REGEX ".*firmware_dnld.c$")

zephyr_library_sources(${WIFI_SRC})

file(GLOB WLCMGR_SRC ./wlcmgr/*.c)
zephyr_library_sources(${WLCMGR_SRC})

file(GLOB DHCPD_SRC ./dhcpd/*.c)
zephyr_library_sources(${DHCPD_SRC})
zephyr_library_include_directories(dhcpd)

# temporary shell source
zephyr_library_sources(cli/wifi_shell.c)
zephyr_library_sources(cli/cli_utils.c)

# macros for wpa_supplicant
if(CONFIG_WPA_SUPP)
zephyr_include_directories(certs)

zephyr_library_include_directories(wifidriver/wpa_supp_if wifidriver/wpa_supp_if/incl)
file(GLOB WIFI_SUPP_SRC ./wifidriver/wpa_supp_if/*.c)
zephyr_library_sources(${WIFI_SUPP_SRC})
endif()

# HTTP Server
if(CONFIG_ENABLE_HTTPSERVER)
set(gen_dir ${ZEPHYR_BINARY_DIR}/include/generated/)
generate_inc_file_for_target(app response_big.html.bin   ${gen_dir}/response_big.html.bin.inc)
endif()

# critical path code relocated to SRAM
zephyr_code_relocate(FILES
                     port/os/os_zephyr.c
                     port/zephyr/net.c
                     wifidriver/mlan_11n_rxreorder.c
                     wifidriver/mlan_wmm.c
                     wifidriver/wifi.c
                     wifidriver/wifi-imu.c
                     LOCATION RAM)

zephyr_code_relocate(FILES
                     # fsl_cache.c
                     # ${ZEPHYR_BASE}/modules/hal_nxp/fsl_memcpy.S
                     ${ZEPHYR_BASE}/modules/hal_nxp/fsl_os_abstraction_zephyr.c
                     ${ZEPHYR_HAL_NXP_MODULE_DIR}/mcux/mcux-sdk/drivers/imu/fsl_imu.c
                     ${ZEPHYR_HAL_NXP_MODULE_DIR}/mcux/components/rpmsg/fsl_adapter_rfimu.c
                     LOCATION RAM)

file(GLOB ZPERF_SRC ${ZEPHYR_BASE}/subsys/net/lib/zperf/*.c)
zephyr_code_relocate(FILES ${ZPERF_SRC} LOCATION RAM)

file(GLOB SOCKET_SRC ${ZEPHYR_BASE}/subsys/net/lib/sockets/*.c)
zephyr_code_relocate(FILES ${SOCKET_SRC} LOCATION RAM)

file(GLOB NET_SRC ${ZEPHYR_BASE}/subsys/net/ip/*.c)
zephyr_code_relocate(FILES ${NET_SRC} LOCATION RAM)

file(GLOB ETH_SRC ${ZEPHYR_BASE}/subsys/net/l2/ethernet/*.c)
zephyr_code_relocate(FILES ${ETH_SRC} LOCATION RAM)

zephyr_code_relocate(FILES ${ZEPHYR_BASE}/subsys/net/buf.c LOCATION RAM)

zephyr_code_relocate(FILES
                     ${ZEPHYR_BASE}/kernel/mem_slab.c
                     ${ZEPHYR_BASE}/kernel/mempool.c
                     ${ZEPHYR_BASE}/kernel/msg_q.c
                     ${ZEPHYR_BASE}/kernel/mutex.c
                     ${ZEPHYR_BASE}/kernel/queue.c
                     ${ZEPHYR_BASE}/kernel/sched.c
                     ${ZEPHYR_BASE}/kernel/sem.c
                     ${ZEPHYR_BASE}/kernel/thread.c
                     ${ZEPHYR_BASE}/kernel/work.c
                     LOCATION RAM)
