# SPDX-License-Identifier: Apache-2.0
# Copyright 2022 NXP

# define part number for this driver
zephyr_library_compile_definitions(RW610)

# Network driver entry point
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

# include OS abstraction layer source
zephyr_library_sources(port/os/os_zephyr.c)

zephyr_library_include_directories(wifidriver wifidriver/incl)
zephyr_library_include_directories(wifi_bt_firmware)

zephyr_library_include_directories(incl)
zephyr_library_include_directories(incl/wifidriver)
zephyr_library_include_directories(incl/wlcmgr)
zephyr_library_include_directories(incl/port/os)
zephyr_library_include_directories(incl/port/zephyr)

# temporary shell source
zephyr_library_include_directories(cli)
zephyr_library_sources(cli/wifi_shell.c)
zephyr_library_sources(cli/cli_utils.c)

# macros for specific board
if(CONFIG_RW610)
zephyr_library_compile_definitions(WIFI_BT_TX_PWR_LIMITS="wlan_txpwrlimit_cfg_WW_rw610.h")
zephyr_library_compile_definitions(CONFIG_COMPRESS_TX_PWTBL)
zephyr_library_compile_definitions(CONFIG_WIFI_MAX_PRIO=1)
zephyr_library_compile_definitions(CONFIG_IPS)
zephyr_library_compile_definitions(CONFIG_EXT_SCAN_SUPPORT)
# zephyr_library_compile_definitions(CONFIG_WIFI_USB_FILE_ACCESS=1)
zephyr_library_compile_definitions(SCAN_CHANNEL_GAP=1)
zephyr_library_compile_definitions(CONFIG_SCAN_WITH_RSSIFILTER)
zephyr_library_compile_definitions(CONFIG_WIFI_DTIM_PERIOD)
zephyr_library_compile_definitions(CONFIG_EXT_SCAN_SUPPORT)
zephyr_library_compile_definitions(CONFIG_RX_ABORT_CFG)
zephyr_library_compile_definitions(CONFIG_CCK_DESENSE_CFG)
zephyr_library_compile_definitions(CONFIG_WIFI_MEM_ACCESS)
zephyr_library_compile_definitions(CONFIG_WIFI_REG_ACCESS)
zephyr_library_compile_definitions(CONFIG_SUBSCRIBE_EVENT_SUPPORT)
zephyr_library_compile_definitions(CONFIG_EVENT_MEM_ACCESS)
zephyr_library_compile_definitions(CONFIG_TX_RX_HISTOGRAM)
zephyr_library_compile_definitions(CONFIG_COEX_DUTY_CYCLE)
zephyr_library_compile_definitions(CONFIG_WIFI_EU_CRYPTO)
zephyr_library_compile_definitions(CONFIG_WIFI_EU_VALIDATION)
zephyr_library_compile_definitions(CONFIG_MMSF)
zephyr_library_compile_definitions(RX_CHAN_INFO)
zephyr_library_compile_definitions(TXPD_RXPD_V3)
endif()

# macros for wpa_supplicant
if(CONFIG_WPA_SUPP)
zephyr_include_directories(
    wifidriver/incl
    incl
    incl/wifidriver
    incl/wlcmgr
    incl/port/os
    incl/port/zephyr
    certs
)

zephyr_library_include_directories(wifidriver/wpa_supp_if wifidriver/wpa_supp_if/incl)
file(GLOB WIFI_SUPP_SRC ./wifidriver/wpa_supp_if/*.c)
zephyr_library_sources(${WIFI_SUPP_SRC})

# macros for wpa_supplicant
#zephyr_library_compile_definitions(CONFIG_WPA_SUPP_WPS=1)
#zephyr_library_compile_definitions(CONFIG_WPA_SUPP_AP=1)

endif()

# HTTP Server
if(CONFIG_ENABLE_HTTPSERVER)
set(gen_dir ${ZEPHYR_BINARY_DIR}/include/generated/)
generate_inc_file_for_target(app response_big.html.bin   ${gen_dir}/response_big.html.bin.inc)
endif()

zephyr_code_relocate(FILES
                     # fsl_cache.c
                     # ${ZEPHYR_BASE}/modules/hal_nxp/fsl_memcpy.S
                     ${ZEPHYR_BASE}/modules/hal_nxp/fsl_os_abstraction_zephyr.c
                     ${ZEPHYR_BASE}/modules/hal_nxp/imu/fsl_adapter_rfimu.c
                     ${ZEPHYR_BASE}/modules/hal_nxp/imu/fsl_imu.c
                     port/os/os_zephyr.c
                     port/zephyr/net.c
                     wifidriver/mlan_11n_rxreorder.c
                     wifidriver/mlan_wmm.c
                     wifidriver/wifi.c
                     wifidriver/wifi-imu.c
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
