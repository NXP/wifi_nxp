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

file(GLOB SUPPLICANT_SRC ./wlcmgr/*.c)
zephyr_library_sources(${SUPPLICANT_SRC})

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
zephyr_library_compile_definitions(CONFIG_5GHz_SUPPORT)
zephyr_library_compile_definitions(CONFIG_WMM)
zephyr_library_compile_definitions(CONFIG_EXT_SCAN_SUPPORT)
zephyr_library_compile_definitions(WIFI_ADD_ON=1)
zephyr_library_compile_definitions(SCAN_CHANNEL_GAP=1)
zephyr_library_compile_definitions(CONFIG_ENABLE_ERROR_LOGS=1)
endif()
