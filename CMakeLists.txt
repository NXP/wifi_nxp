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
zephyr_library_sources(cli/wifi_shell.c)

# macros for specific board
zephyr_library_compile_definitions(WIFI_BT_TX_PWR_LIMITS="wlan_txpwrlimit_cfg_WW_rw610.h")
