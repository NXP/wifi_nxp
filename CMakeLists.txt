# SPDX-License-Identifier: Apache-2.0
# Copyright 2022 NXP

# define part number for this driver
zephyr_library_compile_definitions(RW610)

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

endif()

# HTTP Server
if(CONFIG_ENABLE_HTTPSERVER)
set(gen_dir ${ZEPHYR_BINARY_DIR}/include/generated/)
generate_inc_file_for_target(app response_big.html.bin   ${gen_dir}/response_big.html.bin.inc)
endif()

zephyr_code_relocate(FILES
                     port/os/os_zephyr.c
                     wifidriver/mlan_11n_rxreorder.c
                     wifidriver/mlan_wmm.c
                     wifidriver/wifi.c
                     wifidriver/wifi-imu.c
                     LOCATION RAM)
