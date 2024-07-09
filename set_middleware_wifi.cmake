include_guard(GLOBAL)


if (CONFIG_USE_middleware_wifi_wifi_bt_config_template)
# Add set(CONFIG_USE_middleware_wifi_wifi_bt_config_template true) in config.cmake to use this component

message("middleware_wifi_wifi_bt_config_template component is included from ${CMAKE_CURRENT_LIST_FILE}.")

add_config_file(${CMAKE_CURRENT_LIST_DIR}/../../core/components/wifi_bt_module/template/wifi_bt_config.h ${CMAKE_CURRENT_LIST_DIR}/../../core/components/wifi_bt_module/template/. middleware_wifi_wifi_bt_config_template)
add_config_file(${CMAKE_CURRENT_LIST_DIR}/../../core/components/wifi_bt_module/template/wifi_bt_config.c "" middleware_wifi_wifi_bt_config_template)

if(CONFIG_USE_COMPONENT_CONFIGURATION)
  message("===>Import configuration from ${CMAKE_CURRENT_LIST_FILE}")

  target_compile_definitions(${MCUX_SDK_PROJECT_NAME} PUBLIC
    -DSDIO_ENABLED
  )

endif()


endif()


if (CONFIG_USE_middleware_wifi_fwdnld_intf_abs)
# Add set(CONFIG_USE_middleware_wifi_fwdnld_intf_abs true) in config.cmake to use this component

message("middleware_wifi_fwdnld_intf_abs component is included from ${CMAKE_CURRENT_LIST_FILE}.")

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/./fwdnld_intf_abs/fwdnld_intf_abs.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}/./fwdnld_intf_abs
)


endif()


if (CONFIG_USE_middleware_wireless_coex)
# Add set(CONFIG_USE_middleware_wireless_coex true) in config.cmake to use this component

message("middleware_wireless_coex component is included from ${CMAKE_CURRENT_LIST_FILE}.")

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/../wireless/coex/boards/rw612/app_services_init.c
  ${CMAKE_CURRENT_LIST_DIR}/../wireless/coex/boards/rw612/board.c
  ${CMAKE_CURRENT_LIST_DIR}/../wireless/coex/boards/rw612/clock_config.c
  ${CMAKE_CURRENT_LIST_DIR}/../wireless/coex/boards/rw612/hardware_init.c
  ${CMAKE_CURRENT_LIST_DIR}/../wireless/coex/boards/rw612/peripherals.c
  ${CMAKE_CURRENT_LIST_DIR}/../wireless/coex/boards/rw612/pin_mux.c
  ${CMAKE_CURRENT_LIST_DIR}/../wireless/coex/examples/coex_app/main.c
  ${CMAKE_CURRENT_LIST_DIR}/../wireless/coex/src/common/controller_coex_nxp.c
  ${CMAKE_CURRENT_LIST_DIR}/../wireless/coex/src/common/host_msd_fatfs.c
  ${CMAKE_CURRENT_LIST_DIR}/../wireless/coex/src/edgefast/coex_shell.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}/../wireless/coex/.
  ${CMAKE_CURRENT_LIST_DIR}/../wireless/coex/boards/rw612
  ${CMAKE_CURRENT_LIST_DIR}/../wireless/coex/cmake
  ${CMAKE_CURRENT_LIST_DIR}/../wireless/coex/cmake/platform/rw612
  ${CMAKE_CURRENT_LIST_DIR}/../wireless/coex/cmake/toolchain
  ${CMAKE_CURRENT_LIST_DIR}/../wireless/coex/examples
  ${CMAKE_CURRENT_LIST_DIR}/../wireless/coex/examples/coex_app
  ${CMAKE_CURRENT_LIST_DIR}/../wireless/coex/examples/linker
  ${CMAKE_CURRENT_LIST_DIR}/../wireless/coex/script
  ${CMAKE_CURRENT_LIST_DIR}/../wireless/coex/src
  ${CMAKE_CURRENT_LIST_DIR}/../wireless/coex/src/common
  ${CMAKE_CURRENT_LIST_DIR}/../wireless/coex/src/configs
  ${CMAKE_CURRENT_LIST_DIR}/../wireless/coex/src/configs/ble
  ${CMAKE_CURRENT_LIST_DIR}/../wireless/coex/src/configs/lwip
  ${CMAKE_CURRENT_LIST_DIR}/../wireless/coex/src/configs/mbedtls
  ${CMAKE_CURRENT_LIST_DIR}/../wireless/coex/src/configs/platform
  ${CMAKE_CURRENT_LIST_DIR}/../wireless/coex/src/configs/wifi
  ${CMAKE_CURRENT_LIST_DIR}/../wireless/coex/src/edgefast
  ${CMAKE_CURRENT_LIST_DIR}/../wireless/coex/third_party
  ${CMAKE_CURRENT_LIST_DIR}/../wireless/coex/third_party/mcu-sdk
)


endif()


if (CONFIG_USE_middleware_wifi_template)
# Add set(CONFIG_USE_middleware_wifi_template true) in config.cmake to use this component

message("middleware_wifi_template component is included from ${CMAKE_CURRENT_LIST_FILE}.")

if((CONFIG_USE_component_wifi_bt_module_tx_pwr_limits AND CONFIG_USE_driver_imu) OR (CONFIG_USE_component_wifi_bt_module_tx_pwr_limits AND CONFIG_USE_component_wifi_bt_module_config AND CONFIG_USE_middleware_wifi_wifi_bt_config_template AND (NOT CONFIG_USE_driver_imu)))

add_config_file(${CMAKE_CURRENT_LIST_DIR}/../../core/components/wifi_bt_module/template/app_config.h ${CMAKE_CURRENT_LIST_DIR}/../../core/components/wifi_bt_module/template/. middleware_wifi_template)
add_config_file(${CMAKE_CURRENT_LIST_DIR}/../../core/components/wifi_bt_module/template/wifi_config.h ${CMAKE_CURRENT_LIST_DIR}/../../core/components/wifi_bt_module/template/. middleware_wifi_template)

if(CONFIG_USE_COMPONENT_CONFIGURATION)
  message("===>Import configuration from ${CMAKE_CURRENT_LIST_FILE}")

  target_compile_definitions(${MCUX_SDK_PROJECT_NAME} PUBLIC
    -DOSA_USED
    -DFSL_OSA_TASK_ENABLE=1
    -DLWIP_DNS=1
    -DLWIP_NETIF_HOSTNAME=1
    -DLWIP_IGMP=1
    -D_XOPEN_SOURCE=500
  )

endif()

else()

message(SEND_ERROR "middleware_wifi_template dependency does not meet, please check ${CMAKE_CURRENT_LIST_FILE}.")

endif()

endif()


if (CONFIG_USE_middleware_wifi_osa_free_rtos)
# Add set(CONFIG_USE_middleware_wifi_osa_free_rtos true) in config.cmake to use this component

message("middleware_wifi_osa_free_rtos component is included from ${CMAKE_CURRENT_LIST_FILE}.")

if(CONFIG_USE_component_osa_free_rtos)

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/./port/osa/osa_freertos.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}/./.
  ${CMAKE_CURRENT_LIST_DIR}/./incl
  ${CMAKE_CURRENT_LIST_DIR}/./incl/port/osa
  ${CMAKE_CURRENT_LIST_DIR}/./port/osa
)

else()

message(SEND_ERROR "middleware_wifi_osa_free_rtos dependency does not meet, please check ${CMAKE_CURRENT_LIST_FILE}.")

endif()

endif()


if (CONFIG_USE_middleware_wifi_osa_thread)
# Add set(CONFIG_USE_middleware_wifi_osa_thread true) in config.cmake to use this component

message("middleware_wifi_osa_thread component is included from ${CMAKE_CURRENT_LIST_FILE}.")

if(CONFIG_USE_component_osa_thread)

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/./port/osa/osa_threadx.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}/./.
  ${CMAKE_CURRENT_LIST_DIR}/./incl/port/osa
  ${CMAKE_CURRENT_LIST_DIR}/./port/osa
)

else()

message(SEND_ERROR "middleware_wifi_osa_thread dependency does not meet, please check ${CMAKE_CURRENT_LIST_FILE}.")

endif()

endif()


if (CONFIG_USE_middleware_wifi_osa)
# Add set(CONFIG_USE_middleware_wifi_osa true) in config.cmake to use this component

message("middleware_wifi_osa component is included from ${CMAKE_CURRENT_LIST_FILE}.")

if((CONFIG_USE_middleware_wifi_osa_free_rtos OR CONFIG_USE_middleware_wifi_osa_thread))

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/./port/osa/osa.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/osa/mem_pool.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/osa/mem_pool_config.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/osa/slist.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/osa/stack_simple.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}/./.
  ${CMAKE_CURRENT_LIST_DIR}/./incl/port/osa
)

else()

message(SEND_ERROR "middleware_wifi_osa dependency does not meet, please check ${CMAKE_CURRENT_LIST_FILE}.")

endif()

endif()


if (CONFIG_USE_middleware_wifi_common_files)
# Add set(CONFIG_USE_middleware_wifi_common_files true) in config.cmake to use this component

message("middleware_wifi_common_files component is included from ${CMAKE_CURRENT_LIST_FILE}.")

if(CONFIG_USE_middleware_wifi_osa)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}/./incl
  ${CMAKE_CURRENT_LIST_DIR}/./incl/port/osa
  ${CMAKE_CURRENT_LIST_DIR}/./incl/wifidriver
  ${CMAKE_CURRENT_LIST_DIR}/./wifi_bt_firmware
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver/incl
)

else()

message(SEND_ERROR "middleware_wifi_common_files dependency does not meet, please check ${CMAKE_CURRENT_LIST_FILE}.")

endif()

endif()


if (CONFIG_USE_middleware_wifi_fwdnld)
# Add set(CONFIG_USE_middleware_wifi_fwdnld true) in config.cmake to use this component

message("middleware_wifi_fwdnld component is included from ${CMAKE_CURRENT_LIST_FILE}.")

if(CONFIG_USE_middleware_wifi_template AND CONFIG_USE_middleware_wifi_mlan_sdio AND CONFIG_USE_middleware_wifi_common_files AND CONFIG_USE_middleware_wifi_fwdnld_intf_abs)

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/./wifi_bt_firmware/8801/8801_cpu1.c
  ${CMAKE_CURRENT_LIST_DIR}/./wifi_bt_firmware/IW416/IW416_cpu12.c
  ${CMAKE_CURRENT_LIST_DIR}/./wifi_bt_firmware/IW416/IW416_cpu1.c
  ${CMAKE_CURRENT_LIST_DIR}/./wifi_bt_firmware/IW416/IW416_cpu2.c
  ${CMAKE_CURRENT_LIST_DIR}/./wifi_bt_firmware/8987/8987_cpu12.c
  ${CMAKE_CURRENT_LIST_DIR}/./wifi_bt_firmware/8987/8987_cpu1.c
  ${CMAKE_CURRENT_LIST_DIR}/./wifi_bt_firmware/8987/8987_cpu2.c
  ${CMAKE_CURRENT_LIST_DIR}/./wifi_bt_firmware/nw61x/nw61x_cpu12_se.c
  ${CMAKE_CURRENT_LIST_DIR}/./wifi_bt_firmware/nw61x/nw61x_cpu1_se.c
  ${CMAKE_CURRENT_LIST_DIR}/./wifi_bt_firmware/nw61x/nw61x_cpu2_se.c
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver/sdio.c
  ${CMAKE_CURRENT_LIST_DIR}/./firmware_dnld/firmware_dnld.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}/./incl
  ${CMAKE_CURRENT_LIST_DIR}/./wifi_bt_firmware
  ${CMAKE_CURRENT_LIST_DIR}/./wifi_bt_firmware/8801
  ${CMAKE_CURRENT_LIST_DIR}/./wifi_bt_firmware/IW416
  ${CMAKE_CURRENT_LIST_DIR}/./wifi_bt_firmware/8987
  ${CMAKE_CURRENT_LIST_DIR}/./wifi_bt_firmware/nw61x
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver/incl
  ${CMAKE_CURRENT_LIST_DIR}/./firmware_dnld
  ${CMAKE_CURRENT_LIST_DIR}/./sdio_nxp_abs
  ${CMAKE_CURRENT_LIST_DIR}/./sdio_nxp_abs/incl
  ${CMAKE_CURRENT_LIST_DIR}/./fwdnld_intf_abs
)

else()

message(SEND_ERROR "middleware_wifi_fwdnld dependency does not meet, please check ${CMAKE_CURRENT_LIST_FILE}.")

endif()

endif()


if (CONFIG_USE_middleware_wifi_net_free_rtos)
# Add set(CONFIG_USE_middleware_wifi_net_free_rtos true) in config.cmake to use this component

message("middleware_wifi_net_free_rtos component is included from ${CMAKE_CURRENT_LIST_FILE}.")

if(CONFIG_USE_component_osa_free_rtos AND CONFIG_USE_middleware_lwip AND CONFIG_USE_middleware_lwip_apps_lwiperf)

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/./port/net/net.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/net/wifi_netif.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/net/hooks/lwip_default_hooks.c
  ${CMAKE_CURRENT_LIST_DIR}/./dhcpd/dhcp-server-main.c
  ${CMAKE_CURRENT_LIST_DIR}/./dhcpd/dhcp-server.c
  ${CMAKE_CURRENT_LIST_DIR}/./dhcpd/dns-server.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}/./.
  ${CMAKE_CURRENT_LIST_DIR}/./incl
  ${CMAKE_CURRENT_LIST_DIR}/./incl/port/osa
  ${CMAKE_CURRENT_LIST_DIR}/./port/osa
  ${CMAKE_CURRENT_LIST_DIR}/./incl/port/net
  ${CMAKE_CURRENT_LIST_DIR}/./incl/port/net/hooks
  ${CMAKE_CURRENT_LIST_DIR}/./dhcpd
  ${CMAKE_CURRENT_LIST_DIR}/./incl/wlcmgr
  ${CMAKE_CURRENT_LIST_DIR}/./incl/wifidriver
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver/incl
)

else()

message(SEND_ERROR "middleware_wifi_net_free_rtos dependency does not meet, please check ${CMAKE_CURRENT_LIST_FILE}.")

endif()

endif()


if (CONFIG_USE_middleware_wifi_net_thread)
# Add set(CONFIG_USE_middleware_wifi_net_thread true) in config.cmake to use this component

message("middleware_wifi_net_thread component is included from ${CMAKE_CURRENT_LIST_FILE}.")

if(CONFIG_USE_component_osa_thread)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}/./.
  ${CMAKE_CURRENT_LIST_DIR}/./incl/port/osa
  ${CMAKE_CURRENT_LIST_DIR}/./port/osa
  ${CMAKE_CURRENT_LIST_DIR}/./incl/port/net
  ${CMAKE_CURRENT_LIST_DIR}/./port/net/netxduo
)

else()

message(SEND_ERROR "middleware_wifi_net_thread dependency does not meet, please check ${CMAKE_CURRENT_LIST_FILE}.")

endif()

endif()


if (CONFIG_USE_middleware_wifi_net)
# Add set(CONFIG_USE_middleware_wifi_net true) in config.cmake to use this component

message("middleware_wifi_net component is included from ${CMAKE_CURRENT_LIST_FILE}.")

if((CONFIG_USE_middleware_wifi_net_free_rtos OR CONFIG_USE_middleware_wifi_net_thread))

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}/./.
  ${CMAKE_CURRENT_LIST_DIR}/./incl/port/osa
)

else()

message(SEND_ERROR "middleware_wifi_net dependency does not meet, please check ${CMAKE_CURRENT_LIST_FILE}.")

endif()

endif()


if (CONFIG_USE_middleware_wifi_wifidriver)
# Add set(CONFIG_USE_middleware_wifi_wifidriver true) in config.cmake to use this component

message("middleware_wifi_wifidriver component is included from ${CMAKE_CURRENT_LIST_FILE}.")

if(((CONFIG_USE_utility_debug_console AND (NOT CONFIG_USE_utility_debug_console_lite)) OR (CONFIG_USE_utility_debug_console_lite AND (NOT CONFIG_USE_utility_debug_console))) AND CONFIG_USE_middleware_wifi_template AND CONFIG_USE_middleware_wifi_osa AND CONFIG_USE_middleware_wifi_net AND ((CONFIG_USE_middleware_wifi_sdio AND CONFIG_USE_middleware_wifi_fwdnld AND CONFIG_USE_middleware_wifi_fwdnld_intf_abs) OR (CONFIG_USE_middleware_wifi_imu AND CONFIG_USE_middleware_wifi_common_files)))

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver/mlan_11ac.c
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver/mlan_11ax.c
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver/mlan_11d.c
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver/mlan_11h.c
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver/mlan_11n.c
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver/mlan_11n_aggr.c
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver/mlan_11n_rxreorder.c
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver/mlan_11v.c
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver/mlan_action.c
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver/mlan_11k.c
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver/mlan_mbo.c
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver/mlan_api.c
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver/mlan_cfp.c
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver/mlan_cmdevt.c
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver/mlan_glue.c
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver/mlan_init.c
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver/mlan_join.c
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver/mlan_misc.c
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver/mlan_scan.c
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver/mlan_shim.c
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver/mlan_sta_cmd.c
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver/mlan_sta_cmdresp.c
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver/mlan_sta_event.c
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver/mlan_sta_ioctl.c
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver/mlan_sta_rx.c
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver/mlan_txrx.c
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver/mlan_uap_cmdevent.c
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver/mlan_uap_ioctl.c
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver/mlan_wmm.c
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver/wifi-debug.c
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver/wifi-mem.c
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver/wifi-uap.c
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver/wifi.c
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver/wifi_pwrmgr.c
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver/wpa_supp_if/wifi_nxp.c
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver/wpa_supp_if/rtos_wpa_supp_if.c
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver/wpa_supp_if/wifi_nxp_internal.c
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver/wifi-wps.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}/./incl
  ${CMAKE_CURRENT_LIST_DIR}/./incl/wlcmgr
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver/incl
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver/wpa_supp_if
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver/wpa_supp_if/incl
  ${CMAKE_CURRENT_LIST_DIR}/./certs
  ${CMAKE_CURRENT_LIST_DIR}/./firmware_dnld
  ${CMAKE_CURRENT_LIST_DIR}/./sdio_nxp_abs
  ${CMAKE_CURRENT_LIST_DIR}/./sdio_nxp_abs/incl
)

else()

message(SEND_ERROR "middleware_wifi_wifidriver dependency does not meet, please check ${CMAKE_CURRENT_LIST_FILE}.")

endif()

endif()


if (CONFIG_USE_middleware_wifi)
# Add set(CONFIG_USE_middleware_wifi true) in config.cmake to use this component

message("middleware_wifi component is included from ${CMAKE_CURRENT_LIST_FILE}.")

if(((CONFIG_USE_utility_debug_console AND (NOT CONFIG_USE_utility_debug_console_lite)) OR (CONFIG_USE_utility_debug_console_lite AND (NOT CONFIG_USE_utility_debug_console))) AND CONFIG_USE_middleware_wifi_template AND CONFIG_USE_middleware_wifi_wifidriver)

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/./dhcpd/dhcp-server-main.c
  ${CMAKE_CURRENT_LIST_DIR}/./dhcpd/dhcp-server.c
  ${CMAKE_CURRENT_LIST_DIR}/./dhcpd/dns-server.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/net/net.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/net/wifi_netif.c
  ${CMAKE_CURRENT_LIST_DIR}/./wlcmgr/wlan.c
  ${CMAKE_CURRENT_LIST_DIR}/./wlcmgr/wlan_txpwrlimit_cfg.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}/./incl
  ${CMAKE_CURRENT_LIST_DIR}/./incl/wifidriver
  ${CMAKE_CURRENT_LIST_DIR}/./incl/port/net
  ${CMAKE_CURRENT_LIST_DIR}/./port/net
  ${CMAKE_CURRENT_LIST_DIR}/./incl/port/net/hooks
)

else()

message(SEND_ERROR "middleware_wifi dependency does not meet, please check ${CMAKE_CURRENT_LIST_FILE}.")

endif()

endif()


if (CONFIG_USE_middleware_wifi_sdio)
# Add set(CONFIG_USE_middleware_wifi_sdio true) in config.cmake to use this component

message("middleware_wifi_sdio component is included from ${CMAKE_CURRENT_LIST_FILE}.")

if(CONFIG_USE_middleware_wifi_mlan_sdio AND CONFIG_USE_middleware_wifi_wifidriver)

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver/wifi-sdio.c
)

else()

message(SEND_ERROR "middleware_wifi_sdio dependency does not meet, please check ${CMAKE_CURRENT_LIST_FILE}.")

endif()

endif()


if (CONFIG_USE_middleware_wifi_mlan_sdio)
# Add set(CONFIG_USE_middleware_wifi_mlan_sdio true) in config.cmake to use this component

message("middleware_wifi_mlan_sdio component is included from ${CMAKE_CURRENT_LIST_FILE}.")

if(CONFIG_USE_middleware_wifi_template AND CONFIG_USE_middleware_sdmmc_sdio AND CONFIG_USE_middleware_sdmmc_host_usdhc AND CONFIG_USE_middleware_wifi_common_files AND ((CONFIG_USE_middleware_sdmmc_host_usdhc_freertos) OR (CONFIG_USE_middleware_sdmmc_host_usdhc_azurertos)))

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/./sdio_nxp_abs/mlan_sdio.c
  ${CMAKE_CURRENT_LIST_DIR}/./sdio_nxp_abs/fwdnld_sdio.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver
  ${CMAKE_CURRENT_LIST_DIR}/./sdio_nxp_abs/incl
)

else()

message(SEND_ERROR "middleware_wifi_mlan_sdio dependency does not meet, please check ${CMAKE_CURRENT_LIST_FILE}.")

endif()

endif()


if (CONFIG_USE_middleware_wifi_imu)
# Add set(CONFIG_USE_middleware_wifi_imu true) in config.cmake to use this component

message("middleware_wifi_imu component is included from ${CMAKE_CURRENT_LIST_FILE}.")

if(CONFIG_USE_middleware_wifi_common_files AND CONFIG_USE_component_wireless_imu_adapter AND CONFIG_USE_component_osa_free_rtos AND CONFIG_USE_driver_imu)

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver/wifi-imu.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}/./wifidriver
)

else()

message(SEND_ERROR "middleware_wifi_imu dependency does not meet, please check ${CMAKE_CURRENT_LIST_FILE}.")

endif()

endif()


if (CONFIG_USE_middleware_wifi_cli)
# Add set(CONFIG_USE_middleware_wifi_cli true) in config.cmake to use this component

message("middleware_wifi_cli component is included from ${CMAKE_CURRENT_LIST_FILE}.")

if(CONFIG_USE_middleware_wifi AND CONFIG_USE_middleware_wifi_wifidriver AND CONFIG_USE_utility_debug_console)

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/./cli/cli.c
  ${CMAKE_CURRENT_LIST_DIR}/./cli/cli_mem_simple.c
  ${CMAKE_CURRENT_LIST_DIR}/./cli/cli_utils.c
  ${CMAKE_CURRENT_LIST_DIR}/./cli/wifi_shell.c
  ${CMAKE_CURRENT_LIST_DIR}/./port/osa/osa_cli.c
  ${CMAKE_CURRENT_LIST_DIR}/./dhcpd/dhcp-server-cli.c
  ${CMAKE_CURRENT_LIST_DIR}/./nw_utils/wifi_ping.c
  ${CMAKE_CURRENT_LIST_DIR}/./nw_utils/iperf.c
  ${CMAKE_CURRENT_LIST_DIR}/./nw_utils/init_enet.c
  ${CMAKE_CURRENT_LIST_DIR}/./nw_utils/telnet/telnet_server.c
  ${CMAKE_CURRENT_LIST_DIR}/./wlcmgr/wlan_basic_cli.c
  ${CMAKE_CURRENT_LIST_DIR}/./wlcmgr/wlan_enhanced_tests.c
  ${CMAKE_CURRENT_LIST_DIR}/./wlcmgr/wlan_tests.c
  ${CMAKE_CURRENT_LIST_DIR}/./wlcmgr/wlan_test_mode_tests.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}/./cli
  ${CMAKE_CURRENT_LIST_DIR}/./incl
  ${CMAKE_CURRENT_LIST_DIR}/./incl/wlcmgr
  ${CMAKE_CURRENT_LIST_DIR}/./nw_utils
  ${CMAKE_CURRENT_LIST_DIR}/./nw_utils/telnet
)

else()

message(SEND_ERROR "middleware_wifi_cli dependency does not meet, please check ${CMAKE_CURRENT_LIST_FILE}.")

endif()

endif()


if (CONFIG_USE_middleware_wifi_wmcrypto)
# Add set(CONFIG_USE_middleware_wifi_wmcrypto true) in config.cmake to use this component

message("middleware_wifi_wmcrypto component is included from ${CMAKE_CURRENT_LIST_FILE}.")

if(CONFIG_USE_middleware_wifi AND CONFIG_USE_middleware_wifi_wifidriver)

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/./wmcrypto/wmcrypto.c
  ${CMAKE_CURRENT_LIST_DIR}/./wmcrypto/wmcrypto_mem.c
  ${CMAKE_CURRENT_LIST_DIR}/./wmcrypto/wm_mbedtls_entropy.c
  ${CMAKE_CURRENT_LIST_DIR}/./wmcrypto/wm_mbedtls_mem.c
  ${CMAKE_CURRENT_LIST_DIR}/./wmcrypto/wm_mbedtls_net.c
  ${CMAKE_CURRENT_LIST_DIR}/./wmcrypto/wm_mbedtls_helper_api.c
  ${CMAKE_CURRENT_LIST_DIR}/./wmcrypto/wm_utils.c
  ${CMAKE_CURRENT_LIST_DIR}/./wmcrypto/aescrypto/aes-siv.c
  ${CMAKE_CURRENT_LIST_DIR}/./wmcrypto/aescrypto/aes-ctr.c
  ${CMAKE_CURRENT_LIST_DIR}/./wmcrypto/aescrypto/aes-omac1.c
  ${CMAKE_CURRENT_LIST_DIR}/./wmcrypto/aescrypto/aes-wrap.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}/./wmcrypto
  ${CMAKE_CURRENT_LIST_DIR}/./incl/wmcrypto
  ${CMAKE_CURRENT_LIST_DIR}/./wmcrypto/aescrypto
)

else()

message(SEND_ERROR "middleware_wifi_wmcrypto dependency does not meet, please check ${CMAKE_CURRENT_LIST_FILE}.")

endif()

endif()


if (CONFIG_USE_middleware_wifi_wmtime)
# Add set(CONFIG_USE_middleware_wifi_wmtime true) in config.cmake to use this component

message("middleware_wifi_wmtime component is included from ${CMAKE_CURRENT_LIST_FILE}.")

if(CONFIG_USE_middleware_wifi AND CONFIG_USE_middleware_wifi_wifidriver)

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/./wmtime/wmtime.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}/./wmtime
  ${CMAKE_CURRENT_LIST_DIR}/./incl
)

else()

message(SEND_ERROR "middleware_wifi_wmtime dependency does not meet, please check ${CMAKE_CURRENT_LIST_FILE}.")

endif()

endif()


if (CONFIG_USE_middleware_wifi_wps)
# Add set(CONFIG_USE_middleware_wifi_wps true) in config.cmake to use this component

message("middleware_wifi_wps component is included from ${CMAKE_CURRENT_LIST_FILE}.")

if(CONFIG_USE_middleware_wifi AND CONFIG_USE_middleware_wifi_wifidriver AND CONFIG_USE_middleware_wifi_wmtime AND CONFIG_USE_middleware_wifi_wmcrypto)

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/./wps/wps_eapol.c
  ${CMAKE_CURRENT_LIST_DIR}/./wps/wps_l2.c
  ${CMAKE_CURRENT_LIST_DIR}/./wps/wps_main.c
  ${CMAKE_CURRENT_LIST_DIR}/./wps/wps_mem.c
  ${CMAKE_CURRENT_LIST_DIR}/./wps/wps_msg.c
  ${CMAKE_CURRENT_LIST_DIR}/./wps/wps_os.c
  ${CMAKE_CURRENT_LIST_DIR}/./wps/wps_start.c
  ${CMAKE_CURRENT_LIST_DIR}/./wps/wps_state.c
  ${CMAKE_CURRENT_LIST_DIR}/./wps/wps_wlan.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}/./wps
  ${CMAKE_CURRENT_LIST_DIR}/./incl/wps
)

else()

message(SEND_ERROR "middleware_wifi_wps dependency does not meet, please check ${CMAKE_CURRENT_LIST_FILE}.")

endif()

endif()


if (CONFIG_USE_middleware_wifi_ncp_supp_wmcrypto)
# Add set(CONFIG_USE_middleware_wifi_ncp_supp_wmcrypto true) in config.cmake to use this component

message("middleware_wifi_ncp_supp_wmcrypto component is included from ${CMAKE_CURRENT_LIST_FILE}.")

if(CONFIG_USE_middleware_wifi AND CONFIG_USE_middleware_wifi_wifidriver)

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/./wmcrypto/wmcrypto_mem.c
  ${CMAKE_CURRENT_LIST_DIR}/./wmcrypto/wm_mbedtls_entropy.c
  ${CMAKE_CURRENT_LIST_DIR}/./wmcrypto/wm_mbedtls_mem.c
  ${CMAKE_CURRENT_LIST_DIR}/./wmcrypto/wm_mbedtls_net.c
  ${CMAKE_CURRENT_LIST_DIR}/./wmcrypto/wm_mbedtls_helper_api.c
  ${CMAKE_CURRENT_LIST_DIR}/./wmcrypto/wm_utils.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}/./wmcrypto
  ${CMAKE_CURRENT_LIST_DIR}/./incl/wmcrypto
)

else()

message(SEND_ERROR "middleware_wifi_ncp_supp_wmcrypto dependency does not meet, please check ${CMAKE_CURRENT_LIST_FILE}.")

endif()

endif()


if (CONFIG_USE_middleware_wifi_wls)
# Add set(CONFIG_USE_middleware_wifi_wls true) in config.cmake to use this component

message("middleware_wifi_wls component is included from ${CMAKE_CURRENT_LIST_FILE}.")

if(CONFIG_USE_middleware_wifi AND CONFIG_USE_middleware_wifi_wifidriver)

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/./wls/range_kalman.c
  ${CMAKE_CURRENT_LIST_DIR}/./wls/wls_api.c
  ${CMAKE_CURRENT_LIST_DIR}/./wls/wls_processing.c
  ${CMAKE_CURRENT_LIST_DIR}/./wls/wls_QR_algorithm.c
  ${CMAKE_CURRENT_LIST_DIR}/./wls/wls_radix4Fft.c
  ${CMAKE_CURRENT_LIST_DIR}/./wls/wls_subspace_processing.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}/./wls
)

else()

message(SEND_ERROR "middleware_wifi_wls dependency does not meet, please check ${CMAKE_CURRENT_LIST_FILE}.")

endif()

endif()


if (CONFIG_USE_middleware_edgefast_wifi_nxp)
# Add set(CONFIG_USE_middleware_edgefast_wifi_nxp true) in config.cmake to use this component

message("middleware_edgefast_wifi_nxp component is included from ${CMAKE_CURRENT_LIST_FILE}.")

if(CONFIG_USE_middleware_wifi AND CONFIG_USE_middleware_freertos-kernel)

target_sources(${MCUX_SDK_PROJECT_NAME} PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/../../core/components/edgefast_wifi/source/wpl_nxp.c
)

target_include_directories(${MCUX_SDK_PROJECT_NAME} PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}/../../core/components/edgefast_wifi/include
)

else()

message(SEND_ERROR "middleware_edgefast_wifi_nxp dependency does not meet, please check ${CMAKE_CURRENT_LIST_FILE}.")

endif()

endif()

