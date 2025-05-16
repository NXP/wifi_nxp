
if (CONFIG_MCUX_COMPONENT_middleware.wifi.wifi_bt_config.template)
    mcux_add_source(
		BASE_PATH ${SdkRootDirPath}/components/wifi_bt_module/template
        SOURCES wifi_bt_config.h
                # TODO please change to relative dir
                wifi_bt_config.c
		CONFIG TRUE
    )
    mcux_add_include(
        INCLUDES ./
    )
endif()

if (CONFIG_MCUX_COMPONENT_middleware.wifi.template)
#    mcux_add_source(
#		BASE_PATH ${SdkRootDirPath}/components/wifi_bt_module/template
#        SOURCES app_config.h
#                # TODO please change to relative dir
#                wifi_config.h
#    )
#    mcux_add_include(
#        INCLUDES ./
#    )
endif()

if (CONFIG_MCUX_COMPONENT_middleware.wifi.osa_free_rtos)
    mcux_add_source(
        SOURCES port/osa/osa_freertos.h
                # TODO please change to relative dir
                port/osa/osa_freertos.c
    )
    mcux_add_include(
        INCLUDES ./
                 incl
                 incl/port/osa
                 port/osa
    )
endif()

if (CONFIG_MCUX_COMPONENT_middleware.wifi.osa_thread)
    mcux_add_source(
        SOURCES port/osa/osa_threadx.h
                # TODO please change to relative dir
                port/osa/osa_threadx.c
    )
    mcux_add_include(
        INCLUDES ./
                 incl/port/osa
                 port/osa
    )
endif()

if (CONFIG_MCUX_COMPONENT_middleware.wifi.osa)
    mcux_add_source(
        SOURCES incl/port/osa/osa.h
                # TODO please change to relative dir
                incl/port/osa/mem_pool.h
                # TODO please change to relative dir
                incl/port/osa/mem_pool_config.h
                # TODO please change to relative dir
                incl/port/osa/slist.h
                # TODO please change to relative dir
                incl/port/osa/stack_simple.h
                # TODO please change to relative dir
                port/osa/osa.c
                # TODO please change to relative dir
                port/osa/mem_pool.c
                # TODO please change to relative dir
                port/osa/mem_pool_config.c
                # TODO please change to relative dir
                port/osa/slist.c
                # TODO please change to relative dir
                port/osa/stack_simple.c
    )
    mcux_add_include(
        INCLUDES ./
                 incl/port
                 incl/port/osa
    )
endif()

if (CONFIG_MCUX_COMPONENT_middleware.wifi.common_files)
    mcux_add_source(
        SOURCES incl/wifi_config_default.h
                # TODO please change to relative dir
                incl/wifidriver/wifi-decl.h
                # TODO please change to relative dir
                incl/wifidriver/wifi.h
                # TODO please change to relative dir
                incl/wifidriver/wifi_events.h
                # TODO please change to relative dir
                incl/wifi_cal_data_ext.h
                # TODO please change to relative dir
                incl/wm_utils.h
                # TODO please change to relative dir
                incl/wmerrno.h
                # TODO please change to relative dir
                incl/wmlog.h
                # TODO please change to relative dir
                incl/wmtypes.h
                # TODO please change to relative dir
                wifidriver/incl/mlan_decl.h
                # TODO please change to relative dir
                wifidriver/incl/mlan_ioctl.h
                # TODO please change to relative dir
                wifidriver/incl/type_decls.h
                # TODO please change to relative dir
                wifi_bt_firmware/wlan_bt_fw.h
                incl/wifi_cal_data_frdmrw61x_1ant.h
                incl/wifi_cal_data_rw61x_1ant.h
                incl/wifi_cal_data_rw61x_1ant_diversity.h
                incl/wifi_cal_data_rw61x_2ant.h
                incl/wifi_cal_data_rw61x_3ant_diversity.h
                incl/wifi_cal_data_rw61x_override.h
    )
    mcux_add_include(
        INCLUDES incl
                 incl/port/osa
                 incl/wifidriver
                 wifi_bt_firmware
                 wifidriver
                 wifidriver/incl
    )
endif()

if (CONFIG_MCUX_COMPONENT_middleware.wifi.fwdnld)
    mcux_add_source(
        SOURCES incl/WIFI_IW416_BOARD_AW_AM457_CAL_DATA_EXT.h
                # TODO please change to relative dir
                wifidriver/incl/mlan_main_defs.h
                # TODO please change to relative dir
                wifi_bt_firmware/8801/sd8801_wlan.bin.inc
                # TODO please change to relative dir
                wifi_bt_firmware/8801/sd8801_wlan.h
                # TODO please change to relative dir
                wifi_bt_firmware/8801/8801_cpu1.c
                # TODO please change to relative dir
                wifi_bt_firmware/IW416/sduartIW416_wlan_bt.bin.inc
                # TODO please change to relative dir
                wifi_bt_firmware/IW416/sdIW416_wlan.bin.inc
                # TODO please change to relative dir
                wifi_bt_firmware/IW416/uartIW416_bt.bin.inc
                # TODO please change to relative dir
                wifi_bt_firmware/IW416/sduartIW416_wlan_bt.h
                # TODO please change to relative dir
                wifi_bt_firmware/IW416/sdIW416_wlan.h
                # TODO please change to relative dir
                wifi_bt_firmware/IW416/uartIW416_bt.h
                # TODO please change to relative dir
                wifi_bt_firmware/IW416/IW416_cpu12.c
                # TODO please change to relative dir
                wifi_bt_firmware/IW416/IW416_cpu1.c
                # TODO please change to relative dir
                wifi_bt_firmware/IW416/IW416_cpu2.c
                # TODO please change to relative dir
                wifi_bt_firmware/8987/sduart8987_wlan_bt.bin.inc
                # TODO please change to relative dir
                wifi_bt_firmware/8987/sd8987_wlan.bin.inc
                # TODO please change to relative dir
                wifi_bt_firmware/8987/uart8987_bt.bin.inc
                # TODO please change to relative dir
                wifi_bt_firmware/8987/sduart8987_wlan_bt.h
                # TODO please change to relative dir
                wifi_bt_firmware/8987/sd8987_wlan.h
                # TODO please change to relative dir
                wifi_bt_firmware/8987/uart8987_bt.h
                # TODO please change to relative dir
                wifi_bt_firmware/8987/8987_cpu12.c
                # TODO please change to relative dir
                wifi_bt_firmware/8987/8987_cpu1.c
                # TODO please change to relative dir
                wifi_bt_firmware/8987/8987_cpu2.c
                # TODO please change to relative dir
                wifi_bt_firmware/nw61x/sduart_nw61x.bin.se.inc
                # TODO please change to relative dir
                wifi_bt_firmware/nw61x/sd_nw61x.bin.se.inc
                # TODO please change to relative dir
                wifi_bt_firmware/nw61x/uart_nw61x.bin.se.inc
                # TODO please change to relative dir
                wifi_bt_firmware/nw61x/sduart_nw61x_se.h
                # TODO please change to relative dir
                wifi_bt_firmware/nw61x/sd_nw61x_se.h
                # TODO please change to relative dir
                wifi_bt_firmware/nw61x/uart_nw61x_se.h
                # TODO please change to relative dir
                wifi_bt_firmware/nw61x/nw61x_cpu12_se.c
                # TODO please change to relative dir
                wifi_bt_firmware/nw61x/nw61x_cpu1_se.c
                # TODO please change to relative dir
                wifi_bt_firmware/nw61x/nw61x_cpu2_se.c
                # TODO please change to relative dir
                wifi_bt_firmware/iw610/sduartspi_iw610.bin.se.inc
                # TODO please change to relative dir
                wifi_bt_firmware/iw610/sd_iw610.bin.se.inc
                # TODO please change to relative dir
                wifi_bt_firmware/iw610/uartspi_iw610.bin.se.inc
                wifi_bt_firmware/iw610/sduart_iw610.bin.se.inc
                wifi_bt_firmware/iw610/uart_iw610_bt.bin.se.inc
                # TODO please change to relative dir
                wifi_bt_firmware/iw610/sduart_iw610_se.h
                # TODO please change to relative dir
                wifi_bt_firmware/iw610/sd_iw610_se.h
                # TODO please change to relative dir
                wifi_bt_firmware/iw610/uart_iw610_se.h
                # TODO please change to relative dir
                wifi_bt_firmware/iw610/iw610_cpu12_se.c
                # TODO please change to relative dir
                wifi_bt_firmware/iw610/iw610_cpu2_se.c
                # TODO please change to relative dir
                wifi_bt_firmware/iw610/iw610_cpu1_se.c
                # TODO please change to relative dir
                wifidriver/sdio.c
                # TODO please change to relative dir
                wifidriver/sdio.h
                # TODO please change to relative dir
                firmware_dnld/firmware_dnld.c
                # TODO please change to relative dir
                firmware_dnld/firmware_dnld.h
    )
    mcux_add_include(
        INCLUDES incl
                 wifi_bt_firmware
                 wifi_bt_firmware/8801
                 wifi_bt_firmware/IW416
                 wifi_bt_firmware/8987
                 wifi_bt_firmware/nw61x
                 wifi_bt_firmware/iw610
                 wifidriver
                 wifidriver/incl
                 firmware_dnld
                 sdio_nxp_abs
                 sdio_nxp_abs/incl
                 fwdnld_intf_abs
    )
endif()

if (CONFIG_MCUX_COMPONENT_middleware.wifi.firmware_download)
    mcux_add_source(
        SOURCES incl/WIFI_IW416_BOARD_AW_AM457_CAL_DATA_EXT.h
                # TODO please change to relative dir
                wifidriver/incl/mlan_main_defs.h
                # TODO please change to relative dir
                wifidriver/sdio.c
                # TODO please change to relative dir
                wifidriver/sdio.h
                # TODO please change to relative dir
                firmware_dnld/firmware_dnld.c
                # TODO please change to relative dir
                firmware_dnld/firmware_dnld.h
    )
    mcux_add_include(
        INCLUDES incl
                 wifidriver
                 wifidriver/incl
                 firmware_dnld
                 sdio_nxp_abs
                 sdio_nxp_abs/incl
                 fwdnld_intf_abs
    )
endif()

if (CONFIG_MCUX_COMPONENT_middleware.wifi.net_free_rtos)
    mcux_add_source(
        SOURCES incl/port/net/wm_net.h
                # TODO please change to relative dir
                port/net/net.c
                # TODO please change to relative dir
                port/net/netif_decl.h
                # TODO please change to relative dir
                port/net/wifi_netif.c
                # TODO please change to relative dir
                incl/port/net/hooks/lwip_default_hooks.h
                # TODO please change to relative dir
                port/net/hooks/lwip_default_hooks.c
                # TODO please change to relative dir
                dhcpd/dhcp-bootp.h
                # TODO please change to relative dir
                dhcpd/dhcp-priv.h
                # TODO please change to relative dir
                dhcpd/dhcp-server-main.c
                # TODO please change to relative dir
                dhcpd/dhcp-server.c
                # TODO please change to relative dir
                dhcpd/dns-server.c
                # TODO please change to relative dir
                dhcpd/dns.h
    )
    mcux_add_include(
        INCLUDES ./
                 incl
                 incl/port/osa
                 port/osa
                 incl/port/net
                 incl/port/net/hooks
                 dhcpd
                 incl/wlcmgr
                 incl/wifidriver
                 wifidriver/incl
    )
endif()

if (CONFIG_MCUX_COMPONENT_middleware.wifi.net_thread)
    mcux_add_source(
        SOURCES incl/port/net/wm_net.h
    )
    mcux_add_include(
        INCLUDES ./
                 incl/port/osa
                 port/osa
                 incl/port/net
                 port/net/netxduo
    )
endif()

if (CONFIG_MCUX_COMPONENT_middleware.wifi.net)
    mcux_add_source(
        SOURCES incl/port/net/wm_net.h
    )
    mcux_add_include(
        INCLUDES ./
                 incl/port/osa
    )
endif()

if (CONFIG_MCUX_COMPONENT_middleware.wifi.wifidriver)
    mcux_add_source(
        SOURCES incl/dhcp-server.h
                # TODO please change to relative dir
                incl/wlcmgr/wlan.h
                # TODO please change to relative dir
                incl/nxp_wifi.h
                # TODO please change to relative dir
                incl/wlcmgr/wlan_11d.h
                # TODO please change to relative dir
                incl/wifidriver/wifi_nxp.h
                # TODO please change to relative dir
                wifidriver/incl/mlan.h
                # TODO please change to relative dir
                wifidriver/incl/mlan_11ac.h
                # TODO please change to relative dir
                wifidriver/incl/mlan_11ax.h
                # TODO please change to relative dir
                wifidriver/incl/mlan_11h.h
                # TODO please change to relative dir
                wifidriver/incl/mlan_11n.h
                # TODO please change to relative dir
                wifidriver/incl/mlan_11n_aggr.h
                # TODO please change to relative dir
                wifidriver/incl/mlan_11n_rxreorder.h
                # TODO please change to relative dir
                wifidriver/incl/mlan_11v.h
                # TODO please change to relative dir
                wifidriver/incl/mlan_action.h
                # TODO please change to relative dir
                wifidriver/incl/mlan_11k.h
                # TODO please change to relative dir
                wifidriver/incl/mlan_mbo.h
                # TODO please change to relative dir
                wifidriver/incl/mlan_api.h
                # TODO please change to relative dir
                wifidriver/incl/mlan_fw.h
                # TODO please change to relative dir
                wifidriver/incl/mlan_ieee.h
                # TODO please change to relative dir
                wifidriver/incl/mlan_init.h
                # TODO please change to relative dir
                wifidriver/incl/mlan_join.h
                # TODO please change to relative dir
                wifidriver/incl/mlan_main.h
                # TODO please change to relative dir
                wifidriver/incl/mlan_meas.h
                # TODO please change to relative dir
                wifidriver/incl/mlan_remap_mem_operations.h
                # TODO please change to relative dir
                wifidriver/incl/mlan_uap.h
                # TODO please change to relative dir
                wifidriver/incl/mlan_util.h
                # TODO please change to relative dir
                wifidriver/incl/mlan_wmm.h
                # TODO please change to relative dir
                wifidriver/mlan_11ac.c
                # TODO please change to relative dir
                wifidriver/mlan_11ax.c
                # TODO please change to relative dir
                wifidriver/mlan_11d.c
                # TODO please change to relative dir
                wifidriver/mlan_11h.c
                # TODO please change to relative dir
                wifidriver/mlan_11n.c
                # TODO please change to relative dir
                wifidriver/mlan_11n_aggr.c
                # TODO please change to relative dir
                wifidriver/mlan_11n_rxreorder.c
                # TODO please change to relative dir
                wifidriver/mlan_11v.c
                # TODO please change to relative dir
                wifidriver/mlan_action.c
                # TODO please change to relative dir
                wifidriver/mlan_11k.c
                # TODO please change to relative dir
                wifidriver/mlan_mbo.c
                # TODO please change to relative dir
                wifidriver/mlan_api.c
                # TODO please change to relative dir
                wifidriver/mlan_cfp.c
                # TODO please change to relative dir
                wifidriver/mlan_cmdevt.c
                # TODO please change to relative dir
                wifidriver/mlan_glue.c
                # TODO please change to relative dir
                wifidriver/mlan_init.c
                # TODO please change to relative dir
                wifidriver/mlan_join.c
                # TODO please change to relative dir
                wifidriver/mlan_misc.c
                # TODO please change to relative dir
                wifidriver/mlan_scan.c
                # TODO please change to relative dir
                wifidriver/mlan_shim.c
                # TODO please change to relative dir
                wifidriver/mlan_sta_cmd.c
                # TODO please change to relative dir
                wifidriver/mlan_sta_cmdresp.c
                # TODO please change to relative dir
                wifidriver/mlan_sta_event.c
                # TODO please change to relative dir
                wifidriver/mlan_sta_ioctl.c
                # TODO please change to relative dir
                wifidriver/mlan_sta_rx.c
                # TODO please change to relative dir
                wifidriver/mlan_txrx.c
                # TODO please change to relative dir
                wifidriver/mlan_wmm.c
                # TODO please change to relative dir
                wifidriver/wifi-debug.c
                # TODO please change to relative dir
                wifidriver/wifi-debug.h
                # TODO please change to relative dir
                wifidriver/wifi-internal.h
                # TODO please change to relative dir
                wifidriver/wifi-mem.c
                # TODO please change to relative dir
                wifidriver/wifi.c
                # TODO please change to relative dir
                wifidriver/wifi_common.h
                # TODO please change to relative dir
                wifidriver/wifi_pwrmgr.c
                # TODO please change to relative dir
                wifidriver/wpa_supp_if/incl/rtos_wpa_supp_if.h
                # TODO please change to relative dir
                wifidriver/wpa_supp_if/incl/wifi_nxp_internal.h
                # TODO please change to relative dir
                wifidriver/wpa_supp_if/wifi_nxp.c
                # TODO please change to relative dir
                wifidriver/wpa_supp_if/rtos_wpa_supp_if.c
                # TODO please change to relative dir
                wifidriver/wpa_supp_if/wifi_nxp_internal.c
                # TODO please change to relative dir
                wifidriver/wifi-wps.c
                # TODO please change to relative dir
                certs/ca-cert.h
                # TODO please change to relative dir
                certs/client-cert.h
                # TODO please change to relative dir
                certs/client-key.h
                # TODO please change to relative dir
                certs/server-cert.h
                # TODO please change to relative dir
                certs/server-key.h
                # TODO please change to relative dir
                certs/dh-param.h
    )
    mcux_add_include(
        INCLUDES incl
                 incl/wlcmgr
                 wifidriver
                 wifidriver/incl
                 wifidriver/wpa_supp_if
                 wifidriver/wpa_supp_if/incl
                 certs
                 firmware_dnld
                 sdio_nxp_abs
                 sdio_nxp_abs/incl
    )
endif()

if (CONFIG_MCUX_COMPONENT_middleware.wifi.wifidriver.softap)
    mcux_add_configuration(
        CC  "-DCONFIG_NXP_WIFI_SOFTAP_SUPPORT=1"
    )

    mcux_add_source(SOURCES
        # TODO please change to relative dir
        wifidriver/wifi-uap.c
        wifidriver/mlan_uap_ioctl.c
        wifidriver/mlan_uap_cmdevent.c
    )

    mcux_add_include(INCLUDES
        wifidriver
    )
endif()

if (CONFIG_MCUX_COMPONENT_middleware.wifi)
    mcux_add_source(
        SOURCES dhcpd/dhcp-bootp.h
                # TODO please change to relative dir
                dhcpd/dhcp-priv.h
                # TODO please change to relative dir
                dhcpd/dhcp-server-main.c
                # TODO please change to relative dir
                dhcpd/dhcp-server.c
                # TODO please change to relative dir
                dhcpd/dns-server.c
                # TODO please change to relative dir
                dhcpd/dns.h
                # TODO please change to relative dir
                incl/port/net/wm_net.h
                # TODO please change to relative dir
                incl/wmstats.h
                # TODO please change to relative dir
                port/net/net.c
                # TODO please change to relative dir
                port/net/netif_decl.h
                # TODO please change to relative dir
                port/net/wifi_netif.c
                # TODO please change to relative dir
                wlcmgr/wlan.c
                # TODO please change to relative dir
                wlcmgr/wlan_txpwrlimit_cfg.c
                # TODO please change to relative dir
                ChangeLogKSDK.txt
                # TODO please change to relative dir
                CMakeLists.txt
    )
    mcux_add_include(
        INCLUDES incl
                 incl/wifidriver
                 incl/port/net
                 port/net
                 incl/port/net/hooks
    )
endif()

if (CONFIG_MCUX_COMPONENT_middleware.wifi.sdio)
    mcux_add_source(
        SOURCES wifidriver/wifi-sdio.c
    )
endif()

if (CONFIG_MCUX_COMPONENT_middleware.wifi.mlan_sdio)
    mcux_add_source(
        SOURCES sdio_nxp_abs/mlan_sdio.c
                # TODO please change to relative dir
                sdio_nxp_abs/fwdnld_sdio.c
                # TODO please change to relative dir
                sdio_nxp_abs/incl/fwdnld_sdio.h
                # TODO please change to relative dir
                sdio_nxp_abs/incl/mlan_sdio_defs.h
                # TODO please change to relative dir
                sdio_nxp_abs/incl/mlan_sdio.h
                # TODO please change to relative dir
                sdio_nxp_abs/incl/mlan_sdio_api.h
                # TODO please change to relative dir
                wifidriver/wifi-sdio.h
    )
    mcux_add_include(
        INCLUDES wifidriver
                 sdio_nxp_abs/incl
    )
endif()

if (CONFIG_MCUX_COMPONENT_middleware.wifi.fwdnld_intf_abs)
    mcux_add_source(
        SOURCES fwdnld_intf_abs/fwdnld_intf_abs.c
                # TODO please change to relative dir
                fwdnld_intf_abs/fwdnld_intf_abs.h
    )
    mcux_add_include(
        INCLUDES fwdnld_intf_abs
    )
endif()

if (CONFIG_MCUX_COMPONENT_middleware.wifi.imu)
    mcux_add_source(
        SOURCES wifidriver/wifi-imu.c
                # TODO please change to relative dir
                wifidriver/wifi-imu.h
    )
    mcux_add_include(
        INCLUDES wifidriver
    )
endif()

if (CONFIG_MCUX_COMPONENT_middleware.wifi.cli)
    mcux_add_source(
        SOURCES cli/cli_mem.h
                # TODO please change to relative dir
                cli/cli.c
                # TODO please change to relative dir
                cli/cli_mem_simple.c
                # TODO please change to relative dir
                cli/cli_utils.c
                # TODO please change to relative dir
                cli/wifi_shell.h
                # TODO please change to relative dir
                cli/wifi_shell.c
                # TODO please change to relative dir
                incl/cli.h
                # TODO please change to relative dir
                incl/cli_utils.h
                # TODO please change to relative dir
                port/osa/osa_cli.c
                # TODO please change to relative dir
                dhcpd/dhcp-server-cli.c
                # TODO please change to relative dir
                nw_utils/wifi_ping.c
                # TODO please change to relative dir
                nw_utils/iperf.c
                # TODO please change to relative dir
                incl/iperf.h
                # TODO please change to relative dir
                incl/wifi_ping.h
                # TODO please change to relative dir
                nw_utils/network_cfg.h
                # TODO please change to relative dir
                wlcmgr/wlan_basic_cli.c
                # TODO please change to relative dir
                wlcmgr/wlan_enhanced_tests.c
                # TODO please change to relative dir
                wlcmgr/wlan_tests.c
                # TODO please change to relative dir
                wlcmgr/wlan_test_mode_tests.c
                # TODO please change to relative dir
                incl/wlcmgr/wlan_tests.h
    )
    mcux_add_include(
        INCLUDES cli
                 incl
                 incl/wlcmgr
                 nw_utils
    )
endif()

if (CONFIG_MCUX_COMPONENT_middleware.wifi.wmcrypto)
    mcux_add_source(
        SOURCES wmcrypto/wmcrypto.c
                # TODO please change to relative dir
                incl/wmcrypto/wmcrypto.h
                # TODO please change to relative dir
                wmcrypto/wmcrypto_mem.c
                # TODO please change to relative dir
                wmcrypto/wmcrypto_mem.h
                # TODO please change to relative dir
                wmcrypto/wm_mbedtls_debug.h
                # TODO please change to relative dir
                wmcrypto/wm_mbedtls_entropy.c
                # TODO please change to relative dir
                wmcrypto/wm_mbedtls_entropy.h
                # TODO please change to relative dir
                wmcrypto/wm_mbedtls_mem.c
                # TODO please change to relative dir
                wmcrypto/wm_mbedtls_mem.h
                # TODO please change to relative dir
                wmcrypto/wm_mbedtls_net.c
                # TODO please change to relative dir
                wmcrypto/wm_mbedtls_net.h
                # TODO please change to relative dir
                wmcrypto/wm_mbedtls_helper_api.c
                # TODO please change to relative dir
                wmcrypto/wm_mbedtls_helper_api.h
                # TODO please change to relative dir
                wmcrypto/wm_utils.c
                # TODO please change to relative dir
                wmcrypto/aescrypto/aes.h
                # TODO please change to relative dir
                wmcrypto/aescrypto/aes_siv.h
                # TODO please change to relative dir
                wmcrypto/aescrypto/aes-siv.c
                # TODO please change to relative dir
                wmcrypto/aescrypto/aes-ctr.c
                # TODO please change to relative dir
                wmcrypto/aescrypto/aes-omac1.c
                # TODO please change to relative dir
                wmcrypto/aescrypto/aes-wrap.c
                # TODO please change to relative dir
                wmcrypto/aescrypto/aes_wrap.h
                # TODO please change to relative dir
                wmcrypto/aescrypto/common.h
                # TODO please change to relative dir
                wmcrypto/aescrypto/crypto.h
                # TODO please change to relative dir
                wmcrypto/aescrypto/includes.h
                # TODO please change to relative dir
                wmcrypto/aescrypto/type_def.h
    )
    mcux_add_include(
        INCLUDES wmcrypto
                 incl/wmcrypto
                 wmcrypto/aescrypto
    )
endif()

if (CONFIG_MCUX_COMPONENT_middleware.wifi.wmtime)
    mcux_add_source(
        SOURCES wmtime/wmtime.c
                # TODO please change to relative dir
                incl/wmtime.h
    )
    mcux_add_include(
        INCLUDES wmtime
                 incl
    )
endif()

if (CONFIG_MCUX_COMPONENT_middleware.wifi.ncp_supp_wmcrypto)
    mcux_add_source(
        SOURCES incl/wmcrypto/wmcrypto.h
                # TODO please change to relative dir
                wmcrypto/wmcrypto_mem.c
                # TODO please change to relative dir
                wmcrypto/wmcrypto_mem.h
                # TODO please change to relative dir
                wmcrypto/wm_mbedtls_debug.h
                # TODO please change to relative dir
                wmcrypto/wm_mbedtls_entropy.c
                # TODO please change to relative dir
                wmcrypto/wm_mbedtls_entropy.h
                # TODO please change to relative dir
                wmcrypto/wm_mbedtls_mem.c
                # TODO please change to relative dir
                wmcrypto/wm_mbedtls_mem.h
                # TODO please change to relative dir
                wmcrypto/wm_mbedtls_net.c
                # TODO please change to relative dir
                wmcrypto/wm_mbedtls_net.h
                # TODO please change to relative dir
                wmcrypto/wm_mbedtls_helper_api.c
                # TODO please change to relative dir
                wmcrypto/wm_mbedtls_helper_api.h
                # TODO please change to relative dir
                wmcrypto/wm_utils.c
    )
    mcux_add_include(
        INCLUDES wmcrypto
                 incl/wmcrypto
    )
endif()

if (CONFIG_MCUX_COMPONENT_middleware.wifi.wls)
    mcux_add_source(
        SOURCES wls/range_kalman.h
                # TODO please change to relative dir
                wls/range_kalman.c
                # TODO please change to relative dir
                wls/wls_api.c
                # TODO please change to relative dir
                wls/wls_api.h
                # TODO please change to relative dir
                wls/wls_param_defines.h
                # TODO please change to relative dir
                wls/wls_processing.c
                # TODO please change to relative dir
                wls/wls_processing.h
                # TODO please change to relative dir
                wls/wls_QR_algorithm.c
                # TODO please change to relative dir
                wls/wls_QR_algorithm.h
                # TODO please change to relative dir
                wls/wls_radix4Fft.h
                # TODO please change to relative dir
                wls/wls_radix4Fft.c
                # TODO please change to relative dir
                wls/wls_structure_defs.h
                # TODO please change to relative dir
                wls/wls_subspace_processing.h
                # TODO please change to relative dir
                wls/wls_subspace_processing.c
    )
    mcux_add_include(
        INCLUDES wls
    )
endif()

if(CONFIG_MCUX_COMPONENT_middleware.wifi.slim)
    mcux_add_macro(
        "-DCONFIG_WIFI_SLIM_ROAM=1\
         -DCONFIG_WIFI_SLIM_STA=1\
         -DCONFIG_WIFI_SLIM_UAP=1\
         -DCONFIG_WIFI_SLIM_DISABLE_DBG=1\
         -DCONFIG_WIFI_SLIM_WMM=1"
    )
endif()