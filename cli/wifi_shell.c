/*
 * Copyright 2022 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/shell/shell.h>

#include <wlan.h>
#include <wifi.h>

static int wifi_scan_cb(unsigned int count)
{
	struct wlan_scan_result res;
	int ret;

	if (count == 0) {
		printk("No networks found\n");
		return 0;
	}

	printk("Found %d networks\n", count);

	for (int i = 0; i < count; i++) {
		ret = wlan_get_scan_result(i, &res);
		if (ret) {
			printk("Can't get scan result %d\n", i);
			continue;
		}
		if (res.ssid[0] != '\0') {
			printk("SSID: %s\n", res.ssid);
		} else {
			printk("(hidden)\n");
		}
		printk("Channel: %d\n", res.channel);
		printk("rssi: -%d\n", res.rssi);
	}
	return 0;
}

static int cmd_wifi_scan(const struct shell *shell, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	if (wlan_scan(wifi_scan_cb) != 0) {
		shell_print(shell, "Error: scan request failed");
	} else {
		shell_print(shell, "Scan scheduled...");
	}

	return 0;
}


static int cmd_wifi_connect(const struct shell *shell, size_t argc, char **argv)
{
	struct wlan_network network;
	int ret;

	memset(&network, 0, sizeof(struct wlan_network));
	memcpy(network.name, argv[1], strlen(argv[1]));
	memcpy(network.ssid, argv[2], strlen(argv[2]));
	memcpy(network.security.psk, argv[3], strlen(argv[3]));
	network.security.psk_len = strlen(argv[3]);
	network.security.type = WLAN_SECURITY_WPA2;
	network.ip.ipv4.addr_type = ADDR_TYPE_STATIC;
	ret = wlan_add_network(&network);
	if (ret != WM_SUCCESS) {
		shell_print(shell, "Error: could not add wlan network");
		return ret;
	} else {
		shell_print(shell, "Added SSID %s, PSK %s (WPA2)", network.ssid,
			network.security.psk);
	}
	/* Connect to network */
	ret = wlan_connect(network.name);
	shell_print(shell, "connection status: %d", ret);
	return ret;
}


static int cmd_wifi_disconnect(const struct shell *shell, size_t argc, char **argv)
{
	int ret;

	ret = wlan_disconnect();
	if (ret) {
		shell_print(shell, "failed to disconnect: %d", ret);
	}
	return ret;
}

SHELL_CMD_ARG_REGISTER(wifi_scan, NULL, "Scan for wifi", cmd_wifi_scan, 1, 0);
SHELL_CMD_ARG_REGISTER(wifi_connect, NULL, "Connect to wifi", cmd_wifi_connect, 4, 0);
SHELL_CMD_ARG_REGISTER(wifi_disconnect, NULL, "Disconnect wifi", cmd_wifi_disconnect, 1, 0);
