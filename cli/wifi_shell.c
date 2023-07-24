/*
 * Copyright 2022 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/shell/shell.h>

#include "wifi_shell.h"
#include <wlan.h>
#include <wifi.h>

static struct {
    const struct cli_command *commands[MAX_COMMANDS];
    unsigned int num_commands;
} cli;

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

int cli_register_command(const struct cli_command *command)
{
    unsigned int i;
    if (command->name == NULL || command->function == NULL)
    {
        return 1;
    }

    if (cli.num_commands < MAX_COMMANDS)
    {
        /* Check if the command has already been registered.
         * Return 0, if it has been registered.
         */
        for (i = 0; i < cli.num_commands; i++)
        {
            if (cli.commands[i] == command)
            {
                return 0;
            }
        }
        cli.commands[cli.num_commands++] = command;
        return 0;
    }

    return 1;
}

int cli_unregister_command(const struct cli_command *command)
{
    unsigned int i = 0;
    if (command->name == NULL || command->function == NULL)
    {
        return 1;
    }

    while (i < cli.num_commands)
    {
        if (cli.commands[i] == command)
        {
            cli.num_commands--;
            unsigned int remaining_cmds = cli.num_commands - i;
            if (remaining_cmds > 0U)
            {
                (void)memmove(&cli.commands[i], &cli.commands[i + 1U], (remaining_cmds * sizeof(struct cli_command *)));
            }
            cli.commands[cli.num_commands] = NULL;
            return 0;
        }
        i++;
    }

    return 1;
}

int cli_register_commands(const struct cli_command *commands, int num_commands)
{
    int i;
    for (i = 0; i < num_commands; i++)
    {
        if (cli_register_command(commands++) != 0)
        {
            return 1;
        }
    }
    return 0;
}

int cli_unregister_commands(const struct cli_command *commands, int num_commands)
{
    int i;
    for (i = 0; i < num_commands; i++)
    {
        if (cli_unregister_command(commands++) != 0)
        {
            return 1;
        }
    }

    return 0;
}

static const struct cli_command *lookup_command(char *name, int len)
{
    unsigned int i = 0;
    unsigned int n = 0;

    while (i < MAX_COMMANDS && n < cli.num_commands)
    {
        if (cli.commands[i]->name == NULL)
        {
            i++;
            continue;
        }
        /* See if partial or full match is expected */
        if (len != 0)
        {
            if (strncmp(cli.commands[i]->name, name, (size_t)len) == 0)
            {
                return cli.commands[i];
            }
        }
        else
        {
            if (strcmp(cli.commands[i]->name, name) == 0)
            {
                return cli.commands[i];
            }
        }

        i++;
        n++;
    }

    return NULL;
}

/* prints all registered commands and their help text string, if any. */
void help_command(int argc, char **argv)
{
    unsigned int i = 0, n = 0;

    (void)PRINTF("\r\n");
    while (i < MAX_COMMANDS && n < cli.num_commands)
    {
        if (cli.commands[i]->name != NULL)
        {
            (void)PRINTF("%s %s\r\n", cli.commands[i]->name,
                         cli.commands[i]->help != NULL ? cli.commands[i]->help : "");
            n++;
        }
        i++;
    }
}

/**
 *  wlan shell entry
 *  syntax: wlansh wlan-add ...
 */
static int cmd_wlansh(const struct shell *shell, size_t argc, char **argv)
{
    struct cli_command *command = NULL;

    if (argc < 2)
    {
        shell_print(shell, "wlan command too few arguments");
        return -1;
    }

    if (strcmp(argv[1], "help") == 0)
    {
        help_command(argc, argv);
    }

    command = lookup_command(argv[1], strlen(argv[1]));
    if (command != NULL)
    {
        command->function(argc - 1, &argv[1]);
        shell_print(shell, "Command %s", command->name);
    }
    else
    {
        shell_print(shell, "Unknown comamnd %s", argv[1]);
    }

    return 0;
}

SHELL_CMD_ARG_REGISTER(wlansh, NULL, "WLAN commands", cmd_wlansh, 2, 10);
SHELL_CMD_ARG_REGISTER(wifi_scan, NULL, "Scan for wifi", cmd_wifi_scan, 1, 0);
SHELL_CMD_ARG_REGISTER(wifi_connect, NULL, "Connect to wifi", cmd_wifi_connect, 4, 0);
SHELL_CMD_ARG_REGISTER(wifi_disconnect, NULL, "Disconnect wifi", cmd_wifi_disconnect, 1, 0);
