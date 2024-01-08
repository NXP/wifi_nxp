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

#define INBUF_SIZE 512

static struct {
    const struct cli_command *commands[MAX_COMMANDS];
    unsigned int num_commands;
} cli;

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

    while (i < MAX_COMMANDS && n < cli.num_commands)
    {
        if (cli.commands[i]->name != NULL)
        {
            (void)PRINTF("%s %s\r\n", (char *)cli.commands[i]->name + 5,
                         cli.commands[i]->help != NULL ? cli.commands[i]->help : "");
            n++;
        }
        i++;
    }
}

/* Parse input line and locate arguments (if any), keeping count of the number
 * of arguments and their locations.  Look up and call the corresponding cli
 * function if one is found and pass it the argv array.
 *
 * Returns: 0 on success: the input line contained at least a function name and
 *          that function exists and was called.
 *          1 on lookup failure: there is no corresponding function for the
 *          input line.
 *          2 on invalid syntax: the arguments list couldn't be parsed
 */
int handle_input(char *handle_inbuf)
{
    struct
    {
        unsigned inArg : 1;
        unsigned inQuote : 1;
        unsigned done : 1;
    } stat;
    static char *argv[64];
    int argc = 0;
    int i    = 0;
    unsigned int j                    = 0;
    const struct cli_command *command = NULL;
    const char *p;

    (void)memset((void *)&argv, 0, sizeof(argv));
    (void)memset(&stat, 0, sizeof(stat));

    /*
     * Some terminals add CRLF to the input buffer.
     * Sometimes the CR and LF characters maybe misplaced (it maybe added at the
     * start or at the end of the buffer). Therefore, strip all CRLF (0x0d, 0x0a).
     */
    for (j = 0; j < INBUF_SIZE; j++)
    {
        if (handle_inbuf[j] == (char)0x0D || handle_inbuf[j] == (char)0x0A)
        {
            if (j < (INBUF_SIZE - 1U))
            {
                (void)memmove((handle_inbuf + j), handle_inbuf + j + 1, (INBUF_SIZE - 1 - j));
            }
            handle_inbuf[INBUF_SIZE - 1] = (char)(0x00);
        }
    }

    do
    {
        switch (handle_inbuf[i])
        {
            case '\0':
                if (stat.inQuote != 0U)
                {
                    return 2;
                }
                stat.done = 1;
                break;

            case '"':
                if (i > 0 && handle_inbuf[i - 1] == '\\' && (stat.inArg != 0U))
                {
                    (void)memcpy(&handle_inbuf[i - 1], &handle_inbuf[i], strlen(&handle_inbuf[i]) + 1U);
                    --i;
                    break;
                }
                if ((stat.inQuote == 0U) && (stat.inArg != 0U))
                {
                    break;
                }
                if ((stat.inQuote != 0U) && (stat.inArg == 0U))
                {
                    return 2;
                }

                if ((stat.inQuote == 0U) && (stat.inArg == 0U))
                {
                    stat.inArg   = 1;
                    stat.inQuote = 1;
                    argc++;
                    argv[argc - 1] = &handle_inbuf[i + 1];
                }
                else if ((stat.inQuote != 0U) && (stat.inArg != 0U))
                {
                    stat.inArg      = 0;
                    stat.inQuote    = 0;
                    handle_inbuf[i] = '\0';
                }
                else
                { /* Do Nothing */
                }
                break;

            case ' ':
                if (i > 0 && handle_inbuf[i - 1] == '\\' && (stat.inArg != 0U))
                {
                    (void)memcpy(&handle_inbuf[i - 1], &handle_inbuf[i], strlen(&handle_inbuf[i]) + 1U);
                    --i;
                    break;
                }
                if ((stat.inQuote == 0U) && (stat.inArg != 0U))
                {
                    stat.inArg      = 0;
                    handle_inbuf[i] = '\0';
                }
                break;

            default:
                if (stat.inArg == 0U)
                {
                    stat.inArg = 1;
                    argc++;
                    argv[argc - 1] = &handle_inbuf[i];
                }
                break;
        }
        i++;
    } while ((stat.done == 0U) && (unsigned int)i < INBUF_SIZE);

    if (stat.inQuote != 0U)
    {
        return 2;
    }

    if (argc < 1)
    {
        return 0;
    }

    /*
     * Some comamands can allow extensions like foo.a, foo.b and hence
     * compare commands before first dot.
     */
    i       = ((p = strchr(argv[0], (int)('.'))) == NULL) ? 0 : (p - argv[0]);
    command = lookup_command(argv[0], i);
    if (command == NULL)
    {
        return 1;
    }

    command->function(argc, argv);

    return 0;
}

/* Print out a bad command string, including a hex
 * representation of non-printable characters.
 * Non-printable characters show as "\0xXX".
 */
void print_bad_command(char *cmd_string)
{
    if (cmd_string != NULL)
    {
        unsigned char *c = (unsigned char *)cmd_string;
        (void)PRINTF("command '");
        while (*c != (unsigned char)'\0')
        {
            if (isprint(*c) != 0)
            {
                (void)PRINTF("%c", *c);
            }
            else
            {
                (void)PRINTF("\\0x%x", *c);
            }
            ++c;
        }
        (void)PRINTF("' not found\r\n");
    }
}

static char wlan[256];

/**
 *  wlan shell entry
 *  syntax: wlansh wlan-add ...
 */
int nxp_wifi_request(void *nxp_wifi, char *cmd,
				 size_t clen, char *rsp, size_t rlen)
{
    int ret;

    if (strcmp(cmd, "help") == 0)
    {
        help_command(0, NULL);
        return 0;
    }

    strcpy(wlan, "wlan-");
    strcat(wlan, cmd);

    ret = handle_input(wlan);
    if (ret == 1)
    {
        print_bad_command(cmd);
    }
    else if (ret == 2)
    {
        (void)PRINTF("syntax error\r\n");
    }
    else
    { /* Do Nothing */
    }

    return 0;
}
