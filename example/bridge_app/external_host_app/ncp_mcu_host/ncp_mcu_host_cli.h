/**@file mcu_bridge_cli.h
 *
 *  Copyright 2008-2023 NXP
 *
 *  Licensed under the LA_OPT_NXP_Software_License.txt (the "Agreement")
 *
 */

#ifndef __MCU_BRIDGE_CLI_H__
#define __MCU_BRIDGE_CLI_H__

#define MCU_CLI_STRING_SIZE            500
#define MCU_BRIDGE_MAX_COMMANDS        500
#define MCU_BRIDGE_CLI_BACKGROUND_SIZE 32

#define MCU_BRIDGE_COMMAND_LEN             4096 // The max number bytes which UART can receive.
#define MCU_BRIDGE_RESPONSE_LEN            4096
#define MCU_BRIDGE_CMD_SIZE_LOW_BYTE       4
#define MCU_BRIDGE_CMD_SIZE_HIGH_BYTE      5
#define MCU_BRIDGE_CMD_SEQUENCE_LOW_BYTES  6
#define MCU_BRIDGE_CMD_SEQUENCE_HIGH_BYTES 7

#define WM_LOOKUP_FAIL         1
#define WM_INVAILD_FAIL        2
#define WM_INVAILD_STRING_FAIL 3

#define ICMP_ECHO             8 /* echo */
#define IP_HEADER_LEN         20
#define PING_RECVFROM_TIMEOUT 2000

/** Structure for registering CLI commands */
struct mcu_bridge_cli_command
{
    /** The name of the CLI command */
    const char *name;
    /** The help text associated with the command */
    const char *help;
    /** The function that should be invoked for this command. */
    int (*function)(int argc, char **argv);
};

/** Register a CLI command
 *
 * This function registers a command with the command-line interface.
 *
 * \param[in] command The structure to register one CLI command
 * \return 0 on success
 * \return 1 on failure
 */
int mcu_bridge_cli_register_command(const struct mcu_bridge_cli_command *command);

/** Unregister a CLI command
 *
 * This function unregisters a command from the command-line interface.
 *
 * \param[in] command The structure to unregister one CLI command
 * \return 0 on success
 * \return 1 on failure
 */
int mcu_bridge_cli_unregister_command(const struct mcu_bridge_cli_command *command);

/** Initialize the CLI module
 *
 * \return WM_SUCCESS on success
 * \return error code otherwise.
 */
int mcu_bridge_cli_init(void);

/** Register a batch of CLI commands
 *
 * Often, a module will want to register several commands.
 *
 * \param[in] commands Pointer to an array of commands.
 * \param[in] num_commands Number of commands in the array.
 * \return 0 on success
 * \return 1 on failure
 */
int mcu_bridge_cli_register_commands(const struct mcu_bridge_cli_command *commands, int num_commands);

/** Unregister a batch of CLI commands
 *
 * \param[in] commands Pointer to an array of commands.
 * \param[in] num_commands Number of commands in the array.
 * \return 0 on success
 * \return 1 on failure
 */
int mcu_bridge_cli_unregister_commands(const struct mcu_bridge_cli_command *commands, int num_commands);

/*
 */
typedef int (*cli_name_val_get)(const char *name, char *value, int max_len);

/*
 */
typedef int (*cli_name_val_set)(const char *name, const char *value);

/*
 * @internal
 *
 * CLI help command to print all registered CLIs
 */
int help_command(int argc, char **argv);

/** Find the command 'name' in the mcu_bridge_cli commands table.
 *
 * \param[in] name The name of command
 * \param[in] len  Length of command match
 * \return a pointer to the corresponding cli_command struct
 * \return NULL, no matching cli_command
 */
const struct mcu_bridge_cli_command *lookup_command(char *name, int len);

/**
 * @brief Send tlv command to ncp_bridge app.
 *
 * @return WM_SUCCESS if successful.
 *         -WM_FAIL if unsuccessful.
 */
int mcu_bridge_send_tlv_command();

uint32_t uart_get_crc32(uint8_t *buf, uint16_t len);

#endif /* __MCU_BRIDGE_CLI_H__ */
