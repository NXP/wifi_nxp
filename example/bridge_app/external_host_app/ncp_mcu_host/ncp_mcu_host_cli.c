/** @file bridge_cli.c
 *
 *  @brief  This file provides cli interface for receiving string commands and sending tlv commands.
 *
 *  Copyright 2008-2023 NXP
 *
 *  Licensed under the LA_OPT_NXP_Software_License.txt (the "Agreement")
 *
 */

#include <string.h>
#include <ctype.h>
#include "fsl_debug_console.h"
#include "board.h"
#ifdef CONFIG_CRC32_HW_ACCELERATE
#include "fsl_crc.h"
#endif
#include "ncp_mcu_host_os.h"
#include "ncp_mcu_host_utils.h"
#include "ncp_mcu_host_cli.h"
#include "ncp_mcu_host_command.h"
#include "ncp_mcu_host_app.h"
#include "fsl_lpuart_freertos.h"
#include "fsl_lpuart.h"
#if defined(CONFIG_USB_BRIDGE)
#include "usb_host_config.h"
#include "usb_host.h"
#include "usb_host_cdc.h"
#include "host_cdc.h"
#elif defined(CONFIG_SPI_BRIDGE)
#include "spi_master_app.h"
#endif

#ifdef CONFIG_NCP_UART
extern lpuart_rtos_handle_t ncp_host_tlv_uart_handle;
#endif

#define END_CHAR     '\r'
#define PROMPT       "\r\n# "
#define HALT_MSG     "CLI_HALT"
#define NUM_BUFFERS  1
#define MAX_COMMANDS 120

#define RX_WAIT   OS_WAIT_FOREVER
#define SEND_WAIT OS_WAIT_FOREVER

#define CONFIG_CLI_STACK_SIZE 4096
uint16_t g_cmd_seqno = 0;
unsigned int crc32_table[256];

/*ID number of command sent to ncp*/
uint32_t mcu_last_cmd_sent;

static struct
{
    int initialized;

    unsigned int bp; /* buffer pointer */
    char *inbuf;

    const struct ncp_host_cli_command *commands[MAX_COMMANDS];
    unsigned int num_commands;
    bool echo_disabled;

} ncp_host_cli;

static char mcu_string_command_buff[MCU_CLI_STRING_SIZE];

#ifdef CONFIG_SPI_BRIDGE
AT_NONCACHEABLE_SECTION_INIT(uint8_t mcu_tlv_command_buff[NCP_HOST_COMMAND_LEN]) = {0};
#else
static uint8_t mcu_tlv_command_buff[NCP_HOST_COMMAND_LEN] = {0};
#endif

/* LPUART1: NCP Host input uart */
#define NCP_HOST_INPUT_UART_CLK_FREQ  BOARD_DebugConsoleSrcFreq()
#define NCP_HOST_INPUT_UART           LPUART1
#define NCP_HOST_INPUT_UART_IRQ       LPUART1_IRQn
#define NCP_HOST_INPUT_UART_NVIC_PRIO 5

lpuart_rtos_handle_t ncp_host_input_uart_handle;
struct _lpuart_handle t_ncp_host_input_uart_handle;

static uint8_t background_buffer[NCP_HOST_INPUT_UART_BUF_SIZE];

lpuart_rtos_config_t ncp_host_input_uart_config = {
    .baudrate    = BOARD_DEBUG_UART_BAUDRATE,
    .parity      = kLPUART_ParityDisabled,
    .stopbits    = kLPUART_OneStopBit,
    .buffer      = background_buffer,
    .buffer_size = sizeof(background_buffer),
};

static os_thread_t ncp_host_input_thread;
static os_thread_stack_define(ncp_host_input_stack, 1024);

uint8_t recv_buffer[NCP_HOST_INPUT_UART_SIZE];

extern power_cfg_t global_power_config;
extern uint8_t mcu_device_status;
os_semaphore_t gpio_wakelock;

os_thread_t ping_sock_thread;
static os_thread_stack_define(ping_sock_stack, 1024);

os_thread_t ncp_iperf_tx_thread, ncp_iperf_rx_thread;
static os_thread_stack_define(ncp_iperf_tx_stack, 1024);
static os_thread_stack_define(ncp_iperf_rx_stack, 1024);
/* Find the command 'name' in the bridge ncp_host_cli commands table.
 * If len is 0 then full match will be performed else upto len bytes.
 * Returns: a pointer to the corresponding ncp_host_cli_command struct or NULL.
 */
const struct ncp_host_cli_command *lookup_command(char *name, int len)
{
    int i = 0;
    int n = 0;

    while (i < MAX_COMMANDS && n < ncp_host_cli.num_commands)
    {
        if (ncp_host_cli.commands[i]->name == NULL)
        {
            i++;
            continue;
        }
        /* See if partial or full match is expected */
        if (len != 0)
        {
            if (!strncmp(ncp_host_cli.commands[i]->name, name, len))
                return ncp_host_cli.commands[i];
        }
        else
        {
            if (!strcmp(ncp_host_cli.commands[i]->name, name))
                return ncp_host_cli.commands[i];
        }

        i++;
        n++;
    }

    return NULL;
}

/* Parse input line and locate arguments (if any), keeping count of the number
 * of arguments and their locations.  Look up and call the corresponding ncp_host_cli
 * function if one is found and pass it the argv array.
 *
 * Returns: WM_SUCCESS on success: the input line contained at least a function name and
 *          that function exists and command is processed successfully.
 *          -WM_FAIL on failuer: the input line contained at least a function name and
 *          that function exists and command is processed failed.
 *          WM_LOOKUP_FAIL on lookup failure: there is no corresponding function for the
 *          input line.
 *          WM_INVAILD_FAIL on invalid syntax: the arguments list couldn't be parsed
 *          WM_INVAILD_STRING_FAIL on invalid string command input.
 */
static int handle_input(char *inbuf)
{
    struct
    {
        unsigned inArg : 1;
        unsigned inQuote : 1;
        unsigned done : 1;
    } stat;
    static char *argv[32];
    int argc                                   = 0;
    int i                                      = 0;
    int j                                      = 0;
    const struct ncp_host_cli_command *command = NULL;
    const char *p;

    (void)memset((void *)&argv, 0, sizeof(argv));
    (void)memset(&stat, 0, sizeof(stat));

    /*
     * Some terminals add CRLF to the input buffer.
     * Sometimes the CR and LF characters maybe misplaced (it maybe added at the
     * start or at the end of the buffer). Therefore, strip all CRLF (0x0d, 0x0a).
     */
    for (j = 0; j < MCU_CLI_STRING_SIZE; j++)
    {
        if (inbuf[j] == 0x0D || inbuf[j] == 0x0A)
        {
            if (j < (MCU_CLI_STRING_SIZE - 1))
                (void)memmove((inbuf + j), inbuf + j + 1, (MCU_CLI_STRING_SIZE - j));
            inbuf[MCU_CLI_STRING_SIZE] = 0x00;
        }
    }

    do
    {
        switch (inbuf[i])
        {
            case '\0':
                if (stat.inQuote != 0U)
                    return WM_INVAILD_FAIL;
                stat.done = 1;
                break;

            case '"':
                if (i > 0 && inbuf[i - 1] == '\\' && stat.inArg)
                {
                    (void)memcpy(&inbuf[i - 1], &inbuf[i], strlen(&inbuf[i]) + 1);
                    --i;
                    break;
                }
                if (!stat.inQuote && stat.inArg)
                    break;
                if (stat.inQuote && !stat.inArg)
                    return WM_INVAILD_FAIL;

                if (!stat.inQuote && !stat.inArg)
                {
                    stat.inArg   = 1;
                    stat.inQuote = 1;
                    argc++;
                    argv[argc - 1] = &inbuf[i + 1];
                }
                else if (stat.inQuote && stat.inArg)
                {
                    stat.inArg   = 0;
                    stat.inQuote = 0;
                    inbuf[i]     = '\0';
                }
                else
                { /* Do Nothing */
                }
                break;

            case ' ':
                if (i > 0 && inbuf[i - 1] == '\\' && stat.inArg)
                {
                    (void)memcpy(&inbuf[i - 1], &inbuf[i], strlen(&inbuf[i]) + 1);
                    --i;
                    break;
                }
                if (!stat.inQuote && stat.inArg)
                {
                    stat.inArg = 0;
                    inbuf[i]   = '\0';
                }
                break;

            default:
                if (!stat.inArg)
                {
                    stat.inArg = 1;
                    argc++;
                    argv[argc - 1] = &inbuf[i];
                }
                break;
        }
    } while (!stat.done && ++i < MCU_CLI_STRING_SIZE);

    if (stat.inQuote != 0U)
        return WM_INVAILD_FAIL;

    if (argc < 1)
        return WM_INVAILD_STRING_FAIL;

    if (!ncp_host_cli.echo_disabled)
        (void)PRINTF("\r\n");

    /*
     * Some comamands can allow extensions like foo.a, foo.b and hence
     * compare commands before first dot.
     */
    i       = ((p = strchr(argv[0], '.')) == NULL) ? 0 : (p - argv[0]);
    command = lookup_command(argv[0], i);
    if (command == NULL)
        return WM_LOOKUP_FAIL;

    return command->function(argc, argv);
}

enum
{
    BASIC_KEY,
    EXT_KEY_FIRST_SYMBOL,
    EXT_KEY_SECOND_SYMBOL,
};

/* Get an input line.
 *
 * Returns: 1 if there is input, 0 if the line should be ignored. */
static int get_input(char *inbuf, unsigned int *bp)
{
    static int state = BASIC_KEY;
    static char second_char;
    int ret;
    size_t n;

    while (true)
    {
        /*Receive string command from input uart.*/
        ret = LPUART_RTOS_Receive(&ncp_host_input_uart_handle, recv_buffer, sizeof(recv_buffer), &n);
        if (ret == kStatus_LPUART_RxRingBufferOverrun)
        {
            /* Notify about hardware buffer overrun and un-received buffer content */
            memset(background_buffer, 0, NCP_HOST_INPUT_UART_BUF_SIZE);
            memset(inbuf, 0, MCU_CLI_STRING_SIZE);
            mcu_e("Ring buffer overrun, please enter string command again");
            continue;
        }
        inbuf[*bp] = recv_buffer[0];

        if (state == EXT_KEY_SECOND_SYMBOL)
        {
            if (second_char == 0x4F)
            {
                if (inbuf[*bp] == 0x4D)
                {
                    /* Num. keypad ENTER */
                    inbuf[*bp] = '\0';
                    *bp        = 0;
                    state      = BASIC_KEY;
                    return 1;
                }
            }
        }

        if (state == EXT_KEY_FIRST_SYMBOL)
        {
            second_char = inbuf[*bp];
            if (inbuf[*bp] == 0x4F)
            {
                state = EXT_KEY_SECOND_SYMBOL;
                continue;
            }
            if (inbuf[*bp] == 0x5B)
            {
                state = EXT_KEY_SECOND_SYMBOL;
                continue;
            }
        }
        if (inbuf[*bp] == 0x1B)
        {
            /* We may be seeing a first character from a
               extended key */
            state = EXT_KEY_FIRST_SYMBOL;
            continue;
        }
        state = BASIC_KEY;

        if (inbuf[*bp] == END_CHAR)
        { /* end of input line */
            inbuf[*bp] = '\0';
            *bp        = 0;
            return 1;
        }

        if ((inbuf[*bp] == 0x08) || /* backspace */
            (inbuf[*bp] == 0x7f))
        { /* DEL */
            if (*bp > 0)
            {
                (*bp)--;
                if (!ncp_host_cli.echo_disabled)
                    (void)PRINTF("%c %c", 0x08, 0x08);
            }
            continue;
        }

        if (inbuf[*bp] == '\t')
        {
            inbuf[*bp] = '\0';
            continue;
        }

        if (!ncp_host_cli.echo_disabled)
            (void)PRINTF("%c", inbuf[*bp]);

        (*bp)++;
        if (*bp >= MCU_CLI_STRING_SIZE)
        {
            (void)PRINTF("Error: input buffer overflow\r\n");
            (void)PRINTF(PROMPT);
            *bp = 0;
            return 0;
        }
    }
}

/* Print out a bad command string, including a hex
 * representation of non-printable characters.
 * Non-printable characters show as "\0xXX".
 */
static void print_bad_command(char *cmd_string)
{
    if (cmd_string != NULL)
    {
        unsigned char *c = (unsigned char *)cmd_string;
        (void)PRINTF("command '");
        while (*c != '\0')
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

/* Built-in "help" command: prints all registered commands and their help
 * text string, if any. */
int help_command(int argc, char **argv)
{
    int i, n;

    (void)PRINTF("\r\n");
    for (i = 0, n = 0; i < MAX_COMMANDS && n < ncp_host_cli.num_commands; i++)
    {
        if (ncp_host_cli.commands[i]->name != NULL)
        {
            (void)PRINTF("%s %s\r\n", ncp_host_cli.commands[i]->name,
                         ncp_host_cli.commands[i]->help ? ncp_host_cli.commands[i]->help : "");
            n++;
        }
    }

    return WM_SUCCESS;
}

static struct ncp_host_cli_command built_ins[] = {
    {"help", NULL, help_command},
};

/*
 * Register bridge ncp_host_cli command API
 */

int ncp_host_cli_register_command(const struct ncp_host_cli_command *command)
{
    int i;
    if (!command->name || !command->function)
        return 1;

    if (ncp_host_cli.num_commands < MAX_COMMANDS)
    {
        /* Check if the command has already been registered.
         * Return 0, if it has been registered.
         */
        for (i = 0; i < ncp_host_cli.num_commands; i++)
        {
            if (ncp_host_cli.commands[i] == command)
                return 0;
        }
        ncp_host_cli.commands[ncp_host_cli.num_commands++] = command;
        return 0;
    }

    return 1;
}

int ncp_host_cli_unregister_command(const struct ncp_host_cli_command *command)
{
    int i;
    if (!command->name || !command->function)
        return 1;

    for (i = 0; i < ncp_host_cli.num_commands; i++)
    {
        if (ncp_host_cli.commands[i] == command)
        {
            ncp_host_cli.num_commands--;
            int remaining_cmds = ncp_host_cli.num_commands - i;
            if (remaining_cmds > 0)
            {
                (void)memmove(&ncp_host_cli.commands[i], &ncp_host_cli.commands[i + 1],
                              (remaining_cmds * sizeof(struct ncp_host_cli_command *)));
            }
            ncp_host_cli.commands[ncp_host_cli.num_commands] = NULL;
            return 0;
        }
    }

    return 1;
}

int ncp_host_cli_register_commands(const struct ncp_host_cli_command *commands, int num_commands)
{
    int i;
    for (i = 0; i < num_commands; i++)
        if (ncp_host_cli_register_command(commands++) != 0)
            return 1;
    return 0;
}

int ncp_host_cli_unregister_commands(const struct ncp_host_cli_command *commands, int num_commands)
{
    int i;
    for (i = 0; i < num_commands; i++)
        if (ncp_host_cli_unregister_command(commands++) != 0)
            return 1;

    return 0;
}

#ifdef CONFIG_USB_BRIDGE
extern cdc_instance_struct_t g_cdc;
os_semaphore_t usb_host_send_pipe_seam;

void put_usb_host_send_pipe_sem(void)
{
    os_semaphore_put(&usb_host_send_pipe_seam);
}

void USB_HostCdcDataOutCb(void *param, uint8_t *data, uint32_t dataLength, usb_status_t status)
{
    usb_echo("send dataLength :%d \r\n", dataLength);
    put_usb_host_send_pipe_sem();
}

int usb_host_send_data(uint8_t *data, uint16_t data_len)
{
    uint16_t packet_size        = 0;
    uint16_t remaining_data_len = data_len;

    PRINTF("transfer_size :%d!\r\n", data_len);

    while (remaining_data_len > 0)
    {
        packet_size = (remaining_data_len > NCP_HOST_COMMAND_LEN) ? NCP_HOST_COMMAND_LEN : remaining_data_len;

        USB_HostCdcDataSend(g_cdc.classHandle, (uint8_t *)data + data_len - remaining_data_len, packet_size,
                            USB_HostCdcDataOutCb, &g_cdc);

        os_semaphore_get(&usb_host_send_pipe_seam, OS_WAIT_FOREVER);

        remaining_data_len -= packet_size;
    }

    return WM_SUCCESS;
}

int usb_host_send_cmd(uint16_t transfer_size)
{
    usb_host_send_data((uint8_t *)&mcu_tlv_command_buff[0], transfer_size);

    return WM_SUCCESS;
}

#endif

MCU_NCPCmd_DS_COMMAND *ncp_host_get_command_buffer()
{
    return (MCU_NCPCmd_DS_COMMAND *)(mcu_tlv_command_buff);
}

static void ncp_host_input_task(void *pvParameters)
{
    ncp_host_input_uart_config.srcclk = NCP_HOST_INPUT_UART_CLK_FREQ;
    ncp_host_input_uart_config.base   = NCP_HOST_INPUT_UART;

    NVIC_SetPriority(NCP_HOST_INPUT_UART_IRQ, NCP_HOST_INPUT_UART_NVIC_PRIO);

    if (LPUART_RTOS_Init(&ncp_host_input_uart_handle, &t_ncp_host_input_uart_handle, &ncp_host_input_uart_config) !=
        WM_SUCCESS)
    {
        vTaskSuspend(NULL);
    }

    /* Receive user input and send it back to terminal. */
    while (1)
    {
        int ret;

        if (ncp_host_cli.inbuf == NULL)
        {
            ncp_host_cli.inbuf = mcu_string_command_buff;
            ncp_host_cli.bp    = 0;
        }

        if (get_input(ncp_host_cli.inbuf, &ncp_host_cli.bp))
        {
            /*Wait for command response semaphore.*/
            mcu_get_command_resp_sem();

            if (strcmp(ncp_host_cli.inbuf, HALT_MSG) == 0)
                break;

            ret = handle_input(ncp_host_cli.inbuf);
            if (ret == WM_LOOKUP_FAIL)
            {
                print_bad_command(ncp_host_cli.inbuf);
                /*If string commands don't match with registered commands, release command response semaphore.*/
                mcu_put_command_resp_sem();
            }
            else if (ret == WM_INVAILD_FAIL)
            {
                (void)PRINTF("syntax error\r\n");
                /*If the format of string command is error, release command response semaphore.*/
                mcu_put_command_resp_sem();
            }
            else if (ret == -WM_FAIL)
            {
                (void)PRINTF("Failed to process '%s' command\r\n", ncp_host_cli.inbuf);
                /*If failed to process string command, release command response semaphore.*/
                mcu_put_command_resp_sem();
            }
            else /*Send tlv command to ncp bridge app */
                ncp_host_send_tlv_command();

            (void)PRINTF(PROMPT);
        }
    }
}

/* ping variables */
extern ping_msg_t ping_msg;
int ping_seq_no;
uint32_t ping_time;
uint32_t recvd;

/* Display the final result of ping */
static void display_ping_result(int total, int recvd)
{
    int dropped = total - recvd;
    (void)PRINTF("\r\n--- ping statistics ---\r\n");
    (void)PRINTF("%d packets transmitted, %d received,", total, recvd);
    if (dropped != 0)
        (void)PRINTF(" +%d errors,", dropped);
    (void)PRINTF(" %d%% packet loss\r\n", (dropped * 100) / total);
}

/** Prepare a echo ICMP request */
static void ping_prepare_echo(struct icmp_echo_hdr *iecho, uint16_t len, uint16_t seq_no)
{
    size_t i;
    size_t data_len = len - sizeof(struct icmp_echo_hdr);

    iecho->type   = ICMP_ECHO;
    iecho->code   = 0;
    iecho->chksum = 0;
    iecho->id     = PING_ID;
    iecho->seqno  = PP_HTONS(seq_no);

    /* fill the additional data buffer with some data */
    for (i = 0; i < data_len; i++)
    {
        ((char *)iecho)[sizeof(struct icmp_echo_hdr) + i] = (char)i;
    }

    iecho->chksum = inet_chksum(iecho, len);
}

/* Send an ICMP echo request by NCP_BRIDGE_CMD_WLAN_SOCKET_SENDTO command and get ICMP echo reply by
 * NCP_BRIDGE_CMD_WLAN_SOCKET_RECVFROM command. Print ping statistics in NCP_BRIDGE_CMD_WLAN_SOCKET_RECVFROM
 * command response, and print ping result in ping_sock_task.
 */
static void ping_sock_task(void *pvParameters)
{
    struct icmp_echo_hdr *iecho;

    while (1)
    {
        recvd       = 0;
        ping_seq_no = -1;

        /* demo ping task wait for user input ping command from console */
        (void)os_event_notify_get(OS_WAIT_FOREVER);

        (void)PRINTF("PING %s (%s) %u(%u) bytes of data\r\n", ping_msg.ip_addr, ping_msg.ip_addr, ping_msg.size,
                     ping_msg.size + sizeof(struct ip_hdr) + sizeof(struct icmp_echo_hdr));

        int i = 1;
        /* Ping size is: size of ICMP header + size of payload */
        uint16_t ping_size = sizeof(struct icmp_echo_hdr) + ping_msg.size;

        iecho = (struct icmp_echo_hdr *)os_mem_alloc(ping_size);
        if (!iecho)
        {
            (void)PRINTF("failed to allocate memory for ping packet!\r\n");
            continue;
        }

        while (i <= ping_msg.count)
        {
            /*Wait for command response semaphore.*/
            mcu_get_command_resp_sem();

            /* Prepare ping command */
            ping_prepare_echo(iecho, (uint16_t)ping_size, i);

            mcu_get_command_lock();
            MCU_NCPCmd_DS_COMMAND *ping_sock_command = ncp_host_get_command_buffer();
            ping_sock_command->header.cmd            = NCP_BRIDGE_CMD_WLAN_SOCKET_SENDTO;
            ping_sock_command->header.size           = NCP_BRIDGE_CMD_HEADER_LEN;
            ping_sock_command->header.result         = NCP_BRIDGE_CMD_RESULT_OK;
            ping_sock_command->header.msg_type       = NCP_BRIDGE_MSG_TYPE_CMD;

            NCP_CMD_SOCKET_SENDTO_CFG *ping_sock_tlv =
                (NCP_CMD_SOCKET_SENDTO_CFG *)&ping_sock_command->params.wlan_socket_sendto;
            ping_sock_tlv->handle = ping_msg.handle;
            ping_sock_tlv->port   = ping_msg.port;
            memcpy(ping_sock_tlv->ip_addr, ping_msg.ip_addr, strlen(ping_msg.ip_addr) + 1);
            memcpy(ping_sock_tlv->send_data, iecho, ping_size);
            ping_sock_tlv->size = ping_size;

            /*cmd size*/
            ping_sock_command->header.size += sizeof(NCP_CMD_SOCKET_SENDTO_CFG) - sizeof(char);
            ping_sock_command->header.size += ping_size;

            /* Send ping TLV command */
            ncp_host_send_tlv_command();
            /* Get the current ticks as the start time */
            ping_time = os_ticks_get();

            /* sequence number */
            ping_seq_no = i;

            /* wait for NCP_BRIDGE_CMD_WLAN_SOCKET_SENDTO command response */
            (void)os_event_notify_get(OS_WAIT_FOREVER);

            /*Wait for command response semaphore.*/
            mcu_get_command_resp_sem();

            mcu_get_command_lock();
            /* Prepare get-ping-result command */
            MCU_NCPCmd_DS_COMMAND *ping_res_command = ncp_host_get_command_buffer();
            ping_res_command->header.cmd            = NCP_BRIDGE_CMD_WLAN_SOCKET_RECVFROM;
            ping_res_command->header.size           = NCP_BRIDGE_CMD_HEADER_LEN;
            ping_res_command->header.result         = NCP_BRIDGE_CMD_RESULT_OK;
            ping_res_command->header.msg_type       = NCP_BRIDGE_MSG_TYPE_CMD;

            NCP_CMD_SOCKET_RECVFROM_CFG *ping_res_sock_tlv =
                (NCP_CMD_SOCKET_RECVFROM_CFG *)&ping_res_command->params.wlan_socket_recvfrom;
            ping_res_sock_tlv->handle    = ping_msg.handle;
            ping_res_sock_tlv->recv_size = ping_msg.size + IP_HEADER_LEN;
            ping_res_sock_tlv->timeout   = PING_RECVFROM_TIMEOUT;

            /*cmd size*/
            ping_res_command->header.size += sizeof(NCP_CMD_SOCKET_RECVFROM_CFG);

            /* Send get-ping-result TLV command */
            ncp_host_send_tlv_command();

            /* wait for NCP_BRIDGE_CMD_WLAN_SOCKET_RECVFROM command response */
            (void)os_event_notify_get(OS_WAIT_FOREVER);

            os_thread_sleep(os_msec_to_ticks(1000));

            i++;
        }
        os_mem_free((void *)iecho);
        display_ping_result((int)ping_msg.count, recvd);
    }
}

static void uart_init_crc32(void)
{
    int i, j;
    unsigned int c;
    for (i = 0; i < 256; ++i)
    {
        for (c = i << 24, j = 8; j > 0; --j)
            c = c & 0x80000000 ? (c << 1) ^ CRC32_POLY : (c << 1);
        crc32_table[i] = c;
    }
}

#ifdef CONFIG_CRC32_HW_ACCELERATE
uint32_t uart_get_crc32(uint8_t *buf, uint16_t len)
{
    uint32_t crc;

    CRC_WriteSeed(CRC, 0xffffffffU);
    CRC_WriteData(CRC, buf, len);
    crc = CRC_Get32bitResult(CRC);

    return ~crc;
}
#else
uint32_t uart_get_crc32(uint8_t *buf, uint16_t len)
{
    uint8_t *p;
    unsigned int crc;
    crc = 0xffffffff;
    for (p = buf; len > 0; ++p, --len)
        crc = (crc << 8) ^ (crc32_table[(crc >> 24) ^ *p]);
    return ~crc;
}
#endif

int ncp_host_send_tlv_command()
{
    int ret                        = WM_SUCCESS;
    uint32_t bridge_chksum         = 0;
    uint16_t cmd_len               = 0, index;
    MCU_NCPCmd_DS_COMMAND *mcu_cmd = ncp_host_get_command_buffer();
#ifdef CONFIG_SPI_BRIDGE
    uint16_t total_len = 0;
#endif
    cmd_len = mcu_cmd->header.size;
    /* set cmd seqno */
    mcu_cmd->header.seqnum = g_cmd_seqno;

    if (cmd_len + MCU_CHECKSUM_LEN >= NCP_HOST_COMMAND_LEN)
    {
        PRINTF("The command length exceeds the receiving capacity of mcu bridge application!\r\n");
        ret = -WM_FAIL;
        goto done;
    }
    else if (cmd_len == 0)
    {
        ret = -WM_FAIL;
        goto done;
    }

    bridge_chksum = uart_get_crc32(mcu_tlv_command_buff, cmd_len);
    index         = cmd_len;

    mcu_tlv_command_buff[index]     = bridge_chksum & 0xff;
    mcu_tlv_command_buff[index + 1] = (bridge_chksum & 0xff00) >> 8;
    mcu_tlv_command_buff[index + 2] = (bridge_chksum & 0xff0000) >> 16;
    mcu_tlv_command_buff[index + 3] = (bridge_chksum & 0xff000000) >> 24;

    if (cmd_len >= NCP_BRIDGE_CMD_HEADER_LEN)
    {
        gpio_pin_config_t gpio_out_config = {
            kGPIO_DigitalOutput,
            0,
        };
        /* Wakeup MCU device through GPIO if host configured GPIO wake mode */
        if ((global_power_config.wake_mode == WAKE_MODE_GPIO) && (mcu_device_status == MCU_DEVICE_STATUS_SLEEP))
        {
            //            GPIO_PortInit(GPIO, 0);
            //            GPIO_PinInit(GPIO, 0, 5, &gpio_out_config);
            mcu_d("get gpio_wakelock after GPIO wakeup\r\n");
            /* Block here to wait for MCU device complete the PM3 exit process */
            os_semaphore_get(&gpio_wakelock, OS_WAIT_FOREVER);
            gpio_out_config.outputLogic = 1;
            //            GPIO_PortInit(GPIO, 0);
            //            GPIO_PinInit(GPIO, 0, 5, &gpio_out_config);
            os_semaphore_put(&gpio_wakelock);
        }
        /* write response */
#ifdef CONFIG_NCP_UART
        ret = LPUART_RTOS_Send(&ncp_host_tlv_uart_handle, mcu_tlv_command_buff, cmd_len + MCU_CHECKSUM_LEN);
#elif defined(CONFIG_USB_BRIDGE)
        ret = usb_host_send_cmd(cmd_len + MCU_CHECKSUM_LEN);
#elif defined(CONFIG_SPI_BRIDGE)
        total_len = cmd_len + MCU_CHECKSUM_LEN;
        ret = ncp_host_spi_master_transfer((uint8_t *)&mcu_tlv_command_buff[0], total_len, NCP_HOST_MASTER_TX, true);
        if (ret != WM_SUCCESS)
        {
            mcu_e("failed to write response");
            ret = -WM_FAIL;
            goto done;
        }
#endif

        if (ret != WM_SUCCESS)
        {
            mcu_e("failed to write response");
            ret = -WM_FAIL;
            goto done;
        }
        /*Increase command sequence number*/
        g_cmd_seqno++;
        /*Record command id*/
        mcu_last_cmd_sent = mcu_cmd->header.cmd;
#ifdef CONFIG_NCP_HOST_IO_DUMP
        PRINTF("TLV Command:\r\n");
        dump_hex(mcu_tlv_command_buff, cmd_len + MCU_CHECKSUM_LEN);
#endif
    }
    else
    {
        mcu_e("command length is less than ncp_host_app header length (%d), cmd_len = %d", NCP_BRIDGE_CMD_HEADER_LEN,
              cmd_len);
        ret = -WM_FAIL;
        goto done;
    }

done:
    /*If failed to send tlv command, release command response semaphore to allow processing next string command.*/
    if (ret == -WM_FAIL)
        mcu_put_command_resp_sem();

    mcu_cmd->header.size = 0;
    /*Release mcu command lock*/
    mcu_put_command_lock();

    return ret;
}

/*iperf command tx and rx */
extern iperf_msg_t iperf_msg;
#define NCP_IPERF_PER_PKG_SIZE 1448
#define IPERF_RECV_TIMEOUT     3000
/** A const buffer to send from: we want to measure sending, not copying! */
static const char lwiperf_txbuf_const[NCP_IPERF_PER_PKG_SIZE] = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2',
    '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5',
    '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8',
    '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1',
    '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
    '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6',
    '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2',
    '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5',
    '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8',
    '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1',
    '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
    '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6',
    '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2',
    '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5',
    '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8',
    '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1',
    '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
    '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6',
    '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2',
    '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5',
    '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8',
    '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1',
    '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
    '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6',
    '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2',
    '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5',
    '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8',
    '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1',
    '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9',
};

int iperf_send_setting(void)
{
    if (iperf_msg.iperf_set.iperf_type == NCP_IPERF_TCP_TX || iperf_msg.iperf_set.iperf_type == NCP_IPERF_TCP_RX)
    {
        MCU_NCPCmd_DS_COMMAND *iperf_command = ncp_host_get_command_buffer();
        iperf_command->header.cmd            = NCP_BRIDGE_CMD_WLAN_SOCKET_SEND;
        iperf_command->header.size           = NCP_BRIDGE_CMD_HEADER_LEN;
        iperf_command->header.result         = NCP_BRIDGE_CMD_RESULT_OK;
        iperf_command->header.msg_type       = NCP_BRIDGE_MSG_TYPE_CMD;

        NCP_CMD_SOCKET_SEND_CFG *ncp_iperf_tlv = (NCP_CMD_SOCKET_SEND_CFG *)&iperf_command->params.wlan_socket_send;
        ncp_iperf_tlv->handle                  = iperf_msg.handle;
        ncp_iperf_tlv->size                    = sizeof(iperf_set_t);
        memcpy(ncp_iperf_tlv->send_data, (char *)(&iperf_msg.iperf_set), sizeof(iperf_set_t));

        /*cmd size*/
        iperf_command->header.size += sizeof(NCP_CMD_SOCKET_SEND_CFG);
        iperf_command->header.size += sizeof(iperf_set_t);
        (void)memcpy((char *)lwiperf_txbuf_const, (char *)(&iperf_msg.iperf_set), sizeof(iperf_set_t));
    }
    else if (iperf_msg.iperf_set.iperf_type == NCP_IPERF_UDP_TX || iperf_msg.iperf_set.iperf_type == NCP_IPERF_UDP_RX)
    {
        MCU_NCPCmd_DS_COMMAND *iperf_command = ncp_host_get_command_buffer();
        iperf_command->header.cmd            = NCP_BRIDGE_CMD_WLAN_SOCKET_SENDTO;
        iperf_command->header.size           = NCP_BRIDGE_CMD_HEADER_LEN;
        iperf_command->header.result         = NCP_BRIDGE_CMD_RESULT_OK;
        iperf_command->header.msg_type       = NCP_BRIDGE_MSG_TYPE_CMD;

        NCP_CMD_SOCKET_SENDTO_CFG *ncp_iperf_tlv =
            (NCP_CMD_SOCKET_SENDTO_CFG *)&iperf_command->params.wlan_socket_sendto;
        ncp_iperf_tlv->handle = iperf_msg.handle;
        ncp_iperf_tlv->size   = sizeof(iperf_set_t);
        ncp_iperf_tlv->port   = iperf_msg.port;
        memcpy(ncp_iperf_tlv->ip_addr, iperf_msg.ip_addr, strlen(iperf_msg.ip_addr) + 1);
        memcpy(ncp_iperf_tlv->send_data, (char *)(&iperf_msg.iperf_set), sizeof(iperf_set_t));
        /*cmd size*/
        iperf_command->header.size += sizeof(NCP_CMD_SOCKET_SENDTO_CFG) - sizeof(char);
        iperf_command->header.size += sizeof(iperf_set_t);
        (void)memcpy((char *)lwiperf_txbuf_const, (char *)(&iperf_msg.iperf_set), sizeof(iperf_set_t));
    }
    else
    {
        (void)PRINTF("iperf type is error\r\n");
        return false;
    }
    /* Send iperf TLV command */
    ncp_host_send_tlv_command();
    return true;
}

unsigned long iperf_timer_start = 0, iperf_timer_end = 0;
void ncp_iperf_report(long long total_size)
{
    unsigned long rate       = 0;
    unsigned long total_time = 0;

    total_time = iperf_timer_end - iperf_timer_start;

    rate = (total_size * 1000) / total_time;
    rate = rate * 8 / 1024;

    (void)PRINTF("iperf rate = %lu kbit/s\r\n", rate);
}

void iperf_tcp_tx(void)
{
    MCU_NCPCmd_DS_COMMAND *iperf_command = ncp_host_get_command_buffer();

    if (iperf_msg.iperf_set.iperf_type == NCP_IPERF_TCP_TX)
    {
        iperf_command->header.cmd      = NCP_BRIDGE_CMD_WLAN_SOCKET_SEND;
        iperf_command->header.size     = NCP_BRIDGE_CMD_HEADER_LEN;
        iperf_command->header.result   = NCP_BRIDGE_CMD_RESULT_OK;
        iperf_command->header.msg_type = NCP_BRIDGE_MSG_TYPE_CMD;

        NCP_CMD_SOCKET_SEND_CFG *ncp_iperf_tlv = (NCP_CMD_SOCKET_SEND_CFG *)&iperf_command->params.wlan_socket_send;
        ncp_iperf_tlv->handle                  = iperf_msg.handle;
        ncp_iperf_tlv->size                    = iperf_msg.per_size;
        memcpy(ncp_iperf_tlv->send_data, lwiperf_txbuf_const, iperf_msg.per_size);

        /*cmd size*/
        iperf_command->header.size += sizeof(NCP_CMD_SOCKET_SEND_CFG);
        iperf_command->header.size += iperf_msg.per_size;
    }
    else if (iperf_msg.iperf_set.iperf_type == NCP_IPERF_UDP_TX)
    {
        iperf_command->header.cmd      = NCP_BRIDGE_CMD_WLAN_SOCKET_SENDTO;
        iperf_command->header.size     = NCP_BRIDGE_CMD_HEADER_LEN;
        iperf_command->header.result   = NCP_BRIDGE_CMD_RESULT_OK;
        iperf_command->header.msg_type = NCP_BRIDGE_MSG_TYPE_CMD;

        NCP_CMD_SOCKET_SENDTO_CFG *ncp_iperf_tlv =
            (NCP_CMD_SOCKET_SENDTO_CFG *)&iperf_command->params.wlan_socket_sendto;
        ncp_iperf_tlv->handle = iperf_msg.handle;
        ncp_iperf_tlv->size   = iperf_msg.per_size;
        ncp_iperf_tlv->port   = iperf_msg.port;
        memcpy(ncp_iperf_tlv->send_data, lwiperf_txbuf_const, iperf_msg.per_size);
        memcpy(ncp_iperf_tlv->ip_addr, iperf_msg.ip_addr, strlen(iperf_msg.ip_addr) + 1);

        /*cmd size*/
        iperf_command->header.size += sizeof(NCP_CMD_SOCKET_SENDTO_CFG) - sizeof(char);
        iperf_command->header.size += iperf_msg.per_size;
    }

    /* Send iperf TLV command */
    ncp_host_send_tlv_command();
}

void iperf_tcp_rx(void)
{
    MCU_NCPCmd_DS_COMMAND *ncp_iperf_command = ncp_host_get_command_buffer();

    if (iperf_msg.iperf_set.iperf_type == NCP_IPERF_TCP_RX)
    {
        ncp_iperf_command->header.cmd      = NCP_BRIDGE_CMD_WLAN_SOCKET_RECV;
        ncp_iperf_command->header.size     = NCP_BRIDGE_CMD_HEADER_LEN;
        ncp_iperf_command->header.result   = NCP_BRIDGE_CMD_RESULT_OK;
        ncp_iperf_command->header.msg_type = NCP_BRIDGE_MSG_TYPE_CMD;

        NCP_CMD_SOCKET_RECEIVE_CFG *ncp_iperf_res_sock_tlv =
            (NCP_CMD_SOCKET_RECEIVE_CFG *)&ncp_iperf_command->params.wlan_socket_receive;
        ncp_iperf_res_sock_tlv->handle    = iperf_msg.handle;
        ncp_iperf_res_sock_tlv->recv_size = iperf_msg.per_size;
        ncp_iperf_res_sock_tlv->timeout   = IPERF_TCP_RECV_TIMEOUT;

        /*cmd size*/
        ncp_iperf_command->header.size += sizeof(NCP_CMD_SOCKET_RECEIVE_CFG);
    }
    else if (iperf_msg.iperf_set.iperf_type == NCP_IPERF_UDP_RX)
    {
        ncp_iperf_command->header.cmd      = NCP_BRIDGE_CMD_WLAN_SOCKET_RECVFROM;
        ncp_iperf_command->header.size     = NCP_BRIDGE_CMD_HEADER_LEN;
        ncp_iperf_command->header.result   = NCP_BRIDGE_CMD_RESULT_OK;
        ncp_iperf_command->header.msg_type = NCP_BRIDGE_MSG_TYPE_CMD;

        NCP_CMD_SOCKET_RECVFROM_CFG *ncp_iperf_res_sock_tlv =
            (NCP_CMD_SOCKET_RECVFROM_CFG *)&ncp_iperf_command->params.wlan_socket_recvfrom;
        ncp_iperf_res_sock_tlv->handle    = iperf_msg.handle;
        ncp_iperf_res_sock_tlv->recv_size = iperf_msg.per_size;
        ncp_iperf_res_sock_tlv->timeout   = IPERF_UDP_RECV_TIMEOUT;

        /*cmd size*/
        ncp_iperf_command->header.size += sizeof(NCP_CMD_SOCKET_RECVFROM_CFG);
    }

    /* Send iperf TLV command */
    ncp_host_send_tlv_command();
}

static void ncp_iperf_tx_task(void *pvParameters)
{
    unsigned int pkg_num      = 0;
    long long send_total_size = 0;

    while (1)
    {
        /* demo ping task wait for user input ping command from console */
        (void)os_event_notify_get(OS_WAIT_FOREVER);
        send_total_size = iperf_msg.iperf_set.iperf_count * iperf_msg.per_size;

        mcu_get_command_resp_sem();
        mcu_get_command_lock();
        if (false == iperf_send_setting())
            continue;
        (void)PRINTF("ncp iperf tx start\r\n");
        pkg_num             = 0;
        iperf_msg.status[0] = 0;
        iperf_timer_start   = os_ticks_get();
        while (pkg_num < iperf_msg.iperf_set.iperf_count)
        {
            /*Wait for command response semaphore.*/
            mcu_get_command_resp_sem();
            if (iperf_msg.status[0] == (char)-WM_FAIL)
            {
                iperf_msg.status[0] = 0;
                mcu_put_command_resp_sem();
                break;
            }
            // else if (!(pkg_num % 100))
            //    (void)PRINTF("ncp bridge tx pkg_num = %d\r\n", pkg_num);

            mcu_get_command_lock();

            iperf_tcp_tx();

            pkg_num++;
        }
        iperf_timer_end = os_ticks_get();
        ncp_iperf_report(send_total_size);
        (void)PRINTF("ncp iperf tx run end\r\n");
    }
}

static void ncp_iperf_rx_task(void *pvParameters)
{
    unsigned int pkg_num         = 0;
    unsigned long long recv_size = 0, left_size = 0;

    while (1)
    {
        /* demo ping task wait for user input ping command from console */
        (void)os_event_notify_get(OS_WAIT_FOREVER);
        (void)PRINTF("ncp iperf rx start\r\n");
        mcu_get_command_resp_sem();
        mcu_get_command_lock();
        if (false == iperf_send_setting())
            continue;
        pkg_num             = 0;
        iperf_msg.status[1] = 0;
        recv_size           = 0;
        left_size           = iperf_msg.per_size * iperf_msg.iperf_set.iperf_count;
        iperf_timer_start   = os_ticks_get();
        while (left_size > 0)
        {
            /*Wait for command response semaphore.*/
            mcu_get_command_resp_sem();
            if (iperf_msg.status[1] == (char)-WM_FAIL)
            {
                (void)PRINTF("recv command run fail\r\n");
                iperf_msg.status[1] = 0;
                mcu_put_command_resp_sem();
                break;
            }
            mcu_get_command_lock();
            recv_size += iperf_msg.status[1];
            left_size -= iperf_msg.status[1];
            if (left_size > 0)
            {
                iperf_tcp_rx();
            }
            else
            {
                mcu_put_command_resp_sem();
                mcu_put_command_lock();
            }
            pkg_num++;
        }
        iperf_timer_end = os_ticks_get();
        ncp_iperf_report(recv_size);
        (void)PRINTF("ncp iperf rx end\r\n");
    }
}

int ncp_host_cli_init(void)
{
    int ret;
    static bool cli_init_done;
    if (cli_init_done)
        return WM_SUCCESS;

    (void)memset((void *)&ncp_host_cli, 0, sizeof(ncp_host_cli));

    /* add our built-in commands */
    if (ncp_host_cli_register_commands(&built_ins[0], sizeof(built_ins) / sizeof(struct ncp_host_cli_command)) != 0)
        return -WM_FAIL;

    /* Generate a table for a byte-wise 32-bit CRC calculation on the polynomial. */
    uart_init_crc32();

    ncp_host_cli_command_init();

    int n = 0;
    for (int i = 0; i < MAX_COMMANDS && n < ncp_host_cli.num_commands; i++)
    {
        if (ncp_host_cli.commands[i]->name != NULL)
        {
            (void)PRINTF("%s %s\r\n", ncp_host_cli.commands[i]->name,
                         ncp_host_cli.commands[i]->help ? ncp_host_cli.commands[i]->help : "");
            n++;
        }
    }

    ret = os_thread_create(&ncp_host_input_thread, "ncp host input task", ncp_host_input_task, 0, &ncp_host_input_stack,
                           OS_PRIO_2);
    if (ret != WM_SUCCESS)
    {
        (void)PRINTF("Error: Failed to create ncp host input uart thread: %d\r\n", ret);
        return -WM_FAIL;
    }

#ifdef CONFIG_USB_BRIDGE
    ret = os_semaphore_create(&usb_host_send_pipe_seam, "usb_host_send_pipe_seam");
    if (ret != WM_SUCCESS)
    {
        (void)PRINTF("failed to create usb_host_send_pipe_seam: %d", ret);
        return -WM_FAIL;
    }
    os_semaphore_get(&usb_host_send_pipe_seam, OS_WAIT_FOREVER);
#endif

    ret = os_semaphore_create(&gpio_wakelock, "gpio_wakelock");
    if (ret != WM_SUCCESS)
    {
        (void)PRINTF("failed to create gpio_wakelock: %d", ret);
        return -WM_FAIL;
    }

    ret = os_thread_create(&ping_sock_thread, "ping sock task", ping_sock_task, 0, &ping_sock_stack, OS_PRIO_2);
    if (ret != WM_SUCCESS)
    {
        (void)PRINTF("Error: Failed to create ping socket thread: %d\r\n", ret);
        return -WM_FAIL;
    }

    ret = os_thread_create(&ncp_iperf_tx_thread, "ncp iperf tx task", ncp_iperf_tx_task, 0, &ncp_iperf_tx_stack,
                           OS_PRIO_3);
    if (ret != WM_SUCCESS)
    {
        (void)PRINTF("Error: Failed to create ncp iperf thread: %d\r\n", ret);
        return -WM_FAIL;
    }

    ret = os_thread_create(&ncp_iperf_rx_thread, "ncp iperf rx task", ncp_iperf_rx_task, 0, &ncp_iperf_rx_stack,
                           OS_PRIO_3);
    if (ret != WM_SUCCESS)
    {
        (void)PRINTF("Error: Failed to create ncp iperf thread: %d\r\n", ret);
        return -WM_FAIL;
    }
    return ret;
}
