/** @file bridge_app.c
 *
 *  @brief  This file provides interface for receiving tlv responses and processing tlv responses.
 *
 *  Copyright 2008-2023 NXP
 *
 *  Licensed under the LA_OPT_NXP_Software_License.txt (the "Agreement")
 *
 */

#include <string.h>
#include <stdlib.h>
#include "fsl_debug_console.h"
#include "fsl_usart.h"
#include "FreeRTOS.h"
#include "board.h"
#include "task.h"
#include "fsl_usart_freertos.h"
#include "mcu_bridge_os.h"
#include "mcu_bridge_utils.h"
#include "mcu_bridge_cli.h"
#include "mcu_bridge_command.h"
#include "mcu_bridge_app.h"
#ifdef CONFIG_USB_BRIDGE
#include "usb_host_config.h"
#include "usb_host.h"
#include "usb_host_cdc.h"
#include "host_cdc.h"
#elif defined(CONFIG_SPI_BRIDGE)
#include "spi_master_app.h"
#endif

os_thread_t mcu_bridge_resp_thread;
uint8_t background_resp_buffer[256];
#define USART_SEND_SIZE 1
uint8_t send_buffer[USART_SEND_SIZE];
usart_rtos_handle_t mcu_ncp_uart_handle;
struct _usart_handle t_u_mcu_uart_resp_handle;
#define USART_NVIC_PRIO_USBUART 5

#define BRIDGE_QUEUE_SIZE 4

os_semaphore_t mcu_cmd_resp_sem;
os_mutex_t mcu_command_lock;

#define CONFIG_BRIDGE_STACK_SIZE 4096
static os_thread_stack_define(bridge_app_stack, CONFIG_BRIDGE_STACK_SIZE);

/*MCU bridge NCP uart*/
#define BOARD_DEBUG_UART_USBUART_FRG_CLK \
    (&(const clock_frg_clk_config_t){0, kCLOCK_FrgPllDiv, 255, 0}) /*!< Select FRG0 mux as frg_pll */
#define BOARD_DEBUG_UART_USBUART_CLK_ATTACH kFRG_to_FLEXCOMM0
#define BOARD_DEBUG_UART_USBUART_BASEADDR   (uint32_t) FLEXCOMM0
#define BOARD_DEBUG_UART_USBUART            USART0
#define BOARD_DEBUG_UART_USBUART_CLK_FREQ   CLOCK_GetFlexCommClkFreq(0)
#define BOARD_UART_USBUART_IRQ              FLEXCOMM0_IRQn

struct rtos_usart_config bridge_usart_config = {
    .baudrate    = BOARD_DEBUG_UART_BAUDRATE,
    .parity      = kUSART_ParityDisabled,
    .stopbits    = kUSART_OneStopBit,
    .buffer      = background_resp_buffer,
    .buffer_size = sizeof(background_resp_buffer),
};

extern uint32_t mcu_last_cmd_sent;
/*ID number of command response received from ncp*/
uint32_t mcu_last_resp_rcvd;

static uint8_t mcu_response_buff[MCU_BRIDGE_RESPONSE_LEN];

/**
 * @brief       This function judges if s1 and s2 are equal.
 *
 * @param s1   A pointer to string s1.
 * @param s2   A pointer to string s2.
 *
 * @return     Return 1 if s1 is equal to s2.
 */
int string_equal(const char *s1, const char *s2)
{
    size_t len = strlen(s1);

    if (len == strlen(s2) && !strncmp(s1, s2, len))
        return 1;
    return 0;
}

/**
 * @brief       This function convters string to decimal number.
 *
 * @param arg   A pointer to string.
 * @param dest  A pointer to number.
 * @param len   Length of string arg.
 *
 * @return      return 0 if string arg can be convert to decimal number.
 */
int get_uint(const char *arg, unsigned int *dest, unsigned int len)
{
    int i;
    unsigned int val = 0;

    for (i = 0; i < len; i++)
    {
        if (arg[i] < '0' || arg[i] > '9')
            return 1;
        val *= 10;
        val += arg[i] - '0';
    }

    *dest = val;
    return 0;
}

#ifdef CONFIG_USB_BRIDGE
os_semaphore_t usb_host_recv_pipe_seam;
extern cdc_instance_struct_t g_cdc;
extern uint8_t usb_host_recv_buff[USB_HOST_RECV_BUFF_LEN];
void USB_HostCdcDataInCb(void *param, uint8_t *data, uint32_t dataLength, usb_status_t status);

void put_usb_host_recv_pipe_sem(void)
{
    os_semaphore_put(&usb_host_recv_pipe_seam);
}

void get_usb_host_recv_pipe_sem(void)
{
    os_semaphore_get(&usb_host_recv_pipe_seam, OS_WAIT_FOREVER);
}

void usb_host_save_recv_data(uint8_t *recv_data, uint32_t packet_len)
{
    static uint32_t usb_transfer_len = 0;
    static uint32_t usb_rx_len       = 0;

    if (usb_rx_len < NCP_BRIDGE_CMD_HEADER_LEN)
    {
        memcpy((uint8_t *)&mcu_response_buff[0] + usb_rx_len, recv_data, packet_len);
        usb_rx_len += packet_len;

        if (usb_rx_len >= NCP_BRIDGE_CMD_HEADER_LEN)
        {
            usb_transfer_len = ((mcu_response_buff[MCU_BRIDGE_CMD_SIZE_HIGH_BYTE] << 8) |
                                mcu_response_buff[MCU_BRIDGE_CMD_SIZE_LOW_BYTE]) +
                               MCU_CHECKSUM_LEN;
        }
    }
    else
    {
        if ((packet_len < (sizeof(mcu_response_buff) - usb_rx_len)) && (usb_rx_len < usb_transfer_len))
        {
            memcpy((uint8_t *)&mcu_response_buff[0] + usb_rx_len, recv_data, packet_len);
            usb_rx_len += packet_len;
        }
        else
        {
            PRINTF("[%s] transfer warning. data_len : %d  \r\n", __func__, packet_len);
        }
    }

    if ((usb_rx_len >= usb_transfer_len) && (usb_transfer_len >= NCP_BRIDGE_CMD_HEADER_LEN))
    {
        PRINTF("recv data len: %d ", usb_transfer_len);

        usb_rx_len       = 0;
        usb_transfer_len = 0;
        os_event_notify_put(mcu_bridge_resp_thread);

        PRINTF("data recv success \r\n");
    }
}

/*callback in context of USB_HostTaskFn, so it can asynchronous*/
void USB_HostCdcDataInCb(void *param, uint8_t *data, uint32_t dataLength, usb_status_t status)
{
    cdc_instance_struct_t *cdcInstance = (cdc_instance_struct_t *)param;
    //    usb_echo("recv dataLength :%d status: %d \r\n",dataLength,status);

    if ((dataLength > 0) && (0 == status))
    {
        usb_host_save_recv_data(data, dataLength);
    }

    put_usb_host_recv_pipe_sem();

    if (cdcInstance->bulkInMaxPacketSize == dataLength)
    {
        /* host will prime to receive zero length packet after recvive one maxpacketsize */
        USB_HostCdcDataRecv(g_cdc.classHandle, NULL, 0, USB_HostCdcDataInCb, &g_cdc);
    }
}
#endif

/**
 * @brief       Receive tlv reponses from ncp_bridge and process tlv reponses.
 */
static void mcu_bridge_resp_task(void *pvParameters)
{
    int ret;
    uint16_t msg_type = 0;
#ifndef CONFIG_USB_BRIDGE
    int len       = 0;
    size_t rx_len = 0;
    int resp_len  = 0;
#ifdef CONFIG_SPI_BRIDGE
    int total_len = 0;
#endif
#endif

    while (1)
    {
#ifdef CONFIG_USB_BRIDGE
        os_event_notify_get(OS_WAIT_FOREVER);
#else
        /*Inialize mcu_last_resp_rcvd to 0 and there is no 0x00000000 command.*/
        mcu_last_resp_rcvd = 0;
#ifdef CONFIG_UART_BRIDGE
        while (len < NCP_BRIDGE_CMD_HEADER_LEN)
        {
            USART_RTOS_Receive(&mcu_ncp_uart_handle, mcu_response_buff + len, NCP_BRIDGE_CMD_HEADER_LEN, &rx_len);
            len += rx_len;
        }
#elif defined(CONFIG_SPI_BRIDGE)
        os_event_notify_get(OS_WAIT_FOREVER);
        ret = mcu_bridge_spi_master_transfer(mcu_response_buff + len, NCP_BRIDGE_CMD_HEADER_LEN, MCU_BRIDGE_MASTER_RX,
                                             true);
        if (ret != WM_SUCCESS)
        {
            mcu_e("Failed to receive command header(%d)", ret);
            ret = -WM_FAIL;
            goto done;
        }
        len += NCP_BRIDGE_CMD_HEADER_LEN;
#endif
        /* Length of the packet is indicated by byte[4] & byte[5] of
         * the packet excluding checksum [4 bytes]*/
        resp_len =
            (mcu_response_buff[MCU_BRIDGE_CMD_SIZE_HIGH_BYTE] << 8) | mcu_response_buff[MCU_BRIDGE_CMD_SIZE_LOW_BYTE];
        rx_len = 0;
#ifdef CONFIG_UART_BRIDGE
        while (len < resp_len + MCU_CHECKSUM_LEN)
        {
            ret = USART_RTOS_Receive(&mcu_ncp_uart_handle, mcu_response_buff + len, resp_len + MCU_CHECKSUM_LEN - len,
                                     &rx_len);
            len += rx_len;
            if ((ret == kStatus_USART_RxRingBufferOverrun) || len >= MCU_BRIDGE_RESPONSE_LEN)
            {
                /* Notify about hardware buffer overrun, clear uart ring buffer and cmd buffer */
                memset(background_resp_buffer, 0, sizeof(background_resp_buffer));
                mcu_e("overflow, too much tlv reponse from ncp bridge");
                goto done;
            }
        }
#elif defined(CONFIG_SPI_BRIDGE)
        total_len = resp_len + MCU_CHECKSUM_LEN;
        if (resp_len < NCP_BRIDGE_CMD_HEADER_LEN || total_len >= MCU_BRIDGE_RESPONSE_LEN)
        {
            mcu_e("Invalid tlv reponse length from ncp bridge");
            goto done;
        }
        ret = mcu_bridge_spi_master_transfer(mcu_response_buff + len, total_len - NCP_BRIDGE_CMD_HEADER_LEN,
                                             MCU_BRIDGE_MASTER_RX, false);
        if (ret != WM_SUCCESS)
        {
            mcu_e("Failed to receive command buffer(%d)", ret);
            ret = -WM_FAIL;
            goto done;
        }
        len = total_len;
#endif
#ifdef CONFIG_MCU_BRIDGE_IO_DUMP
        PRINTF("Command response:\r\n");
        dump_hex(mcu_response_buff, len);
#endif
#endif
        msg_type = ((NCP_MCU_BRIDGE_COMMAND *)mcu_response_buff)->msg_type;
        /* validate the command including checksum */
        if (check_command_complete(mcu_response_buff) == WM_SUCCESS)
        {
            if (msg_type == NCP_BRIDGE_MSG_TYPE_EVENT)
            {
                ret = wlan_process_ncp_event(mcu_response_buff);
                if (ret != WM_SUCCESS)
                    PRINTF("Failed to parse ncp event\r\n");
            }
            else
            {
                ret = wlan_process_response(mcu_response_buff);
                if (ret != WM_SUCCESS)
                    PRINTF("Failed to parse ncp tlv reponse\r\n");

                mcu_last_resp_rcvd = ((MCU_NCPCmd_DS_COMMAND *)mcu_response_buff)->header.cmd;
                if (mcu_last_resp_rcvd == NCP_BRIDGE_CMD_INVALID_CMD)
                {
                    PRINTF("Previous command is invalid\r\n");
                    mcu_last_resp_rcvd = 0;
                }
            }
        }
        else
        {
            mcu_e("Incomplete ncp response");
            goto done;
        }
    done:
        /* Reset command response buffer */
        memset(mcu_response_buff, 0, MCU_BRIDGE_RESPONSE_LEN);
#ifndef CONFIG_USB_BRIDGE
        len    = 0;
        rx_len = 0;
#endif

        if (msg_type == NCP_BRIDGE_MSG_TYPE_RESP)
        {
            /*If failed to receive response or successed to parse tlv reponse, release mcu command response semaphore to
             * allow processing new string commands. If reponse can't match to command, don't release command reponse
             * semaphore until receive response which id is same as command id.*/
            if (mcu_last_resp_rcvd == 0 || mcu_last_resp_rcvd == mcu_last_cmd_sent)
                mcu_put_command_resp_sem();
            else
                PRINTF("Receive %d command response and wait for %d comamnd response.\r\n", mcu_last_resp_rcvd,
                       mcu_last_cmd_sent);
        }
    }
}

int check_command_complete(uint8_t *buf)
{
    NCP_MCU_BRIDGE_COMMAND *new_cmd;
    uint16_t msglen;
    uint32_t local_checksum = 0, remote_checksum = 0;

    new_cmd = (NCP_MCU_BRIDGE_COMMAND *)buf;
    /* check crc */
    msglen = new_cmd->size;

    remote_checksum = *(uint32_t *)(buf + msglen);
    local_checksum  = uart_get_crc32(buf, msglen);
    if (remote_checksum == local_checksum)
    {
#ifdef CONFIG_MCU_BRIDGE_DEBUG
        mcu_d("local checksum == remote checksum: 0x%02x \r\n", local_checksum);
#endif
        return 0;
    }
    else
    {
        mcu_e("local checksum: %02x != remote checksum: 0x%02x \r\n", local_checksum, remote_checksum);
        return -1;
    }
}

int mcu_get_command_resp_sem()
{
    return os_semaphore_get(&mcu_cmd_resp_sem, OS_WAIT_FOREVER);
}

int mcu_put_command_resp_sem()
{
    return os_semaphore_put(&mcu_cmd_resp_sem);
}

int mcu_get_command_lock()
{
    return os_mutex_get(&mcu_command_lock, OS_WAIT_FOREVER);
}

int mcu_put_command_lock()
{
    return os_semaphore_put(&mcu_command_lock);
}

void (*g_os_tick_hooks[MAX_CUSTOM_HOOKS])(void);
void (*g_os_idle_hooks[MAX_CUSTOM_HOOKS])(void);
/** The FreeRTOS Tick hook function. */
void vApplicationTickHook(void)
{
    int i;

    for (i = 0; i < MAX_CUSTOM_HOOKS; i++)
    {
        if (g_os_tick_hooks[i] != NULL)
            g_os_tick_hooks[i]();
    }
}
void vApplicationIdleHook(void)
{
    int i;
    for (i = 0; i < MAX_CUSTOM_HOOKS; i++)
    {
        if (g_os_idle_hooks[i] != NULL)
            g_os_idle_hooks[i]();
    }
}

#ifdef CONFIG_UART_BRIDGE
static int mcu_bridge_init_ncp_uart()
{
    int ret;
    CLOCK_SetFRGClock(BOARD_DEBUG_UART_USBUART_FRG_CLK);
    CLOCK_AttachClk(BOARD_DEBUG_UART_USBUART_CLK_ATTACH);
    bridge_usart_config.srcclk = BOARD_DEBUG_UART_USBUART_CLK_FREQ;
    bridge_usart_config.base   = BOARD_DEBUG_UART_USBUART;

    NVIC_SetPriority(BOARD_UART_USBUART_IRQ, USART_NVIC_PRIO_USBUART);

    ret = USART_RTOS_Init(&mcu_ncp_uart_handle, &t_u_mcu_uart_resp_handle, &bridge_usart_config);
    if (ret != WM_SUCCESS)
        return ret;

    return WM_SUCCESS;
}
#endif

/**
 * @brief       This function initializes mcu bridge app. Create locks/queues/tasks.
 *
 * @return      Status returned
 */
int mcu_bridge_app_init()
{
    int ret;

    ret = os_semaphore_create(&mcu_cmd_resp_sem, "mcu_command_resposne_semaphore");
    if (ret != WM_SUCCESS)
    {
        (void)PRINTF("Error: Failed to create mcu command resposne semaphore: %d\r\n", ret);
        return -WM_FAIL;
    }

    ret = os_mutex_create(&mcu_command_lock, "mcu_command_lock", OS_MUTEX_INHERIT);
    if (ret != WM_SUCCESS)
    {
        (void)PRINTF("Error: Failed to create mcu command lock: %d\r\n", ret);
        return -WM_FAIL;
    }

#ifdef CONFIG_UART_BRIDGE
    ret = mcu_bridge_init_ncp_uart();
#elif defined(CONFIG_SPI_BRIDGE)
    ret = mcu_bridge_init_spi_master();
#endif
    if (ret != WM_SUCCESS)
    {
#ifdef CONFIG_UART_BRIDGE
        (void)PRINTF("Error: Failed to initialize ncp UART port: %d\r\n", ret);
#elif defined(CONFIG_SPI_BRIDGE)
        (void)PRINTF("Error: Failed to initialize ncp SPI: %d\r\n", ret);
#endif
        return -WM_FAIL;
    }

    ret = os_thread_create(&mcu_bridge_resp_thread, "mcu bridge resp task", mcu_bridge_resp_task, 0, &bridge_app_stack,
                           OS_PRIO_2);
    if (ret != WM_SUCCESS)
    {
        (void)PRINTF("Error: Failed to create bridge recveive thread: %d\r\n", ret);
        return -WM_FAIL;
    }
#ifdef CONFIG_USB_BRIDGE
    ret = os_semaphore_create(&usb_host_recv_pipe_seam, "usb_host_recv_pipe_seam");
    if (ret != WM_SUCCESS)
    {
        (void)PRINTF("failed to create usb_host_recv_pipe_seam: %d", ret);
        return -WM_FAIL;
    }
    os_semaphore_get(&usb_host_recv_pipe_seam, OS_WAIT_FOREVER);
#endif

    return WM_SUCCESS;
}
