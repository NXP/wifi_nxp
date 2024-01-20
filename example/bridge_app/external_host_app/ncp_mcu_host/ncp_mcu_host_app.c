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
#include "board.h"
#include "task.h"
#include "ncp_mcu_host_os.h"
#include "ncp_mcu_host_utils.h"
#include "ncp_mcu_host_cli.h"
#include "ncp_mcu_host_command.h"
#include "ncp_mcu_host_app.h"
#ifdef CONFIG_NCP_UART
#include "fsl_lpuart_freertos.h"
#include "fsl_lpuart.h"
#elif defined(CONFIG_USB_BRIDGE)
#include "usb_host_config.h"
#include "usb_host.h"
#include "usb_host_cdc.h"
#include "host_cdc.h"
#elif defined(CONFIG_SPI_BRIDGE)
#include "spi_master_app.h"
#endif

os_thread_t ncp_host_tlv_thread;
#define CONFIG_TLV_STACK_SIZE 4096
static os_thread_stack_define(ncp_host_tlv_stack, CONFIG_TLV_STACK_SIZE);

#ifdef CONFIG_NCP_UART
/* LPUART3: NCP Host TLV command uart */
#define NCP_HOST_TLV_UART_CLK_FREQ  BOARD_DebugConsoleSrcFreq()
#define NCP_HOST_TLV_UART           LPUART3
#define NCP_HOST_TLV_UART_IRQ       LPUART3_IRQn
#define NCP_HOST_TLV_UART_NVIC_PRIO 5

lpuart_rtos_handle_t ncp_host_tlv_uart_handle;
struct _lpuart_handle t_ncp_host_tlv_uart_handle;

static uint8_t background_buffer[256];

lpuart_rtos_config_t ncp_host_tlv_uart_config = {
    .baudrate    = 115200,
    .parity      = kLPUART_ParityDisabled,
    .stopbits    = kLPUART_OneStopBit,
    .buffer      = background_buffer,
    .buffer_size = sizeof(background_buffer),
};
#endif

os_semaphore_t mcu_cmd_resp_sem;
os_mutex_t mcu_command_lock;

extern uint32_t mcu_last_cmd_sent;
/*ID number of command response received from ncp*/
uint32_t mcu_last_resp_rcvd;

#ifdef CONFIG_SPI_BRIDGE
AT_NONCACHEABLE_SECTION_INIT(uint8_t mcu_response_buff[NCP_HOST_RESPONSE_LEN]) = {0};
#else
static uint8_t mcu_response_buff[NCP_HOST_RESPONSE_LEN];

#endif
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
            usb_transfer_len = ((mcu_response_buff[NCP_HOST_CMD_SIZE_HIGH_BYTE] << 8) |
                                mcu_response_buff[NCP_HOST_CMD_SIZE_LOW_BYTE]) +
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
        mcu_d("recv data len: %d ", usb_transfer_len);

        usb_rx_len       = 0;
        usb_transfer_len = 0;
        os_event_notify_put(ncp_host_tlv_thread);

        mcu_d("data recv success \r\n");
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

#ifdef CONFIG_NCP_SDIO
void sdio_host_save_recv_data(uint8_t *recv_data, uint32_t packet_len)
{
    uint32_t sdio_transfer_len = 0;
    uint32_t sdio_rx_len       = 0;

    memcpy((uint8_t *)&mcu_response_buff[0], recv_data, packet_len);
    sdio_rx_len += packet_len;

    if (sdio_rx_len >= NCP_BRIDGE_CMD_HEADER_LEN)
    {
        sdio_transfer_len =
            ((mcu_response_buff[NCP_HOST_CMD_SIZE_HIGH_BYTE] << 8) | mcu_response_buff[NCP_HOST_CMD_SIZE_LOW_BYTE]) +
            MCU_CHECKSUM_LEN;
    }
    else
    {
        PRINTF("[%s] transfer warning. data_len : %d  \r\n", __func__, packet_len);
    }

    if ((sdio_rx_len >= sdio_transfer_len) && (sdio_transfer_len >= NCP_BRIDGE_CMD_HEADER_LEN))
    {
        //PRINTF("recv data len: %d ", sdio_transfer_len);
        os_event_notify_put(ncp_host_tlv_thread);
        //PRINTF("data recv success \r\n");
    }
}
#endif

/**
 * @brief       Receive tlv reponses from ncp_bridge and process tlv reponses.
 */
static void ncp_host_tlv_task(void *pvParameters)
{
    int ret;
    uint16_t msg_type = 0;
#if !defined(CONFIG_NCP_SDIO) && !defined(CONFIG_USB_BRIDGE)
    int len       = 0;
    size_t rx_len = 0;
    int resp_len  = 0;
#endif

    while (1)
    {
#ifdef CONFIG_USB_BRIDGE
        os_event_notify_get(OS_WAIT_FOREVER);
#elif defined(CONFIG_NCP_SDIO)
        os_event_notify_get(OS_WAIT_FOREVER);
#else
        /*Inialize mcu_last_resp_rcvd to 0 and there is no 0x00000000 command.*/
        mcu_last_resp_rcvd = 0;
#ifdef CONFIG_NCP_UART
        while (len < NCP_BRIDGE_CMD_HEADER_LEN)
        {
            LPUART_RTOS_Receive(&ncp_host_tlv_uart_handle, mcu_response_buff + len, NCP_BRIDGE_CMD_HEADER_LEN, &rx_len);
            len += rx_len;
        }
#elif defined(CONFIG_SPI_BRIDGE)
        len = ncp_host_spi_master_rx(mcu_response_buff);
#endif

#ifdef CONFIG_NCP_UART
        /* Length of the packet is indicated by byte[4] & byte[5] of
         * the packet excluding checksum [4 bytes]*/
        resp_len =
            (mcu_response_buff[NCP_HOST_CMD_SIZE_HIGH_BYTE] << 8) | mcu_response_buff[NCP_HOST_CMD_SIZE_LOW_BYTE];
        rx_len = 0;

        while (len < resp_len + MCU_CHECKSUM_LEN)
        {
            ret = LPUART_RTOS_Receive(&ncp_host_tlv_uart_handle, mcu_response_buff + len,
                                      resp_len + MCU_CHECKSUM_LEN - len, &rx_len);
            len += rx_len;
            if ((ret == kStatus_LPUART_RxRingBufferOverrun) || len >= NCP_HOST_RESPONSE_LEN)
            {
                /* Notify about hardware buffer overrun, clear uart ring buffer and cmd buffer */
                memset(background_buffer, 0, sizeof(background_buffer));
                mcu_e("overflow, too much tlv reponse from ncp bridge");
                goto done;
            }
        }
#endif
#ifdef CONFIG_NCP_HOST_IO_DUMP
        PRINTF("Command response:\r\n");
        dump_hex(mcu_response_buff, len);
#endif
#endif
        msg_type = ((NCP_HOST_COMMAND *)mcu_response_buff)->msg_type;
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
                if (ret == -WM_FAIL)
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
        memset(mcu_response_buff, 0, NCP_HOST_RESPONSE_LEN);
#if !defined(CONFIG_NCP_SDIO) && !defined(CONFIG_USB_BRIDGE)
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
    NCP_HOST_COMMAND *new_cmd;
    uint16_t msglen;
    uint32_t local_checksum = 0, remote_checksum = 0;

    new_cmd = (NCP_HOST_COMMAND *)buf;
    /* check crc */
    msglen = new_cmd->size;

    remote_checksum = *(uint32_t *)(buf + msglen);
    local_checksum  = uart_get_crc32(buf, msglen);
    if (remote_checksum == local_checksum)
    {
#ifdef CONFIG_NCP_HOST_DEBUG
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

#ifdef CONFIG_NCP_UART
static int ncp_host_init_uart()
{
    int ret;
    ncp_host_tlv_uart_config.srcclk = NCP_HOST_TLV_UART_CLK_FREQ;
    ncp_host_tlv_uart_config.base   = NCP_HOST_TLV_UART;

    NVIC_SetPriority(NCP_HOST_TLV_UART_IRQ, NCP_HOST_TLV_UART_NVIC_PRIO);

    ret = LPUART_RTOS_Init(&ncp_host_tlv_uart_handle, &t_ncp_host_tlv_uart_handle, &ncp_host_tlv_uart_config);
    if (ret != WM_SUCCESS)
        return ret;

    return WM_SUCCESS;
}
#endif

/**
 * @brief       This function initializes NCP host app. Create locks/queues/tasks.
 *
 * @return      Status returned
 */
int ncp_host_app_init()
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

#ifdef CONFIG_NCP_UART
    ret = ncp_host_init_uart();
#elif defined(CONFIG_SPI_BRIDGE)
    ret = ncp_host_init_spi_master();
#endif
    if (ret != WM_SUCCESS)
    {
#ifdef CONFIG_NCP_UART
        (void)PRINTF("Error: Failed to initialize ncp uart port: %d\r\n", ret);
#elif defined(CONFIG_SPI_BRIDGE)
        (void)PRINTF("Error: Failed to initialize ncp SPI: %d\r\n", ret);
#endif
        return -WM_FAIL;
    }

    ret = os_thread_create(&ncp_host_tlv_thread, "ncp host tlv task", ncp_host_tlv_task, 0, &ncp_host_tlv_stack,
                           OS_PRIO_2);
    if (ret != WM_SUCCESS)
    {
        (void)PRINTF("Error: Failed to create ncp host tlv thread: %d\r\n", ret);
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
