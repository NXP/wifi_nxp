/** @file main.c
 *
 *  @brief main file
 *
 *  Copyright 2020-2021 NXP
 *  All rights reserved.
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 */

///////////////////////////////////////////////////////////////////////////////
//  Includes
///////////////////////////////////////////////////////////////////////////////

// SDK Included Files
#include "pin_mux.h"
#include "clock_config.h"
#include "board.h"
#include "fsl_debug_console.h"

#include "fsl_common.h"
#include "fsl_component_serial_manager.h"

#if defined(RW610_SERIES) || defined(RW612_SERIES)
#include "fsl_adapter_rfimu.h"
#include "fsl_usart_freertos.h"
#include "fsl_loader.h"
#else
#include "wlan_bt_fw.h"
#include "wlan.h"
#include "wifi.h"
#include "wm_net.h"
#include <wm_os.h>
#include "dhcp-server.h"
#include "cli.h"
#include "wifi_ping.h"
#include "iperf.h"
#include "wifi-internal.h"
#include "wifi-sdio.h"
#include "fsl_adapter_gpio.h"

#include "fsl_sdmmc_host.h"
#include "fsl_common.h"
#include "fsl_lpuart_freertos.h"
#include "fsl_component_serial_manager.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define SERIAL_PORT_NVIC_PRIO 5

#if !defined(RW610_SERIES) && !defined(RW612_SERIES)
#define DEMO_LPUART          LPUART1
#define DEMO_LPUART_CLK_FREQ BOARD_DebugConsoleSrcFreq()
#define DEMO_LPUART_IRQn     LPUART1_IRQn

#define UART_BUF_SIZE            2048
#define LABTOOL_PATTERN_HDR_LEN  4
#define CHECKSUM_LEN             4
#define CRC32_POLY               0x04c11db7
#define LABTOOL_HCI_RESP_HDR_LEN 3

/* SPI related */
#define LPSPI_MASTER_BASEADDR         (LPSPI1)
#define LPSPI_MASTER_IRQN             (LPSPI1_IRQn)
#define LPSPI_MASTER_PCS_FOR_INIT     (kLPSPI_Pcs0)
#define LPSPI_MASTER_PCS_FOR_TRANSFER (kLPSPI_MasterPcs0)

#define SPI_INT_GPIO      GPIO3
#define SPI_INT_GPIO_PORT 3
#define SPI_INT_GPIO_PIN  5
#define SPI_INT_IRQ       GPIO3_Combined_0_15_IRQn
#define SPI_INT_TYPE      kHAL_GpioInterruptFallingEdge

#define LPSPI_MASTER_CLK_FREQ (CLOCK_GetFreqFromObs(CCM_OBS_LPSPI1_CLK_ROOT))

#define LPSPI_DEALY_COUNT 0xFFFFFU
#define TRANSFER_BAUDRATE 100000U /*! Transfer baudrate - 100k */

/** Command type: WLAN */
#define TYPE_WLAN     0x0002
#define RET_TYPE_WLAN 1

/** Command type: BT */
#define TYPE_BT     0x0003
#define RET_TYPE_BT 2

/** Command type: 15.4 */
#define TYPE_15_4       0x0004
#define RET_TYPE_ZIGBEE 3

#define SDIOPKTTYPE_CMD 0x1
#define BUF_LEN         1024

#if defined(RW610_SERIES) || defined(RW612_SERIES)
#define CONFIG_WIFI_MAX_PRIO (configMAX_PRIORITIES - 1)

#define WM_SUCCESS 0
#define WM_FAIL    1

#define SPI_BUF_ST_IDLE  0
#define SPI_BUF_ST_READY 1
#define SPI_BUF_ST_READ  2
#define SPI_BUF_ST_INUSE 3

#define REMOTE_EPT_ADDR_BT     (40U)
#define LOCAL_EPT_ADDR_BT      (30U)
#define REMOTE_EPT_ADDR_ZIGBEE (20U)
#define LOCAL_EPT_ADDR_ZIGBEE  (10U)

#define EVENT_ACCESS_BY_HOST 0x00000098

#define WIFI_REG8(x)  (*(volatile unsigned char *)(x))
#define WIFI_REG16(x) (*(volatile unsigned short *)(x))
#define WIFI_REG32(x) (*(volatile unsigned long *)(x))

#define WIFI_WRITE_REG8(reg, val)  (WIFI_REG8(reg) = (val))
#define WIFI_WRITE_REG16(reg, val) (WIFI_REG16(reg) = (val))
#define WIFI_WRITE_REG32(reg, val) (WIFI_REG32(reg) = (val))

#define EVENT_PAYLOAD_OFFSET 8

/** Return the byte offset of a field in the given structure */
#define MLAN_FIELD_OFFSET(type, field) ((uint32_t)(uint32_t) & (((type *)0)->field))

#if defined(RW610_SERIES) || defined(RW612_SERIES)
/* Set default mode of fw download */
#ifndef CONFIG_SUPPORT_WIFI
#define CONFIG_SUPPORT_WIFI 1
#endif
#ifndef CONFIG_SUPPORT_BLE
#define CONFIG_SUPPORT_BLE 0
#endif
#ifndef CONFIG_SUPPORT_15D4
#define CONFIG_SUPPORT_15D4 0
#endif
#endif

/* enum for event access mem by host action */
enum
{
    EVENT_ACCESS_ACTION_WRITE = 0,
    EVENT_ACCESS_ACTION_READ  = 1
};

enum
{
    EVENT_ACCESS_TYPE_REG    = 0,
    EVENT_ACCESS_TYPE_EEPROM = 1
};
#endif

enum
{
    MLAN_CARD_NOT_DETECTED = 3,
    MLAN_STATUS_FW_DNLD_FAILED,
    MLAN_STATUS_FW_NOT_DETECTED = 5,
    MLAN_STATUS_FW_NOT_READY,
    MLAN_STATUS_FW_XZ_FAILED,
    MLAN_CARD_CMD_TIMEOUT
};

GPIO_HANDLE_DEFINE(s_SpiMasterGpioHandle);

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Variables
 ******************************************************************************/
uint8_t background_buffer[UART_BUF_SIZE];
#if defined(RW610_SERIES) || defined(RW612_SERIES)
usart_rtos_handle_t handle;
struct _usart_handle t_handle;

struct rtos_usart_config usart_config = {
    .baudrate    = 4800,
    .parity      = kUSART_ParityDisabled,
    .stopbits    = kUSART_OneStopBit,
    .buffer      = background_buffer,
    .buffer_size = sizeof(background_buffer),
};

static RPMSG_HANDLE_DEFINE(bt_rpmsg_handle);
static RPMSG_HANDLE_DEFINE(zigbee_rpmsg_handle);
static hal_rpmsg_handle_t rpmsgHandleList[] = {(hal_rpmsg_handle_t)bt_rpmsg_handle,
                                               (hal_rpmsg_handle_t)zigbee_rpmsg_handle};

uint32_t remote_ept_list[] = {REMOTE_EPT_ADDR_BT, REMOTE_EPT_ADDR_ZIGBEE};
uint32_t local_ept_list[]  = {LOCAL_EPT_ADDR_BT, LOCAL_EPT_ADDR_ZIGBEE};
#else
lpuart_rtos_handle_t handle;
lpuart_rtos_handle_t handle_bt;
struct _lpuart_handle t_handle;
struct _lpuart_handle t_handle_bt;

lpuart_rtos_config_t lpuart_config = {
    .baudrate    = 115200,
    .parity      = kLPUART_ParityDisabled,
    .stopbits    = kLPUART_OneStopBit,
    .buffer      = background_buffer,
    .buffer_size = sizeof(background_buffer),
};

lpuart_rtos_config_t lpuart_config_bt = {
    .baudrate    = BOARD_BT_UART_BAUDRATE,
    .parity      = kLPUART_ParityDisabled,
    .stopbits    = kLPUART_OneStopBit,
    .buffer      = background_buffer_bt,
    .buffer_size = sizeof(background_buffer_bt),
    .enableRxRTS = true,
    .enableTxCTS = true,
};

typedef struct _uart_cb
{ /* uart control block */
    int uart_fd;
    unsigned int crc32_table[256];

    unsigned char uart_buf[UART_BUF_SIZE]; /* uart buffer */

} uart_cb;

static uart_cb uartcb;
static uart_cb uartcb_bt;
/** UART start pattern*/
typedef struct _uart_header
{
    /** pattern */
    short pattern;
    /** Command length */
    short length;
} uart_header;

/** Labtool command header */
typedef struct _cmd_header
{
    /** Command Type */
    short type;
    /** Command Sub-type */
    short sub_type;
    /** Command length (header+payload) */
    short length;
    /** Command status */
    short status;
    /** reserved */
    int reserved;
} cmd_header;

typedef MLAN_PACK_START struct _SDIOPkt
{
    t_u16 size;
    t_u16 pkttype;
    HostCmd_DS_COMMAND hostcmd;
} MLAN_PACK_END SDIOPkt;

typedef struct __attribute__((__packed__)) zigbee_cmd_header
{
    /** Command Type */
    unsigned char type;
    /** Command Length */
    unsigned char length;
    /** Control data */
    unsigned int controldata;
    /** Command Data */
    unsigned char data[SPI_DATA_LENGTH];
} zigbee_cmd_header;

typedef struct __attribute__((__packed__)) _zigbee_cmd_rsp_header
{
    /** Command Type */
    unsigned char type;
    /** Command Length */
    unsigned char length;
    /** Eno of message */
    unsigned char endofmessage;
    /** Command Data */
    unsigned char data[SPI_MSG_BUF_SIZE];
} zigbee_cmd_rsp_header;

typedef struct __attribute__((__packed__)) spi_frame_hdr
{
    unsigned char bit0 : 1; // must be 0
    unsigned char bit1 : 1; // must be 1
    unsigned char reserve : 3;
    unsigned char ccf : 1;
    unsigned char crc : 1;
    unsigned char rst : 1;
    unsigned short recv_len;
    unsigned short data_len;
} spi_frame_hdr;

typedef struct __attribute__((__packed__)) Wrapper_Spinel_CMD_Hdr
{
    unsigned char FLG : 2;
    unsigned char IID : 2;
    unsigned char TID : 4;
    unsigned short SPINEL_CMD_NUM;
    unsigned char MFG_CMD_Payload_Length;
} Wrapper_Spinel_CMD_Hdr;

static uint8_t *rx_buf;
static cmd_header last_cmd_hdr;
t_u8 *local_outbuf;
static SDIOPkt *sdiopkt;

lpspi_master_config_t spiConfig;
lpspi_transfer_t handle_spi;
int spi_buf_len = 0;
uint8_t spi_message_buf[SPI_MSG_BUF_SIZE];
uint8_t zigbee_rsp_buf[SPI_MSG_BUF_SIZE];
int spi_buf_st = SPI_BUF_ST_READY;

/*******************************************************************************
 * Code
 ******************************************************************************/
#if defined(RW610_SERIES) || defined(RW612_SERIES)
const int TASK_MAIN_PRIO = CONFIG_WIFI_MAX_PRIO - 3;
#else
const int TASK_MAIN_PRIO = OS_PRIO_3;
#endif
const int TASK_MAIN_STACK_SIZE = 5 * 2048;

portSTACK_TYPE *task_main_stack = NULL;
TaskHandle_t task_main_task_handler;

#define SDK_VERSION "NXPSDK_v1.3.r13.p1"

static void uart_init_crc32(uart_cb *uartcb)
{
    int i, j;
    unsigned int c;
    for (i = 0; i < 256; ++i)
    {
        for (c = i << 24, j = 8; j > 0; --j)
            c = c & 0x80000000 ? (c << 1) ^ CRC32_POLY : (c << 1);
        uartcb->crc32_table[i] = c;
    }
}

static uint32_t uart_get_crc32(uart_cb *uart, int len, unsigned char *buf)
{
    unsigned int *crc32_table = uart->crc32_table;
    unsigned char *p;
    unsigned int crc;
    crc = 0xffffffff;
    for (p = buf; len > 0; ++p, --len)
        crc = (crc << 8) ^ (crc32_table[(crc >> 24) ^ *p]);
    return ~crc;
}

int set_spi_frame_hdr(spi_frame_hdr *pspihdr,
                      unsigned char rst_flag,
                      unsigned char crc_flag,
                      unsigned char ccf_flag,
                      unsigned short recv_len,
                      unsigned short data_len)
{
    if (!pspihdr)
        return -1;
    memset(pspihdr, 0, sizeof(spi_frame_hdr));
    pspihdr->rst      = rst_flag;
    pspihdr->crc      = crc_flag;
    pspihdr->ccf      = ccf_flag;
    pspihdr->bit1     = 1;
    pspihdr->bit0     = 0;
    pspihdr->recv_len = recv_len;
    pspihdr->data_len = data_len;

    return 0;
}

void spi_rx_collection()
{
    uint8_t tr_txbuf[SPI_TR_DEFAULT_SIZE];
    uint8_t tr_rxbuf[SPI_TR_DEFAULT_SIZE];

    uint8_t tr_rxtemp[SPI_TR_DEFAULT_SIZE];

    int rd_len = SPI_TR_DEFAULT_SIZE + 16 + SPI_HEADER_LENGTH;
    int i;

    spi_frame_hdr *pspihdr;

    spi_buf_st = SPI_BUF_ST_INUSE;

    memset(tr_txbuf, 0, SPI_TR_DEFAULT_SIZE);
    memset(tr_rxbuf, 0, SPI_TR_DEFAULT_SIZE);

    pspihdr = (spi_frame_hdr *)tr_txbuf;

    set_spi_frame_hdr(pspihdr, 0, 0, 0, (unsigned short)SPI_TR_DEFAULT_SIZE, 0);

    handle_spi.txData   = tr_txbuf;
    handle_spi.rxData   = tr_rxbuf;
    handle_spi.dataSize = rd_len;

    handle_spi.configFlags = LPSPI_MASTER_PCS_FOR_TRANSFER | kLPSPI_MasterPcsContinuous | kLPSPI_MasterByteSwap;

    LPSPI_MasterTransferBlocking(LPSPI_MASTER_BASEADDR, &handle_spi);

    for (i = 0; i < SPI_DATA_LENGTH; i++)
    {
        if (tr_rxbuf[i] != 0xFF)
            break;
    }

    memset(tr_rxtemp, 0, SPI_TR_DEFAULT_SIZE);
    memcpy(tr_rxtemp, &tr_rxbuf[i], (SPI_TR_DEFAULT_SIZE - i));
    memcpy(tr_rxbuf, tr_rxtemp, SPI_TR_DEFAULT_SIZE);

    pspihdr = (spi_frame_hdr *)tr_rxbuf;

    if (pspihdr->data_len > (SPI_TR_DEFAULT_SIZE - SPI_HEADER_LENGTH))
    {
        return;
    }

    spi_buf_len = 0;

    if (pspihdr->data_len > 0)
    {
        if ((pspihdr->data_len + spi_buf_len) <= SPI_MSG_BUF_SIZE)
        {
            memcpy(&spi_message_buf[spi_buf_len], &tr_rxbuf[sizeof(spi_frame_hdr)], pspihdr->data_len);
            spi_buf_len += pspihdr->data_len;
        }
    }

    spi_buf_st = SPI_BUF_ST_READ;
}

int read_message_from_spi_buf(char *outBuf, int bufSize)
{
    int byte_read = 0;

    // get data from spi_buf
    if (bufSize >= spi_buf_len)
    {
        memcpy(outBuf, spi_message_buf, spi_buf_len);
        byte_read = spi_buf_len;

        // flush spi_buf
        memset(spi_message_buf, 0, SPI_MSG_BUF_SIZE);
        spi_buf_len = 0;
    }
    else
    {
        memcpy(outBuf, spi_message_buf, bufSize);
        byte_read   = bufSize;
        spi_buf_len = spi_buf_len - bufSize;
        memcpy(spi_message_buf, &spi_message_buf[bufSize], spi_buf_len);
    }

    return byte_read;
}

int read_zigbee(unsigned char *buf, int buflen)
{
    char rcv_buf[2 * 1024] = "";
    int readlen            = 0;

    readlen = read_message_from_spi_buf(rcv_buf, 2 * 1024);

    if (readlen < buflen)
        memcpy(buf, rcv_buf, readlen);
    else
        memcpy(buf, rcv_buf, buflen);

    return readlen;
}

char *check_TxRspMesg(char *inpBuf, int inpLen)
{
    char *chkPtr = NULL;
    Wrapper_Spinel_CMD_Hdr *hdrPtr;

    if (!inpBuf)
        return inpBuf;

    // Check comand response from Spinel layer
    hdrPtr = (Wrapper_Spinel_CMD_Hdr *)inpBuf;

    // check FLG, SPINEL_CMD_NUM, length;
    if ((hdrPtr->FLG == WRAPPER_SPINEL_MFG_CMD_FLG) && (hdrPtr->SPINEL_CMD_NUM == WRAPPER_SPINEL_MFG_CMD_NUM))
    {
        if (hdrPtr->MFG_CMD_Payload_Length == (inpLen - sizeof(Wrapper_Spinel_CMD_Hdr)))
        {
            return inpBuf;
        }
    }
    return chkPtr;
}

void send_zigbee_response_to_uart(uint8_t *rxData, uint32_t payloadlen)
{
    uint32_t bridge_chksum = 0;
    uint32_t msglen;
    int index;
    uart_header *uart_hdr;
    uart_cb *uart = &uartcb;

    memset(rx_buf, 0, BUF_LEN);
    memcpy(rx_buf + sizeof(uart_header) + sizeof(cmd_header), rxData, payloadlen);

    /* Added to send correct cmd header len */
    cmd_header *cmd_hdr;
    cmd_hdr         = &last_cmd_hdr;
    cmd_hdr->length = payloadlen + sizeof(cmd_header);

    memcpy(rx_buf + sizeof(uart_header), (uint8_t *)&last_cmd_hdr, sizeof(cmd_header));

    uart_hdr          = (uart_header *)rx_buf;
    uart_hdr->length  = payloadlen + sizeof(cmd_header);
    uart_hdr->pattern = 0x5555;

    /* calculate CRC. The uart_header is excluded */
    msglen        = payloadlen + sizeof(cmd_header);
    bridge_chksum = uart_get_crc32(uart, msglen, rx_buf + sizeof(uart_header));
    index         = sizeof(uart_header) + msglen;

    rx_buf[index]     = bridge_chksum & 0xff;
    rx_buf[index + 1] = (bridge_chksum & 0xff00) >> 8;
    rx_buf[index + 2] = (bridge_chksum & 0xff0000) >> 16;
    rx_buf[index + 3] = (bridge_chksum & 0xff000000) >> 24;

    /* write response to uart */
    LPUART_RTOS_Send(&handle, rx_buf, payloadlen + sizeof(cmd_header) + sizeof(uart_header) + 4);
    memset(rx_buf, 0, BUF_LEN);
}

void SPI_MASTER_Callback(void *param)
{
    DisableIRQ(SPI_INT_IRQ);
    GPIO_DisableInterrupts(SPI_INT_GPIO, 1U << SPI_INT_GPIO_PIN);
    GPIO_ClearPinsInterruptFlags(SPI_INT_GPIO, 1U << SPI_INT_GPIO_PIN);

    spi_rx_collection();

    EnableIRQ(SPI_INT_IRQ);
    GPIO_EnableInterrupts(SPI_INT_GPIO, 1U << SPI_INT_GPIO_PIN);

    SDK_ISR_EXIT_BARRIER;
}

/*
 send_response_to_uart() handles the response from the firmware.
 This involves
 1. replacing the sdio header with the uart header
 2. computation of the crc of the payload
 3. sending it out to the uart
*/
static int send_response_to_uart(uart_cb *uart, uint8_t *resp, int type)
{
    uint32_t bridge_chksum = 0;
    uint32_t msglen;
    int index;
    uint32_t payloadlen;
    uart_header *uart_hdr;
    SDIOPkt *sdio = (SDIOPkt *)resp;

    int iface_len;

    if (type == 2)
        /* This is because, the last byte of the sdio header
         * (packet type) is also requried by the labtool, to
         * understand the type of packet and take appropriate action */
        iface_len = INTF_HEADER_LEN - 1;
    else
        iface_len = INTF_HEADER_LEN;

    payloadlen = sdio->size - iface_len;
    memset(rx_buf, 0, BUF_LEN);
    memcpy(rx_buf + sizeof(uart_header) + sizeof(cmd_header), resp + iface_len, payloadlen);

    /* Added to send correct cmd header len */
    cmd_header *cmd_hdr;
    cmd_hdr         = &last_cmd_hdr;
    cmd_hdr->length = payloadlen + sizeof(cmd_header);

    memcpy(rx_buf + sizeof(uart_header), (uint8_t *)&last_cmd_hdr, sizeof(cmd_header));

    uart_hdr          = (uart_header *)rx_buf;
    uart_hdr->length  = payloadlen + sizeof(cmd_header);
    uart_hdr->pattern = 0x5555;

    /* calculate CRC. The uart_header is excluded */
    msglen        = payloadlen + sizeof(cmd_header);
    bridge_chksum = uart_get_crc32(uart, msglen, rx_buf + sizeof(uart_header));
    index         = sizeof(uart_header) + msglen;

    rx_buf[index]     = bridge_chksum & 0xff;
    rx_buf[index + 1] = (bridge_chksum & 0xff00) >> 8;
    rx_buf[index + 2] = (bridge_chksum & 0xff0000) >> 16;
    rx_buf[index + 3] = (bridge_chksum & 0xff000000) >> 24;

    /* write response to uart */
#if defined(RW610_SERIES) || defined(RW612_SERIES)
    USART_RTOS_Send(&handle, rx_buf, payloadlen + sizeof(cmd_header) + sizeof(uart_header) + 4);
#else
    LPUART_RTOS_Send(&handle, rx_buf, payloadlen + sizeof(cmd_header) + sizeof(uart_header) + 4);
    memset(rx_buf, 0, BUF_LEN);

    return 0;
}

/*
 check_command_complete() validates the command from the uart.
 It checks for the signature in the header and the crc of the
 payload. This assumes that the uart_buf is circular and data
 can be wrapped.
*/
int check_command_complete(uint8_t *buf)
{
    uart_header *uarthdr;
    uint32_t msglen, endofmsgoffset;
    uart_cb *uart = &uartcb;
    int checksum = 0, bridge_checksum = 0;

    uarthdr = (uart_header *)buf;

    /* out of sync */
    if (uarthdr->pattern != 0x5555)
    {
        PRINTF("Pattern mismatch\r\n");
        return -WM_FAIL;
    }
    /* check crc */
    msglen = uarthdr->length;

    /* add 4 for checksum */
    endofmsgoffset = sizeof(uart_header) + msglen + 4;

    memset((uint8_t *)local_outbuf, 0, sizeof(local_outbuf));
    if (endofmsgoffset < UART_BUF_SIZE)
    {
        memcpy((uint8_t *)local_outbuf, buf, endofmsgoffset);
    }
    else
    {
        memcpy((uint8_t *)local_outbuf, buf, UART_BUF_SIZE);
        /* To do : check if copying method is correct */
        memcpy((uint8_t *)local_outbuf + UART_BUF_SIZE, buf, endofmsgoffset);
    }

    checksum = *(int *)((uint8_t *)local_outbuf + sizeof(uart_header) + msglen);

    bridge_checksum = uart_get_crc32(uart, msglen, (uint8_t *)local_outbuf + sizeof(uart_header));
    if (checksum == bridge_checksum)
    {
        return WM_SUCCESS;
    }
    /* Reset local outbuf */
    memset(local_outbuf, 0, BUF_LEN);

    return -WM_FAIL;
}

#if defined(RW610_SERIES) || defined(RW612_SERIES)
hal_rpmsg_status_t wifi_send_imu_raw_data(uint8_t *data, uint32_t length)
{
    hal_rpmsg_status_t state = kStatus_HAL_RpmsgSuccess;

    if (data == NULL || length == 0)
        return kStatus_HAL_RpmsgError;

    state = HAL_ImuSendCommand(kIMU_LinkCpu1Cpu3, data, length);
    assert(kStatus_HAL_RpmsgSuccess == state);

    return kStatus_HAL_RpmsgSuccess;
}

int rpmsg_raw_packet_send(uint8_t *buf, int m_len, uint8_t t_type)
{
    uint32_t payloadlen;

    cmd_header *cmd_hd = (cmd_header *)(buf + sizeof(uart_header));

    payloadlen = m_len - sizeof(uart_header) - sizeof(cmd_header) - 4;

    memset(local_outbuf, 0, BUF_LEN);
    memcpy(local_outbuf, buf + sizeof(uart_header) + sizeof(cmd_header), payloadlen);

    memcpy(&last_cmd_hdr, cmd_hd, sizeof(cmd_header));

    LPUART_RTOS_Send(&handle_bt, local_outbuf, payloadlen);

    memset(local_outbuf, 0, BUF_LEN);

    return RET_TYPE_BT;
}

int write_cmd_spi(uint8_t *inbuf, char *outbuf, int payloadlen)
{
    uint8_t tr_txbuf[SPI_TR_DEFAULT_SIZE];
    uint8_t tr_rxbuf[SPI_TR_DEFAULT_SIZE];
    spi_frame_hdr *pspihdr;

    memset(tr_txbuf, 0, SPI_TR_DEFAULT_SIZE);
    memset(tr_rxbuf, 0, SPI_TR_DEFAULT_SIZE);

    memset(outbuf, 0, SPI_DATA_LENGTH);

    pspihdr = (spi_frame_hdr *)tr_txbuf;

    set_spi_frame_hdr(pspihdr, 0, 0, 0, 0, (unsigned char)payloadlen);

    memcpy(tr_txbuf + sizeof(spi_frame_hdr), inbuf, payloadlen);

    handle_spi.txData   = tr_txbuf;
    handle_spi.rxData   = tr_rxbuf;
    handle_spi.dataSize = SPI_DATA_LENGTH + SPI_HEADER_LENGTH;

    handle_spi.configFlags = LPSPI_MASTER_PCS_FOR_TRANSFER | kLPSPI_MasterPcsContinuous | kLPSPI_MasterByteSwap;

    LPSPI_MasterTransferBlocking(LPSPI_MASTER_BASEADDR, &handle_spi);

    pspihdr = (spi_frame_hdr *)tr_rxbuf;

    if (pspihdr->data_len > 0)
    {
        /* read from SPI */
        memcpy(outbuf, tr_rxbuf, SPI_DATA_LENGTH);
    }

    return 0;
}

int zigbee_raw_packet_send(uint8_t *buf, int m_len)
{
    uint32_t payloadlen;
    zigbee_cmd_header *cmd_ptr         = (zigbee_cmd_header *)(buf + sizeof(uart_header) + sizeof(cmd_header));
    zigbee_cmd_rsp_header *cmd_rsp_ptr = (zigbee_cmd_rsp_header *)zigbee_rsp_buf;
    int readlen                        = 0;
    long delay                         = 0;

    char *tx_str_per = NULL;
    char local_buf[10000];

    uint8_t txbuf[SPI_DATA_LENGTH];

    char outbuf[SPI_DATA_LENGTH];

    memcpy(txbuf, cmd_ptr->data, cmd_ptr->length);

    memset(outbuf, 0, 16);
    write_cmd_spi(txbuf, outbuf, cmd_ptr->length);

    cmd_header *cmd_hd = (cmd_header *)(buf + sizeof(uart_header));

    memcpy(&last_cmd_hdr, cmd_hd, sizeof(cmd_header));

    os_thread_sleep(os_msec_to_ticks(50));

    if (cmd_ptr->type == DELAY_FOR_READ_COMMAND)
    {
        delay = cmd_ptr->controldata;
        while (delay > 0)
        {
            readlen    = read_zigbee((unsigned char *)local_buf, 10000);
            tx_str_per = check_TxRspMesg((char *)local_buf, readlen);
            if (tx_str_per != NULL)
            {
                break;
            }
            os_thread_sleep(os_msec_to_ticks(500));
            delay = delay - 500;
        }
    }

    readlen    = read_zigbee(cmd_rsp_ptr->data, UART_BUF_SIZE);
    payloadlen = readlen + 3;

    if (cmd_ptr->type == DELAY_FOR_READ_COMMAND)
    {
        if (tx_str_per != NULL)
        {
            memcpy(cmd_rsp_ptr->data, tx_str_per, 7);
            readlen    = 7;
            payloadlen = readlen + 3;
        }
    }

    memcpy(zigbee_rsp_buf, cmd_rsp_ptr, sizeof(zigbee_cmd_rsp_header));

    send_zigbee_response_to_uart(zigbee_rsp_buf, payloadlen);

    return RET_TYPE_ZIGBEE;
}

/*
 process_input_cmd() sends command to the wlan
 card
*/
int process_input_cmd(uint8_t *buf, int m_len)
{
    uart_header *uarthdr;
    int i, ret = -WM_FAIL;
    uint8_t *s, *d;
    cmd_header *cmd_hd = (cmd_header *)(buf + sizeof(uarthdr));

    if (cmd_hd->type == TYPE_WLAN)
    {
        memset(local_outbuf, 0, BUF_LEN);
        sdiopkt = (SDIOPkt *)local_outbuf;

        uarthdr = (uart_header *)buf;

        /* sdiopkt = local_outbuf */
        sdiopkt->pkttype = SDIOPKTTYPE_CMD;

        sdiopkt->size = m_len - sizeof(cmd_header) + INTF_HEADER_LEN;
        d             = (uint8_t *)local_outbuf + INTF_HEADER_LEN;
        s             = (uint8_t *)buf + sizeof(uart_header) + sizeof(cmd_header);

        for (i = 0; i < uarthdr->length - sizeof(cmd_header); i++)
        {
            if (s < buf + UART_BUF_SIZE)
                *d++ = *s++;
            else
            {
                s    = buf;
                *d++ = *s++;
            }
        }

        d = (uint8_t *)&last_cmd_hdr;
        s = (uint8_t *)buf + sizeof(uart_header);

        for (i = 0; i < sizeof(cmd_header); i++)
        {
            if (s < buf + UART_BUF_SIZE)
                *d++ = *s++;
            else
            {
                s    = buf;
                *d++ = *s++;
            }
        }
#if defined(RW610_SERIES) || defined(RW612_SERIES)
        wifi_send_imu_raw_data(local_outbuf, (m_len - sizeof(cmd_header) + INTF_HEADER_LEN));
#else
        wifi_raw_packet_send(local_outbuf, BUF_LEN);

        ret = RET_TYPE_WLAN;
    }
    else if (cmd_hd->type == TYPE_BT)
    {
#if defined(RW610_SERIES) || defined(RW612_SERIES)
        ret = rpmsg_raw_packet_send(buf, m_len, RET_TYPE_BT);
#elif defined(MIMXRT1176_cm7_SERIES)
        ret = bt_raw_packet_send(buf, m_len);
    }
    else if (cmd_hd->type == TYPE_15_4)
    {
#if defined(RW610_SERIES) || defined(RW612_SERIES)
        ret = rpmsg_raw_packet_send(buf, m_len, RET_TYPE_ZIGBEE);
#elif defined(MIMXRT1176_cm7_SERIES)
        ret = zigbee_raw_packet_send(buf, m_len);
    }

    return ret;
}

#if defined(RW610_SERIES) || defined(RW612_SERIES)
void send_rpmsg_response_to_uart(uint8_t *resp, int msg_len)
{
    uint32_t bridge_chksum = 0;
    uint32_t msglen;
    int index;
    uint32_t payloadlen;
    uart_header *uart_hdr;
    uart_cb *uart = &uartcb;
    payloadlen    = msg_len;

    memset(rx_buf, 0, BUF_LEN);
    memcpy(rx_buf + sizeof(uart_header) + sizeof(cmd_header), resp, payloadlen);

    /* Added to send correct cmd header len */
    cmd_header *cmd_hdr;
    cmd_hdr         = &last_cmd_hdr;
    cmd_hdr->length = payloadlen + sizeof(cmd_header);

    memcpy(rx_buf + sizeof(uart_header), (uint8_t *)&last_cmd_hdr, sizeof(cmd_header));

    uart_hdr          = (uart_header *)rx_buf;
    uart_hdr->length  = payloadlen + sizeof(cmd_header);
    uart_hdr->pattern = 0x5555;

    /* calculate CRC. The uart_header is excluded */
    msglen        = payloadlen + sizeof(cmd_header);
    bridge_chksum = uart_get_crc32(uart, msglen, rx_buf + sizeof(uart_header));
    index         = sizeof(uart_header) + msglen;

    rx_buf[index]     = bridge_chksum & 0xff;
    rx_buf[index + 1] = (bridge_chksum & 0xff00) >> 8;
    rx_buf[index + 2] = (bridge_chksum & 0xff0000) >> 16;
    rx_buf[index + 3] = (bridge_chksum & 0xff000000) >> 24;

    /* write response to uart */
    USART_RTOS_Send(&handle, rx_buf, payloadlen + sizeof(cmd_header) + sizeof(uart_header) + 4);
    memset(rx_buf, 0, BUF_LEN);
}
#elif defined(MIMXRT1176_cm7_SERIES)
void send_bt_response_to_uart(uart_cb *uart_bt, int msg_len)
{
    uint32_t bridge_chksum = 0;
    uint32_t msglen;
    int index;
    uint32_t payloadlen;
    uart_header *uart_hdr;
    uart_cb *uart = &uartcb;

    payloadlen = msg_len;

    memset(rx_buf, 0, BUF_LEN);
    memcpy(rx_buf + sizeof(uart_header) + sizeof(cmd_header), uart_bt->uart_buf, payloadlen);

    /* Added to send correct cmd header len */
    cmd_header *cmd_hdr;
    cmd_hdr         = &last_cmd_hdr;
    cmd_hdr->length = payloadlen + sizeof(cmd_header);

    memcpy(rx_buf + sizeof(uart_header), (uint8_t *)&last_cmd_hdr, sizeof(cmd_header));

    uart_hdr          = (uart_header *)rx_buf;
    uart_hdr->length  = payloadlen + sizeof(cmd_header);
    uart_hdr->pattern = 0x5555;

    /* calculate CRC. The uart_header is excluded */
    msglen        = payloadlen + sizeof(cmd_header);
    bridge_chksum = uart_get_crc32(uart, msglen, rx_buf + sizeof(uart_header));
    index         = sizeof(uart_header) + msglen;

    rx_buf[index]     = bridge_chksum & 0xff;
    rx_buf[index + 1] = (bridge_chksum & 0xff00) >> 8;
    rx_buf[index + 2] = (bridge_chksum & 0xff0000) >> 16;
    rx_buf[index + 3] = (bridge_chksum & 0xff000000) >> 24;

    /* write response to uart */
    LPUART_RTOS_Send(&handle, rx_buf, payloadlen + sizeof(cmd_header) + sizeof(uart_header) + 4);
    memset(rx_buf, 0, BUF_LEN);
}

void send_zigbee_response_to_uart(uint8_t *rxData, uint32_t payloadlen)
{
    uint32_t bridge_chksum = 0;
    uint32_t msglen;
    int index;
    uart_header *uart_hdr;
    uart_cb *uart = &uartcb;

    memset(rx_buf, 0, BUF_LEN);
    memcpy(rx_buf + sizeof(uart_header) + sizeof(cmd_header), rxData, payloadlen);

    /* Added to send correct cmd header len */
    cmd_header *cmd_hdr;
    cmd_hdr         = &last_cmd_hdr;
    cmd_hdr->length = payloadlen + sizeof(cmd_header);

    memcpy(rx_buf + sizeof(uart_header), (uint8_t *)&last_cmd_hdr, sizeof(cmd_header));

    uart_hdr          = (uart_header *)rx_buf;
    uart_hdr->length  = payloadlen + sizeof(cmd_header);
    uart_hdr->pattern = 0x5555;

    /* calculate CRC. The uart_header is excluded */
    msglen        = payloadlen + sizeof(cmd_header);
    bridge_chksum = uart_get_crc32(uart, msglen, rx_buf + sizeof(uart_header));
    index         = sizeof(uart_header) + msglen;

    rx_buf[index]     = bridge_chksum & 0xff;
    rx_buf[index + 1] = (bridge_chksum & 0xff00) >> 8;
    rx_buf[index + 2] = (bridge_chksum & 0xff0000) >> 16;
    rx_buf[index + 3] = (bridge_chksum & 0xff000000) >> 24;

    /* write response to uart */
    LPUART_RTOS_Send(&handle, rx_buf, payloadlen + sizeof(cmd_header) + sizeof(uart_header) + 4);
    memset(rx_buf, 0, BUF_LEN);
}
#endif

/*
 read_wlan_resp() handles the responses from the wlan card.
 It waits on wlan card interrupts on account
 of command responses are handled here. The response is
 read and then sent through the uart to the Mfg application
*/
#if defined(RW610_SERIES) || defined(RW612_SERIES)
hal_rpmsg_status_t read_wlan_resp(IMU_Msg_t *pImuMsg, uint32_t len)
{
    assert(NULL != pImuMsg);
    assert(0 != len);
    assert(IMU_MSG_COMMAND_RESPONSE == pImuMsg->Hdr.type);

    uart_cb *uart = &uartcb;

    send_response_to_uart(uart, (uint8_t *)(pImuMsg->PayloadPtr[0]), 1);

    return kStatus_HAL_RpmsgSuccess;
}

hal_rpmsg_return_status_t read_rpmsg_resp(void *param, uint8_t *packet, uint32_t len)
{
    assert(NULL != packet);
    assert(0 != len);

    send_rpmsg_response_to_uart(packet, len);

    return kStatus_HAL_RL_RELEASE;
}
#else
void read_wlan_resp()
{
    uart_cb *uart = &uartcb;
    uint8_t *packet;
    t_u32 pkt_type;
    int rv = wifi_raw_packet_recv(&packet, &pkt_type);
    if (rv != WM_SUCCESS)
        PRINTF("Receive response failed\r\n");
    else
    {
        if (pkt_type == MLAN_TYPE_CMD)
            send_response_to_uart(uart, packet, 1);
    }
}
#if defined(MIMXRT1176_cm7_SERIES)
void read_bt_resp()
{
    uart_cb *uart_bt = &uartcb_bt;
    uint32_t msglen;
    uint32_t payloadlen = 0;
    uint32_t currentlen = 0;
    size_t uart_rx_len  = 0;
    int len;

    memset(uart_bt->uart_buf, 0, sizeof(uart_bt->uart_buf));

    do
    {
        len         = 0;
        uart_rx_len = 0;
        currentlen  = payloadlen;

        while (len != LABTOOL_HCI_RESP_HDR_LEN)
        {
            LPUART_RTOS_Receive(&handle_bt, uart_bt->uart_buf + len + payloadlen, LABTOOL_HCI_RESP_HDR_LEN,
                                &uart_rx_len);
            len += uart_rx_len;
        }

        msglen = uart_bt->uart_buf[currentlen + 2];
        payloadlen += LABTOOL_HCI_RESP_HDR_LEN;
        uart_rx_len = 0;
        len         = 0;

        while (len != msglen)
        {
            LPUART_RTOS_Receive(&handle_bt, uart_bt->uart_buf + len + payloadlen, msglen - len, &uart_rx_len);
            len += uart_rx_len;
        }

        payloadlen += len;

    } while (uart_bt->uart_buf[currentlen + 1] != 0x0E);

    send_bt_response_to_uart(uart_bt, payloadlen);
    memset(uart_bt->uart_buf, 0, sizeof(uart_bt->uart_buf));
}

void read_zigbee_resp()
{
    handle_spi.txData   = NULL;
    handle_spi.rxData   = local_outbuf;
    handle_spi.dataSize = BUF_LEN;

    handle_spi.configFlags = LPSPI_MASTER_PCS_FOR_TRANSFER | kLPSPI_MasterPcsContinuous | kLPSPI_MasterByteSwap;

    LPSPI_MasterTransferBlocking(LPSPI_MASTER_BASEADDR, &handle_spi);

    send_zigbee_response_to_uart(local_outbuf, BUF_LEN);

    memset(local_outbuf, 0, BUF_LEN);
}
#endif
#endif

#if defined(RW610_SERIES) || defined(RW612_SERIES)
static hal_rpmsg_status_t imu_wifi_config()
{
    hal_rpmsg_status_t state = kStatus_HAL_RpmsgSuccess;

    /* Assign IMU channel for CPU1-CPU3 communication */
    state = HAL_ImuInit(kIMU_LinkCpu1Cpu3);
    assert(kStatus_HAL_RpmsgSuccess == state);

    HAL_ImuInstallCallback(kIMU_LinkCpu1Cpu3, read_wlan_resp, IMU_MSG_COMMAND_RESPONSE);

    return state;
}

#if (defined(CONFIG_SUPPORT_BLE) && (CONFIG_SUPPORT_BLE == 1)) || \
    (defined(CONFIG_SUPPORT_15D4) && (CONFIG_SUPPORT_15D4 == 1))
static hal_rpmsg_status_t rpmsg_config(uint32_t linkId)
{
    hal_rpmsg_status_t state = kStatus_HAL_RpmsgSuccess;

    hal_rpmsg_config_t config;
    /* Init RPMSG/IMU Channel */
    config.local_addr  = local_ept_list[linkId];
    config.remote_addr = remote_ept_list[linkId];
    config.imuLink     = kIMU_LinkCpu2Cpu3;
    state              = HAL_RpmsgInit((hal_rpmsg_handle_t)rpmsgHandleList[linkId], &config);
    assert(kStatus_HAL_RpmsgSuccess == state);

    /* RPMSG install rx callback */
    state = HAL_RpmsgInstallRxCallback((hal_rpmsg_handle_t)rpmsgHandleList[linkId], read_rpmsg_resp, NULL);
    assert(kStatus_HAL_RpmsgSuccess == state);

    return state;
}
#endif

static hal_rpmsg_status_t rpmsg_init()
{
#if (defined(CONFIG_SUPPORT_BLE) && (CONFIG_SUPPORT_BLE == 1)) || \
    (defined(CONFIG_SUPPORT_15D4) && (CONFIG_SUPPORT_15D4 == 1))
    uint32_t linkId;
#endif
    hal_rpmsg_status_t state = kStatus_HAL_RpmsgSuccess;

    /* Init RPMSG/IMU Channel */
#if defined (CONFIG_SUPPORT_BLE) && (CONFIG_SUPPORT_BLE == 1)
    linkId = 0;
    state = rpmsg_config(linkId);
#endif
#if defined(CONFIG_SUPPORT_15D4) && (CONFIG_SUPPORT_15D4 == 1)
    linkId = 1;
    state = rpmsg_config(linkId);
#endif

    return state;
}

/*
 task_main() runs in a loop. It polls the uart ring buffer
 checks it for a complete command and sends the command to the
 wlan card
*/
void task_main(void *param)
{
    int32_t result = 0;
    (void)result;
    uint32_t srcClock_Hz;
#endif


#if !defined(RW610_SERIES) && !defined(RW612_SERIES) 
    result = sd_wifi_init(WLAN_TYPE_FCC_CERTIFICATION, WLAN_FW_IN_RAM, wlan_fw_bin, wlan_fw_bin_len);
    /* Initialize WIFI Driver */
#else
    result = sd_wifi_init(WLAN_TYPE_FCC_CERTIFICATION, wlan_fw_bin, wlan_fw_bin_len);
#endif
    if (result != 0)
    {
        switch (result)
        {
            case MLAN_CARD_CMD_TIMEOUT:
            case MLAN_CARD_NOT_DETECTED:
                result = -WIFI_ERROR_CARD_NOT_DETECTED;
                break;
            case MLAN_STATUS_FW_DNLD_FAILED:
                result = -WIFI_ERROR_FW_DNLD_FAILED;
                break;
            case MLAN_STATUS_FW_NOT_DETECTED:
                result = -WIFI_ERROR_FW_NOT_DETECTED;
                break;
#ifdef CONFIG_XZ_DECOMPRESSION
            case MLAN_STATUS_FW_XZ_FAILED:
                result = -WIFI_ERROR_FW_XZ_FAILED;
                break;
#endif /* CONFIG_XZ_DECOMPRESSION */
            case MLAN_STATUS_FW_NOT_READY:
                result = -WIFI_ERROR_FW_NOT_READY;
                break;
        }

        PRINTF("sd_wifi_init failed, result:%d\r\n", result);
    }

    assert(WM_SUCCESS == result);

#if defined(RW610_SERIES) || defined(RW612_SERIES)
    NVIC_SetPriority(BOARD_UART_IRQ, 5);
    usart_config.srcclk = BOARD_DEBUG_UART_CLK_FREQ;
    usart_config.base   = BOARD_DEBUG_UART;
    hal_gpio_pin_config_t sw_config = {
        kHAL_GpioDirectionIn,
        0,
        SPI_INT_GPIO_PORT,
        SPI_INT_GPIO_PIN,
    };

    HAL_GpioInit(s_SpiMasterGpioHandle, &sw_config);
    HAL_GpioSetTriggerMode(s_SpiMasterGpioHandle, SPI_INT_TYPE);
    HAL_GpioInstallCallback(s_SpiMasterGpioHandle, SPI_MASTER_Callback, NULL);

    GPIO_ClearPinsInterruptFlags(SPI_INT_GPIO, 1U << SPI_INT_GPIO_PIN);
    GPIO_EnableInterrupts(SPI_INT_GPIO, 1U << SPI_INT_GPIO_PIN);
    EnableIRQ(SPI_INT_IRQ);

    NVIC_SetPriority(LPUART1_IRQn, 5);
    NVIC_SetPriority(LPUART7_IRQn, HAL_UART_ISR_PRIORITY);

    lpuart_config.srcclk = DEMO_LPUART_CLK_FREQ;
    lpuart_config.base   = DEMO_LPUART;

    lpuart_config_bt.srcclk = BOARD_BT_UART_CLK_FREQ;
    lpuart_config_bt.base   = LPUART7;

    if (kStatus_Success != LPUART_RTOS_Init(&handle, &t_handle, &lpuart_config))
    {
        vTaskSuspend(NULL);
    }

    if (kStatus_Success != LPUART_RTOS_Init(&handle_bt, &t_handle_bt, &lpuart_config_bt))
    {
        vTaskSuspend(NULL);
    }

    local_outbuf = os_mem_alloc(SDIO_OUTBUF_LEN);

    if (local_outbuf == NULL)
    {
        PRINTF("Failed to allocate buffer\r\n");
        return;
    }
    rx_buf = os_mem_alloc(BUF_LEN);

    LPSPI_MasterGetDefaultConfig(&spiConfig);
    spiConfig.baudRate = TRANSFER_BAUDRATE;
    spiConfig.whichPcs = LPSPI_MASTER_PCS_FOR_INIT;

    srcClock_Hz = LPSPI_MASTER_CLK_FREQ;
    LPSPI_MasterInit(LPSPI_MASTER_BASEADDR, &spiConfig, srcClock_Hz);

    /* Flushing the SPI RX buffer */
    spi_rx_collection();

    uart_cb *uart = &uartcb;
    uart_init_crc32(uart);
    
#if defined(RW610_SERIES) || defined(RW612_SERIES)
    /* Download firmware */
#if (CONFIG_SUPPORT_WIFI == 0) && (CONFIG_SUPPORT_15D4 == 0) && (CONFIG_SUPPORT_BLE == 0)
#error "One of CONFIG_SUPPORT_WIFI CONFIG_SUPPORT_15D4 and CONFIG_SUPPORT_BLE should be defined, or it will not download any formware!!"
#endif
#if defined(CONFIG_SUPPORT_WIFI) && (CONFIG_SUPPORT_WIFI == 1)
    sb3_fw_download(LOAD_WIFI_FIRMWARE, 1, 0);
#endif
    /* 15d4 single and 15d4+ble combo */
#if defined(CONFIG_SUPPORT_15D4) && (CONFIG_SUPPORT_15D4 == 1)
    sb3_fw_download(LOAD_15D4_FIRMWARE, 1, 0);
#endif
    /* only ble, no 15d4 */
#if defined(CONFIG_SUPPORT_15D4) && (CONFIG_SUPPORT_15D4 == 0) && defined (CONFIG_SUPPORT_BLE) && (CONFIG_SUPPORT_BLE == 1)
    sb3_fw_download(LOAD_BLE_FIRMWARE, 1, 0);
#endif

    /* Initialize WIFI Driver */
    imu_wifi_config();

    /* Initialize rpmsg */
    rpmsg_init();
#endif
    size_t uart_rx_len = 0;
    int len            = 0;
    int msg_len        = 0;
    while (1)
    {
        len         = 0;
        msg_len     = 0;
        uart_rx_len = 0;
        memset(uart->uart_buf, 0, sizeof(uart->uart_buf));
        while (len != LABTOOL_PATTERN_HDR_LEN)
        {
#if defined(RW610_SERIES) || defined(RW612_SERIES)
            USART_RTOS_Receive(&handle, uart->uart_buf + len, LABTOOL_PATTERN_HDR_LEN, &uart_rx_len);
#else
            LPUART_RTOS_Receive(&handle, uart->uart_buf + len, LABTOOL_PATTERN_HDR_LEN, &uart_rx_len);
            len += uart_rx_len;
        }

        /* Length of the packet is indicated by byte[2] & byte[3] of
        the packet excluding header[4 bytes] + checksum [4 bytes]
        */
        msg_len     = (uart->uart_buf[3] << 8) + uart->uart_buf[2];
        len         = 0;
        uart_rx_len = 0;
        while (len != msg_len + CHECKSUM_LEN)
        {
#if defined(RW610_SERIES) || defined(RW612_SERIES)
            USART_RTOS_Receive(&handle, uart->uart_buf + LABTOOL_PATTERN_HDR_LEN + len, msg_len + CHECKSUM_LEN - len,
                               &uart_rx_len);
#else
            LPUART_RTOS_Receive(&handle, uart->uart_buf + LABTOOL_PATTERN_HDR_LEN + len, msg_len + CHECKSUM_LEN - len,
                                &uart_rx_len);
            len += uart_rx_len;
        }

        /* validate the command including checksum */
        if (check_command_complete(uart->uart_buf) == WM_SUCCESS)
        {
            /* send fw cmd over SDIO after
               stripping off uart header */
            int ret = process_input_cmd(uart->uart_buf, msg_len + 8);
            memset(uart->uart_buf, 0, sizeof(uart->uart_buf));

#if defined(RW610_SERIES) || defined(RW612_SERIES)
            UNUSED(ret);
#else
            if (ret == RET_TYPE_WLAN)
            {
#ifdef SD8978
                vTaskDelay(pdMS_TO_TICKS(60));
#endif
                read_wlan_resp();
            }
            else if (ret == RET_TYPE_BT)
                read_bt_resp();
        }
        else
        {
            memset(background_buffer, 0, UART_BUF_SIZE);
        }
    }
}

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

int main(void)
{
    BaseType_t result = 0;
    (void)result;
    BOARD_InitHardware();
    BOARD_InitBTUARTPins();
    BOARD_InitSpiPins();

    result =
        xTaskCreate(task_main, "main", TASK_MAIN_STACK_SIZE, task_main_stack, TASK_MAIN_PRIO, &task_main_task_handler);
    assert(pdPASS == result);

    vTaskStartScheduler();
    for (;;)
        ;
}
