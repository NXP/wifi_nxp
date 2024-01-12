/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifdef CONFIG_NCP_SDIO
#include <fsl_common.h>
#include <fsl_sdio.h>
#include "ncp_sdio_host.h"
#include "fsl_adapter_gpio.h"
#include "fsl_gpio.h"
#include "fsl_debug_console.h"
#include "board.h"
#include "sdmmc_config.h"
#include "ncp_mcu_host_os.h"

/*******************************************************************************
 * Private macro
 ******************************************************************************/
#define SDHOST_CORE_STACK_SIZE (350)

/*! @brief SD power reset */
#define BOARD_SDMMC_SD_POWER_RESET_GPIO_BASE GPIO1
//#define BOARD_SDMMC_SD_POWER_RESET_GPIO_PORT 1
#define BOARD_SDMMC_SD_POWER_RESET_GPIO_PIN 19U

/*!@ brief host interrupt priority*/
#define BOARD_SDMMC_SDIO_HOST_IRQ_PRIORITY (5U)

/** Card Control Registers : Card to host event */
#define CARD_TO_HOST_EVENT_REG 0x5C
/** Card Control Registers : Upload card ready */
#define UP_LD_CARD_RDY (0x1U << 1)
/** Card Control Registers : Download card ready */
#define DN_LD_CARD_RDY (0x1U << 0)

/** The number of times to try when polling for status bits */
#define MAX_POLL_TRIES 100U

/** Card Control Registers : Function 1 Block size 0 */
#define FN1_BLOCK_SIZE_0 0x110
/** Card Control Registers : Function 1 Block size 1 */
#define FN1_BLOCK_SIZE_1 0x111

#define SDIO_DATA_OUTBUF_LEN 2052U
#define SDIO_CMD_OUTBUF_LEN  4100U

/** Port for memory */
#define MEM_PORT 0x10000

/** Card Control Registers : sdio new mode register 1 */
#define CARD_CONFIG_2_1_REG 0xD9
/** Card Control Registers : cmd53 new mode */
#define CMD53_NEW_MODE (0x1U << 0)

/* Card Control Registers : Command port configuration 0 */
#define CMD_CONFIG_0       0xC4
#define CMD_PORT_RD_LEN_EN (0x1U << 2)
/* Card Control Registers : Command port configuration 1 */
#define CMD_CONFIG_1 0xC5
/* Card Control Registers : cmd port auto enable */
#define CMD_PORT_AUTO_EN (0x1U << 0)

/** Host Control Registers : Host interrupt RSR */
#define HOST_INT_RSR_REG  0x04
#define HOST_INT_RSR_MASK 0xFF

/** Card Control Registers : Miscellaneous Configuration Register */
#define CARD_MISC_CFG_REG 0xD8

/** BIT value */
#define MBIT(x) (((uint32_t)1) << (x))
/** Misc. Config Register : Auto Re-enable interrupts */
#define AUTO_RE_ENABLE_INT MBIT(4)

/** Firmware status 0 register (SCRATCH0_0) */
#define CARD_FW_STATUS0_REG 0xe8
/** Firmware status 1 register (SCRATCH0_1) */
#define CARD_FW_STATUS1_REG 0xe9

/** define SDIO block size for data Tx/Rx */
/* We support up to 480-byte block size due to FW buffer limitation. */
#define SDIO_BLOCK_SIZE 256U

/* Command port */
#define CMD_PORT_SLCT 0x8000U
/** Data port mask */
#define DATA_PORT_MASK 0xffffffffU

/** Host Control Registers : Host interrupt mask */
#define HOST_INT_MASK_REG 0x08
/** Host Control Registers : Upload host interrupt mask */
#define UP_LD_HOST_INT_MASK (0x1U)
/** Host Control Registers : Download host interrupt mask */
#define DN_LD_HOST_INT_MASK (0x2U)
/** Host Control Registers : Cmd port upload interrupt mask */
#define CMD_PORT_UPLD_INT_MASK (0x1U << 6)
/** Host Control Registers : Cmd port download interrupt mask */
#define CMD_PORT_DNLD_INT_MASK (0x1U << 7)
/** Enable Host interrupt mask */
#define HIM_ENABLE (UP_LD_HOST_INT_MASK | DN_LD_HOST_INT_MASK | CMD_PORT_UPLD_INT_MASK | CMD_PORT_DNLD_INT_MASK)

/* Card Control Registers : Command port read length 0 */
#define CMD_RD_LEN_0 0xC0
/* Card Control Registers : Command port read length 1 */
#define CMD_RD_LEN_1 0xC1

/** Firmware ready */
#define FIRMWARE_READY 0xfedcU

#define MNULL ((void *)0)

/** Port for registers */
#define REG_PORT 0U
/** SDIO Block/Byte mode mask */
#define SDIO_BYTE_MODE_MASK 0x80000000U
/** Maximum numbfer of registers to read for multiple port */
#define MAX_MP_REGS 196
/** Maximum port */
#define MAX_PORT 32U
/** Host Control Registers : Host interrupt status */
#define HOST_INT_STATUS_REG 0x0C
/** LSB of read bitmap */
#define RD_BITMAP_L 0x10
/** MSB of read bitmap */
#define RD_BITMAP_U 0x11
/** LSB of read bitmap second word */
#define RD_BITMAP_1L 0x12
/** MSB of read bitmap second word */
#define RD_BITMAP_1U 0x13
/** LSB of write bitmap */
#define WR_BITMAP_L 0x14
/** MSB of write bitmap */
#define WR_BITMAP_U 0x15
/** LSB of write bitmap second word */
#define WR_BITMAP_1L 0x16
/** MSB of write bitmap second word */
#define WR_BITMAP_1U 0x17

/** Host Control Registers : Upload command port host interrupt status */
#define UP_LD_CMD_PORT_HOST_INT_STATUS (0x40U)
/** Host Control Registers : Download command port host interrupt status */
#define DN_LD_CMD_PORT_HOST_INT_STATUS (0x80U)
/** Host Control Registers : Upload host interrupt status */
#define UP_LD_HOST_INT_STATUS (0x1U)
/** Host Control Registers : Download host interrupt status */
#define DN_LD_HOST_INT_STATUS (0x2U)

/** Macros for Data Alignment : address */
#define ALIGN_ADDR(p, a) ((((uint32_t)(p)) + (((uint32_t)(a)) - 1U)) & ~(((uint32_t)(a)) - 1U))
/** DMA alignment */
#define DMA_ALIGNMENT 64U

/** LSB of read length for port 0 */
#define RD_LEN_P0_L 0x18
/** MSB of read length for port 0 */
#define RD_LEN_P0_U 0x19

/** Type command */
#define SDIO_TYPE_CMD 1U
/** Type data */
#define SDIO_TYPE_DATA 0U
/** Type event */
#define SDIO_TYPE_EVENT 3U

/** SDIO header length */
#define SDIO_HEADER_LEN 4U

/*******************************************************************************
 * Definitations
 ******************************************************************************/

/*******************************************************************************
 * Prototypes
 ******************************************************************************/
#ifdef CONFIG_NCP_SDIO
void sdio_host_save_recv_data(uint8_t *recv_data, uint32_t packet_len);
#endif

/*******************************************************************************
 * Variables
 ******************************************************************************/
static sdio_card_t g_sdio_card;
static OSA_MUTEX_HANDLE_DEFINE(sdio_mutex);
static TaskHandle_t sdhost_core_thread;

typedef struct _sdhost_ctrl
{
    /** IO port */
    uint32_t ioport;
    /** SDIO multiple port read bitmap */
    uint32_t mp_rd_bitmap;
    /** SDIO multiple port write bitmap */
    uint32_t mp_wr_bitmap;
    /** SDIO end port from txbufcfg */
    uint16_t mp_end_port;
    /** Current available port for read */
    uint8_t curr_rd_port;
    /** Current available port for write */
    uint8_t curr_wr_port;
    /** Array to store values of SDIO multiple port group registers */
    uint8_t *mp_regs;
} sdhost_ctrl_t;

static sdhost_ctrl_t sdhost_ctrl;

static uint32_t txportno;

static uint8_t mp_regs_buffer[MAX_MP_REGS + DMA_ALIGNMENT];
/*
 * Used to authorize the SDIO interrupt handler to accept the incoming
 * packet from the SDIO interface. If this flag is set a semaphore is
 * signalled.
 */
static bool g_txrx_flag;

/* @brief decription about the read/write buffer
 * The size of the read/write buffer should be a multiple of 512, since SDHC/SDXC card uses 512-byte fixed
 * block length and this driver example is enabled with a SDHC/SDXC card.If you are using a SDSC card, you
 * can define the block length by yourself if the card supports partial access.
 * The address of the read/write buffer should align to the specific DMA data buffer address align value if
 * DMA transfer is used, otherwise the buffer address is not important.
 * At the same time buffer address/size should be aligned to the cache line size if cache is supported.
 */
/*! @brief Data written to the card */
SDK_ALIGN(uint8_t sdh_outbuf[SDIO_CMD_OUTBUF_LEN], BOARD_SDMMC_DATA_BUFFER_ALIGN_SIZE);
SDK_ALIGN(uint8_t sdh_inbuf[SDIO_CMD_OUTBUF_LEN], BOARD_SDMMC_DATA_BUFFER_ALIGN_SIZE);

typedef struct
{
    uint16_t size;
    uint16_t pkttype;
} SDIOHeader;

/** Interrupt status */
static uint8_t g_sdio_ireg;

static OSA_MUTEX_HANDLE_DEFINE(txrx_mutex);

/*******************************************************************************
 * Code
 ******************************************************************************/
int sdio_drv_creg_read(int addr, int fn, uint32_t *resp)
{
    if (KOSA_StatusSuccess != OSA_MutexLock(&sdio_mutex, osaWaitForever_c))
    {
        (void)PRINTF("failed to get sdio_mutex\r\n");
        return false;
    }

    if (SDIO_IO_Read_Direct(&g_sdio_card, (sdio_func_num_t)fn, (uint32_t)addr, (uint8_t *)resp) != kStatus_Success)
    {
        (void)OSA_MutexUnlock(&sdio_mutex);
        return false;
    }

    (void)OSA_MutexUnlock(&sdio_mutex);

    return true;
}

bool sdio_drv_creg_write(int addr, int fn, uint8_t data, uint32_t *resp)
{
    if (KOSA_StatusSuccess != OSA_MutexLock(&sdio_mutex, osaWaitForever_c))
    {
        (void)PRINTF("failed to get sdio_mutex\r\n");
        return false;
    }

    if (SDIO_IO_Write_Direct(&g_sdio_card, (sdio_func_num_t)fn, (uint32_t)addr, &data, true) != kStatus_Success)
    {
        (void)OSA_MutexUnlock(&sdio_mutex);
        return false;
    }

    *resp = data;

    (void)OSA_MutexUnlock(&sdio_mutex);

    return true;
}

int sdio_drv_read(uint32_t addr, uint32_t fn, uint32_t bcnt, uint32_t bsize, uint8_t *buf, uint32_t *resp)
{
    uint32_t flags = 0;
    uint32_t param;

    if (KOSA_StatusSuccess != OSA_MutexLock(&sdio_mutex, osaWaitForever_c))
    {
        (void)PRINTF("failed to get sdio_mutex\r\n");
        return false;
    }

    if (bcnt > 1U)
    {
        flags |= SDIO_EXTEND_CMD_BLOCK_MODE_MASK;
        param = bcnt;
    }
    else
    {
        param = bsize;
    }

    if (SDIO_IO_Read_Extended(&g_sdio_card, (sdio_func_num_t)fn, addr, buf, param, flags) != kStatus_Success)
    {
        (void)OSA_MutexUnlock(&sdio_mutex);
        return false;
    }

    (void)OSA_MutexUnlock(&sdio_mutex);

    return true;
}

bool sdio_drv_write(uint32_t addr, uint32_t fn, uint32_t bcnt, uint32_t bsize, uint8_t *buf, uint32_t *resp)
{
    uint32_t flags = 0;
    uint32_t param;

    if (KOSA_StatusSuccess != OSA_MutexLock(&sdio_mutex, osaWaitForever_c))
    {
        (void)PRINTF("failed to get sdio_mutex\r\n");
        return false;
    }

    if (bcnt > 1U)
    {
        flags |= SDIO_EXTEND_CMD_BLOCK_MODE_MASK;
        param = bcnt;
    }
    else
    {
        param = bsize;
    }

    if (SDIO_IO_Write_Extended(&g_sdio_card, (sdio_func_num_t)fn, addr, buf, param, flags) != kStatus_Success)
    {
        (void)OSA_MutexUnlock(&sdio_mutex);
        return false;
    }

    (void)OSA_MutexUnlock(&sdio_mutex);

    return true;
}

static void SDIO_CardInterruptCallBack(void *userData)
{
    SDMMCHOST_EnableCardInt(g_sdio_card.host, false);

    /* Wake up sdhost core thread. */
    if ((sdhost_core_thread != MNULL) && g_txrx_flag)
    {
        g_txrx_flag = false;
        /* use xTaskNotifyGive(sdhost_core_thread)? */
        (void)os_event_notify_put(sdhost_core_thread);
    }
}

static uint32_t sdio_card_read_scratch_reg(void)
{
    uint32_t val    = 0;
    uint32_t rd_len = 0;

    (void)sdio_drv_creg_read(0x64, 1, &val);
    rd_len = (val & 0xffU);
    (void)sdio_drv_creg_read(0x65, 1, &val);
    rd_len |= ((val & 0xffU) << 8);
    (void)sdio_drv_creg_read(0x66, 1, &val);
    rd_len |= ((val & 0xffU) << 16);
    (void)sdio_drv_creg_read(0x67, 1, &val);
    rd_len |= ((val & 0xffU) << 24);

    return rd_len;
}

status sdio_ioport_init(void)
{
    /* this sets intmask on card and makes interrupts repeatable */
    uint32_t resp = 0;
    uint8_t data;

    sdhost_ctrl.ioport = MEM_PORT;

    (void)PRINTF("IOPORT : (0x%x)\r\n", sdhost_ctrl.ioport);

    /* Enable sdio cmd53 new mode */
    (void)sdio_drv_creg_read(CARD_CONFIG_2_1_REG, 1, &resp);
    data = (uint8_t)((resp & 0xff) | CMD53_NEW_MODE);
    (void)sdio_drv_creg_write(CARD_CONFIG_2_1_REG, 1, data, &resp);
    (void)sdio_drv_creg_read(CARD_CONFIG_2_1_REG, 1, &resp);

    /* configure cmd port  */
    /* enable reading rx length from the register  */
    (void)sdio_drv_creg_read(CMD_CONFIG_0, 1, &resp);
    data = (uint8_t)((resp & 0xff) | CMD_PORT_RD_LEN_EN);
    (void)sdio_drv_creg_write(CMD_CONFIG_0, 1, data, &resp);
    (void)sdio_drv_creg_read(CMD_CONFIG_0, 1, &resp);

    /* enable Dnld/Upld ready auto reset for cmd port
     * after cmd53 is completed */
    (void)sdio_drv_creg_read(CMD_CONFIG_1, 1, &resp);
    data = (uint8_t)((resp & 0xff) | CMD_PORT_AUTO_EN);
    (void)sdio_drv_creg_write(CMD_CONFIG_1, 1, data, &resp);
    (void)sdio_drv_creg_read(CMD_CONFIG_1, 1, &resp);

    /* Set Host interrupt reset to read to clear */
    (void)sdio_drv_creg_read(HOST_INT_RSR_REG, 1, &resp);
    data = (uint8_t)((resp & 0xff) | HOST_INT_RSR_MASK);
    (void)sdio_drv_creg_write(HOST_INT_RSR_REG, 1, data, &resp);

    /* Dnld/Upld ready set to auto reset */
    (void)sdio_drv_creg_read(CARD_MISC_CFG_REG, 1, &resp);
    data = (uint8_t)((resp & 0xff) | AUTO_RE_ENABLE_INT);
    (void)sdio_drv_creg_write(CARD_MISC_CFG_REG, 1, data, &resp);
    // txportno = sdhost_ctrl.ioport;
    return STATUS_SUCCESS;
}

static bool sdio_card_ready_wait(uint32_t card_poll)
{
    uint16_t dat  = 0U;
    uint32_t i    = 0U;
    uint32_t resp = 0;

    for (i = 0; i < card_poll; i++)
    {
        (void)sdio_drv_creg_read(CARD_FW_STATUS0_REG, 1, &resp);
        dat = (uint16_t)(resp & 0xffU);
        (void)sdio_drv_creg_read(CARD_FW_STATUS1_REG, 1, &resp);
        dat |= (uint16_t)((resp & 0xffU) << 8);
        if (dat == FIRMWARE_READY)
        {
            (void)PRINTF("Firmware Ready\r\n");
            return true;
        }
        vTaskDelay((5) / (portTICK_PERIOD_MS));
    }
    return false;
}

/*
 * This function gets interrupt status.
 */
void sdhost_interrupt(void)
{
    /* Read SDIO multiple port group registers */
    uint32_t resp = 0;
    int ret;

    /* Read the registers in DMA aligned buffer */
    ret = sdio_drv_read(REG_PORT | SDIO_BYTE_MODE_MASK, 1, 1, MAX_MP_REGS, sdhost_ctrl.mp_regs, &resp);

    if (!ret)
    {
        return;
    }

    uint8_t sdio_ireg = sdhost_ctrl.mp_regs[HOST_INT_STATUS_REG];

    if (sdio_ireg != 0U)
    {
        /*
         * DN_LD_HOST_INT_STATUS and/or UP_LD_HOST_INT_STATUS
         * Clear the interrupt status register
         */
        g_sdio_ireg |= sdio_ireg;
    }

#ifdef CONFIG_SDIO_IO_DEBUG
    uint32_t rd_bitmap, wr_bitmap;
    rd_bitmap = (uint32_t)sdhost_ctrl.mp_regs[RD_BITMAP_L];
    rd_bitmap |= ((uint32_t)sdhost_ctrl.mp_regs[RD_BITMAP_U]) << 8;
    rd_bitmap |= ((uint32_t)sdhost_ctrl.mp_regs[RD_BITMAP_1L]) << 16;
    rd_bitmap |= ((uint32_t)sdhost_ctrl.mp_regs[RD_BITMAP_1U]) << 24;

    (void)PRINTF("INT : rd_bitmap=0x%x\n\r", rd_bitmap);

    wr_bitmap = (uint32_t)sdhost_ctrl.mp_regs[WR_BITMAP_L];
    wr_bitmap |= ((uint32_t)sdhost_ctrl.mp_regs[WR_BITMAP_U]) << 8;
    wr_bitmap |= ((uint32_t)sdhost_ctrl.mp_regs[WR_BITMAP_1L]) << 16;
    wr_bitmap |= ((uint32_t)sdhost_ctrl.mp_regs[WR_BITMAP_1U]) << 24;

    (void)PRINTF("INT : wr_bitmap=0x%x\n\r", wr_bitmap);

    (void)PRINTF("INT : sdio_ireg = (0x%x)\r\n", sdio_ireg);
#endif /* CONFIG_SDIO_IO_DEBUG */
}

/*
 * This function keeps on looping till all the packets are read
 */
static void handle_sdio_cmd_read(uint32_t rx_len, uint32_t rx_blocks)
{
    uint8_t ret;
    uint32_t blksize = SDIO_BLOCK_SIZE;
    uint32_t resp;

    /* addr = 0 fn = 1 */
    ret = sdio_drv_read(sdhost_ctrl.ioport | CMD_PORT_SLCT, 1, rx_blocks, blksize, sdh_inbuf, &resp);
    if (!ret)
    {
        (void)PRINTF("sdio_drv_read failed (%d)\r\n", ret);
        return;
    }

#ifdef CONFIG_NCP_HOST_IO_DUMP
    SDIOHeader *sdioheader = (SDIOHeader *)(void *)sdh_inbuf;

    if (sdioheader->pkttype == SDIO_TYPE_CMD)
    {
        (void)PRINTF("handle_sdio_packet_read: DUMP:");
        dump_hex((uint8_t *)sdh_inbuf, 1 * rx_len);
    }
#endif

    sdio_host_save_recv_data((uint8_t *)sdh_inbuf + SDIO_HEADER_LEN, rx_len - SDIO_HEADER_LEN);
}

/* returns port number from rd_bitmap. if ctrl port, then it clears
 * the bit and does nothing else
 * if data port then increments curr_port value also */
static status get_rd_port(uint32_t *pport)
{
    uint32_t rd_bitmap = sdhost_ctrl.mp_rd_bitmap;

    if (!(rd_bitmap & DATA_PORT_MASK))
        return STATUS_FAILURE;

    /* Data */
    if ((sdhost_ctrl.mp_rd_bitmap & (1 << sdhost_ctrl.curr_rd_port)) != 0U)
    {
        sdhost_ctrl.mp_rd_bitmap &= (uint32_t)(~(1 << sdhost_ctrl.curr_rd_port));

        *pport = sdhost_ctrl.curr_rd_port;

        if (++sdhost_ctrl.curr_rd_port == sdhost_ctrl.mp_end_port)
            sdhost_ctrl.curr_rd_port = 0;
    }
    else
    {
        (void)PRINTF("wlan_get_rd_port : Returning FAILURE\r\n");
        return STATUS_FAILURE;
    }

    //(void)PRINTF("port=%d mp_rd_bitmap=0x%x -> 0x%x\r\n", *pport, rd_bitmap, sdhost_ctrl.mp_rd_bitmap);

    return STATUS_SUCCESS;
}

/*
 * This function keeps on looping till all the packets are read
 */
static void handle_sdio_packet_read(void)
{
    uint8_t ret;

    sdhost_ctrl.mp_rd_bitmap = (uint32_t)sdhost_ctrl.mp_regs[RD_BITMAP_L];
    sdhost_ctrl.mp_rd_bitmap |= ((uint32_t)sdhost_ctrl.mp_regs[RD_BITMAP_U]) << 8;
    sdhost_ctrl.mp_rd_bitmap |= ((uint32_t)sdhost_ctrl.mp_regs[RD_BITMAP_1L]) << 16;
    sdhost_ctrl.mp_rd_bitmap |= ((uint32_t)sdhost_ctrl.mp_regs[RD_BITMAP_1U]) << 24;

    uint32_t port = 0;
    // Just use one port firstly, would extended to multiple ports if needed
    sdhost_ctrl.curr_rd_port = 0;
    while (true)
    {
        ret = get_rd_port(&port);
        /* nothing to read */
        if (ret != STATUS_SUCCESS)
            break;
        uint32_t rx_len, rx_blocks;

        uint32_t len_reg_l = RD_LEN_P0_L + (port << 1);
        uint32_t len_reg_u = RD_LEN_P0_U + (port << 1);

        rx_len  = ((uint16_t)sdhost_ctrl.mp_regs[len_reg_u]) << 8;
        rx_len |= (uint16_t)sdhost_ctrl.mp_regs[len_reg_l];
        //(void)PRINTF("handle_sdio_packet_read: rx_len (%d)\r\n", rx_len);

        rx_blocks = (rx_len + SDIO_BLOCK_SIZE - 1) / SDIO_BLOCK_SIZE;
        rx_len    = (uint16_t)(rx_blocks * SDIO_BLOCK_SIZE);

        port = sdhost_ctrl.ioport + port;

        uint32_t resp;
        ret = sdio_drv_read(port, 1, rx_blocks, rx_len, sdh_inbuf, &resp);
        if (!ret)
        {
            (void)PRINTF("sdio_drv_read failed (%d)\r\n", ret);
            break;
        }

#ifdef CONFIG_NCP_HOST_IO_DUMP
        SDIOHeader *sdioheader = (SDIOHeader *)(void *)sdh_inbuf;

        if (sdioheader->pkttype == SDIO_TYPE_DATA)
        {
            (void)PRINTF("handle_sdio_packet_read: DUMP:");
            dump_hex((uint8_t *)sdh_inbuf, 1 * datalen);
        }
#endif
        sdio_host_save_recv_data((uint8_t *)sdh_inbuf + SDIO_HEADER_LEN, rx_len - SDIO_HEADER_LEN);
    }
}

/*
 * This is supposed to be called in thread context.
 */
status sdhost_process_int_status(void)
{
    status ret           = STATUS_SUCCESS;
    uint8_t cmd_rd_len_0 = CMD_RD_LEN_0;
    uint8_t cmd_rd_len_1 = CMD_RD_LEN_1;
    uint32_t rx_len;
    uint32_t rx_blocks;

    /* Get the interrupt status */
    sdhost_interrupt();

    uint8_t sdio_ireg = g_sdio_ireg;
    g_sdio_ireg       = 0;

    if (!sdio_ireg)
    {
        goto done;
    }

    /* check the command port */
    /*if ((sdio_ireg & DN_LD_CMD_PORT_HOST_INT_STATUS) != 0U)
    {
        (void)PRINTF("cmd sent\r\n");
    }*/

    if ((sdio_ireg & UP_LD_CMD_PORT_HOST_INT_STATUS) != 0U)
    {
        /* read the len of control packet */
        rx_len = ((uint32_t)sdhost_ctrl.mp_regs[cmd_rd_len_1]) << 8;
        rx_len |= (uint32_t)sdhost_ctrl.mp_regs[cmd_rd_len_0];
        //(void)PRINTF("RX: cmd port rx_len=%u\r\n", rx_len);

        rx_blocks = (rx_len + SDIO_BLOCK_SIZE - 1U) / SDIO_BLOCK_SIZE;

        //(void)PRINTF("CMD: cmd port rx_len=%u rx_blocks=%u\r\n", rx_len, rx_blocks);
        // rx_len = (uint32_t)(rx_blocks * SDIO_BLOCK_SIZE);

        handle_sdio_cmd_read(rx_len, rx_blocks);
    }

    sdhost_ctrl.mp_wr_bitmap = (uint32_t)sdhost_ctrl.mp_regs[WR_BITMAP_L];
    sdhost_ctrl.mp_wr_bitmap |= ((uint32_t)sdhost_ctrl.mp_regs[WR_BITMAP_U]) << 8;
    sdhost_ctrl.mp_wr_bitmap |= ((uint32_t)sdhost_ctrl.mp_regs[WR_BITMAP_1L]) << 16;
    sdhost_ctrl.mp_wr_bitmap |= ((uint32_t)sdhost_ctrl.mp_regs[WR_BITMAP_1U]) << 24;

    /*
     * DN_LD_HOST_INT_STATUS interrupt happens when the txmit sdio
     * ports are freed This is usually when we write to port most
     * significant port.
     */
    if ((sdio_ireg & DN_LD_HOST_INT_STATUS) != 0U)
    {
        sdhost_ctrl.mp_wr_bitmap = (uint32_t)sdhost_ctrl.mp_regs[WR_BITMAP_L];
        sdhost_ctrl.mp_wr_bitmap |= ((uint32_t)sdhost_ctrl.mp_regs[WR_BITMAP_U]) << 8;
        sdhost_ctrl.mp_wr_bitmap |= ((uint32_t)sdhost_ctrl.mp_regs[WR_BITMAP_1L]) << 16;
        sdhost_ctrl.mp_wr_bitmap |= ((uint32_t)sdhost_ctrl.mp_regs[WR_BITMAP_1U]) << 24;
        //(void)PRINTF("data sent\r\n");
    }

    if ((sdio_ireg & UP_LD_HOST_INT_STATUS) != 0U)
    {
        /* This means there is data to be read */
        handle_sdio_packet_read();
    }

    ret = STATUS_SUCCESS;

done:
    return ret;
}

static status sdio_post_init(void)
{
    status status = STATUS_SUCCESS;
    uint32_t resp;

    (void)sdio_drv_creg_write(HOST_INT_MASK_REG, 1, HIM_ENABLE, &resp);

    return status;
}

/**
 *  @brief This function reads the CARD_TO_HOST_EVENT_REG and
 *  checks if input bits are set
 *  @param bits		bits to check status against
 *  @return		true if bits are set
 *                      SDIO_POLLING_STATUS_TIMEOUT if bits
 *                      aren't set
 */
bool sdio_card_status(uint8_t bits)
{
    uint32_t resp = 0;
    uint32_t tries;

    for (tries = 0; tries < MAX_POLL_TRIES; tries++)
    {
        if (!(sdio_drv_creg_read(CARD_TO_HOST_EVENT_REG, 1, &resp)))
        {
            return false;
        }
        if ((resp & bits) == bits)
        {
            return true;
        }
        vTaskDelay((1) / (portTICK_PERIOD_MS));
    }
    return false;
}

/**
 * This function should be called when a packet is ready to be read
 * from the interface.
 */
static void sdhost_core_input(void *argv)
{
    for (;;)
    {
        OSA_SR_ALLOC();
        OSA_ENTER_CRITICAL();
        /* Allow interrupt handler to deliver us a packet */
        g_txrx_flag = true;
        if (g_sdio_card.isHostReady)
        {
            SDMMCHOST_EnableCardInt(g_sdio_card.host, true);
        }

        OSA_EXIT_CRITICAL();

        /* Wait till we receive a packet from SDIO */
        ulTaskNotifyTake(pdTRUE, portMAX_DELAY);

        /* Protect the SDIO from other parallel activities */
        if (KOSA_StatusSuccess != OSA_MutexLock(&txrx_mutex, osaWaitForever_c))
        {
            PRINTF("\r\nFailed to take txrx_mutex semaphore.\r\n");
            break;
        }

        (void)sdhost_process_int_status();

        (void)OSA_MutexUnlock(&txrx_mutex);
    } /* for ;; */
}

static void BOARD_SD_Enable(bool enable)
{
    if (enable)
    {
        /* Enable module */
        /* Enable power supply for SD */
        GPIO_PinWrite(BOARD_SDMMC_SD_POWER_RESET_GPIO_BASE, BOARD_SDMMC_SD_POWER_RESET_GPIO_PIN, 1);
        OSA_TimeDelay(100);
    }
    else
    {
        /* Disable module */
        /* Disable power supply for SD */
        GPIO_PinWrite(BOARD_SDMMC_SD_POWER_RESET_GPIO_BASE, BOARD_SDMMC_SD_POWER_RESET_GPIO_PIN, 0);
        OSA_TimeDelay(100);
    }
}

static void sdio_controller_init(void)
{
    (void)memset(&g_sdio_card, 0, sizeof(sdio_card_t));

    BOARD_SDIO_Config(&g_sdio_card, NULL, BOARD_SDMMC_SDIO_HOST_IRQ_PRIORITY, SDIO_CardInterruptCallBack);
    g_sdio_card.usrParam.pwr = NULL;

    BOARD_SD_Enable(false);

    g_sdio_card.currentTiming = SD_TIMING_MAX;
}

static status sdio_card_init(void)
{
    int ret;
    (void)ret;

    if (SDIO_HostInit(&g_sdio_card) != KOSA_StatusSuccess)
    {
        (void)PRINTF("Failed to init sdio host\r\n");
        return STATUS_FAILURE;
    }

    /* Switch to 1.8V */
    if ((g_sdio_card.usrParam.ioVoltage != NULL) && (g_sdio_card.usrParam.ioVoltage->type == kSD_IOVoltageCtrlByGpio))
    {
        if (g_sdio_card.usrParam.ioVoltage->func != NULL)
        {
            g_sdio_card.usrParam.ioVoltage->func(kSDMMC_OperationVoltage180V);
        }
    }
    else if ((g_sdio_card.usrParam.ioVoltage != NULL) &&
             (g_sdio_card.usrParam.ioVoltage->type == kSD_IOVoltageCtrlByHost))
    {
        SDMMCHOST_SwitchToVoltage(g_sdio_card.host, (uint32_t)kSDMMC_OperationVoltage180V);
    }
    else
    {
        /* Do Nothing */
    }
    g_sdio_card.operationVoltage = kSDMMC_OperationVoltage180V;

    BOARD_SD_Enable(true);

    ret = SDIO_CardInit(&g_sdio_card);
    if (ret != kStatus_Success)
    {
        return STATUS_FAILURE;
    }

    uint32_t resp;

    (void)sdio_drv_creg_read(0x0, 0, &resp);

    (void)PRINTF("Card Version - (0x%x)\r\n", resp & 0xff);

    /* Mask interrupts in card */
    (void)sdio_drv_creg_write(0x4, 0, 0x3, &resp);
    /* Enable IO in card */
    (void)sdio_drv_creg_write(0x2, 0, 0x2, &resp);

    (void)SDIO_SetBlockSize(&g_sdio_card, (sdio_func_num_t)0, 256);
    (void)SDIO_SetBlockSize(&g_sdio_card, (sdio_func_num_t)1, 256);
    (void)SDIO_SetBlockSize(&g_sdio_card, (sdio_func_num_t)2, 256);

    return STATUS_SUCCESS;
}

static status sdio_drvInit(void)
{
    if (KOSA_StatusSuccess != OSA_MutexCreate(&sdio_mutex))
    {
        (void)PRINTF("Failed to create sdio_mutex\r\n");
        return STATUS_FAILURE;
    }

    sdio_controller_init();

    if (sdio_card_init() != STATUS_SUCCESS)
    {
        (void)PRINTF("Card initialization failed\r\n");
        return STATUS_FAILURE;
    }
    else
    {
        (void)PRINTF("Card initialization successful\r\n");
    }

    return STATUS_SUCCESS;
}

static status sdio_hostInit(void)
{
    int ret;
    (void)ret;

    ret = sdio_drvInit();
    if (ret != STATUS_SUCCESS)
    {
        (void)PRINTF("Failed to int sdio driver\r\n");
        return STATUS_FAILURE;
    }

    uint32_t resp;
    bool sdio_card_stat;
    ret = sdio_drv_creg_read(CARD_TO_HOST_EVENT_REG, 1, &resp);
    if (ret && (resp & (DN_LD_CARD_RDY)) == 0U)
    {
        sdio_card_stat = sdio_card_status(UP_LD_CARD_RDY);
        if (sdio_card_stat != false)
        {
            uint32_t rd_len;
            rd_len = sdio_card_read_scratch_reg();
            if (rd_len > 0U)
            {
                (void)sdio_drv_creg_write(FN1_BLOCK_SIZE_0, 0, 0x8, &resp);
                (void)sdio_drv_creg_write(FN1_BLOCK_SIZE_1, 0, 0x0, &resp);

                uint8_t buf[256];
                ret = sdio_drv_read(0x10000, 1, rd_len, 8, buf, &resp);
                if (!ret)
                {
                    (void)PRINTF(
                        "SDIO read failed, "
                        "resp:%x\r\n",
                        resp);
                    return STATUS_FAILURE;
                }
            }
        }
    }
    else if (!ret)
    {
        (void)PRINTF("failed to read EVENT_REG");
        return STATUS_FAILURE;
    }

    return STATUS_SUCCESS;
}

status ncp_sdhost_init(void)
{
    int ret;
    (void)ret;

    // sdhost_ctrl.mp_wr_bitmap = 0;
    sdhost_ctrl.mp_wr_bitmap = 0xffffffff;
    sdhost_ctrl.mp_rd_bitmap = 0;
    sdhost_ctrl.curr_rd_port = 0;
    sdhost_ctrl.curr_wr_port = 0;
    sdhost_ctrl.mp_regs      = (uint8_t *)ALIGN_ADDR(mp_regs_buffer, DMA_ALIGNMENT);
    sdhost_ctrl.mp_end_port  = MAX_PORT;

    txportno = 0;

    ret = sdio_hostInit();
    if (ret != STATUS_SUCCESS)
    {
        (void)PRINTF("Failed to int sdio host driver\r\n");
        return STATUS_FAILURE;
    }

    ret = sdio_ioport_init();
    if (ret == STATUS_SUCCESS)
    {
        if (sdio_card_ready_wait(1000) != true)
        {
            (void)PRINTF("SDIO slave not ready\r\n");
        }
        else
        {
            (void)PRINTF("SDIO slave ready\r\n");
        }
    }

    ret = xTaskCreate(sdhost_core_input, "sdhost_core", SDHOST_CORE_STACK_SIZE, NULL, OS_PRIO_1, &sdhost_core_thread);
    if (ret != pdPASS)
    {
        (void)PRINTF("Create sdhost core thread failed\r\n");
    }

    if (KOSA_StatusSuccess != OSA_MutexCreate(&txrx_mutex))
    {
        (void)PRINTF("Failed to create txrx_mutex\r\n");
        return STATUS_FAILURE;
    }

    ret = sdio_post_init();

    return STATUS_SUCCESS;
}

status sdio_deinit(void)
{
    SDIO_Deinit(&g_sdio_card);

    if (KOSA_StatusSuccess != OSA_MutexDestroy(&sdio_mutex))
    {
        (void)PRINTF("Failed to delete sdio mutex\r\n");
    }

    if (KOSA_StatusSuccess != OSA_MutexDestroy(&txrx_mutex))
    {
        (void)PRINTF("Failed to delete txrx mutex\r\n");
    }

    return STATUS_SUCCESS;
}

void calculate_sdio_write_params(uint32_t txlen, uint32_t *tx_blocks, uint32_t *buflen)
{
    *tx_blocks = (txlen + SDIO_BLOCK_SIZE - 1) / SDIO_BLOCK_SIZE;

    *buflen = SDIO_BLOCK_SIZE;
}

#if 0
static int get_free_port(void)
{
    /* Check if the port is available */
    if (!((1 << txportno) & sdhost_ctrl.mp_wr_bitmap))
    {
        (void)PRINTF("txportno out of sync txportno = (%d) mp_wr_bitmap = (0x%x)\r\n", txportno,
                     sdhost_ctrl.mp_wr_bitmap);

        return STATUS_FAILURE;
    }
    else
    {
        /* Mark the port number we will use */
        sdhost_ctrl.mp_wr_bitmap &= ~(1 << txportno);
    }
    return STATUS_SUCCESS;
}
#endif

status ncp_sdhost_send_data(uint8_t *buf, uint32_t length)
{
    int ret;
    (void)ret;
    uint32_t tx_blocks = 0, buflen = 0;
    SDIOHeader *sdioheader = (SDIOHeader *)(void *)sdh_outbuf;
    uint32_t resp;

    if ((buf == MNULL) || !length)
    {
        return STATUS_FAILURE;
    }

    if (length > SDIO_DATA_OUTBUF_LEN - SDIO_HEADER_LEN)
    {
        (void)PRINTF("Insufficient buffer\r\n");
        return STATUS_FAILURE;
    }

    if (KOSA_StatusSuccess != OSA_MutexLock(&txrx_mutex, osaWaitForever_c))
    {
        (void)PRINTF("failed to get txrx_mutex\r\n");
        return STATUS_FAILURE;
    }
    (void)memset(sdh_outbuf, 0, SDIO_CMD_OUTBUF_LEN);
    sdioheader->pkttype = SDIO_TYPE_DATA;
    sdioheader->size    = length + SDIO_HEADER_LEN;
    calculate_sdio_write_params(sdioheader->size, &tx_blocks, &buflen);
    (void)memcpy((void *)(sdh_outbuf + SDIO_HEADER_LEN), (const void *)buf, length);

    /*ret = get_free_port();
    if (ret == STATUS_FAILURE)
    {
        (void)PRINTF("Get free port failed\r\n");
        return STATUS_FAILURE;
    }
    else
    {
         (void)PRINTF("Get free port %d\r\n", txportno);
    }*/
    (void)sdio_drv_write(sdhost_ctrl.ioport + txportno, 1, tx_blocks, buflen, (uint8_t *)sdh_outbuf, &resp);
    /*txportno++;
    if (txportno == sdhost_ctrl.mp_end_port)
    {
        txportno = 0;
    }*/
    (void)OSA_MutexUnlock(&txrx_mutex);

    return STATUS_SUCCESS;
}

status ncp_sdhost_send_cmd(uint8_t *buf, uint32_t length)
{
    int ret;
    (void)ret;
    SDIOHeader *sdioheader = (SDIOHeader *)(void *)sdh_outbuf;
    uint32_t resp;

    if ((buf == MNULL) || !length)
    {
        return STATUS_FAILURE;
    }

    if (length > SDIO_CMD_OUTBUF_LEN - SDIO_HEADER_LEN)
    {
        (void)PRINTF("Insufficient buffer\r\n");
        return STATUS_FAILURE;
    }

    if (KOSA_StatusSuccess != OSA_MutexLock(&txrx_mutex, osaWaitForever_c))
    {
        (void)PRINTF("failed to get txrx_mutex\r\n");
        return STATUS_FAILURE;
    }
    (void)memset(sdh_outbuf, 0, SDIO_CMD_OUTBUF_LEN);
    sdioheader->pkttype = SDIO_TYPE_CMD;
    sdioheader->size    = length + SDIO_HEADER_LEN;
    uint32_t tx_blocks = 0, buflen = 0;
    calculate_sdio_write_params(sdioheader->size, &tx_blocks, &buflen);

    (void)memcpy((void *)(sdh_outbuf + SDIO_HEADER_LEN), (const void *)buf, length);
    (void)sdio_drv_write(sdhost_ctrl.ioport | CMD_PORT_SLCT, 1, tx_blocks, buflen, (uint8_t *)sdh_outbuf, &resp);
    (void)OSA_MutexUnlock(&txrx_mutex);

    return STATUS_SUCCESS;
}
#endif /* CONFIG_SDIO_BRIDGE */
