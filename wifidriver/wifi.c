/** @file wifi.c
 *
 *  @brief  This file provides WiFi Core API
 *
 *  Copyright 2008-2023 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <mlan_api.h>

#include <stdio.h>
#include <string.h>
#include <wifi.h>
#include <wm_os.h>

#include "wifi-internal.h"
#if defined(RW610)
#include "wifi-imu.h"
#else
#include <mlan_sdio_api.h>
#include "wifi-sdio.h"
#include "mlan_sdio.h"
#include "sdio.h"
#include "firmware_dnld.h"

#ifdef CONFIG_WMM
#include "sdmmc_config.h"
#endif
#endif
#ifdef RW610
#include "fsl_adapter_rfimu.h"
#endif

/* Always keep this include at the end of all include files */
#include <mlan_remap_mem_operations.h>

#ifdef CONFIG_HEAP_DEBUG
os_semaphore_t os_mem_stat_sem;

t_u32 valid_item_cnt = 0;
wifi_os_mem_info wifi_os_mem_stat[OS_MEM_STAT_TABLE_SIZE];
#endif

#ifdef CONFIG_CSI
#define MAX_CSI_LOCAL_BUF        80
#define CSI_LOCAL_BUF_ENTRY_SIZE 768
t_u8 csi_local_buff[MAX_CSI_LOCAL_BUF][CSI_LOCAL_BUF_ENTRY_SIZE] = {
    0,
};

csi_local_buff_statu csi_buff_stat = {0, 0, 0};

int csi_event_cnt        = 0;
t_u64 csi_event_data_len = 0;
#endif

#define WIFI_COMMAND_RESPONSE_WAIT_MS 20000
#define WIFI_CORE_STACK_SIZE          (1024)
/* We don't see events coming in quick succession,
 * MAX_EVENTS = 10 is fairly big value */
#define MAX_EVENTS    20
#define MAX_MCAST_LEN (MLAN_MAX_MULTICAST_LIST_SIZE * MLAN_MAC_ADDR_LENGTH)
#ifdef CONFIG_WiFi_878x
#define MAX_WAIT_TIME 20
#else
#define MAX_WAIT_TIME 35
#endif

#ifndef USB_SUPPORT_ENABLE
#define _T(x) x
#endif

#ifdef CONFIG_WMM
#ifdef RW610
#define BOARD_DATA_BUFFER_ALIGN_SIZE 32
#else
#define BOARD_DATA_BUFFER_ALIGN_SIZE BOARD_SDMMC_DATA_BUFFER_ALIGN_SIZE
#endif

#ifdef CONFIG_WMM_ENH
SDK_ALIGN(uint8_t outbuf_arr[MAX_WMM_BUF_NUM][OUTBUF_WMM_LEN], BOARD_DATA_BUFFER_ALIGN_SIZE);
#else
/* @brief decription about the read/write buffer
 * The size of the read/write buffer should be a multiple of 512, since SDHC/SDXC card uses 512-byte fixed
 * block length and this driver example is enabled with a SDHC/SDXC card.If you are using a SDSC card, you
 * can define the block length by yourself if the card supports partial access.
 * The address of the read/write buffer should align to the specific DMA data buffer address align value if
 * DMA transfer is used, otherwise the buffer address is not important.
 * At the same time buffer address/size should be aligned to the cache line size if cache is supported.
 */
/*! @brief Data written to the card */
SDK_ALIGN(uint8_t outbuf_bk[BK_MAX_BUF][DATA_BUFFER_SIZE], BOARD_DATA_BUFFER_ALIGN_SIZE);
SDK_ALIGN(uint8_t outbuf_vi[VI_MAX_BUF][DATA_BUFFER_SIZE], BOARD_DATA_BUFFER_ALIGN_SIZE);
SDK_ALIGN(uint8_t outbuf_vo[VO_MAX_BUF][DATA_BUFFER_SIZE], BOARD_DATA_BUFFER_ALIGN_SIZE);
SDK_ALIGN(uint8_t outbuf_be[BE_MAX_BUF][DATA_BUFFER_SIZE], BOARD_DATA_BUFFER_ALIGN_SIZE);
#endif
#endif
/* Global variable wm_rand_seed */
uint32_t wm_rand_seed = -1;

static t_u8 wifi_init_done;
static t_u8 wifi_core_init_done;

#ifdef CONFIG_STA_AMPDU_TX
static bool sta_ampdu_tx_enable = true;
#if defined(WIFI_ADD_ON)
t_u8 sta_ampdu_tx_enable_per_tid = 0xFF;
#endif
#endif

#ifdef CONFIG_STA_AMPDU_RX
bool sta_ampdu_rx_enable = true;
#if defined(WIFI_ADD_ON)
t_u8 sta_ampdu_rx_enable_per_tid = 0xFF;
#endif
#endif

#if defined(WIFI_ADD_ON)
#ifdef CONFIG_UAP_AMPDU_TX
bool uap_ampdu_tx_enable         = true;
t_u8 uap_ampdu_tx_enable_per_tid = 0xFF;
#endif

#ifdef CONFIG_UAP_AMPDU_RX
bool uap_ampdu_rx_enable         = true;
t_u8 uap_ampdu_rx_enable_per_tid = 0xFF;
#endif
#endif

int retry_attempts;
wm_wifi_t wm_wifi;
static bool xfer_pending;
static bool scan_thread_in_process = false;

typedef enum __mlan_status
{
    MLAN_CARD_NOT_DETECTED = 3,
    MLAN_STATUS_FW_DNLD_FAILED,
    MLAN_STATUS_FW_NOT_DETECTED,
    MLAN_STATUS_FW_NOT_READY,
#ifdef CONFIG_XZ_DECOMPRESSION
    MLAN_STATUS_FW_XZ_FAILED,
#endif /* CONFIG_XZ_DECOMPRESSION */
    MLAN_CARD_CMD_TIMEOUT
} __mlan_status;

static os_thread_stack_define(wifi_core_stack, WIFI_CORE_STACK_SIZE * sizeof(portSTACK_TYPE));
static os_thread_stack_define(wifi_scan_stack, 2048);
static os_thread_stack_define(wifi_drv_stack, 2048);
static os_queue_pool_define(g_io_events_queue_data, (int)(sizeof(struct bus_message) * MAX_EVENTS));
#ifdef CONFIG_WMM
static os_queue_pool_define(g_tx_data_queue_data, sizeof(struct bus_message) * MAX_EVENTS);
#endif
int wifi_set_mac_multicast_addr(const char *mlist, t_u32 num_of_addr);
int wrapper_get_wpa_ie_in_assoc(uint8_t *wpa_ie);
#ifdef CONFIG_WMM
static void wifi_driver_tx(void *data);
#endif
extern void process_pkt_hdrs(void *pbuf, t_u32 payloadlen, t_u8 interface);

unsigned wifi_get_last_cmd_sent_ms(void)
{
    return wm_wifi.last_sent_cmd_msec;
}

uint32_t wifi_get_value1(void)
{
    return wifi_get_device_value1();
}

/* Wake up Wi-Fi card */
void wifi_wake_up_card(uint32_t *resp)
{
    wcmdr_d("Wakeup device...");
#ifndef RW610
    (void)sdio_drv_creg_write(0x0, 1, 0x02, resp);
#else
    imu_wakeup_card();
#endif
}

/* When Wi-Fi card is in IEEE PS and sleeping
 * CMD or Data cannot be transmited.
 * The card must be woken up.
 * So data or command trasnfer is temporarily kept
 * in pending state. This function returns value
 * of pending flag true/false.
 */
bool wifi_get_xfer_pending(void)
{
    return xfer_pending;
}
/*
 * This function sets the flag value
 */
void wifi_set_xfer_pending(bool xfer_val)
{
    xfer_pending = xfer_val;
}

void wifi_update_last_cmd_sent_ms(void)
{
    wm_wifi.last_sent_cmd_msec = os_ticks_to_msec(os_ticks_get());
}

static int wifi_get_command_resp_sem(unsigned long wait)
{
    return os_semaphore_get(&wm_wifi.command_resp_sem, wait);
}

static int wifi_put_command_resp_sem(void)
{
    return os_semaphore_put(&wm_wifi.command_resp_sem);
}

#define WL_ID_WIFI_CMD "wifi_cmd"

int wifi_get_command_lock(void)
{
    int rv; // = wakelock_get(WL_ID_WIFI_CMD);
            //	if (rv == WM_SUCCESS)
    rv = os_mutex_get(&wm_wifi.command_lock, OS_WAIT_FOREVER);

    return rv;
}

static int wifi_get_mcastf_lock(void)
{
    return os_mutex_get(&wm_wifi.mcastf_mutex, OS_WAIT_FOREVER);
}

static int wifi_put_mcastf_lock(void)
{
    return os_mutex_put(&wm_wifi.mcastf_mutex);
}

int wifi_put_command_lock(void)
{
    int rv = WM_SUCCESS;
    //	rv = wakelock_put(WL_ID_WIFI_CMD);
    //	if (rv == WM_SUCCESS)
    rv = os_mutex_put(&wm_wifi.command_lock);

    return rv;
}

#ifdef CONFIG_WIFI_FW_DEBUG

void wifi_register_fw_dump_cb(int (*wifi_usb_mount_cb)(),
                              int (*wifi_usb_file_open_cb)(char *test_file_name),
                              int (*wifi_usb_file_write_cb)(uint8_t *data, size_t data_len),
                              int (*wifi_usb_file_close_cb)())
{
    wm_wifi.wifi_usb_mount_cb      = wifi_usb_mount_cb;
    wm_wifi.wifi_usb_file_open_cb  = wifi_usb_file_open_cb;
    wm_wifi.wifi_usb_file_write_cb = wifi_usb_file_write_cb;
    wm_wifi.wifi_usb_file_close_cb = wifi_usb_file_close_cb;
}

#ifdef SD8801

#define DEBUG_HOST_READY     0xEE
#define DEBUG_FW_DONE        0xFF
#define DEBUG_MEMDUMP_FINISH 0xFE
#define SDIO_SCRATCH_REG     0x60
#define DEBUG_ITCM_DONE      0xaa
#define DEBUG_DTCM_DONE      0xbb
#define DEBUG_SQRAM_DONE     0xcc

#define DEBUG_DUMP_CTRL_REG  0x63
#define DEBUG_DUMP_FIRST_REG 0x62
#define DEBUG_DUMP_START_REG 0x64
#define DEBUG_DUMP_END_REG   0x6a
#define ITCM_SIZE            0x60000

#define SQRAM_SIZE 0x33500

#define DTCM_SIZE 0x14000

char itcm_dump_file_name[]  = _T("1:/itcm.bin");
char dtcm_dump_file_name[]  = _T("1:/dtcm.bin");
char sqram_dump_file_name[] = _T("1:/sqram.bin");

/**
 *  @brief This function dump firmware memory to file
 *
 *  @return         N/A
 */
void wifi_dump_firmware_info()
{
    int ret = 0;
    unsigned int reg, reg_start, reg_end;
    t_u8 ctrl_data = 0;
    int tries;
    t_u8 data[8], i;
    uint32_t resp;
    wifi_d("==== DEBUG MODE OUTPUT START: %d ====", os_get_timestamp());
    if (wm_wifi.wifi_usb_file_open_cb != NULL)
    {
        ret = wm_wifi.wifi_usb_file_open_cb(itcm_dump_file_name);
        if (ret != WM_SUCCESS)
        {
            wifi_e("File opening failed");
            goto done;
        }
    }
    else
    {
        wifi_e("File open callback is not registered");
        goto done;
    }
    wifi_d("Start ITCM output %d, please wait...", os_get_timestamp());
    reg_start = DEBUG_DUMP_START_REG;
    reg_end   = DEBUG_DUMP_END_REG;
    do
    {
        ret = sdio_drv_creg_write(DEBUG_DUMP_CTRL_REG, 1, DEBUG_HOST_READY, &resp);
        if (!ret)
        {
            wifi_e("SDIO Write ERR");
            goto done;
        }

        for (tries = 0; tries < MAX_POLL_TRIES; tries++)
        {
            ret = sdio_drv_creg_read(DEBUG_DUMP_CTRL_REG, 1, &resp);
            if (!ret)
            {
                wifi_e("SDIO READ ERR");
                goto done;
            }
            ctrl_data = resp & 0xff;

            if ((ctrl_data == DEBUG_FW_DONE) || (ctrl_data == DEBUG_ITCM_DONE) || (ctrl_data == DEBUG_DTCM_DONE) ||
                (ctrl_data == DEBUG_SQRAM_DONE))
                break;
            if (ctrl_data != DEBUG_HOST_READY)
            {
                ret = sdio_drv_creg_write(DEBUG_DUMP_CTRL_REG, 1, DEBUG_HOST_READY, &resp);
                if (!ret)
                {
                    wifi_e("SDIO Write ERR");
                    goto done;
                }
            }
            os_thread_sleep(os_msec_to_ticks(10));
        }
        if (ctrl_data == DEBUG_HOST_READY)
        {
            wifi_e("Fail to pull ctrl_data");
            goto done;
        }
        reg = DEBUG_DUMP_FIRST_REG;
        ret = sdio_drv_creg_read(reg, 1, &resp);
        if (!ret)
        {
            wifi_e("SDIO READ ERR");
            goto done;
        }

        i = 0;
        for (reg = reg_start; reg <= reg_end; reg++)
        {
            ret = sdio_drv_creg_read(reg, 1, &resp);
            if (!ret)
            {
                wifi_e("SDIO READ ERR");
                goto done;
            }
            data[i++] = resp & 0xff;
        }

        dump_hex(data, sizeof(data));

        if (wm_wifi.wifi_usb_file_write_cb != NULL)
        {
            ret = wm_wifi.wifi_usb_file_write_cb(data, sizeof(data));
            if (ret != WM_SUCCESS)
            {
                wifi_e("File writing failed");
                goto done;
            }
        }
        else
        {
            wifi_e("File write callback is not registered");
            goto done;
        }
        switch (ctrl_data)
        {
            case DEBUG_ITCM_DONE:
                if (wm_wifi.wifi_usb_file_close_cb != NULL)
                {
                    ret = wm_wifi.wifi_usb_file_close_cb();
                    if (ret != WM_SUCCESS)
                    {
                        wifi_e("File closing failed");
                        goto done;
                    }
                }
                else
                {
                    wifi_e("File close callback is not registered");
                    goto done;
                }
                if (wm_wifi.wifi_usb_file_open_cb != NULL)
                {
                    ret = wm_wifi.wifi_usb_file_open_cb(dtcm_dump_file_name);
                    if (ret != WM_SUCCESS)
                    {
                        wifi_e("File opening failed");
                        goto done;
                    }
                    wifi_d("Start DTCM output %d, please wait...", os_get_timestamp());
                }
                else
                {
                    wifi_e("USB open callback is not registered");
                    goto done;
                }
                break;
            case DEBUG_DTCM_DONE:
                if (wm_wifi.wifi_usb_file_close_cb != NULL)
                {
                    ret = wm_wifi.wifi_usb_file_close_cb();
                    if (ret != WM_SUCCESS)
                    {
                        wifi_e("File closing failed");
                        goto done;
                    }
                }
                else
                {
                    wifi_e("File close callback is not registered");
                    goto done;
                }
                if (wm_wifi.wifi_usb_file_open_cb != NULL)
                {
                    ret = wm_wifi.wifi_usb_file_open_cb(sqram_dump_file_name);
                    if (ret != WM_SUCCESS)
                    {
                        wifi_e("File opening failed");
                        goto done;
                    }
                    wifi_d("Start SQRAM output %u.%06u, please wait...", os_get_timestamp());
                }
                else
                {
                    wifi_e("USB open cb is not registered");
                    goto done;
                }
                break;
            case DEBUG_SQRAM_DONE:
                if (wm_wifi.wifi_usb_file_close_cb != NULL)
                {
                    ret = wm_wifi.wifi_usb_file_close_cb();
                    if (ret != WM_SUCCESS)
                    {
                        wifi_e("File closing failed");
                        goto done;
                    }
                    wifi_d("End output!");
                }
                else
                {
                    wifi_e("File close callback is not registered");
                    goto done;
                }
                break;
            default:
                wifi_d("Unexpected wifi debug \n");
                break;
        }
    } while (ctrl_data != DEBUG_SQRAM_DONE);

    wifi_d("The output ITCM/DTCM/SQRAM have been saved to files successfully!");
    /* end dump fw memory */
done:
    wifi_d("==== DEBUG MODE OUTPUT END: %d ====\n", os_get_timestamp());

    while (1)
        ;
}

#ifndef RW610
/**
 *  @brief This function reads and displays SDIO registers for debugging
 *
 *  @return         N/A
 */
void wifi_sdio_reg_dbg()
{
    int ret = 0;
    t_u8 loop, index = 0, func, data;
    unsigned int reg, reg_start, reg_end;
    unsigned int scratch_reg = SDIO_SCRATCH_REG;
    unsigned int reg_table[] = {0x28, 0x30, 0x34, 0x38, 0x3c};
    char buf[256], *ptr;
    uint32_t resp;

    for (loop = 0; loop < 5; loop++)
    {
        (void)memset(buf, 0, sizeof(buf));
        ptr = buf;
        if (loop == 0)
        {
            /* Read the registers of SDIO function0 */
            func      = loop;
            reg_start = 0;
            reg_end   = 9;
        }
        else if (loop == 1)
        {
            /* Read the registers of SDIO function1 */
            func      = loop;
            reg_start = 4;
            reg_end   = 9;
        }
        else if (loop == 2)
        {
            /* Read specific registers of SDIO function1 */
            index     = 0;
            func      = 1;
            reg_start = reg_table[index++];
            reg_end   = reg_table[ARRAY_SIZE(reg_table) - 1];
        }
        else
        {
            /* Read the scratch registers of SDIO function1 */
            if (loop == 4)
                os_thread_sleep(os_msec_to_ticks(1));
            func      = 1;
            reg_start = scratch_reg;
            reg_end   = scratch_reg + 10;
        }
        if (loop != 2)
            ptr += sprintf(ptr, "SDIO Func%d (%#x-%#x): ", func, reg_start, reg_end);
        else
            ptr += sprintf(ptr, "SDIO Func%d: ", func);
        for (reg = reg_start; reg <= reg_end;)
        {
#ifndef RW610
            ret = sdio_drv_creg_read(reg, func, &resp);
#endif
            data = resp & 0xff;
            if (loop == 2)
                ptr += sprintf(ptr, "(%#x) ", reg);
            if (!ret)
                ptr += sprintf(ptr, "%02x ", data);
            else
            {
                ptr += sprintf(ptr, "ERR");
                break;
            }
            if (loop == 2 && reg < reg_end)
                reg = reg_table[index++];
            else
                reg++;
        }
        wifi_d("%s", buf);
    }
}
#endif
#elif defined(SD8978) || defined(SD8987) || defined(SD8997) || defined(SD9097) || defined(SD9098) || defined(IW61x) || \
    defined(RW610_SERIES)

#define DEBUG_HOST_READY     0xCC
#define DEBUG_FW_DONE        0xFF
#define DEBUG_MEMDUMP_FINISH 0xFE

#define DEBUG_DUMP_CTRL_REG    0xF9
#define DEBUG_DUMP_START_REG   0xF1
#define DEBUG_DUMP_END_REG     0xF8
#define SDIO_SCRATCH_REG       0xE8
#define DEBUG_DUMP_SCRATCH_REG (void *)0x41382488

char fw_dump_file_name[] = _T("1:/fw_dump.bin");

typedef enum
{
    DUMP_TYPE_ITCM        = 0,
    DUMP_TYPE_DTCM        = 1,
    DUMP_TYPE_SQRAM       = 2,
    DUMP_TYPE_APU_REGS    = 3,
    DUMP_TYPE_CIU_REGS    = 4,
    DUMP_TYPE_ICU_REGS    = 5,
    DUMP_TYPE_MAC_REGS    = 6,
    DUMP_TYPE_EXTEND_7    = 7,
    DUMP_TYPE_EXTEND_8    = 8,
    DUMP_TYPE_EXTEND_9    = 9,
    DUMP_TYPE_EXTEND_10   = 10,
    DUMP_TYPE_EXTEND_11   = 11,
    DUMP_TYPE_EXTEND_12   = 12,
    DUMP_TYPE_EXTEND_13   = 13,
    DUMP_TYPE_EXTEND_LAST = 14
} dumped_mem_type;

#define MAX_NAME_LEN      8
#define MAX_FULL_NAME_LEN 32

typedef struct
{
    t_u8 mem_name[MAX_NAME_LEN];
    t_u8 *mem_Ptr;
    struct file *pfile_mem;
    t_u8 done_flag;
    t_u8 type;
} memory_type_mapping;

memory_type_mapping mem_type_mapping_tbl = {"DUMP", NULL, NULL, 0xDD};

typedef enum
{
    RDWR_STATUS_SUCCESS = 0,
    RDWR_STATUS_FAILURE = 1,
    RDWR_STATUS_DONE    = 2
} rdwr_status;

/**
 *  @brief This function read/write firmware via cmd52
 *
 *  @param doneflag  A flag
 *
 *  @return         MLAN_STATUS_SUCCESS
 */
rdwr_status wifi_cmd52_rdwr_firmware(t_u8 doneflag)
{
    int ret                = 0;
    int tries              = 0;
    t_u8 ctrl_data         = 0;
    t_u8 dbg_dump_ctrl_reg = 0;
    t_u8 debug_host_ready  = 0;
    uint32_t resp;

    dbg_dump_ctrl_reg = DEBUG_DUMP_CTRL_REG;
    debug_host_ready  = DEBUG_HOST_READY;

    ret = sdio_drv_creg_write(dbg_dump_ctrl_reg, 1, debug_host_ready, &resp);
    if (!ret)
    {
        wifi_e("SDIO Write ERR");
        return RDWR_STATUS_FAILURE;
    }
    for (tries = 0; tries < MAX_POLL_TRIES; tries++)
    {
        ret = sdio_drv_creg_read(dbg_dump_ctrl_reg, 1, &resp);
        if (!ret)
        {
            wifi_e("SDIO READ ERR");
            return RDWR_STATUS_FAILURE;
        }
        ctrl_data = resp & 0xff;
        if (ctrl_data == DEBUG_FW_DONE)
            break;
        if (doneflag && ctrl_data == doneflag)
            return RDWR_STATUS_DONE;
        if (ctrl_data != debug_host_ready)
        {
            ret = sdio_drv_creg_write(dbg_dump_ctrl_reg, 1, debug_host_ready, &resp);
            if (!ret)
            {
                wifi_e("SDIO Write ERR");
                return RDWR_STATUS_FAILURE;
            }
        }
        os_thread_sleep(os_msec_to_ticks(1));
    }
    if (ctrl_data == debug_host_ready)
    {
        wifi_e("Fail to pull ctrl_data");
        return RDWR_STATUS_FAILURE;
    }

    return RDWR_STATUS_SUCCESS;
}

/**
 *  @brief This function dump firmware memory to file
 *
 *  @return         N/A
 */
void wifi_dump_firmware_info()
{
    int ret   = 0;
    int tries = 0;
    unsigned int reg, reg_start, reg_end;
    t_u8 start_flag = 0;
    t_u8 doneflag   = 0;
    rdwr_status stat;
    t_u8 dbg_dump_start_reg                    = 0;
    t_u8 dbg_dump_end_reg                      = 0;
    memory_type_mapping *pmem_type_mapping_tbl = &mem_type_mapping_tbl;
    t_u8 data[8], i;
    uint32_t resp;

    dbg_dump_start_reg = DEBUG_DUMP_START_REG;
    dbg_dump_end_reg   = DEBUG_DUMP_END_REG;

    wifi_d("==== DEBUG MODE OUTPUT START: %d.%06u ====", os_get_timestamp());
    /* read the number of the memories which will dump */
    if (RDWR_STATUS_FAILURE == wifi_cmd52_rdwr_firmware(doneflag))
        goto done;

    /** check the reg which indicate dump starting */
    for (reg = dbg_dump_start_reg; reg <= dbg_dump_end_reg; reg++)
    {
        for (tries = 0; tries < MAX_POLL_TRIES; tries++)
        {
            ret = sdio_drv_creg_read(reg, 1, &resp);
            if (!ret)
            {
                wifi_e("SDIO READ ERR");
                goto done;
            }
            start_flag = resp & 0xff;
            /** 0 means dump starting*/
            if (start_flag == 0)
                break;
            os_thread_sleep(os_msec_to_ticks(1));
        }
        if (tries == MAX_POLL_TRIES)
        {
            wifi_d("FW not ready to dump");
            goto done;
        }
    }
    if (wm_wifi.wifi_usb_file_open_cb != NULL)
    {
        ret = wm_wifi.wifi_usb_file_open_cb(fw_dump_file_name);
        if (ret != WM_SUCCESS)
        {
            wifi_e("File opening failed");
            goto done;
        }
    }
    else
    {
        wifi_e("File open callback is not registered");
        goto done;
    }

    doneflag = pmem_type_mapping_tbl->done_flag;
    wifi_d("Start %s output %d, please wait...", pmem_type_mapping_tbl->mem_name, os_get_timestamp());
    do
    {
        stat = wifi_cmd52_rdwr_firmware(doneflag);
        if (RDWR_STATUS_FAILURE == stat)
            goto done;

        reg_start = dbg_dump_start_reg;
        reg_end   = dbg_dump_end_reg;
        i         = 0;
        for (reg = reg_start; reg <= reg_end; reg++)
        {
            ret = sdio_drv_creg_read(reg, 1, &resp);
            if (!ret)
            {
                wifi_e("SDIO READ ERR");
                goto done;
            }
            data[i++] = (resp & 0xff);
        }
        if (wm_wifi.wifi_usb_file_write_cb != NULL)
        {
            ret = wm_wifi.wifi_usb_file_write_cb(data, sizeof(data));
            if (ret != WM_SUCCESS)
            {
                wifi_e("File writing failed");
                goto done;
            }
        }
        else
        {
            wifi_e("File write callback is not registered");
            goto done;
        }

        if (RDWR_STATUS_DONE == stat)
        {
            if (wm_wifi.wifi_usb_file_close_cb != NULL)
            {
                ret = wm_wifi.wifi_usb_file_close_cb();
                if (ret != WM_SUCCESS)
                {
                    wifi_e("File closing failed");
                    goto done;
                }
            }
            else
            {
                wifi_e("File close callback is not registered");
                goto done;
            }
            break;
        }
    } while (1);

    wifi_d("==== DEBUG MODE OUTPUT END: %d ====\n", os_get_timestamp());
    /* end dump fw memory */
done:
    while (1)
        ;
}
#ifndef RW610
/**
 *  @brief This function reads and displays SDIO registers for debugging
 *
 *  @return         N/A
 */
void wifi_sdio_reg_dbg()
{
    int ret = 0;
    t_u8 loop, index = 0, func, data;
    unsigned int reg, reg_start, reg_end;
    unsigned int scratch_reg = SDIO_SCRATCH_REG;
    unsigned int reg_table[] = {0x08, 0x58, 0x5C, 0x5D, 0x60, 0x61, 0x62, 0x64, 0x65, 0x66, 0x68, 0x69, 0x6a};
    char buf[256], *ptr;
    uint32_t resp;

    for (loop = 0; loop < 5; loop++)
    {
        (void)memset(buf, 0, sizeof(buf));
        ptr = buf;
        if (loop == 0)
        {
            /* Read the registers of SDIO function0 */
            func      = loop;
            reg_start = 0;
            reg_end   = 9;
        }
        else if (loop == 1)
        {
            /* Read the registers of SDIO function1 */
            func      = loop;
            reg_start = 0x10;
            reg_end   = 0x17;
        }
        else if (loop == 2)
        {
            /* Read specific registers of SDIO function1 */
            index     = 0;
            func      = 1;
            reg_start = reg_table[index++];
            reg_end   = reg_table[ARRAY_SIZE(reg_table) - 1];
        }
        else
        {
            /* Read the scratch registers of SDIO function1 */
            if (loop == 4)
                os_thread_sleep(os_msec_to_ticks(1));
            func      = 1;
            reg_start = scratch_reg;
            reg_end   = scratch_reg + 10;
        }
        if (loop != 2)
            ptr += sprintf(ptr, "SDIO Func%d (%#x-%#x): ", func, reg_start, reg_end);
        else
            ptr += sprintf(ptr, "SDIO Func%d: ", func);
        for (reg = reg_start; reg <= reg_end;)
        {
            ret  = sdio_drv_creg_read(reg, func, &resp);
            data = resp & 0xff;
            if (loop == 2)
                ptr += sprintf(ptr, "(%#x) ", reg);
            if (ret)
                ptr += sprintf(ptr, "%02x ", data);
            else
            {
                ptr += sprintf(ptr, "ERR");
                break;
            }
            if (loop == 2 && reg < reg_end)
                reg = reg_table[index++];
            else
                reg++;
        }
        wifi_d("%s", buf);
    }
}
#endif
#elif defined(RW610)

/**
 *  @brief This function dump firmware memory to file
 *
 *  @return         N/A
 */
void wifi_dump_firmware_info()
{
    /*Dummy for RW610 */
}

#endif
#endif

#ifdef CONFIG_FW_VDLL
int wifi_wait_for_vdllcmdresp(void *cmd_resp_priv)
{
    int ret                 = WM_SUCCESS;
    HostCmd_DS_COMMAND *cmd = wifi_get_vdllcommand_buffer();
#ifndef RW610
    t_u32 buf_len = MLAN_SDIO_BLOCK_SIZE;
    t_u32 tx_blocks;
#endif

#ifndef RW610
#if defined(CONFIG_ENABLE_WARNING_LOGS) || defined(CONFIG_WIFI_CMD_RESP_DEBUG)

    wcmdr_d("VDLL CMD --- : 0x%x Size: %d Seq: %d", cmd->command, cmd->size, cmd->seq_num);
#endif /* CONFIG_ENABLE_WARNING_LOGS || CONFIG_WIFI_CMD_RESP_DEBUG*/
#endif
    if (cmd->size > WIFI_FW_CMDBUF_SIZE)
    {
        /*
         * This is a error added to be flagged during
         * development cycle. It is not expected to
         * occur in production. The legacy code below
         * only sents out MLAN_SDIO_BLOCK_SIZE or 2 *
         * MLAN_SDIO_BLOCK_SIZE sized packet. If ever
         * in future greater packet size generated then
         * this error will help to localize the problem.
         */
        wifi_e("cmd size greater than WIFI_FW_CMDBUF_SIZE\r\n");
        return -WM_FAIL;
    }

#ifndef RW610
    tx_blocks = ((t_u32)cmd->size + MLAN_SDIO_BLOCK_SIZE - 1U) / MLAN_SDIO_BLOCK_SIZE;

    if (cmd->size < 512U)
    {
        buf_len   = tx_blocks * MLAN_SDIO_BLOCK_SIZE;
        tx_blocks = 1;
    }
#endif

#if defined(RW610)
    (void)wifi_send_cmdbuffer();
#else
    (void)wifi_send_vdllcmdbuffer(tx_blocks, buf_len);
#endif

    return ret;
}
#endif
int wifi_wait_for_cmdresp(void *cmd_resp_priv)
{
    int ret;
    HostCmd_DS_COMMAND *cmd = wifi_get_command_buffer();
#ifndef RW610
    t_u32 buf_len = MLAN_SDIO_BLOCK_SIZE;
    t_u32 tx_blocks;
#endif

#ifndef RW610
#if defined(CONFIG_ENABLE_WARNING_LOGS) || defined(CONFIG_WIFI_CMD_RESP_DEBUG)

    wcmdr_d("CMD --- : 0x%x Size: %d Seq: %d", cmd->command, cmd->size, cmd->seq_num);
#endif /* CONFIG_ENABLE_WARNING_LOGS || CONFIG_WIFI_CMD_RESP_DEBUG*/
#endif
    if (cmd->size > WIFI_FW_CMDBUF_SIZE)
    {
        /*
         * This is a error added to be flagged during
         * development cycle. It is not expected to
         * occur in production. The legacy code below
         * only sents out MLAN_SDIO_BLOCK_SIZE or 2 *
         * MLAN_SDIO_BLOCK_SIZE sized packet. If ever
         * in future greater packet size generated then
         * this error will help to localize the problem.
         */
        wifi_e("cmd size greater than WIFI_FW_CMDBUF_SIZE\r\n");
        (void)wifi_put_command_lock();
        return -WM_FAIL;
    }

#ifndef RW610
    tx_blocks = ((t_u32)cmd->size + MLAN_SDIO_BLOCK_SIZE - 1U) / MLAN_SDIO_BLOCK_SIZE;

    if (cmd->size < 512U)
    {
        buf_len   = tx_blocks * MLAN_SDIO_BLOCK_SIZE;
        tx_blocks = 1;
    }
#endif

#if defined(CONFIG_WIFIDRIVER_PS_LOCK)
    ret = os_rwlock_read_lock(&sleep_rwlock, MAX_WAIT_TIME);
#else
    ret = os_rwlock_read_lock(&ps_rwlock, MAX_WAIT_TIME);
#endif
    if (ret != WM_SUCCESS)
    {
        wifi_e("Failed to wakeup card\r\n");
        // wakelock_put(WL_ID_LL_OUTPUT);
        (void)wifi_put_command_lock();
        return -WM_FAIL;
    }
#ifdef CONFIG_WMM_UAPSD
    /*
     * No PS handshake between driver and FW for the uapsd case,
     * CMD should not wakeup FW, needs to wait to send till receiving PS_AWAKE Event from FW.
     */
    os_semaphore_get(&uapsd_sem, OS_WAIT_FOREVER);
#endif

    /*
     * This is the private pointer. Only the command response handler
     * function knows what it means or where it points to. It can be
     * NULL.
     */
    wm_wifi.cmd_resp_priv = cmd_resp_priv;

#if defined(RW610)
    (void)wifi_send_cmdbuffer();
#else
    (void)wifi_send_cmdbuffer(tx_blocks, buf_len);
#endif

#if defined(CONFIG_WIFIDRIVER_PS_LOCK)
    /* put the sleep_rwlock after send command but not wait for the command response,
     * for sleep confirm command, sleep confirm response(in wifi_process_ps_enh_response())
     * would try to get the sleep_rwlock until get it,
     * so here put the sleep_rwlock as early as possible.
     */
    (void)os_rwlock_read_unlock(&sleep_rwlock);
#endif

    /* Wait max 10 sec for the command response */
    ret = wifi_get_command_resp_sem(WIFI_COMMAND_RESPONSE_WAIT_MS);

    if (ret != WM_SUCCESS)
    {
#ifdef CONFIG_ENABLE_WARNING_LOGS
        t_u32 outbuf_len = 0;
        HostCmd_DS_COMMAND *tmo_cmd =
            (HostCmd_DS_COMMAND *)((t_u8 *)wifi_get_outbuf((uint32_t *)(&outbuf_len)) + INTF_HEADER_LEN);
        wifi_w("Command response timed out. command 0x%x, len %d, seqno 0x%x", tmo_cmd->command, tmo_cmd->size,
               tmo_cmd->seq_num);

#endif /* CONFIG_ENABLE_WARNING_LOGS */
#ifdef CONFIG_WIFI_FW_DEBUG
#ifndef RW610
        wifi_sdio_reg_dbg();

        if (wm_wifi.wifi_usb_mount_cb != NULL)
        {
            ret = wm_wifi.wifi_usb_mount_cb();
            if (ret == WM_SUCCESS)
                wifi_dump_firmware_info();
            else
            {
                wifi_e("USB mounting failed");
            }
        }
        else
            wifi_e("USB mount callback is not registered");
#else
        wifi_dump_firmware_info();
#endif
#endif
    }

    wm_wifi.cmd_resp_priv = NULL;
#ifdef CONFIG_WMM_UAPSD
    os_semaphore_put(&uapsd_sem);
#endif
#ifndef CONFIG_WIFIDRIVER_PS_LOCK
    os_rwlock_read_unlock(&ps_rwlock);
#endif
    wifi_set_xfer_pending(false);
    (void)wifi_put_command_lock();
    return ret;
}

#ifdef CONFIG_P2P
void wifi_wfd_event(bool peer_event, bool action_frame, void *data)
{
    struct wifi_wfd_event event;

    if (wm_wifi.wfd_event_queue)
    {
        event.peer_event   = peer_event;
        event.action_frame = action_frame;
        event.data         = data;
        os_queue_send(wm_wifi.wfd_event_queue, &event, OS_NO_WAIT);
    }
}
#endif

int wifi_event_completion(enum wifi_event event, enum wifi_event_reason result, void *data)
{
    struct wifi_message msg;
    if (wm_wifi.wlc_mgr_event_queue == MNULL)
    {
        wifi_e("wlc_mgr_event_queue has not been created, event %d", event);
        return -WM_FAIL;
    }

    msg.data   = data;
    msg.reason = result;
    msg.event  = (uint16_t)event;
    if (os_queue_send(wm_wifi.wlc_mgr_event_queue, &msg, OS_NO_WAIT) != WM_SUCCESS)
    {
        wifi_e("Failed to send response on Queue, event %d", event);
        return -WM_FAIL;
    }
    return WM_SUCCESS;
}

static int cmp_mac_addr(uint8_t *mac_addr1, uint8_t *mac_addr2)
{
    int i = 0;

    if ((mac_addr1 == MNULL) || (mac_addr2 == MNULL))
    {
        return 1;
    }

    for (i = 0; i < MLAN_MAC_ADDR_LENGTH; i++)
    {
        if (mac_addr1[i] != mac_addr2[i])
        {
            return 1;
        }
    }
    return 0;
}

static int add_mcast_ip(uint8_t *mac_addr)
{
    mcast_filter *node_t, *new_node;
    (void)wifi_get_mcastf_lock();
    node_t = wm_wifi.start_list;
    if (wm_wifi.start_list == NULL)
    {
        new_node = os_mem_alloc(sizeof(mcast_filter));
        if (new_node == NULL)
        {
            (void)wifi_put_mcastf_lock();
            return -WM_FAIL;
        }
        (void)memcpy((void *)new_node->mac_addr, (const void *)mac_addr, MLAN_MAC_ADDR_LENGTH);
        new_node->next     = NULL;
        wm_wifi.start_list = new_node;
        (void)wifi_put_mcastf_lock();
        return WM_SUCCESS;
    }
    while (node_t->next != NULL && cmp_mac_addr(node_t->mac_addr, mac_addr))
    {
        node_t = node_t->next;
    }

    if (!cmp_mac_addr(node_t->mac_addr, mac_addr))
    {
        (void)wifi_put_mcastf_lock();
        return -WM_E_EXIST;
    }
    new_node = os_mem_alloc(sizeof(mcast_filter));
    if (new_node == NULL)
    {
        (void)wifi_put_mcastf_lock();
        return -WM_FAIL;
    }
    (void)memcpy((void *)new_node->mac_addr, (const void *)mac_addr, MLAN_MAC_ADDR_LENGTH);
    new_node->next = NULL;
    node_t->next   = new_node;
    (void)wifi_put_mcastf_lock();
    return WM_SUCCESS;
}

static int remove_mcast_ip(uint8_t *mac_addr)
{
    mcast_filter *curr_node, *prev_node;
    (void)wifi_get_mcastf_lock();
    curr_node = wm_wifi.start_list->next;
    prev_node = wm_wifi.start_list;
    if (wm_wifi.start_list == NULL)
    {
        (void)wifi_put_mcastf_lock();
        return -WM_FAIL;
    }
    if (curr_node == NULL && cmp_mac_addr(prev_node->mac_addr, mac_addr))
    {
        os_mem_free(prev_node);
        wm_wifi.start_list = NULL;
        (void)wifi_put_mcastf_lock();
        return WM_SUCCESS;
    }
    /* If search element is at first location */
    if (!cmp_mac_addr(prev_node->mac_addr, mac_addr))
    {
        wm_wifi.start_list = prev_node->next;
        os_mem_free(prev_node);
        (void)wifi_put_mcastf_lock();
        return WM_SUCCESS;
    }
    /* Find node in linked list */
    while (cmp_mac_addr(curr_node->mac_addr, mac_addr) && curr_node->next != NULL)
    {
        prev_node = curr_node;
        curr_node = curr_node->next;
    }
    if (!cmp_mac_addr(curr_node->mac_addr, mac_addr))
    {
        prev_node->next = curr_node->next;
        os_mem_free(curr_node);
        (void)wifi_put_mcastf_lock();
        return WM_SUCCESS;
    }
    (void)wifi_put_mcastf_lock();
    return -WM_FAIL;
}

static int make_filter_list(char *mlist, int maxlen)
{
    mcast_filter *node_t;
    int maddr_cnt = 0;
    (void)wifi_get_mcastf_lock();
    node_t = wm_wifi.start_list;
    while (node_t != NULL)
    {
        (void)memcpy((void *)mlist, (const void *)node_t->mac_addr, MLAN_MAC_ADDR_LENGTH);
        node_t = (struct mcast_filter *)node_t->next;
        mlist  = mlist + MLAN_MAC_ADDR_LENGTH;
        maddr_cnt++;
        if (maddr_cnt > (maxlen / 6U))
        {
            break;
        }
    }
    (void)wifi_put_mcastf_lock();
    return maddr_cnt;
}

void wifi_get_ipv4_multicast_mac(uint32_t ipaddr, uint8_t *mac_addr)
{
    int i = 0, j = 0;
    uint32_t mac_addr_r = 0x01005E;
    ipaddr              = ipaddr & 0x7FFFFFU;
    /* Generate Multicast Mapped Mac Address for IPv4
     * To get Multicast Mapped MAC address,
     * To calculate 6 byte Multicast-Mapped MAC Address.
     * 1) Fill higher 24-bits with IANA Multicast OUI (01-00-5E)
     * 2) Set 24th bit as Zero
     * 3) Fill lower 23-bits with from IP address (ignoring higher
     * 9bits).
     */
    for (i = 2; i >= 0; i--)
    {
        mac_addr[j] = (uint8_t)((char)(mac_addr_r >> 8 * i) & 0xFF);
        j++;
    }

    for (i = 2; i >= 0; i--)
    {
        mac_addr[j] = (uint8_t)((char)(ipaddr >> 8 * i) & 0xFF);
        j++;
    }
}

#ifdef CONFIG_IPV6
void wifi_get_ipv6_multicast_mac(uint32_t ipaddr, uint8_t *mac_addr)
{
    int i = 0, j = 0;
    uint32_t mac_addr_r = 0x3333;
    /* Generate Multicast Mapped Mac Address for IPv6
     * To get Multicast Mapped MAC address,
     * To calculate 6 byte Multicast-Mapped MAC Address.
     * 1) Fill higher 16-bits with IANA Multicast OUI (33-33)
     * 2) Fill lower 24-bits with from IP address
     */
    for (i = 1; i >= 0; i--)
    {
        mac_addr[j] = (char)(mac_addr_r >> 8 * i) & 0xFF;
        j++;
    }

    for (i = 3; i >= 0; i--)
    {
        mac_addr[j] = (char)(ipaddr >> 8 * i) & 0xFF;
        j++;
    }
}
#endif /* CONFIG_IPV6 */

int wifi_add_mcast_filter(uint8_t *mac_addr)
{
    char mlist[MAX_MCAST_LEN] = {0};
    int len, ret;
    /* If MAC address is 00:11:22:33:44:55,
     * then pass mac_addr array in following format:
     * mac_addr[0] = 00
     * mac_addr[1] = 11
     * mac_addr[2] = 22
     * mac_addr[3] = 33
     * mac_addr[4] = 44
     * mac_addr[5] = 55
     */

    (void)memset(&mlist, 0x00, MAX_MCAST_LEN);
    ret = add_mcast_ip(mac_addr);
    if (ret != WM_SUCCESS)
    {
        return ret;
    }
    len = make_filter_list(mlist, (int)MAX_MCAST_LEN);
    return wifi_set_mac_multicast_addr(mlist, (t_u32)len);
}

int wifi_remove_mcast_filter(uint8_t *mac_addr)
{
    char mlist[MAX_MCAST_LEN];
    int len, ret;
    /* If MAC address is 00:11:22:33:44:55,
     * then pass mac_addr array in following format:
     * mac_addr[0] = 00
     * mac_addr[1] = 11
     * mac_addr[2] = 22
     * mac_addr[3] = 33
     * mac_addr[4] = 44
     * mac_addr[5] = 55
     */

    (void)memset(&mlist, 0x00, MAX_MCAST_LEN);
    ret = remove_mcast_ip(mac_addr);
    if (ret != WM_SUCCESS)
    {
        return ret;
    }
    len = make_filter_list(mlist, (int)MAX_MCAST_LEN);
    ret = wifi_set_mac_multicast_addr(mlist, (uint32_t)len);
    return ret;
}

void wifi_remove_all_mcast_filter(uint8_t need_lock)
{
    mcast_filter *node = NULL;

    if (wm_wifi.start_list == NULL)
        return;

    if (need_lock)
        wifi_get_mcastf_lock();

    while (wm_wifi.start_list)
    {
        node               = wm_wifi.start_list;
        wm_wifi.start_list = node->next;
        os_mem_free(node);
    }

    if (need_lock)
        wifi_put_mcastf_lock();
}

static struct wifi_scan_result common_desc;
int wifi_get_scan_result(unsigned int index, struct wifi_scan_result **desc)
{
    (void)memset(&common_desc, 0x00, sizeof(struct wifi_scan_result));
    int rv = wrapper_bssdesc_first_set(
        (int)index, common_desc.bssid, &common_desc.is_ibss_bit_set, &common_desc.ssid_len, common_desc.ssid,
        &common_desc.Channel, &common_desc.RSSI, &common_desc.beacon_period, &common_desc.dtim_period,
        &common_desc.WPA_WPA2_WEP, &common_desc.wpa_mcstCipher, &common_desc.wpa_ucstCipher,
        &common_desc.rsn_mcstCipher, &common_desc.rsn_ucstCipher, &common_desc.ap_mfpc, &common_desc.ap_mfpr);
    if (rv != WM_SUCCESS)
    {
        wifi_e("wifi_get_scan_result failed");
        return rv;
    }

    /* Country info not populated */
    rv = wrapper_bssdesc_second_set((int)index, &common_desc.phtcap_ie_present, &common_desc.phtinfo_ie_present,
#ifdef CONFIG_11AC
                                    &common_desc.pvhtcap_ie_present,
#endif
#ifdef CONFIG_11AX
                                    &common_desc.phecap_ie_present,
#endif
                                    &common_desc.wmm_ie_present, &common_desc.band, &common_desc.wps_IE_exist,
                                    &common_desc.wps_session, &common_desc.wpa2_entp_IE_exist,
#ifdef CONFIG_11R
                                    &common_desc.mdid,
#endif
#ifdef CONFIG_11K
                                    &common_desc.neighbor_report_supported,
#endif
#ifdef CONFIG_11V
                                    &common_desc.bss_transition_supported,
#endif
                                    &common_desc.trans_mode, common_desc.trans_bssid, &common_desc.trans_ssid_len,
                                    common_desc.trans_ssid
#ifdef CONFIG_MBO
                                    ,
                                    &common_desc.mbo_assoc_disallowed
#endif
    );

    if (rv != WM_SUCCESS)
    {
        wifi_e("wifi_get_scan_result failed");
        return rv;
    }

    *desc = &common_desc;

    return WM_SUCCESS;
}

int wifi_register_event_queue(os_queue_t *event_queue)
{
    if (event_queue == MNULL)
    {
        return -WM_E_INVAL;
    }

    if (wm_wifi.wlc_mgr_event_queue != NULL)
    {
        return -WM_FAIL;
    }

    wm_wifi.wlc_mgr_event_queue = event_queue;
    return WM_SUCCESS;
}

int wifi_unregister_event_queue(os_queue_t *event_queue)
{
    if ((wm_wifi.wlc_mgr_event_queue == MNULL) || wm_wifi.wlc_mgr_event_queue != event_queue)
    {
        return -WM_FAIL;
    }

    wm_wifi.wlc_mgr_event_queue = NULL;
    return WM_SUCCESS;
}

#ifdef CONFIG_P2P
int wifi_register_wfd_event_queue(os_queue_t *event_queue)
{
    if (wm_wifi.wfd_event_queue)
        return -WM_FAIL;

    wm_wifi.wfd_event_queue = event_queue;
    return WM_SUCCESS;
}

int wifi_unregister_wfd_event_queue(os_queue_t *event_queue)
{
    if (!wm_wifi.wfd_event_queue || wm_wifi.wfd_event_queue != event_queue)
        return -WM_FAIL;

    wm_wifi.wfd_event_queue = NULL;
    return WM_SUCCESS;
}
#endif

int wifi_get_wpa_ie_in_assoc(uint8_t *wpa_ie)
{
    return wrapper_get_wpa_ie_in_assoc(wpa_ie);
}

#define WL_ID_WIFI_MAIN_LOOP "wifi_main_loop"

static void wifi_driver_main_loop(void *argv)
{
    int ret;
    struct bus_message msg;

    (void)memset((void *)&msg, 0, sizeof(struct bus_message));

    /* Main Loop */
    while (true)
    {
        ret = os_queue_recv(&wm_wifi.io_events, &msg, OS_WAIT_FOREVER);
        if (ret == WM_SUCCESS)
        {
            // wakelock_get(WL_ID_WIFI_MAIN_LOOP);

            if (msg.event == MLAN_TYPE_EVENT)
            {
                (void)wifi_handle_fw_event(&msg);
                /*
                 * Free the buffer after the event is
                 * handled.
                 */
                wifi_free_eventbuf(msg.data);
            }
            else if (msg.event == MLAN_TYPE_CMD)
            {
                (void)wifi_process_cmd_response((HostCmd_DS_COMMAND *)(void *)((uint8_t *)msg.data + INTF_HEADER_LEN));
                wifi_update_last_cmd_sent_ms();
                (void)wifi_put_command_resp_sem();
            }
            else
            { /* Do Nothing */
            }

            // wakelock_put(WL_ID_WIFI_MAIN_LOOP);
        }
    }
}

#define WL_ID_WIFI_CORE_INPUT "wifi_core_input"
/**
 * This function should be called when a packet is ready to be read
 * from the interface.
 */
static void wifi_core_input(void *argv)
{
    int sta;

    for (;;)
    {
        wifi_core_thread = os_get_current_task_handle();
        sta              = (int)os_enter_critical_section();
        /* Allow interrupt handler to deliver us a packet */
        g_txrx_flag = true;
        //		SDIOC_IntMask(SDIOC_INT_CDINT, UNMASK);
        //		SDIOC_IntSigMask(SDIOC_INT_CDINT, UNMASK);
#ifndef RW610
        sdio_enable_interrupt();
#endif

        os_exit_critical_section((unsigned long)sta);

        /* Wait till we receive a packet from SDIO */
        (void)os_event_notify_get(OS_WAIT_FOREVER);
        // wakelock_get(WL_ID_WIFI_CORE_INPUT);

#if defined(RW610)
        (void)wifi_imu_lock();
#else
        /* Protect the SDIO from other parallel activities */
        (void)wifi_sdio_lock();

        (void)wlan_process_int_status(mlan_adap);
#endif

#if defined(RW610)
        wifi_imu_unlock();
#else
        wifi_sdio_unlock();
#endif
        // wakelock_put(WL_ID_WIFI_CORE_INPUT);
    } /* for ;; */
}

void wifi_user_scan_config_cleanup(void)
{
    if (wm_wifi.g_user_scan_cfg != NULL)
    {
        os_mem_free((void *)wm_wifi.g_user_scan_cfg);
        wm_wifi.g_user_scan_cfg = NULL;
    }
}

void wifi_scan_stop(void)
{
    wm_wifi.scan_stop = true;
    while (scan_thread_in_process)
    {
        /* wait for scan task done */
        os_thread_sleep(os_msec_to_ticks(1000));
    }
    wm_wifi.scan_stop = false;
}

/**
 * This function should be called when scan command is ready
 *
 */
static void wifi_scan_input(void *argv)
{
    mlan_status rv;

    for (;;)
    {
        wm_wifi.wm_wifi_scan_thread = os_get_current_task_handle();
        /* Wait till we receive scan command */
        (void)os_event_notify_get(OS_WAIT_FOREVER);

        if (wm_wifi.scan_stop == true)
        {
            wm_wifi.scan_stop = false;
            wifi_user_scan_config_cleanup();
            break;
        }

        scan_thread_in_process = true;
        if (wm_wifi.g_user_scan_cfg != NULL)
        {
#ifdef CONFIG_WPA_SUPP
            (void)wifi_event_completion(WIFI_EVENT_SCAN_START, WIFI_EVENT_REASON_SUCCESS, NULL);
#endif
            rv = wlan_scan_networks((mlan_private *)mlan_adap->priv[0], NULL, wm_wifi.g_user_scan_cfg);
            if (rv != MLAN_STATUS_SUCCESS)
            {
                wifi_user_scan_config_cleanup();
                (void)wifi_event_completion(WIFI_EVENT_SCAN_RESULT, WIFI_EVENT_REASON_FAILURE, NULL);
            }
        }
        scan_thread_in_process = false;
    } /* for ;; */
    os_thread_self_complete(NULL);
}

static void wifi_core_deinit(void);
static int wifi_low_level_input(const uint8_t interface, const uint8_t *buffer, const uint16_t len);

static int wifi_core_init(void)
{
    int ret;

    if (wifi_core_init_done != 0U)
    {
        return WM_SUCCESS;
    }

    ret = os_mutex_create(&wm_wifi.command_lock, "command lock", OS_MUTEX_INHERIT);

    if (ret != WM_SUCCESS)
    {
        wifi_e("Create command_lock failed");
        goto fail;
    }

    ret = os_semaphore_create(&wm_wifi.command_resp_sem, "command resp sem");

    if (ret != WM_SUCCESS)
    {
        wifi_e("Create command resp sem failed");
        goto fail;
    }

    ret = os_mutex_create(&wm_wifi.mcastf_mutex, "mcastf-mutex", OS_MUTEX_INHERIT);
    if (ret != WM_SUCCESS)
    {
        wifi_e("Create mcastf mutex failed");
        goto fail;
    }

    /*
     * Take the cmd resp lock immediately so that we can later block on
     * it.
     */
    (void)wifi_get_command_resp_sem(OS_WAIT_FOREVER);
    wm_wifi.io_events_queue_data = g_io_events_queue_data;

    ret = os_queue_create(&wm_wifi.io_events, "io-events", (int)sizeof(struct bus_message),
                          &wm_wifi.io_events_queue_data);
    if (ret != WM_SUCCESS)
    {
        wifi_e("Create io events queue failed");
        goto fail;
    }

    ret = bus_register_event_queue(&wm_wifi.io_events);
    if (ret != WM_SUCCESS)
    {
        wifi_e("Register io events queue failed");
        goto fail;
    }

    ret = os_thread_create(&wm_wifi.wm_wifi_main_thread, "wifi_driver", wifi_driver_main_loop, NULL, &wifi_drv_stack,
                           OS_PRIO_1);
    if (ret != WM_SUCCESS)
    {
        wifi_e("Create wifi driver thread failed");
        goto fail;
    }

    ret = bus_register_data_input_function(&wifi_low_level_input);
    if (ret != WM_SUCCESS)
    {
        wifi_e("Register wifi low level input failed");
        goto fail;
    }

    ret =
        os_thread_create(&wm_wifi.wm_wifi_scan_thread, "wifi_scan", wifi_scan_input, NULL, &wifi_scan_stack, OS_PRIO_3);

    if (ret != WM_SUCCESS)
    {
        wifi_e("Create wifi scan thread failed");
        goto fail;
    }

    ret = os_thread_create(&wm_wifi.wm_wifi_core_thread, "stack_dispatcher", wifi_core_input, NULL, &wifi_core_stack,
                           OS_PRIO_1);

    if (ret != WM_SUCCESS)
    {
        wifi_e("Create stack dispatcher thread failed");
        goto fail;
    }

    wifi_core_thread    = wm_wifi.wm_wifi_core_thread;
    wifi_core_init_done = 1;
#ifdef CONFIG_WMM
#ifdef CONFIG_WMM_ENH
    ret = wifi_wmm_buf_pool_init(&outbuf_arr[0][0]);
    if (ret != WM_SUCCESS)
    {
        wifi_e("Unable to init wmm buffer pool");
        goto fail;
    }
#endif

    wm_wifi.tx_data_queue_data = g_tx_data_queue_data;
    ret = os_queue_create(&wm_wifi.tx_data, "tx_data", sizeof(struct bus_message), &wm_wifi.tx_data_queue_data);
    if (ret != WM_SUCCESS)
    {
        PRINTF("Create tx data queue failed");
        goto fail;
    }
    /* Semaphore to protect wmm data parameters */
    ret = os_semaphore_create(&wm_wifi.tx_data_sem, "tx data sem");
    if (ret != WM_SUCCESS)
    {
        PRINTF("Create tx data sem failed");
        goto fail;
    }
    ret = os_thread_create(&wm_wifi.wm_wifi_driver_tx, "wifi_driver_tx", wifi_driver_tx, NULL, &wifi_drv_stack,
                           OS_PRIO_2);
    if (ret != WM_SUCCESS)
    {
        PRINTF("Create tx data thread failed");
        goto fail;
    }
#endif
    wm_wifi.tx_status    = WIFI_DATA_RUNNING;
    wm_wifi.tx_block_cnt = 0;
    wm_wifi.rx_status    = WIFI_DATA_RUNNING;
    wm_wifi.rx_block_cnt = 0;
#ifdef CONFIG_CSI
    /* Semaphore to protect wmm data parameters */
    ret = os_semaphore_create(&csi_buff_stat.csi_data_sem, "usb data sem");
    if (ret != WM_SUCCESS)
    {
        PRINTF("Create usb data sem failed");
        goto fail;
    }
#endif

    return WM_SUCCESS;

fail:

    wifi_core_deinit();

    return -WM_FAIL;
}

static void wifi_core_deinit(void)
{
    int i = 0;

    mlan_adap->in_reset = true;
    for (i = 0; i < (int)(MIN(MLAN_MAX_BSS_NUM, mlan_adap->priv_num)); i++)
    {
        if (mlan_adap->priv[i])
        {
            wlan_clean_txrx(mlan_adap->priv[i]);
#if defined(CONFIG_WMM) && defined(CONFIG_WMM_ENH)
            wlan_ralist_deinit_enh(mlan_adap->priv[i]);
#endif
        }
    }

    wifi_core_init_done = 0;

    bus_deregister_event_queue();
    bus_deregister_data_input_funtion();

    if (wm_wifi.io_events != NULL)
    {
        (void)os_queue_delete(&wm_wifi.io_events);
        wm_wifi.io_events = NULL;
    }
#ifdef CONFIG_WMM
    if (wm_wifi.tx_data != NULL)
    {
        os_queue_delete(&wm_wifi.tx_data);
    }
#ifdef CONFIG_WMM_ENH
    wifi_wmm_buf_pool_deinit();
#else
    memset(wm_wifi.pkt_index, 0x00, sizeof(wm_wifi.pkt_index));
    memset(wm_wifi.pkt_cnt, 0x00, sizeof(wm_wifi.pkt_cnt));
    memset(wm_wifi.send_index, 0x00, sizeof(wm_wifi.send_index));
    memset(wm_wifi.bk_pkt_len, 0x00, sizeof(wm_wifi.bk_pkt_len));
    memset(wm_wifi.be_pkt_len, 0x00, sizeof(wm_wifi.be_pkt_len));
    memset(wm_wifi.vi_pkt_len, 0x00, sizeof(wm_wifi.vi_pkt_len));
    memset(wm_wifi.vo_pkt_len, 0x00, sizeof(wm_wifi.vo_pkt_len));
#endif
#endif
    wifi_remove_all_mcast_filter(0);
    if (wm_wifi.mcastf_mutex != NULL)
    {
        (void)os_mutex_delete(&wm_wifi.mcastf_mutex);
        wm_wifi.mcastf_mutex = NULL;
    }
    if (wm_wifi.command_resp_sem != NULL)
    {
        (void)os_semaphore_delete(&wm_wifi.command_resp_sem);
        wm_wifi.command_resp_sem = NULL;
    }
#ifdef CONFIG_WMM
    if (wm_wifi.tx_data_sem != NULL)
    {
        os_semaphore_delete(&wm_wifi.tx_data_sem);
        wm_wifi.tx_data_sem = NULL;
    }
#endif
    if (wm_wifi.command_lock != NULL)
    {
        (void)os_mutex_delete(&wm_wifi.command_lock);
        wm_wifi.command_lock = NULL;
    }
#ifndef RW610
    if (wm_wifi.wm_wifi_main_thread != NULL)
    {
        (void)os_thread_delete(&wm_wifi.wm_wifi_main_thread);
        wm_wifi.wm_wifi_main_thread = NULL;
    }
    if (wm_wifi.wm_wifi_core_thread != NULL)
    {
        (void)os_thread_delete(&wm_wifi.wm_wifi_core_thread);
        wm_wifi.wm_wifi_core_thread = NULL;
        wifi_core_thread            = NULL;
    }
    if (wm_wifi.wm_wifi_scan_thread != NULL)
    {
        (void)os_thread_delete(&wm_wifi.wm_wifi_scan_thread);
        wm_wifi.wm_wifi_scan_thread = NULL;
    }
#ifdef CONFIG_WMM
    if (wm_wifi.wm_wifi_driver_tx)
    {
        os_thread_delete(&wm_wifi.wm_wifi_driver_tx);
        wm_wifi.wm_wifi_driver_tx = NULL;
    }
#endif
#else
    wm_wifi.cmd_resp_priv   = NULL;
    wm_wifi.cmd_resp_ioctl  = NULL;
    wm_wifi.cmd_resp_status = 0;
    memset(&wm_wifi, 0x00, sizeof(wm_wifi));
#endif
#ifdef CONFIG_HEAP_DEBUG
    if (os_mem_stat_sem != NULL)
    {
        os_semaphore_delete(&os_mem_stat_sem);
        os_mem_stat_sem = NULL;
    }
#endif
#ifdef CONFIG_CSI
    if (csi_buff_stat.csi_data_sem != NULL)
    {
        os_semaphore_delete(&csi_buff_stat.csi_data_sem);
        csi_buff_stat.csi_data_sem = NULL;
    }
#endif
}

int wifi_init(const uint8_t *fw_start_addr, const size_t size)
{
    if (wifi_init_done != 0U)
    {
        return WM_SUCCESS;
    }

    (void)memset(&wm_wifi, 0, sizeof(wm_wifi_t));

#if defined(RW610)
    int ret = (int)imu_wifi_init(WLAN_TYPE_NORMAL, fw_start_addr, size);
#else
    int ret = (int)sd_wifi_init(WLAN_TYPE_NORMAL, fw_start_addr, size);
#endif
    if (ret != 0)
    {
        wifi_e("sd_wifi_init failed. status code %d", ret);
        switch (ret)
        {
            case MLAN_CARD_CMD_TIMEOUT:
            case MLAN_CARD_NOT_DETECTED:
                ret = -WIFI_ERROR_CARD_NOT_DETECTED;
                break;
            case MLAN_STATUS_FW_DNLD_FAILED:
                ret = -WIFI_ERROR_FW_DNLD_FAILED;
                break;
            case MLAN_STATUS_FW_NOT_DETECTED:
                ret = -WIFI_ERROR_FW_NOT_DETECTED;
                break;
#ifdef CONFIG_XZ_DECOMPRESSION
            case MLAN_STATUS_FW_XZ_FAILED:
                ret = -WIFI_ERROR_FW_XZ_FAILED;
                break;
#endif /* CONFIG_XZ_DECOMPRESSION */
            case MLAN_STATUS_FW_NOT_READY:
                ret = -WIFI_ERROR_FW_NOT_READY;
                break;
            default:
                PRINTM(MINFO, "Unexpected MLAN FW Status \n");
                break;
        }
        return ret;
    }

    ret = wifi_core_init();
    if (ret != 0)
    {
        wifi_e("wifi_core_init failed. status code %d", ret);
    }

    if (ret == WM_SUCCESS)
    {
        wifi_init_done = 1;
    }

    return ret;
}

#ifndef RW610
int wifi_init_fcc(const uint8_t *fw_start_addr, const size_t size)
{
    if (wifi_init_done != 0U)
    {
        return WM_SUCCESS;
    }

    int ret = (int)sd_wifi_init(WLAN_TYPE_FCC_CERTIFICATION, fw_start_addr, size);
    if (ret != 0)
    {
        wifi_e("sd_wifi_init failed. status code %d", ret);
        switch (ret)
        {
            case MLAN_CARD_CMD_TIMEOUT:
            case MLAN_CARD_NOT_DETECTED:
                ret = -WIFI_ERROR_CARD_NOT_DETECTED;
                break;
            case MLAN_STATUS_FW_DNLD_FAILED:
                ret = -WIFI_ERROR_FW_DNLD_FAILED;
                break;
            case MLAN_STATUS_FW_NOT_DETECTED:
                ret = -WIFI_ERROR_FW_NOT_DETECTED;
                break;
#ifdef CONFIG_XZ_DECOMPRESSION
            case MLAN_STATUS_FW_XZ_FAILED:
                ret = -WIFI_ERROR_FW_XZ_FAILED;
                break;
#endif /* CONFIG_XZ_DECOMPRESSION */
            case MLAN_STATUS_FW_NOT_READY:
                ret = -WIFI_ERROR_FW_NOT_READY;
                break;
            default:
                wifi_d("sd_wifi_init enexpected MLAN Status \n", ret);
                break;
        }
        return ret;
    }

    ret = wifi_core_init();
    if (ret != 0)
    {
        wifi_e("wifi_core_init failed. status code %d", ret);
    }

    if (ret == WM_SUCCESS)
    {
        wifi_init_done = 1;
    }

    return ret;
}
#endif

void wifi_deinit(void)
{
    if (wifi_init_done == 0U)
    {
        return;
    }

    wifi_init_done = 0;

    wifi_core_deinit();

#if defined(RW610)
    imu_wifi_deinit();
#else
    sd_wifi_deinit();
#endif
}

#ifdef RW610
bool wifi_fw_is_hang(void)
{
    if (mlan_adap && mlan_adap->bus_ops.fw_is_hang)
        return mlan_adap->bus_ops.fw_is_hang();
    return false;
}

void wifi_destroy_wifidriver_tasks(void)
{
#ifdef CONFIG_WMM
    if (wm_wifi.wm_wifi_driver_tx)
    {
        os_thread_delete(&wm_wifi.wm_wifi_driver_tx);
        wm_wifi.wm_wifi_driver_tx = NULL;
    }
#endif

    if (wm_wifi.wm_wifi_main_thread != NULL)
    {
        os_thread_delete(&wm_wifi.wm_wifi_main_thread);
        wm_wifi.wm_wifi_main_thread = NULL;
    }

    if (wm_wifi.wm_wifi_core_thread != NULL)
    {
        os_thread_delete(&wm_wifi.wm_wifi_core_thread);
        wm_wifi.wm_wifi_core_thread = NULL;
        wifi_core_thread            = NULL;
    }

    if (wm_wifi.wm_wifi_scan_thread != NULL)
    {
        (void)os_thread_delete(&wm_wifi.wm_wifi_scan_thread);
        wm_wifi.wm_wifi_scan_thread = NULL;
    }

    imu_uninstall_callback();
}
#endif
void wifi_set_tx_status(t_u8 status)
{
    wm_wifi.tx_status = status;
}

void wifi_set_rx_status(t_u8 status)
{
    wm_wifi.rx_status = status;
}

void wifi_set_packet_retry_count(const int count)
{
    retry_attempts = count;
}

#ifdef CONFIG_STA_AMPDU_TX
void wifi_sta_ampdu_tx_enable(void)
{
    sta_ampdu_tx_enable = true;
}

void wifi_sta_ampdu_tx_disable(void)
{
    sta_ampdu_tx_enable = false;
}

#if defined(WIFI_ADD_ON)
void wifi_sta_ampdu_tx_enable_per_tid(t_u8 tid)
{
    sta_ampdu_tx_enable_per_tid = tid;
}

t_u8 wifi_sta_ampdu_tx_enable_per_tid_is_allowed(t_u8 tid)
{
    if ((sta_ampdu_tx_enable_per_tid >> tid) & 0x01)
        return MTRUE;
    else
        return MFALSE;
}
#endif
#else
void wifi_sta_ampdu_tx_enable(void)
{
}

void wifi_sta_ampdu_tx_disable(void)
{
}
#if defined(WIFI_ADD_ON)
void wifi_sta_ampdu_tx_enable_per_tid(t_u8 tid)
{
}

t_u8 wifi_sta_ampdu_tx_enable_per_tid_is_allowed(t_u8 tid)
{
    return MTRUE;
}
#endif
#endif /* CONFIG_STA_AMPDU_TX */

#ifdef CONFIG_STA_AMPDU_RX
void wifi_sta_ampdu_rx_enable(void)
{
    sta_ampdu_rx_enable = true;
}

void wifi_sta_ampdu_rx_disable(void)
{
    sta_ampdu_rx_enable = false;
}

#if defined(WIFI_ADD_ON)
void wifi_sta_ampdu_rx_enable_per_tid(t_u8 tid)
{
    sta_ampdu_rx_enable_per_tid = tid;
}

t_u8 wifi_sta_ampdu_rx_enable_per_tid_is_allowed(t_u8 tid)
{
    if ((sta_ampdu_rx_enable_per_tid >> tid) & 0x01)
        return MTRUE;
    else
        return MFALSE;
}
#endif
#else
void wifi_sta_ampdu_rx_enable(void)
{
}

void wifi_sta_ampdu_rx_disable(void)
{
}
#if defined(WIFI_ADD_ON)
void wifi_sta_ampdu_rx_enable_per_tid(t_u8 tid)
{
}

t_u8 wifi_sta_ampdu_rx_enable_per_tid_is_allowed(t_u8 tid)
{
    return MTRUE;
}
#endif
#endif /* CONFIG_STA_AMPDU_RX */

#if defined(WIFI_ADD_ON)
#ifdef CONFIG_UAP_AMPDU_TX
void wifi_uap_ampdu_tx_enable(void)
{
    uap_ampdu_tx_enable = true;
}

void wifi_uap_ampdu_tx_disable(void)
{
    uap_ampdu_tx_enable = false;
}

void wifi_uap_ampdu_tx_enable_per_tid(t_u8 tid)
{
    uap_ampdu_tx_enable_per_tid = tid;
}

t_u8 wifi_uap_ampdu_tx_enable_per_tid_is_allowed(t_u8 tid)
{
    if ((uap_ampdu_tx_enable_per_tid >> tid) & 0x01)
        return MTRUE;
    else
        return MFALSE;
}
#else
void wifi_uap_ampdu_tx_enable(void)
{
}

void wifi_uap_ampdu_tx_disable(void)
{
}
void wifi_uap_ampdu_tx_enable_per_tid(t_u8 tid)
{
}

t_u8 wifi_uap_ampdu_tx_enable_per_tid_is_allowed(t_u8 tid)
{
    return MTRUE;
}
#endif /* CONFIG_STA_AMPDU_TX */

#ifdef CONFIG_UAP_AMPDU_RX
void wifi_uap_ampdu_rx_enable(void)
{
    uap_ampdu_rx_enable = true;
}

void wifi_uap_ampdu_rx_disable(void)
{
    uap_ampdu_rx_enable = false;
}

void wifi_uap_ampdu_rx_enable_per_tid(t_u8 tid)
{
    uap_ampdu_rx_enable_per_tid = tid;
}

t_u8 wifi_uap_ampdu_rx_enable_per_tid_is_allowed(t_u8 tid)
{
    if ((uap_ampdu_rx_enable_per_tid >> tid) & 0x01)
        return MTRUE;
    else
        return MFALSE;
}
#else
void wifi_uap_ampdu_rx_enable(void)
{
}

void wifi_uap_ampdu_rx_disable(void)
{
}
void wifi_uap_ampdu_rx_enable_per_tid(t_u8 tid)
{
}

t_u8 wifi_uap_ampdu_rx_enable_per_tid_is_allowed(t_u8 tid)
{
    return MTRUE;
}
#endif /* CONFIG_STA_AMPDU_RX */
#endif

#ifndef CONFIG_WIFI_RX_REORDER
int wifi_register_data_input_callback(void (*data_intput_callback)(const uint8_t interface,
                                                                   const uint8_t *buffer,
                                                                   const uint16_t len))
{
#ifdef CONFIG_HEAP_DEBUG
    int ret;
#endif
    if (wm_wifi.data_intput_callback != NULL)
    {
        return -WM_FAIL;
    }

    wm_wifi.data_intput_callback = data_intput_callback;

#ifdef CONFIG_HEAP_DEBUG
    /* Semaphore to protect os mem stat */
    ret = os_semaphore_create(&os_mem_stat_sem, "os mem stat sem");
    if (ret != WM_SUCCESS)
    {
        PRINTF("Create os mem stat sem failed");
        return -WM_FAIL;
    }
#endif

    return WM_SUCCESS;
}

void wifi_deregister_data_input_callback(void)
{
    wm_wifi.data_intput_callback = NULL;
}
#else
int wifi_register_gen_pbuf_from_data2_callback(void *(*gen_pbuf_from_data2)(t_u8 *payload,
                                                                            t_u16 datalen,
                                                                            void **p_payload))
{
#ifdef CONFIG_HEAP_DEBUG
    int ret;
#endif
    if (wm_wifi.gen_pbuf_from_data2 != NULL)
    {
        return -WM_FAIL;
    }

    wm_wifi.gen_pbuf_from_data2 = gen_pbuf_from_data2;

#ifdef CONFIG_HEAP_DEBUG
    /* Semaphore to protect os mem stat */
    ret = os_semaphore_create(&os_mem_stat_sem, "os mem stat sem");
    if (ret != WM_SUCCESS)
    {
        PRINTF("Create os mem stat sem failed");
        return -WM_FAIL;
    }
#endif

    return WM_SUCCESS;
}

void wifi_deregister_gen_pbuf_from_data2_callback(void)
{
    wm_wifi.gen_pbuf_from_data2 = NULL;
}
#endif

int wifi_register_amsdu_data_input_callback(void (*amsdu_data_intput_callback)(uint8_t interface,
                                                                               uint8_t *buffer,
                                                                               uint16_t len))
{
    if (wm_wifi.amsdu_data_intput_callback != NULL)
    {
        return -WM_FAIL;
    }

    wm_wifi.amsdu_data_intput_callback = amsdu_data_intput_callback;

    return WM_SUCCESS;
}

void wifi_deregister_amsdu_data_input_callback(void)
{
    wm_wifi.amsdu_data_intput_callback = NULL;
}

int wifi_register_deliver_packet_above_callback(void (*deliver_packet_above_callback)(void *rxpd,
                                                                                      uint8_t interface,
                                                                                      void *lwip_pbuf))
{
    if (wm_wifi.deliver_packet_above_callback != NULL)
    {
        return -WM_FAIL;
    }

    wm_wifi.deliver_packet_above_callback = deliver_packet_above_callback;

    return WM_SUCCESS;
}

void wifi_deregister_deliver_packet_above_callback(void)
{
    wm_wifi.deliver_packet_above_callback = NULL;
}

int wifi_register_wrapper_net_is_ip_or_ipv6_callback(bool (*wrapper_net_is_ip_or_ipv6_callback)(const t_u8 *buffer))
{
    if (wm_wifi.wrapper_net_is_ip_or_ipv6_callback != NULL)
    {
        return -WM_FAIL;
    }

    wm_wifi.wrapper_net_is_ip_or_ipv6_callback = wrapper_net_is_ip_or_ipv6_callback;

    return WM_SUCCESS;
}

void wifi_deregister_wrapper_net_is_ip_or_ipv6_callback(void)
{
    wm_wifi.wrapper_net_is_ip_or_ipv6_callback = NULL;
}

#ifdef CONFIG_WPA_SUPP

/**
 *   @brief This function processes the 802.11 mgmt Frame
 *
 *   @param priv            A pointer to mlan_private
 *
 *   @param payload         A pointer to the received buffer
 *   @param payload_len     Length of the received buffer
 *   @param prx_pd          A pointer to RxPD
 *
 *   @return                MLAN_STATUS_SUCCESS or MLAN_STATUS_FAILURE
 */
static mlan_status wlan_process_802dot11_mgmt_pkt2(mlan_private *priv, t_u8 *payload, t_u32 payload_len, RxPD *prx_pd)
{
    // pmlan_adapter pmadapter = priv->adapter;
    // pmlan_callbacks pcb = &pmadapter->callbacks;
    mlan_status ret                   = MLAN_STATUS_SUCCESS;
    wlan_802_11_header *pieee_pkt_hdr = MNULL;
    t_u16 sub_type                    = 0;
    // t_u8 *event_buf = MNULL;
    // mlan_event *pevent = MNULL;
    t_u8 unicast     = 0;
    t_u8 broadcast[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
#if defined(ENABLE_802_11R) || defined(UAP_HOST_MLME)
#ifdef CONFIG_WIFI_EXTRA_DEBUG
    IEEE80211_MGMT *mgmt = MNULL;
#endif
#endif
#ifdef RX_CHAN_INFO
#ifdef TXPD_RXPD_V3
    t_u8 band_config = (prx_pd->rx_info & 0xF);
    t_u8 chan_num    = (prx_pd->rx_info & RXPD_CHAN_MASK) >> 5;
#else
    t_u8 band_config = prx_pd->band_config;
    t_u8 chan_num    = prx_pd->chan_num;
#endif
#endif
    t_u8 category    = 0;
    t_u8 action_code = 0;
#ifdef DOT1AS_SUPPORT
    struct timestamps tstamps;
#endif
#ifdef UAP_HOST_MLME
#ifdef UAP_SUPPORT
    // t_u8 *sta_addr = NULL;
    // sta_node *sta_ptr = MNULL;
    // MrvlIETypes_MgmtFrameSet_t *tlv;
    // pmlan_buffer pmbuf;
#endif
#endif
    nxp_wifi_event_mlme_t resp;
    nxp_wifi_event_mlme_t *presp;

    ENTER();
    if (payload_len > (MAX_EVENT_SIZE - sizeof(mlan_event)))
    {
        wifi_d("Dropping large mgmt frame,len =%d", payload_len);
        LEAVE();
        return ret;
    }
    /* Check  packet type-subtype and compare with mgmt_passthru_mask
     * If event is needed to host, just eventify it */
    pieee_pkt_hdr = (wlan_802_11_header *)payload;
    sub_type      = IEEE80211_GET_FC_MGMT_FRAME_SUBTYPE(pieee_pkt_hdr->frm_ctl);
    if (((1 << sub_type) & priv->mgmt_frame_passthru_mask) == 0)
    {
        wifi_d("Dropping mgmt frame for subtype %d snr=%d.", sub_type, prx_pd->snr);
        LEAVE();
        return ret;
    }
    switch (sub_type)
    {
        case SUBTYPE_ASSOC_REQUEST:
        case SUBTYPE_REASSOC_REQUEST:
#ifdef UAP_HOST_MLME
#ifdef UAP_SUPPORT
            if (priv->uap_host_based)
            {
                if (!memcmp(pieee_pkt_hdr->addr3, priv->curr_addr, MLAN_MAC_ADDR_LENGTH))
                {
                    wifi_d("wlan: HostMlme MICRO_AP_STA_ASSOC " MACSTR "", MAC2STR(pieee_pkt_hdr->addr2));

#if 0
                    sta_addr = os_mem_alloc(MLAN_MAC_ADDR_LENGTH);
                    if (sta_addr == MNULL)
                    {
                        wifi_w("No mem. Cannot process MAC address from assoc");
                        LEAVE();
                        return ret;
                    }

                    (void)memcpy((void *)sta_addr, (const void *)pieee_pkt_hdr->addr2, MLAN_MAC_ADDR_LENGTH);
                    if (wifi_event_completion(WIFI_EVENT_UAP_CLIENT_ASSOC, WIFI_EVENT_REASON_SUCCESS, sta_addr) !=
                        WM_SUCCESS)
                    {
                        /* If fail to send message on queue, free allocated memory ! */
                        os_mem_free((void *)sta_addr);
                    }

                    mgmt    = (IEEE80211_MGMT *)payload;
                    sta_ptr = wlan_add_station_entry(priv, pieee_pkt_hdr->addr2);
                    if (sta_ptr)
                    {
                        sta_ptr->capability = wlan_le16_to_cpu(mgmt->u.assoc_req.capab_info);
                        pmbuf               = wlan_alloc_mlan_buffer(pmadapter, payload_len, 0, MTRUE);
                        if (pmbuf)
                        {
                            wifi_d("check sta capability");
                            pmbuf->data_len = ASSOC_EVENT_FIX_SIZE;
                            tlv = (MrvlIETypes_MgmtFrameSet_t *)(pmbuf->pbuf + pmbuf->data_offset + pmbuf->data_len);
                            tlv->type = wlan_cpu_to_le16(TLV_TYPE_MGMT_FRAME);
                            tlv->len  = sizeof(IEEEtypes_FrameCtl_t);
                            __memcpy(pmadapter, (t_u8 *)&tlv->frame_control, &pieee_pkt_hdr->frm_ctl,
                                     sizeof(IEEEtypes_FrameCtl_t));
                            pmbuf->data_len += sizeof(MrvlIETypes_MgmtFrameSet_t);
                            __memcpy(pmadapter, pmbuf->pbuf + pmbuf->data_offset + pmbuf->data_len,
                                     payload + sizeof(wlan_802_11_header), payload_len - sizeof(wlan_802_11_header));
                            pmbuf->data_len += payload_len - sizeof(wlan_802_11_header);
                            tlv->len += payload_len - sizeof(wlan_802_11_header);
                            tlv->len = wlan_cpu_to_le16(tlv->len);
                            DBG_HEXDUMP(MCMD_D, "assoc_req", pmbuf->pbuf + pmbuf->data_offset, pmbuf->data_len);
                            wlan_check_sta_capability(priv, pmbuf, sta_ptr);
                            wlan_free_mlan_buffer(pmadapter, pmbuf);

                            os_mem_free(pmbuf);
                        }
                    }
#endif
                }
                else
                {
                    wifi_d("wlan: Drop MICRO_AP_STA_ASSOC " MACSTR " from unknown BSSID " MACSTR "\r\n",
                           MAC2STR(pieee_pkt_hdr->addr2), MAC2STR(pieee_pkt_hdr->addr3));
                }
            }
            unicast = MTRUE;
            break;
#endif
#endif
        case SUBTYPE_AUTH:
            unicast = MTRUE;
            wifi_d("wlan: HostMlme Auth received from " MACSTR "\r\n", MAC2STR(pieee_pkt_hdr->addr2));

            if (priv->bss_role == MLAN_BSS_ROLE_STA)
            {
#ifdef CONFIG_HOST_MLME
                if (priv->curr_bss_params.host_mlme)
                {
                    if (priv->auth_flag & HOST_MLME_AUTH_PENDING)
                    {
                        if (priv->auth_alg != WLAN_AUTH_SAE)
                        {
                            priv->auth_flag &= ~HOST_MLME_AUTH_PENDING;
                            priv->auth_flag |= HOST_MLME_AUTH_DONE;
                        }
                    }
                }
#endif
            }
            break;
        case SUBTYPE_PROBE_RESP:
            unicast = MTRUE;
            break;
        case SUBTYPE_DISASSOC:
        case SUBTYPE_DEAUTH:
            if (memcmp(pieee_pkt_hdr->addr1, broadcast, MLAN_MAC_ADDR_LENGTH))
                unicast = MTRUE;
#ifdef UAP_HOST_MLME
#ifdef UAP_SUPPORT
            if (priv->uap_host_based)
            {
                if (!memcmp(pieee_pkt_hdr->addr3, priv->curr_addr, MLAN_MAC_ADDR_LENGTH))
                {
#ifdef CONFIG_WIFI_EXTRA_DEBUG
                    mgmt = (IEEE80211_MGMT *)payload;
#endif

                    wifi_d("wlan: HostMlme Deauth Receive from " MACSTR " reason code: %d\r\n",
                           MAC2STR(pieee_pkt_hdr->addr2), mgmt->u.deauth_req.reason_code);

#if 0
                    sta_addr = os_mem_alloc(MLAN_MAC_ADDR_LENGTH);
                    if (sta_addr == MNULL)
                    {
                        wifi_w("No mem. Cannot process MAC address from deauth");
                        LEAVE();
                        return ret;
                    }

                    (void)memcpy((void *)sta_addr, (const void *)pieee_pkt_hdr->addr2, MLAN_MAC_ADDR_LENGTH);
                    if (wifi_event_completion(WIFI_EVENT_UAP_CLIENT_DEAUTH, WIFI_EVENT_REASON_SUCCESS, sta_addr) !=
                        WM_SUCCESS)
                    {
                        /* If fail to send message on queue, free allocated memory ! */
                        os_mem_free((void *)sta_addr);
                    }
#endif
                }
                else
                {
                    LEAVE();
                    return ret;
                }
            }
#endif
#endif
            if (priv->bss_role == MLAN_BSS_ROLE_STA)
            {
#ifdef CONFIG_HOST_MLME
                if (priv->curr_bss_params.host_mlme)
                {
                    if (memcmp(pieee_pkt_hdr->addr3, (t_u8 *)priv->curr_bss_params.bss_descriptor.mac_address,
                               MLAN_MAC_ADDR_LENGTH))
                    {
                        wifi_d("Dropping Deauth frame from other bssid: type=%d " MACSTR "\r\n", sub_type,
                               MAC2STR(pieee_pkt_hdr->addr3));
                        LEAVE();
                        return ret;
                    }
                    wifi_d("wlan: HostMlme Disconnected: sub_type=%d\n", sub_type);
#if 0
				pmadapter->pending_disconnect_priv = priv;
				wlan_recv_event(
					priv, MLAN_EVENT_ID_DRV_DEFER_HANDLING,
					MNULL);
#endif
                }
#endif
            }
            break;
        case SUBTYPE_ACTION:
            category    = *(payload + sizeof(wlan_802_11_header));
            action_code = *(payload + sizeof(wlan_802_11_header) + 1);
            if (category == IEEE_MGMT_ACTION_CATEGORY_BLOCK_ACK)
            {
                wifi_d("Drop BLOCK ACK action frame: action_code=%d", action_code);
                LEAVE();
                return ret;
            }
            if ((category == IEEE_MGMT_ACTION_CATEGORY_PUBLIC) && (action_code == BSS_20_40_COEX))
            {
                wifi_d("Drop 20/40 BSS Coexistence Management frame");
                LEAVE();
                return ret;
            }
#ifdef HOST_TDLS_SUPPORT
            if ((category == CATEGORY_PUBLIC) && (action_code == TDLS_DISCOVERY_RESPONSE))
            {
                pcb->moal_updata_peer_signal(pmadapter->pmoal_handle, priv->bss_index, pieee_pkt_hdr->addr2,
                                             prx_pd->snr, prx_pd->nf);
                PRINTM(MINFO, "Rx: TDLS discovery response, nf=%d, snr=%d\n", prx_pd->nf, prx_pd->snr);
            }
#endif
#ifdef DOT1AS_SUPPORT
            if ((category == IEEE_MGMT_ACTION_CATEGORY_UNPROTECT_WNM) && (action_code == 0x1))
            {
#ifdef TXPD_RXPD_V3
                prx_pd->toa_tod_tstamps = wlan_le64_to_cpu(prx_pd->toa_tod_tstamps);
                tstamps.t3              = prx_pd->toa_tod_tstamps >> 32;
                tstamps.t2              = (t_u32)prx_pd->toa_tod_tstamps;
#else
                prx_pd->Tsf = wlan_le64_to_cpu(prx_pd->Tsf);
                tstamps.t3  = prx_pd->Tsf >> 32;
                tstamps.t2  = (t_u32)prx_pd->Tsf;
#endif
                tstamps.t2_err       = 0;
                tstamps.t3_err       = 0;
                tstamps.ingress_time = pcb->moal_do_div(pmadapter->host_bbu_clk_delta, 10);
                tstamps.ingress_time += tstamps.t2; // t2, t3 is 10ns
                                                    // and delta is in 1
                                                    // ns unit;
                PRINTM(MINFO, "T2: %d, T3: %d, ingress: %lu\n", tstamps.t2, tstamps.t3, tstamps.ingress_time);
            }
#endif
            if (memcmp(pieee_pkt_hdr->addr1, broadcast, MLAN_MAC_ADDR_LENGTH))
                unicast = MTRUE;
            break;
        default:
            break;
    }
    if (unicast == MTRUE)
    {
        if (memcmp(pieee_pkt_hdr->addr1, priv->curr_addr, MLAN_MAC_ADDR_LENGTH))
        {
            wifi_d("Dropping mgmt frame for others: type=%d " MACSTR "\r\n", sub_type, MAC2STR(pieee_pkt_hdr->addr1));
            LEAVE();
            return ret;
        }
    }

#if 0
	/* Allocate memory for event buffer */
	ret = pcb->moal_malloc(pmadapter->pmoal_handle, MAX_EVENT_SIZE,
			       MLAN_MEM_DEF, &event_buf);
	if ((ret != MLAN_STATUS_SUCCESS) || !event_buf) {
		PRINTM(MERROR, "Could not allocate buffer for event buf\n");
		LEAVE();
		return MLAN_STATUS_FAILURE;
	}
	pevent = (pmlan_event)event_buf;
	pevent->bss_index = priv->bss_index;
#ifdef ENABLE_802_11R
	mgmt = (IEEE80211_MGMT *)payload;
	if (
		priv->bss_role == MLAN_BSS_ROLE_STA &&
#ifdef CONFIG_HOST_MLME
		!priv->curr_bss_params.host_mlme &&
#endif
		sub_type == SUBTYPE_ACTION &&
		mgmt->u.ft_resp.category == FT_CATEGORY &&
		mgmt->u.ft_resp.action == FT_ACTION_RESPONSE &&
		mgmt->u.ft_resp.status_code == 0) {
		PRINTM(MCMND, "FT Action response received\n");
#define FT_ACTION_HEAD_LEN (24 + 6 + 16)
		pevent->event_id = MLAN_EVENT_ID_DRV_FT_RESPONSE;
		pevent->event_len =
			payload_len + MLAN_MAC_ADDR_LENGTH - FT_ACTION_HEAD_LEN;
		memcpy_ext(pmadapter, (t_u8 *)pevent->event_buf,
			   &mgmt->u.ft_resp.target_ap_addr,
			   MLAN_MAC_ADDR_LENGTH, MLAN_MAC_ADDR_LENGTH);
		memcpy_ext(pmadapter,
			   (t_u8 *)(pevent->event_buf + MLAN_MAC_ADDR_LENGTH),
			   payload + FT_ACTION_HEAD_LEN,
			   payload_len - FT_ACTION_HEAD_LEN,
			   pevent->event_len - MLAN_MAC_ADDR_LENGTH);
	} else if (
		priv->bss_role == MLAN_BSS_ROLE_STA &&
#ifdef CONFIG_HOST_MLME
		!priv->curr_bss_params.host_mlme &&
#endif
		sub_type == SUBTYPE_AUTH &&
		mgmt->u.auth.auth_alg == MLAN_AUTH_MODE_FT &&
		mgmt->u.auth.auth_transaction == 2 &&
		mgmt->u.auth.status_code == 0) {
		PRINTM(MCMND, "FT auth response received \n");
#define AUTH_PACKET_LEN (24 + 6 + 6)
		pevent->event_id = MLAN_EVENT_ID_DRV_FT_RESPONSE;
		pevent->event_len =
			payload_len + MLAN_MAC_ADDR_LENGTH - AUTH_PACKET_LEN;
		memcpy_ext(pmadapter, (t_u8 *)pevent->event_buf, mgmt->sa,
			   MLAN_MAC_ADDR_LENGTH, MLAN_MAC_ADDR_LENGTH);
		memcpy_ext(pmadapter,
			   (t_u8 *)(pevent->event_buf + MLAN_MAC_ADDR_LENGTH),
			   payload + AUTH_PACKET_LEN,
			   payload_len - AUTH_PACKET_LEN,
			   pevent->event_len - MLAN_MAC_ADDR_LENGTH);
	} else {
#endif
		pevent->event_id = MLAN_EVENT_ID_DRV_MGMT_FRAME;
		pevent->event_len = payload_len + sizeof(pevent->event_id);
#ifdef RX_CHAN_INFO
		pevent->event_buf[0] = band_config;
		pevent->event_buf[1] = chan_num;
#else
	memcpy_ext(pmadapter, (t_u8 *)pevent->event_buf,
		   (t_u8 *)&pevent->event_id, sizeof(pevent->event_id),
		   pevent->event_len);
#endif
		memcpy_ext(
			pmadapter,
			(t_u8 *)(pevent->event_buf + sizeof(pevent->event_id)),
			payload, payload_len, payload_len);
#ifdef DOT1AS_SUPPORT
		// Append timestamp info at the end of event
		if ((category == IEEE_MGMT_ACTION_CATEGORY_UNPROTECT_WNM) &&
		    (action_code == 0x1)) {
			memcpy_ext(pmadapter,
				   (t_u8 *)(pevent->event_buf +
					    sizeof(pevent->event_id) +
					    payload_len),
				   &tstamps, sizeof(struct timestamps),
				   sizeof(struct timestamps));
			pevent->event_len = payload_len +
					    sizeof(pevent->event_id) +
					    sizeof(struct timestamps);
		}
#endif
#ifdef ENABLE_802_11R
	}
#endif
	wlan_recv_event(priv, pevent->event_id, pevent);
	if (event_buf)
		pcb->moal_mfree(pmadapter->pmoal_handle, event_buf);
#endif

    memmove((uint8_t *)pieee_pkt_hdr + (sizeof(wlan_802_11_header) - MLAN_MAC_ADDR_LENGTH),
            (uint8_t *)pieee_pkt_hdr + (sizeof(wlan_802_11_header)), payload_len - sizeof(wlan_802_11_header));

    payload_len -= MLAN_MAC_ADDR_LENGTH;

    if (priv->bss_role == MLAN_BSS_ROLE_STA)
    {
        if (sub_type == (t_u16)SUBTYPE_AUTH)
        {
            nxp_wifi_event_mlme_t *auth_resp = &wm_wifi.auth_resp;
            memset(auth_resp, 0, sizeof(nxp_wifi_event_mlme_t));
            auth_resp->frame.frame_len = payload_len;
            memcpy((void *)auth_resp->frame.frame, (const void *)pieee_pkt_hdr, payload_len);

            if (wm_wifi.supp_if_callbk_fns->auth_resp_callbk_fn)
            {
                wm_wifi.supp_if_callbk_fns->auth_resp_callbk_fn(wm_wifi.if_priv, auth_resp, auth_resp->frame.frame_len);
            }
        }

        if (sub_type == (t_u16)SUBTYPE_DEAUTH)
        {
            resp.frame.frame_len = payload_len;
            memcpy((void *)resp.frame.frame, (const void *)pieee_pkt_hdr, resp.frame.frame_len);

            if (wm_wifi.supp_if_callbk_fns->deauth_callbk_fn)
            {
                wm_wifi.supp_if_callbk_fns->deauth_callbk_fn(wm_wifi.if_priv, &resp, resp.frame.frame_len);
            }
        }

        if (sub_type == (t_u16)SUBTYPE_DISASSOC)
        {
            resp.frame.frame_len = payload_len;
            memcpy((void *)resp.frame.frame, (const void *)pieee_pkt_hdr, resp.frame.frame_len);

            if (wm_wifi.supp_if_callbk_fns->disassoc_callbk_fn)
            {
                wm_wifi.supp_if_callbk_fns->disassoc_callbk_fn(wm_wifi.if_priv, &resp, resp.frame.frame_len);
            }
        }

        if (sub_type == (t_u16)SUBTYPE_ACTION)
        {
            resp.frame.frame_len = payload_len;
            memcpy((void *)resp.frame.frame, (const void *)pieee_pkt_hdr, resp.frame.frame_len);

            if (wm_wifi.supp_if_callbk_fns->mgmt_rx_callbk_fn)
            {
                wm_wifi.supp_if_callbk_fns->mgmt_rx_callbk_fn(wm_wifi.if_priv, &resp, resp.frame.frame_len);
            }
        }
    }
    else if (priv->bss_role == MLAN_BSS_ROLE_UAP)
    {
        if ((sub_type == (t_u16)SUBTYPE_AUTH) || (sub_type == (t_u16)SUBTYPE_ASSOC_REQUEST) ||
            (sub_type == (t_u16)SUBTYPE_REASSOC_REQUEST))
        {
            presp = (nxp_wifi_event_mlme_t *)os_mem_calloc(sizeof(nxp_wifi_event_mlme_t));

            if (sub_type == (t_u16)SUBTYPE_AUTH)
            {
                priv->auth_req = presp;
            }
            else
            {
                priv->assoc_req = presp;
            }
        }
        else
        {
            presp = &resp;
        }

        if (presp != MNULL)
        {
            presp->frame.frame_len = payload_len;
            memcpy((void *)presp->frame.frame, (const void *)pieee_pkt_hdr, presp->frame.frame_len);
            if (wm_wifi.supp_if_callbk_fns->mgmt_rx_callbk_fn)
            {
                wm_wifi.supp_if_callbk_fns->mgmt_rx_callbk_fn(wm_wifi.hapd_if_priv, presp, presp->frame.frame_len);
            }
        }
    }

    LEAVE();
    return MLAN_STATUS_SUCCESS;
}

static void wifi_is_wpa_supplicant_input(const uint8_t interface, const uint8_t *buffer, const uint16_t len)
{
    mlan_private *priv           = (mlan_private *)mlan_adap->priv[interface];
    RxPD *prx_pd                 = (RxPD *)(void *)((t_u8 *)buffer + INTF_HEADER_LEN);
    wlan_mgmt_pkt *pmgmt_pkt_hdr = MNULL;

    /* Check if this is mgmt packet and needs to
     * forwarded to app as an event
     */
    pmgmt_pkt_hdr          = (wlan_mgmt_pkt *)((t_u8 *)prx_pd + prx_pd->rx_pkt_offset);
    pmgmt_pkt_hdr->frm_len = wlan_le16_to_cpu(pmgmt_pkt_hdr->frm_len);

    if ((pmgmt_pkt_hdr->wlan_header.frm_ctl & IEEE80211_FC_MGMT_FRAME_TYPE_MASK) == 0)
        wlan_process_802dot11_mgmt_pkt2(priv, (t_u8 *)&pmgmt_pkt_hdr->wlan_header,
                                        pmgmt_pkt_hdr->frm_len + sizeof(wlan_mgmt_pkt) - sizeof(pmgmt_pkt_hdr->frm_len),
                                        prx_pd);
}
#endif

#define RX_PKT_TYPE_OFFSET 5U

static int wifi_low_level_input(const uint8_t interface, const uint8_t *buffer, const uint16_t len)
{
#ifdef CONFIG_WPA_SUPP
    if (*((t_u16 *)buffer + RX_PKT_TYPE_OFFSET) == PKT_TYPE_MGMT_FRAME)
    {
        wifi_is_wpa_supplicant_input(interface, buffer, len);
        return WM_SUCCESS;
    }
#endif
    if (wm_wifi.rx_status == WIFI_DATA_BLOCK)
    {
        wm_wifi.rx_block_cnt++;
        return WM_SUCCESS;
    }

    if (mlan_adap->ps_state == PS_STATE_SLEEP)
    {
#if defined(CONFIG_WIFIDRIVER_PS_LOCK)
        os_rwlock_write_unlock(&sleep_rwlock);
#endif
        mlan_adap->ps_state = PS_STATE_AWAKE;
#ifndef CONFIG_WIFIDRIVER_PS_LOCK
        wifi_event_completion(WIFI_EVENT_AWAKE, WIFI_EVENT_REASON_SUCCESS, MNULL);
#endif
    }

#ifdef CONFIG_WIFI_RX_REORDER
    RxPD *rxpd        = (RxPD *)(void *)((t_u8 *)buffer + INTF_HEADER_LEN);
    t_u8 *payload     = MNULL;
    t_u16 payload_len = (t_u16)0U;
    void *p           = MNULL;
    void *p_payload   = MNULL;

    if (wm_wifi.gen_pbuf_from_data2 != MNULL)
    {
        payload     = (t_u8 *)rxpd + rxpd->rx_pkt_offset;
        payload_len = rxpd->rx_pkt_length;

        p = wm_wifi.gen_pbuf_from_data2(payload, payload_len, &p_payload);

        if (p == MNULL)
            return -WM_FAIL;

        return wrapper_wlan_handle_rx_packet(len, rxpd, p, p_payload);
    }
#else
    if (wm_wifi.data_intput_callback != NULL)
    {
        wm_wifi.data_intput_callback(interface, buffer, len);
        return WM_SUCCESS;
    }

#endif

    return -WM_FAIL;
}

#define ERR_INPROGRESS -5

#define WL_ID_LL_OUTPUT "wifi_low_level_output"

#ifdef CONFIG_WMM
#define ETHER_TYPE_IPV4_01       0xc
#define ETHER_TYPE_IPV4_02       0xd
#define ETHER_TYPE_IPV4_VALUE_01 0x8
#define ETHER_TYPE_IPV4_VALUE_02 0x0
#define WMM_PACKET_TOS_IV4       0xf
#define PRIORITY_COMPENSATOR     0x20
#define UDP_IDENTIFIER_POS       0x11
#define UDP_IDENTIFIER_VAL       0xda

#define ETHER_TYPE_IPV6_01       0xc
#define ETHER_TYPE_IPV6_02       0xd
#define ETHER_TYPE_IPV6_VALUE_01 0x86
#define ETHER_TYPE_IPV6_VALUE_02 0xdd
#define WMM_PACKET_TOS_IPV6_01   0xe
#define WMM_PACKET_TOS_IPV6_02   0xf
#define TOS_MASK_IPV6            0x0ff0 /* 0000111111110000 */

/* Packet priority is 16th byte of payload.
 * Provided that the packet is IPV4 type
 * Since value comes between the range of 0-255, coversion is expected between 0-7 to map to TIDs.
 * */
int wifi_wmm_get_pkt_prio(t_u8 *buf, t_u8 *tid, bool *is_udp_frame)
{
    if (buf == NULL)
        return -WM_FAIL;
    if ((buf[ETHER_TYPE_IPV4_01] == ETHER_TYPE_IPV4_VALUE_01 && buf[ETHER_TYPE_IPV4_02] == ETHER_TYPE_IPV4_VALUE_02) ||
        (buf[ETHER_TYPE_IPV6_01] == ETHER_TYPE_IPV6_VALUE_01 && buf[ETHER_TYPE_IPV6_02] == ETHER_TYPE_IPV6_VALUE_02))
    {
        if (buf[ETHER_TYPE_IPV4_01] == ETHER_TYPE_IPV4_VALUE_01 && buf[ETHER_TYPE_IPV4_02] == ETHER_TYPE_IPV4_VALUE_02)
        {
            if (buf[UDP_IDENTIFIER_POS] == UDP_IDENTIFIER_VAL)
                *is_udp_frame = true;

            *tid = (buf[WMM_PACKET_TOS_IV4] / PRIORITY_COMPENSATOR);
        }
        else
        {
            t_u16 ipv6_tos = (buf[WMM_PACKET_TOS_IPV6_01] << 8) | (buf[WMM_PACKET_TOS_IPV6_02]);
            *tid           = (t_u8)(((ipv6_tos & TOS_MASK_IPV6) >> 4) / PRIORITY_COMPENSATOR);
        }
        switch (*tid)
        {
            case 0:
                return WMM_AC_BE;
            case 1:
            case 2:
                return WMM_AC_BK;
            case 3:
                return WMM_AC_BE;
            case 4:
            case 5:
                return WMM_AC_VI;
            case 6:
            case 7:
                return WMM_AC_VO;
            default:
                return WMM_AC_BK;
        }
    }
    else
        return WMM_AC_BK;
}

#ifdef CONFIG_WMM_ENH
#if defined(WIFI_ADD_ON)
#ifdef AMSDU_IN_AMPDU
/* aggregate one amsdu packet and xmit */
static mlan_status wifi_xmit_amsdu_pkts(mlan_private *priv, t_u8 ac, raListTbl *ralist)
{
    outbuf_t *buf                = MNULL;
    t_u32 max_amsdu_size         = MIN(priv->max_amsdu, priv->adapter->tx_buffer_size);
    t_u32 amsdu_offset           = sizeof(TxPD) + INTF_HEADER_LEN;
    t_u8 amsdu_cnt               = 0;
    t_u32 amsdu_buf_used_size    = 0;
    int amsdu_buf_available_size = max_amsdu_size - amsdu_buf_used_size;
    t_u32 amsdu_pkt_len          = 0;
    int pad_len                  = 0;
    int last_pad_len             = 0;
#ifdef CONFIG_WIFI_TP_STAT
    t_u8 *buf_end = MNULL;
#endif

    while (ralist->total_pkts > 0)
    {
        mlan_adap->callbacks.moal_semaphore_get(mlan_adap->pmoal_handle, &ralist->buf_head.plock);
        buf = (outbuf_t *)util_peek_list(mlan_adap->pmoal_handle, &ralist->buf_head, MNULL, MNULL);
        assert(buf != NULL);

#ifdef CONFIG_WIFI_TP_STAT
        buf_end = &buf->data[0] + buf->tx_pd.tx_pkt_length;
        wifi_stat_tx_dequeue_start(buf_end, g_wifi_xmit_schedule_end);
#endif

        /* calculate amsdu buffer length */
        amsdu_buf_used_size += buf->tx_pd.tx_pkt_length + sizeof(TxPD) + INTF_HEADER_LEN;
        if (amsdu_cnt == 0)
        {
            /* First A-MSDU packet */
            amsdu_buf_available_size = max_amsdu_size - amsdu_buf_used_size - LLC_SNAP_LEN;
        }
        else
        {
            /* The following A-MSDU packets */
            amsdu_pkt_len            = amsdu_buf_used_size - sizeof(TxPD) - INTF_HEADER_LEN + LLC_SNAP_LEN;
            pad_len                  = ((amsdu_pkt_len & 3)) ? (4 - ((amsdu_pkt_len)&3)) : 0;
            amsdu_buf_available_size = max_amsdu_size - amsdu_pkt_len - pad_len;
        }

        /* dequeue and store this buffer in amsdu buffer */
        if (amsdu_buf_available_size >= 0)
        {
            util_unlink_list(mlan_adap->pmoal_handle, &ralist->buf_head, &buf->entry, MNULL, MNULL);
            ralist->total_pkts--;
            mlan_adap->callbacks.moal_semaphore_put(mlan_adap->pmoal_handle, &ralist->buf_head.plock);

            amsdu_offset += wlan_11n_form_amsdu_pkt(wifi_get_amsdu_outbuf(amsdu_offset), &buf->data[0],
                                                    buf->tx_pd.tx_pkt_length, &last_pad_len);
            amsdu_cnt++;

#ifdef CONFIG_WIFI_TP_STAT
            wifi_stat_tx_dequeue_end(buf_end);
#endif
            wifi_wmm_buf_put(buf);
            priv->wmm.pkts_queued[ac]--;
        }
        else
        {
            mlan_adap->callbacks.moal_semaphore_put(mlan_adap->pmoal_handle, &ralist->buf_head.plock);
        }

        /*
         * amsdu buffer room not enough, or last packet in this ra_list in AC queue,
         * add amsdu buffer to imu queue
         */
        if (amsdu_buf_available_size < 0 || ralist->total_pkts == 0)
        {
            return wlan_xmit_wmm_amsdu_pkt((mlan_wmm_ac_e)ac, priv->bss_index, amsdu_offset - last_pad_len,
                                           wifi_get_amsdu_outbuf(0), amsdu_cnt);
        }
    }
    return MLAN_STATUS_SUCCESS;
}
#endif
#endif
static inline t_u8 wifi_is_tx_queue_empty()
{
#ifdef RW610
    return HAL_ImuIsTxBufQueueEmpty(kIMU_LinkCpu1Cpu3);
#else
    return MFALSE;
#endif
}

static inline t_u8 wifi_is_max_tx_cnt(int pkt_cnt)
{
#ifdef RW610
    return (pkt_cnt >= IMU_PAYLOAD_SIZE) ? MTRUE : MFALSE;
#else
    return MFALSE;
#endif
}

#if defined(WIFI_ADD_ON)
static mlan_status wifi_xmit_pkts(mlan_private *priv, t_u8 ac, raListTbl *ralist)
{
    mlan_status ret;
    outbuf_t *buf = MNULL;

    mlan_adap->callbacks.moal_semaphore_get(mlan_adap->pmoal_handle, &ralist->buf_head.plock);
    buf = (outbuf_t *)util_dequeue_list(mlan_adap->pmoal_handle, &ralist->buf_head, MNULL, MNULL);
    ralist->total_pkts--;
    mlan_adap->callbacks.moal_semaphore_put(mlan_adap->pmoal_handle, &ralist->buf_head.plock);
    assert(buf != MNULL);

    /* TODO: this may go wrong for TxPD->tx_pkt_type 0xe5 */
    /* this will get card port lock and probably sleep */
    ret = wlan_xmit_wmm_pkt(priv->bss_index, buf->tx_pd.tx_pkt_length + sizeof(TxPD) + INTF_HEADER_LEN,
                            (t_u8 *)&buf->intf_header[0]);
    if (ret != MLAN_STATUS_SUCCESS)
    {
#ifdef WIFI_ADD_ON
        assert(0);
#else
        mlan_adap->callbacks.moal_semaphore_get(mlan_adap->pmoal_handle, &ralist->buf_head.plock);
        util_enqueue_list_head(mlan_adap->pmoal_handle, &ralist->buf_head, &buf->entry, MNULL, MNULL);
        ralist->total_pkts++;
        mlan_adap->callbacks.moal_semaphore_put(mlan_adap->pmoal_handle, &ralist->buf_head.plock);
        return MLAN_STATUS_RESOURCE;
#endif
    }

    wifi_wmm_buf_put(buf);
    priv->wmm.pkts_queued[ac]--;

    return MLAN_STATUS_SUCCESS;
}
#endif

/*
 *  xmit all buffers under this ralist
 *  should be called inside wmm tid_tbl_ptr ra_list lock,
 *  return MLAN_STATUS_SUCESS to continue looping ralists,
 *  return MLAN_STATUS_RESOURCE to break looping ralists
 */
#if defined(WIFI_ADD_ON)
static mlan_status wifi_xmit_ralist_pkts(mlan_private *priv, t_u8 ac, raListTbl *ralist, int *pkt_cnt)
{
    mlan_status ret;

    if (ralist->tx_pause == MTRUE)
        return MLAN_STATUS_SUCCESS;

    while (ralist->total_pkts > 0)
    {
        if (wifi_is_tx_queue_empty() == MTRUE)
            break;

#ifdef AMSDU_IN_AMPDU
        if (wlan_is_amsdu_allowed(priv, priv->bss_index, ralist->total_pkts, ac))
            ret = wifi_xmit_amsdu_pkts(priv, ac, ralist);
        else
#endif
            ret = wifi_xmit_pkts(priv, ac, ralist);

        if (ret != MLAN_STATUS_SUCCESS)
            return ret;

        /*
         * in amsdu case,
         * multiple packets aggregated as one amsdu packet, are counted as one imu packet
         */
        (*pkt_cnt)++;
        if (wifi_is_max_tx_cnt(*pkt_cnt) == MTRUE)
        {
#ifdef WIFI_ADD_ON
            wlan_flush_wmm_pkt(*pkt_cnt);
#endif
            *pkt_cnt = 0;
        }
    }
    return MLAN_STATUS_SUCCESS;
}
#else
static mlan_status wifi_xmit_ralist_pkts(
    mlan_private *priv, t_u8 ac, raListTbl *ralist, tid_tbl_t *tid_ptr, int *pkt_cnt)
{
    mlan_status ret;
    outbuf_t *buf = MNULL;

    if (ralist->tx_pause == MTRUE)
        return MLAN_STATUS_SUCCESS;

    mlan_adap->callbacks.moal_semaphore_get(mlan_adap->pmoal_handle, &ralist->buf_head.plock);

    while (ralist->total_pkts > 0)
    {
        if (wifi_is_tx_queue_empty() == MTRUE)
        {
            mlan_adap->callbacks.moal_semaphore_put(mlan_adap->pmoal_handle, &ralist->buf_head.plock);
            return MLAN_STATUS_RESOURCE;
        }

        buf = (outbuf_t *)util_dequeue_list(mlan_adap->pmoal_handle, &ralist->buf_head, MNULL, MNULL);
        if (buf == MNULL)
            break;

        /* TODO: this may go wrong for TxPD->tx_pkt_type 0xe5 */
        /* this will get card port lock and probably sleep */
        ret = wlan_xmit_wmm_pkt(priv->bss_index, buf->tx_pd.tx_pkt_length + sizeof(TxPD) + INTF_HEADER_LEN,
                                (t_u8 *)&buf->intf_header[0]);
        if (ret != MLAN_STATUS_SUCCESS)
        {
#ifdef WIFI_ADD_ON
            assert(0);
#else
            util_enqueue_list_head(mlan_adap->pmoal_handle, &ralist->buf_head, &buf->entry, MNULL, MNULL);
            mlan_adap->callbacks.moal_semaphore_put(mlan_adap->pmoal_handle, &ralist->buf_head.plock);
            return MLAN_STATUS_RESOURCE;
#endif
        }

        wifi_wmm_buf_put(buf);

        ralist->total_pkts--;
        priv->wmm.pkts_queued[ac]--;
        (*pkt_cnt)++;
        if (wifi_is_max_tx_cnt(*pkt_cnt) == MTRUE)
        {
            *pkt_cnt = 0;
        }
    }
    mlan_adap->callbacks.moal_semaphore_put(mlan_adap->pmoal_handle, &ralist->buf_head.plock);
    return MLAN_STATUS_SUCCESS;
}
#endif

/*
 *  dequeue and xmit all buffers under ac queue
 *  loop each priv
 *      loop each ac queue
 *          loop each ralist
 *              dequeue all buffers from buf_head list and xmit
 */
static int wifi_xmit_wmm_ac_pkts_enh()
{
    int i;
    int ac;
    mlan_status ret;
    int pkt_cnt        = 0;
    mlan_private *priv = MNULL;
    raListTbl *ralist  = MNULL;
    tid_tbl_t *tid_ptr = MNULL;

    for (i = 0; i < MLAN_MAX_BSS_NUM; i++)
    {
        if (i == MLAN_BSS_TYPE_STA)
            priv = mlan_adap->priv[0];
        else
            priv = mlan_adap->priv[1];

        if (priv->tx_pause == MTRUE)
            continue;

        for (ac = WMM_AC_VO; ac >= WMM_AC_BK; ac--)
        {
            tid_ptr = &priv->wmm.tid_tbl_ptr[ac];

            mlan_adap->callbacks.moal_semaphore_get(mlan_adap->pmoal_handle, &tid_ptr->ra_list.plock);

            if (priv->wmm.pkts_queued[ac] == 0)
            {
                mlan_adap->callbacks.moal_semaphore_put(mlan_adap->pmoal_handle, &tid_ptr->ra_list.plock);
                continue;
            }

            ralist =
                (raListTbl *)util_peek_list(mlan_adap->pmoal_handle, (mlan_list_head *)&tid_ptr->ra_list, MNULL, MNULL);

            while (ralist && ralist != (raListTbl *)&tid_ptr->ra_list)
            {
#if defined(WIFI_ADD_ON)
                ret = wifi_xmit_ralist_pkts(priv, ac, ralist, &pkt_cnt);
#else
                ret = wifi_xmit_ralist_pkts(priv, ac, ralist, tid_ptr, &pkt_cnt);
#endif
                if (ret != MLAN_STATUS_SUCCESS)
                {
                    mlan_adap->callbacks.moal_semaphore_put(mlan_adap->pmoal_handle, &tid_ptr->ra_list.plock);
                    goto RET;
                }
                ralist = ralist->pnext;
            }
            mlan_adap->callbacks.moal_semaphore_put(mlan_adap->pmoal_handle, &tid_ptr->ra_list.plock);
        }
    }

RET:
#ifdef WIFI_ADD_ON
    wlan_flush_wmm_pkt(pkt_cnt);
#endif
    return WM_SUCCESS;
}
#else
bool is_wifi_wmm_queue_full(mlan_wmm_ac_e queue)
{
    bool ret = false;
    switch (queue)
    {
        case WMM_AC_BK:
            if (wm_wifi.pkt_cnt[WMM_AC_BK] >= BK_MAX_BUF)
                ret = true;
            break;
        case WMM_AC_BE:
            if (wm_wifi.pkt_cnt[WMM_AC_BE] >= BE_MAX_BUF)
                ret = true;
            break;
        case WMM_AC_VI:
            if (wm_wifi.pkt_cnt[WMM_AC_VI] >= VI_MAX_BUF)
                ret = true;
            break;
        case WMM_AC_VO:
            if (wm_wifi.pkt_cnt[WMM_AC_VO] >= VO_MAX_BUF)
                ret = true;
            break;
        default:
            ret = true;
            break;
    }
    return ret;
}

static void wifi_dump_wmm_pkts_info(t_u8 *tx_buf, mlan_wmm_ac_e ac)
{
    wifi_d("Error in sending %s:",
           ac == WMM_AC_VO ?
               "Voice traffic" :
               ac == WMM_AC_VI ? "Video traffic" : ac == WMM_AC_BK ? "Background traffic" : "Best Effort traffic");
    wifi_d("IP.ID:%u, IP.HeaderChecksum:%u", ((struct ip_hdr *)(tx_buf + sizeof(TxPD) + INTF_HEADER_LEN + 14))->_id,
           ((struct ip_hdr *)(tx_buf + sizeof(TxPD) + INTF_HEADER_LEN + 14))->_chksum);
}

#if defined(WIFI_ADD_ON)
#ifdef AMSDU_IN_AMPDU
static t_u32 wifi_get_wmm_pkt_length(mlan_wmm_ac_e ac, t_u8 offset)
{
    t_u32 pkt_len = 0;
    switch (ac)
    {
        case WMM_AC_BK:
            pkt_len = wm_wifi.bk_pkt_len[(wm_wifi.send_index[ac] + offset) % BK_MAX_BUF];
            break;
        case WMM_AC_BE:
            pkt_len = wm_wifi.be_pkt_len[(wm_wifi.send_index[ac] + offset) % BE_MAX_BUF];
            break;
        case WMM_AC_VI:
            pkt_len = wm_wifi.vi_pkt_len[(wm_wifi.send_index[ac] + offset) % VI_MAX_BUF];
            break;
        case WMM_AC_VO:
            pkt_len = wm_wifi.vo_pkt_len[(wm_wifi.send_index[ac] + offset) % VO_MAX_BUF];
            break;
        default:
            pkt_len = 0;
            break;
    }
    return pkt_len;
}

uint8_t *wifi_get_wmm_send_outbuf(mlan_wmm_ac_e ac, t_u8 offset)
{
    uint8_t *send_outbuf;
    switch (ac)
    {
        case WMM_AC_BK:
            send_outbuf = outbuf_bk[(wm_wifi.send_index[ac] + offset) % BK_MAX_BUF];
            break;
        case WMM_AC_BE:
            send_outbuf = outbuf_be[(wm_wifi.send_index[ac] + offset) % BE_MAX_BUF];
            break;
        case WMM_AC_VI:
            send_outbuf = outbuf_vi[(wm_wifi.send_index[ac] + offset) % VI_MAX_BUF];
            break;
        case WMM_AC_VO:
            send_outbuf = outbuf_vo[(wm_wifi.send_index[ac] + offset) % VO_MAX_BUF];
            break;
        default:
            send_outbuf = outbuf_bk[(wm_wifi.send_index[ac] + offset) % BK_MAX_BUF];
            break;
    }
    return send_outbuf;
}
#endif
#endif

#ifdef WIFI_ADD_ON
static int wifi_xmit_wmm_ac_pkts(t_u8 interface, mlan_wmm_ac_e ac)
{
    int err       = WM_SUCCESS;
    int tx_cnt    = 0;
    int max_buf[] = {BK_MAX_BUF, BE_MAX_BUF, VI_MAX_BUF, VO_MAX_BUF};
#ifdef AMSDU_IN_AMPDU
    uint32_t max_amsdu_size =
        MIN(mlan_adap->priv[interface]->max_amsdu, mlan_adap->priv[interface]->adapter->tx_buffer_size);
    uint8_t i;
    t_u8 tid              = 0;
    bool is_udp_frame     = false;
    bool amsdu_flag       = false;
    uint32_t amsdu_offset = sizeof(TxPD) + INTF_HEADER_LEN;
    uint8_t amsdu_cnt     = 0;
#endif

    while (wm_wifi.pkt_cnt[ac])
    {
#ifdef AMSDU_IN_AMPDU
        uint32_t amsdu_buf_used_size = 0;
        int amsdu_buf_available_size = max_amsdu_size - amsdu_buf_used_size;
        uint32_t amsdu_pkt_len       = 0;
        int pad_len                  = 0;
        amsdu_flag                   = false;
        amsdu_offset                 = sizeof(TxPD) + INTF_HEADER_LEN;
        amsdu_cnt                    = 0;

        wifi_wmm_get_pkt_prio(wifi_get_wmm_send_outbuf(ac, 0) + sizeof(TxPD) + INTF_HEADER_LEN, &tid, &is_udp_frame);

        if (wlan_is_amsdu_allowed(mlan_adap->priv[interface], interface, wm_wifi.pkt_cnt[ac], tid))
        {
            /* Try to calculate how many A-MSDU can be formed within max_amsdu_size during the tx opportunity */
            while (amsdu_buf_available_size >= 0 && amsdu_cnt < wm_wifi.pkt_cnt[ac])
            {
                amsdu_buf_used_size += wifi_get_wmm_pkt_length(ac, amsdu_cnt);
                if (amsdu_cnt == 0)
                {
                    /* First A-MSDU packet */
                    amsdu_buf_available_size = max_amsdu_size - amsdu_buf_used_size - LLC_SNAP_LEN;
                }
                else
                {
                    /* The following A-MSDU packets */
                    amsdu_pkt_len            = amsdu_buf_used_size - sizeof(TxPD) - INTF_HEADER_LEN + LLC_SNAP_LEN;
                    pad_len                  = ((amsdu_pkt_len & 3)) ? (4 - ((amsdu_pkt_len)&3)) : 0;
                    amsdu_buf_available_size = max_amsdu_size - amsdu_pkt_len - pad_len;
                }

                if (amsdu_buf_available_size >= 0)
                {
                    amsdu_cnt++;
                }
            }
            if (amsdu_cnt >= MIN_NUM_AMSDU)
            {
                amsdu_flag = true;
                pad_len    = 0;
                for (i = 0; i < amsdu_cnt; i++)
                {
                    amsdu_offset += wlan_11n_form_amsdu_pkt(
                        wifi_get_amsdu_outbuf(amsdu_offset),
                        wifi_get_wmm_send_outbuf(ac, i) + sizeof(TxPD) + INTF_HEADER_LEN,
                        wifi_get_wmm_pkt_length(ac, i) - sizeof(TxPD) - INTF_HEADER_LEN, &pad_len);
                }
                /* Last A-MSDU packet does not need the padding */
                amsdu_offset -= pad_len;
            }
        }

        if (amsdu_flag)
        {
            err = wlan_xmit_wmm_amsdu_pkt(ac, interface, amsdu_offset, wifi_get_amsdu_outbuf(0), amsdu_cnt);
            if (err != MLAN_STATUS_SUCCESS)
            {
                wifi_e("Error in sending AMSDU %s", ac == WMM_AC_VO ?
                                                        "Voice traffic" :
                                                        ac == WMM_AC_VI ?
                                                        "Video traffic" :
                                                        ac == WMM_AC_BK ? "Background traffic" : "Best Effort traffic");
                goto ret;
            }
        }
        else
#endif
        {
            switch (ac)
            {
                case WMM_AC_VO:
                    err = wlan_xmit_wmm_pkt(interface, wm_wifi.vo_pkt_len[wm_wifi.send_index[ac]],
                                            outbuf_vo[wm_wifi.send_index[ac]]);
                    if (err != MLAN_STATUS_SUCCESS)
                    {
                        wifi_dump_wmm_pkts_info(outbuf_vo[wm_wifi.send_index[ac]], ac);
                        goto ret;
                    }
                    break;
                case WMM_AC_VI:
                    err = wlan_xmit_wmm_pkt(interface, wm_wifi.vi_pkt_len[wm_wifi.send_index[ac]],
                                            outbuf_vi[wm_wifi.send_index[ac]]);
                    if (err != MLAN_STATUS_SUCCESS)
                    {
                        wifi_dump_wmm_pkts_info(outbuf_vi[wm_wifi.send_index[ac]], ac);
                        goto ret;
                    }
                    break;
                case WMM_AC_BE:
                    err = wlan_xmit_wmm_pkt(interface, wm_wifi.be_pkt_len[wm_wifi.send_index[ac]],
                                            outbuf_be[wm_wifi.send_index[ac]]);
                    if (err != MLAN_STATUS_SUCCESS)
                    {
                        wifi_dump_wmm_pkts_info(outbuf_be[wm_wifi.send_index[ac]], ac);
                        goto ret;
                    }
                    break;
                case WMM_AC_BK:
                    err = wlan_xmit_wmm_pkt(interface, wm_wifi.bk_pkt_len[wm_wifi.send_index[ac]],
                                            outbuf_bk[wm_wifi.send_index[ac]]);
                    if (err != MLAN_STATUS_SUCCESS)
                    {
                        wifi_dump_wmm_pkts_info(outbuf_bk[wm_wifi.send_index[ac]], ac);
                        goto ret;
                    }
                    break;
                default:
                    goto ret;
            }
        }
#ifdef AMSDU_IN_AMPDU
        if (amsdu_flag)
        {
            tx_cnt += amsdu_cnt;
            os_semaphore_get(&wm_wifi.tx_data_sem, OS_WAIT_FOREVER);
            wm_wifi.pkt_cnt[ac] -= amsdu_cnt;
            os_semaphore_put(&wm_wifi.tx_data_sem);
            wm_wifi.send_index[ac] = (wm_wifi.send_index[ac] + amsdu_cnt) % max_buf[ac];
        }
        else
#endif
        {
            tx_cnt++;
            os_semaphore_get(&wm_wifi.tx_data_sem, OS_WAIT_FOREVER);
            wm_wifi.pkt_cnt[ac]--;
            os_semaphore_put(&wm_wifi.tx_data_sem);
            wm_wifi.send_index[ac]++;
            if (wm_wifi.send_index[ac] >= max_buf[ac])
                wm_wifi.send_index[ac] = 0;
        }
    }

ret:
    wlan_flush_wmm_pkt(tx_cnt);
    return tx_cnt;
}
#endif
#endif /* CONFIG_WMM_ENH */

#ifdef WIFI_ADD_ON
static void wifi_driver_tx(void *data)
{
    int ret;
    struct bus_message msg;
    while (1)
    {
    get_msg:
#ifdef CONFIG_ECSA
        while (true == get_ecsa_block_tx_flag())
        {
            os_thread_sleep((get_ecsa_block_tx_time() + 2) * wm_wifi.beacon_period);
        }
#endif
        ret = os_queue_recv(&wm_wifi.tx_data, &msg, OS_WAIT_FOREVER);
        if (ret == WM_SUCCESS)
        {
            if (msg.event == MLAN_TYPE_DATA || msg.event == MLAN_TYPE_NULL_DATA)
            {
#ifdef CONFIG_WMM_UAPSD
                while (mlan_adap->priv[msg.reason]->adapter->pps_uapsd_mode &&
                       (mlan_adap->priv[msg.reason]->adapter->tx_lock_flag == MTRUE))
                {
                    os_thread_sleep(os_msec_to_ticks(1));
                }
#endif
#if defined(CONFIG_WIFIDRIVER_PS_LOCK)
                ret = os_rwlock_read_lock(&sleep_rwlock, MAX_WAIT_TIME);
#else
                ret = os_rwlock_read_lock(&ps_rwlock, MAX_WAIT_TIME);
#endif
                if (ret != WM_SUCCESS)
                {
                    wifi_e("Error in getting readlock");
                    goto get_msg;
                }
#ifdef CONFIG_WMM_ENH
                wifi_xmit_wmm_ac_pkts_enh();
                /* Only send packet when the outbuf pool is not empty */
                if (wifi_wmm_get_packet_cnt() > 0)
                {
                    wifi_xmit_wmm_ac_pkts_enh();
                }

#else
                if (wm_wifi.pkt_cnt[WMM_AC_VO] > 0)
                {
                    wifi_xmit_wmm_ac_pkts(msg.reason, WMM_AC_VO);
                }
                else if (wm_wifi.pkt_cnt[WMM_AC_VI] > 0)
                {
                    wifi_xmit_wmm_ac_pkts(msg.reason, WMM_AC_VI);
                }
                else if (wm_wifi.pkt_cnt[WMM_AC_BE] > 0)
                {
                    wifi_xmit_wmm_ac_pkts(msg.reason, WMM_AC_BE);
                }
                else if (wm_wifi.pkt_cnt[WMM_AC_BK] > 0)
                {
                    wifi_xmit_wmm_ac_pkts(msg.reason, WMM_AC_BK);
                }
#endif
#ifdef CONFIG_WMM_UAPSD
                else
                {
                    if (msg.event == MLAN_TYPE_NULL_DATA)
                    {
                        /* send null packet until the finish of CMD response processing */
                        os_semaphore_get(&uapsd_sem, OS_WAIT_FOREVER);
                        if (mlan_adap->priv[msg.reason]->adapter->pps_uapsd_mode &&
                            mlan_adap->priv[msg.reason]->media_connected &&
                            mlan_adap->priv[msg.reason]->adapter->gen_null_pkt)
                        {
                            if (wlan_send_null_packet(mlan_adap->priv[msg.reason],
                                                      MRVDRV_TxPD_POWER_MGMT_NULL_PACKET |
                                                          MRVDRV_TxPD_POWER_MGMT_LAST_PACKET) == MLAN_STATUS_SUCCESS)
                            {
                                mlan_adap->priv[msg.reason]->adapter->tx_lock_flag = MTRUE;
                            }
                        }
                        else
                        {
                            wifi_d(
                                "No need to send null packet, pps_uapsd_mode: %d, media_connected: %d, gen_null_pkt: "
                                "%d",
                                mlan_adap->priv[msg.reason]->adapter->pps_uapsd_mode,
                                mlan_adap->priv[msg.reason]->media_connected,
                                mlan_adap->priv[msg.reason]->adapter->gen_null_pkt);
                            os_semaphore_put(&uapsd_sem);
                            mlan_adap->priv[msg.reason]->adapter->tx_lock_flag = MFALSE;
                        }
                    }
                }
#endif

#if defined(CONFIG_WIFIDRIVER_PS_LOCK)
                os_rwlock_read_unlock(&sleep_rwlock);
#else
                os_rwlock_read_unlock(&ps_rwlock);
#endif
                wifi_set_xfer_pending(false);
            }
        }
    }
}
#else
static void wifi_driver_tx(void *data)
{
#ifndef CONFIG_WMM_ENH
    int err = WM_SUCCESS;
#endif
    int ret;
    struct bus_message msg;
    while (1)
    {
    get_msg:
        ret = os_queue_recv(&wm_wifi.tx_data, &msg, OS_WAIT_FOREVER);
        if (ret == WM_SUCCESS)
        {
            if (msg.event == MLAN_TYPE_DATA)
            {
#if defined(CONFIG_WIFIDRIVER_PS_LOCK)
                ret = os_rwlock_read_lock(&sleep_rwlock, MAX_WAIT_TIME);
#else
                ret = os_rwlock_read_lock(&ps_rwlock, MAX_WAIT_TIME);
#endif
                if (ret != WM_SUCCESS)
                {
                    wifi_e("Error in getting readlock");
                    goto get_msg;
                }
#ifdef CONFIG_WMM_ENH
                wifi_xmit_wmm_ac_pkts_enh();
#else
                if (wm_wifi.pkt_cnt[WMM_AC_VO] > 0)
                {
                    err = wlan_xmit_wmm_pkt(msg.reason, wm_wifi.vo_pkt_len[wm_wifi.send_index[WMM_AC_VO]],
                                            outbuf_vo[wm_wifi.send_index[WMM_AC_VO]]);
                    if (err != MLAN_STATUS_SUCCESS)
                    {
#ifdef CONFIG_WIFI_IO_DEBUG
                        wifi_e("Error in sending Voice traffic");
#endif
                    }
                    os_semaphore_get(&wm_wifi.tx_data_sem, OS_WAIT_FOREVER);
                    wm_wifi.pkt_cnt[WMM_AC_VO]--;
                    os_semaphore_put(&wm_wifi.tx_data_sem);
                    wm_wifi.send_index[WMM_AC_VO]++;
                    if (wm_wifi.send_index[WMM_AC_VO] >= VO_MAX_BUF)
                        wm_wifi.send_index[WMM_AC_VO] = 0;
                }
                else if (wm_wifi.pkt_cnt[WMM_AC_VI] > 0)
                {
                    err = wlan_xmit_wmm_pkt(msg.reason, wm_wifi.vi_pkt_len[wm_wifi.send_index[WMM_AC_VI]],
                                            outbuf_vi[wm_wifi.send_index[WMM_AC_VI]]);
                    if (err != MLAN_STATUS_SUCCESS)
                    {
#ifdef CONFIG_WIFI_IO_DEBUG
                        wifi_e("Error in sending Video traffic");
#endif
                    }
                    os_semaphore_get(&wm_wifi.tx_data_sem, OS_WAIT_FOREVER);
                    wm_wifi.pkt_cnt[WMM_AC_VI]--;
                    os_semaphore_put(&wm_wifi.tx_data_sem);
                    wm_wifi.send_index[WMM_AC_VI]++;
                    if (wm_wifi.send_index[WMM_AC_VI] >= VI_MAX_BUF)
                        wm_wifi.send_index[WMM_AC_VI] = 0;
                }
                else if (wm_wifi.pkt_cnt[WMM_AC_BE] > 0)
                {
                    err = wlan_xmit_wmm_pkt(msg.reason, wm_wifi.be_pkt_len[wm_wifi.send_index[WMM_AC_BE]],
                                            outbuf_be[wm_wifi.send_index[WMM_AC_BE]]);
                    if (err != MLAN_STATUS_SUCCESS)
                    {
#ifdef CONFIG_WIFI_IO_DEBUG
                        wifi_e("Error in sending Best Effort traffic");
#endif
                    }
                    os_semaphore_get(&wm_wifi.tx_data_sem, OS_WAIT_FOREVER);
                    wm_wifi.pkt_cnt[WMM_AC_BE]--;
                    os_semaphore_put(&wm_wifi.tx_data_sem);
                    wm_wifi.send_index[WMM_AC_BE]++;
                    if (wm_wifi.send_index[WMM_AC_BE] >= BE_MAX_BUF)
                        wm_wifi.send_index[WMM_AC_BE] = 0;
                }
                else if (wm_wifi.pkt_cnt[WMM_AC_BK] > 0)
                {
                    err = wlan_xmit_wmm_pkt(msg.reason, wm_wifi.bk_pkt_len[wm_wifi.send_index[WMM_AC_BK]],
                                            outbuf_bk[wm_wifi.send_index[WMM_AC_BK]]);
                    if (err != MLAN_STATUS_SUCCESS)
                    {
#ifdef CONFIG_WIFI_IO_DEBUG
                        wifi_e("Error in sending Background traffic");
#endif
                    }
                    os_semaphore_get(&wm_wifi.tx_data_sem, OS_WAIT_FOREVER);
                    wm_wifi.pkt_cnt[WMM_AC_BK]--;
                    os_semaphore_put(&wm_wifi.tx_data_sem);
                    wm_wifi.send_index[WMM_AC_BK]++;
                    if (wm_wifi.send_index[WMM_AC_BK] >= BK_MAX_BUF)
                        wm_wifi.send_index[WMM_AC_BK] = 0;
                }
                else
                {
                    /* Do nothing */
                }
#endif /* CONFIG_WMM_ENH */

#if defined(CONFIG_WIFIDRIVER_PS_LOCK)
                os_rwlock_read_unlock(&sleep_rwlock);
#else
                os_rwlock_read_unlock(&ps_rwlock);
#endif
                wifi_set_xfer_pending(false);
            }
        }
    }
}
#endif /* WIFI_ADD_ON */
#endif /* CONFIG_WMM */

int wifi_low_level_output(const uint8_t interface,
                          const uint8_t *sd_buffer,
                          const uint16_t len
#ifdef CONFIG_WMM
                          ,
                          uint8_t pkt_prio,
                          uint8_t tid
#endif
)
{
    int ret;
#ifdef CONFIG_WMM
    struct bus_message msg;
#else
    int retry = retry_attempts;
    mlan_status i;
#endif
    mlan_private *pmpriv     = (mlan_private *)mlan_adap->priv[0];
    mlan_private *pmpriv_uap = (mlan_private *)mlan_adap->priv[1];

    w_pkt_d("Data TX: Kernel=>Driver, if %d, len %d", interface, len);

    if (wm_wifi.tx_status == WIFI_DATA_BLOCK)
    {
        wm_wifi.tx_block_cnt++;
        return WM_SUCCESS;
    }

    // wakelock_get(WL_ID_LL_OUTPUT);
#if defined(CONFIG_WIFIDRIVER_PS_LOCK)
    ret = os_rwlock_read_lock(&sleep_rwlock, MAX_WAIT_TIME);
#else
    ret = os_rwlock_read_lock(&ps_rwlock, MAX_WAIT_TIME);
#endif
    if (ret != WM_SUCCESS)
    {
        // wakelock_put(WL_ID_LL_OUTPUT);
        return ERR_INPROGRESS;
    }
    /* Following condition is added to check if device is not connected and data packet is being transmitted */
    if (!pmpriv->media_connected && !pmpriv_uap->media_connected)
    {
#if defined(CONFIG_WMM) && defined(CONFIG_WMM_ENH)
        wifi_wmm_buf_put((outbuf_t *)sd_buffer);
        wifi_wmm_drop_no_media(interface);
#endif
        ret = -WM_E_BUSY;
        goto exit_fn;
    }

#ifdef CONFIG_WMM
#ifdef CONFIG_WMM_ENH
    /* process packet headers with interface header and TxPD */
    process_pkt_hdrs((void *)(sd_buffer + sizeof(mlan_linked_list)), len - sizeof(mlan_linked_list), interface);

    /* add buffer to ra lists */
    if (wlan_wmm_add_buf_txqueue_enh(interface, sd_buffer, len, pkt_prio) != MLAN_STATUS_SUCCESS)
    {
        wifi_wmm_drop_no_media(interface);
        ret = -WM_E_BUSY;
        goto exit_fn;
    }

#else
    /* For rw610, move process_pkt_hdrs from wifi_driver_tx thread to tcpip_thread.
       wifi_driver_tx could be wakeup by tcpip_thread enqueue wmm pkts,
       or CPU1 attach TX buffer in Hal_Imumain task,
       since process_pkt_hdrs needs to know the interface info (bss index),
       Hal_imumain task don't have such info,
       so move process_pkt_hdr out from wifi_driver_tx. */
    if (pkt_prio == WMM_AC_VO)
    {
        wm_wifi.vo_pkt_len[wm_wifi.pkt_index[WMM_AC_VO]] = len;
#ifdef WIFI_ADD_ON
        process_pkt_hdrs((t_u8 *)outbuf_vo[wm_wifi.pkt_index[pkt_prio]],
                         wm_wifi.vo_pkt_len[wm_wifi.pkt_index[pkt_prio]], interface);
#endif

        os_semaphore_get(&wm_wifi.tx_data_sem, OS_WAIT_FOREVER);
        wm_wifi.pkt_cnt[WMM_AC_VO]++;
        os_semaphore_put(&wm_wifi.tx_data_sem);
        wm_wifi.pkt_index[WMM_AC_VO]++;
        if (wm_wifi.pkt_index[WMM_AC_VO] >= VO_MAX_BUF)
            wm_wifi.pkt_index[WMM_AC_VO] = 0;
    }
    else if (pkt_prio == WMM_AC_VI)
    {
        wm_wifi.vi_pkt_len[wm_wifi.pkt_index[WMM_AC_VI]] = len;
#ifdef WIFI_ADD_ON
        process_pkt_hdrs((t_u8 *)outbuf_vi[wm_wifi.pkt_index[pkt_prio]],
                         wm_wifi.vi_pkt_len[wm_wifi.pkt_index[pkt_prio]], interface);
#endif

        os_semaphore_get(&wm_wifi.tx_data_sem, OS_WAIT_FOREVER);
        wm_wifi.pkt_cnt[WMM_AC_VI]++;
        os_semaphore_put(&wm_wifi.tx_data_sem);
        wm_wifi.pkt_index[WMM_AC_VI]++;
        if (wm_wifi.pkt_index[WMM_AC_VI] >= VI_MAX_BUF)
            wm_wifi.pkt_index[WMM_AC_VI] = 0;
    }
    else if (pkt_prio == WMM_AC_BE)
    {
        wm_wifi.be_pkt_len[wm_wifi.pkt_index[WMM_AC_BE]] = len;
#ifdef WIFI_ADD_ON
        process_pkt_hdrs((t_u8 *)outbuf_be[wm_wifi.pkt_index[pkt_prio]],
                         wm_wifi.be_pkt_len[wm_wifi.pkt_index[pkt_prio]], interface);
#endif

        os_semaphore_get(&wm_wifi.tx_data_sem, OS_WAIT_FOREVER);
        wm_wifi.pkt_cnt[WMM_AC_BE]++;
        os_semaphore_put(&wm_wifi.tx_data_sem);
        wm_wifi.pkt_index[WMM_AC_BE]++;
        if (wm_wifi.pkt_index[WMM_AC_BE] >= BE_MAX_BUF)
            wm_wifi.pkt_index[WMM_AC_BE] = 0;
    }
    else if (pkt_prio == WMM_AC_BK)
    {
        wm_wifi.bk_pkt_len[wm_wifi.pkt_index[WMM_AC_BK]] = len;
#ifdef WIFI_ADD_ON
        process_pkt_hdrs((t_u8 *)outbuf_bk[wm_wifi.pkt_index[pkt_prio]],
                         wm_wifi.bk_pkt_len[wm_wifi.pkt_index[pkt_prio]], interface);
#endif

        os_semaphore_get(&wm_wifi.tx_data_sem, OS_WAIT_FOREVER);
        wm_wifi.pkt_cnt[WMM_AC_BK]++;
        os_semaphore_put(&wm_wifi.tx_data_sem);
        wm_wifi.pkt_index[WMM_AC_BK]++;
        if (wm_wifi.pkt_index[WMM_AC_BK] >= BK_MAX_BUF)
            wm_wifi.pkt_index[WMM_AC_BK] = 0;
    }
    else
    {
        /* Do nothing */
    }
#endif

    msg.event  = MLAN_TYPE_DATA;
    msg.reason = interface;
    ret        = os_queue_send(&wm_wifi.tx_data, &msg, OS_NO_WAIT);
#else
#if defined(RW610)
    wifi_imu_lock();
#else
    (void)wifi_sdio_lock();
#endif

    while (true)
    {
        i = wlan_xmit_pkt((t_u8 *)sd_buffer, len, interface);
#if defined(RW610)
        wifi_imu_unlock();
#else
        wifi_sdio_unlock();
#endif
        if (i == MLAN_STATUS_SUCCESS)
        {
            break;
        }
        else
        {
            if (i == MLAN_STATUS_FAILURE)
            {
                ret = -WM_E_NOMEM;
                goto exit_fn;
            }
            else if (i == MLAN_STATUS_RESOURCE)
            {
                if (retry == 0)
                {
                    ret = -WM_E_BUSY;
                    goto exit_fn;
                }
                else
                {
                    retry--;
                    /* Allow the other thread to run and hence
                     * update the write bitmap so that pkt
                     * can be sent to FW */
                    os_thread_sleep(1);
#if defined(RW610)
                    wifi_imu_lock();
#else
                    (void)wifi_sdio_lock();
#endif
                    continue;
                }
            }
            else
            { /* Do Nothing */
            }
            break;
        } /* if (i != MLAN_STATUS_SUCCESS) */
    }     /* while(true) */

    ret = WM_SUCCESS;
#endif

exit_fn:
#if defined(CONFIG_WIFIDRIVER_PS_LOCK)
    (void)os_rwlock_read_unlock(&sleep_rwlock);
#else
    (void)os_rwlock_read_unlock(&ps_rwlock);
#endif
    wifi_set_xfer_pending(false);
    // wakelock_put(WL_ID_LL_OUTPUT);

    return ret;
}

uint8_t *wifi_get_outbuf(uint32_t *outbuf_len)
{
#if defined(RW610)
    return wifi_get_imu_outbuf(outbuf_len);
#else
    return wifi_get_sdio_outbuf(outbuf_len);
#endif
}
#if defined(CONFIG_WMM) && !defined(CONFIG_WMM_ENH)
uint8_t *wifi_wmm_get_sdio_outbuf(uint32_t *outbuf_len, mlan_wmm_ac_e queue)
{
    switch (queue)
    {
        case WMM_AC_BK:
            *outbuf_len = sizeof(outbuf_bk[0]);
            return outbuf_bk[wm_wifi.pkt_index[WMM_AC_BK]];
        case WMM_AC_BE:
            *outbuf_len = sizeof(outbuf_be[0]);
            return outbuf_be[wm_wifi.pkt_index[WMM_AC_BE]];
        case WMM_AC_VI:
            *outbuf_len = sizeof(outbuf_vi[0]);
            return outbuf_vi[wm_wifi.pkt_index[WMM_AC_VI]];
        case WMM_AC_VO:
            *outbuf_len = sizeof(outbuf_vo[0]);
            return outbuf_vo[wm_wifi.pkt_index[WMM_AC_VO]];
        default:
            *outbuf_len = sizeof(outbuf_bk[0]);
            return outbuf_bk[wm_wifi.pkt_index[WMM_AC_BK]];
    }
    return outbuf_bk[0];
}

uint8_t *wifi_wmm_get_outbuf(uint32_t *outbuf_len, mlan_wmm_ac_e queue)
{
    uint8_t *outbuf = NULL;
    outbuf          = wifi_wmm_get_sdio_outbuf(outbuf_len, queue);

    return outbuf;
}
#endif

#ifdef CONFIG_HEAP_DEBUG
static bool get_os_mem_stat_index(char const *func, t_u32 *index)
{
    int i     = 0;
    t_u32 len = strlen(func);

    len = (len > MAX_FUNC_SYMBOL_LEN - 1) ? (MAX_FUNC_SYMBOL_LEN - 1) : len;

    for (i = 0; i < valid_item_cnt; i++)
    {
        if (!strncmp(wifi_os_mem_stat[i].name, func, len))
        {
            // Find matched item
            *index = i;
            return true;
        }
    }

    if (valid_item_cnt >= OS_MEM_STAT_TABLE_SIZE)
    {
        (void)PRINTF("os_mem_stat table full\r\n");
        *index = OS_MEM_STAT_TABLE_SIZE - 1;
    }
    else
    {
        // Add a new item, increase valid_item_cnt
        *index = valid_item_cnt;
        valid_item_cnt++;
    }

    return false;
}

static int record_os_mem_item(t_u32 size, char const *func, t_u32 line_num, bool is_alloc)
{
    t_u32 index = 0;
    t_u32 len   = strlen(func);

    len = (len > MAX_FUNC_SYMBOL_LEN - 1) ? (MAX_FUNC_SYMBOL_LEN - 1) : len;

    // If don't get matched item, record stat in new item; else just increase alloc_cnt or free_cnt.
    if (false == get_os_mem_stat_index(func, &index))
    {
        wifi_os_mem_stat[index].line_num = line_num;

        if (true == is_alloc)
        {
            wifi_os_mem_stat[index].size = size;
        }

        memcpy(wifi_os_mem_stat[index].name, func, len);
    }

    return index;
}

void record_os_mem_alloc(t_u32 size, char const *func, t_u32 line_num)
{
    int index     = 0;
    bool is_alloc = true;

    os_semaphore_get(&os_mem_stat_sem, OS_WAIT_FOREVER);
    index = record_os_mem_item(size, func, line_num, is_alloc);
    wifi_os_mem_stat[index].alloc_cnt++;
    os_semaphore_put(&os_mem_stat_sem);
}

void record_os_mem_free(char const *func, t_u32 line_num)
{
    int index     = 0;
    t_u32 size    = 0;
    bool is_alloc = false;

    os_semaphore_get(&os_mem_stat_sem, OS_WAIT_FOREVER);
    index = record_os_mem_item(size, func, line_num, is_alloc);
    wifi_os_mem_stat[index].free_cnt++;
    os_semaphore_put(&os_mem_stat_sem);
}

void wifi_show_os_mem_stat()
{
    int index = 0;

    (void)PRINTF("os_mem_alloc_stat: \r\n");
    (void)PRINTF(
        "Func name                                                         line_num    size        alloc_cnt    "
        "free_cnt\r\n");

    for (index = 0; index < valid_item_cnt; index++)
    {
        (void)PRINTF("%-64s  %-10d  %-10d  %-10d   %-10d \r\n", wifi_os_mem_stat[index].name,
                     wifi_os_mem_stat[index].line_num, wifi_os_mem_stat[index].size, wifi_os_mem_stat[index].alloc_cnt,
                     wifi_os_mem_stat[index].free_cnt);
    }
}
#endif

/**
 * Frame Tx - Injecting Wireless frames from Host
 *
 * This function is used to Inject Wireless frames from application
 * directly.
 *
 * \param[in] interface Interface on which frame to be injected.
 * \param[in] buf Buffer holding 802.11 Wireless frame (Header + Data).
 * \param[in] len Length of the 802.11 Wireless frame.
 *
 * \return WM_SUCCESS on success or error code.
 *
 */
static int raw_low_level_output(const t_u8 interface, const t_u8 *buf, t_u32 len)
{
    mlan_status i;
    t_u32 pkt_len       = 0;
    uint32_t outbuf_len = 0;
    uint8_t *poutbuf    = wifi_get_outbuf(&outbuf_len);

    pkt_len = sizeof(TxPD) + INTF_HEADER_LEN;

#if defined(RW610)
    wifi_imu_lock();
#else
    (void)wifi_sdio_lock();
#endif

    /* XXX: TODO Get rid on the memset once we are convinced that
     * process_pkt_hdrs sets correct values */
    (void)memset(poutbuf, 0, sizeof(&outbuf_len));

    (void)raw_process_pkt_hdrs((t_u8 *)poutbuf, pkt_len + len - 2U, interface);
    (void)memcpy((void *)((t_u8 *)poutbuf + pkt_len - 2), (const void *)buf, (size_t)len);
    i = wlan_xmit_pkt(poutbuf, pkt_len + len - 2U, interface);
    if (i == MLAN_STATUS_FAILURE)
    {
#if defined(RW610)
        wifi_imu_unlock();
#else
        wifi_sdio_unlock();
#endif

        return (int)-WM_FAIL;
    }

#if defined(RW610)
    wifi_imu_unlock();
#else
    wifi_sdio_unlock();
#endif

    return WM_SUCCESS;
}

int wifi_inject_frame(const enum wlan_bss_type bss_type, const uint8_t *buff, const size_t len)
{
    return raw_low_level_output((t_u8)bss_type, buff, len);
}

#ifdef CONFIG_WPA_SUPP
int wifi_nxp_scan_res_num(void)
{
    mlan_private *pmpriv    = (mlan_private *)mlan_adap->priv[0];
    mlan_adapter *pmadapter = pmpriv->adapter;

    return pmadapter->num_in_scan_table;
}

int wifi_nxp_scan_res_get2(t_u32 table_idx, nxp_wifi_event_new_scan_result_t *scan_res)
{
    mlan_private *pmpriv    = (mlan_private *)mlan_adap->priv[0];
    mlan_adapter *pmadapter = pmpriv->adapter;
    struct os_time t;
    BSSDescriptor_t *bss_new_entry;

    bss_new_entry = &pmadapter->pscan_table[table_idx];
    memcpy(scan_res->mac_addr, bss_new_entry->mac_address, sizeof(bss_new_entry->mac_address));
    scan_res->frequency  = channel_to_frequency(bss_new_entry->channel, (bss_new_entry->bss_band == BAND_A ? 1 : 0));
    scan_res->chan_width = bss_new_entry->curr_bandwidth;
    scan_res->beacon_interval = bss_new_entry->beacon_period;
    memcpy(&scan_res->capability, &bss_new_entry->cap_info, sizeof(unsigned short));
    memcpy(&scan_res->ies_tsf, bss_new_entry->time_stamp, sizeof(bss_new_entry->time_stamp));
    os_get_time(&t);
    scan_res->seen_ms_ago = t.sec * 1000;
    if ((bss_new_entry->ies_len > 0) && (bss_new_entry->ies_len < sizeof(scan_res->ies.ie)))
    {
        memcpy(scan_res->ies.ie, bss_new_entry->ies, bss_new_entry->ies_len);
        scan_res->ies.ie_len = (t_u16)bss_new_entry->ies_len;
    }
    else
    {
        scan_res->ies.ie_len = (t_u16)0U;
    }

    scan_res->rssi = (t_u8) - (bss_new_entry->rssi);

    if ((pmpriv->media_connected == MTRUE) &&
        (memcmp(bss_new_entry->mac_address, (t_u8 *)&pmpriv->curr_bss_params.bss_descriptor.mac_address,
                MLAN_MAC_ADDR_LENGTH) == 0U))

    {
        scan_res->status = 1;
    }
    return WM_SUCCESS;
}

int wifi_nxp_survey_res_get(void)
{
#ifdef SCAN_CHANNEL_GAP
    mlan_private *pmpriv          = (mlan_private *)mlan_adap->priv[0];
    ChanStatistics_t *pchan_stats = NULL;
    mlan_scan_resp scan_resp;
    t_u32 idx;
    nxp_wifi_event_new_survey_result_t survey_res;
    bool more_res = true;
#endif

    ENTER();
    wifi_d("dump_survey");

#ifdef SCAN_CHANNEL_GAP
    memset(&scan_resp, 0, sizeof(scan_resp));
    wifi_get_scan_table(pmpriv, &scan_resp);

    pchan_stats = (ChanStatistics_t *)scan_resp.pchan_stats;

    for (idx = 0; idx < scan_resp.num_in_chan_stats; idx++)
    {
        if (pchan_stats[idx].chan_num == 0)
        {
            if (wm_wifi.supp_if_callbk_fns->survey_res_callbk_fn)
            {
#ifdef CONFIG_HOSTAPD
                if (wm_wifi.hostapd_op)
                {
                    wm_wifi.supp_if_callbk_fns->survey_res_callbk_fn(wm_wifi.hapd_if_priv, NULL, 0, false);
                }
                else
#endif
                {
                    wm_wifi.supp_if_callbk_fns->survey_res_callbk_fn(wm_wifi.if_priv, NULL, 0, false);
                }

                os_thread_sleep(50);
            }

            break;
        }

        memset(&survey_res, 0x00, sizeof(nxp_wifi_event_new_survey_result_t));

        survey_res.freq         = channel_to_frequency(pchan_stats[idx].chan_num, pchan_stats[idx].bandcfg.chanBand);
        survey_res.nf           = pchan_stats[idx].noise;
        survey_res.channel_time = pchan_stats[idx].cca_scan_duration;
        survey_res.channel_time_busy = pchan_stats[idx].cca_busy_duration;

        if (pchan_stats[idx + 1].chan_num == 0)
        {
            more_res = false;
        }
        if (wm_wifi.supp_if_callbk_fns->survey_res_callbk_fn)
        {
#ifdef CONFIG_HOSTAPD
            if (wm_wifi.hostapd_op)
            {
                wm_wifi.supp_if_callbk_fns->survey_res_callbk_fn(wm_wifi.hapd_if_priv, &survey_res,
                                                                 sizeof(nxp_wifi_event_new_survey_result_t), more_res);
            }
            else
#endif
            {
                wm_wifi.supp_if_callbk_fns->survey_res_callbk_fn(wm_wifi.if_priv, &survey_res,
                                                                 sizeof(nxp_wifi_event_new_survey_result_t), more_res);
            }

            os_thread_sleep(50);
        }
    }
#else
    if (wm_wifi.supp_if_callbk_fns->survey_res_callbk_fn)
    {
#ifdef CONFIG_HOSTAPD
        if (wm_wifi.hostapd_op)
        {
            wm_wifi.supp_if_callbk_fns->survey_res_callbk_fn(wm_wifi.hapd_if_priv, NULL, 0, false);
        }
        else
#endif
        {
            wm_wifi.supp_if_callbk_fns->survey_res_callbk_fn(wm_wifi.if_priv, NULL, 0, false);
        }

        os_thread_sleep(50);
    }
#endif
    return WM_SUCCESS;
}

#ifdef CONFIG_WPA_SUPP_WPS
bool wifi_nxp_wps_session_enable(void)
{
    mlan_private *pmpriv = (mlan_private *)mlan_adap->priv[0];

    return pmpriv->wps.session_enable;
}
#endif

static int supp_low_level_output(const t_u8 interface, const t_u8 *buf, t_u32 len)
{
    int i;
    uint32_t pkt_len, outbuf_len;

    uint8_t *outbuf = wifi_get_outbuf(&outbuf_len);

    if (!outbuf)
    {
        return (int)-WM_FAIL;
    }

    pkt_len = sizeof(TxPD) + INTF_HEADER_LEN;

    if ((len + pkt_len) > outbuf_len)
    {
        return (int)-WM_FAIL;
    }

#if defined(RW610)
    wifi_imu_lock();
#else
    wifi_sdio_lock();
#endif

    /* XXX: TODO Get rid on the memset once we are convinced that
     * process_pkt_hdrs sets correct values */
    // memset(outbuf, 0, sizeof(outbuf));
    (void)memset(outbuf, 0x00, pkt_len);

    (void)memcpy((t_u8 *)outbuf + pkt_len, buf, len);

    i = wlan_xmit_pkt(outbuf, pkt_len + len, interface);

    if (i == MLAN_STATUS_FAILURE)
    {
#if defined(RW610)
        wifi_imu_unlock();
#else
        wifi_sdio_unlock();
#endif
        return (int)-WM_FAIL;
    }
#if defined(RW610)
    wifi_imu_unlock();
#else
    wifi_sdio_unlock();
#endif
    return (int)WM_SUCCESS;
}

int wifi_supp_inject_frame(const enum wlan_bss_type bss_type, const uint8_t *buff, const size_t len)
{
    return supp_low_level_output((t_u8)bss_type, buff, len);
}

char *wifi_get_country_str(country_code_t country_code)
{
    if (country_code == COUNTRY_WW)
        return "WW";
    else if (country_code == COUNTRY_US)
        return "US";
    else if (country_code == COUNTRY_CA)
        return "CA";
    else if (country_code == COUNTRY_EU)
        return "EU";
    else if (country_code == COUNTRY_AU)
        return "AU";
    else if (country_code == COUNTRY_KR)
        return "KR";
    else if (country_code == COUNTRY_FR)
        return "FR";
    else if (country_code == COUNTRY_JP)
        return "JP";
    else if (country_code == COUNTRY_CN)
        return "CN";
    else
        return "WW";
}

country_code_t wifi_get_country_code(const char *alpha2)
{
    if (strstr(alpha2, "WW"))
        return COUNTRY_WW;
    else if (strstr(alpha2, "US"))
        return COUNTRY_US;
    else if (strstr(alpha2, "CA"))
        return COUNTRY_CA;
    else if (strstr(alpha2, "EU"))
        return COUNTRY_EU;
    else if (strstr(alpha2, "AU"))
        return COUNTRY_AU;
    else if (strstr(alpha2, "KR"))
        return COUNTRY_KR;
    else if (strstr(alpha2, "FR"))
        return COUNTRY_FR;
    else if (strstr(alpha2, "JP"))
        return COUNTRY_JP;
    else if (strstr(alpha2, "CN"))
        return COUNTRY_CN;
    else
        return COUNTRY_NONE;
}

int wifi_nxp_set_country(unsigned int bss_type, const char *alpha2)
{
    country_code_t country = wifi_get_country_code(alpha2);

    if (country == COUNTRY_NONE)
        return -WM_FAIL;

    if (bss_type == BSS_TYPE_STA)
    {
        return wifi_set_country(country);
    }
    else
    {
        return wifi_uap_set_country(country);
    }
}

int wifi_nxp_get_country(unsigned int bss_type, char *alpha2)
{
    country_code_t country = COUNTRY_NONE;

    if (bss_type == BSS_TYPE_STA)
    {
        country = wifi_get_country();
    }
    else
    {
        country = wifi_uap_get_country();
    }

    if (country == COUNTRY_NONE)
        return -WM_FAIL;

    strncpy(alpha2, wifi_get_country_str(country), 2);
    alpha2[2] = '\0';

    return WM_SUCCESS;
}

int wifi_nxp_get_signal(unsigned int bss_type, nxp_wifi_signal_info_t *signal_params)
{
    wifi_rssi_info_t rssi_info;

    (void)wifi_send_rssi_info_cmd(&rssi_info);

    signal_params->current_signal    = rssi_info.bcn_rssi_last;
    signal_params->avg_signal        = rssi_info.data_rssi_avg;
    signal_params->avg_beacon_signal = rssi_info.bcn_rssi_avg;
    signal_params->current_noise     = rssi_info.bcn_nf_last;

    return WM_SUCCESS;
}

int wifi_nxp_send_mlme(unsigned int bss_type, int channel, unsigned int wait_time, const t_u8 *data, size_t data_len)
{
    mlan_private *pmpriv              = (mlan_private *)mlan_adap->priv[bss_type];
    wlan_mgmt_pkt *pmgmt_pkt_hdr      = MNULL;
    wlan_802_11_header *pieee_pkt_hdr = MNULL;
    t_u8 buf[1500];

    // dump_hex(data, data_len);
    memset(buf, 0x00, sizeof(buf));

    if ((bss_type == BSS_TYPE_STA) && (pmpriv->media_connected == MFALSE))
    {
        wifi_remain_on_channel(true, channel, wait_time);
    }

    pmgmt_pkt_hdr = (wlan_mgmt_pkt *)&buf[0];

    pmgmt_pkt_hdr->frm_len = data_len + MLAN_MAC_ADDR_LENGTH;

    pieee_pkt_hdr = (wlan_802_11_header *)(void *)&pmgmt_pkt_hdr->wlan_header;

    memcpy(pieee_pkt_hdr, data, sizeof(wlan_802_11_header) - MLAN_MAC_ADDR_LENGTH);

    memcpy(pieee_pkt_hdr + 1, data + sizeof(wlan_802_11_header) - MLAN_MAC_ADDR_LENGTH,
           data_len - (sizeof(wlan_802_11_header) - MLAN_MAC_ADDR_LENGTH));

    data_len = pmgmt_pkt_hdr->frm_len + 2U;

    return wifi_inject_frame(bss_type, buf, data_len);
}
#endif

int wifi_remain_on_channel(const bool status, const uint8_t channel, const uint32_t duration)
{
    wifi_remain_on_channel_t roc;

    (void)memset(&roc, 0x00, sizeof(wifi_remain_on_channel_t));

    roc.remove = (uint16_t)!status;

    roc.channel = channel;

    roc.remain_period = duration;

#ifdef CONFIG_5GHz_SUPPORT
    if (channel > 14)
    {
        roc.bandcfg |= 1;
    }
#endif

    return wifi_send_remain_on_channel_cmd(MLAN_BSS_TYPE_STA, &roc);
}

#ifdef RW610
int wifi_imu_get_task_lock(void)
{
    return imu_get_task_lock();
}

int wifi_imu_put_task_lock(void)
{
    return imu_put_task_lock();
}
#endif

#ifdef CONFIG_CSI

/* csi data recv user callback */
int (*csi_data_recv)(void *buffer) = NULL;

int register_csi_user_callback(int (*csi_data_recv_callback)(void *buffer))
{
    csi_data_recv = csi_data_recv_callback;

    return WM_SUCCESS;
}

void process_csi_info_callback(void *data)
{
    if (csi_data_recv != NULL)
    {
        csi_data_recv(data);
    }
}

void csi_local_buff_init()
{
    csi_event_cnt      = 0;
    csi_event_data_len = 0;

    csi_buff_stat.write_index    = 0;
    csi_buff_stat.read_index     = 0;
    csi_buff_stat.valid_data_cnt = 0;

    memset(csi_local_buff, 0x00, sizeof(csi_local_buff));
}

void csi_save_data_to_local_buff(void *data)
{
    os_semaphore_get(&csi_buff_stat.csi_data_sem, OS_WAIT_FOREVER);

    if (csi_buff_stat.valid_data_cnt >= MAX_CSI_LOCAL_BUF)
    {
        os_semaphore_put(&csi_buff_stat.csi_data_sem);
        wifi_w("******csi_local_buff is full******\r\n");
        return;
    }

    memcpy(&csi_local_buff[csi_buff_stat.write_index][0], (t_u8 *)data, CSI_LOCAL_BUF_ENTRY_SIZE);

    csi_buff_stat.valid_data_cnt++;

    csi_buff_stat.write_index = (csi_buff_stat.write_index + 1) % MAX_CSI_LOCAL_BUF;

    os_semaphore_put(&csi_buff_stat.csi_data_sem);
}

void csi_deliver_data_to_user()
{
    int i               = 0;
    t_u16 save_data_len = 0;

    os_semaphore_get(&csi_buff_stat.csi_data_sem, OS_WAIT_FOREVER);

    for (i = 0; (i < MAX_CSI_LOCAL_BUF) && (csi_buff_stat.valid_data_cnt > 0); i++)
    {
        pcsi_record_ds csi_record = (pcsi_record_ds)(&csi_local_buff[csi_buff_stat.read_index][0]);
        save_data_len             = (csi_record->Len & 0x1fff) * 4;
        save_data_len = (save_data_len >= CSI_LOCAL_BUF_ENTRY_SIZE) ? CSI_LOCAL_BUF_ENTRY_SIZE : save_data_len;

        process_csi_info_callback((t_u8 *)csi_record);

        csi_buff_stat.valid_data_cnt--;

        csi_buff_stat.read_index = (csi_buff_stat.read_index + 1) % MAX_CSI_LOCAL_BUF;
    }

    os_semaphore_put(&csi_buff_stat.csi_data_sem);
}
#endif
