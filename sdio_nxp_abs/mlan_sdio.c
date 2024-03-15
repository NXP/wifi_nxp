/** @file mlan_sdio.c
 *
 *  @brief This file provides mlan driver for SDIO
 *
 *  Copyright 2008-2024 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 *
 */

#if defined(SDK_OS_FREE_RTOS)

#include <wmerrno.h>
#include <fsl_os_abstraction.h>
#include <mlan_sdio_api.h>
#include <mlan_main_defs.h>
#include <board.h>
#include <wifi_bt_config.h>
#include <fsl_common.h>
#include <fsl_clock.h>
#include <fsl_sdio.h>
#include <fsl_sdmmc_spec.h>
#include <fsl_usdhc.h>

#include "fsl_sdmmc_host.h"
#include "fsl_sdmmc_common.h"
#if ((defined __DCACHE_PRESENT) && __DCACHE_PRESENT) || (defined FSL_FEATURE_HAS_L1CACHE && FSL_FEATURE_HAS_L1CACHE)
#if !(defined(FSL_SDK_ENABLE_DRIVER_CACHE_CONTROL) && FSL_SDK_ENABLE_DRIVER_CACHE_CONTROL)
#include "fsl_cache.h"
#endif
#endif

/* Command port */
#define CMD_PORT_SLCT 0x8000U

#define MLAN_SDIO_BYTE_MODE_MASK 0x80000000U

#define SDIO_CMD_TIMEOUT 2000

#if FSL_USDHC_ENABLE_SCATTER_GATHER_TRANSFER
#define SDMMCHOST_TRANSFER_COMPLETE_TIMEOUT (~0U)
#define SDMMCHOST_TRANSFER_CMD_EVENT                                                                                   \
    SDMMC_OSA_EVENT_TRANSFER_CMD_SUCCESS | SDMMC_OSA_EVENT_TRANSFER_CMD_FAIL | SDMMC_OSA_EVENT_TRANSFER_DATA_SUCCESS | \
        SDMMC_OSA_EVENT_TRANSFER_DATA_FAIL
#define SDMMCHOST_TRANSFER_DATA_EVENT SDMMC_OSA_EVENT_TRANSFER_DATA_SUCCESS | SDMMC_OSA_EVENT_TRANSFER_DATA_FAIL

static size_t sg_idx, num_sg;

static usdhc_scatter_gather_data_list_t sgDataList[SDIO_MP_AGGR_DEF_PKT_LIMIT_MAX];

void sg_init_table()
{
    memset(&sgDataList, 0, sizeof(sgDataList));
    sg_idx = 0;
}

void sg_set_num(size_t n_sg)
{
    num_sg = n_sg;
}

void sg_set_buf(uint32_t *buf, size_t len)
{
    sgDataList[sg_idx].dataAddr = buf;
    sgDataList[sg_idx].dataSize = len;
    if (sg_idx > 0)
    {
        sgDataList[sg_idx - 1].dataList = &sgDataList[sg_idx];
    }

    sg_idx++;
}
#endif

extern void handle_cdint(int error);

static sdio_card_t wm_g_sd;
static OSA_MUTEX_HANDLE_DEFINE(sdio_mutex);

int sdio_drv_creg_read(int addr, int fn, uint32_t *resp)
{
    osa_status_t status;

    status = OSA_MutexLock((osa_mutex_handle_t)sdio_mutex, osaWaitForever_c);
    if (status != KOSA_StatusSuccess)
    {
        sdio_e("failed to get mutex\r\n");
        return 0;
    }

    if (SDIO_IO_Read_Direct(&wm_g_sd, (sdio_func_num_t)fn, (uint32_t)addr, (uint8_t *)resp) != KOSA_StatusSuccess)
    {
        (void)OSA_MutexUnlock((osa_mutex_handle_t)sdio_mutex);
        return 0;
    }

    (void)OSA_MutexUnlock((osa_mutex_handle_t)sdio_mutex);

    return 1;
}

int sdio_drv_creg_write(int addr, int fn, uint8_t data, uint32_t *resp)
{
    osa_status_t status;

    status = OSA_MutexLock((osa_mutex_handle_t)sdio_mutex, osaWaitForever_c);
    if (status != KOSA_StatusSuccess)
    {
        sdio_e("failed to get mutex\r\n");
        return 0;
    }

    if (SDIO_IO_Write_Direct(&wm_g_sd, (sdio_func_num_t)fn, (uint32_t)addr, &data, true) != KOSA_StatusSuccess)
    {
        (void)OSA_MutexUnlock((osa_mutex_handle_t)sdio_mutex);
        return false;
    }

    *resp = data;

    (void)OSA_MutexUnlock((osa_mutex_handle_t)sdio_mutex);

    return 1;
}

int sdio_drv_read(uint32_t addr, uint32_t fn, uint32_t bcnt, uint32_t bsize, uint8_t *buf, uint32_t *resp)
{
    osa_status_t status;
    uint32_t flags = 0;
    uint32_t param;

    status = OSA_MutexLock((osa_mutex_handle_t)sdio_mutex, osaWaitForever_c);
    if (status != KOSA_StatusSuccess)
    {
        sdio_e("failed to get mutex\r\n");
        return 0;
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

    if (addr & (CMD_PORT_SLCT | MLAN_SDIO_BYTE_MODE_MASK))
    {
        if (SDIO_IO_Read_Extended(&wm_g_sd, (sdio_func_num_t)fn, addr, buf, param, flags) != KOSA_StatusSuccess)
        {
            (void)OSA_MutexUnlock((osa_mutex_handle_t)sdio_mutex);
            return 0;
        }
    }
    else
    {
#if FSL_USDHC_ENABLE_SCATTER_GATHER_TRANSFER
        if (SDIO_IO_Read_Extended(&wm_g_sd, (sdio_func_num_t)fn, addr, (uint8_t *)sgDataList[0].dataAddr, param,
                                  flags) != KOSA_StatusSuccess)
#else
        if (SDIO_IO_Read_Extended(&wm_g_sd, (sdio_func_num_t)fn, addr, buf, param, flags) != KOSA_StatusSuccess)
#endif
        {
            (void)OSA_MutexUnlock((osa_mutex_handle_t)sdio_mutex);
            return 0;
        }
    }

    (void)OSA_MutexUnlock((osa_mutex_handle_t)sdio_mutex);

    return 1;
}

#if FSL_USDHC_ENABLE_SCATTER_GATHER_TRANSFER
int sdio_drv_read_mb(uint32_t addr, uint32_t fn, uint32_t bcnt, uint32_t bsize)
{
    osa_status_t ret;
    sdio_func_num_t func = (sdio_func_num_t)fn;
    uint32_t regAddr     = addr;
    uint8_t *buffer      = NULL;
    uint32_t count;
    uint32_t flags = 0;
    uint32_t event = 0U;
    usdhc_adma_config_t dmaConfig;

    sdmmchost_transfer_t dcontent = {0U};
    sdmmchost_cmd_t command       = {0U};
    sdmmchost_data_t data         = {0U};
    bool blockMode                = false;
    bool opCode                   = false;
    status_t error                = kStatus_Success;
    sdio_card_t *card             = &wm_g_sd;
    sdmmchost_t *host             = card->host;
    sdmmchost_transfer_t *content = &dcontent;
    int i;

    ret = OSA_MutexLock(&sdio_mutex, osaWaitForever_c);
    if (ret != KOSA_StatusSuccess)
    {
        sdio_e("failed to get mutex\r\n");
        return false;
    }

    if (bcnt > 1U)
    {
        flags |= SDIO_EXTEND_CMD_BLOCK_MODE_MASK;
        count = bcnt;
    }
    else
    {
        count = bsize;
    }

    (void)SDMMC_OSAMutexLock(&card->lock, osaWaitForever_c);

    /* check if card support block mode */
    if (((card->cccrflags & (uint32_t)kSDIO_CCCRSupportMultiBlock) != 0U) &&
        ((flags & SDIO_EXTEND_CMD_BLOCK_MODE_MASK) != 0U))
    {
        blockMode = true;
    }

    /* op code =0 : read/write to fixed addr
     *  op code =1 :read/write addr incrementing
     */
    if ((flags & SDIO_EXTEND_CMD_OP_CODE_MASK) != 0U)
    {
        opCode = true;
    }

    /* check the byte size counter in non-block mode
     * so you need read CIS for each function first,before you do read/write
     */
    if (!blockMode)
    {
        if ((func == kSDIO_FunctionNum0) && (card->commonCIS.fn0MaxBlkSize != 0U) &&
            (count > card->commonCIS.fn0MaxBlkSize))
        {
            error = kStatus_SDMMC_SDIO_InvalidArgument;
        }
        else if ((func != kSDIO_FunctionNum0) && (card->funcCIS[(uint32_t)func - 1U].ioMaxBlockSize != 0U) &&
                 (count > card->funcCIS[(uint32_t)func - 1U].ioMaxBlockSize))
        {
            error = kStatus_SDMMC_SDIO_InvalidArgument;
        }
        else
        {
            /* Intentional empty */
        }
    }

    command.index    = (uint32_t)kSDIO_RWIOExtended;
    command.argument = ((uint32_t)func << SDIO_CMD_ARGUMENT_FUNC_NUM_POS) |
                       ((regAddr & SDIO_CMD_ARGUMENT_REG_ADDR_MASK) << SDIO_CMD_ARGUMENT_REG_ADDR_POS) |
                       (count & SDIO_EXTEND_CMD_COUNT_MASK) |
                       ((blockMode ? 1UL : 0UL) << SDIO_EXTEND_CMD_ARGUMENT_BLOCK_MODE_POS |
                        ((opCode ? 1UL : 0UL) << SDIO_EXTEND_CMD_ARGUMENT_OP_CODE_POS));
    command.responseType = kCARD_ResponseTypeR5;
    command.responseErrorFlags =
        ((uint32_t)kSDIO_StatusCmdCRCError | (uint32_t)kSDIO_StatusIllegalCmd | (uint32_t)kSDIO_StatusError |
         (uint32_t)kSDIO_StatusFunctionNumError | (uint32_t)kSDIO_StatusOutofRange);

    if (blockMode)
    {
        if (func == kSDIO_FunctionNum0)
        {
            data.blockSize = card->io0blockSize;
        }
        else
        {
            data.blockSize = card->ioFBR[(uint32_t)func - 1U].ioBlockSize;
        }
        data.blockCount = count;
    }
    else
    {
        data.blockSize  = count;
        data.blockCount = 1U;
    }
    data.rxData = (uint32_t *)(uint32_t)buffer;

    dcontent.command = &command;
    dcontent.data    = &data;
    //        error           = SDMMCHOST_TransferFunction(card->host, &content);

    usdhc_scatter_gather_data_t scatterGatherData;
    usdhc_scatter_gather_transfer_t transfer = {.data = NULL, .command = content->command};

    ret = OSA_MutexLock(&sdio_mutex, osaWaitForever_c);
    if (ret != KOSA_StatusSuccess)
    {
        sdio_e("failed to get mutex\r\n");
        return 0;
    }

    (void)SDMMC_OSAMutexLock(&host->lock, osaWaitForever_c);

    if (content->data != NULL)
    {
        (void)memset(&dmaConfig, 0, sizeof(usdhc_adma_config_t));
        /* config adma */
        dmaConfig.dmaMode = SDMMCHOST_DMA_MODE;
#if !(defined(FSL_FEATURE_USDHC_HAS_NO_RW_BURST_LEN) && FSL_FEATURE_USDHC_HAS_NO_RW_BURST_LEN)
        dmaConfig.burstLen = kUSDHC_EnBurstLenForINCR;
#endif
        dmaConfig.admaTable      = host->dmaDesBuffer;
        dmaConfig.admaTableWords = host->dmaDesBufferWordsNum;

        scatterGatherData.enableAutoCommand12 = content->data->enableAutoCommand12;
        scatterGatherData.enableAutoCommand23 = content->data->enableAutoCommand23;
        scatterGatherData.enableIgnoreError   = content->data->enableIgnoreError;
        scatterGatherData.dataType            = content->data->dataType;
        scatterGatherData.blockSize           = content->data->blockSize;

        transfer.data = &scatterGatherData;

        scatterGatherData.dataDirection   = kUSDHC_TransferDirectionReceive;
        scatterGatherData.sgData.dataSize = content->data->blockSize * content->data->blockCount;

        scatterGatherData.sgData.dataAddr = sgDataList[0].dataAddr;
        scatterGatherData.sgData.dataSize = sgDataList[0].dataSize;
        scatterGatherData.sgData.dataList = sgDataList[0].dataList;
    }

    /* clear redundant transfer event flag */
    (void)SDMMC_OSAEventClear(&(host->hostEvent), SDMMCHOST_TRANSFER_CMD_EVENT);

    error = USDHC_TransferScatterGatherADMANonBlocking(host->hostController.base, &host->handle, &dmaConfig, &transfer);

    if (error == kStatus_Success)
    {
        /* wait command event */
        if ((kStatus_Fail == SDMMC_OSAEventWait(&(host->hostEvent), SDMMCHOST_TRANSFER_CMD_EVENT,
                                                SDMMCHOST_TRANSFER_COMPLETE_TIMEOUT, &event)) ||
            ((event & SDMMC_OSA_EVENT_TRANSFER_CMD_FAIL) != 0U))
        {
            error = kStatus_Fail;
        }
        else
        {
            if (content->data != NULL)
            {
                if ((event & SDMMC_OSA_EVENT_TRANSFER_DATA_SUCCESS) == 0U)
                {
                    if (((event & SDMMC_OSA_EVENT_TRANSFER_DATA_FAIL) != 0U) ||
                        (kStatus_Fail == SDMMC_OSAEventWait(&(host->hostEvent), SDMMCHOST_TRANSFER_DATA_EVENT,
                                                            SDMMCHOST_TRANSFER_COMPLETE_TIMEOUT, &event) ||
                         ((event & SDMMC_OSA_EVENT_TRANSFER_DATA_FAIL) != 0U)))
                    {
                        error = kStatus_Fail;
                    }
                }
            }
        }
    }

    if (error != kStatus_Success)
    {
        /* host error recovery */
        //        SDMMCHOST_ErrorRecovery(host->hostController.base);
    }
    else
    {
        if ((content->data != NULL) && (content->data->rxData != NULL))
        {
#if defined SDMMCHOST_ENABLE_CACHE_LINE_ALIGN_TRANSFER && SDMMCHOST_ENABLE_CACHE_LINE_ALIGN_TRANSFER
            if (((uint32_t)content->data->rxData % SDMMC_DATA_BUFFER_ALIGN_CACHE) != 0U)
            {
#if ((defined __DCACHE_PRESENT) && __DCACHE_PRESENT) || (defined FSL_FEATURE_HAS_L1CACHE && FSL_FEATURE_HAS_L1CACHE)
#if !(defined(FSL_SDK_ENABLE_DRIVER_CACHE_CONTROL) && FSL_SDK_ENABLE_DRIVER_CACHE_CONTROL)
                if (host->enableCacheControl == kSDMMCHOST_CacheControlRWBuffer)
                {
                    DCACHE_InvalidateByRange((uint32_t)scatterGatherData.sgData.dataAddr,
                                             scatterGatherData.sgData.dataSize);

                    //                    DCACHE_InvalidateByRange((uint32_t)sgDataList0.dataAddr,
                    //                    sgDataList0.dataSize);

                    //                    DCACHE_InvalidateByRange((uint32_t)sgDataList1.dataAddr,
                    //                    sgDataList1.dataSize);
                }
#endif
#endif
                //                memcpy(content->data->rxData, scatterGatherData.sgData.dataAddr,
                //                scatterGatherData.sgData.dataSize); memcpy((void *)((uint32_t)content->data->rxData +
                //                content->data->blockCount * content->data->blockSize -
                //                                sgDataList1.dataSize),
                //                       sgDataList1.dataAddr, sgDataList1.dataSize);
            }
            else
#endif
            {
#if ((defined __DCACHE_PRESENT) && __DCACHE_PRESENT) || (defined FSL_FEATURE_HAS_L1CACHE && FSL_FEATURE_HAS_L1CACHE)
#if !(defined(FSL_SDK_ENABLE_DRIVER_CACHE_CONTROL) && FSL_SDK_ENABLE_DRIVER_CACHE_CONTROL)
                /* invalidate the cache for read */
                if (host->enableCacheControl == kSDMMCHOST_CacheControlRWBuffer)
                {
                    DCACHE_InvalidateByRange((uint32_t)content->data->rxData,
                                             (content->data->blockSize) * (content->data->blockCount));
                }
#endif
#endif
            }
        }
    }

    (void)SDMMC_OSAMutexUnlock(&host->lock);

    if (kStatus_Success != error)
    {
        error = kStatus_SDMMC_TransferFailed;
    }

    (void)SDMMC_OSAMutexUnlock(&card->lock);

    (void)OSA_MutexUnlock(&sdio_mutex);

    if (error != KOSA_StatusSuccess)
    {
        (void)OSA_MutexUnlock(&sdio_mutex);
        return 0;
    }

    (void)OSA_MutexUnlock(&sdio_mutex);

    for (i = 0; i < num_sg; i++)
    {
        // dump_hex(sgDataList[i].dataAddr, sgDataList[i].dataSize);
    }

    return 1;
}
#endif

int sdio_drv_write(uint32_t addr, uint32_t fn, uint32_t bcnt, uint32_t bsize, uint8_t *buf, uint32_t *resp)
{
    osa_status_t status;
    uint32_t flags = 0;
    uint32_t param;

    status = OSA_MutexLock((osa_mutex_handle_t)sdio_mutex, osaWaitForever_c);
    if (status != KOSA_StatusSuccess)
    {
        sdio_e("failed to get mutex\r\n");
        return 0;
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

    if (SDIO_IO_Write_Extended(&wm_g_sd, (sdio_func_num_t)fn, addr, buf, param, flags) != KOSA_StatusSuccess)
    {
        (void)OSA_MutexUnlock((osa_mutex_handle_t)sdio_mutex);
        return false;
    }

    (void)OSA_MutexUnlock((osa_mutex_handle_t)sdio_mutex);

    return 1;
}

static void SDIO_CardInterruptCallBack(void *userData)
{
    SDMMCHOST_EnableCardInt(wm_g_sd.host, false);
    handle_cdint(0);
}

void sdio_enable_interrupt(void)
{
    if (wm_g_sd.isHostReady)
    {
        SDMMCHOST_EnableCardInt(wm_g_sd.host, true);
    }
}

void sdio_disable_interrupt(void)
{
    if (wm_g_sd.isHostReady)
    {
        SDMMCHOST_EnableCardInt(wm_g_sd.host, false);
    }
}

static void sdio_controller_init(void)
{
    (void)memset(&wm_g_sd, 0, sizeof(sdio_card_t));

    BOARD_WIFI_BT_Config(&wm_g_sd, SDIO_CardInterruptCallBack);

#if defined(SD_TIMING_MAX)
    wm_g_sd.currentTiming = SD_TIMING_MAX;
#endif
#if defined(SD_CLOCK_MAX)
    wm_g_sd.usrParam.maxFreq = SD_CLOCK_MAX;
#endif
}

static int sdio_card_init(void)
{
    int ret       = WM_SUCCESS;
    uint32_t resp = 0;

    if (SDIO_HostInit(&wm_g_sd) != KOSA_StatusSuccess)
    {
        return kStatus_SDMMC_HostNotReady;
    }

#if defined(SDMMCHOST_OPERATION_VOLTAGE_3V3)
    /* Disable switch to 1.8V in SDIO_ProbeBusVoltage() */
    wm_g_sd.usrParam.ioVoltage = NULL;
#elif defined(SDMMCHOST_OPERATION_VOLTAGE_1V8)
    /* Switch to 1.8V */
    if ((wm_g_sd.usrParam.ioVoltage != NULL) && (wm_g_sd.usrParam.ioVoltage->type == kSD_IOVoltageCtrlByGpio))
    {
        if (wm_g_sd.usrParam.ioVoltage->func != NULL)
        {
            wm_g_sd.usrParam.ioVoltage->func(kSDMMC_OperationVoltage180V);
        }
    }
#if SDMMCHOST_SUPPORT_VOLTAGE_CONTROL
    else if ((wm_g_sd.usrParam.ioVoltage != NULL) && (wm_g_sd.usrParam.ioVoltage->type == kSD_IOVoltageCtrlByHost))
    {
        SDMMCHOST_SwitchToVoltage(wm_g_sd.host, (uint32_t)kSDMMC_OperationVoltage180V);
    }
#endif
    else
    {
        /* Do Nothing */
    }
    wm_g_sd.operationVoltage = kSDMMC_OperationVoltage180V;
#endif

#if !defined(COEX_APP_SUPPORT) || (defined(COEX_APP_SUPPORT) && !defined(CONFIG_WIFI_IND_DNLD))
    BOARD_WIFI_BT_Enable(true);
#endif

    ret = SDIO_CardInit(&wm_g_sd);
    if (ret != WM_SUCCESS)
    {
        return ret;
    }

    (void)sdio_drv_creg_read(0x0, 0, &resp);

    sdio_d("Card Version - (0x%x)", resp & 0xff);

    /* Mask interrupts in card */
    (void)sdio_drv_creg_write(0x4, 0, 0x3, &resp);
    /* Enable IO in card */
    //    (void)sdio_drv_creg_write(0x2, 0, 0x2, &resp);

    (void)SDIO_SetBlockSize(&wm_g_sd, (sdio_func_num_t)0, 256);
    (void)SDIO_SetBlockSize(&wm_g_sd, (sdio_func_num_t)1, 256);
    (void)SDIO_SetBlockSize(&wm_g_sd, (sdio_func_num_t)2, 256);

    return ret;
}

static void print_card_info(sdio_card_t *card)
{
    assert(card != NULL);

    if (card->operationVoltage == kSDMMC_OperationVoltage330V)
    {
        sdio_d("Voltage: 3.3V");
    }
    else if (card->operationVoltage == kSDMMC_OperationVoltage180V)
    {
        sdio_d("Voltage: 1.8V");
    }

    if (card->currentTiming == kSD_TimingSDR12DefaultMode)
    {
        if (card->operationVoltage == kSDMMC_OperationVoltage330V)
        {
            sdio_d("Timing mode: Default mode");
        }
        else if (card->operationVoltage == kSDMMC_OperationVoltage180V)
        {
            sdio_d("Timing mode: SDR12 mode");
        }
    }
    else if (card->currentTiming == kSD_TimingSDR25HighSpeedMode)
    {
        if (card->operationVoltage == kSDMMC_OperationVoltage180V)
        {
            sdio_d("Timing mode: SDR25");
        }
        else
        {
            sdio_d("Timing mode: High Speed");
        }
    }
    else if (card->currentTiming == kSD_TimingSDR50Mode)
    {
        sdio_d("Timing mode: SDR50");
    }
    else if (card->currentTiming == kSD_TimingSDR104Mode)
    {
        sdio_d("Timing mode: SDR104");
    }
    else if (card->currentTiming == kSD_TimingDDR50Mode)
    {
        sdio_d("Timing mode: DDR50");
    }
}

int sdio_drv_init(void (*cd_int)(int))
{
    osa_status_t status;

    status = OSA_MutexCreate((osa_mutex_handle_t)sdio_mutex);
    if (status != KOSA_StatusSuccess)
    {
        sdio_e("Failed to create mutex");
        return -WM_FAIL;
    }

    sdio_controller_init();

    if (sdio_card_init() != WM_SUCCESS)
    {
        sdio_e("Card initialization failed");
        return -WM_FAIL;
    }
    else
    {
        sdio_d("Card initialization successful");
    }

    print_card_info(&wm_g_sd);

    return WM_SUCCESS;
}

void sdio_drv_deinit(void)
{
    osa_status_t status;

    SDIO_Deinit(&wm_g_sd);

    status = OSA_MutexDestroy((osa_mutex_handle_t)sdio_mutex);
    if (status != KOSA_StatusSuccess)
    {
        sdio_e("Failed to delete mutex");
    }
}

#elif defined(__ZEPHYR__)

#include <mlan_sdio_api.h>
#include <wm_os.h>
#include <fsl_common.h>
#include <fsl_gpio.h>
#include <zephyr/sd/sdio.h>

#define SDIO_CMD_TIMEOUT 2000

const struct device *sdhc_dev = DEVICE_DT_GET(
                DT_BUS(DT_COMPAT_GET_ANY_STATUS_OKAY(nxp_wifi)));

static struct sd_card wm_g_sd;
static struct sdio_func g_sdio_funcs[8];

int sdio_drv_creg_read(int addr, int fn, uint32_t *resp)
{
    struct sdio_func *func = &g_sdio_funcs[fn];

    if (sdio_read_byte(func, addr, (uint8_t *)resp) != 0)
    {
        return 0;
    }

    return 1;
}

int sdio_drv_creg_write(int addr, int fn, uint8_t data, uint32_t *resp)
{
    struct sdio_func *func = &g_sdio_funcs[fn];

    if (sdio_rw_byte(func, addr, data, (uint8_t *)resp) != 0)
    {
        return 0;
    }

    return 1;
}

int sdio_drv_read(uint32_t addr, uint32_t fn, uint32_t bcnt, uint32_t bsize, uint8_t *buf, uint32_t *resp)
{
    struct sdio_func *func = &g_sdio_funcs[fn];

    if (sdio_read_addr(func, addr, buf, bcnt * bsize) != 0)
    {
        return 0;
    }

    return 1;
}

int sdio_drv_write(uint32_t addr, uint32_t fn, uint32_t bcnt, uint32_t bsize, uint8_t *buf, uint32_t *resp)
{
    struct sdio_func *func = &g_sdio_funcs[fn];

    if (sdio_write_addr(func, addr, buf, bcnt * bsize) != 0)
    {
        return 0;
    }

    return 1;
}

extern void handle_cdint(int error);

void sdio_irq_handler(const struct device *dev, int reason, const void *user_data)
{
    if (reason == SDHC_INT_SDIO)
    {
        sdhc_disable_interrupt(sdhc_dev, SDHC_INT_SDIO);
        handle_cdint(0);
    }
}

void sdio_enable_interrupt(void)
{
    sdhc_enable_interrupt(sdhc_dev, (sdhc_interrupt_cb_t)sdio_irq_handler, SDHC_INT_SDIO,
                          NULL);
    return;
}

static void sdio_controller_init(void)
{
    (void)memset(&wm_g_sd, 0, sizeof(struct sd_card));
}

static int sdio_card_init(void)
{
    int ret = WM_SUCCESS;
    uint32_t resp;

    if (!device_is_ready(sdhc_dev))
    {
        sdio_e("SD controller not ready");
        return -EIO;
    }

    if (!sdhc_card_present(sdhc_dev))
    {
        sdio_e("SDIO card not present");
        return -EIO;
    }

    ret = sd_init(sdhc_dev, &wm_g_sd);
    if (ret)
    {
        return ret;
    }

    memcpy(&g_sdio_funcs[0], &wm_g_sd.func0, sizeof(struct sdio_func));
    (void)sdio_drv_creg_read(0x0, 0, &resp);

    sdio_d("Card Version - (0x%x)", resp & 0xff);
    /* Init SDIO functions */
    sdio_init_func(&wm_g_sd, &g_sdio_funcs[1], SDIO_FUNC_NUM_1);
    sdio_init_func(&wm_g_sd, &g_sdio_funcs[2], SDIO_FUNC_NUM_2);

    /* Mask interrupts in card */
    (void)sdio_drv_creg_write(0x4, 0, 0x3, &resp);
    /* Enable IO in card */
    (void)sdio_drv_creg_write(0x2, 0, 0x2, &resp);


    (void)sdio_set_block_size(&g_sdio_funcs[0], 256);
    (void)sdio_set_block_size(&g_sdio_funcs[1], 256);
    (void)sdio_set_block_size(&g_sdio_funcs[2], 256);

    return ret;
}

int sdio_drv_init(void (*cd_int)(int))
{
    sdio_controller_init();

    if (sdio_card_init() != WM_SUCCESS)
    {
        sdio_e("Card initialization failed");
        return -WM_FAIL;
    }
    else
    {
        sdio_d("Card initialization successful");
    }

    return WM_SUCCESS;
}

void sdio_drv_deinit(void)
{
    // SDIO_Deinit(&wm_g_sd);
}

#endif
