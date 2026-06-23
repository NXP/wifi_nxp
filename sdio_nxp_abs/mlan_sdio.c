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
#include <mlan_sdio_defs.h>
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

#if CONFIG_WIFI_IND_RESET
#include "board.h"

#if (defined(MIMXRT1062_SERIES) || defined(MIMXRT1061_SERIES))
#if defined(SD8978) || defined(SD8987)
/* IR-OOB TRIGGER Connect Fly-Wire between J16.1 and J108.4 for 1XK-M2, 1ZM-M2*/
#define IR_OUTBAND_TRIGGER_GPIO			GPIO1
#define IR_OUTBAND_TRIGGER_GPIO_PIN		(23U)
#define IR_OUTBAND_TRIGGER_GPIO_NAME   "GPIO1"
//#define IOMUXC_GPIO_IR_OUTBAND_TRIGGER IOMUXC_GPIO_AD_B1_07_GPIO1_IO23
#elif defined(SD9177) || defined(IW610)
/* IR-OOB TRIGGER for 2EL-M2, Internal Routing to M2 Slot*/
#define IR_OUTBAND_TRIGGER_GPIO			GPIO1
#define IR_OUTBAND_TRIGGER_GPIO_PIN		(24U)
#define IR_OUTBAND_TRIGGER_GPIO_NAME   "GPIO1"
//#define IOMUXC_GPIO_IR_OUTBAND_TRIGGER IOMUXC_GPIO_AD_B1_08_GPIO1_IO24
#endif

#elif (defined(MIMXRT1176_cm7_SERIES) || defined(MIMXRT1175_cm7_SERIES) || defined(MIMXRT1173_cm7_SERIES) || defined(MIMXRT1172_SERIES) || defined(MIMXRT1171_SERIES)) // For RT1170
#if defined(IW610)
#define IR_OUTBAND_TRIGGER_GPIO   	   	GPIO9
#define IR_OUTBAND_TRIGGER_GPIO_PIN   	(15U)
#define IR_OUTBAND_TRIGGER_GPIO_NAME   "GPIO9"
#else
/* IR OUT-BAND TRIGGER GPIO*/
/*Output GPIO J9 PIN2 (IOMUXC_GPIO_DISP_B2_11) for RT1170-EVKA/B*/
#define IR_OUTBAND_TRIGGER_GPIO   		GPIO5
#define IR_OUTBAND_TRIGGER_GPIO_PIN   	(12U)
#define IR_OUTBAND_TRIGGER_GPIO_NAME  	"GPIO5"
#endif
#elif defined(CPU_MCXN947VDF_cm33_core0) || defined(CPU_MCXN947VPB_cm33_core0) // For FRDM-MCXN947
#if defined(IW610)
/* IR OUT-BAND TRIGGER GPIO */
#define IR_OUTBAND_TRIGGER_GPIO          GPIO1
#define IR_OUTBAND_TRIGGER_GPIO_PIN      (22U)
#define IR_OUTBAND_TRIGGER_GPIO_NAME     "GPIO1"
#endif
#endif /* (defined(CPU_MIMXRT1062DVMAA) || (CPU_MIMXRT1062DVL6A)) */
#endif

#if CONFIG_WIFI_SG_DEBUG
#define wifi_sg_d(...) wmlog("wifi SG", ##__VA_ARGS__)
#else
#define wifi_sg_d(...)
#endif /* ! CONFIG_WIFI_SG_DEBUG */

/* Command port */
#define CMD_PORT_SLCT 0x8000U

#define MLAN_SDIO_BYTE_MODE_MASK 0x80000000U

#define SDIO_CMD_TIMEOUT 2000

extern void handle_cdint(int error);

static sdio_card_t wm_g_sd;
static OSA_MUTEX_HANDLE_DEFINE(sdio_mutex);

int sdio_drv_creg_read(int addr, int fn, uint32_t *resp)
{
    osa_status_t status;
    uint8_t read_val = 0;

    /* CERT INT31-C: Check value before casting from int to uint32_t */
    if (addr < 0)
    {
        sdio_e("invalid address: negative value\r\n");
        return 0;
    }

    status = OSA_MutexLock((osa_mutex_handle_t)sdio_mutex, osaWaitForever_c);
    if (status != KOSA_StatusSuccess)
    {
        sdio_e("failed to get mutex\r\n");
        return 0;
    }

    if (SDIO_IO_Read_Direct(&wm_g_sd, (sdio_func_num_t)fn, (uint32_t)addr, &read_val) != KOSA_StatusSuccess)
    {
        (void)OSA_MutexUnlock((osa_mutex_handle_t)sdio_mutex);
        return 0;
    }

    *resp = read_val;

    (void)OSA_MutexUnlock((osa_mutex_handle_t)sdio_mutex);

    return 1;
}

int sdio_drv_creg_write(int addr, int fn, uint8_t data, uint32_t *resp)
{
    osa_status_t status;

    /* CERT INT31-C: Check value before casting from int to uint32_t */
    if (addr < 0)
    {
        sdio_e("invalid address: negative value\r\n");
        return 0;
    }

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

    /* coverity[cert_int31_c_violation:SUPPRESS] fn is always 0 or 1 per SDIO spec */
    if (SDIO_IO_Read_Extended(&wm_g_sd, (sdio_func_num_t)fn, addr, buf, param, flags) != KOSA_StatusSuccess)
    {
        (void)OSA_MutexUnlock((osa_mutex_handle_t)sdio_mutex);
        return 0;
    }

    (void)OSA_MutexUnlock((osa_mutex_handle_t)sdio_mutex);

    return 1;
}

int sdio_drv_write(uint32_t addr, uint32_t fn, uint32_t bcnt, uint32_t bsize, uint8_t *buf, uint32_t *resp)
{
    osa_status_t status;
    uint32_t flags = 0;
    uint32_t param;
    uint32_t sd_retry = 0;
    uint32_t sd_status = 0;

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

retry:
    /* coverity[cert_int31_c_violation:SUPPRESS] fn is always 0 or 1 per SDIO spec */
    if (SDIO_IO_Write_Extended(&wm_g_sd, (sdio_func_num_t)fn, addr, buf, param, flags) != KOSA_StatusSuccess)
    {
        /* issue abort cmd52 command through Fn0 */
        (void)sdio_drv_creg_write(IO_ABORT, 0, 0x01, &sd_status);
        /* issue terminate CMD53 */
        (void)sdio_drv_creg_write(HOST_TO_CARD_EVENT_REG, 1, HOST_TERM_CMD53, &sd_status);

        if (sd_retry < MAX_WRITE_IOMEM_RETRY)
        {
            sd_retry++;
            goto retry;
        }

        (void)OSA_MutexUnlock((osa_mutex_handle_t)sdio_mutex);
        return false;
    }

    (void)OSA_MutexUnlock((osa_mutex_handle_t)sdio_mutex);

    return 1;
}

#if CONFIG_TX_RX_ZERO_COPY
int sdio_drv_read_sg(uint32_t addr, uint32_t fn, uint32_t bcnt, uint32_t bsize, void *sg_list)
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

    if (SDIO_IO_Read_Extended_Scatter_Gather(&wm_g_sd, (sdio_func_num_t)fn, addr, sg_list, param, flags) != KOSA_StatusSuccess)
    {
        (void)OSA_MutexUnlock((osa_mutex_handle_t)sdio_mutex);
        return 0;
    }

    (void)OSA_MutexUnlock((osa_mutex_handle_t)sdio_mutex);

    return 1;
}

int sdio_drv_write_sg(uint32_t addr, uint32_t fn, uint32_t bcnt, uint32_t bsize, void *sg_list)
{
    osa_status_t status;
    uint32_t flags = 0;
    uint32_t param;
    uint32_t sd_retry = 0;
    uint32_t sd_status = 0;

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

retry:
    if (SDIO_IO_Write_Extended_Scatter_Gather(&wm_g_sd, (sdio_func_num_t)fn, addr, sg_list, param, flags) != KOSA_StatusSuccess)
    {
        /* issue abort cmd52 command through Fn0 */
        (void)sdio_drv_creg_write(IO_ABORT, 0, 0x01, &sd_status);
        /* issue terminate CMD53 */
        (void)sdio_drv_creg_write(HOST_TO_CARD_EVENT_REG, 1, HOST_TERM_CMD53, &sd_status);

        if (sd_retry < MAX_WRITE_IOMEM_RETRY)
        {
            sd_retry++;
            goto retry;
        }

        (void)OSA_MutexUnlock((osa_mutex_handle_t)sdio_mutex);
        return 0;
    }

    (void)OSA_MutexUnlock((osa_mutex_handle_t)sdio_mutex);

    return 1;
}
#endif

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
#if defined(IW610)
    uint32_t data = 0;
    int reg_ret   = 0;
#endif

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

#if !defined(COEX_APP_SUPPORT) || (defined(COEX_APP_SUPPORT) && !(CONFIG_WIFI_IND_DNLD))
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
    (void)sdio_drv_creg_write(0x2, 0, 0x2, &resp);

#if defined(IW610)
    reg_ret = sdio_drv_creg_read(SD_CARD_CTRL3, 0, &data);
    if (reg_ret)
    {
        data &= 0xFFU;
        data |= SD_ONE_BLK_WR_TOKEN_EN;
        (void)sdio_drv_creg_write(SD_CARD_CTRL3, 0, (uint8_t)data, &resp);
    }

    reg_ret = sdio_drv_creg_read(SDIO_CCCR_IF, 0, &data);
    if (reg_ret)
    {
        data &= 0xFFU;
        data |= SDIO_BUS_ECSI;
        (void)sdio_drv_creg_write(SDIO_CCCR_IF, 0, (uint8_t)data, &resp);
    }
#endif

#if defined(SD9177) || defined(SD8978) || defined(IW610)
    (void)SDIO_SetBlockSize(&wm_g_sd, (sdio_func_num_t)0, 1);
#elif defined(SD8801) || defined(SD8987)
    (void)SDIO_SetBlockSize(&wm_g_sd, (sdio_func_num_t)0, 256);
#endif
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

bool sdio_get_enume_status(void)
{
    return ((wm_g_sd.sdioVersion == SDIO_VERSION_2_0) || (wm_g_sd.sdioVersion == SDIO_VERSION_3_0)) &&
           ((wm_g_sd.cccrVersioin == CCCR_VERSION_1_2) || (wm_g_sd.cccrVersioin == CCCR_VERSION_1_3)) &&
           ((wm_g_sd.sdVersion == SD_PHY_VERSION_2_0) || (wm_g_sd.sdVersion == SD_PHY_VERSION_3_0));
}

#if CONFIG_WIFI_IND_RESET
void sdio_oob_reset(void)
{
#ifdef IR_OUTBAND_TRIGGER_GPIO
    GPIO_PinWrite(IR_OUTBAND_TRIGGER_GPIO, IR_OUTBAND_TRIGGER_GPIO_PIN, 0);
    OSA_TimeDelay(10);
    GPIO_PinWrite(IR_OUTBAND_TRIGGER_GPIO, IR_OUTBAND_TRIGGER_GPIO_PIN, 1);
    OSA_TimeDelay(10);
#endif
}

void sdio_oob_init(void)
{
#ifdef IR_OUTBAND_TRIGGER_GPIO
#if defined(CPU_MCXN947VDF_cm33_core0) || defined(CPU_MCXN947VPB_cm33_core0)
    gpio_pin_config_t out_config = {kGPIO_DigitalOutput, 1};
#else
    gpio_pin_config_t out_config = {kGPIO_DigitalOutput, 1, kGPIO_NoIntmode};
#endif
#if defined(IOMUXC_GPIO_IR_OUTBAND_TRIGGER)
    /* GPIO_AD_B0_10 is configured as GPIO1_IO10 */
    IOMUXC_SetPinMux(IOMUXC_GPIO_IR_OUTBAND_TRIGGER, 0U);
#endif
    GPIO_PinInit(IR_OUTBAND_TRIGGER_GPIO, IR_OUTBAND_TRIGGER_GPIO_PIN, &out_config);
#endif
}
#endif /* CONFIG_WIFI_IND_RESET */

#elif defined(__ZEPHYR__)

#include <mlan_sdio_api.h>
#include <osa.h>
#include <fsl_common.h>
#include <fsl_gpio.h>
#include <zephyr/sd/sdio.h>

#define SDIO_CMD_TIMEOUT 2000

const struct device *sdhc_dev = DEVICE_DT_GET(DT_BUS(DT_COMPAT_GET_ANY_STATUS_OKAY(nxp_wifi)));

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
    sdhc_enable_interrupt(sdhc_dev, (sdhc_interrupt_cb_t)sdio_irq_handler, SDHC_INT_SDIO, NULL);
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
