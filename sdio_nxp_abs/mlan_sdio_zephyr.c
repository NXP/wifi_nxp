/** @file mlan_sdio.c
 *
 *  @brief This file provides mlan driver for SDIO
 *
 *  Copyright 2008-2023 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 *
 */

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

static os_mutex_t sdio_mutex;

int sdio_drv_creg_read(int addr, int fn, uint32_t *resp)
{
    int ret;

    ret = os_mutex_get(&sdio_mutex, OS_WAIT_FOREVER);
    if (ret == -WM_FAIL)
    {
        sdio_e("failed to get mutex\r\n");
        return 0;
    }

    struct sdio_func *func = &g_sdio_funcs[fn];

    if (sdio_read_byte(func, addr, (uint8_t *)resp) != 0)
    {
        (void)os_mutex_put(&sdio_mutex);
        return 0;
    }

    (void)os_mutex_put(&sdio_mutex);

    return 1;
}

int sdio_drv_creg_write(int addr, int fn, uint8_t data, uint32_t *resp)
{
    int ret;

    ret = os_mutex_get(&sdio_mutex, OS_WAIT_FOREVER);
    if (ret == -WM_FAIL)
    {
        sdio_e("failed to get mutex\r\n");
        return 0;
    }

    struct sdio_func *func = &g_sdio_funcs[fn];

    if (sdio_rw_byte(func, addr, data, (uint8_t *)resp) != 0)
    {
        (void)os_mutex_put(&sdio_mutex);
        return 0;
    }

    (void)os_mutex_put(&sdio_mutex);

    return 1;
}

int sdio_drv_read(uint32_t addr, uint32_t fn, uint32_t bcnt, uint32_t bsize, uint8_t *buf, uint32_t *resp)
{
    int ret;

    ret = os_mutex_get(&sdio_mutex, OS_WAIT_FOREVER);
    if (ret == -WM_FAIL)
    {
        sdio_e("failed to get mutex\r\n");
        return 0;
    }

    struct sdio_func *func = &g_sdio_funcs[fn];

    if (sdio_read_addr(func, addr, buf, bcnt * bsize) != 0)
    {
        (void)os_mutex_put(&sdio_mutex);
        return 0;
    }

    (void)os_mutex_put(&sdio_mutex);

    return 1;
}

int sdio_drv_write(uint32_t addr, uint32_t fn, uint32_t bcnt, uint32_t bsize, uint8_t *buf, uint32_t *resp)
{
    int ret;

    ret = os_mutex_get(&sdio_mutex, OS_WAIT_FOREVER);
    if (ret == -WM_FAIL)
    {
        sdio_e("failed to get mutex\r\n");
        return 0;
    }

    struct sdio_func *func = &g_sdio_funcs[fn];

    if (sdio_write_addr(func, addr, buf, bcnt * bsize) != 0)
    {
        (void)os_mutex_put(&sdio_mutex);
        return 0;
    }

    (void)os_mutex_put(&sdio_mutex);

    return 1;
}

void BOARD_WIFI_BT_Enable(bool enable)
{
    if (enable)
    {
        /* Enable module */
        /* Enable power supply for SD */
        GPIO_PinWrite(GPIO1, 5U, 1);
    }
    else
    {
        /* Disable module */
        /* Disable power supply for SD */
        GPIO_PinWrite(GPIO1, 5U, 0);
    }
    k_msleep(100);
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

    sdio_enable_interrupt();
}

static int sdio_card_init(void)
{
    int ret = WM_SUCCESS;
    uint32_t resp;

    BOARD_WIFI_BT_Enable(true);

    if (!device_is_ready(sdhc_dev)) {
        sdio_e("SD controller not ready");
	return -EIO;
    }

    if (!sdhc_card_present(sdhc_dev)) {
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
    int ret;

    ret = os_mutex_create(&sdio_mutex, "sdio-mutex", OS_MUTEX_INHERIT);
    if (ret == -WM_FAIL)
    {
        sdio_e("Failed to create mutex\r\n");
        return -WM_FAIL;
    }
    BOARD_WIFI_BT_Enable(false);

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
    int ret;

    // SDIO_Deinit(&wm_g_sd);

    ret = os_mutex_delete(&sdio_mutex);
    if (ret != WM_SUCCESS)
    {
        sdio_e("Failed to delete mutex");
    }
}
