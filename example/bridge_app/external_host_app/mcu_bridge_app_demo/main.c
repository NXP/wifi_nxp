/** @file main.c
 *
 *  @brief main file
 *
 *  Copyright 2023 NXP
 *  All rights reserved.
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 */

///////////////////////////////////////////////////////////////////////////////
//  Includes
///////////////////////////////////////////////////////////////////////////////

// SDK Included Files
#include "board.h"
#include "fsl_debug_console.h"
#include "app.h"
#include "fsl_power.h"
#include "mcu_bridge_os.h"
#include "mcu_bridge_utils.h"
#include "mcu_bridge_cli.h"
#include "mcu_bridge_app.h"
#ifdef CONFIG_USB_BRIDGE
#include "host_cdc_app.h"
#elif defined(CONFIG_SPI_BRIDGE)
#include "spi_master_app.h"
#endif

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/*******************************************************************************
 * Prototypes
 ******************************************************************************/
int wlan_reset_cli_init(void);

/*******************************************************************************
 * Code
 ******************************************************************************/

const int TASK_MAIN_PRIO = OS_PRIO_3;
#ifdef CONFIG_WPS2
const int TASK_MAIN_STACK_SIZE = 1500;
#else
const int TASK_MAIN_STACK_SIZE = 800;
#endif

portSTACK_TYPE *task_main_stack = NULL;
TaskHandle_t task_main_task_handler;

static void printSeparator(void)
{
    PRINTF("========================================\r\n");
}

static void mcu_gpio_init()
{
    /* Define the init structure for the input/output switch pin */
    gpio_pin_config_t gpio_in_config = {
        kGPIO_DigitalInput,
        0,
    };
    gpio_pin_config_t gpio_out_config = {
        kGPIO_DigitalOutput,
        1,
    };

    GPIO_PortInit(GPIO, 0);
    GPIO_PinInit(GPIO, BOARD_SW4_GPIO_PORT, BOARD_SW4_GPIO_PIN, &gpio_in_config);
    /* Init output GPIO */
    GPIO_PinInit(GPIO, 0, 22, &gpio_out_config);
}

void task_main(void *param)
{
    int32_t result = 0;
    (void)result;

    mcu_gpio_init();

    PRINTF("Initialize MCU BRIDGE APP\r\n");
    printSeparator();

    result = mcu_bridge_app_init();

    assert(WM_SUCCESS == result);

    result = mcu_bridge_cli_init();

    assert(WM_SUCCESS == result);
#ifdef CONFIG_USB_BRIDGE
    result = usb_host_init();

    assert(WM_SUCCESS == result);
#endif
    printSeparator();

    while (1)
    {
        /* wait for interface up */
        os_thread_sleep(os_msec_to_ticks(5000));
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
    POWER_PowerOffBle();

    printSeparator();
    PRINTF("MCU bridge APP demo\r\n");
    printSeparator();

    result =
        xTaskCreate(task_main, "main", TASK_MAIN_STACK_SIZE, task_main_stack, TASK_MAIN_PRIO, &task_main_task_handler);
    assert(pdPASS == result);

    vTaskStartScheduler();
    for (;;)
        ;
}
