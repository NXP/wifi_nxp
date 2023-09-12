/** @file healthmon.c
 *
 *  @brief  This file provides Core Healthmon definition
 *
 *  Copyright 2008-2023 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 *
 * The Health Monitoring module that queries the health of various
 * entities and keeps strobing the watchdog when all is well.
 */
#include <wm_os.h>
#include <healthmon.h>
#include "fsl_wdog.h"

#include <wmlog.h>
#define hmon_e(...) wmlog_e("hmon", ##__VA_ARGS__)
#define hmon_w(...) wmlog_w("hmon", ##__VA_ARGS__)

#ifdef CONFIG_HEALTHMON_DEBUG
#define hmon_d(...) wmlog("hmon", ##__VA_ARGS__)
#else
#define hmon_d(...)
#endif /* ! CONFIG_HEALTHMON_DEBUG */

#define DEMO_WDOG_BASE       WDOG1
#define DEMO_WDOG_IRQHandler WDOG1_IRQHandler

struct healthmon_privdata
{
    unsigned char is_valid;
    unsigned char failed;
    unsigned int last_check;
};

static struct healthmon_gdata
{
    struct healthmon_handler handlers[MAX_HM_HANDLERS];
    struct healthmon_privdata priv[MAX_HM_HANDLERS];
    void (*final_about_to_die)();
    os_semaphore_t h_sem;
    unsigned int last_strobe;
} hm_gdata;

static os_thread_t healthmon_thread;
static os_thread_stack_define(healthmon_stack, 1024);
static unsigned char healthmon_running;
static unsigned char healthmon_initialized;

void DEMO_WDOG_IRQHandler(void)
{
    WDOG_ClearInterruptStatus(DEMO_WDOG_BASE, kWDOG_InterruptFlag);
    /* User code. User can do urgent case before timeout reset.
     * IE. user can backup the ram data or ram log to flash.
     * the period is set by config.interruptTimeValue, user need to
     * check the period between interrupt and timeout.
     */
}

int healthmon_set_final_about_to_die_handler(void (*fun)())
{
    if (!healthmon_initialized)
        return -WM_E_PERM;
    hm_gdata.final_about_to_die = fun;
    return WM_SUCCESS;
}

void healthmon_display_stat(void)
{
    int i, ret;
    char c_is_sick, c_about_to_die;

    ret = os_semaphore_get(&hm_gdata.h_sem, OS_WAIT_FOREVER);
    if (ret != WM_SUCCESS)
    {
        hmon_e("Error getting h_sem.");
        return;
    }

    for (i = 0; i < MAX_HM_HANDLERS; i++)
    {
        if (!hm_gdata.priv[i].is_valid)
            continue;
        c_is_sick      = hm_gdata.handlers[i].is_sick ? 'Y' : 'N';
        c_about_to_die = hm_gdata.handlers[i].about_to_die ? 'Y' : 'N';
        PRINTF("%s\t%c\t%c\t%d", hm_gdata.handlers[i].name, c_is_sick, c_about_to_die, hm_gdata.priv[i].failed);
    }

    ret = os_semaphore_put(&hm_gdata.h_sem);
    if (ret != WM_SUCCESS)
    {
        hmon_e("Error putting h_sem. ");
        return;
    }

    return;
}

static void call_die_handlers(int failed_module_index)
{
    int i;

    for (i = 0; i < MAX_HM_HANDLERS; i++)
    {
        if (!hm_gdata.priv[i].is_valid)
            continue;
        if (!hm_gdata.handlers[i].about_to_die)
            continue;

        hm_gdata.handlers[i].about_to_die(i == failed_module_index);
    }

    if (hm_gdata.final_about_to_die != NULL)
        hm_gdata.final_about_to_die();

    return;
}

static void healthmon_loop(os_thread_arg_t data)
{
    int ret, i;
    unsigned int cur_msec;
#ifndef CONFIG_SW_WATCHDOG
    wdog_config_t config;
#endif
    int should_probe_wd = 1;

    healthmon_running = 1;

#ifndef CONFIG_SW_WATCHDOG
    /* Watchdog driver init  is required by the healthmon */
    WDOG_GetDefaultConfig(&config);
    config.timeoutValue       = 0x7FU; /* Timeout value is (0x7F + 1)/2 = 64 sec. */
    config.enableInterrupt    = true;
    config.interruptTimeValue = 0x3FU; /* Interrupt occurred (0x4)/2 = 2 sec before WDOG timeout. */

    WDOG_Init(DEMO_WDOG_BASE, &config);
#endif

    while (healthmon_running)
    {
        ret = os_semaphore_get(&hm_gdata.h_sem, OS_WAIT_FOREVER);
        if (ret != WM_SUCCESS)
        {
            hmon_e("Error getting h_sem. ");
            continue;
        }

        for (i = 0; i < MAX_HM_HANDLERS; i++)
        {
            cur_msec = os_ticks_to_msec(os_ticks_get());
            if (!hm_gdata.priv[i].is_valid)
                continue;

            if (cur_msec < hm_gdata.priv[i].last_check + (hm_gdata.handlers[i].check_interval * 1000))
                continue;

            if (hm_gdata.handlers[i].is_sick)
            {
                bool sick                   = (hm_gdata.handlers[i].is_sick)(cur_msec);
                hm_gdata.priv[i].last_check = cur_msec;

                if (sick)
                {
                    hm_gdata.priv[i].failed++;
                }
                else
                {
                    hm_gdata.priv[i].failed = 0;
                }
            }

            if (hm_gdata.priv[i].failed >= hm_gdata.handlers[i].consecutive_failures)
            {
                call_die_handlers(i);
                should_probe_wd = 0;
                break;
            }
        }

        ret = os_semaphore_put(&hm_gdata.h_sem);
        if (ret != WM_SUCCESS)
        {
            hmon_e("Error putting h_sem. ");
            continue;
        }

        if (should_probe_wd)
        {
            if ((hm_gdata.last_strobe + (WD_STROBE_INTERVAL * 1000)) <= cur_msec)
            {
#ifndef CONFIG_SW_WATCHDOG
                WDOG_Refresh(DEMO_WDOG_BASE);
#endif
                hm_gdata.last_strobe = cur_msec;
            }
        }
        else
        {
#ifdef CONFIG_SW_WATCHDOG
            WDOG_TriggerSystemSoftwareReset(DEMO_WDOG_BASE);
#else
            break;
#endif
        }

        os_thread_sleep(os_msec_to_ticks(WKUP_INTERVAL * 1000));
    }

    os_thread_self_complete(&healthmon_thread);
}

static int lock_and_find_handler_by_name(const char *name)
{
    int i, ret;

    if (!name)
        return -1;

    ret = os_semaphore_get(&hm_gdata.h_sem, OS_WAIT_FOREVER);
    if (ret != WM_SUCCESS)
    {
        hmon_e("Error getting h_sem. ");
        return -1;
    }

    for (i = 0; i < MAX_HM_HANDLERS; i++)
    {
        if (!hm_gdata.priv[i].is_valid)
        {
            continue;
        }
        if (strncmp(hm_gdata.handlers[i].name, name, HM_NAME_MAX))
        {
            continue;
        }

        return i;
    }

    return -1;
}

static void unlock_handler_list()
{
    int ret;

    ret = os_semaphore_put(&hm_gdata.h_sem);
    if (ret != WM_SUCCESS)
    {
        hmon_e("Error putting h_sem. ");
    }
    return;
}

int healthmon_change_check_interval(const char *name, unsigned int interval)
{
    int index;

    if ((interval < WKUP_INTERVAL) || (interval % WKUP_INTERVAL))
        return -WM_FAIL;

    index = lock_and_find_handler_by_name(name);
    if (index < 0)
    {
        hmon_e("Handler not found ");
        unlock_handler_list();
        return -WM_FAIL;
    }

    hm_gdata.handlers[index].check_interval = interval;

    unlock_handler_list();

    return WM_SUCCESS;
}

int healthmon_unregister_handler(const char *name)
{
    int index;

    index = lock_and_find_handler_by_name(name);
    if (index < 0)
    {
        hmon_e("Handler not found ");
        unlock_handler_list();
        return -WM_FAIL;
    }

    memset(&(hm_gdata.handlers[index]), 0, sizeof(struct healthmon_handler));
    hm_gdata.priv[index].is_valid = 0;

    unlock_handler_list();

    return WM_SUCCESS;
}

int healthmon_register_handler(struct healthmon_handler *handler)
{
    int i, index;

    if (strlen(handler->name) == 0)
        return -WM_FAIL;

    if ((handler->check_interval < WKUP_INTERVAL) || (handler->check_interval % WKUP_INTERVAL) != 0)
    {
        hmon_e(
            "Invalid wakeup interval specified. "
            "Wakeup interval should be multiple of %d "
            "and greater than %d seconds ",
            WKUP_INTERVAL, WKUP_INTERVAL);
        return -WM_FAIL;
    }

    if ((!handler->is_sick) && (!handler->about_to_die))
    {
        hmon_e("No callback registered.");
        return -WM_FAIL;
    }

    index = lock_and_find_handler_by_name(handler->name);
    if (index >= 0)
    {
        hmon_e("Handler already registered");
        unlock_handler_list();
        return -WM_FAIL;
    }

    for (i = 0; i < MAX_HM_HANDLERS; i++)
    {
        if (!hm_gdata.priv[i].is_valid)
        {
            memcpy(&(hm_gdata.handlers[i]), handler, sizeof(struct healthmon_handler));
            hm_gdata.priv[i].is_valid = 1;
            break;
        }
    }

    unlock_handler_list();

    if (i == MAX_HM_HANDLERS)
    {
        hmon_e("Can't register more than %d handlers ", MAX_HM_HANDLERS);
        return -WM_FAIL;
    }

    return WM_SUCCESS;
}

int healthmon_init()
{
    int i, ret;

    if (healthmon_initialized)
        return WM_SUCCESS;

    for (i = 0; i < MAX_HM_HANDLERS; i++)
    {
        memset(&(hm_gdata.handlers[i]), 0, sizeof(struct healthmon_handler));
        hm_gdata.priv[i].is_valid = 0;
        hm_gdata.priv[i].failed   = 0;
    }

    ret = os_semaphore_create(&hm_gdata.h_sem, "healthmon_sem");
    if (ret != WM_SUCCESS)
    {
        hmon_e("Failed to create healthmon semaphore");
        return -WM_FAIL;
    }

    ret = os_thread_create(&healthmon_thread, "healthmon", healthmon_loop, 0, &healthmon_stack, OS_PRIO_4);
    if (ret != WM_SUCCESS)
    {
        (void)os_semaphore_delete(&hm_gdata.h_sem);
        hmon_e("Failed to create healthmon thread");
        return -WM_FAIL;
    }

    healthmon_initialized = 1;
    healthmon_running     = 0;
}
