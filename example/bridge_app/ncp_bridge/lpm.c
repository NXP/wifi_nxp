/*
 * Copyright 2020 NXP
 * All rights reserved.
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifdef CONFIG_HOST_SLEEP
#include "pin_mux.h"
#include "board.h"
#include "lpm.h"
#include "host_sleep.h"
#include "fsl_pm_core.h"
#include "fsl_pm_device.h"
#include "fsl_power.h"
#include "fsl_rtc.h"
#include "wm_os.h"
#include "wlan.h"
#include "cli.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/*******************************************************************************
 * Variables
 ******************************************************************************/
power_init_config_t initCfg = {
    /* VCORE AVDD18 supplied from iBuck on RD board. */
    .iBuck = true,
    /* Keep CAU_SOC_SLP_REF_CLK for LPOSC. */
    .gateCauRefClk = false,
};
#ifdef CONFIG_POWER_MANAGER
/* Global power manager handle */
AT_ALWAYS_ON_DATA(pm_handle_t pm_handle);
AT_ALWAYS_ON_DATA(pm_wakeup_source_t wlanWakeupSource);
AT_ALWAYS_ON_DATA(pm_wakeup_source_t rtcWakeupSource);
extern pm_notify_element_t wlan_notify;
status_t powerManager_BoardNotify(pm_event_type_t eventType, uint8_t powerState, void *data);
AT_ALWAYS_ON_DATA_INIT(pm_notify_element_t board_notify) = {
    .notifyCallback = powerManager_BoardNotify,
    .data           = NULL,
};
#ifdef CONFIG_UART_INTERRUPT
extern bool usart_suspend_flag;
#endif
#endif
extern int wakeup_by;
#ifdef CONFIG_HOST_SLEEP
extern int is_hs_handshake_done;
#endif
extern int bridge_uart_reinit();
extern int bridge_uart_deinit();
extern void usb_device_app_reinit(void);
#ifdef CONFIG_CRC32_HW_ACCELERATE
extern void hw_crc32_init();
#endif
/*******************************************************************************
 * APIs
 ******************************************************************************/
void lpm_pm3_exit_hw_reinit()
{
    BOARD_InitBootPins();
    if (BOARD_IS_XIP())
    {
        BOARD_BootClockLPR();
        CLOCK_InitT3RefClk(kCLOCK_T3MciIrc48m);
        CLOCK_EnableClock(kCLOCK_T3PllMci256mClk);
        CLOCK_EnableClock(kCLOCK_Otp);
        CLOCK_EnableClock(kCLOCK_Els);
        CLOCK_EnableClock(kCLOCK_ElsApb);
        RESET_PeripheralReset(kOTP_RST_SHIFT_RSTn);
        RESET_PeripheralReset(kELS_APB_RST_SHIFT_RSTn);
    }
    else
    {
        BOARD_InitBootClocks();
    }
    BOARD_InitDebugConsole();
#ifdef CONFIG_CRC32_HW_ACCELERATE
    hw_crc32_init();
#endif
#ifdef CONFIG_USB_BRIDGE
    usb_device_app_reinit();
#endif
    usart_suspend_flag = false;
    bridge_uart_reinit();
#ifdef CONFIG_UART_INTERRUPT
    cli_uart_reinit();
#endif
    RTC_Init(RTC);
}

#ifdef CONFIG_POWER_MANAGER
status_t powerManager_BoardNotify(pm_event_type_t eventType, uint8_t powerState, void *data)
{
    if (is_hs_handshake_done != WLAN_HOSTSLEEP_SUCCESS)
        return kStatus_PMPowerStateNotAllowed;
    if (eventType == kPM_EventEnteringSleep)
    {
        if (powerState == PM_LP_STATE_PM3)
        {
            bridge_uart_deinit();
#ifdef CONFIG_UART_INTERRUPT
            cli_uart_deinit();
#endif
            DbgConsole_Deinit();
        }
        else
        {
            /* Do Nothing */
        }
    }
    else if (eventType == kPM_EventExitingSleep)
    {
        if (powerState == PM_LP_STATE_PM3)
        {
            lpm_pm3_exit_hw_reinit();
        }
        else
        {
            /* Do Nothing */
        }
    }
    return kStatus_PMSuccess;
}

void powerManager_StartRtcTimer(uint64_t timeOutUs)
{
    uint32_t currSeconds;

    /* Read the RTC seconds register to get current time in seconds */
    currSeconds = RTC_GetSecondsTimerCount(RTC);
    /* Add alarm seconds to current time */
    currSeconds += (timeOutUs + 999999U) / 1000000U;
    /* Set alarm time in seconds */
    RTC_SetSecondsTimerMatch(RTC, currSeconds);
    PM_EnableWakeupSource(&rtcWakeupSource);
}

void powerManager_StopRtcTimer()
{
    PM_DisableWakeupSource(&rtcWakeupSource);
    RTC_ClearStatusFlags(RTC, kRTC_AlarmFlag);
}

void powerManager_RTC_Init()
{
    DisableIRQ(RTC_IRQn);
    POWER_ClearWakeupStatus(RTC_IRQn);
    POWER_DisableWakeup(RTC_IRQn);
    RTC_Init(RTC);
    /* Enable wakeup in PD mode */
    RTC_EnableAlarmTimerInterruptFromDPD(RTC, true);
    /* Start RTC */
    RTC_ClearStatusFlags(RTC, kRTC_AlarmFlag);
    RTC_StartTimer(RTC);
    /* Register RTC timer callbacks in power manager */
    PM_RegisterTimerController(&pm_handle, powerManager_StartRtcTimer, powerManager_StopRtcTimer, NULL, NULL);
}

void powerManager_Wakeupsource_Init()
{
    memset(&wlanWakeupSource, 0x0, sizeof(pm_wakeup_source_t));
    memset(&rtcWakeupSource, 0x0, sizeof(pm_wakeup_source_t));
    /* Init wakeup sources. Corresponding IRQ numbers act as wsId here. */
    PM_InitWakeupSource(&wlanWakeupSource, WL_MCI_WAKEUP0_IRQn, NULL, true);
    PM_InitWakeupSource(&rtcWakeupSource, RTC_IRQn, NULL, false);
}

void powerManager_Init()
{
    PM_CreateHandle(&pm_handle);
    /* Init and start RTC time counter */
    powerManager_RTC_Init();
    /* Set priority of RTC and PIN1 interrupt */
    NVIC_SetPriority(RTC_IRQn, LPM_RTC_PIN1_PRIORITY);
    NVIC_SetPriority(PIN1_INT_IRQn, LPM_RTC_PIN1_PRIORITY);
    /* Register WLAN notifier */
    PM_RegisterNotify(kPM_NotifyGroup0, &wlan_notify);
    /* Register board notifier */
    PM_RegisterNotify(kPM_NotifyGroup2, &board_notify);
    /* Init WLAN wakeup source */
    powerManager_Wakeupsource_Init();
    PM_EnablePowerManager(true);
    os_setup_idle_function(powerManager_EnterLowPower);
    wakeup_by = 0;
}
#endif

int LPM_Init(void)
{
    uint32_t resetSrc;

    POWER_InitPowerConfig(&initCfg);
    resetSrc = POWER_GetResetCause();
    PRINTF("\r\nMCU wakeup source 0x%x...\r\n", resetSrc);
    /* In case PM3/PM4 wakeup, the wakeup config and status need to be cleared */
    POWER_ClearResetCause(resetSrc);

#ifdef CONFIG_POWER_MANAGER
    powerManager_Init();
#endif

    NVIC_SetPriority(PIN1_INT_IRQn, LPM_RTC_PIN1_PRIORITY);
    return kStatus_PMSuccess;
}
#endif /* CONFIG_HOST_SLEEP */
