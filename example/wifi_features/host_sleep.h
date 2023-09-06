/** @file host_sleep.h
 *
 *  @brief Host sleep file
 *
 *  Copyright 2021 NXP
 *  All rights reserved.
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef _HOST_SLEEP_H_
#define _HOST_SLEEP_H_

#include "fsl_adapter_gpio.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/

#define APP_WAKEUP_GPIO           GPIO5
#define APP_WAKEUP_GPIO_PORT      5
#define APP_WAKEUP_GPIO_PIN       12
#define APP_WAKEUP_IRQ            GPIO5_Combined_0_15_IRQn
#define APP_WAKEUP_INTTERUPT_TYPE kHAL_GpioInterruptFallingEdge

/*******************************************************************************
 * Variables
 ******************************************************************************/

#ifdef ENABLE_HOST_SLEEP
void APP_SetWakeupConfig(void);
void CpuModeTransition(void);
#endif

#endif /*_HOST_SLEEP_H_*/
