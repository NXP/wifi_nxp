/*
 *  Copyright 2023 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef _OSA_FREERTOS_H_
#define _OSA_FREERTOS_H_

#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "semphr.h"
#include "timers.h"
#include "portmacro.h"

#if (defined(configSUPPORT_STATIC_ALLOCATION) && (configSUPPORT_STATIC_ALLOCATION > 0U)) && \
    !((defined(configSUPPORT_DYNAMIC_ALLOCATION) && (configSUPPORT_DYNAMIC_ALLOCATION > 0U)))

#define CONFIG_MEM_POOLS 1

#include <mem_pool_config.h>

#endif

/*** Timer Management ***/
/**
 * OS Timer Activate Options
 */
typedef enum osa_timer_activation
{
    /** Start the timer on creation. */
    OSA_TIMER_AUTO_ACTIVATE,
    /** Do not start the timer on creation. */
    OSA_TIMER_NO_ACTIVATE,
} osa_timer_activate_t;

typedef TimerHandle_t osa_timer_arg_t;
typedef TickType_t osa_timer_tick;

#ifdef CONFIG_HEAP_STAT
/** This function dumps complete statistics
 *  of the heap memory.
 */
void OSA_DumpMemStats(void);
#endif

/**
 * \def os_get_runtime_stats(__buff__)
 *
 * Get ASCII formatted run time statistics
 *
 * Please ensure that your buffer is big enough for the formatted data to
 * fit. Failing to do this may cause memory data corruption.
 */
#define OSA_GetRuntimeStats(__buff__) vTaskGetRunTimeStats(__buff__)

/**
 * \def os_get_task_list(__buff__)
 *
 * Get ASCII formatted task list
 *
 * Please ensure that your buffer is big enough for the formatted data to
 * fit. Failing to do this may cause memory data corruption.
 */

#define OSA_GetTaskList(__buff__) vTaskList(__buff__)

#endif /* ! _OSA_FREERTOS_H_ */
