/** @file fsl_wifi_osa.h
 *
 *  @brief  This file provides functions for sdk osa abstraction layer.
 *
 *  Copyright 2022 NXP
 *
 *  Licensed under the LA_OPT_NXP_Software_License.txt (the "Agreement")
 *
 */

#include "fsl_wifi_osa.h"

/*******************************************************************************
 * Definitons
 ******************************************************************************/

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Variables
 ******************************************************************************/

/*******************************************************************************
 * Code
 ******************************************************************************/
/*!
 * brief Initialize OSA.
 */
void WIFI_OSAInit(void)
{
    /* Intentional empty */
}

/*!
 * brief Create a mutex.
 * param mutexHandle mutex handle.
 * retval kStatus_Fail or kStatus_Success.
 */
status_t WIFI_OSAMutexCreate(void *mutexHandle)
{
    assert(mutexHandle != NULL);

    (void)OSA_MutexCreate(&((wifi_osa_mutex_t *)mutexHandle)->handle);

    return kStatus_Success;
}

/*!
 * brief set event.
 * param mutexHandle mutex handle.
 * param millisec The maximum number of milliseconds to wait for the mutex.
 *                 If the mutex is locked, Pass the value osaWaitForever_c will
 *                 wait indefinitely, pass 0 will return KOSA_StatusTimeout
 *                 immediately.
 * retval kStatus_Fail or kStatus_Success.
 */
status_t WIFI_OSAMutexLock(void *mutexHandle, uint32_t millisec)
{
    assert(mutexHandle != NULL);

    (void)OSA_MutexLock(&((wifi_osa_mutex_t *)mutexHandle)->handle, millisec);

    return kStatus_Success;
}

/*!
 * brief Get event flag.
 * param mutexHandle mutex handle.
 * retval kStatus_Fail or kStatus_Success.
 */
status_t WIFI_OSAMutexUnlock(void *mutexHandle)
{
    assert(mutexHandle != NULL);

    (void)OSA_MutexUnlock(&((wifi_osa_mutex_t *)mutexHandle)->handle);

    return kStatus_Success;
}

/*!
 * brief Delete mutex.
 * param mutexHandle The mutex handle.
 */
status_t WIFI_OSAMutexDestroy(void *mutexHandle)
{
    assert(mutexHandle != NULL);

    (void)OSA_MutexDestroy(&((wifi_osa_mutex_t *)mutexHandle)->handle);

    return kStatus_Success;
}

/*!
 * brief wifi delay.
 * param milliseconds time to delay
 */
void WIFI_OSADelay(uint32_t milliseconds)
{
    OSA_TimeDelay(milliseconds);
}

/*!
 * brief wifi delay us.
 * param microseconds time to delay
 * return actual delayed microseconds
 */
uint32_t WIFI_OSADelayUs(uint32_t microseconds)
{
    uint32_t milliseconds = microseconds / 1000U + ((microseconds % 1000U) == 0U ? 0U : 1U);
    OSA_TimeDelay(milliseconds);
    return milliseconds * 1000U;
}
