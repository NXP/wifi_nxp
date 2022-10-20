/** @file fsl_wifi_osa.h
 *
 *  @brief  This file provides functions for sdk osa abstraction layer.
 *
 *  Copyright 2022 NXP
 *
 *  Licensed under the LA_OPT_NXP_Software_License.txt (the "Agreement")
 *
 */

#ifndef _FSL_WIFI_OSA_H_
#define _FSL_WIFI_OSA_H_

#include "fsl_common.h"
#include "fsl_os_abstraction.h"

/*!
 * @addtogroup wifi_osa WIFI OSA
 * @ingroup card
 * @{
 */
/*******************************************************************************
 * Definitions
 ******************************************************************************/
/*!@brief wifi osa mutex */
typedef struct _wifi_osa_mutex
{
    OSA_MUTEX_HANDLE_DEFINE(handle);
} wifi_osa_mutex_t;
/*******************************************************************************
 * API
 ******************************************************************************/
#if defined(__cplusplus)
extern "C" {
#endif

/*!
 * @name wifi osa Function
 * @{
 */

/*!
 * @brief Initialize OSA.
 */
void WIFI_OSAInit(void);

/*!
 * @brief Create a mutex.
 * @param mutexHandle mutex handle.
 * @retval kStatus_Fail or kStatus_Success.
 */
status_t WIFI_OSAMutexCreate(void *mutexHandle);

/*!
 * @brief set event.
 * @param mutexHandle mutex handle.
 * @param millisec The maximum number of milliseconds to wait for the mutex.
 *                 If the mutex is locked, Pass the value osaWaitForever_c will
 *                 wait indefinitely, pass 0 will return KOSA_StatusTimeout
 *                 immediately.
 * @retval kStatus_Fail or kStatus_Success.
 */
status_t WIFI_OSAMutexLock(void *mutexHandle, uint32_t millisec);

/*!
 * @brief Get event flag.
 * @param mutexHandle mutex handle.
 * @retval kStatus_Fail or kStatus_Success.
 */
status_t WIFI_OSAMutexUnlock(void *mutexHandle);

/*!
 * @brief Delete mutex.
 * @param mutexHandle The mutex handle.
 */
status_t WIFI_OSAMutexDestroy(void *mutexHandle);

/*!
 * @brief wifi delay.
 * @param milliseconds time to delay
 */
void WIFI_OSADelay(uint32_t milliseconds);

/*!
 * @brief wifi delay us.
 * @param microseconds time to delay
 * @return actual delayed microseconds
 */
uint32_t WIFI_OSADelayUs(uint32_t microseconds);

/* @} */

#if defined(__cplusplus)
}
#endif
/* @} */
#endif /* _FSL_WIFI_OSA_H_*/
