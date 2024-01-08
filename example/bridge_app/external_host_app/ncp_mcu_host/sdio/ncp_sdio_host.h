/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifdef CONFIG_NCP_SDIO
#ifndef _SDIO_HOST_APP_H_
#define _SDIO_HOST_APP_H_

#include "fsl_common.h"
#include "FreeRTOS.h"
#include "task.h"

/*!
 * @addtogroup SDHOST_APP
 * @{
 */

/*******************************************************************************
 * Public macro
 ******************************************************************************/

/*******************************************************************************
 * Definitions
 ******************************************************************************/
/** status */
typedef enum _status
{
    STATUS_FAILURE = 1,
    STATUS_SUCCESS = 0,
} status;

/*******************************************************************************
 * API
 ******************************************************************************/
/** NCP SDIO host initialization
 *
 * \return 0 on success
 * \return 1 on failure
 */
status ncp_sdhost_init(void);

/** Send data by NCP SDIO host
 *
 * \param[in] Pointer to data.
 * \param[in] Length of data.
 * \return 0 on success
 * \return 1 on failure
 */
status ncp_sdhost_send_data(uint8_t *buf, uint32_t length);

/** Send command by NCP SDIO host
 *
 * \param[in] Pointer to command.
 * \param[in] Length of command.
 * \return 0 on success
 * \return 1 on failure
 */
status ncp_sdhost_send_cmd(uint8_t *buf, uint32_t length);

/*! @} */

#endif /* _SDIO_HOST_APP_H_ */
#endif /* CONFIG_NCP_SDIO */