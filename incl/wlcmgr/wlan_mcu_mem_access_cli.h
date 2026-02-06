/*
 *  Copyright 2008-2022, 2024 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 *
 */

/*! \file wlan_mcu_mem_access_cli.h
 * \brief This file provides MCU memory read/write initlization interfaces.
 */



#ifndef _WLAN_MCU_MEM_ACCESS_CLI_H
#define _WLAN_MCU_MEM_ACCESS_CLI_H


#ifdef __cplusplus
extern "C" {
#endif

#endif

#if CONFIG_MCU_MEM_ACCESS

/** Register MCU mem read/write CLI commands
 * This function registers MCU mem read/write CLI commands
 *
 * \note This function gets called by \ref wlan_cli_init().
 *
 * \return WLAN_ERROR_NONE if the CLI commands were registered or
 * \return WLAN_ERROR_ACTION if they were not registered (for example
 *   if this function was called while the CLI commands were already
 *   registered).
 */
int mcu_mem_access_init(void);


#ifdef __cplusplus
}
#endif

#endif /*CONFIG_MCU_MEM_ACCESS */
