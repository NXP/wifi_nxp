/*
 *  Copyright 2021-2023 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#ifdef CONFIG_WIFI_FEATURES
/** Register WLAN Features CLI commands.
 *
 *  Register the WLAN Features CLI commands offload and hostwake features.
 *
 *  \note This function can only be called by the application after \ref wlan_init()
 *  called.
 *
 *  \return WM_SUCCESS if the CLI commands were registered or
 *  \return -WM_FAIL if they were not (for example if this function
 *           was called while the CLI commands were already registered).
 */
int wlan_features_cli_init(void);
#endif
