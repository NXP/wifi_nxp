/** @file nxp_miscs.h
 *
 * @brief This file contains WLAN  specific defines etc.
 *
 * Copyright 2008 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */


#ifndef _NXP_MISCS_H
#define _NXP_MISCS_H



#ifdef __cplusplus
extern "C" {
#endif

extern int configure_11n_settings(int, BYTE *, int *, BYTE *);
extern int configure_he_settings(int, BYTE *, int *, BYTE *);



#ifdef __cplusplus
}
#endif

#endif /*_NXP_MISCS_H */
