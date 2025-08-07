/*
 *  Copyright 2025 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 *
 */

/*! \file event.h
 * \brief This file provides essential macro definitions and data structures for processing CSI event data.
 */

#ifndef _LIB_CSI_EVENT_H_
#define _LIB_CSI_EVENT_H_

#include    <ctype.h>
#include    <stdlib.h>
#include    "wls_structure_defs.h"

#define PI_ALPHA_FACTOR 0.1f
#define KALMAN_N0  0.2f
#define KALMAN_P0 0.5f
#define KALMAN_ALPHA 0.005f
 
/** Structure for CSI config data*/
typedef struct wls_csi_cfg
 {
	 /** Channel number for FTM session*/
	 t_u8 channel;
	 /** Indicate CSI filter was set in conf file */
	 t_u8 csiFilterSet;
     /** Indicate whether start to caculate Ambient Motion Index.
     * 0 - stop. 1 - start */
	 t_u8 start;
	 /**CSI processing config*/
	 hal_wls_processing_input_params_t wls_processing_input;
	 /**CSI filter parameters*/
	 csi_filter_param_t gcsi_filter_param;
 } wls_csi_cfg_t, ami_cfg_t;

#endif /* _LIB_CSI_EVENT_H */