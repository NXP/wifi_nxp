/** @file  event.h
  *
  * @brief This handles CSI events
  *
  *
  * Copyright 2024-2025 NXP
  *
  * NXP CONFIDENTIAL
  * The source code contained or described herein and all documents related to
  * the source code (Materials) are owned by NXP, its
  * suppliers and/or its licensors. Title to the Materials remains with NXP,
  * its suppliers and/or its licensors. The Materials contain
  * trade secrets and proprietary and confidential information of NXP, its
  * suppliers and/or its licensors. The Materials are protected by worldwide copyright
  * and trade secret laws and treaty provisions. No part of the Materials may be
  * used, copied, reproduced, modified, published, uploaded, posted,
  * transmitted, distributed, or disclosed in any way without NXP's prior
  * express written permission.
  *
  * No license under any patent, copyright, trade secret or other intellectual
  * property right is granted to or conferred upon you by disclosure or delivery
  * of the Materials, either expressly, by implication, inducement, estoppel or
  * otherwise. Any license under such intellectual property rights must be
  * express and approved by NXP in writing.
  *
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