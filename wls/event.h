#if (CONFIG_WLS_CSI_PROC) || (CONFIG_CSI_PROC)
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

#ifndef _LIBCSI_EVENT_H_
#define _LIBCSI_EVENT_H_

#include    <ctype.h>
#include    <unistd.h>
#include    <stdlib.h>
#include    "wls_structure_defs.h"

/*
#define CUS_EVT_TOD_TOA "EVENT=TOD-TOA"

#define CUS_EVT_MLAN_CSI	            "EVENT=MLAN_CSI"

#define CSI_DUMP_FILE_MAX               1200000 // 1.2MB
*/

/** Length of ethernet address */
#define ETH_ALEN                      6

/** Unsigned long long integer */
typedef unsigned long long t_u64;
typedef unsigned char t_u8;

#define NO_UPDATE 0
#define IIR_UPDATE 1
#define KALMAN_UPDATE 2

#define PI_ALPHA_FACTOR 0.1f
#define KALMAN_N0  0.2f
#define KALMAN_P0 0.5f
#define KALMAN_ALPHA 0.005f

/** Structure for ftm command private data*/
typedef struct _csi_filter_param
 {
	/**peer mac address */
	t_u8 peer_mac[ETH_ALEN];
	/** Number of CSI to process */
	t_u8 num_csi;
	/**CSI bandwidth: 20/40/80 */
  t_u8 packet_bandwidth;
	/**CSI number of Rx: 1/2 */
  t_u8 num_rx;
	/**CSI number of Tx antennas/streams: 1/2/3/4 */
  t_u8 num_tx;
	/**CSI format: legacy/HT/VHT/HE */
  t_u8 packet_format;
	/** Reference Update */
	t_u8 reference_update;
	/** IIR filter coefficient */
	float IIR_alpha;
	/** Kalman filter parameters */
	float kalman_p0;
	float kalman_alpha;
	float kalman_N0;	
	t_u64 kalman_prev_tsf;
 }csi_filter_param_t;
 
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
	 
 } wls_csi_cfg_t, csi_proc_cfg_t;

 /*
int proc_csi_event(event_header * event, unsigned int *resArray);
void proc_csi_event_wls(event_header * event, unsigned int *resArray);


void send_csi_ack(unsigned int *resArray);
*/

#endif /* _LIBCSI_EVENT_H */

#endif /* CONFIG_WLS_CSI_PROC || CONFIG_CSI_PROC */
