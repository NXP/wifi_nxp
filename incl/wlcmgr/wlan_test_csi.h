/*  Copyright 2026 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 *
 */

/*! \file wlan_test_csi.h
 *  \brief CSI (Channel State Information) asynchronous processing APIs
 *
 *  This file provides APIs for asynchronous CSI data processing to prevent
 *  blocking of time-sensitive tasks (e.g., IMU, SDIO). The implementation
 *  uses a dedicated processing task and message queue to decouple CSI data
 *  reception from processing.
 *
 */

#ifndef __WLAN_TEST_CSI_H__
#define __WLAN_TEST_CSI_H__

#if CONFIG_CSI

/* Debug configuration - enables statistics tracking and verbose logging */
#ifndef CONFIG_CSI_DEBUG
#define CONFIG_CSI_DEBUG 1
#endif

/** 
 * @brief CSI message structure for queue communication
 *
 * This structure is used to pass CSI data references from the callback
 * (Wi-Fi driver task) to the processing task via message queue.
 */
typedef struct {
    void *data_ptr;      /** Pointer to CSI data buffer */
    t_u16 data_len;      /** Length of CSI data in bytes */
} csi_msg_t;

#if CONFIG_CSI_DEBUG
/** 
 * @brief CSI processing statistics (debug mode only)
 *
 * Tracks CSI data flow and system health metrics for debugging
 * and performance analysis. Only available when CONFIG_CSI_DEBUG is enabled.
 */
typedef struct {
    uint32_t total_packets;        /** Total CSI packets processed */
    uint32_t user_drop_count;      /** Packets dropped due to queue full or fast consume */
    uint32_t enqueue_drop_count;    /** Packets dropped due to enqueue failuer */
    uint32_t wraparound_detected;  /** Number of buffer wraparound events detected */
    uint32_t fast_consume_events;  /** Number of fast consume recovery events */
    uint32_t processing_errors;    /** Processing error count */
    uint32_t max_queue_usage;      /** Peak queue occupancy (max messages) */
} csi_user_stats;
#endif

int csi_data_recv_user(void *buffer, size_t data_len);

int csi_create_process_task(void);

int csi_destroy_process_task(void);

int csi_data_recv_user(void *buffer, size_t data_len);

#endif /* CONFIG_CSI */

#endif /* WLAN_TEST_CSI_H */
