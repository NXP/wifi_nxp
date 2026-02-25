/** @file wlan_test_csi.c
 *
 *  @brief This file implements asynchronous CSI (Channel State Information) data
 *  processing to prevent blocking of time-sensitive tasks.
 *
 *  The implementation uses a dedicated processing task and message queue
 *  to decouple CSI data reception from processing.
 *
 *  Architecture:
 *    WiFi Driver Task -> Message Queue -> CSI Processing Task
 *    (fast callback)     (decoupling)     (actual processing)
 *
 *
 *  Copyright 2026 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "osa.h"
#include "wlan.h"
#include "wifi.h"
#include "wlan_tests.h"
#include "wlan_test_csi.h"
#include "wmlog.h"

#if CONFIG_CSI

#define CONFIG_CSI_DEBUG_SUMMARY 20

#define w_csi_e(...) wmlog_e("wifi_csi", ##__VA_ARGS__)
#define w_csi_w(...) wmlog_w("wifi_csi", ##__VA_ARGS__)

#if CONFIG_CSI_DEBUG
#define w_csi_d(...) wmlog("wifi_csi", ##__VA_ARGS__)
#else
#define w_csi_d(...)
#endif

/* Message queue size matches driver buffer size for 1:1 mapping */
#define CSI_MSG_QUEUE_SIZE MAX_CSI_LOCAL_BUF

/** Task definitions */
#define CONFIG_WIFI_CSI_PROCESS_STACK_SIZE (2048)
#define WLAN_CSI_PROCESS_PRI WLAN_TASK_PRI_LOW

static void csi_process_task(void *arg);
static OSA_TASK_HANDLE_DEFINE(csi_process_task_handle);
static OSA_TASK_DEFINE(csi_process_task, WLAN_CSI_PROCESS_PRI, 1, CONFIG_WIFI_CSI_PROCESS_STACK_SIZE, 0);

static OSA_MSGQ_HANDLE_DEFINE(csi_msg_queue, CSI_MSG_QUEUE_SIZE, sizeof(csi_msg_t));

/* Task lifecycle control flag */
static volatile bool csi_task_running = false;

/* Host-side state tracking for wraparound detection */
static uint32_t host_read_wrap_count = 0;  /** Number of times host read index wrapped */
static t_u8 host_last_read_idx = 0;        /** Last processed buffer index */

#if CONFIG_CSI_DEBUG
static csi_user_stats wlan_csi_stat;
#endif

/**
 * @brief Enqueue CSI data for asynchronous processing
 *
 * This function is called from the WiFi driver task context (via callback)
 * when CSI data is received from firmware. It quickly enqueues the data
 * pointer to the message queue and returns, allowing the driver task to
 * continue without blocking.
 *
 * The actual CSI data processing is performed by the dedicated csi_process_task()
 * in a separate task context, preventing blocking of time-sensitive operations
 * (IMU, SDIO) in the WiFi driver task.
 *
 * @param[in] buffer Pointer to CSI data buffer in driver's local buffer
 *                   This pointer must remain valid until processed by csi_process_task()
 * @param[in] data_len Length of CSI data in bytes (typically CSI_LOCAL_BUF_ENTRY_SIZE)
 *
 * @return WM_SUCCESS if data successfully enqueued
 * @return -WM_FAIL if message queue is full (data will be dropped)
 */
int csi_data_recv_user(void *buffer, size_t data_len)
{
    csi_msg_t msg;
    int ret;
    
    /* Construct message with data pointer (not copying data itself) */
    msg.data_ptr = buffer;
    msg.data_len = (t_u16)data_len;
    
    /* Try to enqueue message - non-blocking operation */
    ret = OSA_MsgQPut((osa_msgq_handle_t)csi_msg_queue, &msg);
    if (ret != KOSA_StatusSuccess)
    {
#if CONFIG_CSI_DEBUG
            wlan_csi_stat.enqueue_drop_count++;
#endif
        return -WM_FAIL;
    }
    
#if CONFIG_CSI_DEBUG
    /* Track peak queue usage for performance analysis */
    t_u32 msg_count = OSA_MsgQAvailableMsgs((osa_msgq_handle_t)csi_msg_queue);
    if (msg_count > wlan_csi_stat.max_queue_usage)
    {
        wlan_csi_stat.max_queue_usage = msg_count;
    }
#endif
    
    return WM_SUCCESS;
}

/**
 * @brief Rapidly drain messages from queue to free queue buffer space
 *
 * This internal function is called when buffer wraparound is detected,
 * indicating that the driver buffer is filling faster than the processing
 * task can consume. It quickly drains a specified number of messages from
 * the queue WITHOUT full processing.
 *
 * @param[in] target_count Number of messages to consume from queue
 *
 * @return Number of messages actually consumed (may be less if queue empties)
 *
 */
static int fast_consume_queue(int target_count)
{
    csi_msg_t msg;
    int consumed = 0;

    w_csi_d(" Fast consume: target=%d messages\r\n", target_count);
    
    /** Rapidly consume messages without full processing */
    while (consumed < target_count)
    {
        if (OSA_MsgQGet((osa_msgq_handle_t)csi_msg_queue, &msg, 0) != WM_SUCCESS)
        {
            break;
        }
        
#if CONFIG_CSI_DEBUG
        wlan_csi_stat.user_drop_count++;
#endif
        /** Skip processing, just consume to make room */
        consumed++;
    }
    
#if CONFIG_CSI_DEBUG
    wlan_csi_stat.fast_consume_events++;
    w_csi_d(" Fast consumed %d messages\r\n", consumed);
#endif
    
    return consumed;
}

/**
 * @brief Calculate how far ahead the driver buffer is compared to host processing
 *
 * This function calculates the gap between the driver's current read position
 * and the host's last processed position, accounting for buffer wraparound.
 * This metric indicates how much backlog exists in the system.
 *
 * The calculation handles three cases:
 * 1. Same wrap cycle: Simple subtraction of indices
 * 2. Driver wrapped once ahead: Account for one full buffer cycle
 * 3. Driver wrapped multiple times: Account for multiple buffer cycles
 *
 * @param[in] driver_read_idx Driver's current read index (0 to MAX_CSI_LOCAL_BUF-1)
 * @param[in] host_last_idx   Host's last processed index
 * @param[in] driver_wrap     Driver's wraparound count
 * @param[in] host_wrap       Host's wraparound count
 *
 * @return Number of buffer positions the driver is ahead of host
 *         Value indicates system backlog (higher = more backlog)
 *         Returns 0 if negative wrap difference (should not happen)
 *
 */
static int calculate_driver_ahead(t_u8 driver_read_idx, t_u8 host_last_idx,
                                  uint32_t driver_wrap, uint32_t host_wrap)
{
    int ahead_count = 0;
    int wrap_diff = (int)(driver_wrap - host_wrap);
    
    if (wrap_diff == 0)
    {
        /** Same wrap cycle - simple subtraction */
        ahead_count = (driver_read_idx >= host_last_idx) ? 
                      (driver_read_idx - host_last_idx) : 0;
    }
    else if (wrap_diff >= 1)
    {
        /** Driver wrapped multiple times ahead of host */
        ahead_count = (wrap_diff - 1) * MAX_CSI_LOCAL_BUF +
                      (MAX_CSI_LOCAL_BUF - host_last_idx) + driver_read_idx;
    }
    else
    {
        /** Negative wrap_diff - should not happen */
        ahead_count = 0;
    }

    if (ahead_count > CSI_MSG_QUEUE_SIZE)
    {
        w_csi_d(" Driver ahead: driver_idx=%u, host_idx=%u, "
               "driver_wrap=%u, host_wrap=%u => ahead=%d (capacity=%d)\r\n",
               driver_read_idx, host_last_idx, driver_wrap, host_wrap, 
               ahead_count, CSI_MSG_QUEUE_SIZE);
    }
    
    return ahead_count;
}

/**
 * @brief Detect driver buffer wraparound and trigger recovery if needed
 *
 * This function implements wraparound detection and automatic recovery.
 * It monitors the driver buffer state and takes action when the driver
 * has wrapped around ahead of host processing.
 *
 * Detection:
 * - Calculates driver backlog (how far ahead driver is)
 * - Checks if backlog exceeds available queue space
 *
 * Recovery (if wraparound detected):
 * - Fast consumes excess messages from queue
 * - Frees up space for driver callback to return
 * - Allows driver buffer to advance and accept new data
 *
 * @param[in] driver_wrap_count  Driver's current wraparound count
 * @param[in] driver_read_idx    Driver's current read index
 *
 * @return true  Wraparound detected and recovery performed
 * @return false Normal operation, no wraparound detected
 *
 */
static bool detect_and_recover_wraparound(uint32_t driver_wrap_count, 
                                   t_u8 driver_read_idx)
{
    int driver_ahead = calculate_driver_ahead(driver_read_idx, 
                                              host_last_read_idx,  // Global
                                              driver_wrap_count, 
                                              host_read_wrap_count); // Global
    
    /** Get current queue size */
    t_u32 current_queue_size = OSA_MsgQAvailableMsgs((osa_msgq_handle_t)csi_msg_queue);
    
    /** Calculate available space */
    int queue_available = CSI_MSG_QUEUE_SIZE - current_queue_size;
    
    /** Check if we have enough space */
    if (driver_ahead > queue_available)
    {
        /** Not enough space - make room */
        int excess = driver_ahead - queue_available;

        w_csi_d(" Queue space shortage: driver ahead %d, available %d, "
               "excess %d, current queue size %u\r\n",
               driver_ahead, queue_available, excess, current_queue_size);

        int consume_count = excess;
        if (consume_count > (int)current_queue_size)
        {
            consume_count = current_queue_size;
        }
        
        if (consume_count > 0)
        {
            fast_consume_queue(consume_count);
        }
        
        return true;
    }
    
    return false;
}

/**
 * @brief User-defined CSI data processing callback
 *
 * This function is called by the CSI processing task to handle each CSI data packet.
 * It serves as the application-level processing point where custom CSI analysis,
 * logging, or forwarding can be implemented.
 *
 * Current Implementation:
 * - Prints notification message
 * - Dumps CSI data in hexadecimal format for debugging
 *
 * Customization Examples:
 * Users can modify this function to implement:
 * - Channel estimation and analysis
 * - CSI data filtering or preprocessing  
 * - Data forwarding to external systems or cloud
 * - Real-time signal quality monitoring
 * - Statistical analysis and trending
 *
 * @param[in] buffer    Pointer to CSI data buffer
 * @param[in] data_len  Length of CSI data in bytes
 *
 * @return None
 *
 */
static void csi_user_process(void *buffer, size_t data_len)
{
    PRINTF("CSI user callback: Event CSI data\r\n");
    dump_hex(buffer, data_len);
}

/**
 * @brief Main CSI data processing task
 *
 * This task runs in a separate context from the WiFi driver task,
 * continuously processing CSI data messages from the queue. It implements:
 * - Message queue polling with blocking wait
 * - Wraparound detection and recovery
 * - Host state synchronization
 * - Statistics tracking
 *
 * @param[in] arg Unused (reserved for future use)
 *
 */
static void csi_process_task(void *arg)
{
    csi_msg_t msg;
    int ret;
    
    /** Variables for driver state monitoring */
    t_u8 driver_write_idx, driver_read_idx, driver_valid_cnt;
    uint32_t driver_wrap_count;

    w_csi_d(" Processing task started\r\n");
    
    while (csi_task_running)
    {
        /** Get CSI data from message queue (blocking wait forever) */
        ret = OSA_MsgQGet((osa_msgq_handle_t)csi_msg_queue, &msg, osaWaitForever_c);
        
        if (ret != WM_SUCCESS)
        {
            /** Should not happen with wait forever, but handle gracefully */
            continue;
        }
        
        /** Check for exit signal */
        if (msg.data_ptr == NULL)
        {
            break;
        }
        
        /** Get current driver state (read-only) */
        wifi_get_csi_buff_status(&driver_write_idx, &driver_read_idx, 
                                 &driver_valid_cnt, &driver_wrap_count, NULL);

        /** Check for wraparound condition */
        if (detect_and_recover_wraparound(driver_wrap_count, driver_read_idx))
        {
            host_last_read_idx = driver_read_idx;
            host_read_wrap_count = driver_wrap_count;
            /** Space shortage handled, skip current message */
            continue;
        }

        csi_user_process(msg.data_ptr, msg.data_len);

        t_u8 old_host_idx = host_last_read_idx;
        
        /** Host processed one message, advance index */
        host_last_read_idx = (host_last_read_idx + 1) % CSI_MSG_QUEUE_SIZE;
        
        /** Check if host index wrapped */
        if (host_last_read_idx < old_host_idx)
        {
            /** Host read index wrapped - increment wrap count */
            host_read_wrap_count++;
            w_csi_d(" Host read wrap, count now=%u\r\n", 
                   host_read_wrap_count);
        }

#if CONFIG_CSI_DEBUG
        wlan_csi_stat.total_packets++;
#endif
    }
    
    w_csi_d("\r\n === Final Statistics ===\r\n");
    w_csi_d("  Porcessed packets: %u\r\n", wlan_csi_stat.total_packets);
    w_csi_d("  User drops: %u\r\n", wlan_csi_stat.user_drop_count);
    w_csi_d("  Enqueue drops: %u\r\n", wlan_csi_stat.enqueue_drop_count);
    w_csi_d("  Wraparounds detected: %u\r\n", wlan_csi_stat.wraparound_detected);
    w_csi_d("  Fast consume events: %u\r\n", wlan_csi_stat.fast_consume_events);
    w_csi_d("  Max queue usage: %u/%u\r\n", wlan_csi_stat.max_queue_usage, CSI_MSG_QUEUE_SIZE);
    w_csi_d("===========================\r\n\r\n");
    
    w_csi_d(" Processing task exiting\r\n");
    OSA_TaskDestroy((osa_task_handle_t)csi_process_task_handle);
}


/**
 * @brief Create and start CSI processing task
 *
 * Initializes the complete CSI asynchronous processing subsystem:
 * 1. Creates message queue for callback-to-task communication
 * 2. Initializes host state tracking variables
 * 3. Resets statistics (if CONFIG_CSI_DEBUG enabled)
 * 4. Creates and starts the processing task
 *
 * This function should be called once during CSI feature initialization,
 * before registering the CSI callback with the driver.
 *
 * @return WM_SUCCESS if all initialization successful
 * @return -WM_FAIL if message queue or task creation fails
 *
 */
int csi_create_process_task(void)
{
    int ret;
    
    /** Create message queue */
    ret = OSA_MsgQCreate((osa_msgq_handle_t)csi_msg_queue, 
                        CSI_MSG_QUEUE_SIZE, 
                        sizeof(csi_msg_t));
    if (ret != WM_SUCCESS)
    {
        w_csi_e(" Failed to create message queue\r\n");
        return -WM_FAIL;
    }
    
    /** Initialize state variables */
    host_read_wrap_count = 0;
    host_last_read_idx = 0;
    csi_task_running = true;
    
#if CONFIG_CSI_DEBUG
    memset(&wlan_csi_stat, 0, sizeof(wlan_csi_stat));
#endif
    
    /** Create processing task */
    ret = OSA_TaskCreate((osa_task_handle_t)csi_process_task_handle,
                        OSA_TASK(csi_process_task),
                        NULL);
    if (ret != WM_SUCCESS)
    {
        w_csi_e(" Failed to create processing task\r\n");
        OSA_MsgQDestroy((osa_msgq_handle_t)csi_msg_queue);
        return -WM_FAIL;
    }
    
    w_csi_d(" Processing task created successfully (queue size: %d)\r\n", CSI_MSG_QUEUE_SIZE);
    return WM_SUCCESS;
}

/**
 * @brief Stop and destroy CSI processing task
 *
 * Gracefully shuts down the CSI asynchronous processing subsystem:
 * 1. Sets stop flag (csi_task_running = false)
 * 2. Sends NULL message to wake up and signal task exit
 * 3. Waits for task to complete and self-destruct
 * 4. Destroys message queue
 *
 * This function should be called during CSI feature cleanup, typically
 * before disabling CSI in firmware or before system shutdown.
 *
 * @return WM_SUCCESS on successful cleanup
 *
 */
int csi_destroy_process_task(void)
{
    csi_task_running = false;
    
    /** Send dummy message to wake up task (ensure it can exit) */
    csi_msg_t dummy_msg = {NULL, 0};
    OSA_MsgQPut((osa_msgq_handle_t)csi_msg_queue, &dummy_msg);
    
    OSA_TimeDelay(100);
    
    OSA_MsgQDestroy((osa_msgq_handle_t)csi_msg_queue);
    
    w_csi_d(" Processing task destroyed\r\n");
    
    return WM_SUCCESS;
}

#endif
