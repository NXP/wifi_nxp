/** @file wps_os.h
 *
 *  @brief This file contains definition for timer and socket read functions
 *
 *  Copyright 2008-2022 NXP
 *
 *  NXP CONFIDENTIAL
 *  The source code contained or described herein and all documents related to
 *  the source code ("Materials") are owned by NXP, its suppliers and/or its
 *  licensors. Title to the Materials remains with NXP, its suppliers and/or its
 *  licensors. The Materials contain trade secrets and proprietary and
 *  confidential information of NXP, its suppliers and/or its licensors. The
 *  Materials are protected by worldwide copyright and trade secret laws and
 *  treaty provisions. No part of the Materials may be used, copied, reproduced,
 *  modified, published, uploaded, posted, transmitted, distributed, or
 *  disclosed in any way without NXP's prior express written permission.
 *
 *  No license under any patent, copyright, trade secret or other intellectual
 *  property right is granted to or conferred upon you by disclosure or delivery
 *  of the Materials, either expressly, by implication, inducement, estoppel or
 *  otherwise. Any license under such intellectual property rights must be
 *  express and approved by NXP in writing.
 *
 */

#ifndef _WPS_OS_H_
#define _WPS_OS_H_

#include "wps_def.h"
#include "wps_l2.h"

#include "wifi_nxp_wps.h"
#include <wm_os.h>
#include <wm_net.h>

/* Data structure definition for main loop */
struct wps_sock_s
{
    /** socket no */
    int sock;
    /** private data for callback */
    void *callback_data;
    /** handler */
    void (*handler)(int sock, void *sock_ctx);
};

struct wps_timeout_s
{
    /** next pointer */
    struct wps_timeout_s *next;
    /** time */
    struct timeval time;
    /** private data for callback */
    void *callback_data;
    /** timeout handler */
    void (*handler)(void *timeout_ctx);
};

typedef struct wps_loop_s
{
    /** terminate */
    int terminate;
    /** max socket number */
    int max_sock;
    /** read count */
    int reader_count;
    /** read socket */
    struct wps_sock_s *readers;
    /** timeout */
    struct wps_timeout_s *timeout;
} WPS_LOOP_S;

struct wps_thread_t
{
    int initialized;
#ifdef CONFIG_P2P
    os_mutex_t p2p_session;
    os_queue_t peer_event_queue;
    os_queue_t event_queue;
#endif
    os_queue_t cmd_queue;
    os_queue_t data_queue;
#ifdef CONFIG_P2P
    os_queue_pool_t peer_event_queue_data;
    os_queue_pool_t event_queue_data;
#endif
    os_queue_pool_t cmd_queue_data;
    os_queue_pool_t data_queue_data;
    int (*cb)(enum wps_event event, void *data, uint16_t len);
};

#ifndef timer_cmp
#define timer_cmp(a, b) (((a)->tv_sec == (b)->tv_sec) ? ((a)->tv_usec < (b)->tv_usec) : ((a)->tv_sec < (b)->tv_sec))
#endif
#ifndef timersub
#define timersub(a, b, result)                           \
    do                                                   \
    {                                                    \
        (result)->tv_sec  = (a)->tv_sec - (b)->tv_sec;   \
        (result)->tv_usec = (a)->tv_usec - (b)->tv_usec; \
        if ((result)->tv_usec < 0)                       \
        {                                                \
            --(result)->tv_sec;                          \
            (result)->tv_usec += 1000000;                \
        }                                                \
    } while (0)
#endif

/**
 *  @brief Process interface deinit
 *
 *  @param wps_s        A pointer to global WPS structure
 *  @return             None
 */
void wps_intf_deinit(WPS_DATA *wps_s);

/**
 *  @brief Process main loop initialization
 *
 *  @param wps_s    A pointer to global WPS structure
 *  @return         WPS_STATUS_SUCCESS--success, otherwise--fail
 */
int wps_loop_init(WPS_DATA *wps_s);

/**
 *  @brief Process main loop free
 *
 *  @param wps_s        A pointer to global WPS structure
 *  @return             None
 */
void wps_loop_deinit(WPS_DATA *wps_s);

/**
 *  @brief Register the signal handler to Linux kernel
 *
 *  @return         WPS_STATUS_SUCCESS--success, otherwise--fail
 */
int wps_set_signal_handler(void);

/**
 *  @brief Main loop procedure for socket read and timer functions
 *
 *  @return             None
 */
void wps_main_loop_proc(void);

/**
 *  @brief Disable main loop
 *
 *  @return         None
 */
void wps_main_loop_shutdown(void);

/**
 *  @brief Enable main loop
 *
 *  @return         None
 */
void wps_main_loop_enable(void);

/**
 *  @brief Check main loop status
 *
 *  @return         true or false
 */
bool is_wps_main_loop_running(void);
/**
 *  @brief Register a time-out handler to main loop timer function
 *
 *  @param secs             Time-out value in seconds
 *  @param usecs            Time-out value in micro-seconds
 *  @param handler          A function pointer of time-out handler
 *  @param callback_data    Private data for callback
 *  @return         WPS_STATUS_SUCCESS--success, otherwise--fail
 */
int wps_start_timer(unsigned int secs, unsigned int usecs, void (*handler)(void *user_data), void *callback_data);

/**
 *  @brief Cancel time-out handler to main loop timer function
 *
 *  @param handler          Time-out handler to be canceled
 *  @param callback_data    Private data for callback
 *  @return         Number of timer being removed
 */
int wps_cancel_timer(void (*handler)(void *timeout_ctx), void *callback_data);
void wps_peer_event_receive();
#ifdef CONFIG_P2P
void wps_event_receive(WPS_DATA *wps_s, WFD_DATA *pwfd_data);
#endif
#endif /* _WPS_OS_H_ */
