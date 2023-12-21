/** @file wm_mbedtls_net.h
 *
 *  @brief This is header file for porting mbedtls net APIs
 *
 *  Copyright 2008-2020 NXP
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

#ifndef WM_MBEDTLS_NET_H
#define WM_MBEDTLS_NET_H

#define MBEDTLS_ERR_NET_SOCKET_FAILED    -0x0042
#define MBEDTLS_ERR_NET_CONNECT_FAILED   -0x0044
#define MBEDTLS_ERR_NET_BIND_FAILED      -0x0046
#define MBEDTLS_ERR_NET_LISTEN_FAILED    -0x0048
#define MBEDTLS_ERR_NET_ACCEPT_FAILED    -0x004A
#define MBEDTLS_ERR_NET_RECV_FAILED      -0x004C
#define MBEDTLS_ERR_NET_SEND_FAILED      -0x004E
#define MBEDTLS_ERR_NET_CONN_RESET       -0x0050
#define MBEDTLS_ERR_NET_UNKNOWN_HOST     -0x0052
#define MBEDTLS_ERR_NET_BUFFER_TOO_SMALL -0x0043
#define MBEDTLS_ERR_NET_INVALID_CONTEXT  -0x0045

#include <mbedtls/ssl.h>

/**
 * \brief			Set socket file descriptor,
 *					network layer send, recv functions
 *					in input SSL context
 *
 * \param ssl		SSL context
 * \param sock_fd	socket file descriptor
 */
void wm_mbedtls_set_fd(mbedtls_ssl_context *ssl, int sock_fd);

#endif /* WM_MBEDTLS_NET_H */
