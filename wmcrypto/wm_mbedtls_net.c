/** @file wm_mbedtls_net.c
 *
 *  @brief This file ports mbedtls net related APIs
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

#include <lwip/sockets.h>
#include <wmerrno.h>
#include <wm_mbedtls_debug.h>

#include <mbedtls/ssl.h>

#include "wm_mbedtls_net.h"

/* Read at most 'len' characters */
static int wm_mbedtls_net_recv(void *ctx, unsigned char *buf, size_t len)
{
    int ret;
    int fd = (int)ctx;

    if (fd < 0)
        return MBEDTLS_ERR_NET_INVALID_CONTEXT;

    ret = (int)read(fd, buf, len);

    if (ret < 0)
    {
        if (lwip_fcntl(fd, F_GETFL, 0) != 0)
            return MBEDTLS_ERR_SSL_WANT_READ;

        if (errno == EPIPE || errno == ECONNRESET)
            return MBEDTLS_ERR_NET_CONN_RESET;

        if (errno == EINTR)
            return MBEDTLS_ERR_SSL_WANT_READ;

        return MBEDTLS_ERR_NET_RECV_FAILED;
    }

    return ret;
}

/*
 * Read at most 'len' characters, blocking for at most 'timeout' ms
 */
static int wm_mbedtls_net_recv_timeout(void *ctx, unsigned char *buf, size_t len, uint32_t timeout)
{
    int ret;
    int fd = (int)ctx;

    if (fd < 0)
        return MBEDTLS_ERR_NET_INVALID_CONTEXT;

    /*------------------------------------------------------------
     * Get previous timeout on socket before receive.
     * This value will be used to restore timeout on socket.
     */
    uint32_t previous_timeout = 0;
    socklen_t timeout_len     = sizeof(int);

    if (WM_SUCCESS != getsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &previous_timeout, &timeout_len))
    {
        wm_mbedtls_e("Failed to get previous socket timeout");
        return -WM_FAIL;
    }

    /*------------------------------------------------------------
     * Set timeout on socket before receive
     */
    if (WM_SUCCESS != setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(int)))
    {
        wm_mbedtls_e(
            "Failed to set socket "
            "timeout: %d",
            timeout);
        return -WM_FAIL;
    }
    /*------------------------------------------------------------
     */
    /* This call will not block */
    ret = wm_mbedtls_net_recv(ctx, buf, len);

    /*------------------------------------------------------------
     * Restore previous timeout on socket
     */
    if (WM_SUCCESS != setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &previous_timeout, sizeof(int)))
    {
        wm_mbedtls_e(
            "Failed to restore previous socket "
            "timeout: %d",
            previous_timeout);
        return -WM_FAIL;
    }
    /*------------------------------------------------------------
     */
    return ret;
}

/*
 * Write at most 'len' characters
 */
static int wm_mbedtls_net_send(void *ctx, const unsigned char *buf, size_t len)
{
    int ret;
    int fd = (int)ctx;

    if (fd < 0)
        return MBEDTLS_ERR_NET_INVALID_CONTEXT;

    ret = (int)write(fd, buf, len);

    if (ret < 0)
    {
        if (lwip_fcntl(fd, F_GETFL, 0) != 0)
            return MBEDTLS_ERR_SSL_WANT_WRITE;

        if (errno == EPIPE || errno == ECONNRESET)
            return MBEDTLS_ERR_NET_CONN_RESET;

        if (errno == EINTR)
            return MBEDTLS_ERR_SSL_WANT_WRITE;

        return MBEDTLS_ERR_NET_SEND_FAILED;
    }
    return ret;
}

void wm_mbedtls_set_fd(mbedtls_ssl_context *ssl, int fd)
{
    /* Set:
     *
     * socket file descriptor
     * 'send', 'read', 'recv timeout' functions of lwip network stack
     */
    mbedtls_ssl_set_bio(ssl, (void *)fd, (mbedtls_ssl_send_t *)wm_mbedtls_net_send,
                        (mbedtls_ssl_recv_t *)wm_mbedtls_net_recv,
                        (mbedtls_ssl_recv_timeout_t *)wm_mbedtls_net_recv_timeout);
}
