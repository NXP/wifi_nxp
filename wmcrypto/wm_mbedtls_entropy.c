/** @file wm_mbedtls_entropy.c
 *
 *  @brief This file ports mbedtls entropy functions on marvell platform
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

#include "wm_mbedtls_entropy.h"

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/platform.h>
#include <mbedtls/entropy_poll.h>

#include <wm_utils.h>
#include <wm_mbedtls_debug.h>

static struct
{
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
} wm_mbedtls_gdata;

static int wm_wrap_entropy_poll(void *data, unsigned char *output, size_t len, size_t *olen)
{
    ((void)data);
    get_random_sequence(output, len);
    *olen = len;
    return 0;
}

mbedtls_ctr_drbg_context *wm_mbedtls_get_ctr_drbg_ctx()
{
    return &wm_mbedtls_gdata.ctr_drbg;
}

int wm_mbedtls_entropy_ctr_drbg_setup()
{
    int ret                          = 0;
    const unsigned char *custom_name = (const unsigned char *)"WMSDK_4.0";
    size_t custom_name_len           = strlen((const char *)custom_name);

    mbedtls_entropy_init(&wm_mbedtls_gdata.entropy);

    mbedtls_entropy_add_source(&wm_mbedtls_gdata.entropy, wm_wrap_entropy_poll, NULL, MBEDTLS_ENTROPY_MIN_PLATFORM,
                               MBEDTLS_ENTROPY_SOURCE_STRONG);

    mbedtls_ctr_drbg_init(&wm_mbedtls_gdata.ctr_drbg);

    if ((ret = mbedtls_ctr_drbg_seed(&wm_mbedtls_gdata.ctr_drbg, mbedtls_entropy_func, &wm_mbedtls_gdata.entropy,
                                     custom_name, custom_name_len)) != 0)
    {
        wm_mbedtls_e(
            "mbedtls_ctr_drbg_seed returned, "
            "ret = -0x%02X",
            -ret);
        return -1;
    }
    return 0;
}
