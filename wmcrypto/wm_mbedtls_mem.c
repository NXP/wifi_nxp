/** @file wm_mbedtls_mem.c
 *
 *  @brief This file provides wrappers for dynamic memory management functions
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

#include "wm_mbedtls_mem.h"

#include <mbedtls/platform.h>

#include <wm_os.h>

static void *wmos_wrap_calloc(size_t block_count, size_t block_size)
{
    return os_mem_calloc(block_count * block_size);
}

static void wmos_wrap_free(void *ptr)
{
    os_mem_free(ptr);
}

int wm_mbedtls_set_mem_alloc()
{
    return mbedtls_platform_set_calloc_free(wmos_wrap_calloc, wmos_wrap_free);
}
