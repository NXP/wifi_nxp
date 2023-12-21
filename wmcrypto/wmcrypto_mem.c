/* @file wmcrypto_mem.c
 *
 *  @brief This file provides crypto  memory routines
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

#include <string.h>
#include <wm_os.h>

#include "wmcrypto.h"
#include "wmcrypto_mem.h"

void *crypto_mem_malloc(size_t size)
{
    if (size == 0)
        return NULL;

    void *buffer_ptr = os_mem_alloc(size);
    if (!buffer_ptr)
    {
        crypto_e("Failed to allocate mem: Size: %d", size);
        return NULL;
    }

    return buffer_ptr;
}

void crypto_mem_free(void *buffer)
{
    os_mem_free(buffer);
}

void *crypto_mem_calloc(size_t nmemb, size_t size)
{
    return crypto_mem_malloc(nmemb * size);
}
