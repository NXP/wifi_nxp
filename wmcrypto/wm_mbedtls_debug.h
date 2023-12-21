/** @file wm_mbedtls_debug.h
 *
 *  @brief This file ports debug logs of mbedtls on marvell hardware
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

#ifndef WM_MBEDTLS_DEBUG_H
#define WM_MBEDTLS_DEBUG_H

#include <wmlog.h>

#define wm_mbedtls_e(...) wmlog_e("wm_mbedtls", ##__VA_ARGS__)
#define wm_mbedtls_w(...) wmlog_w("wm_mbedtls", ##__VA_ARGS__)

#ifdef CONFIG_WM_MBEDTLS_DEBUG
#define wm_mbedtls_d(...) wmlog("wm_mbedtls", ##__VA_ARGS__)
#else
#define wm_mbedtls_d(...)
#endif /* !CONFIG_WM_MBEDTLS_DEBUG */

#endif /* WM_MBEDTLS_DEBUG_H */
