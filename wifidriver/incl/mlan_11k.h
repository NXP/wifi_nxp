/** @file mlan_11k.h
 *
 *  @brief Interface for the BTM module implemented in mlan_11k.c
 *
 *  Driver interface functions and type declarations for the process RRM data
 *    module implemented in mlan_11k.c.
 *
 *  Copyright 2022-2022 NXP
 *
 *  NXP CONFIDENTIAL
 *  The source code contained or described herein and all documents related to
 *  the source code ("Materials") are owned by NXP, its
 *  suppliers and/or its licensors. Title to the Materials remains with NXP,
 *  its suppliers and/or its licensors. The Materials contain
 *  trade secrets and proprietary and confidential information of NXP, its
 *  suppliers and/or its licensors. The Materials are protected by worldwide
 * copyright and trade secret laws and treaty provisions. No part of the
 * Materials may be used, copied, reproduced, modified, published, uploaded,
 * posted, transmitted, distributed, or disclosed in any way without NXP's prior
 *  express written permission.
 *
 *  No license under any patent, copyright, trade secret or other intellectual
 *  property right is granted to or conferred upon you by disclosure or delivery
 *  of the Materials, either expressly, by implication, inducement, estoppel or
 *  otherwise. Any license under such intellectual property rights must be
 *  express and approved by NXP in writing.
 *
 */

/********************************************************
Change log:
    08/24/2022: initial version
********************************************************/

#ifndef _MLAN_11K_H_
#define _MLAN_11K_H_

#ifdef CONFIG_11K

/** Add RRM Capabilities */
void wlan_dot11k_formatRrmCapabilities(IEEEtypes_RrmEnabledCapabilities_t *pRrmCapIe, t_u16 bcnInterval);
#endif /* CONFIG_11K */

#endif /* !_MLAN_11K_H_ */
