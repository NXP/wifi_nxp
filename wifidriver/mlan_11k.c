/** @file mlan_11k.c
 *
 *  @brief  This file provides functions for process 11k(RRM) feature
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
#ifdef CONFIG_11K

#include <mlan_api.h>

/********************************************************
                Local Variables
********************************************************/

/********************************************************
                Global Variables
********************************************************/

/********************************************************
                Local Functions
********************************************************/

/********************************************************
                Global functions
********************************************************/
/**
 * @brief This function sets up the RRM Enabled Capabilites IE.
 *
 * @param pRrmCapIe A pointer to Rrm Enabled Capabilities element structure
 * @param bcnInterval Beacon interval
 *
 * @return void
 */
void wlan_dot11k_formatRrmCapabilities(IEEEtypes_RrmEnabledCapabilities_t *pRrmCapIe, t_u16 bcnInterval)
{
    (void)memset((void *)pRrmCapIe, 0x00, sizeof(IEEEtypes_RrmEnabledCapabilities_t));

    pRrmCapIe->LinkMeas       = 1;
    pRrmCapIe->BcnPassiveMeas = 1;
    pRrmCapIe->BcnActiveMeas  = 1;
    pRrmCapIe->BcnTableMeas   = 1;
    pRrmCapIe->TxStreamMeas   = 1;

    pRrmCapIe->OpChanMaxMeas    = 4; /* TBD: copy the result from fw dot11k_getRmMeasMax() */
    pRrmCapIe->NonOpChanMaxMeas = 2; /* TBD: copy the result from fw dot11k_getRmMeasMax() */

    pRrmCapIe->ParallelMeas = 0;
    pRrmCapIe->RepeatMeas   = 0;
}
#endif /* CONFIG_11K */
