#ifdef CONFIG_WLS_CSI_PROC
#ifdef APP_GPL_FILE
/** @file range_kalman.c
 *
 * @brief This file contains Kalman filter for WLS range measurements
 *
 *
 * Copyright 2023 NXP
 *
 * This software file (the File) is distributed by NXP
 * under the terms of the GNU General Public License Version 2, June 1991
 * (the License).  You may use, redistribute and/or modify the File in
 * accordance with the terms and conditions of the License, a copy of which
 * is available by writing to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA or on the
 * worldwide web at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
 *
 * THE FILE IS DISTRIBUTED AS-IS, WITHOUT WARRANTY OF ANY KIND, AND THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE
 * ARE EXPRESSLY DISCLAIMED.  The License provides additional details about
 * this warranty disclaimer.
 *
 */
#elif defined(APACHE)
/** @file range_kalman.c
 *
 * @brief This file contains Kalman filter for WLS range measurements
 *
 *
 * Copyright 2023 NXP
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an ASIS BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
#elif defined(FREE_BSD)
/** @file range_kalman.c
 *
 * @brief This file contains Kalman filter for WLS range measurements
 *
 *
 * Copyright 2023 NXP
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
 * following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
 * disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
 * following disclaimer in the documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
 * products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ASIS AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#else
/** @file range_kalman.c
 *
 * @brief This file contains Kalman filter for WLS range measurements
 *
 *  Usage:
 *
 *
 * Copyright 2023 NXP
 *
 * NXP CONFIDENTIAL
 * The source code contained or described herein and all documents related to
 * the source code (Materials) are owned by NXP, its
 * suppliers and/or its licensors. Title to the Materials remains with NXP,
 * its suppliers and/or its licensors. The Materials contain
 * trade secrets and proprietary and confidential information of NXP, its
 * suppliers and/or its licensors. The Materials are protected by worldwide copyright
 * and trade secret laws and treaty provisions. No part of the Materials may be
 * used, copied, reproduced, modified, published, uploaded, posted,
 * transmitted, distributed, or disclosed in any way without NXP's prior
 * express written permission.
 *
 * No license under any patent, copyright, trade secret or other intellectual
 * property right is granted to or conferred upon you by disclosure or delivery
 * of the Materials, either expressly, by implication, inducement, estoppel or
 * otherwise. Any license under such intellectual property rights must be
 * express and approved by NXP in writing.
 *
 */
#endif

#include "range_kalman.h"
#include "fsl_debug_console.h"
#include <stdio.h>
#include <math.h>

#ifdef RANGE_RUN_FLT
int range_kalman(range_kalman_state *in)
{
    float range_hat, range_rate_hat;
    float nu, S1;
    float R1_11, R1_12, R1_22, W1_1, W1_2;
    float delta_T  = (float)(in->time - in->last_time) / 1000; // now seconds
    float delta_T2 = delta_T * delta_T;
    float delta_T3 = delta_T2 * delta_T;

    // state propagation
    // A = | 1 T |
    //     | 0 1 |
    range_hat      = in->last_range + delta_T * in->last_range_rate;
    range_rate_hat = in->last_range_rate;
    // residual
    nu = in->range_measurement - range_hat; // H = [1; 0]

    // propagated cov = A*R11*A' + Q
    R1_11 = in->R0_11 + delta_T * 2 * in->R0_12 + delta_T2 * in->R0_22;
    R1_12 = in->R0_12 + delta_T * in->R0_22;
    R1_22 = in->R0_22;
    // Q = | T^3/3 T^2/2 | *  drive_var
    //     | T^2/2 T     |
    R1_11 += in->drive_var * delta_T3 / 3;
    R1_12 += in->drive_var * delta_T2 / 2;
    R1_22 += in->drive_var * delta_T;

    // inovation cov S1 = y_err + H*R1*H'
    S1 = in->measurement_var + R1_11;
    // filter gain W1 = (R1*H')/S1
    W1_1 = R1_11 / S1;
    W1_2 = R1_12 / S1;

    // updated covariance R11 = R1 - W1*S1*W1'
    R1_11 -= W1_1 * S1 * W1_1;
    in->R0_11 = (R1_11 > 0) ? R1_11 : 0;
    R1_12 -= W1_1 * S1 * W1_2;
    in->R0_12 = R1_12;
    R1_22 -= W1_2 * S1 * W1_2;
    in->R0_22 = (R1_22 > 0) ? R1_22 : 0;
    // updated state
    range_hat += W1_1 * nu;
    in->last_range = (range_hat > 0) ? range_hat : 0;
    range_rate_hat += W1_2 * nu;
    in->last_range_rate = range_rate_hat;
    in->last_time       = in->time;

    PRINTF("Kalman update R mat: %f m, %f m/s; d-time: %d ms; range rate %f m/s\r\n", (double)sqrtf(in->R0_11),
           (double)sqrtf(in->R0_22), (int)(delta_T * 1000), (double)in->last_range_rate);
    return 0; // no errors
}

void range_kalman_init(range_kalman_state *in,
                       float range,
                       unsigned long long time,
                       float range_drive_var,
                       float range_measurement_var,
                       float range_rate_init)
{
    // initialize state
    in->last_range      = range;
    in->last_range_rate = 0;
    in->last_time       = time;

    in->R0_11 = range_measurement_var;
    in->R0_12 = 0;
    in->R0_22 = range_rate_init;

    // initialize parameters
    in->drive_var       = range_drive_var;
    in->measurement_var = range_measurement_var;
}

#else
int range_kalman(range_kalman_state *in)
{
    int range_hat, range_rate_hat;
    int nu, S1;
    int R1_11, R1_12, R1_22, W1_1, W1_2;
    unsigned int delta_T  = in->time - in->last_time; // format ??
    unsigned int delta_T2 = delta_T * delta_T;
    unsigned int delta_T3 = delta_T2 * delta_T;

    // state propagation
    // A = | 1 T |
    //     | 0 1 |
    range_hat      = in->last_range + delta_T * in->last_range_rate;
    range_rate_hat = in->last_range_rate;
    // residual
    nu = in->range_measurement - range_hat; // H = [1; 0]

    // propagated cov = A*R11*A' + Q
    R1_11 = in->R0_11 + delta_T * 2 * in->R0_12 + delta_T2 * in->R0_22;
    R1_12 = in->R0_12 + delta_T * in->R0_22;
    R1_22 = in->R0_22;
    // Q = | T^3/3 T^2/2 | *  drive_var
    //     | T^2/2 T     |
    R1_11 += in->drive_var * delta_T3 / 3;
    R1_12 += in->drive_var * delta_T2 / 2;
    R1_22 += in->drive_var * delta_T;

    // inovation cov S1 = y_err + H*R1*H'
    S1 = in->measurement_var + R1_11;
    // filter gain W1 = (R1*H')/S1
    W1_1 = R1_11 / S1;
    W1_2 = R1_12 / S1;

    // updated covariance R11 = R1 - W1*S1*W1'
    R1_11 -= W1_1 * S1 * W1_1;
    in->R0_11 = (R1_11 > 0) ? (unsigned short)R1_11 : 0;
    R1_12 -= W1_1 * S1 * W1_2;
    in->R0_12 = R1_12;
    R1_22 -= W1_2 * S1 * W1_2;
    in->R0_22 = (R1_22 > 0) ? (unsigned short)R1_22 : 0;
    // updated state
    range_hat += W1_1 * nu;
    in->last_range = (range_hat > 0) ? (unsigned short)range_hat : 0;
    range_rate_hat += W1_2 * nu;
    in->last_range_rate = (signed short)range_rate_hat;
    in->last_time       = in->time;

    return 0; // no errors
}
#endif

#endif /* CONFIG_WLS_CSI_PROC */
