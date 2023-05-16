#ifdef CONFIG_WLS_CSI_PROC
#ifdef APP_GPL_FILE
/** @file wls_processing.h
 *
 * @brief This file contains header file for CSI processing functions
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
/** @file wls_processing.h
 *
 * @brief This file contains header file for CSI processing functions
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
/** @file wls_processing.h
 *
 * @brief This file contains header file for CSI processing functions
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
/** @file wls_processing.h
 *
 * @brief This file contains header file for CSI processing functions
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

/************************************************************************
 * DFW header file for CSI processing functions
 ************************************************************************/

#ifdef DFW_CSI_PROC
#include "dsp_cmd.h"
#endif
#include "wls_structure_defs.h"

#ifndef WLS_PROCESSING_H
#define WLS_PROCESSING_H

int myAtan2(int valI, int valQ);

int myAsin(int x);

unsigned int mySqrt(int x);

unsigned int mySqrtLut(int x);

void readHexDataDemodulateProcess(hal_pktinfo_t *pktinfo,
                                  hal_wls_processing_input_params_t *inputVals,
                                  unsigned int *dataPtr,
                                  int csiDataSize,
                                  unsigned int *fftInBuffer,
                                  unsigned int *powerPerSubband,
                                  int *phaseRollPtr,
                                  int chNum);
void readHexDataDemodulateProcessParallel(hal_pktinfo_t *pktinfo,
                                          hal_wls_processing_input_params_t *inputVals,
                                          unsigned int *dataPtr,
                                          int csiDataSize,
                                          unsigned int *fftInBfr,
                                          unsigned int *powerPerSubband,
                                          int *phaseRollPtr,
                                          int chNum);

void readHexDataDemodulateProcessVhtHeNg1(hal_pktinfo_t *pktinfo,
                                          hal_wls_processing_input_params_t *inputVals,
                                          unsigned int *dataPtr,
                                          int csiDataSize,
                                          unsigned int *fftInBuffer,
                                          unsigned int *powerPerSubband,
                                          int *phaseRollPtr,
                                          int chNum);
void readHexDataDemodulateProcessVhtHeNg1Parallel(hal_pktinfo_t *pktinfo,
                                                  hal_wls_processing_input_params_t *inputVals,
                                                  unsigned int *dataPtr,
                                                  int csiDataSize,
                                                  unsigned int *fftInBuffer,
                                                  unsigned int *powerPerSubband,
                                                  int *phaseRollPtr,
                                                  int chNum);

void detectPhaseJump(hal_pktinfo_t *pktinfo,
                     hal_wls_processing_input_params_t *inputVals,
                     unsigned int *fftInBfr,
                     int *phaseRollPtr);

void calculateTotalPower(hal_pktinfo_t *pktinfo, unsigned int *powerPerSubband, unsigned int *totalpower);

void processLegacyPackets(hal_pktinfo_t *pktinfo, unsigned int *fftInBuffer, int bufferspacing, int *phaseRollPtr);

void interpolatePilots(
    hal_pktinfo_t *pktinfo, unsigned int *fftInBuffer, int bufferspacing, int *phaseRollPtr, unsigned int *totalpower);
void interpolatePilotsParallel(
    hal_pktinfo_t *pktinfo, unsigned int *fftInBuffer, int bufferspacing, int *phaseRollPtr, unsigned int *totalpower);

void ifftProcessing(hal_pktinfo_t *pktinfo, unsigned int *fftInBuffer, unsigned int *fftOutBuffer, int bufferspacing);

void interpolateBandEdges20(hal_pktinfo_t *pktinfo, unsigned int *fftInBuffer, int phaseRollNg);
void interpolateBandEdges20Parallel(hal_pktinfo_t *pktinfo, unsigned int *fftInBuffer, int *phaseRollPtr);

void interpolateBandEdges40(hal_pktinfo_t *pktinfo, unsigned int *fftInBuffer, int phaseRollNg);
void interpolateBandEdges40Parallel(hal_pktinfo_t *pktinfo, unsigned int *fftInBuffer, int *phaseRollPtr);

void interpolateBandEdges(hal_pktinfo_t *pktinfo, unsigned int *fftInBuffer, int phaseRollNg);
void interpolateBandEdgesParallel(hal_pktinfo_t *pktinfo, unsigned int *fftInBuffer, int *phaseRollPtr);

void interpolatePairValue(unsigned int *valLeft, unsigned int *valRight, int phaseRollNg);
void interpolatePairValueParallel(unsigned int *valLeft, unsigned int *valRight, int *phaseRollPtr);

void findActiveSubbands(
    hal_pktinfo_t *pktinfo, unsigned int *powerPerSubband, unsigned int *totalpower, int chNum, int ftmSignalBW);

void zeroOutTones(hal_pktinfo_t *pktinfo, unsigned int *fftInBuffer, int bufferspacing);

void removeToneRotation(hal_pktinfo_t *pktinfo, unsigned int *fftInBfr, int bufferspacing);
void removeToneRotationParallel(hal_pktinfo_t *pktinfo, unsigned int *fftInBfr, int bufferspacing);

void calcPdpAndFirstPathMin(hal_pktinfo_t *pktinfo,
                            unsigned int *fftOutBuffer,
                            unsigned int *pdpOutBuffer,
                            unsigned int *totalpower,
                            int *idxRes,
                            unsigned int *valRes,
                            int *firstPathDelay);

void calcPdpAndMax(hal_pktinfo_t *pktinfo,
                   unsigned int *fftOutBuffer,
                   unsigned int *pdpOutBuffer,
                   unsigned int *totalpower,
                   int *idxRes,
                   unsigned int *valRes);
void calcPdpAndMaxParallel(hal_pktinfo_t *pktinfo,
                           unsigned int *fftOutBuffer,
                           unsigned int *pdpOutBuffer,
                           unsigned int *totalpower,
                           int *idxRes,
                           unsigned int *valRes);

int findFirstPath(hal_pktinfo_t *pktinfo, unsigned int *pdpOutBuffer, int maxIdx, unsigned int maxVal, int stride);

void dumpRawComplex(hal_pktinfo_t *pktinfo, unsigned int *fftBuffer, int peakIdx, unsigned int *destArray);

#endif

#endif  /* CONFIG_WLS_CSI_PROC */