#ifdef CONFIG_WLS_CSI_PROC
#ifdef APP_GPL_FILE
/** @file wls_radix4Fft.h
 *
 * @brief This file contains header file for fixed-point FFT functions
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
/** @file wls_radix4Fft.h
 *
 * @brief This file contains header file for fixed-point FFT functions
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
/** @file wls_radix4Fft.h
 *
 * @brief This file contains header file for fixed-point FFT functions
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
/** @file wls_radix4Fft.h
 *
 * @brief This file contains header file for fixed-point FFT functions
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
 * DFW header file for fixed-point FFT functions
 ************************************************************************/

#ifndef WLS_RADIX4_FFT
#define WLS_RADIX4_FFT

#include "wls_param_defines.h"

#define INT8  signed char
#define INT16 short
#define INT32 int
#ifdef STA_20_ONLY
#define MAX_FFT_SIZE_256
#define MAX_FFT_SIZE 256
#else
#define MAX_FFT_SIZE_2048
#define MAX_FFT_SIZE 2048
#endif
//#define TWIDDLE_HALF_SIZE
#define TWIDDLE_BIPT 15
//#define BIASED_ROUNDING

// call separate stages
void radix4FftStageOne(INT16 *pSrc, INT16 *pDst, int Nfft);
void radix4FftMainStages(INT16 *pSrc, INT16 *pDst, int Nfft, const INT16 *pCoeff, int lenCoeff);
void radix4FftLastStage(INT16 *pSrc, INT16 *pDst, int Nfft, const INT16 *pCoeff, int lenCoeff);

void radix4IfftStageOne(INT16 *pSrc, INT16 *pDst, int Nfft);
void radix4IfftMainStages(INT16 *pSrc, INT16 *pDst, int Nfft, const INT16 *pCoeff, int lenCoeff);
void radix4IfftLastStage(INT16 *pSrc, INT16 *pDst, int Nfft, const INT16 *pCoeff, int lenCoeff);

// auxiliary function
unsigned int reverse(register unsigned int x);
#ifndef ARM_DS5
int __clz(int x);
#endif

void radix4Fft(INT16 *pSrc, INT16 *pDst, int Nfft, const INT16 *pCoeff, int lenCoeff);
void radix4Fft4in64(unsigned int *loadPtr, unsigned int *fftOutBfr, const INT16 *pCoeff, int lenCoeff);

void radix4Ifft(INT16 *pSrc, INT16 *pDst, int Nfft, const INT16 *pCoeff, int lenCoeff);
void radix4IfftParallel(INT16 *pSrc, INT16 *pDst, int Nfft, const INT16 *pCoeff, int lenCoeff);
void radix4IfftStride(INT16 *pSrc, INT16 *pDst, int Nfft, const INT16 *pCoeff, int lenCoeff);

void radix2Ifft(INT16 *pSrc, int Nfft, const INT16 *pCoeff, int lenCoeff);
void radix2IfftParallel(INT16 *pSrc, int Nfft, const INT16 *pCoeff, int lenCoeff);
void radix2IfftStride(INT16 *pSrc, int Nfft, const INT16 *pCoeff, int lenCoeff);

void radix2FftFlt(float *pBfr, int Nfft, const float *pCoeff, int lenCoeff);
void radix2IfftFlt(float *pBfr, int Nfft, const float *pCoeff, int lenCoeff);

#define MAX_FFT_FLT 64
extern const float twiddleTableFlt[2 * MAX_FFT_FLT];

#ifdef TWIDDLE_HALF_SIZE
extern const INT16 radix4FftTwiddleArr[MAX_FFT_SIZE];
#else
extern const INT16 radix4FftTwiddleArr[2 * MAX_FFT_SIZE];
#endif

#endif

#endif  /* CONFIG_WLS_CSI_PROC */