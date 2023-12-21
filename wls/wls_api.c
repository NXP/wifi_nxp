#ifdef CONFIG_WLS_CSI_PROC
#ifdef APP_GPL_FILE
/** @file wls_api.c
  *
  * @brief This file contains source code for CSI processing API.
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
/** @file wls_api.c
  *
  * @brief This file contains source code for CSI processing API.
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
/** @file wls_api.c
  *
  * @brief This file contains source code for CSI processing API.
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
  * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following
  * disclaimer in the documentation and/or other materials provided with the distribution.
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
/** @file wls_api.c
  *
  * @brief This file contains source code for CSI processing API.
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
* DFW source code for CSI processing API.
************************************************************************/

// Standard includes.
//#include <stdio.h>
//#include <stdlib.h>
#include <string.h>

// Specific includes.
#include "wls_param_defines.h"
#include "wls_structure_defs.h"

#include "wls_radix4Fft.h"
#ifdef ENABLE_AOA
#include "wls_aoa_processing.h"
#endif
#ifdef ARM_DS5
#include "wls_processing_Neon_Intrinsic.h"
#endif

#include "wls_processing.h"
#ifdef FFT_PARALLEL
#include "wls_processing_parallel.h"
#endif
#ifdef ENABLE_SUBSPACE_FTIMING
#include "wls_subspace_processing.h"
#endif

#ifdef DEBUG_OUT_FD
void saveDebug(unsigned int *writePointer, unsigned int *readPointer, int size){
	int ii;

	for(ii=0;ii<size;ii++){
		writePointer[ii] = readPointer[ii];
	}
}
#endif

int wls_process_csi(
	unsigned int *bufferMemory,						// CSI buffer
	unsigned int *fftBuffer,						// 2k times (MAX_RX*MAX_TX+1) scratch memory
	hal_wls_packet_params_t *packetparams,			// values from Rx/Tx-Info, used mostly to find correct CSI buffer
	hal_wls_processing_input_params_t *inputVals,	// WLS / AoA CSI Processing Parameters Structure
	unsigned int *resArray)							// outputs � phase roll, first path, pktinfo, difference of rxInfo CSI TSF counters
{													// weight1, weight2, angle, delay (16 bits each) for AoA processing per Peak

	int csiDataSize;
	int fftSize, ifftSizeOsf, firstPathDelay, maxIdx;
	unsigned int maxVal;
	unsigned int *fftInBuffer, *pdpOut;
	unsigned int powerPerSubband[4 * MAX_RX*MAX_TX]; // max num. of 40 MHz subbands
	unsigned int totalpower[MAX_RX*MAX_TX + 1];
	int phaseRollNg[MAX_RX*MAX_TX];
	unsigned int headerBuffer[HEADER_LEN];


	int header_length, start_csi = 0;
	unsigned int tempVec[2] = { 0,0 };
#ifdef ENABLE_AOA
	hal_cal_struc_t calData;
#endif
	hal_csirxinfo_t *csirxinfo;
	hal_pktinfo_t *pktinfo;

	memcpy(&headerBuffer, bufferMemory, HEADER_LEN*sizeof(unsigned int));

	if(!(inputVals->enableCsi)){
		return -1;
	}

#if defined(DEBUG_CYCLE_TIME)
    DEBUG_DELTA_TIME_US1 = ((UINT64)HAL_REGS32(0x8000a604) << 32) + HAL_REGS32(0x8000a600);
#endif

	csirxinfo = (hal_csirxinfo_t*)headerBuffer;

	tempVec[0] = (unsigned int)csirxinfo->pktinfo;
	pktinfo = (hal_pktinfo_t*)tempVec;

	if(pktinfo->packetType<3){ // HT, legacy
		if(pktinfo->packetType==0){ // legacy
			pktinfo->sigBw = pktinfo->rxDevBw;
		}

		if(pktinfo->sigBw){ // bw > 20 MHz
			pktinfo->NgDsfShift = pktinfo->Ng+1;
		}
		else{ // 20 MHz
			pktinfo->NgDsfShift = 0;
		}
	}
	else{ // VHT, HE
		pktinfo->NgDsfShift = 0;
		//pktinfo->Ng = 0; // not used
	}

#ifdef SMAC_BFINFO
	header_length = csirxinfo->header_length;
	csiDataSize = bufferMemory[header_length]-1;
	start_csi = header_length + 1;
#else
	header_length = HEADER_LEN;
	start_csi = header_length;
	if (csirxinfo->ltf) {
		start_csi += bufferMemory[header_length];
	}
	csiDataSize = bufferMemory[start_csi] - 1;
	start_csi++;
#endif

	fftSize = pktinfo->sigBw+IFFT_OSF_SHIFT-pktinfo->NgDsfShift;
	pktinfo->fftSize = (fftSize < MAX_IFFT_SIZE_SHIFT)? fftSize:MAX_IFFT_SIZE_SHIFT;
	pktinfo->scOffset = 0;
	ifftSizeOsf = 1<<(pktinfo->fftSize+6);
#if defined(FFT_INPLACE)
	fftInBuffer = fftBuffer;
#else
	fftInBuffer = fftBuffer + NUM_PARALLEL * ifftSizeOsf;
#endif
	// expand data from 8->16 bit, demodulate pilots for L-LTF, measure power and linear phase
	if (pktinfo->packetType > 2){ // VHT+HE (Ng=1)
#ifdef FFT_PARALLEL
		readHexDataDemodulateProcessVhtHeNg1Parallel(pktinfo, inputVals, bufferMemory + start_csi, csiDataSize, fftInBuffer, powerPerSubband, phaseRollNg, packetparams->chNum);
#else
		readHexDataDemodulateProcessVhtHeNg1(pktinfo, inputVals, bufferMemory + start_csi, csiDataSize, fftInBuffer, powerPerSubband, phaseRollNg, packetparams->chNum);
#endif
		if (pktinfo->sigBw == 3) // 160 MHz only
			detectPhaseJump(pktinfo, inputVals, fftInBuffer, phaseRollNg);
	}
	else { // Legacy, HT, Ng=2/4
#ifdef FFT_PARALLEL
		readHexDataDemodulateProcessParallel(pktinfo, inputVals, bufferMemory + start_csi, csiDataSize, fftInBuffer, powerPerSubband, phaseRollNg, packetparams->chNum);
#else
		readHexDataDemodulateProcess(pktinfo, inputVals, bufferMemory + start_csi, csiDataSize, fftInBuffer, powerPerSubband, phaseRollNg, packetparams->chNum);
#endif
	}
	if (pktinfo->packetType == 0) { // in case of legacy packets, check active subbands  && (packetparams->ftmSignalBW<pktinfo->sigBw)
		findActiveSubbands(pktinfo, powerPerSubband, totalpower, packetparams->chNum, packetparams->ftmSignalBW);
		zeroOutTones(pktinfo, fftInBuffer, ifftSizeOsf);
	}
	else {
		calculateTotalPower(pktinfo, powerPerSubband, totalpower);
	}
#ifndef STA_20_ONLY
	if (((pktinfo->packetType < 4) && (pktinfo->sigBw > 0)) || (pktinfo->rxDevBw == 3) ) { // not for HE and BW > 20 MHz
#if defined(FFT_PARALLEL) && defined(ARM_DS5)
		removeToneRotationIntrinsic(pktinfo, fftInBuffer, ifftSizeOsf);
#elif defined(FFT_PARALLEL) && !defined(ARM_DS5)
		removeToneRotationParallel(pktinfo, fftInBuffer, ifftSizeOsf);
#else
		removeToneRotation(pktinfo, fftInBuffer, ifftSizeOsf);
#endif
	}
	if ((pktinfo->packetType == 0) && (pktinfo->rxDevBw > 0)) { // all legacy except full interpolation for 20in20
		processLegacyPackets(pktinfo, fftInBuffer, ifftSizeOsf, phaseRollNg);
	}
#endif
	if ((pktinfo->packetType >2) || ((pktinfo->packetType == 1) && (pktinfo->Ng == 0)) // add HT20, HT40 case, Ng=2
		|| ((pktinfo->packetType == 0) && (pktinfo->sigBw == 0) && (pktinfo->rxDevBw == 0))) // add Leg20 case, DevBw=0
	{
#if defined(FFT_PARALLEL) && defined(ARM_DS5)
		interpolatePilotsIntrinsic(pktinfo, fftInBuffer, ifftSizeOsf, phaseRollNg, totalpower);
#elif defined(FFT_PARALLEL) && !defined(ARM_DS5)
		interpolatePilotsParallel(pktinfo, fftInBuffer, ifftSizeOsf, phaseRollNg, totalpower);
#else
		interpolatePilots(pktinfo, fftInBuffer, ifftSizeOsf, phaseRollNg, totalpower);
#endif
	}
#if defined(DEBUG_OUT_FD) && !defined(ARM_DS5)
    saveDebug(bufferMemory, fftInBuffer+0*ifftSizeOsf, ifftSizeOsf);
#endif
	// ifft processing
	ifftProcessing(pktinfo, fftInBuffer, fftBuffer, ifftSizeOsf); // ifftSizeOsf might not match pktinfo->sigBw

	// update
	fftSize = (1<<(pktinfo->sigBw+6));
	ifftSizeOsf = 1<<(pktinfo->fftSize+6);
    pktinfo->rsvd1 = 0;

	resArray[2] = (unsigned int)tempVec[0]; // = pktinfo
    resArray[3] = (unsigned int)tempVec[1]; // = pktinfo

#if defined(DEBUG_OUT_TD) && !defined(ARM_DS5)
	saveDebug(bufferMemory+data_length, fftBuffer+0*ifftSizeOsf, NUM_PARALLEL*ifftSizeOsf);
#endif
	// determine first path
	pdpOut = fftBuffer+(MAX_RX*MAX_TX)*ifftSizeOsf; // last buffer

	if(inputVals->useToaMin==1){
		calcPdpAndFirstPathMin(pktinfo, fftBuffer, pdpOut, totalpower, &maxIdx, &maxVal, &firstPathDelay);
	}
	else
	{
#if defined(FFT_PARALLEL) && defined(ARM_DS5)
		calcPdpAndMaxIntrinsic(pktinfo, fftBuffer, pdpOut, totalpower, &maxIdx, &maxVal);
#else
		calcPdpAndMaxParallel(pktinfo, fftBuffer, pdpOut, totalpower, &maxIdx, &maxVal);
#endif
		firstPathDelay = findFirstPath(pktinfo, pdpOut, maxIdx, maxVal, 1);
	}
	if(pktinfo->packetType>2){ // Ng=1 case
		resArray[0] = ((phaseRollNg[0]*fftSize<<2)/5)>>(pktinfo->sigBw);
	}
	else
	{ // Ng=2/4 case
		resArray[0] = ((phaseRollNg[0]*fftSize<<1)/5)>>(pktinfo->sigBw+pktinfo->Ng);
	}
#ifdef ENABLE_SUBSPACE_FTIMING
	{
		int fineTimingRes, retVal = 1;
		if(inputVals->useSubspace==1){
			retVal = calcSubspaceFineTiming(pktinfo, fftBuffer, totalpower, firstPathDelay, &fineTimingRes, pdpOut, packetparams);
		}
		if(retVal){ // error or not uses, use first path
			fineTimingRes = firstPathDelay;
		}
		resArray[1] = ((fineTimingRes<<(14-TOA_FPATH_BIPT))/5)>>(pktinfo->fftSize+pktinfo->NgDsfShift);
	}
#else
	// final format is 32.TOA_FPATH_BIPT in micro seconds
	resArray[1] = ((firstPathDelay<<(14-TOA_FPATH_BIPT))/5)>>(pktinfo->fftSize+pktinfo->NgDsfShift);
#endif
#ifdef ENABLE_AOA
	if(inputVals->enableAoA && pktinfo->nRx){ // at least 2 Rx paths
		readCalDataNew(&calData, packetparams, pktinfo, inputVals);
		resArray[4] = maxVal>>15;
		if(inputVals->useFindAngleDelayPeaks && (pktinfo->nRx>1)){ // at least 3 Rx paths
			findAngleDelayPeaks(pktinfo, packetparams, inputVals, &calData, fftBuffer, pdpOut, totalpower, maxIdx, resArray+4);
		}
		else{
			findAngleLinPhase(pktinfo, packetparams, &calData, fftBuffer, totalpower, firstPathDelay, resArray+5);
		}
	}
	if(inputVals->dumpRawAngle){
		dumpRawComplex(pktinfo,fftBuffer,firstPathDelay,resArray+8);
	}
#endif
#if defined(DEBUG_CYCLE_TIME)
    DEBUG_DELTA_TIME_US2 = ((UINT64)HAL_REGS32(0x8000a604) << 32) + HAL_REGS32(0x8000a600);
    DEBUG_DELTA_TIME_US  = DEBUG_DELTA_TIME_US2 - DEBUG_DELTA_TIME_US1;
#endif

	return 0;
}

#endif  /* CONFIG_WLS_CSI_PROC */