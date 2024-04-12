/****************************************************************************
 *
 * Copyright (c) 2016 Wi-Fi Alliance
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER
 * RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE
 * USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <osa.h>

#if CONFIG_SIGMA_AGENT
#include "wfa_debug.h"
#include "wfa_main.h"
#include "wfa_types.h"
#include "wfa_dut.h"
#include "wfa_sock.h"
#include "wfa_tg.h"

extern tgStream_t *gStreams;
#if 0
extern tgE2EStats_t *e2eStats;
#endif

extern tgWMM_t wmm_thr[];
extern void *wfa_wmm_thread(void *thr_param);

void wfa_dut_init(BYTE **tBuf, BYTE **rBuf, BYTE **paBuf, BYTE **cBuf, struct timeval **timerp)
{
    /* allocate the traffic stream table */
    gStreams = (tgStream_t *)OSA_MemoryAllocate(WFA_MAX_TRAFFIC_STREAMS * sizeof(tgStream_t));
    if (gStreams == NULL)
    {
        DPRINT_ERR(WFA_ERR, "Failed to OSA_MemoryAllocate theStreams\n");
        exit(1);
    }

    /* a buffer used to carry receive and send test traffic */
    *tBuf = (BYTE *)OSA_MemoryAllocate(MAX_UDP_LEN + 1); /* alloc a traffic buffer */
    if (*tBuf == NULL)
    {
        DPRINT_ERR(WFA_ERR, "Failed to OSA_MemoryAllocate traffic buffer\n");
        exit(1);
    }

    /* a buffer used for response of control command */
    *rBuf = (BYTE *)OSA_MemoryAllocate(WFA_RESP_BUF_SZ);
    if (*rBuf == NULL)
    {
        DPRINT_ERR(WFA_ERR, "Failed to OSA_MemoryAllocate response buffer\n");
        exit(1);
    }

    /* timer used in select call */
    *timerp = OSA_MemoryAllocate(sizeof(struct timeval));
    if (*timerp == NULL)
    {
        DPRINT_ERR(WFA_ERR, "Failed to OSA_MemoryAllocate timer val\n");
        exit(1);
    }

    /* control command buf */
    *cBuf = OSA_MemoryAllocate(WFA_BUFF_2K);
    if (*cBuf == NULL)
    {
        DPRINT_ERR(WFA_ERR, "Failed to OSA_MemoryAllocate control command buf\n");
        exit(1);
    }

    /* parameters buff */
    *paBuf = OSA_MemoryAllocate(MAX_PARMS_BUFF);
    if (*paBuf == NULL)
    {
        DPRINT_ERR(WFA_ERR, "Failed to OSA_MemoryAllocate parms value buff\n");
        exit(1);
    }
}
#endif
