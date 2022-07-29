/** @file mlan_sdio.h
 *
 *  @brief This file contains definitions for SDIO interface.
 *
 *  Copyright 2008-2022 NXP
 *
 *  Licensed under the LA_OPT_NXP_Software_License.txt (the "Agreement")
 *
 */
/****************************************************
Change log:
****************************************************/

#ifndef _MLAN_SDIO_H
#define _MLAN_SDIO_H

#include "mlan_sdio_defs.h"

/** Event header Len*/
#define MLAN_EVENT_HEADER_LEN 8

/** SDIO byte mode size */
#define MAX_BYTE_MODE_SIZE 512

/** The base address for packet with multiple ports aggregation */
#define SDIO_MPA_ADDR_BASE 0x1000U

#ifdef SDIO_MULTI_PORT_TX_AGGR

/** SDIO Tx aggregation in progress ? */
#define MP_TX_AGGR_IN_PROGRESS(a) (a->mpa_tx.pkt_cnt > 0)

/** SDIO Tx aggregation buffer room for next packet ? */
#define MP_TX_AGGR_BUF_HAS_ROOM(a, mbuf, len) ((a->mpa_tx.buf_len + len) <= a->mpa_tx.buf_size)

/** Copy current packet (SDIO Tx aggregation buffer) to SDIO buffer */
#define MP_TX_AGGR_BUF_PUT(a, mbuf, port)                                                     \
    do                                                                                        \
    {                                                                                         \
        pmadapter->callbacks.moal_memmove(a->pmoal_handle, &a->mpa_tx.buf[a->mpa_tx.buf_len], \
                                          mbuf->pbuf + mbuf->data_offset, mbuf->data_len);    \
        a->mpa_tx.buf_len += mbuf->data_len;                                                  \
        if (!a->mpa_tx.pkt_cnt)                                                               \
        {                                                                                     \
            a->mpa_tx.start_port = port;                                                      \
        }                                                                                     \
        if (a->mpa_tx.start_port <= port)                                                     \
        {                                                                                     \
            a->mpa_tx.ports |= (1 << (a->mpa_tx.pkt_cnt));                                    \
        }                                                                                     \
        else                                                                                  \
        {                                                                                     \
            a->mpa_tx.ports |= (1 << (a->mpa_tx.pkt_cnt + 1 + (MAX_PORT - a->mp_end_port)));  \
        }                                                                                     \
        a->mpa_tx.pkt_cnt++;                                                                  \
    } while (0);

/** SDIO Tx aggregation limit ? */
#define MP_TX_AGGR_PKT_LIMIT_REACHED(a) (a->mpa_tx.pkt_cnt == a->mpa_tx.pkt_aggr_limit)

/** SDIO Tx aggregation port limit ? */
#define MP_TX_AGGR_PORT_LIMIT_REACHED(a)         \
    ((a->curr_wr_port < a->mpa_tx.start_port) && \
     (((MAX_PORT - a->mpa_tx.start_port) + a->curr_wr_port) >= SDIO_MP_AGGR_DEF_PKT_LIMIT))

/** Reset SDIO Tx aggregation buffer parameters */
#define MP_TX_AGGR_BUF_RESET(a)   \
    do                            \
    {                             \
        a->mpa_tx.pkt_cnt    = 0; \
        a->mpa_tx.buf_len    = 0; \
        a->mpa_tx.ports      = 0; \
        a->mpa_tx.start_port = 0; \
    } while (0);

#endif /* SDIO_MULTI_PORT_TX_AGGR */

#ifdef SDIO_MULTI_PORT_RX_AGGR_FOR_REF

/** SDIO Rx aggregation limit ? */
#define MP_RX_AGGR_PKT_LIMIT_REACHED(a) (a->mpa_rx.pkt_cnt == a->mpa_rx.pkt_aggr_limit)

/** SDIO Rx aggregation port limit ? */
#define MP_RX_AGGR_PORT_LIMIT_REACHED(a)         \
    ((a->curr_rd_port < a->mpa_rx.start_port) && \
     (((MAX_PORT - a->mpa_rx.start_port) + a->curr_rd_port) >= SDIO_MP_AGGR_DEF_PKT_LIMIT))

/** SDIO Rx aggregation in progress ? */
#define MP_RX_AGGR_IN_PROGRESS(a) (a->mpa_rx.pkt_cnt > 0)

/** SDIO Rx aggregation buffer room for next packet ? */
#define MP_RX_AGGR_BUF_HAS_ROOM(a, rx_len) ((a->mpa_rx.buf_len + rx_len) <= a->mpa_rx.buf_size)

/** Prepare to copy current packet from card to SDIO Rx aggregation buffer */
#define MP_RX_AGGR_SETUP(a, mbuf, port, rx_len)                \
    do                                                         \
    {                                                          \
        a->mpa_rx.buf_len += rx_len;                           \
        if (!a->mpa_rx.pkt_cnt)                                \
        {                                                      \
            a->mpa_rx.start_port = port;                       \
        }                                                      \
        if (a->mpa_rx.start_port <= port)                      \
        {                                                      \
            a->mpa_rx.ports |= (1 << (a->mpa_rx.pkt_cnt));     \
        }                                                      \
        else                                                   \
        {                                                      \
            a->mpa_rx.ports |= (1 << (a->mpa_rx.pkt_cnt + 1)); \
        }                                                      \
        a->mpa_rx.mbuf_arr[a->mpa_rx.pkt_cnt] = mbuf;          \
        a->mpa_rx.len_arr[a->mpa_rx.pkt_cnt]  = rx_len;        \
        a->mpa_rx.pkt_cnt++;                                   \
    } while (0);

/** Reset SDIO Rx aggregation buffer parameters */
#define MP_RX_AGGR_BUF_RESET(a)   \
    do                            \
    {                             \
        a->mpa_rx.pkt_cnt    = 0; \
        a->mpa_rx.buf_len    = 0; \
        a->mpa_rx.ports      = 0; \
        a->mpa_rx.start_port = 0; \
    } while (0);

#endif /* SDIO_MULTI_PORT_RX_AGGR */

#ifndef CONFIG_MLAN_WMSDK
/** Enable host interrupt */
mlan_status wlan_enable_host_int(pmlan_adapter pmadapter);
/** Probe and initialization function */
mlan_status wlan_sdio_probe(pmlan_adapter pmadapter);
/** multi interface download check */
mlan_status wlan_check_winner_status(mlan_adapter *pmadapter, t_u32 *val);
/** Firmware status check */
mlan_status wlan_check_fw_status(mlan_adapter *pmadapter, t_u32 pollnum);
#endif /* CONFIG_MLAN_WMSDK */

/** Read interrupt status */
t_void wlan_interrupt(pmlan_adapter pmadapter);
/** Process Interrupt Status */
/* wmsdk */
/* mlan_status wlan_process_int_status(mlan_adapter * pmadapter); */
/** Transfer data to card */
#ifndef CONFIG_MLAN_WMSDK
mlan_status wlan_sdio_host_to_card(mlan_adapter *pmadapter, t_u8 type, mlan_buffer *mbuf, mlan_tx_param *tx_param);
mlan_status wlan_set_sdio_gpio_int(IN pmlan_private priv);
mlan_status wlan_cmd_sdio_gpio_int(pmlan_private pmpriv,
                                   IN HostCmd_DS_COMMAND *cmd,
                                   IN t_u16 cmd_action,
                                   IN t_void *pdata_buf);
#endif /* CONFIG_MLAN_WMSDK */
#endif /* _MLAN_SDIO_H */
