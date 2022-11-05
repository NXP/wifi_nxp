/** @file fwdnld_sdio.c
 *
 *  @brief  This file provides interface abstraction APIs for SDIO
 *
 *  Copyright 2022 NXP
 *
 *  Licensed under the LA_OPT_NXP_Software_License.txt (the "Agreement")
 *
 */
#include <string.h>
#include "fwdnld_intf_abs.h"
#include "fwdnld_sdio.h"
#include "mlan_sdio_defs.h"
#include <mlan_sdio_api.h>
#include "sdio.h"

fwdnld_intf_t sdio_intf_g;
fwdnld_sdio_intf_specific sdio_intf_specific_g;

/*
 * FW dnld blocksize set 0x110 to 0 and 0x111 to 0x01 => 0x100 => 256
 * Note this only applies to the blockmode we use 256 bytes
 * as block because MLAN_SDIO_BLOCK_SIZE = 256
 */
static int32_t wlan_set_fw_dnld_size(void)
{
    uint32_t resp;

    bool rv = sdio_drv_creg_write(FN1_BLOCK_SIZE_0, 0, 0, &resp);
    if (rv == false)
    {
        return FWDNLD_INTF_FAIL;
    }

    rv = sdio_drv_creg_write(FN1_BLOCK_SIZE_1, 0, 1, &resp);
    if (rv == false)
    {
        return FWDNLD_INTF_FAIL;
    }

    return FWDNLD_INTF_SUCCESS;
}

static void wlan_card_fw_status(t_u16 *dat)
{
    uint32_t resp = 0;

    (void)sdio_drv_creg_read(CARD_FW_STATUS0_REG, 1, &resp);
    *dat = (t_u16)(resp & 0xffU);
    (void)sdio_drv_creg_read(CARD_FW_STATUS1_REG, 1, &resp);
    *dat |= (t_u16)((resp & 0xffU) << 8);
}

static bool wlan_card_ready_wait(t_u32 card_poll)
{
    t_u16 dat = 0U;
    t_u32 i   = 0U;

    for (i = 0; i < card_poll; i++)
    {
        (void)wlan_card_fw_status(&dat);
        if (dat == FIRMWARE_READY)
        {
            sdio_io_d("Firmware Ready");
            return true;
        }
        os_thread_sleep(os_msec_to_ticks(5));
    }
    return false;
}

static fwdnld_intf_ret_t sdio_prep_for_fwdnld(fwdnld_intf_t *intf, void *settings)
{
    /* set fw download block size */
    return wlan_set_fw_dnld_size();
}

static fwdnld_intf_ret_t sdio_post_fwdnld_check_conn_ready(fwdnld_intf_t *intf, void *settings)
{
    if (wlan_card_ready_wait(1000) != true)
    {
        sdio_io_e("SDIO - FW Ready Registers not set");
        return FWDNLD_INTF_FAIL;
    }
    else
    {
        sdio_io_d("WLAN FW download Successful");
        return FWDNLD_INTF_SUCCESS;
    }
}

static fwdnld_intf_ret_t sdio_interface_send(fwdnld_intf_t *intf,
                                             const uint8_t *buffer,
                                             uint32_t transfer_len,
                                             uint32_t *len)
{
    uint32_t tx_blocks = 0, txlen = 0, buflen = 0, offset = 0;
    uint32_t outbuf_len;
    uint8_t *loutbuf = NULL;
    uint32_t resp;
    uint32_t tries        = 0, ioport;
    fwdnld_intf_ret_t ret = FWDNLD_INTF_SUCCESS;

    loutbuf    = GET_INTF_OUTBUF(intf);
    outbuf_len = GET_INTF_OUTBUFLEN(intf);
    (void)memset(loutbuf, 0, outbuf_len);
    *len = 0;

    do
    {
        /* Read CARD_STATUS_REG (0X30) FN =1 */
        for (tries = 0; tries < MAX_POLL_TRIES; tries++)
        {
            if (wlan_card_status(DN_LD_CARD_RDY | CARD_IO_READY) == true)
            {
                *len = wlan_card_read_f1_base_regs();
            }
            else
            {
                sdio_io_e("Error in wlan_card_status()");
                break;
            }

            // (void)PRINTF("len %d =>", len);
            if (*len != 0U)
            {
                break;
            }
        }

        if (*len == 0U)
        {
            sdio_io_e("Card timeout %s:%d", __func__, __LINE__);
            return FWDNLD_INTF_FAIL;
        }
        else if (*len > outbuf_len)
        {
            sdio_io_e("FW Download Failure. Invalid len");
            return FWDNLD_INTF_FAIL;
        }
        else
        {
        }

        txlen = *len;

        /* Set blocksize to transfer - checking for last block */
        if (transfer_len < txlen)
        {
            txlen = transfer_len;
            *len  = txlen;
        }

        ioport = GET_INTF_SDIO_IOPORT(intf);
        (void)memcpy((void *)loutbuf, (const void *)(buffer + offset), txlen);
        calculate_sdio_write_params(txlen, (unsigned int *)&tx_blocks, (unsigned int *)&buflen);
        (void)sdio_drv_write(ioport, 1, tx_blocks, buflen, (uint8_t *)loutbuf, &resp);

        if (*len <= transfer_len)
        {
            transfer_len -= *len;
            offset += *len;
        }
        else
        {
            ret = FWDNLD_INTF_FAIL;
            break;
        }
        *len = 0;

    } while (transfer_len > 0);

    return ret;
}

fwdnld_intf_t *sdio_init_interface(void *settings)
{
    int32_t ret;
    ret = sdio_init();
    if (ret != 0)
    {
        return NULL;
    }
    sdio_intf_g.intf_s.fwdnld_intf_send        = sdio_interface_send;
    sdio_intf_g.intf_s.fwdnld_intf_prepare     = sdio_prep_for_fwdnld;
    sdio_intf_g.intf_s.fwdnld_intf_check_ready = sdio_post_fwdnld_check_conn_ready;
    sdio_intf_g.intf_s.outbuf                  = wifi_get_sdio_outbuf(&sdio_intf_g.intf_s.outbuf_len);
    sdio_intf_g.intf_s.intf_specific           = &sdio_intf_specific_g;

    ret = sdio_ioport_init();
    if (ret != 0)
    {
        return NULL;
    }
    sdio_intf_specific_g.ioport = wifi_get_sdio_ioport();
    return &sdio_intf_g;
}
