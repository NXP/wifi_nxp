/** @file firmware_load.c
 *
 *  @brief  This file provides firmware download related API
 *
 *  Copyright 2021-2022 NXP
 *
 *  Licensed under the LA_OPT_NXP_Software_License.txt (the "Agreement")
 *
 */

#include <mlan_sdio_api.h>

#if defined(CONFIG_XZ_DECOMPRESSION)
#include <xz.h>
#include <decompress.h>
#endif /* CONFIG_XZ_DECOMPRESSION */

/* Additional WMSDK header files */
#include "mlan_sdio_defs.h"
#include "type_decls.h"
#include "fsl_sdmmc_common.h"
#include "fsl_sdmmc_host.h"
#include "fsl_common.h"
#include "sdmmc_config.h"
#include "sdio.h"
#include "firmware_dnld.h"

extern t_u32 ioport_g;

static const uint8_t *wlanfw;

/* remove this after mlan integration complete */
enum
{
    FWDNLD_STATUS_FAILURE    = 0xffffffff,
    FWDNLD_STATUS_SUCCESS    = 0,
    FWDNLD_CARD_NOT_DETECTED = 3,
    FWDNLD_STATUS_FW_DNLD_FAILED,
    FWDNLD_STATUS_FW_NOT_DETECTED = 5,
    FWDNLD_STATUS_FW_NOT_READY,
    FWDNLD_STATUS_FW_XZ_FAILED,
    FWDNLD_CARD_CMD_TIMEOUT
};

static void wlan_card_fw_status(t_u16 *dat)
{
    uint32_t resp = 0;

    (void)sdio_drv_creg_read(CARD_FW_STATUS0_REG, 1, &resp);
    *dat = (t_u16)(resp & 0xff);
    (void)sdio_drv_creg_read(CARD_FW_STATUS1_REG, 1, &resp);
    *dat |= (t_u16)((resp & 0xff) << 8);
}

static bool wlan_card_ready_wait(t_u32 card_poll)
{
    t_u16 dat;
    int i;

    for (i = 0; i < card_poll; i++)
    {
        (void)wlan_card_fw_status(&dat);
        if (dat == FIRMWARE_READY)
        {
            fwdnld_io_d("Firmware Ready");
            return true;
        }
        os_thread_sleep(os_msec_to_ticks(5));
    }
    return false;
}

static int32_t wlan_download_normal_fw(enum wlan_fw_storage_type st,
                                       const t_u8 *wlanfw,
                                       t_u32 firmwarelen,
                                       t_u32 ioport)
{
    t_u32 tx_blocks = 0, txlen = 0, buflen = 0;
    t_u16 len    = 0;
    t_u32 offset = 0;
    t_u32 tries  = 0;
    uint32_t resp;
    uint32_t outbuf_len;

    (void)memset(outbuf, 0, SDIO_OUTBUF_LEN);
    (void)wifi_get_sdio_outbuf(&outbuf_len);

    do
    {
        if (offset >= firmwarelen)
        {
            break;
        }

        /* Read CARD_STATUS_REG (0X30) FN =1 */
        for (tries = 0; tries < MAX_POLL_TRIES; tries++)
        {
            if (wlan_card_status(DN_LD_CARD_RDY | CARD_IO_READY) == true)
            {
                len = wlan_card_read_f1_base_regs();
            }
            else
            {
                fwdnld_io_e("Error in wlan_card_status()");
                break;
            }

            // (void)PRINTF("len %d =>", len);
            if (len != 0U)
            {
                break;
            }
        }

        if (!len)
        {
            fwdnld_io_e("Card timeout %s:%d", __func__, __LINE__);
            return FWDNLD_STATUS_FAILURE;
        }
        else if (len > outbuf_len)
        {
            fwdnld_io_e("FW Download Failure. Invalid len");
            return FWDNLD_STATUS_FAILURE;
        }
        else
        { /* Do Nothing */
        }

        txlen = len;

        /* Set blocksize to transfer - checking for last block */
        if ((firmwarelen - offset) < txlen)
        {
            txlen = firmwarelen - offset;
        }

        calculate_sdio_write_params(txlen, &tx_blocks, &buflen);
#if 0
		if (st == WLAN_FW_IN_FLASH)
			flash_drv_read(fl_dev, outbuf, txlen,
				       (t_u32) (wlanfw + offset));
		else
#endif
        if (st == WLAN_FW_IN_RAM)
        {
            (void)memcpy((void *)outbuf, (const void *)(wlanfw + offset), txlen);
        }

        (void)sdio_drv_write(ioport, 1, tx_blocks, buflen, (t_u8 *)outbuf, &resp);
        offset += txlen;

        // (void)PRINTF("  offset %d\r\n", offset);
        len = 0;
    } while (true);

    return FWDNLD_STATUS_SUCCESS;
}

#if defined(CONFIG_XZ_DECOMPRESSION)
int32_t wlan_download_decomp_fw(enum wlan_fw_storage_type st, t_u8 *wlanfw, t_u32 firmwarelen, t_u32 ioport)
{
    t_u32 tx_blocks = 0, txlen = 0, buflen = 0;
    t_u16 len    = 0;
    t_u32 offset = 0;
    t_u32 tries  = 0;
    uint32_t resp;

    (void)memset(outbuf, 0, SDIO_OUTBUF_LEN);

#define SBUF_SIZE 2048
    int ret;
    struct xz_buf stream;
    uint32_t retlen, readlen = 0;
    t_u8 *sbuf = (t_u8 *)os_mem_alloc(SBUF_SIZE);
    if (sbuf == NULL)
    {
        fwdnld_io_e("Allocation failed");
        return FWDNLD_STATUS_FAILURE;
    }

    xz_uncompress_init(&stream, sbuf, outbuf);

    do
    {
        /* Read CARD_STATUS_REG (0X30) FN =1 */
        for (tries = 0; tries < MAX_POLL_TRIES; tries++)
        {
            if (wlan_card_status(DN_LD_CARD_RDY | CARD_IO_READY) == true)
            {
                len = wlan_card_read_f1_base_regs();
            }
            else
            {
                fwdnld_io_e("Error in wlan_card_status()");
                break;
            }

            if (len)
                break;
        }

        if (!len)
        {
            fwdnld_io_e("Card timeout %s:%d", __func__, __LINE__);
            break;
        }
        else if (len > WLAN_UPLD_SIZE)
        {
            fwdnld_io_e("FW Download Failure. Invalid len");
            xz_uncompress_end();
            os_mem_free(sbuf);
            return FWDNLD_STATUS_FW_DNLD_FAILED;
        }

        txlen = len;

        do
        {
            if (stream.in_pos == stream.in_size)
            {
                readlen = MIN(SBUF_SIZE, firmwarelen);
#if 0
				if (st == WLAN_FW_IN_FLASH)
					flash_drv_read(fl_dev, sbuf, readlen,
						(t_u32)(wlanfw + offset));
				else
#endif
                if (st == WLAN_FW_IN_RAM)
                    (void)memcpy((void *)sbuf, (const void *)(wlanfw + offset), readlen);
                offset += readlen;
                firmwarelen -= readlen;
            }
            ret = xz_uncompress_stream(&stream, sbuf, readlen, outbuf, txlen, &retlen);

            if (ret == XZ_STREAM_END)
            {
                txlen = retlen;
                break;
            }
            else if (ret != XZ_OK)
            {
                fwdnld_io_e("Decompression failed:%d", ret);
                break;
            }
        } while (retlen == 0);

        calculate_sdio_write_params(txlen, &tx_blocks, &buflen);

        sdio_drv_write(ioport, 1, tx_blocks, buflen, (t_u8 *)outbuf, &resp);

        if (ret == XZ_STREAM_END)
        {
            fwdnld_io_d("Decompression successful");
            break;
        }
        else if (ret != XZ_OK)
        {
            fwdnld_io_e("Exit:%d", ret);
            break;
        }
        len = 0;
    } while (1);

    xz_uncompress_end();
    os_mem_free(sbuf);

    if (ret == XZ_OK || ret == XZ_STREAM_END)
        return FWDNLD_STATUS_SUCCESS;
    else
        return FWDNLD_STATUS_FW_XZ_FAILED;
}

#endif /* CONFIG_XZ_DECOMPRESSION */

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
        return FWDNLD_STATUS_FAILURE;
    }

    rv = sdio_drv_creg_write(FN1_BLOCK_SIZE_1, 0, 1, &resp);
    if (rv == false)
    {
        return FWDNLD_STATUS_FAILURE;
    }

    return FWDNLD_STATUS_SUCCESS;
}

/*
 * Download firmware to the card through SDIO.
 * The firmware is stored in Flash.
 */
int32_t firmware_download(enum wlan_fw_storage_type st, const uint8_t *fw_ram_start_addr, const size_t size)
{
    t_u32 firmwarelen;
    wlanfw_hdr_type wlanfwhdr;
    int32_t ret;

    /* set fw download block size */
    ret = wlan_set_fw_dnld_size();
    if (ret != FWDNLD_STATUS_SUCCESS)
    {
        return ret;
    }
#if 0
	if (st == WLAN_FW_IN_FLASH) {
		fl_dev = flash_drv_open(fl->fl_dev);
		if (fl_dev == NULL) {
			fwdnld_io_e("Flash drv init is required before open");
			return FWDNLD_STATUS_FW_NOT_DETECTED;
		}
	}

	if (st == WLAN_FW_IN_FLASH)
		wlanfw = (t_u8 *)fl->fl_start;
	else
#endif
    if (st == WLAN_FW_IN_RAM)
    {
        wlanfw = fw_ram_start_addr;
    }

    fwdnld_io_d("Start copying wlan firmware over sdio from 0x%x", (t_u32)wlanfw);

#if 0
	if (st == WLAN_FW_IN_FLASH)
		flash_drv_read(fl_dev, (t_u8 *) &wlanfwhdr, sizeof(wlanfwhdr),
			       (t_u32) wlanfw);
	else
#endif
    if (st == WLAN_FW_IN_RAM)
    {
        (void)memcpy((void *)&wlanfwhdr, (const void *)wlanfw, sizeof(wlanfwhdr));
    }

    //	if (wlanfwhdr.magic_number != WLAN_MAGIC_NUM) {
    //		fwdnld_io_e("WLAN FW not detected in Flash.");
    //		return MLAN_STATUS_FW_NOT_DETECTED;
    //	}

    //	fwdnld_io_d("Valid WLAN FW found in %s flash",
    //			fl->fl_dev ? "external" : "internal");

    /* skip the wlanhdr and move wlanfw to beginning of the firmware */
    //	wlanfw += sizeof(wlanfwhdr);
    firmwarelen = size;

#if defined(CONFIG_XZ_DECOMPRESSION)
    t_u8 buffer[6];
#if 0
	if (st == WLAN_FW_IN_FLASH)
		flash_drv_read(fl_dev, buffer, sizeof(buffer),
						(t_u32) wlanfw);
	else
#endif
    (void)memcpy((void *)buffer, (const void *)wlanfw, sizeof(buffer));

    /* See if image is XZ compressed or not */
    if (verify_xz_header(buffer) == WM_SUCCESS)
    {
        fwdnld_io_d(
            "XZ Compressed image found, start decompression,"
            " len: %d",
            firmwarelen);
        ret = wlan_download_decomp_fw(st, wlanfw, firmwarelen, ioport_g);
    }
    else
#endif /* CONFIG_XZ_DECOMPRESSION */
    {
        fwdnld_io_d(
            "Un-compressed image found, start download,"
            " len: %d",
            firmwarelen);
        ret = wlan_download_normal_fw(st, wlanfw, firmwarelen, ioport_g);
    }
#if 0
	if (st == WLAN_FW_IN_FLASH)
		flash_drv_close(fl_dev);
#endif
    if (ret != FWDNLD_STATUS_SUCCESS)
    {
        return ret;
    }

    if (wlan_card_ready_wait(1000) != true)
    {
        fwdnld_io_e("SDIO - FW Ready Registers not set");
        return FWDNLD_STATUS_FAILURE;
    }
    else
    {
        fwdnld_io_d("WLAN FW download Successful");
        return FWDNLD_STATUS_SUCCESS;
    }
}
