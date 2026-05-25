/** @file mlan_mgmt_ie.c
 *
 *  @brief  This file provides functions for MGMT IE management
 *
 *  Copyright 2026 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <mlan_api.h>
#include <osa.h>
#if defined(RW610)
#include "wifi-imu.h"
#else
#include "wifi-sdio.h"
#endif
#include "mlan_mgmt_ie.h"

/********************************************************
    Local Variables
********************************************************/

static mlan_buf_cfg s_mgmt_buf_cfgs[] = {
    {MLAN_MGMT_BUF_SM_SIZE, 0},
    {MLAN_MGMT_BUF_MD_SIZE, 0},
    {MLAN_MGMT_BUF_LG_SIZE, 0}
};

#define MGMT_BUFPOOL_NUM (sizeof(s_mgmt_buf_cfgs)/sizeof(s_mgmt_buf_cfgs[0]))

static OSA_MUTEX_HANDLE_DEFINE(s_ie_mutex);

static mlan_buf_handle s_mgmt_buf_handle = {0};
static mlan_buf_class s_mlan_buf_class[MGMT_BUFPOOL_NUM] = {0};
static bool s_mgmt_ie_initialized = false;

/********************************************************
                Local Functions
********************************************************/

static void *wrapper_mgmt_buf_malloc(t_u32 size)
{
#if !CONFIG_MEM_POOLS
    return OSA_MemoryAllocate((uint32_t)size);
#else
    if (size <= 256U)
    {
        return OSA_MemoryPoolAllocate(buf_256_MemoryPool);
    }
    else if (size <= 512U)
    {
        return OSA_MemoryPoolAllocate(buf_512_MemoryPool);
    }
    else
    {
        return OSA_MemoryPoolAllocate(buf_2048_MemoryPool);
    }
#endif
}

static void wrapper_mgmt_buf_free(void *ptr)
{
    if (ptr == MNULL)
    {
        return;
    }

#if !CONFIG_MEM_POOLS
    OSA_MemoryFree(ptr);
#else
#define POOL_256_SZ     (256 * 8 + 8 * sizeof(uint32_t))
#define POOL_512_SZ     (512 * 4 + 4 * sizeof(uint32_t))
#define POOL_2048_SZ    (2048 * 4 + 4 * sizeof(uint32_t))
    if (ptr >= buf_256_MemoryPool && ptr < (buf_256_MemoryPool + POOL_256_SZ))
    {
        OSA_MemoryPoolFree(buf_256_MemoryPool, ptr);
    }
    else if (ptr >= buf_512_MemoryPool && ptr < (buf_512_MemoryPool + POOL_512_SZ))
    {
        OSA_MemoryPoolFree(buf_512_MemoryPool, ptr);
    }
    else if (ptr >= buf_2048_MemoryPool && ptr < (buf_2048_MemoryPool + POOL_2048_SZ))
    {
        OSA_MemoryPoolFree(buf_2048_MemoryPool, ptr);
    }
    else
    {
        wifi_e("Invalid pointer to free %p", ptr);
    }
#endif
}

static inline void wrapper_mgmt_ie_lock(void)
{
    (void)OSA_MutexLock((osa_mutex_handle_t)s_ie_mutex, osaWaitForever_c);
}

static inline void wrapper_mgmt_ie_unlock(void)
{
    (void)OSA_MutexUnlock((osa_mutex_handle_t)s_ie_mutex);
}

static t_s8 util_buf_pool_init(pmlan_buf_handle handle,
                                pmlan_buf_class classes,
                                pmlan_buf_cfg cfgs,
                                t_u32 num,
                                void *(*malloc_fn)(t_u32),
                                void (*free_fn)(void *))
{
    t_u32 i, j;
    t_u32 total_size = 0;
    t_u32 block_size = 0;
    t_u8 *pos           = MNULL;
    pmlan_buf_block blk = MNULL;

    if (!handle || !classes || !cfgs || num == 0 || !malloc_fn || !free_fn)
    {
        return -1;
    }

    (void)memset(handle, 0, sizeof(*handle));

    handle->classes   = classes;
    handle->class_num = num;
    handle->malloc_fn = malloc_fn;
    handle->free_fn   = free_fn;

    for (i = 0; i < num; i++)
    {
        if (cfgs[i].buf_size == 0)
        {
            return -1;
        }

        block_size = ALIGN_SZ((sizeof(mlan_buf_block) + cfgs[i].buf_size), 4);
        total_size += block_size * cfgs[i].buf_cnt;
    }

    handle->mem_base = (t_u8 *)malloc_fn(total_size);
    if (!handle->mem_base)
    {
        return -1;
    }
    handle->mem_size = total_size;

    pos = handle->mem_base;

    for (i = 0; i < num; i++)
    {
        classes[i].free_list = MNULL;
        classes[i].buf_size  = cfgs[i].buf_size;
        classes[i].total     = cfgs[i].buf_cnt;
        classes[i].class_id  = i;
        classes[i].base      = pos;

        block_size = ALIGN_SZ((sizeof(mlan_buf_block) + classes[i].buf_size), 4);

        for (j = 0; j < classes[i].total; j++)
        {
            blk = (pmlan_buf_block)(pos + j * block_size);
            blk->next     = classes[i].free_list;
            blk->class_id = i;
            blk->magic    = 0;
            classes[i].free_list = blk;
        }

        pos += block_size * classes[i].total;
    }

    return 0;
}

static void util_buf_pool_deinit(pmlan_buf_handle handle)
{
    if (!handle)
    {
        return;
    }

    if (handle->mem_base)
    {
        handle->free_fn(handle->mem_base);
        handle->mem_base = MNULL;
    }

    handle->mem_size  = 0;
    handle->classes   = MNULL;
    handle->class_num = 0;
    handle->malloc_fn = MNULL;
    handle->free_fn   = MNULL;
}

static t_u8 *util_buf_pool_alloc(pmlan_buf_handle handle, t_u16 size)
{
    t_u32 i;
    pmlan_buf_class cls = MNULL;
    pmlan_buf_block blk = MNULL;

    if (!handle)
    {
        return MNULL;
    }

    for (i = 0; i < handle->class_num; i++)
    {
        cls = &handle->classes[i];

        if (size <= cls->buf_size && cls->free_list != MNULL)
        {
            blk = cls->free_list;
            cls->free_list = blk->next;
            blk->magic = MLAN_BUF_MAGIC;
            return blk->data;
        }
    }

    return MNULL;
}

static void util_buf_pool_free(pmlan_buf_handle handle, void *ptr)
{
    pmlan_buf_block blk = MNULL;
    pmlan_buf_class cls = MNULL;
    t_u32 block_size = 0;
    t_u8 id = 0xFF;

    if (!handle || !ptr)
    {
        return;
    }

    blk = util_container_of(ptr, mlan_buf_block, data);
    if (blk->magic != MLAN_BUF_MAGIC)
    {
        return;
    }

    id = blk->class_id;
    if (id >= handle->class_num)
    {
        return;
    }

    cls = &handle->classes[id];
    block_size = ALIGN_SZ(sizeof(mlan_buf_block) + cls->buf_size, 4);
    if ((t_u8 *)blk < cls->base || (t_u8 *)blk >= (cls->base + block_size * cls->total))
    {
        return;
    }

    blk->next      = cls->free_list;
    blk->magic     = 0;
    cls->free_list = blk;
}

static void *util_buf_pool_renew(pmlan_buf_handle handle,
                            void *ptr,
                            t_u16 new_size,
                            t_u16 copy_size)
{
    pmlan_buf_block blk = MNULL;
    pmlan_buf_class cls = MNULL;
    void *new_ptr       = MNULL;

    if (!handle || !ptr)
    {
        return MNULL;
    }

    blk = util_container_of(ptr, mlan_buf_block, data);

    if (blk->magic != MLAN_BUF_MAGIC)
    {
        return MNULL;
    }

    if (blk->class_id >= handle->class_num)
    {
        return MNULL;
    }

    cls = &handle->classes[blk->class_id];
    if (cls->buf_size >= new_size)
    {
        return ptr;
    }

    new_ptr = util_buf_pool_alloc(handle, new_size);
    if (!new_ptr)
    {
        return MNULL;
    }

    (void)memcpy(new_ptr, ptr, MIN(copy_size, cls->buf_size));

    util_buf_pool_free(handle, ptr);

    return new_ptr;
}

mlan_status wifi_mgmt_ie_init(void)
{
    if (s_mgmt_ie_initialized == MTRUE)
    {
        return MLAN_STATUS_SUCCESS;
    }

    s_mgmt_buf_cfgs[0].buf_cnt = MLAN_MGMT_BUF_SM_CNT; // mlan_adap->mgmt_ie_cnt_sm;
    s_mgmt_buf_cfgs[1].buf_cnt = MLAN_MGMT_BUF_MD_CNT; // mlan_adap->mgmt_ie_cnt_md;
    s_mgmt_buf_cfgs[2].buf_cnt = MLAN_MGMT_BUF_LG_CNT; // mlan_adap->mgmt_ie_cnt_lg;

    if (util_buf_pool_init(&s_mgmt_buf_handle, s_mlan_buf_class, s_mgmt_buf_cfgs,
                        MGMT_BUFPOOL_NUM, wrapper_mgmt_buf_malloc, wrapper_mgmt_buf_free) != 0)
    {
        wifi_e("Failed to init mgmt buffer pool");
        return MLAN_STATUS_FAILURE;
    }

    if (OSA_MutexCreate((osa_mutex_handle_t)s_ie_mutex) != KOSA_StatusSuccess)
    {
        wifi_e("Failed to create IE mutex");
        return MLAN_STATUS_FAILURE;
    }

    s_mgmt_ie_initialized = MTRUE;

    return MLAN_STATUS_SUCCESS;
}

void wifi_mgmt_ie_deinit(void)
{
    if (s_mgmt_ie_initialized == MTRUE)
    {
        if (OSA_MutexDestroy((osa_mutex_handle_t)s_ie_mutex) != KOSA_StatusSuccess)
        {
            wifi_e("Failed to destroy IE mutex");
            return;
        }

        util_buf_pool_deinit(&s_mgmt_buf_handle);
        s_mgmt_ie_initialized = MFALSE;
    }
}

static inline t_u8 *wifi_mgmt_buf_get(t_u16 size)
{
    return util_buf_pool_alloc(&s_mgmt_buf_handle, size);
}

static inline void wifi_mgmt_buf_put(t_u8 *buf)
{
    util_buf_pool_free(&s_mgmt_buf_handle, buf);
}

static inline t_u8 *wifi_mgmt_buf_renew(t_u8 *buf, t_u16 old_size, t_u16 new_size)
{
    return util_buf_pool_renew(&s_mgmt_buf_handle, buf, new_size, old_size);
}

static inline void clear_mgmt_ie_entry(pmlan_adapter pmadapter, t_u16 idx)
{
    pmadapter->mgmt_ie[idx].bss_type   = MLAN_BSS_TYPE_ANY;
    pmadapter->mgmt_ie[idx].cust_ie    = MNULL;
    pmadapter->mgmt_ie[idx].ie_offset  = 0;
    pmadapter->mgmt_ie[idx].cur_ie_len = 0;
}

static inline void clear_mgmt_buffer_entry(pmlan_adapter pmadapter, t_u16 idx)
{
    pmadapter->mgmt_buffer[idx].ie_index          = MLAN_MGMT_IE_INVALID_IDX;
    pmadapter->mgmt_buffer[idx].mgmt_subtype_mask = MLAN_MGMT_IE_INVALID_MASK;
    pmadapter->mgmt_buffer[idx].ie_length         = 0;
    if (pmadapter->mgmt_buffer[idx].ie_buf != MNULL)
    {
        wifi_mgmt_buf_put(pmadapter->mgmt_buffer[idx].ie_buf);
        pmadapter->mgmt_buffer[idx].ie_buf            = MNULL;
    }
}

static inline t_u16 find_free_fw_idx(pmlan_adapter pmadapter)
{
    t_u16 i;

    for (i = 0; i < pmadapter->max_mgmt_ie_index; i++)
    {
        if (pmadapter->mgmt_buffer[i].mgmt_subtype_mask == MLAN_MGMT_IE_INVALID_MASK)
        {
            return i;
        }
    }

    wifi_e("No free FW index available");
    return MLAN_MGMT_IE_INVALID_IDX;
}

static mlan_status wifi_mgmt_ie_remove(mlan_private *priv, t_u16 drv_idx, t_u16 fw_idx)
{
    mlan_adapter *pmadapter     = priv->adapter;
    custom_ie_entry *pmgmt_ie   = pmadapter->mgmt_ie;
    custom_ie_hdr *pmgmt_buffer = pmadapter->mgmt_buffer;
    t_u8 i = 0;

    ENTER();

    (void)memmove(pmgmt_buffer[fw_idx].ie_buf + pmgmt_ie[drv_idx].ie_offset,
                  pmgmt_buffer[fw_idx].ie_buf + pmgmt_ie[drv_idx].ie_offset + pmgmt_ie[drv_idx].cur_ie_len,
                  pmgmt_buffer[fw_idx].ie_length - (pmgmt_ie[drv_idx].ie_offset + pmgmt_ie[drv_idx].cur_ie_len));

    pmgmt_buffer[fw_idx].ie_length -= pmgmt_ie[drv_idx].cur_ie_len;

    for (i = 0; i < MAX_MGMT_IE_DRV_INDEX; i++)
    {
        if (pmgmt_ie[i].cust_ie && (i != drv_idx) &&
            pmgmt_ie[i].cust_ie->ie_index == fw_idx &&
            pmgmt_ie[i].ie_offset > pmgmt_ie[drv_idx].ie_offset)
        {
            pmgmt_ie[i].ie_offset -= pmgmt_ie[drv_idx].cur_ie_len;
        }
    }

    if (pmgmt_buffer[fw_idx].ie_length == 0U)
    {
        clear_mgmt_buffer_entry(pmadapter, fw_idx);
    }

    clear_mgmt_ie_entry(pmadapter, drv_idx);

    LEAVE();

    return MLAN_STATUS_SUCCESS;
}

static t_u16 wifi_mgmt_ie_get_autoidx(mlan_private *priv, t_u16 ie_mask, t_u16 ie_len)
{
    mlan_adapter *pmadapter     = priv->adapter;
    custom_ie_entry *pmgmt_ie   = MNULL;
    custom_ie_hdr *pmgmt_buffer = MNULL;
    t_u8 *new_buf               = MNULL;
    t_u8 i = 0;
    t_u16 drv_idx = MLAN_MGMT_IE_INVALID_IDX, fw_idx = MLAN_MGMT_IE_INVALID_IDX;

    ENTER();

    if (!priv || ie_mask == 0 || ie_len == 0)
    {
        wifi_e("Invalid input parameters");
        LEAVE();
        return MLAN_MGMT_IE_INVALID_IDX;
    }

    pmgmt_ie     = pmadapter->mgmt_ie;
    pmgmt_buffer = pmadapter->mgmt_buffer;

    for (i = 0; i < MAX_MGMT_IE_DRV_INDEX; i++)
    {
        if (!pmgmt_ie[i].cust_ie)
        {
            if (drv_idx == MLAN_MGMT_IE_INVALID_IDX)
            {
                drv_idx = i;
            }
            continue;
        }

        if (fw_idx == MLAN_MGMT_IE_INVALID_IDX)
        {
            if (pmgmt_ie[i].bss_type == priv->bss_type &&
                pmgmt_ie[i].cust_ie->mgmt_subtype_mask == ie_mask)
            {
                new_buf = wifi_mgmt_buf_renew(pmgmt_ie[i].cust_ie->ie_buf,
                                              pmgmt_ie[i].cust_ie->ie_length,
                                              pmgmt_ie[i].cust_ie->ie_length + ie_len);
                if (new_buf == MNULL)
                {
                    continue;
                }
                pmgmt_ie[i].cust_ie->ie_buf = new_buf;
                fw_idx = pmgmt_ie[i].cust_ie->ie_index;
            }
        }

        if (fw_idx != MLAN_MGMT_IE_INVALID_IDX && drv_idx != MLAN_MGMT_IE_INVALID_IDX)
        {
            break;
        }
    }

    if (drv_idx == MLAN_MGMT_IE_INVALID_IDX)
    {
        wifi_e("No free DRV index available");
        LEAVE();
        return MLAN_MGMT_IE_INVALID_IDX;
    }

    if (fw_idx == MLAN_MGMT_IE_INVALID_IDX)
    {
        fw_idx = find_free_fw_idx(pmadapter);
        if (fw_idx == MLAN_MGMT_IE_INVALID_IDX)
        {
            wifi_e("No free FW index available");
            LEAVE();
            return MLAN_MGMT_IE_INVALID_IDX;
        }
        clear_mgmt_buffer_entry(pmadapter, fw_idx);
    }
    clear_mgmt_ie_entry(pmadapter, drv_idx);

    pmgmt_buffer[fw_idx].ie_index = fw_idx;
    pmgmt_ie[drv_idx].cust_ie = &pmgmt_buffer[fw_idx];

    LEAVE();

    return drv_idx;
}

static mlan_status append_custom_ie(custom_ie **pos, t_u32 *remain_len, t_u16 *total_len, custom_ie_hdr *src)
{
    t_u16 len;

    if (!src)
    {
        return MLAN_STATUS_SUCCESS;
    }

    len = sizeof(custom_ie) - MAX_IE_SIZE + src->ie_length;
    if (len > *remain_len)
    {
        return MLAN_STATUS_FAILURE;
    }

    (*pos)->ie_index = src->ie_index;
    (*pos)->mgmt_subtype_mask = src->mgmt_subtype_mask;
    (*pos)->ie_length = src->ie_length;

    memcpy((*pos)->ie_buffer, src->ie_buf, src->ie_length);

    *pos = (custom_ie *)((t_u8 *)(*pos) + len);
    *remain_len -= len;
    *total_len += len;

    return MLAN_STATUS_SUCCESS;
}

static mlan_status wifi_mgmt_ie_list_set(mlan_private *priv, custom_ie_hdr *ies_list, t_u8 ies_cnt)
{
    mlan_status status                 = MLAN_STATUS_SUCCESS;
    mlan_ds_misc_custom_ie *pcustom_ie = MNULL;
    custom_ie *pos                     = MNULL;
    t_u16 len                          = 0;
    t_u32 remain_len                   = 0;
    HostCmd_DS_COMMAND *cmd            = MNULL;

    ENTER();

    pcustom_ie = wrapper_mgmt_buf_malloc(sizeof(mlan_ds_misc_custom_ie));
    if (!pcustom_ie)
    {
        wifi_e("Fail to allocate custome_ie\n");
        LEAVE();
        return MLAN_STATUS_FAILURE;
    }

    pcustom_ie->type = TLV_TYPE_MGMT_IE;

    pos        = pcustom_ie->ie_data_list;
    remain_len = sizeof(pcustom_ie->ie_data_list);

    for (int i = 0; i < ies_cnt; i++)
    {
        if (ies_list[i].mgmt_subtype_mask == MLAN_MGMT_IE_INVALID_MASK)
        {
            continue;
        }

        status = append_custom_ie(&pos, &remain_len, &len, &ies_list[i]);
        if (status != MLAN_STATUS_SUCCESS)
        {
            wifi_e("Failed to append custom IE");
            goto out;
        }
        pcustom_ie->len = len;
    }

    (void)wifi_get_command_lock();

    cmd = wifi_get_command_buffer();
    (void)memset(cmd, 0x00, sizeof(HostCmd_DS_COMMAND));

    cmd->seq_num = wifi_get_cmd_seq_num(priv);
    cmd->result  = 0x0;

#if UAP_SUPPORT
    if (priv->bss_type == MLAN_BSS_TYPE_UAP
#if CONFIG_WPA_SUPP_P2P
        || ((priv->bss_type == MLAN_BSS_TYPE_WIFIDIRECT) && (priv->bss_role == MLAN_BSS_ROLE_UAP))
#endif
        )
    {
        wifi_d("Sending System Config command for UAP");
        status = wlan_ops_uap_prepare_cmd(priv, HOST_CMD_APCMD_SYS_CONFIGURE, HostCmd_ACT_GEN_SET, 0,
                                          MNULL, (void *)pcustom_ie, cmd);
    }
    else
#endif
    {
        wifi_d("Sending MGMT IE list set command for STA");
        status = wlan_ops_sta_prepare_cmd(priv, HostCmd_CMD_MGMT_IE_LIST, HostCmd_ACT_GEN_SET, 0,
                                          MNULL, (void *)pcustom_ie, cmd);
    }
    if (status != MLAN_STATUS_SUCCESS)
    {
        wifi_e("Failed to prepare cmd.");
        wm_wifi.cmd_resp_priv = NULL;
        (void)wifi_put_command_lock();
        goto out;
    }

    (void)wifi_wait_for_cmdresp(MNULL);

out:
    if (pcustom_ie != MNULL)
    {
        wrapper_mgmt_buf_free(pcustom_ie);
    }

    LEAVE();

    return status;
}

static mlan_status wifi_mgmt_ie_add(mlan_private *priv, t_u16 ie_mask, t_u8 *ie_buf, t_u16 ie_len, t_u16 *index, bool download)
{
    mlan_status status          = MLAN_STATUS_SUCCESS;
    mlan_adapter *pmadapter     = priv->adapter;
    custom_ie_entry *pmgmt_ie   = MNULL;
    custom_ie_hdr *pmgmt_buffer = MNULL;
    t_u16 drv_idx = MLAN_MGMT_IE_INVALID_IDX;
    t_u16 fw_idx  = MLAN_MGMT_IE_INVALID_IDX;

    ENTER();

    drv_idx = wifi_mgmt_ie_get_autoidx(priv, ie_mask, ie_len);
    if (drv_idx == MLAN_MGMT_IE_INVALID_IDX || drv_idx >= MAX_MGMT_IE_DRV_INDEX)
    {
        wifi_e("Invalid DRV index");
        status = MLAN_STATUS_FAILURE;
        goto out;
    }

    pmgmt_ie     = pmadapter->mgmt_ie;
    pmgmt_buffer = pmgmt_ie[drv_idx].cust_ie;
    fw_idx       = pmgmt_buffer->ie_index;

    wifi_d("[Add] drv_idx=%d, fw_idx=%d", drv_idx, fw_idx);

    if (pmgmt_buffer->mgmt_subtype_mask == MLAN_MGMT_IE_INVALID_MASK)
    {
        pmgmt_buffer->ie_buf = wifi_mgmt_buf_get(ie_len);
        if (pmgmt_buffer->ie_buf == MNULL)
        {
            wifi_e("Failed to allocate memory for IE buffer");
            clear_mgmt_ie_entry(pmadapter, drv_idx);
            status = MLAN_STATUS_FAILURE;
            goto out;
        }
        pmgmt_buffer->ie_index = fw_idx;
        pmgmt_buffer->mgmt_subtype_mask = ie_mask;
    }

    pmgmt_ie[drv_idx].ie_offset  = pmgmt_buffer->ie_length;
    pmgmt_ie[drv_idx].bss_type   = priv->bss_type;
    pmgmt_ie[drv_idx].cur_ie_len = ie_len;

    (void)memcpy(pmgmt_buffer->ie_buf + pmgmt_buffer->ie_length, ie_buf, ie_len);
    pmgmt_buffer->ie_length += ie_len;

    if (index != MNULL)
    {
        *index = drv_idx;
    }

    if (download)
    {
        if (wifi_mgmt_ie_list_set(priv, pmgmt_buffer, 1) != MLAN_STATUS_SUCCESS)
        {
            clear_mgmt_buffer_entry(pmadapter, fw_idx);
            clear_mgmt_ie_entry(pmadapter, drv_idx);
            status = MLAN_STATUS_FAILURE;
            goto out;
        }
    }

    status = MLAN_STATUS_SUCCESS;

out:
    LEAVE();

    return status;
}

static mlan_status wifi_mgmt_ie_update(mlan_private *priv, t_u16 ie_mask, t_u8 *ie_buf, t_u16 ie_len, t_u16 *index)
{
    mlan_status status           = MLAN_STATUS_SUCCESS;
    mlan_adapter *pmadapter      = priv->adapter;
    custom_ie_entry *pmgmt_ie    = MNULL;
    custom_ie_hdr *pmgmt_buffer  = MNULL;
    custom_ie_hdr *pmgmt_buffer2 = MNULL;
    custom_ie_hdr ies_list[2]    = {0};
    t_u16 drv_idx = MLAN_MGMT_IE_INVALID_IDX;
    t_u16 fw_idx  = MLAN_MGMT_IE_INVALID_IDX;
    t_u16 new_idx = MLAN_MGMT_IE_INVALID_IDX;
    t_u8 ies_cnt  = 0;
    t_u8 *tmp_buf = MNULL;

    ENTER();

    if (!ie_buf || !index || *index == MLAN_MGMT_IE_INVALID_IDX || *index >= MAX_MGMT_IE_DRV_INDEX)
    {
        wifi_e("Invalid parameters");
        status = MLAN_STATUS_FAILURE;
        goto out;
    }

    for (int i = 0; i < 2; i++) {
        ies_list[i].ie_index = MLAN_MGMT_IE_INVALID_IDX;
        ies_list[i].mgmt_subtype_mask = MLAN_MGMT_IE_INVALID_MASK;
        ies_list[i].ie_length = 0;
        ies_list[i].ie_buf = NULL;
    }

    pmgmt_ie     = pmadapter->mgmt_ie;
    drv_idx      = *index;
    pmgmt_buffer = pmgmt_ie[drv_idx].cust_ie;
    fw_idx       = pmgmt_buffer->ie_index;

    if (pmgmt_buffer->ie_length == pmgmt_ie[drv_idx].cur_ie_len)
    {
        tmp_buf = wifi_mgmt_buf_renew(pmgmt_buffer->ie_buf, pmgmt_buffer->ie_length, ie_len);
        if (tmp_buf == MNULL)
        {
            wifi_e("Failed to renew memory for IE buffer");
            status = MLAN_STATUS_FAILURE;
            goto out;
        }
        pmgmt_buffer->ie_buf = tmp_buf;
        (void)memcpy(pmgmt_buffer->ie_buf, ie_buf, ie_len);
        pmgmt_buffer->ie_length      = ie_len;
        pmgmt_ie[drv_idx].cur_ie_len = ie_len;
        ies_list[ies_cnt++] = *pmgmt_buffer;
    }
    else
    {
        status = wifi_mgmt_ie_remove(priv, drv_idx, fw_idx);
        if (status != MLAN_STATUS_SUCCESS)
        {
            wifi_e("Failed to remove management IE");
            goto out;
        }

        status = wifi_mgmt_ie_add(priv, ie_mask, ie_buf, ie_len, &new_idx, 0);
        if (status != MLAN_STATUS_SUCCESS)
        {
            wifi_e("Failed to add management IE");
            goto out;
        }

        ies_list[ies_cnt++] = *pmgmt_buffer;
        if (pmgmt_ie[new_idx].cust_ie->ie_index != fw_idx)
        {
            pmgmt_buffer2 = pmgmt_ie[new_idx].cust_ie;
            ies_list[ies_cnt++] = *pmgmt_buffer2;
        }
        *index = new_idx;
    }

    status = wifi_mgmt_ie_list_set(priv, ies_list, ies_cnt);
    if (status != MLAN_STATUS_SUCCESS)
    {
        goto out;
    }

    status = MLAN_STATUS_SUCCESS;

out:
    LEAVE();

    return status;
}

mlan_status wifi_mgmt_ie_clear(mlan_private *priv, t_u16 *index)
{
    mlan_status status          = MLAN_STATUS_SUCCESS;
    mlan_adapter *pmadapter     = priv->adapter;
    custom_ie_entry *pmgmt_ie   = MNULL;
    custom_ie_hdr *pmgmt_buffer = MNULL;
    t_u16 drv_idx = MLAN_MGMT_IE_INVALID_IDX;
    t_u16 fw_idx  = MLAN_MGMT_IE_INVALID_IDX;

    ENTER();

    wrapper_mgmt_ie_lock();

    if (!index || *index == MLAN_MGMT_IE_INVALID_IDX || *index >= MAX_MGMT_IE_DRV_INDEX)
    {
        wifi_e("Invalid parameters");
        status = MLAN_STATUS_FAILURE;
        goto out;
    }

    drv_idx      = *index;
    pmgmt_ie     = pmadapter->mgmt_ie;
    pmgmt_buffer = pmgmt_ie[drv_idx].cust_ie;
    fw_idx       = pmgmt_buffer->ie_index;

    if (pmgmt_buffer->ie_length == pmgmt_ie[drv_idx].cur_ie_len)
    {
        pmgmt_buffer->mgmt_subtype_mask = MGMT_MASK_CLEAR;
        pmgmt_buffer->ie_length         = 0;
    }
    else
    {
        status = wifi_mgmt_ie_remove(priv, drv_idx, fw_idx);
        if (status != MLAN_STATUS_SUCCESS)
        {
            wifi_e("Failed to remove management IE");
            goto out;
        }
    }

    status = wifi_mgmt_ie_list_set(priv, pmgmt_buffer, 1);
    if (status != MLAN_STATUS_SUCCESS)
    {
        wifi_e("Failed to download mgmt IE");
        goto out;
    }

    if (pmgmt_buffer->mgmt_subtype_mask == MGMT_MASK_CLEAR)
    {
        clear_mgmt_buffer_entry(pmadapter, fw_idx);
    }

    clear_mgmt_ie_entry(pmadapter, drv_idx);
    *index = MLAN_MGMT_IE_INVALID_IDX;

    status = MLAN_STATUS_SUCCESS;

out:
    wrapper_mgmt_ie_unlock();

    LEAVE();

    return status;
}

mlan_status wifi_mgmt_ie_replace_IE(mlan_private *priv, t_u8 *ie_buf, t_u16 ie_len, IEEEtypes_ElementId_e ie_id, t_u8 *oui)
{
    mlan_status status          = MLAN_STATUS_SUCCESS;
    mlan_adapter *pmadapter     = priv->adapter;
    custom_ie_entry *pmgmt_ie   = MNULL;
    custom_ie_hdr *pmgmt_buffer = MNULL;
    t_u16 drv_idx    = MLAN_MGMT_IE_INVALID_IDX;
    t_u16 cur_fw_idx = MLAN_MGMT_IE_INVALID_IDX;
    t_u16 fw_idx_dnld_bitmap = 0;
    t_u8 *cur_mgmt_ie_buf = MNULL;
    t_u16 cur_mgmt_ie_len = 0;
    t_u8 *tmp_ie_buf    = MNULL;
    t_u16 tmp_ie_offset = 0;
    IEEEtypes_Header_t *cur_ie              = MNULL;
    IEEEtypes_VendorHeader_t *cur_vendor_ie = MNULL;
    t_u16 cur_ie_len = 0;
    custom_ie_hdr ie_data[MAX_MGMT_IE_INDEX_TO_FW];
    t_u8 ie_cnt = 0;
    t_u8 i = 0;

    ENTER();

    wrapper_mgmt_ie_lock();

    tmp_ie_buf = wrapper_mgmt_buf_malloc(MAX_IE_SIZE);
    if (!tmp_ie_buf)
    {
        wifi_e("Failed to allocate memory for IE buffer");
        status = MLAN_STATUS_FAILURE;
        goto out;
    }

    for (int i = 0; i < MAX_MGMT_IE_INDEX_TO_FW; i++) {
        ie_data[i].ie_index = MLAN_MGMT_IE_INVALID_IDX;
        ie_data[i].mgmt_subtype_mask = MLAN_MGMT_IE_INVALID_MASK;
        ie_data[i].ie_length = 0;
        ie_data[i].ie_buf = NULL;
    }

    pmgmt_ie = pmadapter->mgmt_ie;

    for (i = 0; i < MAX_MGMT_IE_DRV_INDEX; i++)
    {
        if ((pmgmt_ie[i].bss_type == priv->bss_type) &&
            (pmgmt_ie[i].cust_ie != MNULL))
        {
            t_u8 match_found = 0;
            pmgmt_buffer    = pmgmt_ie[i].cust_ie;
            cur_fw_idx      = pmgmt_buffer->ie_index;
            cur_mgmt_ie_buf = pmgmt_buffer->ie_buf + pmgmt_ie[i].ie_offset;
            cur_mgmt_ie_len = pmgmt_ie[i].cur_ie_len;

            tmp_ie_offset = 0;

            while (tmp_ie_offset < cur_mgmt_ie_len)
            {
                cur_ie = (IEEEtypes_Header_t *)(cur_mgmt_ie_buf + tmp_ie_offset);
                cur_ie_len = cur_ie->len + 2U;

                if (cur_ie->element_id == ie_id)
                {
                    wifi_d("Found matching IE [%d] at offset %d", i, tmp_ie_offset);
                    if (ie_id == VENDOR_SPECIFIC_221)
                    {
                        cur_vendor_ie = (IEEEtypes_VendorHeader_t *)cur_ie;
                        if (!memcmp(cur_vendor_ie->oui, oui, 3) &&
                            (cur_vendor_ie->oui_type == oui[3]))
                        {
                            match_found = 1;
                        }
                    }
                    else
                    {
                        match_found = 1;
                    }

                    if (match_found)
                    {
                        wifi_d("Matched IE found, replacing IE");
                        //TODO: ECSA improvement
                        if (cur_ie->element_id == COUNTRY_INFO)
                        {
                            wifi_d("Update COUNTRY_INFO IE");
                            drv_idx = i;
                            status = wifi_mgmt_ie_update(priv, pmgmt_buffer->mgmt_subtype_mask, ie_buf, ie_len, &drv_idx);
                            if (status != MLAN_STATUS_SUCCESS)
                            {
                                wifi_e("Failed to update COUNTRY_INFO IE");
                                goto out;
                            }
                        }
                        else if (cur_ie_len == ie_len)
                        {
                            wifi_d("IE length matches, replacing in-place");
                            (void)memcpy(cur_ie, ie_buf, ie_len);
                            fw_idx_dnld_bitmap |= MBIT(cur_fw_idx);
                            pmgmt_ie[i].bss_type |= MLAN_MGMT_IE_UPDATED; /* Mark this IE is updated by replace_IE API */
                        }
                        else
                        {
                            wifi_d("IE length differs, reconstructing IE buffer");
                            t_u16 new_len = pmgmt_ie[i].cur_ie_len - cur_ie_len + ie_len;
                            t_u8 *dst = tmp_ie_buf;
                            t_u8 *src = pmgmt_buffer->ie_buf + pmgmt_ie[i].ie_offset;
                            /** copy prefix */
                            (void)memcpy(dst, src, tmp_ie_offset);
                            dst += tmp_ie_offset;
                            /** insert new IE */
                            (void)memcpy(dst, ie_buf, ie_len);
                            dst += ie_len;
                            /** copy suffix */
                            (void)memcpy(dst,
                                         src + tmp_ie_offset + cur_ie_len,
                                         pmgmt_ie[i].cur_ie_len - (tmp_ie_offset + cur_ie_len));
                            wifi_mgmt_ie_remove(priv, i, cur_fw_idx);
                            status = wifi_mgmt_ie_add(priv, pmgmt_buffer->mgmt_subtype_mask, tmp_ie_buf, new_len, &drv_idx, 0);
                            if (status != MLAN_STATUS_SUCCESS || drv_idx == MLAN_MGMT_IE_INVALID_IDX)
                            {
                                wifi_e("Failed to add management IE");
                                status = MLAN_STATUS_FAILURE;
                                goto out;
                            }
                            if (pmgmt_ie[drv_idx].cust_ie->ie_index != cur_fw_idx)
                            {
                                fw_idx_dnld_bitmap |= MBIT(pmgmt_ie[drv_idx].cust_ie->ie_index);
                            }
                            fw_idx_dnld_bitmap |= MBIT(cur_fw_idx);
                            pmgmt_ie[drv_idx].bss_type |= MLAN_MGMT_IE_UPDATED;
                        }
                        break;
                    }
                }
                tmp_ie_offset += cur_ie_len;
            }
        }
    }

    if (ie_id == COUNTRY_INFO)
    {
        wifi_d("Skip downloading COUNTRY_INFO IE as it's already updated");;
        goto out;
    }

    pmgmt_buffer = pmadapter->mgmt_buffer;

    for (i = 0; i < pmadapter->max_mgmt_ie_index; i++)
    {
        if (fw_idx_dnld_bitmap & MBIT(i))
        {
            ie_data[ie_cnt++] = pmgmt_buffer[i];
            if (ie_cnt == MAX_MGMT_IE_INDEX_TO_FW)
            {
                status = wifi_mgmt_ie_list_set(priv, ie_data, ie_cnt);
                if (status != MLAN_STATUS_SUCCESS)
                {
                    wifi_e("Failed to download mgmt IE");
                    goto out;
                }
                ie_cnt = 0;
                (void)memset(ie_data, 0, sizeof(ie_data));
            }
        }
    }

    if (ie_cnt > 0)
    {
        status = wifi_mgmt_ie_list_set(priv, ie_data, ie_cnt);
        if (status != MLAN_STATUS_SUCCESS)
        {
            wifi_e("Failed to download mgmt IE");
            goto out;
        }
    }

    for (i = 0; i < MAX_MGMT_IE_DRV_INDEX; i++)
    {
        if (pmgmt_ie[i].bss_type & MLAN_MGMT_IE_UPDATED)
        {
            pmgmt_ie[i].bss_type &= ~MLAN_MGMT_IE_UPDATED;
        }
    }

    status = MLAN_STATUS_SUCCESS;

out:
    if (tmp_ie_buf != MNULL)
    {
        wrapper_mgmt_buf_free(tmp_ie_buf);
    }

    wrapper_mgmt_ie_unlock();

    LEAVE();

    return status;
}

mlan_status wifi_mgmt_ie_set(mlan_private *priv, t_u16 ie_mask, t_u8 *ie_buf, t_u16 ie_len, t_u16 *index)
{
    mlan_status status = MLAN_STATUS_FAILURE;

    ENTER();

    if (!priv || !ie_buf || ie_len == 0 || !index)
    {
        wifi_e("Invalid parameters");
        LEAVE();
        return MLAN_STATUS_FAILURE;
    }

    wrapper_mgmt_ie_lock();

    if (*index == MLAN_MGMT_IE_INVALID_IDX)
    {
        status = wifi_mgmt_ie_add(priv, ie_mask, ie_buf, ie_len, index, 1);
    }
    else
    {
        status = wifi_mgmt_ie_update(priv, ie_mask, ie_buf, ie_len, index);
    }

    wrapper_mgmt_ie_unlock();

    LEAVE();

    return status;
}

void wlan_init_mgmt_ie_param(pmlan_adapter pmadapter)
{
    t_u8 i = 0;

    ENTER();

    pmadapter->max_mgmt_ie_index = 0;
    pmadapter->mgmt_ie_cnt_sm = 0;
    pmadapter->mgmt_ie_cnt_md = 0;
    pmadapter->mgmt_ie_cnt_lg = 0;

    for (i = 0; i < MAX_MGMT_IE_DRV_INDEX; i++)
    {
        clear_mgmt_ie_entry(pmadapter, i);
    }

    for (i = 0; i < MAX_MGMT_IE_FW_INDEX; i++)
    {
        clear_mgmt_buffer_entry(pmadapter, i);
    }

    LEAVE();
}

static void ie_dump_hex(const char *title, const t_u8 *buf, t_u16 len)
{
    t_u16 i;

    if (!buf || !len)
    {
        return;
    }

    (void)PRINTF("%s (len=%u):\n", title, len);

    for (i = 0; i < len; i++)
    {
        if (i % 16 == 0)
        {
            (void)PRINTF("%04x: ", i);
        }

        (void)PRINTF("%02x ", buf[i]);

        if ((i % 16 == 15) || (i == len - 1))
        {
            (void)PRINTF("\n");
        }
    }
}

static void dump_mgmt_buffer(pmlan_adapter pmadapter)
{
    t_u16 i;

    (void)PRINTF("=========== MGMT BUFFER DUMP ===========\n");

    for (i = 0; i < pmadapter->max_mgmt_ie_index; i++)
    {
        custom_ie_hdr *buf = &pmadapter->mgmt_buffer[i];

        if (buf->mgmt_subtype_mask == MLAN_MGMT_IE_INVALID_MASK)
            continue;

        (void)PRINTF("FW_IDX=%u\n", i);
        (void)PRINTF("  mask       = 0x%04x\n", buf->mgmt_subtype_mask);
        (void)PRINTF("  ie_length  = %u\n", buf->ie_length);
        (void)PRINTF("  ie_buf     = %p\n", buf->ie_buf);

        if (buf->ie_buf && buf->ie_length > 0)
        {
            ie_dump_hex("  IE DATA", buf->ie_buf, buf->ie_length);
        }
    }
}

static void dump_mgmt_ie(pmlan_adapter pmadapter)
{
    t_u16 i;

    (void)PRINTF("\n=========== MGMT IE (DRV) DUMP ===========\n");

    (void)PRINTF("--------------------------------------------------------------------------------\n");
    (void)PRINTF("| %-7s | %-7s | %-10s | %-10s | %-8s | %-8s |\n",
           "DRV_IDX", "FW_IDX", "MASK", "BSS_TYPE", "OFFSET", "LEN");
    (void)PRINTF("--------------------------------------------------------------------------------\n");

    for (i = 0; i < MAX_MGMT_IE_DRV_INDEX; i++)
    {
        custom_ie_entry *ie = &pmadapter->mgmt_ie[i];

        if (!ie->cust_ie)
        {
            continue;
        }

        (void)PRINTF("| %-7u | %-7u | 0x%08x | %-10u | %-8u | %-8u |\n",
               i,
               ie->cust_ie->ie_index,
               ie->cust_ie->mgmt_subtype_mask,
               ie->bss_type,
               ie->ie_offset,
               ie->cur_ie_len);
    }

    PRINTF("--------------------------------------------------------------------------------\n\n");
}

static void dump_buf_pool(pmlan_buf_handle handle)
{
    t_u32 i;
    pmlan_buf_class cls;
    pmlan_buf_block blk;
    t_u32 free_cnt;

    (void)PRINTF("=========== BUF POOL DUMP ===========\n");

    if (!handle)
        return;

    (void)PRINTF("mem_base=%p size=%u\n", handle->mem_base, handle->mem_size);

    for (i = 0; i < handle->class_num; i++)
    {
        cls = &handle->classes[i];
        free_cnt = 0;

        blk = cls->free_list;
        while (blk)
        {
            free_cnt++;
            blk = blk->next;
        }

        (void)PRINTF("CLASS[%u]\n", i);
        (void)PRINTF("  buf_size   = %u\n", cls->buf_size);
        (void)PRINTF("  total      = %u\n", cls->total);
        (void)PRINTF("  free       = %u\n", free_cnt);
        (void)PRINTF("  used       = %u\n", cls->total - free_cnt);
    }
}

static void dump_mgmt_ie_visual(pmlan_adapter pmadapter)
{
    t_u16 fw, drv;
    t_u8 has_ref;

    (void)PRINTF("=========== MGMT IE MAP (VISUAL) ===========\n\n");

    for (fw = 0; fw < pmadapter->max_mgmt_ie_index; fw++)
    {
        custom_ie_hdr *buf = &pmadapter->mgmt_buffer[fw];

        if (buf->mgmt_subtype_mask == MLAN_MGMT_IE_INVALID_MASK)
        {
            continue;
        }

        (void)PRINTF("FW[%02u]\n", fw);
        has_ref = 0;
        for (drv = 0; drv < MAX_MGMT_IE_DRV_INDEX; drv++)
        {
            custom_ie_entry *ie = &pmadapter->mgmt_ie[drv];

            if (ie->cust_ie &&
                ie->cust_ie->ie_index == fw)
            {
                (void)PRINTF("   └── DRV[%02u]\n", drv);
                has_ref = 1;
            }
        }

        if (!has_ref)
        {
            (void)PRINTF("   └── (no drv)\n");
        }

        (void)PRINTF("\n");
    }
}

void wifi_mgmt_ie_dump(pmlan_adapter pmadapter)
{
    if (!pmadapter)
        return;

    (void)PRINTF("\n\n========== WIFI MGMT IE DUMP ==========\n");
    dump_buf_pool(&s_mgmt_buf_handle);
    dump_mgmt_buffer(pmadapter);
    dump_mgmt_ie(pmadapter);
    dump_mgmt_ie_visual(pmadapter);
    (void)PRINTF("=============================================\n\n");
}
