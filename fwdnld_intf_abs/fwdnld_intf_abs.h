/** @file fwdnld_inf_abs.h
 *
 *  @brief  This file provides interface abstraction APIs
 *
 *  Copyright 2022 NXP
 *
 *  Licensed under the LA_OPT_NXP_Software_License.txt (the "Agreement")
 *
 */

#ifndef _FWDNLD_INTF_ABS_H_
#define _FWDNLD_INTF_ABS_H_

#include <stddef.h>
#include <stdint.h>

/* Return type defines */
typedef enum
{
    /* Please add interface specific return types with the values
     * APIs just return interface returned return types*/
    FWDNLD_INTF_FAIL    = 0xffffffff,
    FWDNLD_INTF_SUCCESS = 0,
    FWDNLD_INTF_PART_WRITE,
    FWDNLD_INTF_PART_READ,
    FWDNLD_INTF_WAIT,
    FWDNLD_INTF_EPARAM
} fwdnld_intf_ret_t;

/*Interface type defines*/

typedef enum
{
    FWDNLD_INTF_IMU,
    FWDNLD_INTF_SDIO,
    FWDNLD_INTF_SPI,
    FWDNLD_INTF_UART
} fwdnld_intf_type_t;

struct fwdnldintf;

typedef struct intf_elems
{
    /* Functions for the interface */
    fwdnld_intf_ret_t (*fwdnld_intf_send)(struct fwdnldintf *intf,
                                          const uint8_t *buff,
                                          uint32_t transfer_len,
                                          uint32_t *transferred_len);
    fwdnld_intf_ret_t (*fwdnld_intf_prepare)(struct fwdnldintf *intf, void *params);
    fwdnld_intf_ret_t (*fwdnld_intf_check_ready)(struct fwdnldintf *intf, void *params);
    /* interface values to be stored */
    uint8_t *outbuf; /* For Tx */
    uint32_t outbuf_len;
    uint8_t *inbuf; /* For Rx */
    uint32_t inbuf_len;
    void *intf_specific; /*Place holder to store interface specific struct */
} intf_t;

typedef struct fwdnldintf
{
    fwdnld_intf_type_t intf_type;
    intf_t intf_s; /*returned by interface init */
} fwdnld_intf_t;

#define GET_INTF_TYPE(x)      ((x)->intf_type)
#define GET_INTF_OUTBUF(x)    ((x)->intf_s.outbuf)
#define GET_INTF_OUTBUFLEN(x) ((x)->intf_s.outbuf_len)

#endif /*_FWDNLD_INTF_ABS_H_*/
