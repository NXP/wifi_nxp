/*  Copyright 2008-2020 NXP
 *
 *  Licensed under the LA_OPT_NXP_Software_License.txt (the "Agreement")
 *
 */

/*! \file wlan_tests.h
 *  \brief WLAN Connection Manager Tests
 */

#ifndef __WLAN_TESTS_H__
#define __WLAN_TESTS_H__

#if defined(CONFIG_11AX) && defined(CONFIG_11AX_TWT)
/* index enum of cfgs */
enum
{
    TEST_WLAN_11AX_CFG,
    TEST_WLAN_BCAST_TWT,
    TEST_WLAN_TWT_SETUP,
    TEST_WLAN_TWT_TEARDOWN,
};

/*
 *  Structs for mutiple config data in freeRTOS, split cfg to various param modules.
 *  Modify cfg data by param index
 *  test_cfg_param_t param module of cfg
 *  test_cfg_table_t cfg table for all the param modules of a cfg
 */
typedef struct
{
    /* name of param */
    const char *name;
    /* offset in cfg data */
    int offset;
    int len;
    const char *notes;
} test_cfg_param_t;

typedef struct
{
    /* name of cfg */
    const char *name;
    /* point of stored data for sending cmd, stored in Little-Endian */
    uint8_t *data;
    /* len of data */
    int len;
    /* point of list for all the params */
    const test_cfg_param_t *param_list;
    /* total number of params */
    int param_num;
} test_cfg_table_t;

/*
 *  Cfg table process
 *  syntax: "wlan-11axcfg <option> <arguments>"
 *  demo: "wlan-11axcfg dump" dump data
 *        "wlan-11axcfg help" dump data and notes
 *        "wlan-11axcfg set 1 ff 01" set param[1] in cfg param list to 0xff 0x01 (511 in uint16_t)
 *        "wlan-11axcfg done" send corresponding cmd to wifi driver
 */
void test_wlan_cfg_process(uint32_t index, int argc, char **argv);
#endif /* CONFIG_11AX && CONFIG_11AX_TWT */
/** Print the TX PWR Limit table received from Wi-Fi firmware
 *
 * \param[in] txpwrlimit A \ref wlan_txpwrlimit_t struct holding the
 * 		the TX PWR Limit table received from Wi-Fi firmware.
 *
 */
void print_txpwrlimit(wlan_txpwrlimit_t txpwrlimit);
#endif /* WLAN_TESTS_H */
