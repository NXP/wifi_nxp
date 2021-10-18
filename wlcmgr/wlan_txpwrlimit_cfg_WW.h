/** @file wlan_txpwrlimit_cfg_WW.h
 *
 *  @brief  This file provides WLAN World Wide Safe Mode Tx Power Limits.
 *
 *  Copyright 2008-2021 NXP
 *
 *  Permission is hereby granted, free of charge, to any person obtaining
 *  a copy of this software and associated documentation files (the
 *  'Software'), to deal in the Software without restriction, including
 *  without limitation the rights to use, copy, modify, merge, publish,
 *  distribute, sub license, and/or sell copies of the Software, and to
 *  permit persons to whom the Software is furnished to do so, subject
 *  to the following conditions:
 *
 *  The above copyright notice and this permission notice (including the
 *  next paragraph) shall be included in all copies or substantial
 *  portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT.
 *  IN NO EVENT SHALL NXP AND/OR ITS SUPPLIERS BE LIABLE FOR ANY
 *  CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 *  TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 *  SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#include <wlan.h>
#include <wifi.h>

#ifdef CONFIG_11AX
static wifi_txpwrlimit_t
    tx_pwrlimit_2g_cfg =
        {
            .subband = (wifi_SubBand_t)0x00,
            .num_chans = 14,
            .txpwrlimit_config[0] =
                {
                    .num_mod_grps = 20,
                    .chan_desc =
                        {
                            .start_freq = 2407,
                            .chan_width = 20,
                            .chan_num   = 1,
                        },
                    .txpwrlimit_entry = {{0, 17},
                                         {1, 16},
                                         {2, 16},
                                         {3, 16},
                                         {4, 16},
                                         {5, 16},
                                         {6, 16},
                                         {7, 14},
                                         {8, 14},
                                         {9, 14},
                                         {10, 16},
                                         {11, 14},
                                         {12, 0},
                                         {13, 0},
                                         {14, 0},
                                         {15, 0},
                                         {16, 16},
                                         {17, 16},
                                         {18, 14},
                                         {19, 0}},
                },
            .txpwrlimit_config[1] =
                {
                    .num_mod_grps = 20,
                    .chan_desc =
                        {
                            .start_freq = 2407,
                            .chan_width = 20,
                            .chan_num   = 2,
                        },
                    .txpwrlimit_entry = {{0, 17},
                                         {1, 16},
                                         {2, 16},
                                         {3, 16},
                                         {4, 16},
                                         {5, 16},
                                         {6, 16},
                                         {7, 13},
                                         {8, 13},
                                         {9, 13},
                                         {10, 16},
                                         {11, 13},
                                         {12, 0},
                                         {13, 0},
                                         {14, 0},
                                         {15, 0},
                                         {16, 16},
                                         {17, 16},
                                         {18, 13},
                                         {19, 0}},
                },
            .txpwrlimit_config[2] =
                {
                    .num_mod_grps = 20,
                    .chan_desc =
                        {
                            .start_freq = 2407,
                            .chan_width = 20,
                            .chan_num   = 3,
                        },
                    .txpwrlimit_entry = {{0, 17},
                                         {1, 17},
                                         {2, 17},
                                         {3, 17},
                                         {4, 17},
                                         {5, 17},
                                         {6, 17},
                                         {7, 14},
                                         {8, 14},
                                         {9, 14},
                                         {10, 17},
                                         {11, 14},
                                         {12, 0},
                                         {13, 0},
                                         {14, 0},
                                         {15, 0},
                                         {16, 17},
                                         {17, 17},
                                         {18, 14},
                                         {19, 0}},
                },
            .txpwrlimit_config[3] =
                {
                    .num_mod_grps = 20,
                    .chan_desc =
                        {
                            .start_freq = 2407,
                            .chan_width = 20,
                            .chan_num   = 4,
                        },
                    .txpwrlimit_entry = {{0, 17},
                                         {1, 18},
                                         {2, 18},
                                         {3, 18},
                                         {4, 18},
                                         {5, 18},
                                         {6, 18},
                                         {7, 13},
                                         {8, 19},
                                         {9, 18},
                                         {10, 18},
                                         {11, 18},
                                         {12, 0},
                                         {13, 0},
                                         {14, 0},
                                         {15, 0},
                                         {16, 18},
                                         {17, 17},
                                         {18, 17},
                                         {19, 0}},
                },
            .txpwrlimit_config[4] =
                {
                    .num_mod_grps = 20,
                    .chan_desc =
                        {
                            .start_freq = 2407,
                            .chan_width = 20,
                            .chan_num   = 5,
                        },
                    .txpwrlimit_entry = {{0, 15},
                                         {1, 16},
                                         {2, 16},
                                         {3, 16},
                                         {4, 16},
                                         {5, 16},
                                         {6, 16},
                                         {7, 14},
                                         {8, 17},
                                         {9, 17},
                                         {10, 16},
                                         {11, 17},
                                         {12, 0},
                                         {13, 0},
                                         {14, 0},
                                         {15, 0},
                                         {16, 16},
                                         {17, 16},
                                         {18, 17},
                                         {19, 0}},
                },
            .txpwrlimit_config[5] =
                {
                    .num_mod_grps = 20,
                    .chan_desc =
                        {
                            .start_freq = 2407,
                            .chan_width = 20,
                            .chan_num   = 6,
                        },
                    .txpwrlimit_entry = {{0, 15},
                                         {1, 16},
                                         {2, 16},
                                         {3, 16},
                                         {4, 16},
                                         {5, 16},
                                         {6, 16},
                                         {7, 17},
                                         {8, 13},
                                         {9, 13},
                                         {10, 16},
                                         {11, 13},
                                         {12, 0},
                                         {13, 0},
                                         {14, 0},
                                         {15, 0},
                                         {16, 16},
                                         {17, 16},
                                         {18, 13},
                                         {19, 0}},
                },
            .txpwrlimit_config[6] =
                {
                    .num_mod_grps = 20,
                    .chan_desc =
                        {
                            .start_freq = 2407,
                            .chan_width = 20,
                            .chan_num   = 7,
                        },
                    .txpwrlimit_entry = {{0, 15},
                                         {1, 16},
                                         {2, 16},
                                         {3, 16},
                                         {4, 16},
                                         {5, 16},
                                         {6, 16},
                                         {7, 17},
                                         {8, 13},
                                         {9, 13},
                                         {10, 16},
                                         {11, 13},
                                         {12, 0},
                                         {13, 0},
                                         {14, 0},
                                         {15, 0},
                                         {16, 16},
                                         {17, 16},
                                         {18, 13},
                                         {19, 0}},
                },
            .txpwrlimit_config[7] =
                {
                    .num_mod_grps = 20,
                    .chan_desc =
                        {
                            .start_freq = 2407,
                            .chan_width = 20,
                            .chan_num   = 8,
                        },
                    .txpwrlimit_entry = {{0, 15},
                                         {1, 16},
                                         {2, 16},
                                         {3, 16},
                                         {4, 16},
                                         {5, 16},
                                         {6, 16},
                                         {7, 17},
                                         {8, 14},
                                         {9, 14},
                                         {10, 16},
                                         {11, 14},
                                         {12, 0},
                                         {13, 0},
                                         {14, 0},
                                         {15, 0},
                                         {16, 16},
                                         {17, 16},
                                         {18, 14},
                                         {19, 0}},
                },
            .txpwrlimit_config[8] =
                {
                    .num_mod_grps = 20,
                    .chan_desc =
                        {
                            .start_freq = 2407,
                            .chan_width = 20,
                            .chan_num   = 9,
                        },
                    .txpwrlimit_entry = {{0, 15},
                                         {1, 17},
                                         {2, 17},
                                         {3, 17},
                                         {4, 16},
                                         {5, 16},
                                         {6, 16},
                                         {7, 13},
                                         {8, 14},
                                         {9, 14},
                                         {10, 16},
                                         {11, 14},
                                         {12, 0},
                                         {13, 0},
                                         {14, 0},
                                         {15, 0},
                                         {16, 16},
                                         {17, 16},
                                         {18, 14},
                                         {19, 0}},
                },
            .txpwrlimit_config[9] =
                {
                    .num_mod_grps = 20,
                    .chan_desc =
                        {
                            .start_freq = 2407,
                            .chan_width = 20,
                            .chan_num   = 10,
                        },
                    .txpwrlimit_entry = {{0, 15},
                                         {1, 16},
                                         {2, 16},
                                         {3, 16},
                                         {4, 15},
                                         {5, 15},
                                         {6, 15},
                                         {7, 0},
                                         {8, 0},
                                         {9, 0},
                                         {10, 15},
                                         {11, 0},
                                         {12, 0},
                                         {13, 0},
                                         {14, 0},
                                         {15, 0},
                                         {16, 15},
                                         {17, 15},
                                         {18, 0},
                                         {19, 0}},
                },
            .txpwrlimit_config[10] =
                {
                    .num_mod_grps = 20,
                    .chan_desc =
                        {
                            .start_freq = 2407,
                            .chan_width = 20,
                            .chan_num   = 11,
                        },
                    .txpwrlimit_entry = {{0, 15},
                                         {1, 15},
                                         {2, 15},
                                         {3, 15},
                                         {4, 14},
                                         {5, 14},
                                         {6, 14},
                                         {7, 0},
                                         {8, 0},
                                         {9, 0},
                                         {10, 14},
                                         {11, 0},
                                         {12, 0},
                                         {13, 0},
                                         {14, 0},
                                         {15, 0},
                                         {16, 14},
                                         {17, 14},
                                         {18, 0},
                                         {19, 0}},
                },
            .txpwrlimit_config[11] =
                {
                    .num_mod_grps = 20,
                    .chan_desc =
                        {
                            .start_freq = 2407,
                            .chan_width = 20,
                            .chan_num   = 12,
                        },
                    .txpwrlimit_entry = {{0, 16},
                                         {1, 15},
                                         {2, 15},
                                         {3, 15},
                                         {4, 14},
                                         {5, 14},
                                         {6, 14},
                                         {7, 0},
                                         {8, 0},
                                         {9, 0},
                                         {10, 14},
                                         {11, 0},
                                         {12, 0},
                                         {13, 0},
                                         {14, 0},
                                         {15, 0},
                                         {16, 14},
                                         {17, 14},
                                         {18, 0},
                                         {19, 0}},
                },
            .txpwrlimit_config[12] =
                {
                    .num_mod_grps = 20,
                    .chan_desc =
                        {
                            .start_freq = 2407,
                            .chan_width = 20,
                            .chan_num   = 13,
                        },
                    .txpwrlimit_entry = {{0, 16},
                                         {1, 15},
                                         {2, 15},
                                         {3, 15},
                                         {4, 14},
                                         {5, 14},
                                         {6, 14},
                                         {7, 0},
                                         {8, 0},
                                         {9, 0},
                                         {10, 14},
                                         {11, 0},
                                         {12, 0},
                                         {13, 0},
                                         {14, 0},
                                         {15, 0},
                                         {16, 14},
                                         {17, 14},
                                         {18, 0},
                                         {19, 0}},
                },
            .txpwrlimit_config[13] =
                {
                    .num_mod_grps = 20,
                    .chan_desc =
                        {
                            .start_freq = 2414,
                            .chan_width = 20,
                            .chan_num   = 14,
                        },
                    .txpwrlimit_entry = {{0, 0},
                                         {1, 0},
                                         {2, 0},
                                         {3, 0},
                                         {4, 0},
                                         {5, 0},
                                         {6, 0},
                                         {7, 0},
                                         {8, 0},
                                         {9, 0},
                                         {10, 0},
                                         {11, 0},
                                         {12, 0},
                                         {13, 0},
                                         {14, 0},
                                         {15, 0},
                                         {16, 0},
                                         {17, 0},
                                         {18, 0},
                                         {19, 0}},
                },
        };

#ifdef CONFIG_5GHz_SUPPORT
static wifi_txpwrlimit_t
    tx_pwrlimit_5g_cfg =
        {
            .subband   = (wifi_SubBand_t)0x00,
            .num_chans = 25,
            .txpwrlimit_config[0] =
                {
                    .num_mod_grps = 19,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 36,
                        },
                    .txpwrlimit_entry = {{1, 19},
                                         {2, 19},
                                         {3, 19},
                                         {4, 19},
                                         {5, 19},
                                         {6, 19},
                                         {7, 19},
                                         {8, 19},
                                         {9, 18},
                                         {10, 19},
                                         {11, 18},
                                         {12, 17},
                                         {13, 17},
                                         {14, 17},
                                         {15, 16},
                                         {16, 18},
                                         {17, 17},
                                         {18, 15},
                                         {19, 13}},
                },
            .txpwrlimit_config[1] =
                {
                    .num_mod_grps = 19,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 40,
                        },
                    .txpwrlimit_entry = {{1, 19},
                                         {2, 19},
                                         {3, 19},
                                         {4, 19},
                                         {5, 19},
                                         {6, 19},
                                         {7, 19},
                                         {8, 19},
                                         {9, 18},
                                         {10, 19},
                                         {11, 18},
                                         {12, 17},
                                         {13, 17},
                                         {14, 17},
                                         {15, 16},
                                         {16, 18},
                                         {17, 17},
                                         {18, 15},
                                         {19, 13}},
                },
            .txpwrlimit_config[2] =
                {
                    .num_mod_grps = 19,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 44,
                        },
                    .txpwrlimit_entry = {{1, 19},
                                         {2, 19},
                                         {3, 19},
                                         {4, 19},
                                         {5, 19},
                                         {6, 19},
                                         {7, 19},
                                         {8, 19},
                                         {9, 18},
                                         {10, 19},
                                         {11, 18},
                                         {12, 17},
                                         {13, 17},
                                         {14, 17},
                                         {15, 16},
                                         {16, 18},
                                         {17, 17},
                                         {18, 15},
                                         {19, 13}},
                },
            .txpwrlimit_config[3] =
                {
                    .num_mod_grps = 19,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 48,
                        },
                    .txpwrlimit_entry = {{1, 19},
                                         {2, 19},
                                         {3, 19},
                                         {4, 19},
                                         {5, 19},
                                         {6, 19},
                                         {7, 19},
                                         {8, 19},
                                         {9, 18},
                                         {10, 19},
                                         {11, 18},
                                         {12, 17},
                                         {13, 17},
                                         {14, 17},
                                         {15, 16},
                                         {16, 18},
                                         {17, 17},
                                         {18, 15},
                                         {19, 13}},
                },
            .txpwrlimit_config[4] =
                {
                    .num_mod_grps = 19,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 52,
                        },
                    .txpwrlimit_entry = {{1, 19},
                                         {2, 19},
                                         {3, 19},
                                         {4, 19},
                                         {5, 19},
                                         {6, 19},
                                         {7, 19},
                                         {8, 19},
                                         {9, 18},
                                         {10, 19},
                                         {11, 18},
                                         {12, 16},
                                         {13, 16},
                                         {14, 16},
                                         {15, 16},
                                         {16, 18},
                                         {17, 17},
                                         {18, 15},
                                         {19, 13}},
                },
            .txpwrlimit_config[5] =
                {
                    .num_mod_grps = 19,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 56,
                        },
                    .txpwrlimit_entry = {{1, 19},
                                         {2, 19},
                                         {3, 19},
                                         {4, 19},
                                         {5, 19},
                                         {6, 19},
                                         {7, 19},
                                         {8, 19},
                                         {9, 18},
                                         {10, 19},
                                         {11, 18},
                                         {12, 16},
                                         {13, 16},
                                         {14, 16},
                                         {15, 16},
                                         {16, 18},
                                         {17, 17},
                                         {18, 15},
                                         {19, 13}},
                },
            .txpwrlimit_config[6] =
                {
                    .num_mod_grps = 19,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 60,
                        },
                    .txpwrlimit_entry = {{1, 19},
                                         {2, 19},
                                         {3, 19},
                                         {4, 19},
                                         {5, 19},
                                         {6, 19},
                                         {7, 18},
                                         {8, 18},
                                         {9, 18},
                                         {10, 19},
                                         {11, 18},
                                         {12, 16},
                                         {13, 16},
                                         {14, 16},
                                         {15, 16},
                                         {16, 18},
                                         {17, 17},
                                         {18, 15},
                                         {19, 13}},
                },
            .txpwrlimit_config[7] =
                {
                    .num_mod_grps = 19,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 64,
                        },
                    .txpwrlimit_entry = {{1, 19},
                                         {2, 19},
                                         {3, 19},
                                         {4, 18},
                                         {5, 18},
                                         {6, 18},
                                         {7, 18},
                                         {8, 18},
                                         {9, 18},
                                         {10, 18},
                                         {11, 18},
                                         {12, 16},
                                         {13, 16},
                                         {14, 16},
                                         {15, 16},
                                         {16, 18},
                                         {17, 17},
                                         {18, 15},
                                         {19, 13}},
                },
            .txpwrlimit_config[8] =
                {
                    .num_mod_grps = 19,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 100,
                        },
                    .txpwrlimit_entry = {{1, 18},
                                         {2, 18},
                                         {3, 17},
                                         {4, 17},
                                         {5, 17},
                                         {6, 16},
                                         {7, 15},
                                         {8, 15},
                                         {9, 15},
                                         {10, 16},
                                         {11, 15},
                                         {12, 13},
                                         {13, 13},
                                         {14, 13},
                                         {15, 13},
                                         {16, 15},
                                         {17, 14},
                                         {18, 14},
                                         {19, 12}},
                },
            .txpwrlimit_config[9] =
                {
                    .num_mod_grps = 19,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 104,
                        },
                    .txpwrlimit_entry = {{1, 18},
                                         {2, 18},
                                         {3, 17},
                                         {4, 18},
                                         {5, 18},
                                         {6, 16},
                                         {7, 15},
                                         {8, 15},
                                         {9, 15},
                                         {10, 16},
                                         {11, 15},
                                         {12, 13},
                                         {13, 13},
                                         {14, 13},
                                         {15, 13},
                                         {16, 15},
                                         {17, 14},
                                         {18, 14},
                                         {19, 12}},
                },
            .txpwrlimit_config[10] =
                {
                    .num_mod_grps = 19,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 108,
                        },
                    .txpwrlimit_entry = {{1, 18},
                                         {2, 18},
                                         {3, 17},
                                         {4, 18},
                                         {5, 18},
                                         {6, 16},
                                         {7, 18},
                                         {8, 18},
                                         {9, 16},
                                         {10, 16},
                                         {11, 15},
                                         {12, 13},
                                         {13, 13},
                                         {14, 13},
                                         {15, 13},
                                         {16, 15},
                                         {17, 14},
                                         {18, 14},
                                         {19, 12}},
                },
            .txpwrlimit_config[11] =
                {
                    .num_mod_grps = 19,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 112,
                        },
                    .txpwrlimit_entry = {{1, 18},
                                         {2, 18},
                                         {3, 17},
                                         {4, 18},
                                         {5, 18},
                                         {6, 16},
                                         {7, 18},
                                         {8, 18},
                                         {9, 16},
                                         {10, 16},
                                         {11, 15},
                                         {12, 13},
                                         {13, 13},
                                         {14, 13},
                                         {15, 13},
                                         {16, 15},
                                         {17, 14},
                                         {18, 14},
                                         {19, 12}},
                },
            .txpwrlimit_config[12] =
                {
                    .num_mod_grps = 19,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 116,
                        },
                    .txpwrlimit_entry = {{1, 18},
                                         {2, 18},
                                         {3, 17},
                                         {4, 18},
                                         {5, 18},
                                         {6, 16},
                                         {7, 18},
                                         {8, 18},
                                         {9, 16},
                                         {10, 16},
                                         {11, 15},
                                         {12, 18},
                                         {13, 18},
                                         {14, 15},
                                         {15, 15},
                                         {16, 15},
                                         {17, 14},
                                         {18, 14},
                                         {19, 12}},
                },
            .txpwrlimit_config[13] =
                {
                    .num_mod_grps = 19,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 120,
                        },
                    .txpwrlimit_entry = {{1, 18},
                                         {2, 18},
                                         {3, 17},
                                         {4, 18},
                                         {5, 18},
                                         {6, 16},
                                         {7, 18},
                                         {8, 18},
                                         {9, 16},
                                         {10, 16},
                                         {11, 15},
                                         {12, 18},
                                         {13, 18},
                                         {14, 15},
                                         {15, 15},
                                         {16, 15},
                                         {17, 14},
                                         {18, 14},
                                         {19, 12}},
                },
            .txpwrlimit_config[14] =
                {
                    .num_mod_grps = 19,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 124,
                        },
                    .txpwrlimit_entry = {{1, 19},
                                         {2, 19},
                                         {3, 19},
                                         {4, 19},
                                         {5, 19},
                                         {6, 18},
                                         {7, 18},
                                         {8, 19},
                                         {9, 18},
                                         {10, 18},
                                         {11, 17},
                                         {12, 18},
                                         {13, 18},
                                         {14, 16},
                                         {15, 15},
                                         {16, 17},
                                         {17, 16},
                                         {18, 15},
                                         {19, 11}},
                },
            .txpwrlimit_config[15] =
                {
                    .num_mod_grps = 19,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 128,
                        },
                    .txpwrlimit_entry = {{1, 19},
                                         {2, 19},
                                         {3, 19},
                                         {4, 19},
                                         {5, 19},
                                         {6, 18},
                                         {7, 18},
                                         {8, 19},
                                         {9, 18},
                                         {10, 18},
                                         {11, 17},
                                         {12, 18},
                                         {13, 18},
                                         {14, 16},
                                         {15, 15},
                                         {16, 17},
                                         {17, 16},
                                         {18, 15},
                                         {19, 11}},
                },
            .txpwrlimit_config[16] =
                {
                    .num_mod_grps = 19,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 132,
                        },
                    .txpwrlimit_entry = {{1, 19},
                                         {2, 19},
                                         {3, 19},
                                         {4, 19},
                                         {5, 19},
                                         {6, 18},
                                         {7, 18},
                                         {8, 19},
                                         {9, 18},
                                         {10, 18},
                                         {11, 17},
                                         {12, 18},
                                         {13, 18},
                                         {14, 16},
                                         {15, 15},
                                         {16, 17},
                                         {17, 16},
                                         {18, 15},
                                         {19, 11}},
                },
            .txpwrlimit_config[17] =
                {
                    .num_mod_grps = 19,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 136,
                        },
                    .txpwrlimit_entry = {{1, 19},
                                         {2, 19},
                                         {3, 19},
                                         {4, 19},
                                         {5, 19},
                                         {6, 18},
                                         {7, 18},
                                         {8, 19},
                                         {9, 18},
                                         {10, 18},
                                         {11, 17},
                                         {12, 18},
                                         {13, 18},
                                         {14, 16},
                                         {15, 15},
                                         {16, 17},
                                         {17, 16},
                                         {18, 15},
                                         {19, 11}},
                },
            .txpwrlimit_config[18] =
                {
                    .num_mod_grps = 19,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 140,
                        },
                    .txpwrlimit_entry = {{1, 19},
                                         {2, 19},
                                         {3, 19},
                                         {4, 19},
                                         {5, 19},
                                         {6, 18},
                                         {7, 18},
                                         {8, 19},
                                         {9, 18},
                                         {10, 18},
                                         {11, 17},
                                         {12, 18},
                                         {13, 18},
                                         {14, 16},
                                         {15, 15},
                                         {16, 17},
                                         {17, 16},
                                         {18, 15},
                                         {19, 11}},
                },
            .txpwrlimit_config[19] =
                {
                    .num_mod_grps = 19,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 144,
                        },
                    .txpwrlimit_entry = {{1, 19},
                                         {2, 19},
                                         {3, 19},
                                         {4, 19},
                                         {5, 19},
                                         {6, 18},
                                         {7, 18},
                                         {8, 19},
                                         {9, 18},
                                         {10, 18},
                                         {11, 17},
                                         {12, 18},
                                         {13, 18},
                                         {14, 16},
                                         {15, 15},
                                         {16, 17},
                                         {17, 16},
                                         {18, 15},
                                         {19, 11}},
                },
            .txpwrlimit_config[20] =
                {
                    .num_mod_grps = 19,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 149,
                        },
                    .txpwrlimit_entry = {{1, 16},
                                         {2, 16},
                                         {3, 16},
                                         {4, 15},
                                         {5, 15},
                                         {6, 15},
                                         {7, 14},
                                         {8, 14},
                                         {9, 14},
                                         {10, 15},
                                         {11, 14},
                                         {12, 14},
                                         {13, 14},
                                         {14, 14},
                                         {15, 14},
                                         {16, 15},
                                         {17, 15},
                                         {18, 13},
                                         {19, 11}},
                },
            .txpwrlimit_config[21] =
                {
                    .num_mod_grps = 19,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 153,
                        },
                    .txpwrlimit_entry = {{1, 19},
                                         {2, 19},
                                         {3, 19},
                                         {4, 19},
                                         {5, 19},
                                         {6, 18},
                                         {7, 14},
                                         {8, 19},
                                         {9, 18},
                                         {10, 17},
                                         {11, 17},
                                         {12, 14},
                                         {13, 14},
                                         {14, 14},
                                         {15, 14},
                                         {16, 17},
                                         {17, 16},
                                         {18, 13},
                                         {19, 11}},
                },
            .txpwrlimit_config[22] =
                {
                    .num_mod_grps = 19,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 157,
                        },
                    .txpwrlimit_entry = {{1, 19},
                                         {2, 19},
                                         {3, 19},
                                         {4, 19},
                                         {5, 19},
                                         {6, 18},
                                         {7, 19},
                                         {8, 19},
                                         {9, 18},
                                         {10, 17},
                                         {11, 17},
                                         {12, 14},
                                         {13, 14},
                                         {14, 14},
                                         {15, 14},
                                         {16, 17},
                                         {17, 16},
                                         {18, 13},
                                         {19, 11}},
                },
            .txpwrlimit_config[23] =
                {
                    .num_mod_grps = 19,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 161,
                        },
                    .txpwrlimit_entry = {{1, 18},
                                         {2, 18},
                                         {3, 18},
                                         {4, 18},
                                         {5, 18},
                                         {6, 18},
                                         {7, 19},
                                         {8, 19},
                                         {9, 18},
                                         {10, 17},
                                         {11, 17},
                                         {12, 14},
                                         {13, 14},
                                         {14, 14},
                                         {15, 14},
                                         {16, 17},
                                         {17, 16},
                                         {18, 13},
                                         {19, 11}},
                },
            .txpwrlimit_config[24] =
                {
                    .num_mod_grps = 19,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 165,
                        },
                    .txpwrlimit_entry = {{1, 15},
                                         {2, 15},
                                         {3, 15},
                                         {4, 15},
                                         {5, 15},
                                         {6, 15},
                                         {7, 14},
                                         {8, 14},
                                         {9, 14},
                                         {10, 15},
                                         {11, 14},
                                         {12, 14},
                                         {13, 14},
                                         {14, 14},
                                         {15, 14},
                                         {16, 15},
                                         {17, 15},
                                         {18, 13},
                                         {19, 11}},
                },
};
#endif /* CONFIG_5GHz_SUPPORT */
#elif defined(CONFIG_11AC)
static wifi_txpwrlimit_t
    tx_pwrlimit_2g_cfg =
        {
            .subband   = (wifi_SubBand_t)0x00,
            .num_chans = 14,
            .txpwrlimit_config[0] =
                {
                    .num_mod_grps = 12,
                    .chan_desc =
                        {
                            .start_freq = 2407,
                            .chan_width = 20,
                            .chan_num   = 1,
                        },
                    .txpwrlimit_entry = {{0, 18},
                                         {1, 18},
                                         {2, 16},
                                         {3, 14},
                                         {4, 18},
                                         {5, 16},
                                         {6, 14},
                                         {7, 18},
                                         {8, 16},
                                         {9, 14},
                                         {10, 16},
                                         {11, 16}},
                },
            .txpwrlimit_config[1] =
                {
                    .num_mod_grps = 12,
                    .chan_desc =
                        {
                            .start_freq = 2407,
                            .chan_width = 20,
                            .chan_num   = 2,
                        },
                    .txpwrlimit_entry = {{0, 18},
                                         {1, 18},
                                         {2, 16},
                                         {3, 14},
                                         {4, 18},
                                         {5, 16},
                                         {6, 14},
                                         {7, 18},
                                         {8, 16},
                                         {9, 14},
                                         {10, 16},
                                         {11, 16}},
                },
            .txpwrlimit_config[2] =
                {
                    .num_mod_grps = 12,
                    .chan_desc =
                        {
                            .start_freq = 2407,
                            .chan_width = 20,
                            .chan_num   = 3,
                        },
                    .txpwrlimit_entry = {{0, 18},
                                         {1, 18},
                                         {2, 16},
                                         {3, 14},
                                         {4, 18},
                                         {5, 16},
                                         {6, 14},
                                         {7, 18},
                                         {8, 16},
                                         {9, 14},
                                         {10, 16},
                                         {11, 16}},
                },
            .txpwrlimit_config[3] =
                {
                    .num_mod_grps = 12,
                    .chan_desc =
                        {
                            .start_freq = 2407,
                            .chan_width = 20,
                            .chan_num   = 4,
                        },
                    .txpwrlimit_entry = {{0, 18},
                                         {1, 18},
                                         {2, 16},
                                         {3, 14},
                                         {4, 18},
                                         {5, 16},
                                         {6, 14},
                                         {7, 18},
                                         {8, 16},
                                         {9, 14},
                                         {10, 16},
                                         {11, 16}},
                },
            .txpwrlimit_config[4] =
                {
                    .num_mod_grps = 12,
                    .chan_desc =
                        {
                            .start_freq = 2407,
                            .chan_width = 20,
                            .chan_num   = 5,
                        },
                    .txpwrlimit_entry = {{0, 18},
                                         {1, 18},
                                         {2, 16},
                                         {3, 14},
                                         {4, 18},
                                         {5, 16},
                                         {6, 14},
                                         {7, 18},
                                         {8, 16},
                                         {9, 14},
                                         {10, 16},
                                         {11, 16}},
                },
            .txpwrlimit_config[5] =
                {
                    .num_mod_grps = 12,
                    .chan_desc =
                        {
                            .start_freq = 2407,
                            .chan_width = 20,
                            .chan_num   = 6,
                        },
                    .txpwrlimit_entry = {{0, 18},
                                         {1, 18},
                                         {2, 16},
                                         {3, 14},
                                         {4, 18},
                                         {5, 16},
                                         {6, 14},
                                         {7, 18},
                                         {8, 16},
                                         {9, 14},
                                         {10, 16},
                                         {11, 16}},
                },
            .txpwrlimit_config[6] =
                {
                    .num_mod_grps = 12,
                    .chan_desc =
                        {
                            .start_freq = 2407,
                            .chan_width = 20,
                            .chan_num   = 7,
                        },
                    .txpwrlimit_entry = {{0, 18},
                                         {1, 18},
                                         {2, 16},
                                         {3, 14},
                                         {4, 18},
                                         {5, 16},
                                         {6, 14},
                                         {7, 18},
                                         {8, 16},
                                         {9, 14},
                                         {10, 16},
                                         {11, 16}},
                },
            .txpwrlimit_config[7] =
                {
                    .num_mod_grps = 12,
                    .chan_desc =
                        {
                            .start_freq = 2407,
                            .chan_width = 20,
                            .chan_num   = 8,
                        },
                    .txpwrlimit_entry = {{0, 18},
                                         {1, 18},
                                         {2, 16},
                                         {3, 14},
                                         {4, 18},
                                         {5, 16},
                                         {6, 14},
                                         {7, 18},
                                         {8, 16},
                                         {9, 14},
                                         {10, 16},
                                         {11, 16}},
                },
            .txpwrlimit_config[8] =
                {
                    .num_mod_grps = 12,
                    .chan_desc =
                        {
                            .start_freq = 2407,
                            .chan_width = 20,
                            .chan_num   = 9,
                        },
                    .txpwrlimit_entry = {{0, 18},
                                         {1, 18},
                                         {2, 16},
                                         {3, 14},
                                         {4, 18},
                                         {5, 16},
                                         {6, 14},
                                         {7, 18},
                                         {8, 16},
                                         {9, 14},
                                         {10, 16},
                                         {11, 16}},
                },
            .txpwrlimit_config[9] =
                {
                    .num_mod_grps = 12,
                    .chan_desc =
                        {
                            .start_freq = 2407,
                            .chan_width = 20,
                            .chan_num   = 10,
                        },
                    .txpwrlimit_entry = {{0, 18},
                                         {1, 18},
                                         {2, 16},
                                         {3, 14},
                                         {4, 18},
                                         {5, 16},
                                         {6, 14},
                                         {7, 18},
                                         {8, 16},
                                         {9, 14},
                                         {10, 16},
                                         {11, 16}},
                },
            .txpwrlimit_config[10] =
                {
                    .num_mod_grps = 12,
                    .chan_desc =
                        {
                            .start_freq = 2407,
                            .chan_width = 20,
                            .chan_num   = 11,
                        },
                    .txpwrlimit_entry = {{0, 18},
                                         {1, 18},
                                         {2, 16},
                                         {3, 14},
                                         {4, 18},
                                         {5, 16},
                                         {6, 14},
                                         {7, 18},
                                         {8, 16},
                                         {9, 14},
                                         {10, 16},
                                         {11, 16}},
                },
            .txpwrlimit_config[11] =
                {
                    .num_mod_grps = 12,
                    .chan_desc =
                        {
                            .start_freq = 2407,
                            .chan_width = 20,
                            .chan_num   = 12,
                        },
                    .txpwrlimit_entry = {{0, 16},
                                         {1, 16},
                                         {2, 16},
                                         {3, 14},
                                         {4, 16},
                                         {5, 16},
                                         {6, 14},
                                         {7, 16},
                                         {8, 16},
                                         {9, 14},
                                         {10, 16},
                                         {11, 16}},
                },
            .txpwrlimit_config[12] =
                {
                    .num_mod_grps = 12,
                    .chan_desc =
                        {
                            .start_freq = 2407,
                            .chan_width = 20,
                            .chan_num   = 13,
                        },
                    .txpwrlimit_entry = {{0, 16},
                                         {1, 16},
                                         {2, 16},
                                         {3, 14},
                                         {4, 16},
                                         {5, 16},
                                         {6, 14},
                                         {7, 16},
                                         {8, 16},
                                         {9, 14},
                                         {10, 16},
                                         {11, 16}},
                },
            .txpwrlimit_config[13] =
                {
                    .num_mod_grps = 12,
                    .chan_desc =
                        {
                            .start_freq = 2414,
                            .chan_width = 20,
                            .chan_num   = 14,
                        },
                    .txpwrlimit_entry = {{0, 12},
                                         {1, 12},
                                         {2, 12},
                                         {3, 12},
                                         {4, 12},
                                         {5, 12},
                                         {6, 12},
                                         {7, 12},
                                         {8, 12},
                                         {9, 12},
                                         {10, 12},
                                         {11, 12}},
                },
};

#ifdef CONFIG_5GHz_SUPPORT
static wifi_txpwrlimit_t
    tx_pwrlimit_5g_cfg =
        {
            .subband   = (wifi_SubBand_t)0x00,
            .num_chans = 39,
            .txpwrlimit_config[0] =
                {
                    .num_mod_grps = 16,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 36,
                        },
                    .txpwrlimit_entry = {{0, 0},
                                         {1, 16},
                                         {2, 16},
                                         {3, 14},
                                         {4, 16},
                                         {5, 16},
                                         {6, 14},
                                         {7, 16},
                                         {8, 16},
                                         {9, 14},
                                         {10, 15},
                                         {11, 14},
                                         {12, 15},
                                         {13, 15},
                                         {14, 14},
                                         {15, 13}},
                },
            .txpwrlimit_config[1] =
                {
                    .num_mod_grps = 16,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 40,
                        },
                    .txpwrlimit_entry = {{0, 0},
                                         {1, 16},
                                         {2, 16},
                                         {3, 14},
                                         {4, 16},
                                         {5, 16},
                                         {6, 14},
                                         {7, 16},
                                         {8, 16},
                                         {9, 14},
                                         {10, 15},
                                         {11, 14},
                                         {12, 15},
                                         {13, 15},
                                         {14, 14},
                                         {15, 13}},
                },
            .txpwrlimit_config[2] =
                {
                    .num_mod_grps = 16,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 44,
                        },
                    .txpwrlimit_entry = {{0, 0},
                                         {1, 16},
                                         {2, 16},
                                         {3, 14},
                                         {4, 16},
                                         {5, 16},
                                         {6, 14},
                                         {7, 16},
                                         {8, 16},
                                         {9, 14},
                                         {10, 15},
                                         {11, 14},
                                         {12, 15},
                                         {13, 15},
                                         {14, 14},
                                         {15, 13}},
                },
            .txpwrlimit_config[3] =
                {
                    .num_mod_grps = 16,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 48,
                        },
                    .txpwrlimit_entry = {{0, 0},
                                         {1, 16},
                                         {2, 16},
                                         {3, 14},
                                         {4, 16},
                                         {5, 16},
                                         {6, 14},
                                         {7, 16},
                                         {8, 16},
                                         {9, 14},
                                         {10, 15},
                                         {11, 14},
                                         {12, 15},
                                         {13, 15},
                                         {14, 14},
                                         {15, 13}},
                },
            .txpwrlimit_config[4] =
                {
                    .num_mod_grps = 16,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 52,
                        },
                    .txpwrlimit_entry = {{0, 0},
                                         {1, 17},
                                         {2, 16},
                                         {3, 14},
                                         {4, 17},
                                         {5, 16},
                                         {6, 14},
                                         {7, 17},
                                         {8, 16},
                                         {9, 14},
                                         {10, 15},
                                         {11, 14},
                                         {12, 15},
                                         {13, 15},
                                         {14, 14},
                                         {15, 13}},
                },
            .txpwrlimit_config[5] =
                {
                    .num_mod_grps = 16,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 56,
                        },
                    .txpwrlimit_entry = {{0, 0},
                                         {1, 17},
                                         {2, 16},
                                         {3, 14},
                                         {4, 17},
                                         {5, 16},
                                         {6, 14},
                                         {7, 17},
                                         {8, 16},
                                         {9, 14},
                                         {10, 15},
                                         {11, 14},
                                         {12, 15},
                                         {13, 15},
                                         {14, 14},
                                         {15, 13}},
                },
            .txpwrlimit_config[6] =
                {
                    .num_mod_grps = 16,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 60,
                        },
                    .txpwrlimit_entry = {{0, 0},
                                         {1, 17},
                                         {2, 16},
                                         {3, 14},
                                         {4, 17},
                                         {5, 16},
                                         {6, 14},
                                         {7, 17},
                                         {8, 16},
                                         {9, 14},
                                         {10, 15},
                                         {11, 14},
                                         {12, 15},
                                         {13, 15},
                                         {14, 14},
                                         {15, 13}},
                },
            .txpwrlimit_config[7] =
                {
                    .num_mod_grps = 16,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 64,
                        },
                    .txpwrlimit_entry =
                        {{0, 0},
                         {1, 17},
                         {2, 16},
                         {3, 14},
                         {4, 17},
                         {5, 16},
                         {6, 14},
                         {7, 17},
                         {8, 16},
                         {9, 14},
                         {10, 15},
                         {11, 14},
                         {12, 15},
                         {13, 15},
                         {14, 14},
                         {15, 13}},
                },
            .txpwrlimit_config[8] =
                {
                    .num_mod_grps = 16,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 100,
                        },
                    .txpwrlimit_entry =
                        {{0, 0},
                         {1, 17},
                         {2, 16},
                         {3, 14},
                         {4, 17},
                         {5, 16},
                         {6, 14},
                         {7, 17},
                         {8, 16},
                         {9, 14},
                         {10, 15},
                         {11, 14},
                         {12, 15},
                         {13, 15},
                         {14, 14},
                         {15, 13}},
                },
            .txpwrlimit_config[9] =
                {
                    .num_mod_grps = 16,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 104,
                        },
                    .txpwrlimit_entry =
                        {{0, 0},
                         {1, 17},
                         {2, 16},
                         {3, 14},
                         {4, 17},
                         {5, 16},
                         {6, 14},
                         {7, 17},
                         {8, 16},
                         {9, 14},
                         {10, 15},
                         {11, 14},
                         {12, 15},
                         {13, 15},
                         {14, 14},
                         {15, 13}},
                },
            .txpwrlimit_config[10] =
                {
                    .num_mod_grps = 16,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 108,
                        },
                    .txpwrlimit_entry =
                        {{0, 0},
                         {1, 17},
                         {2, 16},
                         {3, 14},
                         {4, 17},
                         {5, 16},
                         {6, 14},
                         {7, 17},
                         {8, 16},
                         {9, 14},
                         {10, 15},
                         {11, 14},
                         {12, 15},
                         {13, 15},
                         {14, 14},
                         {15, 13}},
                },
            .txpwrlimit_config[11] =
                {
                    .num_mod_grps = 16,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 112,
                        },
                    .txpwrlimit_entry =
                        {{0, 0},
                         {1, 17},
                         {2, 16},
                         {3, 14},
                         {4, 17},
                         {5, 16},
                         {6, 14},
                         {7, 17},
                         {8, 16},
                         {9, 14},
                         {10, 15},
                         {11, 14},
                         {12, 15},
                         {13, 15},
                         {14, 14},
                         {15, 13}},
                },
            .txpwrlimit_config[12] =
                {
                    .num_mod_grps = 16,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 116,
                        },
                    .txpwrlimit_entry =
                        {{0, 0},
                         {1, 17},
                         {2, 16},
                         {3, 14},
                         {4, 17},
                         {5, 16},
                         {6, 14},
                         {7, 17},
                         {8, 16},
                         {9, 14},
                         {10, 15},
                         {11, 14},
                         {12, 15},
                         {13, 15},
                         {14, 14},
                         {15, 13}},
                },
            .txpwrlimit_config[13] =
                {
                    .num_mod_grps = 16,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 120,
                        },
                    .txpwrlimit_entry =
                        {{0, 0},
                         {1, 17},
                         {2, 16},
                         {3, 14},
                         {4, 17},
                         {5, 16},
                         {6, 14},
                         {7, 17},
                         {8, 16},
                         {9, 14},
                         {10, 15},
                         {11, 14},
                         {12, 15},
                         {13, 15},
                         {14, 14},
                         {15, 13}},
                },
            .txpwrlimit_config[14] =
                {
                    .num_mod_grps = 16,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 124,
                        },
                    .txpwrlimit_entry =
                        {{0, 0},
                         {1, 17},
                         {2, 16},
                         {3, 14},
                         {4, 17},
                         {5, 16},
                         {6, 14},
                         {7, 17},
                         {8, 16},
                         {9, 14},
                         {10, 15},
                         {11, 14},
                         {12, 15},
                         {13, 15},
                         {14, 14},
                         {15, 13}},
                },
            .txpwrlimit_config[15] =
                {
                    .num_mod_grps = 16,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 128,
                        },
                    .txpwrlimit_entry =
                        {{0, 0},
                         {1, 17},
                         {2, 16},
                         {3, 14},
                         {4, 17},
                         {5, 16},
                         {6, 14},
                         {7, 17},
                         {8, 16},
                         {9, 14},
                         {10, 15},
                         {11, 14},
                         {12, 15},
                         {13, 15},
                         {14, 14},
                         {15, 13}},
                },
            .txpwrlimit_config[16] =
                {
                    .num_mod_grps = 16,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 132,
                        },
                    .txpwrlimit_entry =
                        {{0, 0},
                         {1, 17},
                         {2, 16},
                         {3, 14},
                         {4, 17},
                         {5, 16},
                         {6, 14},
                         {7, 17},
                         {8, 16},
                         {9, 14},
                         {10, 15},
                         {11, 14},
                         {12, 15},
                         {13, 15},
                         {14, 14},
                         {15, 13}},
                },
            .txpwrlimit_config[17] =
                {
                    .num_mod_grps = 16,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 136,
                        },
                    .txpwrlimit_entry =
                        {{0, 0},
                         {1, 17},
                         {2, 16},
                         {3, 14},
                         {4, 17},
                         {5, 16},
                         {6, 14},
                         {7, 17},
                         {8, 16},
                         {9, 14},
                         {10, 15},
                         {11, 14},
                         {12, 15},
                         {13, 15},
                         {14, 14},
                         {15, 13}},
                },
            .txpwrlimit_config[18] =
                {
                    .num_mod_grps = 16,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 140,
                        },
                    .txpwrlimit_entry =
                        {{0, 0},
                         {1, 17},
                         {2, 16},
                         {3, 14},
                         {4, 17},
                         {5, 16},
                         {6, 14},
                         {7, 17},
                         {8, 16},
                         {9, 14},
                         {10, 15},
                         {11, 14},
                         {12, 15},
                         {13, 15},
                         {14, 14},
                         {15, 13}},
                },
            .txpwrlimit_config[19] =
                {
                    .num_mod_grps = 16,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 144,
                        },
                    .txpwrlimit_entry =
                        {{0, 0},
                         {1, 17},
                         {2, 16},
                         {3, 14},
                         {4, 17},
                         {5, 16},
                         {6, 14},
                         {7, 17},
                         {8, 16},
                         {9, 14},
                         {10, 15},
                         {11, 14},
                         {12, 15},
                         {13, 15},
                         {14, 14},
                         {15, 13}},
                },
            .txpwrlimit_config[20] =
                {
                    .num_mod_grps = 16,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 149,
                        },
                    .txpwrlimit_entry =
                        {{0, 0},
                         {1, 17},
                         {2, 16},
                         {3, 14},
                         {4, 17},
                         {5, 16},
                         {6, 14},
                         {7, 17},
                         {8, 16},
                         {9, 14},
                         {10, 15},
                         {11, 14},
                         {12, 15},
                         {13, 15},
                         {14, 14},
                         {15, 13}},
                },
            .txpwrlimit_config[21] =
                {
                    .num_mod_grps = 16,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 153,
                        },
                    .txpwrlimit_entry =
                        {{0, 0},
                         {1, 17},
                         {2, 16},
                         {3, 14},
                         {4, 17},
                         {5, 16},
                         {6, 14},
                         {7, 17},
                         {8, 16},
                         {9, 14},
                         {10, 15},
                         {11, 14},
                         {12, 15},
                         {13, 15},
                         {14, 14},
                         {15, 13}},
                },
            .txpwrlimit_config[22] =
                {
                    .num_mod_grps = 16,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 157,
                        },
                    .txpwrlimit_entry =
                        {{0, 0},
                         {1, 17},
                         {2, 16},
                         {3, 14},
                         {4, 17},
                         {5, 16},
                         {6, 14},
                         {7, 17},
                         {8, 16},
                         {9, 14},
                         {10, 15},
                         {11, 14},
                         {12, 15},
                         {13, 15},
                         {14, 14},
                         {15, 13}},
                },
            .txpwrlimit_config[23] =
                {
                    .num_mod_grps = 16,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 161,
                        },
                    .txpwrlimit_entry =
                        {{0, 0},
                         {1, 17},
                         {2, 16},
                         {3, 14},
                         {4, 17},
                         {5, 16},
                         {6, 14},
                         {7, 17},
                         {8, 16},
                         {9, 14},
                         {10, 15},
                         {11, 14},
                         {12, 15},
                         {13, 15},
                         {14, 14},
                         {15, 13}},
                },
            .txpwrlimit_config[24] =
                {
                    .num_mod_grps = 16,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 165,
                        },
                    .txpwrlimit_entry =
                        {{0, 0},
                         {1, 17},
                         {2, 16},
                         {3, 14},
                         {4, 17},
                         {5, 16},
                         {6, 14},
                         {7, 17},
                         {8, 16},
                         {9, 14},
                         {10, 15},
                         {11, 14},
                         {12, 15},
                         {13, 15},
                         {14, 14},
                         {15, 13}},
                },
            .txpwrlimit_config[25] =
                {
                    .num_mod_grps = 16,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 183,
                        },
                    .txpwrlimit_entry =
                        {{0, 0},
                         {1, 17},
                         {2, 16},
                         {3, 14},
                         {4, 17},
                         {5, 16},
                         {6, 14},
                         {7, 17},
                         {8, 16},
                         {9, 14},
                         {10, 15},
                         {11, 14},
                         {12, 15},
                         {13, 15},
                         {14, 14},
                         {15, 13}},
                },
            .txpwrlimit_config[26] =
                {
                    .num_mod_grps = 16,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 184,
                        },
                    .txpwrlimit_entry =
                        {{0, 0},
                         {1, 17},
                         {2, 16},
                         {3, 14},
                         {4, 17},
                         {5, 16},
                         {6, 14},
                         {7, 17},
                         {8, 16},
                         {9, 14},
                         {10, 15},
                         {11, 14},
                         {12, 15},
                         {13, 15},
                         {14, 14},
                         {15, 13}},
                },
            .txpwrlimit_config[27] =
                {
                    .num_mod_grps = 16,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 185,
                        },
                    .txpwrlimit_entry =
                        {{0, 0},
                         {1, 17},
                         {2, 16},
                         {3, 14},
                         {4, 17},
                         {5, 16},
                         {6, 14},
                         {7, 17},
                         {8, 16},
                         {9, 14},
                         {10, 15},
                         {11, 14},
                         {12, 15},
                         {13, 15},
                         {14, 14},
                         {15, 13}},
                },
            .txpwrlimit_config[28] =
                {
                    .num_mod_grps = 16,
                    .chan_desc    = {.start_freq = 5000, .chan_width = 20, .chan_num = 187},
                    .txpwrlimit_entry =
                        {{0, 0},
                         {1, 17},
                         {2, 16},
                         {3, 14},
                         {4, 17},
                         {5, 16},
                         {6, 14},
                         {7, 17},
                         {8, 16},
                         {9, 14},
                         {10, 15},
                         {11, 14},
                         {12, 15},
                         {13, 15},
                         {14, 14},
                         {15, 13}},
                },
            .txpwrlimit_config[29] =
                {
                    .num_mod_grps = 16,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 188,
                        },
                    .txpwrlimit_entry =
                        {{0, 0},
                         {1, 17},
                         {2, 16},
                         {3, 14},
                         {4, 17},
                         {5, 16},
                         {6, 14},
                         {7, 17},
                         {8, 16},
                         {9, 14},
                         {10, 15},
                         {11, 14},
                         {12, 15},
                         {13, 15},
                         {14, 14},
                         {15, 13}},
                },
            .txpwrlimit_config[30] =
                {
                    .num_mod_grps = 16,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 189,
                        },
                    .txpwrlimit_entry =
                        {{0, 0},
                         {1, 17},
                         {2, 16},
                         {3, 14},
                         {4, 17},
                         {5, 16},
                         {6, 14},
                         {7, 17},
                         {8, 16},
                         {9, 14},
                         {10, 15},
                         {11, 14},
                         {12, 15},
                         {13, 15},
                         {14, 14},
                         {15, 13}},
                },
            .txpwrlimit_config[31] =
                {
                    .num_mod_grps = 16,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 192,
                        },
                    .txpwrlimit_entry =
                        {{0, 0},
                         {1, 17},
                         {2, 16},
                         {3, 14},
                         {4, 17},
                         {5, 16},
                         {6, 14},
                         {7, 17},
                         {8, 16},
                         {9, 14},
                         {10, 15},
                         {11, 14},
                         {12, 15},
                         {13, 15},
                         {14, 14},
                         {15, 13}},
                },
            .txpwrlimit_config[32] =
                {
                    .num_mod_grps = 16,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 196,
                        },
                    .txpwrlimit_entry =
                        {{0, 0},
                         {1, 17},
                         {2, 16},
                         {3, 14},
                         {4, 17},
                         {5, 16},
                         {6, 14},
                         {7, 17},
                         {8, 16},
                         {9, 14},
                         {10, 15},
                         {11, 14},
                         {12, 15},
                         {13, 15},
                         {14, 14},
                         {15, 13}},
                },
            .txpwrlimit_config[33] =
                {
                    .num_mod_grps = 16,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 7,
                        },
                    .txpwrlimit_entry =
                        {{0, 0},
                         {1, 17},
                         {2, 16},
                         {3, 14},
                         {4, 17},
                         {5, 16},
                         {6, 14},
                         {7, 17},
                         {8, 16},
                         {9, 14},
                         {10, 15},
                         {11, 14},
                         {12, 15},
                         {13, 15},
                         {14, 14},
                         {15, 13}},
                },
            .txpwrlimit_config[34] =
                {
                    .num_mod_grps = 16,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 8,
                        },
                    .txpwrlimit_entry =
                        {{0, 0},
                         {1, 17},
                         {2, 16},
                         {3, 14},
                         {4, 17},
                         {5, 16},
                         {6, 14},
                         {7, 17},
                         {8, 16},
                         {9, 14},
                         {10, 15},
                         {11, 14},
                         {12, 15},
                         {13, 15},
                         {14, 14},
                         {15, 13}},
                },
            .txpwrlimit_config[35] =
                {
                    .num_mod_grps = 16,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 11,
                        },
                    .txpwrlimit_entry =
                        {{0, 0},
                         {1, 17},
                         {2, 16},
                         {3, 14},
                         {4, 17},
                         {5, 16},
                         {6, 14},
                         {7, 17},
                         {8, 16},
                         {9, 14},
                         {10, 15},
                         {11, 14},
                         {12, 15},
                         {13, 15},
                         {14, 14},
                         {15, 13}},
                },
            .txpwrlimit_config[36] =
                {
                    .num_mod_grps = 16,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 12,
                        },
                    .txpwrlimit_entry =
                        {{0, 0},
                         {1, 17},
                         {2, 16},
                         {3, 14},
                         {4, 17},
                         {5, 16},
                         {6, 14},
                         {7, 17},
                         {8, 16},
                         {9, 14},
                         {10, 15},
                         {11, 14},
                         {12, 15},
                         {13, 15},
                         {14, 14},
                         {15, 13}},
                },
            .txpwrlimit_config[37] =
                {
                    .num_mod_grps = 16,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 16,
                        },
                    .txpwrlimit_entry =
                        {{0, 0},
                         {1, 17},
                         {2, 16},
                         {3, 14},
                         {4, 17},
                         {5, 16},
                         {6, 14},
                         {7, 17},
                         {8, 16},
                         {9, 14},
                         {10, 15},
                         {11, 14},
                         {12, 15},
                         {13, 15},
                         {14, 14},
                         {15, 13}},
                },
            .txpwrlimit_config[38] =
                {
                    .num_mod_grps = 16,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 34,
                        },
                    .txpwrlimit_entry =
                        {{0, 0},
                         {1, 17},
                         {2, 16},
                         {3, 14},
                         {4, 17},
                         {5, 16},
                         {6, 14},
                         {7, 17},
                         {8, 16},
                         {9, 14},
                         {10, 15},
                         {11, 14},
                         {12, 15},
                         {13, 15},
                         {14, 14},
                         {15, 13}},
                },
};
#endif /* CONFIG_5GHz_SUPPORT */
#else
static wifi_txpwrlimit_t tx_pwrlimit_2g_cfg =
    {
        .subband   = (wifi_SubBand_t)0x00,
        .num_chans = 14,
        .txpwrlimit_config[0] =
            {
                .num_mod_grps = 10,
                .chan_desc =
                    {
                        .start_freq = 2407,
                        .chan_width = 20,
                        .chan_num   = 1,
                    },
                .txpwrlimit_entry = {{0, 8}, {1, 8}, {2, 8}, {3, 8}, {4, 8}, {5, 8}, {6, 8}, {7, 8}, {8, 8}, {9, 8}},
            },
        .txpwrlimit_config[1] =
            {
                .num_mod_grps = 10,
                .chan_desc =
                    {
                        .start_freq = 2407,
                        .chan_width = 20,
                        .chan_num   = 2,
                    },
                .txpwrlimit_entry = {{0, 8}, {1, 8}, {2, 8}, {3, 8}, {4, 8}, {5, 8}, {6, 8}, {7, 8}, {8, 8}, {9, 8}},
            },
        .txpwrlimit_config[2] =
            {
                .num_mod_grps = 10,
                .chan_desc =
                    {
                        .start_freq = 2407,
                        .chan_width = 20,
                        .chan_num   = 3,
                    },
                .txpwrlimit_entry = {{0, 8}, {1, 8}, {2, 8}, {3, 8}, {4, 8}, {5, 8}, {6, 8}, {7, 8}, {8, 8}, {9, 8}},
            },
        .txpwrlimit_config[3] =
            {
                .num_mod_grps = 10,
                .chan_desc =
                    {
                        .start_freq = 2407,
                        .chan_width = 20,
                        .chan_num   = 4,
                    },
                .txpwrlimit_entry = {{0, 8}, {1, 8}, {2, 8}, {3, 8}, {4, 8}, {5, 8}, {6, 8}, {7, 8}, {8, 8}, {9, 8}},
            },
        .txpwrlimit_config[4] =
            {
                .num_mod_grps = 10,
                .chan_desc =
                    {
                        .start_freq = 2407,
                        .chan_width = 20,
                        .chan_num   = 5,
                    },
                .txpwrlimit_entry = {{0, 8}, {1, 8}, {2, 8}, {3, 8}, {4, 8}, {5, 8}, {6, 8}, {7, 8}, {8, 8}, {9, 8}},
            },
        .txpwrlimit_config[5] =
            {
                .num_mod_grps = 10,
                .chan_desc =
                    {
                        .start_freq = 2407,
                        .chan_width = 20,
                        .chan_num   = 6,
                    },
                .txpwrlimit_entry = {{0, 8}, {1, 8}, {2, 8}, {3, 8}, {4, 8}, {5, 8}, {6, 8}, {7, 8}, {8, 8}, {9, 8}},
            },
        .txpwrlimit_config[6] =
            {
                .num_mod_grps = 10,
                .chan_desc =
                    {
                        .start_freq = 2407,
                        .chan_width = 20,
                        .chan_num   = 7,
                    },
                .txpwrlimit_entry = {{0, 8}, {1, 8}, {2, 8}, {3, 8}, {4, 8}, {5, 8}, {6, 8}, {7, 8}, {8, 8}, {9, 8}},
            },
        .txpwrlimit_config[7] =
            {
                .num_mod_grps = 10,
                .chan_desc =
                    {
                        .start_freq = 2407,
                        .chan_width = 20,
                        .chan_num   = 8,
                    },
                .txpwrlimit_entry = {{0, 8}, {1, 8}, {2, 8}, {3, 8}, {4, 8}, {5, 8}, {6, 8}, {7, 8}, {8, 8}, {9, 8}},
            },
        .txpwrlimit_config[8] =
            {
                .num_mod_grps = 10,
                .chan_desc =
                    {
                        .start_freq = 2407,
                        .chan_width = 20,
                        .chan_num   = 9,
                    },
                .txpwrlimit_entry = {{0, 8}, {1, 8}, {2, 8}, {3, 8}, {4, 8}, {5, 8}, {6, 8}, {7, 8}, {8, 8}, {9, 8}},
            },
        .txpwrlimit_config[9] =
            {
                .num_mod_grps = 10,
                .chan_desc =
                    {
                        .start_freq = 2407,
                        .chan_width = 20,
                        .chan_num   = 10,
                    },
                .txpwrlimit_entry = {{0, 8}, {1, 8}, {2, 8}, {3, 8}, {4, 8}, {5, 8}, {6, 8}, {7, 8}, {8, 8}, {9, 8}},
            },
        .txpwrlimit_config[10] =
            {
                .num_mod_grps = 10,
                .chan_desc =
                    {
                        .start_freq = 2407,
                        .chan_width = 20,
                        .chan_num   = 11,
                    },
                .txpwrlimit_entry = {{0, 8}, {1, 8}, {2, 8}, {3, 8}, {4, 8}, {5, 8}, {6, 8}, {7, 8}, {8, 8}, {9, 8}},
            },
        .txpwrlimit_config[11] =
            {
                .num_mod_grps = 10,
                .chan_desc =
                    {
                        .start_freq = 2407,
                        .chan_width = 20,
                        .chan_num   = 12,
                    },
                .txpwrlimit_entry = {{0, 8}, {1, 8}, {2, 8}, {3, 8}, {4, 8}, {5, 8}, {6, 8}, {7, 8}, {8, 8}, {9, 8}},
            },
        .txpwrlimit_config[12] =
            {
                .num_mod_grps = 10,
                .chan_desc =
                    {
                        .start_freq = 2407,
                        .chan_width = 20,
                        .chan_num   = 13,
                    },
                .txpwrlimit_entry = {{0, 8}, {1, 8}, {2, 8}, {3, 8}, {4, 8}, {5, 8}, {6, 8}, {7, 8}, {8, 8}, {9, 8}},
            },
        .txpwrlimit_config[13] =
            {
                .num_mod_grps = 10,
                .chan_desc =
                    {
                        .start_freq = 2414,
                        .chan_width = 20,
                        .chan_num   = 14,
                    },
                .txpwrlimit_entry = {{0, 0}, {1, 0}, {2, 0}, {3, 0}, {4, 0}, {5, 0}, {6, 0}, {7, 0}, {8, 0}, {9, 0}},
            },
};

#ifdef CONFIG_5GHz_SUPPORT
static wifi_txpwrlimit_t
    tx_pwrlimit_5g_cfg =
        {
            .subband   = (wifi_SubBand_t)0x00,
            .num_chans = 39,
            .txpwrlimit_config[0] =
                {
                    .num_mod_grps = 9,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 36,
                        },
                    .txpwrlimit_entry = {{1, 8}, {2, 8}, {3, 8}, {4, 8}, {5, 8}, {6, 8}, {7, 8}, {8, 8}, {9, 8}},
                },
            .txpwrlimit_config[1] =
                {
                    .num_mod_grps = 9,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 40,
                        },
                    .txpwrlimit_entry = {{1, 8}, {2, 8}, {3, 8}, {4, 8}, {5, 8}, {6, 8}, {7, 8}, {8, 8}, {9, 8}},
                },
            .txpwrlimit_config[2] =
                {
                    .num_mod_grps = 9,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 44,
                        },
                    .txpwrlimit_entry = {{1, 8}, {2, 8}, {3, 8}, {4, 8}, {5, 8}, {6, 8}, {7, 8}, {8, 8}, {9, 8}},
                },
            .txpwrlimit_config[3] =
                {
                    .num_mod_grps = 9,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 48,
                        },
                    .txpwrlimit_entry = {{1, 8}, {2, 8}, {3, 8}, {4, 8}, {5, 8}, {6, 8}, {7, 8}, {8, 8}, {9, 8}},
                },
            .txpwrlimit_config[4] =
                {
                    .num_mod_grps = 9,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 52,
                        },
                    .txpwrlimit_entry = {{1, 8}, {2, 8}, {3, 8}, {4, 8}, {5, 8}, {6, 8}, {7, 8}, {8, 8}, {9, 8}},
                },
            .txpwrlimit_config[5] =
                {
                    .num_mod_grps = 9,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 56,
                        },
                    .txpwrlimit_entry = {{1, 8}, {2, 8}, {3, 8}, {4, 8}, {5, 8}, {6, 8}, {7, 8}, {8, 8}, {9, 8}},
                },
            .txpwrlimit_config[6] =
                {
                    .num_mod_grps = 9,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 60,
                        },
                    .txpwrlimit_entry = {{1, 8}, {2, 8}, {3, 8}, {4, 8}, {5, 8}, {6, 8}, {7, 8}, {8, 8}, {9, 8}},
                },
            .txpwrlimit_config[7] =
                {
                    .num_mod_grps = 9,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 64,
                        },
                    .txpwrlimit_entry = {{1, 8}, {2, 8}, {3, 8}, {4, 8}, {5, 8}, {6, 8}, {7, 8}, {8, 8}, {9, 8}},
                },
            .txpwrlimit_config[8] =
                {
                    .num_mod_grps = 9,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 100,
                        },
                    .txpwrlimit_entry = {{1, 8}, {2, 8}, {3, 8}, {4, 8}, {5, 8}, {6, 8}, {7, 8}, {8, 8}, {9, 8}},
                },
            .txpwrlimit_config[9] =
                {
                    .num_mod_grps = 9,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 104,
                        },
                    .txpwrlimit_entry = {{1, 8}, {2, 8}, {3, 8}, {4, 8}, {5, 8}, {6, 8}, {7, 8}, {8, 8}, {9, 8}},
                },
            .txpwrlimit_config[10] =
                {
                    .num_mod_grps = 9,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 108,
                        },
                    .txpwrlimit_entry = {{1, 8}, {2, 8}, {3, 8}, {4, 8}, {5, 8}, {6, 8}, {7, 8}, {8, 8}, {9, 8}},
                },
            .txpwrlimit_config[11] =
                {
                    .num_mod_grps = 9,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 112,
                        },
                    .txpwrlimit_entry = {{1, 8}, {2, 8}, {3, 8}, {4, 8}, {5, 8}, {6, 8}, {7, 8}, {8, 8}, {9, 8}},
                },
            .txpwrlimit_config[12] =
                {
                    .num_mod_grps = 9,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 116,
                        },
                    .txpwrlimit_entry = {{1, 8}, {2, 8}, {3, 8}, {4, 8}, {5, 8}, {6, 8}, {7, 8}, {8, 8}, {9, 8}},
                },
            .txpwrlimit_config[13] =
                {
                    .num_mod_grps = 9,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 120,
                        },
                    .txpwrlimit_entry = {{1, 8}, {2, 8}, {3, 8}, {4, 8}, {5, 8}, {6, 8}, {7, 8}, {8, 8}, {9, 8}},
                },
            .txpwrlimit_config[14] =
                {
                    .num_mod_grps = 9,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 124,
                        },
                    .txpwrlimit_entry = {{1, 8}, {2, 8}, {3, 8}, {4, 8}, {5, 8}, {6, 8}, {7, 8}, {8, 8}, {9, 8}},
                },
            .txpwrlimit_config[15] =
                {
                    .num_mod_grps = 9,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 128,
                        },
                    .txpwrlimit_entry = {{1, 8}, {2, 8}, {3, 8}, {4, 8}, {5, 8}, {6, 8}, {7, 8}, {8, 8}, {9, 8}},
                },
            .txpwrlimit_config[16] =
                {
                    .num_mod_grps = 9,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 132,
                        },
                    .txpwrlimit_entry = {{1, 8}, {2, 8}, {3, 8}, {4, 8}, {5, 8}, {6, 8}, {7, 8}, {8, 8}, {9, 8}},
                },
            .txpwrlimit_config[17] =
                {
                    .num_mod_grps = 9,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 136,
                        },
                    .txpwrlimit_entry = {{1, 8}, {2, 8}, {3, 8}, {4, 8}, {5, 8}, {6, 8}, {7, 8}, {8, 8}, {9, 8}},
                },
            .txpwrlimit_config[18] =
                {
                    .num_mod_grps = 9,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 140,
                        },
                    .txpwrlimit_entry = {{1, 8}, {2, 8}, {3, 8}, {4, 8}, {5, 8}, {6, 8}, {7, 8}, {8, 8}, {9, 8}},
                },
            .txpwrlimit_config[19] =
                {
                    .num_mod_grps = 9,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 144,
                        },
                    .txpwrlimit_entry = {{1, 8}, {2, 8}, {3, 8}, {4, 8}, {5, 8}, {6, 8}, {7, 8}, {8, 8}, {9, 8}},
                },
            .txpwrlimit_config[20] =
                {
                    .num_mod_grps = 9,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 149,
                        },
                    .txpwrlimit_entry = {{1, 8}, {2, 8}, {3, 8}, {4, 8}, {5, 8}, {6, 8}, {7, 8}, {8, 8}, {9, 8}},
                },
            .txpwrlimit_config[21] =
                {
                    .num_mod_grps = 9,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 153,
                        },
                    .txpwrlimit_entry = {{1, 8}, {2, 8}, {3, 8}, {4, 8}, {5, 8}, {6, 8}, {7, 8}, {8, 8}, {9, 8}},
                },
            .txpwrlimit_config[22] =
                {
                    .num_mod_grps = 9,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 157,
                        },
                    .txpwrlimit_entry = {{1, 8}, {2, 8}, {3, 8}, {4, 8}, {5, 8}, {6, 8}, {7, 8}, {8, 8}, {9, 8}},
                },
            .txpwrlimit_config[23] =
                {
                    .num_mod_grps = 9,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 161,
                        },
                    .txpwrlimit_entry = {{1, 8}, {2, 8}, {3, 8}, {4, 8}, {5, 8}, {6, 8}, {7, 8}, {8, 8}, {9, 8}},
                },
            .txpwrlimit_config[24] =
                {
                    .num_mod_grps = 9,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 165,
                        },
                    .txpwrlimit_entry = {{1, 8}, {2, 8}, {3, 8}, {4, 8}, {5, 8}, {6, 8}, {7, 8}, {8, 8}, {9, 8}},
                },
            .txpwrlimit_config[25] =
                {
                    .num_mod_grps = 9,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 183,
                        },
                    .txpwrlimit_entry =
                        {{1, 17}, {2, 16}, {3, 14}, {4, 17}, {5, 16}, {6, 14}, {7, 17}, {8, 16}, {9, 14}},
                },
            .txpwrlimit_config[26] =
                {
                    .num_mod_grps = 9,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 184,
                        },
                    .txpwrlimit_entry =
                        {{1, 17}, {2, 16}, {3, 14}, {4, 17}, {5, 16}, {6, 14}, {7, 17}, {8, 16}, {9, 14}},
                },
            .txpwrlimit_config[27] =
                {
                    .num_mod_grps = 9,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 185,
                        },
                    .txpwrlimit_entry =
                        {{1, 17}, {2, 16}, {3, 14}, {4, 17}, {5, 16}, {6, 14}, {7, 17}, {8, 16}, {9, 14}},
                },
            .txpwrlimit_config[28] =
                {
                    .num_mod_grps = 9,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 187,
                        },
                    .txpwrlimit_entry =
                        {{1, 17}, {2, 16}, {3, 14}, {4, 17}, {5, 16}, {6, 14}, {7, 17}, {8, 16}, {9, 14}},
                },
            .txpwrlimit_config[29] =
                {
                    .num_mod_grps = 9,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 188,
                        },
                    .txpwrlimit_entry =
                        {{1, 17}, {2, 16}, {3, 14}, {4, 17}, {5, 16}, {6, 14}, {7, 17}, {8, 16}, {9, 14}},
                },
            .txpwrlimit_config[30] =
                {
                    .num_mod_grps = 9,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 189,
                        },
                    .txpwrlimit_entry =
                        {{1, 17}, {2, 16}, {3, 14}, {4, 17}, {5, 16}, {6, 14}, {7, 17}, {8, 16}, {9, 14}},
                },
            .txpwrlimit_config[31] =
                {
                    .num_mod_grps = 9,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 192,
                        },
                    .txpwrlimit_entry =
                        {{1, 17}, {2, 16}, {3, 14}, {4, 17}, {5, 16}, {6, 14}, {7, 17}, {8, 16}, {9, 14}},
                },
            .txpwrlimit_config[32] =
                {
                    .num_mod_grps = 9,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 196,
                        },
                    .txpwrlimit_entry =
                        {{1, 17}, {2, 16}, {3, 14}, {4, 17}, {5, 16}, {6, 14}, {7, 17}, {8, 16}, {9, 14}},
                },
            .txpwrlimit_config[33] =
                {
                    .num_mod_grps = 9,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 7,
                        },
                    .txpwrlimit_entry =
                        {{1, 17}, {2, 16}, {3, 14}, {4, 17}, {5, 16}, {6, 14}, {7, 17}, {8, 16}, {9, 14}},
                },
            .txpwrlimit_config[34] =
                {
                    .num_mod_grps = 9,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 8,
                        },
                    .txpwrlimit_entry =
                        {{1, 17}, {2, 16}, {3, 14}, {4, 17}, {5, 16}, {6, 14}, {7, 17}, {8, 16}, {9, 14}},
                },
            .txpwrlimit_config[35] =
                {
                    .num_mod_grps = 9,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 11,
                        },
                    .txpwrlimit_entry =
                        {{1, 17}, {2, 16}, {3, 14}, {4, 17}, {5, 16}, {6, 14}, {7, 17}, {8, 16}, {9, 14}},
                },
            .txpwrlimit_config[36] =
                {
                    .num_mod_grps = 9,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 12,
                        },
                    .txpwrlimit_entry =
                        {{1, 17}, {2, 16}, {3, 14}, {4, 17}, {5, 16}, {6, 14}, {7, 17}, {8, 16}, {9, 14}},
                },
            .txpwrlimit_config[37] =
                {
                    .num_mod_grps = 9,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 16,
                        },
                    .txpwrlimit_entry =
                        {{1, 17}, {2, 16}, {3, 14}, {4, 17}, {5, 16}, {6, 14}, {7, 17}, {8, 16}, {9, 14}},
                },
            .txpwrlimit_config[38] =
                {
                    .num_mod_grps = 9,
                    .chan_desc =
                        {
                            .start_freq = 5000,
                            .chan_width = 20,
                            .chan_num   = 34,
                        },
                    .txpwrlimit_entry =
                        {{1, 17}, {2, 16}, {3, 14}, {4, 17}, {5, 16}, {6, 14}, {7, 17}, {8, 16}, {9, 14}},
                },
};
#endif /* CONFIG_5GHz_SUPPORT */
#endif /* CONFIG_11AX */
