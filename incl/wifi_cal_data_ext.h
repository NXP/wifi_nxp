/** @file wifi_cal_data_ext.h
 *
 *  @brief  This file contains the cal data
 */
/*
 *  Copyright 2021 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef _WIFI_CAL_DATA_H_
#define _WIFI_CAL_DATA_H_

#if defined(SD8978)
/* Following cal data is specific to IW416 QFN A1 chips */
#ifdef CONFIG_WLAN_CALDATA_1ANT
const uint8_t int_cal_data[] = {
    0x01, 0x00, 0x0E, 0x00, 0x64, 0x01, 0x00, 0x20, 0x77, 0x0E, 0x00, 0x00, 0x00, 0x20, 0x01, 0x01, 0x20, 0x00, 0xA0,
    0x02, 0xBE, 0x19, 0x00, 0x3F, 0x00, 0x10, 0x00, 0x02, 0x58, 0x81, 0x02, 0x00, 0x00, 0x3E, 0x01, 0x00, 0x00, 0x36,
    0x00, 0x3C, 0x22, 0x4B, 0x00, 0x00, 0x00, 0x5C, 0xFF, 0xFF, 0x06, 0x00, 0x05, 0x11, 0x62, 0x03, 0xFF, 0xFF, 0x6B,
    0x6B, 0x05, 0x17, 0x5F, 0x43, 0xFF, 0xFF, 0x76, 0x76, 0x05, 0x14, 0x57, 0x47, 0xFF, 0xFF, 0x54, 0x54, 0x05, 0x16,
    0x5B, 0x4B, 0xFF, 0xFF, 0x6E, 0x6E, 0x05, 0x15, 0x62, 0x4F, 0xFF, 0xFF, 0x72, 0x72, 0x05, 0x13, 0x4B, 0x53, 0xFF,
    0xFF, 0x54, 0x54, 0x00, 0x6C, 0x92, 0x4D, 0x00, 0x00, 0x00, 0xC8, 0xFF, 0xF1, 0x0C, 0x00, 0x01, 0xA5, 0xFF, 0xFF,
    0x00, 0x06, 0x10, 0x5F, 0x01, 0x93, 0xFF, 0xFF, 0x40, 0x10, 0x10, 0x5F, 0x01, 0x9F, 0xFF, 0xFF, 0x44, 0x30, 0x10,
    0x5F, 0x01, 0x97, 0xFF, 0xFF, 0x48, 0x78, 0x10, 0x5F, 0x01, 0x92, 0xFF, 0xFF, 0x4C, 0x9D, 0x10, 0x5F, 0x01, 0x92,
    0xFF, 0xFF, 0x50, 0x50, 0x10, 0x5F, 0x40, 0x0A, 0xFF, 0xFF, 0x00, 0x06, 0x10, 0x5F, 0x40, 0x1C, 0xFF, 0xFF, 0x40,
    0x10, 0x10, 0x5F, 0x40, 0x1C, 0xFF, 0xFF, 0x44, 0x30, 0x10, 0x5F, 0x40, 0x1C, 0xFF, 0xFF, 0x48, 0x78, 0x10, 0x5F,
    0x40, 0x1E, 0xFF, 0xFF, 0x4C, 0x9D, 0x10, 0x5F, 0x40, 0x1C, 0xFF, 0xFF, 0x50, 0x50, 0x10, 0x5F, 0x00, 0x24, 0xDE,
    0x49, 0x00, 0x00, 0x00, 0xEC, 0xFF, 0xFF, 0x06, 0x00, 0x03, 0xFF, 0x04, 0x05, 0x43, 0xFF, 0x08, 0x09, 0x47, 0xFF,
    0x08, 0x09, 0x4B, 0xFF, 0x06, 0x07, 0x4F, 0xFF, 0x06, 0x07, 0x53, 0xFF, 0x06, 0x07, 0x00, 0x44, 0x06, 0x5A, 0x00,
    0x00, 0x01, 0x30, 0x00, 0x07, 0x01, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0x00, 0x22, 0x00, 0x08, 0x00, 0x0C, 0x00, 0x0C, 0x00, 0x0C, 0x00, 0x0C, 0x00, 0x0C, 0x00, 0x0C, 0x00,
    0x08, 0x00, 0x0C, 0x00, 0x0C, 0x00, 0x0C, 0x00, 0x0C, 0x00, 0x0C, 0x00, 0x0C, 0x00, 0x0C, 0x00, 0x0C, 0x00, 0x0C,
    0x00, 0x0C, 0x00, 0x0C, 0x00, 0x0C, 0x00, 0x18, 0x8C, 0x53, 0x00, 0x00, 0x01, 0x48, 0x39, 0x54, 0xDC, 0x66, 0xBC,
    0x58, 0x44, 0xD0, 0xBE, 0x5D, 0x2F, 0x1B, 0x41, 0x1A, 0xB8, 0x52, 0x00, 0x1C, 0x9B, 0x37, 0xFF, 0xFF, 0xFF, 0xFF,
    0x02, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x2D, 0xC6, 0xC0, 0x33, 0x44, 0x55, 0x66, 0x00, 0xF0, 0x11,
    0x22};
#else
const uint8_t int_cal_data[] = {0x00};
#endif
#endif

#if defined(SD8987)
const uint8_t int_cal_data[] = {0x00};
#endif

#if defined(SD8801)
const uint8_t int_cal_data[] = {0x00};
#endif

#if defined(SD9177)
#ifdef CONFIG_WLAN_CALDATA_2ANT_DIVERSITY
/*Antenna Diversity*/
const uint8_t int_cal_data[] = {
    0x01, 0x00, 0x0F, 0x00, 0x6C, 0x01, 0x00, 0x20, 0x99, 0x0F, 0x00, 0x00, 0x00, 0x20, 0xFF, 0xFF, 0x40, 0x00, 0x77,
    0x00, 0x27, 0x07, 0x00, 0x00, 0x00, 0x10, 0x00, 0x03, 0xE8, 0x88, 0x02, 0x00, 0x00, 0x3F, 0x01, 0x00, 0x00, 0x71,
    0x00, 0x2C, 0x9A, 0x4B, 0x00, 0x00, 0x00, 0x4C, 0xFF, 0xFF, 0x04, 0x00, 0x00, 0xC6, 0xC6, 0x03, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xDB, 0xDB, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE1, 0xE1, 0x4B, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDD,
    0xDD, 0x4F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8C, 0xE4, 0x61, 0x00, 0x00, 0x00, 0xD8, 0xFF, 0xF1, 0x08, 0x00, 0x00,
    0x05, 0x01, 0x25, 0xFB, 0x6E, 0x20, 0x21, 0xC4, 0x40, 0x5B, 0xE8, 0xCB, 0x22, 0x78, 0x6F, 0x00, 0x0B, 0x01, 0x27,
    0xFB, 0xDE, 0x3C, 0x22, 0xC4, 0xB0, 0x7B, 0xF0, 0xCB, 0x32, 0x8C, 0x77, 0x44, 0x28, 0x01, 0x10, 0xFB, 0x3E, 0x30,
    0x24, 0xC3, 0xF0, 0x4B, 0xE4, 0xCA, 0xE2, 0x30, 0x67, 0x44, 0x38, 0x01, 0x0F, 0xFC, 0x1E, 0x68, 0x25, 0xC4, 0xB0,
    0x7F, 0xF2, 0xCB, 0x32, 0x54, 0x70, 0x48, 0x6C, 0x01, 0x37, 0xFB, 0x6E, 0x38, 0x25, 0xC3, 0xF0, 0x4F, 0xE6, 0xCA,
    0xB2, 0x34, 0x68, 0x48, 0x84, 0x01, 0x36, 0xFC, 0x6E, 0x7C, 0x26, 0xC4, 0xF0, 0x93, 0xF7, 0xCB, 0x02, 0x68, 0x75,
    0x4C, 0x99, 0x01, 0x3B, 0xFE, 0x1E, 0xE8, 0x26, 0xC6, 0x80, 0xF8, 0x12, 0xCA, 0xE2, 0x90, 0x89, 0x4C, 0xA5, 0x01,
    0x3F, 0xFE, 0x4E, 0xF4, 0x27, 0xC6, 0x50, 0xFC, 0x15, 0xCA, 0x92, 0x78, 0x83, 0x00, 0x1C, 0xFD, 0x62, 0x00, 0x00,
    0x00, 0xF4, 0xFF, 0xFF, 0x04, 0x00, 0x03, 0xF0, 0xFC, 0x3F, 0x47, 0xF0, 0xFC, 0x3F, 0x4B, 0xF0, 0xFC, 0x3F, 0x4F,
    0xF0, 0xFC, 0x3F, 0x00, 0x18, 0x5C, 0x53, 0x00, 0x00, 0x01, 0x0C, 0x39, 0x06, 0x75, 0x0D, 0xBC, 0x55, 0x1F, 0x97,
    0x3D, 0x16, 0x3D, 0x21, 0x41, 0x49, 0xAE, 0xBC, 0x00, 0x44, 0xCE, 0x5A, 0x00, 0x00, 0x01, 0x50, 0x00, 0x07, 0x01,
    0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0xFF, 0xFF, 0x00, 0x22, 0x00, 0x01,
    0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01,
    0x00, 0x1C, 0x00, 0x37, 0xFF, 0xFF, 0xFF, 0xFF, 0x04, 0x04, 0x77, 0x01, 0x00, 0x00, 0x00, 0x09, 0x00, 0x2D, 0xC6,
    0xC0, 0xDA, 0x21, 0x12, 0x14, 0x00, 0x00, 0xC0, 0x95,
};

#else
const uint8_t int_cal_data[] = {
    0x01, 0x00, 0x0F, 0x00, 0xD0, 0x01, 0x00, 0x20, 0x98, 0x0F, 0x00, 0x00, 0x00, 0x20, 0xFF, 0xFF, 0x40, 0x00, 0x77,
    0x00, 0x28, 0x07, 0x00, 0x00, 0x00, 0x10, 0x00, 0x03, 0xE8, 0x88, 0x02, 0x00, 0x00, 0x3F, 0x01, 0x00, 0x00, 0x71,
    0x00, 0x2C, 0x9A, 0x4B, 0x00, 0x00, 0x00, 0x4C, 0xFF, 0xFF, 0x04, 0x00, 0x00, 0xC6, 0xC6, 0x03, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xDB, 0xDB, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE1, 0xE1, 0x4B, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDD,
    0xDD, 0x4F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8C, 0x7D, 0x61, 0x00, 0x00, 0x00, 0xD8, 0xFF, 0xF1, 0x08, 0x00, 0x00,
    0x05, 0x01, 0x00, 0x39, 0x7D, 0x9C, 0x23, 0x02, 0x6F, 0xE3, 0xC8, 0x0A, 0xC2, 0x0C, 0x55, 0x00, 0x0B, 0x01, 0x0E,
    0x39, 0x5D, 0x9C, 0x25, 0x02, 0x6F, 0xDF, 0xC8, 0x0A, 0xB2, 0x0C, 0x55, 0x44, 0x28, 0x01, 0xCE, 0x3A, 0x7D, 0xF0,
    0x27, 0x03, 0x40, 0x1B, 0xD7, 0x0A, 0xF2, 0x1C, 0x60, 0x44, 0x38, 0x01, 0xD4, 0x3A, 0xBE, 0x10, 0x29, 0x03, 0x70,
    0x27, 0xDB, 0x0A, 0xB2, 0x1C, 0x61, 0x48, 0x6C, 0x01, 0xD1, 0x3A, 0x4E, 0x00, 0x29, 0x03, 0x00, 0x07, 0xD3, 0x0B,
    0x12, 0x10, 0x5F, 0x48, 0x84, 0x01, 0xD2, 0x3A, 0x8E, 0x00, 0x2A, 0x03, 0x20, 0x0F, 0xD6, 0x0A, 0xB2, 0x0C, 0x5E,
    0x4C, 0x99, 0x01, 0xD6, 0x3A, 0x2D, 0xE0, 0x2A, 0x02, 0xCF, 0xFB, 0xD0, 0x0A, 0x51, 0xF4, 0x58, 0x4C, 0xA5, 0x01,
    0xD3, 0x3A, 0x0D, 0xE0, 0x2B, 0x02, 0x9F, 0xEF, 0xCF, 0x09, 0xF1, 0xE4, 0x54, 0x00, 0x1C, 0x55, 0x62, 0x00, 0x00,
    0x00, 0xF4, 0xFF, 0xFF, 0x04, 0x00, 0x03, 0xF0, 0x84, 0x21, 0x47, 0xF0, 0x84, 0x21, 0x4B, 0xF0, 0x84, 0x21, 0x4F,
    0xF0, 0x84, 0x21, 0x00, 0x18, 0x2D, 0x53, 0x00, 0x00, 0x01, 0x0C, 0x39, 0x1B, 0x30, 0x73, 0xBC, 0x15, 0x18, 0x2B,
    0xBE, 0x82, 0x8F, 0x5C, 0x41, 0x4C, 0xCC, 0xCD, 0x00, 0x70, 0xDD, 0x5A, 0x00, 0x00, 0x01, 0x7C, 0x00, 0x07, 0x02,
    0x04, 0x00, 0x07, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x02, 0x00, 0x03,
    0x00, 0x03, 0x00, 0x03, 0x00, 0x03, 0x00, 0x03, 0x00, 0x03, 0x00, 0x03, 0x00, 0x05, 0x00, 0x03, 0x00, 0x03, 0x00,
    0x03, 0x00, 0x05, 0x00, 0x03, 0x00, 0x03, 0x00, 0x03, 0x00, 0x03, 0x00, 0x03, 0x00, 0x03, 0x00, 0x03, 0x00, 0x03,
    0xFF, 0xFF, 0x00, 0x20, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00,
    0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05,
    0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x10, 0xE4, 0x63, 0x00, 0x00, 0x01, 0x8C, 0xF1, 0x11, 0x00, 0x01, 0x00,
    0x00, 0x0D, 0x0D, 0x00, 0x1C, 0x07, 0x37, 0x00, 0x00, 0x01, 0xA8, 0x07, 0x0D, 0x77, 0x01, 0x00, 0x00, 0x00, 0x28,
    0x00, 0x01, 0xC2, 0x00, 0x23, 0xBB, 0x5E, 0x71, 0x00, 0x00, 0xDC, 0xFE, 0x00, 0x18, 0x60, 0x68, 0x00, 0x00, 0x01,
    0xC0, 0x00, 0x74, 0x00, 0x01, 0xFE, 0xBB, 0x5E, 0x70, 0xDC, 0xFE, 0x23, 0xFF, 0x00, 0x00, 0x00, 0x68, 0x00, 0x10,
    0x87, 0x64, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x04, 0x00, 0x01, 0x00, 0x04, 0x00, 0x01};
#endif
#endif

#ifdef RW610
#ifdef FRDMRW610
#define CONFIG_WLAN_CALDATA_1ANT
#endif
#ifdef CONFIG_WLAN_CALDATA_1ANT
/*one ANT*/
const uint8_t cal_data_rw610[] = {
    0x01, 0x00, 0x0F, 0x00, 0xB8, 0x01, 0x00, 0x20, 0xB6, 0x0F, 0x00, 0x00, 0x00, 0x20, 0xFF, 0xFF, 0x40, 0x00, 0x7C,
    0x00, 0x2A, 0x11, 0x00, 0x00, 0x00, 0x10, 0x00, 0x04, 0x26, 0x79, 0x02, 0x00, 0x00, 0x3F, 0x01, 0x00, 0x00, 0x12,
    0x00, 0x2C, 0xC6, 0x4B, 0x00, 0x00, 0x00, 0x4C, 0xFF, 0xFF, 0x04, 0x00, 0x00, 0xDC, 0xDB, 0x03, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xCF, 0xD5, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00, 0xCF, 0xD4, 0x4B, 0x00, 0x00, 0x00, 0x00, 0x00, 0xCA,
    0xCA, 0x4F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8C, 0x75, 0x61, 0x00, 0x00, 0x00, 0xD8, 0xFF, 0xF0, 0x08, 0x00, 0x00,
    0x05, 0x01, 0x3F, 0x3C, 0x1E, 0x50, 0x23, 0x05, 0x00, 0x8B, 0xF2, 0x0B, 0x92, 0xA8, 0x7D, 0x00, 0x0B, 0x01, 0x42,
    0x3C, 0xAE, 0x70, 0x24, 0x05, 0x70, 0xAB, 0xFA, 0x0B, 0x82, 0xAC, 0x83, 0x44, 0x28, 0x01, 0x64, 0x3B, 0x0E, 0x28,
    0x26, 0x03, 0xF0, 0x43, 0xE0, 0x0B, 0x22, 0x34, 0x69, 0x44, 0x38, 0x01, 0xF2, 0x3A, 0xEE, 0x20, 0x28, 0x03, 0xC0,
    0x3B, 0xDE, 0x0A, 0xD2, 0x28, 0x67, 0x48, 0x6C, 0x01, 0x20, 0x3C, 0x2E, 0x70, 0x28, 0x04, 0xE0, 0x87, 0xF3, 0x0B,
    0x92, 0x64, 0x76, 0x48, 0x84, 0x01, 0x0E, 0x3B, 0x5E, 0x3C, 0x29, 0x04, 0x40, 0x5B, 0xE7, 0x0B, 0x32, 0x44, 0x6D,
    0x4C, 0x99, 0x01, 0x0A, 0x3B, 0xBE, 0x54, 0x2A, 0x04, 0x60, 0x6B, 0xED, 0x0A, 0xE2, 0x3C, 0x6C, 0x4C, 0xA5, 0x01,
    0x94, 0x3B, 0x4E, 0x34, 0x2A, 0x03, 0xF0, 0x4F, 0xE5, 0x0A, 0x92, 0x24, 0x66, 0x00, 0x1C, 0xD6, 0x62, 0x00, 0x00,
    0x00, 0xF4, 0xFF, 0xFF, 0x04, 0x00, 0x00, 0x03, 0x18, 0xC6, 0x44, 0x02, 0x10, 0x84, 0x48, 0x02, 0x94, 0xA5, 0x4C,
    0x04, 0x21, 0x08, 0x00, 0x70, 0x4B, 0x5A, 0x00, 0x00, 0x01, 0x64, 0x00, 0x07, 0x02, 0x04, 0x00, 0x0F, 0x00, 0x00,
    0x00, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x02, 0x00, 0x02, 0x00, 0x01, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01,
    0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0xFF, 0xFF, 0x00, 0x20, 0x00,
    0x02, 0x00, 0x01, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02,
    0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00,
    0x02, 0x00, 0x10, 0x01, 0x63, 0x00, 0x00, 0x01, 0x74, 0xF1, 0x11, 0x00, 0x01, 0x00, 0x00, 0x0D, 0x08, 0x00, 0x1C,
    0xD4, 0x37, 0x00, 0x00, 0x01, 0x90, 0x03, 0x04, 0x7C, 0x01, 0x00, 0x00, 0x00, 0x28, 0x00, 0x2D, 0xC6, 0xC0, 0xFF,
    0xFF, 0xFF, 0xFF, 0x00, 0xF0, 0xFF, 0xFF, 0x00, 0x18, 0xCE, 0x68, 0x00, 0x00, 0x01, 0xA8, 0x00, 0x65, 0x00, 0x01,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x48, 0x00, 0x64, 0x00, 0x10, 0x8D, 0x64, 0xFF, 0xFF, 0xFF,
    0xFF, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00};
#else
#ifdef CONFIG_WLAN_CALDATA_3ANT_DIVERSITY
const uint8_t cal_data_rw610[] = {
    0x01, 0x00, 0x0F, 0x00, 0xA8, 0x01, 0x00, 0x20, 0x46, 0x0F, 0x00, 0x00, 0x00, 0x20, 0xFF, 0xFF, 0x40, 0x00, 0x72,
    0x00, 0x22, 0x00, 0x00, 0xA3, 0x00, 0x00, 0x00, 0x04, 0x26, 0x79, 0x02, 0x00, 0x00, 0x3F, 0x01, 0x00, 0x00, 0x12,
    0x00, 0x8C, 0x93, 0x61, 0x00, 0x00, 0x00, 0xAC, 0xFF, 0xF0, 0x08, 0x00, 0x00, 0x05, 0x01, 0x15, 0x3B, 0xAE, 0x30,
    0x20, 0x04, 0xC0, 0x73, 0xED, 0x0C, 0x12, 0x84, 0x7B, 0x00, 0x0B, 0x01, 0x18, 0x3B, 0xCE, 0x38, 0x21, 0x04, 0xE0,
    0x7B, 0xEE, 0x0C, 0x12, 0x88, 0x7A, 0x44, 0x28, 0x01, 0x1E, 0x3B, 0x8E, 0x40, 0x21, 0x04, 0x30, 0x5B, 0xE8, 0x0B,
    0x82, 0x50, 0x6B, 0x44, 0x38, 0x01, 0x2D, 0x3B, 0xAE, 0x4C, 0x23, 0x04, 0xB0, 0x6F, 0xEC, 0x0B, 0x72, 0x9C, 0x79,
    0x48, 0x6C, 0x01, 0x15, 0x3C, 0x1E, 0x68, 0x24, 0x04, 0xC0, 0x7F, 0xF0, 0x0B, 0xA2, 0x60, 0x75, 0x48, 0x84, 0x01,
    0x2D, 0x3B, 0x8E, 0x44, 0x24, 0x04, 0x80, 0x67, 0xE9, 0x0B, 0x52, 0x7C, 0x77, 0x4C, 0x99, 0x01, 0x22, 0x3B, 0xFE,
    0x60, 0x24, 0x04, 0xA0, 0x7B, 0xF0, 0x0A, 0xD2, 0x50, 0x72, 0x4C, 0xA5, 0x01, 0x0F, 0x3B, 0x4E, 0x30, 0x25, 0x03,
    0xE0, 0x47, 0xE4, 0x0A, 0x92, 0x28, 0x68, 0x00, 0x70, 0x7A, 0x5A, 0x00, 0x00, 0x01, 0x1C, 0x00, 0x07, 0x02, 0x04,
    0x00, 0x0F, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x0C, 0xFF, 0xFF, 0x00, 0x02, 0x00, 0x02, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01,
    0x00, 0x02, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0xFF,
    0xFF, 0x00, 0x20, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02,
    0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00,
    0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x10, 0x49, 0x63, 0x00, 0x00, 0x01, 0x2C, 0xF1, 0x11, 0x00, 0x01, 0x00, 0x00,
    0x0D, 0x08, 0x00, 0x2C, 0x49, 0x4B, 0x00, 0x00, 0x01, 0x58, 0xFF, 0xFF, 0x04, 0x00, 0x00, 0xE4, 0xEA, 0x03, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xE0, 0xE2, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDD, 0xE0, 0x4B, 0x00, 0x00, 0x00, 0x00,
    0x00, 0xDB, 0xDA, 0x4F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1C, 0xF3, 0x62, 0x00, 0x00, 0x01, 0x74, 0xFF, 0xFF, 0x04,
    0x00, 0x00, 0x02, 0x90, 0xA4, 0x44, 0x04, 0xA5, 0x29, 0x48, 0x04, 0x20, 0xE8, 0x4C, 0x04, 0x21, 0x08, 0x00, 0x1C,
    0x0A, 0x37, 0x00, 0x00, 0x01, 0x90, 0x03, 0x04, 0x72, 0x01, 0x00, 0x00, 0x00, 0x28, 0x00, 0x2D, 0xC6, 0xC0, 0xDA,
    0x01, 0x07, 0x97, 0x00, 0xF0, 0xC0, 0x95, 0x00, 0x18, 0x27, 0x68, 0xFF, 0xFF, 0xFF, 0xFF, 0x65, 0x00, 0x00, 0x01,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00};
#elif defined(CONFIG_WLAN_CALDATA_1ANT_WITH_DIVERSITY)
const uint8_t cal_data_rw610[] = {
    0x01, 0x00, 0x0F, 0x00, 0xB8, 0x01, 0x00, 0x20, 0x24, 0x0F, 0x00, 0x00, 0x00, 0x20, 0xFF, 0xFF, 0x40, 0x00, 0x7C,
    0x00, 0x2C, 0x11, 0x00, 0x00, 0x00, 0x10, 0x00, 0x04, 0x11, 0x30, 0x02, 0x00, 0x00, 0x3F, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x2C, 0xC6, 0x4B, 0x00, 0x00, 0x00, 0x4C, 0xFF, 0xFF, 0x04, 0x00, 0x00, 0xDC, 0xDB, 0x03, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xCF, 0xD5, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00, 0xCF, 0xD4, 0x4B, 0x00, 0x00, 0x00, 0x00, 0x00, 0xCA,
    0xCA, 0x4F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8C, 0x28, 0x61, 0x00, 0x00, 0x00, 0xD8, 0xFF, 0xF0, 0x08, 0x00, 0x00,
    0x05, 0x01, 0x3D, 0x3C, 0x3E, 0x54, 0x22, 0x05, 0x10, 0x8F, 0xF4, 0x0B, 0xB2, 0xA8, 0x7E, 0x00, 0x0B, 0x01, 0x39,
    0x3C, 0x6E, 0x64, 0x23, 0x05, 0x50, 0x9B, 0xF7, 0x0B, 0xB2, 0xA8, 0x80, 0x44, 0x28, 0x01, 0x37, 0x3A, 0x9E, 0x0C,
    0x25, 0x03, 0x80, 0x27, 0xDA, 0x0A, 0xB2, 0x18, 0x62, 0x44, 0x38, 0x01, 0x07, 0x3A, 0xBE, 0x14, 0x26, 0x03, 0xA0,
    0x33, 0xDC, 0x0A, 0xB2, 0x20, 0x64, 0x48, 0x6C, 0x01, 0x37, 0x3B, 0x2E, 0x30, 0x28, 0x03, 0xF0, 0x47, 0xE3, 0x0A,
    0xF2, 0x30, 0x68, 0x48, 0x84, 0x01, 0x1D, 0x3B, 0xDE, 0x58, 0x28, 0x04, 0xA0, 0x73, 0xEE, 0x0B, 0x62, 0x58, 0x72,
    0x4C, 0x99, 0x01, 0x25, 0x3C, 0x5E, 0x78, 0x29, 0x04, 0xF0, 0x8F, 0xF6, 0x0B, 0x22, 0x58, 0x73, 0x4C, 0xA5, 0x01,
    0x22, 0x3B, 0xEE, 0x5C, 0x2A, 0x04, 0x80, 0x77, 0xEF, 0x0A, 0xE2, 0x44, 0x6D, 0x00, 0x1C, 0x31, 0x62, 0x00, 0x00,
    0x00, 0xF4, 0xFF, 0xFF, 0x04, 0x00, 0x00, 0x03, 0x9C, 0xE7, 0x44, 0x02, 0x10, 0x84, 0x48, 0x02, 0x94, 0xA5, 0x4C,
    0x04, 0x21, 0x08, 0x00, 0x70, 0x93, 0x5A, 0x00, 0x00, 0x01, 0x64, 0x00, 0x07, 0x02, 0x04, 0x00, 0x0F, 0x00, 0x00,
    0x00, 0x0F, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x0C, 0xFF, 0xFF, 0x00, 0x02, 0x00, 0x06, 0x00, 0x05, 0x00, 0x05, 0x00,
    0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x06, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x06, 0x00, 0x05,
    0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0xFF, 0xFF, 0x00, 0x20, 0x00,
    0x06, 0x00, 0x05, 0x00, 0x06, 0x00, 0x06, 0x00, 0x06, 0x00, 0x06, 0x00, 0x06, 0x00, 0x06, 0x00, 0x06, 0x00, 0x06,
    0x00, 0x06, 0x00, 0x06, 0x00, 0x06, 0x00, 0x06, 0x00, 0x06, 0x00, 0x06, 0x00, 0x06, 0x00, 0x06, 0x00, 0x06, 0x00,
    0x06, 0x00, 0x10, 0x01, 0x63, 0x00, 0x00, 0x01, 0x74, 0xF1, 0x11, 0x00, 0x01, 0x00, 0x00, 0x0D, 0x08, 0x00, 0x1C,
    0xD4, 0x37, 0x00, 0x00, 0x01, 0x90, 0x03, 0x04, 0x7C, 0x01, 0x00, 0x00, 0x00, 0x28, 0x00, 0x2D, 0xC6, 0xC0, 0xFF,
    0xFF, 0xFF, 0xFF, 0x00, 0xF0, 0xFF, 0xFF, 0x00, 0x18, 0x0C, 0x68, 0x00, 0x00, 0x01, 0xA8, 0x00, 0x74, 0x00, 0x01,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x2D, 0x00, 0x32, 0x00, 0x10, 0x7D, 0x64, 0xFF, 0xFF, 0xFF,
    0xFF, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00};
#else /*TWO ANT*/
const uint8_t cal_data_rw610[] = {
    0x01, 0x00, 0x0F, 0x00, 0x38, 0x01, 0x00, 0x20, 0xE1, 0x0F, 0x00, 0x00, 0x00, 0x20, 0xFF, 0xFF, 0x40, 0x00, 0x7A,
    0x00, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x26, 0x79, 0x02, 0x00, 0x00, 0x3F, 0x01, 0x00, 0x00, 0x12,
    0x00, 0x8C, 0xE1, 0x61, 0x00, 0x00, 0x00, 0xAC, 0xFF, 0xF0, 0x08, 0x00, 0x00, 0x05, 0x01, 0x15, 0x3C, 0x1E, 0x4C,
    0x20, 0x05, 0x20, 0x8B, 0xF2, 0x0C, 0x82, 0xC0, 0x81, 0x00, 0x0B, 0x01, 0x15, 0x3C, 0x3E, 0x54, 0x21, 0x05, 0x40,
    0x97, 0xF5, 0x0C, 0x92, 0xC8, 0x83, 0x44, 0x28, 0x01, 0x03, 0x3A, 0x9E, 0x08, 0x23, 0x03, 0x90, 0x2B, 0xDA, 0x0A,
    0xF2, 0x28, 0x65, 0x44, 0x38, 0x01, 0x00, 0x3A, 0xAE, 0x0C, 0x25, 0x03, 0x80, 0x2B, 0xDB, 0x0A, 0xD2, 0x20, 0x64,
    0x48, 0x6C, 0x01, 0x18, 0x3B, 0xCE, 0x54, 0x26, 0x04, 0xA0, 0x73, 0xED, 0x0B, 0xD2, 0x5C, 0x73, 0x48, 0x84, 0x01,
    0x1A, 0x3B, 0x5E, 0x38, 0x27, 0x04, 0x40, 0x5B, 0xE6, 0x0B, 0xB2, 0x64, 0x6F, 0x4C, 0x99, 0x01, 0x06, 0x3B, 0xAE,
    0x48, 0x29, 0x04, 0x90, 0x6B, 0xEB, 0x0B, 0x92, 0x6C, 0x74, 0x4C, 0xA5, 0x01, 0xFE, 0x3B, 0x2E, 0x2C, 0x29, 0x04,
    0x00, 0x4B, 0xE4, 0x0B, 0x22, 0x48, 0x6A, 0x00, 0x10, 0xBF, 0x63, 0x00, 0x00, 0x00, 0xBC, 0xF1, 0x11, 0x00, 0x01,
    0x00, 0x00, 0x08, 0x08, 0x00, 0x2C, 0xF6, 0x4B, 0x00, 0x00, 0x00, 0xE8, 0xFF, 0xFF, 0x04, 0x00, 0x00, 0xD6, 0xDA,
    0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0xDB, 0xDD, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD6, 0xD9, 0x4B, 0x00, 0x00,
    0x00, 0x00, 0x00, 0xD6, 0xD9, 0x4F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1C, 0x98, 0x62, 0x00, 0x00, 0x01, 0x04, 0xFF,
    0xFF, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x44, 0x01, 0x08, 0x42, 0x48, 0x02, 0x94, 0xA5, 0x4C, 0x03, 0x9C, 0xE7,
    0x00, 0x1C, 0x47, 0x37, 0x00, 0x00, 0x01, 0x20, 0x02, 0x04, 0x7A, 0x01, 0x00, 0x00, 0x00, 0x28, 0x00, 0x2D, 0xC6,
    0xC0, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xF0, 0xFF, 0xFF, 0x00, 0x18, 0x8C, 0x68, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00,
    0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00};
#endif
#endif
#endif
#endif
