/*  Copyright 2025 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 *
 */
/*!\file nchache_attr.h
 *\brief This file provides macros for ncache.init section.
 */

#ifndef NCACHE_ATTR_H
#define NCACHE_ATTR_H

#if (defined(MIMXRT1062_SERIES) || defined(MIMXRT1061_SERIES))
    #if defined(__GNUC__)
        #define ATTR_NCACHE_INIT __attribute__((section(".ncache.init")))
    #else
        #define ATTR_NCACHE_INIT
    #endif
#else
    #define ATTR_NCACHE_INIT
#endif

#endif // NCACHE_ATTR_H
