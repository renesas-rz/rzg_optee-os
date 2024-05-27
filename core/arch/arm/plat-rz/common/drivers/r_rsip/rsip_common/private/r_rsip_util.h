/**********************************************************************************************************************
 * DISCLAIMER
 * This software is supplied by Renesas Electronics Corporation and is only intended for use with Renesas products. No
 * other uses are authorized. This software is owned by Renesas Electronics Corporation and is protected under all
 * applicable laws, including copyright laws.
 * THIS SOFTWARE IS PROVIDED "AS IS" AND RENESAS MAKES NO WARRANTIES REGARDING
 * THIS SOFTWARE, WHETHER EXPRESS, IMPLIED OR STATUTORY, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. ALL SUCH WARRANTIES ARE EXPRESSLY DISCLAIMED. TO THE MAXIMUM
 * EXTENT PERMITTED NOT PROHIBITED BY LAW, NEITHER RENESAS ELECTRONICS CORPORATION NOR ANY OF ITS AFFILIATED COMPANIES
 * SHALL BE LIABLE FOR ANY DIRECT, INDIRECT, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES FOR ANY REASON RELATED TO
 * THIS SOFTWARE, EVEN IF RENESAS OR ITS AFFILIATES HAVE BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
 * Renesas reserves the right, without notice, to make changes to this software and to discontinue the availability of
 * this software. By using this software, you agree to the additional terms and conditions found by accessing the
 * following link:
 * http://www.renesas.com/disclaimer
 *
 * Copyright (C) 2024 Renesas Electronics Corporation. All rights reserved.
 *********************************************************************************************************************/

#ifndef R_RSIP_UTIL_H
#define R_RSIP_UTIL_H

/***********************************************************************************************************************
 * Includes
 **********************************************************************************************************************/
#include <stdint.h>
#include "bsp_api.h"

/***********************************************************************************************************************
 * Macro definitions
 **********************************************************************************************************************/

/*
 * Set compiler optimization option for primitive functions.
 * GNU Toolchain: "Os"
 * IAR Embedded Workbench: "size" (enabled only if default optimization level is "high")
 * Other toolchains: no change
 */
#if defined(__GNUC__)
 #define RSIP_PRV_PRIMITIVE_FUNC    __attribute__((optimize("Os")))
#elif defined(__ICCARM__)
 #define RSIP_PRV_PRIMITIVE_FUNC    _Pragma("optimize = size")
#else
 #define RSIP_PRV_PRIMITIVE_FUNC
#endif

/* CPU Architecture and endianness */
#if defined(__ARM_ARCH)
 #define RSIP_PRV_ARCH_ARM
 #define RSIP_PRV_STATIC_INLINE    __STATIC_FORCEINLINE
 #define RSIP_PRV_LITTLE_ENDIAN    !__ARM_BIG_ENDIAN
#else
 #error Unsupported architecture.
#endif

#if RSIP_PRV_LITTLE_ENDIAN
 #define BSWAP_32BIG_C(data)    ((((data) & 0xff000000U) >> 24) | (((data) & 0x00ff0000U) >> 8) | \
                                 (((data) & 0x0000ff00U) << 8) | (((data) & 0x000000ffU) << 24))
#else
 #define BSWAP_32BIG_C(data)    (data)
#endif

/***********************************************************************************************************************
 * Typedef definitions
 **********************************************************************************************************************/

/**********************************************************************************************************************
 * Exported global variables
 **********************************************************************************************************************/

/**********************************************************************************************************************
 * Public Function Prototypes
 **********************************************************************************************************************/

/*******************************************************************************************************************//**
 * Changes data endianness to big-endian.
 *
 * bswap_32big(): For other than const variable. This inline function directly uses ISA.
 *
 * BSWAP_32BIG_C(): For const variable. This macro uses bit shift operation.
 *
 * @param[in] data 32-bit data
 *
 * @return big-endian data
 **********************************************************************************************************************/
RSIP_PRV_STATIC_INLINE uint32_t bswap_32big (uint32_t data)
{
#if RSIP_PRV_LITTLE_ENDIAN && defined(RSIP_PRV_ARCH_ARM)
    return __REV(data);
#else
    return data;
#endif
}

#endif                                 /* R_RSIP_UTIL_H */
