/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2020, Renesas Electronics Corporation
 */

#ifndef RZG_COMMON_H
#define RZG_COMMON_H

#include <string.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <arm.h>

#if defined(PLATFORM_FLAVOR_ek874)
#if (RZG_DRAM_ECC == 1 && RZG_ECC_FULL == 2)
/* Apply for ECC Full Single setting */
#define NSEC_DDR_0_BASE		0x47E00000U
#define NSEC_DDR_0_SIZE		0x3C200000
#else //(RZG_DRAM_ECC == 1 && RZG_ECC_FULL == 2)
/* Apply for non-ECC or Partial ECC setting */
#define NSEC_DDR_0_BASE		0x47E00000U
#define NSEC_DDR_0_SIZE		0x78200000
#endif //(RZG_DRAM_ECC == 1 && RZG_ECC_FULL == 2)

#elif defined(PLATFORM_FLAVOR_hihope_rzg2h)
#if (RZG_DRAM_ECC == 1)
#if (RZG_ECC_FULL == 1)
/* Apply for ECC Full Dual setting */
#define NSEC_DDR_0_BASE		0x47E00000U
#define NSEC_DDR_0_SIZE		0x78200000
#elif (RZG_ECC_FULL == 2)
/* Apply for ECC Full Single setting */
#define NSEC_DDR_0_BASE		0x47E00000U
#define NSEC_DDR_0_SIZE		0x4C200000
#define NSEC_DDR_1_BASE		0x600000000U
#define NSEC_DDR_1_SIZE		0x40000000
#else //(RZG_ECC_FULL)
/* Apply for ECC Partial setting */
/* Define full of DDR0/DDR1 memory map*/
#define NSEC_DDR_0_BASE		0x47E00000U
#define NSEC_DDR_0_SIZE		0x78200000
#define NSEC_DDR_1_BASE		0x600000000U
#define NSEC_DDR_1_SIZE		0x80000000
#endif
#else //(RZG_DRAM_ECC == 1)
/* Define original memory*/
#define NSEC_DDR_0_BASE		0x47E00000U
#define NSEC_DDR_0_SIZE		0x78200000
#define NSEC_DDR_1_BASE		0x500000000U
#define NSEC_DDR_1_SIZE		0x80000000
#endif //(RZG_DRAM_ECC == 1

#elif defined(PLATFORM_FLAVOR_hihope_rzg2m)

#if (RZG_DRAM_ECC == 1 && RZG_ECC_FULL == 1)
/* Apply for ECC Full Dual setting */
#define NSEC_DDR_0_BASE		0x47E00000U
#define NSEC_DDR_0_SIZE		0x78200000
#elif (RZG_DRAM_ECC == 1 && RZG_ECC_FULL == 2)
/* Apply for ECC Full Single setting */
#define NSEC_DDR_0_BASE		0x47E00000U
#define NSEC_DDR_0_SIZE		0x4C200000
#define NSEC_DDR_1_BASE		0x600000000U
#define NSEC_DDR_1_SIZE		0x40000000
#else
/* Apply for non-ECC or Partial ECC setting */
/* Define original memory*/
#define NSEC_DDR_0_BASE		0x47E00000U
#define NSEC_DDR_0_SIZE		0x78200000
#define NSEC_DDR_1_BASE		0x600000000U
#define NSEC_DDR_1_SIZE		0x80000000
#endif

#elif defined(PLATFORM_FLAVOR_hihope_rzg2n)

#if (RZG_DRAM_ECC == 1 && RZG_ECC_FULL == 2)
/* Apply for ECC Full Single setting */
#define NSEC_DDR_0_BASE		0x47E00000U
#define NSEC_DDR_0_SIZE		0x78200000
#define NSEC_DDR_1_BASE		0x480000000U
#define NSEC_DDR_1_SIZE		0x18000000
#else
/* Apply for non-ECC or Partial ECC setting */
#define NSEC_DDR_0_BASE		0x47E00000U
#define NSEC_DDR_0_SIZE		0x78200000
#define NSEC_DDR_1_BASE		0x480000000U
#define NSEC_DDR_1_SIZE		0x80000000
#endif

#else
#error "Unknown platform flavor"
#endif

#if defined(PLATFORM_FLAVOR_hihope_rzg2n)
#if (PMIC_ROHM_BD9571)
/* Parameters value passed from ARM Trusted FW */
#define TFW_ARG_CPU_SUSPEND	(0x0UL)
#define TFW_ARG_SYSTEM_SUSPEND	(0x1UL)
#endif
#endif

#endif /* RZG_COMMON_H */
