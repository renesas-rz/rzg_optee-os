/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, GlobalLogic
 * Copyright (c) 2021, Renesas Electronics
 */

#ifndef RZG2L_DEF_H
#define RZG2L_DEF_H

#include <mm/generic_ram_layout.h>

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		64

#define GICD_BASE			0x11900000

#define CONSOLE_UART_BASE	0x1004B800

#if defined(PLATFORM_FLAVOR_g2l_dev13_1)
/* DDR 512Mbyte x2 */
#define NSEC_DDR_0_BASE		0x47E00000U
#define NSEC_DDR_0_SIZE		0x18200000
#define NSEC_DDR_1_BASE		0x60000000U
#define NSEC_DDR_1_SIZE		0x20000000

#elif defined(PLATFORM_FLAVOR_g2l_dev15_4)
/* DDR 2Gbyte x2 */
#define NSEC_DDR_0_BASE		0x47E00000U
#define NSEC_DDR_0_SIZE		0x78200000
#define NSEC_DDR_1_BASE		0xC0000000U
#define NSEC_DDR_1_SIZE		0x80000000

#elif defined(PLATFORM_FLAVOR_g2l_dev21_4)
/* DDR 2Gbyte x2 */
#define NSEC_DDR_0_BASE		0x47E00000U
#define NSEC_DDR_0_SIZE		0x78200000
#define NSEC_DDR_1_BASE		0xC0000000U
#define NSEC_DDR_1_SIZE		0x80000000

#elif defined(PLATFORM_FLAVOR_g2l_smarc_2)
/* DDR 1Gbyte x2 */
#define NSEC_DDR_0_BASE		0x47E00000U
#define NSEC_DDR_0_SIZE		0x38200000
#define NSEC_DDR_1_BASE		0x80000000U
#define NSEC_DDR_1_SIZE		0x40000000

#elif defined(PLATFORM_FLAVOR_g2l_smarc_4)
/* DDR 2Gbyte x2 */
#define NSEC_DDR_0_BASE		0x47E00000U
#define NSEC_DDR_0_SIZE		0x78200000
#define NSEC_DDR_1_BASE		0xC0000000U
#define NSEC_DDR_1_SIZE		0x80000000

#else
#error "Unknown platform flavor"
#endif

#define TEE_SHMEM_START		(TZDRAM_BASE + TZDRAM_SIZE)
#define TEE_SHMEM_SIZE		0x100000

#endif /*RZG2L_DEF_H*/
