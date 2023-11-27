/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, GlobalLogic
 * Copyright (c) 2023, Renesas Electronics
 */

#ifndef RZG3S_CONFIG_H
#define RZG3S_CONFIG_H

#include <mm/generic_ram_layout.h>

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		64

#define GICD_BASE			0x11900000U

#define CONSOLE_UART_BASE	0x1004B800U

#define CHIPID_BASE			0x11861140U
#define CHIPID_SIZE			16

#if defined(PLATFORM_FLAVOR_g3s_dev14_1)
/* DDR 1Gbyte x1 */
#define NSEC_DDR_0_BASE     0x47E00000U
#define NSEC_DDR_0_SIZE     0x38200000
#elif defined(PLATFORM_FLAVOR_g3s_smarc_2)
/* DDR 1Gbyte x2 */
#define NSEC_DDR_0_BASE     0x47E00000U
#define NSEC_DDR_0_SIZE     0x38200000
#define NSEC_DDR_1_BASE     0xC0000000U
#define NSEC_DDR_1_SIZE     0x40000000
#else
#error "Unknown platform flavor"
#endif

#define TEE_SHMEM_START		(TZDRAM_BASE + TZDRAM_SIZE)
#define TEE_SHMEM_SIZE		0x100000

#endif /*RZG3S_CONFIG_H*/
