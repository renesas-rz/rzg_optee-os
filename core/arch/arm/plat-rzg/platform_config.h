/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, GlobalLogic
 * Copyright (c) 2020, Renesas Electronics Corporation
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		64

#define DEVICE0_BASE		0xE6000000
#define DEVICE0_SIZE		0x002FFFFF

#define GIC_BASE		0xF1000000
#define GICC_BASE		0xF1020000
#define GICD_BASE		0xF1010000

#define CONSOLE_UART_BASE	0xE6E88000

#define TEE_SHMEM_START		(TZDRAM_BASE + TZDRAM_SIZE)
#define TEE_SHMEM_SIZE		0x100000

#endif /*PLATFORM_CONFIG_H*/
