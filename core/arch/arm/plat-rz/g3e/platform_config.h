/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2025-2026, Renesas Electronics Corporation
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT 64

#define GIC_BASE 0x14900000U
#define GIC_SIZE CORE_MMU_PGDIR_SIZE

#define CONSOLE_UART_BASE 0x11C01400U
#define UART_BASE ROUNDDOWN(CONSOLE_UART_BASE, SMALL_PAGE_SIZE)
#define UART_SIZE (SMALL_PAGE_SIZE << 1)

#define SCE_BASE 0x104B0000
#define SCE_SIZE 0x00010000

#define OTP_BASE 0x10450000U
#define OTP_SIZE 0x00010000
#define OTP_CPID_ADDR 0x114C
#define OTP_CPID_SIZE 16

#define CPG_BASE 0x10420000U
#define CPG_SIZE 0x00010000

#define SPI_BASE 0x11030000U
#define SPI_SIZE 0x00010000
#define SFLASH_BASE 0x20000000U
#define SFLASH_SIZE 0x10000000

#if defined(PLATFORM_FLAVOR_g3e_smarc)
/* DDR 8Gbyte x1 */
#define NSEC_DDR_0_BASE 0x47E00000U
#define NSEC_DDR_0_SIZE 0x1F8200000U

#else
#error "Unknown platform flavor"
#endif

#define TEE_SHMEM_START (TZDRAM_BASE + TZDRAM_SIZE)
#define TEE_SHMEM_SIZE 0x100000

#endif /* PLATFORM_CONFIG_H */
