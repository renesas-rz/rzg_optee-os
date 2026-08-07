/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2024-2026, Renesas Electronics Corporation
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT 64

#define GIC_BASE 0x12400000U
#define GIC_SIZE CORE_MMU_PGDIR_SIZE

#define CONSOLE_UART_BASE 0x1004B800U
#define UART_BASE ROUNDDOWN(CONSOLE_UART_BASE, SMALL_PAGE_SIZE)
#define UART_SIZE (SMALL_PAGE_SIZE << 1)

#define SCE_BASE 0x11850000
#define SCE_SIZE 0x00010000

#define OTP_BASE 0x11860000U
#define OTP_SIZE 0x00010000
#define OTP_CPID_ADDR 0x1140U
#define OTP_CPID_SIZE 16

#define CPG_BASE 0x11010000
#define CPG_SIZE 0x00010000

#define SPI_BASE 0x10060000U
#define SPI_SIZE 0x00030000
#define SFLASH_BASE 0x20000000U
#define SFLASH_SIZE 0x10000000
#define SFLASH_KUK_ADDR 0x20A00000U

#if defined(PLATFORM_FLAVOR_g3s_dev14_1)
/* DDR 1Gbyte x1 */
#define NSEC_DDR_0_BASE 0x47E00000U
#define NSEC_DDR_0_SIZE 0x38200000

#elif defined(PLATFORM_FLAVOR_smarc_rzg3s)
/* DDR 1Gbyte x2 */
#define NSEC_DDR_0_BASE 0x47E00000U
#define NSEC_DDR_0_SIZE 0x38200000

#else
#error "Unknown platform flavor"
#endif

#define TEE_SHMEM_START (TZDRAM_BASE + TZDRAM_SIZE)
#define TEE_SHMEM_SIZE 0x100000

#endif /* PLATFORM_CONFIG_H */
