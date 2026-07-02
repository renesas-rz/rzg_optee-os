/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2024-2026, Renesas Electronics Corporation
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		64

#define GIC_BASE			0x83000000U
#define GIC_SIZE			(CORE_MMU_PGDIR_SIZE << 1)

#define CONSOLE_UART_BASE	0x80005000U
#define UART_BASE			ROUNDDOWN(CONSOLE_UART_BASE, SMALL_PAGE_SIZE)
#define UART_SIZE			(SMALL_PAGE_SIZE << 1)

#define SCE_BASE			0x81080000U
#define SCE_SIZE			0x00004000

#define OTP_BASE			0x810C0000U
#define OTP_SIZE			0x00004000

#define SPI_0_BASE			0x801C0000U
#define SPI_1_BASE			0x801C1000U
#define SPI_SIZE			0x00001000
#define SPI_FLASH_BASE_0	0x40000000U
#define SPI_FLASH_BASE_1	0x50000000U
#define SPI_FLASH_SIZE		0x10000000
#define SPI_SECTOR_SIZE		0x00010000

#define PERI_BASE			0x80280000U
#define PERI_SIZE			0x00020000
#define PERI_BASE_SAFETY	0x81280000U
#define PERI_SIZE_SAFETY	0x00020000

#define CPG_BASE			0x80280000U
#define CPG_SIZE			0x00010000
#define SYS_BASE			0x80290000U
#define SYS_SIZE			0x00010000
#define SYS_BASE_SAFETY		0x81290000U
#define SYS_SIZE_SAFETY		0x00010000

#define MBXSEM_BASE			0x80240000U
#define MBXSEM_SIZE			0x00001000U

#if defined(PLATFORM_FLAVOR_t2h_dev_1) || defined(PLATFORM_FLAVOR_n2h_eval)
/* DDR 8Gbyte x1 */
#define NSEC_DDR_0_BASE		0x203E00000
#define NSEC_DDR_0_SIZE		0x1FC200000

#else
#error "Unknown platform flavor"
#endif

#define TEE_SHMEM_START		(TZDRAM_BASE + TZDRAM_SIZE)
#define TEE_SHMEM_SIZE		0x00100000

/* OTP mapping */
#define OTP_UNIQUE_ID_ADDR		U(0x00E5)
#define OTP_UNIQUE_ID_SIZE		(8)

#endif /* PLATFORM_CONFIG_H */
