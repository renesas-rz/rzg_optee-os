/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2021-2025, Renesas Electronics Corporation
 */

#ifndef RZV2H_CONFIG_H
#define RZV2H_CONFIG_H

#include <mm/generic_ram_layout.h>

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		64

#define GICD_BASE		0x14900000U

#define CONSOLE_UART_BASE	0x11C01400U

#define OTP_BASE		0x10450000U
#define OTP_SIZE		0x00010000
#define CHIPID_BASE		(OTP_BASE + 0x114CU)
#define CHIPID_SIZE		16

#define CPG_REG_BASE		0x10420000U
#define CPG_REG_SIZE		0x00010000

#define SPI_FLASH_BASE		0x20000000U
#define SPI_FLASH_SIZE		0x10000000
#define SPI_SECTOR_SIZE		0x00010000

#define XSPI_REG_BASE		0x11030000U
#define XSPI_REG_SIZE		0x00010000

#define SCE_REG_BASE		0x10440000
#define SCE_REG_SIZE		0x00010000

#if defined(PLATFORM_FLAVOR_v2h_evk_1) || defined(PLATFORM_FLAVOR_v2n_evk)
/* DDR 8Gbyte x1 */
#define NSEC_DDR_0_BASE		0x47E00000U
#define NSEC_DDR_0_SIZE		0x1F8200000U

/* DDR 8Gbyte x1 */
#define NSEC_DDR_1_BASE		0x240000000U
#define NSEC_DDR_1_SIZE		0x200000000U

#else
#error "Unknown platform flavor"
#endif

#define TEE_SHMEM_START		(TZDRAM_BASE + TZDRAM_SIZE)
#define TEE_SHMEM_SIZE		0x00100000

#endif /*RZV2H_CONFIG_H*/
