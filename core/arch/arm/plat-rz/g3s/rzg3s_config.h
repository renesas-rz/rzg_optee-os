/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2024-2025, Renesas Electronics Corporation
 */

#ifndef RZG3S_CONFIG_H
#define RZG3S_CONFIG_H

#include <mm/generic_ram_layout.h>

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		64

#define GICD_BASE		0x12400000U

#define CONSOLE_UART_BASE	0x1004B800U

#define OTP_BASE		0x11860000U
#define OTP_SIZE		0x00010000
#define CHIPID_BASE		(OTP_BASE + 0x1140U)
#define CHIPID_SIZE		16

#define CPG_REG_BASE		0x11010000
#define CPG_REG_SIZE		0x00010000

#define SPI_FLASH_BASE		0x20000000U
#define SPI_FLASH_SIZE		0x10000000
#define SPI_SECTOR_SIZE		0x10000

#define XSPI_REG_BASE		0x10060000U
#define XSPI_REG_SIZE		0x30000

#define SCE_REG_BASE		0x11850000
#define SCE_REG_SIZE		0x00010000

#if defined(PLATFORM_FLAVOR_g3s_dev14_1)
/* DDR 1Gbyte x1 */
#define NSEC_DDR_0_BASE		0x47E00000U
#define NSEC_DDR_0_SIZE		0x38200000
#elif defined(PLATFORM_FLAVOR_g3s_smarc_2)
/* DDR 1Gbyte x2 */
#define NSEC_DDR_0_BASE		0x47E00000U
#define NSEC_DDR_0_SIZE		0x38200000
#define NSEC_DDR_1_BASE		0xC0000000U
#define NSEC_DDR_1_SIZE		0x40000000
#else
#error "Unknown platform flavor"
#endif

#define TEE_SHMEM_START		(TZDRAM_BASE + TZDRAM_SIZE)
#define TEE_SHMEM_SIZE		0x100000

#endif /*RZG3S_CONFIG_H*/
