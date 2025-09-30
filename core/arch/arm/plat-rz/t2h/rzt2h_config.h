/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2024, Renesas Electronics Corporation
 */

#ifndef RZT2H_CONFIG_H
#define RZT2H_CONFIG_H

#include <mm/generic_ram_layout.h>

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		64

#define GICD_BASE		0x83000000U

#define CONSOLE_UART_BASE	0x80005000U

#define CHIPID_BASE		U(0x00E5)
#define CHIPID_SIZE		16

#define SPI_FLASH_BASE_0	0x40000000U
#define SPI_FLASH_BASE_1	0x50000000U
#define SPI_FLASH_SIZE		0x10000000
#define SPI_SECTOR_SIZE		0x00010000

#define XSPI_REG_BASE_0		0x801C0000U
#define XSPI_REG_BASE_1		0x801C1000U
#define XSPI_REG_SIZE		0x00001000

#define MBXSEM_BASE		0x80240000U
#define MBXSEM_SIZE		0x00001000U
#define SYS_BASE		0x80280000U
#define SYS_SIZE		0x00010000U
#define SYS_NS_BASE		0x80290000U
#define SYS_NS_SIZE		0x00010000
#define SYS_SAFETY_BASE		0x81290000U
#define SYS_SAFETY_SIZE		0x00007000U

#define SCE_REG_BASE		0x81080000U
#define SCE_REG_SIZE		0x00004000

#define OTP_BASE		0x810C0000U
#define OTP_REG_SIZE		0x00004000

#if defined(PLATFORM_FLAVOR_t2h_dev_1) || defined(PLATFORM_FLAVOR_n2h_eval)
/* DDR 8Gbyte x1 */
#define NSEC_DDR_0_BASE		0x203E00000
#define NSEC_DDR_0_SIZE		0x1FC200000
#else
#error "Unknown platform flavor"
#endif

#define TEE_SHMEM_START		(TZDRAM_BASE + TZDRAM_SIZE)
#define TEE_SHMEM_SIZE		0x00100000

#endif /*RZT2H_CONFIG_H*/
