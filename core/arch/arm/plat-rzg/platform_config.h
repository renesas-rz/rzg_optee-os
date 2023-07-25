/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, GlobalLogic
 * Copyright (c) 2020-2023, Renesas Electronics Corporation
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		64

#define DEVICE0_BASE		0xE6000000
#define DEVICE0_SIZE		0x002FFFFF

#define DEVICE1_BASE		0xE6360000
#define DEVICE1_SIZE		0x19CA0000

#define GIC_BASE			0xF1000000
#define GICC_BASE			0xF1020000
#define GICD_BASE			0xF1010000

#define	CPG_BASE			0xE6150000
#define	CPG_REG_SIZE		0x00000BB0

#define RPC_BASE			0xEE200000
#define RPC_REG_SIZE		0x00009000

#define PRR_BASE			0xFFF00044
#define PRR_REG_SIZE		0x00000200

#define PRR_PRODUCT_MASK	0x00007F00
#define PRR_CUT_MASK		0x000000FF
#define PRR_PRODUCT_G2H		0x00004F00
#define PRR_PRODUCT_G2M		0x00005200
#define PRR_PRODUCT_G2N		0x00005500
#define PRR_PRODUCT_G2E		0x00005700
#define PRR_PRODUCT_10		0x00U
#define PRR_PRODUCT_11		0x01U
#define PRR_PRODUCT_20		0x10U
#define PRR_PRODUCT_21		0x11U
#define PRR_PRODUCT_30		0x20U

#define CONSOLE_UART_BASE	0xE6E88000

#define TSIP_DATA_ADDR		0x440FE000
#define TSIP_DATA_SIZE		0x00002000

#define TEE_SHMEM_START		(TZDRAM_BASE + TZDRAM_SIZE)
#define TEE_SHMEM_SIZE		0x100000

#endif /*PLATFORM_CONFIG_H*/
