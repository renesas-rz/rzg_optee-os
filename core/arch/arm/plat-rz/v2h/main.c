// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2024-2025, Renesas Electronics Corporation
 */

#include <console.h>
#include <drivers/gic.h>
#include <drivers/scif.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <platform_config.h>

register_phys_mem(MEM_AREA_IO_SEC, SCE_BASE, SCE_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, OTP_BASE, OTP_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, CPG_BASE, CPG_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, SPI_BASE, SPI_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, UART_BASE, UART_SIZE);

register_phys_mem_pgdir(MEM_AREA_IO_NSEC, GIC_BASE, GIC_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_NSEC, SFLASH_BASE, SFLASH_SIZE);

register_dynamic_shm(NSEC_DDR_0_BASE, NSEC_DDR_0_SIZE);
#ifdef NSEC_DDR_1_BASE
register_dynamic_shm(NSEC_DDR_1_BASE, NSEC_DDR_1_SIZE);
#endif

static struct scif_uart_data console_data __nex_bss;

void plat_console_init(void)
{
	scif_uart_init(&console_data, CONSOLE_UART_BASE);
	register_serial_console(&console_data.chip);
}
