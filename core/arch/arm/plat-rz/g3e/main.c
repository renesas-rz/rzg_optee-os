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

register_phys_mem(MEM_AREA_IO_NSEC, CPG_REG_BASE, CPG_REG_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, OTP_BASE, OTP_SIZE);
register_phys_mem(MEM_AREA_IO_SEC, SCE_REG_BASE, SCE_REG_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC, XSPI_REG_BASE, XSPI_REG_SIZE);
register_phys_mem(MEM_AREA_IO_NSEC,
		  ROUNDDOWN(CONSOLE_UART_BASE, SMALL_PAGE_SIZE),
		  (SMALL_PAGE_SIZE * 2));
register_phys_mem(MEM_AREA_IO_NSEC, GICD_BASE, (GIC_DIST_REG_SIZE << 4));
register_phys_mem_pgdir(MEM_AREA_IO_NSEC, SPI_FLASH_BASE, SPI_FLASH_SIZE);

register_dynamic_shm(NSEC_DDR_0_BASE, NSEC_DDR_0_SIZE);
#ifdef NSEC_DDR_1_BASE
register_dynamic_shm(NSEC_DDR_1_BASE, NSEC_DDR_1_SIZE);
#endif
#ifdef NSEC_DDR_2_BASE
register_dynamic_shm(NSEC_DDR_2_BASE, NSEC_DDR_2_SIZE);
#endif
#ifdef NSEC_DDR_3_BASE
register_dynamic_shm(NSEC_DDR_3_BASE, NSEC_DDR_3_SIZE);
#endif

static struct scif_uart_data console_data __nex_bss;

void plat_console_init(void)
{
	scif_uart_init(&console_data, CONSOLE_UART_BASE);
	register_serial_console(&console_data.chip);
}
