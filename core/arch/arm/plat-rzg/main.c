// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, GlobalLogic
 * Copyright (c) 2019-2020, Renesas Electronics Corporation
 */

#include <console.h>
#include <drivers/gic.h>
#include <drivers/scif.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <platform_config.h>

#if defined(PLATFORM_FLAVOR_hihope_rzg2n)
#if (PMIC_ROHM_BD9571)
#include <kernel/spinlock.h>
#include <kernel/boot.h>

#include "rzg_suspend_to_ram.h"
#endif
#endif

#include "rzg_common.h"

register_phys_mem_pgdir(MEM_AREA_IO_SEC, DEVICE0_BASE, DEVICE0_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, CONSOLE_UART_BASE, SCIF_REG_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICD_BASE, GIC_DIST_REG_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, GICC_BASE, GIC_DIST_REG_SIZE);

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

#if defined(PLATFORM_FLAVOR_hihope_rzg2n)
#if (PMIC_ROHM_BD9571)
static uint32_t suspend_to_ram_save_flag = 0U;
static uint32_t main_cpu_lock = (uint32_t)SPINLOCK_UNLOCK;

unsigned long thread_cpu_suspend_handler(unsigned long a0,
					 unsigned long a1 __unused)
{
	uint32_t exceptions;

	exceptions = cpu_spin_lock_xsave(&main_cpu_lock);
	FMSG("a0=0x%lX, a1=0x%lX", a0, a1);

	if (a0 >= TFW_ARG_SYSTEM_SUSPEND) {
		if (suspend_to_ram_save_flag == 0U) {
			suspend_to_ram_save();
			suspend_to_ram_save_flag = 1U;
			FMSG("END suspend_to_ram_save");
		} else {
			/* no operation */
		}
	} else {
		/* in case of CPU_SUSPEND(CPU Idle), no operation */
	}

	cpu_spin_unlock_xrestore(&main_cpu_lock, exceptions);
	return 0U;
}

unsigned long thread_cpu_resume_handler(unsigned long a0 __unused,
                                unsigned long a1 __unused)
{
	uint32_t exceptions;

	exceptions = cpu_spin_lock_xsave(&main_cpu_lock);
	FMSG("a0=0x%lX, a1=0x%lX", a0, a1);

	if (suspend_to_ram_save_flag == 1U) {
		suspend_to_ram_restore();
		suspend_to_ram_save_flag = 0U;
		FMSG("END suspend_to_ram_restore");
	} else {
		/* no operation */
	}

	cpu_spin_unlock_xrestore(&main_cpu_lock, exceptions);
	return 0U;
}
#endif
#endif

static struct scif_uart_data console_data __nex_bss;

void console_init(void)
{
	scif_uart_init(&console_data, CONSOLE_UART_BASE);
	register_serial_console(&console_data.chip);
}
