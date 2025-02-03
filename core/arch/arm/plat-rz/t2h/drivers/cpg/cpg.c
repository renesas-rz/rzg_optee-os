/*
 * Copyright (c) 2024, Renesas Electronics Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include <io.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <cpg.h>
#include <sys.h>
#include <sys_regs.h>
#include <xspi.h>

extern vaddr_t sys_base;
extern vaddr_t sys_safety_base;

static void cpg_mstop_xspi0(void)
{
	volatile uint32_t dummy;

	/* Enable write to Module Stop */
	sys_base_unlock(PRCRx_LOW_POWER);

	/* Clear bit to release XSPI from Module Stop State */
	io_write32(sys_base + MSTPCRA, io_read32(sys_base + MSTPCRA) & (~BIT32(MSTPCRA_MSTPCRA04)));

	/* Dummy reads from sys_base + MSTPCRA */
	dummy = io_read32(sys_base + MSTPCRA);
	dummy = io_read32(sys_base + MSTPCRA);
	dummy = io_read32(sys_base + MSTPCRA);
	dummy = io_read32(sys_base + MSTPCRA);
	dummy = io_read32(sys_base + MSTPCRA);
	dummy = io_read32(sys_base + MSTPCRA);
	dummy = io_read32(sys_base + MSTPCRA);

	/* The below is to avoid both a 'checkpatch.pl' and a compile issue "error: variable 'dummy' set but not used [-Werror=unused-but-set-variable]" */
	(void)dummy;

	/* Disable write to Module Stop Register */
	sys_base_lock(PRCRx_LOW_POWER);

	/* Enable write to System Registers */
	sys_safetybase_unlock(PRCRx_SYS_CTRL);

	/* Clear bit to release XSPI from Bus Stop Request State */
	io_write32(sys_safety_base + SSTPCR6, io_read32(sys_safety_base + SSTPCR6) & ~SSTPCR6_XSPI0_REQ_MSK);
	while (0U != (io_read32(sys_safety_base + SSTPCR6) & SSTPCR6_XSPI0_ACK_MSK)) {
		/* nothing */
	}
	/* Dummy read from a xSPI0 register*/
	dummy = (uint32_t)xspi_dummy_read(0);

	/* Disable write to System Registers */
	sys_safetybase_lock(PRCRx_SYS_CTRL);
}

static void cpg_mstop_xspi0_stop(void)
{
	volatile uint32_t dummy;

	/* Enable write to System Registers */
	sys_safetybase_unlock(PRCRx_SYS_CTRL);

	/* Set bit to release XSPI from Bus Stop Request State */
	io_write32(sys_safety_base + SSTPCR6, io_read32(sys_safety_base + SSTPCR6) | SSTPCR6_XSPI0_REQ_MSK);
	while (0U == (io_read32(sys_safety_base + SSTPCR6) & SSTPCR6_XSPI0_ACK_MSK)) {
		/* nothing */
	}
	/* Dummy read from a xSPI0 register*/
	dummy = (uint32_t)xspi_dummy_read(0);

	/* Disable write to System Registers */
	sys_safetybase_lock(PRCRx_SYS_CTRL);

	/* Enable write to Module Stop */
	sys_base_unlock(PRCRx_LOW_POWER);

	/* Set bit to release XSPI from Module Stop State */
	io_write32(sys_base + MSTPCRA, io_read32(sys_base + MSTPCRA) | BIT32(MSTPCRA_MSTPCRA04));
	/* Dummy reads from sys_base + MSTPCRA */
	dummy = io_read32(sys_base + MSTPCRA);
	dummy = io_read32(sys_base + MSTPCRA);
	dummy = io_read32(sys_base + MSTPCRA);
	dummy = io_read32(sys_base + MSTPCRA);
	dummy = io_read32(sys_base + MSTPCRA);
	dummy = io_read32(sys_base + MSTPCRA);
	dummy = io_read32(sys_base + MSTPCRA);

	/* The below is to avoid both a 'checkpatch.pl' and a compile issue "error: variable 'dummy' set but not used [-Werror=unused-but-set-variable]" */
	(void)dummy;

	/* Disable write to Module Stop Register */
	sys_base_lock(PRCRx_LOW_POWER);
}

static void cpg_mstop_xspi1(void)
{
	volatile uint32_t dummy;

	/* Enable write to Module Stop */
	sys_base_unlock(PRCRx_LOW_POWER);

	/* Clear bit to release XSPI from Module Stop State */
	io_write32(sys_base + MSTPCRA, io_read32(sys_base + MSTPCRA) & (~BIT32(MSTPCRA_MSTPCRA05)));

	/* Dummy reads from sys_base + MSTPCRA */
	dummy = io_read32(sys_base + MSTPCRA);
	dummy = io_read32(sys_base + MSTPCRA);
	dummy = io_read32(sys_base + MSTPCRA);
	dummy = io_read32(sys_base + MSTPCRA);
	dummy = io_read32(sys_base + MSTPCRA);
	dummy = io_read32(sys_base + MSTPCRA);
	dummy = io_read32(sys_base + MSTPCRA);

	/* The below is to avoid both a 'checkpatch.pl' and a compile issue "error: variable 'dummy' set but not used [-Werror=unused-but-set-variable]" */
	(void)dummy;

	/* Disable write to Module Stop Register */
	sys_base_lock(PRCRx_LOW_POWER);

	/* Enable write to System Registers */
	sys_safetybase_unlock(PRCRx_SYS_CTRL);

	/* Clear bit to release XSPI from Bus Stop Request State */
	io_write32(sys_safety_base + SSTPCR6, io_read32(sys_safety_base + SSTPCR6) & ~SSTPCR6_XSPI1_REQ_MSK);
	while (0U != (io_read32(sys_safety_base + SSTPCR6) & SSTPCR6_XSPI1_ACK_MSK)) {
		/* nothing */
	}

	/* Dummy read from a xSPI1 register */
	dummy = (uint32_t)xspi_dummy_read(1);

	/* Disable write to System Registers */
	sys_safetybase_lock(PRCRx_SYS_CTRL);
}

static void cpg_mstop_xspi1_stop(void)
{
	volatile uint32_t dummy;

	/* Enable write to System Registers */
	sys_safetybase_unlock(PRCRx_SYS_CTRL);

	/* Clear bit to release XSPI from Bus Stop Request State */
	io_write32(sys_safety_base + SSTPCR6, io_read32(sys_safety_base + SSTPCR6) | SSTPCR6_XSPI1_REQ_MSK);

	while (0U == (io_read32(sys_safety_base + SSTPCR6) & SSTPCR6_XSPI1_ACK_MSK)) {
		/* nothing */
	}

	/* Dummy read from a xSPI1 register */
	dummy = (uint32_t)xspi_dummy_read(1);

	/* Disable write to System Registers */
	sys_safetybase_lock(PRCRx_SYS_CTRL);

	/* Enable write to Module Stop */
	sys_base_unlock(PRCRx_LOW_POWER);

	/* Clear bit to release XSPI from Module Stop State */
	io_write32(sys_base + MSTPCRA, io_read32(sys_base + MSTPCRA) | BIT32(MSTPCRA_MSTPCRA05));
	/* Dummy reads from sys_base + MSTPCRA */
	dummy = io_read32(sys_base + MSTPCRA);
	dummy = io_read32(sys_base + MSTPCRA);
	dummy = io_read32(sys_base + MSTPCRA);
	dummy = io_read32(sys_base + MSTPCRA);
	dummy = io_read32(sys_base + MSTPCRA);
	dummy = io_read32(sys_base + MSTPCRA);
	dummy = io_read32(sys_base + MSTPCRA);

	/* The below is to avoid both a 'checkpatch.pl' and a compile issue "error: variable 'dummy' set but not used [-Werror=unused-but-set-variable]" */
	(void)dummy;

	/* Disable write to Module Stop Register */
	sys_base_lock(PRCRx_LOW_POWER);
}

static void cpg_reset_xspi0(void)
{
	volatile uint32_t dummy;

	/* Enable write to Module Stop and Reset Registers */
	sys_base_unlock(PRCRx_LOW_POWER);

	/* Clear bit to release XSPI from Module Reset State */
	io_write32(sys_base + MRCTLA, io_read32(sys_base + MRCTLA) & (~BIT32(MRCTLA_MRCTLA04)));

	/* Dummy read from sys_base + MRCTLA */
	dummy = io_read32(sys_base + MRCTLA);

	/* The below is to avoid both a 'checkpatch.pl' and a compile issue "error: variable 'dummy' set but not used [-Werror=unused-but-set-variable]" */
	(void)dummy;

	/* Disable write to Module Stop and Reset Registers */
	sys_base_lock(PRCRx_LOW_POWER);
}

static void cpg_reset_xspi0_stop(void)
{
	volatile uint32_t dummy;

	/* Enable write to Module Stop and Reset Registers */
	sys_base_unlock(PRCRx_LOW_POWER);

	/* Clear bit to release XSPI from Module Reset State */
	io_write32(sys_base + MRCTLA, io_read32(sys_base + MRCTLA) | BIT32(MRCTLA_MRCTLA04));
	/* Dummy read from sys_base + MRCTLA */
	dummy = io_read32(sys_base + MRCTLA);

	/* The below is to avoid both a 'checkpatch.pl' and a compile issue "error: variable 'dummy' set but not used [-Werror=unused-but-set-variable]" */
	(void)dummy;

	/* Disable write to Module Stop and Reset Registers */
	sys_base_lock(PRCRx_LOW_POWER);
}

static void cpg_reset_xspi1(void)
{
	volatile uint32_t dummy;

	/* Enable write to Module Stop and Reset Registers */
	sys_base_unlock(PRCRx_LOW_POWER);

	/* Clear bit to release XSPI from Module Reset State */
	io_write32(sys_base + MRCTLA, io_read32(sys_base + MRCTLA) & (~BIT32(MRCTLA_MRCTLA05)));
	/* Dummy read from sys_base + MRCTLA */
	dummy = io_read32(sys_base + MRCTLA);

	/* The below is to avoid both a 'checkpatch.pl' and a compile issue "error: variable 'dummy' set but not used [-Werror=unused-but-set-variable]" */
	(void)dummy;

	/* Disable write to Module Stop and Reset Registers */
	sys_base_lock(PRCRx_LOW_POWER);
}

static void cpg_reset_xspi1_stop(void)
{
	volatile uint32_t dummy;

	/* Enable write to Module Stop and Reset Registers */
	sys_base_unlock(PRCRx_LOW_POWER);

	/* Clear bit to release XSPI from Module Reset State */
	io_write32(sys_base + MRCTLA, io_read32(sys_base + MRCTLA) | BIT32(MRCTLA_MRCTLA05));

	/* Dummy read from sys_base + MRCTLA */
	dummy = io_read32(sys_base + MRCTLA);

	/* The below is to avoid both a 'checkpatch.pl' and a compile issue "error: variable 'dummy' set but not used [-Werror=unused-but-set-variable]" */
	(void)dummy;

	/* Disable write to Module Stop and Reset Registers */
	sys_base_lock(PRCRx_LOW_POWER);
}

void cpg_xspi_start(void)
{
	cpg_mstop_xspi0();
	cpg_reset_xspi0();

	cpg_mstop_xspi1();
	cpg_reset_xspi1();
}

void cpg_xspi_stop(void)
{
	cpg_mstop_xspi0_stop();
	cpg_reset_xspi0_stop();

	cpg_mstop_xspi1_stop();
	cpg_reset_xspi1_stop();
}