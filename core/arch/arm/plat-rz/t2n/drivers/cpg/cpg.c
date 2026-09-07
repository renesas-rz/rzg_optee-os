// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2024, Renesas Electronics Corporation
 */

#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include <initcall.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <cpg.h>
#include <sys.h>
#include <xspi.h>
#include <hwsem.h>
#include <cpg_regs.h>
#include <platform_config.h>

#define CPG_DUMMY_READ_COUNT U(7)

static vaddr_t cpg_base;

static void cpg_mreset_enable(vaddr_t base, uint32_t offset, uint32_t mask)
{
	size_t i = 0;
	uint32_t value = 0;

	sys_unlock_pwr();

	value = io_read32(base + offset);
	if ((value & mask) == 0) {
		value |= mask;
		io_write32(base + offset, value);

		for (i = 0; i < CPG_DUMMY_READ_COUNT; i++)
			(void)io_read32(base + offset);
	}

	sys_lock_pwr();
}

static void cpg_mreset_disable(vaddr_t base, uint32_t offset, uint32_t mask)
{
	size_t i = 0;
	uint32_t value = 0;

	sys_unlock_pwr();

	value = io_read32(base + offset);
	if ((value & mask) != 0) {
		value &= ~mask;
		io_write32(base + offset, value);

		for (i = 0; i < CPG_DUMMY_READ_COUNT; i++)
			(void)io_read32(base + offset);
	}

	sys_lock_pwr();
}

static void cpg_mstop_enable(vaddr_t base, uint32_t offset, uint32_t mask)
{
	uint32_t value = 0;

	sys_unlock_cgc();

	value = io_read32(base + offset);
	if ((value & mask) == 0) {
		value |= mask;
		io_write32(base + offset, value);

		(void)io_read32(base + offset);
	}

	sys_lock_cgc();
}

static void cpg_mstop_disable(vaddr_t base, uint32_t offset, uint32_t mask)
{
	uint32_t value = 0;

	sys_unlock_cgc();

	value = io_read32(base + offset);

	if ((value & mask) != 0) {
		value &= ~mask;
		io_write32(base + offset, value);

		(void)io_read32(base + offset);
	}

	sys_lock_cgc();
}

static void cpg_module_start_xspi0(void)
{
	size_t i = 0;

	/* Release module stop */
	cpg_mstop_disable(cpg_base, CPG_MSTPCRA_OFFSET, CPG_MSTPCRA_XSPI0);

	/* Release module reset */
	cpg_mreset_disable(cpg_base, CPG_MRCTLA_OFFSET, CPG_MRCTLA_XSPI0);

	/* Enable slave interface */
	sys_start_slave_xspi0();

	for (i = 0; i < CPG_DUMMY_READ_COUNT; i++)
		(void)xspi_dummy_read(0);
}

static void cpg_module_stop_xspi0(void)
{
	/* Disable slave interface */
	sys_stop_slave_xspi0();

	/* Assert module reset */
	cpg_mreset_enable(cpg_base, CPG_MRCTLA_OFFSET, CPG_MRCTLA_XSPI0);

	/* Enter module stop */
	cpg_mstop_enable(cpg_base, CPG_MSTPCRA_OFFSET, CPG_MSTPCRA_XSPI0);
}

static void cpg_module_start_xspi1(void)
{
	size_t i = 0;

	/* Release module stop */
	cpg_mstop_disable(cpg_base, CPG_MSTPCRA_OFFSET, CPG_MSTPCRA_XSPI1);

	/* Release module reset */
	cpg_mreset_disable(cpg_base, CPG_MRCTLA_OFFSET, CPG_MRCTLA_XSPI1);

	/* Enable slave interface */
	sys_start_slave_xspi1();

	for (i = 0; i < CPG_DUMMY_READ_COUNT; i++)
		(void)xspi_dummy_read(1);
}

static void cpg_module_stop_xspi1(void)
{
	/* Disable slave interface */
	sys_stop_slave_xspi1();

	/* Assert module reset */
	cpg_mreset_enable(cpg_base, CPG_MRCTLA_OFFSET, CPG_MRCTLA_XSPI1);

	/* Enter module stop */
	cpg_mstop_enable(cpg_base, CPG_MSTPCRA_OFFSET, CPG_MSTPCRA_XSPI1);
}

void cpg_xspi_start(void)
{
	sem_regprotect_lock();

	cpg_module_start_xspi0();
	cpg_module_start_xspi1();

	sem_regprotect_unlock();
}

void cpg_xspi_stop(void)
{
	sem_regprotect_lock();

	cpg_module_stop_xspi0();
	cpg_module_stop_xspi1();

	sem_regprotect_unlock();
}

static TEE_Result cpg_init(void)
{
	cpg_base = (vaddr_t)phys_to_virt_io(CPG_BASE, CPG_SIZE);
	assert(cpg_base);
	return TEE_SUCCESS;
}

service_init_late(cpg_init);
