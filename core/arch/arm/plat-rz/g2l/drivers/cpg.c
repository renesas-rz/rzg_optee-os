/*
 * Copyright (c) 2023, Renesas Electronics Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include <io.h>
#include <initcall.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <cpg.h>
#include <cpg_regs.h>

#define CPG_T_CLK						(0)
#define CPG_T_RST						(1)

typedef struct {
	uintptr_t reg;
	uintptr_t mon;
	uint32_t  val;
	uint32_t  type;
} st_cpg_clkrst_t;

register_phys_mem_pgdir(MEM_AREA_IO_NSEC, CPG_REG_BASE, CPG_REG_SIZE);

static vaddr_t cpg_base;

inline static void cpg_io_write(uint32_t reg, uint32_t data)
{
	io_write32(cpg_base + reg, data);
}

inline static uint32_t cpg_io_read(uint32_t reg)
{
	return io_read32(cpg_base + reg);
}

static const st_cpg_clkrst_t cpg_spi_multi[] = {
	{
		(uintptr_t)CPG_CLKON_SPI_MULTI,
		(uintptr_t)CPG_CLKMON_SPI_MULTI,
		0x00030003,
		CPG_T_CLK
	},
	{
		(uintptr_t)CPG_RST_SPI,
		(uintptr_t)CPG_RSTMON_SPI,
		0x00010001,
		CPG_T_RST
	}
};

static void cpg_clkrst_start(const st_cpg_clkrst_t *tbl, const uint32_t size)
{
	uint32_t cnt;
	uint32_t mask;
	uint32_t cmp;

	for (cnt = 0; cnt < size; cnt++, tbl++) {
		cpg_io_write(tbl->reg, tbl->val);

		mask = (tbl->val >> 16) & 0xFFFF;
		cmp = tbl->val & 0xFFFF;
		if (tbl->type == CPG_T_RST) {
			cmp = ~(cmp);
		}
		while ((cpg_io_read(tbl->mon) & mask) != (cmp & mask))
			;
	}
}

static void cpg_clkrst_stop(const st_cpg_clkrst_t *tbl, const uint32_t size)
{
	uint32_t cnt;
	uint32_t mask;
	uint32_t cmp;

	for (cnt = 0; cnt < size; cnt++, tbl++) {
		cpg_io_write(tbl->reg, tbl->val & 0xFFFF0000);

		mask = (tbl->val >> 16) & 0xFFFF;
		cmp = 0;
		if (tbl->type == CPG_T_RST) {
			cmp = ~(cmp);
		}
		while ((cpg_io_read(tbl->mon) & mask) != (cmp & mask))
			;
	}
}

void cpg_spi_multi_start(void)
{
	cpg_clkrst_start(cpg_spi_multi, ARRAY_SIZE(cpg_spi_multi));
	cpg_io_write(CPG_BUS_MCPU1_MSTOP, 0x00020000);
}

void cpg_spi_multi_stop(void)
{
	cpg_clkrst_stop(cpg_spi_multi, ARRAY_SIZE(cpg_spi_multi));
	cpg_io_write(CPG_BUS_MCPU1_MSTOP, 0x00020002);
}

static TEE_Result cpg_init(void)
{
	cpg_base = (vaddr_t)phys_to_virt_io(CPG_REG_BASE, CPG_REG_SIZE);

	return TEE_SUCCESS;
}

driver_init(cpg_init);
