// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2024, Renesas Electronics Corporation
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
	uintptr_t addr;
	uint32_t  val;
} CPG_REG_SETTING;

typedef struct {
	CPG_REG_SETTING reg;
	CPG_REG_SETTING mon;
	uint32_t  type;
} CPG_SETUP_DATA;


register_phys_mem_pgdir(MEM_AREA_IO_NSEC, CPG_REG_BASE, CPG_REG_SIZE);

static vaddr_t cpg_base;

inline static void cpg_io_write(uint32_t reg, uint32_t data)
{
	DMSG("cpg_io_write: Addr:0x%x, Val:0x%x ", reg, data);
	io_write32(cpg_base + reg, data);
}

inline static uint32_t cpg_io_read(uint32_t reg)
{
	uint32_t ret;
	ret = io_read32(cpg_base + reg);
	DMSG("cpg_io_read: Addr:0x%x, Val:0x%x ", reg, ret);
	return ret;
}

static CPG_SETUP_DATA cpg_clk_on_tbl[] = {

	{	/* xSPI */
		.reg =  {
				.addr = (uintptr_t)CPG_CLKON_9,
				.val  = 0x00008000,
				},

		.mon =  {
				.addr = (uintptr_t)CPG_CLKMON_4,
				.val  = 0x80000000,
				},

		.type = CPG_T_CLK
	},

	{	/* xSPI */
		.reg =  {
				.addr = (uintptr_t)CPG_CLKON_10,
				.val  = 0x00000003,
				},

		.mon =  {
				.addr = (uintptr_t)CPG_CLKMON_5,
				.val  = 0x00000007,
				},

		.type = CPG_T_CLK
	},
};


static CPG_SETUP_DATA cpg_reset_tbl[] = {
	{	/* xSPI */
		.reg =  {
				.addr = (uintptr_t)CPG_RST_10,
				.val  = 0x00000018,
				},

		.mon =  {
				.addr = (uintptr_t)CPG_RSTMON_4,
				.val  = 0x00300000,
				},

		.type = CPG_T_RST
	}
};

static void cpg_clkon_rst(CPG_SETUP_DATA const *array, uint32_t num)
{
	int i;
	uint32_t mask;
	uint32_t cmp;

	for (i = 0; i < num; i++, array++) {
		/*
		 * Upper 16bits are enables for lower 16bits so write the upper 16bits with same value as lower value
		 */
		uint32_t val = (array->reg.val & 0xFFFF) | ((array->reg.val & 0xFFFF) << 16);

		cpg_io_write(array->reg.addr, val);

		mask = array->mon.val;
		cmp  = mask;

		if (array->type == CPG_T_RST)
			cmp = ~cmp;

		while ((cpg_io_read(array->mon.addr) & mask) != (cmp & mask))
			;
	}
}

static void cpg_clkoff_rst(CPG_SETUP_DATA const *array, uint32_t num)
{
	int i;
	uint32_t mask;
	uint32_t cmp;

	for (i = 0; i < num; i++, array++) {
		/*
		 * Upper 16bits are enables for lower 16bits so write the upper 16bits with same value as lower value
		 */
		uint32_t val = (array->reg.val & 0xFFFF) | ((array->reg.val & 0xFFFF) << 16);


		if ((array->type == CPG_T_CLK) || (array->type == CPG_T_RST))
			val = val & 0xffff0000;

		cpg_io_write(array->reg.addr, val);

		mask = array->mon.val;
		cmp  = mask;

		if (array->type == CPG_T_CLK)
			cmp = ~cmp;

		while ((cpg_io_read(array->mon.addr) & mask) != (cmp & mask))
			;
	}
}



void cpg_xspi_start(void)
{
	DMSG("cpg_xspi_start is called.");

	cpg_clkon_rst(&cpg_clk_on_tbl[0], ARRAY_SIZE(cpg_clk_on_tbl));
	cpg_clkon_rst(&cpg_reset_tbl[0], ARRAY_SIZE(cpg_reset_tbl));

	cpg_io_write(CPG_BUS_4_MSTOP, 0x00200000);
	cpg_io_write(CPG_BUS_5_MSTOP, 0x00200000);

	cpg_io_write(CPG_CSDIV, 0x10002000);
	cpg_io_write(CPG_SSEL1, 0x10001000);
}

void cpg_xspi_stop(void)
{
	DMSG("cpg_xspi_stop is called.");

	cpg_clkoff_rst(&cpg_clk_on_tbl[0], ARRAY_SIZE(cpg_clk_on_tbl));
	cpg_clkoff_rst(&cpg_reset_tbl[0], ARRAY_SIZE(cpg_reset_tbl));

	cpg_io_write(CPG_BUS_4_MSTOP, 0x00200020);
	cpg_io_write(CPG_BUS_5_MSTOP, 0x00200020);
}

static TEE_Result cpg_init(void)
{
	cpg_base = (vaddr_t)phys_to_virt_io(CPG_REG_BASE, CPG_REG_SIZE);

	return TEE_SUCCESS;
}

driver_init(cpg_init);
