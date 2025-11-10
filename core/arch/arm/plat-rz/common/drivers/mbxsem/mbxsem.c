// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2025, Renesas Electronics Corporation
 */

#include <initcall.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <trace.h>
#include <platform_config.h>
#include <mbxsem.h>
#include <mbxsem_regs.h>

static vaddr_t mbxsem_base;

void mbxsem_wait(uint8_t sem_num)
{
	uint32_t value;

	value = io_read32(mbxsem_base + MBXSEM_SEMRCENAR);

	if (MBXSEM_SEMRCENAR_EN(value, sem_num))
		while ((io_read32(mbxsem_base + MBXSEM_SEMAR(sem_num))
			    & MBXSEM_SEMAR_SEM) != MBXSEM_SEMAR_SEM)
			;
}

void mbxsem_post(uint8_t sem_num)
{
	uint32_t value;

	value = io_read32(mbxsem_base + MBXSEM_SEMRCENAR);

	if (MBXSEM_SEMRCENAR_EN(value, sem_num))
		io_write32(mbxsem_base + MBXSEM_SEMAR(sem_num), MBXSEM_SEMAR_SEM);
}

static TEE_Result mbxsem_init(void)
{
	mbxsem_base = (vaddr_t)phys_to_virt_io(MBXSEM_BASE, MBXSEM_SIZE);

	return TEE_SUCCESS;
}

service_init(mbxsem_init);

