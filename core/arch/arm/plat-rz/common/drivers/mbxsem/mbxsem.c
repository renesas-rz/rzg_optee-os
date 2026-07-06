// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2025, Renesas Electronics Corporation
 */

#include <initcall.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <trace.h>
#include <mbxsem.h>
#include <mbxsem_regs.h>
#include <platform_config.h>

static vaddr_t mbxsem_base;

static inline void mbxsem_io_write(uint32_t reg, uint32_t value)
{
	io_write32(mbxsem_base + reg, value);
}

static inline uint32_t mbxsem_io_read(uint32_t reg)
{
	return io_read32(mbxsem_base + reg);
}

void mbxsem_sem_lock(enum mbxsem_num sem_num)
{
	uint32_t value;

	assert(sem_num < MBXSEM_NUM_MAX);

	value = mbxsem_io_read(MBXSEM_SEMRCENAR);
	assert((value & MBXSEM_SEMRCENAR_EN(sem_num)) != 0U);

	/*
	 * SEMAR uses read-clear semantics.
	 * Reading a value of 1 acquires the semaphore and
	 * automatically clears the SEM bit to 0.
	 */
	while ((mbxsem_io_read(MBXSEM_SEMAR(sem_num)) & MBXSEM_SEMAR_SEM) == 0U)
		;
}

void mbxsem_sem_unlock(enum mbxsem_num sem_num)
{
	uint32_t value;

	assert(sem_num < MBXSEM_NUM_MAX);

	value = mbxsem_io_read(MBXSEM_SEMRCENAR);
	assert((value & MBXSEM_SEMRCENAR_EN(sem_num)) != 0U);

	mbxsem_io_write(MBXSEM_SEMAR(sem_num), MBXSEM_SEMAR_SEM);
}

void mbxsem_sem_init(enum mbxsem_num sem_num)
{
	uint32_t value;

	assert(sem_num < MBXSEM_NUM_MAX);

	value = mbxsem_io_read(MBXSEM_SEMRCENAR);

	if ((MBXSEM_SEMRCENAR_EN(sem_num) & value) == 0U) {
		mbxsem_io_write(MBXSEM_SEMAR(sem_num), MBXSEM_SEMAR_SEM);
		mbxsem_io_write(MBXSEM_SEMRCENAR,
				MBXSEM_SEMRCENAR_EN(sem_num) | value);
	}
}

static TEE_Result mbxsem_init(void)
{
	mbxsem_base = (vaddr_t)phys_to_virt_io(MBXSEM_BASE, MBXSEM_SIZE);
	if (!mbxsem_base)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

early_init(mbxsem_init);
