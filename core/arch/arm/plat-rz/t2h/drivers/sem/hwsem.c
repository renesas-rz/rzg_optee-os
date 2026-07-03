// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2026, Renesas Electronics Corporation
 */

#include <initcall.h>
#include <mbxsem.h>
#include <hwsem.h>

#define MBXSEM_REGPROTECT MBXSEM_NUM_7

void sem_regprotect_lock(void)
{
	mbxsem_sem_lock(MBXSEM_REGPROTECT);
}

void sem_regprotect_unlock(void)
{
	mbxsem_sem_unlock(MBXSEM_REGPROTECT);
}

static TEE_Result sem_init(void)
{
	mbxsem_sem_init(MBXSEM_REGPROTECT);
	return TEE_SUCCESS;
}

service_init(sem_init);
