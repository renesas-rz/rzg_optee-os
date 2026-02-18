// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2026, Renesas Electronics Corporation
 */

#include <string.h>
#include <io.h>
#include <kernel/panic.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <rng_support.h>
#include <platform_config.h>
#include <trace.h>

#if CFG_RZ_TSIP
#include <r_sce.h>
#endif
#if CFG_RZ_RSIP
#include <r_rsip.h>
extern rsip_instance_ctrl_t rsip_instance_ctrl;
#endif

#define LOCAL_BUFFER_SIZE (16)

static uint32_t buffer[LOCAL_BUFFER_SIZE / sizeof(uint32_t)];

#if CFG_RZ_TSIP
static fsp_err_t get_random_number(uint32_t *rand)
{
	return g_sce_protected_on_sce.randomNumberGenerate(rand);
}
#endif

#if CFG_RZ_RSIP
static fsp_err_t get_random_number(uint32_t *rand)
{
	return R_RSIP_RandomNumberGenerate(&rsip_instance_ctrl, (uint8_t *const)rand);
}
#endif

static TEE_Result random_number_generator(uint32_t *rand, size_t size)
{
	size_t n;
	const size_t rand_sz = 4;

	assert(0 == (size % rand_sz));

	for (n = 0; n < size; n += rand_sz) {
		fsp_err_t err = get_random_number(&rand[n]);

		switch (err) {
		case FSP_SUCCESS:
			break;
		default:
			return TEE_ERROR_BUSY;
		}
	}

	return TEE_SUCCESS;
}

TEE_Result hw_get_random_bytes(void *buf, size_t len)
{
	TEE_Result ret = TEE_SUCCESS;

	for (size_t i = 0; i < len; i += sizeof(buffer)) {
		ret = random_number_generator(buffer, ARRAY_SIZE(buffer));
		if (ret != TEE_SUCCESS)
			return ret;

		memcpy((uintptr_t)buf + i, buffer, MIN(sizeof(buffer), len - i));
	}

	return ret;
}
