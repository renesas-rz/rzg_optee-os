// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, Renesas Electronics
 */

#include <io.h>
#include <kernel/panic.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <rng_support.h>
#include <platform_config.h>
#include <trace.h>

#include <r_sce.h>
#include <string.h>

#define LOCAL_BUFFER_SIZE (16)

static uint32_t buffer[LOCAL_BUFFER_SIZE / sizeof(uint32_t)];

static TEE_Result random_number_generator(uint32_t *rand, size_t size)
{
	fsp_err_t err;

	size_t n;
	const size_t rand_sz = 4;

	assert(0 == (size % rand_sz));

	for (n = 0; n < size; n += rand_sz)
	{
		err = g_sce_protected_on_sce.randomNumberGenerate(&rand[n]);
		switch (err)
		{
			case FSP_SUCCESS:
				break;
			default: /* FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT */
				return TEE_ERROR_BUSY;
		}
	}

	return TEE_SUCCESS;
}

TEE_Result hw_get_random_bytes(void *buf, size_t len)
{
	TEE_Result ret = TEE_SUCCESS;

	for(size_t i = 0; i < len; i += sizeof(buffer))
	{
		if (TEE_SUCCESS != (ret = random_number_generator(buffer, ARRAY_SIZE(buffer))))
		{
			return ret;
		}
		memcpy(buf + i, buffer, MIN(sizeof(buffer), len - i));
	}

	return ret;
}
