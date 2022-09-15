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

#define LOCAL_BUFFER_SIZE (16)

static int32_t pos = -1;
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

uint8_t hw_get_random_byte(void)
{
	uint8_t *queue = (uint8_t *)buffer;

	if (pos > 0) {
		pos--;
		return queue[pos];
	}

	if (TEE_SUCCESS != random_number_generator(buffer, ARRAY_SIZE(buffer)))
	{
		panic("Failed to generate random numbers");
	}

	pos = LOCAL_BUFFER_SIZE - 1;

	return queue[pos];
}
