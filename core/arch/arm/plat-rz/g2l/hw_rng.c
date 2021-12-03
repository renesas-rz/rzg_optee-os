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

#include "drivers/sce.h"

#define LOCAL_BUFFER_SIZE 16

static int32_t pos = -1;
static uint32_t buffer[LOCAL_BUFFER_SIZE / sizeof(uint32_t)];

uint8_t hw_get_random_byte(void)
{
	uint8_t *queue = (uint8_t *)buffer;

	if (pos > 0) {
		pos--;
		return queue[pos];
	}

	if (TEE_SUCCESS != SCE_RandomNumberGenerate(buffer, ARRAY_SIZE(buffer)))
	{
		panic("Failed to generate random numbers");
	}

	pos = LOCAL_BUFFER_SIZE - 1;

	return queue[pos];
}
