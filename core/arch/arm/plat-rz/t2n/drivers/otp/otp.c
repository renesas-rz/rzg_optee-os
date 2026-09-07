// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2025-2026, Renesas Electronics Corporation
 */

#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <string_ext.h>
#include <tee_api_types.h>
#include <otp_drv.h>
#include <otp_service.h>
#include <platform_config.h>

static bool rzt2n_otp_read(uint32_t addr, uint32_t *p_value, uint32_t count)
{
	size_t half_words = count * 2;
	uint16_t *dst = (uint16_t *)p_value;

	for (size_t i = 0U; i < half_words; i++) {
		uint32_t data = 0;

		if (!r_otp_read(addr + i, &data, 1))
			return false;
		dst[i] = (uint16_t)data;
	}
	return true;
}

TEE_Result otp_read_cpid(void *buf, size_t *len)
{
	size_t read_len;
	uint32_t chipid[OTPM_CPID_SIZE / sizeof(uint32_t)];

	assert(buf && len);

	read_len = MIN(*len, sizeof(chipid));

	memset(buf, 0, *len);

	if (!rzt2n_otp_read(OTPM_CPID_ADDR, chipid, ARRAY_SIZE(chipid)))
		return TEE_ERROR_GENERIC;

	memcpy(buf, chipid, read_len);

	memzero_explicit(chipid, sizeof(chipid));

	*len = read_len;

	return TEE_SUCCESS;
}
