// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2025-2026, Renesas Electronics Corporation
 */

#include <stdint.h>
#include <assert.h>
#include <string_ext.h>
#include <tee_api_types.h>
#include <otp_drv.h>
#include <otp_service.h>
#include <platform_config.h>

TEE_Result otp_read_cpid(void *buf, size_t *len)
{
	size_t read_len;
	uint32_t chipid[OTPM_CPID_WORDS];

	assert(buf && len);

	read_len = MIN(*len, sizeof(chipid));

	memset(buf, 0, *len);

	if (!r_otp_read(OTPM_CPID_ADDR, chipid, ARRAY_SIZE(chipid)))
		return TEE_ERROR_GENERIC;

	memcpy(buf, chipid, read_len);

	memzero_explicit(chipid, sizeof(chipid));

	*len = read_len;

	return TEE_SUCCESS;
}
