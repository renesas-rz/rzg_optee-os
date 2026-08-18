// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2026, Renesas Electronics Corporation
 */
#include <tee_api_types.h>
#include <rng_support.h>
#include <hw_crypto.h>

#include <hw_crypto.h>

__weak TEE_Result plat_crypto_get_random_bytes(void *buf __unused,
					       size_t len __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result hw_get_random_bytes(void *buf, size_t len)
{
	return plat_crypto_get_random_bytes(buf, len);
}
