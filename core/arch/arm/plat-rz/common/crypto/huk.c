// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2021-2025, Renesas Electronics Corporation
 */

#include <assert.h>
#include <trace.h>
#include <io.h>
#include <kernel/tee_common_otp.h>
#include <mm/core_memprot.h>
#include <tee_api_types.h>
#include <tee/tee_cryp_pbkdf2.h>
#include <otp_service.h>
#include <platform_config.h>

/*
 * Reference implementation.
 *
 * Platforms may override this function to obtain root material
 * from OTP, Secure IP, or other device-specific sources.
 */
static TEE_Result huk_read_root_material(uint8_t *buf, size_t *len)
{
	return otp_read_cpid(buf, len);
}

/*
 * Reference implementation of HUK derivation.
 *
 * This sample derives a device-unique HUK from the root material
 * returned by huk_read_root_material(). The default implementation
 * uses the Chip ID as input material for PBKDF2-HMAC-SHA256.
 *
 * Production platforms should replace the root material with a
 * device-specific secret such as a Secure IP HUK or OTP secret.
 *
 * The salt value and iteration count are provided only as reference
 * parameters for the sample implementation and should be reviewed
 * according to product security requirements.
 */
static TEE_Result huk_kdf(uint8_t *huk, size_t huk_length)
{
	uint8_t password[HW_UNIQUE_KEY_LENGTH];
	size_t password_len = sizeof(password);

	static const uint32_t huk_pbkdf2_iteration_count = 1000U;

	static const uint8_t huk_pbkdf2_salt[] = {
		0x76, 0x6A, 0xEF, 0x5C, 0x39, 0xEF, 0x6C, 0x26,
		0x41, 0x6C, 0x46, 0x68, 0x05, 0x43, 0x06, 0xC0,
	};

	TEE_Result res = huk_read_root_material(password, &password_len);
	if (res != TEE_SUCCESS)
		return res;

	return tee_cryp_pbkdf2(TEE_ALG_HMAC_SHA256, password, password_len,
			       huk_pbkdf2_salt, sizeof(huk_pbkdf2_salt),
			       huk_pbkdf2_iteration_count, huk, huk_length);
}

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	return huk_kdf(hwkey->data, sizeof(hwkey->data));
}
