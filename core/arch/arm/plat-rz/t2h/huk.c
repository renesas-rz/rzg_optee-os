// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2024, Renesas Electronics Corporation
 */

#include <trace.h>
#include <kernel/tee_common_otp.h>
#include <tee/tee_cryp_pbkdf2.h>

#include "platform_config.h"
#include <otp_drv.h>

#define REGISTER_SIZE	(sizeof(uint32_t))

static void read_chipid(uint8_t *chipid)
{
	uint32_t i;
	uint32_t read_data;
	uint32_t read_num = OTP_UNIQUE_ID_SIZE / REGISTER_SIZE;
	uint8_t password[OTP_UNIQUE_ID_SIZE] = {0};

	r_otp_read(OTP_UNIQUE_ID_ADDR, (uint32_t *)&password[0], read_num);

	for (i = 0U; i < read_num; i++) {
		(void)memcpy(&read_data, &password[i * REGISTER_SIZE], REGISTER_SIZE);
		read_data = TEE_U32_TO_BIG_ENDIAN(read_data);
		(void)memcpy(&chipid[i * REGISTER_SIZE], &read_data, REGISTER_SIZE);
	}
}

static TEE_Result huk_kdf(uint8_t *huk, size_t huk_length)
{
	uint8_t password[OTP_UNIQUE_ID_SIZE] = {0};

	uint8_t salt[] = {0x76, 0x6A, 0xEF, 0x5C, 0x39, 0xEF, 0x6C, 0x26, 0x41, 0x6C, 0x46, 0x68, 0x05, 0x43, 0x06, 0xC0};

	uint32_t iteration_count = 1000;

	read_chipid(password);

	return tee_cryp_pbkdf2(TEE_ALG_HMAC_SHA256, password, sizeof(password), salt, sizeof(salt), iteration_count,
				huk, huk_length);
}

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	return huk_kdf(hwkey->data, sizeof(hwkey->data));
}
