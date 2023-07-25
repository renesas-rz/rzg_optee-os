// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2019-2023, Renesas Electronics Corporation
 */

#include <trace.h>
#include <io.h>
#include <kernel/panic.h>
#include <kernel/tee_common_otp.h>
#include <mm/core_memprot.h>
#include <tee/tee_cryp_pbkdf2.h>

#define LIFEC_BASE	(0xE6110000U)	/* Life Cycle base address */

static void read_uid_reg(uint8_t *read_uid, uint32_t read_num);

static const uint32_t uid_read_num = 3U;
static const uint32_t reg_size = sizeof(uint32_t);

static void read_uid_reg(uint8_t *read_uid, uint32_t read_num)
{
	uint32_t i;
	vaddr_t uid_addr;

	uid_addr = (vaddr_t) phys_to_virt_io(LIFEC_BASE, 0x50U);
	uid_addr = uid_addr + 0x40U;

	/* get uid from LifeC register. */
	for (i = 0U; i < read_num; i++) {
		uint32_t uid = TEE_U32_TO_BIG_ENDIAN(io_read32(uid_addr));
		(void)memcpy(&read_uid[i * reg_size], &uid, reg_size);
		uid_addr += reg_size;
	}
}

static TEE_Result huk_kdf(uint8_t *huk, size_t huk_length)
{
	uint8_t password[uid_read_num * reg_size];

	uint8_t salt[] = {0x76,0x6A,0xEF,0x5C,0x39,0xEF,0x6C,0x26,0x41,0x6C,0x46,0x68,0x05,0x43,0x06,0xC0};

	uint32_t iteration_count = 1000;

	read_uid_reg(password, uid_read_num);

	return tee_cryp_pbkdf2(TEE_ALG_HMAC_SHA256, password, sizeof(password), salt, sizeof(salt), iteration_count,
				huk, huk_length);
}

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	return huk_kdf(hwkey->data, sizeof(hwkey->data));
}
