// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, Renesas Electronics
 */

#include <trace.h>
#include <io.h>
#include <kernel/panic.h>
#include <kernel/tee_common_otp.h>
#include <mm/core_memprot.h>
#include <tee/tee_cryp_pbkdf2.h>

#define CHIPID_BASE		(0x11861140U)
#define CHIPID_SIZE		(16)

#define REGISTER_SIZE	(sizeof(uint32_t))

register_phys_mem_pgdir(MEM_AREA_IO_SEC, CHIPID_BASE, CHIPID_SIZE);

static void read_chipid(uint8_t *chipid)
{
	uint32_t i;
	vaddr_t  addr_va;
	uint32_t read_num = CHIPID_SIZE / REGISTER_SIZE;

	addr_va = (vaddr_t)phys_to_virt_io(CHIPID_BASE);

	for (i = 0U; i < read_num; i++) {
		uint32_t read_data = io_read32(addr_va);
		read_data = TEE_U32_TO_BIG_ENDIAN(read_data);
		(void)memcpy(&chipid[i * REGISTER_SIZE], &read_data, REGISTER_SIZE);
		addr_va += REGISTER_SIZE;
	}
}

static TEE_Result huk_kdf(uint8_t *huk, size_t huk_length)
{
	uint8_t password[CHIPID_SIZE];

	uint8_t salt[] = {0x76,0x6A,0xEF,0x5C,0x39,0xEF,0x6C,0x26,0x41,0x6C,0x46,0x68,0x05,0x43,0x06,0xC0};

	uint32_t iteration_count = 1000;

	read_chipid(password);

	return tee_cryp_pbkdf2(TEE_ALG_HMAC_SHA256, password, sizeof(password), salt, sizeof(salt), iteration_count,
				huk, huk_length);
}

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	return huk_kdf(hwkey->data, sizeof(hwkey->data));
}
