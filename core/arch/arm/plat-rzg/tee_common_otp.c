// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2019-2020, Renesas Electronics Corporation
 */

#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <trace.h>
#include <io.h>
#include <tee/tee_cryp_utl.h>
#include <kernel/tee_common_otp.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>

#include "tomcrypt.h"

#define LIFEC_BASE	(0xE6110000U)	/* Life Cycle base address */

static void read_uid_reg(uint8_t *read_uid, uint32_t read_num);

static const uint32_t uid_read_num = 3U;
static const uint32_t reg_size = sizeof(uint32_t);

static void read_uid_reg(uint8_t *read_uid, uint32_t read_num)
{
	uint32_t uid;
	uint32_t i;
	uint32_t lifec_va;
	uint32_t uid_addr;

	lifec_va = (uint32_t) phys_to_virt_io(LIFEC_BASE, 0x50U);
	uid_addr = lifec_va + 0x40U;

	/* get uid from LifeC register. */
	for (i = 0U; i < read_num; i++) {
		uid = io_read32(uid_addr);
		uid = TEE_U32_TO_BIG_ENDIAN(uid);
		(void)memcpy(&read_uid[i * reg_size], &uid, reg_size);
		uid_addr += reg_size;
	}
}

TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	TEE_Result rc = TEE_ERROR_GENERIC;

	const uint8_t string_for_die_id_gen[] = "rzg_hw_unique_key";

	const uint32_t uid_size = uid_read_num * reg_size;
	const uint32_t str_size = sizeof(string_for_die_id_gen);

	const uint32_t indata_size = uid_size + str_size;
	const uint32_t digest_size = (uint32_t)TEE_SHA256_HASH_SIZE;

	uint8_t input_data[indata_size];
	uint8_t digest[digest_size];

	if (hwkey != NULL) {
		int res;
		hash_state hs;
		uint32_t i;

		/* get uid from LifeC register. */
		read_uid_reg(input_data, uid_read_num);

		/* edit input data. add a fixed string. */
		(void)memcpy(&input_data[uid_size], string_for_die_id_gen, str_size);

		/* get hash for SHA256 */
		if ((res = sha256_init(&hs)) == CRYPT_OK) {
			if ((res = sha256_process(&hs, input_data, indata_size)) == CRYPT_OK) {
				if ((res = sha256_done(&hs, digest)) == CRYPT_OK) {
					for (i = 0U; i < HW_UNIQUE_KEY_LENGTH; i++) {
						hwkey->data[i] = digest[i % digest_size];
					}
					rc = TEE_SUCCESS;	/* success */
				} else {
					EMSG("sha256_done() error. 0x%x", res);
				}
			} else {
				EMSG("sha256_process() error. 0x%x", res);
			}
		} else {
			EMSG("sha256_init() error. 0x%x", res);
		}
	} else {
		EMSG("hwkey is 0x%p.", hwkey);
	}

	return rc;
}

int tee_otp_get_die_id(uint8_t *buffer, size_t len)
{
	int32_t rc = -1;

	const uint32_t uid_size = uid_read_num * reg_size;

	uint8_t read_uid[uid_size];

	if ((buffer != NULL) && (len != 0U)) {
		uint32_t i;

		/* get uid from LifeC register. */
		read_uid_reg(read_uid, uid_read_num);

		for (i = 0U; i < len; i++) {
			buffer[i] = read_uid[i % uid_size];
		}
		rc = 0;	/* success */
	} else {
		EMSG("buffer is 0x%p. len is %zu.", buffer, len);
	}

	return rc;
}
