// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2026, Renesas Electronics Corporation
 */

#include <string.h>
#include <assert.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <tee_api_types.h>
#include <otp_service.h>
#include <platform_config.h>

#if defined(OTP_CPID_ADDR) && defined(OTP_CPID_SIZE)

#define OTP_CPID_BASE (OTP_BASE + OTP_CPID_ADDR)

TEE_Result otp_read_cpid(void *buf, size_t *len)
{
	size_t i;
	size_t read_len;
	vaddr_t addr;

	assert(buf && len);
	read_len = MIN(*len, (size_t)OTP_CPID_SIZE);

	addr = (vaddr_t)phys_to_virt_io(OTP_CPID_BASE, OTP_CPID_SIZE);
	assert(addr);

	memset(buf, 0, *len);

	for (i = 0; i < read_len; i += sizeof(uint32_t)) {
		uint32_t value = TEE_U32_TO_BIG_ENDIAN(io_read32(addr + i));

		memcpy((uint8_t *)buf + i, &value,
		       MIN(read_len - i, sizeof(value)));
	}

	*len = read_len;

	return TEE_SUCCESS;
}
#endif
