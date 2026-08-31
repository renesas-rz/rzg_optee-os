// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2021-2025, Renesas Electronics Corporation
 */

#include <string.h>
#include <assert.h>
#include <initcall.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <kernel/panic.h>
#include <hw_crypto.h>
#include <tee/tee_cryp_utl.h>
#include <sflash.h>
#include <r_sce.h>
#include <platform_config.h>

static sce_cfg_t sce_cfg;
static sce_instance_ctrl_t sce_instance_ctrl;

TEE_Result plat_crypto_get_random_bytes(void *buf, size_t len)
{
	TEE_Result ret = TEE_ERROR_GENERIC;

	size_t i = 0;
	uint32_t rand[4];
	const size_t rand_size = sizeof(rand);

	for (i = 0; i < len; i += rand_size) {
		fsp_err_t err =
			g_sce_protected_on_sce.randomNumberGenerate(rand);
		if (err != FSP_SUCCESS)
			return TEE_ERROR_BUSY;

		memcpy((uint8_t *)buf + i, rand, MIN(rand_size, len - i));
	}

	if (i >= len)
		ret = TEE_SUCCESS;

	return ret;
}

#if defined(SFLASH_KUK_ADDR)
TEE_Result plat_crypto_get_key_update_key(uint8_t *key, size_t len)
{
	sflash_open();
	sflash_read(SFLASH_KUK_ADDR, (uintptr_t)key, len);
	sflash_close();
	return TEE_SUCCESS;
}
#endif /* SFLASH_KUK_ADDR */

static TEE_Result sce_init(void)
{
	fsp_err_t err;

	int32_t retry_cnt = 3;

	gp_sce = (uint32_t *)phys_to_virt_io(SCE_BASE, SCE_SIZE);

	while (0 < retry_cnt) {
		err = g_sce_protected_on_sce.open(&sce_instance_ctrl, &sce_cfg);
		switch (err) {
		case FSP_ERR_CRYPTO_SCE_RETRY:
			retry_cnt--;
			break;
		default:
			retry_cnt = 0;
			break;
		}
	}

	if (FSP_SUCCESS != err) {
		EMSG("Failed to initialize SCE (0x%08x).", err);
		panic();
	}

	return TEE_SUCCESS;
}

#ifdef CFG_INSECURE
service_init_crypto(sce_init);
#else
void plat_rng_init(void)
{
	sce_init();
}
#endif
