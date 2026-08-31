// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2024-2025, Renesas Electronics Corporation
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
#include <r_rsip.h>
#include <r_rsip_addr.h>
#include <platform_config.h>

rsip_cfg_t rsip_cfg;
rsip_instance_ctrl_t rsip_instance_ctrl;

volatile uint32_t *gp_sce;

TEE_Result plat_crypto_get_random_bytes(void *buf, size_t len)
{
	TEE_Result ret = TEE_ERROR_GENERIC;

	size_t i = 0;
	uint32_t rand[4];
	const size_t rand_size = sizeof(rand);

	for (i = 0; i < len; i += rand_size) {
		fsp_err_t err = R_RSIP_RandomNumberGenerate(
			&rsip_instance_ctrl, (uint8_t *const)rand);
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

static TEE_Result rsip_init(void)
{
	fsp_err_t err;

	gp_sce = (uint32_t *)phys_to_virt_io(SCE_BASE, SCE_SIZE);

	err = R_RSIP_Open(&rsip_instance_ctrl, &rsip_cfg);
	if (FSP_SUCCESS != err) {
		EMSG("Failed to initialize RSIP (0x%08x).", err);
		panic();
	}

	return TEE_SUCCESS;
}

#ifdef CFG_INSECURE
service_init_crypto(rsip_init);
#else
void plat_rng_init(void)
{
	rsip_init();
}
#endif
