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

#include <r_sce.h>
#include "platform_config.h"

static sce_cfg_t sce_cfg;
static sce_instance_ctrl_t sce_instance_ctrl;

static TEE_Result SCE_Init(void)
{
	fsp_err_t err;

	int32_t retry_cnt = 3;

	gp_sce = (uint32_t *)phys_to_virt_io(SCE_REG_BASE, SCE_REG_SIZE);

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

driver_init(SCE_Init);
