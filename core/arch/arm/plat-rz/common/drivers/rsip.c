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

#include <r_rsip.h>
#include <r_rsip_addr.h>

rsip_cfg_t rsip_cfg;
rsip_instance_ctrl_t rsip_instance_ctrl;

volatile uint32_t *gp_sce;

static TEE_Result RSIP_Init(void)
{
	fsp_err_t err;

	gp_sce = (uint32_t *)phys_to_virt_io(SCE_REG_BASE, SCE_REG_SIZE);

	err = R_RSIP_Open(&rsip_instance_ctrl, &rsip_cfg);
	if (FSP_SUCCESS != err) {
		EMSG("Failed to initialize RSIP (0x%08x).", err);
		panic();
	}

	return TEE_SUCCESS;
}

service_init(RSIP_Init);
