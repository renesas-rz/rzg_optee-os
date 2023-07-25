// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2021-2023 Renesas Electronics Corporation. All rights reserved.
 */

#include <initcall.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <kernel/panic.h>
#include "drivers/tsip.h"
#include "drivers/R_TSIP_Core_Lib.h"

s_tsip_data_st *tsip_data = NULL;

static TEE_Result init_tsip(void)
{
	uint32_t err;
	vaddr_t tsip_base_address;
	vaddr_t mstp_base_address;

	tsip_base_address = (vaddr_t)phys_to_virt_io(TSIP_BASE_ADDR, TSIP_SIZE);
	mstp_base_address = (vaddr_t)phys_to_virt_io(MSTP_BASE_ADDR, MSTP_SIZE);

	tsip_data = (s_tsip_data_st *)phys_to_virt_io(TSIP_DATA_ADDR, TSIP_DATA_SIZE);

	err = R_TSIP_Lib_Init((uint8_t *)tsip_data->sram, (uint8_t *)tsip_data->inst,
						  (uint8_t *)tsip_base_address, (uint8_t *)mstp_base_address);
	if (R_PASS != err)
	{
		EMSG("Failed to initialize TSIP Library (0x%08x).", err);
		panic();
	}

	return TEE_SUCCESS;
}

driver_init(init_tsip);
