/*
 * Copyright (c) 2021-2023, Renesas Electronics Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stdio.h>
#include <string.h>
#include <compiler.h>
#include <trace.h>
#include <kernel/pseudo_ta.h>
#include <mm/tee_pager.h>
#include <mm/tee_mm.h>
#include "drivers/spi.h"
#include "pta/flash_pta.h"

#define TA_NAME "flash.ta"

static TEE_Result spi_write(uint32_t param_types, TEE_Param p[TEE_NUM_PARAMS])
{
	TEE_Result result = TEE_SUCCESS;

	uint32_t exp_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
										TEE_PARAM_TYPE_MEMREF_INPUT,
										TEE_PARAM_TYPE_NONE,
										TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_type)
		return TEE_ERROR_BAD_PARAMETERS;

	rzg_spi_init_driver();

	if (0 < p[1].memref.size) {

		if (rzg_spi_write_buff(p[0].value.a, (uint64_t)p[1].memref.buffer, p[1].memref.size)) {
			EMSG("Fail to write data to SPI");
			result = TEE_ERROR_GENERIC;
		}
	}

	rzg_spi_deinit_driver();

	return result;
}

/*
 * Trusted Application Entry Points
 */
static TEE_Result create_ta(void)
{
	DMSG("create entry point for pseudo TA \"%s\"", TA_NAME);
	return TEE_SUCCESS;
}

static void destroy_ta(void)
{
	DMSG("destroy entry point for pseudo ta \"%s\"", TA_NAME);
}

static TEE_Result open_session(uint32_t nParamTypes __unused,
							   TEE_Param pParams[TEE_NUM_PARAMS] __unused,
							   void **ppSessionContext __unused)
{
	DMSG("open entry point for pseudo ta \"%s\"", TA_NAME);
	return TEE_SUCCESS;
}

static void close_session(void *pSessionContext __unused)
{
	DMSG("close entry point for pseudo ta \"%s\"", TA_NAME);
}

static TEE_Result invoke_command(void *psess __unused,
								 uint32_t cmd, uint32_t ptypes,
								 TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd)
	{
	case FLASH_CMD_WRITE_SPI:
		return spi_write(ptypes, params);
	default:
		break;
	}
	return TEE_ERROR_BAD_PARAMETERS;
}

pseudo_ta_register(.uuid = FLASH_UUID, .name = TA_NAME,
				   .flags = PTA_DEFAULT_FLAGS,
				   .create_entry_point = create_ta,
				   .destroy_entry_point = destroy_ta,
				   .open_session_entry_point = open_session,
				   .close_session_entry_point = close_session,
				   .invoke_command_entry_point = invoke_command);
