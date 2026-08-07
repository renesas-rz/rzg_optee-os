// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2021-2026, Renesas Electronics Corporation
 */

#include <stdio.h>
#include <string.h>
#include <compiler.h>
#include <trace.h>
#include <kernel/pseudo_ta.h>
#include <mm/tee_pager.h>
#include <mm/tee_mm.h>
#include <platform_config.h>
#include <sflash.h>
#include <pta_flash.h>

#define TA_NAME "flash.ta"

static uintptr_t spi_offset_to_addr(uint32_t ch, uintptr_t offset)
{
	switch (ch) {
#ifdef SFLASH_BASE
	case 0:
		return SFLASH_BASE + offset;
#else
#ifdef SFLASH_0_BASE
	case 0:
		return SFLASH_0_BASE + offset;
#endif
#ifdef SFLASH_1_BASE
	case 1:
		return SFLASH_1_BASE + offset;
#endif
#endif
	default:
		return 0;
	}
}

static TEE_Result spi_flash_write(uint32_t param_types,
				  TEE_Param p[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;

	uintptr_t addr = 0;

	uint32_t exp_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					    TEE_PARAM_TYPE_MEMREF_INPUT,
					    TEE_PARAM_TYPE_NONE,
					    TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_type)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!IS_ALIGNED_WITH_TYPE(p[0].value.a, uint32_t))
		return TEE_ERROR_BAD_PARAMETERS;

	addr = spi_offset_to_addr(p[0].value.b, p[0].value.a);
	if (!addr)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!IS_ALIGNED_WITH_TYPE(p[1].memref.buffer, uint32_t))
		return TEE_ERROR_BAD_PARAMETERS;

	if (0 < p[1].memref.size) {
		res = sflash_open();
		if (res)
			return res;

		res = sflash_write_buffer(addr, (uintptr_t)p[1].memref.buffer,
					  p[1].memref.size);

		sflash_close();
	}

	return res;
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

static TEE_Result invoke_command(void *psess __unused, uint32_t cmd,
				 uint32_t ptypes,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd) {
	case PTA_CMD_FLASH_WRITE_SPI:
		return spi_flash_write(ptypes, params);
	default:
		break;
	}
	return TEE_ERROR_BAD_PARAMETERS;
}

pseudo_ta_register(.uuid = PTA_FLASH_UUID, .name = TA_NAME,
		   .flags = PTA_DEFAULT_FLAGS, .create_entry_point = create_ta,
		   .destroy_entry_point = destroy_ta,
		   .open_session_entry_point = open_session,
		   .close_session_entry_point = close_session,
		   .invoke_command_entry_point = invoke_command);
