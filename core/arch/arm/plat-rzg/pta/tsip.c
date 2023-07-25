/*
 * Copyright (c) 2021-2023, Renesas Electronics Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <compiler.h>
#include <trace.h>
#include <kernel/pseudo_ta.h>
#include <kernel/thread.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include "drivers/tsip.h"
#include "drivers/R_TSIP_Core_Lib.h"
#include "pta/tsip_pta.h"

#define TA_NAME "tsip.ta"

#define TEMP_ENC_KEYRING_SIZE	(0x2B0)

static TEE_Result tsip_su_activate(void)
{
	uint32_t err;
	static bool activated = false;

	if (!activated) {
		err = R_TSIP_SU_Activate();
		if (R_PASS != err) {
			EMSG("Failed to activate Firmware Update Process (0x%08x).", err);
			return TEE_ERROR_GENERIC;
		}
		activated = true;
	}
	return TEE_SUCCESS;
}

static TEE_Result tsip_update_keyring(uint32_t type, TEE_Param p[TEE_NUM_PARAMS])
{
	uint32_t err;
	uint32_t exp_type = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (type != exp_type) {
		EMSG("Invalid Param types");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if ((!IS_ALIGNED_WITH_TYPE(p[0].memref.buffer, uint32_t)) ||
		(!IS_ALIGNED_WITH_TYPE(p[1].memref.buffer, uint32_t))) {
		EMSG("Buffer must be 4-byte aligned");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if ((p[0].memref.size < TEMP_ENC_KEYRING_SIZE) ||
		(p[1].memref.size < sizeof(tsip_data->inst))) {
		EMSG("Buffer size is not large enough");
		return TEE_ERROR_SHORT_BUFFER;
	}

	if (tsip_su_activate())
		return TEE_ERROR_GENERIC;

	err = R_TSIP_SU_Key((uint8_t *)p[0].memref.buffer);
	if (R_PASS != err) {
		EMSG("Failed to Re-Encrypt Keyring data via TSIP (0x%08x).", err);
		return TEE_ERROR_GENERIC;
	}

	memcpy((void *)p[1].memref.buffer, (void *)tsip_data->inst, sizeof(tsip_data->inst));

	p[1].memref.size = sizeof(tsip_data->inst);

	return TEE_SUCCESS;
}

static TEE_Result tsip_update_firmware(uint32_t type, TEE_Param p[TEE_NUM_PARAMS])
{
	uint32_t err;
	uintptr_t imem_base;
	uintptr_t omem_base;
	uintptr_t fwu_offset;
	st_update_fw_t *fwu_param;
	TSIP_UPDATE_BOOT_DATA tsip_update_boot_data;

	uint32_t exp_type = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_MEMREF_INOUT, TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT);

	DMSG("has been called");

	if (type != exp_type) {
		EMSG("Invalid Param types");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if ((p[0].value.a <= 0) || (p[0].value.a > UPDATE_BOOT_DATA_MAX) ||
		(p[1].memref.size < (p[0].value.a * sizeof(st_update_fw_t)))) {
		EMSG("Bad parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if ((!IS_ALIGNED_WITH_TYPE(p[2].memref.buffer, uint32_t)) ||
		(!IS_ALIGNED_WITH_TYPE(p[3].memref.buffer, uint32_t))) {
		EMSG("Buffer must be 4-byte aligned");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (tsip_su_activate())
		return TEE_ERROR_GENERIC;

	fwu_offset = 0;
	fwu_param = (st_update_fw_t *)p[1].memref.buffer;
	imem_base = (uintptr_t)p[2].memref.buffer;
	omem_base = (uintptr_t)p[3].memref.buffer;

	memset(tsip_update_boot_data, 0, sizeof(tsip_update_boot_data));

	for (int i = 0; i < p[0].value.a; i++) {

		if (fwu_param[i].length == 0)
			continue;

		if ((!IS_ALIGNED(fwu_param[i].offset, sizeof(uint32_t))) ||
			(!IS_ALIGNED(fwu_param[i].length, sizeof(uint32_t)))) {
			EMSG("Input data must be 4-byte aligned");
			return TEE_ERROR_BAD_PARAMETERS;
		}

		if (fwu_param[i].offset + fwu_param[i].length > p[2].memref.size) {
			EMSG("Input buffer size is not large enough");
			return TEE_ERROR_SHORT_BUFFER;
		}

		tsip_update_boot_data[i].InData_BootData_UpdateFlag = 1;
		tsip_update_boot_data[i].InData_BootData = (uint8_t *)(imem_base + fwu_param[i].offset);
		tsip_update_boot_data[i].InData_BootData_ByteSize = fwu_param[i].length;
		tsip_update_boot_data[i].OutData_BootData = (uint8_t *)omem_base + fwu_offset;

		fwu_param[i].length += (16 + ((i == 0) ? sizeof(tsip_data->head) : 0));
		fwu_param[i].offset = fwu_offset;

		if ((fwu_param[i].offset + fwu_param[i].length) > p[3].memref.size) {
			EMSG("Output buffer size is not large enough");
			return TEE_ERROR_SHORT_BUFFER;
		}

		fwu_offset += fwu_param[i].length;
	}

	err = R_TSIP_UpdateBootData(&tsip_update_boot_data);
	if (R_PASS != err) {
		EMSG("Failed to Re-Encypt Firmware data via TSIP (0x%08x).", err);
		return TEE_ERROR_GENERIC;
	}

	/* Get boot header information for secure boot */
	if (fwu_param[0].length != 0) {
		fwu_offset = (fwu_param[0].offset + fwu_param[0].length) - sizeof(tsip_data->head);
		memcpy((uint8_t *)omem_base + fwu_offset, tsip_data->head, sizeof(tsip_data->head));
	}

	return TEE_SUCCESS;
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
	switch (cmd) {
	case TSIP_CMD_UPDATE_KEYRING:
		return tsip_update_keyring(ptypes, params);
	case TSIP_CMD_UPDATE_FIRMWARE:
		return tsip_update_firmware(ptypes, params);
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
}

pseudo_ta_register(.uuid = TSIP_UUID, .name = TA_NAME,
				   .flags = PTA_DEFAULT_FLAGS,
				   .create_entry_point = create_ta,
				   .destroy_entry_point = destroy_ta,
				   .open_session_entry_point = open_session,
				   .close_session_entry_point = close_session,
				   .invoke_command_entry_point = invoke_command);
