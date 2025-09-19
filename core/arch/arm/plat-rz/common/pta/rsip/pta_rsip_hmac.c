// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2024, Renesas Electronics Corporation
 */

#include <kernel/pseudo_ta.h>

#include <r_rsip.h>
#include <pta_rsip_hmac.h>

#define PTA_NAME "rsip_hmac.pta"

extern rsip_instance_ctrl_t rsip_instance_ctrl;

static TEE_Result hmac_generateinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS],
				    rsip_byte_size_wrapped_key_t key_size)
{
	fsp_err_t err;

	rsip_hmac_handle_t *handle;
	rsip_wrapped_key_t *wrapped_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	handle = (rsip_hmac_handle_t *)params[0].memref.buffer;
	if (!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, rsip_hmac_handle_t)) {
		EMSG("handle err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	wrapped_key = (rsip_wrapped_key_t *)params[1].memref.buffer;
	if (!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t) || (key_size > params[1].memref.size)) {
		EMSG("key err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = R_RSIP_HMAC_GenerateInit(&rsip_instance_ctrl, handle, wrapped_key);
	switch ((uint32_t)err) {
	case FSP_SUCCESS:
		break;
	case FSP_ERR_ASSERTION:
		return TEE_ERROR_BAD_PARAMETERS;
	case FSP_ERR_NOT_OPEN:
		return TEE_ERROR_BAD_STATE;
	case FSP_ERR_INVALID_STATE:
		return TEE_ERROR_BAD_STATE;
	case FSP_ERR_NOT_ENABLED:
		return TEE_ERROR_BAD_PARAMETERS;
	case FSP_ERR_INVALID_ARGUMENT:
		return TEE_ERROR_BAD_PARAMETERS;
	default:
		return TEE_ERROR_GENERIC;
	}

	params[0].memref.size = sizeof(rsip_hmac_handle_t);

	return TEE_SUCCESS;
}

static TEE_Result hmac_generateupdate(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	rsip_hmac_handle_t *handle;
	uint8_t *message;
	uint32_t message_length;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	handle = (rsip_hmac_handle_t *)params[0].memref.buffer;
	if (!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, rsip_hmac_handle_t)) {
		EMSG("handle err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	message = (uint8_t *)params[1].memref.buffer;
	message_length = (uint32_t)params[1].memref.size;
	if (!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t)) {
		EMSG("message err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = R_RSIP_HMAC_GenerateUpdate(&rsip_instance_ctrl, handle, message, message_length);
	switch ((uint32_t)err) {
	case FSP_SUCCESS:
		break;
	case FSP_ERR_ASSERTION:
		return TEE_ERROR_BAD_PARAMETERS;
	case FSP_ERR_NOT_OPEN:
		return TEE_ERROR_BAD_STATE;
	case FSP_ERR_INVALID_STATE:
		return TEE_ERROR_BAD_STATE;
	case FSP_ERR_CRYPTO_RSIP_KEY_SET_FAIL:
		return TEE_ERROR_BAD_PARAMETERS;
	case FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT:
		return TEE_ERROR_ACCESS_CONFLICT;
	case FSP_ERR_CRYPTO_RSIP_FATAL:
		return TEE_ERROR_GENERIC;
	default:
		return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

static TEE_Result hmac_generatefinal(uint32_t types, TEE_Param params[TEE_NUM_PARAMS], uint32_t mac_size)
{
	fsp_err_t err;

	rsip_hmac_handle_t *handle;
	uint8_t *mac;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	handle = (rsip_hmac_handle_t *)params[0].memref.buffer;
	if (!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, rsip_hmac_handle_t)) {
		EMSG("handle err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	mac = (uint8_t *)params[1].memref.buffer;
	if ((!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t)) || (mac_size > params[1].memref.size)) {
		EMSG("mac err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = R_RSIP_HMAC_GenerateFinal(&rsip_instance_ctrl, handle, mac);
	switch ((uint32_t)err) {
	case FSP_SUCCESS:
		break;
	case FSP_ERR_ASSERTION:
		return TEE_ERROR_BAD_PARAMETERS;
	case FSP_ERR_NOT_OPEN:
		return TEE_ERROR_BAD_STATE;
	case FSP_ERR_INVALID_STATE:
		return TEE_ERROR_BAD_STATE;
	case FSP_ERR_CRYPTO_RSIP_KEY_SET_FAIL:
		return TEE_ERROR_BAD_PARAMETERS;
	case FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT:
		return TEE_ERROR_ACCESS_CONFLICT;
	case FSP_ERR_CRYPTO_RSIP_FATAL:
		return TEE_ERROR_GENERIC;
	default:
		return TEE_ERROR_BAD_STATE;
	}

	params[1].memref.size = mac_size;

	return TEE_SUCCESS;
}

static TEE_Result hmac_verifyinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS],
				  rsip_byte_size_wrapped_key_t key_size)
{
	fsp_err_t err;

	rsip_hmac_handle_t *handle;
	rsip_wrapped_key_t *wrapped_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	handle = (rsip_hmac_handle_t *)params[0].memref.buffer;
	if (!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t)) {
		EMSG("handle err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	wrapped_key = (rsip_wrapped_key_t *)params[1].memref.buffer;
	if (!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t) || (key_size > params[1].memref.size)) {
		EMSG("key err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = R_RSIP_HMAC_VerifyInit(&rsip_instance_ctrl, handle, wrapped_key);
	switch ((uint32_t)err) {
	case FSP_SUCCESS:
		break;
	case FSP_ERR_ASSERTION:
		return TEE_ERROR_BAD_PARAMETERS;
	case FSP_ERR_NOT_OPEN:
		return TEE_ERROR_BAD_STATE;
	case FSP_ERR_INVALID_STATE:
		return TEE_ERROR_BAD_STATE;
	case FSP_ERR_NOT_ENABLED:
		return TEE_ERROR_BAD_PARAMETERS;
	case FSP_ERR_INVALID_ARGUMENT:
		return TEE_ERROR_BAD_PARAMETERS;
	default:
		return TEE_ERROR_GENERIC;
	}

	params[0].memref.size = sizeof(rsip_hmac_handle_t);

	return TEE_SUCCESS;
}

static TEE_Result hmac_verifyupdate(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	rsip_hmac_handle_t *handle;
	uint8_t *message;
	uint32_t message_length;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	handle = (rsip_hmac_handle_t *)params[0].memref.buffer;
	if (!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t)) {
		EMSG("handle err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	message = (uint8_t *)params[1].memref.buffer;
	message_length = (uint32_t)params[1].memref.size;
	if (!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t)) {
		EMSG("message err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = R_RSIP_HMAC_VerifyUpdate(&rsip_instance_ctrl, handle, message, message_length);
	switch ((uint32_t)err) {
	case FSP_SUCCESS:
		break;
	case FSP_ERR_ASSERTION:
		return TEE_ERROR_BAD_PARAMETERS;
	case FSP_ERR_NOT_OPEN:
		return TEE_ERROR_BAD_STATE;
	case FSP_ERR_INVALID_STATE:
		return TEE_ERROR_BAD_STATE;
	case FSP_ERR_CRYPTO_RSIP_KEY_SET_FAIL:
		return TEE_ERROR_BAD_PARAMETERS;
	case FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT:
		return TEE_ERROR_ACCESS_CONFLICT;
	case FSP_ERR_CRYPTO_RSIP_FATAL:
		return TEE_ERROR_GENERIC;
	default:
		return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

static TEE_Result hmac_verifyfinal(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	rsip_hmac_handle_t *handle;
	uint8_t *mac;
	uint32_t mac_length;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	handle = (rsip_hmac_handle_t *)params[0].memref.buffer;
	if (!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t)) {
		EMSG("handle err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	mac = (uint8_t *)params[1].memref.buffer;
	mac_length = (uint32_t)params[1].memref.size;
	if (!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t)) {
		EMSG("mac err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = R_RSIP_HMAC_VerifyFinal(&rsip_instance_ctrl, handle, mac, mac_length);
	switch ((uint32_t)err) {
	case FSP_SUCCESS:
		break;
	case FSP_ERR_ASSERTION:
		return TEE_ERROR_BAD_PARAMETERS;
	case FSP_ERR_NOT_OPEN:
		return TEE_ERROR_BAD_STATE;
	case FSP_ERR_INVALID_STATE:
		return TEE_ERROR_BAD_STATE;
	case FSP_ERR_INVALID_SIZE:
		return TEE_ERROR_BAD_PARAMETERS;
	case FSP_ERR_CRYPTO_RSIP_KEY_SET_FAIL:
		return TEE_ERROR_BAD_PARAMETERS;
	case FSP_ERR_CRYPTO_RSIP_FAIL:
		return TEE_ERROR_GENERIC;
	case FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT:
		return TEE_ERROR_ACCESS_CONFLICT;
	case FSP_ERR_CRYPTO_RSIP_FATAL:
		return TEE_ERROR_GENERIC;
	default:
		return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *session __unused, uint32_t cmd,
				 uint32_t ptypes,
		    TEE_Param params[TEE_NUM_PARAMS])
{
	EMSG(PTA_NAME" command %#"PRIx32" ptypes %#"PRIx32, cmd, ptypes);

	switch (cmd) {
	case PTA_CMD_HMAC_SHA1_GenerateInit:
		return hmac_generateinit(ptypes, params, RSIP_BYTE_SIZE_WRAPPED_KEY_HMAC_SHA1);
	case PTA_CMD_HMAC_SHA224_GenerateInit:
		return hmac_generateinit(ptypes, params, RSIP_BYTE_SIZE_WRAPPED_KEY_HMAC_SHA224);
	case PTA_CMD_HMAC_SHA256_GenerateInit:
		return hmac_generateinit(ptypes, params, RSIP_BYTE_SIZE_WRAPPED_KEY_HMAC_SHA256);

	case PTA_CMD_HMAC_SHA1_GenerateUpdate:
	case PTA_CMD_HMAC_SHA224_GenerateUpdate:
	case PTA_CMD_HMAC_SHA256_GenerateUpdate:
		return hmac_generateupdate(ptypes, params);

	case PTA_CMD_HMAC_SHA1_GenerateFinal:
		return hmac_generatefinal(ptypes, params, SHA1_MAC_SIZE);
	case PTA_CMD_HMAC_SHA224_GenerateFinal:
		return hmac_generatefinal(ptypes, params, SHA224_MAC_SIZE);
	case PTA_CMD_HMAC_SHA256_GenerateFinal:
		return hmac_generatefinal(ptypes, params, SHA256_MAC_SIZE);

	case PTA_CMD_HMAC_SHA1_VerifyInit:
		return hmac_verifyinit(ptypes, params, RSIP_BYTE_SIZE_WRAPPED_KEY_HMAC_SHA1);
	case PTA_CMD_HMAC_SHA224_VerifyInit:
		return hmac_verifyinit(ptypes, params, RSIP_BYTE_SIZE_WRAPPED_KEY_HMAC_SHA224);
	case PTA_CMD_HMAC_SHA256_VerifyInit:
		return hmac_verifyinit(ptypes, params, RSIP_BYTE_SIZE_WRAPPED_KEY_HMAC_SHA256);

	case PTA_CMD_HMAC_SHA1_VerifyUpdate:
	case PTA_CMD_HMAC_SHA224_VerifyUpdate:
	case PTA_CMD_HMAC_SHA256_VerifyUpdate:
		return hmac_verifyupdate(ptypes, params);

	case PTA_CMD_HMAC_SHA1_VerifyFinal:
	case PTA_CMD_HMAC_SHA224_VerifyFinal:
	case PTA_CMD_HMAC_SHA256_VerifyFinal:
		return hmac_verifyfinal(ptypes, params);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

pseudo_ta_register(.uuid = PTA_RSIP_HMAC_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invoke_command);
