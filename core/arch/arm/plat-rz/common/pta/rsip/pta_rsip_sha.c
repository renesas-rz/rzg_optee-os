// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2024, Renesas Electronics Corporation
 */

#include <kernel/pseudo_ta.h>

#include <r_rsip.h>
#include <pta_rsip_sha.h>

#define PTA_NAME "rsip_sha.pta"

extern rsip_instance_ctrl_t rsip_instance_ctrl;

static TEE_Result sha_generateinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS], rsip_hash_type_t const hash_type)
{
	fsp_err_t err;
	rsip_sha_handle_t *handle;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	handle = (rsip_sha_handle_t *)params[0].memref.buffer;
	if (!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, rsip_sha_handle_t)) {
		EMSG("handle err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = R_RSIP_SHA_GenerateInit(&rsip_instance_ctrl, handle, hash_type);
	switch ((uint32_t)err) {
	case FSP_SUCCESS:
		break;
	case FSP_ERR_ASSERTION:
		return TEE_ERROR_BAD_PARAMETERS;
	case FSP_ERR_NOT_OPEN:
		return TEE_ERROR_BAD_STATE;
	case FSP_ERR_INVALID_STATE:
		return TEE_ERROR_BAD_STATE;
	default:
		return TEE_ERROR_GENERIC;
	}

	params[0].memref.size = sizeof(rsip_sha_handle_t);

	return TEE_SUCCESS;
}

static TEE_Result sha_generateupdate(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;
	rsip_sha_handle_t *handle;
	uint8_t *message;
	uint32_t message_length;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	handle = (rsip_sha_handle_t *)params[0].memref.buffer;
	if (!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, rsip_sha_handle_t)) {
		EMSG("handle err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	message = (uint8_t *)params[1].memref.buffer;
	message_length = (uint32_t)params[1].memref.size;
	if (!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t)) {
		EMSG("message err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = R_RSIP_SHA_GenerateUpdate(&rsip_instance_ctrl, handle, message, message_length);
	switch ((uint32_t)err) {
	case FSP_SUCCESS:
		break;
	case FSP_ERR_ASSERTION:
		return TEE_ERROR_BAD_PARAMETERS;
	case FSP_ERR_NOT_OPEN:
		return TEE_ERROR_BAD_STATE;
	case FSP_ERR_INVALID_STATE:
		return TEE_ERROR_BAD_STATE;
	case FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT:
		return TEE_ERROR_ACCESS_CONFLICT;
	case FSP_ERR_CRYPTO_RSIP_FATAL:
		return TEE_ERROR_GENERIC;
	default:
		return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

static TEE_Result sha_generatefinal(uint32_t types, TEE_Param params[TEE_NUM_PARAMS], uint32_t hash_size)
{
	fsp_err_t err;
	rsip_sha_handle_t *handle;
	uint8_t *digest;
	uint32_t digest_length;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	handle = (rsip_sha_handle_t *)params[0].memref.buffer;
	if (!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, rsip_sha_handle_t)) {
		EMSG("handle err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	digest = (uint8_t *)params[1].memref.buffer;
	digest_length = (uint32_t)params[1].memref.size;
	if (!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t) || (hash_size > digest_length)) {
		EMSG("digest err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = R_RSIP_SHA_GenerateFinal(&rsip_instance_ctrl, handle, digest);
	switch ((uint32_t)err) {
	case FSP_SUCCESS:
		break;
	case FSP_ERR_ASSERTION:
		return TEE_ERROR_BAD_PARAMETERS;
	case FSP_ERR_NOT_OPEN:
		return TEE_ERROR_BAD_STATE;
	case FSP_ERR_INVALID_STATE:
		return TEE_ERROR_BAD_STATE;
	case FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT:
		return TEE_ERROR_ACCESS_CONFLICT;
	case FSP_ERR_CRYPTO_RSIP_FATAL:
		return TEE_ERROR_GENERIC;
	default:
		return TEE_ERROR_BAD_STATE;
	}

	params[1].memref.size = hash_size;

	return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *session __unused, uint32_t cmd,
				 uint32_t ptypes,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	EMSG(PTA_NAME" command %#"PRIx32" ptypes %#"PRIx32, cmd, ptypes);

	switch (cmd) {
	case PTA_CMD_SHA1_Init:
		return sha_generateinit(ptypes, params, RSIP_HASH_TYPE_SHA1);
	case PTA_CMD_SHA224_Init:
		return sha_generateinit(ptypes, params, RSIP_HASH_TYPE_SHA224);
	case PTA_CMD_SHA256_Init:
		return sha_generateinit(ptypes, params, RSIP_HASH_TYPE_SHA256);
	case PTA_CMD_SHA384_Init:
		return sha_generateinit(ptypes, params, RSIP_HASH_TYPE_SHA384);
	case PTA_CMD_SHA512_Init:
		return sha_generateinit(ptypes, params, RSIP_HASH_TYPE_SHA512);
	case PTA_CMD_SHA512_224_Init:
		return sha_generateinit(ptypes, params, RSIP_HASH_TYPE_SHA512_224);
	case PTA_CMD_SHA512_256_Init:
		return sha_generateinit(ptypes, params, RSIP_HASH_TYPE_SHA512_256);

	case PTA_CMD_SHA1_Update:
	case PTA_CMD_SHA224_Update:
	case PTA_CMD_SHA256_Update:
	case PTA_CMD_SHA384_Update:
	case PTA_CMD_SHA512_Update:
	case PTA_CMD_SHA512_224_Update:
	case PTA_CMD_SHA512_256_Update:
		return sha_generateupdate(ptypes, params);

	case PTA_CMD_SHA1_Final:
		return sha_generatefinal(ptypes, params, SHA1_HASH_SIZE);
	case PTA_CMD_SHA224_Final:
		return sha_generatefinal(ptypes, params, SHA224_HASH_SIZE);
	case PTA_CMD_SHA256_Final:
		return sha_generatefinal(ptypes, params, SHA256_HASH_SIZE);
	case PTA_CMD_SHA384_Final:
		return sha_generatefinal(ptypes, params, SHA384_HASH_SIZE);
	case PTA_CMD_SHA512_Final:
		return sha_generatefinal(ptypes, params, SHA512_HASH_SIZE);
	case PTA_CMD_SHA512_224_Final:
		return sha_generatefinal(ptypes, params, SHA512_224_HASH_SIZE);
	case PTA_CMD_SHA512_256_Final:
		return sha_generatefinal(ptypes, params, SHA512_256_HASH_SIZE);

	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

pseudo_ta_register(.uuid = PTA_RSIP_SHA_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invoke_command);
