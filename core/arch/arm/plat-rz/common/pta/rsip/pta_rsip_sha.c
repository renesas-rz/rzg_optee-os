// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2024, Renesas Electronics Corporation
 */

#include <kernel/pseudo_ta.h>
#include <r_rsip.h>
#include <pta_rsip_sha.h>

#include "pta_rsip_cmd.h"
#include "pta_rsip_util.h"

#define PTA_NAME "rsip_sha.pta"

struct rsip_sha_desc {
	rsip_hash_type_t type;
	size_t digest_size;
};

struct sha_ctx {
	struct rsip_sha_desc desc;
	rsip_sha_handle_t handle;
};

static TEE_Result get_sha_desc(enum pta_sha_type type,
			       struct rsip_sha_desc *desc)
{
	switch (type) {
	case PTA_SHA_TYPE_SHA1:
		desc->type = RSIP_HASH_TYPE_SHA1;
		desc->digest_size = RSIP_DIGEST_SIZE_SHA1;
		return TEE_SUCCESS;
	case PTA_SHA_TYPE_SHA224:
		desc->type = RSIP_HASH_TYPE_SHA224;
		desc->digest_size = RSIP_DIGEST_SIZE_SHA224;
		return TEE_SUCCESS;
	case PTA_SHA_TYPE_SHA256:
		desc->type = RSIP_HASH_TYPE_SHA256;
		desc->digest_size = RSIP_DIGEST_SIZE_SHA256;
		return TEE_SUCCESS;
	case PTA_SHA_TYPE_SHA384:
		desc->type = RSIP_HASH_TYPE_SHA384;
		desc->digest_size = RSIP_DIGEST_SIZE_SHA384;
		return TEE_SUCCESS;
	case PTA_SHA_TYPE_SHA512:
		desc->type = RSIP_HASH_TYPE_SHA512;
		desc->digest_size = RSIP_DIGEST_SIZE_SHA512;
		return TEE_SUCCESS;
	case PTA_SHA_TYPE_SHA512_224:
		desc->type = RSIP_HASH_TYPE_SHA512_224;
		desc->digest_size = RSIP_DIGEST_SIZE_SHA224;
		return TEE_SUCCESS;
	case PTA_SHA_TYPE_SHA512_256:
		desc->type = RSIP_HASH_TYPE_SHA512_256;
		desc->digest_size = RSIP_DIGEST_SIZE_SHA256;
		return TEE_SUCCESS;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

static TEE_Result sha_init(struct sha_ctx *ctx, uint32_t types,
			   TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

	uint32_t exp_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	if (types != exp_types)
		return TEE_ERROR_BAD_PARAMETERS;

	res = get_sha_desc((enum pta_sha_type)params[0].value.a, &ctx->desc);
	if (res != TEE_SUCCESS)
		return res;

	err = R_RSIP_SHA_GenerateInit(&rsip_instance_ctrl, &ctx->handle,
				      ctx->desc.type);
	if (err != FSP_SUCCESS)
		return rsip_err_to_tee(err);

	return TEE_SUCCESS;
}

static TEE_Result sha_update(struct sha_ctx *ctx, uint32_t types,
			     TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

	uint8_t *msg = NULL;
	uint32_t msg_len = 0;

	uint32_t exp_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_NONE,
					     TEE_PARAM_TYPE_NONE,
					     TEE_PARAM_TYPE_NONE);
	if (types != exp_types)
		return TEE_ERROR_BAD_PARAMETERS;

	msg = params[0].memref.buffer;
	msg_len = (uint32_t)params[0].memref.size;
	if (msg_len && (!msg || !IS_ALIGNED_WITH_UINT32(msg)))
		return TEE_ERROR_BAD_PARAMETERS;
	if (!IS_ALIGNED(msg_len, sizeof(uint32_t)))
		return TEE_ERROR_BAD_PARAMETERS;

	err = R_RSIP_SHA_GenerateUpdate(&rsip_instance_ctrl, &ctx->handle, msg,
					msg_len);
	if (err != FSP_SUCCESS)
		return rsip_err_to_tee(err);

	return TEE_SUCCESS;
}

static TEE_Result sha_final(struct sha_ctx *ctx, uint32_t types,
			    TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

	uint8_t *msg = NULL;
	uint32_t msg_len = 0;
	uint32_t msg_tail[1] = { 0 };
	uint8_t *digest = NULL;
	uint32_t digest_max = 0;
	uint32_t digest_buff[RSIP_DIGEST_SIZE_MAX / sizeof(uint32_t)] = { 0 };

	uint32_t exp_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_MEMREF_OUTPUT,
					     TEE_PARAM_TYPE_NONE,
					     TEE_PARAM_TYPE_NONE);
	if (types != exp_types)
		return TEE_ERROR_BAD_PARAMETERS;

	msg = params[0].memref.buffer;
	msg_len = (uint32_t)params[0].memref.size;
	if (msg_len && (!msg || !IS_ALIGNED_WITH_UINT32(msg)))
		return TEE_ERROR_BAD_PARAMETERS;
	if (msg_len >= sizeof(msg_tail))
		return TEE_ERROR_BAD_PARAMETERS;

	digest = params[1].memref.buffer;
	digest_max = (uint32_t)params[1].memref.size;
	params[1].memref.size = ctx->desc.digest_size;
	if (!digest || !IS_ALIGNED_WITH_UINT32(digest))
		return TEE_ERROR_BAD_PARAMETERS;
	if (digest_max < params[1].memref.size)
		return TEE_ERROR_SHORT_BUFFER;

	if (msg_len) {
		memcpy(msg_tail, msg, msg_len);

		err = R_RSIP_SHA_GenerateUpdate(&rsip_instance_ctrl,
						&ctx->handle,
						(uint8_t *)msg_tail, msg_len);
		if (err != FSP_SUCCESS)
			res = rsip_err_to_tee(err);
	}

	err = R_RSIP_SHA_GenerateFinal(&rsip_instance_ctrl, &ctx->handle,
				       (uint8_t *)digest_buff);
	if (res == TEE_SUCCESS && err != FSP_SUCCESS)
		res = rsip_err_to_tee(err);

	if (res == TEE_SUCCESS)
		memcpy(digest, digest_buff, ctx->desc.digest_size);

	return res;
}

/*
 * PTA session entry point.
 */
static TEE_Result open_session(uint32_t nParamTypes __unused,
			       TEE_Param pParams[TEE_NUM_PARAMS] __unused,
			       void **ppSessionContext)
{
	struct sha_ctx *ctx = NULL;

	DMSG("open entry point for pseudo ta \"%s\"", PTA_NAME);

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return TEE_ERROR_OUT_OF_MEMORY;
	*ppSessionContext = ctx;

	return TEE_SUCCESS;
}

/*
 * PTA session exit point.
 */
static void close_session(void *session)
{
	DMSG("close entry point for pseudo ta \"%s\"", PTA_NAME);

	free(session);
}

static TEE_Result invoke_command(void *session, uint32_t cmd, uint32_t ptypes,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	DMSG(PTA_NAME " command %#" PRIx32 " ptypes %#" PRIx32, cmd, ptypes);

	if (!session)
		return TEE_ERROR_BAD_PARAMETERS;

	switch (cmd) {
	case PTA_CMD_SHA_Init:
		return sha_init(session, ptypes, params);
	case PTA_CMD_SHA_Update:
		return sha_update(session, ptypes, params);
	case PTA_CMD_SHA_Final:
		return sha_final(session, ptypes, params);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

pseudo_ta_register(.uuid = PTA_RSIP_SHA_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .open_session_entry_point = open_session,
		   .close_session_entry_point = close_session,
		   .invoke_command_entry_point = invoke_command);
