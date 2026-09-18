// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2022, Renesas Electronics Corporation
 */

#include <stdint.h>
#include <string.h>
#include <kernel/pseudo_ta.h>
#include <r_sce.h>
#include <pta_sce_sha.h>

#include "pta_sce_cmd.h"
#include "pta_sce_util.h"

#define PTA_NAME "sce_sha.pta"

struct sce_sha_desc {
	enum sce_hash_type type;
	size_t digest_size;
};

struct sha_ctx {
	struct sce_sha_desc desc;
	sce_sha_md5_handle_t handle;
};

static TEE_Result get_sha_desc(enum pta_sha_type type,
			       struct sce_sha_desc *desc)
{
	switch (type) {
	case PTA_SHA_TYPE_SHA224:
		desc->type = SCE_HASH_TYPE_SHA224;
		desc->digest_size = SCE_DIGEST_SIZE_SHA224;
		return TEE_SUCCESS;
	case PTA_SHA_TYPE_SHA256:
		desc->type = SCE_HASH_TYPE_SHA256;
		desc->digest_size = SCE_DIGEST_SIZE_SHA256;
		return TEE_SUCCESS;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

static TEE_Result sce_sha_init(struct sha_ctx *ctx)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;

	switch (ctx->desc.type) {
	case SCE_HASH_TYPE_SHA224:
		err = R_SCE_SHA224_Init(&ctx->handle);
		break;
	case SCE_HASH_TYPE_SHA256:
		err = R_SCE_SHA256_Init(&ctx->handle);
		break;
	default:
		return TEE_ERROR_GENERIC;
	}
	return sce_err_to_tee(err);
}

static TEE_Result sce_sha_update(struct sha_ctx *ctx, uint8_t *msg,
				 uint32_t msg_len)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;

	switch (ctx->desc.type) {
	case SCE_HASH_TYPE_SHA224:
		err = R_SCE_SHA224_Update(&ctx->handle, msg, msg_len);
		break;
	case SCE_HASH_TYPE_SHA256:
		err = R_SCE_SHA256_Update(&ctx->handle, msg, msg_len);
		break;
	default:
		return TEE_ERROR_GENERIC;
	}
	return sce_err_to_tee(err);
}

static TEE_Result sce_sha_final(struct sha_ctx *ctx, uint8_t *digest,
				uint32_t *digest_len)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;

	switch (ctx->desc.type) {
	case SCE_HASH_TYPE_SHA224:
		err = R_SCE_SHA224_Final(&ctx->handle, digest, digest_len);
		break;
	case SCE_HASH_TYPE_SHA256:
		err = R_SCE_SHA256_Final(&ctx->handle, digest, digest_len);
		break;
	default:
		return TEE_ERROR_GENERIC;
	}
	return sce_err_to_tee(err);
}

static TEE_Result sha_init(struct sha_ctx *ctx, uint32_t types,
			   TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_GENERIC;

	uint32_t exp_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	if (types != exp_types)
		return TEE_ERROR_BAD_PARAMETERS;

	res = get_sha_desc((enum pta_sha_type)params[0].value.a, &ctx->desc);
	if (res != TEE_SUCCESS)
		return res;

	return sce_sha_init(ctx);
}

static TEE_Result sha_update(struct sha_ctx *ctx, uint32_t types,
			     TEE_Param params[TEE_NUM_PARAMS])
{
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

	return sce_sha_update(ctx, msg, msg_len);
}

static TEE_Result sha_final(struct sha_ctx *ctx, uint32_t types,
			    TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;

	uint8_t *msg = NULL;
	uint32_t msg_len = 0;
	uint32_t msg_tail[1] = { 0 };
	uint8_t *digest = NULL;
	uint32_t digest_max = 0;
	uint32_t digest_buff[SCE_DIGEST_SIZE_MAX / sizeof(uint32_t)] = { 0 };
	uint32_t digest_len = sizeof(digest_buff);

	uint32_t exp_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_MEMREF_OUTPUT,
					     TEE_PARAM_TYPE_NONE,
					     TEE_PARAM_TYPE_NONE);
	if (types != exp_types) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto cleanup;
	}

	msg = params[0].memref.buffer;
	msg_len = (uint32_t)params[0].memref.size;
	if (msg_len && (!msg || !IS_ALIGNED_WITH_UINT32(msg))) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto cleanup;
	}
	if (msg_len >= sizeof(msg_tail)) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto cleanup;
	}

	digest = params[1].memref.buffer;
	digest_max = (uint32_t)params[1].memref.size;
	params[1].memref.size = ctx->desc.digest_size;
	if (!digest || !IS_ALIGNED_WITH_UINT32(digest)) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto cleanup;
	}
	if (digest_max < params[1].memref.size) {
		res = TEE_ERROR_SHORT_BUFFER;
		goto cleanup;
	}

	if (msg_len) {
		memcpy(msg_tail, msg, msg_len);

		res = sce_sha_update(ctx, (uint8_t *)msg_tail, msg_len);
		if (res != TEE_SUCCESS)
			goto cleanup;
	}

	res = sce_sha_final(ctx, (uint8_t *)digest_buff, &digest_len);

	if (res == TEE_SUCCESS && digest_len != ctx->desc.digest_size)
		res = TEE_ERROR_GENERIC;
	if (res == TEE_SUCCESS)
		memcpy(digest, digest_buff, ctx->desc.digest_size);

	return res;
cleanup:
	sce_sha_final(ctx, (uint8_t *)digest_buff, &digest_len);
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
pseudo_ta_register(.uuid = PTA_SCE_SHA_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .open_session_entry_point = open_session,
		   .close_session_entry_point = close_session,
		   .invoke_command_entry_point = invoke_command);
