// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2024, Renesas Electronics Corporation
 */

#include <kernel/pseudo_ta.h>
#include <r_rsip.h>
#include <pta_rsip_hmac.h>

#include "pta_rsip_cmd.h"
#include "pta_rsip_util.h"

#define PTA_NAME "rsip_hmac.pta"

struct rsip_hmac_desc {
	size_t mac_size;
};

struct hmac_ctx {
	struct rsip_hmac_desc desc;
	rsip_hmac_handle_t handle;
};

static TEE_Result get_hmac_desc(rsip_key_type_t key_type,
				struct rsip_hmac_desc *desc)
{
	switch (key_type) {
	case RSIP_KEY_TYPE_HMAC_SHA1:
		desc->mac_size = RSIP_DIGEST_SIZE_SHA1;
		return TEE_SUCCESS;
	case RSIP_KEY_TYPE_HMAC_SHA224:
		desc->mac_size = RSIP_DIGEST_SIZE_SHA224;
		return TEE_SUCCESS;
	case RSIP_KEY_TYPE_HMAC_SHA256:
		desc->mac_size = RSIP_DIGEST_SIZE_SHA256;
		return TEE_SUCCESS;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

static TEE_Result get_hmac_wrapped_key(TEE_Param *p,
				       const rsip_wrapped_key_t **wrapped_key)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	const struct rsip_key_desc *key_desc = NULL;

	size_t wrapped_len = p->memref.size;
	rsip_wrapped_key_t *key = p->memref.buffer;

	if (!key || !IS_ALIGNED_WITH_UINT32(key))
		return TEE_ERROR_BAD_PARAMETERS;
	if (wrapped_len < sizeof(key->type))
		return TEE_ERROR_BAD_PARAMETERS;

	res = get_key_desc(key->type, &key_desc);
	if (res != TEE_SUCCESS)
		return res;
	if (wrapped_len != key_desc->wrapped_size)
		return TEE_ERROR_BAD_PARAMETERS;

	switch (key->type) {
	case RSIP_KEY_TYPE_HMAC_SHA1:
	case RSIP_KEY_TYPE_HMAC_SHA224:
	case RSIP_KEY_TYPE_HMAC_SHA256:
		*wrapped_key = key;
		return TEE_SUCCESS;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

static TEE_Result hmac_gen_init(struct hmac_ctx *ctx, uint32_t types,
				TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

	const rsip_wrapped_key_t *wrapped_key = NULL;

	uint32_t exp_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_NONE,
					     TEE_PARAM_TYPE_NONE,
					     TEE_PARAM_TYPE_NONE);
	if (types != exp_types)
		return TEE_ERROR_BAD_PARAMETERS;

	res = get_hmac_wrapped_key(&params[0], &wrapped_key);
	if (res != TEE_SUCCESS)
		return res;

	res = get_hmac_desc(wrapped_key->type, &ctx->desc);
	if (res != TEE_SUCCESS)
		return res;

	err = R_RSIP_HMAC_GenerateInit(&rsip_instance_ctrl, &ctx->handle,
				       wrapped_key);
	if (err != FSP_SUCCESS)
		return rsip_err_to_tee(err);

	return TEE_SUCCESS;
}

static TEE_Result hmac_gen_update(struct hmac_ctx *ctx, uint32_t types,
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

	err = R_RSIP_HMAC_GenerateUpdate(&rsip_instance_ctrl, &ctx->handle, msg,
					 msg_len);
	if (err != FSP_SUCCESS)
		return rsip_err_to_tee(err);

	return TEE_SUCCESS;
}

static TEE_Result hmac_gen_final(struct hmac_ctx *ctx, uint32_t types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

	uint8_t *msg = NULL;
	uint32_t msg_len = 0;
	uint32_t msg_tail[1] = { 0 };
	uint8_t *mac = NULL;
	uint32_t mac_max = 0;
	uint32_t mac_buff[RSIP_HMAC_MAC_SIZE_MAX / sizeof(uint32_t)] = { 0 };

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

	mac = params[1].memref.buffer;
	mac_max = params[1].memref.size;
	params[1].memref.size = ctx->desc.mac_size;
	if (!mac || !IS_ALIGNED_WITH_UINT32(mac)) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto cleanup;
	}
	if (mac_max < params[1].memref.size) {
		res = TEE_ERROR_SHORT_BUFFER;
		goto cleanup;
	}

	if (msg_len) {
		memcpy(msg_tail, msg, msg_len);

		err = R_RSIP_HMAC_GenerateUpdate(&rsip_instance_ctrl,
						 &ctx->handle,
						 (uint8_t *)msg_tail, msg_len);
		if (err != FSP_SUCCESS) {
			res = rsip_err_to_tee(err);
			goto cleanup;
		}
	}

	err = R_RSIP_HMAC_GenerateFinal(&rsip_instance_ctrl, &ctx->handle,
					(uint8_t *)mac_buff);
	res = rsip_err_to_tee(err);

	if (res == TEE_SUCCESS)
		memcpy(mac, mac_buff, ctx->desc.mac_size);

	return res;
cleanup:
	R_RSIP_HMAC_GenerateFinal(&rsip_instance_ctrl, &ctx->handle,
				  (uint8_t *)mac_buff);
	return res;
}

static TEE_Result hmac_verify_init(struct hmac_ctx *ctx, uint32_t types,
				   TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

	const rsip_wrapped_key_t *wrapped_key = NULL;

	uint32_t exp_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_NONE,
					     TEE_PARAM_TYPE_NONE,
					     TEE_PARAM_TYPE_NONE);
	if (types != exp_types)
		return TEE_ERROR_BAD_PARAMETERS;

	res = get_hmac_wrapped_key(&params[0], &wrapped_key);
	if (res != TEE_SUCCESS)
		return res;

	res = get_hmac_desc(wrapped_key->type, &ctx->desc);
	if (res != TEE_SUCCESS)
		return res;

	err = R_RSIP_HMAC_VerifyInit(&rsip_instance_ctrl, &ctx->handle,
				     wrapped_key);
	if (err != FSP_SUCCESS)
		return rsip_err_to_tee(err);

	return TEE_SUCCESS;
}

static TEE_Result hmac_verify_update(struct hmac_ctx *ctx, uint32_t types,
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

	err = R_RSIP_HMAC_VerifyUpdate(&rsip_instance_ctrl, &ctx->handle, msg,
				       msg_len);
	if (err != FSP_SUCCESS)
		return rsip_err_to_tee(err);

	return TEE_SUCCESS;
}

static TEE_Result hmac_verify_final(struct hmac_ctx *ctx, uint32_t types,
				    TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

	uint8_t *msg = NULL;
	uint32_t msg_len = 0;
	uint32_t msg_tail[1] = { 0 };
	uint8_t *mac = NULL;
	uint32_t mac_len = 0;
	uint32_t mac_buff[RSIP_HMAC_MAC_SIZE_MAX / sizeof(uint32_t)] = { 0 };

	uint32_t exp_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_MEMREF_INPUT,
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

	mac = params[1].memref.buffer;
	mac_len = (uint32_t)params[1].memref.size;
	if (!mac || !IS_ALIGNED_WITH_UINT32(mac)) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto cleanup;
	}
	if (mac_len < RSIP_HMAC_MAC_SIZE_MIN) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto cleanup;
	}
	if (mac_len > ctx->desc.mac_size) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto cleanup;
	}

	if (msg_len) {
		memcpy(msg_tail, msg, msg_len);

		err = R_RSIP_HMAC_VerifyUpdate(&rsip_instance_ctrl,
					       &ctx->handle,
					       (uint8_t *)msg_tail, msg_len);
		if (err != FSP_SUCCESS) {
			res = rsip_err_to_tee(err);
			goto cleanup;
		}
	}

	memcpy(mac_buff, mac, mac_len);
	err = R_RSIP_HMAC_VerifyFinal(&rsip_instance_ctrl, &ctx->handle,
				      (uint8_t *)mac_buff, mac_len);
	return rsip_verify_err_to_tee(err, RSIP_VERIFY_MAC);
cleanup:
	mac_len = ctx->desc.mac_size;
	R_RSIP_HMAC_VerifyFinal(&rsip_instance_ctrl, &ctx->handle,
				(uint8_t *)mac_buff, mac_len);
	return res;
}

/*
 * PTA session entry point.
 */
static TEE_Result open_session(uint32_t nParamTypes __unused,
			       TEE_Param pParams[TEE_NUM_PARAMS] __unused,
			       void **ppSessionContext)
{
	struct hmac_ctx *ctx = NULL;

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
	case PTA_CMD_HMAC_GenerateInit:
		return hmac_gen_init(session, ptypes, params);
	case PTA_CMD_HMAC_GenerateUpdate:
		return hmac_gen_update(session, ptypes, params);
	case PTA_CMD_HMAC_GenerateFinal:
		return hmac_gen_final(session, ptypes, params);
	case PTA_CMD_HMAC_VerifyInit:
		return hmac_verify_init(session, ptypes, params);
	case PTA_CMD_HMAC_VerifyUpdate:
		return hmac_verify_update(session, ptypes, params);
	case PTA_CMD_HMAC_VerifyFinal:
		return hmac_verify_final(session, ptypes, params);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

pseudo_ta_register(.uuid = PTA_RSIP_HMAC_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .open_session_entry_point = open_session,
		   .close_session_entry_point = close_session,
		   .invoke_command_entry_point = invoke_command);
