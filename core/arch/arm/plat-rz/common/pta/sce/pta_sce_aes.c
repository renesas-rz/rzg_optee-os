// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2022-2026, Renesas Electronics Corporation
 */

#include <stdint.h>
#include <string.h>
#include <kernel/pseudo_ta.h>
#include <r_sce.h>
#include <pta_sce_aes.h>

#include "pta_sce_cmd.h"
#include "pta_sce_util.h"

#define PTA_NAME "sce_aes.pta"

struct aes_ctx {
	enum sce_aes_mode mode;
	sce_key_type_t key_type;
	union {
		sce_aes_handle_t aes;
		sce_cmac_handle_t cmac;
	} handle;
};

static TEE_Result get_aes_wrapped_key(TEE_Param *p,
				      struct sce_wrapped_key **wrapped_key)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	const struct sce_key_desc *key_desc = NULL;

	size_t wrapped_len = p->memref.size;
	struct sce_wrapped_key *key = p->memref.buffer;

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
	case SCE_KEY_INDEX_TYPE_AES128:
	case SCE_KEY_INDEX_TYPE_AES256:
		*wrapped_key = key;
		return TEE_SUCCESS;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

static void aes_pad_final_block(uint8_t *block, uint8_t *src, size_t len,
				enum sce_aes_mode mode __unused)
{
	/* Apply zero padding. Add other padding methods here if needed. */
	memset(block, 0, AES_BLOCK_SIZE);
	memcpy(block, src, len);
}

static void aes_unpad_final_block(uint8_t *dst, uint8_t *block, size_t *len,
				  enum sce_aes_mode mode __unused)
{
	/* Zero padding does not require unpadding. */
	memcpy(dst, block, *len);
}

static TEE_Result sce_gen_init_vec(uint8_t *init_vec)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;
	uint32_t rand[AES_BLOCK_SIZE / sizeof(uint32_t)];

	err = R_SCE_RandomNumberGenerate(rand);
	if (err == FSP_SUCCESS)
		memcpy(init_vec, rand, AES_BLOCK_SIZE);

	return sce_err_to_tee(err);
}

static TEE_Result sce_aes_enc_init(struct aes_ctx *ctx,
				   struct sce_wrapped_key *wrapped_key,
				   uint8_t *init_vec)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;
	sce_aes_handle_t *aes = &ctx->handle.aes;
	sce_aes_wrapped_key_t key;

	memcpy(&key, wrapped_key, sizeof(key));

	switch (ctx->mode) {
	case SCE_AES_MODE_ECB:
		if (ctx->key_type == SCE_KEY_INDEX_TYPE_AES128)
			err = R_SCE_AES128ECB_EncryptInit(aes, &key);
		else
			err = R_SCE_AES256ECB_EncryptInit(aes, &key);
		break;
	case SCE_AES_MODE_CBC:
		if (ctx->key_type == SCE_KEY_INDEX_TYPE_AES128)
			err = R_SCE_AES128CBC_EncryptInit(aes, &key, init_vec);
		else
			err = R_SCE_AES256CBC_EncryptInit(aes, &key, init_vec);
		break;
	case SCE_AES_MODE_CTR:
		if (ctx->key_type == SCE_KEY_INDEX_TYPE_AES128)
			err = R_SCE_AES128CTR_EncryptInit(aes, &key, init_vec);
		else
			err = R_SCE_AES256CTR_EncryptInit(aes, &key, init_vec);
		break;
	default:
		return TEE_ERROR_GENERIC;
	}
	return sce_err_to_tee(err);
}

static TEE_Result sce_aes_enc_update(struct aes_ctx *ctx, uint8_t *plain,
				     uint8_t *cipher, uint32_t plain_len)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;
	sce_aes_handle_t *aes = &ctx->handle.aes;

	switch (ctx->mode) {
	case SCE_AES_MODE_ECB:
		if (ctx->key_type == SCE_KEY_INDEX_TYPE_AES128)
			err = R_SCE_AES128ECB_EncryptUpdate(aes, plain, cipher,
							    plain_len);
		else
			err = R_SCE_AES256ECB_EncryptUpdate(aes, plain, cipher,
							    plain_len);
		break;
	case SCE_AES_MODE_CBC:
		if (ctx->key_type == SCE_KEY_INDEX_TYPE_AES128)
			err = R_SCE_AES128CBC_EncryptUpdate(aes, plain, cipher,
							    plain_len);
		else
			err = R_SCE_AES256CBC_EncryptUpdate(aes, plain, cipher,
							    plain_len);
		break;
	case SCE_AES_MODE_CTR:
		if (ctx->key_type == SCE_KEY_INDEX_TYPE_AES128)
			err = R_SCE_AES128CTR_EncryptUpdate(aes, plain, cipher,
							    plain_len);
		else
			err = R_SCE_AES256CTR_EncryptUpdate(aes, plain, cipher,
							    plain_len);
		break;
	default:
		return TEE_ERROR_GENERIC;
	}
	return sce_err_to_tee(err);
}

static TEE_Result sce_aes_enc_final(struct aes_ctx *ctx)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;
	sce_aes_handle_t *aes = &ctx->handle.aes;
	uint8_t *cipher = NULL; // nothing ever written here
	uint32_t cipher_length = 0; // 0 always written here

	switch (ctx->mode) {
	case SCE_AES_MODE_ECB:
		if (ctx->key_type == SCE_KEY_INDEX_TYPE_AES128)
			err = R_SCE_AES128ECB_EncryptFinal(aes, cipher,
							   &cipher_length);
		else
			err = R_SCE_AES256ECB_EncryptFinal(aes, cipher,
							   &cipher_length);
		break;
	case SCE_AES_MODE_CBC:
		if (ctx->key_type == SCE_KEY_INDEX_TYPE_AES128)
			err = R_SCE_AES128CBC_EncryptFinal(aes, cipher,
							   &cipher_length);
		else
			err = R_SCE_AES256CBC_EncryptFinal(aes, cipher,
							   &cipher_length);
		break;
	case SCE_AES_MODE_CTR:
		if (ctx->key_type == SCE_KEY_INDEX_TYPE_AES128)
			err = R_SCE_AES128CTR_EncryptFinal(aes, cipher,
							   &cipher_length);
		else
			err = R_SCE_AES256CTR_EncryptFinal(aes, cipher,
							   &cipher_length);
		break;
	default:
		return TEE_ERROR_GENERIC;
	}
	return sce_err_to_tee(err);
}

static TEE_Result sce_aes_dec_init(struct aes_ctx *ctx,
				   struct sce_wrapped_key *wrapped_key,
				   uint8_t *init_vec)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;
	sce_aes_handle_t *aes = &ctx->handle.aes;
	sce_aes_wrapped_key_t key;

	memcpy(&key, wrapped_key, sizeof(key));

	switch (ctx->mode) {
	case SCE_AES_MODE_ECB:
		if (ctx->key_type == SCE_KEY_INDEX_TYPE_AES128)
			err = R_SCE_AES128ECB_DecryptInit(aes, &key);
		else
			err = R_SCE_AES256ECB_DecryptInit(aes, &key);
		break;
	case SCE_AES_MODE_CBC:
		if (ctx->key_type == SCE_KEY_INDEX_TYPE_AES128)
			err = R_SCE_AES128CBC_DecryptInit(aes, &key, init_vec);
		else
			err = R_SCE_AES256CBC_DecryptInit(aes, &key, init_vec);
		break;
	case SCE_AES_MODE_CTR:
		if (ctx->key_type == SCE_KEY_INDEX_TYPE_AES128)
			err = R_SCE_AES128CTR_DecryptInit(aes, &key, init_vec);
		else
			err = R_SCE_AES256CTR_DecryptInit(aes, &key, init_vec);
		break;
	default:
		return TEE_ERROR_GENERIC;
	}
	return sce_err_to_tee(err);
}

static TEE_Result sce_aes_dec_update(struct aes_ctx *ctx, uint8_t *cipher,
				     uint8_t *plain, uint32_t cipher_len)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;
	sce_aes_handle_t *aes = &ctx->handle.aes;

	switch (ctx->mode) {
	case SCE_AES_MODE_ECB:
		if (ctx->key_type == SCE_KEY_INDEX_TYPE_AES128)
			err = R_SCE_AES128ECB_DecryptUpdate(aes, cipher, plain,
							    cipher_len);
		else
			err = R_SCE_AES256ECB_DecryptUpdate(aes, cipher, plain,
							    cipher_len);
		break;
	case SCE_AES_MODE_CBC:
		if (ctx->key_type == SCE_KEY_INDEX_TYPE_AES128)
			err = R_SCE_AES128CBC_DecryptUpdate(aes, cipher, plain,
							    cipher_len);
		else
			err = R_SCE_AES256CBC_DecryptUpdate(aes, cipher, plain,
							    cipher_len);
		break;
	case SCE_AES_MODE_CTR:
		if (ctx->key_type == SCE_KEY_INDEX_TYPE_AES128)
			err = R_SCE_AES128CTR_DecryptUpdate(aes, cipher, plain,
							    cipher_len);
		else
			err = R_SCE_AES256CTR_DecryptUpdate(aes, cipher, plain,
							    cipher_len);
		break;
	default:
		return TEE_ERROR_GENERIC;
	}
	return sce_err_to_tee(err);
}

static TEE_Result sce_aes_dec_final(struct aes_ctx *ctx)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;
	sce_aes_handle_t *aes = &ctx->handle.aes;
	uint8_t *plain = NULL; // nothing ever written here
	uint32_t plain_length = 0; // 0 always written here

	switch (ctx->mode) {
	case SCE_AES_MODE_ECB:
		if (ctx->key_type == SCE_KEY_INDEX_TYPE_AES128)
			err = R_SCE_AES128ECB_DecryptFinal(aes, plain,
							   &plain_length);
		else
			err = R_SCE_AES256ECB_DecryptFinal(aes, plain,
							   &plain_length);
		break;
	case SCE_AES_MODE_CBC:
		if (ctx->key_type == SCE_KEY_INDEX_TYPE_AES128)
			err = R_SCE_AES128CBC_DecryptFinal(aes, plain,
							   &plain_length);
		else
			err = R_SCE_AES256CBC_DecryptFinal(aes, plain,
							   &plain_length);
		break;
	case SCE_AES_MODE_CTR:
		if (ctx->key_type == SCE_KEY_INDEX_TYPE_AES128)
			err = R_SCE_AES128CTR_DecryptFinal(aes, plain,
							   &plain_length);
		else
			err = R_SCE_AES256CTR_DecryptFinal(aes, plain,
							   &plain_length);
		break;
	default:
		return TEE_ERROR_GENERIC;
	}
	return sce_err_to_tee(err);
}

static TEE_Result sce_cmac_gen_init(struct aes_ctx *ctx,
				    struct sce_wrapped_key *wrapped_key)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;
	sce_cmac_handle_t *cmac = &ctx->handle.cmac;
	sce_aes_wrapped_key_t key;

	memcpy(&key, wrapped_key, sizeof(key));

	if (ctx->key_type == SCE_KEY_INDEX_TYPE_AES128)
		err = R_SCE_AES128CMAC_GenerateInit(cmac, &key);
	else
		err = R_SCE_AES256CMAC_GenerateInit(cmac, &key);

	return sce_err_to_tee(err);
}

static TEE_Result sce_cmac_gen_update(struct aes_ctx *ctx, uint8_t *msg,
				      uint32_t msg_len)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;
	sce_cmac_handle_t *cmac = &ctx->handle.cmac;

	if (ctx->key_type == SCE_KEY_INDEX_TYPE_AES128)
		err = R_SCE_AES128CMAC_GenerateUpdate(cmac, msg, msg_len);
	else
		err = R_SCE_AES256CMAC_GenerateUpdate(cmac, msg, msg_len);
	return sce_err_to_tee(err);
}

static TEE_Result sce_cmac_gen_final(struct aes_ctx *ctx, uint8_t *mac)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;
	sce_cmac_handle_t *cmac = &ctx->handle.cmac;

	if (ctx->key_type == SCE_KEY_INDEX_TYPE_AES128)
		err = R_SCE_AES128CMAC_GenerateFinal(cmac, mac);
	else
		err = R_SCE_AES256CMAC_GenerateFinal(cmac, mac);

	return sce_err_to_tee(err);
}

static TEE_Result sce_cmac_verify_init(struct aes_ctx *ctx,
				       struct sce_wrapped_key *wrapped_key)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;
	sce_cmac_handle_t *cmac = &ctx->handle.cmac;
	sce_aes_wrapped_key_t key;

	memcpy(&key, wrapped_key, sizeof(key));

	if (ctx->key_type == SCE_KEY_INDEX_TYPE_AES128)
		err = R_SCE_AES128CMAC_VerifyInit(cmac, &key);
	else
		err = R_SCE_AES256CMAC_VerifyInit(cmac, &key);

	return sce_err_to_tee(err);
}

static TEE_Result sce_cmac_verify_update(struct aes_ctx *ctx, uint8_t *msg,
					 uint32_t msg_len)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;
	sce_cmac_handle_t *cmac = &ctx->handle.cmac;

	if (ctx->key_type == SCE_KEY_INDEX_TYPE_AES128)
		err = R_SCE_AES128CMAC_VerifyUpdate(cmac, msg, msg_len);
	else
		err = R_SCE_AES256CMAC_VerifyUpdate(cmac, msg, msg_len);

	return sce_err_to_tee(err);
}

static TEE_Result sce_cmac_verify_final(struct aes_ctx *ctx, uint8_t *mac,
					uint32_t mac_len)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;
	sce_cmac_handle_t *cmac = &ctx->handle.cmac;

	if (ctx->key_type == SCE_KEY_INDEX_TYPE_AES128)
		err = R_SCE_AES128CMAC_VerifyFinal(cmac, mac, mac_len);
	else
		err = R_SCE_AES256CMAC_VerifyFinal(cmac, mac, mac_len);

	return sce_err_to_tee(err);
}

static TEE_Result aes_enc_init(struct aes_ctx *ctx, uint32_t types,
			       TEE_Param params[TEE_NUM_PARAMS],
			       enum sce_aes_mode mode)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	size_t init_vec_max = 0;
	uint8_t *init_vec = NULL;

	struct sce_wrapped_key *wrapped_key = NULL;

	uint32_t exp_types =
		(mode != SCE_AES_MODE_ECB) ?
			TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_MEMREF_OUTPUT,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE) :
			TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE);
	if (types != exp_types)
		return TEE_ERROR_BAD_PARAMETERS;

	res = get_aes_wrapped_key(&params[0], &wrapped_key);
	if (res != TEE_SUCCESS)
		return res;

	ctx->mode = mode;
	ctx->key_type = wrapped_key->type;

	if (ctx->mode != SCE_AES_MODE_ECB) {
		init_vec = params[1].memref.buffer;
		init_vec_max = params[1].memref.size;
		params[1].memref.size = AES_BLOCK_SIZE;
		if (!init_vec || !IS_ALIGNED_WITH_UINT32(init_vec))
			return TEE_ERROR_BAD_PARAMETERS;
		if (init_vec_max < params[1].memref.size)
			return TEE_ERROR_SHORT_BUFFER;

		res = sce_gen_init_vec(init_vec);
		if (res != TEE_SUCCESS)
			return res;
	}

	return sce_aes_enc_init(ctx, wrapped_key, init_vec);
}

static TEE_Result aes_enc_update(struct aes_ctx *ctx, uint32_t types,
				 TEE_Param params[TEE_NUM_PARAMS],
				 enum sce_aes_mode mode)
{
	uint8_t *plain = NULL;
	uint32_t plain_len = 0;
	uint8_t *cipher = NULL;
	uint32_t cipher_max = 0;

	uint32_t exp_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_MEMREF_OUTPUT,
					     TEE_PARAM_TYPE_NONE,
					     TEE_PARAM_TYPE_NONE);
	if (types != exp_types)
		return TEE_ERROR_BAD_PARAMETERS;
	if (mode != ctx->mode)
		return TEE_ERROR_BAD_PARAMETERS;

	plain = params[0].memref.buffer;
	plain_len = (uint32_t)params[0].memref.size;
	if (plain_len && (!plain || !IS_ALIGNED_WITH_UINT32(plain)))
		return TEE_ERROR_BAD_PARAMETERS;
	if (!IS_ALIGNED(plain_len, AES_BLOCK_SIZE))
		return TEE_ERROR_BAD_PARAMETERS;

	cipher = params[1].memref.buffer;
	cipher_max = (uint32_t)params[1].memref.size;
	params[1].memref.size = (size_t)plain_len;
	if (plain_len && (!cipher || !IS_ALIGNED_WITH_UINT32(cipher)))
		return TEE_ERROR_BAD_PARAMETERS;
	if (cipher_max < params[1].memref.size)
		return TEE_ERROR_SHORT_BUFFER;

	return sce_aes_enc_update(ctx, plain, cipher, plain_len);
}

static TEE_Result aes_enc_final(struct aes_ctx *ctx, uint32_t types,
				TEE_Param params[TEE_NUM_PARAMS],
				enum sce_aes_mode mode)
{
	TEE_Result res = TEE_SUCCESS;

	uint8_t *plain = NULL;
	uint32_t plain_len = 0;
	uint32_t plain_tail[AES_BLOCK_SIZE / sizeof(uint32_t)] = { 0 };
	uint8_t *cipher = NULL;
	uint32_t cipher_max = 0;
	uint32_t cipher_tail[AES_BLOCK_SIZE / sizeof(uint32_t)] = { 0 };

	uint32_t exp_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_MEMREF_OUTPUT,
					     TEE_PARAM_TYPE_NONE,
					     TEE_PARAM_TYPE_NONE);
	if (types != exp_types) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto cleanup;
	}
	if (mode != ctx->mode) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto cleanup;
	}

	plain = params[0].memref.buffer;
	plain_len = (uint32_t)params[0].memref.size;
	if (plain_len && (!plain || !IS_ALIGNED_WITH_UINT32(plain))) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto cleanup;
	}
	if (plain_len >= AES_BLOCK_SIZE) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto cleanup;
	}

	cipher = params[1].memref.buffer;
	cipher_max = (uint32_t)params[1].memref.size;

	if (mode == SCE_AES_MODE_CTR)
		params[1].memref.size = plain_len;
	else
		params[1].memref.size = plain_len ? AES_BLOCK_SIZE : 0;

	if (plain_len) {
		if (!cipher || !IS_ALIGNED_WITH_UINT32(cipher)) {
			res = TEE_ERROR_BAD_PARAMETERS;
			goto cleanup;
		}
		if (cipher_max < params[1].memref.size) {
			res = TEE_ERROR_SHORT_BUFFER;
			goto cleanup;
		}

		aes_pad_final_block((void *)plain_tail, plain, plain_len, mode);

		res = sce_aes_enc_update(ctx, (uint8_t *)plain_tail,
					 (uint8_t *)cipher_tail,
					 AES_BLOCK_SIZE);
		if (res != TEE_SUCCESS)
			goto cleanup;

		memcpy(cipher, cipher_tail, params[1].memref.size);
	}

	return sce_aes_enc_final(ctx);
cleanup:
	sce_aes_enc_final(ctx);
	return res;
}

static TEE_Result aes_dec_init(struct aes_ctx *ctx, uint32_t types,
			       TEE_Param params[TEE_NUM_PARAMS],
			       enum sce_aes_mode mode)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	size_t init_vec_len = 0;
	uint8_t *init_vec = NULL;

	struct sce_wrapped_key *wrapped_key = NULL;

	uint32_t exp_types =
		(mode != SCE_AES_MODE_ECB) ?
			TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE) :
			TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE);
	if (types != exp_types)
		return TEE_ERROR_BAD_PARAMETERS;

	res = get_aes_wrapped_key(&params[0], &wrapped_key);
	if (res != TEE_SUCCESS)
		return res;

	ctx->mode = mode;
	ctx->key_type = wrapped_key->type;

	if (mode != SCE_AES_MODE_ECB) {
		init_vec = params[1].memref.buffer;
		init_vec_len = params[1].memref.size;
		if (!init_vec || !IS_ALIGNED_WITH_UINT32(init_vec))
			return TEE_ERROR_BAD_PARAMETERS;
		if (init_vec_len != AES_BLOCK_SIZE)
			return TEE_ERROR_BAD_PARAMETERS;
	}

	return sce_aes_dec_init(ctx, wrapped_key, init_vec);
}

static TEE_Result aes_dec_update(struct aes_ctx *ctx, uint32_t types,
				 TEE_Param params[TEE_NUM_PARAMS],
				 enum sce_aes_mode mode)
{
	uint8_t *cipher = NULL;
	uint32_t cipher_len = 0;
	uint8_t *plain = NULL;
	uint32_t plain_max = 0;

	uint32_t exp_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_MEMREF_OUTPUT,
					     TEE_PARAM_TYPE_NONE,
					     TEE_PARAM_TYPE_NONE);
	if (types != exp_types)
		return TEE_ERROR_BAD_PARAMETERS;
	if (mode != ctx->mode)
		return TEE_ERROR_BAD_PARAMETERS;

	cipher = params[0].memref.buffer;
	cipher_len = (uint32_t)params[0].memref.size;
	if (cipher_len && (!cipher || !IS_ALIGNED_WITH_UINT32(cipher)))
		return TEE_ERROR_BAD_PARAMETERS;
	if (!IS_ALIGNED(cipher_len, AES_BLOCK_SIZE))
		return TEE_ERROR_BAD_PARAMETERS;

	plain = params[1].memref.buffer;
	plain_max = (uint32_t)params[1].memref.size;
	params[1].memref.size = (size_t)cipher_len;
	if (cipher_len && (!plain || !IS_ALIGNED_WITH_UINT32(plain)))
		return TEE_ERROR_BAD_PARAMETERS;
	if (plain_max < params[1].memref.size)
		return TEE_ERROR_SHORT_BUFFER;

	return sce_aes_dec_update(ctx, cipher, plain, cipher_len);
}

static TEE_Result aes_dec_final(struct aes_ctx *ctx, uint32_t types,
				TEE_Param params[TEE_NUM_PARAMS],
				enum sce_aes_mode mode)
{
	TEE_Result res = TEE_SUCCESS;

	uint8_t *cipher = NULL;
	uint32_t cipher_len = 0;
	uint32_t cipher_tail[AES_BLOCK_SIZE / sizeof(uint32_t)] = { 0 };
	uint8_t *plain = NULL;
	uint32_t plain_max = 0;
	uint32_t plain_tail[AES_BLOCK_SIZE / sizeof(uint32_t)] = { 0 };

	uint32_t exp_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_MEMREF_OUTPUT,
					     TEE_PARAM_TYPE_NONE,
					     TEE_PARAM_TYPE_NONE);
	if (types != exp_types) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto cleanup;
	}
	if (mode != ctx->mode) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto cleanup;
	}

	cipher = params[0].memref.buffer;
	cipher_len = (uint32_t)params[0].memref.size;
	if (cipher_len && (!cipher || !IS_ALIGNED_WITH_UINT32(cipher))) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto cleanup;
	}
	if ((cipher_len % AES_BLOCK_SIZE) && mode != SCE_AES_MODE_CTR) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto cleanup;
	}
	if (cipher_len > AES_BLOCK_SIZE) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto cleanup;
	}

	plain = params[1].memref.buffer;
	plain_max = (uint32_t)params[1].memref.size;
	params[1].memref.size = cipher_len;

	if (cipher_len) {
		if (!plain || !IS_ALIGNED_WITH_UINT32(plain)) {
			res = TEE_ERROR_BAD_PARAMETERS;
			goto cleanup;
		}
		if (plain_max < params[1].memref.size) {
			res = TEE_ERROR_SHORT_BUFFER;
			goto cleanup;
		}

		memcpy(cipher_tail, cipher, cipher_len);
		res = sce_aes_dec_update(ctx, (uint8_t *)cipher_tail,
					 (uint8_t *)plain_tail, AES_BLOCK_SIZE);
		if (res != TEE_SUCCESS)
			goto cleanup;

		aes_unpad_final_block(plain, (uint8_t *)plain_tail,
				      &params[1].memref.size, mode);
	}

	return sce_aes_dec_final(ctx);
cleanup:
	sce_aes_dec_final(ctx);
	return res;
}

static TEE_Result cmac_gen_init(struct aes_ctx *ctx, uint32_t types,
				TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;

	struct sce_wrapped_key *wrapped_key = NULL;

	uint32_t exp_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_NONE,
					     TEE_PARAM_TYPE_NONE,
					     TEE_PARAM_TYPE_NONE);
	if (types != exp_types)
		return TEE_ERROR_BAD_PARAMETERS;

	res = get_aes_wrapped_key(&params[0], &wrapped_key);
	if (res != TEE_SUCCESS)
		return res;

	ctx->key_type = wrapped_key->type;

	return sce_cmac_gen_init(ctx, wrapped_key);
}

static TEE_Result cmac_gen_update(struct aes_ctx *ctx, uint32_t types,
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
	if (!IS_ALIGNED(msg_len, AES_BLOCK_SIZE))
		return TEE_ERROR_BAD_PARAMETERS;

	return sce_cmac_gen_update(ctx, msg, msg_len);
}

static TEE_Result cmac_gen_final(struct aes_ctx *ctx, uint32_t types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;

	uint8_t *msg = NULL;
	uint32_t msg_len = 0;
	uint32_t msg_tail[AES_BLOCK_SIZE / sizeof(uint32_t)] = { 0 };
	uint8_t *mac = NULL;
	uint32_t mac_max = 0;
	uint32_t mac_buff[AES_BLOCK_SIZE / sizeof(uint32_t)] = { 0 };

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
	if (msg_len >= AES_BLOCK_SIZE) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto cleanup;
	}

	mac = params[1].memref.buffer;
	mac_max = (uint32_t)params[1].memref.size;
	params[1].memref.size = AES_BLOCK_SIZE;
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
		res = sce_cmac_gen_update(ctx, (uint8_t *)msg_tail, msg_len);
		if (res != TEE_SUCCESS)
			goto cleanup;
	}

	res = sce_cmac_gen_final(ctx, (uint8_t *)mac_buff);
	if (res == TEE_SUCCESS)
		memcpy(mac, mac_buff, AES_BLOCK_SIZE);

	return res;
cleanup:
	sce_cmac_gen_final(ctx, (uint8_t *)mac_buff);
	return res;
}

static TEE_Result cmac_verify_init(struct aes_ctx *ctx, uint32_t types,
				   TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;

	struct sce_wrapped_key *wrapped_key = NULL;

	uint32_t exp_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_NONE,
					     TEE_PARAM_TYPE_NONE,
					     TEE_PARAM_TYPE_NONE);
	if (types != exp_types)
		return TEE_ERROR_BAD_PARAMETERS;

	res = get_aes_wrapped_key(&params[0], &wrapped_key);
	if (res != TEE_SUCCESS)
		return res;

	ctx->key_type = wrapped_key->type;

	return sce_cmac_verify_init(ctx, wrapped_key);
}

static TEE_Result cmac_verify_update(struct aes_ctx *ctx, uint32_t types,
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
	if (!IS_ALIGNED(msg_len, AES_BLOCK_SIZE))
		return TEE_ERROR_BAD_PARAMETERS;

	return sce_cmac_verify_update(ctx, msg, msg_len);
}

static TEE_Result cmac_verify_final(struct aes_ctx *ctx, uint32_t types,
				    TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;

	uint8_t *msg = NULL;
	uint32_t msg_len = 0;
	uint32_t msg_tail[AES_BLOCK_SIZE / sizeof(uint32_t)] = { 0 };
	uint8_t *mac = NULL;
	uint32_t mac_len = 0;
	uint32_t mac_buff[AES_BLOCK_SIZE / sizeof(uint32_t)] = { 0 };

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
	if (msg_len >= AES_BLOCK_SIZE) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto cleanup;
	}

	mac = params[1].memref.buffer;
	mac_len = (uint32_t)params[1].memref.size;
	if (!mac || !IS_ALIGNED_WITH_UINT32(mac)) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto cleanup;
	}
	if (mac_len < 2 || mac_len > AES_BLOCK_SIZE) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto cleanup;
	}

	if (msg_len) {
		memcpy(msg_tail, msg, msg_len);
		res = sce_cmac_verify_update(ctx, (uint8_t *)msg_tail, msg_len);
		if (res != TEE_SUCCESS)
			goto cleanup;
	}

	memcpy(mac_buff, mac, mac_len);
	return sce_cmac_verify_final(ctx, (uint8_t *)mac_buff, mac_len);
cleanup:
	mac_len = AES_BLOCK_SIZE;
	sce_cmac_verify_final(ctx, (uint8_t *)mac_buff, mac_len);
	return res;
}

/*
 * PTA session entry point.
 */
static TEE_Result open_session(uint32_t nParamTypes __unused,
			       TEE_Param pParams[TEE_NUM_PARAMS] __unused,
			       void **ppSessionContext)
{
	struct aes_ctx *ctx = NULL;

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

static TEE_Result invoke_command_aes(struct aes_ctx *ctx, uint32_t cmd,
				     uint32_t ptypes,
				     TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	enum sce_aes_mode mode = SCE_AES_MODE_ECB;

	res = get_sce_aes_mode(cmd, &mode);
	if (res != TEE_SUCCESS)
		return res;

	switch (cmd) {
	case PTA_CMD_AES_ECB_EncryptInit:
	case PTA_CMD_AES_CBC_EncryptInit:
	case PTA_CMD_AES_CTR_EncryptInit:
		return aes_enc_init(ctx, ptypes, params, mode);
	case PTA_CMD_AES_ECB_EncryptUpdate:
	case PTA_CMD_AES_CBC_EncryptUpdate:
	case PTA_CMD_AES_CTR_EncryptUpdate:
		return aes_enc_update(ctx, ptypes, params, mode);
	case PTA_CMD_AES_ECB_EncryptFinal:
	case PTA_CMD_AES_CBC_EncryptFinal:
	case PTA_CMD_AES_CTR_EncryptFinal:
		return aes_enc_final(ctx, ptypes, params, mode);
	case PTA_CMD_AES_ECB_DecryptInit:
	case PTA_CMD_AES_CBC_DecryptInit:
	case PTA_CMD_AES_CTR_DecryptInit:
		return aes_dec_init(ctx, ptypes, params, mode);
	case PTA_CMD_AES_ECB_DecryptUpdate:
	case PTA_CMD_AES_CBC_DecryptUpdate:
	case PTA_CMD_AES_CTR_DecryptUpdate:
		return aes_dec_update(ctx, ptypes, params, mode);
	case PTA_CMD_AES_ECB_DecryptFinal:
	case PTA_CMD_AES_CBC_DecryptFinal:
	case PTA_CMD_AES_CTR_DecryptFinal:
		return aes_dec_final(ctx, ptypes, params, mode);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

static TEE_Result invoke_command_cmac(struct aes_ctx *ctx, uint32_t cmd,
				      uint32_t ptypes,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd) {
	case PTA_CMD_AES_CMAC_GenerateInit:
		return cmac_gen_init(ctx, ptypes, params);
	case PTA_CMD_AES_CMAC_GenerateUpdate:
		return cmac_gen_update(ctx, ptypes, params);
	case PTA_CMD_AES_CMAC_GenerateFinal:
		return cmac_gen_final(ctx, ptypes, params);
	case PTA_CMD_AES_CMAC_VerifyInit:
		return cmac_verify_init(ctx, ptypes, params);
	case PTA_CMD_AES_CMAC_VerifyUpdate:
		return cmac_verify_update(ctx, ptypes, params);
	case PTA_CMD_AES_CMAC_VerifyFinal:
		return cmac_verify_final(ctx, ptypes, params);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

static TEE_Result invoke_command(void *session, uint32_t cmd, uint32_t ptypes,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	DMSG(PTA_NAME " command %#" PRIx32 " ptypes %#" PRIx32, cmd, ptypes);

	if (!session)
		return TEE_ERROR_BAD_PARAMETERS;

	switch (PTA_CMD_GET_VARIANT(cmd)) {
	case PTA_VARIANT_AES_CMAC:
		return invoke_command_cmac(session, cmd, ptypes, params);
	case PTA_VARIANT_AES_ECB:
	case PTA_VARIANT_AES_CBC:
	case PTA_VARIANT_AES_CTR:
		return invoke_command_aes(session, cmd, ptypes, params);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
pseudo_ta_register(.uuid = PTA_SCE_AES_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .open_session_entry_point = open_session,
		   .close_session_entry_point = close_session,
		   .invoke_command_entry_point = invoke_command);
