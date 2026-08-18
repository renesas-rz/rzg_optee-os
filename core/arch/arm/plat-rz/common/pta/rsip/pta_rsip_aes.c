// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2024, Renesas Electronics Corporation
 */

#include <kernel/pseudo_ta.h>
#include <r_rsip.h>
#include <pta_rsip_aes.h>

#include "pta_rsip_cmd.h"
#include "pta_rsip_util.h"

#define PTA_NAME "rsip_aes.pta"

static TEE_Result get_aes_wrapped_key(TEE_Param *p,
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
	case RSIP_KEY_TYPE_AES_128:
	case RSIP_KEY_TYPE_AES_256:
		*wrapped_key = key;
		return TEE_SUCCESS;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

static TEE_Result get_xts_wrapped_key(TEE_Param *p,
				      const rsip_wrapped_key_t **wrapped_key)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	size_t wrapped_len = p->memref.size;
	rsip_wrapped_key_t *key = p->memref.buffer;
	const struct rsip_key_desc *key_desc = NULL;

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
	case RSIP_KEY_TYPE_AES_128_XTS:
	case RSIP_KEY_TYPE_AES_256_XTS:
		*wrapped_key = key;
		return TEE_SUCCESS;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

static void aes_pad_final_block(uint8_t *block, const uint8_t *src, size_t len,
				rsip_aes_mode_t mode __unused)
{
	/* Apply zero padding. Add other padding methods here if needed. */
	memset(block, 0, AES_BLOCK_SIZE);
	memcpy(block, src, len);
}

static void aes_unpad_final_block(uint8_t *dst, const uint8_t *block,
				  size_t *len, rsip_aes_mode_t mode __unused)
{
	/* Zero padding does not require unpadding. */
	memcpy(dst, block, *len);
}

static TEE_Result aes_enc_init(uint32_t types, TEE_Param params[TEE_NUM_PARAMS],
			       rsip_aes_mode_t mode)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

	size_t init_vec_max = 0;
	uint8_t *init_vec = NULL;

	const rsip_wrapped_key_t *wrapped_key = NULL;

	uint32_t exp_types =
		(mode != RSIP_AES_MODE_ECB) ?
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

	if (mode != RSIP_AES_MODE_ECB) {
		init_vec = params[1].memref.buffer;
		init_vec_max = params[1].memref.size;
		params[1].memref.size = AES_BLOCK_SIZE;
		if (!init_vec || !IS_ALIGNED_WITH_UINT32(init_vec))
			return TEE_ERROR_BAD_PARAMETERS;
		if (init_vec_max < params[1].memref.size)
			return TEE_ERROR_SHORT_BUFFER;

		err = R_RSIP_RandomNumberGenerate(&rsip_instance_ctrl,
						  init_vec);
		if (err != FSP_SUCCESS)
			return rsip_err_to_tee(err);
	}

	err = R_RSIP_AES_Cipher_EncryptInit(&rsip_instance_ctrl, mode,
					    wrapped_key, init_vec);
	if (err != FSP_SUCCESS)
		return rsip_err_to_tee(err);

	return TEE_SUCCESS;
}

static TEE_Result xts_enc_init(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

	size_t tweak_len = 0;
	uint8_t *tweak = NULL;

	const rsip_wrapped_key_t *wrapped_key = NULL;

	uint32_t exp_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_NONE,
					     TEE_PARAM_TYPE_NONE);
	if (types != exp_types)
		return TEE_ERROR_BAD_PARAMETERS;

	res = get_xts_wrapped_key(&params[0], &wrapped_key);
	if (res != TEE_SUCCESS)
		return res;

	tweak = params[1].memref.buffer;
	tweak_len = params[1].memref.size;
	if (!tweak || !IS_ALIGNED_WITH_UINT32(tweak))
		return TEE_ERROR_BAD_PARAMETERS;
	if (tweak_len != AES_BLOCK_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	err = R_RSIP_AES_Cipher_EncryptInit(
		&rsip_instance_ctrl, RSIP_AES_MODE_XTS, wrapped_key, tweak);
	if (err != FSP_SUCCESS)
		return rsip_err_to_tee(err);

	return TEE_SUCCESS;
}

static TEE_Result aes_enc_update(uint32_t types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

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

	err = R_RSIP_AES_Cipher_EncryptUpdate(&rsip_instance_ctrl, plain,
					      cipher, plain_len);
	if (err != FSP_SUCCESS)
		return rsip_err_to_tee(err);

	return TEE_SUCCESS;
}

static TEE_Result aes_enc_final(uint32_t types,
				TEE_Param params[TEE_NUM_PARAMS],
				rsip_aes_mode_t mode)
{
	TEE_Result res = TEE_SUCCESS;
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

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
	if (types != exp_types)
		return TEE_ERROR_BAD_PARAMETERS;

	plain = params[0].memref.buffer;
	plain_len = (uint32_t)params[0].memref.size;
	if (plain_len && (!plain || !IS_ALIGNED_WITH_UINT32(plain)))
		return TEE_ERROR_BAD_PARAMETERS;
	if (plain_len >= AES_BLOCK_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	cipher = params[1].memref.buffer;
	cipher_max = (uint32_t)params[1].memref.size;

	if (mode == RSIP_AES_MODE_CTR)
		params[1].memref.size = plain_len;
	else
		params[1].memref.size = plain_len ? AES_BLOCK_SIZE : 0;

	if (plain_len) {
		if (!cipher || !IS_ALIGNED_WITH_UINT32(cipher))
			return TEE_ERROR_BAD_PARAMETERS;
		if (cipher_max < params[1].memref.size)
			return TEE_ERROR_SHORT_BUFFER;

		aes_pad_final_block((void *)plain_tail, plain, plain_len, mode);

		err = R_RSIP_AES_Cipher_EncryptUpdate(&rsip_instance_ctrl,
						      (uint8_t *)plain_tail,
						      (uint8_t *)cipher_tail,
						      AES_BLOCK_SIZE);
		if (err != FSP_SUCCESS)
			res = rsip_err_to_tee(err);
		else
			memcpy(cipher, cipher_tail, params[1].memref.size);
	}

	err = R_RSIP_AES_Cipher_EncryptFinal(&rsip_instance_ctrl, NULL, NULL);
	if (res == TEE_SUCCESS && err != FSP_SUCCESS)
		res = rsip_err_to_tee(err);

	return res;
}

static TEE_Result xts_enc_final(uint32_t types,
				TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

	uint8_t *plain = NULL;
	uint32_t plain_len = 0;
	uint32_t plain_tail[(2 * AES_BLOCK_SIZE) / sizeof(uint32_t)] = { 0 };
	uint8_t *cipher = NULL;
	uint32_t cipher_max = 0;
	uint32_t cipher_tail[(2 * AES_BLOCK_SIZE) / sizeof(uint32_t)] = { 0 };

	uint32_t exp_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_MEMREF_OUTPUT,
					     TEE_PARAM_TYPE_NONE,
					     TEE_PARAM_TYPE_NONE);
	if (types != exp_types)
		return TEE_ERROR_BAD_PARAMETERS;

	plain = params[0].memref.buffer;
	plain_len = (uint32_t)params[0].memref.size;
	if (plain_len && (!plain || !IS_ALIGNED_WITH_UINT32(plain)))
		return TEE_ERROR_BAD_PARAMETERS;
	if (plain_len &&
	    (plain_len <= AES_BLOCK_SIZE || plain_len >= (2 * AES_BLOCK_SIZE)))
		return TEE_ERROR_BAD_PARAMETERS;

	cipher = params[1].memref.buffer;
	cipher_max = (uint32_t)params[1].memref.size;

	params[1].memref.size = plain_len;

	if (plain_len) {
		if (!cipher || !IS_ALIGNED_WITH_UINT32(cipher))
			return TEE_ERROR_BAD_PARAMETERS;
		if (cipher_max < params[1].memref.size)
			return TEE_ERROR_SHORT_BUFFER;

		memcpy(plain_tail, plain, plain_len);
		err = R_RSIP_AES_Cipher_EncryptUpdate(&rsip_instance_ctrl,
						      (uint8_t *)plain_tail,
						      (uint8_t *)cipher_tail,
						      plain_len);
		if (err != FSP_SUCCESS)
			res = rsip_err_to_tee(err);
	}

	err = R_RSIP_AES_Cipher_EncryptFinal(
		&rsip_instance_ctrl, (uint8_t *)cipher_tail, &cipher_max);
	if (res == TEE_SUCCESS && err != FSP_SUCCESS)
		res = rsip_err_to_tee(err);

	/* XTS Final must return same size as input tail */
	if (res == TEE_SUCCESS && cipher_max != plain_len)
		res = TEE_ERROR_GENERIC;

	if (res == TEE_SUCCESS && plain_len)
		memcpy(cipher, cipher_tail, plain_len);

	return res;
}

static TEE_Result aes_dec_init(uint32_t types, TEE_Param params[TEE_NUM_PARAMS],
			       rsip_aes_mode_t mode)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

	size_t init_vec_len = 0;
	uint8_t *init_vec = NULL;

	const rsip_wrapped_key_t *wrapped_key = NULL;

	uint32_t exp_types =
		(mode != RSIP_AES_MODE_ECB) ?
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

	if (mode != RSIP_AES_MODE_ECB) {
		init_vec = params[1].memref.buffer;
		init_vec_len = params[1].memref.size;
		if (!init_vec || !IS_ALIGNED_WITH_UINT32(init_vec))
			return TEE_ERROR_BAD_PARAMETERS;
		if (init_vec_len != AES_BLOCK_SIZE)
			return TEE_ERROR_BAD_PARAMETERS;
	}

	err = R_RSIP_AES_Cipher_DecryptInit(&rsip_instance_ctrl, mode,
					    wrapped_key, init_vec);
	if (err != FSP_SUCCESS)
		return rsip_err_to_tee(err);

	return TEE_SUCCESS;
}

static TEE_Result xts_dec_init(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

	size_t tweak_len = 0;
	uint8_t *tweak = NULL;

	const rsip_wrapped_key_t *wrapped_key = NULL;

	uint32_t exp_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_NONE,
					     TEE_PARAM_TYPE_NONE);
	if (types != exp_types)
		return TEE_ERROR_BAD_PARAMETERS;

	res = get_xts_wrapped_key(&params[0], &wrapped_key);
	if (res != TEE_SUCCESS)
		return res;

	tweak = params[1].memref.buffer;
	tweak_len = params[1].memref.size;
	if (!tweak || !IS_ALIGNED_WITH_UINT32(tweak))
		return TEE_ERROR_BAD_PARAMETERS;
	if (tweak_len != AES_BLOCK_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	err = R_RSIP_AES_Cipher_DecryptInit(
		&rsip_instance_ctrl, RSIP_AES_MODE_XTS, wrapped_key, tweak);
	if (err != FSP_SUCCESS)
		return rsip_err_to_tee(err);

	return TEE_SUCCESS;
}

static TEE_Result aes_dec_update(uint32_t types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

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

	err = R_RSIP_AES_Cipher_DecryptUpdate(&rsip_instance_ctrl, cipher,
					      plain, cipher_len);
	if (err != FSP_SUCCESS)
		return rsip_err_to_tee(err);

	return TEE_SUCCESS;
}

static TEE_Result aes_dec_final(uint32_t types,
				TEE_Param params[TEE_NUM_PARAMS],
				rsip_aes_mode_t mode)
{
	TEE_Result res = TEE_SUCCESS;
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

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
	if (types != exp_types)
		return TEE_ERROR_BAD_PARAMETERS;

	cipher = params[0].memref.buffer;
	cipher_len = (uint32_t)params[0].memref.size;
	if (cipher_len && (!cipher || !IS_ALIGNED_WITH_UINT32(cipher)))
		return TEE_ERROR_BAD_PARAMETERS;
	if ((cipher_len % AES_BLOCK_SIZE) && mode != RSIP_AES_MODE_CTR)
		return TEE_ERROR_BAD_PARAMETERS;
	if (cipher_len > AES_BLOCK_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	plain = params[1].memref.buffer;
	plain_max = (uint32_t)params[1].memref.size;
	params[1].memref.size = cipher_len;

	if (cipher_len) {
		if (!plain || !IS_ALIGNED_WITH_UINT32(plain))
			return TEE_ERROR_BAD_PARAMETERS;
		if (plain_max < params[1].memref.size)
			return TEE_ERROR_SHORT_BUFFER;

		memcpy(cipher_tail, cipher, cipher_len);
		err = R_RSIP_AES_Cipher_DecryptUpdate(&rsip_instance_ctrl,
						      (uint8_t *)cipher_tail,
						      (uint8_t *)plain_tail,
						      AES_BLOCK_SIZE);
		if (err != FSP_SUCCESS)
			res = rsip_err_to_tee(err);
		else
			aes_unpad_final_block(plain, (uint8_t *)plain_tail,
					      &params[1].memref.size, mode);
	}

	err = R_RSIP_AES_Cipher_DecryptFinal(&rsip_instance_ctrl, NULL, NULL);
	if (res == TEE_SUCCESS && err != FSP_SUCCESS)
		res = rsip_err_to_tee(err);

	return res;
}

static TEE_Result xts_dec_final(uint32_t types,
				TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

	uint8_t *cipher = NULL;
	uint32_t cipher_len = 0;
	uint32_t cipher_tail[(2 * AES_BLOCK_SIZE) / sizeof(uint32_t)] = { 0 };
	uint8_t *plain = NULL;
	uint32_t plain_max = 0;
	uint32_t plain_tail[(2 * AES_BLOCK_SIZE) / sizeof(uint32_t)] = { 0 };

	uint32_t exp_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_MEMREF_OUTPUT,
					     TEE_PARAM_TYPE_NONE,
					     TEE_PARAM_TYPE_NONE);
	if (types != exp_types)
		return TEE_ERROR_BAD_PARAMETERS;

	cipher = params[0].memref.buffer;
	cipher_len = (uint32_t)params[0].memref.size;
	if (cipher_len && (!cipher || !IS_ALIGNED_WITH_UINT32(cipher)))
		return TEE_ERROR_BAD_PARAMETERS;
	if (cipher_len && (cipher_len <= AES_BLOCK_SIZE ||
			   cipher_len >= (AES_BLOCK_SIZE * 2)))
		return TEE_ERROR_BAD_PARAMETERS;

	plain = params[1].memref.buffer;
	plain_max = (uint32_t)params[1].memref.size;
	params[1].memref.size = cipher_len;

	if (cipher_len) {
		if (!plain || !IS_ALIGNED_WITH_UINT32(plain))
			return TEE_ERROR_BAD_PARAMETERS;
		if (plain_max < cipher_len)
			return TEE_ERROR_SHORT_BUFFER;

		memcpy(cipher_tail, cipher, cipher_len);
		err = R_RSIP_AES_Cipher_DecryptUpdate(&rsip_instance_ctrl,
						      (uint8_t *)cipher_tail,
						      (uint8_t *)plain_tail,
						      cipher_len);
		if (err != FSP_SUCCESS)
			res = rsip_err_to_tee(err);
	}

	err = R_RSIP_AES_Cipher_DecryptFinal(&rsip_instance_ctrl,
					     (uint8_t *)plain_tail, &plain_max);
	if (res == TEE_SUCCESS && err != FSP_SUCCESS)
		res = rsip_err_to_tee(err);

	/* XTS Final must return same size as input tail */
	if (res == TEE_SUCCESS && plain_max != cipher_len)
		res = TEE_ERROR_GENERIC;

	if (res == TEE_SUCCESS && cipher_len)
		memcpy(plain, plain_tail, cipher_len);

	return res;
}

static TEE_Result gcm_enc_init(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

	size_t nonce_max = 0;
	uint8_t *nonce = NULL;
	uint32_t nonce_buff[AES_BLOCK_SIZE / sizeof(uint32_t)] = { 0 };

	const rsip_wrapped_key_t *wrapped_key = NULL;

	uint32_t exp_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_MEMREF_OUTPUT,
					     TEE_PARAM_TYPE_NONE,
					     TEE_PARAM_TYPE_NONE);
	if (types != exp_types)
		return TEE_ERROR_BAD_PARAMETERS;

	res = get_aes_wrapped_key(&params[0], &wrapped_key);
	if (res != TEE_SUCCESS)
		return res;

	nonce = params[1].memref.buffer;
	nonce_max = params[1].memref.size;
	params[1].memref.size = GCM_NONCE_SIZE;
	if (!nonce || !IS_ALIGNED_WITH_UINT32(nonce))
		return TEE_ERROR_BAD_PARAMETERS;
	if (nonce_max < params[1].memref.size)
		return TEE_ERROR_SHORT_BUFFER;

	err = R_RSIP_RandomNumberGenerate(&rsip_instance_ctrl,
					  (uint8_t *)nonce_buff);
	if (err != FSP_SUCCESS)
		return rsip_err_to_tee(err);

	err = R_RSIP_AES_GCM_EncryptInit(&rsip_instance_ctrl, wrapped_key,
					 (uint8_t *)nonce_buff, GCM_NONCE_SIZE);
	if (err != FSP_SUCCESS)
		return rsip_err_to_tee(err);

	memcpy(nonce, nonce_buff, GCM_NONCE_SIZE);

	return TEE_SUCCESS;
}

static TEE_Result gcm_enc_aad(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

	uint8_t *aad = NULL;
	uint32_t aad_len = 0;

	uint32_t exp_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_NONE,
					     TEE_PARAM_TYPE_NONE,
					     TEE_PARAM_TYPE_NONE);
	if (types != exp_types)
		return TEE_ERROR_BAD_PARAMETERS;

	aad = params[0].memref.buffer;
	aad_len = (uint32_t)params[0].memref.size;
	if (aad_len && (!aad || !IS_ALIGNED_WITH_UINT32(aad)))
		return TEE_ERROR_BAD_PARAMETERS;
	if (!IS_ALIGNED(aad_len, AES_BLOCK_SIZE))
		return TEE_ERROR_BAD_PARAMETERS;

	err = R_RSIP_AES_GCM_EncryptUpdate(&rsip_instance_ctrl, NULL, NULL, 0,
					   aad, aad_len);
	if (err != FSP_SUCCESS)
		return rsip_err_to_tee(err);

	return TEE_SUCCESS;
}

static TEE_Result gcm_enc_aad_final(uint32_t types,
				    TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

	uint8_t *aad = NULL;
	uint32_t aad_len = 0;
	uint32_t aad_buff[AES_BLOCK_SIZE / sizeof(uint32_t)] = { 0 };

	uint32_t exp_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_NONE,
					     TEE_PARAM_TYPE_NONE,
					     TEE_PARAM_TYPE_NONE);
	if (types != exp_types)
		return TEE_ERROR_BAD_PARAMETERS;

	aad = params[0].memref.buffer;
	aad_len = (uint32_t)params[0].memref.size;
	if (aad_len && (!aad || !IS_ALIGNED_WITH_UINT32(aad)))
		return TEE_ERROR_BAD_PARAMETERS;
	if (aad_len >= AES_BLOCK_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	if (aad_len) {
		memcpy(aad_buff, aad, aad_len);
		err = R_RSIP_AES_GCM_EncryptUpdate(&rsip_instance_ctrl, NULL,
						   NULL, 0, (uint8_t *)aad_buff,
						   aad_len);
		if (err != FSP_SUCCESS)
			return rsip_err_to_tee(err);
	}

	return TEE_SUCCESS;
}

static TEE_Result gcm_enc_update(uint32_t types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

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

	err = R_RSIP_AES_GCM_EncryptUpdate(&rsip_instance_ctrl, plain, cipher,
					   plain_len, NULL, 0);
	if (err != FSP_SUCCESS)
		return rsip_err_to_tee(err);

	return TEE_SUCCESS;
}

static TEE_Result gcm_enc_final(uint32_t types,
				TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

	uint8_t *plain = NULL;
	uint32_t plain_len = 0;
	uint32_t plain_tail[AES_BLOCK_SIZE / sizeof(uint32_t)] = { 0 };
	uint8_t *cipher = NULL;
	uint32_t cipher_max = 0;
	uint32_t cipher_tail[AES_BLOCK_SIZE / sizeof(uint32_t)] = { 0 };
	uint8_t *tag = NULL;
	uint32_t tag_max = 0;
	uint32_t tag_buff[AES_BLOCK_SIZE / sizeof(uint32_t)] = { 0 };

	uint32_t exp_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_MEMREF_OUTPUT,
					     TEE_PARAM_TYPE_MEMREF_OUTPUT,
					     TEE_PARAM_TYPE_NONE);
	if (types != exp_types)
		return TEE_ERROR_BAD_PARAMETERS;

	plain = params[0].memref.buffer;
	plain_len = (uint32_t)params[0].memref.size;
	if (plain_len && (!plain || !IS_ALIGNED_WITH_UINT32(plain)))
		return TEE_ERROR_BAD_PARAMETERS;
	if (plain_len >= AES_BLOCK_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	cipher = params[1].memref.buffer;
	cipher_max = (uint32_t)params[1].memref.size;
	params[1].memref.size = (size_t)plain_len;
	if (plain_len && (!cipher || !IS_ALIGNED_WITH_UINT32(cipher)))
		return TEE_ERROR_BAD_PARAMETERS;
	if (cipher_max < params[1].memref.size)
		return TEE_ERROR_SHORT_BUFFER;

	tag = params[2].memref.buffer;
	tag_max = (uint32_t)params[2].memref.size;
	params[2].memref.size = AES_BLOCK_SIZE;
	if (!tag || !IS_ALIGNED_WITH_UINT32(tag))
		return TEE_ERROR_BAD_PARAMETERS;
	if (tag_max < params[2].memref.size)
		return TEE_ERROR_SHORT_BUFFER;

	if (plain_len) {
		memcpy(plain_tail, plain, plain_len);
		err = R_RSIP_AES_GCM_EncryptUpdate(&rsip_instance_ctrl,
						   (uint8_t *)plain_tail,
						   (uint8_t *)cipher_tail,
						   plain_len, NULL, 0);
		if (err != FSP_SUCCESS)
			res = rsip_err_to_tee(err);
	}

	err = R_RSIP_AES_GCM_EncryptFinal(&rsip_instance_ctrl,
					  (uint8_t *)cipher_tail, &cipher_max,
					  (uint8_t *)tag_buff);
	if (res == TEE_SUCCESS && err != FSP_SUCCESS)
		res = rsip_err_to_tee(err);

	/* GCM Final must return same size as input tail */
	if (res == TEE_SUCCESS && cipher_max != plain_len)
		res = TEE_ERROR_GENERIC;

	if (res == TEE_SUCCESS) {
		if (cipher_max)
			memcpy(cipher, cipher_tail, cipher_max);
		memcpy(tag, tag_buff, AES_BLOCK_SIZE);
	}

	return res;
}

static TEE_Result gcm_dec_init(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

	uint8_t *nonce = NULL;
	uint32_t nonce_len = 0;

	const rsip_wrapped_key_t *wrapped_key = NULL;

	uint32_t exp_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_NONE,
					     TEE_PARAM_TYPE_NONE);
	if (types != exp_types)
		return TEE_ERROR_BAD_PARAMETERS;

	res = get_aes_wrapped_key(&params[0], &wrapped_key);
	if (res != TEE_SUCCESS)
		return res;

	nonce = params[1].memref.buffer;
	nonce_len = (uint32_t)params[1].memref.size;
	if (!nonce || !IS_ALIGNED_WITH_UINT32(nonce))
		return TEE_ERROR_BAD_PARAMETERS;
	if (!nonce_len || nonce_len > AES_BLOCK_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	err = R_RSIP_AES_GCM_DecryptInit(&rsip_instance_ctrl, wrapped_key,
					 nonce, nonce_len);
	if (err != FSP_SUCCESS)
		return rsip_err_to_tee(err);

	return TEE_SUCCESS;
}

static TEE_Result gcm_dec_aad(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

	uint8_t *aad = NULL;
	uint32_t aad_len = 0;

	uint32_t exp_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_NONE,
					     TEE_PARAM_TYPE_NONE,
					     TEE_PARAM_TYPE_NONE);
	if (types != exp_types)
		return TEE_ERROR_BAD_PARAMETERS;

	aad = params[0].memref.buffer;
	aad_len = (uint32_t)params[0].memref.size;
	if (aad_len && (!aad || !IS_ALIGNED_WITH_UINT32(aad)))
		return TEE_ERROR_BAD_PARAMETERS;
	if (!IS_ALIGNED(aad_len, AES_BLOCK_SIZE))
		return TEE_ERROR_BAD_PARAMETERS;

	err = R_RSIP_AES_GCM_DecryptUpdate(&rsip_instance_ctrl, NULL, NULL, 0,
					   aad, aad_len);
	if (err != FSP_SUCCESS)
		return rsip_err_to_tee(err);

	return TEE_SUCCESS;
}

static TEE_Result gcm_dec_aad_final(uint32_t types,
				    TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

	uint8_t *aad = NULL;
	uint32_t aad_len = 0;
	uint32_t aad_buff[AES_BLOCK_SIZE / sizeof(uint32_t)] = { 0 };

	uint32_t exp_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_NONE,
					     TEE_PARAM_TYPE_NONE,
					     TEE_PARAM_TYPE_NONE);
	if (types != exp_types)
		return TEE_ERROR_BAD_PARAMETERS;

	aad = params[0].memref.buffer;
	aad_len = (uint32_t)params[0].memref.size;
	if (aad_len && (!aad || !IS_ALIGNED_WITH_UINT32(aad)))
		return TEE_ERROR_BAD_PARAMETERS;
	if (aad_len >= AES_BLOCK_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	if (aad_len) {
		memcpy(aad_buff, aad, aad_len);
		err = R_RSIP_AES_GCM_DecryptUpdate(&rsip_instance_ctrl, NULL,
						   NULL, 0, (uint8_t *)aad_buff,
						   aad_len);
		if (err != FSP_SUCCESS)
			return rsip_err_to_tee(err);
	}

	return TEE_SUCCESS;
}

static TEE_Result gcm_dec_update(uint32_t types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

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

	err = R_RSIP_AES_GCM_DecryptUpdate(&rsip_instance_ctrl, cipher, plain,
					   cipher_len, NULL, 0);
	if (err != FSP_SUCCESS)
		return rsip_err_to_tee(err);

	return TEE_SUCCESS;
}

static TEE_Result gcm_dec_final(uint32_t types,
				TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

	uint8_t *cipher = NULL;
	uint32_t cipher_len = 0;
	uint32_t cipher_tail[AES_BLOCK_SIZE / sizeof(uint32_t)] = { 0 };
	uint8_t *plain = NULL;
	uint32_t plain_max = 0;
	uint32_t plain_tail[AES_BLOCK_SIZE / sizeof(uint32_t)] = { 0 };
	uint8_t *tag = NULL;
	uint32_t tag_len = 0;
	uint32_t tag_buff[AES_BLOCK_SIZE / sizeof(uint32_t)] = { 0 };

	uint32_t exp_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_MEMREF_OUTPUT,
					     TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_NONE);
	if (types != exp_types)
		return TEE_ERROR_BAD_PARAMETERS;

	cipher = params[0].memref.buffer;
	cipher_len = (uint32_t)params[0].memref.size;
	if (cipher_len && (!cipher || !IS_ALIGNED_WITH_UINT32(cipher)))
		return TEE_ERROR_BAD_PARAMETERS;
	if (cipher_len >= AES_BLOCK_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	plain = params[1].memref.buffer;
	plain_max = (uint32_t)params[1].memref.size;
	params[1].memref.size = (size_t)cipher_len;
	if (cipher_len && (!plain || !IS_ALIGNED_WITH_UINT32(plain)))
		return TEE_ERROR_BAD_PARAMETERS;
	if (plain_max < params[1].memref.size)
		return TEE_ERROR_SHORT_BUFFER;

	tag = params[2].memref.buffer;
	tag_len = (uint32_t)params[2].memref.size;
	if (!tag || !IS_ALIGNED_WITH_UINT32(tag))
		return TEE_ERROR_BAD_PARAMETERS;
	if (!tag_len || (tag_len > AES_BLOCK_SIZE))
		return TEE_ERROR_BAD_PARAMETERS;

	if (cipher_len) {
		memcpy(cipher_tail, cipher, cipher_len);
		err = R_RSIP_AES_GCM_DecryptUpdate(&rsip_instance_ctrl,
						   (uint8_t *)cipher_tail,
						   (uint8_t *)plain_tail,
						   cipher_len, NULL, 0);
		if (err != FSP_SUCCESS)
			res = rsip_err_to_tee(err);
	}

	memcpy(tag_buff, tag, tag_len);
	err = R_RSIP_AES_GCM_DecryptFinal(&rsip_instance_ctrl,
					  (uint8_t *)plain_tail, &plain_max,
					  (uint8_t *)tag_buff, tag_len);
	if (res == TEE_SUCCESS && err != FSP_SUCCESS)
		res = rsip_err_to_tee(err);

	/* GCM Final must return same size as input tail */
	if (res == TEE_SUCCESS && plain_max != cipher_len)
		res = TEE_ERROR_GENERIC;

	if (res == TEE_SUCCESS && plain_max) {
		memcpy(plain, plain_tail, plain_max);
	}

	return res;
}

static TEE_Result cmac_gen_init(uint32_t types,
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

	res = get_aes_wrapped_key(&params[0], &wrapped_key);
	if (res != TEE_SUCCESS)
		return res;

	err = R_RSIP_AES_CMAC_GenerateInit(&rsip_instance_ctrl, wrapped_key);
	if (err != FSP_SUCCESS)
		return rsip_err_to_tee(err);

	return TEE_SUCCESS;
}

static TEE_Result cmac_gen_update(uint32_t types,
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
	if (!IS_ALIGNED(msg_len, AES_BLOCK_SIZE))
		return TEE_ERROR_BAD_PARAMETERS;

	err = R_RSIP_AES_CMAC_GenerateUpdate(&rsip_instance_ctrl, msg, msg_len);
	if (err != FSP_SUCCESS)
		return rsip_err_to_tee(err);

	return TEE_SUCCESS;
}

static TEE_Result cmac_gen_final(uint32_t types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

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
	if (types != exp_types)
		return TEE_ERROR_BAD_PARAMETERS;

	msg = params[0].memref.buffer;
	msg_len = (uint32_t)params[0].memref.size;
	if (msg_len && (!msg || !IS_ALIGNED_WITH_UINT32(msg)))
		return TEE_ERROR_BAD_PARAMETERS;
	if (msg_len >= AES_BLOCK_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	mac = params[1].memref.buffer;
	mac_max = (uint32_t)params[1].memref.size;
	params[1].memref.size = AES_BLOCK_SIZE;
	if (!mac || !IS_ALIGNED_WITH_UINT32(mac))
		return TEE_ERROR_BAD_PARAMETERS;
	if (mac_max < params[1].memref.size)
		return TEE_ERROR_SHORT_BUFFER;

	if (msg_len) {
		memcpy(msg_tail, msg, msg_len);
		err = R_RSIP_AES_CMAC_GenerateUpdate(
			&rsip_instance_ctrl, (uint8_t *)msg_tail, msg_len);
		if (err != FSP_SUCCESS)
			res = rsip_err_to_tee(err);
	}

	err = R_RSIP_AES_CMAC_GenerateFinal(&rsip_instance_ctrl,
					    (uint8_t *)mac_buff);
	if (res == TEE_SUCCESS && err != FSP_SUCCESS)
		res = rsip_err_to_tee(err);

	if (res == TEE_SUCCESS)
		memcpy(mac, mac_buff, AES_BLOCK_SIZE);

	return res;
}

static TEE_Result cmac_verify_init(uint32_t types,
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

	res = get_aes_wrapped_key(&params[0], &wrapped_key);
	if (res != TEE_SUCCESS)
		return res;

	err = R_RSIP_AES_CMAC_VerifyInit(&rsip_instance_ctrl, wrapped_key);
	if (err != FSP_SUCCESS)
		return rsip_err_to_tee(err);

	return TEE_SUCCESS;
}

static TEE_Result cmac_verify_update(uint32_t types,
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
	if (!IS_ALIGNED(msg_len, AES_BLOCK_SIZE))
		return TEE_ERROR_BAD_PARAMETERS;

	err = R_RSIP_AES_CMAC_VerifyUpdate(&rsip_instance_ctrl, msg, msg_len);
	if (err != FSP_SUCCESS)
		return rsip_err_to_tee(err);

	return TEE_SUCCESS;
}

static TEE_Result cmac_verify_final(uint32_t types,
				    TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

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
	if (types != exp_types)
		return TEE_ERROR_BAD_PARAMETERS;

	msg = params[0].memref.buffer;
	msg_len = (uint32_t)params[0].memref.size;
	if (msg_len && (!msg || !IS_ALIGNED_WITH_UINT32(msg)))
		return TEE_ERROR_BAD_PARAMETERS;
	if (msg_len >= AES_BLOCK_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	mac = params[1].memref.buffer;
	mac_len = (uint32_t)params[1].memref.size;
	if (!mac || !IS_ALIGNED_WITH_UINT32(mac))
		return TEE_ERROR_BAD_PARAMETERS;
	if (mac_len < 2 || mac_len > AES_BLOCK_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	if (msg_len) {
		memcpy(msg_tail, msg, msg_len);
		err = R_RSIP_AES_CMAC_VerifyUpdate(
			&rsip_instance_ctrl, (uint8_t *)msg_tail, msg_len);
		if (err != FSP_SUCCESS)
			res = rsip_err_to_tee(err);
	}

	memcpy(mac_buff, mac, mac_len);

	err = R_RSIP_AES_CMAC_VerifyFinal(&rsip_instance_ctrl,
					  (uint8_t *)mac_buff, mac_len);
	if (res == TEE_SUCCESS && err != FSP_SUCCESS)
		res = rsip_err_to_tee(err);

	return res;
}

static TEE_Result invoke_command_aes(uint32_t cmd, uint32_t ptypes,
				     TEE_Param params[TEE_NUM_PARAMS])
{
	rsip_aes_mode_t mode = RSIP_AES_MODE_ECB;

	TEE_Result res = get_rsip_aes_mode(cmd, &mode);
	if (res != TEE_SUCCESS)
		return res;

	switch (cmd) {
	case PTA_CMD_AES_ECB_EncryptInit:
	case PTA_CMD_AES_CBC_EncryptInit:
	case PTA_CMD_AES_CTR_EncryptInit:
		return aes_enc_init(ptypes, params, mode);
	case PTA_CMD_AES_ECB_EncryptUpdate:
	case PTA_CMD_AES_CBC_EncryptUpdate:
	case PTA_CMD_AES_CTR_EncryptUpdate:
		return aes_enc_update(ptypes, params);
	case PTA_CMD_AES_ECB_EncryptFinal:
	case PTA_CMD_AES_CBC_EncryptFinal:
	case PTA_CMD_AES_CTR_EncryptFinal:
		return aes_enc_final(ptypes, params, mode);
	case PTA_CMD_AES_ECB_DecryptInit:
	case PTA_CMD_AES_CBC_DecryptInit:
	case PTA_CMD_AES_CTR_DecryptInit:
		return aes_dec_init(ptypes, params, mode);
	case PTA_CMD_AES_ECB_DecryptUpdate:
	case PTA_CMD_AES_CBC_DecryptUpdate:
	case PTA_CMD_AES_CTR_DecryptUpdate:
		return aes_dec_update(ptypes, params);
	case PTA_CMD_AES_ECB_DecryptFinal:
	case PTA_CMD_AES_CBC_DecryptFinal:
	case PTA_CMD_AES_CTR_DecryptFinal:
		return aes_dec_final(ptypes, params, mode);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

static TEE_Result invoke_command_xts(uint32_t cmd, uint32_t ptypes,
				     TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd) {
	case PTA_CMD_AES_XTS_EncryptInit:
		return xts_enc_init(ptypes, params);
	case PTA_CMD_AES_XTS_EncryptUpdate:
		return aes_enc_update(ptypes, params);
	case PTA_CMD_AES_XTS_EncryptFinal:
		return xts_enc_final(ptypes, params);
	case PTA_CMD_AES_XTS_DecryptInit:
		return xts_dec_init(ptypes, params);
	case PTA_CMD_AES_XTS_DecryptUpdate:
		return aes_dec_update(ptypes, params);
	case PTA_CMD_AES_XTS_DecryptFinal:
		return xts_dec_final(ptypes, params);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

static TEE_Result invoke_command_gcm(uint32_t cmd, uint32_t ptypes,
				     TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd) {
	case PTA_CMD_AES_GCM_EncryptInit:
		return gcm_enc_init(ptypes, params);
	case PTA_CMD_AES_GCM_EncryptAADUpdate:
		return gcm_enc_aad(ptypes, params);
	case PTA_CMD_AES_GCM_EncryptAADFinal:
		return gcm_enc_aad_final(ptypes, params);
	case PTA_CMD_AES_GCM_EncryptUpdate:
		return gcm_enc_update(ptypes, params);
	case PTA_CMD_AES_GCM_EncryptFinal:
		return gcm_enc_final(ptypes, params);
	case PTA_CMD_AES_GCM_DecryptInit:
		return gcm_dec_init(ptypes, params);
	case PTA_CMD_AES_GCM_DecryptAADUpdate:
		return gcm_dec_aad(ptypes, params);
	case PTA_CMD_AES_GCM_DecryptAADFinal:
		return gcm_dec_aad_final(ptypes, params);
	case PTA_CMD_AES_GCM_DecryptUpdate:
		return gcm_dec_update(ptypes, params);
	case PTA_CMD_AES_GCM_DecryptFinal:
		return gcm_dec_final(ptypes, params);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

static TEE_Result invoke_command_cmac(uint32_t cmd, uint32_t ptypes,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd) {
	case PTA_CMD_AES_CMAC_GenerateInit:
		return cmac_gen_init(ptypes, params);
	case PTA_CMD_AES_CMAC_GenerateUpdate:
		return cmac_gen_update(ptypes, params);
	case PTA_CMD_AES_CMAC_GenerateFinal:
		return cmac_gen_final(ptypes, params);
	case PTA_CMD_AES_CMAC_VerifyInit:
		return cmac_verify_init(ptypes, params);
	case PTA_CMD_AES_CMAC_VerifyUpdate:
		return cmac_verify_update(ptypes, params);
	case PTA_CMD_AES_CMAC_VerifyFinal:
		return cmac_verify_final(ptypes, params);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

static TEE_Result invoke_command(void *session __unused, uint32_t cmd,
				 uint32_t ptypes,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	DMSG(PTA_NAME " command %#" PRIx32 " ptypes %#" PRIx32, cmd, ptypes);

	switch (PTA_CMD_GET_VARIANT(cmd)) {
	case PTA_VARIANT_AES_XTS:
		return invoke_command_xts(cmd, ptypes, params);
	case PTA_VARIANT_AES_GCM:
		return invoke_command_gcm(cmd, ptypes, params);
	case PTA_VARIANT_AES_CMAC:
		return invoke_command_cmac(cmd, ptypes, params);
	default:
		return invoke_command_aes(cmd, ptypes, params);
	}
}

pseudo_ta_register(.uuid = PTA_RSIP_AES_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS | TA_FLAG_DEVICE_ENUM,
		   .invoke_command_entry_point = invoke_command);
