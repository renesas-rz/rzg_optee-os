// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2024, Renesas Electronics Corporation
 */

#include <kernel/pseudo_ta.h>

#include <r_rsip.h>
#include <pta_rsip_rsa.h>

#define PTA_NAME "rsip_rsa.pta"

extern rsip_instance_ctrl_t rsip_instance_ctrl;

static TEE_Result generate_hash(uint8_t const *const message, uint32_t const message_length,
				rsip_hash_type_t hash_type, uint8_t *digest)
{
	fsp_err_t err;

	err = R_RSIP_SHA_Compute(&rsip_instance_ctrl, hash_type, message, message_length, digest);
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

	return  TEE_SUCCESS;
}

static TEE_Result rsassa_pkcs1_v1_5_sign(uint32_t types, TEE_Param params[TEE_NUM_PARAMS],
					 uint32_t sig_size, rsip_byte_size_wrapped_key_t key_size)
{
	fsp_err_t err;
	TEE_Result result;

	uint8_t *message;
	uint32_t message_length;
	uint8_t *signature;
	uint8_t digest[32];
	rsip_wrapped_key_t *wrapped_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	message = (uint8_t *)params[0].memref.buffer;
	message_length = (uint32_t)params[0].memref.size;
	if (!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t)) {
		EMSG("message err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	signature = (uint8_t *)params[1].memref.buffer;
	if ((!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t)) || (sig_size > params[1].memref.size)) {
		EMSG("signature err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	wrapped_key = (rsip_wrapped_key_t *)params[2].memref.buffer;
	if ((!IS_ALIGNED_WITH_TYPE(params[2].memref.buffer, uint32_t)) || (key_size > params[2].memref.size)) {
		EMSG("key err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	result = generate_hash(message, message_length, RSIP_HASH_TYPE_SHA256, digest);
	if (TEE_SUCCESS != result)
		return result;

	err = R_RSIP_RSASSA_PKCS1_V1_5_Sign(&rsip_instance_ctrl, wrapped_key, RSIP_HASH_TYPE_SHA256, digest, signature);
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
	case FSP_ERR_CRYPTO_RSIP_KEY_SET_FAIL:
		return TEE_ERROR_BAD_PARAMETERS;
	case FSP_ERR_CRYPTO_RSIP_FAIL:
		return TEE_ERROR_GENERIC;
	case FSP_ERR_INVALID_SIZE:
		return TEE_ERROR_BAD_PARAMETERS;
	case FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT:
		return TEE_ERROR_ACCESS_CONFLICT;
	case FSP_ERR_CRYPTO_RSIP_FATAL:
		return TEE_ERROR_GENERIC;
	default:
		return TEE_ERROR_BAD_STATE;
	}

	params[1].memref.size = sig_size;

	return TEE_SUCCESS;
}

static TEE_Result rsassa_pkcs1_v1_5_verify(uint32_t types, TEE_Param params[TEE_NUM_PARAMS],
					   rsip_byte_size_wrapped_key_t key_size)
{
	fsp_err_t err;
	TEE_Result result;

	uint8_t *message;
	uint32_t message_length;
	uint8_t *signature;
	uint8_t digest[32];
	rsip_wrapped_key_t *wrapped_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	signature = (uint8_t *)params[0].memref.buffer;
	if (!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t)) {
		EMSG("signature err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	message = (uint8_t *)params[1].memref.buffer;
	message_length = (uint32_t)params[1].memref.size;
	if (!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t)) {
		EMSG("message err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	wrapped_key = (rsip_wrapped_key_t *)params[2].memref.buffer;
	if ((!IS_ALIGNED_WITH_TYPE(params[2].memref.buffer, uint32_t)) || (key_size > params[2].memref.size)) {
		EMSG("key err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	result = generate_hash(message, message_length, RSIP_HASH_TYPE_SHA256, digest);
	if (TEE_SUCCESS != result)
		return result;

	err = R_RSIP_RSASSA_PKCS1_V1_5_Verify(&rsip_instance_ctrl, wrapped_key, RSIP_HASH_TYPE_SHA256, digest, signature);
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
	case FSP_ERR_CRYPTO_RSIP_KEY_SET_FAIL:
		return TEE_ERROR_BAD_PARAMETERS;
	case FSP_ERR_CRYPTO_RSIP_FAIL:
		return TEE_ERROR_GENERIC;
	case FSP_ERR_INVALID_SIZE:
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

static TEE_Result rsassa_pss_sign(uint32_t types, TEE_Param params[TEE_NUM_PARAMS],
				  uint32_t sig_size, rsip_byte_size_wrapped_key_t key_size)
{
	fsp_err_t err;
	TEE_Result result;

	uint8_t *message;
	uint32_t message_length;
	uint8_t *signature;
	uint8_t digest[32];
	rsip_wrapped_key_t *wrapped_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	message = (uint8_t *)params[0].memref.buffer;
	message_length = (uint32_t)params[0].memref.size;
	if (!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t)) {
		EMSG("message err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	signature = (uint8_t *)params[1].memref.buffer;
	if ((!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t)) || (sig_size > params[1].memref.size)) {
		EMSG("signature err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	wrapped_key = (rsip_wrapped_key_t *)params[2].memref.buffer;
	if ((!IS_ALIGNED_WITH_TYPE(params[2].memref.buffer, uint32_t)) || (key_size > params[2].memref.size)) {
		EMSG("key err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	result = generate_hash(message, message_length, RSIP_HASH_TYPE_SHA256, digest);
	if (TEE_SUCCESS != result)
		return result;

	err = R_RSIP_RSASSA_PSS_Sign(&rsip_instance_ctrl, wrapped_key, RSIP_HASH_TYPE_SHA256, RSIP_MGF_TYPE_MGF1_SHA256,
				     RSIP_RSA_SALT_LENGTH_HASH, digest, signature);
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
	case FSP_ERR_CRYPTO_RSIP_KEY_SET_FAIL:
		return TEE_ERROR_BAD_PARAMETERS;
	case FSP_ERR_CRYPTO_RSIP_FAIL:
		return TEE_ERROR_GENERIC;
	case FSP_ERR_INVALID_SIZE:
		return TEE_ERROR_BAD_PARAMETERS;
	case FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT:
		return TEE_ERROR_ACCESS_CONFLICT;
	case FSP_ERR_CRYPTO_RSIP_FATAL:
		return TEE_ERROR_GENERIC;
	default:
		return TEE_ERROR_BAD_STATE;
	}

	params[1].memref.size = sig_size;

	return TEE_SUCCESS;
}

static TEE_Result rsassa_pss_verify(uint32_t types, TEE_Param params[TEE_NUM_PARAMS], rsip_byte_size_wrapped_key_t key_size)
{
	fsp_err_t err;
	TEE_Result result;

	uint8_t *signature;
	uint8_t *message;
	uint32_t message_length;
	uint8_t digest[32];
	rsip_wrapped_key_t *wrapped_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	signature = (uint8_t *)params[0].memref.buffer;
	if (!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t)) {
		EMSG("signature err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	message = (uint8_t *)params[1].memref.buffer;
	message_length = (uint32_t)params[1].memref.size;
	if (!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t)) {
		EMSG("message err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	wrapped_key = (rsip_wrapped_key_t *)params[2].memref.buffer;
	if ((!IS_ALIGNED_WITH_TYPE(params[2].memref.buffer, uint32_t)) || (key_size > params[2].memref.size)) {
		EMSG("key err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	result = generate_hash(message, message_length, RSIP_HASH_TYPE_SHA256, digest);
	if (TEE_SUCCESS != result)
		return result;

	err = R_RSIP_RSASSA_PSS_Verify(&rsip_instance_ctrl, wrapped_key, RSIP_HASH_TYPE_SHA256, RSIP_MGF_TYPE_MGF1_SHA256,
				       RSIP_RSA_SALT_LENGTH_HASH, digest, signature);
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
	case FSP_ERR_CRYPTO_RSIP_KEY_SET_FAIL:
		return TEE_ERROR_BAD_PARAMETERS;
	case FSP_ERR_CRYPTO_RSIP_FAIL:
		return TEE_ERROR_GENERIC;
	case FSP_ERR_INVALID_SIZE:
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

static TEE_Result rsa_encrypt(uint32_t types, TEE_Param params[TEE_NUM_PARAMS],
			      uint32_t cipher_size, rsip_byte_size_wrapped_key_t key_size)
{
	fsp_err_t err;

	uint8_t *plain;
	uint8_t *cipher;
	rsip_wrapped_key_t *wrapped_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	plain = (uint8_t *)params[0].memref.buffer;
	if (!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t))
		return TEE_ERROR_BAD_PARAMETERS;

	cipher = (uint8_t *)params[1].memref.buffer;
	if ((!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t)) || (cipher_size > params[1].memref.size)) {
		EMSG("cipher err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	wrapped_key = (rsip_wrapped_key_t *)params[2].memref.buffer;
	if ((!IS_ALIGNED_WITH_TYPE(params[2].memref.buffer, uint32_t)) || (key_size > params[2].memref.size)) {
		EMSG("key err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = R_RSIP_RSA_Encrypt(&rsip_instance_ctrl, wrapped_key, plain, cipher);
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

	params[1].memref.size = cipher_size;

	return TEE_SUCCESS;
}

static TEE_Result rsa_decrypt(uint32_t types, TEE_Param params[TEE_NUM_PARAMS],
			      uint32_t plain_size, rsip_byte_size_wrapped_key_t key_size)
{
	fsp_err_t err;

	uint8_t *cipher;
	uint8_t *plain;
	rsip_wrapped_key_t *wrapped_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	cipher = (uint8_t *)params[0].memref.buffer;
	if (!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t)) {
		EMSG("cipher err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	plain = (uint8_t *)params[1].memref.buffer;
	if ((!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t)) || (plain_size > params[1].memref.size)) {
		EMSG("plain err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	wrapped_key = (rsip_wrapped_key_t *)params[2].memref.buffer;
	if ((!IS_ALIGNED_WITH_TYPE(params[2].memref.buffer, uint32_t)) || (key_size > params[2].memref.size)) {
		EMSG("key err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = R_RSIP_RSA_Decrypt(&rsip_instance_ctrl, wrapped_key, cipher, plain);
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

	params[1].memref.size = plain_size;

	return TEE_SUCCESS;
}

static TEE_Result rsaes_pkcs1_v1_5_encrypt(uint32_t types, TEE_Param params[TEE_NUM_PARAMS],
					   uint32_t cipher_size, rsip_byte_size_wrapped_key_t key_size)
{
	fsp_err_t err;

	uint8_t *plain;
	uint32_t plain_length;
	uint8_t *cipher;
	rsip_wrapped_key_t *wrapped_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	plain = (uint8_t *)params[0].memref.buffer;
	plain_length = (uint32_t)params[0].memref.size;
	if (!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t)) {
		EMSG("plain err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	cipher = (uint8_t *)params[1].memref.buffer;
	if ((!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t)) || (cipher_size > params[1].memref.size)) {
		EMSG("cipher err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	wrapped_key = (rsip_wrapped_key_t *)params[2].memref.buffer;
	if ((!IS_ALIGNED_WITH_TYPE(params[2].memref.buffer, uint32_t)) || (key_size > params[2].memref.size)) {
		EMSG("key err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = R_RSIP_RSAES_PKCS1_V1_5_Encrypt(&rsip_instance_ctrl, wrapped_key, plain, plain_length, cipher);
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
	case FSP_ERR_CRYPTO_RSIP_KEY_SET_FAIL:
		return TEE_ERROR_BAD_PARAMETERS;
	case FSP_ERR_CRYPTO_RSIP_FAIL:
		return TEE_ERROR_GENERIC;
	case FSP_ERR_INVALID_SIZE:
		return TEE_ERROR_BAD_PARAMETERS;
	case FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT:
		return TEE_ERROR_ACCESS_CONFLICT;
	case FSP_ERR_CRYPTO_RSIP_FATAL:
		return TEE_ERROR_GENERIC;
	default:
		return TEE_ERROR_BAD_STATE;
	}

	params[1].memref.size = cipher_size;

	return TEE_SUCCESS;
}

static TEE_Result rsaes_pkcs1_v1_5_decrypt(uint32_t types, TEE_Param params[TEE_NUM_PARAMS],
					   rsip_byte_size_wrapped_key_t key_size)
{
	fsp_err_t err;

	uint8_t *plain;
	uint32_t plain_length;
	uint32_t plain_buffer_length = 512;
	uint8_t *cipher;
	uint32_t cipher_length;
	rsip_wrapped_key_t *wrapped_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	cipher = (uint8_t *)params[0].memref.buffer;
	cipher_length = (uint32_t)params[0].memref.size;
	if (!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t))
		return TEE_ERROR_BAD_PARAMETERS;

	plain = (uint8_t *)params[1].memref.buffer;
	plain_length = (uint32_t)params[1].memref.size;
	if ((!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t)) || (plain_length < cipher_length)) {
		EMSG("plain err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	wrapped_key = (rsip_wrapped_key_t *)params[2].memref.buffer;
	if ((!IS_ALIGNED_WITH_TYPE(params[2].memref.buffer, uint32_t)) || (key_size > params[2].memref.size)) {
		EMSG("key err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = R_RSIP_RSAES_PKCS1_V1_5_Decrypt(&rsip_instance_ctrl, wrapped_key, cipher, plain,
					      &plain_length, plain_buffer_length);
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
	case FSP_ERR_CRYPTO_RSIP_KEY_SET_FAIL:
		return TEE_ERROR_BAD_PARAMETERS;
	case FSP_ERR_CRYPTO_RSIP_FAIL:
		return TEE_ERROR_GENERIC;
	case FSP_ERR_INVALID_SIZE:
		return TEE_ERROR_BAD_PARAMETERS;
	case FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT:
		return TEE_ERROR_ACCESS_CONFLICT;
	case FSP_ERR_CRYPTO_RSIP_FATAL:
		return TEE_ERROR_GENERIC;
	default:
		return TEE_ERROR_BAD_STATE;
	}

	params[1].memref.size = plain_length;

	return TEE_SUCCESS;
}

static TEE_Result rsaes_oaep_encrypt(uint32_t types, TEE_Param params[TEE_NUM_PARAMS],
				     uint32_t cipher_size, rsip_byte_size_wrapped_key_t key_size)
{
	fsp_err_t err;

	uint8_t *plain;
	uint32_t plain_length;
	uint8_t *cipher;
	uint8_t *label;
	uint32_t label_length;
	rsip_wrapped_key_t *wrapped_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INPUT))
		return TEE_ERROR_BAD_PARAMETERS;

	plain = (uint8_t *)params[0].memref.buffer;
	plain_length = (uint32_t)params[0].memref.size;
	if (!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t)) {
		EMSG("plain err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	cipher = (uint8_t *)params[1].memref.buffer;
	if ((!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t)) || (cipher_size > params[1].memref.size)) {
		EMSG("cipher err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	wrapped_key = (rsip_wrapped_key_t *)params[2].memref.buffer;
	if ((!IS_ALIGNED_WITH_TYPE(params[2].memref.buffer, uint32_t)) || (key_size > params[2].memref.size)) {
		EMSG("key err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	label = (uint8_t *)params[3].memref.buffer;
	label_length = (uint32_t)params[3].memref.size;
	if (!IS_ALIGNED_WITH_TYPE(params[3].memref.buffer, uint32_t)) {
		EMSG("label err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = R_RSIP_RSAES_OAEP_Encrypt(&rsip_instance_ctrl, wrapped_key, RSIP_HASH_TYPE_SHA256, RSIP_MGF_TYPE_MGF1_SHA256,
					label, label_length, plain, plain_length, cipher);
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
	case FSP_ERR_CRYPTO_RSIP_KEY_SET_FAIL:
		return TEE_ERROR_BAD_PARAMETERS;
	case FSP_ERR_CRYPTO_RSIP_FAIL:
		return TEE_ERROR_GENERIC;
	case FSP_ERR_INVALID_SIZE:
		return TEE_ERROR_BAD_PARAMETERS;
	case FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT:
		return TEE_ERROR_ACCESS_CONFLICT;
	case FSP_ERR_CRYPTO_RSIP_FATAL:
		return TEE_ERROR_GENERIC;
	default:
		return TEE_ERROR_BAD_STATE;
	}

	params[1].memref.size = cipher_size;

	return TEE_SUCCESS;
}

static TEE_Result rsaes_oaep_decrypt(uint32_t types, TEE_Param params[TEE_NUM_PARAMS], rsip_byte_size_wrapped_key_t key_size)
{
	fsp_err_t err;

	uint8_t *plain;
	uint32_t plain_length;
	uint32_t plain_buffer_length = 512;
	uint8_t *cipher;
	uint32_t cipher_length;
	uint8_t *label;
	uint32_t label_length;
	rsip_wrapped_key_t *wrapped_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INPUT))
		return TEE_ERROR_BAD_PARAMETERS;

	cipher = (uint8_t *)params[0].memref.buffer;
	cipher_length = (uint32_t)params[0].memref.size;
	if (!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t)) {
		EMSG("cipher err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	plain = (uint8_t *)params[1].memref.buffer;
	plain_length = (uint32_t)params[1].memref.size;
	if ((!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t)) || (plain_length < cipher_length)) {
		EMSG("plain err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	wrapped_key = (rsip_wrapped_key_t *)params[2].memref.buffer;
	if ((!IS_ALIGNED_WITH_TYPE(params[2].memref.buffer, uint32_t)) || (key_size > params[2].memref.size)) {
		EMSG("key err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	label = (uint8_t *)params[3].memref.buffer;
	label_length = (uint32_t)params[3].memref.size;
	if (!IS_ALIGNED_WITH_TYPE(params[3].memref.buffer, uint32_t)) {
		EMSG("label err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = R_RSIP_RSAES_OAEP_Decrypt(&rsip_instance_ctrl, wrapped_key, RSIP_HASH_TYPE_SHA256, RSIP_MGF_TYPE_MGF1_SHA256,
					label, label_length, cipher, plain, &plain_length, plain_buffer_length);
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
	case FSP_ERR_CRYPTO_RSIP_KEY_SET_FAIL:
		return TEE_ERROR_BAD_PARAMETERS;
	case FSP_ERR_CRYPTO_RSIP_FAIL:
		return TEE_ERROR_GENERIC;
	case FSP_ERR_INVALID_SIZE:
		return TEE_ERROR_BAD_PARAMETERS;
	case FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT:
		return TEE_ERROR_ACCESS_CONFLICT;
	case FSP_ERR_CRYPTO_RSIP_FATAL:
		return TEE_ERROR_GENERIC;
	default:
		return TEE_ERROR_BAD_STATE;
	}

	params[1].memref.size = plain_length;

	return TEE_SUCCESS;
}

static TEE_Result rsassa_pkcs1024_signaturegenerate(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return rsassa_pkcs1_v1_5_sign(types, params, SIGNATURE_BYTE_SIZE_RSA_1024, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_1024_PRIVATE_ENHANCED);
}

static TEE_Result rsassa_pkcs2048_signaturegenerate(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return rsassa_pkcs1_v1_5_sign(types, params, SIGNATURE_BYTE_SIZE_RSA_2048, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_2048_PRIVATE_ENHANCED);
}

static TEE_Result rsassa_pkcs3072_signaturegenerate(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return rsassa_pkcs1_v1_5_sign(types, params, SIGNATURE_BYTE_SIZE_RSA_3072, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_3072_PRIVATE);
}

static TEE_Result rsassa_pkcs4096_signaturegenerate(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return rsassa_pkcs1_v1_5_sign(types, params, SIGNATURE_BYTE_SIZE_RSA_4096, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_4096_PRIVATE);
}

static TEE_Result rsassa_pkcs1024_signatureverify(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return rsassa_pkcs1_v1_5_verify(types, params, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_1024_PUBLIC_ENHANCED);
}

static TEE_Result rsassa_pkcs2048_signatureverify(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return rsassa_pkcs1_v1_5_verify(types, params, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_2048_PUBLIC_ENHANCED);
}

static TEE_Result rsassa_pkcs3072_signatureverify(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return rsassa_pkcs1_v1_5_verify(types, params, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_3072_PUBLIC);
}

static TEE_Result rsassa_pkcs4096_signatureverify(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return rsassa_pkcs1_v1_5_verify(types, params, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_4096_PUBLIC);
}

static TEE_Result rsassa_pss1024_signature(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return rsassa_pss_sign(types, params, SIGNATURE_BYTE_SIZE_RSA_1024, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_1024_PRIVATE_ENHANCED);
}

static TEE_Result rsassa_pss2048_signature(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return rsassa_pss_sign(types, params, SIGNATURE_BYTE_SIZE_RSA_2048, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_2048_PRIVATE_ENHANCED);
}

static TEE_Result rsassa_pss3072_signature(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return rsassa_pss_sign(types, params, SIGNATURE_BYTE_SIZE_RSA_3072, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_3072_PRIVATE);
}

static TEE_Result rsassa_pss4096_signature(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return rsassa_pss_sign(types, params, SIGNATURE_BYTE_SIZE_RSA_4096, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_4096_PRIVATE);
}

static TEE_Result rsassa_pss1024_verify(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return rsassa_pss_verify(types, params, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_1024_PUBLIC_ENHANCED);
}

static TEE_Result rsassa_pss2048_verify(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return rsassa_pss_verify(types, params, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_2048_PUBLIC_ENHANCED);
}

static TEE_Result rsassa_pss3072_verify(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return rsassa_pss_verify(types, params, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_3072_PUBLIC);
}

static TEE_Result rsassa_pss4096_verify(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return rsassa_pss_verify(types, params, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_4096_PUBLIC);
}

static TEE_Result rsa_1024_encrypt(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return rsa_encrypt(types, params, CIPHER_BYTE_SIZE_RSA_1024, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_1024_PUBLIC_ENHANCED);
}

static TEE_Result rsa_2048_encrypt(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return rsa_encrypt(types, params, CIPHER_BYTE_SIZE_RSA_2048, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_2048_PUBLIC_ENHANCED);
}

static TEE_Result rsa_3072_encrypt(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return rsa_encrypt(types, params, CIPHER_BYTE_SIZE_RSA_3072, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_3072_PUBLIC);
}

static TEE_Result rsa_4096_encrypt(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return rsa_encrypt(types, params, CIPHER_BYTE_SIZE_RSA_4096, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_4096_PUBLIC);
}

static TEE_Result rsa_1024_decrypt(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return rsa_decrypt(types, params, CIPHER_BYTE_SIZE_RSA_1024, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_1024_PRIVATE_ENHANCED);
}

static TEE_Result rsa_2048_decrypt(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return rsa_decrypt(types, params, CIPHER_BYTE_SIZE_RSA_2048, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_2048_PRIVATE_ENHANCED);
}

static TEE_Result rsa_3072_decrypt(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return rsa_decrypt(types, params, CIPHER_BYTE_SIZE_RSA_3072, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_3072_PRIVATE);
}

static TEE_Result rsa_4096_decrypt(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return rsa_decrypt(types, params, CIPHER_BYTE_SIZE_RSA_4096, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_4096_PRIVATE);
}

static TEE_Result rsaes_pkcs1024_encrypt(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return rsaes_pkcs1_v1_5_encrypt(types, params, CIPHER_BYTE_SIZE_RSA_1024, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_1024_PUBLIC_ENHANCED);
}

static TEE_Result rsaes_pkcs2048_encrypt(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return rsaes_pkcs1_v1_5_encrypt(types, params, CIPHER_BYTE_SIZE_RSA_2048, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_2048_PUBLIC_ENHANCED);
}

static TEE_Result rsaes_pkcs3072_encrypt(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return rsaes_pkcs1_v1_5_encrypt(types, params, CIPHER_BYTE_SIZE_RSA_3072, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_3072_PUBLIC);
}

static TEE_Result rsaes_pkcs4096_encrypt(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return rsaes_pkcs1_v1_5_encrypt(types, params, CIPHER_BYTE_SIZE_RSA_4096, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_4096_PUBLIC);
}

static TEE_Result rsaes_pkcs1024_decrypt(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return rsaes_pkcs1_v1_5_decrypt(types, params, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_1024_PRIVATE_ENHANCED);
}

static TEE_Result rsaes_pkcs2048_decrypt(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return rsaes_pkcs1_v1_5_decrypt(types, params, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_2048_PRIVATE_ENHANCED);
}

static TEE_Result rsaes_pkcs3072_decrypt(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return rsaes_pkcs1_v1_5_decrypt(types, params, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_3072_PRIVATE);
}

static TEE_Result rsaes_pkcs4096_decrypt(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return rsaes_pkcs1_v1_5_decrypt(types, params, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_4096_PRIVATE);
}

static TEE_Result rsaes_oaep1024_encrypt(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return rsaes_oaep_encrypt(types, params, CIPHER_BYTE_SIZE_RSA_1024, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_1024_PUBLIC_ENHANCED);
}

static TEE_Result rsaes_oaep2048_encrypt(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return rsaes_oaep_encrypt(types, params, CIPHER_BYTE_SIZE_RSA_2048, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_2048_PUBLIC_ENHANCED);
}

static TEE_Result rsaes_oaep3072_encrypt(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return rsaes_oaep_encrypt(types, params, CIPHER_BYTE_SIZE_RSA_3072, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_3072_PUBLIC);
}

static TEE_Result rsaes_oaep4096_encrypt(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return rsaes_oaep_encrypt(types, params, CIPHER_BYTE_SIZE_RSA_4096, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_4096_PUBLIC);
}

static TEE_Result rsaes_oaep1024_decrypt(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return rsaes_oaep_decrypt(types, params, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_1024_PRIVATE_ENHANCED);
}

static TEE_Result rsaes_oaep2048_decrypt(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return rsaes_oaep_decrypt(types, params, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_2048_PRIVATE_ENHANCED);
}

static TEE_Result rsaes_oaep3072_decrypt(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return rsaes_oaep_decrypt(types, params, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_3072_PRIVATE);
}

static TEE_Result rsaes_oaep4096_decrypt(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return rsaes_oaep_decrypt(types, params, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_4096_PRIVATE);
}

static TEE_Result invoke_command(void *session __unused, uint32_t cmd,
				 uint32_t ptypes,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	EMSG(PTA_NAME" command %#"PRIx32" ptypes %#"PRIx32, cmd, ptypes);

	switch (cmd) {
	case PTA_CMD_RSASSA_PKCS1024_SignatureGenerate:
		return rsassa_pkcs1024_signaturegenerate(ptypes, params);
	case PTA_CMD_RSASSA_PKCS2048_SignatureGenerate:
		return rsassa_pkcs2048_signaturegenerate(ptypes, params);
	case PTA_CMD_RSASSA_PKCS3072_SignatureGenerate:
		return rsassa_pkcs3072_signaturegenerate(ptypes, params);
	case PTA_CMD_RSASSA_PKCS4096_SignatureGenerate:
		return rsassa_pkcs4096_signaturegenerate(ptypes, params);

	case PTA_CMD_RSASSA_PKCS1024_SignatureVerify:
		return rsassa_pkcs1024_signatureverify(ptypes, params);
	case PTA_CMD_RSASSA_PKCS2048_SignatureVerify:
		return rsassa_pkcs2048_signatureverify(ptypes, params);
	case PTA_CMD_RSASSA_PKCS3072_SignatureVerify:
		return rsassa_pkcs3072_signatureverify(ptypes, params);
	case PTA_CMD_RSASSA_PKCS4096_SignatureVerify:
		return rsassa_pkcs4096_signatureverify(ptypes, params);

	case PTA_CMD_RSASSA_PSS1024_SignatureGenerate:
		return rsassa_pss1024_signature(ptypes, params);
	case PTA_CMD_RSASSA_PSS2048_SignatureGenerate:
		return rsassa_pss2048_signature(ptypes, params);
	case PTA_CMD_RSASSA_PSS3072_SignatureGenerate:
		return rsassa_pss3072_signature(ptypes, params);
	case PTA_CMD_RSASSA_PSS4096_SignatureGenerate:
		return rsassa_pss4096_signature(ptypes, params);

	case PTA_CMD_RSASSA_PSS1024_SignatureVerify:
		return rsassa_pss1024_verify(ptypes, params);
	case PTA_CMD_RSASSA_PSS2048_SignatureVerify:
		return rsassa_pss2048_verify(ptypes, params);
	case PTA_CMD_RSASSA_PSS3072_SignatureVerify:
		return rsassa_pss3072_verify(ptypes, params);
	case PTA_CMD_RSASSA_PSS4096_SignatureVerify:
		return rsassa_pss4096_verify(ptypes, params);

	case PTA_CMD_RSA_1024_Encrypt:
		return rsa_1024_encrypt(ptypes, params);
	case PTA_CMD_RSA_2048_Encrypt:
		return rsa_2048_encrypt(ptypes, params);
	case PTA_CMD_RSA_3072_Encrypt:
		return rsa_3072_encrypt(ptypes, params);
	case PTA_CMD_RSA_4096_Encrypt:
		return rsa_4096_encrypt(ptypes, params);

	case PTA_CMD_RSA_1024_Decrypt:
		return rsa_1024_decrypt(ptypes, params);
	case PTA_CMD_RSA_2048_Decrypt:
		return rsa_2048_decrypt(ptypes, params);
	case PTA_CMD_RSA_3072_Decrypt:
		return rsa_3072_decrypt(ptypes, params);
	case PTA_CMD_RSA_4096_Decrypt:
		return rsa_4096_decrypt(ptypes, params);

	case PTA_CMD_RSAES_PKCS1024_Encrypt:
		return rsaes_pkcs1024_encrypt(ptypes, params);
	case PTA_CMD_RSAES_PKCS2048_Encrypt:
		return rsaes_pkcs2048_encrypt(ptypes, params);
	case PTA_CMD_RSAES_PKCS3072_Encrypt:
		return rsaes_pkcs3072_encrypt(ptypes, params);
	case PTA_CMD_RSAES_PKCS4096_Encrypt:
		return rsaes_pkcs4096_encrypt(ptypes, params);

	case PTA_CMD_RSAES_PKCS1024_Decrypt:
		return rsaes_pkcs1024_decrypt(ptypes, params);
	case PTA_CMD_RSAES_PKCS2048_Decrypt:
		return rsaes_pkcs2048_decrypt(ptypes, params);
	case PTA_CMD_RSAES_PKCS3072_Decrypt:
		return rsaes_pkcs3072_decrypt(ptypes, params);
	case PTA_CMD_RSAES_PKCS4096_Decrypt:
		return rsaes_pkcs4096_decrypt(ptypes, params);

	case PTA_CMD_RSAES_OAEP1024_Encrypt:
		return rsaes_oaep1024_encrypt(ptypes, params);
	case PTA_CMD_RSAES_OAEP2048_Encrypt:
		return rsaes_oaep2048_encrypt(ptypes, params);
	case PTA_CMD_RSAES_OAEP3072_Encrypt:
		return rsaes_oaep3072_encrypt(ptypes, params);
	case PTA_CMD_RSAES_OAEP4096_Encrypt:
		return rsaes_oaep4096_encrypt(ptypes, params);

	case PTA_CMD_RSAES_OAEP1024_Decrypt:
		return rsaes_oaep1024_decrypt(ptypes, params);
	case PTA_CMD_RSAES_OAEP2048_Decrypt:
		return rsaes_oaep2048_decrypt(ptypes, params);
	case PTA_CMD_RSAES_OAEP3072_Decrypt:
		return rsaes_oaep3072_decrypt(ptypes, params);
	case PTA_CMD_RSAES_OAEP4096_Decrypt:
		return rsaes_oaep4096_decrypt(ptypes, params);

	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

pseudo_ta_register(.uuid = PTA_RSIP_RSA_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invoke_command);
