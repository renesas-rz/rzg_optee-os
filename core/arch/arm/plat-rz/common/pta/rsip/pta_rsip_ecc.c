// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2024, Renesas Electronics Corporation
 */

#include <kernel/pseudo_ta.h>
#include <tee/tee_cryp_utl.h>

#include <r_rsip.h>
#include <pta_rsip_ecc.h>
#include <pta_rsip_sha.h>

#define PTA_NAME "rsip_ecc.pta"

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

	return TEE_SUCCESS;
}

static TEE_Result ecdsa_secp192r1_sign(uint32_t types, TEE_Param params[TEE_NUM_PARAMS],
				       rsip_byte_size_wrapped_key_t key_size)
{
	fsp_err_t err;
	TEE_Result result;

	uint8_t *message;
	uint32_t message_length;
	uint8_t *signature;
	rsip_wrapped_key_t *wrapped_key;

	uint8_t digest[SHA256_HASH_SIZE];
	uint8_t sha1_digest[SHA1_HASH_SIZE];

	memset(digest, 0, SHA256_HASH_SIZE);
	memset(sha1_digest, 0, SHA1_HASH_SIZE);

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
	if (!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t) || (SIGNATURE_SIZE > params[1].memref.size)) {
		EMSG("signature err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	wrapped_key = (rsip_wrapped_key_t *)params[2].memref.buffer;
	if (!IS_ALIGNED_WITH_TYPE(params[2].memref.buffer, uint32_t) || (key_size > params[2].memref.size)) {
		EMSG("key err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	result = generate_hash(message, message_length, RSIP_HASH_TYPE_SHA1, sha1_digest);
	if (TEE_SUCCESS != result)
		return result;

	memcpy(&digest[8], sha1_digest, SHA1_HASH_SIZE);

	err = R_RSIP_ECDSA_Sign(&rsip_instance_ctrl, wrapped_key, digest, signature);
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

	params[1].memref.size = SIGNATURE_SIZE;

	return TEE_SUCCESS;
}

static TEE_Result ecdsa_secp224r1_sign(uint32_t types, TEE_Param params[TEE_NUM_PARAMS],
				       rsip_byte_size_wrapped_key_t key_size)
{
	fsp_err_t err;
	TEE_Result result;

	uint8_t *message;
	uint32_t message_length;
	uint8_t *signature;
	rsip_wrapped_key_t *wrapped_key;

	uint8_t digest[SHA256_HASH_SIZE];
	uint8_t sha224_digest[SHA224_HASH_SIZE];

	memset(digest, 0, SHA256_HASH_SIZE);
	memset(sha224_digest, 0, SHA224_HASH_SIZE);

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
	if (!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t) || (SIGNATURE_SIZE > params[1].memref.size)) {
		EMSG("signature err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	wrapped_key = (rsip_wrapped_key_t *)params[2].memref.buffer;
	if (!IS_ALIGNED_WITH_TYPE(params[2].memref.buffer, uint32_t) || (key_size > params[2].memref.size)) {
		EMSG("key err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	result = generate_hash(message, message_length, RSIP_HASH_TYPE_SHA224, sha224_digest);
	if (TEE_SUCCESS != result)
		return result;

	memcpy(&digest[4], sha224_digest, SHA224_HASH_SIZE);

	err = R_RSIP_ECDSA_Sign(&rsip_instance_ctrl, wrapped_key, digest, signature);
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

	params[1].memref.size = SIGNATURE_SIZE;

	return TEE_SUCCESS;
}

static TEE_Result ecdsa_secp256r1_sign(uint32_t types, TEE_Param params[TEE_NUM_PARAMS],
				       rsip_byte_size_wrapped_key_t key_size)
{
	fsp_err_t err;
	TEE_Result result;

	uint8_t *message;
	uint32_t message_length;
	uint8_t *signature;
	rsip_wrapped_key_t *wrapped_key;

	uint8_t digest[SHA256_HASH_SIZE];

	memset(digest, 0, SHA256_HASH_SIZE);

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
	if (!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t) || (SIGNATURE_SIZE > params[1].memref.size)) {
		EMSG("signature err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	wrapped_key = (rsip_wrapped_key_t *)params[2].memref.buffer;
	if (!IS_ALIGNED_WITH_TYPE(params[2].memref.buffer, uint32_t) || (key_size > params[2].memref.size)) {
		EMSG("key err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	result = generate_hash(message, message_length, RSIP_HASH_TYPE_SHA256, digest);
	if (TEE_SUCCESS != result)
		return result;

	err = R_RSIP_ECDSA_Sign(&rsip_instance_ctrl, wrapped_key, digest, signature);
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

	params[1].memref.size = SIGNATURE_SIZE;

	return TEE_SUCCESS;
}

static TEE_Result ecdsa_brainpoolp256r1_sign(uint32_t types, TEE_Param params[TEE_NUM_PARAMS],
					     rsip_byte_size_wrapped_key_t key_size)
{
	fsp_err_t err;
	TEE_Result result;

	uint8_t *message;
	uint32_t message_length;
	uint8_t *signature;
	rsip_wrapped_key_t *wrapped_key;

	uint8_t digest[SHA256_HASH_SIZE];

	memset(digest, 0, SHA256_HASH_SIZE);

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
	if (!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t) || (SIGNATURE_SIZE > params[1].memref.size)) {
		EMSG("signature err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	wrapped_key = (rsip_wrapped_key_t *)params[2].memref.buffer;
	if (!IS_ALIGNED_WITH_TYPE(params[2].memref.buffer, uint32_t) || (key_size > params[2].memref.size)) {
		EMSG("key err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	result = generate_hash(message, message_length, RSIP_HASH_TYPE_SHA256, digest);
	if (TEE_SUCCESS != result)
		return result;

	err = R_RSIP_ECDSA_Sign(&rsip_instance_ctrl, wrapped_key, digest, signature);
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

	params[1].memref.size = SIGNATURE_SIZE;

	return TEE_SUCCESS;
}

static TEE_Result ecdsa_secp192r1_verify(uint32_t types, TEE_Param params[TEE_NUM_PARAMS],
					 rsip_byte_size_wrapped_key_t key_size)
{
	fsp_err_t err;
	TEE_Result result;

	uint8_t *signature;
	uint8_t *message;
	uint32_t message_length;
	rsip_wrapped_key_t *wrapped_key;

	uint8_t digest[SHA256_HASH_SIZE];
	uint8_t sha1_digest[SHA1_HASH_SIZE];

	memset(digest, 0, SHA256_HASH_SIZE);
	memset(sha1_digest, 0, SHA1_HASH_SIZE);

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
	if (!IS_ALIGNED_WITH_TYPE(params[2].memref.buffer, uint32_t) || (key_size > params[2].memref.size)) {
		EMSG("key err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	result = generate_hash(message, message_length, RSIP_HASH_TYPE_SHA1, sha1_digest);
	if (TEE_SUCCESS != result)
		return result;

	memcpy(&digest[8], sha1_digest, SHA1_HASH_SIZE);

	err = R_RSIP_ECDSA_Verify(&rsip_instance_ctrl, wrapped_key, digest, signature);
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

	return TEE_SUCCESS;
}

static TEE_Result ecdsa_secp224r1_verify(uint32_t types, TEE_Param params[TEE_NUM_PARAMS],
					 rsip_byte_size_wrapped_key_t key_size)
{
	fsp_err_t err;
	TEE_Result result;

	uint8_t *signature;
	uint8_t *message;
	uint32_t message_length;
	rsip_wrapped_key_t *wrapped_key;

	uint8_t digest[SHA256_HASH_SIZE];
	uint8_t sha224_digest[SHA224_HASH_SIZE];

	memset(digest, 0, SHA256_HASH_SIZE);
	memset(sha224_digest, 0, SHA224_HASH_SIZE);

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
	if (!IS_ALIGNED_WITH_TYPE(params[2].memref.buffer, uint32_t) || (key_size > params[2].memref.size)) {
		EMSG("key err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	result = generate_hash(message, message_length, RSIP_HASH_TYPE_SHA224, sha224_digest);
	if (TEE_SUCCESS != result)
		return result;

	memcpy(&digest[4], sha224_digest, SHA224_HASH_SIZE);

	err = R_RSIP_ECDSA_Verify(&rsip_instance_ctrl, wrapped_key, digest, signature);
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

	return TEE_SUCCESS;
}

static TEE_Result ecdsa_secp256r1_verify(uint32_t types, TEE_Param params[TEE_NUM_PARAMS],
					 rsip_byte_size_wrapped_key_t key_size)
{
	fsp_err_t err;
	TEE_Result result;

	uint8_t *signature;
	uint8_t *message;
	uint32_t message_length;
	rsip_wrapped_key_t *wrapped_key;

	uint8_t digest[SHA256_HASH_SIZE];

	memset(digest, 0, SHA256_HASH_SIZE);

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
	if (!IS_ALIGNED_WITH_TYPE(params[2].memref.buffer, uint32_t) || (key_size > params[2].memref.size)) {
		EMSG("key err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	result = generate_hash(message, message_length, RSIP_HASH_TYPE_SHA256, digest);
	if (TEE_SUCCESS != result)
		return result;

	err = R_RSIP_ECDSA_Verify(&rsip_instance_ctrl, wrapped_key, digest, signature);
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

	return TEE_SUCCESS;
}

static TEE_Result ecdsa_brainpoolp256r1_verify(uint32_t types, TEE_Param params[TEE_NUM_PARAMS],
					       rsip_byte_size_wrapped_key_t key_size)
{
	fsp_err_t err;
	TEE_Result result;

	uint8_t *signature;
	uint8_t *message;
	uint32_t message_length;
	rsip_wrapped_key_t *wrapped_key;

	uint8_t digest[SHA256_HASH_SIZE];

	memset(digest, 0, SHA256_HASH_SIZE);

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
	if (!IS_ALIGNED_WITH_TYPE(params[2].memref.buffer, uint32_t) || (key_size > params[2].memref.size)) {
		EMSG("key err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	result = generate_hash(message, message_length, RSIP_HASH_TYPE_SHA256, digest);
	if (TEE_SUCCESS != result)
		return result;

	err = R_RSIP_ECDSA_Verify(&rsip_instance_ctrl, wrapped_key, digest, signature);
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

	return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *session __unused, uint32_t cmd,
				 uint32_t ptypes,
		    TEE_Param params[TEE_NUM_PARAMS])
{
	EMSG(PTA_NAME" command %#"PRIx32" ptypes %#"PRIx32, cmd, ptypes);

	switch (cmd) {
	case PTA_CMD_ECDSA_secp192r1_SignatureGenerate:
		return ecdsa_secp192r1_sign(ptypes, params,
				RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_secp192r1_PRIVATE);
	case PTA_CMD_ECDSA_secp224r1_SignatureGenerate:
		return ecdsa_secp224r1_sign(ptypes, params,
				RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_secp224r1_PRIVATE);
	case PTA_CMD_ECDSA_secp256r1_SignatureGenerate:
		return ecdsa_secp256r1_sign(ptypes, params,
				RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_secp256r1_PRIVATE);
	case PTA_CMD_ECDSA_BrainpoolP256r1_SignatureGenerate:
		return ecdsa_brainpoolp256r1_sign(ptypes, params,
				RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_BRAINPOOLP256R1_PRIVATE);

	case PTA_CMD_ECDSA_secp192r1_SignatureVerify:
		return ecdsa_secp192r1_verify(ptypes, params,
				RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_secp192r1_PUBLIC);
	case PTA_CMD_ECDSA_secp224r1_SignatureVerify:
		return ecdsa_secp224r1_verify(ptypes, params,
				RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_secp224r1_PUBLIC);
	case PTA_CMD_ECDSA_secp256r1_SignatureVerify:
		return ecdsa_secp256r1_verify(ptypes, params,
				RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_secp256r1_PUBLIC);
	case PTA_CMD_ECDSA_BrainpoolP256r1_SignatureVerify:
		return ecdsa_brainpoolp256r1_verify(ptypes, params,
				RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_BRAINPOOLP256R1_PUBLIC);

	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

pseudo_ta_register(.uuid = PTA_RSIP_ECC_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invoke_command);
