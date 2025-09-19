// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2024, Renesas Electronics Corporation
 */

#include <kernel/pseudo_ta.h>

#include <r_rsip.h>
#include <pta_rsip_aes.h>

#define PTA_NAME "rsip_aes.pta"

extern rsip_instance_ctrl_t rsip_instance_ctrl;

static TEE_Result aes_cipher_encryptinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS],
					 rsip_aes_mode_t mode, rsip_byte_size_wrapped_key_t key_size)
{
	fsp_err_t err;

	rsip_wrapped_key_t *wrapped_key;
	uint8_t *initial_vector;

	initial_vector = (uint8_t *)params[1].memref.buffer;
	if (mode != RSIP_AES_MODE_ECB) {
		if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_NONE,
					     TEE_PARAM_TYPE_NONE))
			return TEE_ERROR_BAD_PARAMETERS;

		if (!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t)) {
			EMSG("initial_vector err");
			return TEE_ERROR_BAD_PARAMETERS;
		}
	} else {
		if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_NONE,
					     TEE_PARAM_TYPE_NONE,
					     TEE_PARAM_TYPE_NONE)) {
			return TEE_ERROR_BAD_PARAMETERS;
		}
	}

	wrapped_key = (rsip_wrapped_key_t *)params[0].memref.buffer;
	if ((!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t)) || (key_size > params[0].memref.size)) {
		EMSG("key err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = R_RSIP_AES_Cipher_EncryptInit(&rsip_instance_ctrl, mode, wrapped_key, initial_vector);
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
	case FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT:
		return TEE_ERROR_ACCESS_CONFLICT;
	case FSP_ERR_CRYPTO_RSIP_FATAL:
		return TEE_ERROR_GENERIC;
	default:
		return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

static TEE_Result aes_cipher_encryptupdate(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	uint8_t *plain;
	uint8_t *cipher;
	uint32_t plain_length;
	uint32_t cipher_length;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	plain = (uint8_t *)params[0].memref.buffer;
	plain_length = (uint32_t)params[0].memref.size;
	if (!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t)) {
		EMSG("plain err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	cipher = (uint8_t *)params[1].memref.buffer;
	cipher_length = (uint32_t)params[1].memref.size;
	if ((!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t)) || (cipher_length < plain_length)) {
		EMSG("cipher err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = R_RSIP_AES_Cipher_EncryptUpdate(&rsip_instance_ctrl, plain, cipher, plain_length);
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
	default:
		return TEE_ERROR_BAD_STATE;
	}

	params[1].memref.size = plain_length;

	return TEE_SUCCESS;
}

static TEE_Result aes_cipher_encryptfinal(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	uint8_t *cipher;
	uint32_t cipher_length = 0;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	cipher = (uint8_t *)params[0].memref.buffer;
	cipher_length = (uint32_t)params[0].memref.size;
	if ((!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t)) || (AES_BLOCK_LEN > params[0].memref.size)) {
		EMSG("cipher err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = R_RSIP_AES_Cipher_EncryptFinal(&rsip_instance_ctrl, cipher, &cipher_length);
	switch ((uint32_t)err) {
	case FSP_SUCCESS:
		break;
	case FSP_ERR_ASSERTION:
		return TEE_ERROR_BAD_PARAMETERS;
	case FSP_ERR_NOT_OPEN:
		return TEE_ERROR_BAD_STATE;
	case FSP_ERR_INVALID_STATE:
		return TEE_ERROR_BAD_STATE;
	case FSP_ERR_CRYPTO_RSIP_FAIL:
		return TEE_ERROR_GENERIC;
	case FSP_ERR_CRYPTO_RSIP_FATAL:
		return TEE_ERROR_GENERIC;
	default:
		return TEE_ERROR_BAD_STATE;
	}

	params[0].memref.size = cipher_length;

	return TEE_SUCCESS;
}

static TEE_Result aes_cipher_decryptinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS],
					 rsip_aes_mode_t mode, rsip_byte_size_wrapped_key_t key_size)
{
	fsp_err_t err;

	rsip_wrapped_key_t *wrapped_key;
	uint8_t *initial_vector;

	initial_vector = (uint8_t *)params[1].memref.buffer;
	if (mode != RSIP_AES_MODE_ECB) {
		if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_NONE,
					     TEE_PARAM_TYPE_NONE))
			return TEE_ERROR_BAD_PARAMETERS;

		if (!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t)) {
			EMSG("initial_vector err");
			return TEE_ERROR_BAD_PARAMETERS;
		}
	} else {
		if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_NONE,
					     TEE_PARAM_TYPE_NONE,
					     TEE_PARAM_TYPE_NONE))
			return TEE_ERROR_BAD_PARAMETERS;
	}

	wrapped_key = (rsip_wrapped_key_t *)params[0].memref.buffer;
	if ((!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t)) || (key_size > params[0].memref.size)) {
		EMSG("key err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = R_RSIP_AES_Cipher_DecryptInit(&rsip_instance_ctrl, mode, wrapped_key, initial_vector);
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
	case FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT:
		return TEE_ERROR_ACCESS_CONFLICT;
	case FSP_ERR_CRYPTO_RSIP_FATAL:
		return TEE_ERROR_GENERIC;
	default:
		return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

static TEE_Result aes_cipher_decryptupdate(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	uint8_t *cipher;
	uint8_t *plain;
	uint32_t cipher_length;
	uint32_t plain_length;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
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

	err = R_RSIP_AES_Cipher_DecryptUpdate(&rsip_instance_ctrl, cipher, plain, cipher_length);
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
	default:
		return TEE_ERROR_BAD_STATE;
	}

	params[1].memref.size = cipher_length;

	return TEE_SUCCESS;
}

static TEE_Result aes_cipher_decryptfinal(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	uint8_t *plain;
	uint32_t plain_length = 0;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	plain = (uint8_t *)params[0].memref.buffer;
	plain_length = (uint32_t)params[0].memref.size;
	if ((!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t)) || (AES_BLOCK_LEN > params[0].memref.size)) {
		EMSG("plain err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = R_RSIP_AES_Cipher_DecryptFinal(&rsip_instance_ctrl, plain, &plain_length);
	switch ((uint32_t)err) {
	case FSP_SUCCESS:
		break;
	case FSP_ERR_ASSERTION:
		return TEE_ERROR_BAD_PARAMETERS;
	case FSP_ERR_NOT_OPEN:
		return TEE_ERROR_BAD_STATE;
	case FSP_ERR_INVALID_STATE:
		return TEE_ERROR_BAD_STATE;
	case FSP_ERR_CRYPTO_RSIP_FAIL:
		return TEE_ERROR_GENERIC;
	case FSP_ERR_CRYPTO_RSIP_FATAL:
		return TEE_ERROR_GENERIC;
	default:
		return TEE_ERROR_BAD_STATE;
	}

	params[0].memref.size = plain_length;

	return TEE_SUCCESS;
}

static TEE_Result aes_cmac_generateinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS],
					rsip_byte_size_wrapped_key_t key_size)
{
	fsp_err_t err;

	rsip_wrapped_key_t *wrapped_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	wrapped_key = (rsip_wrapped_key_t *)params[0].memref.buffer;
	if ((!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t)) || (key_size > params[0].memref.size)) {
		EMSG("key err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = R_RSIP_AES_CMAC_GenerateInit(&rsip_instance_ctrl, wrapped_key);
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
	case FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT:
		return TEE_ERROR_ACCESS_CONFLICT;
	case FSP_ERR_CRYPTO_RSIP_FATAL:
		return TEE_ERROR_GENERIC;
	default:
		return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

static TEE_Result aes_cmac_generateupdate(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	uint8_t *message;
	uint32_t message_length;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	message = (uint8_t *)params[0].memref.buffer;
	message_length = (uint32_t)params[0].memref.size;
	if (!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t))
		return TEE_ERROR_BAD_PARAMETERS;

	err = R_RSIP_AES_CMAC_GenerateUpdate(&rsip_instance_ctrl, message, message_length);
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
		return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

static TEE_Result aes_cmac_generatefinal(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	uint8_t *mac;
	uint32_t mac_length;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	mac = (uint8_t *)params[0].memref.buffer;
	mac_length = params[0].memref.size;
	if ((!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t)) || (MAC_BYTE_SIZE > mac_length))
		return TEE_ERROR_BAD_PARAMETERS;

	err = R_RSIP_AES_CMAC_GenerateFinal(&rsip_instance_ctrl, mac);
	switch ((uint32_t)err) {
	case FSP_SUCCESS:
		break;
	case FSP_ERR_ASSERTION:
		return TEE_ERROR_BAD_PARAMETERS;
	case FSP_ERR_NOT_OPEN:
		return TEE_ERROR_BAD_STATE;
	case FSP_ERR_INVALID_STATE:
		return TEE_ERROR_BAD_STATE;
	case FSP_ERR_CRYPTO_RSIP_FAIL:
		return TEE_ERROR_GENERIC;
	case FSP_ERR_CRYPTO_RSIP_FATAL:
		return TEE_ERROR_GENERIC;
	default:
		return TEE_ERROR_BAD_STATE;
	}

	params[0].memref.size = RSIP_BYTE_SIZE_AES_BLOCK;

	return TEE_SUCCESS;
}

static TEE_Result aes_cmac_verifyinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS],
				      rsip_byte_size_wrapped_key_t key_size)
{
	fsp_err_t err;

	rsip_wrapped_key_t *wrapped_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	wrapped_key = (rsip_wrapped_key_t *)params[0].memref.buffer;
	if ((!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t)) || (key_size > params[0].memref.size)) {
		EMSG("key err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = R_RSIP_AES_CMAC_VerifyInit(&rsip_instance_ctrl, wrapped_key);
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
	case FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT:
		return TEE_ERROR_ACCESS_CONFLICT;
	case FSP_ERR_CRYPTO_RSIP_FATAL:
		return TEE_ERROR_GENERIC;
	default:
		return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

static TEE_Result aes_cmac_verifyupdate(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	uint8_t *message;
	uint32_t message_length;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	message = (uint8_t *)params[0].memref.buffer;
	message_length = (uint32_t)params[0].memref.size;
	if (!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t))
		return TEE_ERROR_BAD_PARAMETERS;

	err = R_RSIP_AES_CMAC_VerifyUpdate(&rsip_instance_ctrl, message, message_length);
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
		return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

static TEE_Result aes_cmac_verifyfinal(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	uint8_t *mac;
	uint32_t mac_length;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	mac = (uint8_t *)params[0].memref.buffer;
	mac_length = params[0].memref.size;
	if (!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t)) {
		EMSG("mac err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = R_RSIP_AES_CMAC_VerifyFinal(&rsip_instance_ctrl, mac, mac_length);
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
	case FSP_ERR_CRYPTO_RSIP_FAIL:
		return TEE_ERROR_GENERIC;
	case FSP_ERR_CRYPTO_RSIP_AUTHENTICATION:
		return TEE_ERROR_MAC_INVALID;
	case FSP_ERR_CRYPTO_RSIP_FATAL:
		return TEE_ERROR_GENERIC;
	default:
		return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

static TEE_Result aes_gcm_encryptinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS],
				      rsip_byte_size_wrapped_key_t key_size)
{
	fsp_err_t err;

	rsip_wrapped_key_t *wrapped_key;
	uint8_t *initial_vector;
	uint32_t  initial_vector_length;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	wrapped_key = (rsip_wrapped_key_t *)params[0].memref.buffer;
	if ((!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t)) || (key_size > params[0].memref.size)) {
		EMSG("key err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	initial_vector = (uint8_t *)params[1].memref.buffer;
	initial_vector_length = params[1].memref.size;
	if (!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t))
		return TEE_ERROR_BAD_PARAMETERS;

	err = R_RSIP_AES_GCM_EncryptInit(&rsip_instance_ctrl, wrapped_key, initial_vector, initial_vector_length);
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
	case FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT:
		return TEE_ERROR_ACCESS_CONFLICT;
	case FSP_ERR_CRYPTO_RSIP_FATAL:
		return TEE_ERROR_GENERIC;
	default:
		return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

static TEE_Result aes_gcm_encryptupdate(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	uint8_t *plain;
	uint8_t *cipher;
	uint8_t *aad;
	uint32_t plain_length;
	uint32_t cipher_length;
	uint32_t aad_length;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	plain = (uint8_t *)params[0].memref.buffer;
	plain_length = (uint32_t)params[0].memref.size;
	if (!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t))
		return TEE_ERROR_BAD_PARAMETERS;

	cipher = (uint8_t *)params[1].memref.buffer;
	cipher_length = (uint32_t)params[1].memref.size;
	if ((!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t)) || (cipher_length < plain_length))
		return TEE_ERROR_BAD_PARAMETERS;

	aad = (uint8_t *)params[2].memref.buffer;
	aad_length = (uint32_t)params[2].memref.size;
	if (!IS_ALIGNED_WITH_TYPE(params[2].memref.buffer, uint32_t))
		return TEE_ERROR_BAD_PARAMETERS;

	err = R_RSIP_AES_GCM_EncryptUpdate(&rsip_instance_ctrl, plain, cipher, plain_length, aad, aad_length);
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
	default:
		return TEE_ERROR_BAD_STATE;
	}

	params[1].memref.size = plain_length;

	return TEE_SUCCESS;
}

static TEE_Result aes_gcm_encryptfinal(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	uint8_t *cipher;
	uint8_t *p_tag;
	uint32_t remaining_length = 0;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	cipher = (uint8_t *)params[0].memref.buffer;
	if ((!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t)) || (AES_BLOCK_LEN > params[0].memref.size)) {
		EMSG("cipher err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	p_tag  = (uint8_t *)params[1].memref.buffer;
	if ((!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t)) || (AES_BLOCK_LEN > params[1].memref.size)) {
		EMSG("tag err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = R_RSIP_AES_GCM_EncryptFinal(&rsip_instance_ctrl, cipher, &remaining_length, p_tag);
	switch ((uint32_t)err) {
	case FSP_SUCCESS:
		break;
	case FSP_ERR_ASSERTION:
		return TEE_ERROR_BAD_PARAMETERS;
	case FSP_ERR_NOT_OPEN:
		return TEE_ERROR_BAD_STATE;
	case FSP_ERR_INVALID_STATE:
		return TEE_ERROR_BAD_STATE;
	case FSP_ERR_CRYPTO_RSIP_FAIL:
		return TEE_ERROR_GENERIC;
	case FSP_ERR_CRYPTO_RSIP_FATAL:
		return TEE_ERROR_GENERIC;
	default:
		return TEE_ERROR_BAD_STATE;
	}

	params[0].memref.size = remaining_length;
	params[1].memref.size = RSIP_BYTE_SIZE_AES_BLOCK; // tag size 16byte

	return TEE_SUCCESS;
}

static TEE_Result aes_gcm_decryptinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS],
				      rsip_byte_size_wrapped_key_t key_size)
{
	fsp_err_t err;

	rsip_wrapped_key_t *wrapped_key;
	uint8_t *initial_vector;
	uint32_t  initial_vector_length;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	wrapped_key = (rsip_wrapped_key_t *)params[0].memref.buffer;
	if ((!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t)) || (key_size > params[0].memref.size)) {
		EMSG("key err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	initial_vector = (uint8_t *)params[1].memref.buffer;
	initial_vector_length = params[1].memref.size;
	if (!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t))
		return TEE_ERROR_BAD_PARAMETERS;

	err = R_RSIP_AES_GCM_DecryptInit(&rsip_instance_ctrl, wrapped_key, initial_vector, initial_vector_length);
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
	case FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT:
		return TEE_ERROR_ACCESS_CONFLICT;
	case FSP_ERR_CRYPTO_RSIP_FATAL:
		return TEE_ERROR_GENERIC;
	default:
		return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

static TEE_Result aes_gcm_decryptupdate(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	uint8_t *cipher;
	uint8_t *plain;
	uint8_t *aad;
	uint32_t cipher_length;
	uint32_t plain_length;
	uint32_t aad_length;

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
	if ((!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t)) || (plain_length < cipher_length))
		return TEE_ERROR_BAD_PARAMETERS;

	aad = (uint8_t *)params[2].memref.buffer;
	aad_length = (uint32_t)params[2].memref.size;
	if (!IS_ALIGNED_WITH_TYPE(params[2].memref.buffer, uint32_t))
		return TEE_ERROR_BAD_PARAMETERS;

	err = R_RSIP_AES_GCM_DecryptUpdate(&rsip_instance_ctrl, cipher, plain, cipher_length, aad, aad_length);
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
	default:
		return TEE_ERROR_BAD_STATE;
	}

	params[1].memref.size = cipher_length;

	return TEE_SUCCESS;
}

static TEE_Result aes_gcm_decryptfinal(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	uint8_t *plain;
	uint8_t *p_tag;
	uint32_t p_tag_length;
	uint32_t remaining_length = 0;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	plain = (uint8_t *)params[0].memref.buffer;
	if ((!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t)) || (AES_BLOCK_LEN > params[0].memref.size)) {
		EMSG("plain err");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	p_tag  = (uint8_t *)params[1].memref.buffer;
	p_tag_length = params[1].memref.size;
	if ((!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t)) || (AES_BLOCK_LEN > params[1].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	err = R_RSIP_AES_GCM_DecryptFinal(&rsip_instance_ctrl, plain, &remaining_length, p_tag, p_tag_length);
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
	case FSP_ERR_CRYPTO_RSIP_FAIL:
		return TEE_ERROR_GENERIC;
	case FSP_ERR_CRYPTO_RSIP_AUTHENTICATION:
		return TEE_ERROR_MAC_INVALID;
	case FSP_ERR_CRYPTO_RSIP_FATAL:
		return TEE_ERROR_GENERIC;
	default:
		return TEE_ERROR_BAD_STATE;
	}

	params[0].memref.size = remaining_length;

	return TEE_SUCCESS;
}

static TEE_Result aes128ecb_encryptinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return aes_cipher_encryptinit(types, params, RSIP_AES_MODE_ECB, RSIP_BYTE_SIZE_WRAPPED_KEY_AES_128);
}

static TEE_Result aes256ecb_encryptinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return aes_cipher_encryptinit(types, params, RSIP_AES_MODE_ECB, RSIP_BYTE_SIZE_WRAPPED_KEY_AES_256);
}

static TEE_Result aes128cbc_encryptinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return aes_cipher_encryptinit(types, params, RSIP_AES_MODE_CBC, RSIP_BYTE_SIZE_WRAPPED_KEY_AES_128);
}

static TEE_Result aes256cbc_encryptinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return aes_cipher_encryptinit(types, params, RSIP_AES_MODE_CBC, RSIP_BYTE_SIZE_WRAPPED_KEY_AES_256);
}

static TEE_Result aes128ctr_encryptinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return aes_cipher_encryptinit(types, params, RSIP_AES_MODE_CTR, RSIP_BYTE_SIZE_WRAPPED_KEY_AES_128);
}

static TEE_Result aes256ctr_encryptinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return aes_cipher_encryptinit(types, params, RSIP_AES_MODE_CTR, RSIP_BYTE_SIZE_WRAPPED_KEY_AES_256);
}

static TEE_Result aes128xts_encryptinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return aes_cipher_encryptinit(types, params, RSIP_AES_MODE_XTS, RSIP_BYTE_SIZE_WRAPPED_KEY_AES_128_XTS);
}

static TEE_Result aes256xts_encryptinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return aes_cipher_encryptinit(types, params, RSIP_AES_MODE_XTS, RSIP_BYTE_SIZE_WRAPPED_KEY_AES_256_XTS);
}

static TEE_Result aes128ecb_decryptinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return aes_cipher_decryptinit(types, params, RSIP_AES_MODE_ECB, RSIP_BYTE_SIZE_WRAPPED_KEY_AES_128);
}

static TEE_Result aes256ecb_decryptinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return aes_cipher_decryptinit(types, params, RSIP_AES_MODE_ECB, RSIP_BYTE_SIZE_WRAPPED_KEY_AES_256);
}

static TEE_Result aes128cbc_decryptinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return aes_cipher_decryptinit(types, params, RSIP_AES_MODE_CBC, RSIP_BYTE_SIZE_WRAPPED_KEY_AES_128);
}

static TEE_Result aes256cbc_decryptinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return aes_cipher_decryptinit(types, params, RSIP_AES_MODE_CBC, RSIP_BYTE_SIZE_WRAPPED_KEY_AES_256);
}

static TEE_Result aes128ctr_decryptinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return aes_cipher_decryptinit(types, params, RSIP_AES_MODE_CTR, RSIP_BYTE_SIZE_WRAPPED_KEY_AES_128);
}

static TEE_Result aes256ctr_decryptinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return aes_cipher_decryptinit(types, params, RSIP_AES_MODE_CTR, RSIP_BYTE_SIZE_WRAPPED_KEY_AES_256);
}

static TEE_Result aes128xts_decryptinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return aes_cipher_decryptinit(types, params, RSIP_AES_MODE_XTS, RSIP_BYTE_SIZE_WRAPPED_KEY_AES_128_XTS);
}

static TEE_Result aes256xts_decryptinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return aes_cipher_decryptinit(types, params, RSIP_AES_MODE_XTS, RSIP_BYTE_SIZE_WRAPPED_KEY_AES_256_XTS);
}

static TEE_Result aes128cmac_generateinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return aes_cmac_generateinit(types, params, RSIP_BYTE_SIZE_WRAPPED_KEY_AES_128);
}

static TEE_Result aes256cmac_generateinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return aes_cmac_generateinit(types, params, RSIP_BYTE_SIZE_WRAPPED_KEY_AES_256);
}

static TEE_Result aes128cmac_verifyinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return aes_cmac_verifyinit(types, params, RSIP_BYTE_SIZE_WRAPPED_KEY_AES_128);
}

static TEE_Result aes256cmac_verifyinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return aes_cmac_verifyinit(types, params, RSIP_BYTE_SIZE_WRAPPED_KEY_AES_256);
}

static TEE_Result aes128gcm_encryptinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return aes_gcm_encryptinit(types, params, RSIP_BYTE_SIZE_WRAPPED_KEY_AES_128);
}

static TEE_Result aes256gcm_encryptinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return aes_gcm_encryptinit(types, params, RSIP_BYTE_SIZE_WRAPPED_KEY_AES_256);
}

static TEE_Result aes128gcm_decryptinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return aes_gcm_decryptinit(types, params, RSIP_BYTE_SIZE_WRAPPED_KEY_AES_128);
}

static TEE_Result aes256gcm_decryptinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return aes_gcm_decryptinit(types, params, RSIP_BYTE_SIZE_WRAPPED_KEY_AES_256);
}

static TEE_Result invoke_command(void *session __unused,
				 uint32_t cmd,
				 uint32_t ptypes,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	EMSG(PTA_NAME" command %#"PRIx32" ptypes %#"PRIx32, cmd, ptypes);

	switch (cmd) {
	case PTA_CMD_AES128ECB_EncryptInit:
		return aes128ecb_encryptinit(ptypes, params);
	case PTA_CMD_AES256ECB_EncryptInit:
		return aes256ecb_encryptinit(ptypes, params);

	case PTA_CMD_AES128CBC_EncryptInit:
		return aes128cbc_encryptinit(ptypes, params);
	case PTA_CMD_AES256CBC_EncryptInit:
		return aes256cbc_encryptinit(ptypes, params);

	case PTA_CMD_AES128CTR_EncryptInit:
		return aes128ctr_encryptinit(ptypes, params);
	case PTA_CMD_AES256CTR_EncryptInit:
		return aes256ctr_encryptinit(ptypes, params);

	case PTA_CMD_AES128XTS_EncryptInit:
		return aes128xts_encryptinit(ptypes, params);
	case PTA_CMD_AES256XTS_EncryptInit:
		return aes256xts_encryptinit(ptypes, params);

	case PTA_CMD_AES128ECB_EncryptUpdate:
	case PTA_CMD_AES256ECB_EncryptUpdate:
	case PTA_CMD_AES128CBC_EncryptUpdate:
	case PTA_CMD_AES256CBC_EncryptUpdate:
	case PTA_CMD_AES128CTR_EncryptUpdate:
	case PTA_CMD_AES256CTR_EncryptUpdate:
	case PTA_CMD_AES128XTS_EncryptUpdate:
	case PTA_CMD_AES256XTS_EncryptUpdate:
		return aes_cipher_encryptupdate(ptypes, params);

	case PTA_CMD_AES128ECB_EncryptFinal:
	case PTA_CMD_AES256ECB_EncryptFinal:
	case PTA_CMD_AES128CBC_EncryptFinal:
	case PTA_CMD_AES256CBC_EncryptFinal:
	case PTA_CMD_AES128CTR_EncryptFinal:
	case PTA_CMD_AES256CTR_EncryptFinal:
	case PTA_CMD_AES128XTS_EncryptFinal:
	case PTA_CMD_AES256XTS_EncryptFinal:
		return aes_cipher_encryptfinal(ptypes, params);

	case PTA_CMD_AES128ECB_DecryptInit:
		return aes128ecb_decryptinit(ptypes, params);
	case PTA_CMD_AES256ECB_DecryptInit:
		return aes256ecb_decryptinit(ptypes, params);

	case PTA_CMD_AES128CBC_DecryptInit:
		return aes128cbc_decryptinit(ptypes, params);
	case PTA_CMD_AES256CBC_DecryptInit:
		return aes256cbc_decryptinit(ptypes, params);

	case PTA_CMD_AES128CTR_DecryptInit:
		return aes128ctr_decryptinit(ptypes, params);
	case PTA_CMD_AES256CTR_DecryptInit:
		return aes256ctr_decryptinit(ptypes, params);

	case PTA_CMD_AES128XTS_DecryptInit:
		return aes128xts_decryptinit(ptypes, params);
	case PTA_CMD_AES256XTS_DecryptInit:
		return aes256xts_decryptinit(ptypes, params);

	case PTA_CMD_AES128ECB_DecryptUpdate:
	case PTA_CMD_AES256ECB_DecryptUpdate:
	case PTA_CMD_AES128CBC_DecryptUpdate:
	case PTA_CMD_AES256CBC_DecryptUpdate:
	case PTA_CMD_AES128CTR_DecryptUpdate:
	case PTA_CMD_AES256CTR_DecryptUpdate:
	case PTA_CMD_AES128XTS_DecryptUpdate:
	case PTA_CMD_AES256XTS_DecryptUpdate:
		return aes_cipher_decryptupdate(ptypes, params);
	case PTA_CMD_AES128ECB_DecryptFinal:
	case PTA_CMD_AES256ECB_DecryptFinal:
	case PTA_CMD_AES128CBC_DecryptFinal:
	case PTA_CMD_AES256CBC_DecryptFinal:
	case PTA_CMD_AES128CTR_DecryptFinal:
	case PTA_CMD_AES256CTR_DecryptFinal:
	case PTA_CMD_AES128XTS_DecryptFinal:
	case PTA_CMD_AES256XTS_DecryptFinal:
		return aes_cipher_decryptfinal(ptypes, params);

	case PTA_CMD_AES128CMAC_GenerateInit:
		return aes128cmac_generateinit(ptypes, params);
	case PTA_CMD_AES256CMAC_GenerateInit:
		return aes256cmac_generateinit(ptypes, params);
	case PTA_CMD_AES128CMAC_GenerateUpdate:
	case PTA_CMD_AES256CMAC_GenerateUpdate:
		return aes_cmac_generateupdate(ptypes, params);
	case PTA_CMD_AES128CMAC_GenerateFinal:
	case PTA_CMD_AES256CMAC_GenerateFinal:
		return aes_cmac_generatefinal(ptypes, params);
	case PTA_CMD_AES128CMAC_VerifyInit:
		return aes128cmac_verifyinit(ptypes, params);
	case PTA_CMD_AES256CMAC_VerifyInit:
		return aes256cmac_verifyinit(ptypes, params);
	case PTA_CMD_AES128CMAC_VerifyUpdate:
	case PTA_CMD_AES256CMAC_VerifyUpdate:
		return aes_cmac_verifyupdate(ptypes, params);
	case PTA_CMD_AES128CMAC_VerifyFinal:
	case PTA_CMD_AES256CMAC_VerifyFinal:
		return aes_cmac_verifyfinal(ptypes, params);

	case PTA_CMD_AES128GCM_EncryptInit:
		return aes128gcm_encryptinit(ptypes, params);
	case PTA_CMD_AES256GCM_EncryptInit:
		return aes256gcm_encryptinit(ptypes, params);

	case PTA_CMD_AES128GCM_EncryptUpdate:
	case PTA_CMD_AES256GCM_EncryptUpdate:
		return aes_gcm_encryptupdate(ptypes, params);

	case PTA_CMD_AES128GCM_EncryptFinal:
	case PTA_CMD_AES256GCM_EncryptFinal:
		return aes_gcm_encryptfinal(ptypes, params);

	case PTA_CMD_AES128GCM_DecryptInit:
		return aes128gcm_decryptinit(ptypes, params);
	case PTA_CMD_AES256GCM_DecryptInit:
		return aes256gcm_decryptinit(ptypes, params);

	case PTA_CMD_AES128GCM_DecryptUpdate:
	case PTA_CMD_AES256GCM_DecryptUpdate:
		return aes_gcm_decryptupdate(ptypes, params);

	case PTA_CMD_AES128GCM_DecryptFinal:
	case PTA_CMD_AES256GCM_DecryptFinal:
		return aes_gcm_decryptfinal(ptypes, params);

	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

pseudo_ta_register(.uuid = PTA_RSIP_AES_UUID,
		   .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS | TA_FLAG_DEVICE_ENUM,
		   .invoke_command_entry_point = invoke_command
);
