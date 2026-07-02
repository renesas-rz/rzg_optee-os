// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2022, Renesas Electronics Corporation
 */

#include <utee_defines.h>
#include <kernel/pseudo_ta.h>
#include <platform_config.h>

#include <r_sce.h>
#include <sflash.h>
#include <pta_sce.h>

#define PTA_NAME "sce.pta"

static sce_key_update_key_t key_update_key;

static uint32_t crc32calc(const uint8_t *data, uint32_t len)
{
	uint32_t crc = 0xFFFFFFFF;

	while (0 < (len--)) {
		crc ^= ((uint32_t)*data << 24);
		for (int32_t j = 0; j < 8; j++) {
			if ((crc >> 31) & 1)
				crc = (crc << 1) ^ 0x04C11DB7;
			else
				crc <<= 1;
		}
		data++;
	}
	return crc;
}

static TEE_Result aes128_wrappedkeygenerate(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_aes_wrapped_key_t *wrapped_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	wrapped_key = (sce_aes_wrapped_key_t *)params[0].memref.buffer;
	if ((NULL == wrapped_key) || (sizeof(sce_aes_wrapped_key_t) > params[0].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	err = g_sce_protected_on_sce.AES128_WrappedKeyGenerate(wrapped_key);
	switch (err) {
	case FSP_SUCCESS:
		break;
	default: /* FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT */
		return TEE_ERROR_ACCESS_CONFLICT;
	}

	params[0].memref.size = sizeof(sce_aes_wrapped_key_t);

	return TEE_SUCCESS;
}

static TEE_Result aes256_wrappedkeygenerate(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_aes_wrapped_key_t *wrapped_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	wrapped_key = (sce_aes_wrapped_key_t *)params[0].memref.buffer;
	if ((NULL == wrapped_key) || (sizeof(sce_aes_wrapped_key_t) > params[0].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	err = g_sce_protected_on_sce.AES256_WrappedKeyGenerate(wrapped_key);
	switch (err) {
	case FSP_SUCCESS:
		break;
	default: /* FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT */
		return TEE_ERROR_ACCESS_CONFLICT;
	}

	params[0].memref.size = sizeof(sce_aes_wrapped_key_t);

	return TEE_SUCCESS;
}

static TEE_Result rsa1024_wrappedkeypairgenerate(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_rsa1024_wrapped_pair_key_t *wrapped_pair_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	wrapped_pair_key = (sce_rsa1024_wrapped_pair_key_t *)params[0].memref.buffer;
	if ((NULL == wrapped_pair_key) || (sizeof(sce_rsa1024_wrapped_pair_key_t) > params[0].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	err = g_sce_protected_on_sce.RSA1024_WrappedKeyPairGenerate(wrapped_pair_key);
	switch (err) {
	case FSP_SUCCESS:
		break;
	case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
		return TEE_ERROR_ACCESS_CONFLICT;
	default: /* FSP_ERR_CRYPTO_SCE_FAIL */
		return TEE_ERROR_GENERIC;
	}

	params[0].memref.size = sizeof(sce_rsa1024_wrapped_pair_key_t);

	return TEE_SUCCESS;
}

static TEE_Result rsa2048_wrappedkeypairgenerate(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_rsa2048_wrapped_pair_key_t *wrapped_pair_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	wrapped_pair_key = (sce_rsa2048_wrapped_pair_key_t *)params[0].memref.buffer;
	if ((NULL == wrapped_pair_key) || (sizeof(sce_rsa2048_wrapped_pair_key_t) > params[0].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	err = g_sce_protected_on_sce.RSA2048_WrappedKeyPairGenerate(wrapped_pair_key);
	switch (err) {
	case FSP_SUCCESS:
		break;
	case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
		return TEE_ERROR_ACCESS_CONFLICT;
	default: /* FSP_ERR_CRYPTO_SCE_FAIL */
		return TEE_ERROR_GENERIC;
	}

	params[0].memref.size = sizeof(sce_rsa2048_wrapped_pair_key_t);

	return TEE_SUCCESS;
}

static TEE_Result ecc_secp192r1_wrappedkeypairgenerate(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_ecc_wrapped_pair_key_t *wrapped_pair_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	wrapped_pair_key = (sce_ecc_wrapped_pair_key_t *)params[0].memref.buffer;
	if ((NULL == wrapped_pair_key) || (sizeof(sce_ecc_wrapped_pair_key_t) > params[0].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	err = g_sce_protected_on_sce.ECC_secp192r1_WrappedKeyPairGenerate(wrapped_pair_key);
	switch (err) {
	case FSP_SUCCESS:
		break;
	case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
		return TEE_ERROR_ACCESS_CONFLICT;
	default: /* FSP_ERR_CRYPTO_SCE_FAIL */
		return TEE_ERROR_GENERIC;
	}

	params[0].memref.size = sizeof(sce_ecc_wrapped_pair_key_t);

	return TEE_SUCCESS;
}

static TEE_Result ecc_secp224r1_wrappedkeypairgenerate(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_ecc_wrapped_pair_key_t *wrapped_pair_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	wrapped_pair_key = (sce_ecc_wrapped_pair_key_t *)params[0].memref.buffer;
	if ((NULL == wrapped_pair_key) || (sizeof(sce_ecc_wrapped_pair_key_t) > params[0].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	err = g_sce_protected_on_sce.ECC_secp224r1_WrappedKeyPairGenerate(wrapped_pair_key);
	switch (err) {
	case FSP_SUCCESS:
		break;
	case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
		return TEE_ERROR_ACCESS_CONFLICT;
	default: /* FSP_ERR_CRYPTO_SCE_FAIL */
		return TEE_ERROR_GENERIC;
	}

	params[0].memref.size = sizeof(sce_ecc_wrapped_pair_key_t);

	return TEE_SUCCESS;
}

static TEE_Result ecc_secp256r1_wrappedkeypairgenerate(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_ecc_wrapped_pair_key_t *wrapped_pair_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	wrapped_pair_key = (sce_ecc_wrapped_pair_key_t *)params[0].memref.buffer;
	if ((NULL == wrapped_pair_key) || (sizeof(sce_ecc_wrapped_pair_key_t) > params[0].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	err = g_sce_protected_on_sce.ECC_secp256r1_WrappedKeyPairGenerate(wrapped_pair_key);
	switch (err) {
	case FSP_SUCCESS:
		break;
	case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
		return TEE_ERROR_ACCESS_CONFLICT;
	default: /* FSP_ERR_CRYPTO_SCE_FAIL */
		return TEE_ERROR_GENERIC;
	}

	params[0].memref.size = sizeof(sce_ecc_wrapped_pair_key_t);

	return TEE_SUCCESS;
}

static TEE_Result ecc_brainpoolp512r1_wrappedkeypairgenerate(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_ecc_wrapped_pair_key_t *wrapped_pair_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	wrapped_pair_key = (sce_ecc_wrapped_pair_key_t *)params[0].memref.buffer;
	if ((NULL == wrapped_pair_key) || (sizeof(sce_ecc_wrapped_pair_key_t) > params[0].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	err = g_sce_protected_on_sce.ECC_BrainpoolP512r1_WrappedKeyPairGenerate(wrapped_pair_key);
	switch (err) {
	case FSP_SUCCESS:
		break;
	case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
		return TEE_ERROR_ACCESS_CONFLICT;
	default: /* FSP_ERR_CRYPTO_SCE_FAIL */
		return TEE_ERROR_GENERIC;
	}

	params[0].memref.size = sizeof(sce_ecc_wrapped_pair_key_t);

	return TEE_SUCCESS;
}

static TEE_Result randomnumbergenerate(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	uint32_t *random;

	const uint32_t random_length = 16;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	random = (uint32_t *)params[0].memref.buffer;
	if ((NULL == random) || (random_length > params[0].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	err = g_sce_protected_on_sce.randomNumberGenerate(random);
	switch (err) {
	case FSP_SUCCESS:
		break;
	default: /* FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT */
		return TEE_ERROR_ACCESS_CONFLICT;
	}

	params[0].memref.size = random_length;

	return TEE_SUCCESS;
}

static int parser_encrypted_key(uintptr_t enc_data, size_t size, uint8_t **initial_vector, uint8_t **encrypted_key)
{
	struct st_encrypted_key_header_t {
		uint32_t unused[2];
		uint8_t  initial_vector[16];
	};

	uint32_t expected_crc = *(uint32_t *)((enc_data + size) - sizeof(expected_crc));
	uint32_t crc = crc32calc((uint8_t *)enc_data, size - sizeof(expected_crc));

	if (expected_crc == TEE_U32_BSWAP(crc)) {
		*initial_vector = ((struct st_encrypted_key_header_t *)enc_data)->initial_vector;
		*encrypted_key  = (uint8_t *)(enc_data + sizeof(struct st_encrypted_key_header_t));
		return 0;
	}
	return -1;
}

static TEE_Result aes128_encryptedkeywrap(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	uint8_t *initial_vector;
	uint8_t *encrypted_key;
	sce_aes_wrapped_key_t *wrapped_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	if ((!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t)) || (sizeof(st_encrypted_aes128_key_t) > params[0].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	if (0 != parser_encrypted_key((uintptr_t)params[0].memref.buffer, sizeof(st_encrypted_aes128_key_t), &initial_vector, &encrypted_key))
		return TEE_ERROR_BAD_PARAMETERS;

	wrapped_key = (sce_aes_wrapped_key_t *)params[1].memref.buffer;
	if ((!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t)) || (sizeof(sce_aes_wrapped_key_t) > params[1].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	err = g_sce_protected_on_sce.AES128_EncryptedKeyWrap(initial_vector, encrypted_key, &key_update_key, wrapped_key);
	switch (err) {
	case FSP_SUCCESS:
		break;
	case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
		return TEE_ERROR_ACCESS_CONFLICT;
	default: /* FSP_ERR_CRYPTO_SCE_FAIL */
		return TEE_ERROR_GENERIC;
	}

	params[1].memref.size = sizeof(sce_aes_wrapped_key_t);

	return TEE_SUCCESS;
}

static TEE_Result aes256_encryptedkeywrap(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	uint8_t *initial_vector;
	uint8_t *encrypted_key;
	sce_aes_wrapped_key_t *wrapped_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	if ((!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t)) || (sizeof(st_encrypted_aes256_key_t) > params[0].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	if (0 != parser_encrypted_key((uintptr_t)params[0].memref.buffer, sizeof(st_encrypted_aes256_key_t), &initial_vector, &encrypted_key))
		return TEE_ERROR_BAD_PARAMETERS;

	wrapped_key = (sce_aes_wrapped_key_t *)params[1].memref.buffer;
	if ((!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t)) || (sizeof(sce_aes_wrapped_key_t) > params[1].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	err = g_sce_protected_on_sce.AES256_EncryptedKeyWrap(initial_vector, encrypted_key, &key_update_key, wrapped_key);
	switch (err) {
	case FSP_SUCCESS:
		break;
	case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
		return TEE_ERROR_ACCESS_CONFLICT;
	default: /* FSP_ERR_CRYPTO_SCE_FAIL */
		return TEE_ERROR_GENERIC;
	}

	params[1].memref.size = sizeof(sce_aes_wrapped_key_t);

	return TEE_SUCCESS;
}

static TEE_Result rsa1024_encryptedpublickeywrap(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	uint8_t *initial_vector;
	uint8_t *encrypted_key;
	sce_rsa1024_public_wrapped_key_t *wrapped_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	if ((!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t)) || (sizeof(st_encrypted_rsa_1024_public_key_t) > params[0].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	if (0 != parser_encrypted_key((uintptr_t)params[0].memref.buffer, sizeof(st_encrypted_rsa_1024_public_key_t), &initial_vector, &encrypted_key))
		return TEE_ERROR_BAD_PARAMETERS;

	wrapped_key = (sce_rsa1024_public_wrapped_key_t *)params[1].memref.buffer;
	if ((!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t)) || (sizeof(sce_rsa1024_public_wrapped_key_t) > params[1].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	err = g_sce_protected_on_sce.RSA1024_EncryptedPublicKeyWrap(initial_vector, encrypted_key, &key_update_key, wrapped_key);
	switch (err) {
	case FSP_SUCCESS:
		break;
	case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
		return TEE_ERROR_ACCESS_CONFLICT;
	default: /* FSP_ERR_CRYPTO_SCE_FAIL */
		return TEE_ERROR_GENERIC;
	}

	params[1].memref.size = sizeof(sce_rsa1024_public_wrapped_key_t);

	return TEE_SUCCESS;
}

static TEE_Result rsa1024_encryptedprivatekeywrap(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	uint8_t *initial_vector;
	uint8_t *encrypted_key;
	sce_rsa1024_private_wrapped_key_t *wrapped_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	if ((!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t)) || (sizeof(st_encrypted_rsa_1024_private_key_t) > params[0].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	if (0 != parser_encrypted_key((uintptr_t)params[0].memref.buffer, sizeof(st_encrypted_rsa_1024_private_key_t), &initial_vector, &encrypted_key))
		return TEE_ERROR_BAD_PARAMETERS;

	wrapped_key = (sce_rsa1024_private_wrapped_key_t *)params[1].memref.buffer;
	if ((!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t)) || (sizeof(sce_rsa1024_private_wrapped_key_t) > params[1].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	err = g_sce_protected_on_sce.RSA1024_EncryptedPrivateKeyWrap(initial_vector, encrypted_key, &key_update_key, wrapped_key);
	switch (err) {
	case FSP_SUCCESS:
		break;
	case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
		return TEE_ERROR_ACCESS_CONFLICT;
	default: /* FSP_ERR_CRYPTO_SCE_FAIL */
		return TEE_ERROR_GENERIC;
	}

	params[1].memref.size = sizeof(sce_rsa1024_private_wrapped_key_t);

	return TEE_SUCCESS;
}

static TEE_Result rsa2048_encryptedpublickeywrap(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	uint8_t *initial_vector;
	uint8_t *encrypted_key;
	sce_rsa2048_public_wrapped_key_t *wrapped_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	if ((!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t)) || (sizeof(st_encrypted_rsa_2048_public_key_t) > params[0].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	if (0 != parser_encrypted_key((uintptr_t)params[0].memref.buffer, sizeof(st_encrypted_rsa_2048_public_key_t), &initial_vector, &encrypted_key))
		return TEE_ERROR_BAD_PARAMETERS;

	wrapped_key = (sce_rsa2048_public_wrapped_key_t *)params[1].memref.buffer;
	if ((!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t)) || (sizeof(sce_rsa2048_public_wrapped_key_t) > params[1].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	err = g_sce_protected_on_sce.RSA2048_EncryptedPublicKeyWrap(initial_vector, encrypted_key, &key_update_key, wrapped_key);
	switch (err) {
	case FSP_SUCCESS:
		break;
	case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
		return TEE_ERROR_ACCESS_CONFLICT;
	default: /* FSP_ERR_CRYPTO_SCE_FAIL */
		return TEE_ERROR_GENERIC;
	}

	params[1].memref.size = sizeof(sce_rsa2048_public_wrapped_key_t);

	return TEE_SUCCESS;
}

static TEE_Result rsa2048_encryptedprivatekeywrap(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	uint8_t *initial_vector;
	uint8_t *encrypted_key;
	sce_rsa2048_private_wrapped_key_t *wrapped_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	if ((!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t)) || (sizeof(st_encrypted_rsa_2048_private_key_t) > params[0].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	if (0 != parser_encrypted_key((uintptr_t)params[0].memref.buffer, sizeof(st_encrypted_rsa_2048_private_key_t), &initial_vector, &encrypted_key))
		return TEE_ERROR_BAD_PARAMETERS;

	wrapped_key = (sce_rsa2048_private_wrapped_key_t *)params[1].memref.buffer;
	if ((!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t)) || (sizeof(sce_rsa2048_private_wrapped_key_t) > params[1].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	err = g_sce_protected_on_sce.RSA2048_EncryptedPrivateKeyWrap(initial_vector, encrypted_key, &key_update_key, wrapped_key);
	switch (err) {
	case FSP_SUCCESS:
		break;
	case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
		return TEE_ERROR_ACCESS_CONFLICT;
	default: /* FSP_ERR_CRYPTO_SCE_FAIL */
		return TEE_ERROR_GENERIC;
	}

	params[1].memref.size = sizeof(sce_rsa2048_private_wrapped_key_t);

	return TEE_SUCCESS;
}

static TEE_Result rsa4096_encryptedpublickeywrap(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	uint8_t *initial_vector;
	uint8_t *encrypted_key;
	sce_rsa4096_public_wrapped_key_t *wrapped_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	if ((!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t)) || (sizeof(st_encrypted_rsa_4096_public_key_t) > params[0].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	if (0 != parser_encrypted_key((uintptr_t)params[0].memref.buffer, sizeof(st_encrypted_rsa_4096_public_key_t), &initial_vector, &encrypted_key))
		return TEE_ERROR_BAD_PARAMETERS;

	wrapped_key = (sce_rsa4096_public_wrapped_key_t *)params[1].memref.buffer;
	if ((!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t)) || (sizeof(sce_rsa4096_public_wrapped_key_t) > params[1].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	err = g_sce_protected_on_sce.RSA4096_EncryptedPublicKeyWrap(initial_vector, encrypted_key, &key_update_key, wrapped_key);
	switch (err) {
	case FSP_SUCCESS:
		break;
	case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
		return TEE_ERROR_ACCESS_CONFLICT;
	default: /* FSP_ERR_CRYPTO_SCE_FAIL */
	return TEE_ERROR_GENERIC;
	}

	params[1].memref.size = sizeof(sce_rsa4096_public_wrapped_key_t);

	return TEE_SUCCESS;
}

static TEE_Result ecc_secp192r1_encryptedpublickeywrap(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	uint8_t *initial_vector;
	uint8_t *encrypted_key;
	sce_ecc_public_wrapped_key_t *wrapped_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	if ((!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t)) || (sizeof(st_encrypted_ecc_secp192r1_public_key_t) > params[0].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	if (0 != parser_encrypted_key((uintptr_t)params[0].memref.buffer, sizeof(st_encrypted_ecc_secp192r1_public_key_t), &initial_vector, &encrypted_key))
		return TEE_ERROR_BAD_PARAMETERS;

	wrapped_key = (sce_ecc_public_wrapped_key_t *)params[1].memref.buffer;
	if ((!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t)) || (sizeof(sce_ecc_public_wrapped_key_t) > params[1].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	err = g_sce_protected_on_sce.ECC_secp192r1_EncryptedPublicKeyWrap(initial_vector, encrypted_key, &key_update_key, wrapped_key);
	switch (err) {
	case FSP_SUCCESS:
		break;
	case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
		return TEE_ERROR_ACCESS_CONFLICT;
	default: /* FSP_ERR_CRYPTO_SCE_FAIL */
		return TEE_ERROR_GENERIC;
	}

	params[1].memref.size = sizeof(sce_ecc_public_wrapped_key_t);

	return TEE_SUCCESS;
}

static TEE_Result ecc_secp192r1_encryptedprivatekeywrap(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	uint8_t *initial_vector;
	uint8_t *encrypted_key;
	sce_ecc_private_wrapped_key_t *wrapped_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	if ((!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t)) || (sizeof(st_encrypted_ecc_secp192r1_private_key_t) > params[0].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	if (0 != parser_encrypted_key((uintptr_t)params[0].memref.buffer, sizeof(st_encrypted_ecc_secp192r1_private_key_t), &initial_vector, &encrypted_key))
		return TEE_ERROR_BAD_PARAMETERS;

	wrapped_key = (sce_ecc_private_wrapped_key_t *)params[1].memref.buffer;
	if ((!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t)) || (sizeof(sce_ecc_private_wrapped_key_t) > params[1].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	err = g_sce_protected_on_sce.ECC_secp192r1_EncryptedPrivateKeyWrap(initial_vector, encrypted_key, &key_update_key, wrapped_key);
	switch (err) {
	case FSP_SUCCESS:
		break;
	case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
		return TEE_ERROR_ACCESS_CONFLICT;
	default: /* FSP_ERR_CRYPTO_SCE_FAIL */
		return TEE_ERROR_GENERIC;
	}

	params[1].memref.size = sizeof(sce_ecc_private_wrapped_key_t);

	return TEE_SUCCESS;
}

static TEE_Result ecc_secp224r1_encryptedpublickeywrap(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	uint8_t *initial_vector;
	uint8_t *encrypted_key;
	sce_ecc_public_wrapped_key_t *wrapped_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	if ((!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t)) || (sizeof(st_encrypted_ecc_secp224r1_public_key_t) > params[0].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	if (0 != parser_encrypted_key((uintptr_t)params[0].memref.buffer, sizeof(st_encrypted_ecc_secp224r1_public_key_t), &initial_vector, &encrypted_key))
		return TEE_ERROR_BAD_PARAMETERS;

	wrapped_key = (sce_ecc_public_wrapped_key_t *)params[1].memref.buffer;
	if ((!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t)) || (sizeof(sce_ecc_public_wrapped_key_t) > params[1].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	err = g_sce_protected_on_sce.ECC_secp224r1_EncryptedPublicKeyWrap(initial_vector, encrypted_key, &key_update_key, wrapped_key);
	switch (err) {
	case FSP_SUCCESS:
		break;
	case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
		return TEE_ERROR_ACCESS_CONFLICT;
	default: /* FSP_ERR_CRYPTO_SCE_FAIL */
		return TEE_ERROR_GENERIC;
	}

	params[1].memref.size = sizeof(sce_ecc_public_wrapped_key_t);

	return TEE_SUCCESS;
}

static TEE_Result ecc_secp224r1_encryptedprivatekeywrap(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	uint8_t *initial_vector;
	uint8_t *encrypted_key;
	sce_ecc_private_wrapped_key_t *wrapped_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	if ((!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t)) || (sizeof(st_encrypted_ecc_secp224r1_private_key_t) > params[0].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	if (0 != parser_encrypted_key((uintptr_t)params[0].memref.buffer, sizeof(st_encrypted_ecc_secp224r1_private_key_t), &initial_vector, &encrypted_key))
		return TEE_ERROR_BAD_PARAMETERS;

	wrapped_key = (sce_ecc_private_wrapped_key_t *)params[1].memref.buffer;
	if ((!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t)) || (sizeof(sce_ecc_private_wrapped_key_t) > params[1].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	err = g_sce_protected_on_sce.ECC_secp224r1_EncryptedPrivateKeyWrap(initial_vector, encrypted_key, &key_update_key, wrapped_key);
	switch (err) {
	case FSP_SUCCESS:
		break;
	case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
		return TEE_ERROR_ACCESS_CONFLICT;
	default: /* FSP_ERR_CRYPTO_SCE_FAIL */
		return TEE_ERROR_GENERIC;
	}

	params[1].memref.size = sizeof(sce_ecc_private_wrapped_key_t);

	return TEE_SUCCESS;
}

static TEE_Result ecc_secp256r1_encryptedpublickeywrap(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	uint8_t *initial_vector;
	uint8_t *encrypted_key;
	sce_ecc_public_wrapped_key_t *wrapped_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	if ((!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t)) || (sizeof(st_encrypted_ecc_secp256r1_public_key_t) > params[0].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	if (0 != parser_encrypted_key((uintptr_t)params[0].memref.buffer, sizeof(st_encrypted_ecc_secp256r1_public_key_t), &initial_vector, &encrypted_key))
		return TEE_ERROR_BAD_PARAMETERS;

	wrapped_key = (sce_ecc_public_wrapped_key_t *)params[1].memref.buffer;
	if ((!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t)) || (sizeof(sce_ecc_public_wrapped_key_t) > params[1].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	err = g_sce_protected_on_sce.ECC_secp256r1_EncryptedPublicKeyWrap(initial_vector, encrypted_key, &key_update_key, wrapped_key);
	switch (err) {
	case FSP_SUCCESS:
		break;
	case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
		return TEE_ERROR_ACCESS_CONFLICT;
	default: /* FSP_ERR_CRYPTO_SCE_FAIL */
		return TEE_ERROR_GENERIC;
	}

	params[1].memref.size = sizeof(sce_ecc_public_wrapped_key_t);

	return TEE_SUCCESS;
}

static TEE_Result ecc_secp256r1_encryptedprivatekeywrap(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	uint8_t *initial_vector;
	uint8_t *encrypted_key;
	sce_ecc_private_wrapped_key_t *wrapped_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	if ((!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t)) || (sizeof(st_encrypted_ecc_secp256r1_private_key_t) > params[0].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	if (0 != parser_encrypted_key((uintptr_t)params[0].memref.buffer, sizeof(st_encrypted_ecc_secp256r1_private_key_t), &initial_vector, &encrypted_key))
		return TEE_ERROR_BAD_PARAMETERS;

	wrapped_key = (sce_ecc_private_wrapped_key_t *)params[1].memref.buffer;
	if ((!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t)) || (sizeof(sce_ecc_private_wrapped_key_t) > params[1].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	err = g_sce_protected_on_sce.ECC_secp256r1_EncryptedPrivateKeyWrap(initial_vector, encrypted_key, &key_update_key, wrapped_key);
	switch (err) {
	case FSP_SUCCESS:
		break;
	case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
		return TEE_ERROR_ACCESS_CONFLICT;
	default: /* FSP_ERR_CRYPTO_SCE_FAIL */
		return TEE_ERROR_GENERIC;
	}

	params[1].memref.size = sizeof(sce_ecc_private_wrapped_key_t);

	return TEE_SUCCESS;
}

static TEE_Result ecc_brainpoolp512r1_encryptedpublickeywrap(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	uint8_t *initial_vector;
	uint8_t *encrypted_key;
	sce_ecc_public_wrapped_key_t *wrapped_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	if ((!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t)) || (sizeof(st_encrypted_ecc_brainpoolp512r1_public_key_t) > params[0].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	if (0 != parser_encrypted_key((uintptr_t)params[0].memref.buffer, sizeof(st_encrypted_ecc_brainpoolp512r1_public_key_t), &initial_vector, &encrypted_key))
		return TEE_ERROR_BAD_PARAMETERS;

	wrapped_key = (sce_ecc_public_wrapped_key_t *)params[1].memref.buffer;
	if ((!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t)) || (sizeof(sce_ecc_public_wrapped_key_t) > params[1].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	err = g_sce_protected_on_sce.ECC_BrainpoolP512r1_EncryptedPublicKeyWrap(initial_vector, encrypted_key, &key_update_key, wrapped_key);
	switch (err) {
	case FSP_SUCCESS:
		break;
	case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
		return TEE_ERROR_ACCESS_CONFLICT;
	default: /* FSP_ERR_CRYPTO_SCE_FAIL */
		return TEE_ERROR_GENERIC;
	}

	params[1].memref.size = sizeof(sce_ecc_public_wrapped_key_t);

	return TEE_SUCCESS;
}

static TEE_Result ecc_brainpoolp512r1_encryptedprivatekeywrap(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	uint8_t *initial_vector;
	uint8_t *encrypted_key;
	sce_ecc_private_wrapped_key_t *wrapped_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	if ((!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t)) || (sizeof(st_encrypted_ecc_brainpoolp512r1_private_key_t) > params[0].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	if (0 != parser_encrypted_key((uintptr_t)params[0].memref.buffer, sizeof(st_encrypted_ecc_brainpoolp512r1_private_key_t), &initial_vector, &encrypted_key))
		return TEE_ERROR_BAD_PARAMETERS;

	wrapped_key = (sce_ecc_private_wrapped_key_t *)params[1].memref.buffer;
	if ((!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t)) || (sizeof(sce_ecc_private_wrapped_key_t) > params[1].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	err = g_sce_protected_on_sce.ECC_BrainpoolP512r1_EncryptedPrivateKeyWrap(initial_vector, encrypted_key, &key_update_key, wrapped_key);
	switch (err) {
	case FSP_SUCCESS:
		break;
	case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
		return TEE_ERROR_ACCESS_CONFLICT;
	default: /* FSP_ERR_CRYPTO_SCE_FAIL */
		return TEE_ERROR_GENERIC;
	}

	params[1].memref.size = sizeof(sce_ecc_private_wrapped_key_t);

	return TEE_SUCCESS;
}

static TEE_Result open_session(uint32_t nParamTypes __unused,
			       TEE_Param pParams[TEE_NUM_PARAMS] __unused,
			       void **ppSessionContext __unused)
{
	DMSG("open entry point for pseudo ta \"%s\"", PTA_NAME);
	sflash_open();
	sflash_read(CFG_KUK_BASE, &key_update_key, sizeof(key_update_key));
	sflash_close();
	return TEE_SUCCESS;
}

static void close_session(void *pSessionContext __unused)
{
	DMSG("close entry point for pseudo ta \"%s\"", PTA_NAME);
}

static TEE_Result invoke_command(void *session __unused, uint32_t cmd,
				 uint32_t ptypes,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	DMSG(PTA_NAME" command %#"PRIx32" ptypes %#"PRIx32, cmd, ptypes);

	switch (cmd) {
	case PTA_CMD_AES128_WrappedKeyGenerate:
		return aes128_wrappedkeygenerate(ptypes, params);
	case PTA_CMD_AES256_WrappedKeyGenerate:
		return aes256_wrappedkeygenerate(ptypes, params);
	case PTA_CMD_RSA1024_WrappedKeyPairGenerate:
		return rsa1024_wrappedkeypairgenerate(ptypes, params);
	case PTA_CMD_RSA2048_WrappedKeyPairGenerate:
		return rsa2048_wrappedkeypairgenerate(ptypes, params);
	case PTA_CMD_ECC_secp192r1_WrappedKeyPairGenerate:
		return ecc_secp192r1_wrappedkeypairgenerate(ptypes, params);
	case PTA_CMD_ECC_secp224r1_WrappedKeyPairGenerate:
		return ecc_secp224r1_wrappedkeypairgenerate(ptypes, params);
	case PTA_CMD_ECC_secp256r1_WrappedKeyPairGenerate:
		return ecc_secp256r1_wrappedkeypairgenerate(ptypes, params);
	case PTA_CMD_ECC_BrainpoolP512r1_WrappedKeyPairGenerate:
		return ecc_brainpoolp512r1_wrappedkeypairgenerate(ptypes, params);
	case PTA_CMD_RandomNumberGenerate:
		return randomnumbergenerate(ptypes, params);
	case PTA_CMD_AES128_EncryptedKeyWrap:
		return aes128_encryptedkeywrap(ptypes, params);
	case PTA_CMD_AES256_EncryptedKeyWrap:
		return aes256_encryptedkeywrap(ptypes, params);
	case PTA_CMD_RSA1024_EncryptedPublicKeyWrap:
		return rsa1024_encryptedpublickeywrap(ptypes, params);
	case PTA_CMD_RSA1024_EncryptedPrivateKeyWrap:
		return rsa1024_encryptedprivatekeywrap(ptypes, params);
	case PTA_CMD_RSA2048_EncryptedPublicKeyWrap:
		return rsa2048_encryptedpublickeywrap(ptypes, params);
	case PTA_CMD_RSA2048_EncryptedPrivateKeyWrap:
		return rsa2048_encryptedprivatekeywrap(ptypes, params);
	case PTA_CMD_RSA4096_EncryptedPublicKeyWrap:
		return rsa4096_encryptedpublickeywrap(ptypes, params);
	case PTA_CMD_ECC_secp192r1_EncryptedPublicKeyWrap:
		return ecc_secp192r1_encryptedpublickeywrap(ptypes, params);
	case PTA_CMD_ECC_secp224r1_EncryptedPublicKeyWrap:
		return ecc_secp224r1_encryptedpublickeywrap(ptypes, params);
	case PTA_CMD_ECC_secp256r1_EncryptedPublicKeyWrap:
		return ecc_secp256r1_encryptedpublickeywrap(ptypes, params);
	case PTA_CMD_ECC_BrainpoolP512r1_EncryptedPublicKeyWrap:
		return ecc_brainpoolp512r1_encryptedpublickeywrap(ptypes, params);
	case PTA_CMD_ECC_secp192r1_EncryptedPrivateKeyWrap:
		return ecc_secp192r1_encryptedprivatekeywrap(ptypes, params);
	case PTA_CMD_ECC_secp224r1_EncryptedPrivateKeyWrap:
		return ecc_secp224r1_encryptedprivatekeywrap(ptypes, params);
	case PTA_CMD_ECC_secp256r1_EncryptedPrivateKeyWrap:
		return ecc_secp256r1_encryptedprivatekeywrap(ptypes, params);
	case PTA_CMD_ECC_BrainpoolP512r1_EncryptedPrivateKeyWrap:
		return ecc_brainpoolp512r1_encryptedprivatekeywrap(ptypes, params);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

pseudo_ta_register(.uuid = PTA_SCE_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .open_session_entry_point = open_session,
		   .close_session_entry_point = close_session,
		   .invoke_command_entry_point = invoke_command);
