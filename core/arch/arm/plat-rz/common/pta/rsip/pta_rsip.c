// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2024, Renesas Electronics Corporation
 */

#include <utee_defines.h>
#include <kernel/pseudo_ta.h>
#include <platform_config.h>

#include <sflash.h>
#include <r_rsip.h>
#include <r_rsip_api.h>
#include <pta_rsip.h>

#define PTA_NAME "rsip.pta"

extern rsip_instance_ctrl_t rsip_instance_ctrl;

static uint32_t key_update_key[RSIP_BYTE_SIZE_WRAPPED_KEY_KEY_UPDATE_KEY / sizeof(uint32_t)];

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

static TEE_Result keygenerate(uint32_t types, TEE_Param params[TEE_NUM_PARAMS],
			      rsip_key_type_t key_type, rsip_byte_size_wrapped_key_t key_size)
{
	fsp_err_t err;

	rsip_wrapped_key_t *wrapped_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	wrapped_key = (rsip_wrapped_key_t *)params[0].memref.buffer;
	if ((!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t)) || (key_size > params[0].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	err = R_RSIP_KeyGenerate(&rsip_instance_ctrl, key_type, wrapped_key);
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
	case FSP_ERR_UNSUPPORTED:
		return TEE_ERROR_NOT_SUPPORTED;
	case FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT:
		return TEE_ERROR_ACCESS_CONFLICT;
	case FSP_ERR_CRYPTO_RSIP_FATAL:
		return TEE_ERROR_GENERIC;
	default:
		return TEE_ERROR_BAD_STATE;
	}

	params[0].memref.size = key_size;

	return TEE_SUCCESS;
}

static TEE_Result keypairgenerate(uint32_t types, TEE_Param params[TEE_NUM_PARAMS],
				  rsip_key_pair_type_t key_type, rsip_byte_size_wrapped_key_t pub_key_size, rsip_byte_size_wrapped_key_t pri_key_size)
{
	fsp_err_t err;

	rsip_wrapped_key_t *wrapped_pub_key;
	rsip_wrapped_key_t *wrapped_pri_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	wrapped_pri_key = (rsip_wrapped_key_t *)params[0].memref.buffer;
	if ((!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t)) || (pri_key_size > params[0].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	wrapped_pub_key = (rsip_wrapped_key_t *)params[1].memref.buffer;
	if ((!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t)) || (pub_key_size > params[1].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	err = R_RSIP_KeyPairGenerate(&rsip_instance_ctrl, key_type, wrapped_pub_key, wrapped_pri_key);
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
	case FSP_ERR_UNSUPPORTED:
		return TEE_ERROR_NOT_SUPPORTED;
	case FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT:
		return TEE_ERROR_ACCESS_CONFLICT;
	case FSP_ERR_CRYPTO_RSIP_FATAL:
	return TEE_ERROR_GENERIC;
	default:
	return TEE_ERROR_BAD_STATE;
	}

	params[0].memref.size = pri_key_size;
	params[1].memref.size = pub_key_size;

	return TEE_SUCCESS;
}

static TEE_Result randomnumbergenerate(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	uint8_t *random;

	const uint32_t random_length = 16;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	random = (uint8_t *)params[0].memref.buffer;
	if (!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t))
		return TEE_ERROR_BAD_PARAMETERS;

	err = R_RSIP_RandomNumberGenerate(&rsip_instance_ctrl, random);
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

static TEE_Result keyimportwithkuk(uint32_t types, TEE_Param params[TEE_NUM_PARAMS],
				   rsip_key_type_t key_type, size_t enc_key_size, rsip_byte_size_wrapped_key_t wrap_key_size)
{
	fsp_err_t err;

	uint8_t *initial_vector;
	uint8_t *encrypted_key;
	rsip_wrapped_key_t *wrapped_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	if ((!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t)) || (enc_key_size > params[0].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	if (0 != parser_encrypted_key((uintptr_t)params[0].memref.buffer, enc_key_size, &initial_vector, &encrypted_key))
		return TEE_ERROR_BAD_PARAMETERS;

	wrapped_key = (rsip_wrapped_key_t *)params[1].memref.buffer;
	if ((!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t)) || (wrap_key_size > params[1].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	err = R_RSIP_KeyImportWithKUK(&rsip_instance_ctrl, key_update_key, initial_vector, key_type, encrypted_key, wrapped_key);
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
	case FSP_ERR_CRYPTO_RSIP_FAIL:
		return TEE_ERROR_GENERIC;
	case FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT:
		return TEE_ERROR_ACCESS_CONFLICT;
	case FSP_ERR_CRYPTO_RSIP_FATAL:
		return TEE_ERROR_GENERIC;
	default:
		return TEE_ERROR_BAD_STATE;
	}

	params[1].memref.size = wrap_key_size;

	return TEE_SUCCESS;
}

static TEE_Result rsapublickeyexport(uint32_t types, TEE_Param params[TEE_NUM_PARAMS],
				     rsip_byte_size_wrapped_key_t wrap_key_size, uint32_t key_size_n, uint32_t key_size_e)
{
	fsp_err_t err;

	rsip_wrapped_key_t *wrapped_key;
	uint8_t *p_raw_public_key_n;
	uint8_t *p_raw_public_key_e;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	wrapped_key = (rsip_wrapped_key_t *)params[0].memref.buffer;
	if ((!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t)) || (wrap_key_size > params[0].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	if ((!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t)) || (key_size_n > params[1].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	if ((!IS_ALIGNED_WITH_TYPE(params[2].memref.buffer, uint32_t)) || (key_size_e > params[2].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	err = R_RSIP_RSAPublicKeyExport(wrapped_key, (uint8_t const **const)&p_raw_public_key_n,
					(uint8_t const **const)&p_raw_public_key_e);
	switch ((uint32_t)err) {
	case FSP_SUCCESS:
		break;
	case FSP_ERR_ASSERTION:
		return TEE_ERROR_BAD_PARAMETERS;
	case FSP_ERR_INVALID_ARGUMENT:
		return TEE_ERROR_BAD_PARAMETERS;
	default:
		return TEE_ERROR_BAD_STATE;
	}

	memcpy(params[1].memref.buffer, p_raw_public_key_n, key_size_n);
	memcpy(params[2].memref.buffer, p_raw_public_key_e, key_size_e);
	params[1].memref.size = key_size_n;
	params[2].memref.size = key_size_e;

	return TEE_SUCCESS;
}

static TEE_Result eccpublickeyexport(uint32_t types, TEE_Param params[TEE_NUM_PARAMS],
				     rsip_byte_size_wrapped_key_t wrap_key_size, uint32_t key_size_qx, uint32_t key_size_qy)
{
	fsp_err_t err;

	rsip_wrapped_key_t *wrapped_key;
	uint8_t *p_raw_public_key_qx;
	uint8_t *p_raw_public_key_qy;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	wrapped_key = (rsip_wrapped_key_t *)params[0].memref.buffer;
	if ((!IS_ALIGNED_WITH_TYPE(params[0].memref.buffer, uint32_t)) || (wrap_key_size > params[0].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	if ((!IS_ALIGNED_WITH_TYPE(params[1].memref.buffer, uint32_t)) || (key_size_qx > params[1].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	if ((!IS_ALIGNED_WITH_TYPE(params[2].memref.buffer, uint32_t)) || (key_size_qy > params[2].memref.size))
		return TEE_ERROR_BAD_PARAMETERS;

	err = R_RSIP_ECCPublicKeyExport(wrapped_key, (uint8_t const **const)&p_raw_public_key_qx,
					(uint8_t const **const)&p_raw_public_key_qy);
	switch ((uint32_t)err) {
	case FSP_SUCCESS:
		break;
	case FSP_ERR_ASSERTION:
		return TEE_ERROR_BAD_PARAMETERS;
	case FSP_ERR_INVALID_ARGUMENT:
		return TEE_ERROR_BAD_PARAMETERS;
	default:
		return TEE_ERROR_GENERIC;
	}

	memcpy(params[1].memref.buffer, p_raw_public_key_qx, key_size_qx);
	memcpy(params[2].memref.buffer, p_raw_public_key_qy, key_size_qy);
	params[1].memref.size = key_size_qx;
	params[2].memref.size = key_size_qy;

	return TEE_SUCCESS;
}

static TEE_Result keygenerate_aes128(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return keygenerate(types, params, RSIP_KEY_TYPE_AES_128, RSIP_BYTE_SIZE_WRAPPED_KEY_AES_128);
}

static TEE_Result keygenerate_aes256(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return keygenerate(types, params, RSIP_KEY_TYPE_AES_256, RSIP_BYTE_SIZE_WRAPPED_KEY_AES_256);
}

static TEE_Result keygenerate_aes128_xts(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return keygenerate(types, params, RSIP_KEY_TYPE_AES_128_XTS, RSIP_BYTE_SIZE_WRAPPED_KEY_AES_128_XTS);
}

static TEE_Result keygenerate_aes256_xts(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return keygenerate(types, params, RSIP_KEY_TYPE_AES_256_XTS, RSIP_BYTE_SIZE_WRAPPED_KEY_AES_256_XTS);
}

static TEE_Result keypairgenerate_rsa1024(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return keypairgenerate(types, params, RSIP_KEY_PAIR_TYPE_RSA_1024,
	RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_1024_PUBLIC_ENHANCED, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_1024_PRIVATE_ENHANCED);
}

static TEE_Result keypairgenerate_rsa2048(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return keypairgenerate(types, params, RSIP_KEY_PAIR_TYPE_RSA_2048,
		RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_2048_PUBLIC_ENHANCED, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_2048_PRIVATE_ENHANCED);
}

static TEE_Result keypairgenerate_rsa3072(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return keypairgenerate(types, params, RSIP_KEY_PAIR_TYPE_RSA_3072,
		RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_3072_PUBLIC, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_3072_PRIVATE);
}

static TEE_Result keypairgenerate_rsa4096(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return keypairgenerate(types, params, RSIP_KEY_PAIR_TYPE_RSA_4096,
		RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_4096_PUBLIC, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_4096_PRIVATE);
}

static TEE_Result keypairgenerate_ecc_secp192r1(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return keypairgenerate(types, params, RSIP_KEY_PAIR_TYPE_ECC_secp192r1,
		RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_secp192r1_PUBLIC, RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_secp192r1_PRIVATE);
}

static TEE_Result keypairgenerate_ecc_secp224r1(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return keypairgenerate(types, params, RSIP_KEY_PAIR_TYPE_ECC_secp224r1,
		RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_secp224r1_PUBLIC, RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_secp224r1_PRIVATE);
}

static TEE_Result keypairgenerate_ecc_secp256r1(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return keypairgenerate(types, params, RSIP_KEY_PAIR_TYPE_ECC_secp256r1,
		RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_secp256r1_PUBLIC, RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_secp256r1_PRIVATE);
}

static TEE_Result keypairgenerate_brainpoolp256r1(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return keypairgenerate(types, params, RSIP_KEY_PAIR_TYPE_ECC_BRAINPOOLP256R1,
		RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_BRAINPOOLP256R1_PUBLIC, RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_BRAINPOOLP256R1_PRIVATE);
}

static TEE_Result keyimportwithkuk_aes128(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return keyimportwithkuk(types, params, RSIP_KEY_TYPE_AES_128,
		sizeof(st_encrypted_aes128_key_t), RSIP_BYTE_SIZE_WRAPPED_KEY_AES_128);
}

static TEE_Result keyimportwithkuk_aes256(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return keyimportwithkuk(types, params, RSIP_KEY_TYPE_AES_256,
		sizeof(st_encrypted_aes256_key_t), RSIP_BYTE_SIZE_WRAPPED_KEY_AES_256);
}

static TEE_Result keyimportwithkuk_aes128_xts(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return keyimportwithkuk(types, params, RSIP_KEY_TYPE_AES_128_XTS,
		sizeof(st_encrypted_aes128xts_key_t), RSIP_BYTE_SIZE_WRAPPED_KEY_AES_128_XTS);
}

static TEE_Result keyimportwithkuk_aes256_xts(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return keyimportwithkuk(types, params, RSIP_KEY_TYPE_AES_256_XTS,
		sizeof(st_encrypted_aes256xts_key_t), RSIP_BYTE_SIZE_WRAPPED_KEY_AES_256_XTS);
}

static TEE_Result keyimportwithkuk_rsa1024_public(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return keyimportwithkuk(types, params, RSIP_KEY_TYPE_RSA_1024_PUBLIC_ENHANCED,
		sizeof(st_encrypted_rsa_1024_public_key_t), RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_1024_PUBLIC_ENHANCED);
}

static TEE_Result keyimportwithkuk_rsa1024_private(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return keyimportwithkuk(types, params, RSIP_KEY_TYPE_RSA_1024_PRIVATE_ENHANCED,
		sizeof(st_encrypted_rsa_1024_private_key_t), RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_1024_PRIVATE_ENHANCED);
}

static TEE_Result keyimportwithkuk_rsa2048_public(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return keyimportwithkuk(types, params, RSIP_KEY_TYPE_RSA_2048_PUBLIC_ENHANCED,
		sizeof(st_encrypted_rsa_2048_public_key_t), RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_2048_PUBLIC_ENHANCED);
}

static TEE_Result keyimportwithkuk_rsa2048_private(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return keyimportwithkuk(types, params, RSIP_KEY_TYPE_RSA_2048_PRIVATE_ENHANCED,
		sizeof(st_encrypted_rsa_2048_private_key_t), RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_2048_PRIVATE_ENHANCED);
}

static TEE_Result keyimportwithkuk_rsa3072_public(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return keyimportwithkuk(types, params, RSIP_KEY_TYPE_RSA_3072_PUBLIC,
		sizeof(st_encrypted_rsa_3072_public_key_t), RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_3072_PUBLIC);
}

static TEE_Result keyimportwithkuk_rsa3072_private(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return keyimportwithkuk(types, params, RSIP_KEY_TYPE_RSA_3072_PRIVATE,
		sizeof(st_encrypted_rsa_3072_private_key_t), RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_3072_PRIVATE);
}

static TEE_Result keyimportwithkuk_rsa4096_public(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return keyimportwithkuk(types, params, RSIP_KEY_TYPE_RSA_4096_PUBLIC,
		sizeof(st_encrypted_rsa_4096_public_key_t), RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_4096_PUBLIC);
}

static TEE_Result keyimportwithkuk_rsa4096_private(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return keyimportwithkuk(types, params, RSIP_KEY_TYPE_RSA_4096_PRIVATE,
		sizeof(st_encrypted_rsa_4096_private_key_t), RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_4096_PRIVATE);
}

static TEE_Result keyimportwithkuk_secp192r1_public(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return keyimportwithkuk(types, params, RSIP_KEY_TYPE_ECC_secp192r1_PUBLIC,
		sizeof(st_encrypted_ecc_secp192r1_public_key_t), RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_secp192r1_PUBLIC);
}

static TEE_Result keyimportwithkuk_secp192r1_private(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return keyimportwithkuk(types, params, RSIP_KEY_TYPE_ECC_secp192r1_PRIVATE,
		sizeof(st_encrypted_ecc_secp192r1_private_key_t), RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_secp192r1_PRIVATE);
}

static TEE_Result keyimportwithkuk_secp224r1_public(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return keyimportwithkuk(types, params, RSIP_KEY_TYPE_ECC_secp224r1_PUBLIC,
		sizeof(st_encrypted_ecc_secp224r1_public_key_t), RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_secp224r1_PUBLIC);
}

static TEE_Result keyimportwithkuk_secp224r1_private(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return keyimportwithkuk(types, params, RSIP_KEY_TYPE_ECC_secp224r1_PRIVATE,
		sizeof(st_encrypted_ecc_secp224r1_private_key_t), RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_secp224r1_PRIVATE);
}

static TEE_Result keyimportwithkuk_secp256r1_public(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return keyimportwithkuk(types, params, RSIP_KEY_TYPE_ECC_secp256r1_PUBLIC,
		sizeof(st_encrypted_ecc_secp256r1_public_key_t), RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_secp256r1_PUBLIC);
}

static TEE_Result keyimportwithkuk_secp256r1_private(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return keyimportwithkuk(types, params, RSIP_KEY_TYPE_ECC_secp256r1_PRIVATE,
		sizeof(st_encrypted_ecc_secp256r1_private_key_t), RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_secp256r1_PRIVATE);
}

static TEE_Result keyimportwithkuk_brainpoolp256r1_public(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return keyimportwithkuk(types, params, RSIP_KEY_TYPE_ECC_BRAINPOOLP256R1_PUBLIC,
		sizeof(st_encrypted_ecc_brainpoolp256r1_public_key_t), RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_BRAINPOOLP256R1_PUBLIC);
}

static TEE_Result keyimportwithkuk_brainpoolp256r1_private(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return keyimportwithkuk(types, params, RSIP_KEY_TYPE_ECC_BRAINPOOLP256R1_PRIVATE,
		sizeof(st_encrypted_ecc_brainpoolp256r1_private_key_t), RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_BRAINPOOLP256R1_PRIVATE);
}

static TEE_Result keyimportwithkuk_hmac_sha1(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return keyimportwithkuk(types, params, RSIP_KEY_TYPE_HMAC_SHA1,
		sizeof(st_encrypted_hmac_sha1_key_t), RSIP_BYTE_SIZE_WRAPPED_KEY_HMAC_SHA1);
}

static TEE_Result keyimportwithkuk_hmac_sha224(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return keyimportwithkuk(types, params, RSIP_KEY_TYPE_HMAC_SHA224,
		sizeof(st_encrypted_hmac_sha224_key_t), RSIP_BYTE_SIZE_WRAPPED_KEY_HMAC_SHA224);
}

static TEE_Result keyimportwithkuk_hmac_sha256(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return keyimportwithkuk(types, params, RSIP_KEY_TYPE_HMAC_SHA256,
		sizeof(st_encrypted_hmac_sha256_key_t), RSIP_BYTE_SIZE_WRAPPED_KEY_HMAC_SHA256);
}

static TEE_Result rsa1024publickeyexport(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return rsapublickeyexport(types, params, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_1024_PUBLIC_ENHANCED,
		WRAPPED_KEY_BYTE_SIZE_RSA_1024_PUBLIC_N, WRAPPED_KEY_BYTE_SIZE_RSA_1024_PUBLIC_E);
}

static TEE_Result rsa2048publickeyexport(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return rsapublickeyexport(types, params, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_2048_PUBLIC_ENHANCED,
		WRAPPED_KEY_BYTE_SIZE_RSA_2048_PUBLIC_N, WRAPPED_KEY_BYTE_SIZE_RSA_2048_PUBLIC_E);
}

static TEE_Result rsa3072publickeyexport(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return rsapublickeyexport(types, params, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_3072_PUBLIC,
		WRAPPED_KEY_BYTE_SIZE_RSA_3072_PUBLIC_N, WRAPPED_KEY_BYTE_SIZE_RSA_3072_PUBLIC_E);
}

static TEE_Result rsa4096publickeyexport(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return rsapublickeyexport(types, params, RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_4096_PUBLIC,
		WRAPPED_KEY_BYTE_SIZE_RSA_4096_PUBLIC_N, WRAPPED_KEY_BYTE_SIZE_RSA_4096_PUBLIC_E);
}

static TEE_Result eccsecp192r1publickeyexport(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return eccpublickeyexport(types, params, RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_secp192r1_PUBLIC,
		WRAPPED_KEY_BYTE_SIZE_ECC_secp192r1_PUBLIC_QX, WRAPPED_KEY_BYTE_SIZE_ECC_secp192r1_PUBLIC_QY);
}

static TEE_Result eccsecp224r1publickeyexport(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return eccpublickeyexport(types, params, RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_secp224r1_PUBLIC,
		WRAPPED_KEY_BYTE_SIZE_ECC_secp224r1_PUBLIC_QX, WRAPPED_KEY_BYTE_SIZE_ECC_secp224r1_PUBLIC_QY);
}

static TEE_Result eccsecp256r1publickeyexport(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return eccpublickeyexport(types, params, RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_secp256r1_PUBLIC,
		WRAPPED_KEY_BYTE_SIZE_ECC_secp256r1_PUBLIC_QX, WRAPPED_KEY_BYTE_SIZE_ECC_secp256r1_PUBLIC_QY);
}

static TEE_Result eccbrainpoolp256r1publickeyexport(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	return eccpublickeyexport(types, params, RSIP_BYTE_SIZE_ENCRYPTED_KEY_ECC_BRAINPOOLP256R1_PUBLIC,
		WRAPPED_KEY_BYTE_SIZE_ECC_BRAINPOOLP256R1_PUBLIC_QX, WRAPPED_KEY_BYTE_SIZE_ECC_BRAINPOOLP256R1_PUBLIC_QY);
}

static TEE_Result open_session(uint32_t nParamTypes __unused,
			       TEE_Param pParams[TEE_NUM_PARAMS] __unused,
			       void **ppSessionContext __unused)
{
	DMSG("open entry point for pseudo ta \"%s\"", PTA_NAME);
	sflash_open();
	sflash_read(CFG_KUK_BASE, key_update_key, sizeof(key_update_key));
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
	EMSG(PTA_NAME" command %#"PRIx32" ptypes %#"PRIx32, cmd, ptypes);

	switch (cmd) {
	case PTA_CMD_AES128_WrappedKeyGenerate:
		return keygenerate_aes128(ptypes, params);
	case PTA_CMD_AES256_WrappedKeyGenerate:
		return keygenerate_aes256(ptypes, params);
	case PTA_CMD_AES128_XTS_WrappedKeyGenerate:
		return keygenerate_aes128_xts(ptypes, params);
	case PTA_CMD_AES256_XTS_WrappedKeyGenerate:
		return keygenerate_aes256_xts(ptypes, params);
	case PTA_CMD_RSA1024_WrappedKeyPairGenerate:
		return keypairgenerate_rsa1024(ptypes, params);
	case PTA_CMD_RSA2048_WrappedKeyPairGenerate:
		return keypairgenerate_rsa2048(ptypes, params);
	case PTA_CMD_RSA3072_WrappedKeyPairGenerate:
		return keypairgenerate_rsa3072(ptypes, params);
	case PTA_CMD_RSA4096_WrappedKeyPairGenerate:
		return keypairgenerate_rsa4096(ptypes, params);
	case PTA_CMD_ECC_secp192r1_WrappedKeyPairGenerate:
		return keypairgenerate_ecc_secp192r1(ptypes, params);
	case PTA_CMD_ECC_secp224r1_WrappedKeyPairGenerate:
		return keypairgenerate_ecc_secp224r1(ptypes, params);
	case PTA_CMD_ECC_secp256r1_WrappedKeyPairGenerate:
		return keypairgenerate_ecc_secp256r1(ptypes, params);
	case PTA_CMD_ECC_BrainpoolP256r1_WrappedKeyPairGenerate:
		return keypairgenerate_brainpoolp256r1(ptypes, params);

	case PTA_CMD_RandomNumberGenerate:
		return randomnumbergenerate(ptypes, params);

	case PTA_CMD_AES128_EncryptedKeyWrap:
		return keyimportwithkuk_aes128(ptypes, params);
	case PTA_CMD_AES256_EncryptedKeyWrap:
		return keyimportwithkuk_aes256(ptypes, params);
	case PTA_CMD_AES128_XTS_EncryptedKeyWrap:
		return keyimportwithkuk_aes128_xts(ptypes, params);
	case PTA_CMD_AES256_XTS_EncryptedKeyWrap:
		return keyimportwithkuk_aes256_xts(ptypes, params);

	case PTA_CMD_RSA1024_EncryptedPublicKeyWrap:
		return keyimportwithkuk_rsa1024_public(ptypes, params);
	case PTA_CMD_RSA1024_EncryptedPrivateKeyWrap:
		return keyimportwithkuk_rsa1024_private(ptypes, params);
	case PTA_CMD_RSA2048_EncryptedPublicKeyWrap:
		return keyimportwithkuk_rsa2048_public(ptypes, params);
	case PTA_CMD_RSA2048_EncryptedPrivateKeyWrap:
		return keyimportwithkuk_rsa2048_private(ptypes, params);
	case PTA_CMD_RSA3072_EncryptedPublicKeyWrap:
		return keyimportwithkuk_rsa3072_public(ptypes, params);
	case PTA_CMD_RSA3072_EncryptedPrivateKeyWrap:
		return keyimportwithkuk_rsa3072_private(ptypes, params);
	case PTA_CMD_RSA4096_EncryptedPublicKeyWrap:
		return keyimportwithkuk_rsa4096_public(ptypes, params);
	case PTA_CMD_RSA4096_EncryptedPrivateKeyWrap:
		return keyimportwithkuk_rsa4096_private(ptypes, params);

	case PTA_CMD_ECC_secp192r1_EncryptedPublicKeyWrap:
		return keyimportwithkuk_secp192r1_public(ptypes, params);
	case PTA_CMD_ECC_secp224r1_EncryptedPublicKeyWrap:
		return keyimportwithkuk_secp224r1_public(ptypes, params);
	case PTA_CMD_ECC_secp256r1_EncryptedPublicKeyWrap:
		return keyimportwithkuk_secp256r1_public(ptypes, params);
	case PTA_CMD_ECC_BrainpoolP256r1_EncryptedPublicKeyWrap:
		return keyimportwithkuk_brainpoolp256r1_public(ptypes, params);

	case PTA_CMD_ECC_secp192r1_EncryptedPrivateKeyWrap:
		return keyimportwithkuk_secp192r1_private(ptypes, params);
	case PTA_CMD_ECC_secp224r1_EncryptedPrivateKeyWrap:
		return keyimportwithkuk_secp224r1_private(ptypes, params);
	case PTA_CMD_ECC_secp256r1_EncryptedPrivateKeyWrap:
		return keyimportwithkuk_secp256r1_private(ptypes, params);
	case PTA_CMD_ECC_BrainpoolP256r1_EncryptedPrivateKeyWrap:
		return keyimportwithkuk_brainpoolp256r1_private(ptypes, params);

	case PTA_CMD_HMAC_SHA1_EncryptedKeyWrap:
		return keyimportwithkuk_hmac_sha1(ptypes, params);
	case PTA_CMD_HMAC_SHA224_EncryptedKeyWrap:
		return keyimportwithkuk_hmac_sha224(ptypes, params);
	case PTA_CMD_HMAC_SHA256_EncryptedKeyWrap:
		return keyimportwithkuk_hmac_sha256(ptypes, params);

	case PTA_CMD_RSA_1024_Public_Key_Export:
		return rsa1024publickeyexport(ptypes, params);
	case PTA_CMD_RSA_2048_Public_Key_Export:
		return rsa2048publickeyexport(ptypes, params);
	case PTA_CMD_RSA_3072_Public_Key_Export:
		return rsa3072publickeyexport(ptypes, params);
	case PTA_CMD_RSA_4096_Public_Key_Export:
		return rsa4096publickeyexport(ptypes, params);

	case PTA_CMD_ECC_secp192r1_Public_Key_Export:
		return eccsecp192r1publickeyexport(ptypes, params);
	case PTA_CMD_ECC_secp224r1_Public_Key_Export:
		return eccsecp224r1publickeyexport(ptypes, params);
	case PTA_CMD_ECC_secp256r1_Public_Key_Export:
		return eccsecp256r1publickeyexport(ptypes, params);
	case PTA_CMD_ECC_BrainpoolP256r1_Public_Key_Export:
		return eccbrainpoolp256r1publickeyexport(ptypes, params);

	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

pseudo_ta_register(.uuid = PTA_RSIP_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .open_session_entry_point = open_session,
		   .close_session_entry_point = close_session,
		   .invoke_command_entry_point = invoke_command);
