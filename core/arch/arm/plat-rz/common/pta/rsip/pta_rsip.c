// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2024, Renesas Electronics Corporation
 */

#include <kernel/pseudo_ta.h>
#include <r_rsip.h>
#include <hw_crypto.h>
#include <pta_rsip.h>

#include "pta_rsip_cmd.h"
#include "pta_rsip_util.h"

#define PTA_NAME "rsip.pta"

static union wrapped_key_buffer key1;
static union wrapped_key_buffer key2;
static union wrapped_key_buffer wkuk;

static TEE_Result get_rsa_public_param_size(rsip_key_type_t key_type,
					    size_t *modulus_size,
					    size_t *exponent_size)
{
	switch (key_type) {
	case RSIP_KEY_TYPE_RSA_1024_PUBLIC_ENHANCED:
		*modulus_size = RSIP_RSA_MOD_SIZE_1024;
		break;
	case RSIP_KEY_TYPE_RSA_2048_PUBLIC_ENHANCED:
		*modulus_size = RSIP_RSA_MOD_SIZE_2048;
		break;
	case RSIP_KEY_TYPE_RSA_3072_PUBLIC:
		*modulus_size = RSIP_RSA_MOD_SIZE_3072;
		break;
	case RSIP_KEY_TYPE_RSA_4096_PUBLIC:
		*modulus_size = RSIP_RSA_MOD_SIZE_4096;
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
	*exponent_size = RSIP_RSA_EXPONENT_SIZE;

	return TEE_SUCCESS;
}

static TEE_Result get_ecc_public_param_size(rsip_key_type_t key_type,
					    size_t *qx_size, size_t *qy_size)
{
	size_t coord_size = 0;

	switch (key_type) {
	case RSIP_KEY_TYPE_ECC_secp192r1_PUBLIC:
		coord_size = RSIP_ECC_COORD_SIZE_192;
		break;
	case RSIP_KEY_TYPE_ECC_secp224r1_PUBLIC:
		coord_size = RSIP_ECC_COORD_SIZE_224;
		break;
	case RSIP_KEY_TYPE_ECC_secp256r1_PUBLIC:
	case RSIP_KEY_TYPE_ECC_BRAINPOOLP256R1_PUBLIC:
		coord_size = RSIP_ECC_COORD_SIZE_256;
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
	*qx_size = coord_size;
	*qy_size = coord_size;

	return TEE_SUCCESS;
}

/*
 * Generate a wrapped symmetric key.
 */
static TEE_Result generate_wrapped_key(uint32_t types,
				       TEE_Param params[TEE_NUM_PARAMS],
				       rsip_key_type_t key_type)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

	size_t wrapped_buf_size = 0;
	rsip_wrapped_key_t *wrapped_key = NULL;
	const struct rsip_key_desc *key_desc = NULL;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
				     TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	res = get_key_desc(key_type, &key_desc);
	if (res != TEE_SUCCESS)
		return res;

	wrapped_key = params[0].memref.buffer;
	wrapped_buf_size = params[0].memref.size;
	if (!wrapped_key || !IS_ALIGNED_WITH_UINT32(wrapped_key))
		return TEE_ERROR_BAD_PARAMETERS;

	err = R_RSIP_KeyGenerate(&rsip_instance_ctrl, key_type,
				 &key1.wrapped_key);
	if (err != FSP_SUCCESS)
		return rsip_err_to_tee(err);

	params[0].memref.size = key_desc->wrapped_size;
	if (wrapped_buf_size < params[0].memref.size)
		return TEE_ERROR_SHORT_BUFFER;

	memcpy(wrapped_key, &key1, params[0].memref.size);

	return TEE_SUCCESS;
}

/*
 * Generate a wrapped public/private key pair.
 */
static TEE_Result generate_wrapped_keypair(uint32_t types,
					   TEE_Param params[TEE_NUM_PARAMS],
					   rsip_key_pair_type_t pair_type)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

	size_t wrapped_pribuf_size = 0;
	rsip_wrapped_key_t *wrapped_prikey = NULL;
	const struct rsip_key_desc *pri_desc = NULL;

	size_t wrapped_pubbuf_size = 0;
	rsip_wrapped_key_t *wrapped_pubkey = NULL;
	const struct rsip_key_desc *pub_desc = NULL;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
				     TEE_PARAM_TYPE_MEMREF_OUTPUT,
				     TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	res = get_keypair_desc(pair_type, &pri_desc, &pub_desc);
	if (res != TEE_SUCCESS)
		return res;

	wrapped_prikey = params[0].memref.buffer;
	wrapped_pribuf_size = params[0].memref.size;
	if (!wrapped_prikey || !IS_ALIGNED_WITH_UINT32(wrapped_prikey))
		return TEE_ERROR_BAD_PARAMETERS;

	wrapped_pubkey = params[1].memref.buffer;
	wrapped_pubbuf_size = params[1].memref.size;
	if (!wrapped_pubkey || !IS_ALIGNED_WITH_UINT32(wrapped_pubkey))
		return TEE_ERROR_BAD_PARAMETERS;

	err = R_RSIP_KeyPairGenerate(&rsip_instance_ctrl, pair_type,
				     &key1.wrapped_key, &key2.wrapped_key);
	if (err != FSP_SUCCESS)
		return rsip_err_to_tee(err);

	params[0].memref.size = pri_desc->wrapped_size;
	params[1].memref.size = pub_desc->wrapped_size;
	if (wrapped_pribuf_size < params[0].memref.size ||
	    wrapped_pubbuf_size < params[1].memref.size)
		return TEE_ERROR_SHORT_BUFFER;

	memcpy(wrapped_prikey, &key2, params[0].memref.size);
	memcpy(wrapped_pubkey, &key1, params[1].memref.size);

	return TEE_SUCCESS;
}

/*
 * Calculate the CRC32 of a buffer.
 */
static uint32_t calc_crc32(const uint8_t *ptr, uint32_t len)
{
	uint32_t crc = 0xFFFFFFFF;

	while (0 < (len--)) {
		uint8_t val = *ptr;
		crc ^= ((uint32_t)val << 24);
		for (int32_t j = 0; j < 8; j++) {
			if ((crc >> 31) & 1)
				crc = (crc << 1) ^ 0x04C11DB7;
			else
				crc <<= 1;
		}
		ptr++;
	}
	return crc;
}

/*
 * Parse an encrypted key blob and validate its CRC.
 *
 * On success, iv and key point to the IV and encrypted
 * key payload stored in the original blob.
 */
static bool parse_encrypted_key_blob(const uint8_t *blob, size_t blob_size,
				     size_t key_size, const uint8_t **init_vec,
				     const uint8_t **encrypted_key)
{
	const struct {
		uint32_t unused[2];
		uint8_t init_vec[16];
	} *hdr = (const void *)blob;

	size_t blob_len = sizeof(*hdr) + key_size;

	if (blob_size >= (blob_len + sizeof(uint32_t))) {
		uint32_t blob_crc = 0;
		uint32_t calc_crc = calc_crc32(blob, blob_len);

		memcpy(&blob_crc, blob + blob_len, sizeof(blob_crc));

		if (blob_crc == TEE_U32_BSWAP(calc_crc)) {
			*init_vec = hdr->init_vec;
			*encrypted_key = blob + sizeof(*hdr);
			return true;
		}
	}

	return false;
}

/*
 * Import an encrypted key using the loaded KUK.
 */
static TEE_Result import_key_with_kuk(uint32_t types,
				      TEE_Param params[TEE_NUM_PARAMS],
				      rsip_key_type_t key_type)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

	const uint8_t *init_vec = NULL;
	const uint8_t *encrypted_key = NULL;

	size_t wrapped_buf_size = 0;
	rsip_wrapped_key_t *wrapped_key = NULL;
	const struct rsip_key_desc *key_desc = NULL;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_OUTPUT,
				     TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	res = get_key_desc(key_type, &key_desc);
	if (res != TEE_SUCCESS)
		return res;

	if (!params[0].memref.buffer ||
	    !IS_ALIGNED_WITH_UINT32(params[0].memref.buffer))
		return TEE_ERROR_BAD_PARAMETERS;
	if (!parse_encrypted_key_blob(
		    params[0].memref.buffer, params[0].memref.size,
		    key_desc->encrypted_size, &init_vec, &encrypted_key))
		return TEE_ERROR_BAD_PARAMETERS;

	wrapped_key = params[1].memref.buffer;
	wrapped_buf_size = params[1].memref.size;
	if (!wrapped_key || !IS_ALIGNED_WITH_UINT32(wrapped_key))
		return TEE_ERROR_BAD_PARAMETERS;

	err = R_RSIP_KeyImportWithKUK(&rsip_instance_ctrl, &wkuk.wrapped_key,
				      init_vec, key_type, encrypted_key,
				      &key1.wrapped_key);
	if (err != FSP_SUCCESS)
		return rsip_err_to_tee(err);

	params[1].memref.size = key_desc->wrapped_size;
	if (wrapped_buf_size < params[1].memref.size)
		return TEE_ERROR_SHORT_BUFFER;

	memcpy(wrapped_key, &key1, params[1].memref.size);

	return TEE_SUCCESS;
}

/*
 * Export RSA public key parameters from a wrapped key.
 *
 * param0: modulus (N)
 * param1: public exponent (E)
 */
static TEE_Result export_rsa_public_key(uint32_t types,
					TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

	size_t param_n_buf_size = 0;
	const uint8_t *param_n = NULL;

	size_t param_e_buf_size = 0;
	const uint8_t *param_e = NULL;

	size_t wrapped_buf_size = 0;
	rsip_wrapped_key_t *wrapped_key = NULL;
	const struct rsip_key_desc *key_desc = NULL;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_OUTPUT,
				     TEE_PARAM_TYPE_MEMREF_OUTPUT,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	wrapped_key = params[0].memref.buffer;
	wrapped_buf_size = params[0].memref.size;
	if (!wrapped_key || !IS_ALIGNED_WITH_UINT32(wrapped_key))
		return TEE_ERROR_BAD_PARAMETERS;
	if (wrapped_buf_size < sizeof(wrapped_key->type))
		return TEE_ERROR_BAD_PARAMETERS;

	res = get_key_desc(wrapped_key->type, &key_desc);
	if (res != TEE_SUCCESS)
		return res;
	if (wrapped_buf_size != key_desc->wrapped_size)
		return TEE_ERROR_BAD_PARAMETERS;

	param_n_buf_size = params[1].memref.size;
	if (!params[1].memref.buffer ||
	    !IS_ALIGNED_WITH_UINT32(params[1].memref.buffer))
		return TEE_ERROR_BAD_PARAMETERS;

	param_e_buf_size = params[2].memref.size;
	if (!params[2].memref.buffer ||
	    !IS_ALIGNED_WITH_UINT32(params[2].memref.buffer))
		return TEE_ERROR_BAD_PARAMETERS;

	err = R_RSIP_RSAPublicKeyExport(wrapped_key, &param_n, &param_e);
	if (err != FSP_SUCCESS)
		return rsip_err_to_tee(err);

	res = get_rsa_public_param_size(wrapped_key->type,
					&params[1].memref.size,
					&params[2].memref.size);
	if (res != TEE_SUCCESS)
		return res;

	if (param_n_buf_size < params[1].memref.size ||
	    param_e_buf_size < params[2].memref.size)
		return TEE_ERROR_SHORT_BUFFER;

	memcpy(params[1].memref.buffer, param_n, params[1].memref.size);
	memcpy(params[2].memref.buffer, param_e, params[2].memref.size);

	return TEE_SUCCESS;
}

/*
 * Export ECC public key parameters from a wrapped key.
 *
 * param0: public key Qx
 * param1: public key Qy
 */
static TEE_Result export_ecc_public_key(uint32_t types,
					TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

	size_t param_qx_buf_size = 0;
	const uint8_t *param_qx = NULL;

	size_t param_qy_buf_size = 0;
	const uint8_t *param_qy = NULL;

	size_t wrapped_buf_size = 0;
	rsip_wrapped_key_t *wrapped_key = NULL;
	const struct rsip_key_desc *key_desc = NULL;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_OUTPUT,
				     TEE_PARAM_TYPE_MEMREF_OUTPUT,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	wrapped_key = params[0].memref.buffer;
	wrapped_buf_size = params[0].memref.size;
	if (!wrapped_key || !IS_ALIGNED_WITH_UINT32(wrapped_key))
		return TEE_ERROR_BAD_PARAMETERS;
	if (wrapped_buf_size < sizeof(wrapped_key->type))
		return TEE_ERROR_BAD_PARAMETERS;

	res = get_key_desc(wrapped_key->type, &key_desc);
	if (res != TEE_SUCCESS)
		return res;
	if (wrapped_buf_size != key_desc->wrapped_size)
		return TEE_ERROR_BAD_PARAMETERS;

	param_qx_buf_size = params[1].memref.size;
	if (!params[1].memref.buffer ||
	    !IS_ALIGNED_WITH_UINT32(params[1].memref.buffer))
		return TEE_ERROR_BAD_PARAMETERS;

	param_qy_buf_size = params[2].memref.size;
	if (!params[2].memref.buffer ||
	    !IS_ALIGNED_WITH_UINT32(params[2].memref.buffer))
		return TEE_ERROR_BAD_PARAMETERS;

	err = R_RSIP_ECCPublicKeyExport(wrapped_key, &param_qx, &param_qy);
	if (err != FSP_SUCCESS)
		return rsip_err_to_tee(err);

	res = get_ecc_public_param_size(wrapped_key->type,
					&params[1].memref.size,
					&params[2].memref.size);
	if (res != TEE_SUCCESS)
		return res;

	if (param_qx_buf_size < params[1].memref.size ||
	    param_qy_buf_size < params[2].memref.size)
		return TEE_ERROR_SHORT_BUFFER;

	memcpy(params[1].memref.buffer, param_qx, params[1].memref.size);
	memcpy(params[2].memref.buffer, param_qy, params[2].memref.size);

	return TEE_SUCCESS;
}

/*
 * Fill the output buffer with random data generated by
 * the RSIP random number generator.
 */
static TEE_Result generate_random_number(uint32_t types,
					 TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

	uint8_t *rand = NULL;
	uint32_t rand_len = 0;
	uint32_t rand_buff[4] = { 0 };

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
				     TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	rand = params[0].memref.buffer;
	rand_len = (uint32_t)params[0].memref.size;
	if ((rand_len && !rand) || !IS_ALIGNED_WITH_UINT32(rand))
		return TEE_ERROR_BAD_PARAMETERS;

	for (size_t i = 0; i < rand_len; i += sizeof(rand_buff)) {
		const size_t chunk = MIN(rand_len - i, sizeof(rand_buff));

		err = R_RSIP_RandomNumberGenerate(&rsip_instance_ctrl,
						  (uint8_t *)rand_buff);
		if (err != FSP_SUCCESS)
			return rsip_err_to_tee(err);

		memcpy(rand + i, rand_buff, chunk);
	}

	return TEE_SUCCESS;
}

/*
 * PTA session entry point.
 */
static TEE_Result open_session(uint32_t nParamTypes __unused,
			       TEE_Param pParams[TEE_NUM_PARAMS] __unused,
			       void **ppSessionContext __unused)
{
	DMSG("open entry point for pseudo ta \"%s\"", PTA_NAME);

	return plat_crypto_get_key_update_key(
		wkuk.value, RSIP_BYTE_SIZE_WRAPPED_KEY_KEY_UPDATE_KEY);
}

/*
 * PTA session exit point.
 */
static void close_session(void *pSessionContext __unused)
{
	DMSG("close entry point for pseudo ta \"%s\"", PTA_NAME);
}

/*
 * Dispatch PTA commands to the corresponding RSIP handler.
 */
static TEE_Result invoke_command_gen_key(uint32_t cmd, uint32_t ptypes,
					 TEE_Param params[TEE_NUM_PARAMS])
{
	rsip_key_type_t type = RSIP_KEY_TYPE_INVALID;

	TEE_Result res = get_rsip_key_type(cmd, &type);
	if (res != TEE_SUCCESS)
		return res;

	switch (cmd) {
	case PTA_CMD_AES128_WrappedKeyGenerate:
	case PTA_CMD_AES256_WrappedKeyGenerate:
	case PTA_CMD_AES128_XTS_WrappedKeyGenerate:
	case PTA_CMD_AES256_XTS_WrappedKeyGenerate:
		return generate_wrapped_key(ptypes, params, type);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

static TEE_Result invoke_command_gen_keypair(uint32_t cmd, uint32_t ptypes,
					     TEE_Param params[TEE_NUM_PARAMS])
{
	rsip_key_pair_type_t type = RSIP_KEY_PAIR_TYPE_INVALID;

	TEE_Result res = get_rsip_keypair_type(cmd, &type);
	if (res != TEE_SUCCESS)
		return res;

	switch (cmd) {
	case PTA_CMD_RSA_1024_WrappedKeyPairGenerate:
	case PTA_CMD_RSA_2048_WrappedKeyPairGenerate:
	case PTA_CMD_RSA_3072_WrappedKeyPairGenerate:
	case PTA_CMD_RSA_4096_WrappedKeyPairGenerate:
	case PTA_CMD_ECC_secp192r1_WrappedKeyPairGenerate:
	case PTA_CMD_ECC_secp224r1_WrappedKeyPairGenerate:
	case PTA_CMD_ECC_secp256r1_WrappedKeyPairGenerate:
	case PTA_CMD_ECC_BrainpoolP256r1_WrappedKeyPairGenerate:
		return generate_wrapped_keypair(ptypes, params, type);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

static TEE_Result invoke_command_import_key(uint32_t cmd, uint32_t ptypes,
					    TEE_Param params[TEE_NUM_PARAMS])
{
	rsip_key_type_t type = RSIP_KEY_TYPE_INVALID;

	TEE_Result res = get_rsip_key_type(cmd, &type);
	if (res != TEE_SUCCESS)
		return res;

	switch (cmd) {
	case PTA_CMD_AES128_EncryptedKeyWrap:
	case PTA_CMD_AES256_EncryptedKeyWrap:
	case PTA_CMD_AES128_XTS_EncryptedKeyWrap:
	case PTA_CMD_AES256_XTS_EncryptedKeyWrap:
	case PTA_CMD_HMAC_SHA1_EncryptedKeyWrap:
	case PTA_CMD_HMAC_SHA224_EncryptedKeyWrap:
	case PTA_CMD_HMAC_SHA256_EncryptedKeyWrap:
	case PTA_CMD_RSA_1024_EncryptedPublicKeyWrap:
	case PTA_CMD_RSA_1024_EncryptedPrivateKeyWrap:
	case PTA_CMD_RSA_2048_EncryptedPublicKeyWrap:
	case PTA_CMD_RSA_2048_EncryptedPrivateKeyWrap:
	case PTA_CMD_RSA_3072_EncryptedPublicKeyWrap:
	case PTA_CMD_RSA_3072_EncryptedPrivateKeyWrap:
	case PTA_CMD_RSA_4096_EncryptedPublicKeyWrap:
	case PTA_CMD_RSA_4096_EncryptedPrivateKeyWrap:
	case PTA_CMD_ECC_secp192r1_EncryptedPublicKeyWrap:
	case PTA_CMD_ECC_secp192r1_EncryptedPrivateKeyWrap:
	case PTA_CMD_ECC_secp224r1_EncryptedPublicKeyWrap:
	case PTA_CMD_ECC_secp224r1_EncryptedPrivateKeyWrap:
	case PTA_CMD_ECC_secp256r1_EncryptedPublicKeyWrap:
	case PTA_CMD_ECC_secp256r1_EncryptedPrivateKeyWrap:
	case PTA_CMD_ECC_BrainpoolP256r1_EncryptedPublicKeyWrap:
	case PTA_CMD_ECC_BrainpoolP256r1_EncryptedPrivateKeyWrap:
		return import_key_with_kuk(ptypes, params, type);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

static TEE_Result invoke_command_export_key(uint32_t cmd, uint32_t ptypes,
					    TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd) {
	case PTA_CMD_RSA_Public_Key_Export:
		return export_rsa_public_key(ptypes, params);
	case PTA_CMD_ECC_Public_Key_Export:
		return export_ecc_public_key(ptypes, params);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

static TEE_Result invoke_command(void *session __unused, uint32_t cmd,
				 uint32_t ptypes,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	DMSG(PTA_NAME " command %#" PRIx32 " ptypes %#" PRIx32, cmd, ptypes);

	switch (PTA_CMD_GET_FEATURE(cmd)) {
	case PTA_FEATURE_KEY_GEN:
		return invoke_command_gen_key(cmd, ptypes, params);
	case PTA_FEATURE_KEYPAIR_GEN:
		return invoke_command_gen_keypair(cmd, ptypes, params);
	case PTA_FEATURE_KEY_IMPORT:
		return invoke_command_import_key(cmd, ptypes, params);
	case PTA_FEATURE_KEY_EXPORT:
		return invoke_command_export_key(cmd, ptypes, params);
	case PTA_FEATURE_RANDOM:
		return generate_random_number(ptypes, params);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

pseudo_ta_register(.uuid = PTA_RSIP_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .open_session_entry_point = open_session,
		   .close_session_entry_point = close_session,
		   .invoke_command_entry_point = invoke_command);
