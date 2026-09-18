// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2022-2026, Renesas Electronics Corporation
 */

#include <stdint.h>
#include <string.h>
#include <kernel/pseudo_ta.h>
#include <r_sce.h>
#include <pta_sce_rsa.h>

#include "pta_sce_cmd.h"
#include "pta_sce_util.h"

#define PTA_NAME "sce_rsa.pta"

struct sce_rsa_desc {
	size_t modulus_size;
};

struct sce_rsa_hash_desc {
	size_t hash_size;
	uint8_t rsa_hash;
};

static TEE_Result get_rsa_wrapped_key(TEE_Param *p,
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

	*wrapped_key = key;

	return TEE_SUCCESS;
}

static TEE_Result get_rsa_desc(sce_key_type_t key_type,
			       struct sce_rsa_desc *desc)
{
	switch (key_type) {
	case SCE_KEY_INDEX_TYPE_RSA1024_PUBLIC:
	case SCE_KEY_INDEX_TYPE_RSA1024_PRIVATE:
		desc->modulus_size = SCE_RSA_MOD_SIZE_1024;
		return TEE_SUCCESS;
	case SCE_KEY_INDEX_TYPE_RSA2048_PUBLIC:
	case SCE_KEY_INDEX_TYPE_RSA2048_PRIVATE:
		desc->modulus_size = SCE_RSA_MOD_SIZE_2048;
		return TEE_SUCCESS;
	case SCE_KEY_INDEX_TYPE_RSA4096_PUBLIC:
		desc->modulus_size = SCE_RSA_MOD_SIZE_4096;
		return TEE_SUCCESS;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

static TEE_Result get_rsa_hash_desc(enum sce_hash_type hash_type,
				    struct sce_rsa_hash_desc *desc)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	res = get_digest_size(hash_type, &desc->hash_size);
	if (res != TEE_SUCCESS)
		return res;

	switch (hash_type) {
	case SCE_HASH_TYPE_SHA256:
		desc->rsa_hash = HW_SCE_RSA_HASH_SHA256;
		return TEE_SUCCESS;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

static TEE_Result generate_hash(struct sce_rsa_hash_desc *hash_desc,
				uint8_t *msg, uint32_t msg_len, uint8_t *hash)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;
	sce_sha_md5_handle_t handle;
	uint32_t empty_msg[1] = { 0 };
	uint32_t hash_len = 0;

	if (hash_desc->rsa_hash != HW_SCE_RSA_HASH_SHA256)
		return TEE_ERROR_NOT_SUPPORTED;

	if (!msg_len)
		msg = (uint8_t *)empty_msg;

	err = R_SCE_SHA256_Init(&handle);
	if (err != FSP_SUCCESS)
		return sce_err_to_tee(err);

	err = R_SCE_SHA256_Update(&handle, msg, msg_len);
	if (err != FSP_SUCCESS) {
		R_SCE_SHA256_Final(&handle, hash, &hash_len);
		return sce_err_to_tee(err);
	}

	err = R_SCE_SHA256_Final(&handle, hash, &hash_len);
	if (err == FSP_SUCCESS && hash_len != hash_desc->hash_size)
		return TEE_ERROR_GENERIC;

	return sce_err_to_tee(err);
}

static TEE_Result sce_rsa1024_pkcs1_sign(sce_rsa_byte_data_t *hash,
					 sce_rsa_byte_data_t *sig,
					 struct sce_wrapped_key *wrapped_key,
					 uint8_t rsa_hash)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;
	sce_rsa1024_private_wrapped_key_t private_key;

	memcpy(&private_key, wrapped_key, sizeof(private_key));

	err = R_SCE_RSASSA_PKCS1024_SignatureGenerate(hash, sig, &private_key,
						      rsa_hash);
	return sce_err_to_tee(err);
}

static TEE_Result sce_rsa2048_pkcs1_sign(sce_rsa_byte_data_t *hash,
					 sce_rsa_byte_data_t *sig,
					 struct sce_wrapped_key *wrapped_key,
					 uint8_t rsa_hash)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;
	sce_rsa2048_private_wrapped_key_t private_key;

	memcpy(&private_key, wrapped_key, sizeof(private_key));

	err = R_SCE_RSASSA_PKCS2048_SignatureGenerate(hash, sig, &private_key,
						      rsa_hash);
	return sce_err_to_tee(err);
}

static TEE_Result sce_rsa1024_pkcs1_verify(sce_rsa_byte_data_t *hash,
					   sce_rsa_byte_data_t *sig,
					   struct sce_wrapped_key *wrapped_key,
					   uint8_t rsa_hash)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;
	sce_rsa1024_public_wrapped_key_t public_key;

	memcpy(&public_key, wrapped_key, sizeof(public_key));

	err = R_SCE_RSASSA_PKCS1024_SignatureVerify(sig, hash, &public_key,
						    rsa_hash);
	return sce_verify_err_to_tee(err, SCE_VERIFY_RSA);
}

static TEE_Result sce_rsa2048_pkcs1_verify(sce_rsa_byte_data_t *hash,
					   sce_rsa_byte_data_t *sig,
					   struct sce_wrapped_key *wrapped_key,
					   uint8_t rsa_hash)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;
	sce_rsa2048_public_wrapped_key_t public_key;

	memcpy(&public_key, wrapped_key, sizeof(public_key));

	err = R_SCE_RSASSA_PKCS2048_SignatureVerify(sig, hash, &public_key,
						    rsa_hash);
	return sce_verify_err_to_tee(err, SCE_VERIFY_RSA);
}

static TEE_Result sce_rsa4096_pkcs1_verify(sce_rsa_byte_data_t *hash,
					   sce_rsa_byte_data_t *sig,
					   struct sce_wrapped_key *wrapped_key,
					   uint8_t rsa_hash)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;
	sce_rsa4096_public_wrapped_key_t public_key;

	memcpy(&public_key, wrapped_key, sizeof(public_key));

	err = R_SCE_RSASSA_PKCS4096_SignatureVerify(sig, hash, &public_key,
						    rsa_hash);
	return sce_verify_err_to_tee(err, SCE_VERIFY_RSA);
}

static TEE_Result sce_rsa1024_pkcs1_encrypt(sce_rsa_byte_data_t *plain,
					    sce_rsa_byte_data_t *cipher,
					    struct sce_wrapped_key *wrapped_key)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;
	sce_rsa1024_public_wrapped_key_t public_key;

	memcpy(&public_key, wrapped_key, sizeof(public_key));

	err = R_SCE_RSAES_PKCS1024_Encrypt(plain, cipher, &public_key);

	return sce_err_to_tee(err);
}

static TEE_Result sce_rsa2048_pkcs1_encrypt(sce_rsa_byte_data_t *plain,
					    sce_rsa_byte_data_t *cipher,
					    struct sce_wrapped_key *wrapped_key)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;
	sce_rsa2048_public_wrapped_key_t public_key;

	memcpy(&public_key, wrapped_key, sizeof(public_key));

	err = R_SCE_RSAES_PKCS2048_Encrypt(plain, cipher, &public_key);

	return sce_err_to_tee(err);
}

static TEE_Result sce_rsa4096_pkcs1_encrypt(sce_rsa_byte_data_t *plain,
					    sce_rsa_byte_data_t *cipher,
					    struct sce_wrapped_key *wrapped_key)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;
	sce_rsa4096_public_wrapped_key_t public_key;

	memcpy(&public_key, wrapped_key, sizeof(public_key));

	err = R_SCE_RSAES_PKCS4096_Encrypt(plain, cipher, &public_key);

	return sce_err_to_tee(err);
}

static TEE_Result sce_rsa1024_pkcs1_decrypt(sce_rsa_byte_data_t *cipher,
					    sce_rsa_byte_data_t *plain,
					    struct sce_wrapped_key *wrapped_key)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;
	sce_rsa1024_private_wrapped_key_t private_key;

	memcpy(&private_key, wrapped_key, sizeof(private_key));

	err = R_SCE_RSAES_PKCS1024_Decrypt(cipher, plain, &private_key);

	return sce_err_to_tee(err);
}

static TEE_Result sce_rsa2048_pkcs1_decrypt(sce_rsa_byte_data_t *cipher,
					    sce_rsa_byte_data_t *plain,
					    struct sce_wrapped_key *wrapped_key)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;
	sce_rsa2048_private_wrapped_key_t private_key;

	memcpy(&private_key, wrapped_key, sizeof(private_key));

	err = R_SCE_RSAES_PKCS2048_Decrypt(cipher, plain, &private_key);

	return sce_err_to_tee(err);
}

static TEE_Result sce_rsa_pkcs1_sign(struct sce_rsa_desc *rsa_desc,
				     struct sce_rsa_hash_desc *hash_desc,
				     struct sce_wrapped_key *wrapped_key,
				     uint8_t *digest, uint8_t *signature)
{
	sce_rsa_byte_data_t hash = { 0 };
	sce_rsa_byte_data_t sig = { 0 };

	if (hash_desc->rsa_hash != HW_SCE_RSA_HASH_SHA256)
		return TEE_ERROR_NOT_IMPLEMENTED;

	hash.pdata = digest;
	hash.data_length = hash_desc->hash_size;
	hash.data_type = 1;

	sig.pdata = signature;
	sig.data_length = rsa_desc->modulus_size;
	sig.data_type = 0;

	switch (wrapped_key->type) {
	case SCE_KEY_INDEX_TYPE_RSA1024_PRIVATE:
		return sce_rsa1024_pkcs1_sign(&hash, &sig, wrapped_key,
					      hash_desc->rsa_hash);
	case SCE_KEY_INDEX_TYPE_RSA2048_PRIVATE:
		return sce_rsa2048_pkcs1_sign(&hash, &sig, wrapped_key,
					      hash_desc->rsa_hash);
	default:
		return TEE_ERROR_GENERIC;
	}
}

static TEE_Result sce_rsa_pkcs1_verify(struct sce_rsa_desc *rsa_desc,
				       struct sce_rsa_hash_desc *hash_desc,
				       struct sce_wrapped_key *wrapped_key,
				       uint8_t *digest, uint8_t *signature)
{
	sce_rsa_byte_data_t hash = { 0 };
	sce_rsa_byte_data_t sig = { 0 };

	if (hash_desc->rsa_hash != HW_SCE_RSA_HASH_SHA256)
		return TEE_ERROR_NOT_IMPLEMENTED;

	hash.pdata = digest;
	hash.data_length = hash_desc->hash_size;
	hash.data_type = 1;

	sig.pdata = signature;
	sig.data_length = rsa_desc->modulus_size;
	sig.data_type = 0;

	switch (wrapped_key->type) {
	case SCE_KEY_INDEX_TYPE_RSA1024_PUBLIC:
		return sce_rsa1024_pkcs1_verify(&hash, &sig, wrapped_key,
						hash_desc->rsa_hash);
	case SCE_KEY_INDEX_TYPE_RSA2048_PUBLIC:
		return sce_rsa2048_pkcs1_verify(&hash, &sig, wrapped_key,
						hash_desc->rsa_hash);
	case SCE_KEY_INDEX_TYPE_RSA4096_PUBLIC:
		return sce_rsa4096_pkcs1_verify(&hash, &sig, wrapped_key,
						hash_desc->rsa_hash);
	default:
		return TEE_ERROR_GENERIC;
	}
}

static TEE_Result sce_rsa_pkcs1_encrypt(struct sce_rsa_desc *rsa_desc,
					struct sce_wrapped_key *wrapped_key,
					uint8_t *plain, uint32_t plain_length,
					uint8_t *cipher,
					uint32_t *cipher_length)
{
	TEE_Result res = TEE_SUCCESS;
	sce_rsa_byte_data_t plain_data = { 0 };
	sce_rsa_byte_data_t cipher_data = { 0 };

	plain_data.pdata = plain;
	plain_data.data_length = plain_length;

	cipher_data.pdata = cipher;
	cipher_data.data_length = rsa_desc->modulus_size;

	switch (wrapped_key->type) {
	case SCE_KEY_INDEX_TYPE_RSA1024_PUBLIC:
		res = sce_rsa1024_pkcs1_encrypt(&plain_data, &cipher_data,
						wrapped_key);
		break;
	case SCE_KEY_INDEX_TYPE_RSA2048_PUBLIC:
		res = sce_rsa2048_pkcs1_encrypt(&plain_data, &cipher_data,
						wrapped_key);
		break;
	case SCE_KEY_INDEX_TYPE_RSA4096_PUBLIC:
		res = sce_rsa4096_pkcs1_encrypt(&plain_data, &cipher_data,
						wrapped_key);
		break;
	default:
		return TEE_ERROR_GENERIC;
	}

	if (res == TEE_SUCCESS)
		*cipher_length = cipher_data.data_length;
	return res;
}

static TEE_Result sce_rsa_pkcs1_decrypt(struct sce_rsa_desc *rsa_desc,
					struct sce_wrapped_key *wrapped_key,
					uint8_t *cipher, uint32_t cipher_length,
					uint8_t *plain, uint32_t *plain_length)
{
	TEE_Result res = TEE_SUCCESS;
	sce_rsa_byte_data_t plain_data = { 0 };
	sce_rsa_byte_data_t cipher_data = { 0 };

	cipher_data.pdata = cipher;
	cipher_data.data_length = cipher_length;

	plain_data.pdata = plain;
	plain_data.data_length = rsa_desc->modulus_size;

	switch (wrapped_key->type) {
	case SCE_KEY_INDEX_TYPE_RSA1024_PRIVATE:
		res = sce_rsa1024_pkcs1_decrypt(&cipher_data, &plain_data,
						wrapped_key);
		break;
	case SCE_KEY_INDEX_TYPE_RSA2048_PRIVATE:
		res = sce_rsa2048_pkcs1_decrypt(&cipher_data, &plain_data,
						wrapped_key);
		break;
	default:
		return TEE_ERROR_GENERIC;
	}

	if (res == TEE_SUCCESS)
		*plain_length = plain_data.data_length;
	return res;
}

static TEE_Result rsa_pkcs1_sign(uint32_t types,
				 TEE_Param params[TEE_NUM_PARAMS],
				 enum sce_hash_type hash_type)
{
	TEE_Result res = TEE_SUCCESS;

	struct sce_rsa_desc rsa_desc = { 0 };
	struct sce_rsa_hash_desc hash_desc = { 0 };

	uint8_t *msg = NULL;
	uint32_t msg_len = 0;
	uint8_t *sig = NULL;
	uint32_t sig_max = 0;
	uint32_t digest[SCE_DIGEST_SIZE_MAX / sizeof(uint32_t)] = { 0 };

	struct sce_wrapped_key *wrapped_key = NULL;

	uint32_t exp_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_MEMREF_OUTPUT,
					     TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_NONE);
	if (types != exp_types)
		return TEE_ERROR_BAD_PARAMETERS;

	res = get_rsa_wrapped_key(&params[2], &wrapped_key);
	if (res != TEE_SUCCESS)
		return res;

	res = get_rsa_desc(wrapped_key->type, &rsa_desc);
	if (res != TEE_SUCCESS)
		return res;

	res = get_rsa_hash_desc(hash_type, &hash_desc);
	if (res != TEE_SUCCESS)
		return res;

	msg = params[0].memref.buffer;
	msg_len = (uint32_t)params[0].memref.size;
	if (msg_len && (!msg || !IS_ALIGNED_WITH_UINT32(msg)))
		return TEE_ERROR_BAD_PARAMETERS;

	sig = params[1].memref.buffer;
	sig_max = (uint32_t)params[1].memref.size;
	params[1].memref.size = rsa_desc.modulus_size;
	if (!sig || !IS_ALIGNED_WITH_UINT32(sig))
		return TEE_ERROR_BAD_PARAMETERS;
	if (sig_max < params[1].memref.size)
		return TEE_ERROR_SHORT_BUFFER;

	res = generate_hash(&hash_desc, msg, msg_len, (uint8_t *)digest);
	if (res != TEE_SUCCESS)
		return res;

	return sce_rsa_pkcs1_sign(&rsa_desc, &hash_desc, wrapped_key,
				  (uint8_t *)digest, sig);
}

static TEE_Result rsa_pkcs1_verify(uint32_t types,
				   TEE_Param params[TEE_NUM_PARAMS],
				   enum sce_hash_type hash_type)
{
	TEE_Result res = TEE_SUCCESS;

	struct sce_rsa_desc rsa_desc = { 0 };
	struct sce_rsa_hash_desc hash_desc = { 0 };

	uint8_t *msg = NULL;
	uint32_t msg_len = 0;
	uint8_t *sig = NULL;
	uint32_t sig_len = 0;
	uint32_t digest[SCE_DIGEST_SIZE_MAX / sizeof(uint32_t)] = { 0 };

	struct sce_wrapped_key *wrapped_key = NULL;

	uint32_t exp_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_NONE);
	if (types != exp_types)
		return TEE_ERROR_BAD_PARAMETERS;

	res = get_rsa_wrapped_key(&params[2], &wrapped_key);
	if (res != TEE_SUCCESS)
		return res;

	res = get_rsa_desc(wrapped_key->type, &rsa_desc);
	if (res != TEE_SUCCESS)
		return res;

	res = get_rsa_hash_desc(hash_type, &hash_desc);
	if (res != TEE_SUCCESS)
		return res;

	msg = params[0].memref.buffer;
	msg_len = (uint32_t)params[0].memref.size;
	if (msg_len && (!msg || !IS_ALIGNED_WITH_UINT32(msg)))
		return TEE_ERROR_BAD_PARAMETERS;

	sig = params[1].memref.buffer;
	sig_len = (uint32_t)params[1].memref.size;
	if (!sig || !IS_ALIGNED_WITH_UINT32(sig))
		return TEE_ERROR_BAD_PARAMETERS;
	if (sig_len != rsa_desc.modulus_size)
		return TEE_ERROR_BAD_PARAMETERS;

	res = generate_hash(&hash_desc, msg, msg_len, (uint8_t *)digest);
	if (res != TEE_SUCCESS)
		return res;

	return sce_rsa_pkcs1_verify(&rsa_desc, &hash_desc, wrapped_key,
				    (uint8_t *)digest, sig);
}

static TEE_Result rsa_pkcs1_encrypt(uint32_t types,
				    TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;

	struct sce_rsa_desc rsa_desc = { 0 };

	uint8_t *plain = NULL;
	uint32_t plain_len = 0;
	uint8_t *cipher = NULL;
	uint32_t cipher_len = 0;
	uint32_t cipher_buff[SCE_RSA_MOD_SIZE_MAX / sizeof(uint32_t)] = { 0 };
	uint32_t cipher_buff_len = (uint32_t)sizeof(cipher_buff);

	struct sce_wrapped_key *wrapped_key = NULL;

	uint32_t exp_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_MEMREF_OUTPUT,
					     TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_NONE);
	if (types != exp_types)
		return TEE_ERROR_BAD_PARAMETERS;

	res = get_rsa_wrapped_key(&params[2], &wrapped_key);
	if (res != TEE_SUCCESS)
		return res;

	res = get_rsa_desc(wrapped_key->type, &rsa_desc);
	if (res != TEE_SUCCESS)
		return res;

	plain = params[0].memref.buffer;
	plain_len = (uint32_t)params[0].memref.size;
	if (!plain || !IS_ALIGNED_WITH_UINT32(plain))
		return TEE_ERROR_BAD_PARAMETERS;
	if (plain_len > (rsa_desc.modulus_size - 11))
		return TEE_ERROR_BAD_PARAMETERS;

	res = sce_rsa_pkcs1_encrypt(&rsa_desc, wrapped_key, plain, plain_len,
				    (uint8_t *)cipher_buff, &cipher_buff_len);
	if (res != TEE_SUCCESS)
		return res;

	cipher = params[1].memref.buffer;
	cipher_len = params[1].memref.size;
	params[1].memref.size = cipher_buff_len;
	if (!cipher || !IS_ALIGNED_WITH_UINT32(cipher))
		return TEE_ERROR_BAD_PARAMETERS;
	if (cipher_len < params[1].memref.size)
		return TEE_ERROR_SHORT_BUFFER;

	memcpy(cipher, cipher_buff, params[1].memref.size);

	return TEE_SUCCESS;
}

static TEE_Result rsa_pkcs1_decrypt(uint32_t types,
				    TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;

	struct sce_rsa_desc rsa_desc = { 0 };

	uint8_t *cipher = NULL;
	uint32_t cipher_len = 0;
	uint8_t *plain = NULL;
	uint32_t plain_len = 0;
	uint32_t plain_buff[SCE_RSA_MOD_SIZE_MAX / sizeof(uint32_t)] = { 0 };
	uint32_t plain_buff_len = (uint32_t)sizeof(plain_buff);

	struct sce_wrapped_key *wrapped_key = NULL;

	uint32_t exp_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_MEMREF_OUTPUT,
					     TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_NONE);
	if (types != exp_types)
		return TEE_ERROR_BAD_PARAMETERS;

	res = get_rsa_wrapped_key(&params[2], &wrapped_key);
	if (res != TEE_SUCCESS)
		return res;

	res = get_rsa_desc(wrapped_key->type, &rsa_desc);
	if (res != TEE_SUCCESS)
		return res;

	cipher = params[0].memref.buffer;
	cipher_len = (uint32_t)params[0].memref.size;
	if (!cipher || !IS_ALIGNED_WITH_UINT32(cipher))
		return TEE_ERROR_BAD_PARAMETERS;
	if (cipher_len > rsa_desc.modulus_size)
		return TEE_ERROR_BAD_PARAMETERS;

	res = sce_rsa_pkcs1_decrypt(&rsa_desc, wrapped_key, cipher, cipher_len,
				    (uint8_t *)plain_buff, &plain_buff_len);
	if (res != TEE_SUCCESS)
		return res;

	plain = params[1].memref.buffer;
	plain_len = (uint32_t)params[1].memref.size;
	params[1].memref.size = plain_buff_len;
	if (!plain || !IS_ALIGNED_WITH_UINT32(plain))
		return TEE_ERROR_BAD_PARAMETERS;
	if (plain_len < params[1].memref.size)
		return TEE_ERROR_SHORT_BUFFER;

	memcpy(plain, plain_buff, params[1].memref.size);

	return TEE_SUCCESS;
}

static TEE_Result invoke_command_rsassa_pkcs1(uint32_t cmd, uint32_t ptypes,
					      TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd) {
	case PTA_CMD_RSASSA_PKCS1_SHA256_Sign:
		return rsa_pkcs1_sign(ptypes, params, SCE_HASH_TYPE_SHA256);
	case PTA_CMD_RSASSA_PKCS1_SHA256_Verify:
		return rsa_pkcs1_verify(ptypes, params, SCE_HASH_TYPE_SHA256);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

static TEE_Result invoke_command_rsaes_pkcs1(uint32_t cmd, uint32_t ptypes,
					     TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd) {
	case PTA_CMD_RSAES_PKCS1_Encrypt:
		return rsa_pkcs1_encrypt(ptypes, params);
	case PTA_CMD_RSAES_PKCS1_Decrypt:
		return rsa_pkcs1_decrypt(ptypes, params);
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
	case PTA_RSA_VARIANT_PKCS1:
		switch (PTA_CMD_GET_FEATURE(cmd)) {
		case PTA_FEATURE_SIGN:
			return invoke_command_rsassa_pkcs1(cmd, ptypes, params);
		case PTA_FEATURE_CIPHER:
			return invoke_command_rsaes_pkcs1(cmd, ptypes, params);
		default:
			return TEE_ERROR_NOT_SUPPORTED;
		}
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

pseudo_ta_register(.uuid = PTA_SCE_RSA_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invoke_command);
