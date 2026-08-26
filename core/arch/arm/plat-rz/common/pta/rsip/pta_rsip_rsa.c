// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2024, Renesas Electronics Corporation
 */

#include <inttypes.h>
#include <kernel/pseudo_ta.h>
#include <r_rsip.h>
#include <string.h>
#include <trace.h>
#include <util.h>
#include <pta_rsip_rsa.h>

#include "pta_rsip_cmd.h"
#include "pta_rsip_util.h"

#define PTA_NAME "rsip_rsa.pta"

struct rsip_rsa_desc {
	size_t modulus_size;
};

struct rsip_rsa_hash_desc {
	size_t hash_size;
	int32_t salt_len;
	rsip_mgf_type_t mgf_type;
};

static TEE_Result get_rsa_wrapped_key(TEE_Param *p,
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

	*wrapped_key = key;

	return TEE_SUCCESS;
}

static TEE_Result get_rsa_desc(rsip_key_type_t key_type,
			       struct rsip_rsa_desc *desc)
{
	switch (key_type) {
	case RSIP_KEY_TYPE_RSA_1024_PUBLIC_ENHANCED:
	case RSIP_KEY_TYPE_RSA_1024_PRIVATE_ENHANCED:
		desc->modulus_size = RSIP_RSA_MOD_SIZE_1024;
		return TEE_SUCCESS;
	case RSIP_KEY_TYPE_RSA_2048_PUBLIC_ENHANCED:
	case RSIP_KEY_TYPE_RSA_2048_PRIVATE_ENHANCED:
		desc->modulus_size = RSIP_RSA_MOD_SIZE_2048;
		return TEE_SUCCESS;
	case RSIP_KEY_TYPE_RSA_3072_PUBLIC:
	case RSIP_KEY_TYPE_RSA_3072_PRIVATE:
		desc->modulus_size = RSIP_RSA_MOD_SIZE_3072;
		return TEE_SUCCESS;
	case RSIP_KEY_TYPE_RSA_4096_PUBLIC:
	case RSIP_KEY_TYPE_RSA_4096_PRIVATE:
		desc->modulus_size = RSIP_RSA_MOD_SIZE_4096;
		return TEE_SUCCESS;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

static TEE_Result get_rsa_hash_desc(rsip_hash_type_t hash_type,
				    struct rsip_rsa_hash_desc *desc)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	res = get_digest_size(hash_type, &desc->hash_size);
	if (res != TEE_SUCCESS)
		return res;

	desc->salt_len = RSIP_RSA_SALT_LENGTH_AUTO;

	switch (hash_type) {
	case RSIP_HASH_TYPE_SHA1:
		desc->mgf_type = RSIP_MGF_TYPE_MGF1_SHA1;
		return TEE_SUCCESS;
	case RSIP_HASH_TYPE_SHA224:
		desc->mgf_type = RSIP_MGF_TYPE_MGF1_SHA224;
		return TEE_SUCCESS;
	case RSIP_HASH_TYPE_SHA256:
		desc->mgf_type = RSIP_MGF_TYPE_MGF1_SHA256;
		return TEE_SUCCESS;
	case RSIP_HASH_TYPE_SHA384:
		desc->mgf_type = RSIP_MGF_TYPE_MGF1_SHA384;
		return TEE_SUCCESS;
	case RSIP_HASH_TYPE_SHA512:
		desc->mgf_type = RSIP_MGF_TYPE_MGF1_SHA512;
		return TEE_SUCCESS;
	case RSIP_HASH_TYPE_SHA512_224:
		desc->mgf_type = RSIP_MGF_TYPE_MGF1_SHA512_224;
		return TEE_SUCCESS;
	case RSIP_HASH_TYPE_SHA512_256:
		desc->mgf_type = RSIP_MGF_TYPE_MGF1_SHA512_256;
		return TEE_SUCCESS;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

static TEE_Result generate_hash(rsip_hash_type_t hash_type, const uint8_t *msg,
				uint32_t msg_len, uint8_t *digest)
{
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

	uint32_t empty_msg[1] = { 0 };

	if (!msg_len)
		msg = (uint8_t *)empty_msg;

	err = R_RSIP_SHA_Compute(&rsip_instance_ctrl, hash_type, msg, msg_len,
				 digest);
	if (err != FSP_SUCCESS)
		return rsip_err_to_tee(err);

	return TEE_SUCCESS;
}

static TEE_Result rsa_pkcs1_sign(uint32_t types,
				 TEE_Param params[TEE_NUM_PARAMS],
				 rsip_hash_type_t hash_type)
{
	TEE_Result res = TEE_SUCCESS;
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

	struct rsip_rsa_desc rsa_desc = { 0 };

	uint8_t *msg = NULL;
	uint32_t msg_len = 0;
	uint8_t *sig = NULL;
	uint32_t sig_max = 0;
	uint32_t digest[RSIP_DIGEST_SIZE_MAX / sizeof(uint32_t)] = { 0 };

	const rsip_wrapped_key_t *wrapped_key = NULL;

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

	res = generate_hash(hash_type, msg, msg_len, (uint8_t *)digest);
	if (res != TEE_SUCCESS)
		return res;

	err = R_RSIP_RSASSA_PKCS1_V1_5_Sign(&rsip_instance_ctrl, wrapped_key,
					    hash_type, (uint8_t *)digest, sig);
	if (err != FSP_SUCCESS)
		return rsip_err_to_tee(err);

	return TEE_SUCCESS;
}

static TEE_Result rsa_pkcs1_verify(uint32_t types,
				   TEE_Param params[TEE_NUM_PARAMS],
				   rsip_hash_type_t hash_type)
{
	TEE_Result res = TEE_SUCCESS;
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

	struct rsip_rsa_desc rsa_desc = { 0 };

	uint8_t *msg = NULL;
	uint32_t msg_len = 0;
	uint8_t *sig = NULL;
	uint32_t sig_len = 0;
	uint32_t digest[RSIP_DIGEST_SIZE_MAX / sizeof(uint32_t)] = { 0 };

	const rsip_wrapped_key_t *wrapped_key = NULL;

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

	res = generate_hash(hash_type, msg, msg_len, (uint8_t *)digest);
	if (res != TEE_SUCCESS)
		return res;

	err = R_RSIP_RSASSA_PKCS1_V1_5_Verify(&rsip_instance_ctrl, wrapped_key,
					      hash_type, (uint8_t *)digest,
					      sig);
	if (err != FSP_SUCCESS)
		return rsip_verify_err_to_tee(err, RSIP_VERIFY_RSA);

	return TEE_SUCCESS;
}

static TEE_Result rsa_pss_sign(uint32_t types, TEE_Param params[TEE_NUM_PARAMS],
			       rsip_hash_type_t hash_type)
{
	TEE_Result res = TEE_SUCCESS;
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

	struct rsip_rsa_desc rsa_desc = { 0 };
	struct rsip_rsa_hash_desc hash_desc = { 0 };

	uint8_t *msg = NULL;
	uint32_t msg_len = 0;
	uint8_t *sig = NULL;
	uint32_t sig_max = 0;
	uint32_t digest[RSIP_DIGEST_SIZE_MAX / sizeof(uint32_t)] = { 0 };

	const rsip_wrapped_key_t *wrapped_key = NULL;

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

	res = generate_hash(hash_type, msg, msg_len, (uint8_t *)digest);
	if (res != TEE_SUCCESS)
		return res;

	err = R_RSIP_RSASSA_PSS_Sign(&rsip_instance_ctrl, wrapped_key,
				     hash_type, hash_desc.mgf_type,
				     hash_desc.salt_len, (uint8_t *)digest,
				     sig);
	if (err != FSP_SUCCESS)
		return rsip_err_to_tee(err);

	return TEE_SUCCESS;
}

static TEE_Result rsa_pss_verify(uint32_t types,
				 TEE_Param params[TEE_NUM_PARAMS],
				 rsip_hash_type_t hash_type)
{
	TEE_Result res = TEE_SUCCESS;
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

	struct rsip_rsa_desc rsa_desc = { 0 };
	struct rsip_rsa_hash_desc hash_desc = { 0 };

	uint8_t *msg = NULL;
	uint32_t msg_len = 0;
	uint8_t *sig = NULL;
	uint32_t sig_len = 0;
	uint32_t digest[RSIP_DIGEST_SIZE_MAX / sizeof(uint32_t)] = { 0 };

	const rsip_wrapped_key_t *wrapped_key = NULL;

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

	res = generate_hash(hash_type, msg, msg_len, (uint8_t *)digest);
	if (res != TEE_SUCCESS)
		return res;

	err = R_RSIP_RSASSA_PSS_Verify(&rsip_instance_ctrl, wrapped_key,
				       hash_type, hash_desc.mgf_type,
				       hash_desc.salt_len, (uint8_t *)digest,
				       sig);
	if (err != FSP_SUCCESS)
		return rsip_verify_err_to_tee(err, RSIP_VERIFY_RSA);

	return TEE_SUCCESS;
}

static TEE_Result rsa_pkcs1_encrypt(uint32_t types,
				    TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

	struct rsip_rsa_desc rsa_desc = { 0 };

	uint8_t *plain = NULL;
	uint32_t plain_len = 0;
	uint8_t *cipher = NULL;
	uint32_t cipher_max = 0;

	const rsip_wrapped_key_t *wrapped_key = NULL;

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

	cipher = params[1].memref.buffer;
	cipher_max = (uint32_t)params[1].memref.size;
	params[1].memref.size = rsa_desc.modulus_size;
	if (!cipher || !IS_ALIGNED_WITH_UINT32(cipher))
		return TEE_ERROR_BAD_PARAMETERS;
	if (cipher_max < params[1].memref.size)
		return TEE_ERROR_SHORT_BUFFER;

	err = R_RSIP_RSAES_PKCS1_V1_5_Encrypt(&rsip_instance_ctrl, wrapped_key,
					      plain, plain_len, cipher);
	if (err != FSP_SUCCESS)
		return rsip_err_to_tee(err);

	return TEE_SUCCESS;
}

static TEE_Result rsa_pkcs1_decrypt(uint32_t types,
				    TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

	struct rsip_rsa_desc rsa_desc = { 0 };

	uint8_t *cipher = NULL;
	uint32_t cipher_len = 0;
	uint8_t *plain = NULL;
	uint32_t plain_max = 0;
	uint32_t plain_buff[RSIP_RSA_MOD_SIZE_MAX / sizeof(uint32_t)] = { 0 };
	uint32_t plain_len = 0;

	const rsip_wrapped_key_t *wrapped_key = NULL;

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
	if (cipher_len != rsa_desc.modulus_size)
		return TEE_ERROR_BAD_PARAMETERS;

	plain = params[1].memref.buffer;
	if (!plain || !IS_ALIGNED_WITH_UINT32(plain))
		return TEE_ERROR_BAD_PARAMETERS;

	err = R_RSIP_RSAES_PKCS1_V1_5_Decrypt(&rsip_instance_ctrl, wrapped_key,
					      cipher, (uint8_t *)plain_buff,
					      &plain_len,
					      (uint32_t)sizeof(plain_buff));
	if (err != FSP_SUCCESS)
		return rsip_err_to_tee(err);

	plain_max = (uint32_t)params[1].memref.size;
	params[1].memref.size = (size_t)plain_len;
	if (plain_max < params[1].memref.size)
		return TEE_ERROR_SHORT_BUFFER;

	memcpy(plain, plain_buff, plain_len);

	return TEE_SUCCESS;
}

static TEE_Result rsa_oaep_encrypt(uint32_t types,
				   TEE_Param params[TEE_NUM_PARAMS],
				   rsip_hash_type_t hash_type)
{
	TEE_Result res = TEE_SUCCESS;
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

	struct rsip_rsa_desc rsa_desc = { 0 };
	struct rsip_rsa_hash_desc hash_desc = { 0 };

	uint8_t *plain = NULL;
	uint32_t plain_len = 0;
	uint8_t *cipher = NULL;
	uint32_t cipher_max = 0;
	uint8_t *label = NULL;
	uint32_t label_len = 0;

	const rsip_wrapped_key_t *wrapped_key = NULL;

	uint32_t exp_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_MEMREF_OUTPUT,
					     TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_MEMREF_INPUT);
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

	plain = params[0].memref.buffer;
	plain_len = (uint32_t)params[0].memref.size;
	if (!plain || !IS_ALIGNED_WITH_UINT32(plain))
		return TEE_ERROR_BAD_PARAMETERS;
	if (plain_len > (rsa_desc.modulus_size - (2 * hash_desc.hash_size + 2)))
		return TEE_ERROR_BAD_PARAMETERS;

	cipher = params[1].memref.buffer;
	cipher_max = (uint32_t)params[1].memref.size;
	params[1].memref.size = rsa_desc.modulus_size;
	if (!cipher || !IS_ALIGNED_WITH_UINT32(cipher))
		return TEE_ERROR_BAD_PARAMETERS;
	if (cipher_max < rsa_desc.modulus_size)
		return TEE_ERROR_SHORT_BUFFER;

	label = params[3].memref.buffer;
	label_len = (uint32_t)params[3].memref.size;
	if (label_len && (!label || !IS_ALIGNED_WITH_UINT32(label)))
		return TEE_ERROR_BAD_PARAMETERS;

	err = R_RSIP_RSAES_OAEP_Encrypt(&rsip_instance_ctrl, wrapped_key,
					hash_type, hash_desc.mgf_type, label,
					label_len, plain, plain_len, cipher);
	if (err != FSP_SUCCESS)
		return rsip_err_to_tee(err);

	return TEE_SUCCESS;
}

static TEE_Result rsa_oaep_decrypt(uint32_t types,
				   TEE_Param params[TEE_NUM_PARAMS],
				   rsip_hash_type_t hash_type)
{
	TEE_Result res = TEE_SUCCESS;
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

	struct rsip_rsa_desc rsa_desc = { 0 };
	struct rsip_rsa_hash_desc hash_desc = { 0 };

	uint8_t *cipher = NULL;
	uint32_t cipher_len = 0;
	uint8_t *plain = NULL;
	uint32_t plain_max = 0;
	uint8_t *label = NULL;
	uint32_t label_len = 0;
	uint32_t plain_buff[RSIP_RSA_MOD_SIZE_MAX / sizeof(uint32_t)] = { 0 };
	uint32_t plain_len = 0;

	const rsip_wrapped_key_t *wrapped_key = NULL;

	uint32_t exp_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_MEMREF_OUTPUT,
					     TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_MEMREF_INPUT);
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

	cipher = params[0].memref.buffer;
	cipher_len = (uint32_t)params[0].memref.size;
	if (!cipher || !IS_ALIGNED_WITH_UINT32(cipher))
		return TEE_ERROR_BAD_PARAMETERS;
	if (cipher_len != rsa_desc.modulus_size)
		return TEE_ERROR_BAD_PARAMETERS;

	plain = params[1].memref.buffer;
	if (!plain || !IS_ALIGNED_WITH_UINT32(plain))
		return TEE_ERROR_BAD_PARAMETERS;

	label = params[3].memref.buffer;
	label_len = (uint32_t)params[3].memref.size;
	if (label_len && (!label || !IS_ALIGNED_WITH_UINT32(label)))
		return TEE_ERROR_BAD_PARAMETERS;

	err = R_RSIP_RSAES_OAEP_Decrypt(&rsip_instance_ctrl, wrapped_key,
					hash_type, hash_desc.mgf_type, label,
					label_len, cipher,
					(uint8_t *)plain_buff, &plain_len,
					(uint32_t)sizeof(plain_buff));
	if (err != FSP_SUCCESS)
		return rsip_err_to_tee(err);

	plain_max = (uint32_t)params[1].memref.size;
	params[1].memref.size = (size_t)plain_len;
	if (plain_max < params[1].memref.size)
		return TEE_ERROR_SHORT_BUFFER;

	memcpy(plain, plain_buff, plain_len);

	return TEE_SUCCESS;
}

static TEE_Result rsa_raw_encrypt(uint32_t types,
				  TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

	struct rsip_rsa_desc rsa_desc = { 0 };

	uint8_t *plain = NULL;
	uint32_t plain_len = 0;
	uint32_t plain_buff[RSIP_RSA_MOD_SIZE_MAX / sizeof(uint32_t)] = { 0 };
	uint32_t plain_lpad = 0;
	uint8_t *cipher = NULL;
	uint32_t cipher_max = 0;

	const rsip_wrapped_key_t *wrapped_key = NULL;

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
	if (!plain_len || plain_len > rsa_desc.modulus_size)
		return TEE_ERROR_BAD_PARAMETERS;

	cipher = params[1].memref.buffer;
	cipher_max = (uint32_t)params[1].memref.size;
	params[1].memref.size = rsa_desc.modulus_size;
	if (!cipher || !IS_ALIGNED_WITH_UINT32(cipher))
		return TEE_ERROR_BAD_PARAMETERS;
	if (cipher_max < params[1].memref.size)
		return TEE_ERROR_SHORT_BUFFER;

	plain_lpad = (uint32_t)rsa_desc.modulus_size - plain_len;
	memcpy((uint8_t *)plain_buff + plain_lpad, plain, plain_len);

	err = R_RSIP_RSA_Encrypt(&rsip_instance_ctrl, wrapped_key,
				 (uint8_t *)plain_buff, cipher);
	if (err != FSP_SUCCESS)
		return rsip_err_to_tee(err);

	return TEE_SUCCESS;
}

static TEE_Result rsa_raw_decrypt(uint32_t types,
				  TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

	struct rsip_rsa_desc rsa_desc = { 0 };

	uint8_t *cipher = NULL;
	uint32_t cipher_len = 0;
	uint8_t *plain = NULL;
	uint32_t plain_max = 0;

	const rsip_wrapped_key_t *wrapped_key = NULL;

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
	if (cipher_len != rsa_desc.modulus_size)
		return TEE_ERROR_BAD_PARAMETERS;

	plain = params[1].memref.buffer;
	plain_max = (uint32_t)params[1].memref.size;
	params[1].memref.size = rsa_desc.modulus_size;
	if (!plain || !IS_ALIGNED_WITH_UINT32(plain))
		return TEE_ERROR_BAD_PARAMETERS;
	if (plain_max < params[1].memref.size)
		return TEE_ERROR_SHORT_BUFFER;

	err = R_RSIP_RSA_Decrypt(&rsip_instance_ctrl, wrapped_key, cipher,
				 plain);
	if (err != FSP_SUCCESS)
		return rsip_err_to_tee(err);

	return TEE_SUCCESS;
}

static TEE_Result invoke_command_rsassa_pkcs1(uint32_t cmd, uint32_t ptypes,
					      TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd) {
	case PTA_CMD_RSASSA_PKCS1_SHA1_Sign:
		return rsa_pkcs1_sign(ptypes, params, RSIP_HASH_TYPE_SHA1);
	case PTA_CMD_RSASSA_PKCS1_SHA224_Sign:
		return rsa_pkcs1_sign(ptypes, params, RSIP_HASH_TYPE_SHA224);
	case PTA_CMD_RSASSA_PKCS1_SHA256_Sign:
		return rsa_pkcs1_sign(ptypes, params, RSIP_HASH_TYPE_SHA256);
	case PTA_CMD_RSASSA_PKCS1_SHA384_Sign:
		return rsa_pkcs1_sign(ptypes, params, RSIP_HASH_TYPE_SHA384);
	case PTA_CMD_RSASSA_PKCS1_SHA512_Sign:
		return rsa_pkcs1_sign(ptypes, params, RSIP_HASH_TYPE_SHA512);
	case PTA_CMD_RSASSA_PKCS1_SHA1_Verify:
		return rsa_pkcs1_verify(ptypes, params, RSIP_HASH_TYPE_SHA1);
	case PTA_CMD_RSASSA_PKCS1_SHA224_Verify:
		return rsa_pkcs1_verify(ptypes, params, RSIP_HASH_TYPE_SHA224);
	case PTA_CMD_RSASSA_PKCS1_SHA256_Verify:
		return rsa_pkcs1_verify(ptypes, params, RSIP_HASH_TYPE_SHA256);
	case PTA_CMD_RSASSA_PKCS1_SHA384_Verify:
		return rsa_pkcs1_verify(ptypes, params, RSIP_HASH_TYPE_SHA384);
	case PTA_CMD_RSASSA_PKCS1_SHA512_Verify:
		return rsa_pkcs1_verify(ptypes, params, RSIP_HASH_TYPE_SHA512);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

static TEE_Result invoke_command_rsassa_pss(uint32_t cmd, uint32_t ptypes,
					    TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd) {
	case PTA_CMD_RSASSA_PSS_SHA1_Sign:
		return rsa_pss_sign(ptypes, params, RSIP_HASH_TYPE_SHA1);
	case PTA_CMD_RSASSA_PSS_SHA224_Sign:
		return rsa_pss_sign(ptypes, params, RSIP_HASH_TYPE_SHA224);
	case PTA_CMD_RSASSA_PSS_SHA256_Sign:
		return rsa_pss_sign(ptypes, params, RSIP_HASH_TYPE_SHA256);
	case PTA_CMD_RSASSA_PSS_SHA384_Sign:
		return rsa_pss_sign(ptypes, params, RSIP_HASH_TYPE_SHA384);
	case PTA_CMD_RSASSA_PSS_SHA512_Sign:
		return rsa_pss_sign(ptypes, params, RSIP_HASH_TYPE_SHA512);
	case PTA_CMD_RSASSA_PSS_SHA1_Verify:
		return rsa_pss_verify(ptypes, params, RSIP_HASH_TYPE_SHA1);
	case PTA_CMD_RSASSA_PSS_SHA224_Verify:
		return rsa_pss_verify(ptypes, params, RSIP_HASH_TYPE_SHA224);
	case PTA_CMD_RSASSA_PSS_SHA256_Verify:
		return rsa_pss_verify(ptypes, params, RSIP_HASH_TYPE_SHA256);
	case PTA_CMD_RSASSA_PSS_SHA384_Verify:
		return rsa_pss_verify(ptypes, params, RSIP_HASH_TYPE_SHA384);
	case PTA_CMD_RSASSA_PSS_SHA512_Verify:
		return rsa_pss_verify(ptypes, params, RSIP_HASH_TYPE_SHA512);
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

static TEE_Result invoke_command_rsaes_oaep(uint32_t cmd, uint32_t ptypes,
					    TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd) {
	case PTA_CMD_RSAES_OAEP_SHA1_Encrypt:
		return rsa_oaep_encrypt(ptypes, params, RSIP_HASH_TYPE_SHA1);
	case PTA_CMD_RSAES_OAEP_SHA224_Encrypt:
		return rsa_oaep_encrypt(ptypes, params, RSIP_HASH_TYPE_SHA224);
	case PTA_CMD_RSAES_OAEP_SHA256_Encrypt:
		return rsa_oaep_encrypt(ptypes, params, RSIP_HASH_TYPE_SHA256);
	case PTA_CMD_RSAES_OAEP_SHA384_Encrypt:
		return rsa_oaep_encrypt(ptypes, params, RSIP_HASH_TYPE_SHA384);
	case PTA_CMD_RSAES_OAEP_SHA512_Encrypt:
		return rsa_oaep_encrypt(ptypes, params, RSIP_HASH_TYPE_SHA512);
	case PTA_CMD_RSAES_OAEP_SHA1_Decrypt:
		return rsa_oaep_decrypt(ptypes, params, RSIP_HASH_TYPE_SHA1);
	case PTA_CMD_RSAES_OAEP_SHA224_Decrypt:
		return rsa_oaep_decrypt(ptypes, params, RSIP_HASH_TYPE_SHA224);
	case PTA_CMD_RSAES_OAEP_SHA256_Decrypt:
		return rsa_oaep_decrypt(ptypes, params, RSIP_HASH_TYPE_SHA256);
	case PTA_CMD_RSAES_OAEP_SHA384_Decrypt:
		return rsa_oaep_decrypt(ptypes, params, RSIP_HASH_TYPE_SHA384);
	case PTA_CMD_RSAES_OAEP_SHA512_Decrypt:
		return rsa_oaep_decrypt(ptypes, params, RSIP_HASH_TYPE_SHA512);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

static TEE_Result invoke_command_rsa_raw(uint32_t cmd, uint32_t ptypes,
					 TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd) {
	case PTA_CMD_RSA_RAW_Encrypt:
		return rsa_raw_encrypt(ptypes, params);
	case PTA_CMD_RSA_RAW_Decrypt:
		return rsa_raw_decrypt(ptypes, params);
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
	case PTA_RSA_VARIANT_RAW:
		return invoke_command_rsa_raw(cmd, ptypes, params);
	case PTA_RSA_VARIANT_PKCS1:
		switch (PTA_CMD_GET_FEATURE(cmd)) {
		case PTA_FEATURE_SIGN:
			return invoke_command_rsassa_pkcs1(cmd, ptypes, params);
		case PTA_FEATURE_CIPHER:
			return invoke_command_rsaes_pkcs1(cmd, ptypes, params);
		default:
			return TEE_ERROR_NOT_SUPPORTED;
		}
	case PTA_RSA_VARIANT_OAEP:
		return invoke_command_rsaes_oaep(cmd, ptypes, params);
	case PTA_RSA_VARIANT_PSS:
		return invoke_command_rsassa_pss(cmd, ptypes, params);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

pseudo_ta_register(.uuid = PTA_RSIP_RSA_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invoke_command);
