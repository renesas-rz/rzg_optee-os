// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2024, Renesas Electronics Corporation
 */

#include <kernel/pseudo_ta.h>
#include <r_rsip.h>
#include <pta_rsip_ecc.h>

#include "pta_rsip_cmd.h"
#include "pta_rsip_util.h"

#define PTA_NAME "rsip_ecc.pta"

struct rsip_ecc_desc {
	size_t digest_size;
	size_t signature_size;
};

static TEE_Result get_ecc_desc(rsip_key_type_t key_type,
			       struct rsip_ecc_desc *desc)
{
	switch (key_type) {
	case RSIP_KEY_TYPE_ECC_secp192r1_PUBLIC:
	case RSIP_KEY_TYPE_ECC_secp192r1_PRIVATE:
		desc->digest_size = RSIP_ECC_COORD_SIZE_192;
		desc->signature_size = 2 * RSIP_ECC_COORD_SIZE_192;
		return TEE_SUCCESS;
	case RSIP_KEY_TYPE_ECC_secp224r1_PUBLIC:
	case RSIP_KEY_TYPE_ECC_secp224r1_PRIVATE:
		desc->digest_size = RSIP_ECC_COORD_SIZE_224;
		desc->signature_size = 2 * RSIP_ECC_COORD_SIZE_224;
		return TEE_SUCCESS;
	case RSIP_KEY_TYPE_ECC_secp256r1_PUBLIC:
	case RSIP_KEY_TYPE_ECC_secp256r1_PRIVATE:
	case RSIP_KEY_TYPE_ECC_BRAINPOOLP256R1_PUBLIC:
	case RSIP_KEY_TYPE_ECC_BRAINPOOLP256R1_PRIVATE:
		desc->digest_size = RSIP_ECC_COORD_SIZE_256;
		desc->signature_size = 2 * RSIP_ECC_COORD_SIZE_256;
		return TEE_SUCCESS;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

static TEE_Result get_ecc_wrapped_key(TEE_Param *p, rsip_key_type_t type,
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

	if (key->type == type) {
		*wrapped_key = key;
		return TEE_SUCCESS;
	}

	return TEE_ERROR_BAD_PARAMETERS;
}

static void ecc_digest_pack(uint8_t *dst, const uint8_t *src,
			    const struct rsip_ecc_desc *desc)
{
	size_t field_size = ROUNDUP(desc->digest_size, 16);
	size_t field_lpad = field_size - desc->digest_size;

	memset(dst, 0, field_size);
	memcpy(dst + field_lpad, src, desc->digest_size);
}

static void ecc_signature_unpack(uint8_t *dst, const uint8_t *src,
				 const struct rsip_ecc_desc *desc)
{
	size_t param_size = desc->signature_size / 2;
	size_t field_size = ROUNDUP(param_size, 16);
	size_t field_lpad = field_size - param_size;

	memcpy(dst, src + field_lpad, param_size);
	memcpy(dst + param_size, src + field_size + field_lpad, param_size);
}

static void ecc_signature_pack(uint8_t *dst, const uint8_t *src,
			       const struct rsip_ecc_desc *desc)
{
	size_t param_size = desc->signature_size / 2;
	size_t field_size = ROUNDUP(param_size, 16);
	size_t field_lpad = field_size - param_size;

	memset(dst, 0, field_size * 2);
	memcpy(dst + field_lpad, src, param_size);
	memcpy(dst + field_size + field_lpad, src + param_size, param_size);
}

static TEE_Result ecdsa_sign(uint32_t types, TEE_Param params[TEE_NUM_PARAMS],
			     rsip_key_type_t type)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

	struct rsip_ecc_desc ecc_desc = { 0 };

	size_t digest_len = 0;
	uint8_t *digest = NULL;
	uint32_t digest_buff[RSIP_DIGEST_SIZE_MAX / sizeof(uint32_t)] = { 0 };
	size_t sig_max = 0;
	uint8_t *sig = NULL;
	uint32_t sig_buff[RSIP_ECDSA_SIG_SIZE_MAX / sizeof(uint32_t)] = { 0 };

	const rsip_wrapped_key_t *wrapped_key = NULL;

	uint32_t exp_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_MEMREF_OUTPUT,
					     TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_NONE);
	if (types != exp_types)
		return TEE_ERROR_BAD_PARAMETERS;

	res = get_ecc_wrapped_key(&params[2], type, &wrapped_key);
	if (res != TEE_SUCCESS)
		return res;

	res = get_ecc_desc(wrapped_key->type, &ecc_desc);
	if (res != TEE_SUCCESS)
		return res;

	digest = params[0].memref.buffer;
	digest_len = params[0].memref.size;
	if (!digest || !IS_ALIGNED_WITH_UINT32(digest))
		return TEE_ERROR_BAD_PARAMETERS;
	if (digest_len != ecc_desc.digest_size)
		return TEE_ERROR_BAD_PARAMETERS;

	sig = params[1].memref.buffer;
	sig_max = params[1].memref.size;
	params[1].memref.size = ecc_desc.signature_size;
	if (!sig || !IS_ALIGNED_WITH_UINT32(sig))
		return TEE_ERROR_BAD_PARAMETERS;
	if (sig_max < params[1].memref.size)
		return TEE_ERROR_SHORT_BUFFER;

	ecc_digest_pack((uint8_t *)digest_buff, digest, &ecc_desc);

	err = R_RSIP_ECDSA_Sign(&rsip_instance_ctrl, wrapped_key,
				(uint8_t *)digest_buff, (uint8_t *)sig_buff);
	if (err != FSP_SUCCESS)
		return rsip_err_to_tee(err);

	ecc_signature_unpack(sig, (uint8_t *)sig_buff, &ecc_desc);

	return TEE_SUCCESS;
}

static TEE_Result ecdsa_verify(uint32_t types, TEE_Param params[TEE_NUM_PARAMS],
			       rsip_key_type_t type)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	fsp_err_t err = FSP_ERR_CRYPTO_RSIP_FAIL;

	struct rsip_ecc_desc ecc_desc = { 0 };

	size_t digest_len = 0;
	uint8_t *digest = NULL;
	uint32_t digest_buff[RSIP_DIGEST_SIZE_MAX / sizeof(uint32_t)] = { 0 };
	size_t sig_len = 0;
	uint8_t *sig = NULL;
	uint32_t sig_buff[RSIP_ECDSA_SIG_SIZE_MAX / sizeof(uint32_t)] = { 0 };

	const rsip_wrapped_key_t *wrapped_key = NULL;

	uint32_t exp_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_MEMREF_INPUT,
					     TEE_PARAM_TYPE_NONE);
	if (types != exp_types)
		return TEE_ERROR_BAD_PARAMETERS;

	res = get_ecc_wrapped_key(&params[2], type, &wrapped_key);
	if (res != TEE_SUCCESS)
		return res;

	res = get_ecc_desc(wrapped_key->type, &ecc_desc);
	if (res != TEE_SUCCESS)
		return res;

	digest = params[0].memref.buffer;
	digest_len = params[0].memref.size;
	if (!digest || !IS_ALIGNED_WITH_UINT32(digest))
		return TEE_ERROR_BAD_PARAMETERS;
	if (digest_len != ecc_desc.digest_size)
		return TEE_ERROR_BAD_PARAMETERS;

	sig = params[1].memref.buffer;
	sig_len = params[1].memref.size;
	if (!sig || !IS_ALIGNED_WITH_UINT32(sig))
		return TEE_ERROR_BAD_PARAMETERS;
	if (sig_len != ecc_desc.signature_size)
		return TEE_ERROR_BAD_PARAMETERS;

	ecc_digest_pack((void *)digest_buff, digest, &ecc_desc);

	ecc_signature_pack((void *)sig_buff, sig, &ecc_desc);

	err = R_RSIP_ECDSA_Verify(&rsip_instance_ctrl, wrapped_key,
				  (uint8_t *)digest_buff, (uint8_t *)sig_buff);
	if (err != FSP_SUCCESS)
		return rsip_verify_err_to_tee(err, RSIP_VERIFY_ECC);

	return TEE_SUCCESS;
}

static TEE_Result invoke_command_secp(uint32_t cmd, uint32_t ptypes,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd) {
	case PTA_CMD_ECDSA_secp192r1_SignatureGenerate:
		return ecdsa_sign(ptypes, params,
				  RSIP_KEY_TYPE_ECC_secp192r1_PRIVATE);
	case PTA_CMD_ECDSA_secp224r1_SignatureGenerate:
		return ecdsa_sign(ptypes, params,
				  RSIP_KEY_TYPE_ECC_secp224r1_PRIVATE);
	case PTA_CMD_ECDSA_secp256r1_SignatureGenerate:
		return ecdsa_sign(ptypes, params,
				  RSIP_KEY_TYPE_ECC_secp256r1_PRIVATE);

	case PTA_CMD_ECDSA_secp192r1_SignatureVerify:
		return ecdsa_verify(ptypes, params,
				    RSIP_KEY_TYPE_ECC_secp192r1_PUBLIC);
	case PTA_CMD_ECDSA_secp224r1_SignatureVerify:
		return ecdsa_verify(ptypes, params,
				    RSIP_KEY_TYPE_ECC_secp224r1_PUBLIC);
	case PTA_CMD_ECDSA_secp256r1_SignatureVerify:
		return ecdsa_verify(ptypes, params,
				    RSIP_KEY_TYPE_ECC_secp256r1_PUBLIC);

	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

static TEE_Result invoke_command_brainpool(uint32_t cmd, uint32_t ptypes,
					   TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd) {
	case PTA_CMD_ECDSA_BrainpoolP256r1_SignatureGenerate:
		return ecdsa_sign(ptypes, params,
				  RSIP_KEY_TYPE_ECC_BRAINPOOLP256R1_PRIVATE);

	case PTA_CMD_ECDSA_BrainpoolP256r1_SignatureVerify:
		return ecdsa_verify(ptypes, params,
				    RSIP_KEY_TYPE_ECC_BRAINPOOLP256R1_PUBLIC);

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
	case PTA_VARIANT_ECC_SECP:
		return invoke_command_secp(cmd, ptypes, params);
	case PTA_VARIANT_ECC_BRAINPOOL:
		return invoke_command_brainpool(cmd, ptypes, params);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

pseudo_ta_register(.uuid = PTA_RSIP_ECC_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invoke_command);
