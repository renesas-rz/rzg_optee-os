// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2024-2026, Renesas Electronics Corporation
 */

#include <util.h>
#include <tee_api_types.h>
#include <kernel/panic.h>

#include "pta_sce_util.h"

#define SCE_WRAPPED_KEY_BYTE(x) (sizeof(sce_##x##_wrapped_key_t))
#define SCE_KEY_INST_DATA_BYTE(x) ((SCE_OEM_KEY_SIZE_##x##_INST_DATA_WORD) << 2)

static const struct sce_key_desc key_descs[] = {
	[SCE_KEY_INDEX_TYPE_AES128] = {
		.wrapped_size = SCE_WRAPPED_KEY_BYTE(aes),
		.encrypted_size = SCE_KEY_INST_DATA_BYTE(AES128),
	},
	[SCE_KEY_INDEX_TYPE_AES256] = {
		.wrapped_size = SCE_WRAPPED_KEY_BYTE(aes),
		.encrypted_size = SCE_KEY_INST_DATA_BYTE(AES256),
	},
	[SCE_KEY_INDEX_TYPE_ECC_P192_PUBLIC] = {
		.wrapped_size = SCE_WRAPPED_KEY_BYTE(ecc_public),
		.encrypted_size = SCE_KEY_INST_DATA_BYTE(ECCP192_PUBLIC_KEY),
	},
	[SCE_KEY_INDEX_TYPE_ECC_P192_PRIVATE] = {
		.wrapped_size = SCE_WRAPPED_KEY_BYTE(ecc_private),
		.encrypted_size = SCE_KEY_INST_DATA_BYTE(ECCP192_PRIVATE_KEY),
	},
	[SCE_KEY_INDEX_TYPE_ECC_P224_PUBLIC] = {
		.wrapped_size = SCE_WRAPPED_KEY_BYTE(ecc_public),
		.encrypted_size = SCE_KEY_INST_DATA_BYTE(ECCP224_PUBLIC_KEY),
	},
	[SCE_KEY_INDEX_TYPE_ECC_P224_PRIVATE] = {
		.wrapped_size = SCE_WRAPPED_KEY_BYTE(ecc_private),
		.encrypted_size = SCE_KEY_INST_DATA_BYTE(ECCP224_PRIVATE_KEY),
	},
	[SCE_KEY_INDEX_TYPE_ECC_P256_PUBLIC] = {
		.wrapped_size = SCE_WRAPPED_KEY_BYTE(ecc_public),
		.encrypted_size = SCE_KEY_INST_DATA_BYTE(ECCP256_PUBLIC_KEY),
	},
	[SCE_KEY_INDEX_TYPE_ECC_P256_PRIVATE] = {
		.wrapped_size = SCE_WRAPPED_KEY_BYTE(ecc_private),
		.encrypted_size = SCE_KEY_INST_DATA_BYTE(ECCP256_PRIVATE_KEY),
	},
	[SCE_KEY_INDEX_TYPE_ECC_P512_PUBLIC] = {
		.wrapped_size = SCE_WRAPPED_KEY_BYTE(ecc_public),
		.encrypted_size = SCE_KEY_INST_DATA_BYTE(ECCP512_PUBLIC_KEY),
	},
	[SCE_KEY_INDEX_TYPE_ECC_P512_PRIVATE] = {
		.wrapped_size = SCE_WRAPPED_KEY_BYTE(ecc_private),
		.encrypted_size = SCE_KEY_INST_DATA_BYTE(ECCP512_PRIVATE_KEY),
	},
	[SCE_KEY_INDEX_TYPE_RSA1024_PUBLIC] = {
		.wrapped_size = SCE_WRAPPED_KEY_BYTE(rsa1024_public),
		.encrypted_size = SCE_KEY_INST_DATA_BYTE(RSA1024_PUBLIC_KEY),
	},
	[SCE_KEY_INDEX_TYPE_RSA1024_PRIVATE] = {
		.wrapped_size = SCE_WRAPPED_KEY_BYTE(rsa1024_private),
		.encrypted_size = SCE_KEY_INST_DATA_BYTE(RSA1024_PRIVATE_KEY),
	},
	[SCE_KEY_INDEX_TYPE_RSA2048_PUBLIC] = {
		.wrapped_size = SCE_WRAPPED_KEY_BYTE(rsa2048_public),
		.encrypted_size = SCE_KEY_INST_DATA_BYTE(RSA2048_PUBLIC_KEY),
	},
	[SCE_KEY_INDEX_TYPE_RSA2048_PRIVATE] = {
		.wrapped_size = SCE_WRAPPED_KEY_BYTE(rsa2048_private),
		.encrypted_size = SCE_KEY_INST_DATA_BYTE(RSA2048_PRIVATE_KEY),
	},
	[SCE_KEY_INDEX_TYPE_RSA4096_PUBLIC] = {
		.wrapped_size = SCE_WRAPPED_KEY_BYTE(rsa4096_public),
		.encrypted_size = SCE_KEY_INST_DATA_BYTE(RSA4096_PUBLIC_KEY),
	},
};

TEE_Result get_key_desc(sce_key_type_t type,
			const struct sce_key_desc **key_desc)
{
	if (type >= ARRAY_SIZE(key_descs))
		return TEE_ERROR_BAD_PARAMETERS;
	if (key_descs[type].wrapped_size == 0)
		return TEE_ERROR_BAD_PARAMETERS;
	if (key_descs[type].encrypted_size == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	*key_desc = &key_descs[type];
	return TEE_SUCCESS;
}

TEE_Result get_key_pair_desc(enum sce_key_pair_type type,
			     const struct sce_key_desc **prikey_desc,
			     const struct sce_key_desc **pubkey_desc)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	sce_key_type_t prikey = 0;
	sce_key_type_t pubkey = 0;

	switch (type) {
	case SCE_KEY_PAIR_TYPE_ECC_secp192r1:
		prikey = SCE_KEY_INDEX_TYPE_ECC_P192_PRIVATE;
		pubkey = SCE_KEY_INDEX_TYPE_ECC_P192_PUBLIC;
		break;
	case SCE_KEY_PAIR_TYPE_ECC_secp224r1:
		prikey = SCE_KEY_INDEX_TYPE_ECC_P224_PRIVATE;
		pubkey = SCE_KEY_INDEX_TYPE_ECC_P224_PUBLIC;
		break;
	case SCE_KEY_PAIR_TYPE_ECC_secp256r1:
		prikey = SCE_KEY_INDEX_TYPE_ECC_P256_PRIVATE;
		pubkey = SCE_KEY_INDEX_TYPE_ECC_P256_PUBLIC;
		break;
	case SCE_KEY_PAIR_TYPE_ECC_BRAINPOOLP512R1:
		prikey = SCE_KEY_INDEX_TYPE_ECC_P512_PRIVATE;
		pubkey = SCE_KEY_INDEX_TYPE_ECC_P512_PUBLIC;
		break;
	case SCE_KEY_PAIR_TYPE_RSA_1024:
		prikey = SCE_KEY_INDEX_TYPE_RSA1024_PRIVATE;
		pubkey = SCE_KEY_INDEX_TYPE_RSA1024_PUBLIC;
		break;
	case SCE_KEY_PAIR_TYPE_RSA_2048:
		prikey = SCE_KEY_INDEX_TYPE_RSA2048_PRIVATE;
		pubkey = SCE_KEY_INDEX_TYPE_RSA2048_PUBLIC;
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	res = get_key_desc(prikey, prikey_desc);
	if (res != TEE_SUCCESS)
		return res;
	res = get_key_desc(pubkey, pubkey_desc);
	if (res != TEE_SUCCESS)
		return res;

	return TEE_SUCCESS;
}

TEE_Result get_digest_size(enum sce_hash_type hash_type, size_t *digest_size)
{
	switch (hash_type) {
	case SCE_HASH_TYPE_SHA1:
		*digest_size = SCE_DIGEST_SIZE_SHA1;
		return TEE_SUCCESS;
	case SCE_HASH_TYPE_SHA224:
		*digest_size = SCE_DIGEST_SIZE_SHA224;
		return TEE_SUCCESS;
	case SCE_HASH_TYPE_SHA256:
		*digest_size = SCE_DIGEST_SIZE_SHA256;
		return TEE_SUCCESS;
	case SCE_HASH_TYPE_SHA384:
		*digest_size = SCE_DIGEST_SIZE_SHA384;
		return TEE_SUCCESS;
	case SCE_HASH_TYPE_SHA512:
		*digest_size = SCE_DIGEST_SIZE_SHA512;
		return TEE_SUCCESS;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

/*
 * Convert SCE/FSP error codes to TEE_Result.
 */
TEE_Result sce_err_to_tee(fsp_err_t err)
{
	switch ((uint32_t)err) {
	case FSP_SUCCESS:
		return TEE_SUCCESS;
	case FSP_ERR_CRYPTO_SCE_PARAMETER:
		return TEE_ERROR_BAD_PARAMETERS;
	case FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION:
		return TEE_ERROR_BAD_STATE;
	case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
		return TEE_ERROR_BUSY;
	case FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL:
		return TEE_ERROR_BAD_FORMAT;
	case FSP_ERR_CRYPTO_SCE_AUTHENTICATION:
		return TEE_ERROR_MAC_INVALID;
	case FSP_ERR_CRYPTO_SCE_FAIL:
		return TEE_ERROR_BAD_FORMAT;
	default:
		DMSG("Unhandled SCE error: %#" PRIx32, (uint32_t)err);
		return TEE_ERROR_GENERIC;
	}
}

TEE_Result sce_verify_err_to_tee(fsp_err_t err, enum sce_verify_type type)
{
	if (err != FSP_ERR_CRYPTO_SCE_FAIL &&
	    err != FSP_ERR_CRYPTO_SCE_AUTHENTICATION)
		return sce_err_to_tee(err);

	switch (type) {
	case SCE_VERIFY_ECC:
	case SCE_VERIFY_RSA:
		return TEE_ERROR_SIGNATURE_INVALID;
	case SCE_VERIFY_MAC:
		return TEE_ERROR_MAC_INVALID;
	default:
		panic();
	}
}
