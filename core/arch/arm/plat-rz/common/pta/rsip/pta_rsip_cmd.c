// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2024, Renesas Electronics Corporation
 */

#include <tee_api_types.h>

#include "pta_rsip_cmd.h"

#define PTA_KEY_TYPE(class, size) (((class) << 4) | (size))

static rsip_key_type_t get_aes_key_type(uint32_t cmd)
{
	switch (PTA_CMD_GET_TYPE(cmd)) {
	case PTA_KEY_SIZE_128:
		return (PTA_CMD_GET_VARIANT(cmd) == PTA_VARIANT_AES_XTS) ?
			       RSIP_KEY_TYPE_AES_128_XTS :
			       RSIP_KEY_TYPE_AES_128;
	case PTA_KEY_SIZE_256:
		return (PTA_CMD_GET_VARIANT(cmd) == PTA_VARIANT_AES_XTS) ?
			       RSIP_KEY_TYPE_AES_256_XTS :
			       RSIP_KEY_TYPE_AES_256;
	default:
		return RSIP_KEY_TYPE_INVALID;
	}
}

static rsip_key_type_t get_hmac_key_type(uint32_t cmd)
{
	switch (PTA_CMD_GET_VARIANT(cmd)) {
	case PTA_VARIANT_HMAC_SHA1:
		return RSIP_KEY_TYPE_HMAC_SHA1;
	case PTA_VARIANT_HMAC_SHA224:
		return RSIP_KEY_TYPE_HMAC_SHA224;
	case PTA_VARIANT_HMAC_SHA256:
		return RSIP_KEY_TYPE_HMAC_SHA256;
	default:
		return RSIP_KEY_TYPE_INVALID;
	}
}

static rsip_key_type_t get_ecc_key_type(uint32_t cmd)
{
	switch (PTA_CMD_GET_VARIANT(cmd)) {
	case PTA_VARIANT_ECC_SECP:
		switch (PTA_CMD_GET_TYPE(cmd)) {
		case PTA_KEY_TYPE(PTA_KEY_CLASS_PUBLIC, PTA_KEY_SIZE_192):
			return RSIP_KEY_TYPE_ECC_secp192r1_PUBLIC;
		case PTA_KEY_TYPE(PTA_KEY_CLASS_PUBLIC, PTA_KEY_SIZE_224):
			return RSIP_KEY_TYPE_ECC_secp224r1_PUBLIC;
		case PTA_KEY_TYPE(PTA_KEY_CLASS_PUBLIC, PTA_KEY_SIZE_256):
			return RSIP_KEY_TYPE_ECC_secp256r1_PUBLIC;
		case PTA_KEY_TYPE(PTA_KEY_CLASS_PRIVATE, PTA_KEY_SIZE_192):
			return RSIP_KEY_TYPE_ECC_secp192r1_PRIVATE;
		case PTA_KEY_TYPE(PTA_KEY_CLASS_PRIVATE, PTA_KEY_SIZE_224):
			return RSIP_KEY_TYPE_ECC_secp224r1_PRIVATE;
		case PTA_KEY_TYPE(PTA_KEY_CLASS_PRIVATE, PTA_KEY_SIZE_256):
			return RSIP_KEY_TYPE_ECC_secp256r1_PRIVATE;
		default:
			return RSIP_KEY_TYPE_INVALID;
		}
	case PTA_VARIANT_ECC_BRAINPOOL:
		switch (PTA_CMD_GET_TYPE(cmd)) {
		case PTA_KEY_TYPE(PTA_KEY_CLASS_PUBLIC, PTA_KEY_SIZE_256):
			return RSIP_KEY_TYPE_ECC_BRAINPOOLP256R1_PUBLIC;
		case PTA_KEY_TYPE(PTA_KEY_CLASS_PRIVATE, PTA_KEY_SIZE_256):
			return RSIP_KEY_TYPE_ECC_BRAINPOOLP256R1_PRIVATE;
		default:
			return RSIP_KEY_TYPE_INVALID;
		}
	default:
		return RSIP_KEY_TYPE_INVALID;
	}
}

static rsip_key_type_t get_rsa_key_type(uint32_t cmd)
{
	switch (PTA_CMD_GET_TYPE(cmd)) {
	case PTA_KEY_TYPE(PTA_KEY_CLASS_PUBLIC, PTA_KEY_SIZE_1024):
		return RSIP_KEY_TYPE_RSA_1024_PUBLIC_ENHANCED;
	case PTA_KEY_TYPE(PTA_KEY_CLASS_PUBLIC, PTA_KEY_SIZE_2048):
		return RSIP_KEY_TYPE_RSA_2048_PUBLIC_ENHANCED;
	case PTA_KEY_TYPE(PTA_KEY_CLASS_PUBLIC, PTA_KEY_SIZE_3072):
		return RSIP_KEY_TYPE_RSA_3072_PUBLIC;
	case PTA_KEY_TYPE(PTA_KEY_CLASS_PUBLIC, PTA_KEY_SIZE_4096):
		return RSIP_KEY_TYPE_RSA_4096_PUBLIC;
	case PTA_KEY_TYPE(PTA_KEY_CLASS_PRIVATE, PTA_KEY_SIZE_1024):
		return RSIP_KEY_TYPE_RSA_1024_PRIVATE_ENHANCED;
	case PTA_KEY_TYPE(PTA_KEY_CLASS_PRIVATE, PTA_KEY_SIZE_2048):
		return RSIP_KEY_TYPE_RSA_2048_PRIVATE_ENHANCED;
	case PTA_KEY_TYPE(PTA_KEY_CLASS_PRIVATE, PTA_KEY_SIZE_3072):
		return RSIP_KEY_TYPE_RSA_3072_PRIVATE;
	case PTA_KEY_TYPE(PTA_KEY_CLASS_PRIVATE, PTA_KEY_SIZE_4096):
		return RSIP_KEY_TYPE_RSA_4096_PRIVATE;
	default:
		return RSIP_KEY_TYPE_INVALID;
	}
}

TEE_Result get_rsip_key_type(uint32_t cmd, rsip_key_type_t *type)
{
	rsip_key_type_t key_type = RSIP_KEY_TYPE_INVALID;

	switch (PTA_CMD_GET_ALG(cmd)) {
	case PTA_ALG_AES:
		key_type = get_aes_key_type(cmd);
		break;
	case PTA_ALG_RSA:
		key_type = get_rsa_key_type(cmd);
		break;
	case PTA_ALG_ECC:
		key_type = get_ecc_key_type(cmd);
		break;
	case PTA_ALG_HMAC:
		key_type = get_hmac_key_type(cmd);
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	if (key_type == RSIP_KEY_TYPE_INVALID)
		return TEE_ERROR_NOT_SUPPORTED;

	*type = key_type;
	return TEE_SUCCESS;
}

static rsip_key_pair_type_t get_rsa_keypair_type(uint32_t cmd)
{
	switch (PTA_CMD_GET_TYPE(cmd) & 0xF) {
	case PTA_KEY_SIZE_1024:
		return RSIP_KEY_PAIR_TYPE_RSA_1024;
	case PTA_KEY_SIZE_2048:
		return RSIP_KEY_PAIR_TYPE_RSA_2048;
	case PTA_KEY_SIZE_3072:
		return RSIP_KEY_PAIR_TYPE_RSA_3072;
	case PTA_KEY_SIZE_4096:
		return RSIP_KEY_PAIR_TYPE_RSA_4096;
	default:
		return RSIP_KEY_PAIR_TYPE_INVALID;
	}
}

static rsip_key_pair_type_t get_ecc_keypair_type(uint32_t cmd)
{
	switch (PTA_CMD_GET_VARIANT(cmd)) {
	case PTA_VARIANT_ECC_SECP:
		switch (PTA_CMD_GET_TYPE(cmd) & 0xF) {
		case PTA_KEY_SIZE_192:
			return RSIP_KEY_PAIR_TYPE_ECC_secp192r1;
		case PTA_KEY_SIZE_224:
			return RSIP_KEY_PAIR_TYPE_ECC_secp224r1;
		case PTA_KEY_SIZE_256:
			return RSIP_KEY_PAIR_TYPE_ECC_secp256r1;
		default:
			return RSIP_KEY_PAIR_TYPE_INVALID;
		}
	case PTA_VARIANT_ECC_BRAINPOOL:
		switch (PTA_CMD_GET_TYPE(cmd & 0xF)) {
		case PTA_KEY_SIZE_256:
			return RSIP_KEY_PAIR_TYPE_ECC_BRAINPOOLP256R1;
		default:
			return RSIP_KEY_PAIR_TYPE_INVALID;
		}
	default:
		return RSIP_KEY_PAIR_TYPE_INVALID;
	}
}

TEE_Result get_rsip_keypair_type(uint32_t cmd, rsip_key_pair_type_t *type)
{
	rsip_key_pair_type_t keypair_type = RSIP_KEY_PAIR_TYPE_INVALID;

	switch (PTA_CMD_GET_ALG(cmd)) {
	case PTA_ALG_RSA:
		keypair_type = get_rsa_keypair_type(cmd);
		break;
	case PTA_ALG_ECC:
		keypair_type = get_ecc_keypair_type(cmd);
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	if (keypair_type == RSIP_KEY_PAIR_TYPE_INVALID)
		return TEE_ERROR_NOT_SUPPORTED;

	*type = keypair_type;
	return TEE_SUCCESS;
}

TEE_Result get_rsip_aes_mode(uint32_t cmd, rsip_aes_mode_t *mode)
{
	if (PTA_CMD_GET_ALG(cmd) != PTA_ALG_AES)
		return TEE_ERROR_NOT_SUPPORTED;

	switch (PTA_CMD_GET_VARIANT(cmd)) {
	case PTA_VARIANT_AES_ECB:
		*mode = RSIP_AES_MODE_ECB;
		return TEE_SUCCESS;
	case PTA_VARIANT_AES_CBC:
		*mode = RSIP_AES_MODE_CBC;
		return TEE_SUCCESS;
	case PTA_VARIANT_AES_CTR:
		*mode = RSIP_AES_MODE_CTR;
		return TEE_SUCCESS;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
