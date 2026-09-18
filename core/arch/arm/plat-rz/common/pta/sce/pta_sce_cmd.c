// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2026, Renesas Electronics Corporation
 */

#include <tee_api_types.h>

#include "pta_sce_cmd.h"
#include "pta_sce_util.h"

#define PTA_KEY_TYPE(class, size) (((class) << 4) | (size))

static sce_key_type_t get_aes_key_type(uint32_t cmd)
{
	if (PTA_CMD_GET_VARIANT(cmd) == PTA_VARIANT_AES_XTS)
		return SCE_KEY_INDEX_TYPE_INVALID;

	switch (PTA_CMD_GET_TYPE(cmd)) {
	case PTA_KEY_SIZE_128:
		return SCE_KEY_INDEX_TYPE_AES128;
	case PTA_KEY_SIZE_256:
		return SCE_KEY_INDEX_TYPE_AES256;
	default:
		return SCE_KEY_INDEX_TYPE_INVALID;
	}
}

static sce_key_type_t get_ecc_key_type(uint32_t cmd)
{
	switch (PTA_CMD_GET_VARIANT(cmd)) {
	case PTA_VARIANT_ECC_SECP:
		switch (PTA_CMD_GET_TYPE(cmd)) {
		case PTA_KEY_TYPE(PTA_KEY_CLASS_PUBLIC, PTA_KEY_SIZE_192):
			return SCE_KEY_INDEX_TYPE_ECC_P192_PUBLIC;
		case PTA_KEY_TYPE(PTA_KEY_CLASS_PUBLIC, PTA_KEY_SIZE_224):
			return SCE_KEY_INDEX_TYPE_ECC_P224_PUBLIC;
		case PTA_KEY_TYPE(PTA_KEY_CLASS_PUBLIC, PTA_KEY_SIZE_256):
			return SCE_KEY_INDEX_TYPE_ECC_P256_PUBLIC;
		case PTA_KEY_TYPE(PTA_KEY_CLASS_PRIVATE, PTA_KEY_SIZE_192):
			return SCE_KEY_INDEX_TYPE_ECC_P192_PRIVATE;
		case PTA_KEY_TYPE(PTA_KEY_CLASS_PRIVATE, PTA_KEY_SIZE_224):
			return SCE_KEY_INDEX_TYPE_ECC_P224_PRIVATE;
		case PTA_KEY_TYPE(PTA_KEY_CLASS_PRIVATE, PTA_KEY_SIZE_256):
			return SCE_KEY_INDEX_TYPE_ECC_P256_PRIVATE;
		default:
			return SCE_KEY_INDEX_TYPE_INVALID;
		}
	case PTA_VARIANT_ECC_BRAINPOOL:
		switch (PTA_CMD_GET_TYPE(cmd)) {
		case PTA_KEY_TYPE(PTA_KEY_CLASS_PUBLIC, PTA_KEY_SIZE_512):
			return SCE_KEY_INDEX_TYPE_ECC_P512_PUBLIC;
		case PTA_KEY_TYPE(PTA_KEY_CLASS_PRIVATE, PTA_KEY_SIZE_512):
			return SCE_KEY_INDEX_TYPE_ECC_P512_PRIVATE;
		default:
			return SCE_KEY_INDEX_TYPE_INVALID;
		}
	default:
		return SCE_KEY_INDEX_TYPE_INVALID;
	}
}

static sce_key_type_t get_rsa_key_type(uint32_t cmd)
{
	switch (PTA_CMD_GET_TYPE(cmd)) {
	case PTA_KEY_TYPE(PTA_KEY_CLASS_PUBLIC, PTA_KEY_SIZE_1024):
		return SCE_KEY_INDEX_TYPE_RSA1024_PUBLIC;
	case PTA_KEY_TYPE(PTA_KEY_CLASS_PUBLIC, PTA_KEY_SIZE_2048):
		return SCE_KEY_INDEX_TYPE_RSA2048_PUBLIC;
	case PTA_KEY_TYPE(PTA_KEY_CLASS_PUBLIC, PTA_KEY_SIZE_4096):
		return SCE_KEY_INDEX_TYPE_RSA4096_PUBLIC;
	case PTA_KEY_TYPE(PTA_KEY_CLASS_PRIVATE, PTA_KEY_SIZE_1024):
		return SCE_KEY_INDEX_TYPE_RSA1024_PRIVATE;
	case PTA_KEY_TYPE(PTA_KEY_CLASS_PRIVATE, PTA_KEY_SIZE_2048):
		return SCE_KEY_INDEX_TYPE_RSA2048_PRIVATE;
	default:
		return SCE_KEY_INDEX_TYPE_INVALID;
	}
}

TEE_Result get_sce_key_type(uint32_t cmd, sce_key_type_t *type)
{
	sce_key_type_t key_type = SCE_KEY_INDEX_TYPE_INVALID;

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
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	if (key_type == SCE_KEY_INDEX_TYPE_INVALID)
		return TEE_ERROR_NOT_SUPPORTED;

	*type = key_type;
	return TEE_SUCCESS;
}

static enum sce_key_pair_type get_rsa_key_pair_type(uint32_t cmd)
{
	switch (PTA_CMD_GET_TYPE(cmd) & 0xF) {
	case PTA_KEY_SIZE_1024:
		return SCE_KEY_PAIR_TYPE_RSA_1024;
	case PTA_KEY_SIZE_2048:
		return SCE_KEY_PAIR_TYPE_RSA_2048;
	default:
		return SCE_KEY_PAIR_TYPE_INVALID;
	}
}

static enum sce_key_pair_type get_ecc_key_pair_type(uint32_t cmd)
{
	switch (PTA_CMD_GET_VARIANT(cmd)) {
	case PTA_VARIANT_ECC_SECP:
		switch (PTA_CMD_GET_TYPE(cmd) & 0xF) {
		case PTA_KEY_SIZE_192:
			return SCE_KEY_PAIR_TYPE_ECC_secp192r1;
		case PTA_KEY_SIZE_224:
			return SCE_KEY_PAIR_TYPE_ECC_secp224r1;
		case PTA_KEY_SIZE_256:
			return SCE_KEY_PAIR_TYPE_ECC_secp256r1;
		default:
			return SCE_KEY_PAIR_TYPE_INVALID;
		}
	case PTA_VARIANT_ECC_BRAINPOOL:
		switch (PTA_CMD_GET_TYPE(cmd) & 0xF) {
		case PTA_KEY_SIZE_512:
			return SCE_KEY_PAIR_TYPE_ECC_BRAINPOOLP512R1;
		default:
			return SCE_KEY_PAIR_TYPE_INVALID;
		}
	default:
		return SCE_KEY_PAIR_TYPE_INVALID;
	}
}

TEE_Result get_sce_key_pair_type(uint32_t cmd, enum sce_key_pair_type *type)
{
	enum sce_key_pair_type key_pair_type = SCE_KEY_PAIR_TYPE_INVALID;

	switch (PTA_CMD_GET_ALG(cmd)) {
	case PTA_ALG_RSA:
		key_pair_type = get_rsa_key_pair_type(cmd);
		break;
	case PTA_ALG_ECC:
		key_pair_type = get_ecc_key_pair_type(cmd);
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	if (key_pair_type == SCE_KEY_PAIR_TYPE_INVALID)
		return TEE_ERROR_NOT_SUPPORTED;

	*type = key_pair_type;
	return TEE_SUCCESS;
}

TEE_Result get_sce_aes_mode(uint32_t cmd, enum sce_aes_mode *mode)
{
	if (PTA_CMD_GET_ALG(cmd) != PTA_ALG_AES)
		return TEE_ERROR_NOT_SUPPORTED;

	switch (PTA_CMD_GET_VARIANT(cmd)) {
	case PTA_VARIANT_AES_ECB:
		*mode = SCE_AES_MODE_ECB;
		return TEE_SUCCESS;
	case PTA_VARIANT_AES_CBC:
		*mode = SCE_AES_MODE_CBC;
		return TEE_SUCCESS;
	case PTA_VARIANT_AES_CTR:
		*mode = SCE_AES_MODE_CTR;
		return TEE_SUCCESS;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
