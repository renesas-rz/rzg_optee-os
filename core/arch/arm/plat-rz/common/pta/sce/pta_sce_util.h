/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2026, Renesas Electronics Corporation
 */

#ifndef __PTA_SCE_UTIL_H
#define __PTA_SCE_UTIL_H

#include <r_sce.h>
#include <r_sce_api.h>

#define IS_ALIGNED_WITH_UINT32(x) \
	IS_ALIGNED((uintptr_t)(x), __alignof__(uint32_t))

#define SCE_DIGEST_SIZE_SHA1 (20U)
#define SCE_DIGEST_SIZE_SHA224 (28U)
#define SCE_DIGEST_SIZE_SHA256 (32U)
#define SCE_DIGEST_SIZE_SHA384 (48U)
#define SCE_DIGEST_SIZE_SHA512 (64U)
#define SCE_DIGEST_SIZE_MAX (SCE_DIGEST_SIZE_SHA512)

#define SCE_RSA_MOD_SIZE_1024 (128U)
#define SCE_RSA_MOD_SIZE_2048 (256U)
#define SCE_RSA_MOD_SIZE_3072 (384U)
#define SCE_RSA_MOD_SIZE_4096 (512U)
#define SCE_RSA_MOD_SIZE_MAX (SCE_RSA_MOD_SIZE_4096)
#define SCE_RSA_EXPONENT_SIZE (4U)

#define SCE_ECC_COORD_SIZE_192 (24U)
#define SCE_ECC_COORD_SIZE_224 (28U)
#define SCE_ECC_COORD_SIZE_256 (32U)
#define SCE_ECC_COORD_SIZE_512 (64U)

#define SCE_ECDSA_SIG_SIZE_MAX (2 * SCE_ECC_COORD_SIZE_512)

#define SCE_BYTE_SIZE_WRAPPED_KEY_MAX (sizeof(sce_rsa4096_public_wrapped_key_t))

enum sce_key_pair_type {
	SCE_KEY_PAIR_TYPE_INVALID,
	SCE_KEY_PAIR_TYPE_ECC_secp192r1,
	SCE_KEY_PAIR_TYPE_ECC_secp224r1,
	SCE_KEY_PAIR_TYPE_ECC_secp256r1,
	SCE_KEY_PAIR_TYPE_ECC_BRAINPOOLP512R1,
	SCE_KEY_PAIR_TYPE_RSA_1024,
	SCE_KEY_PAIR_TYPE_RSA_2048,
	SCE_KEY_PAIR_TYPE_RSA_4096,
	SCE_KEY_PAIR_TYPE_NUM,
};

enum sce_hash_type {
	SCE_HASH_TYPE_SHA1,
	SCE_HASH_TYPE_SHA224,
	SCE_HASH_TYPE_SHA256,
	SCE_HASH_TYPE_SHA384,
	SCE_HASH_TYPE_SHA512,
};

enum sce_aes_mode {
	SCE_AES_MODE_ECB,
	SCE_AES_MODE_CBC,
	SCE_AES_MODE_CTR,
};

typedef SCE_KEY_INDEX_TYPE sce_key_type_t;

struct sce_wrapped_key {
	sce_key_type_t type;
	uint8_t value[];
};

/*
 * The buffer is shared between the wrapped-key structure
 * and a raw byte array representation.
 */
union wrapped_key_buffer {
	struct sce_wrapped_key wrapped_key;
	uint8_t value[SCE_BYTE_SIZE_WRAPPED_KEY_MAX];
};

struct sce_key_desc {
	size_t wrapped_size;
	size_t encrypted_size;
};

/*
 * Verification operation type used for SCE error
 * conversion.
 */
enum sce_verify_type {
	SCE_VERIFY_ECC,
	SCE_VERIFY_RSA,
	SCE_VERIFY_MAC,
};

TEE_Result get_key_desc(sce_key_type_t type,
			const struct sce_key_desc **key_desc);
TEE_Result get_key_pair_desc(enum sce_key_pair_type type,
			     const struct sce_key_desc **prikey_desc,
			     const struct sce_key_desc **pubkey_desc);
TEE_Result get_digest_size(enum sce_hash_type hash_type, size_t *digest_size);

/*
 * Convert SCE/FSP error codes to TEE_Result.
 */
TEE_Result sce_err_to_tee(fsp_err_t err);

/*
 * Convert SCE verification results to TEE_Result.
 */
TEE_Result sce_verify_err_to_tee(fsp_err_t err, enum sce_verify_type type);

#endif /* __PTA_SCE_UTIL_H */
