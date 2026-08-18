/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2026, Renesas Electronics Corporation
 */

#ifndef __PTA_RSIP_UTIL_H
#define __PTA_RSIP_UTIL_H

#include <r_rsip.h>

#define IS_ALIGNED_WITH_UINT32(x) \
	IS_ALIGNED((uintptr_t)(x), __alignof__(uint32_t))

#define RSIP_DIGEST_SIZE_SHA1 (20U)
#define RSIP_DIGEST_SIZE_SHA224 (28U)
#define RSIP_DIGEST_SIZE_SHA256 (32U)
#define RSIP_DIGEST_SIZE_SHA384 (48U)
#define RSIP_DIGEST_SIZE_SHA512 (64U)
#define RSIP_DIGEST_SIZE_MAX (RSIP_DIGEST_SIZE_SHA512)

#define RSIP_HMAC_MAC_SIZE_MIN (4U)
#define RSIP_HMAC_MAC_SIZE_MAX (RSIP_DIGEST_SIZE_SHA256)

#define RSIP_RSA_MOD_SIZE_1024 (128U)
#define RSIP_RSA_MOD_SIZE_2048 (256U)
#define RSIP_RSA_MOD_SIZE_3072 (384U)
#define RSIP_RSA_MOD_SIZE_4096 (512U)
#define RSIP_RSA_MOD_SIZE_MAX (RSIP_RSA_MOD_SIZE_4096)
#define RSIP_RSA_EXPONENT_SIZE (4U)

#define RSIP_ECC_COORD_SIZE_192 (24U)
#define RSIP_ECC_COORD_SIZE_224 (28U)
#define RSIP_ECC_COORD_SIZE_256 (32U)

#define RSIP_ECDSA_SIG_SIZE_MAX (64U)

/*
 * Imported key update key (KUK).
 *
 * The buffer is shared between the wrapped-key structure
 * and a raw byte array representation.
 */
union wrapped_key_buffer {
	rsip_wrapped_key_t wrapped_key;
	uint8_t value[RSIP_BYTE_SIZE_WRAPPED_KEY_MAX];
};

struct rsip_key_desc {
	size_t wrapped_size;
	size_t encrypted_size;
};

/*
 * Verification operation type used for RSIP error
 * conversion.
 */
enum rsip_verify_type {
	RSIP_VERIFY_ECC,
	RSIP_VERIFY_RSA,
	RSIP_VERIFY_MAC,
};

TEE_Result get_key_desc(rsip_key_type_t type,
			const struct rsip_key_desc **key_desc);

TEE_Result get_keypair_desc(rsip_key_pair_type_t type,
			    const struct rsip_key_desc **prikey_desc,
			    const struct rsip_key_desc **pubkey_desc);

TEE_Result get_digest_size(rsip_hash_type_t hash_type, size_t *digest_size);

/*
 * Convert RSIP/FSP error codes to TEE_Result.
 */
TEE_Result rsip_err_to_tee(fsp_err_t err);

/*
 * Convert RSIP verification results to TEE_Result.
 */
TEE_Result rsip_verify_err_to_tee(fsp_err_t err, enum rsip_verify_type type);

extern rsip_instance_ctrl_t rsip_instance_ctrl;

#endif /* __PTA_RSIP_UTIL_H */
