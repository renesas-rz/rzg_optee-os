/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2026, Renesas Electronics Corporation
 */

#ifndef __PTA_RSIP_CMD_H
#define __PTA_RSIP_CMD_H

#include <r_rsip.h>

#define PTA_CMD_GET_FEATURE(cmd) (((cmd) >> 24) & 0xF)
#define PTA_CMD_GET_VARIANT(cmd) (((cmd) >> 20) & 0xF)
#define PTA_CMD_GET_ALG(cmd) (((cmd) >> 16) & 0xF)
#define PTA_CMD_GET_TYPE(cmd) (((cmd) >> 8) & 0xFF)
#define PTA_CMD_GET_DIR(cmd) (((cmd) >> 3) & 0x1)
#define PTA_CMD_GET_STRM(cmd) (((cmd) >> 0) & 0x7)

enum pta_feature {
	PTA_FEATURE_KEY_GEN = 0x1,
	PTA_FEATURE_KEYPAIR_GEN = 0x2,
	PTA_FEATURE_KEY_IMPORT = 0x3,
	PTA_FEATURE_KEY_EXPORT = 0x4,
	PTA_FEATURE_RANDOM = 0x5,
	PTA_FEATURE_CIPHER = 0x6,
	PTA_FEATURE_MAC = 0x7,
	PTA_FEATURE_SIGN = 0x8,
	PTA_FEATURE_HASH = 0x9,
};

enum pta_alg {
	PTA_ALG_NONE = 0x0,

	PTA_ALG_AES = 0x2,
	PTA_ALG_SHA = 0x3,
	PTA_ALG_RSA = 0x4,
	PTA_ALG_ECC = 0x5,
	PTA_ALG_HMAC = 0x6,
};

enum pta_aes_variant {
	PTA_VARIANT_AES_ECB = 0x1,
	PTA_VARIANT_AES_CBC = 0x2,
	PTA_VARIANT_AES_CTR = 0x3,
	PTA_VARIANT_AES_XTS = 0x4,
	PTA_VARIANT_AES_GCM = 0x5,
	PTA_VARIANT_AES_CMAC = 0x8,
};

enum pta_hmac_variant {
	PTA_VARIANT_HMAC_SHA1 = 0x1,
	PTA_VARIANT_HMAC_SHA224 = 0x2,
	PTA_VARIANT_HMAC_SHA256 = 0x3,
};

enum pta_ecc_variant {
	PTA_VARIANT_ECC_SECP = 0x1,
	PTA_VARIANT_ECC_BRAINPOOL = 0x2,
};

enum pta_rsa_variant {
	PTA_RSA_VARIANT_RAW = 0x1,
	PTA_RSA_VARIANT_PKCS1 = 0x2,
	PTA_RSA_VARIANT_OAEP = 0x3,
	PTA_RSA_VARIANT_PSS = 0x4,
};

enum pta_key_class {
	PTA_KEY_CLASS_NONE = 0x0,
	PTA_KEY_CLASS_PUBLIC = 0x1,
	PTA_KEY_CLASS_PRIVATE = 0x2,
};

enum pta_key_size {
	PTA_KEY_SIZE_NONE = 0x0,

	PTA_KEY_SIZE_128 = 0x1,
	PTA_KEY_SIZE_192 = 0x2,
	PTA_KEY_SIZE_224 = 0x3,
	PTA_KEY_SIZE_256 = 0x4,
	PTA_KEY_SIZE_384 = 0x5,
	PTA_KEY_SIZE_512 = 0x6,

	PTA_KEY_SIZE_1024 = 0x8,
	PTA_KEY_SIZE_2048 = 0x9,
	PTA_KEY_SIZE_3072 = 0xA,
	PTA_KEY_SIZE_4096 = 0xB,
};

enum pta_dir {
	PTA_DIR_ENCRYPT = 0x0,
	PTA_DIR_GENERATE = 0x0,

	PTA_DIR_DECRYPT = 0x1,
	PTA_DIR_VERIFY = 0x1,
};

TEE_Result get_rsip_key_type(uint32_t cmd, rsip_key_type_t *type);
TEE_Result get_rsip_keypair_type(uint32_t cmd, rsip_key_pair_type_t *type);
TEE_Result get_rsip_aes_mode(uint32_t cmd, rsip_aes_mode_t *mode);

#endif /* __PTA_RSIP_CMD_H */
