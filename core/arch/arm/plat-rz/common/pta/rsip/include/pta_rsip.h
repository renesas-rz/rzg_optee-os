/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2024-2026, Renesas Electronics Corporation
 */

#ifndef __PTA_RSIP_H
#define __PTA_RSIP_H

#define PTA_RSIP_UUID                                                   \
	{                                                               \
		0x4c00fad8, 0x7b34, 0x422f,                             \
		{                                                       \
			0xb7, 0x3c, 0x04, 0xa7, 0x9b, 0x58, 0x1b, 0x7e, \
		}                                                       \
	}

/*
 * Generate an AES-128 wrapped key.
 * memref[0] (out): Wrapped key buffer (52 bytes).
 */
#define PTA_CMD_AES128_WrappedKeyGenerate (0x11020100)

/*
 * Generate an AES-256 wrapped key.
 * memref[0] (out): Wrapped key buffer (68 bytes).
 */
#define PTA_CMD_AES256_WrappedKeyGenerate (0x11020400)

/*
 * Generate an AES-128-XTS wrapped key.
 * memref[0] (out): Wrapped key buffer (68 bytes).
 */
#define PTA_CMD_AES128_XTS_WrappedKeyGenerate (0x11420100)

/*
 * Generate an AES-256-XTS wrapped key.
 * memref[0] (out): Wrapped key buffer (100 bytes).
 */
#define PTA_CMD_AES256_XTS_WrappedKeyGenerate (0x11420400)

/*
 * Generate an RSA-1024 wrapped key pair.
 * memref[0] (out): Wrapped private key buffer (292 bytes).
 * memref[1] (out): Wrapped public key buffer (180 bytes).
 */
#define PTA_CMD_RSA_1024_WrappedKeyPairGenerate (0x12040800)

/*
 * Generate an RSA-2048 wrapped key pair.
 * memref[0] (out): Wrapped private key buffer (548 bytes).
 * memref[1] (out): Wrapped public key buffer (308 bytes).
 */
#define PTA_CMD_RSA_2048_WrappedKeyPairGenerate (0x12040900)

/*
 * Generate an RSA-3072 wrapped key pair.
 * memref[0] (out): Wrapped private key buffer (804 bytes).
 * memref[1] (out): Wrapped public key buffer (436 bytes).
 */
#define PTA_CMD_RSA_3072_WrappedKeyPairGenerate (0x12040A00)

/*
 * Generate an RSA-4096 wrapped key pair.
 * memref[0] (out): Wrapped private key buffer (1060 bytes).
 * memref[1] (out): Wrapped public key buffer (564 bytes).
 */
#define PTA_CMD_RSA_4096_WrappedKeyPairGenerate (0x12040B00)

/*
 * Generate a secp192r1 wrapped key pair.
 * memref[0] (out): Wrapped private key buffer (68 bytes).
 * memref[1] (out): Wrapped public key buffer (100 bytes).
 */
#define PTA_CMD_ECC_secp192r1_WrappedKeyPairGenerate (0x12150200)

/*
 * Generate a secp224r1 wrapped key pair.
 * memref[0] (out): Wrapped private key buffer (68 bytes).
 * memref[1] (out): Wrapped public key buffer (100 bytes).
 */
#define PTA_CMD_ECC_secp224r1_WrappedKeyPairGenerate (0x12150300)

/*
 * Generate a secp256r1 wrapped key pair.
 * memref[0] (out): Wrapped private key buffer (68 bytes).
 * memref[1] (out): Wrapped public key buffer (100 bytes).
 */
#define PTA_CMD_ECC_secp256r1_WrappedKeyPairGenerate (0x12150400)

/*
 * Generate a BrainpoolP256r1 wrapped key pair.
 * memref[0] (out): Wrapped private key buffer (68 bytes).
 * memref[1] (out): Wrapped public key buffer (100 bytes).
 */
#define PTA_CMD_ECC_BrainpoolP256r1_WrappedKeyPairGenerate (0x12250400)

/*
 * Wrap an encrypted AES-128 key.
 * memref[0] (in): Encrypted AES-128 key blob (60 bytes).
 * memref[1] (out): Wrapped key buffer (52 bytes).
 */
#define PTA_CMD_AES128_EncryptedKeyWrap (0x13020100)

/*
 * Wrap an encrypted AES-256 key.
 * memref[0] (in): Encrypted AES-256 key blob (76 bytes).
 * memref[1] (out): Wrapped key buffer (68 bytes).
 */
#define PTA_CMD_AES256_EncryptedKeyWrap (0x13020400)

/*
 * Wrap an encrypted AES-128-XTS key.
 * memref[0] (in): Encrypted AES-128-XTS key blob (76 bytes).
 * memref[1] (out): Wrapped key buffer (68 bytes).
 */
#define PTA_CMD_AES128_XTS_EncryptedKeyWrap (0x13420100)

/*
 * Wrap an encrypted AES-256-XTS key.
 * memref[0] (in): Encrypted AES-256-XTS key blob (108 bytes).
 * memref[1] (out): Wrapped key buffer (100 bytes).
 */
#define PTA_CMD_AES256_XTS_EncryptedKeyWrap (0x13420400)

/*
 * Wrap an encrypted HMAC-SHA1 key.
 * memref[0] (in): Encrypted HMAC-SHA1 key blob (76 bytes).
 * memref[1] (out): Wrapped key buffer (68 bytes).
 */
#define PTA_CMD_HMAC_SHA1_EncryptedKeyWrap (0x13160100)

/*
 * Wrap an encrypted HMAC-SHA224 key.
 * memref[0] (in): Encrypted HMAC-SHA224 key blob (76 bytes).
 * memref[1] (out): Wrapped key buffer (68 bytes).
 */
#define PTA_CMD_HMAC_SHA224_EncryptedKeyWrap (0x13260200)

/*
 * Wrap an encrypted HMAC-SHA256 key.
 * memref[0] (in): Encrypted HMAC-SHA256 key blob (76 bytes).
 * memref[1] (out): Wrapped key buffer (68 bytes).
 */
#define PTA_CMD_HMAC_SHA256_EncryptedKeyWrap (0x13360300)

/*
 * Wrap an encrypted RSA-1024 public key.
 * memref[0] (in): Encrypted RSA-1024 public key blob (188 bytes).
 * memref[1] (out): Wrapped public key buffer (180 bytes).
 */
#define PTA_CMD_RSA_1024_EncryptedPublicKeyWrap (0x13041800)

/*
 * Wrap an encrypted RSA-1024 private key.
 * memref[0] (in): Encrypted RSA-1024 private key blob (300 bytes).
 * memref[1] (out): Wrapped private key buffer (292 bytes).
 */
#define PTA_CMD_RSA_1024_EncryptedPrivateKeyWrap (0x13042800)

/*
 * Wrap an encrypted RSA-2048 public key.
 * memref[0] (in): Encrypted RSA-2048 public key blob (316 bytes).
 * memref[1] (out): Wrapped public key buffer (308 bytes).
 */
#define PTA_CMD_RSA_2048_EncryptedPublicKeyWrap (0x13041900)

/*
 * Wrap an encrypted RSA-2048 private key.
 * memref[0] (in): Encrypted RSA-2048 private key blob (556 bytes).
 * memref[1] (out): Wrapped private key buffer (548 bytes).
 */
#define PTA_CMD_RSA_2048_EncryptedPrivateKeyWrap (0x13042900)

/*
 * Wrap an encrypted RSA-3072 public key.
 * memref[0] (in): Encrypted RSA-3072 public key blob (444 bytes).
 * memref[1] (out): Wrapped public key buffer (436 bytes).
 */
#define PTA_CMD_RSA_3072_EncryptedPublicKeyWrap (0x13041A00)

/*
 * Wrap an encrypted RSA-3072 private key.
 * memref[0] (in): Encrypted RSA-3072 private key blob (812 bytes).
 * memref[1] (out): Wrapped private key buffer (804 bytes).
 */
#define PTA_CMD_RSA_3072_EncryptedPrivateKeyWrap (0x13042A00)

/*
 * Wrap an encrypted RSA-4096 public key.
 * memref[0] (in): Encrypted RSA-4096 public key blob (572 bytes).
 * memref[1] (out): Wrapped public key buffer (564 bytes).
 */
#define PTA_CMD_RSA_4096_EncryptedPublicKeyWrap (0x13041B00)

/*
 * Wrap an encrypted RSA-4096 private key.
 * memref[0] (in): Encrypted RSA-4096 private key blob (1068 bytes).
 * memref[1] (out): Wrapped private key buffer (1060 bytes).
 */
#define PTA_CMD_RSA_4096_EncryptedPrivateKeyWrap (0x13042B00)

/*
 * Wrap an encrypted secp192r1 public key.
 * memref[0] (in): Encrypted secp192r1 public key blob (108 bytes).
 * memref[1] (out): Wrapped public key buffer (100 bytes).
 */
#define PTA_CMD_ECC_secp192r1_EncryptedPublicKeyWrap (0x13151200)

/*
 * Wrap an encrypted secp192r1 private key.
 * memref[0] (in): Encrypted secp192r1 private key blob (76 bytes).
 * memref[1] (out): Wrapped private key buffer (68 bytes).
 */
#define PTA_CMD_ECC_secp192r1_EncryptedPrivateKeyWrap (0x13152200)

/*
 * Wrap an encrypted secp224r1 public key.
 * memref[0] (in): Encrypted secp224r1 public key blob (108 bytes).
 * memref[1] (out): Wrapped public key buffer (100 bytes).
 */
#define PTA_CMD_ECC_secp224r1_EncryptedPublicKeyWrap (0x13151300)

/*
 * Wrap an encrypted secp224r1 private key.
 * memref[0] (in): Encrypted secp224r1 private key blob (76 bytes).
 * memref[1] (out): Wrapped private key buffer (68 bytes).
 */
#define PTA_CMD_ECC_secp224r1_EncryptedPrivateKeyWrap (0x13152300)

/*
 * Wrap an encrypted secp256r1 public key.
 * memref[0] (in): Encrypted secp256r1 public key blob (108 bytes).
 * memref[1] (out): Wrapped public key buffer (100 bytes).
 */
#define PTA_CMD_ECC_secp256r1_EncryptedPublicKeyWrap (0x13151400)

/*
 * Wrap an encrypted secp256r1 private key.
 * memref[0] (in): Encrypted secp256r1 private key blob (76 bytes).
 * memref[1] (out): Wrapped private key buffer (68 bytes).
 */
#define PTA_CMD_ECC_secp256r1_EncryptedPrivateKeyWrap (0x13152400)

/*
 * Wrap an encrypted BrainpoolP256r1 public key.
 * memref[0] (in): Encrypted BrainpoolP256r1 public key blob (108 bytes).
 * memref[1] (out): Wrapped public key buffer (100 bytes).
 */
#define PTA_CMD_ECC_BrainpoolP256r1_EncryptedPublicKeyWrap (0x13251400)

/*
 * Wrap an encrypted BrainpoolP256r1 private key.
 * memref[0] (in): Encrypted BrainpoolP256r1 private key blob (76 bytes).
 * memref[1] (out): Wrapped private key buffer (68 bytes).
 */
#define PTA_CMD_ECC_BrainpoolP256r1_EncryptedPrivateKeyWrap (0x13252400)

/*
 * Export RSA public key parameters.
 *
 * The RSA key size is determined from the input wrapped key type.
 *
 * memref[0] (in): Wrapped RSA public key buffer.
 * memref[1] (out): RSA modulus buffer.
 *                  Required size depends on the wrapped key type:
 *                  - RSA-1024 : 128 bytes
 *                  - RSA-2048 : 256 bytes
 *                  - RSA-3072 : 384 bytes
 *                  - RSA-4096 : 512 bytes
 * memref[2] (out): RSA public exponent buffer (4 bytes).
 */
#define PTA_CMD_RSA_Public_Key_Export (0x14040000)

/*
 * Export ECC public key parameters.
 *
 * The ECC curve is determined from the input wrapped key type.
 *
 * memref[0] (in): Wrapped ECC public key buffer.
 * memref[1] (out): Public key Qx buffer.
 * memref[2] (out): Public key Qy buffer.
 *
 * Required output sizes depend on the wrapped key type:
 * - secp192r1        : 24 bytes
 * - secp224r1        : 28 bytes
 * - secp256r1        : 32 bytes
 * - brainpoolP256r1  : 32 bytes
 */
#define PTA_CMD_ECC_Public_Key_Export (0x14050000)

/*
 * Generate random data.
 * memref[0] (out): Output buffer filled with random data.
 */
#define PTA_CMD_RandomNumberGenerate (0x15000000)

#endif /* __PTA_RSIP_H */
