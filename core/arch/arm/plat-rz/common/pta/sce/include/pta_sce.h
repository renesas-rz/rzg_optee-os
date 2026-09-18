/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2022-2026, Renesas Electronics Corporation
 */

#ifndef __PTA_SCE_H
#define __PTA_SCE_H

#define PTA_SCE_UUID                                                    \
	{                                                               \
		0xbd7d42dc, 0x3946, 0x49d7,                             \
		{                                                       \
			0x89, 0xbe, 0x09, 0x16, 0x63, 0x04, 0x5a, 0x26, \
		}                                                       \
	}

/*
 * Generate an AES-128 wrapped key.
 * memref[0] (out): Wrapped key buffer (68 bytes).
 */
#define PTA_CMD_AES128_WrappedKeyGenerate (0x11020100)

/*
 * Generate an AES-256 wrapped key.
 * memref[0] (out): Wrapped key buffer (68 bytes).
 */
#define PTA_CMD_AES256_WrappedKeyGenerate (0x11020400)

/*
 * Generate an RSA-1024 wrapped key pair.
 * memref[0] (out): Wrapped private key buffer (420 bytes).
 * memref[1] (out): Wrapped public key buffer (308 bytes).
 */
#define PTA_CMD_RSA_1024_WrappedKeyPairGenerate (0x12040800)

/*
 * Generate an RSA-2048 wrapped key pair.
 * memref[0] (out): Wrapped private key buffer (792 bytes).
 * memref[1] (out): Wrapped public key buffer (552 bytes).
 */
#define PTA_CMD_RSA_2048_WrappedKeyPairGenerate (0x12040900)

/*
 * Generate a secp192r1 wrapped key pair.
 * memref[0] (out): Wrapped private key buffer (100 bytes).
 * memref[1] (out): Wrapped public key buffer (164 bytes).
 */
#define PTA_CMD_ECC_secp192r1_WrappedKeyPairGenerate (0x12150200)

/*
 * Generate a secp224r1 wrapped key pair.
 * memref[0] (out): Wrapped private key buffer (100 bytes).
 * memref[1] (out): Wrapped public key buffer (164 bytes).
 */
#define PTA_CMD_ECC_secp224r1_WrappedKeyPairGenerate (0x12150300)

/*
 * Generate a secp256r1 wrapped key pair.
 * memref[0] (out): Wrapped private key buffer (100 bytes).
 * memref[1] (out): Wrapped public key buffer (164 bytes).
 */
#define PTA_CMD_ECC_secp256r1_WrappedKeyPairGenerate (0x12150400)

/*
 * Generate a BrainpoolP512r1 wrapped key pair.
 * memref[0] (out): Wrapped private key buffer (100 bytes).
 * memref[1] (out): Wrapped public key buffer (164 bytes).
 */
#define PTA_CMD_ECC_BrainpoolP512r1_WrappedKeyPairGenerate (0x12250600)

/*
 * Wrap an encrypted AES-128 key.
 * memref[0] (in): Encrypted AES-128 key blob (60 bytes).
 * memref[1] (out): Wrapped key buffer (68 bytes).
 */
#define PTA_CMD_AES128_EncryptedKeyWrap (0x13020100)

/*
 * Wrap an encrypted AES-256 key.
 * memref[0] (in): Encrypted AES-256 key blob (76 bytes).
 * memref[1] (out): Wrapped key buffer (68 bytes).
 */
#define PTA_CMD_AES256_EncryptedKeyWrap (0x13020400)
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
 * Wrap an encrypted RSA-4096 public key.
 * memref[0] (in): Encrypted RSA-4096 public key blob (572 bytes).
 * memref[1] (out): Wrapped public key buffer (540 bytes).
 */
#define PTA_CMD_RSA_4096_EncryptedPublicKeyWrap (0x13041B00)

/*
 * Wrap an encrypted secp192r1 public key.
 * memref[0] (in): Encrypted secp192r1 public key blob (108 bytes).
 * memref[1] (out): Wrapped public key buffer (164 bytes).
 */
#define PTA_CMD_ECC_secp192r1_EncryptedPublicKeyWrap (0x13151200)

/*
 * Wrap an encrypted secp192r1 private key.
 * memref[0] (in): Encrypted secp192r1 private key blob (76 bytes).
 * memref[1] (out): Wrapped private key buffer (100 bytes).
 */
#define PTA_CMD_ECC_secp192r1_EncryptedPrivateKeyWrap (0x13152200)

/*
 * Wrap an encrypted secp224r1 public key.
 * memref[0] (in): Encrypted secp224r1 public key blob (108 bytes).
 * memref[1] (out): Wrapped public key buffer (164 bytes).
 */
#define PTA_CMD_ECC_secp224r1_EncryptedPublicKeyWrap (0x13151300)

/*
 * Wrap an encrypted secp224r1 private key.
 * memref[0] (in): Encrypted secp224r1 private key blob (76 bytes).
 * memref[1] (out): Wrapped private key buffer (100 bytes).
 */
#define PTA_CMD_ECC_secp224r1_EncryptedPrivateKeyWrap (0x13152300)

/*
 * Wrap an encrypted secp256r1 public key.
 * memref[0] (in): Encrypted secp256r1 public key blob (108 bytes).
 * memref[1] (out): Wrapped public key buffer (164 bytes).
 */
#define PTA_CMD_ECC_secp256r1_EncryptedPublicKeyWrap (0x13151400)

/*
 * Wrap an encrypted secp256r1 private key.
 * memref[0] (in): Encrypted secp256r1 private key blob (76 bytes).
 * memref[1] (out): Wrapped private key buffer (100 bytes).
 */
#define PTA_CMD_ECC_secp256r1_EncryptedPrivateKeyWrap (0x13152400)

/*
 * Wrap an encrypted BrainpoolP512r1 public key.
 * memref[0] (in): Encrypted BrainpoolP512r1 public key blob (172 bytes).
 * memref[1] (out): Wrapped public key buffer (164 bytes).
 */
#define PTA_CMD_ECC_BrainpoolP512r1_EncryptedPublicKeyWrap (0x13251600)

/*
 * Wrap an encrypted BrainpoolP512r1 private key.
 * memref[0] (in): Encrypted BrainpoolP512r1 private key blob (108 bytes).
 * memref[1] (out): Wrapped private key buffer (100 bytes).
 */
#define PTA_CMD_ECC_BrainpoolP512r1_EncryptedPrivateKeyWrap (0x13252600)

/*
 * Generate random data.
 * memref[0] (out): Output buffer filled with random data.
 */
#define PTA_CMD_RandomNumberGenerate (0x15000000)

#endif /* __PTA_SCE_H */
