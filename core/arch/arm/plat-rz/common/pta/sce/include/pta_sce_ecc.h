/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2022-2026, Renesas Electronics Corporation
 */

#ifndef __PTA_SCE_ECC_H
#define __PTA_SCE_ECC_H

#define PTA_SCE_ECC_UUID                                                \
	{                                                               \
		0x39e9043e, 0x3e80, 0x4a3c,                             \
		{                                                       \
			0x8a, 0x67, 0x6c, 0xb9, 0xc9, 0x0d, 0x27, 0xb3, \
		}                                                       \
	}

/*
 * Generate ECDSA secp192r1 signature.
 * memref[0] (in): Hash buffer.
 *                 Length must be 24 bytes.
 * memref[1] (out): Signature buffer.
 *                  Length must be 48 bytes.
 * memref[2] (in): Wrapped private key buffer.
 *                 Length must be 100 bytes.
 */
#define PTA_CMD_ECDSA_secp192r1_SignatureGenerate (0x58152200)

/*
 * Verify ECDSA secp192r1 signature.
 * memref[0] (in): Hash buffer.
 *                 Length must be 24 bytes.
 * memref[1] (in): Signature buffer.
 *                 Length must be 48 bytes.
 * memref[2] (in): Wrapped public key buffer.
 *                 Length must be 164 bytes.
 */
#define PTA_CMD_ECDSA_secp192r1_SignatureVerify (0x58151208)

/*
 * Generate ECDSA secp224r1 signature.
 * memref[0] (in): Hash buffer.
 *                 Length must be 28 bytes.
 * memref[1] (out): Signature buffer.
 *                  Length must be 56 bytes.
 * memref[2] (in): Wrapped private key buffer.
 *                 Length must be 100 bytes.
 */
#define PTA_CMD_ECDSA_secp224r1_SignatureGenerate (0x58152300)

/*
 * Verify ECDSA secp224r1 signature.
 * memref[0] (in): Hash buffer.
 *                 Length must be 28 bytes.
 * memref[1] (in): Signature buffer.
 *                 Length must be 56 bytes.
 * memref[2] (in): Wrapped public key buffer.
 *                 Length must be 164 bytes.
 */
#define PTA_CMD_ECDSA_secp224r1_SignatureVerify (0x58151308)

/*
 * Generate ECDSA secp256r1 signature.
 * memref[0] (in): Hash buffer.
 *                 Length must be 32 bytes.
 * memref[1] (out): Signature buffer.
 *                  Length must be 64 bytes.
 * memref[2] (in): Wrapped private key buffer.
 *                 Length must be 100 bytes.
 */
#define PTA_CMD_ECDSA_secp256r1_SignatureGenerate (0x58152400)

/*
 * Verify ECDSA secp256r1 signature.
 * memref[0] (in): Hash buffer.
 *                 Length must be 32 bytes.
 * memref[1] (in): Signature buffer.
 *                 Length must be 64 bytes.
 * memref[2] (in): Wrapped public key buffer.
 *                 Length must be 164 bytes.
 */
#define PTA_CMD_ECDSA_secp256r1_SignatureVerify (0x58151408)

/*
 * Generate ECDSA BrainpoolP512r1 signature.
 * memref[0] (in): Hash buffer.
 *                 Length must be 64 bytes.
 * memref[1] (out): Signature buffer.
 *                  Length must be 128 bytes.
 * memref[2] (in): Wrapped private key buffer.
 *                 Length must be 100 bytes.
 */
#define PTA_CMD_ECDSA_BrainpoolP512r1_SignatureGenerate (0x58252600)

/*
 * Verify ECDSA BrainpoolP512r1 signature.
 * memref[0] (in): Hash buffer.
 *                 Length must be 64 bytes.
 * memref[1] (in): Signature buffer.
 *                 Length must be 128 bytes.
 * memref[2] (in): Wrapped public key buffer.
 *                 Length must be 164 bytes.
 */
#define PTA_CMD_ECDSA_BrainpoolP512r1_SignatureVerify (0x58251608)

#endif /* __PTA_SCE_ECC_H */
