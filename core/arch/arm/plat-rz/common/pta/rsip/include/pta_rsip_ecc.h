/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2024-2026, Renesas Electronics Corporation
 */

#ifndef __PTA_RSIP_ECC_H
#define __PTA_RSIP_ECC_H

#define PTA_RSIP_ECC_UUID                                               \
	{                                                               \
		0xc9fa39b6, 0xecb9, 0x43fe,                             \
		{                                                       \
			0x8d, 0xd2, 0x5b, 0x31, 0x67, 0x71, 0xc5, 0x59, \
		}                                                       \
	}

/*
 * Generate ECDSA secp192r1 signature.
 * memref[0] (in): Hash buffer.
 *                 Length must be 24 bytes.
 * memref[1] (out): Signature buffer.
 *                  Length must be 48 bytes.
 * memref[2] (in): Wrapped private key buffer.
 *                 Length must be 68 bytes.
 */
#define PTA_CMD_ECDSA_secp192r1_SignatureGenerate (0x58152200)

/*
 * Verify ECDSA secp192r1 signature.
 * memref[0] (in): Hash buffer.
 *                 Length must be 24 bytes.
 * memref[1] (in): Signature buffer.
 *                 Length must be 48 bytes.
 * memref[2] (in): Wrapped public key buffer.
 *                 Length must be 100 bytes.
 */
#define PTA_CMD_ECDSA_secp192r1_SignatureVerify (0x58151208)

/*
 * Generate ECDSA secp224r1 signature.
 * memref[0] (in): Hash buffer.
 *                 Length must be 28 bytes.
 * memref[1] (out): Signature buffer.
 *                  Length must be 56 bytes.
 * memref[2] (in): Wrapped private key buffer.
 *                 Length must be 68 bytes.
 */
#define PTA_CMD_ECDSA_secp224r1_SignatureGenerate (0x58152300)

/*
 * Verify ECDSA secp224r1 signature.
 * memref[0] (in): Hash buffer.
 *                 Length must be 28 bytes.
 * memref[1] (in): Signature buffer.
 *                 Length must be 56 bytes.
 * memref[2] (in): Wrapped public key buffer.
 *                 Length must be 100 bytes.
 */
#define PTA_CMD_ECDSA_secp224r1_SignatureVerify (0x58151308)

/*
 * Generate ECDSA secp256r1 signature.
 * memref[0] (in): Hash buffer.
 *                 Length must be 32 bytes.
 * memref[1] (out): Signature buffer.
 *                  Length must be 64 bytes.
 * memref[2] (in): Wrapped private key buffer.
 *                 Length must be 68 bytes.
 */
#define PTA_CMD_ECDSA_secp256r1_SignatureGenerate (0x58152400)

/*
 * Verify ECDSA secp256r1 signature.
 * memref[0] (in): Hash buffer.
 *                 Length must be 32 bytes.
 * memref[1] (in): Signature buffer.
 *                 Length must be 64 bytes.
 * memref[2] (in): Wrapped public key buffer.
 *                 Length must be 100 bytes.
 */
#define PTA_CMD_ECDSA_secp256r1_SignatureVerify (0x58151408)

/*
 * Generate ECDSA BrainpoolP256r1 signature.
 * memref[0] (in): Hash buffer.
 *                 Length must be 32 bytes.
 * memref[1] (out): Signature buffer.
 *                  Length must be 64 bytes.
 * memref[2] (in): Wrapped private key buffer.
 *                 Length must be 68 bytes.
 */
#define PTA_CMD_ECDSA_BrainpoolP256r1_SignatureGenerate (0x58252400)

/*
 * Verify ECDSA BrainpoolP256r1 signature.
 * memref[0] (in): Hash buffer.
 *                 Length must be 32 bytes.
 * memref[1] (in): Signature buffer.
 *                 Length must be 64 bytes.
 * memref[2] (in): Wrapped public key buffer.
 *                 Length must be 100 bytes.
 */
#define PTA_CMD_ECDSA_BrainpoolP256r1_SignatureVerify (0x58251408)

#endif /* __PTA_RSIP_ECC_H */
