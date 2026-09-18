/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2022-2026, Renesas Electronics Corporation
 */

#ifndef __PTA_SCE_RSA_H
#define __PTA_SCE_RSA_H

#define PTA_SCE_RSA_UUID                                                \
	{                                                               \
		0xd3fb2816, 0xe4eb, 0x4b2e,                             \
		{                                                       \
			0xb9, 0x11, 0x3b, 0xb2, 0xa3, 0x9e, 0xa8, 0xd1, \
		}                                                       \
	}

/*
 * Generate RSASSA-PKCS1-v1_5 SHA-256 signature.
 * memref[0] (in): Message buffer.
 * memref[1] (out): Signature buffer.
 *                  Length must be equal to the RSA modulus size.
 * memref[2] (in): Wrapped private key buffer.
 */
#define PTA_CMD_RSASSA_PKCS1_SHA256_Sign (0x48242030)

/*
 * Verify RSASSA-PKCS1-v1_5 SHA-256 signature.
 * memref[0] (in): Message buffer.
 * memref[1] (in): Signature buffer.
 *                 Length must be equal to the RSA modulus size.
 * memref[2] (in): Wrapped public key buffer.
 */
#define PTA_CMD_RSASSA_PKCS1_SHA256_Verify (0x48241038)

/*
 * Encrypt RSAES-PKCS1-v1_5 plaintext.
 * memref[0] (in): Plaintext buffer.
 * memref[1] (out): Ciphertext buffer.
 *                  Length must be equal to the RSA modulus size.
 * memref[2] (in): Wrapped public key buffer.
 */
#define PTA_CMD_RSAES_PKCS1_Encrypt (0x46241000)

/*
 * Decrypt RSAES-PKCS1-v1_5 ciphertext.
 * memref[0] (in): Ciphertext buffer.
 *                 Length must be equal to the RSA modulus size.
 * memref[1] (out): Plaintext buffer.
 * memref[2] (in): Wrapped private key buffer.
 */
#define PTA_CMD_RSAES_PKCS1_Decrypt (0x46242008)

#endif /* __PTA_SCE_RSA_H */
