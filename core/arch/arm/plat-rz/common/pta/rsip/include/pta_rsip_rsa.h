/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2024-2026, Renesas Electronics Corporation
 */
#ifndef __PTA_RSIP_RSA_H
#define __PTA_RSIP_RSA_H

#define PTA_RSIP_RSA_UUID                                               \
	{                                                               \
		0xb3485f45, 0xe0af, 0x427e,                             \
		{                                                       \
			0x9f, 0x3b, 0x42, 0x7f, 0x8a, 0x6e, 0x1f, 0xa8, \
		}                                                       \
	}

/*
 * The RSA key size is determined from the input wrapped key.
 *
 * RSASSA-PSS commands use:
 *   - the hash algorithm encoded in the command name
 *   - MGF1 with the same hash algorithm
 *   - a salt length equal to the hash size
 *
 * RSAES-OAEP commands use:
 *   - the hash algorithm encoded in the command name
 *   - MGF1 with the same hash algorithm
 */

/*
 * Generate RSASSA-PKCS1-v1_5 SHA-1 signature.
 * memref[0] (in): Message buffer.
 * memref[1] (out): Signature buffer.
 *                  Length must be equal to the RSA modulus size.
 * memref[2] (in): Wrapped private key buffer.
 */
#define PTA_CMD_RSASSA_PKCS1_SHA1_Sign (0x48242010)

/*
 * Verify RSASSA-PKCS1-v1_5 SHA-1 signature.
 * memref[0] (in): Message buffer.
 * memref[1] (in): Signature buffer.
 *                 Length must be equal to the RSA modulus size.
 * memref[2] (in): Wrapped public key buffer.
 */
#define PTA_CMD_RSASSA_PKCS1_SHA1_Verify (0x48241018)

/*
 * Generate RSASSA-PKCS1-v1_5 SHA-224 signature.
 * memref[0] (in): Message buffer.
 * memref[1] (out): Signature buffer.
 *                  Length must be equal to the RSA modulus size.
 * memref[2] (in): Wrapped private key buffer.
 */
#define PTA_CMD_RSASSA_PKCS1_SHA224_Sign (0x48242020)

/*
 * Verify RSASSA-PKCS1-v1_5 SHA-224 signature.
 * memref[0] (in): Message buffer.
 * memref[1] (in): Signature buffer.
 *                 Length must be equal to the RSA modulus size.
 * memref[2] (in): Wrapped public key buffer.
 */
#define PTA_CMD_RSASSA_PKCS1_SHA224_Verify (0x48241028)

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
 * Generate RSASSA-PKCS1-v1_5 SHA-384 signature.
 * memref[0] (in): Message buffer.
 * memref[1] (out): Signature buffer.
 *                  Length must be equal to the RSA modulus size.
 * memref[2] (in): Wrapped private key buffer.
 */
#define PTA_CMD_RSASSA_PKCS1_SHA384_Sign (0x48242040)

/*
 * Verify RSASSA-PKCS1-v1_5 SHA-384 signature.
 * memref[0] (in): Message buffer.
 * memref[1] (in): Signature buffer.
 *                 Length must be equal to the RSA modulus size.
 * memref[2] (in): Wrapped public key buffer.
 */
#define PTA_CMD_RSASSA_PKCS1_SHA384_Verify (0x48241048)

/*
 * Generate RSASSA-PKCS1-v1_5 SHA-512 signature.
 * memref[0] (in): Message buffer.
 * memref[1] (out): Signature buffer.
 *                  Length must be equal to the RSA modulus size.
 * memref[2] (in): Wrapped private key buffer.
 */
#define PTA_CMD_RSASSA_PKCS1_SHA512_Sign (0x48242050)

/*
 * Verify RSASSA-PKCS1-v1_5 SHA-512 signature.
 * memref[0] (in): Message buffer.
 * memref[1] (in): Signature buffer.
 *                 Length must be equal to the RSA modulus size.
 * memref[2] (in): Wrapped public key buffer.
 */
#define PTA_CMD_RSASSA_PKCS1_SHA512_Verify (0x48241058)

/*
 * Generate RSASSA-PSS SHA-1 signature.
 * memref[0] (in): Message buffer.
 * memref[1] (out): Signature buffer.
 *                  Length must be equal to the RSA modulus size.
 * memref[2] (in): Wrapped private key buffer.
 */
#define PTA_CMD_RSASSA_PSS_SHA1_Sign (0x48442010)

/*
 * Verify RSASSA-PSS SHA-1 signature.
 * memref[0] (in): Message buffer.
 * memref[1] (in): Signature buffer.
 *                 Length must be equal to the RSA modulus size.
 * memref[2] (in): Wrapped public key buffer.
 */
#define PTA_CMD_RSASSA_PSS_SHA1_Verify (0x48441018)

/*
 * Generate RSASSA-PSS SHA-224 signature.
 * memref[0] (in): Message buffer.
 * memref[1] (out): Signature buffer.
 *                  Length must be equal to the RSA modulus size.
 * memref[2] (in): Wrapped private key buffer.
 */
#define PTA_CMD_RSASSA_PSS_SHA224_Sign (0x48442020)

/*
 * Verify RSASSA-PSS SHA-224 signature.
 * memref[0] (in): Message buffer.
 * memref[1] (in): Signature buffer.
 *                 Length must be equal to the RSA modulus size.
 * memref[2] (in): Wrapped public key buffer.
 */
#define PTA_CMD_RSASSA_PSS_SHA224_Verify (0x48441028)

/*
 * Generate RSASSA-PSS SHA-256 signature.
 * memref[0] (in): Message buffer.
 * memref[1] (out): Signature buffer.
 *                  Length must be equal to the RSA modulus size.
 * memref[2] (in): Wrapped private key buffer.
 */
#define PTA_CMD_RSASSA_PSS_SHA256_Sign (0x48442030)

/*
 * Verify RSASSA-PSS SHA-256 signature.
 * memref[0] (in): Message buffer.
 * memref[1] (in): Signature buffer.
 *                 Length must be equal to the RSA modulus size.
 * memref[2] (in): Wrapped public key buffer.
 */
#define PTA_CMD_RSASSA_PSS_SHA256_Verify (0x48441038)

/*
 * Generate RSASSA-PSS SHA-384 signature.
 * memref[0] (in): Message buffer.
 * memref[1] (out): Signature buffer.
 *                  Length must be equal to the RSA modulus size.
 * memref[2] (in): Wrapped private key buffer.
 */
#define PTA_CMD_RSASSA_PSS_SHA384_Sign (0x48442040)

/*
 * Verify RSASSA-PSS SHA-384 signature.
 * memref[0] (in): Message buffer.
 * memref[1] (in): Signature buffer.
 *                 Length must be equal to the RSA modulus size.
 * memref[2] (in): Wrapped public key buffer.
 */
#define PTA_CMD_RSASSA_PSS_SHA384_Verify (0x48441048)

/*
 * Generate RSASSA-PSS SHA-512 signature.
 * memref[0] (in): Message buffer.
 * memref[1] (out): Signature buffer.
 *                  Length must be equal to the RSA modulus size.
 * memref[2] (in): Wrapped private key buffer.
 */
#define PTA_CMD_RSASSA_PSS_SHA512_Sign (0x48442050)

/*
 * Verify RSASSA-PSS SHA-512 signature.
 * memref[0] (in): Message buffer.
 * memref[1] (in): Signature buffer.
 *                 Length must be equal to the RSA modulus size.
 * memref[2] (in): Wrapped public key buffer.
 */
#define PTA_CMD_RSASSA_PSS_SHA512_Verify (0x48441058)

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

/*
 * Encrypt RSAES-OAEP SHA-1 plaintext.
 * memref[0] (in): Plaintext buffer.
 * memref[1] (out): Ciphertext buffer.
 *                  Length must be equal to the RSA modulus size.
 * memref[2] (in): Wrapped public key buffer.
 * memref[3] (in, optional): OAEP label buffer.
 */
#define PTA_CMD_RSAES_OAEP_SHA1_Encrypt (0x46341010)

/*
 * Decrypt RSAES-OAEP SHA-1 ciphertext.
 * memref[0] (in): Ciphertext buffer.
 *                 Length must be equal to the RSA modulus size.
 * memref[1] (out): Plaintext buffer.
 * memref[2] (in): Wrapped private key buffer.
 * memref[3] (in, optional): OAEP label buffer.
 */
#define PTA_CMD_RSAES_OAEP_SHA1_Decrypt (0x46342018)

/*
 * Encrypt RSAES-OAEP SHA-224 plaintext.
 * memref[0] (in): Plaintext buffer.
 * memref[1] (out): Ciphertext buffer.
 *                  Length must be equal to the RSA modulus size.
 * memref[2] (in): Wrapped public key buffer.
 * memref[3] (in, optional): OAEP label buffer.
 */
#define PTA_CMD_RSAES_OAEP_SHA224_Encrypt (0x46341020)

/*
 * Decrypt RSAES-OAEP SHA-224 ciphertext.
 * memref[0] (in): Ciphertext buffer.
 *                 Length must be equal to the RSA modulus size.
 * memref[1] (out): Plaintext buffer.
 * memref[2] (in): Wrapped private key buffer.
 * memref[3] (in, optional): OAEP label buffer.
 */
#define PTA_CMD_RSAES_OAEP_SHA224_Decrypt (0x46342028)

/*
 * Encrypt RSAES-OAEP SHA-256 plaintext.
 * memref[0] (in): Plaintext buffer.
 * memref[1] (out): Ciphertext buffer.
 *                  Length must be equal to the RSA modulus size.
 * memref[2] (in): Wrapped public key buffer.
 * memref[3] (in, optional): OAEP label buffer.
 */
#define PTA_CMD_RSAES_OAEP_SHA256_Encrypt (0x46341030)

/*
 * Decrypt RSAES-OAEP SHA-256 ciphertext.
 * memref[0] (in): Ciphertext buffer.
 *                 Length must be equal to the RSA modulus size.
 * memref[1] (out): Plaintext buffer.
 * memref[2] (in): Wrapped private key buffer.
 * memref[3] (in, optional): OAEP label buffer.
 */
#define PTA_CMD_RSAES_OAEP_SHA256_Decrypt (0x46342038)

/*
 * Encrypt RSAES-OAEP SHA-384 plaintext.
 * memref[0] (in): Plaintext buffer.
 * memref[1] (out): Ciphertext buffer.
 *                  Length must be equal to the RSA modulus size.
 * memref[2] (in): Wrapped public key buffer.
 * memref[3] (in, optional): OAEP label buffer.
 */
#define PTA_CMD_RSAES_OAEP_SHA384_Encrypt (0x46341040)

/*
 * Decrypt RSAES-OAEP SHA-384 ciphertext.
 * memref[0] (in): Ciphertext buffer.
 *                 Length must be equal to the RSA modulus size.
 * memref[1] (out): Plaintext buffer.
 * memref[2] (in): Wrapped private key buffer.
 * memref[3] (in, optional): OAEP label buffer.
 */
#define PTA_CMD_RSAES_OAEP_SHA384_Decrypt (0x46342048)

/*
 * Encrypt RSAES-OAEP SHA-512 plaintext.
 * memref[0] (in): Plaintext buffer.
 * memref[1] (out): Ciphertext buffer.
 *                  Length must be equal to the RSA modulus size.
 * memref[2] (in): Wrapped public key buffer.
 * memref[3] (in, optional): OAEP label buffer.
 */
#define PTA_CMD_RSAES_OAEP_SHA512_Encrypt (0x46341050)

/*
 * Decrypt RSAES-OAEP SHA-512 ciphertext.
 * memref[0] (in): Ciphertext buffer.
 *                 Length must be equal to the RSA modulus size.
 * memref[1] (out): Plaintext buffer.
 * memref[2] (in): Wrapped private key buffer.
 * memref[3] (in, optional): OAEP label buffer.
 */
#define PTA_CMD_RSAES_OAEP_SHA512_Decrypt (0x46342058)

/*
 * Raw RSA encryption.
 * memref[0] (in): Plaintext buffer.
 *                 Length must be:
 *                 - 1 to RSA modulus size bytes
 *                 Inputs shorter than the modulus size are left-padded with zeros.
 * memref[1] (out): Ciphertext buffer.
 *                  Length must be equal to the RSA modulus size.
 * memref[2] (in): Wrapped public key buffer.
 */
#define PTA_CMD_RSA_RAW_Encrypt (0x46141000)

/*
 * Raw RSA decryption.
 * memref[0] (in): Ciphertext buffer.
 *                 Length must be equal to the RSA modulus size.
 * memref[1] (out): Plaintext buffer.
 *                  Length must be equal to the RSA modulus size.
 * memref[2] (in): Wrapped private key buffer.
 */
#define PTA_CMD_RSA_RAW_Decrypt (0x46142008)

#endif /* __PTA_RSIP_RSA_H */
