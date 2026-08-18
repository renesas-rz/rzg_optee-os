/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2024-2026, Renesas Electronics Corporation
 */

#ifndef __PTA_RSIP_AES_H
#define __PTA_RSIP_AES_H

#define PTA_RSIP_AES_UUID                                               \
	{                                                               \
		0xa6afb4b5, 0x3438, 0x4aeb,                             \
		{                                                       \
			0x95, 0x5c, 0xf8, 0xbb, 0x01, 0xbe, 0xad, 0x04, \
		}                                                       \
	}

/*
 * Supports AES-128 and AES-256.
 * The key size is determined from the input wrapped key type.
 */

#define AES_BLOCK_SIZE (16)
#define GCM_NONCE_SIZE (12)

/*
 * Initialize AES ECB encryption.
 * memref[0] (in): Wrapped AES key buffer.
 */
#define PTA_CMD_AES_ECB_EncryptInit (0x26120001)

/*
 * Update AES ECB encryption.
 * memref[0] (in): Plaintext buffer.
 *                 Length must be a multiple of AES_BLOCK_SIZE.
 * memref[1] (out): Ciphertext buffer.
 */
#define PTA_CMD_AES_ECB_EncryptUpdate (0x26120002)

/*
 * Finalize AES ECB encryption.
 * memref[0] (in): Final plaintext buffer.
 *                 Length must be 0 to (AES_BLOCK_SIZE - 1) bytes
 * memref[1] (out): Ciphertext buffer (AES_BLOCK_SIZE bytes).
 */
#define PTA_CMD_AES_ECB_EncryptFinal (0x26120003)

/*
 * Initialize AES ECB decryption.
 * memref[0] (in): Wrapped AES key buffer.
 */
#define PTA_CMD_AES_ECB_DecryptInit (0x26120009)

/*
 * Update AES ECB decryption.
 * memref[0] (in): Ciphertext buffer.
 *                 Length must be a multiple of AES_BLOCK_SIZE.
 * memref[1] (out): Plaintext buffer.
 */
#define PTA_CMD_AES_ECB_DecryptUpdate (0x2612000A)

/*
 * Finalize AES ECB decryption.
 * memref[0] (in): Final ciphertext buffer.
 *                 Length must be 0 or AES_BLOCK_SIZE bytes
 * memref[1] (out): Plaintext buffer.
 */
#define PTA_CMD_AES_ECB_DecryptFinal (0x2612000B)

/*
 * Initialize AES CBC encryption.
 * memref[0] (in): Wrapped AES key buffer.
 * memref[1] (out): Generated initialization vector (16 bytes).
 */
#define PTA_CMD_AES_CBC_EncryptInit (0x26220001)

/*
 * Update AES CBC encryption.
 * memref[0] (in): Plaintext buffer.
 *                 Length must be a multiple of AES_BLOCK_SIZE.
 * memref[1] (out): Ciphertext buffer.
 */
#define PTA_CMD_AES_CBC_EncryptUpdate (0x26220002)

/*
 * Finalize AES CBC encryption.
 * memref[0] (in): Final plaintext buffer.
 *                 Length must be 0 to (AES_BLOCK_SIZE - 1) bytes
 * memref[1] (out): Ciphertext buffer (AES_BLOCK_SIZE bytes).
 */
#define PTA_CMD_AES_CBC_EncryptFinal (0x26220003)

/*
 * Initialize AES CBC decryption.
 * memref[0] (in): Wrapped AES key buffer.
 * memref[1] (in): Initialization vector (16 bytes).
 */
#define PTA_CMD_AES_CBC_DecryptInit (0x26220009)

/*
 * Update AES CBC decryption.
 * memref[0] (in): Ciphertext buffer.
 *                 Length must be a multiple of AES_BLOCK_SIZE.
 * memref[1] (out): Plaintext buffer.
 */
#define PTA_CMD_AES_CBC_DecryptUpdate (0x2622000A)

/*
 * Finalize AES CBC decryption.
 * memref[0] (in): Final ciphertext buffer.
 *                 Length must be 0 or AES_BLOCK_SIZE bytes
 * memref[1] (out): Plaintext buffer.
 */
#define PTA_CMD_AES_CBC_DecryptFinal (0x2622000B)

/*
 * Initialize AES CTR encryption.
 * memref[0] (in): Wrapped AES key buffer.
 * memref[1] (out): Generated initialization vector (16 bytes).
 */
#define PTA_CMD_AES_CTR_EncryptInit (0x26320001)

/*
 * Update AES CTR encryption.
 * memref[0] (in): Plaintext buffer.
 *                 Length must be a multiple of AES_BLOCK_SIZE.
 * memref[1] (out): Ciphertext buffer.
 */
#define PTA_CMD_AES_CTR_EncryptUpdate (0x26320002)

/*
 * Finalize AES CTR encryption.
 * memref[0] (in): Final plaintext buffer.
 *                 Length must be 0 to (AES_BLOCK_SIZE - 1) bytes
 * memref[1] (out): Ciphertext buffer.
 */
#define PTA_CMD_AES_CTR_EncryptFinal (0x26320003)

/*
 * Initialize AES CTR decryption.
 * memref[0] (in): Wrapped AES key buffer.
 * memref[1] (in): Initialization vector (16 bytes).
 */
#define PTA_CMD_AES_CTR_DecryptInit (0x26320009)

/*
 * Update AES CTR decryption.
 * memref[0] (in): Ciphertext buffer.
 *                 Length must be a multiple of AES_BLOCK_SIZE.
 * memref[1] (out): Plaintext buffer.
 */
#define PTA_CMD_AES_CTR_DecryptUpdate (0x2632000A)

/*
 * Finalize AES CTR decryption.
 * memref[0] (in): Final ciphertext buffer.
 *                 Length must be 0 to AES_BLOCK_SIZE bytes
 * memref[1] (out): Plaintext buffer.
 */
#define PTA_CMD_AES_CTR_DecryptFinal (0x2632000B)

/*
 * Initialize AES XTS encryption.
 * memref[0] (in): Wrapped AES-XTS key buffer (68 bytes).
 * memref[1] (in): Tweak buffer (16 bytes).
 */
#define PTA_CMD_AES_XTS_EncryptInit (0x26420001)

/*
 * Update AES XTS encryption.
 * memref[0] (in): Plaintext buffer.
 * memref[1] (out): Ciphertext buffer.
 */
#define PTA_CMD_AES_XTS_EncryptUpdate (0x26420002)

/*
 * Finalize AES XTS encryption.
 * memref[0] (in): Final plaintext buffer.
 *                 Length must be:
 *                 - 0 or
 *                 - AES_BLOCK_SIZE + 1 to (2 * AES_BLOCK_SIZE - 1) bytes
 * memref[1] (out): Ciphertext buffer.
 */
#define PTA_CMD_AES_XTS_EncryptFinal (0x26420003)

/*
 * Initialize AES XTS decryption.
 * memref[0] (in): Wrapped AES-XTS key buffer (68 bytes).
 * memref[1] (in): Tweak buffer (16 bytes).
 */
#define PTA_CMD_AES_XTS_DecryptInit (0x26420009)

/*
 * Update AES XTS decryption.
 * memref[0] (in): Ciphertext buffer.
 * memref[1] (out): Plaintext buffer.
 */
#define PTA_CMD_AES_XTS_DecryptUpdate (0x2642000A)

/*
 * Finalize AES XTS decryption.
 * memref[0] (in): Final ciphertext buffer.
 *                 Length must be:
 *                 - 0, or
 *                 - AES_BLOCK_SIZE + 1 to (2 * AES_BLOCK_SIZE - 1) bytes
 * memref[1] (out): Plaintext buffer.
 */
#define PTA_CMD_AES_XTS_DecryptFinal (0x2642000B)

/*
 * Initialize AES GCM encryption.
 * memref[0] (in): Wrapped AES key buffer.
 * memref[1] (in): Generated nonce (PTA_GCM_NONCE_SIZE bytes).
 */
#define PTA_CMD_AES_GCM_EncryptInit (0x26520001)

/*
 * AAD Update AES GCM encryption.
 * memref[0] (in): AAD buffer.
 *                 Length must be a multiple of AES_BLOCK_SIZE.
 */
#define PTA_CMD_AES_GCM_EncryptAADUpdate (0x26520002)

/*
 * AAD Final AES GCM encryption.
 * memref[0] (in): Final AAD buffer.
 *                 Length must be 0 to (AES_BLOCK_SIZE - 1) bytes
 */
#define PTA_CMD_AES_GCM_EncryptAADFinal (0x26520003)

/*
 * Update AES GCM encryption.
 * memref[0] (in): Plaintext buffer.
 *                 Length must be a multiple of AES_BLOCK_SIZE.
 * memref[1] (out): Ciphertext buffer.
 */
#define PTA_CMD_AES_GCM_EncryptUpdate (0x26520004)

/*
 * Finalize AES GCM encryption.
 * memref[0] (in): Final plaintext buffer.
 *                 Length must be 0 to (AES_BLOCK_SIZE - 1) bytes
 * memref[1] (out): Ciphertext buffer.
 * memref[2] (out): Authentication tag buffer (16 bytes).
 */
#define PTA_CMD_AES_GCM_EncryptFinal (0x26520005)

/*
 * Initialize AES GCM decryption.
 * memref[0] (in): Wrapped AES key buffer.
 * memref[1] (in): Nonce.
 */
#define PTA_CMD_AES_GCM_DecryptInit (0x26520009)

/*
 * AAD Update AES GCM decryption.
 * memref[0] (in): AAD buffer.
 *                 Length must be a multiple of AES_BLOCK_SIZE.
 */
#define PTA_CMD_AES_GCM_DecryptAADUpdate (0x2652000A)

/*
 * AAD Final AES GCM decryption.
 * memref[0] (in): Final AAD buffer.
 *                 Length must be 0 to (AES_BLOCK_SIZE - 1) bytes
 */
#define PTA_CMD_AES_GCM_DecryptAADFinal (0x2652000B)

/*
 * Update AES GCM decryption.
 * memref[0] (in): Ciphertext buffer.
 *                 Length must be a multiple of AES_BLOCK_SIZE.
 * memref[1] (out): Plaintext buffer.
 */
#define PTA_CMD_AES_GCM_DecryptUpdate (0x2652000C)

/*
 * Finalize AES GCM decryption.
 * memref[0] (in): Final ciphertext buffer.
 *                 Length must be 0 to (AES_BLOCK_SIZE - 1) bytes
 * memref[1] (out): Plaintext buffer.
 * memref[2] (in): Authentication tag buffer (1 to 16 bytes).
 */
#define PTA_CMD_AES_GCM_DecryptFinal (0x2652000D)

/*
 * Initialize AES CMAC generation.
 * memref[0] (in): Wrapped AES key buffer.
 */
#define PTA_CMD_AES_CMAC_GenerateInit (0x27820001)

/*
 * Update AES CMAC generation.
 * memref[0] (in): Message buffer.
 *                 Length must be a multiple of AES_BLOCK_SIZE.
 */
#define PTA_CMD_AES_CMAC_GenerateUpdate (0x27820002)

/*
 * Finalize AES CMAC generation.
 * memref[0] (in): Final message buffer.
 *                 Length must be 0 to (AES_BLOCK_SIZE - 1) bytes
 * memref[1] (out): MAC buffer (16 bytes).
 */
#define PTA_CMD_AES_CMAC_GenerateFinal (0x27820003)

/*
 * Initialize AES CMAC verification.
 * memref[0] (in): Wrapped AES key buffer.
 */
#define PTA_CMD_AES_CMAC_VerifyInit (0x27820009)

/*
 * Update AES CMAC verification.
 * memref[0] (in): Message buffer.
 *                 Length must be a multiple of AES_BLOCK_SIZE.
 */
#define PTA_CMD_AES_CMAC_VerifyUpdate (0x2782000A)

/*
 * Finalize AES CMAC verification.
 * memref[0] (in): Final message buffer.
 *                 Length must be 0 to (AES_BLOCK_SIZE - 1) bytes
 * memref[1] (in): MAC buffer (2 to 16 bytes).
 */
#define PTA_CMD_AES_CMAC_VerifyFinal (0x2782000B)

#endif /* __PTA_RSIP_AES_H */
