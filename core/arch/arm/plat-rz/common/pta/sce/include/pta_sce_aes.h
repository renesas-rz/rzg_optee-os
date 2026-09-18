/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2022-2026, Renesas Electronics Corporation
 */

#ifndef __PTA_SCE_AES_H
#define __PTA_SCE_AES_H

#define PTA_SCE_AES_UUID                                                \
	{                                                               \
		0xf45f899c, 0xdc88, 0x4181,                             \
		{                                                       \
			0xa6, 0xf1, 0x7b, 0xa7, 0x67, 0xa1, 0x1d, 0xd0, \
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

#endif /* __PTA_SCE_AES_H */
