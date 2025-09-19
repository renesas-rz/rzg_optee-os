/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2022, Renesas Electronics Corporation
 */

#ifndef __PTA_SCE_H
#define __PTA_SCE_H

#include <r_sce_api.h>

#define PTA_SCE_UUID  \
	{ 0x3b221d77, 0xe679, 0x4ca5, \
		{ 0xa4, 0x48, 0x1f, 0x9f, 0x16, 0x02, 0x15, 0xc5 } }

/*
 * [in/out] memref[0] : Wrapped key (sce_aes_wrapped_key_t)
 */
#define PTA_CMD_AES128_WrappedKeyGenerate                   (0x00010000)

/*
 * [in/out] memref[0] : Wrapped key (sce_aes_wrapped_key_t)
 */
#define PTA_CMD_AES256_WrappedKeyGenerate                   (0x00010100)

/*
 * [in/out] memref[0] : Wrapped key (sce_rsa1024_wrapped_pair_key_t)
 */
#define PTA_CMD_RSA1024_WrappedKeyPairGenerate              (0x00011000)

/*
 * [in/out] memref[0] : Wrapped key (sce_rsa2048_wrapped_pair_key_t)
 */
#define PTA_CMD_RSA2048_WrappedKeyPairGenerate              (0x00011100)

/*
 * [in/out] memref[0] : Wrapped key (sce_ecc_wrapped_pair_key_t)
 */
#define PTA_CMD_ECC_secp192r1_WrappedKeyPairGenerate        (0x00012000)

/*
 * [in/out] memref[0] : Wrapped key (sce_ecc_wrapped_pair_key_t)
 */
#define PTA_CMD_ECC_secp224r1_WrappedKeyPairGenerate        (0x00012100)

/*
 * [in/out] memref[0] : Wrapped key (sce_ecc_wrapped_pair_key_t)
 */
#define PTA_CMD_ECC_secp256r1_WrappedKeyPairGenerate        (0x00012200)

/*
 * [in/out] memref[0] : Wrapped key (sce_ecc_wrapped_pair_key_t)
 */
#define PTA_CMD_ECC_BrainpoolP512r1_WrappedKeyPairGenerate  (0x00013000)

/*
 * [in/out] memref[0] : random data (16byte)
 */
#define PTA_CMD_RandomNumberGenerate                        (0x00014000)

/*
 * [in]     memref[0] : Encrypted Key (st_encrypted_aes128_key_t)
 * [in/out] memref[1] : Wrapped key (sce_aes_wrapped_key_t)
 */
typedef struct {
	uint32_t unused[2];
	uint8_t  initial_vector[16];
	uint8_t  encrypted_user_key[32];
	uint8_t  crc[4];
} st_encrypted_aes128_key_t;
#define PTA_CMD_AES128_EncryptedKeyWrap                     (0x00015000)

/*
 * [in]     memref[0] : Encrypted Key (st_encrypted_aes256_key_t)
 * [in/out] memref[1] : Wrapped key (sce_aes_wrapped_key_t)
 */
typedef struct {
	uint32_t unused[2];
	uint8_t  initial_vector[16];
	uint8_t  encrypted_user_key[48];
	uint8_t  crc[4];
} st_encrypted_aes256_key_t;
#define PTA_CMD_AES256_EncryptedKeyWrap                     (0x00015100)

/*
 * [in]     memref[0] : Encrypted Key (st_encrypted_rsa_1024_public_key_t)
 * [in/out] memref[1] : Wrapped key (sce_rsa1024_public_wrapped_key_t)
 */
typedef struct {
	uint32_t unused[2];
	uint8_t  initial_vector[16];
	uint8_t  encrypted_user_key[160];
	uint8_t  crc[4];
} st_encrypted_rsa_1024_public_key_t;
#define PTA_CMD_RSA1024_EncryptedPublicKeyWrap              (0x00016000)

/*
 * [in]     memref[0] : Encrypted Key (st_encrypted_rsa_1024_private_key_t)
 * [in/out] memref[1] : Wrapped key (sce_rsa1024_private_wrapped_key_t)
 */
typedef struct {
	uint32_t unused[2];
	uint8_t  initial_vector[16];
	uint8_t  encrypted_user_key[272];
	uint8_t  crc[4];
} st_encrypted_rsa_1024_private_key_t;
#define PTA_CMD_RSA1024_EncryptedPrivateKeyWrap             (0x00016010)

/*
 * [in]     memref[0] : Encrypted Key (st_encrypted_rsa_2048_public_key_t)
 * [in/out] memref[1] : Wrapped key (sce_rsa2048_public_wrapped_key_t)
 */
typedef struct {
	uint32_t unused[2];
	uint8_t  initial_vector[16];
	uint8_t  encrypted_user_key[288];
	uint8_t  crc[4];
} st_encrypted_rsa_2048_public_key_t;
#define PTA_CMD_RSA2048_EncryptedPublicKeyWrap              (0x00016100)

/*
 * [in]     memref[0] : Encrypted Key (st_encrypted_rsa_2048_private_key_t)
 * [in/out] memref[1] : Wrapped key (sce_rsa2048_private_wrapped_key_t)
 */
typedef struct {
	uint32_t unused[2];
	uint8_t  initial_vector[16];
	uint8_t  encrypted_user_key[528];
	uint8_t  crc[4];
} st_encrypted_rsa_2048_private_key_t;
#define PTA_CMD_RSA2048_EncryptedPrivateKeyWrap             (0x00016110)

/*
 * [in]     memref[0] : Encrypted Key (st_encrypted_rsa_4096_public_key_t)
 * [in/out] memref[1] : Wrapped key (sce_rsa4096_public_wrapped_key_t)
 */
typedef struct {
	uint32_t unused[2];
	uint8_t  initial_vector[16];
	uint8_t  encrypted_user_key[544];
	uint8_t  crc[4];
} st_encrypted_rsa_4096_public_key_t;
#define PTA_CMD_RSA4096_EncryptedPublicKeyWrap              (0x00016200)

/*
 * [in]     memref[0] : Encrypted Key (st_encrypted_ecc_secp192r1_public_key_t)
 * [in/out] memref[1] : Wrapped key (sce_ecc_public_wrapped_key_t)
 */
typedef struct {
	uint32_t unused[2];
	uint8_t  initial_vector[16];
	uint8_t  encrypted_user_key[80];
	uint8_t  crc[4];
} st_encrypted_ecc_secp192r1_public_key_t;
#define PTA_CMD_ECC_secp192r1_EncryptedPublicKeyWrap        (0x00017000)

/*
 * [in]     memref[0] : Encrypted Key (st_encrypted_ecc_secp192r1_private_key_t)
 * [in/out] memref[1] : Wrapped key (sce_ecc_private_wrapped_key_t)
 */
typedef struct {
	uint32_t unused[2];
	uint8_t  initial_vector[16];
	uint8_t  encrypted_user_key[48];
	uint8_t  crc[4];
} st_encrypted_ecc_secp192r1_private_key_t;
#define PTA_CMD_ECC_secp192r1_EncryptedPrivateKeyWrap       (0x00017010)

/*
 * [in]     memref[0] : Encrypted Key (st_encrypted_ecc_secp224r1_public_key_t)
 * [in/out] memref[1] : Wrapped key (sce_ecc_public_wrapped_key_t)
 */
typedef struct {
	uint32_t unused[2];
	uint8_t  initial_vector[16];
	uint8_t  encrypted_user_key[80];
	uint8_t  crc[4];
} st_encrypted_ecc_secp224r1_public_key_t;
#define PTA_CMD_ECC_secp224r1_EncryptedPublicKeyWrap        (0x00017100)

/*
 * [in]     memref[0] : Encrypted Key (st_encrypted_ecc_secp224r1_private_key_t)
 * [in/out] memref[1] : Wrapped key (sce_ecc_private_wrapped_key_t)
 */
typedef struct {
	uint32_t unused[2];
	uint8_t  initial_vector[16];
	uint8_t  encrypted_user_key[48];
	uint8_t  crc[4];
} st_encrypted_ecc_secp224r1_private_key_t;
#define PTA_CMD_ECC_secp224r1_EncryptedPrivateKeyWrap       (0x00017110)

/*
 * [in]     memref[0] : Encrypted Key (st_encrypted_ecc_secp256r1_public_key_t)
 * [in/out] memref[1] : Wrapped key (sce_ecc_public_wrapped_key_t)
 */
typedef struct {
	uint32_t unused[2];
	uint8_t  initial_vector[16];
	uint8_t  encrypted_user_key[80];
	uint8_t  crc[4];
} st_encrypted_ecc_secp256r1_public_key_t;
#define PTA_CMD_ECC_secp256r1_EncryptedPublicKeyWrap        (0x00017200)

/*
 * [in]     memref[0] : Encrypted Key (st_encrypted_ecc_secp256r1_private_key_t)
 * [in/out] memref[1] : Wrapped key (sce_ecc_private_wrapped_key_t)
 */
typedef struct {
	uint32_t unused[2];
	uint8_t  initial_vector[16];
	uint8_t  encrypted_user_key[48];
	uint8_t  crc[4];
} st_encrypted_ecc_secp256r1_private_key_t;
#define PTA_CMD_ECC_secp256r1_EncryptedPrivateKeyWrap       (0x00017210)

/*
 * [in]     memref[0] : Encrypted Key (st_encrypted_ecc_brainpoolp512r1_public_key_t)
 * [in/out] memref[1] : Wrapped key (sce_ecc_public_wrapped_key_t)
 */
typedef struct {
	uint32_t unused[2];
	uint8_t  initial_vector[16];
	uint8_t  encrypted_user_key[144];
	uint8_t  crc[4];
} st_encrypted_ecc_brainpoolp512r1_public_key_t;
#define PTA_CMD_ECC_BrainpoolP512r1_EncryptedPublicKeyWrap  (0x00018000)

/*
 * [in]     memref[0] : Encrypted Key (st_encrypted_ecc_brainpoolp512r1_private_key_t)
 * [in/out] memref[1] : Wrapped key (sce_ecc_private_wrapped_key_t)
 */
typedef struct {
	uint32_t unused[2];
	uint8_t  initial_vector[16];
	uint8_t  encrypted_user_key[80];
	uint8_t  crc[4];
} st_encrypted_ecc_brainpoolp512r1_private_key_t;
#define PTA_CMD_ECC_BrainpoolP512r1_EncryptedPrivateKeyWrap (0x00018010)

#endif /* __PTA_SCE_H */
