/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2024, Renesas Electronics Corporation
 */

#ifndef __PTA_RSIP_H
#define __PTA_RSIP_H

#include <r_rsip_api.h>

#define PTA_RSIP_UUID  \
	{ 0xc0bcc4d4, 0x5b01, 0x46e7, \
		{ 0xa1, 0x11, 0xc2, 0x9b, 0x28, 0xd8, 0x3d, 0xa0 } }

#define WRAPPED_KEY_BYTE_SIZE_RSA_1024_PUBLIC_N               128U  ///< RSA-1024 public key
#define WRAPPED_KEY_BYTE_SIZE_RSA_1024_PUBLIC_E               4U    ///< RSA-1024 public key
#define WRAPPED_KEY_BYTE_SIZE_RSA_2048_PUBLIC_N               256U  ///< RSA-2048 public key
#define WRAPPED_KEY_BYTE_SIZE_RSA_2048_PUBLIC_E               4U    ///< RSA-2048 public key
#define WRAPPED_KEY_BYTE_SIZE_RSA_3072_PUBLIC_N               384U  ///< RSA-3072 public key
#define WRAPPED_KEY_BYTE_SIZE_RSA_3072_PUBLIC_E               4U    ///< RSA-3072 public key
#define WRAPPED_KEY_BYTE_SIZE_RSA_4096_PUBLIC_N               512U  ///< RSA-4096 public key
#define WRAPPED_KEY_BYTE_SIZE_RSA_4096_PUBLIC_E               4U    ///< RSA-4096 public key

#define WRAPPED_KEY_BYTE_SIZE_ECC_secp192r1_PUBLIC_QX         24U   ///< secp192r1 public key
#define WRAPPED_KEY_BYTE_SIZE_ECC_secp192r1_PUBLIC_QY         24U   ///< secp192r1 public key
#define WRAPPED_KEY_BYTE_SIZE_ECC_secp224r1_PUBLIC_QX         28U   ///< secp224r1 public key
#define WRAPPED_KEY_BYTE_SIZE_ECC_secp224r1_PUBLIC_QY         28U   ///< secp224r1 public key
#define WRAPPED_KEY_BYTE_SIZE_ECC_secp256r1_PUBLIC_QX         32U   ///< secp256r1 public key
#define WRAPPED_KEY_BYTE_SIZE_ECC_secp256r1_PUBLIC_QY         32U   ///< secp256r1 public key
#define WRAPPED_KEY_BYTE_SIZE_ECC_BRAINPOOLP256R1_PUBLIC_QX   32U   ///< brainpoolP256r1 public key
#define WRAPPED_KEY_BYTE_SIZE_ECC_BRAINPOOLP256R1_PUBLIC_QY   32U   ///< brainpoolP256r1 public key

/*
 * [in/out]    memref[0] : Wrapped key (rsip_wrapped_key_t:52byte)
 */
#define PTA_CMD_AES128_WrappedKeyGenerate                   (0x00010000)

/*
 * [in/out]    memref[0] : Wrapped key (rsip_wrapped_key_t:68byte)
 */
#define PTA_CMD_AES256_WrappedKeyGenerate                   (0x00010100)

/*
 * [in/out]    memref[0] : Wrapped key (rsip_wrapped_key_t:68byte)
 */
#define PTA_CMD_AES128_XTS_WrappedKeyGenerate               (0x00010200)

/*
 * [in/out]    memref[0] : Wrapped key (rsip_wrapped_key_t:100byte)
 */
#define PTA_CMD_AES256_XTS_WrappedKeyGenerate               (0x00010300)

/*
 * [in/out]    memref[0] : Wrapped Public  key (rsip_wrapped_key_t:180byte)
 * [in/out]    memref[1] : Wrapped Private key (rsip_wrapped_key_t:292byte)
 */
#define PTA_CMD_RSA1024_WrappedKeyPairGenerate              (0x00011000)

/*
 * [in/out]    memref[0] : Wrapped Public  key (rsip_wrapped_key_t:308byte)
 * [in/out]    memref[1] : Wrapped Private key (rsip_wrapped_key_t:548byte)
 */
#define PTA_CMD_RSA2048_WrappedKeyPairGenerate              (0x00011100)

/*
 * [in/out]    memref[0] : Wrapped Public  key (rsip_wrapped_key_t:436byte)
 * [in/out]    memref[1] : Wrapped Private key (rsip_wrapped_key_t:804byte)
 */
#define PTA_CMD_RSA3072_WrappedKeyPairGenerate              (0x00011200)

/*
 * [in/out]    memref[0] : Wrapped Public  key (rsip_wrapped_key_t:564byte)
 * [in/out]    memref[1] : Wrapped Private key (rsip_wrapped_key_t:1060byte)
 */
#define PTA_CMD_RSA4096_WrappedKeyPairGenerate              (0x00011300)

/*
 * [in/out]    memref[0] : Wrapped Public  key (rsip_wrapped_key_t:100byte)
 * [in/out]    memref[1] : Wrapped Private key (rsip_wrapped_key_t:68byte)
 */
#define PTA_CMD_ECC_secp192r1_WrappedKeyPairGenerate        (0x00012000)

/*
 * [in/out]    memref[0] : Wrapped Public  key (rsip_wrapped_key_t:100byte)
 * [in/out]    memref[1] : Wrapped Private key (rsip_wrapped_key_t:68byte)
 */
#define PTA_CMD_ECC_secp224r1_WrappedKeyPairGenerate        (0x00012100)

/*
 * [in/out]    memref[0] : Wrapped Public  key (rsip_wrapped_key_t:100byte)
 * [in/out]    memref[1] : Wrapped Private key (rsip_wrapped_key_t:68byte)
 */
#define PTA_CMD_ECC_secp256r1_WrappedKeyPairGenerate        (0x00012200)

/*
 * [in/out]    memref[0] : Wrapped Public  key (rsip_wrapped_key_t:100byte)
 * [in/out]    memref[1] : Wrapped Private key (rsip_wrapped_key_t:68byte)
 */
#define PTA_CMD_ECC_BrainpoolP256r1_WrappedKeyPairGenerate  (0x0001D000)

/*
 * [in/out]    memref[0] : random data (16byte)
 */
#define PTA_CMD_RandomNumberGenerate                        (0x00014000)

/*
 * [in]        memref[0] : Encrypted Key (st_encrypted_aes128_key_t)
 * [in/out]    memref[1] : Wrapped key (rsip_wrapped_key_t:52byte)
 */
typedef struct {
	uint32_t unused[2];
	uint8_t  initial_vector[16];
	uint8_t  encrypted_user_key[32];
	uint8_t  crc[4];
} st_encrypted_aes128_key_t;
#define PTA_CMD_AES128_EncryptedKeyWrap                     (0x00015000)

/*
 * [in]        memref[0] : Encrypted Key (st_encrypted_aes256_key_t)
 * [in/out]    memref[1] : Wrapped key (rsip_wrapped_key_t:68byte)
 */
typedef struct {
	uint32_t unused[2];
	uint8_t  initial_vector[16];
	uint8_t  encrypted_user_key[48];
	uint8_t  crc[4];
} st_encrypted_aes256_key_t;
#define PTA_CMD_AES256_EncryptedKeyWrap                     (0x00015100)

/*
 * [in]        memref[0] : Encrypted Key (st_encrypted_aes128xts_key_t)
 * [in/out]    memref[1] : Wrapped key (rsip_wrapped_key_t:68byte)
 */
typedef struct {
	uint32_t unused[2];
	uint8_t  initial_vector[16];
	uint8_t  encrypted_user_key[48];
	uint8_t  crc[4];
} st_encrypted_aes128xts_key_t;
#define PTA_CMD_AES128_XTS_EncryptedKeyWrap                 (0x00015200)

/*
 * [in]        memref[0] : Encrypted Key (st_encrypted_aes256xts_key_t)
 * [in/out]    memref[1] : Wrapped key (rsip_wrapped_key_t:100byte)
 */
typedef struct {
	uint32_t unused[2];
	uint8_t  initial_vector[16];
	uint8_t  encrypted_user_key[80];
	uint8_t  crc[4];
} st_encrypted_aes256xts_key_t;
#define PTA_CMD_AES256_XTS_EncryptedKeyWrap                 (0x00015300)

/*
 * [in]        memref[0] : Encrypted Key (st_encrypted_rsa_1024_public_key_t)
 * [in/out]    memref[1] : Wrapped key (rsip_wrapped_key_t:180byte)
 */
typedef struct {
	uint32_t unused[2];
	uint8_t  initial_vector[16];
	uint8_t  encrypted_user_key[160];
	uint8_t  crc[4];
} st_encrypted_rsa_1024_public_key_t;
#define PTA_CMD_RSA1024_EncryptedPublicKeyWrap              (0x00016000)

/*
 * [in]        memref[0] : Encrypted Key (st_encrypted_rsa_1024_private_key_t)
 * [in/out]    memref[1] : Wrapped key (rsip_wrapped_key_t:292byte)
 */
typedef struct {
	uint32_t unused[2];
	uint8_t  initial_vector[16];
	uint8_t  encrypted_user_key[272];
	uint8_t  crc[4];
} st_encrypted_rsa_1024_private_key_t;
#define PTA_CMD_RSA1024_EncryptedPrivateKeyWrap             (0x00016010)

/*
 * [in]        memref[0] : Encrypted Key (st_encrypted_rsa_2048_public_key_t)
 * [in/out]    memref[1] : Wrapped key (rsip_wrapped_key_t:308byte)
 */
typedef struct {
	uint32_t unused[2];
	uint8_t  initial_vector[16];
	uint8_t  encrypted_user_key[288];
	uint8_t  crc[4];
} st_encrypted_rsa_2048_public_key_t;
#define PTA_CMD_RSA2048_EncryptedPublicKeyWrap              (0x00016100)

/*
 * [in]        memref[0] : Encrypted Key (st_encrypted_rsa_2048_private_key_t)
 * [in/out]    memref[1] : Wrapped key (rsip_wrapped_key_t:548byte)
 */
typedef struct {
	uint32_t unused[2];
	uint8_t  initial_vector[16];
	uint8_t  encrypted_user_key[528];
	uint8_t  crc[4];
} st_encrypted_rsa_2048_private_key_t;
#define PTA_CMD_RSA2048_EncryptedPrivateKeyWrap             (0x00016110)

/*
 * [in]        memref[0] : Encrypted Key (st_encrypted_rsa_3072_public_key_t)
 * [in/out]    memref[1] : Wrapped key (rsip_wrapped_key_t:436byte)
 */
typedef struct {
	uint32_t unused[2];
	uint8_t  initial_vector[16];
	uint8_t  encrypted_user_key[416];
	uint8_t  crc[4];
} st_encrypted_rsa_3072_public_key_t;
#define PTA_CMD_RSA3072_EncryptedPublicKeyWrap              (0x00016300)

/*
 * [in]        memref[0] : Encrypted Key (st_encrypted_rsa_3072_private_key_t)
 * [in/out]    memref[1] : Wrapped key (rsip_wrapped_key_t:804byte)
 */
typedef struct {
	uint32_t unused[2];
	uint8_t  initial_vector[16];
	uint8_t  encrypted_user_key[784];
	uint8_t  crc[4];
} st_encrypted_rsa_3072_private_key_t;
#define PTA_CMD_RSA3072_EncryptedPrivateKeyWrap             (0x00016310)

/*
 * [in]        memref[0] : Encrypted Key (st_encrypted_rsa_4096_public_key_t)
 * [in/out]    memref[1] : Wrapped key (rsip_wrapped_key_t:564byte)
 */
typedef struct {
	uint32_t unused[2];
	uint8_t  initial_vector[16];
	uint8_t  encrypted_user_key[544];
	uint8_t  crc[4];
} st_encrypted_rsa_4096_public_key_t;
#define PTA_CMD_RSA4096_EncryptedPublicKeyWrap              (0x00016200)

/*
 * [in]        memref[0] : Encrypted Key (st_encrypted_rsa_4096_private_key_t)
 * [in/out]    memref[1] : Wrapped key (rsip_wrapped_key_t:1060byte)
 */
typedef struct {
	uint32_t unused[2];
	uint8_t  initial_vector[16];
	uint8_t  encrypted_user_key[1040];
	uint8_t  crc[4];
} st_encrypted_rsa_4096_private_key_t;
#define PTA_CMD_RSA4096_EncryptedPrivateKeyWrap             (0x00016210)

/*
 * [in]        memref[0] : Encrypted Key (st_encrypted_ecc_secp192r1_public_key_t)
 * [in/out]    memref[1] : Wrapped key (rsip_wrapped_key_t:100byte)
 */
typedef struct {
	uint32_t unused[2];
	uint8_t  initial_vector[16];
	uint8_t  encrypted_user_key[80];
	uint8_t  crc[4];
} st_encrypted_ecc_secp192r1_public_key_t;
#define PTA_CMD_ECC_secp192r1_EncryptedPublicKeyWrap        (0x00017000)

/*
 * [in]        memref[0] : Encrypted Key (st_encrypted_ecc_secp192r1_private_key_t)
 * [in/out]    memref[1] : Wrapped key (rsip_wrapped_key_t:68byte)
 */
typedef struct {
	uint32_t unused[2];
	uint8_t  initial_vector[16];
	uint8_t  encrypted_user_key[48];
	uint8_t  crc[4];
} st_encrypted_ecc_secp192r1_private_key_t;
#define PTA_CMD_ECC_secp192r1_EncryptedPrivateKeyWrap       (0x00017010)

/*
 * [in]        memref[0] : Encrypted Key (st_encrypted_ecc_secp224r1_public_key_t)
 * [in/out]    memref[1] : Wrapped key (rsip_wrapped_key_t:100byte)
 */
typedef struct {
	uint32_t unused[2];
	uint8_t  initial_vector[16];
	uint8_t  encrypted_user_key[80];
	uint8_t  crc[4];
} st_encrypted_ecc_secp224r1_public_key_t;
#define PTA_CMD_ECC_secp224r1_EncryptedPublicKeyWrap        (0x00017100)

/*
 * [in]        memref[0] : Encrypted Key (st_encrypted_ecc_secp224r1_private_key_t)
 * [in/out]    memref[1] : Wrapped key (rsip_wrapped_key_t:68byte)
 */
typedef struct {
	uint32_t unused[2];
	uint8_t  initial_vector[16];
	uint8_t  encrypted_user_key[48];
	uint8_t  crc[4];
} st_encrypted_ecc_secp224r1_private_key_t;
#define PTA_CMD_ECC_secp224r1_EncryptedPrivateKeyWrap       (0x00017110)

/*
 * [in]        memref[0] : Encrypted Key (st_encrypted_ecc_secp256r1_public_key_t)
 * [in/out]    memref[1] : Wrapped key (rsip_wrapped_key_t:100byte)
 */
typedef struct {
	uint32_t unused[2];
	uint8_t  initial_vector[16];
	uint8_t  encrypted_user_key[80];
	uint8_t  crc[4];
} st_encrypted_ecc_secp256r1_public_key_t;
#define PTA_CMD_ECC_secp256r1_EncryptedPublicKeyWrap        (0x00017200)

/*
 * [in]        memref[0] : Encrypted Key (st_encrypted_ecc_secp256r1_private_key_t)
 * [in/out]    memref[1] : Wrapped key (rsip_wrapped_key_t:68byte)
 */
typedef struct {
	uint32_t unused[2];
	uint8_t  initial_vector[16];
	uint8_t  encrypted_user_key[48];
	uint8_t  crc[4];
} st_encrypted_ecc_secp256r1_private_key_t;
#define PTA_CMD_ECC_secp256r1_EncryptedPrivateKeyWrap       (0x00017210)

/*
 * [in]        memref[0] : Encrypted Key (st_encrypted_ecc_brainpoolp256r1_public_key_t)
 * [in/out]    memref[1] : Wrapped key (rsip_wrapped_key_t:100byte)
 */
typedef struct {
	uint32_t unused[2];
	uint8_t  initial_vector[16];
	uint8_t  encrypted_user_key[80];
	uint8_t  crc[4];
} st_encrypted_ecc_brainpoolp256r1_public_key_t;
#define PTA_CMD_ECC_BrainpoolP256r1_EncryptedPublicKeyWrap  (0x00019000)

/*
 * [in]        memref[0] : Encrypted Key (st_encrypted_ecc_brainpoolp256r1_private_key_t)
 * [in/out]    memref[1] : Wrapped key (rsip_wrapped_key_t:68byte)
 */
typedef struct {
	uint32_t unused[2];
	uint8_t  initial_vector[16];
	uint8_t  encrypted_user_key[48];
	uint8_t  crc[4];
} st_encrypted_ecc_brainpoolp256r1_private_key_t;
#define PTA_CMD_ECC_BrainpoolP256r1_EncryptedPrivateKeyWrap (0x00019010)

/*
 * [in]        memref[0] : Encrypted Key (st_encrypted_hmac_sha1_key_t)
 * [in/out]    memref[1] : Wrapped key (rsip_wrapped_key_t:68byte)
 */
typedef struct {
	uint32_t unused[2];
	uint8_t  initial_vector[16];
	uint8_t  encrypted_user_key[48];
	uint8_t  crc[4];
} st_encrypted_hmac_sha1_key_t;
#define PTA_CMD_HMAC_SHA1_EncryptedKeyWrap                  (0x0001A000)

/*
 * [in]        memref[0] : Encrypted Key (48byte)
 * [in/out]    memref[1] : Wrapped key (rsip_wrapped_key_t:68byte)
 */
typedef struct {
	uint32_t unused[2];
	uint8_t  initial_vector[16];
	uint8_t  encrypted_user_key[48];
	uint8_t  crc[4];
} st_encrypted_hmac_sha224_key_t;
#define PTA_CMD_HMAC_SHA224_EncryptedKeyWrap                (0x0001A100)

/*
 * [in]        memref[0] : Encrypted Key (st_encrypted_hmac_sha256_key_t)
 * [in/out]    memref[1] : Wrapped key (rsip_wrapped_key_t:68byte)
 */
typedef struct {
	uint32_t unused[2];
	uint8_t  initial_vector[16];
	uint8_t  encrypted_user_key[48];
	uint8_t  crc[4];
} st_encrypted_hmac_sha256_key_t;
#define PTA_CMD_HMAC_SHA256_EncryptedKeyWrap                (0x0001A200)

/*
 * [in]         memref[0] : Wrapped key (rsip_wrapped_key_t:180byte)
 * [in/out]     memref[1] : Raw_N (128byte)
 * [in/out]     memref[2] : Raw_E (4byte)
 */
#define PTA_CMD_RSA_1024_Public_Key_Export                  (0x0001B000)

/*
 * [in]         memref[0] : Wrapped key (rsip_wrapped_key_t:308byte)
 * [in/out]     memref[1] : Raw_N (256byte)
 * [in/out]     memref[2] : Raw_E (4byte)
 */
#define PTA_CMD_RSA_2048_Public_Key_Export                  (0x0001B100)

/*
 * [in]         memref[0] : Wrapped key (rsip_wrapped_key_t:436byte)
 * [in/out]     memref[1] : Raw_N (384byte)
 * [in/out]     memref[2] : Raw_E (4byte)
 */
#define PTA_CMD_RSA_3072_Public_Key_Export                  (0x0001B200)

/*
 * [in]         memref[0] : Wrapped key (rsip_wrapped_key_t:564byte)
 * [in/out]     memref[1] : Raw_N (512byte)
 * [in/out]     memref[2] : Raw_E (4byte)
 */
#define PTA_CMD_RSA_4096_Public_Key_Export                  (0x0001B300)

/*
 * [in]         memref[0] : Wrapped key (rsip_wrapped_key_t:100byte)
 * [in/out]     memref[1] : Raw_Qx (32byte)
 * [in/out]     memref[2] : Raw_Qy (32byte)
 */
#define PTA_CMD_ECC_secp192r1_Public_Key_Export             (0x0001C000)

/*
 * [in]         memref[0] : Wrapped key (rsip_wrapped_key_t:100byte)
 * [in/out]     memref[1] : Raw_Qx (32byte)
 * [in/out]     memref[2] : Raw_Qy (32byte)
 */
#define PTA_CMD_ECC_secp224r1_Public_Key_Export             (0x0001C100)

/*
 * [in]         memref[0] : Wrapped key (rsip_wrapped_key_t:100byte)
 * [in/out]     memref[1] : Raw_Qx (32byte)
 * [in/out]     memref[2] : Raw_Qy (32byte)
 */
#define PTA_CMD_ECC_secp256r1_Public_Key_Export             (0x0001C200)

/*
 * [in]         memref[0] : Wrapped key (rsip_wrapped_key_t:100byte)
 * [in/out]     memref[1] : Raw_Qx (32byte)
 * [in/out]     memref[2] : Raw_Qy (32byte)
 */
#define PTA_CMD_ECC_BrainpoolP256r1_Public_Key_Export       (0x0001C300)

#endif /* __PTA_RSIP_H */
