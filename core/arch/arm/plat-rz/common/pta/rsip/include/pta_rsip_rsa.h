/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2024, Renesas Electronics Corporation
 */

#ifndef __PTA_RSIP_RSA_H
#define __PTA_RSIP_RSA_H

#include <r_rsip_api.h>

#define PTA_RSIP_RSA_UUID \
	{ 0x38225144, 0xb347, 0x467e, \
		{ 0x93, 0x7e, 0x1e, 0xf8, 0xff, 0x7e, 0x5a, 0xe1 } }

#define SIGNATURE_BYTE_SIZE_RSA_1024        (128U)
#define SIGNATURE_BYTE_SIZE_RSA_2048        (256U)
#define SIGNATURE_BYTE_SIZE_RSA_3072        (384U)
#define SIGNATURE_BYTE_SIZE_RSA_4096        (512U)

#define CIPHER_BYTE_SIZE_RSA_1024           (128U)
#define CIPHER_BYTE_SIZE_RSA_2048           (256U)
#define CIPHER_BYTE_SIZE_RSA_3072           (384U)
#define CIPHER_BYTE_SIZE_RSA_4096           (512U)

/*
 * Signs message with RSASSA-PKCS1-v1_5.
 *
 * Hash function : SHA-256
 */

/*
 * [in]      memref[0] : Message
 * [in/out]  memref[1] : Signature (128byte)
 * [in]      memref[2] : Wrapped key (rsip_wrapped_key_t:292byte)
 */
#define PTA_CMD_RSASSA_PKCS1024_SignatureGenerate   (0x00040000)
/*
 * [in]      memref[0] : Signature (128byte)
 * [in]      memref[1] : Message
 * [in]      memref[2] : Wrapped key (rsip_wrapped_key_t:180byte)
 */
#define PTA_CMD_RSASSA_PKCS1024_SignatureVerify     (0x00040010)
/*
 * [in]      memref[0] : Message
 * [in/out]  memref[1] : Signature (256byte)
 * [in]      memref[2] : Wrapped key (rsip_wrapped_key_t:548byte)
 */
#define PTA_CMD_RSASSA_PKCS2048_SignatureGenerate   (0x00040100)
/*
 * [in]      memref[0] : Signature (256byte)
 * [in]      memref[1] : Message
 * [in]      memref[2] : Wrapped key (rsip_wrapped_key_t:308byte)
 */
#define PTA_CMD_RSASSA_PKCS2048_SignatureVerify     (0x00040110)
/*
 * [in]      memref[0] : Message
 * [in/out]  memref[1] : Signature (384byte)
 * [in]      memref[2] : Wrapped key (rsip_wrapped_key_t:804byte)
 */
#define PTA_CMD_RSASSA_PKCS3072_SignatureGenerate   (0x00040300)
/*
 * [in]      memref[0] : Signature (384byte)
 * [in]      memref[1] : Message
 * [in]      memref[2] : Wrapped key (rsip_wrapped_key_t:436byte)
 */
#define PTA_CMD_RSASSA_PKCS3072_SignatureVerify     (0x00040310)
/*
 * [in]      memref[0] : Message
 * [in/out]  memref[1] : Signature (512byte)
 * [in]      memref[2] : Wrapped key (rsip_wrapped_key_t:1060byte)
 */
#define PTA_CMD_RSASSA_PKCS4096_SignatureGenerate   (0x00040200)
/*
 * [in]      memref[0] : Signature (512byte)
 * [in]      memref[1] : Message
 * [in]      memref[2] : Wrapped key (rsip_wrapped_key_t:564byte)
 */
#define PTA_CMD_RSASSA_PKCS4096_SignatureVerify     (0x00040210)

/*
 * Encrypts plaintext with RSAES-PKCS1-v1_5.
 *
 * mLen (plain_length) and k (RSA key length) must meet the following condition.
 *
 * mlen <= k - 11
 */

/*
 * [in]      memref[0] : Plain (size <= 117byte)
 * [in/out]  memref[1] : Cipher (size == 128byte)
 * [in]      memref[2] : Wrapped key (rsip_wrapped_key_t:180byte)
 */
#define PTA_CMD_RSAES_PKCS1024_Encrypt              (0x00041000)
/*
 * [in]      memref[0] : Cipher (size == 128byte)
 * [in/out]  memref[1] : Plain (size <= 117byte)
 * [in]      memref[2] : Wrapped key (rsip_wrapped_key_t:292byte)
 */
#define PTA_CMD_RSAES_PKCS1024_Decrypt              (0x00041010)
/*
 * [in]      memref[0] : Plain (size <= 245byte)
 * [in/out]  memref[1] : Cipher (size == 256byte)
 * [in]      memref[2] : Wrapped key (rsip_wrapped_key_t:308byte)
 */
#define PTA_CMD_RSAES_PKCS2048_Encrypt              (0x00041100)
/*
 * [in]      memref[0] : Cipher (size == 256byte)
 * [in/out]  memref[1] : Plain (size <= 245byte)
 * [in]      memref[2] : Wrapped key (rsip_wrapped_key_t:548byte)
 */
#define PTA_CMD_RSAES_PKCS2048_Decrypt              (0x00041110)
/*
 * [in]      memref[0] : Plain (size <= 373byte)
 * [in/out]  memref[1] : Cipher (size == 384byte)
 * [in]      memref[2] : Wrapped key (rsip_wrapped_key_t:436byte)
 */
#define PTA_CMD_RSAES_PKCS3072_Encrypt              (0x00041300)
/*
 * [in]      memref[0] : Cipher (size == 384byte)
 * [in/out]  memref[1] : Plain (size <= 373byte)
 * [in]      memref[2] : Wrapped key (rsip_wrapped_key_t:804byte)
 */
#define PTA_CMD_RSAES_PKCS3072_Decrypt              (0x00041310)
/*
 * [in]      memref[0] : Plain (size <= 501byte)
 * [in/out]  memref[1] : Cipher (size == 512byte)
 * [in]      memref[2] : Wrapped key (rsip_wrapped_key_t:564byte)
 */
#define PTA_CMD_RSAES_PKCS4096_Encrypt              (0x00041200)
/*
 * [in]      memref[0] : Cipher (size == 512byte)
 * [in/out]  memref[1] : Plain (size <= 501byte)
 * [in]      memref[2] : Wrapped key (rsip_wrapped_key_t:1060byte)
 */
#define PTA_CMD_RSAES_PKCS4096_Decrypt              (0x00041210)

/*
 * Signs message with RSASSA-PSS.
 *
 * Hash function : SHA-256
 * Mask generation function : MGF1 with SHA-256
 * Salt length : 32byte (hash length of SHA-256)
 */

/*
 * [in]      memref[0] : Message
 * [in/out]  memref[1] : Signature (128byte)
 * [in]      memref[2] : Wrapped key (rsip_wrapped_key_t:292byte)
 */
#define PTA_CMD_RSASSA_PSS1024_SignatureGenerate    (0x00042000)
/*
 * [in]      memref[0] : Signature (128byte)
 * [in]      memref[1] : Wrapped key (rsip_wrapped_key_t:180byte)
 */
#define PTA_CMD_RSASSA_PSS1024_SignatureVerify      (0x00042010)
/*
 * [in]      memref[0] : Message
 * [in/out]  memref[1] : Signature (256byte)
 * [in]      memref[2] : Wrapped key (rsip_wrapped_key_t:548byte)
 */
#define PTA_CMD_RSASSA_PSS2048_SignatureGenerate    (0x00042100)
/*
 * [in]      memref[0] : Signature (256byte)
 * [in]      memref[1] : Wrapped key (rsip_wrapped_key_t:384byte)
 */
#define PTA_CMD_RSASSA_PSS2048_SignatureVerify      (0x00042110)
/*
 * [in]      memref[0] : Message
 * [in/out]  memref[1] : Signature (384byte)
 * [in]      memref[2] : Wrapped key (rsip_wrapped_key_t:804byte)
 */
#define PTA_CMD_RSASSA_PSS3072_SignatureGenerate    (0x00042200)
/*
 * [in]      memref[0] : Signature (384byte)
 * [in]      memref[1] : Wrapped key (rsip_wrapped_key_t:436byte)
 */
#define PTA_CMD_RSASSA_PSS3072_SignatureVerify      (0x00042210)
/*
 * [in]      memref[0] : Message
 * [in/out]  memref[1] : Signature (512byte)
 * [in]      memref[2] : Wrapped key (rsip_wrapped_key_t:1060byte)
 */
#define PTA_CMD_RSASSA_PSS4096_SignatureGenerate    (0x00042300)
/*
 * [in]      memref[0] : Signature (512byte)
 * [in]      memref[1] : Wrapped key (rsip_wrapped_key_t:564byte)
 */
#define PTA_CMD_RSASSA_PSS4096_SignatureVerify      (0x00042310)

/*
 * [in]      memref[0] : Plain (128byte)
 * [in/out]  memref[1] : Cipher (128byte)
 * [in]      memref[2] : Wrapped key (rsip_wrapped_key_t:180byte)
 */
#define PTA_CMD_RSA_1024_Encrypt                    (0x00043000)
/*
 * [in]      memref[0] : Cipher (128byte)
 * [in/out]  memref[1] : Plain (128byte)
 * [in]      memref[2] : Wrapped key (rsip_wrapped_key_t:292byte)
 */
#define PTA_CMD_RSA_1024_Decrypt                    (0x00043010)
/*
 * [in]      memref[0] : Plain (256byte)
 * [in/out]  memref[1] : Cipher (256byte)
 * [in]      memref[2] : Wrapped key (rsip_wrapped_key_t:308byte)
 */
#define PTA_CMD_RSA_2048_Encrypt                    (0x00043100)
/*
 * [in]      memref[0] : Cipher (256byte)
 * [in/out]  memref[1] : Plain (256byte)
 * [in]      memref[2] : Wrapped key (rsip_wrapped_key_t:548byte)
 */
#define PTA_CMD_RSA_2048_Decrypt                    (0x00043110)
/*
 * [in]      memref[0] : Plain (384byte)
 * [in/out]  memref[1] : Cipher (384byte)
 * [in]      memref[2] : Wrapped key (rsip_wrapped_key_t:436byte)
 */
#define PTA_CMD_RSA_3072_Encrypt                    (0x00043200)
/*
 * [in]      memref[0] : Cipher (384byte)
 * [in/out]  memref[1] : Plain (384byte)
 * [in]      memref[2] : Wrapped key (rsip_wrapped_key_t:804byte)
 */
#define PTA_CMD_RSA_3072_Decrypt                    (0x00043210)
/*
 * [in]      memref[0] : Plain (512byte)
 * [in/out]  memref[1] : Cipher (512byte)
 * [in]      memref[2] : Wrapped key (rsip_wrapped_key_t:564byte)
 */
#define PTA_CMD_RSA_4096_Encrypt                    (0x00043300)
/*
 * [in]      memref[0] : Cipher (512byte)
 * [in/out]  memref[1] : Plain (512byte)
 * [in]      memref[2] : Wrapped key (rsip_wrapped_key_t:1060byte)
 */
#define PTA_CMD_RSA_4096_Decrypt                    (0x00043310)

/*
 * Encrypts plaintext with RSAES-OAEP.
 *
 * Hash function : SHA-256
 * Mask generation function : MGF1 with SHA-256
 *
 * mLen (plain_length), hLen (output length of hash_function), and k (RSA key length)
 * must meet the following condition.
 *
 * mLen <= k - 2 hLen - 2
 */

/*
 * [in]      memref[0] : Plain (size <= 62byte)
 * [in/out]  memref[1] : Cipher (size == 128byte)
 * [in]      memref[2] : Wrapped key (rsip_wrapped_key_t:180byte)
 * [in]      memref[3] : Label
 */
#define PTA_CMD_RSAES_OAEP1024_Encrypt              (0x00044000)
/*
 * [in]      memref[0] : Cipher (size == 128byte)
 * [in/out]  memref[1] : Plain (size <= 62byte)
 * [in]      memref[2] : Wrapped key (rsip_wrapped_key_t:292byte)
 * [in]      memref[3] : Label
 */
#define PTA_CMD_RSAES_OAEP1024_Decrypt              (0x00044010)
/*
 * [in]      memref[0] : Plain (size <= 190byte)
 * [in/out]  memref[1] : Cipher (size == 256byte)
 * [in]      memref[2] : Wrapped key (rsip_wrapped_key_t:308byte)
 * [in]      memref[3] : Label
 */
#define PTA_CMD_RSAES_OAEP2048_Encrypt              (0x00044100)
/*
 * [in]      memref[0] : Cipher (size == 256byte)
 * [in/out]  memref[1] : Plain (size <= 190byte)
 * [in]      memref[2] : Wrapped key (rsip_wrapped_key_t:548byte)
 * [in]      memref[3] : Label
 */
#define PTA_CMD_RSAES_OAEP2048_Decrypt              (0x00044110)
/*
 * [in]      memref[0] : Plain (size <= 318byte)
 * [in/out]  memref[1] : Cipher (size == 384byte)
 * [in]      memref[2] : Wrapped key (rsip_wrapped_key_t:436byte)
 * [in]      memref[3] : Label
 */
#define PTA_CMD_RSAES_OAEP3072_Encrypt              (0x00044200)
/*
 * [in]      memref[0] : Cipher (size == 384byte)
 * [in/out]  memref[1] : Plain (size <= 318byte)
 * [in]      memref[2] : Wrapped key (rsip_wrapped_key_t:804byte)
 * [in]      memref[3] : Label
 */
#define PTA_CMD_RSAES_OAEP3072_Decrypt              (0x00044210)
/*
 * [in]      memref[0] : Plain (size <= 446byte)
 * [in/out]  memref[1] : Cipher (size == 512byte)
 * [in]      memref[2] : Wrapped key (rsip_wrapped_key_t:564byte)
 * [in]      memref[3] : Label
 */
#define PTA_CMD_RSAES_OAEP4096_Encrypt              (0x00044300)
/*
 * [in]      memref[0] : Cipher (size == 512byte)
 * [in/out]  memref[1] : Plain (size <= 446byte)
 * [in]      memref[2] : Wrapped key (rsip_wrapped_key_t:1060byte)
 * [in]      memref[3] : Label
 */
#define PTA_CMD_RSAES_OAEP4096_Decrypt              (0x00044310)

#endif /* __PTA_RSIP_RSA_H */
