/**********************************************************************************************************************
 * DISCLAIMER
 * This software is supplied by Renesas Electronics Corporation and is only intended for use with Renesas products. No
 * other uses are authorized. This software is owned by Renesas Electronics Corporation and is protected under all
 * applicable laws, including copyright laws.
 * THIS SOFTWARE IS PROVIDED "AS IS" AND RENESAS MAKES NO WARRANTIES REGARDING
 * THIS SOFTWARE, WHETHER EXPRESS, IMPLIED OR STATUTORY, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. ALL SUCH WARRANTIES ARE EXPRESSLY DISCLAIMED. TO THE MAXIMUM
 * EXTENT PERMITTED NOT PROHIBITED BY LAW, NEITHER RENESAS ELECTRONICS CORPORATION NOR ANY OF ITS AFFILIATED COMPANIES
 * SHALL BE LIABLE FOR ANY DIRECT, INDIRECT, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES FOR ANY REASON RELATED TO
 * THIS SOFTWARE, EVEN IF RENESAS OR ITS AFFILIATES HAVE BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
 * Renesas reserves the right, without notice, to make changes to this software and to discontinue the availability of
 * this software. By using this software, you agree to the additional terms and conditions found by accessing the
 * following link:
 * http://www.renesas.com/disclaimer
 *
 * Copyright (C) 2022 Renesas Electronics Corporation. All rights reserved.
 *********************************************************************************************************************/
/**********************************************************************************************************************
 * File Name    : r_sce.h
 * Version      : 1.0
 * Description  : SCE API header file
 *********************************************************************************************************************/
/**********************************************************************************************************************
 * History : DD.MM.YYYY Version  Description
 *         : 03.31.2022 1.00     First Release
 *********************************************************************************************************************/

/*******************************************************************************************************************//**
 * @addtogroup SCE_PROTECTED
 * @{
 **********************************************************************************************************************/

#include <stdint.h>
#include "r_sce_api.h"

#ifndef R_SCE_H
#define R_SCE_H


/***********************************************************************************************************************
 * Macro definitions
 **********************************************************************************************************************/

/* Various information. */
#define HW_SCE_BASE                     (0x11850000)
#define HW_SCE_SIZE                     (0x10000)
#define HW_SCE_SRAM_WORD_SIZE           (20U)
#define HW_SCE_SINST_WORD_SIZE          (140U)
#define HW_SCE_SINST2_WORD_SIZE         (16U)
#define HW_SCE_SHEAP_WORD_SIZE          (1496U)
#define HW_SCE_MAC_SIZE                 (16U)

/* ECC curve types. */
#define SCE_ECC_CURVE_TYPE_NIST         (0)
#define SCE_ECC_CURVE_TYPE_BRAINPOOL    (1)
#define SCE_ECC_CURVE_TYPE_KOBLITZ      (2)

/* ECC curve size */
#define SCE_ECC_KEY_LENGTH_256          (0)
#define SCE_ECC_KEY_LENGTH_224          (1)
#define SCE_ECC_KEY_LENGTH_192          (2)

/***********************************************************************************************************************
 * Typedef definitions
 **********************************************************************************************************************/

/* key index type */
typedef enum
{
    SCE_KEY_INDEX_TYPE_INVALID = 0U,
    SCE_KEY_INDEX_TYPE_AES128,
    SCE_KEY_INDEX_TYPE_AES256,
    SCE_KEY_INDEX_TYPE_TDES,
    SCE_KEY_INDEX_TYPE_HMAC_SHA1,
    SCE_KEY_INDEX_TYPE_HMAC_SHA256,
    SCE_KEY_INDEX_TYPE_RSA1024_PUBLIC,
    SCE_KEY_INDEX_TYPE_RSA1024_PRIVATE,
    SCE_KEY_INDEX_TYPE_RSA2048_PUBLIC,
    SCE_KEY_INDEX_TYPE_RSA2048_PRIVATE,
    SCE_KEY_INDEX_TYPE_RSA3072_PUBLIC,
    SCE_KEY_INDEX_TYPE_RSA3072_PRIVATE,
    SCE_KEY_INDEX_TYPE_RSA4096_PUBLIC,
    SCE_KEY_INDEX_TYPE_RSA4096_PRIVATE,
    SCE_KEY_INDEX_TYPE_AES128_FOR_TLS,
    SCE_KEY_INDEX_TYPE_AES192_FOR_TLS,
    SCE_KEY_INDEX_TYPE_AES256_FOR_TLS,
    SCE_KEY_INDEX_TYPE_HMAC_SHA1_FOR_TLS,
    SCE_KEY_INDEX_TYPE_HMAC_SHA256_FOR_TLS,
    SCE_KEY_INDEX_TYPE_UPDATE_KEY_RING,
    SCE_KEY_INDEX_TYPE_TLS_CA_CERTIFICATION_PUBLIC_KEY,
    SCE_KEY_INDEX_TYPE_TLS_P256_ECC_KEY,
    SCE_KEY_INDEX_TYPE_ECC_P192_PUBLIC,
    SCE_KEY_INDEX_TYPE_ECC_P224_PUBLIC,
    SCE_KEY_INDEX_TYPE_ECC_P256_PUBLIC,
    SCE_KEY_INDEX_TYPE_ECC_P384_PUBLIC,
    SCE_KEY_INDEX_TYPE_ECC_P512_PUBLIC,
    SCE_KEY_INDEX_TYPE_ECC_P192_PRIVATE,
    SCE_KEY_INDEX_TYPE_ECC_P224_PRIVATE,
    SCE_KEY_INDEX_TYPE_ECC_P256_PRIVATE,
    SCE_KEY_INDEX_TYPE_ECC_P384_PRIVATE,
    SCE_KEY_INDEX_TYPE_ECC_P512_PRIVATE,
    SCE_KEY_INDEX_TYPE_ECC_P256R1_PUBLIC,
    SCE_KEY_INDEX_TYPE_ECC_P384R1_PUBLIC,
    SCE_KEY_INDEX_TYPE_ECC_P256R1_PRIVATE,
    SCE_KEY_INDEX_TYPE_ECC_P384R1_PRIVATE,
    SCE_KEY_INDEX_TYPE_ECC_SECP256K1_PUBLIC,
    SCE_KEY_INDEX_TYPE_ECC_SECP256K1_PRIVATE,
    SCE_KEY_INDEX_TYPE_ECDH_SHARED_SECRET,
    SCE_KEY_INDEX_TYPE_AES128_FOR_ECDH,
    SCE_KEY_INDEX_TYPE_AES256_FOR_ECDH,
    SCE_KEY_INDEX_TYPE_HMAC_SHA256_FOR_ECDH,
    SCE_KEY_INDEX_TYPE_AES128_GCM_FOR_DLMS_COSEM,
    SCE_KEY_INDEX_TYPE_AES256_GCM_FOR_DLMS_COSEM,
    SCE_KEY_INDEX_TYPE_AES128_KEY_WRAP_FOR_DLMS_COSEM,
    SCE_KEY_INDEX_TYPE_AES128_GCM_WITH_IV,
} SCE_KEY_INDEX_TYPE;

/* OEM Command */
typedef enum e_sce_oem_cmd
{
    SCE_OEM_CMD_AES128 = 5,
    SCE_OEM_CMD_AES256 = 7,
    SCE_OEM_CMD_RSA1024_PUBLIC = 10,
    SCE_OEM_CMD_RSA1024_PRIVATE,
    SCE_OEM_CMD_RSA2048_PUBLIC,
    SCE_OEM_CMD_RSA2048_PRIVATE,
    SCE_OEM_CMD_RSA3072_PUBLIC,
    SCE_OEM_CMD_RSA3072_PRIVATE,
    SCE_OEM_CMD_RSA4096_PUBLIC,
    SCE_OEM_CMD_RSA4096_PRIVATE,
    SCE_OEM_CMD_ECC_P192_PUBLIC,
    SCE_OEM_CMD_ECC_P192_PRIVATE,
    SCE_OEM_CMD_ECC_P224_PUBLIC,
    SCE_OEM_CMD_ECC_P224_PRIVATE,
    SCE_OEM_CMD_ECC_P256_PUBLIC,
    SCE_OEM_CMD_ECC_P256_PRIVATE,
    SCE_OEM_CMD_ECC_P384_PUBLIC,
    SCE_OEM_CMD_ECC_P384_PRIVATE,
    SCE_OEM_CMD_ECC_P512_PUBLIC,
    SCE_OEM_CMD_ECC_P512_PRIVATE,
    SCE_OEM_CMD_HMAC_SHA256 = 28,
    SCE_OEM_CMD_NUM
} sce_oem_cmd_t;

/** SCE private control block. DO NOT MODIFY. Initialization occurs when R_SCE_Open() is called. */
typedef struct st_sce_instance_ctrl
{
        uint32_t open;                     // Indicates whether the open() API has been successfully
} sce_instance_ctrl_t;

/**********************************************************************************************************************
 * Exported global variables
 **********************************************************************************************************************/
/**********************************************************************************************************************
 External global variables
 *********************************************************************************************************************/
/* memory area for SCE procedure */
extern volatile uint32_t * gp_sce;

/** @cond INC_HEADER_DEFS_SEC */
/** Filled in Interface API structure for this Instance. */
extern const sce_api_t g_sce_protected_on_sce;

/** @endcond */

/**********************************************************************************************************************
 * Public Function Prototypes
 **********************************************************************************************************************/
fsp_err_t R_SCE_Open(sce_ctrl_t * const p_ctrl, sce_cfg_t const * const p_cfg);
fsp_err_t R_SCE_Close(sce_ctrl_t * const p_ctrl);
fsp_err_t R_SCE_SoftwareReset(void);

fsp_err_t R_SCE_AES128_WrappedKeyGenerate(sce_aes_wrapped_key_t * wrapped_key);
fsp_err_t R_SCE_AES256_WrappedKeyGenerate(sce_aes_wrapped_key_t * wrapped_key);
fsp_err_t R_SCE_RSA1024_WrappedKeyPairGenerate(sce_rsa1024_wrapped_pair_key_t * wrapped_pair_key);
fsp_err_t R_SCE_RSA2048_WrappedKeyPairGenerate(sce_rsa2048_wrapped_pair_key_t * wrapped_pair_key);
fsp_err_t R_SCE_ECC_secp192r1_WrappedKeyPairGenerate(sce_ecc_wrapped_pair_key_t * wrapped_pair_key);
fsp_err_t R_SCE_ECC_secp224r1_WrappedKeyPairGenerate(sce_ecc_wrapped_pair_key_t * wrapped_pair_key);
fsp_err_t R_SCE_ECC_secp256r1_WrappedKeyPairGenerate(sce_ecc_wrapped_pair_key_t * wrapped_pair_key);
fsp_err_t R_SCE_ECC_BrainpoolP512r1_WrappedKeyPairGenerate(sce_ecc_wrapped_pair_key_t * wrapped_pair_key);
fsp_err_t R_SCE_RandomNumberGenerate(uint32_t * random);

fsp_err_t R_SCE_AES128_EncryptedKeyWrap(uint8_t               * initial_vector,
        uint8_t               * encrypted_key,
        sce_key_update_key_t  * key_update_key,
        sce_aes_wrapped_key_t * wrapped_key);
fsp_err_t R_SCE_AES256_EncryptedKeyWrap(uint8_t               * initial_vector,
        uint8_t               * encrypted_key,
        sce_key_update_key_t  * key_update_key,
        sce_aes_wrapped_key_t * wrapped_key);

fsp_err_t R_SCE_RSA1024_EncryptedPublicKeyWrap(uint8_t                          * initial_vector,
        uint8_t                          * encrypted_key,
        sce_key_update_key_t             * key_update_key,
        sce_rsa1024_public_wrapped_key_t * wrapped_key);
fsp_err_t R_SCE_RSA1024_EncryptedPrivateKeyWrap(uint8_t                           * initial_vector,
        uint8_t                           * encrypted_key,
        sce_key_update_key_t              * key_update_key,
        sce_rsa1024_private_wrapped_key_t * wrapped_key);
fsp_err_t R_SCE_RSA2048_EncryptedPublicKeyWrap(uint8_t                          * initial_vector,
        uint8_t                          * encrypted_key,
        sce_key_update_key_t             * key_update_key,
        sce_rsa2048_public_wrapped_key_t * wrapped_key);
fsp_err_t R_SCE_RSA2048_EncryptedPrivateKeyWrap(uint8_t                           * initial_vector,
        uint8_t                           * encrypted_key,
        sce_key_update_key_t              * key_update_key,
        sce_rsa2048_private_wrapped_key_t * wrapped_key);
fsp_err_t R_SCE_RSA4096_EncryptedPublicKeyWrap(uint8_t                          * initial_vector,
        uint8_t                          * encrypted_key,
        sce_key_update_key_t             * key_update_key,
        sce_rsa4096_public_wrapped_key_t * wrapped_key);

fsp_err_t R_SCE_ECC_secp192r1_EncryptedPublicKeyWrap(uint8_t                      * initial_vector,
        uint8_t                      * encrypted_key,
        sce_key_update_key_t         * key_update_key,
        sce_ecc_public_wrapped_key_t * wrapped_key);
fsp_err_t R_SCE_ECC_secp224r1_EncryptedPublicKeyWrap(uint8_t                      * initial_vector,
        uint8_t                      * encrypted_key,
        sce_key_update_key_t         * key_update_key,
        sce_ecc_public_wrapped_key_t * wrapped_key);
fsp_err_t R_SCE_ECC_secp256r1_EncryptedPublicKeyWrap(uint8_t                      * initial_vector,
        uint8_t                      * encrypted_key,
        sce_key_update_key_t         * key_update_key,
        sce_ecc_public_wrapped_key_t * wrapped_key);
fsp_err_t R_SCE_ECC_BrainpoolP512r1_EncryptedPublicKeyWrap(uint8_t                * initial_vector,
        uint8_t                      * encrypted_key,
        sce_key_update_key_t         * key_update_key,
        sce_ecc_public_wrapped_key_t * wrapped_key);
fsp_err_t R_SCE_ECC_secp192r1_EncryptedPrivateKeyWrap(uint8_t                       * initial_vector,
        uint8_t                       * encrypted_key,
        sce_key_update_key_t          * key_update_key,
        sce_ecc_private_wrapped_key_t * wrapped_key);
fsp_err_t R_SCE_ECC_secp224r1_EncryptedPrivateKeyWrap(uint8_t                       * initial_vector,
        uint8_t                       * encrypted_key,
        sce_key_update_key_t          * key_update_key,
        sce_ecc_private_wrapped_key_t * wrapped_key);
fsp_err_t R_SCE_ECC_secp256r1_EncryptedPrivateKeyWrap(uint8_t                       * initial_vector,
        uint8_t                       * encrypted_key,
        sce_key_update_key_t          * key_update_key,
        sce_ecc_private_wrapped_key_t * wrapped_key);
fsp_err_t R_SCE_ECC_BrainpoolP512r1_EncryptedPrivateKeyWrap(uint8_t                       * initial_vector,
        uint8_t                       * encrypted_key,
        sce_key_update_key_t          * key_update_key,
        sce_ecc_private_wrapped_key_t * wrapped_key);

fsp_err_t R_SCE_AES128ECB_EncryptInit(sce_aes_handle_t * handle, sce_aes_wrapped_key_t * wrapped_key);
fsp_err_t R_SCE_AES128ECB_EncryptUpdate(sce_aes_handle_t * handle,
        uint8_t          * plain,
        uint8_t          * cipher,
        uint32_t           plain_length);
fsp_err_t R_SCE_AES128ECB_EncryptFinal(sce_aes_handle_t * handle, uint8_t * cipher, uint32_t * cipher_length);
fsp_err_t R_SCE_AES128ECB_DecryptInit(sce_aes_handle_t * handle, sce_aes_wrapped_key_t * wrapped_key);
fsp_err_t R_SCE_AES128ECB_DecryptUpdate(sce_aes_handle_t * handle,
        uint8_t          * cipher,
        uint8_t          * plain,
        uint32_t           cipher_length);
fsp_err_t R_SCE_AES128ECB_DecryptFinal(sce_aes_handle_t * handle, uint8_t * plain, uint32_t * plain_length);
fsp_err_t R_SCE_AES256ECB_EncryptInit(sce_aes_handle_t * handle, sce_aes_wrapped_key_t * wrapped_key);
fsp_err_t R_SCE_AES256ECB_EncryptUpdate(sce_aes_handle_t * handle,
        uint8_t          * plain,
        uint8_t          * cipher,
        uint32_t           plain_length);
fsp_err_t R_SCE_AES256ECB_EncryptFinal(sce_aes_handle_t * handle, uint8_t * cipher, uint32_t * cipher_length);
fsp_err_t R_SCE_AES256ECB_DecryptInit(sce_aes_handle_t * handle, sce_aes_wrapped_key_t * wrapped_key);
fsp_err_t R_SCE_AES256ECB_DecryptUpdate(sce_aes_handle_t * handle,
        uint8_t          * cipher,
        uint8_t          * plain,
        uint32_t           cipher_length);
fsp_err_t R_SCE_AES256ECB_DecryptFinal(sce_aes_handle_t * handle, uint8_t * plain, uint32_t * plain_length);

fsp_err_t R_SCE_AES128CBC_EncryptInit(sce_aes_handle_t      * handle,
        sce_aes_wrapped_key_t * wrapped_key,
        uint8_t               * initial_vector);
fsp_err_t R_SCE_AES128CBC_EncryptUpdate(sce_aes_handle_t * handle,
        uint8_t          * plain,
        uint8_t          * cipher,
        uint32_t           plain_length);
fsp_err_t R_SCE_AES128CBC_EncryptFinal(sce_aes_handle_t * handle, uint8_t * cipher, uint32_t * cipher_length);
fsp_err_t R_SCE_AES128CBC_DecryptInit(sce_aes_handle_t      * handle,
        sce_aes_wrapped_key_t * wrapped_key,
        uint8_t               * initial_vector);
fsp_err_t R_SCE_AES128CBC_DecryptUpdate(sce_aes_handle_t * handle,
        uint8_t          * cipher,
        uint8_t          * plain,
        uint32_t           cipher_length);
fsp_err_t R_SCE_AES128CBC_DecryptFinal(sce_aes_handle_t * handle, uint8_t * plain, uint32_t * plain_length);
fsp_err_t R_SCE_AES256CBC_EncryptInit(sce_aes_handle_t      * handle,
        sce_aes_wrapped_key_t * wrapped_key,
        uint8_t               * initial_vector);
fsp_err_t R_SCE_AES256CBC_EncryptUpdate(sce_aes_handle_t * handle,
        uint8_t          * plain,
        uint8_t          * cipher,
        uint32_t           plain_length);
fsp_err_t R_SCE_AES256CBC_EncryptFinal(sce_aes_handle_t * handle, uint8_t * cipher, uint32_t * cipher_length);
fsp_err_t R_SCE_AES256CBC_DecryptInit(sce_aes_handle_t      * handle,
        sce_aes_wrapped_key_t * wrapped_key,
        uint8_t               * initial_vector);
fsp_err_t R_SCE_AES256CBC_DecryptUpdate(sce_aes_handle_t * handle,
        uint8_t          * cipher,
        uint8_t          * plain,
        uint32_t           cipher_length);
fsp_err_t R_SCE_AES256CBC_DecryptFinal(sce_aes_handle_t * handle, uint8_t * plain, uint32_t * plain_length);

fsp_err_t R_SCE_AES128CTR_EncryptInit(sce_aes_handle_t      * handle,
        sce_aes_wrapped_key_t * wrapped_key,
        uint8_t               * initial_vector);
fsp_err_t R_SCE_AES128CTR_EncryptUpdate(sce_aes_handle_t * handle,
        uint8_t          * plain,
        uint8_t          * cipher,
        uint32_t           plain_length);
fsp_err_t R_SCE_AES128CTR_EncryptFinal(sce_aes_handle_t * handle, uint8_t * cipher, uint32_t * cipher_length);
fsp_err_t R_SCE_AES128CTR_DecryptInit(sce_aes_handle_t      * handle,
        sce_aes_wrapped_key_t * wrapped_key,
        uint8_t               * initial_vector);
fsp_err_t R_SCE_AES128CTR_DecryptUpdate(sce_aes_handle_t * handle,
        uint8_t          * cipher,
        uint8_t          * plain,
        uint32_t           cipher_length);
fsp_err_t R_SCE_AES128CTR_DecryptFinal(sce_aes_handle_t * handle, uint8_t * plain, uint32_t * plain_length);
fsp_err_t R_SCE_AES256CTR_EncryptInit(sce_aes_handle_t      * handle,
        sce_aes_wrapped_key_t * wrapped_key,
        uint8_t               * initial_vector);
fsp_err_t R_SCE_AES256CTR_EncryptUpdate(sce_aes_handle_t * handle,
        uint8_t          * plain,
        uint8_t          * cipher,
        uint32_t           plain_length);
fsp_err_t R_SCE_AES256CTR_EncryptFinal(sce_aes_handle_t * handle, uint8_t * cipher, uint32_t * cipher_length);
fsp_err_t R_SCE_AES256CTR_DecryptInit(sce_aes_handle_t      * handle,
        sce_aes_wrapped_key_t * wrapped_key,
        uint8_t               * initial_vector);
fsp_err_t R_SCE_AES256CTR_DecryptUpdate(sce_aes_handle_t * handle,
        uint8_t          * cipher,
        uint8_t          * plain,
        uint32_t           cipher_length);
fsp_err_t R_SCE_AES256CTR_DecryptFinal(sce_aes_handle_t * handle, uint8_t * plain, uint32_t * plain_length);

fsp_err_t R_SCE_AES128CMAC_GenerateInit(sce_cmac_handle_t * handle, sce_aes_wrapped_key_t * wrapped_key);
fsp_err_t R_SCE_AES128CMAC_GenerateUpdate(sce_cmac_handle_t * handle, uint8_t * message, uint32_t message_length);
fsp_err_t R_SCE_AES128CMAC_GenerateFinal(sce_cmac_handle_t * handle, uint8_t * mac);
fsp_err_t R_SCE_AES128CMAC_VerifyInit(sce_cmac_handle_t * handle, sce_aes_wrapped_key_t * wrapped_key);
fsp_err_t R_SCE_AES128CMAC_VerifyUpdate(sce_cmac_handle_t * handle, uint8_t * message, uint32_t message_length);
fsp_err_t R_SCE_AES128CMAC_VerifyFinal(sce_cmac_handle_t * handle, uint8_t * mac, uint32_t mac_length);
fsp_err_t R_SCE_AES256CMAC_GenerateInit(sce_cmac_handle_t * handle, sce_aes_wrapped_key_t * wrapped_key);
fsp_err_t R_SCE_AES256CMAC_GenerateUpdate(sce_cmac_handle_t * handle, uint8_t * message, uint32_t message_length);
fsp_err_t R_SCE_AES256CMAC_GenerateFinal(sce_cmac_handle_t * handle, uint8_t * mac);
fsp_err_t R_SCE_AES256CMAC_VerifyInit(sce_cmac_handle_t * handle, sce_aes_wrapped_key_t * wrapped_key);
fsp_err_t R_SCE_AES256CMAC_VerifyUpdate(sce_cmac_handle_t * handle, uint8_t * message, uint32_t message_length);
fsp_err_t R_SCE_AES256CMAC_VerifyFinal(sce_cmac_handle_t * handle, uint8_t * mac, uint32_t mac_length);

fsp_err_t R_SCE_SHA224_Init(sce_sha_md5_handle_t * handle);
fsp_err_t R_SCE_SHA224_Update(sce_sha_md5_handle_t * handle, uint8_t * message, uint32_t message_length);
fsp_err_t R_SCE_SHA224_Final(sce_sha_md5_handle_t * handle, uint8_t * digest, uint32_t * digest_length);
fsp_err_t R_SCE_SHA256_Init(sce_sha_md5_handle_t * handle);
fsp_err_t R_SCE_SHA256_Update(sce_sha_md5_handle_t * handle, uint8_t * message, uint32_t message_length);
fsp_err_t R_SCE_SHA256_Final(sce_sha_md5_handle_t * handle, uint8_t * digest, uint32_t * digest_length);

fsp_err_t R_SCE_RSASSA_PKCS1024_SignatureGenerate(sce_rsa_byte_data_t               * message_hash,
        sce_rsa_byte_data_t               * signature,
        sce_rsa1024_private_wrapped_key_t * wrapped_key,
        uint8_t                             hash_type);
fsp_err_t R_SCE_RSASSA_PKCS1024_SignatureVerify(sce_rsa_byte_data_t              * signature,
        sce_rsa_byte_data_t              * message_hash,
        sce_rsa1024_public_wrapped_key_t * wrapped_key,
        uint8_t                            hash_type);
fsp_err_t R_SCE_RSASSA_PKCS2048_SignatureGenerate(sce_rsa_byte_data_t               * message_hash,
        sce_rsa_byte_data_t               * signature,
        sce_rsa2048_private_wrapped_key_t * wrapped_key,
        uint8_t                             hash_type);
fsp_err_t R_SCE_RSASSA_PKCS2048_SignatureVerify(sce_rsa_byte_data_t              * signature,
        sce_rsa_byte_data_t              * message_hash,
        sce_rsa2048_public_wrapped_key_t * wrapped_key,
        uint8_t                            hash_type);
fsp_err_t R_SCE_RSASSA_PKCS4096_SignatureVerify(sce_rsa_byte_data_t              * signature,
        sce_rsa_byte_data_t              * message_hash,
        sce_rsa4096_public_wrapped_key_t * wrapped_key,
        uint8_t                            hash_type);

fsp_err_t R_SCE_RSAES_PKCS1024_Encrypt(sce_rsa_byte_data_t              * plain,
        sce_rsa_byte_data_t              * cipher,
        sce_rsa1024_public_wrapped_key_t * wrapped_key);
fsp_err_t R_SCE_RSAES_PKCS1024_Decrypt(sce_rsa_byte_data_t               * cipher,
        sce_rsa_byte_data_t               * plain,
        sce_rsa1024_private_wrapped_key_t * wrapped_key);
fsp_err_t R_SCE_RSAES_PKCS2048_Encrypt(sce_rsa_byte_data_t              * plain,
        sce_rsa_byte_data_t              * cipher,
        sce_rsa2048_public_wrapped_key_t * wrapped_key);
fsp_err_t R_SCE_RSAES_PKCS2048_Decrypt(sce_rsa_byte_data_t               * cipher,
        sce_rsa_byte_data_t               * plain,
        sce_rsa2048_private_wrapped_key_t * wrapped_key);
fsp_err_t R_SCE_RSAES_PKCS4096_Encrypt(sce_rsa_byte_data_t              * plain,
        sce_rsa_byte_data_t              * cipher,
        sce_rsa4096_public_wrapped_key_t * wrapped_key);

fsp_err_t R_SCE_ECDSA_secp192r1_SignatureGenerate(sce_ecdsa_byte_data_t         * message_hash,
        sce_ecdsa_byte_data_t         * signature,
        sce_ecc_private_wrapped_key_t * wrapped_key);
fsp_err_t R_SCE_ECDSA_secp224r1_SignatureGenerate(sce_ecdsa_byte_data_t         * message_hash,
        sce_ecdsa_byte_data_t         * signature,
        sce_ecc_private_wrapped_key_t * wrapped_key);
fsp_err_t R_SCE_ECDSA_secp256r1_SignatureGenerate(sce_ecdsa_byte_data_t         * message_hash,
        sce_ecdsa_byte_data_t         * signature,
        sce_ecc_private_wrapped_key_t * wrapped_key);
fsp_err_t R_SCE_ECDSA_BrainpoolP512r1_SignatureGenerate(sce_ecdsa_byte_data_t         * message_hash,
        sce_ecdsa_byte_data_t         * signature,
        sce_ecc_private_wrapped_key_t * wrapped_key);
fsp_err_t R_SCE_ECDSA_secp192r1_SignatureVerify(sce_ecdsa_byte_data_t        * signature,
        sce_ecdsa_byte_data_t        * message_hash,
        sce_ecc_public_wrapped_key_t * wrapped_key);
fsp_err_t R_SCE_ECDSA_secp224r1_SignatureVerify(sce_ecdsa_byte_data_t        * signature,
        sce_ecdsa_byte_data_t        * message_hash,
        sce_ecc_public_wrapped_key_t * wrapped_key);
fsp_err_t R_SCE_ECDSA_secp256r1_SignatureVerify(sce_ecdsa_byte_data_t        * signature,
        sce_ecdsa_byte_data_t        * message_hash,
        sce_ecc_public_wrapped_key_t * wrapped_key);
fsp_err_t R_SCE_ECDSA_BrainpoolP512r1_SignatureVerify(sce_ecdsa_byte_data_t        * signature,
        sce_ecdsa_byte_data_t        * message_hash,
        sce_ecc_public_wrapped_key_t * wrapped_key);

#endif                                 /* R_SCE_H */

/*******************************************************************************************************************//**
 * @} (end addtogroup SCE_PROTECTED)
 **********************************************************************************************************************/
