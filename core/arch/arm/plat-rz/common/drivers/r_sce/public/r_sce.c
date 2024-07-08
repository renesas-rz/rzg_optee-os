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
 * File Name    : r_sce.c
 * Version      : 1.0
 * Description  : SCE Common Public API source file
 *********************************************************************************************************************/
/**********************************************************************************************************************
 * History : DD.MM.YYYY Version  Description
 *         : 03.31.2022 1.00     First Release
 *********************************************************************************************************************/


/***********************************************************************************************************************
 * Includes
 **********************************************************************************************************************/
#include <string.h>
#include "r_sce_private.h"

/***********************************************************************************************************************
 * Macro definitions
 **********************************************************************************************************************/
#define HW_STATE_UNAVAILABLE    (1)
#define HW_STATE_AVAILABLE      (2)

/* 5*(key_length/2)*2 is recommended by NIST FIPS186-4 */
#define SCE_RSA_RETRY_COUNT_FOR_RSA1024_KEY_GENERATION (5*(1024/2)*2)
#define SCE_RSA_RETRY_COUNT_FOR_RSA2048_KEY_GENERATION (5*(2048/2)*2)


/***********************************************************************************************************************
 * Typedef definitions
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Private function prototypes
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Private global variables
 **********************************************************************************************************************/
static lifecycle_t gs_lifecycle;

/**********************************************************************************************************************
 Global variables
 *********************************************************************************************************************/
uint32_t S_RAM[HW_SCE_SRAM_WORD_SIZE];
uint32_t S_HEAP[HW_SCE_SHEAP_WORD_SIZE];
uint32_t S_INST2[HW_SCE_SINST2_WORD_SIZE];

uint32_t        g_private_id_counter;
extern uint32_t g_aes128ecbenc_private_id;
extern uint32_t g_aes128ecbdec_private_id;
extern uint32_t g_aes256ecbenc_private_id;
extern uint32_t g_aes256ecbdec_private_id;
extern uint32_t g_aes128cbcenc_private_id;
extern uint32_t g_aes128cbcdec_private_id;
extern uint32_t g_aes256cbcenc_private_id;
extern uint32_t g_aes256cbcdec_private_id;
extern uint32_t g_aes128ctrenc_private_id;
extern uint32_t g_aes128ctrdec_private_id;
extern uint32_t g_aes256ctrenc_private_id;
extern uint32_t g_aes256ctrdec_private_id;
extern uint32_t g_aes128cmacgen_private_id;
extern uint32_t g_aes128cmacver_private_id;
extern uint32_t g_aes256cmacgen_private_id;
extern uint32_t g_aes256cmacver_private_id;
extern uint32_t g_sha224_private_id;
extern uint32_t g_sha256_private_id;

const sce_api_t g_sce_protected_on_sce =
{
        .open                                              = R_SCE_Open,
        .close                                             = R_SCE_Close,
        .softwareReset                                     = R_SCE_SoftwareReset,
        .randomNumberGenerate                              = R_SCE_RandomNumberGenerate,
        .AES128_WrappedKeyGenerate                         = R_SCE_AES128_WrappedKeyGenerate,
        .AES256_WrappedKeyGenerate                         = R_SCE_AES256_WrappedKeyGenerate,
        .AES128_EncryptedKeyWrap                           = R_SCE_AES128_EncryptedKeyWrap,
        .AES256_EncryptedKeyWrap                           = R_SCE_AES256_EncryptedKeyWrap,
        .AES128ECB_EncryptInit                             = R_SCE_AES128ECB_EncryptInit,
        .AES128ECB_EncryptUpdate                           = R_SCE_AES128ECB_EncryptUpdate,
        .AES128ECB_EncryptFinal                            = R_SCE_AES128ECB_EncryptFinal,
        .AES128ECB_DecryptInit                             = R_SCE_AES128ECB_DecryptInit,
        .AES128ECB_DecryptUpdate                           = R_SCE_AES128ECB_DecryptUpdate,
        .AES128ECB_DecryptFinal                            = R_SCE_AES128ECB_DecryptFinal,
        .AES256ECB_EncryptInit                             = R_SCE_AES256ECB_EncryptInit,
        .AES256ECB_EncryptUpdate                           = R_SCE_AES256ECB_EncryptUpdate,
        .AES256ECB_EncryptFinal                            = R_SCE_AES256ECB_EncryptFinal,
        .AES256ECB_DecryptInit                             = R_SCE_AES256ECB_DecryptInit,
        .AES256ECB_DecryptUpdate                           = R_SCE_AES256ECB_DecryptUpdate,
        .AES256ECB_DecryptFinal                            = R_SCE_AES256ECB_DecryptFinal,
        .AES128CBC_EncryptInit                             = R_SCE_AES128CBC_EncryptInit,
        .AES128CBC_EncryptUpdate                           = R_SCE_AES128CBC_EncryptUpdate,
        .AES128CBC_EncryptFinal                            = R_SCE_AES128CBC_EncryptFinal,
        .AES128CBC_DecryptInit                             = R_SCE_AES128CBC_DecryptInit,
        .AES128CBC_DecryptUpdate                           = R_SCE_AES128CBC_DecryptUpdate,
        .AES128CBC_DecryptFinal                            = R_SCE_AES128CBC_DecryptFinal,
        .AES256CBC_EncryptInit                             = R_SCE_AES256CBC_EncryptInit,
        .AES256CBC_EncryptUpdate                           = R_SCE_AES256CBC_EncryptUpdate,
        .AES256CBC_EncryptFinal                            = R_SCE_AES256CBC_EncryptFinal,
        .AES256CBC_DecryptInit                             = R_SCE_AES256CBC_DecryptInit,
        .AES256CBC_DecryptUpdate                           = R_SCE_AES256CBC_DecryptUpdate,
        .AES256CBC_DecryptFinal                            = R_SCE_AES256CBC_DecryptFinal,
        .AES128CTR_EncryptInit                             = R_SCE_AES128CTR_EncryptInit,
        .AES128CTR_EncryptUpdate                           = R_SCE_AES128CTR_EncryptUpdate,
        .AES128CTR_EncryptFinal                            = R_SCE_AES128CTR_EncryptFinal,
        .AES128CTR_DecryptInit                             = R_SCE_AES128CTR_DecryptInit,
        .AES128CTR_DecryptUpdate                           = R_SCE_AES128CTR_DecryptUpdate,
        .AES128CTR_DecryptFinal                            = R_SCE_AES128CTR_DecryptFinal,
        .AES256CTR_EncryptInit                             = R_SCE_AES256CTR_EncryptInit,
        .AES256CTR_EncryptUpdate                           = R_SCE_AES256CTR_EncryptUpdate,
        .AES256CTR_EncryptFinal                            = R_SCE_AES256CTR_EncryptFinal,
        .AES256CTR_DecryptInit                             = R_SCE_AES256CTR_DecryptInit,
        .AES256CTR_DecryptUpdate                           = R_SCE_AES256CTR_DecryptUpdate,
        .AES256CTR_DecryptFinal                            = R_SCE_AES256CTR_DecryptFinal,
        .AES128CMAC_GenerateInit                           = R_SCE_AES128CMAC_GenerateInit,
        .AES128CMAC_GenerateUpdate                         = R_SCE_AES128CMAC_GenerateUpdate,
        .AES128CMAC_GenerateFinal                          = R_SCE_AES128CMAC_GenerateFinal,
        .AES128CMAC_VerifyInit                             = R_SCE_AES128CMAC_VerifyInit,
        .AES128CMAC_VerifyUpdate                           = R_SCE_AES128CMAC_VerifyUpdate,
        .AES128CMAC_VerifyFinal                            = R_SCE_AES128CMAC_VerifyFinal,
        .AES256CMAC_GenerateInit                           = R_SCE_AES256CMAC_GenerateInit,
        .AES256CMAC_GenerateUpdate                         = R_SCE_AES256CMAC_GenerateUpdate,
        .AES256CMAC_GenerateFinal                          = R_SCE_AES256CMAC_GenerateFinal,
        .AES256CMAC_VerifyInit                             = R_SCE_AES256CMAC_VerifyInit,
        .AES256CMAC_VerifyUpdate                           = R_SCE_AES256CMAC_VerifyUpdate,
        .AES256CMAC_VerifyFinal                            = R_SCE_AES256CMAC_VerifyFinal,
        .SHA224_Init                                       = R_SCE_SHA224_Init,
        .SHA224_Update                                     = R_SCE_SHA224_Update,
        .SHA224_Final                                      = R_SCE_SHA224_Final,
        .SHA256_Init                                       = R_SCE_SHA256_Init,
        .SHA256_Update                                     = R_SCE_SHA256_Update,
        .SHA256_Final                                      = R_SCE_SHA256_Final,
        .RSA1024_WrappedKeyPairGenerate                    = R_SCE_RSA1024_WrappedKeyPairGenerate,
        .RSA2048_WrappedKeyPairGenerate                    = R_SCE_RSA2048_WrappedKeyPairGenerate,
        .RSA1024_EncryptedPublicKeyWrap                    = R_SCE_RSA1024_EncryptedPublicKeyWrap,
        .RSA1024_EncryptedPrivateKeyWrap                   = R_SCE_RSA1024_EncryptedPrivateKeyWrap,
        .RSA2048_EncryptedPublicKeyWrap                    = R_SCE_RSA2048_EncryptedPublicKeyWrap,
        .RSA2048_EncryptedPrivateKeyWrap                   = R_SCE_RSA2048_EncryptedPrivateKeyWrap,
        .RSA4096_EncryptedPublicKeyWrap                    = R_SCE_RSA4096_EncryptedPublicKeyWrap,
        .RSASSA_PKCS1024_SignatureGenerate                 = R_SCE_RSASSA_PKCS1024_SignatureGenerate,
        .RSASSA_PKCS2048_SignatureGenerate                 = R_SCE_RSASSA_PKCS2048_SignatureGenerate,
        .RSASSA_PKCS1024_SignatureVerify                   = R_SCE_RSASSA_PKCS1024_SignatureVerify,
        .RSASSA_PKCS2048_SignatureVerify                   = R_SCE_RSASSA_PKCS2048_SignatureVerify,
        .RSASSA_PKCS4096_SignatureVerify                   = R_SCE_RSASSA_PKCS4096_SignatureVerify,
        .RSAES_PKCS1024_Encrypt                            = R_SCE_RSAES_PKCS1024_Encrypt,
        .RSAES_PKCS2048_Encrypt                            = R_SCE_RSAES_PKCS2048_Encrypt,
        .RSAES_PKCS4096_Encrypt                            = R_SCE_RSAES_PKCS4096_Encrypt,
        .RSAES_PKCS1024_Decrypt                            = R_SCE_RSAES_PKCS1024_Decrypt,
        .RSAES_PKCS2048_Decrypt                            = R_SCE_RSAES_PKCS2048_Decrypt,
        .ECC_secp192r1_WrappedKeyPairGenerate              = R_SCE_ECC_secp192r1_WrappedKeyPairGenerate,
        .ECC_secp224r1_WrappedKeyPairGenerate              = R_SCE_ECC_secp224r1_WrappedKeyPairGenerate,
        .ECC_secp256r1_WrappedKeyPairGenerate              = R_SCE_ECC_secp256r1_WrappedKeyPairGenerate,
        .ECC_BrainpoolP512r1_WrappedKeyPairGenerate        = R_SCE_ECC_BrainpoolP512r1_WrappedKeyPairGenerate,
        .ECC_secp192r1_EncryptedPublicKeyWrap              = R_SCE_ECC_secp192r1_EncryptedPublicKeyWrap,
        .ECC_secp224r1_EncryptedPublicKeyWrap              = R_SCE_ECC_secp224r1_EncryptedPublicKeyWrap,
        .ECC_secp256r1_EncryptedPublicKeyWrap              = R_SCE_ECC_secp256r1_EncryptedPublicKeyWrap,
        .ECC_BrainpoolP512r1_EncryptedPublicKeyWrap        = R_SCE_ECC_BrainpoolP512r1_EncryptedPublicKeyWrap,
        .ECC_secp192r1_EncryptedPrivateKeyWrap             = R_SCE_ECC_secp192r1_EncryptedPrivateKeyWrap,
        .ECC_secp224r1_EncryptedPrivateKeyWrap             = R_SCE_ECC_secp224r1_EncryptedPrivateKeyWrap,
        .ECC_secp256r1_EncryptedPrivateKeyWrap             = R_SCE_ECC_secp256r1_EncryptedPrivateKeyWrap,
        .ECC_BrainpoolP512r1_EncryptedPrivateKeyWrap       = R_SCE_ECC_BrainpoolP512r1_EncryptedPrivateKeyWrap,
        .ECDSA_secp192r1_SignatureGenerate                 = R_SCE_ECDSA_secp192r1_SignatureGenerate,
        .ECDSA_secp224r1_SignatureGenerate                 = R_SCE_ECDSA_secp224r1_SignatureGenerate,
        .ECDSA_secp256r1_SignatureGenerate                 = R_SCE_ECDSA_secp256r1_SignatureGenerate,
        .ECDSA_BrainpoolP512r1_SignatureGenerate           = R_SCE_ECDSA_BrainpoolP512r1_SignatureGenerate,
        .ECDSA_secp192r1_SignatureVerify                   = R_SCE_ECDSA_secp192r1_SignatureVerify,
        .ECDSA_secp224r1_SignatureVerify                   = R_SCE_ECDSA_secp224r1_SignatureVerify,
        .ECDSA_secp256r1_SignatureVerify                   = R_SCE_ECDSA_secp256r1_SignatureVerify,
        .ECDSA_BrainpoolP512r1_SignatureVerify             = R_SCE_ECDSA_BrainpoolP512r1_SignatureVerify,
};

/*******************************************************************************************************************//**
 * @addtogroup SCE_PROTECTED
 * @{
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Functions
 **********************************************************************************************************************/

/*******************************************************************************************************************//**
 * Enables use of SCE functionality.
 *
 * @param[in] p_ctrl Pointer to control structure.
 * @param[in] p_cfg Pointer to pin configuration structure.
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              The error-detection self-test failed to terminate normally.
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource needed
 *                                              by the processing routine was in use by another processing routine.
 * @retval FSP_ERR_CRYPTO_SCE_RETRY             Indicates that an entropy evaluation failure occurred.
 *                                              Run the function again.
 *
 * @return See @ref RENESAS_ERROR_CODES or functions called by this function for other possible return codes.
 *
 * @note The valid pre-run state is SCE disabled.
 *       The pre-run state is SCE Disabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Open (sce_ctrl_t * const p_ctrl, sce_cfg_t const * const p_cfg)
{
    fsp_err_t error_code = FSP_SUCCESS;
    uint32_t state;

    sce_instance_ctrl_t * p_instance_ctrl = (sce_instance_ctrl_t *) p_ctrl;
    p_instance_ctrl->open = 1;
    gs_lifecycle          = p_cfg->lifecycle;

    /* Check for need to do self-test */
    error_code = R_SCE_StateCheckSub(&state);
    if (FSP_SUCCESS != error_code)
    {
        return error_code;
    }

    if (HW_STATE_UNAVAILABLE == state)
    {
        error_code = R_SCE_SelfCheck2Private();
        if (FSP_SUCCESS != error_code)
        {
            return error_code;
        }
    }

    g_private_id_counter       = 0;
    g_aes128ecbenc_private_id  = 0;
    g_aes128ecbdec_private_id  = 0;
    g_aes256ecbenc_private_id  = 0;
    g_aes256ecbdec_private_id  = 0;
    g_aes128cbcenc_private_id  = 0;
    g_aes128cbcdec_private_id  = 0;
    g_aes256cbcenc_private_id  = 0;
    g_aes256cbcdec_private_id  = 0;
    g_aes128ctrenc_private_id  = 0;
    g_aes128ctrdec_private_id  = 0;
    g_aes256ctrenc_private_id  = 0;
    g_aes256ctrdec_private_id  = 0;
    g_aes128cmacgen_private_id = 0;
    g_aes128cmacver_private_id = 0;
    g_aes256cmacgen_private_id = 0;
    g_aes256cmacver_private_id = 0;
    g_sha224_private_id        = 0;
    g_sha256_private_id        = 0;

    return error_code;
}

/*******************************************************************************************************************//**
 * Stops supply of power to the SCE.
 *
 * @param[in] p_ctrl Pointer to control structure.
 *
 * @retval FSP_SUCCESS              Normal termination
 *
 * @note The pre-run state is any state.
 *       After the function runs the state transitions to SCE Disabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Close (sce_ctrl_t * const p_ctrl)
{
    sce_instance_ctrl_t * p_instance_ctrl = (sce_instance_ctrl_t *) p_ctrl;
    p_instance_ctrl->open = 0;

    return FSP_SUCCESS;
}

/*******************************************************************************************************************//**
 * Software reset to SCE.
 *
 * Reverts the state to the SCE initial state.
 *
 * @retval FSP_SUCCESS              Normal termination
 *
 * @note The pre-run state is any state.
 *       After the function runs the state transitions to SCE Disabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_SoftwareReset (void)
{
    R_SCE_SoftwareResetSub();

    return FSP_SUCCESS;
}

/*******************************************************************************************************************//**
 * This API can generate 4 words random number.
 *
 * @param[in,out] random Stores 4words (16 bytes) random data.
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource needed
 *                                              by the processing routine was in use by another processing routine.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_RandomNumberGenerate (uint32_t * random)
{
    return R_SCE_GenerateRandomNumberSub(random);
}

/*******************************************************************************************************************//**
 * This API outputs 128-bit AES wrapped key from a random number.
 *
 * This API generates a wrapped key from a random number in the SCE. Accordingly, user key input is unnecessary.
 * By encrypting data using the wrapped key is output by this API, dead copying of data can be prevented.
 *
 * @param[in,out] wrapped_key 128-bit AES wrapped key
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource needed
 *                                              by the processing routine was in use by another processing routine.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Disabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES128_WrappedKeyGenerate (sce_aes_wrapped_key_t * wrapped_key)
{
    fsp_err_t error_code = FSP_SUCCESS;
    error_code = R_SCE_GenerateAes128RandomKeyIndexSub(wrapped_key->value);
    if (FSP_SUCCESS == error_code)
    {
        wrapped_key->type = SCE_KEY_INDEX_TYPE_AES128;
    }
    else if (FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT == error_code)
    {
        wrapped_key->type = SCE_KEY_INDEX_TYPE_INVALID;
    }
    else
    {
        /* not used */
    }

    return error_code;
}

/*******************************************************************************************************************//**
 * This API outputs 256-bit AES wrapped key from a random number.
 *
 * This API generates a wrapped key from a random number in the SCE. Accordingly, user key input is unnecessary.
 * By encrypting data using the wrapped key is output by this API, dead copying of data can be prevented.
 *
 * @param[in,out] wrapped_key 256-bit AES wrapped key
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource needed
 *                                              by the processing routine was in use by another processing routine.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Disabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES256_WrappedKeyGenerate (sce_aes_wrapped_key_t * wrapped_key)
{
    fsp_err_t error_code = FSP_SUCCESS;
    error_code = R_SCE_GenerateAes256RandomKeyIndexSub(wrapped_key->value);
    if (FSP_SUCCESS == error_code)
    {
        wrapped_key->type = SCE_KEY_INDEX_TYPE_AES256;
    }
    else
    {
        wrapped_key->type = SCE_KEY_INDEX_TYPE_INVALID;
    }

    return error_code;
}

/*******************************************************************************************************************//**
 * This API wraps 128-bit AES key within the user routine.
 *
 * @param[in] initial_vector Initialization vector when generating encrypted_key
 * @param[in] encrypted_key  User key encryptedand MAC appended
 * @param[in] key_update_key Key update keyring
 * @param[in,out] wrapped_key   128-bit AES wrapped key
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource needed
 *                                              by the processing routine was in use by another processing routine.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              An internal error occurred.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES128_EncryptedKeyWrap (uint8_t               * initial_vector,
        uint8_t               * encrypted_key,
        sce_key_update_key_t  * key_update_key,
        sce_aes_wrapped_key_t * wrapped_key)
{
    fsp_err_t     error_code = FSP_SUCCESS;
    lifecycle_t   lifecycle  = gs_lifecycle;
    sce_oem_cmd_t key_type   = SCE_OEM_CMD_AES128;

    memcpy(S_INST2, key_update_key->value, (HW_SCE_SINST2_WORD_SIZE * 4));

    error_code = R_SCE_UpdateOemKeyIndexPrivate(lifecycle,
            key_type,
            initial_vector,
            encrypted_key,
            (uint32_t *) &wrapped_key->value);

    if (FSP_SUCCESS == error_code)
    {
        wrapped_key->type = SCE_KEY_INDEX_TYPE_AES128;
    }
    else
    {
        wrapped_key->type = SCE_KEY_INDEX_TYPE_INVALID;
    }

    return error_code;
}

/*******************************************************************************************************************//**
 * This API wraps 256-bit AES key within the user routine.
 *
 * @param[in] initial_vector Initialization vector when generating encrypted_key
 * @param[in] encrypted_key  User key encryptedand MAC appended
 * @param[in] key_update_key Key update keyring
 * @param[in,out] wrapped_key   256-bit AES wrapped key
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource needed
 *                                              by the processing routine was in use by another processing routine.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              An internal error occurred.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES256_EncryptedKeyWrap (uint8_t               * initial_vector,
        uint8_t               * encrypted_key,
        sce_key_update_key_t  * key_update_key,
        sce_aes_wrapped_key_t * wrapped_key)
{
    fsp_err_t     error_code = FSP_SUCCESS;
    lifecycle_t   lifecycle  = gs_lifecycle;
    sce_oem_cmd_t key_type   = SCE_OEM_CMD_AES256;

    memcpy(S_INST2, key_update_key->value, (HW_SCE_SINST2_WORD_SIZE * 4));

    error_code = R_SCE_UpdateOemKeyIndexPrivate(lifecycle,
            key_type,
            initial_vector,
            encrypted_key,
            (uint32_t *) &wrapped_key->value);

    if (FSP_SUCCESS == error_code)
    {
        wrapped_key->type = SCE_KEY_INDEX_TYPE_AES256;
    }
    else
    {
        wrapped_key->type = SCE_KEY_INDEX_TYPE_INVALID;
    }

    return error_code;
}

/*******************************************************************************************************************//**
 * This API outputs a wrapped key pair for a 1024-bit RSA public key and private key pair. These keys are generated
 * from a random value produced internally by the SCE. Consequently, there is no need to input a user key.
 * Dead copying of data can be prevented by encrypting the data using the wrapped key output by this API.
 * A public wrapped key is generated by wrapped_pair_key->pub_key, and a private wrapped key is generated by
 * wrapped_pair_key->priv_key. As the public key exponent, only 0x00010001 is generated.
 *
 * @param [in,out] wrapped_pair_key User key index for RSA 1024-bit public key and private key pair
 *
 * @retval FSP_SUCCESS                          Normal end
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource needed
 *                                              by the processing routine was in use by another processing routine.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              An internal error occurred. Key generation failed.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_RSA1024_WrappedKeyPairGenerate (sce_rsa1024_wrapped_pair_key_t * wrapped_pair_key)
{
    fsp_err_t error_code = FSP_SUCCESS;
    error_code = R_SCE_GenerateRsa1024RandomKeyIndexSub(SCE_RSA_RETRY_COUNT_FOR_RSA1024_KEY_GENERATION,
            /* Casting uint32_t pointer is used for address. */
            (uint32_t *) &wrapped_pair_key->pub_key.value,
            (uint32_t *) &wrapped_pair_key->priv_key.value);
    if (FSP_SUCCESS == error_code)
    {
        wrapped_pair_key->pub_key.type  = SCE_KEY_INDEX_TYPE_RSA1024_PUBLIC;
        wrapped_pair_key->priv_key.type = SCE_KEY_INDEX_TYPE_RSA1024_PRIVATE;
    }
    else
    {
        wrapped_pair_key->pub_key.type  = SCE_KEY_INDEX_TYPE_INVALID;
        wrapped_pair_key->priv_key.type = SCE_KEY_INDEX_TYPE_INVALID;
    }

    return error_code;
}

/*******************************************************************************************************************//**
 * This API outputs a wrapped key pair for a 2048-bit RSA public key and private key pair. These keys are generated
 * from a random value produced internally by the SCE. Consequently, there is no need to input a user key.
 * Dead copying of data can be prevented by encrypting the data using the wrapped key output by this API.
 * A public wrapped key is generated by wrapped_pair_key->pub_key, and a private wrapped key is generated by
 * wrapped_pair_key->priv_key. As the public key exponent, only 0x00010001 is generated.
 *
 * @param [in,out] wrapped_pair_key User key index for RSA 2048-bit public key and private key pair
 *
 * @retval FSP_SUCCESS                          Normal end
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource needed
 *                                              by the processing routine was in use by another processing routine.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              An internal error occurred. Key generation failed.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_RSA2048_WrappedKeyPairGenerate (sce_rsa2048_wrapped_pair_key_t * wrapped_pair_key)
{
    fsp_err_t error_code = FSP_SUCCESS;
    error_code = R_SCE_GenerateRsa2048RandomKeyIndexSub(SCE_RSA_RETRY_COUNT_FOR_RSA2048_KEY_GENERATION,
            /* Casting uint32_t pointer is used for address. */
            (uint32_t *) &wrapped_pair_key->pub_key.value,
            (uint32_t *) &wrapped_pair_key->priv_key.value);
    if (FSP_SUCCESS == error_code)
    {
        wrapped_pair_key->pub_key.type  = SCE_KEY_INDEX_TYPE_RSA2048_PUBLIC;
        wrapped_pair_key->priv_key.type = SCE_KEY_INDEX_TYPE_RSA2048_PRIVATE;
    }
    else
    {
        wrapped_pair_key->pub_key.type  = SCE_KEY_INDEX_TYPE_INVALID;
        wrapped_pair_key->priv_key.type = SCE_KEY_INDEX_TYPE_INVALID;
    }

    return error_code;
}

/*******************************************************************************************************************//**
 * This API wraps 1024-bit RSA public key within the user routine.
 *
 * @param[in] initial_vector Initialization vector when generating encrypted_key
 * @param[in] encrypted_key  User key encryptedand MAC appended
 * @param[in] key_update_key Key update keyring
 * @param[in,out] wrapped_key   1024-bit RSA public wrapped key
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource needed
 *                                              by the processing routine was in use by another processing routine.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              An internal error occurred.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_RSA1024_EncryptedPublicKeyWrap (uint8_t                          * initial_vector,
        uint8_t                          * encrypted_key,
        sce_key_update_key_t             * key_update_key,
        sce_rsa1024_public_wrapped_key_t * wrapped_key)
{
    fsp_err_t     error_code = FSP_SUCCESS;
    lifecycle_t   lifecycle  = gs_lifecycle;
    sce_oem_cmd_t key_type   = SCE_OEM_CMD_RSA1024_PUBLIC;

    memcpy(S_INST2, key_update_key->value, (HW_SCE_SINST2_WORD_SIZE * 4));

    error_code = R_SCE_UpdateOemKeyIndexPrivate(lifecycle,
            key_type,
            initial_vector,
            encrypted_key,
            (uint32_t *) &wrapped_key->value);

    if (FSP_SUCCESS == error_code)
    {
        wrapped_key->type = SCE_KEY_INDEX_TYPE_RSA1024_PUBLIC;
    }
    else
    {
        wrapped_key->type = SCE_KEY_INDEX_TYPE_INVALID;
    }

    return error_code;
}

/*******************************************************************************************************************//**
 * This API wraps 1024-bit RSA private key within the user routine.
 *
 * @param[in] initial_vector Initialization vector when generating encrypted_key
 * @param[in] encrypted_key  User key encryptedand MAC appended
 * @param[in] key_update_key Key update keyring
 * @param[in,out] wrapped_key   1024-bit RSA private wrapped key
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource needed
 *                                              by the processing routine was in use by another processing routine.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              An internal error occurred.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_RSA1024_EncryptedPrivateKeyWrap (uint8_t                           * initial_vector,
        uint8_t                           * encrypted_key,
        sce_key_update_key_t              * key_update_key,
        sce_rsa1024_private_wrapped_key_t * wrapped_key)
{
    fsp_err_t     error_code = FSP_SUCCESS;
    lifecycle_t   lifecycle  = gs_lifecycle;
    sce_oem_cmd_t key_type   = SCE_OEM_CMD_RSA1024_PRIVATE;

    memcpy(S_INST2, key_update_key->value, (HW_SCE_SINST2_WORD_SIZE * 4));

    error_code = R_SCE_UpdateOemKeyIndexPrivate(lifecycle,
            key_type,
            initial_vector,
            encrypted_key,
            (uint32_t *) &wrapped_key->value);

    if (FSP_SUCCESS == error_code)
    {
        wrapped_key->type = SCE_KEY_INDEX_TYPE_RSA1024_PRIVATE;
    }
    else
    {
        wrapped_key->type = SCE_KEY_INDEX_TYPE_INVALID;
    }

    return error_code;
}

/*******************************************************************************************************************//**
 * This API wraps 2048-bit RSA public key within the user routine.
 *
 * @param[in] initial_vector Initialization vector when generating encrypted_key
 * @param[in] encrypted_key  User key encryptedand MAC appended
 * @param[in] key_update_key Key update keyring
 * @param[in,out] wrapped_key   1024-bit RSA public wrapped key
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource needed
 *                                              by the processing routine was in use by another processing routine.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              An internal error occurred.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_RSA2048_EncryptedPublicKeyWrap (uint8_t                          * initial_vector,
        uint8_t                          * encrypted_key,
        sce_key_update_key_t             * key_update_key,
        sce_rsa2048_public_wrapped_key_t * wrapped_key)
{
    fsp_err_t     error_code = FSP_SUCCESS;
    lifecycle_t   lifecycle  = gs_lifecycle;
    sce_oem_cmd_t key_type   = SCE_OEM_CMD_RSA2048_PUBLIC;

    memcpy(S_INST2, key_update_key->value, (HW_SCE_SINST2_WORD_SIZE * 4));

    error_code = R_SCE_UpdateOemKeyIndexPrivate(lifecycle,
            key_type,
            initial_vector,
            encrypted_key,
            (uint32_t *) &wrapped_key->value);

    if (FSP_SUCCESS == error_code)
    {
        wrapped_key->type = SCE_KEY_INDEX_TYPE_RSA2048_PUBLIC;
    }
    else
    {
        wrapped_key->type = SCE_KEY_INDEX_TYPE_INVALID;
    }

    return error_code;
}

/*******************************************************************************************************************//**
 * This API wraps 2048-bit RSA private key within the user routine.
 *
 * @param[in] initial_vector Initialization vector when generating encrypted_key
 * @param[in] encrypted_key  User key encryptedand MAC appended
 * @param[in] key_update_key Key update keyring
 * @param[in,out] wrapped_key   2048-bit RSA private wrapped key
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource needed
 *                                              by the processing routine was in use by another processing routine.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              An internal error occurred.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_RSA2048_EncryptedPrivateKeyWrap (uint8_t                           * initial_vector,
        uint8_t                           * encrypted_key,
        sce_key_update_key_t              * key_update_key,
        sce_rsa2048_private_wrapped_key_t * wrapped_key)
{
    fsp_err_t     error_code = FSP_SUCCESS;
    lifecycle_t   lifecycle  = gs_lifecycle;
    sce_oem_cmd_t key_type   = SCE_OEM_CMD_RSA2048_PRIVATE;

    memcpy(S_INST2, key_update_key->value, (HW_SCE_SINST2_WORD_SIZE * 4));

    error_code = R_SCE_UpdateOemKeyIndexPrivate(lifecycle,
            key_type,
            initial_vector,
            encrypted_key,
            (uint32_t *) &wrapped_key->value);

    if (FSP_SUCCESS == error_code)
    {
        wrapped_key->type = SCE_KEY_INDEX_TYPE_RSA2048_PRIVATE;
    }
    else
    {
        wrapped_key->type = SCE_KEY_INDEX_TYPE_INVALID;
    }

    return error_code;
}

/*******************************************************************************************************************//**
 * This API wraps 4096-bit RSA public key within the user routine.
 *
 * @param[in] initial_vector Initialization vector when generating encrypted_key
 * @param[in] encrypted_key  User key encryptedand MAC appended
 * @param[in] key_update_key Key update keyring
 * @param[in,out] wrapped_key   1024-bit RSA public wrapped key
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource needed
 *                                              by the processing routine was in use by another processing routine.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              An internal error occurred.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_RSA4096_EncryptedPublicKeyWrap (uint8_t                          * initial_vector,
        uint8_t                          * encrypted_key,
        sce_key_update_key_t             * key_update_key,
        sce_rsa4096_public_wrapped_key_t * wrapped_key)
{
    fsp_err_t     error_code = FSP_SUCCESS;
    lifecycle_t   lifecycle  = gs_lifecycle;
    sce_oem_cmd_t key_type   = SCE_OEM_CMD_RSA4096_PUBLIC;

    memcpy(S_INST2, key_update_key->value, (HW_SCE_SINST2_WORD_SIZE * 4));

    error_code = R_SCE_UpdateOemKeyIndexPrivate(lifecycle,
            key_type,
            initial_vector,
            encrypted_key,
            (uint32_t *) &wrapped_key->value);

    if (FSP_SUCCESS == error_code)
    {
        wrapped_key->type = SCE_KEY_INDEX_TYPE_RSA4096_PUBLIC;
    }
    else
    {
        wrapped_key->type = SCE_KEY_INDEX_TYPE_INVALID;
    }

    return error_code;
}

/*******************************************************************************************************************//**
 * This is an API for outputting a wrapped key pair for secp192r1 public key and private key pair.
 * These keys are generated from a random number value internally within the SCE.
 * There is therefore no need to input user keys. It is possible to prevent dead copying of data by using the
 * wrapped key output by this API to encrypt the data. The public key index is generated in wrapped_pair_key->pub_key,
 * and the private key index is generated in wrapped_pair_key->priv_key.
 *
 * @param[in,out] wrapped_pair_key Wrapped pair key for secp192r1 public key and private key pair
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource needed
 *                                              by the processing routine was in use by another processing routine.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              An internal error occurred.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_ECC_secp192r1_WrappedKeyPairGenerate (sce_ecc_wrapped_pair_key_t * wrapped_pair_key)
{
    uint32_t  indata_cmd;
    uint32_t  curvetype;
    fsp_err_t error_code = FSP_SUCCESS;

    indata_cmd = change_endian_long(SCE_ECC_KEY_LENGTH_192);
    curvetype  = change_endian_long(SCE_ECC_CURVE_TYPE_NIST);
    error_code = R_SCE_GenerateEccRandomKeyIndexSub(&curvetype,
            /* Casting uint32_t pointer is used for address. */
            &indata_cmd,
            (uint32_t *) &wrapped_pair_key->pub_key.value,
            (uint32_t *) &wrapped_pair_key->priv_key.value);
    if (FSP_SUCCESS == error_code)
    {
        wrapped_pair_key->pub_key.type  = SCE_KEY_INDEX_TYPE_ECC_P192_PUBLIC;
        wrapped_pair_key->priv_key.type = SCE_KEY_INDEX_TYPE_ECC_P192_PRIVATE;
    }
    else
    {
        wrapped_pair_key->pub_key.type  = SCE_KEY_INDEX_TYPE_INVALID;
        wrapped_pair_key->priv_key.type = SCE_KEY_INDEX_TYPE_INVALID;
    }

    return error_code;
}

/*******************************************************************************************************************//**
 * This is an API for outputting a wrapped key pair for secp224r1 public key and private key pair.
 * These keys are generated from a random number value internally within the SCE.
 * There is therefore no need to input user keys. It is possible to prevent dead copying of data by using the
 * wrapped key output by this API to encrypt the data. The public key index is generated in wrapped_pair_key->pub_key,
 * and the private key index is generated in wrapped_pair_key->priv_key.
 *
 * @param[in,out] wrapped_pair_key Wrapped pair key for secp224r1 public key and private key pair
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource needed
 *                                              by the processing routine was in use by another processing routine.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              An internal error occurred.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_ECC_secp224r1_WrappedKeyPairGenerate (sce_ecc_wrapped_pair_key_t * wrapped_pair_key)
{
    uint32_t  indata_cmd;
    uint32_t  curvetype;
    fsp_err_t error_code = FSP_SUCCESS;

    indata_cmd = change_endian_long(SCE_ECC_KEY_LENGTH_224);
    curvetype  = change_endian_long(SCE_ECC_CURVE_TYPE_NIST);
    error_code = R_SCE_GenerateEccRandomKeyIndexSub(&curvetype,
            /* Casting uint32_t pointer is used for address. */
            &indata_cmd,
            (uint32_t *) &wrapped_pair_key->pub_key.value,
            (uint32_t *) &wrapped_pair_key->priv_key.value);
    if (FSP_SUCCESS == error_code)
    {
        wrapped_pair_key->pub_key.type  = SCE_KEY_INDEX_TYPE_ECC_P224_PUBLIC;
        wrapped_pair_key->priv_key.type = SCE_KEY_INDEX_TYPE_ECC_P224_PRIVATE;
    }
    else
    {
        wrapped_pair_key->pub_key.type  = SCE_KEY_INDEX_TYPE_INVALID;
        wrapped_pair_key->priv_key.type = SCE_KEY_INDEX_TYPE_INVALID;
    }

    return error_code;
}

/*******************************************************************************************************************//**
 * This is an API for outputting a wrapped key pair for secp256r1 public key and private key pair.
 * These keys are generated from a random number value internally within the SCE.
 * There is therefore no need to input user keys. It is possible to prevent dead copying of data by using the
 * wrapped key output by this API to encrypt the data. The public key index is generated in wrapped_pair_key->pub_key,
 * and the private key index is generated in wrapped_pair_key->priv_key.
 *
 * @param[in,out] wrapped_pair_key Wrapped pair key for secp256r1 public key and private key pair
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource needed
 *                                              by the processing routine was in use by another processing routine.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              An internal error occurred.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_ECC_secp256r1_WrappedKeyPairGenerate (sce_ecc_wrapped_pair_key_t * wrapped_pair_key)
{
    uint32_t  indata_cmd;
    uint32_t  curvetype;
    fsp_err_t error_code = FSP_SUCCESS;

    indata_cmd = change_endian_long(SCE_ECC_KEY_LENGTH_256);
    curvetype  = change_endian_long(SCE_ECC_CURVE_TYPE_NIST);
    error_code = R_SCE_GenerateEccRandomKeyIndexSub(&curvetype,
            /* Casting uint32_t pointer is used for address. */
            &indata_cmd,
            (uint32_t *) &wrapped_pair_key->pub_key.value,
            (uint32_t *) &wrapped_pair_key->priv_key.value);
    if (FSP_SUCCESS == error_code)
    {
        wrapped_pair_key->pub_key.type  = SCE_KEY_INDEX_TYPE_ECC_P256_PUBLIC;
        wrapped_pair_key->priv_key.type = SCE_KEY_INDEX_TYPE_ECC_P256_PRIVATE;
    }
    else
    {
        wrapped_pair_key->pub_key.type  = SCE_KEY_INDEX_TYPE_INVALID;
        wrapped_pair_key->priv_key.type = SCE_KEY_INDEX_TYPE_INVALID;
    }

    return error_code;
}

/*******************************************************************************************************************//**
 * This is an API for outputting a wrapped key pair for BrainpoolP512r1 public key and private key pair. 
 * These keys are generated from a random number value internally within the SCE.
 * There is therefore no need to input user keys. It is possible to prevent dead copying of data by using the
 * wrapped key output by this API to encrypt the data. The public key index is generated in wrapped_pair_key->pub_key,
 * and the private key index is generated in wrapped_pair_key->priv_key.
 *
 * @param[in,out] wrapped_pair_key Wrapped pair key for BrainpoolP512r1 public key and private key pair
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource needed
 *                                              by the processing routine was in use by another processing routine.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              An internal error occurred.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_ECC_BrainpoolP512r1_WrappedKeyPairGenerate (sce_ecc_wrapped_pair_key_t * wrapped_pair_key)
{
    fsp_err_t error_code = FSP_SUCCESS;

    error_code = R_SCE_GenerateEccP512RandomKeyIndexSub(
            /* Casting uint32_t pointer is used for address. */
            (uint32_t *) &wrapped_pair_key->pub_key.value,
            (uint32_t *) &wrapped_pair_key->priv_key.value);
    if (FSP_SUCCESS == error_code)
    {
        wrapped_pair_key->pub_key.type  = SCE_KEY_INDEX_TYPE_ECC_P512_PUBLIC;
        wrapped_pair_key->priv_key.type = SCE_KEY_INDEX_TYPE_ECC_P512_PRIVATE;
    }
    else
    {
        wrapped_pair_key->pub_key.type  = SCE_KEY_INDEX_TYPE_INVALID;
        wrapped_pair_key->priv_key.type = SCE_KEY_INDEX_TYPE_INVALID;
    }

    return error_code;
}

/*******************************************************************************************************************//**
 * This API wraps secp192r1 public key within the user routine.
 *
 * @param[in] initial_vector Initialization vector when generating encrypted_key
 * @param[in] encrypted_key  User key encryptedand MAC appended
 * @param[in] key_update_key Key update keyring
 * @param[in,out] wrapped_key   secp192r1 public wrapped key
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource needed
 *                                              by the processing routine was in use by another processing routine.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              An internal error occurred.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_ECC_secp192r1_EncryptedPublicKeyWrap (uint8_t                      * initial_vector,
        uint8_t                      * encrypted_key,
        sce_key_update_key_t         * key_update_key,
        sce_ecc_public_wrapped_key_t * wrapped_key)
{
    fsp_err_t     error_code = FSP_SUCCESS;
    lifecycle_t   lifecycle  = gs_lifecycle;
    sce_oem_cmd_t key_type   = SCE_OEM_CMD_ECC_P192_PUBLIC;

    memcpy(S_INST2, key_update_key->value, (HW_SCE_SINST2_WORD_SIZE * 4));

    error_code = R_SCE_UpdateOemKeyIndexPrivate(lifecycle,
            key_type,
            initial_vector,
            encrypted_key,
            (uint32_t *) &wrapped_key->value);

    if (FSP_SUCCESS == error_code)
    {
        wrapped_key->type = SCE_KEY_INDEX_TYPE_ECC_P192_PUBLIC;
    }
    else
    {
        wrapped_key->type = SCE_KEY_INDEX_TYPE_INVALID;
    }

    return error_code;
}

/*******************************************************************************************************************//**
 * This API wraps secp224r1 public key within the user routine.
 *
 * @param[in] initial_vector Initialization vector when generating encrypted_key
 * @param[in] encrypted_key  User key encryptedand MAC appended
 * @param[in] key_update_key Key update keyring
 * @param[in,out] wrapped_key   secp224r1 public wrapped key
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource needed
 *                                              by the processing routine was in use by another processing routine.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              An internal error occurred.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_ECC_secp224r1_EncryptedPublicKeyWrap (uint8_t                      * initial_vector,
        uint8_t                      * encrypted_key,
        sce_key_update_key_t         * key_update_key,
        sce_ecc_public_wrapped_key_t * wrapped_key)
{
    fsp_err_t     error_code = FSP_SUCCESS;
    lifecycle_t   lifecycle  = gs_lifecycle;
    sce_oem_cmd_t key_type   = SCE_OEM_CMD_ECC_P224_PUBLIC;

    memcpy(S_INST2, key_update_key->value, (HW_SCE_SINST2_WORD_SIZE * 4));

    error_code = R_SCE_UpdateOemKeyIndexPrivate(lifecycle,
            key_type,
            initial_vector,
            encrypted_key,
            (uint32_t *) &wrapped_key->value);

    if (FSP_SUCCESS == error_code)
    {
        wrapped_key->type = SCE_KEY_INDEX_TYPE_ECC_P224_PUBLIC;
    }
    else
    {
        wrapped_key->type = SCE_KEY_INDEX_TYPE_INVALID;
    }

    return error_code;
}

/*******************************************************************************************************************//**
 * This API wraps secp256r1 public key within the user routine.
 *
 * @param[in] initial_vector Initialization vector when generating encrypted_key
 * @param[in] encrypted_key  User key encryptedand MAC appended
 * @param[in] key_update_key Key update keyring
 * @param[in,out] wrapped_key   secp256r1 public wrapped key
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource needed
 *                                              by the processing routine was in use by another processing routine.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              An internal error occurred.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_ECC_secp256r1_EncryptedPublicKeyWrap (uint8_t                      * initial_vector,
        uint8_t                      * encrypted_key,
        sce_key_update_key_t         * key_update_key,
        sce_ecc_public_wrapped_key_t * wrapped_key)
{
    fsp_err_t     error_code = FSP_SUCCESS;
    lifecycle_t   lifecycle  = gs_lifecycle;
    sce_oem_cmd_t key_type   = SCE_OEM_CMD_ECC_P256_PUBLIC;

    memcpy(S_INST2, key_update_key->value, (HW_SCE_SINST2_WORD_SIZE * 4));

    error_code = R_SCE_UpdateOemKeyIndexPrivate(lifecycle,
            key_type,
            initial_vector,
            encrypted_key,
            (uint32_t *) &wrapped_key->value);

    if (FSP_SUCCESS == error_code)
    {
        wrapped_key->type = SCE_KEY_INDEX_TYPE_ECC_P256_PUBLIC;
    }
    else
    {
        wrapped_key->type = SCE_KEY_INDEX_TYPE_INVALID;
    }

    return error_code;
}

/*******************************************************************************************************************//**
 * This API wraps BrainpoolP512r1 public key within the user routine.
 *
 * @param[in] initial_vector Initialization vector when generating encrypted_key
 * @param[in] encrypted_key  User key encryptedand MAC appended
 * @param[in] key_update_key Key update keyring
 * @param[in,out] wrapped_key   BrainpoolP512r1 public wrapped key
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource needed
 *                                              by the processing routine was in use by another processing routine.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              An internal error occurred.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_ECC_BrainpoolP512r1_EncryptedPublicKeyWrap (uint8_t * initial_vector,
        uint8_t                      * encrypted_key,
        sce_key_update_key_t         * key_update_key,
        sce_ecc_public_wrapped_key_t * wrapped_key)
{
    fsp_err_t     error_code = FSP_SUCCESS;
    lifecycle_t   lifecycle  = gs_lifecycle;
    sce_oem_cmd_t key_type   = SCE_OEM_CMD_ECC_P512_PUBLIC;

    memcpy(S_INST2, key_update_key->value, (HW_SCE_SINST2_WORD_SIZE * 4));

    error_code = R_SCE_UpdateOemKeyIndexPrivate(lifecycle,
            key_type,
            initial_vector,
            encrypted_key,
            (uint32_t *) &wrapped_key->value);

    if (FSP_SUCCESS == error_code)
    {
        wrapped_key->type = SCE_KEY_INDEX_TYPE_ECC_P512_PUBLIC;
    }
    else
    {
        wrapped_key->type = SCE_KEY_INDEX_TYPE_INVALID;
    }

    return error_code;
}

/*******************************************************************************************************************//**
 * This API wraps secp192r1 private key within the user routine.
 *
 * @param[in] initial_vector Initialization vector when generating encrypted_key
 * @param[in] encrypted_key  User key encryptedand MAC appended
 * @param[in] key_update_key Key update keyring
 * @param[in,out] wrapped_key   secp192r1 private wrapped key
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource needed
 *                                              by the processing routine was in use by another processing routine.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              An internal error occurred.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_ECC_secp192r1_EncryptedPrivateKeyWrap (uint8_t                       * initial_vector,
        uint8_t                       * encrypted_key,
        sce_key_update_key_t          * key_update_key,
        sce_ecc_private_wrapped_key_t * wrapped_key)
{
    fsp_err_t     error_code = FSP_SUCCESS;
    lifecycle_t   lifecycle  = gs_lifecycle;
    sce_oem_cmd_t key_type   = SCE_OEM_CMD_ECC_P192_PRIVATE;

    memcpy(S_INST2, key_update_key->value, (HW_SCE_SINST2_WORD_SIZE * 4));

    error_code = R_SCE_UpdateOemKeyIndexPrivate(lifecycle,
            key_type,
            initial_vector,
            encrypted_key,
            (uint32_t *) &wrapped_key->value);

    if (FSP_SUCCESS == error_code)
    {
        wrapped_key->type = SCE_KEY_INDEX_TYPE_ECC_P192_PRIVATE;
    }
    else
    {
        wrapped_key->type = SCE_KEY_INDEX_TYPE_INVALID;
    }

    return error_code;
}

/*******************************************************************************************************************//**
 * This API wraps secp224r1 private key within the user routine.
 *
 * @param[in] initial_vector Initialization vector when generating encrypted_key
 * @param[in] encrypted_key  User key encryptedand MAC appended
 * @param[in] key_update_key Key update keyring
 * @param[in,out] wrapped_key   secp224r1 private wrapped key
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource needed
 *                                              by the processing routine was in use by another processing routine.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              An internal error occurred.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_ECC_secp224r1_EncryptedPrivateKeyWrap (uint8_t                       * initial_vector,
        uint8_t                       * encrypted_key,
        sce_key_update_key_t          * key_update_key,
        sce_ecc_private_wrapped_key_t * wrapped_key)
{
    fsp_err_t     error_code = FSP_SUCCESS;
    lifecycle_t   lifecycle  = gs_lifecycle;
    sce_oem_cmd_t key_type   = SCE_OEM_CMD_ECC_P224_PRIVATE;

    memcpy(S_INST2, key_update_key->value, (HW_SCE_SINST2_WORD_SIZE * 4));

    error_code = R_SCE_UpdateOemKeyIndexPrivate(lifecycle,
            key_type,
            initial_vector,
            encrypted_key,
            (uint32_t *) &wrapped_key->value);

    if (FSP_SUCCESS == error_code)
    {
        wrapped_key->type = SCE_KEY_INDEX_TYPE_ECC_P224_PRIVATE;
    }
    else
    {
        wrapped_key->type = SCE_KEY_INDEX_TYPE_INVALID;
    }

    return error_code;
}

/*******************************************************************************************************************//**
 * This API wraps secp256r1 private key within the user routine.
 *
 * @param[in] initial_vector Initialization vector when generating encrypted_key
 * @param[in] encrypted_key  User key encryptedand MAC appended
 * @param[in] key_update_key Key update keyring
 * @param[in,out] wrapped_key   secp256r1 private wrapped key
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource needed
 *                                              by the processing routine was in use by another processing routine.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              An internal error occurred.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_ECC_secp256r1_EncryptedPrivateKeyWrap (uint8_t                       * initial_vector,
        uint8_t                       * encrypted_key,
        sce_key_update_key_t          * key_update_key,
        sce_ecc_private_wrapped_key_t * wrapped_key)
{
    fsp_err_t     error_code = FSP_SUCCESS;
    lifecycle_t   lifecycle  = gs_lifecycle;
    sce_oem_cmd_t key_type   = SCE_OEM_CMD_ECC_P256_PRIVATE;

    memcpy(S_INST2, key_update_key->value, (HW_SCE_SINST2_WORD_SIZE * 4));

    error_code = R_SCE_UpdateOemKeyIndexPrivate(lifecycle,
            key_type,
            initial_vector,
            encrypted_key,
            (uint32_t *) &wrapped_key->value);

    if (FSP_SUCCESS == error_code)
    {
        wrapped_key->type = SCE_KEY_INDEX_TYPE_ECC_P256_PRIVATE;
    }
    else
    {
        wrapped_key->type = SCE_KEY_INDEX_TYPE_INVALID;
    }

    return error_code;
}

/*******************************************************************************************************************//**
 * This API wraps BrainpoolP512r1 private key within the user routine.
 *
 * @param[in] initial_vector Initialization vector when generating encrypted_key
 * @param[in] encrypted_key  User key encryptedand MAC appended
 * @param[in] key_update_key Key update keyring
 * @param[in,out] wrapped_key   BrainpoolP512r1 private wrapped key
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource needed
 *                                              by the processing routine was in use by another processing routine.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              An internal error occurred.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_ECC_BrainpoolP512r1_EncryptedPrivateKeyWrap (uint8_t                       * initial_vector,
        uint8_t                       * encrypted_key,
        sce_key_update_key_t          * key_update_key,
        sce_ecc_private_wrapped_key_t * wrapped_key)
{
    fsp_err_t     error_code = FSP_SUCCESS;
    lifecycle_t   lifecycle  = gs_lifecycle;
    sce_oem_cmd_t key_type   = SCE_OEM_CMD_ECC_P512_PRIVATE;

    memcpy(S_INST2, key_update_key->value, (HW_SCE_SINST2_WORD_SIZE * 4));

    error_code = R_SCE_UpdateOemKeyIndexPrivate(lifecycle,
            key_type,
            initial_vector,
            encrypted_key,
            (uint32_t *) &wrapped_key->value);

    if (FSP_SUCCESS == error_code)
    {
        wrapped_key->type = SCE_KEY_INDEX_TYPE_ECC_P512_PRIVATE;
    }
    else
    {
        wrapped_key->type = SCE_KEY_INDEX_TYPE_INVALID;
    }

    return error_code;
}

/*******************************************************************************************************************//**
 * @} (end addtogroup SCE_PROTECTED)
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Private Functions
 **********************************************************************************************************************/

/*******************************************************************************************************************//**
 * Self check No2
 *
 * @retval FSP_SUCCESS                          Normal termination.
 * @retval FSP_ERR_CRYPTO_SCE_RETRY             self-test2 fail
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT resource conflict
 **********************************************************************************************************************/
fsp_err_t R_SCE_SelfCheck2Private (void)
{
    return R_SCE_SelfCheck2Sub();
}

/*******************************************************************************************************************//**
 * This API Updates OEM key index (wrapped key).
 *
 * @param[in] lifecycle         (no use)
 * @param[in] key_type          User key type define in sce_oem_cmd_t
 * @param[in] encrypted_oem_key User key encryptedand MAC appended
 * @param[in] key_update_key    Key update keyring
 * @param[in,out] wrapped_key   wrapped key
 *
 * @retval FSP_SUCCESS
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT
 * @retval FSP_ERR_CRYPTO_SCE_FAIL
 **********************************************************************************************************************/
fsp_err_t R_SCE_UpdateOemKeyIndexPrivate (lifecycle_t   lifecycle,
        sce_oem_cmd_t key_type,
        uint8_t     * iv,
        uint8_t     * encrypted_oem_key,
        uint32_t    * key_index)
{
    uint32_t  indata_cmd;
    uint32_t  curvetype;
    fsp_err_t error_code = FSP_SUCCESS;

    FSP_PARAMETER_NOT_USED(lifecycle);

    switch (key_type)
    {
        case SCE_OEM_CMD_AES128:
            error_code = R_SCE_AES128_EncryptedKeyWrapSub((uint32_t *) iv, (uint32_t *) encrypted_oem_key, key_index);
            break;
        case SCE_OEM_CMD_AES256:
            error_code = R_SCE_AES256_EncryptedKeyWrapSub((uint32_t *) iv, (uint32_t *) encrypted_oem_key, key_index);
            break;
        case SCE_OEM_CMD_RSA1024_PUBLIC:
            error_code = R_SCE_RSA1024_EncryptedPublicKeyWrapSub((uint32_t *) iv,
                    (uint32_t *) encrypted_oem_key, key_index);
            break;
        case SCE_OEM_CMD_RSA1024_PRIVATE:
            error_code = R_SCE_RSA1024_EncryptedPrivateKeyWrapSub((uint32_t *) iv,
                    (uint32_t *) encrypted_oem_key, key_index);
            break;
        case SCE_OEM_CMD_RSA2048_PUBLIC:
            error_code = R_SCE_RSA2048_EncryptedPublicKeyWrapSub((uint32_t *) iv,
                    (uint32_t *) encrypted_oem_key, key_index);
            break;
        case SCE_OEM_CMD_RSA2048_PRIVATE:
            error_code = R_SCE_RSA2048_EncryptedPrivateKeyWrapSub((uint32_t *) iv,
                    (uint32_t *) encrypted_oem_key, key_index);
            break;
        case SCE_OEM_CMD_RSA4096_PUBLIC:
            error_code = R_SCE_RSA4096_EncryptedPublicKeyWrapSub((uint32_t *) iv,
                    (uint32_t *) encrypted_oem_key, key_index);
            break;
        case SCE_OEM_CMD_ECC_P192_PUBLIC:
            indata_cmd = change_endian_long(SCE_ECC_KEY_LENGTH_192);
            curvetype  = change_endian_long(SCE_ECC_CURVE_TYPE_NIST);
            error_code = R_SCE_ECC192224256_EncryptedPublicKeyWrapSub(&curvetype,
                    &indata_cmd,
                    (uint32_t *) iv,
                    (uint32_t *) encrypted_oem_key,
                    key_index);
            break;
        case SCE_OEM_CMD_ECC_P224_PUBLIC:
            indata_cmd = change_endian_long(SCE_ECC_KEY_LENGTH_224);
            curvetype  = change_endian_long(SCE_ECC_CURVE_TYPE_NIST);
            error_code = R_SCE_ECC192224256_EncryptedPublicKeyWrapSub(&curvetype,
                    &indata_cmd,
                    (uint32_t *) iv,
                    (uint32_t *) encrypted_oem_key,
                    key_index);
            break;
        case SCE_OEM_CMD_ECC_P256_PUBLIC:
            indata_cmd = change_endian_long(SCE_ECC_KEY_LENGTH_256);
            curvetype  = change_endian_long(SCE_ECC_CURVE_TYPE_NIST);
            error_code = R_SCE_ECC192224256_EncryptedPublicKeyWrapSub(&curvetype,
                    &indata_cmd,
                    (uint32_t *) iv,
                    (uint32_t *) encrypted_oem_key,
                    key_index);
            break;
        case SCE_OEM_CMD_ECC_P512_PUBLIC:
            error_code = R_SCE_ECC_BrainpoolP512r1_EncryptedPublicKeyWrapSub((uint32_t *) iv,
                    (uint32_t *) encrypted_oem_key, key_index);
            break;
        case SCE_OEM_CMD_ECC_P192_PRIVATE:
            indata_cmd = change_endian_long(SCE_ECC_KEY_LENGTH_192);
            curvetype  = change_endian_long(SCE_ECC_CURVE_TYPE_NIST);
            error_code = R_SCE_ECC192224256_EncryptedPrivateKeyWrapSub(&curvetype,
                    &indata_cmd,
                    (uint32_t *) iv,
                    (uint32_t *) encrypted_oem_key,
                    key_index);
            break;
        case SCE_OEM_CMD_ECC_P224_PRIVATE:
            indata_cmd = change_endian_long(SCE_ECC_KEY_LENGTH_224);
            curvetype  = change_endian_long(SCE_ECC_CURVE_TYPE_NIST);
            error_code = R_SCE_ECC192224256_EncryptedPrivateKeyWrapSub(&curvetype,
                    &indata_cmd,
                    (uint32_t *) iv,
                    (uint32_t *) encrypted_oem_key,
                    key_index);
            break;
        case SCE_OEM_CMD_ECC_P256_PRIVATE:
            indata_cmd = change_endian_long(SCE_ECC_KEY_LENGTH_256);
            curvetype  = change_endian_long(SCE_ECC_CURVE_TYPE_NIST);
            error_code = R_SCE_ECC192224256_EncryptedPrivateKeyWrapSub(&curvetype,
                    &indata_cmd,
                    (uint32_t *) iv,
                    (uint32_t *) encrypted_oem_key,
                    key_index);
            break;
        case SCE_OEM_CMD_ECC_P512_PRIVATE:
            error_code = R_SCE_ECC_BrainpoolP512r1_EncryptedPrivateKeyWrapSub((uint32_t *) iv,
                    (uint32_t *) encrypted_oem_key, key_index);
            break;
        default:
            error_code = FSP_ERR_CRYPTO_SCE_FAIL; /* Not support Key type */
            break;
    }

    return error_code;
}
