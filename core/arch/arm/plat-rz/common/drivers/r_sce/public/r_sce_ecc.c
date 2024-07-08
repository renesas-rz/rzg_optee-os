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
 * File Name    : r_sce_ecc.c
 * Version      : 1.0
 * Description  : SCE ECC Public API source file
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
/* Hash data output position for ECDSA P-192. : (256 - 192) / 32 */
#define SCE_PRV_HASH_WORD_POS_ECDSA_P192    (2)
/* Hash data output position for ECDSA P-224. : (256 - 224) / 32 */
#define SCE_PRV_HASH_WORD_POS_ECDSA_P224    (1)
/* Hash data output position for ECDSA P-256. : (256 - 256) / 32 */
#define SCE_PRV_HASH_WORD_POS_ECDSA_P256    (0)
/* For ECDSA P-512 : (256 - 512) / 32 */
#define SCE_PRV_HASH_WORD_POS_ECDSA_P512    (0xFFFFFFF8UL)

#ifndef SCE_HEX_FF
#define SCE_HEX_FF                         (0xFF)
#endif
#ifndef SCE_HEX_80
#define SCE_HEX_80                         (0x80)
#endif
#ifndef SCE_DEC_64
#define SCE_DEC_64                         (64)
#endif

/***********************************************************************************************************************
 * Typedef definitions
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Private function prototypes
 **********************************************************************************************************************/
static fsp_err_t set_ecdsa_hash_data(sce_ecdsa_byte_data_t * p_message_hash,
        uint32_t              * data_buff,
        uint32_t                hash_word_pos);

/***********************************************************************************************************************
 * Private global variables
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Global variables
 **********************************************************************************************************************/

/*******************************************************************************************************************//**
 * @addtogroup SCE_PROTECTED
 * @{
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Functions
 **********************************************************************************************************************/

/*******************************************************************************************************************//**
 * When a message is specified in the first argument, message_hash->data_type, a SHA-256 hash of the message text
 * input as the first argument, message_hash->pdata, is calculated, and the signature text is written to the second
 * argument, signature, in accordance with secp192r1 using the private wrapped key input as the third argument,
 * wrapped_key.
 *
 * When a hash value is specified in the first argument, message_hash->data_type, the signature text for the first
 * 24 bytes of the SHA-256 hash value input to the first argument, message_hash->pdata, is written to the second
 * argument, signature, in accordance with secp192r1 using the private wrapped key input as the third argument,
 * wrapped_key.
 *
 * @param[in]     message_hash Message or hash value to which to attach signature
 *                             @arg message_hash->pdata       : Specifies pointer to array storing the message or 
 *                                                              hash value
 *                             @arg message_hash->data_length : Specifies effective data length of the array
 *                                                              (Specify only when Message is selected)
 *                             @arg message_hash->data_type   : Selects the data type of message_hash
 *                                                              (Message: 0 Hash value: 1)
 * @param[in,out] signature    Signature text storage destination information
 *                             @arg signature->pdata       : Specifies pointer to array storing signature text
 *                                                           The signature format is "0 padding (64 bits) || 
 *                                                           signature r (192 bits) || 0 padding (64 bits) || 
 *                                                           signature s (192 bits)".
 *                             @arg signature->data_length : Data length (byte units)
 * @param[in]     wrapped_key  Input wrapped key of secp192r1 private key.
 *
 * @retval FSP_SUCCESS                          Normal end
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource required
 *                                              by the processing is in use by other processing.
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL      Invalid wrapped key was input.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              An internal error occurred.
 * @retval FSP_ERR_CRYPTO_SCE_PARAMETER         Input data is invalid.
 * @retval FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION An invalid function was called.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_ECDSA_secp192r1_SignatureGenerate (sce_ecdsa_byte_data_t         * message_hash,
        sce_ecdsa_byte_data_t         * signature,
        sce_ecc_private_wrapped_key_t * wrapped_key)
{
    uint32_t  indata_cmd;
    uint32_t  curvetype;
    fsp_err_t error_code = FSP_SUCCESS;
    uint32_t  data_buff[SCE_PRV_HASH_WORD_POS_ECDSA_P192 + (HW_SCE_SHA256_HASH_LENGTH_BYTE_SIZE / sizeof(uint32_t))] =
    {
            0
    };

    error_code = set_ecdsa_hash_data(message_hash, data_buff, SCE_PRV_HASH_WORD_POS_ECDSA_P192);
    if (FSP_SUCCESS != error_code)
    {
        return error_code;
    }

    indata_cmd = change_endian_long(SCE_ECC_KEY_LENGTH_192);
    curvetype  = change_endian_long(SCE_ECC_CURVE_TYPE_NIST);
    error_code = R_SCE_EcdsaSignatureGenerateSub(
            /* Casting uint32_t pointer is used for address. */
            &curvetype,
            &indata_cmd,
            (uint32_t *) &wrapped_key->value,
            (uint32_t *) data_buff,
            (uint32_t *) signature->pdata);
    signature->data_length = HW_SCE_ECDSA_DATA_BYTE_SIZE;

    return error_code;
}

/*******************************************************************************************************************//**
 * When a message is specified in the first argument, message_hash->data_type, a SHA-256 hash of the message text
 * input as the first argument, message_hash->pdata, is calculated, and the signature text is written to the second
 * argument, signature, in accordance with secp224r1 using the private wrapped key input as the third argument,
 * wrapped_key.
 *
 * When a hash value is specified in the first argument, message_hash->data_type, the signature text for the first
 * 28 bytes of the SHA-256 hash value input to the first argument, message_hash->pdata, is written to the second
 * argument, signature, in accordance with secp224r1 using the private wrapped key input as the third argument,
 * wrapped_key.
 *
 * @param[in]     message_hash Message or hash value to which to attach signature
 *                             @arg message_hash->pdata       : Specifies pointer to array storing the message or 
 *                                                              hash value
 *                             @arg message_hash->data_length : Specifies effective data length of the array
 *                                                              (Specify only when Message is selected)
 *                             @arg message_hash->data_type   : Selects the data type of message_hash
 *                                                              (Message: 0 Hash value: 1)
 * @param[in,out] signature    Signature text storage destination information
 *                             @arg signature->pdata       : Specifies pointer to array storing signature text
 *                                                           The signature format is "0 padding (32 bits) || 
 *                                                           signature r (224 bits) || 0 padding (32 bits) || 
 *                                                           signature s (224 bits)".
 *                             @arg signature->data_length : Data length (byte units)
 * @param[in]     wrapped_key  Input wrapped key of secp224r1 private key.
 *
 * @retval FSP_SUCCESS                          Normal end
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource required
 *                                              by the processing is in use by other processing.
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL      Invalid wrapped key was input.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              An internal error occurred.
 * @retval FSP_ERR_CRYPTO_SCE_PARAMETER         Input data is invalid.
 * @retval FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION An invalid function was called.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_ECDSA_secp224r1_SignatureGenerate (sce_ecdsa_byte_data_t         * message_hash,
        sce_ecdsa_byte_data_t         * signature,
        sce_ecc_private_wrapped_key_t * wrapped_key)
{
    uint32_t  indata_cmd;
    uint32_t  curvetype;
    fsp_err_t error_code = FSP_SUCCESS;
    uint32_t  data_buff[SCE_PRV_HASH_WORD_POS_ECDSA_P224 + (HW_SCE_SHA256_HASH_LENGTH_BYTE_SIZE / sizeof(uint32_t))] =
    {
            0
    };

    error_code = set_ecdsa_hash_data(message_hash, data_buff, SCE_PRV_HASH_WORD_POS_ECDSA_P224);
    if (FSP_SUCCESS != error_code)
    {
        return error_code;
    }

    indata_cmd = change_endian_long(SCE_ECC_KEY_LENGTH_224);
    curvetype  = change_endian_long(SCE_ECC_CURVE_TYPE_NIST);
    error_code = R_SCE_EcdsaSignatureGenerateSub(
            /* Casting uint32_t pointer is used for address. */
            &curvetype,
            &indata_cmd,
            (uint32_t *) &wrapped_key->value,
            (uint32_t *) data_buff,
            (uint32_t *) signature->pdata);
    signature->data_length = HW_SCE_ECDSA_DATA_BYTE_SIZE;

    return error_code;
}

/*******************************************************************************************************************//**
 * When a message is specified in the first argument, message_hash->data_type, a SHA-256 hash of the message text
 * input as the first argument, message_hash->pdata, is calculated, and the signature text is written to the second
 * argument, signature, in accordance with secp256r1 using the private wrapped key input as the third argument,
 * wrapped_key.
 *
 * When a hash value is specified in the first argument, message_hash->data_type, the signature text for the first
 * 32 bytes of the SHA-256 hash value input to the first argument, message_hash->pdata, is written to the second
 * argument, signature, in accordance with secp256r1 using the private wrapped key input as the third argument,
 * wrapped_key.
 *
 * @param[in]     message_hash Message or hash value to which to attach signature
 *                             @arg message_hash->pdata       : Specifies pointer to array storing the message or 
 *                                                              hash value
 *                             @arg message_hash->data_length : Specifies effective data length of the array
 *                                                              (Specify only when Message is selected)
 *                             @arg message_hash->data_type   : Selects the data type of message_hash
 *                                                              (Message: 0 Hash value: 1)
 * @param[in,out] signature    Signature text storage destination information
 *                             @arg signature->pdata       : Specifies pointer to array storing signature text
 *                                                           The signature format is "signature r (256 bits) ||
 *                                                           signature s (256 bits)".
 *                             @arg signature->data_length : Data length (byte units)
 * @param[in]     wrapped_key  Input wrapped key of secp256r1 private key.
 *
 * @retval FSP_SUCCESS                          Normal end
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource required
 *                                              by the processing is in use by other processing.
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL      Invalid wrapped key was input.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              An internal error occurred.
 * @retval FSP_ERR_CRYPTO_SCE_PARAMETER         Input data is invalid.
 * @retval FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION An invalid function was called.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_ECDSA_secp256r1_SignatureGenerate (sce_ecdsa_byte_data_t         * message_hash,
        sce_ecdsa_byte_data_t         * signature,
        sce_ecc_private_wrapped_key_t * wrapped_key)
{
    uint32_t  indata_cmd;
    uint32_t  curvetype;
    fsp_err_t error_code = FSP_SUCCESS;
    uint32_t  data_buff[SCE_PRV_HASH_WORD_POS_ECDSA_P256 + (HW_SCE_SHA256_HASH_LENGTH_BYTE_SIZE / sizeof(uint32_t))] =
    {
            0
    };

    error_code = set_ecdsa_hash_data(message_hash, data_buff, SCE_PRV_HASH_WORD_POS_ECDSA_P256);
    if (FSP_SUCCESS != error_code)
    {
        return error_code;
    }

    indata_cmd = change_endian_long(SCE_ECC_KEY_LENGTH_256);
    curvetype  = change_endian_long(SCE_ECC_CURVE_TYPE_NIST);
    error_code = R_SCE_EcdsaSignatureGenerateSub(
            /* Casting uint32_t pointer is used for address. */
            &curvetype,
            &indata_cmd,
            (uint32_t *) &wrapped_key->value,
            (uint32_t *) data_buff,
            (uint32_t *) signature->pdata);
    signature->data_length = HW_SCE_ECDSA_DATA_BYTE_SIZE;

    return error_code;
}

/*******************************************************************************************************************//**
 * When a hash value is specified in the first argument, message_hash->data_type, the signature text for the first
 * 64 bytes of the SHA-512 hash value input to the first argument, message_hash->pdata, is written to the second
 * argument, signature, in accordance with BrainpoolP512r1 using the private wrapped key input as the third argument,
 * wrapped_key.
 *
 * @param[in]     message_hash Message or hash value to which to attach signature
 *                             @arg message_hash->pdata       : Specifies pointer to array storing the message or
 *                                                              hash value
 *                             @arg message_hash->data_length : Specifies effective data length of the array
 *                                                              (Specify only when Message is selected)
 *                             @arg message_hash->data_type   : Selects the data type of message_hash
 *                                                              (only Hash value(1) is support)
 * @param[in,out] signature    Signature text storage destination information
 *                             @arg signature->pdata       : Specifies pointer to array storing signature text
 *                                                           The signature format is "signature r (512 bits) ||
 *                                                           signature s (512 bits)".
 *                             @arg signature->data_length : Data length (byte units)
 * @param[in]     wrapped_key  Input wrapped key of BrainpoolP512r1 private key.
 *
 * @retval FSP_SUCCESS                          Normal end
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource required
 *                                              by the processing is in use by other processing.
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL      Invalid wrapped key was input.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              An internal error occurred.
 * @retval FSP_ERR_CRYPTO_SCE_PARAMETER         Input data is invalid.
 * @retval FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION An invalid function was called.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_ECDSA_BrainpoolP512r1_SignatureGenerate (sce_ecdsa_byte_data_t         * message_hash,
        sce_ecdsa_byte_data_t         * signature,
        sce_ecc_private_wrapped_key_t * wrapped_key)
{
    fsp_err_t error_code = FSP_SUCCESS;
    uint32_t  data_buff[(HW_SCE_SHA512_HASH_LENGTH_BYTE_SIZE / sizeof(uint32_t))] =
    {
            0
    };

    if (1 != message_hash->data_type)
    {
        return FSP_ERR_CRYPTO_SCE_PARAMETER;
    }

    error_code = set_ecdsa_hash_data(message_hash, data_buff, SCE_PRV_HASH_WORD_POS_ECDSA_P512);
    if (FSP_SUCCESS != error_code)
    {
        return error_code;
    }

    error_code = R_SCE_EcdsaP512SignatureGenerateSub(
            /* Casting uint32_t pointer is used for address. */
            (uint32_t *) &wrapped_key->value,
            (uint32_t *) data_buff,
            (uint32_t *) signature->pdata);
    signature->data_length = HW_SCE_ECDSA_P512_DATA_BYTE_SIZE;

    return error_code;
}

/*******************************************************************************************************************//**
 * When a message is specified in the second argument, message_hash->data_type, a SHA-256 hash of the message text
 * input as the second argument, message_hash->pdata, is calculated, and the signature text input to the first argument,
 * signature, is validated in accordance with secp192r1 using the public wrapped key input as the third argument,
 * wrapped_key.
 *
 * When a hash value is specified in the second argument, message_hash->data_type, the signature text for the first
 * 24 bytes of the SHA-256 hash value input to the second argument, message_hash->pdata, input to the first argument,
 * signature, is validated in accordance with secp192r1 using the public wrapped key input as the third argument,
 * wrapped_key.
 *
 * @param[in]     signature    Signature text information to be verified
 *                             @arg signature->pdata       : Specifies pointer to array storing signature text
 *                                                           The signature format is "0 padding (64 bits) || 
 *                                                           signature r (192 bits) || 0 padding (64 bits) || 
 *                                                           signature s (192 bits)".
 *                             @arg signature->data_length : Specifies the data length (byte units) (nonuse)
 * @param[in,out] message_hash Message or hash value to be verified
 *                             @arg message_hash->pdata       : Specifies pointer to array storing the message or 
 *                                                              hash value
 *                             @arg message_hash->data_length : Specifies effective data length of the array
 *                                                              (Specify only when Message is selected)
 *                             @arg message_hash->data_type   : Selects the data type of message_hash
 *                                                              (Message: 0 Hash value: 1)
 * @param[in]     wrapped_key  Input wrapped key of secp192r1 public key.
 *
 * @retval FSP_SUCCESS                          Normal end
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource required
 *                                              by the processing is in use by other processing.
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL      Invalid wrapped key was input.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              An internal error occurred or signature verification failed.
 * @retval FSP_ERR_CRYPTO_SCE_PARAMETER         Input data is invalid.
 * @retval FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION An invalid function was called.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_ECDSA_secp192r1_SignatureVerify (sce_ecdsa_byte_data_t        * signature,
        sce_ecdsa_byte_data_t        * message_hash,
        sce_ecc_public_wrapped_key_t * wrapped_key)
{
    uint32_t  indata_cmd;
    uint32_t  curvetype;
    fsp_err_t error_code = FSP_SUCCESS;
    uint32_t  data_buff[SCE_PRV_HASH_WORD_POS_ECDSA_P192 + (HW_SCE_SHA256_HASH_LENGTH_BYTE_SIZE / sizeof(uint32_t))] =
    {
            0
    };

    error_code = set_ecdsa_hash_data(message_hash, data_buff, SCE_PRV_HASH_WORD_POS_ECDSA_P192);
    if (FSP_SUCCESS != error_code)
    {
        return error_code;
    }

    indata_cmd = change_endian_long(SCE_ECC_KEY_LENGTH_192);
    curvetype  = change_endian_long(SCE_ECC_CURVE_TYPE_NIST);
    error_code = R_SCE_EcdsaSignatureVerificationSub(
            /* Casting uint32_t pointer is used for address. */
            &curvetype,
            &indata_cmd,
            (uint32_t *) &wrapped_key->value,
            (uint32_t *) data_buff,
            (uint32_t *) signature->pdata);

    return error_code;
}

/*******************************************************************************************************************//**
 * When a message is specified in the second argument, message_hash->data_type, a SHA-256 hash of the message text
 * input as the second argument, message_hash->pdata, is calculated, and the signature text input to the first argument,
 * signature, is validated in accordance with secp224r1 using the public wrapped key input as the third argument,
 * wrapped_key.
 *
 * When a hash value is specified in the second argument, message_hash->data_type, the signature text for the first
 * 28 bytes of the SHA-256 hash value input to the second argument, message_hash->pdata, input to the first argument,
 * signature, is validated in accordance with secp224r1 using the public wrapped key input as the third argument,
 * wrapped_key.
 *
 * @param[in]     signature    Signature text information to be verified
 *                             @arg signature->pdata       : Specifies pointer to array storing signature text
 *                                                           The signature format is "0 padding (32 bits) || 
 *                                                           signature r (224 bits) || 0 padding (32 bits) || 
 *                                                           signature s (224 bits)".
 *                             @arg signature->data_length : Specifies the data length (byte units) (nonuse)
 * @param[in,out] message_hash Message or hash value to be verified
 *                             @arg message_hash->pdata       : Specifies pointer to array storing the message or 
 *                                                              hash value
 *                             @arg message_hash->data_length : Specifies effective data length of the array
 *                                                              (Specify only when Message is selected)
 *                             @arg message_hash->data_type   : Selects the data type of message_hash
 *                                                              (Message: 0 Hash value: 1)
 * @param[in]     wrapped_key  Input wrapped key of secp224r1 public key.
 *
 * @retval FSP_SUCCESS                          Normal end
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource required
 *                                              by the processing is in use by other processing.
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL      Invalid wrapped key was input.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              An internal error occurred or signature verification failed.
 * @retval FSP_ERR_CRYPTO_SCE_PARAMETER         Input data is invalid.
 * @retval FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION An invalid function was called.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_ECDSA_secp224r1_SignatureVerify (sce_ecdsa_byte_data_t        * signature,
        sce_ecdsa_byte_data_t        * message_hash,
        sce_ecc_public_wrapped_key_t * wrapped_key)
{
    uint32_t  indata_cmd;
    uint32_t  curvetype;
    fsp_err_t error_code = FSP_SUCCESS;
    uint32_t  data_buff[SCE_PRV_HASH_WORD_POS_ECDSA_P224 + (HW_SCE_SHA256_HASH_LENGTH_BYTE_SIZE / sizeof(uint32_t))] =
    {
            0
    };

    error_code = set_ecdsa_hash_data(message_hash, data_buff, SCE_PRV_HASH_WORD_POS_ECDSA_P224);
    if (FSP_SUCCESS != error_code)
    {
        return error_code;
    }

    indata_cmd = change_endian_long(SCE_ECC_KEY_LENGTH_224);
    curvetype  = change_endian_long(SCE_ECC_CURVE_TYPE_NIST);
    error_code = R_SCE_EcdsaSignatureVerificationSub(
            /* Casting uint32_t pointer is used for address. */
            &curvetype,
            &indata_cmd,
            (uint32_t *) &wrapped_key->value,
            (uint32_t *) data_buff,
            (uint32_t *) signature->pdata);

    return error_code;
}

/*******************************************************************************************************************//**
 * When a message is specified in the second argument, message_hash->data_type, a SHA-256 hash of the message text
 * input as the second argument, message_hash->pdata, is calculated, and the signature text input to the first argument,
 * signature, is validated in accordance with secp256r1 using the public wrapped key input as the third argument,
 * wrapped_key.
 *
 * When a hash value is specified in the second argument, message_hash->data_type, the signature text for the first
 * 32 bytes of the SHA-256 hash value input to the second argument, message_hash->pdata, input to the first argument,
 * signature, is validated in accordance with secp256r1 using the public wrapped key input as the third argument,
 * wrapped_key.
 *
 * @param[in]     signature    Signature text information to be verified
 *                             @arg signature->pdata       : Specifies pointer to array storing signature text
 *                                                           The signature format is "signature r (256 bits) ||
 *                                                           signature s (256 bits)".
 *                             @arg signature->data_length : Specifies the data length (byte units) (nonuse)
 * @param[in,out] message_hash Message or hash value to be verified
 *                             @arg message_hash->pdata       : Specifies pointer to array storing the message or 
 *                                                              hash value
 *                             @arg message_hash->data_length : Specifies effective data length of the array
 *                                                              (Specify only when Message is selected)
 *                             @arg message_hash->data_type   : Selects the data type of message_hash
 *                                                              (Message: 0 Hash value: 1)
 * @param[in]     wrapped_key  Input wrapped key of secp256r1 public key.
 *
 * @retval FSP_SUCCESS                          Normal end
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource required
 *                                              by the processing is in use by other processing.
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL      Invalid wrapped key was input.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              An internal error occurred or signature verification failed.
 * @retval FSP_ERR_CRYPTO_SCE_PARAMETER         Input data is invalid.
 * @retval FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION An invalid function was called.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_ECDSA_secp256r1_SignatureVerify (sce_ecdsa_byte_data_t        * signature,
        sce_ecdsa_byte_data_t        * message_hash,
        sce_ecc_public_wrapped_key_t * wrapped_key)
{
    uint32_t  indata_cmd;
    uint32_t  curvetype;
    fsp_err_t error_code = FSP_SUCCESS;
    uint32_t  data_buff[SCE_PRV_HASH_WORD_POS_ECDSA_P256 + (HW_SCE_SHA256_HASH_LENGTH_BYTE_SIZE / sizeof(uint32_t))] =
    {
            0
    };

    error_code = set_ecdsa_hash_data(message_hash, data_buff, SCE_PRV_HASH_WORD_POS_ECDSA_P256);
    if (FSP_SUCCESS != error_code)
    {
        return error_code;
    }

    indata_cmd = change_endian_long(SCE_ECC_KEY_LENGTH_256);
    curvetype  = change_endian_long(SCE_ECC_CURVE_TYPE_NIST);
    error_code = R_SCE_EcdsaSignatureVerificationSub(
            /* Casting uint32_t pointer is used for address. */
            &curvetype,
            &indata_cmd,
            (uint32_t *) &wrapped_key->value,
            (uint32_t *) data_buff,
            (uint32_t *) signature->pdata);

    return error_code;
}

/*******************************************************************************************************************//**
 * When a hash value is specified in the second argument, message_hash->data_type, the signature text for the first
 * 32 bytes of the SHA-256 hash value input to the second argument, message_hash->pdata, input to the first argument,
 * signature, is validated in accordance with BrainpoolP512r1 using the public wrapped key input as the third argument,
 * wrapped_key.
 *
 * @param[in]     signature    Signature text information to be verified
 *                             @arg signature->pdata       : Specifies pointer to array storing signature text
 *                                                           The signature format is "signature r (512 bits) ||
 *                                                           signature s (512 bits)".
 *                             @arg signature->data_length : Specifies the data length (byte units) (nonuse)
 * @param[in,out] message_hash Message or hash value to be verified
 *                             @arg message_hash->pdata       : Specifies pointer to array storing the message or
 *                                                              hash value
 *                             @arg message_hash->data_length : Specifies effective data length of the array
 *                                                              (Specify only when Message is selected)
 *                             @arg message_hash->data_type   : Selects the data type of message_hash
 *                                                              (only Hash value(1) is support)
 * @param[in]     wrapped_key  Input wrapped key of BrainpoolP512r1 public key.
 *
 * @retval FSP_SUCCESS                          Normal end
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource required
 *                                              by the processing is in use by other processing.
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL      Invalid wrapped key was input.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              An internal error occurred or signature verification failed.
 * @retval FSP_ERR_CRYPTO_SCE_PARAMETER         Input data is invalid.
 * @retval FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION An invalid function was called.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_ECDSA_BrainpoolP512r1_SignatureVerify (sce_ecdsa_byte_data_t        * signature,
        sce_ecdsa_byte_data_t        * message_hash,
        sce_ecc_public_wrapped_key_t * wrapped_key)
{
    fsp_err_t error_code = FSP_SUCCESS;
    uint32_t  data_buff[(HW_SCE_SHA512_HASH_LENGTH_BYTE_SIZE / sizeof(uint32_t))] =
    {
            0
    };

    if (1 != message_hash->data_type)
    {
        return FSP_ERR_CRYPTO_SCE_PARAMETER;
    }

    error_code = set_ecdsa_hash_data(message_hash, data_buff, SCE_PRV_HASH_WORD_POS_ECDSA_P512);
    if (FSP_SUCCESS != error_code)
    {
        return error_code;
    }

    error_code = R_SCE_EcdsaP512SignatureVerificationSub(
            /* Casting uint32_t pointer is used for address. */
            (uint32_t *) &wrapped_key->value,
            (uint32_t *) data_buff,
            (uint32_t *) signature->pdata);

    return error_code;
}

/*******************************************************************************************************************//**
 * @} (end addtogroup SCE_PROTECTED)
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Private Functions
 **********************************************************************************************************************/

/*******************************************************************************************************************//**
 * For messages, SHA hash operation is performed and the hash value is set according to ECDSA.
 *
 * @param p_message_hash message or hash value information
 * @param data_buff      pointer to the hash value area, including 0 padding
 * @param hash_word_pos  hash value output word position from the beginning of the data_buff
 *
 * @retval FSP_SUCCESS                          Normal termination.
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT resource conflict
 * @retval FSP_ERR_CRYPTO_SCE_PARAMETER         Input parameter illegal
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              Internal error occurred.
 * @retval FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION An invalid function was called.
 **********************************************************************************************************************/
static fsp_err_t set_ecdsa_hash_data (sce_ecdsa_byte_data_t * p_message_hash,
        uint32_t              * data_buff,
        uint32_t                hash_word_pos)
{
    fsp_err_t            error_code    = FSP_SUCCESS;
    sce_sha_md5_handle_t ex_sha_handle =
    {
            0
    };
    uint32_t hash_length = 0;

    if (0 == p_message_hash->data_type)
    {
        if (SCE_PRV_HASH_WORD_POS_ECDSA_P512 != hash_word_pos)
        {
            R_SCE_SHA256_Init(&ex_sha_handle);
            error_code = R_SCE_SHA256_Update(&ex_sha_handle, p_message_hash->pdata, p_message_hash->data_length);
            if (FSP_SUCCESS == error_code)
            {
                /* Casting uint8_t pointer is used for address. */
                error_code = R_SCE_SHA256_Final(&ex_sha_handle, (uint8_t *) &data_buff[hash_word_pos], &hash_length);
            }
        }
        else
        {
            error_code = FSP_ERR_CRYPTO_SCE_FAIL;
        }
    }
    else if (1 == p_message_hash->data_type)
    {
        if (SCE_PRV_HASH_WORD_POS_ECDSA_P512 != hash_word_pos)
        {
            memcpy(&data_buff[hash_word_pos],
                    p_message_hash->pdata,
                    HW_SCE_SHA256_HASH_LENGTH_BYTE_SIZE - (hash_word_pos * sizeof(uint32_t)));
        }
        else
        {
            memcpy(data_buff, p_message_hash->pdata, HW_SCE_SHA512_HASH_LENGTH_BYTE_SIZE);
        }
    }
    else
    {
        error_code = FSP_ERR_CRYPTO_SCE_PARAMETER;
    }

    return error_code;
}
