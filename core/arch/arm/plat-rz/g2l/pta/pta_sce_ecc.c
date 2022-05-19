// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, Renesas Electronics
 */

#include <kernel/pseudo_ta.h>
#include <tee/tee_cryp_utl.h>

#include <r_sce.h>
#include <pta_sce_ecc.h>

#define PTA_NAME "sce_ecc.pta"

static uint32_t sha512_hash[HW_SCE_SHA512_HASH_LENGTH_BYTE_SIZE / sizeof(uint32_t)];

static TEE_Result ecdsa_secp192r1_signaturegenerate(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
    fsp_err_t err;

    sce_ecdsa_byte_data_t message_hash;
    sce_ecdsa_byte_data_t signature;
    sce_ecc_private_wrapped_key_t * wrapped_key;

    if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                    TEE_PARAM_TYPE_MEMREF_INOUT,
                    TEE_PARAM_TYPE_MEMREF_INPUT,
                    TEE_PARAM_TYPE_NONE)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    message_hash.pdata = (uint8_t *)params[0].memref.buffer;
    message_hash.data_length = params[0].memref.size;
    message_hash.data_type = 0;
    if ((NULL == message_hash.pdata) && (0 < message_hash.data_length)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    signature.pdata = (uint8_t *)params[1].memref.buffer;
    signature.data_length = params[1].memref.size;
    signature.data_type = 0;
    if ((NULL == signature.pdata) || (HW_SCE_ECDSA_DATA_BYTE_SIZE > signature.data_length)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    wrapped_key = (sce_ecc_private_wrapped_key_t *)params[2].memref.buffer;
    if ((NULL == wrapped_key) || (sizeof(sce_ecc_private_wrapped_key_t) != params[2].memref.size)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    err = g_sce_protected_on_sce.ECDSA_secp192r1_SignatureGenerate(&message_hash, &signature, wrapped_key);
    switch (err)
    {
        case FSP_SUCCESS:
            break;
        case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
            return TEE_ERROR_ACCESS_CONFLICT;
        case FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL:
            return TEE_ERROR_BAD_PARAMETERS;
        case FSP_ERR_CRYPTO_SCE_PARAMETER:
            return TEE_ERROR_BAD_PARAMETERS;
        default: /* FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION */
            return TEE_ERROR_BAD_STATE;
    }

    params[1].memref.size = signature.data_length;

    return TEE_SUCCESS;
}

static TEE_Result ecdsa_secp192r1_signatureverify(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
    fsp_err_t err;

    sce_ecdsa_byte_data_t signature;
    sce_ecdsa_byte_data_t message_hash;
    sce_ecc_public_wrapped_key_t * wrapped_key;

    if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                    TEE_PARAM_TYPE_MEMREF_INPUT,
                    TEE_PARAM_TYPE_MEMREF_INPUT,
                    TEE_PARAM_TYPE_NONE)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    signature.pdata = (uint8_t *)params[0].memref.buffer;
    signature.data_length = params[0].memref.size;
    signature.data_type = 0;
    if ((NULL == signature.pdata) || (HW_SCE_ECDSA_DATA_BYTE_SIZE != signature.data_length)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    message_hash.pdata = (uint8_t *)params[1].memref.buffer;
    message_hash.data_length = params[1].memref.size;
    message_hash.data_type = 0;
    if ((NULL == message_hash.pdata) && (0 < message_hash.data_length)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    wrapped_key = (sce_ecc_public_wrapped_key_t *)params[2].memref.buffer;
    if ((NULL == wrapped_key) || (sizeof(sce_ecc_public_wrapped_key_t) != params[2].memref.size)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    err = g_sce_protected_on_sce.ECDSA_secp192r1_SignatureVerify(&signature, &message_hash, wrapped_key);
    switch (err)
    {
        case FSP_SUCCESS:
            break;
        case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
            return TEE_ERROR_ACCESS_CONFLICT;
        case FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL:
            return TEE_ERROR_BAD_PARAMETERS;
        case FSP_ERR_CRYPTO_SCE_FAIL:
            return TEE_ERROR_GENERIC;
        case FSP_ERR_CRYPTO_SCE_PARAMETER:
            return TEE_ERROR_BAD_PARAMETERS;
        default: /* FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION */
            return TEE_ERROR_BAD_STATE;
    }

    return TEE_SUCCESS;
}

static TEE_Result ecdsa_secp224r1_signaturegenerate(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
    fsp_err_t err;

    sce_ecdsa_byte_data_t message_hash;
    sce_ecdsa_byte_data_t signature;
    sce_ecc_private_wrapped_key_t * wrapped_key;

    if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                    TEE_PARAM_TYPE_MEMREF_INOUT,
                    TEE_PARAM_TYPE_MEMREF_INPUT,
                    TEE_PARAM_TYPE_NONE)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    message_hash.pdata = (uint8_t *)params[0].memref.buffer;
    message_hash.data_length = params[0].memref.size;
    message_hash.data_type = 0;
    if ((NULL == message_hash.pdata) && (0 < message_hash.data_length)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    signature.pdata = (uint8_t *)params[1].memref.buffer;
    signature.data_length = params[1].memref.size;
    signature.data_type = 0;
    if ((NULL == signature.pdata) || (HW_SCE_ECDSA_DATA_BYTE_SIZE > signature.data_length)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    wrapped_key = (sce_ecc_private_wrapped_key_t *)params[2].memref.buffer;
    if ((NULL == wrapped_key) || (sizeof(sce_ecc_private_wrapped_key_t) != params[2].memref.size)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    err = g_sce_protected_on_sce.ECDSA_secp224r1_SignatureGenerate(&message_hash, &signature, wrapped_key);
    switch (err)
    {
        case FSP_SUCCESS:
            break;
        case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
            return TEE_ERROR_ACCESS_CONFLICT;
        case FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL:
            return TEE_ERROR_BAD_PARAMETERS;
        case FSP_ERR_CRYPTO_SCE_PARAMETER:
            return TEE_ERROR_BAD_PARAMETERS;
        default: /* FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION */
            return TEE_ERROR_BAD_STATE;
    }

    params[1].memref.size = signature.data_length;

    return TEE_SUCCESS;
}

static TEE_Result ecdsa_secp224r1_signatureverify(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
    fsp_err_t err;

    sce_ecdsa_byte_data_t signature;
    sce_ecdsa_byte_data_t message_hash;
    sce_ecc_public_wrapped_key_t * wrapped_key;

    if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                    TEE_PARAM_TYPE_MEMREF_INPUT,
                    TEE_PARAM_TYPE_MEMREF_INPUT,
                    TEE_PARAM_TYPE_NONE)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    signature.pdata = (uint8_t *)params[0].memref.buffer;
    signature.data_length = params[0].memref.size;
    signature.data_type = 0;
    if ((NULL == signature.pdata) || (HW_SCE_ECDSA_DATA_BYTE_SIZE != signature.data_length)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    message_hash.pdata = (uint8_t *)params[1].memref.buffer;
    message_hash.data_length = params[1].memref.size;
    message_hash.data_type = 0;
    if ((NULL == message_hash.pdata) && (0 < message_hash.data_length)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    wrapped_key = (sce_ecc_public_wrapped_key_t *)params[2].memref.buffer;
    if ((NULL == wrapped_key) || (sizeof(sce_ecc_public_wrapped_key_t) != params[2].memref.size)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    err = g_sce_protected_on_sce.ECDSA_secp224r1_SignatureVerify(&signature, &message_hash, wrapped_key);
    switch (err)
    {
        case FSP_SUCCESS:
            break;
        case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
            return TEE_ERROR_ACCESS_CONFLICT;
        case FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL:
            return TEE_ERROR_BAD_PARAMETERS;
        case FSP_ERR_CRYPTO_SCE_FAIL:
            return TEE_ERROR_GENERIC;
        case FSP_ERR_CRYPTO_SCE_PARAMETER:
            return TEE_ERROR_BAD_PARAMETERS;
        default: /* FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION */
            return TEE_ERROR_BAD_STATE;
    }

    return TEE_SUCCESS;
}

static TEE_Result ecdsa_secp256r1_signaturegenerate(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
    fsp_err_t err;

    sce_ecdsa_byte_data_t message_hash;
    sce_ecdsa_byte_data_t signature;
    sce_ecc_private_wrapped_key_t * wrapped_key;

    if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                    TEE_PARAM_TYPE_MEMREF_INOUT,
                    TEE_PARAM_TYPE_MEMREF_INPUT,
                    TEE_PARAM_TYPE_NONE)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    message_hash.pdata = (uint8_t *)params[0].memref.buffer;
    message_hash.data_length = params[0].memref.size;
    message_hash.data_type = 0;
    if ((NULL == message_hash.pdata) && (0 < message_hash.data_length)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    signature.pdata = (uint8_t *)params[1].memref.buffer;
    signature.data_length = params[1].memref.size;
    signature.data_type = 0;
    if ((NULL == signature.pdata) || (HW_SCE_ECDSA_DATA_BYTE_SIZE > signature.data_length)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    wrapped_key = (sce_ecc_private_wrapped_key_t *)params[2].memref.buffer;
    if ((NULL == wrapped_key) || (sizeof(sce_ecc_private_wrapped_key_t) != params[2].memref.size)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    err = g_sce_protected_on_sce.ECDSA_secp256r1_SignatureGenerate(&message_hash, &signature, wrapped_key);
    switch (err)
    {
        case FSP_SUCCESS:
            break;
        case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
            return TEE_ERROR_ACCESS_CONFLICT;
        case FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL:
            return TEE_ERROR_BAD_PARAMETERS;
        case FSP_ERR_CRYPTO_SCE_PARAMETER:
            return TEE_ERROR_BAD_PARAMETERS;
        default: /* FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION */
            return TEE_ERROR_BAD_STATE;
    }

    params[1].memref.size = signature.data_length;

    return TEE_SUCCESS;
}

static TEE_Result ecdsa_secp256r1_signatureverify(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
    fsp_err_t err;

    sce_ecdsa_byte_data_t signature;
    sce_ecdsa_byte_data_t message_hash;
    sce_ecc_public_wrapped_key_t * wrapped_key;

    if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                    TEE_PARAM_TYPE_MEMREF_INPUT,
                    TEE_PARAM_TYPE_MEMREF_INPUT,
                    TEE_PARAM_TYPE_NONE)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    signature.pdata = (uint8_t *)params[0].memref.buffer;
    signature.data_length = params[0].memref.size;
    signature.data_type = 0;
    if ((NULL == signature.pdata) || (HW_SCE_ECDSA_DATA_BYTE_SIZE != signature.data_length)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    message_hash.pdata = (uint8_t *)params[1].memref.buffer;
    message_hash.data_length = params[1].memref.size;
    message_hash.data_type = 0;
    if ((NULL == message_hash.pdata) && (0 < message_hash.data_length)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    wrapped_key = (sce_ecc_public_wrapped_key_t *)params[2].memref.buffer;
    if ((NULL == wrapped_key) || (sizeof(sce_ecc_public_wrapped_key_t) != params[2].memref.size)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    err = g_sce_protected_on_sce.ECDSA_secp256r1_SignatureVerify(&signature, &message_hash, wrapped_key);
    switch (err)
    {
        case FSP_SUCCESS:
            break;
        case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
            return TEE_ERROR_ACCESS_CONFLICT;
        case FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL:
            return TEE_ERROR_BAD_PARAMETERS;
        case FSP_ERR_CRYPTO_SCE_FAIL:
            return TEE_ERROR_GENERIC;
        case FSP_ERR_CRYPTO_SCE_PARAMETER:
            return TEE_ERROR_BAD_PARAMETERS;
        default: /* FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION */
            return TEE_ERROR_BAD_STATE;
    }

    return TEE_SUCCESS;
}

static TEE_Result ecdsa_brainpoolp512r1_signaturegenerate(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
    fsp_err_t err;

    sce_ecdsa_byte_data_t message_hash;
    sce_ecdsa_byte_data_t signature;
    sce_ecc_private_wrapped_key_t * wrapped_key;

    if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                    TEE_PARAM_TYPE_MEMREF_INOUT,
                    TEE_PARAM_TYPE_MEMREF_INPUT,
                    TEE_PARAM_TYPE_NONE)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    message_hash.pdata = (uint8_t *)sha512_hash;
    message_hash.data_length = HW_SCE_SHA512_HASH_LENGTH_BYTE_SIZE;
    message_hash.data_type = 1;
    err = tee_hash_createdigest(TEE_ALG_SHA512, params[0].memref.buffer, params[0].memref.size, 
        message_hash.pdata, message_hash.data_length);
    if (err) {
        return err;
    }
    
    signature.pdata = (uint8_t *)params[1].memref.buffer;
    signature.data_length = params[1].memref.size;
    signature.data_type = 0;
    if ((NULL == signature.pdata) || (HW_SCE_ECDSA_P512_DATA_BYTE_SIZE > signature.data_length)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    wrapped_key = (sce_ecc_private_wrapped_key_t *)params[2].memref.buffer;
    if ((NULL == wrapped_key) || (sizeof(sce_ecc_private_wrapped_key_t) != params[2].memref.size)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    err = g_sce_protected_on_sce.ECDSA_BrainpoolP512r1_SignatureGenerate(&message_hash, &signature, wrapped_key);
    switch (err)
    {
        case FSP_SUCCESS:
            break;
        case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
            return TEE_ERROR_ACCESS_CONFLICT;
        case FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL:
            return TEE_ERROR_BAD_PARAMETERS;
        case FSP_ERR_CRYPTO_SCE_PARAMETER:
            return TEE_ERROR_BAD_PARAMETERS;
        default: /* FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION */
            return TEE_ERROR_BAD_STATE;
    }

    params[1].memref.size = signature.data_length;

    return TEE_SUCCESS;
}

static TEE_Result ecdsa_brainpoolp512r1_signatureverify(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
    fsp_err_t err;

    sce_ecdsa_byte_data_t signature;
    sce_ecdsa_byte_data_t message_hash;
    sce_ecc_public_wrapped_key_t * wrapped_key;

    if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                    TEE_PARAM_TYPE_MEMREF_INPUT,
                    TEE_PARAM_TYPE_MEMREF_INPUT,
                    TEE_PARAM_TYPE_NONE)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    signature.pdata = (uint8_t *)params[0].memref.buffer;
    signature.data_length = params[0].memref.size;
    signature.data_type = 0;
    if ((NULL == signature.pdata) || (HW_SCE_ECDSA_P512_DATA_BYTE_SIZE != signature.data_length)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    message_hash.pdata = (uint8_t *)sha512_hash;
    message_hash.data_length = HW_SCE_SHA512_HASH_LENGTH_BYTE_SIZE;
    message_hash.data_type = 1;
    err = tee_hash_createdigest(TEE_ALG_SHA512, params[1].memref.buffer, params[1].memref.size, 
        message_hash.pdata, message_hash.data_length);
    if (err) {
        return err;
    }
    
    wrapped_key = (sce_ecc_public_wrapped_key_t *)params[2].memref.buffer;
    if ((NULL == wrapped_key) || (sizeof(sce_ecc_public_wrapped_key_t) != params[2].memref.size)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    err = g_sce_protected_on_sce.ECDSA_BrainpoolP512r1_SignatureVerify(&signature, &message_hash, wrapped_key);
    switch (err)
    {
        case FSP_SUCCESS:
            break;
        case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
            return TEE_ERROR_ACCESS_CONFLICT;
        case FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL:
            return TEE_ERROR_BAD_PARAMETERS;
        case FSP_ERR_CRYPTO_SCE_FAIL:
            return TEE_ERROR_GENERIC;
        case FSP_ERR_CRYPTO_SCE_PARAMETER:
            return TEE_ERROR_BAD_PARAMETERS;
        default: /* FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION */
            return TEE_ERROR_BAD_STATE;
    }

    return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *session __unused, uint32_t cmd,
                    uint32_t ptypes,
                    TEE_Param params[TEE_NUM_PARAMS])
{
    DMSG(PTA_NAME" command %#"PRIx32" ptypes %#"PRIx32, cmd, ptypes);

    switch (cmd)
    {
        case PTA_CMD_ECDSA_secp192r1_SignatureGenerate :
            return ecdsa_secp192r1_signaturegenerate(ptypes, params);
        case PTA_CMD_ECDSA_secp192r1_SignatureVerify :
            return ecdsa_secp192r1_signatureverify(ptypes, params);
        case PTA_CMD_ECDSA_secp224r1_SignatureGenerate :
            return ecdsa_secp224r1_signaturegenerate(ptypes, params);
        case PTA_CMD_ECDSA_secp224r1_SignatureVerify :
            return ecdsa_secp224r1_signatureverify(ptypes, params);
        case PTA_CMD_ECDSA_secp256r1_SignatureGenerate :
            return ecdsa_secp256r1_signaturegenerate(ptypes, params);
        case PTA_CMD_ECDSA_secp256r1_SignatureVerify :
            return ecdsa_secp256r1_signatureverify(ptypes, params);
        case PTA_CMD_ECDSA_BrainpoolP512r1_SignatureGenerate :
            return ecdsa_brainpoolp512r1_signaturegenerate(ptypes, params);
        case PTA_CMD_ECDSA_BrainpoolP512r1_SignatureVerify :
            return ecdsa_brainpoolp512r1_signatureverify(ptypes, params);
        default:
            return TEE_ERROR_NOT_SUPPORTED;
    }
}

pseudo_ta_register(.uuid = PTA_SCE_ECC_UUID, .name = PTA_NAME,
           .flags = PTA_DEFAULT_FLAGS,
           .invoke_command_entry_point = invoke_command);
