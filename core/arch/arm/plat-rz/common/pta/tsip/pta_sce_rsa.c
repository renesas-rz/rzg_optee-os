// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, Renesas Electronics
 */

#include <kernel/pseudo_ta.h>

#include <r_sce.h>
#include <pta_sce_rsa.h>

#define PTA_NAME "sce_rsa.pta"

static TEE_Result rsassa_pkcs1024_signaturegenerate(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
    fsp_err_t err;

    sce_rsa_byte_data_t message_hash;
    sce_rsa_byte_data_t signature;
    sce_rsa1024_private_wrapped_key_t * wrapped_key;

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
    if ((NULL == signature.pdata) || (HW_SCE_RSA_1024_DATA_BYTE_SIZE > signature.data_length)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    wrapped_key = (sce_rsa1024_private_wrapped_key_t *)params[2].memref.buffer;
    if ((NULL == wrapped_key) || (sizeof(sce_rsa1024_private_wrapped_key_t) != params[2].memref.size)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    err = g_sce_protected_on_sce.RSASSA_PKCS1024_SignatureGenerate(&message_hash, &signature, wrapped_key, HW_SCE_RSA_HASH_SHA256);
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

static TEE_Result rsassa_pkcs1024_signatureverify(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
    fsp_err_t err;

    sce_rsa_byte_data_t signature;
    sce_rsa_byte_data_t message_hash;
    sce_rsa1024_public_wrapped_key_t * wrapped_key;

    if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                    TEE_PARAM_TYPE_MEMREF_INPUT,
                    TEE_PARAM_TYPE_MEMREF_INPUT,
                    TEE_PARAM_TYPE_NONE)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    signature.pdata = (uint8_t *)params[0].memref.buffer;
    signature.data_length = params[0].memref.size;
    signature.data_type = 0;
    if ((NULL == signature.pdata) || (HW_SCE_RSA_1024_DATA_BYTE_SIZE != signature.data_length)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    message_hash.pdata = (uint8_t *)params[1].memref.buffer;
    message_hash.data_length = params[1].memref.size;
    message_hash.data_type = 0;
    if ((NULL == message_hash.pdata) && (0 < message_hash.data_length)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    wrapped_key = (sce_rsa1024_public_wrapped_key_t *)params[2].memref.buffer;
    if ((NULL == wrapped_key) || (sizeof(sce_rsa1024_public_wrapped_key_t) != params[2].memref.size)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    err = g_sce_protected_on_sce.RSASSA_PKCS1024_SignatureVerify(&signature, &message_hash, wrapped_key, HW_SCE_RSA_HASH_SHA256);
    switch (err)
    {
        case FSP_SUCCESS:
            break;
        case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
            return TEE_ERROR_ACCESS_CONFLICT;
        case FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL:
            return TEE_ERROR_BAD_PARAMETERS;
        case FSP_ERR_CRYPTO_SCE_AUTHENTICATION:
            return TEE_ERROR_SIGNATURE_INVALID;
        case FSP_ERR_CRYPTO_SCE_PARAMETER:
            return TEE_ERROR_BAD_PARAMETERS;
        default: /* FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION */
            return TEE_ERROR_BAD_STATE;
    }

    return TEE_SUCCESS;
}

static TEE_Result rsassa_pkcs2048_signaturegenerate(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
    fsp_err_t err;

    sce_rsa_byte_data_t message_hash;
    sce_rsa_byte_data_t signature;
    sce_rsa2048_private_wrapped_key_t * wrapped_key;

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
    if ((NULL == signature.pdata) || (HW_SCE_RSA_2048_DATA_BYTE_SIZE > signature.data_length)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    wrapped_key = (sce_rsa2048_private_wrapped_key_t *)params[2].memref.buffer;
    if ((NULL == wrapped_key) || (sizeof(sce_rsa2048_private_wrapped_key_t) != params[2].memref.size)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    err = g_sce_protected_on_sce.RSASSA_PKCS2048_SignatureGenerate(&message_hash, &signature, wrapped_key, HW_SCE_RSA_HASH_SHA256);
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

static TEE_Result rsassa_pkcs2048_signatureverify(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
    fsp_err_t err;

    sce_rsa_byte_data_t signature;
    sce_rsa_byte_data_t message_hash;
    sce_rsa2048_public_wrapped_key_t * wrapped_key;

    if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                    TEE_PARAM_TYPE_MEMREF_INPUT,
                    TEE_PARAM_TYPE_MEMREF_INPUT,
                    TEE_PARAM_TYPE_NONE)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    signature.pdata = (uint8_t *)params[0].memref.buffer;
    signature.data_length = params[0].memref.size;
    signature.data_type = 0;
    if ((NULL == signature.pdata) || (HW_SCE_RSA_2048_DATA_BYTE_SIZE != signature.data_length)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    message_hash.pdata = (uint8_t *)params[1].memref.buffer;
    message_hash.data_length = params[1].memref.size;
    message_hash.data_type = 0;
    if ((NULL == message_hash.pdata) && (0 < message_hash.data_length)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    wrapped_key = (sce_rsa2048_public_wrapped_key_t *)params[2].memref.buffer;
    if ((NULL == wrapped_key) || (sizeof(sce_rsa2048_public_wrapped_key_t) != params[2].memref.size)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    err = g_sce_protected_on_sce.RSASSA_PKCS2048_SignatureVerify(&signature, &message_hash, wrapped_key, HW_SCE_RSA_HASH_SHA256);
    switch (err)
    {
        case FSP_SUCCESS:
            break;
        case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
            return TEE_ERROR_ACCESS_CONFLICT;
        case FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL:
            return TEE_ERROR_BAD_PARAMETERS;
        case FSP_ERR_CRYPTO_SCE_AUTHENTICATION:
            return TEE_ERROR_SIGNATURE_INVALID;
        case FSP_ERR_CRYPTO_SCE_PARAMETER:
            return TEE_ERROR_BAD_PARAMETERS;
        default: /* FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION */
            return TEE_ERROR_BAD_STATE;
    }

    return TEE_SUCCESS;
}

static TEE_Result rsassa_pkcs4096_signatureverify(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
    fsp_err_t err;

    sce_rsa_byte_data_t signature;
    sce_rsa_byte_data_t message_hash;
    sce_rsa4096_public_wrapped_key_t * wrapped_key;

    if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                    TEE_PARAM_TYPE_MEMREF_INPUT,
                    TEE_PARAM_TYPE_MEMREF_INPUT,
                    TEE_PARAM_TYPE_NONE)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    signature.pdata = (uint8_t *)params[0].memref.buffer;
    signature.data_length = params[0].memref.size;
    signature.data_type = 0;
    if ((NULL == signature.pdata) || (HW_SCE_RSA_4096_DATA_BYTE_SIZE != signature.data_length)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    message_hash.pdata = (uint8_t *)params[1].memref.buffer;
    message_hash.data_length = params[1].memref.size;
    message_hash.data_type = 0;
    if ((NULL == message_hash.pdata) && (0 < message_hash.data_length)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    wrapped_key = (sce_rsa4096_public_wrapped_key_t *)params[2].memref.buffer;
    if ((NULL == wrapped_key) || (sizeof(sce_rsa4096_public_wrapped_key_t) != params[2].memref.size)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    err = g_sce_protected_on_sce.RSASSA_PKCS4096_SignatureVerify(&signature, &message_hash, wrapped_key, HW_SCE_RSA_HASH_SHA256);
    switch (err)
    {
        case FSP_SUCCESS:
            break;
        case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
            return TEE_ERROR_ACCESS_CONFLICT;
        case FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL:
            return TEE_ERROR_BAD_PARAMETERS;
        case FSP_ERR_CRYPTO_SCE_AUTHENTICATION:
            return TEE_ERROR_SIGNATURE_INVALID;
        case FSP_ERR_CRYPTO_SCE_PARAMETER:
            return TEE_ERROR_BAD_PARAMETERS;
        default: /* FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION */
            return TEE_ERROR_BAD_STATE;
    }

    return TEE_SUCCESS;
}

static TEE_Result rsaes_pkcs1024_encrypt(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
    fsp_err_t err;

    sce_rsa_byte_data_t plain;
    sce_rsa_byte_data_t cipher;
    sce_rsa1024_public_wrapped_key_t * wrapped_key;

    if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                    TEE_PARAM_TYPE_MEMREF_INOUT,
                    TEE_PARAM_TYPE_MEMREF_INPUT,
                    TEE_PARAM_TYPE_NONE)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    plain.pdata = (uint8_t *)params[0].memref.buffer;
    plain.data_length = params[0].memref.size;
    plain.data_type = 0;
    if (NULL == plain.pdata) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    cipher.pdata = (uint8_t *)params[1].memref.buffer;
    cipher.data_length = params[1].memref.size;
    cipher.data_type = 0;
    if (NULL == cipher.pdata) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    wrapped_key = (sce_rsa1024_public_wrapped_key_t *)params[2].memref.buffer;
    if ((NULL == wrapped_key) || (sizeof(sce_rsa1024_public_wrapped_key_t) != params[2].memref.size)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    err = g_sce_protected_on_sce.RSAES_PKCS1024_Encrypt(&plain, &cipher, wrapped_key);
    switch (err)
    {
        case FSP_SUCCESS:
            break;
        case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
            return TEE_ERROR_ACCESS_CONFLICT;
        case FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL:
            return TEE_ERROR_BAD_PARAMETERS;
        default: /* FSP_ERR_CRYPTO_SCE_PARAMETER */
            return TEE_ERROR_BAD_PARAMETERS;
    }

    params[1].memref.size = cipher.data_length;

    return TEE_SUCCESS;
}

static TEE_Result rsaes_pkcs1024_decrypt(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
    fsp_err_t err;

    sce_rsa_byte_data_t plain;
    sce_rsa_byte_data_t cipher;
    sce_rsa1024_private_wrapped_key_t * wrapped_key;

    if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                    TEE_PARAM_TYPE_MEMREF_INOUT,
                    TEE_PARAM_TYPE_MEMREF_INPUT,
                    TEE_PARAM_TYPE_NONE)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    cipher.pdata = (uint8_t *)params[0].memref.buffer;
    cipher.data_length = params[0].memref.size;
    cipher.data_type = 0;
    if (NULL == cipher.pdata) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    plain.pdata = (uint8_t *)params[1].memref.buffer;
    plain.data_length = params[1].memref.size;
    plain.data_type = 0;
    if (NULL == plain.pdata) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    wrapped_key = (sce_rsa1024_private_wrapped_key_t *)params[2].memref.buffer;
    if ((NULL == wrapped_key) || (sizeof(sce_rsa1024_private_wrapped_key_t) != params[2].memref.size)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    err = g_sce_protected_on_sce.RSAES_PKCS1024_Decrypt(&cipher, &plain, wrapped_key);
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
        default: /* FSP_ERR_CRYPTO_SCE_FAIL */
            return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}
static TEE_Result rsaes_pkcs2048_encrypt(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
    fsp_err_t err;

    sce_rsa_byte_data_t plain;
    sce_rsa_byte_data_t cipher;
    sce_rsa2048_public_wrapped_key_t * wrapped_key;

    if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                    TEE_PARAM_TYPE_MEMREF_INOUT,
                    TEE_PARAM_TYPE_MEMREF_INPUT,
                    TEE_PARAM_TYPE_NONE)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    plain.pdata = (uint8_t *)params[0].memref.buffer;
    plain.data_length = params[0].memref.size;
    plain.data_type = 0;
    if (NULL == plain.pdata) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    cipher.pdata = (uint8_t *)params[1].memref.buffer;
    cipher.data_length = params[1].memref.size;
    cipher.data_type = 0;
    if (NULL == cipher.pdata) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    wrapped_key = (sce_rsa2048_public_wrapped_key_t *)params[2].memref.buffer;
    if ((NULL == wrapped_key) || (sizeof(sce_rsa2048_public_wrapped_key_t) != params[2].memref.size)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    err = g_sce_protected_on_sce.RSAES_PKCS2048_Encrypt(&plain, &cipher, wrapped_key);
    switch (err)
    {
        case FSP_SUCCESS:
            break;
        case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
            return TEE_ERROR_ACCESS_CONFLICT;
        case FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL:
            return TEE_ERROR_BAD_PARAMETERS;
        default: /* FSP_ERR_CRYPTO_SCE_PARAMETER */
            return TEE_ERROR_BAD_PARAMETERS;
    }

    params[1].memref.size = cipher.data_length;

    return TEE_SUCCESS;
}

static TEE_Result rsaes_pkcs2048_decrypt(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
    fsp_err_t err;

    sce_rsa_byte_data_t plain;
    sce_rsa_byte_data_t cipher;
    sce_rsa2048_private_wrapped_key_t * wrapped_key;

    if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                    TEE_PARAM_TYPE_MEMREF_INOUT,
                    TEE_PARAM_TYPE_MEMREF_INPUT,
                    TEE_PARAM_TYPE_NONE)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    cipher.pdata = (uint8_t *)params[0].memref.buffer;
    cipher.data_length = params[0].memref.size;
    cipher.data_type = 0;
    if (NULL == cipher.pdata) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    plain.pdata = (uint8_t *)params[1].memref.buffer;
    plain.data_length = params[1].memref.size;
    plain.data_type = 0;
    if (NULL == plain.pdata) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    wrapped_key = (sce_rsa2048_private_wrapped_key_t *)params[2].memref.buffer;
    if ((NULL == wrapped_key) || (sizeof(sce_rsa2048_private_wrapped_key_t) != params[2].memref.size)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    err = g_sce_protected_on_sce.RSAES_PKCS2048_Decrypt(&cipher, &plain, wrapped_key);
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
        default: /* FSP_ERR_CRYPTO_SCE_FAIL */
            return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static TEE_Result rsaes_pkcs4096_encrypt(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
    fsp_err_t err;

    sce_rsa_byte_data_t plain;
    sce_rsa_byte_data_t cipher;
    sce_rsa4096_public_wrapped_key_t * wrapped_key;

    if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                    TEE_PARAM_TYPE_MEMREF_INOUT,
                    TEE_PARAM_TYPE_MEMREF_INPUT,
                    TEE_PARAM_TYPE_NONE)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    plain.pdata = (uint8_t *)params[0].memref.buffer;
    plain.data_length = params[0].memref.size;
    plain.data_type = 0;
    if (NULL == plain.pdata) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    cipher.pdata = (uint8_t *)params[1].memref.buffer;
    cipher.data_length = params[1].memref.size;
    cipher.data_type = 0;
    if (NULL == cipher.pdata) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    wrapped_key = (sce_rsa4096_public_wrapped_key_t *)params[2].memref.buffer;
    if ((NULL == wrapped_key) || (sizeof(sce_rsa4096_public_wrapped_key_t) != params[2].memref.size)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    err = g_sce_protected_on_sce.RSAES_PKCS4096_Encrypt(&plain, &cipher, wrapped_key);
    switch (err)
    {
        case FSP_SUCCESS:
            break;
        case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
            return TEE_ERROR_ACCESS_CONFLICT;
        case FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL:
            return TEE_ERROR_BAD_PARAMETERS;
        default: /* FSP_ERR_CRYPTO_SCE_PARAMETER */
            return TEE_ERROR_BAD_PARAMETERS;
    }

    params[1].memref.size = cipher.data_length;

    return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *session __unused, uint32_t cmd,
                    uint32_t ptypes,
                    TEE_Param params[TEE_NUM_PARAMS])
{
    DMSG(PTA_NAME" command %#"PRIx32" ptypes %#"PRIx32, cmd, ptypes);

    switch (cmd) {
        case PTA_CMD_RSASSA_PKCS1024_SignatureGenerate :
		    return rsassa_pkcs1024_signaturegenerate(ptypes, params);
        case PTA_CMD_RSASSA_PKCS1024_SignatureVerify :
		    return rsassa_pkcs1024_signatureverify(ptypes, params);
        case PTA_CMD_RSASSA_PKCS2048_SignatureGenerate :
		    return rsassa_pkcs2048_signaturegenerate(ptypes, params);
        case PTA_CMD_RSASSA_PKCS2048_SignatureVerify :
		    return rsassa_pkcs2048_signatureverify(ptypes, params);
        case PTA_CMD_RSASSA_PKCS4096_SignatureVerify :
		    return rsassa_pkcs4096_signatureverify(ptypes, params);
        case PTA_CMD_RSAES_PKCS1024_Encrypt :
		    return rsaes_pkcs1024_encrypt(ptypes, params);
        case PTA_CMD_RSAES_PKCS1024_Decrypt :
		    return rsaes_pkcs1024_decrypt(ptypes, params);
        case PTA_CMD_RSAES_PKCS2048_Encrypt :
		    return rsaes_pkcs2048_encrypt(ptypes, params);
        case PTA_CMD_RSAES_PKCS2048_Decrypt :
		    return rsaes_pkcs2048_decrypt(ptypes, params);
        case PTA_CMD_RSAES_PKCS4096_Encrypt :
		    return rsaes_pkcs4096_encrypt(ptypes, params);
        default:
            return TEE_ERROR_NOT_SUPPORTED;
    }
}

pseudo_ta_register(.uuid = PTA_SCE_RSA_UUID, .name = PTA_NAME,
           .flags = PTA_DEFAULT_FLAGS,
           .invoke_command_entry_point = invoke_command);
