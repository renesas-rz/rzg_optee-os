// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, Renesas Electronics
 */

#include <kernel/pseudo_ta.h>

#include <r_sce.h>
#include <pta_sce_sha.h>

#define PTA_NAME "sce_sha.pta"

static TEE_Result sha224_init(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
    fsp_err_t err;

    sce_sha_md5_handle_t * handle;

    if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
                    TEE_PARAM_TYPE_NONE,
                    TEE_PARAM_TYPE_NONE,
                    TEE_PARAM_TYPE_NONE)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    handle = (sce_sha_md5_handle_t *)params[0].memref.buffer;
    if ((NULL == handle) || (sizeof(sce_sha_md5_handle_t) > params[0].memref.size)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    err = g_sce_protected_on_sce.SHA224_Init(handle);
    switch (err)
    {
        case FSP_SUCCESS:
            break;
        default:
            return TEE_ERROR_GENERIC;
    }

    params[0].memref.size = sizeof(sce_sha_md5_handle_t);
    
    return TEE_SUCCESS;
}

static TEE_Result sha224_update(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
    fsp_err_t err;

    sce_sha_md5_handle_t * handle;
    uint8_t * message;
    uint32_t message_length;

    if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
                    TEE_PARAM_TYPE_MEMREF_INPUT,
                    TEE_PARAM_TYPE_NONE,
                    TEE_PARAM_TYPE_NONE)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    handle = (sce_sha_md5_handle_t *)params[0].memref.buffer;
    if ((NULL == handle) || (sizeof(sce_sha_md5_handle_t) != params[0].memref.size)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    message = (uint8_t *)params[1].memref.buffer;
    message_length = (uint32_t)params[1].memref.size;

    err = g_sce_protected_on_sce.SHA224_Update(handle, message, message_length);
    switch (err)
    {
        case FSP_SUCCESS:
            break;
        case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
            return TEE_ERROR_ACCESS_CONFLICT;
        case FSP_ERR_CRYPTO_SCE_PARAMETER:
            return TEE_ERROR_BAD_PARAMETERS;
        default: /* FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION */
            return TEE_ERROR_BAD_STATE;
    }

    return TEE_SUCCESS;
}

static TEE_Result sha224_final(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
    fsp_err_t err;

    sce_sha_md5_handle_t * handle;
    uint8_t * digest;
    uint32_t digest_length;

    if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
                    TEE_PARAM_TYPE_MEMREF_INOUT,
                    TEE_PARAM_TYPE_NONE,
                    TEE_PARAM_TYPE_NONE)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    handle = (sce_sha_md5_handle_t *)params[0].memref.buffer;
    if ((NULL == handle) || (sizeof(sce_sha_md5_handle_t) != params[0].memref.size)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    digest = (uint8_t *)params[1].memref.buffer;
    digest_length = (uint32_t)params[1].memref.size;
    if ((NULL == digest) || (HW_SCE_SHA224_HASH_LENGTH_BYTE_SIZE > digest_length)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    err = g_sce_protected_on_sce.SHA224_Final(handle, digest, &digest_length);
    switch (err)
    {
        case FSP_SUCCESS:
            break;
        case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
            return TEE_ERROR_ACCESS_CONFLICT;
        case FSP_ERR_CRYPTO_SCE_PARAMETER:
            return TEE_ERROR_BAD_PARAMETERS;
        default: /* FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION */
            return TEE_ERROR_BAD_STATE;
    }

    params[1].memref.size = digest_length;

    return TEE_SUCCESS;
}

static TEE_Result sha256_init(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
    fsp_err_t err;

    sce_sha_md5_handle_t * handle;

    if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
                    TEE_PARAM_TYPE_NONE,
                    TEE_PARAM_TYPE_NONE,
                    TEE_PARAM_TYPE_NONE)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    handle = (sce_sha_md5_handle_t *)params[0].memref.buffer;
    if ((NULL == handle) || (sizeof(sce_sha_md5_handle_t) > params[0].memref.size)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    err = g_sce_protected_on_sce.SHA256_Init(handle);
    switch (err)
    {
        case FSP_SUCCESS:
            break;
        default:
            return TEE_ERROR_GENERIC;
    }

    params[0].memref.size = sizeof(sce_sha_md5_handle_t);
    
    return TEE_SUCCESS;
}

static TEE_Result sha256_update(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
    fsp_err_t err;

    sce_sha_md5_handle_t * handle;
    uint8_t              * message;
    uint32_t               message_length;

    if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
                    TEE_PARAM_TYPE_MEMREF_INPUT,
                    TEE_PARAM_TYPE_NONE,
                    TEE_PARAM_TYPE_NONE)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    handle = (sce_sha_md5_handle_t *)params[0].memref.buffer;
    if ((NULL == handle) || (sizeof(sce_sha_md5_handle_t) != params[0].memref.size)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    message = (uint8_t *)params[1].memref.buffer;
    message_length = (uint32_t)params[1].memref.size;

    err = g_sce_protected_on_sce.SHA256_Update(handle, message, message_length);
    switch (err)
    {
        case FSP_SUCCESS:
            break;
        case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
            return TEE_ERROR_ACCESS_CONFLICT;
        case FSP_ERR_CRYPTO_SCE_PARAMETER:
            return TEE_ERROR_BAD_PARAMETERS;
        default: /* FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION */
            return TEE_ERROR_BAD_STATE;
    }

    return TEE_SUCCESS;
}

static TEE_Result sha256_final(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
    fsp_err_t err;

    sce_sha_md5_handle_t * handle;
    uint8_t              * digest;
    uint32_t               digest_length;

    if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
                    TEE_PARAM_TYPE_MEMREF_INOUT,
                    TEE_PARAM_TYPE_NONE,
                    TEE_PARAM_TYPE_NONE)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    handle = (sce_sha_md5_handle_t *)params[0].memref.buffer;
    if ((NULL == handle) || (sizeof(sce_sha_md5_handle_t) != params[0].memref.size)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    digest = (uint8_t *)params[1].memref.buffer;
    digest_length = (uint32_t)params[1].memref.size;
    if ((NULL == digest) || (HW_SCE_SHA256_HASH_LENGTH_BYTE_SIZE > digest_length)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    err = g_sce_protected_on_sce.SHA256_Final(handle, digest, &digest_length);
    switch (err)
    {
        case FSP_SUCCESS:
            break;
        case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
            return TEE_ERROR_ACCESS_CONFLICT;
        case FSP_ERR_CRYPTO_SCE_PARAMETER:
            return TEE_ERROR_BAD_PARAMETERS;
        default: /* FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION */
            return TEE_ERROR_BAD_STATE;
    }

    params[1].memref.size = digest_length;

    return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *session __unused, uint32_t cmd,
                    uint32_t ptypes,
                    TEE_Param params[TEE_NUM_PARAMS])
{
    DMSG(PTA_NAME" command %#"PRIx32" ptypes %#"PRIx32, cmd, ptypes);

    switch (cmd) {
        case PTA_CMD_SHA224_Init :
            return sha224_init(ptypes, params);
        case PTA_CMD_SHA224_Update :
            return sha224_update(ptypes, params);
        case PTA_CMD_SHA224_Final :
            return sha224_final(ptypes, params);
        case PTA_CMD_SHA256_Init :
            return sha256_init(ptypes, params);
        case PTA_CMD_SHA256_Update :
            return sha256_update(ptypes, params);
        case PTA_CMD_SHA256_Final :            
            return sha256_final(ptypes, params);
        default:
            return TEE_ERROR_NOT_SUPPORTED;
    }
}

pseudo_ta_register(.uuid = PTA_SCE_SHA_UUID, .name = PTA_NAME,
           .flags = PTA_DEFAULT_FLAGS,
           .invoke_command_entry_point = invoke_command);
