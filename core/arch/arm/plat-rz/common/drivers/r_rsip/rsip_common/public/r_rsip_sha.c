// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2024, Renesas Electronics Corporation
 */

/***********************************************************************************************************************
 * Includes
 **********************************************************************************************************************/
#include "r_rsip_public.h"

/***********************************************************************************************************************
 * Macro definitions
 **********************************************************************************************************************/

/* Block size */
#define RSIP_PRV_BYTE_SIZE_HASH_BLOCK_SHA1_SHA224_SHA256    (64U)
#define RSIP_PRV_BYTE_SIZE_HASH_BLOCK_SHA384_SHA512         (128U)

/* MAC length */
#define RSIP_PRV_BYTE_SIZE_HMAC_SHA1_MAC                    (20U)
#define RSIP_PRV_BYTE_SIZE_HMAC_SHA224_MAC                  (28U)
#define RSIP_PRV_BYTE_SIZE_HMAC_SHA256_MAC                  (32U)

/***********************************************************************************************************************
 * Typedef definitions
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Private function prototypes
 **********************************************************************************************************************/

static fsp_err_t hmac_init(rsip_ctrl_t              * p_ctrl,
                           rsip_hmac_handle_t       * p_handle,
                           const rsip_wrapped_key_t * p_wrapped_key,
                           bool                       is_generate);
static fsp_err_t hmac_update(rsip_ctrl_t * const        p_ctrl,
                             rsip_hmac_handle_t * const p_handle,
                             uint8_t const * const      p_message,
                             uint32_t const             message_length,
                             bool                       is_generate);

/***********************************************************************************************************************
 * Private global variables
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Global variables
 **********************************************************************************************************************/

/*******************************************************************************************************************//**
 * @addtogroup RSIP
 * @{
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Functions
 **********************************************************************************************************************/

/*******************************************************************************************************************//**
 * Generates SHA message digest.
 *
 * @param[in,out] p_ctrl         Pointer to control block.
 * @param[in]     hash_type      Generating hash type.
 * @param[in]     p_message      Pointer to message. The length is message_length.
 * @param[in]     message_length Byte length of message (0 or more bytes).
 * @param[out]    p_digest       Pointer to destination of message digest. The length depends on hash type.
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_ASSERTION                     A required parameter is NULL.
 * @retval FSP_ERR_NOT_OPEN                      Module is not open.
 * @retval FSP_ERR_INVALID_STATE                 Internal state is illegal.
 *
 * @retval FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource required
 *                                               by the processing is in use by other processing.
 * @retval FSP_ERR_CRYPTO_RSIP_FATAL             Software corruption is detected.
 **********************************************************************************************************************/
fsp_err_t R_RSIP_SHA_Compute (rsip_ctrl_t * const    p_ctrl,
                              rsip_hash_type_t const hash_type,
                              uint8_t const * const  p_message,
                              uint32_t const         message_length,
                              uint8_t * const        p_digest)
{
    rsip_instance_ctrl_t * p_instance_ctrl = (rsip_instance_ctrl_t *) p_ctrl;
    fsp_err_t              err             = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_FATAL;

#if RSIP_CFG_PARAM_CHECKING_ENABLE
    FSP_ASSERT(p_instance_ctrl);
    FSP_ASSERT(p_message || (0 == message_length));
    FSP_ASSERT(p_digest);
    FSP_ERROR_RETURN(RSIP_OPEN == p_instance_ctrl->open, FSP_ERR_NOT_OPEN);
#endif

    /* Check state */
    FSP_ERROR_RETURN(r_rsip_state_check_init(p_instance_ctrl), FSP_ERR_INVALID_STATE);

    /* Call function (cast to match the argument type with the function) */
    rsip_ret_t rsip_ret = r_rsip_sha1sha2_compute_single((const uint32_t *) p_message,
                                                         (uint32_t *) p_digest,
                                                         hash_type,
                                                         message_length);

    /* Check error */
    switch (rsip_ret)
    {
        case RSIP_RET_PASS:
        {
            err = FSP_SUCCESS;
            break;
        }

        case RSIP_RET_RESOURCE_CONFLICT:
        {
            err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT;
            break;
        }

        default:
        {
            err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_FATAL;
        }
    }

    return err;
}

/*******************************************************************************************************************//**
 * Generates HMAC.
 *
 * @param[in,out] p_ctrl         Pointer to control block.
 * @param[in]     p_wrapped_key  Pointer to wrapped key of HMAC key.
 * @param[in]     p_message      Pointer to message. The length is message_length.
 * @param[in]     message_length Byte length of message (0 or more bytes).
 * @param[out]    p_mac          Pointer to destination of message digest. The length depends on MAC type.
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_ASSERTION                     A required parameter is NULL.
 * @retval FSP_ERR_NOT_OPEN                      Module is not open.
 * @retval FSP_ERR_INVALID_STATE                 Internal state is illegal.
 * @retval FSP_ERR_NOT_ENABLED                   Input key type is disabled in this function by configuration.
 * @retval FSP_ERR_INVALID_ARGUMENT              Input key type is illegal.
 * @retval FSP_ERR_CRYPTO_RSIP_KEY_SET_FAIL      Input key value is illegal.
 *
 * @retval FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource required
 *                                               by the processing is in use by other processing.
 * @retval FSP_ERR_CRYPTO_RSIP_FATAL             Software corruption is detected.
 **********************************************************************************************************************/
fsp_err_t R_RSIP_HMAC_Compute (rsip_ctrl_t * const        p_ctrl,
                               const rsip_wrapped_key_t * p_wrapped_key,
                               uint8_t const * const      p_message,
                               uint32_t const             message_length,
                               uint8_t * const            p_mac)
{
    rsip_instance_ctrl_t * p_instance_ctrl = (rsip_instance_ctrl_t *) p_ctrl;
    fsp_err_t              err             = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_FATAL;

#if RSIP_CFG_PARAM_CHECKING_ENABLE
    FSP_ASSERT(p_instance_ctrl);
    FSP_ASSERT(p_wrapped_key);
    FSP_ASSERT(p_message || (0 == message_length));
    FSP_ASSERT(p_mac);
    FSP_ERROR_RETURN(RSIP_OPEN == p_instance_ctrl->open, FSP_ERR_NOT_OPEN);

    /* Check key type */
    FSP_ERROR_RETURN(RSIP_PRV_IS_HMAC_KEY(p_wrapped_key->type), FSP_ERR_INVALID_ARGUMENT);

    /* Check configuration */
    FSP_ERROR_RETURN(gp_func_hmac_single[RSIP_PRV_HMAC_REBASE(p_wrapped_key->type)], FSP_ERR_NOT_ENABLED);
#endif

    /* Check state */
    FSP_ERROR_RETURN(r_rsip_state_check_init(p_instance_ctrl), FSP_ERR_INVALID_STATE);

    /* Set primitive */
    rsip_func_hmac_single_t p_primitive = gp_func_hmac_single[RSIP_PRV_HMAC_REBASE(p_wrapped_key->type)];

    /* Call function (cast to match the argument type with the function) */
    rsip_ret_t rsip_ret = r_rsip_hmac_compute_single((const uint32_t *) p_message,
                                                     (uint32_t *) p_mac,
                                                     p_primitive,
                                                     p_wrapped_key,
                                                     message_length);

    /* Check error */
    switch (rsip_ret)
    {
        case RSIP_RET_PASS:
        {
            err = FSP_SUCCESS;
            break;
        }

        case RSIP_RET_RESOURCE_CONFLICT:
        {
            err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT;
            break;
        }

        case RSIP_RET_KEY_FAIL:
        {
            err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_KEY_SET_FAIL;
            break;
        }

        /* RSIP_RET_FAIL is not used in this function */
        case RSIP_RET_FAIL:
        default:
        {
            err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_FATAL;
        }
    }

    return err;
}

/*******************************************************************************************************************//**
 * Verifies HMAC.
 *
 * @param[in,out] p_ctrl         Pointer to control block.
 * @param[in]     p_wrapped_key  Pointer to wrapped key of HMAC key.
 * @param[in]     p_message      Pointer to message. The length is message_length.
 * @param[in]     message_length Byte length of message (0 or more bytes).
 * @param[in]     p_mac          Pointer to MAC. The length depends on mac_length.
 * @param[in]     mac_length     Byte length of MAC.
 *                               @arg HMAC-SHA1:   4 to 20
 *                               @arg HMAC-SHA224: 4 to 28
 *                               @arg HMAC-SHA256  4 to 32
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_ASSERTION                     A required parameter is NULL.
 * @retval FSP_ERR_NOT_OPEN                      Module is not open.
 * @retval FSP_ERR_INVALID_STATE                 Internal state is illegal.
 * @retval FSP_ERR_INVALID_SIZE                  mac_length is illegal.
 * @retval FSP_ERR_NOT_ENABLED                   Input key type is disabled in this function by configuration.
 * @retval FSP_ERR_INVALID_ARGUMENT              Input key type is illegal.
 * @retval FSP_ERR_CRYPTO_RSIP_KEY_SET_FAIL      Input key value is illegal.
 * @retval FSP_ERR_CRYPTO_RSIP_FAIL              MAC verification is failed.
 *
 * @retval FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource required
 *                                               by the processing is in use by other processing.
 * @retval FSP_ERR_CRYPTO_RSIP_FATAL             Software corruption is detected.
 **********************************************************************************************************************/
fsp_err_t R_RSIP_HMAC_Verify (rsip_ctrl_t * const        p_ctrl,
                              const rsip_wrapped_key_t * p_wrapped_key,
                              uint8_t const * const      p_message,
                              uint32_t const             message_length,
                              uint8_t const * const      p_mac,
                              uint32_t const             mac_length)
{
    rsip_instance_ctrl_t * p_instance_ctrl = (rsip_instance_ctrl_t *) p_ctrl;
    fsp_err_t              err             = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_FATAL;

#if RSIP_CFG_PARAM_CHECKING_ENABLE
    FSP_ASSERT(p_instance_ctrl);
    FSP_ASSERT(p_wrapped_key);
    FSP_ASSERT(p_message || (0 == message_length));
    FSP_ASSERT(p_mac);
    FSP_ERROR_RETURN(RSIP_OPEN == p_instance_ctrl->open, FSP_ERR_NOT_OPEN);

    /* Check key type */
    FSP_ERROR_RETURN(RSIP_PRV_IS_HMAC_KEY(p_wrapped_key->type), FSP_ERR_INVALID_ARGUMENT);

    /* Check configuration */
    FSP_ERROR_RETURN(gp_func_hmac_single[RSIP_PRV_HMAC_REBASE(p_wrapped_key->type)], FSP_ERR_NOT_ENABLED);
#endif

    /* mac_length must be 4 or greater (common) */
    FSP_ERROR_RETURN(4 <= mac_length, FSP_ERR_INVALID_SIZE);

    rsip_key_type_t key_type = p_wrapped_key->type;

    /* mac_length must be 20 or less (SHA-1) */
    FSP_ERROR_RETURN((RSIP_KEY_TYPE_HMAC_SHA1 != key_type) || (mac_length <= RSIP_PRV_BYTE_SIZE_HMAC_SHA1_MAC),
                     FSP_ERR_INVALID_SIZE);

    /* mac_length must be 28 or less (SHA-224) */
    FSP_ERROR_RETURN((RSIP_KEY_TYPE_HMAC_SHA224 != key_type) ||
                     (mac_length <= RSIP_PRV_BYTE_SIZE_HMAC_SHA224_MAC),
                     FSP_ERR_INVALID_SIZE);

    /* mac_length must be 32 or less (SHA-256) */
    FSP_ERROR_RETURN((RSIP_KEY_TYPE_HMAC_SHA256 != key_type) ||
                     (mac_length <= RSIP_PRV_BYTE_SIZE_HMAC_SHA256_MAC),
                     FSP_ERR_INVALID_SIZE);

    /* Check state */
    FSP_ERROR_RETURN(r_rsip_state_check_init(p_instance_ctrl), FSP_ERR_INVALID_STATE);

    /* Set primitive */
    rsip_func_hmac_single_t p_primitive = gp_func_hmac_single[RSIP_PRV_HMAC_REBASE(p_wrapped_key->type)];

    /* Call function (cast to match the argument type with the function) */
    rsip_ret_t rsip_ret = r_rsip_hmac_verify_single((const uint32_t *) p_message,
                                                    p_mac,
                                                    p_primitive,
                                                    p_wrapped_key,
                                                    message_length,
                                                    mac_length);

    /* Check error */
    switch (rsip_ret)
    {
        case RSIP_RET_PASS:
        {
            err = FSP_SUCCESS;
            break;
        }

        case RSIP_RET_RESOURCE_CONFLICT:
        {
            err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT;
            break;
        }

        case RSIP_RET_KEY_FAIL:
        {
            err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_KEY_SET_FAIL;
            break;
        }

        case RSIP_RET_FAIL:
        {
            err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_FAIL;
            break;
        }

        default:
        {
            err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_FATAL;
        }
    }

    return err;
}

/*******************************************************************************************************************//**
 * Prepares a SHA generation.
 *
 * @param[in,out] p_ctrl    Pointer to control block.
 * @param[in,out] p_handle  Pointer to SHA control block. Must be declared by user. Elements are set here.
 * @param[in]     hash_type Generating hash type.
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_ASSERTION                     A required parameter is NULL.
 * @retval FSP_ERR_NOT_OPEN                      Module is not open.
 * @retval FSP_ERR_INVALID_STATE                 Internal state is illegal.
 **********************************************************************************************************************/
fsp_err_t R_RSIP_SHA_GenerateInit (rsip_ctrl_t * const       p_ctrl,
                                   rsip_sha_handle_t * const p_handle,
                                   rsip_hash_type_t const    hash_type)
{
#if RSIP_CFG_PARAM_CHECKING_ENABLE
    rsip_instance_ctrl_t * p_instance_ctrl = (rsip_instance_ctrl_t *) p_ctrl;

    FSP_ASSERT(p_instance_ctrl);
    FSP_ASSERT(p_handle);
    FSP_ERROR_RETURN(RSIP_OPEN == p_instance_ctrl->open, FSP_ERR_NOT_OPEN);
#endif

    return r_rsip_sha_generate_init(p_ctrl, p_handle, hash_type);
}

/*******************************************************************************************************************//**
 * Inputs message.
 *
 * @param[in,out] p_ctrl         Pointer to control block.
 * @param[in,out] p_handle       Pointer to SHA control block.
 * @param[in]     p_message      Pointer to message. The length is message_length.
 * @param[in]     message_length Byte length of message (0 or more bytes).
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_ASSERTION                     A required parameter is NULL.
 * @retval FSP_ERR_NOT_OPEN                      Module is not open.
 * @retval FSP_ERR_INVALID_STATE                 Internal state is illegal.
 *
 * @retval FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource required
 *                                               by the processing is in use by other processing.
 * @retval FSP_ERR_CRYPTO_RSIP_FATAL             Software corruption is detected.
 **********************************************************************************************************************/
fsp_err_t R_RSIP_SHA_GenerateUpdate (rsip_ctrl_t * const       p_ctrl,
                                     rsip_sha_handle_t * const p_handle,
                                     uint8_t const * const     p_message,
                                     uint32_t const            message_length)
{
#if RSIP_CFG_PARAM_CHECKING_ENABLE
    rsip_instance_ctrl_t * p_instance_ctrl = (rsip_instance_ctrl_t *) p_ctrl;

    FSP_ASSERT(p_instance_ctrl);
    FSP_ASSERT(p_handle);
    FSP_ASSERT(p_message || (0 == message_length));
    FSP_ERROR_RETURN(RSIP_OPEN == p_instance_ctrl->open, FSP_ERR_NOT_OPEN);
#endif

    return r_rsip_sha_generate_update(p_ctrl, p_handle, p_message, message_length);
}

/*******************************************************************************************************************//**
 * Finalizes a SHA generation.
 *
 * @param[in,out] p_ctrl   Pointer to control block.
 * @param[in,out] p_handle Pointer to SHA control block.
 * @param[out]    p_digest Pointer to destination of message digest. The length depends on hash type.
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_ASSERTION                     A required parameter is NULL.
 * @retval FSP_ERR_NOT_OPEN                      Module is not open.
 * @retval FSP_ERR_INVALID_STATE                 Internal state is illegal.
 *
 * @retval FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource required
 *                                               by the processing is in use by other processing.
 * @retval FSP_ERR_CRYPTO_RSIP_FATAL             Software corruption is detected.
 **********************************************************************************************************************/
fsp_err_t R_RSIP_SHA_GenerateFinal (rsip_ctrl_t * const       p_ctrl,
                                    rsip_sha_handle_t * const p_handle,
                                    uint8_t * const           p_digest)
{
#if RSIP_CFG_PARAM_CHECKING_ENABLE
    rsip_instance_ctrl_t * p_instance_ctrl = (rsip_instance_ctrl_t *) p_ctrl;

    FSP_ASSERT(p_instance_ctrl);
    FSP_ASSERT(p_handle);
    FSP_ASSERT(p_digest);
    FSP_ERROR_RETURN(RSIP_OPEN == p_instance_ctrl->open, FSP_ERR_NOT_OPEN);
#endif

    return r_rsip_sha_generate_final(p_ctrl, p_handle, p_digest);
}

/*******************************************************************************************************************//**
 * Prepares a HMAC generation.
 *
 * @param[in,out] p_ctrl        Pointer to control block.
 * @param[in,out] p_handle      Pointer to HMAC control block. Must be declared by user. Elements are set here.
 * @param[in]     p_wrapped_key Pointer to wrapped key of HMAC key.
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_ASSERTION                     A required parameter is NULL.
 * @retval FSP_ERR_NOT_OPEN                      Module is not open.
 * @retval FSP_ERR_INVALID_STATE                 Internal state is illegal.
 * @retval FSP_ERR_NOT_ENABLED                   Input key type is disabled in this function by configuration.
 * @retval FSP_ERR_INVALID_ARGUMENT              Input key type is illegal.
 **********************************************************************************************************************/
fsp_err_t R_RSIP_HMAC_GenerateInit (rsip_ctrl_t * const              p_ctrl,
                                    rsip_hmac_handle_t * const       p_handle,
                                    rsip_wrapped_key_t const * const p_wrapped_key)
{
    return hmac_init(p_ctrl, p_handle, p_wrapped_key, true);
}

/*******************************************************************************************************************//**
 * Inputs message.
 *
 * @param[in,out] p_ctrl         Pointer to control block.
 * @param[in,out] p_handle       Pointer to HMAC control block.
 * @param[in]     p_message      Pointer to message. The length is message_length.
 * @param[in]     message_length Byte length of message (0 or more bytes).
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_ASSERTION                     A required parameter is NULL.
 * @retval FSP_ERR_NOT_OPEN                      Module is not open.
 * @retval FSP_ERR_INVALID_STATE                 Internal state is illegal.
 * @retval FSP_ERR_CRYPTO_RSIP_KEY_SET_FAIL      Input key value is illegal.
 *
 * @retval FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource required
 *                                               by the processing is in use by other processing.
 * @retval FSP_ERR_CRYPTO_RSIP_FATAL             Software corruption is detected.
 **********************************************************************************************************************/
fsp_err_t R_RSIP_HMAC_GenerateUpdate (rsip_ctrl_t * const        p_ctrl,
                                      rsip_hmac_handle_t * const p_handle,
                                      uint8_t const * const      p_message,
                                      uint32_t const             message_length)
{
    return hmac_update(p_ctrl, p_handle, p_message, message_length, true);
}

/*******************************************************************************************************************//**
 * Finalizes a HMAC generation.
 *
 * @param[in,out] p_ctrl   Pointer to control block.
 * @param[in,out] p_handle Pointer to HMAC control block.
 * @param[out]    p_mac    Pointer to destination of message digest. The length depends on MAC type.
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_ASSERTION                     A required parameter is NULL.
 * @retval FSP_ERR_NOT_OPEN                      Module is not open.
 * @retval FSP_ERR_INVALID_STATE                 Internal state is illegal.
 * @retval FSP_ERR_CRYPTO_RSIP_KEY_SET_FAIL      Input key value is illegal.
 *
 * @retval FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource required
 *                                               by the processing is in use by other processing.
 * @retval FSP_ERR_CRYPTO_RSIP_FATAL             Software corruption is detected.
 **********************************************************************************************************************/
fsp_err_t R_RSIP_HMAC_GenerateFinal (rsip_ctrl_t * const        p_ctrl,
                                     rsip_hmac_handle_t * const p_handle,
                                     uint8_t * const            p_mac)
{
    rsip_instance_ctrl_t * p_instance_ctrl = (rsip_instance_ctrl_t *) p_ctrl;
    fsp_err_t              err             = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_FATAL;

#if RSIP_CFG_PARAM_CHECKING_ENABLE
    FSP_ASSERT(p_instance_ctrl);
    FSP_ASSERT(p_handle);
    FSP_ASSERT(p_mac);
    FSP_ERROR_RETURN(RSIP_OPEN == p_instance_ctrl->open, FSP_ERR_NOT_OPEN);
#endif

    /* Check state */
    FSP_ERROR_RETURN(r_rsip_state_check_init(p_instance_ctrl), FSP_ERR_INVALID_STATE);
    FSP_ERROR_RETURN((RSIP_USER_HANDLE_STATE_UPDATE_EMPTY == p_handle->state) ||
                     (RSIP_USER_HANDLE_STATE_UPDATE == p_handle->state),
                     FSP_ERR_INVALID_STATE);
    FSP_ERROR_RETURN(p_handle->is_generate, FSP_ERR_INVALID_STATE);

    /* Call function */
    rsip_ret_t rsip_ret =
        r_rsip_hmac_calc_multi(p_handle, p_handle->buffer, p_handle->buffered_length, p_mac, 0, true);

    /* Check error */
    switch (rsip_ret)
    {
        case RSIP_RET_PASS:
        {
            /* State transition */
            p_handle->state = RSIP_USER_HANDLE_STATE_INIT;

            err = FSP_SUCCESS;
            break;
        }

        case RSIP_RET_RESOURCE_CONFLICT:
        {
            err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT;
            break;
        }

        case RSIP_RET_KEY_FAIL:
        {
            err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_KEY_SET_FAIL;
            break;
        }

        /* RSIP_RET_FAIL is not used in this function */
        case RSIP_RET_FAIL:
        default:
        {
            err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_FATAL;
        }
    }

    return err;
}

/*******************************************************************************************************************//**
 * Prepares a HMAC verification.
 *
 * @param[in,out] p_ctrl        Pointer to control block.
 * @param[in,out] p_handle      Pointer to HMAC control block. Must be declared by user. Elements are set here.
 * @param[in]     p_wrapped_key Pointer to wrapped key of HMAC key.
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_ASSERTION                     A required parameter is NULL.
 * @retval FSP_ERR_NOT_OPEN                      Module is not open.
 * @retval FSP_ERR_INVALID_STATE                 Internal state is illegal.
 * @retval FSP_ERR_NOT_ENABLED                   Input key type is disabled in this function by configuration.
 * @retval FSP_ERR_INVALID_ARGUMENT              Input key type is illegal.
 **********************************************************************************************************************/
fsp_err_t R_RSIP_HMAC_VerifyInit (rsip_ctrl_t * const              p_ctrl,
                                  rsip_hmac_handle_t * const       p_handle,
                                  rsip_wrapped_key_t const * const p_wrapped_key)
{
    return hmac_init(p_ctrl, p_handle, p_wrapped_key, false);
}

/*******************************************************************************************************************//**
 * Inputs message.
 *
 * @param[in,out] p_ctrl         Pointer to control block.
 * @param[in,out] p_handle       Pointer to HMAC control block.
 * @param[in]     p_message      Pointer to message. The length is message_length.
 * @param[in]     message_length Byte length of message (0 or more bytes).
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_ASSERTION                     A required parameter is NULL.
 * @retval FSP_ERR_NOT_OPEN                      Module is not open.
 * @retval FSP_ERR_INVALID_STATE                 Internal state is illegal.
 * @retval FSP_ERR_CRYPTO_RSIP_KEY_SET_FAIL      Input key value is illegal.
 *
 * @retval FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource required
 *                                               by the processing is in use by other processing.
 * @retval FSP_ERR_CRYPTO_RSIP_FATAL             Software corruption is detected.
 **********************************************************************************************************************/
fsp_err_t R_RSIP_HMAC_VerifyUpdate (rsip_ctrl_t * const        p_ctrl,
                                    rsip_hmac_handle_t * const p_handle,
                                    uint8_t const * const      p_message,
                                    uint32_t const             message_length)
{
    return hmac_update(p_ctrl, p_handle, p_message, message_length, false);
}

/*******************************************************************************************************************//**
 * Finalizes a HMAC verification.
 *
 * @param[in,out] p_ctrl     Pointer to control block.
 * @param[in,out] p_handle       Pointer to HMAC control block.
 * @param[in]     p_mac      Pointer to MAC. The length depends on mac_length.
 * @param[in]     mac_length Byte length of MAC.
 *                           @arg HMAC-SHA1:   4 to 20
 *                           @arg HMAC-SHA224: 4 to 28
 *                           @arg HMAC-SHA256  4 to 32
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_ASSERTION                     A required parameter is NULL.
 * @retval FSP_ERR_NOT_OPEN                      Module is not open.
 * @retval FSP_ERR_INVALID_STATE                 Internal state is illegal.
 * @retval FSP_ERR_INVALID_SIZE                  mac_length is illegal.
 * @retval FSP_ERR_CRYPTO_RSIP_KEY_SET_FAIL      Input key value is illegal.
 * @retval FSP_ERR_CRYPTO_RSIP_FAIL              MAC verification is failed.
 *
 * @retval FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource required
 *                                               by the processing is in use by other processing.
 * @retval FSP_ERR_CRYPTO_RSIP_FATAL             Software corruption is detected.
 **********************************************************************************************************************/
fsp_err_t R_RSIP_HMAC_VerifyFinal (rsip_ctrl_t * const        p_ctrl,
                                   rsip_hmac_handle_t * const p_handle,
                                   uint8_t const * const      p_mac,
                                   uint32_t const             mac_length)
{
    rsip_instance_ctrl_t * p_instance_ctrl = (rsip_instance_ctrl_t *) p_ctrl;
    fsp_err_t              err             = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_FATAL;

#if RSIP_CFG_PARAM_CHECKING_ENABLE
    FSP_ASSERT(p_instance_ctrl);
    FSP_ASSERT(p_handle);
    FSP_ASSERT(p_mac);
    FSP_ERROR_RETURN(RSIP_OPEN == p_instance_ctrl->open, FSP_ERR_NOT_OPEN);
#endif

    /* Check state */
    FSP_ERROR_RETURN(r_rsip_state_check_init(p_instance_ctrl), FSP_ERR_INVALID_STATE);
    FSP_ERROR_RETURN((RSIP_USER_HANDLE_STATE_UPDATE_EMPTY == p_handle->state) ||
                     (RSIP_USER_HANDLE_STATE_UPDATE == p_handle->state),
                     FSP_ERR_INVALID_STATE);
    FSP_ERROR_RETURN(!p_handle->is_generate, FSP_ERR_INVALID_STATE);

    /* mac_length must be 4 or greater (common) */
    FSP_ERROR_RETURN(4 <= mac_length, FSP_ERR_INVALID_SIZE);

    rsip_key_type_t key_type = ((rsip_wrapped_key_t *) &(p_handle->wrapped_key))->type;

    /* mac_length must be 20 or less (SHA-1) */
    FSP_ERROR_RETURN((RSIP_KEY_TYPE_HMAC_SHA1 != key_type) || (mac_length <= RSIP_PRV_BYTE_SIZE_HMAC_SHA1_MAC),
                     FSP_ERR_INVALID_SIZE);

    /* mac_length must be 28 or less (SHA-224) */
    FSP_ERROR_RETURN((RSIP_KEY_TYPE_HMAC_SHA224 != key_type) ||
                     (mac_length <= RSIP_PRV_BYTE_SIZE_HMAC_SHA224_MAC),
                     FSP_ERR_INVALID_SIZE);

    /* mac_length must be 32 or less (SHA-256) */
    FSP_ERROR_RETURN((RSIP_KEY_TYPE_HMAC_SHA256 != key_type) ||
                     (mac_length <= RSIP_PRV_BYTE_SIZE_HMAC_SHA256_MAC),
                     FSP_ERR_INVALID_SIZE);

    /* Call function (cast to match the argument type with the function) */
    rsip_ret_t rsip_ret = r_rsip_hmac_calc_multi(p_handle,
                                                 p_handle->buffer,
                                                 p_handle->buffered_length,
                                                 (uint8_t *) p_mac,
                                                 mac_length,
                                                 true);

    /* Check error */
    switch (rsip_ret)
    {
        case RSIP_RET_PASS:
        {
            /* State transition */
            p_handle->state = RSIP_USER_HANDLE_STATE_INIT;

            err = FSP_SUCCESS;
            break;
        }

        case RSIP_RET_RESOURCE_CONFLICT:
        {
            err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT;
            break;
        }

        case RSIP_RET_KEY_FAIL:
        {
            err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_KEY_SET_FAIL;
            break;
        }

        case RSIP_RET_FAIL:
        {
            err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_FAIL;
            break;
        }

        default:
        {
            err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_FATAL;
        }
    }

    return err;
}

/*******************************************************************************************************************//**
 * @} (end addtogroup RSIP)
 **********************************************************************************************************************/

/*******************************************************************************************************************//**
 * Prepares a SHA generation.
 *
 * @param[in,out] p_ctrl    Pointer to control block.
 * @param[in,out] p_handle  Pointer to SHA control block. Must be declared by user. Elements are set here.
 * @param[in]     hash_type Generating hash type.
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_INVALID_STATE                 Internal state is illegal.
 **********************************************************************************************************************/
fsp_err_t r_rsip_sha_generate_init (rsip_ctrl_t * const       p_ctrl,
                                    rsip_sha_handle_t * const p_handle,
                                    rsip_hash_type_t const    hash_type)
{
    rsip_instance_ctrl_t * p_instance_ctrl = (rsip_instance_ctrl_t *) p_ctrl;

    /* Check state */
    FSP_ERROR_RETURN(r_rsip_state_check_init(p_instance_ctrl), FSP_ERR_INVALID_STATE);

    /* Reset handle */
    p_handle->buffered_length = 0;
    p_handle->total_length    = 0;

    /* Set hash type */
    p_handle->type = hash_type;

    /* Set block size */
    switch (hash_type)
    {
        /* SHA-1, SHA-224, SHA-256 */
        case RSIP_HASH_TYPE_SHA1:
        case RSIP_HASH_TYPE_SHA224:
        case RSIP_HASH_TYPE_SHA256:
        {
            p_handle->block_size = RSIP_PRV_BYTE_SIZE_HASH_BLOCK_SHA1_SHA224_SHA256;
            break;
        }

        /* SHA-384, SHA-512, SHA-512/224, SHA-512/256 */
        default:
        {
            p_handle->block_size = RSIP_PRV_BYTE_SIZE_HASH_BLOCK_SHA384_SHA512;
        }
    }

    /* State transition */
    p_handle->state = RSIP_USER_HANDLE_STATE_UPDATE_EMPTY;

    return FSP_SUCCESS;
}

/*******************************************************************************************************************//**
 * Inputs message.
 *
 * @param[in,out] p_ctrl         Pointer to control block.
 * @param[in,out] p_handle       Pointer to SHA control block.
 * @param[in]     p_message      Pointer to message. The length is message_length.
 * @param[in]     message_length Byte length of message (0 or more bytes).
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_INVALID_STATE                 Internal state is illegal.
 *
 * @retval FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource required
 *                                               by the processing is in use by other processing.
 * @retval FSP_ERR_CRYPTO_RSIP_FATAL             Software corruption is detected.
 **********************************************************************************************************************/
fsp_err_t r_rsip_sha_generate_update (rsip_ctrl_t * const       p_ctrl,
                                      rsip_sha_handle_t * const p_handle,
                                      uint8_t const * const     p_message,
                                      uint32_t const            message_length)
{
    rsip_instance_ctrl_t * p_instance_ctrl = (rsip_instance_ctrl_t *) p_ctrl;

    /* Check state */
    FSP_ERROR_RETURN(r_rsip_state_check_init(p_instance_ctrl), FSP_ERR_INVALID_STATE);
    FSP_ERROR_RETURN((RSIP_USER_HANDLE_STATE_UPDATE_EMPTY == p_handle->state) ||
                     (RSIP_USER_HANDLE_STATE_UPDATE == p_handle->state),
                     FSP_ERR_INVALID_STATE);

    fsp_err_t err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_FATAL;
    if (0 == message_length)
    {
        err = FSP_SUCCESS;
    }
    else
    {
        rsip_ret_t      rsip_ret      = RSIP_RET_PASS;
        const uint8_t * p_msg_pos     = p_message;
        uint32_t        processed_len = 0;

        /* (1) Remaining message in buffer and head of new input message */
        if ((0 != p_handle->buffered_length) &&
            (p_handle->block_size < (p_handle->buffered_length + message_length)))
        {
            uint32_t len = p_handle->block_size - p_handle->buffered_length;

            /* Copy head of new message to buffer */
            memcpy(p_handle->buffer + p_handle->buffered_length, p_msg_pos, len);

            /* Call function */
            rsip_ret = r_rsip_sha1sha2_calc_multi(p_handle, p_handle->buffer, p_handle->block_size, NULL);

            p_handle->buffered_length = 0;
            processed_len            += len;
        }

        /* (2) New input message except last block */
        if ((p_handle->block_size < message_length) && (RSIP_RET_PASS == rsip_ret))
        {
            uint32_t len = ((message_length - processed_len - 1) / p_handle->block_size) *
                           p_handle->block_size;

            /* Call function */
            rsip_ret = r_rsip_sha1sha2_calc_multi(p_handle, p_message + processed_len, len, NULL);

            processed_len += len;
        }

        /* Check error */
        switch (rsip_ret)
        {
            case RSIP_RET_PASS:
            {
                /* (3) Last block */
                memcpy(p_handle->buffer + p_handle->buffered_length,
                       p_message + processed_len,
                       message_length - processed_len);
                p_handle->buffered_length += message_length - processed_len;

                err = FSP_SUCCESS;
                break;
            }

            case RSIP_RET_RESOURCE_CONFLICT:
            {
                err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT;
                break;
            }

            default:
            {
                err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_FATAL;
            }
        }
    }

    return err;
}

/*******************************************************************************************************************//**
 * Finalizes a SHA generation.
 *
 * @param[in,out] p_ctrl   Pointer to control block.
 * @param[in,out] p_handle Pointer to SHA control block.
 * @param[out]    p_digest Pointer to destination of message digest. The length depends on hash type.
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_INVALID_STATE                 Internal state is illegal.
 *
 * @retval FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource required
 *                                               by the processing is in use by other processing.
 * @retval FSP_ERR_CRYPTO_RSIP_FATAL             Software corruption is detected.
 **********************************************************************************************************************/
fsp_err_t r_rsip_sha_generate_final (rsip_ctrl_t * const       p_ctrl,
                                     rsip_sha_handle_t * const p_handle,
                                     uint8_t * const           p_digest)
{
    rsip_instance_ctrl_t * p_instance_ctrl = (rsip_instance_ctrl_t *) p_ctrl;
    fsp_err_t              err             = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_FATAL;

    /* Check state */
    FSP_ERROR_RETURN(r_rsip_state_check_init(p_instance_ctrl), FSP_ERR_INVALID_STATE);
    FSP_ERROR_RETURN((RSIP_USER_HANDLE_STATE_UPDATE_EMPTY == p_handle->state) ||
                     (RSIP_USER_HANDLE_STATE_UPDATE == p_handle->state),
                     FSP_ERR_INVALID_STATE);

    /* Call function */
    rsip_ret_t rsip_ret = r_rsip_sha1sha2_calc_multi(p_handle, p_handle->buffer, p_handle->buffered_length, p_digest);

    /* Check error */
    switch (rsip_ret)
    {
        case RSIP_RET_PASS:
        {
            /* State transition */
            p_handle->state = RSIP_USER_HANDLE_STATE_INIT;

            err = FSP_SUCCESS;
            break;
        }

        case RSIP_RET_RESOURCE_CONFLICT:
        {
            err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT;
            break;
        }

        default:
        {
            err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_FATAL;
        }
    }

    return err;
}

/***********************************************************************************************************************
 * Private Functions
 **********************************************************************************************************************/

/*******************************************************************************************************************//**
 * Prepares a HMAC.
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_ASSERTION                     A required parameter is NULL.
 * @retval FSP_ERR_NOT_OPEN                      Module is not open.
 * @retval FSP_ERR_INVALID_STATE                 Internal state is illegal.
 * @retval FSP_ERR_NOT_ENABLED                   Input key type is disabled in this function by configuration.
 * @retval FSP_ERR_INVALID_ARGUMENT              Input key type is illegal.
 **********************************************************************************************************************/
static fsp_err_t hmac_init (rsip_ctrl_t              * p_ctrl,
                            rsip_hmac_handle_t       * p_handle,
                            const rsip_wrapped_key_t * p_wrapped_key,
                            bool                       is_generate)
{
    rsip_instance_ctrl_t * p_instance_ctrl = (rsip_instance_ctrl_t *) p_ctrl;

#if RSIP_CFG_PARAM_CHECKING_ENABLE
    FSP_ASSERT(p_instance_ctrl);
    FSP_ASSERT(p_handle);
    FSP_ASSERT(p_wrapped_key);
    FSP_ERROR_RETURN(RSIP_OPEN == p_instance_ctrl->open, FSP_ERR_NOT_OPEN);

    /* Check key type */
    FSP_ERROR_RETURN(RSIP_PRV_IS_HMAC_KEY(p_wrapped_key->type), FSP_ERR_INVALID_ARGUMENT);

    /* Check configuration */
    FSP_ERROR_RETURN(gp_func_hmac_multi[RSIP_PRV_HMAC_REBASE(p_wrapped_key->type)], FSP_ERR_NOT_ENABLED);
#endif

    /* Check state */
    FSP_ERROR_RETURN(r_rsip_state_check_init(p_instance_ctrl), FSP_ERR_INVALID_STATE);

    /* Reset handle */
    p_handle->buffered_length = 0;
    p_handle->total_length    = 0;

    /* Copy wrapped key */
    memcpy(p_handle->wrapped_key, p_wrapped_key, RSIP_BYTE_SIZE_WRAPPED_KEY_HMAC_SHA256);

    /* Set primitive */
    p_handle->p_primitive = (rsip_func_hmac_multi_t *) gp_func_hmac_multi[RSIP_PRV_HMAC_REBASE(p_wrapped_key->type)];

    /* Set block size */
    p_handle->block_size = RSIP_PRV_BYTE_SIZE_HASH_BLOCK_SHA1_SHA224_SHA256;

    /* State transition */
    p_handle->state = RSIP_USER_HANDLE_STATE_UPDATE_EMPTY;

    /* Set flag */
    p_handle->is_generate = is_generate;

    return FSP_SUCCESS;
}

/*******************************************************************************************************************//**
 * Inputs message.
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_ASSERTION                     A required parameter is NULL.
 * @retval FSP_ERR_NOT_OPEN                      Module is not open.
 * @retval FSP_ERR_INVALID_STATE                 Internal state is illegal.
 * @retval FSP_ERR_CRYPTO_RSIP_KEY_SET_FAIL      Input key value is illegal.
 *
 * @retval FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource required
 *                                               by the processing is in use by other processing.
 * @retval FSP_ERR_CRYPTO_RSIP_FATAL             Software corruption is detected.
 **********************************************************************************************************************/
static fsp_err_t hmac_update (rsip_ctrl_t * const        p_ctrl,
                              rsip_hmac_handle_t * const p_handle,
                              uint8_t const * const      p_message,
                              uint32_t const             message_length,
                              bool                       is_generate)
{
    rsip_instance_ctrl_t * p_instance_ctrl = (rsip_instance_ctrl_t *) p_ctrl;
    fsp_err_t              err             = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_FATAL;

#if RSIP_CFG_PARAM_CHECKING_ENABLE
    FSP_ASSERT(p_instance_ctrl);
    FSP_ASSERT(p_handle);
    FSP_ASSERT(p_message || (0 == message_length));
    FSP_ERROR_RETURN(RSIP_OPEN == p_instance_ctrl->open, FSP_ERR_NOT_OPEN);
#endif

    /* Check state */
    FSP_ERROR_RETURN(r_rsip_state_check_init(p_instance_ctrl), FSP_ERR_INVALID_STATE);
    FSP_ERROR_RETURN((RSIP_USER_HANDLE_STATE_UPDATE_EMPTY == p_handle->state) ||
                     (RSIP_USER_HANDLE_STATE_UPDATE == p_handle->state),
                     FSP_ERR_INVALID_STATE);
    FSP_ERROR_RETURN(is_generate == p_handle->is_generate, FSP_ERR_INVALID_STATE);

    if (0 == message_length)
    {
        err = FSP_SUCCESS;
    }
    else
    {
        rsip_ret_t      rsip_ret      = RSIP_RET_PASS;
        const uint8_t * p_msg_pos     = p_message;
        uint32_t        processed_len = 0;

        /* (1) Remaining message in buffer and head of new input message */
        if ((0 != p_handle->buffered_length) &&
            (p_handle->block_size < (p_handle->buffered_length + message_length)))
        {
            uint32_t len = p_handle->block_size - p_handle->buffered_length;

            /* Copy head of new message to buffer */
            memcpy(p_handle->buffer + p_handle->buffered_length, p_msg_pos, len);

            /* Call function */
            rsip_ret = r_rsip_hmac_calc_multi(p_handle, p_handle->buffer, p_handle->block_size, NULL, 0, false);

            p_handle->buffered_length = 0;
            processed_len            += len;
        }

        /* (2) New input message except last block */
        if ((p_handle->block_size < message_length) && (RSIP_RET_PASS == rsip_ret))
        {
            uint32_t len = ((message_length - processed_len - 1) / p_handle->block_size) *
                           p_handle->block_size;

            /* Call function */
            rsip_ret = r_rsip_hmac_calc_multi(p_handle, p_message + processed_len, len, NULL, 0, false);

            processed_len += len;
        }

        /* Check error */
        switch (rsip_ret)
        {
            case RSIP_RET_PASS:
            {
                /* (3) Last block */
                memcpy(p_handle->buffer + p_handle->buffered_length,
                       p_message + processed_len,
                       message_length - processed_len);
                p_handle->buffered_length += message_length - processed_len;

                err = FSP_SUCCESS;
                break;
            }

            case RSIP_RET_RESOURCE_CONFLICT:
            {
                err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT;
                break;
            }

            case RSIP_RET_KEY_FAIL:
            {
                err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_KEY_SET_FAIL;
                break;
            }

            /* RSIP_RET_FAIL is not used in this function */
            case RSIP_RET_FAIL:
            default:
            {
                err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_FATAL;
            }
        }
    }

    return err;
}
