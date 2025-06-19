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

/***********************************************************************************************************************
 * Typedef definitions
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Private function prototypes
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Private global variables
 **********************************************************************************************************************/

static const rsip_key_type_t gs_key_pair_type_to_public_key_type[] =
{
    [RSIP_KEY_PAIR_TYPE_ECC_secp192r1]       = RSIP_KEY_TYPE_ECC_secp192r1_PUBLIC,
    [RSIP_KEY_PAIR_TYPE_ECC_secp224r1]       = RSIP_KEY_TYPE_ECC_secp224r1_PUBLIC,
    [RSIP_KEY_PAIR_TYPE_ECC_secp256r1]       = RSIP_KEY_TYPE_ECC_secp256r1_PUBLIC,
    [RSIP_KEY_PAIR_TYPE_ECC_BRAINPOOLP256R1] = RSIP_KEY_TYPE_ECC_BRAINPOOLP256R1_PUBLIC,
    [RSIP_KEY_PAIR_TYPE_RSA_1024]            = RSIP_KEY_TYPE_RSA_1024_PUBLIC_ENHANCED,
    [RSIP_KEY_PAIR_TYPE_RSA_2048]            = RSIP_KEY_TYPE_RSA_2048_PUBLIC_ENHANCED,
    [RSIP_KEY_PAIR_TYPE_RSA_3072]            = RSIP_KEY_TYPE_RSA_3072_PUBLIC,
    [RSIP_KEY_PAIR_TYPE_RSA_4096]            = RSIP_KEY_TYPE_RSA_4096_PUBLIC,
};

static const rsip_key_type_t gs_key_pair_type_to_private_key_type[] =
{
    [RSIP_KEY_PAIR_TYPE_ECC_secp192r1]       = RSIP_KEY_TYPE_ECC_secp192r1_PRIVATE,
    [RSIP_KEY_PAIR_TYPE_ECC_secp224r1]       = RSIP_KEY_TYPE_ECC_secp224r1_PRIVATE,
    [RSIP_KEY_PAIR_TYPE_ECC_secp256r1]       = RSIP_KEY_TYPE_ECC_secp256r1_PRIVATE,
    [RSIP_KEY_PAIR_TYPE_ECC_BRAINPOOLP256R1] = RSIP_KEY_TYPE_ECC_BRAINPOOLP256R1_PRIVATE,
    [RSIP_KEY_PAIR_TYPE_RSA_1024]            = RSIP_KEY_TYPE_RSA_1024_PRIVATE_ENHANCED,
    [RSIP_KEY_PAIR_TYPE_RSA_2048]            = RSIP_KEY_TYPE_RSA_2048_PRIVATE_ENHANCED,
    [RSIP_KEY_PAIR_TYPE_RSA_3072]            = RSIP_KEY_TYPE_RSA_3072_PRIVATE,
    [RSIP_KEY_PAIR_TYPE_RSA_4096]            = RSIP_KEY_TYPE_RSA_4096_PRIVATE,
};

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
 * Opens the RSIP driver module.
 *
 * @param[in,out] p_ctrl Pointer to control block. Must be declared by user. Elements are set here.
 * @param[in]     p_cfg  Pointer to configuration structure.
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_ASSERTION                     A required parameter is NULL.
 * @retval FSP_ERR_ALREADY_OPEN                  Module is already open.
 * @retval FSP_ERR_CRYPTO_RSIP_KEY_SET_FAIL      Internal key value is illegal.
 * @retval FSP_ERR_CRYPTO_RSIP_FAIL              Hardware initialization is failed.
 *
 * @retval FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource required
 *                                               by the processing is in use by other processing.
 * @retval FSP_ERR_CRYPTO_RSIP_FATAL             Software corruption or hardware fault is detected.
 **********************************************************************************************************************/
fsp_err_t R_RSIP_Open (rsip_ctrl_t * const p_ctrl, rsip_cfg_t const * const p_cfg)
{
    rsip_instance_ctrl_t * p_instance_ctrl = (rsip_instance_ctrl_t *) p_ctrl;

#if RSIP_CFG_PARAM_CHECKING_ENABLE
    FSP_ASSERT(p_instance_ctrl);
    FSP_ASSERT(p_cfg);
    FSP_ERROR_RETURN(RSIP_OPEN != p_instance_ctrl->open, FSP_ERR_ALREADY_OPEN);
#endif

    /* Set configuration */
    p_instance_ctrl->p_cfg = p_cfg;

    /* Device-specific sequence */
    rsip_ret_t rsip_ret = r_rsip_open();

    /* Check error */
    fsp_err_t err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_FATAL;
    switch (rsip_ret)
    {
        case RSIP_RET_PASS:
        {
            /* Reset handle */
            r_rsip_handle_reset(&p_instance_ctrl->handle);

            /* State transition */
            r_rsip_state_transit_init(p_instance_ctrl);

            /* Set driver status to open */
            p_instance_ctrl->open = RSIP_OPEN;

            err = FSP_SUCCESS;
            break;
        }

        case RSIP_RET_RESOURCE_CONFLICT:
        {
            err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT;
            break;
        }

        /* Treat PASS_1 as FAIL */
        case RSIP_RET_FAIL:
        case RSIP_RET_PASS_1:
        {
            err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_FAIL;
            break;
        }

        case RSIP_RET_KEY_FAIL:
        {
            err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_KEY_SET_FAIL;
            break;
        }

        /* Treat RETRY as FATAL */
        case RSIP_RET_RETRY:
        default:
        {
            err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_FATAL;
        }
    }

    return err;
}

/*******************************************************************************************************************//**
 * Closes the RSIP driver module.
 *
 * @param[in,out] p_ctrl Pointer to control block.
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_ASSERTION                     A required parameter is NULL.
 * @retval FSP_ERR_NOT_OPEN                      Module is not open.
 *
 * @retval FSP_ERR_CRYPTO_RSIP_FATAL             Software corruption is detected.
 **********************************************************************************************************************/
fsp_err_t R_RSIP_Close (rsip_ctrl_t * const p_ctrl)
{
    rsip_instance_ctrl_t * p_instance_ctrl = (rsip_instance_ctrl_t *) p_ctrl;

#if RSIP_CFG_PARAM_CHECKING_ENABLE
    FSP_ASSERT(p_instance_ctrl);
    FSP_ERROR_RETURN(RSIP_OPEN == p_instance_ctrl->open, FSP_ERR_NOT_OPEN);
#endif

    /* Device-specific sequence */
    rsip_ret_t rsip_ret = r_rsip_close();

    /* Check error */
    fsp_err_t err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_FATAL;
    switch (rsip_ret)
    {
        case RSIP_RET_PASS:
        {
            /* Set driver status to close */
            p_instance_ctrl->open = 0U;

            err = FSP_SUCCESS;
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
 * Generates a 128-bit random number.
 *
 * @param[in,out] p_ctrl   Pointer to control block.
 * @param[out]    p_random Pointer to destination of random number. The length is 16 bytes.
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
fsp_err_t R_RSIP_RandomNumberGenerate (rsip_ctrl_t * const p_ctrl, uint8_t * const p_random)
{
#if RSIP_CFG_PARAM_CHECKING_ENABLE
    rsip_instance_ctrl_t * p_instance_ctrl = (rsip_instance_ctrl_t *) p_ctrl;

    FSP_ASSERT(p_instance_ctrl);
    FSP_ASSERT(p_random);
    FSP_ERROR_RETURN(RSIP_OPEN == p_instance_ctrl->open, FSP_ERR_NOT_OPEN);
#endif

    return r_rsip_random_number_generate(p_ctrl, p_random);
}

/*******************************************************************************************************************//**
 * Generates a wrapped symmetric key from a random number. In this API, user key input is unnecessary.
 * By encrypting data using the wrapped key is output by this API, dead copying of data can be prevented.
 *
 * @param[in,out] p_ctrl        Pointer to control block.
 * @param[in]     key_type      Outputs key type.
 * @param[out]    p_wrapped_key Pointer to destination of wrapped key. The length depends on key type.
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_ASSERTION                     A required parameter is NULL.
 * @retval FSP_ERR_NOT_OPEN                      Module is not open.
 * @retval FSP_ERR_INVALID_STATE                 Internal state is illegal.
 * @retval FSP_ERR_NOT_ENABLED                   Input key type is disabled in this function by configuration.
 * @retval FSP_ERR_UNSUPPORTED                   Input key type is unsupported.
 *
 * @retval FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource required
 *                                               by the processing is in use by other processing.
 * @retval FSP_ERR_CRYPTO_RSIP_FATAL             Software corruption is detected.
 *
 * @sa Section @ref r-rsip-key-management "Key Management"
 **********************************************************************************************************************/
fsp_err_t R_RSIP_KeyGenerate (rsip_ctrl_t * const        p_ctrl,
                              rsip_key_type_t const      key_type,
                              rsip_wrapped_key_t * const p_wrapped_key)
{
    rsip_instance_ctrl_t * p_instance_ctrl = (rsip_instance_ctrl_t *) p_ctrl;

    /* Set primitive */
    rsip_func_key_generate_t p_primitive = gp_func_key_generate[key_type];

#if RSIP_CFG_PARAM_CHECKING_ENABLE
    FSP_ASSERT(p_instance_ctrl);
    FSP_ASSERT(p_wrapped_key);
    FSP_ERROR_RETURN(RSIP_OPEN == p_instance_ctrl->open, FSP_ERR_NOT_OPEN);

    /* Check key type */
    FSP_ERROR_RETURN(g_key_generate_supported_algs[key_type], FSP_ERR_UNSUPPORTED);

    /* Check if the key type is enabled on configuration */
    FSP_ERROR_RETURN(p_primitive, FSP_ERR_NOT_ENABLED);
#endif

    /* Check state */
    FSP_ERROR_RETURN(r_rsip_state_check_init(p_instance_ctrl), FSP_ERR_INVALID_STATE);

    /* Call primitive (cast to match the argument type with the primitive function) */
    rsip_ret_t rsip_ret = p_primitive((uint32_t *) p_wrapped_key->value);

    /* Check error */
    fsp_err_t err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_FATAL;
    switch (rsip_ret)
    {
        case RSIP_RET_PASS:
        {
            p_wrapped_key->type = key_type;

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
 * Generates a wrapped asymmetric key pair from a random number. In this API, user key input is unnecessary.
 * By encrypting data using the wrapped key is output by this API, dead copying of data can be prevented.
 *
 * @param[in,out] p_ctrl                Pointer to control block.
 * @param[in]     key_pair_type         Output key pair type.
 * @param[out]    p_wrapped_public_key  Pointer to destination of wrapped public key. The length depends on key type.
 * @param[out]    p_wrapped_private_key Pointer to destination of wrapped private key. The length depends on key type.
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_ASSERTION                     A required parameter is NULL.
 * @retval FSP_ERR_NOT_OPEN                      Module is not open.
 * @retval FSP_ERR_INVALID_STATE                 Internal state is illegal.
 * @retval FSP_ERR_NOT_ENABLED                   Input key type is disabled in this function by configuration.
 * @retval FSP_ERR_UNSUPPORTED                   Input key type is unsupported.
 *
 * @retval FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource required
 *                                               by the processing is in use by other processing.
 * @retval FSP_ERR_CRYPTO_RSIP_FATAL             Software corruption is detected.
 *
 * @sa Section @ref r-rsip-key-management "Key Management"
 **********************************************************************************************************************/
fsp_err_t R_RSIP_KeyPairGenerate (rsip_ctrl_t * const        p_ctrl,
                                  rsip_key_pair_type_t const key_pair_type,
                                  rsip_wrapped_key_t * const p_wrapped_public_key,
                                  rsip_wrapped_key_t * const p_wrapped_private_key)
{
    rsip_instance_ctrl_t * p_instance_ctrl = (rsip_instance_ctrl_t *) p_ctrl;

    /* Set primitive */
    rsip_func_key_pair_generate_t p_primitive = gp_func_key_pair_generate[key_pair_type];

#if RSIP_CFG_PARAM_CHECKING_ENABLE
    FSP_ASSERT(p_instance_ctrl);
    FSP_ASSERT(p_wrapped_public_key);
    FSP_ASSERT(p_wrapped_private_key);
    FSP_ERROR_RETURN(RSIP_OPEN == p_instance_ctrl->open, FSP_ERR_NOT_OPEN);

    /* Check key type */
    FSP_ERROR_RETURN(g_key_pair_generate_supported_algs[key_pair_type], FSP_ERR_UNSUPPORTED);

    /* Check if the key type is enabled on configuration */
    FSP_ERROR_RETURN(p_primitive, FSP_ERR_NOT_ENABLED);
#endif

    /* Check state */
    FSP_ERROR_RETURN(r_rsip_state_check_init(p_instance_ctrl), FSP_ERR_INVALID_STATE);

    /* Call primitive (cast to match the argument type with the primitive function) */
    rsip_ret_t rsip_ret = p_primitive((uint32_t *) p_wrapped_public_key->value,
                                      (uint32_t *) p_wrapped_private_key->value);

    /* Check error */
    fsp_err_t err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_FATAL;
    switch (rsip_ret)
    {
        case RSIP_RET_PASS:
        {
            p_wrapped_public_key->type  = gs_key_pair_type_to_public_key_type[key_pair_type];
            p_wrapped_private_key->type = gs_key_pair_type_to_private_key_type[key_pair_type];

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
 * Imports a user key with KUK (Key Update Key) within the user routine.
 *
 * @param[in,out] p_ctrl           Pointer to control block.
 * @param[in]     p_key_update_key Pointer to Key Update Key.
 * @param[in]     p_initial_vector Pointer to initialization vector when generating encrypted_key.
 *                                 The length is 16 bytes.
 * @param[in]     key_type         Inputs/Outputs key type.
 * @param[in]     p_encrypted_key  Pointer to encrypted user key. The length depends on the key type.
 * @param[out]    p_wrapped_key    Pointer to destination of wrapped key. The length depends on the key type.
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_ASSERTION                     A required parameter is NULL.
 * @retval FSP_ERR_NOT_OPEN                      Module is not open.
 * @retval FSP_ERR_INVALID_STATE                 Internal state is illegal.
 * @retval FSP_ERR_NOT_ENABLED                   Input key type is disabled in this function by configuration.
 * @retval FSP_ERR_UNSUPPORTED                   Input key type is unsupported.
 * @retval FSP_ERR_INVALID_ARGUMENT              p_key_update_key->type is illegal.
 * @retval FSP_ERR_CRYPTO_RSIP_FAIL              Input parameter is invalid.
 *
 * @retval FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource required
 *                                               by the processing is in use by other processing.
 * @retval FSP_ERR_CRYPTO_RSIP_FATAL             Software corruption is detected.
 *
 * @sa Section @ref r-rsip-key-management "Key Management"
 **********************************************************************************************************************/
fsp_err_t R_RSIP_KeyImportWithKUK (rsip_ctrl_t * const              p_ctrl,
                                   rsip_wrapped_key_t const * const p_key_update_key,
                                   uint8_t const * const            p_initial_vector,
                                   rsip_key_type_t const            key_type,
                                   uint8_t const * const            p_encrypted_key,
                                   rsip_wrapped_key_t * const       p_wrapped_key)
{
    rsip_instance_ctrl_t * p_instance_ctrl = (rsip_instance_ctrl_t *) p_ctrl;

    /* Set primitive */
    rsip_func_key_import_with_kuk_t p_primitive = gp_func_key_import_with_kuk[key_type];

#if RSIP_CFG_PARAM_CHECKING_ENABLE
    FSP_ASSERT(p_instance_ctrl);
    FSP_ASSERT(p_key_update_key);
    FSP_ASSERT(p_initial_vector);
    FSP_ASSERT(p_encrypted_key);
    FSP_ASSERT(p_wrapped_key);
    FSP_ERROR_RETURN(RSIP_OPEN == p_instance_ctrl->open, FSP_ERR_NOT_OPEN);

    /* Check key type */
    FSP_ERROR_RETURN(g_key_import_with_kuk_supported_algs[key_type], FSP_ERR_UNSUPPORTED);

    /* Check if the key type is enabled on configuration */
    FSP_ERROR_RETURN(p_primitive, FSP_ERR_NOT_ENABLED);

    /* Check key type of KUK */
    FSP_ERROR_RETURN(RSIP_KEY_TYPE_KEY_UPDATE_KEY == p_key_update_key->type, FSP_ERR_INVALID_ARGUMENT);
#endif

    /* Check state */
    FSP_ERROR_RETURN(r_rsip_state_check_init(p_instance_ctrl), FSP_ERR_INVALID_STATE);

    /* Store KUK */
    r_rsip_kuk_store(p_key_update_key->value);

    /* Call primitive (cast to match the argument type with the primitive function) */
    rsip_ret_t rsip_ret =
        p_primitive((uint32_t const *) p_initial_vector,
                    (uint32_t const *) p_encrypted_key,
                    (uint32_t *) p_wrapped_key->value);

    /* Check error */
    fsp_err_t err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_FATAL;
    switch (rsip_ret)
    {
        case RSIP_RET_PASS:
        {
            p_wrapped_key->type = key_type;

            err = FSP_SUCCESS;
            break;
        }

        case RSIP_RET_RESOURCE_CONFLICT:
        {
            err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT;
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
 * Exports ECC public key parameters from a wrapped key.
 *
 * @param[in]  p_wrapped_public_key Pointer to wrapped key of ECC public key.
 * @param[out] pp_raw_public_key_qx Pointer to raw `Q_x`. The length depends on the key length.
 * @param[out] pp_raw_public_key_qy Pointer to raw `Q_y`. The length depends on the key length.
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_ASSERTION                     A required parameter is NULL.
 * @retval FSP_ERR_INVALID_ARGUMENT              Key type is illegal.
 *
 * @note Outputs are only available inside the scope of the wrapped key. If necessary, please copy them.
 * @sa Section @ref r-rsip-key-management "Key Management"
 **********************************************************************************************************************/
fsp_err_t R_RSIP_ECCPublicKeyExport (rsip_wrapped_key_t const * const p_wrapped_public_key,
                                     uint8_t const ** const           pp_raw_public_key_qx,
                                     uint8_t const ** const           pp_raw_public_key_qy)
{
#if RSIP_CFG_PARAM_CHECKING_ENABLE
    FSP_ASSERT(p_wrapped_public_key);
    FSP_ASSERT(pp_raw_public_key_qx);
    FSP_ASSERT(pp_raw_public_key_qy);
#endif

    fsp_err_t err = FSP_ERR_INVALID_ARGUMENT;
    switch (p_wrapped_public_key->type)
    {
        /* The parameter positions of the following key types are the same */
        case RSIP_KEY_TYPE_ECC_secp192r1_PUBLIC:
        {
            *pp_raw_public_key_qx = p_wrapped_public_key->value + RSIP_CFG_BYTE_POS_WRAPPED_PUBLIC_KEY_ECC_192_QX;
            *pp_raw_public_key_qy = p_wrapped_public_key->value + RSIP_CFG_BYTE_POS_WRAPPED_PUBLIC_KEY_ECC_192_QY;

            err = FSP_SUCCESS;
            break;
        }
        case RSIP_KEY_TYPE_ECC_secp224r1_PUBLIC:
        {
            *pp_raw_public_key_qx = p_wrapped_public_key->value + RSIP_CFG_BYTE_POS_WRAPPED_PUBLIC_KEY_ECC_224_QX;
            *pp_raw_public_key_qy = p_wrapped_public_key->value + RSIP_CFG_BYTE_POS_WRAPPED_PUBLIC_KEY_ECC_224_QY;

            err = FSP_SUCCESS;
            break;
        }
        case RSIP_KEY_TYPE_ECC_secp256r1_PUBLIC:
        case RSIP_KEY_TYPE_ECC_BRAINPOOLP256R1_PUBLIC:
        {
            *pp_raw_public_key_qx = p_wrapped_public_key->value + RSIP_CFG_BYTE_POS_WRAPPED_PUBLIC_KEY_ECC_256_QX;
            *pp_raw_public_key_qy = p_wrapped_public_key->value + RSIP_CFG_BYTE_POS_WRAPPED_PUBLIC_KEY_ECC_256_QY;

            err = FSP_SUCCESS;
            break;
        }

        default:
        {
            /* Do nothing */
        }
    }

    return err;
}

/*******************************************************************************************************************//**
 * Exports RSA public key parameters from a wrapped key.
 *
 * @param[in]  p_wrapped_public_key Pointer to wrapped key of RSA public key.
 * @param[out] pp_raw_public_key_n  Pointer to raw `n`. The length is as same as the key length.
 * @param[out] pp_raw_public_key_e  Pointer to raw `e`. The length is 4 bytes.
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_ASSERTION                     A required parameter is NULL.
 * @retval FSP_ERR_INVALID_ARGUMENT              Key type is illegal.
 *
 * @note Outputs are only available inside the scope of the wrapped key. If necessary, please copy them.
 * @sa Section @ref r-rsip-key-management "Key Management"
 **********************************************************************************************************************/
fsp_err_t R_RSIP_RSAPublicKeyExport (rsip_wrapped_key_t const * const p_wrapped_public_key,
                                     uint8_t const ** const           pp_raw_public_key_n,
                                     uint8_t const ** const           pp_raw_public_key_e)
{
#if RSIP_CFG_PARAM_CHECKING_ENABLE
    FSP_ASSERT(p_wrapped_public_key);
    FSP_ASSERT(pp_raw_public_key_n);
    FSP_ASSERT(pp_raw_public_key_e);
#endif

    fsp_err_t err = FSP_ERR_INVALID_ARGUMENT;
    switch (p_wrapped_public_key->type)
    {
        /* The parameter positions of the following key types are the same */
        case RSIP_KEY_TYPE_RSA_1024_PUBLIC_ENHANCED:
        {
            *pp_raw_public_key_n = p_wrapped_public_key->value + RSIP_CFG_BYTE_POS_WRAPPED_PUBLIC_KEY_RSA_1024_N;
            *pp_raw_public_key_e = p_wrapped_public_key->value + RSIP_CFG_BYTE_POS_WRAPPED_PUBLIC_KEY_RSA_1024_E;

            err = FSP_SUCCESS;
            break;
        }

        /* The parameter positions of the following key types are the same */
        case RSIP_KEY_TYPE_RSA_2048_PUBLIC_ENHANCED:
        {
            *pp_raw_public_key_n = p_wrapped_public_key->value + RSIP_CFG_BYTE_POS_WRAPPED_PUBLIC_KEY_RSA_2048_N;
            *pp_raw_public_key_e = p_wrapped_public_key->value + RSIP_CFG_BYTE_POS_WRAPPED_PUBLIC_KEY_RSA_2048_E;

            err = FSP_SUCCESS;
            break;
        }

        case RSIP_KEY_TYPE_RSA_3072_PUBLIC:
        {
            *pp_raw_public_key_n = p_wrapped_public_key->value + RSIP_CFG_BYTE_POS_WRAPPED_PUBLIC_KEY_RSA_3072_N;
            *pp_raw_public_key_e = p_wrapped_public_key->value + RSIP_CFG_BYTE_POS_WRAPPED_PUBLIC_KEY_RSA_3072_E;

            err = FSP_SUCCESS;
            break;
        }

        case RSIP_KEY_TYPE_RSA_4096_PUBLIC:
        {
            *pp_raw_public_key_n = p_wrapped_public_key->value + RSIP_CFG_BYTE_POS_WRAPPED_PUBLIC_KEY_RSA_4096_N;
            *pp_raw_public_key_e = p_wrapped_public_key->value + RSIP_CFG_BYTE_POS_WRAPPED_PUBLIC_KEY_RSA_4096_E;

            err = FSP_SUCCESS;
            break;
        }

        default:
        {
            /* Do nothing */
        }
    }

    return err;
}

/*******************************************************************************************************************//**
 * @} (end addtogroup RSIP)
 **********************************************************************************************************************/

/*******************************************************************************************************************//**
 * Generates a 128-bit random number.
 *
 * @param[in,out] p_ctrl   Pointer to control block.
 * @param[out]    p_random Pointer to destination of random number. The length is 16 bytes.
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_INVALID_STATE                 Internal state is illegal.
 *
 * @retval FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource required
 *                                               by the processing is in use by other processing.
 * @retval FSP_ERR_CRYPTO_RSIP_FATAL             Software corruption is detected.
 **********************************************************************************************************************/
fsp_err_t r_rsip_random_number_generate (rsip_ctrl_t * const p_ctrl, uint8_t * const p_random)
{
    rsip_instance_ctrl_t * p_instance_ctrl = (rsip_instance_ctrl_t *) p_ctrl;

    /* Check state */
    FSP_ERROR_RETURN(r_rsip_state_check_init(p_instance_ctrl), FSP_ERR_INVALID_STATE);

    /* Call primitive (cast to match the argument type with the primitive function) */
    rsip_ret_t rsip_ret = gp_func_random_number_generate((uint32_t *) p_random);

    /* Check error */
    fsp_err_t err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_FATAL;
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

/***********************************************************************************************************************
 * Private Functions
 **********************************************************************************************************************/
