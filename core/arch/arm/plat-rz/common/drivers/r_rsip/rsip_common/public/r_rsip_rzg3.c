// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2024, Renesas Electronics Corporation
 */

/***********************************************************************************************************************
 * Includes
 **********************************************************************************************************************/
#include "r_rsip_public.h"
#include "r_rsip_wrapper.h"
#include "r_rsip_otp.h"
#include "r_rsip_primitive.h"

/***********************************************************************************************************************
 * Macro definitions
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Typedef definitions
 **********************************************************************************************************************/

/* Key import with UFPK */
typedef rsip_ret_t (* rsip_func_key_import_with_ufpk_t)(const uint32_t InData_SharedKeyNum[],
                                                        const uint32_t InData_SharedKeyIndex[],
                                                        const uint32_t InData_SessionKey[], const uint32_t InData_IV[],
                                                        const uint32_t InData_InstData[], uint32_t OutData_KeyIndex[]);

/***********************************************************************************************************************
 * Private function prototypes
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Private global variables
 **********************************************************************************************************************/

#if RSIP_CFG_PARAM_CHECKING_ENABLE
static const rsip_key_type_bool_table_t gs_key_import_with_ufpk_supported_algs =
{
    [RSIP_KEY_TYPE_AES_128]                     = true,
    [RSIP_KEY_TYPE_AES_256]                     = true,
    [RSIP_KEY_TYPE_AES_128_XTS]                 = true,
    [RSIP_KEY_TYPE_AES_256_XTS]                 = true,
    [RSIP_KEY_TYPE_ECC_secp192r1_PUBLIC]        = true,
    [RSIP_KEY_TYPE_ECC_secp192r1_PRIVATE]       = true,
    [RSIP_KEY_TYPE_ECC_secp224r1_PUBLIC]        = true,
    [RSIP_KEY_TYPE_ECC_secp224r1_PRIVATE]       = true,
    [RSIP_KEY_TYPE_ECC_secp256r1_PUBLIC]        = true,
    [RSIP_KEY_TYPE_ECC_secp256r1_PRIVATE]       = true,
    [RSIP_KEY_TYPE_ECC_BRAINPOOLP256R1_PUBLIC]  = true,
    [RSIP_KEY_TYPE_ECC_BRAINPOOLP256R1_PRIVATE] = true,
    [RSIP_KEY_TYPE_RSA_1024_PUBLIC_ENHANCED]    = true,
    [RSIP_KEY_TYPE_RSA_1024_PRIVATE_ENHANCED]   = true,
    [RSIP_KEY_TYPE_RSA_2048_PUBLIC_ENHANCED]    = true,
    [RSIP_KEY_TYPE_RSA_2048_PRIVATE_ENHANCED]   = true,
    [RSIP_KEY_TYPE_RSA_3072_PUBLIC]             = true,
    [RSIP_KEY_TYPE_RSA_3072_PRIVATE]            = true,
    [RSIP_KEY_TYPE_RSA_4096_PUBLIC]             = true,
    [RSIP_KEY_TYPE_RSA_4096_PRIVATE]            = true,
    [RSIP_KEY_TYPE_HMAC_SHA1]                   = true,
    [RSIP_KEY_TYPE_HMAC_SHA224]                 = true,
    [RSIP_KEY_TYPE_HMAC_SHA256]                 = true,
    [RSIP_KEY_TYPE_KEY_UPDATE_KEY]              = true,
    [RSIP_KEY_TYPE_SECURE_BOOT_DECRYPTION]      = true
};
#endif

static const rsip_func_key_import_with_ufpk_t gsp_func_key_import_with_ufpk[] =
{
#if RSIP_CFG_KEY_IMPORT_WITH_UFPK_AES_128_ENABLE
    [RSIP_KEY_TYPE_AES_128] = r_rsip_p10,
#else
    [RSIP_KEY_TYPE_AES_128] = NULL,
#endif
#if RSIP_CFG_KEY_IMPORT_WITH_UFPK_AES_256_ENABLE
    [RSIP_KEY_TYPE_AES_256] = r_rsip_p04,
#else
    [RSIP_KEY_TYPE_AES_256] = NULL,
#endif
#if RSIP_CFG_KEY_IMPORT_WITH_UFPK_AES_128_XTS_ENABLE
    [RSIP_KEY_TYPE_AES_128_XTS] = r_rsip_p18,
#else
    [RSIP_KEY_TYPE_AES_128_XTS] = NULL,
#endif
#if RSIP_CFG_KEY_IMPORT_WITH_UFPK_AES_256_XTS_ENABLE
    [RSIP_KEY_TYPE_AES_256_XTS] = r_rsip_p1a,
#else
    [RSIP_KEY_TYPE_AES_256_XTS] = NULL,
#endif
#if RSIP_CFG_KEY_IMPORT_WITH_UFPK_ECC_secp192r1_PUBLIC_ENABLE
    [RSIP_KEY_TYPE_ECC_secp192r1_PUBLIC] = r_rsip_wrapper_pfa_secp192r1,
#else
    [RSIP_KEY_TYPE_ECC_secp192r1_PUBLIC] = NULL,
#endif
#if RSIP_CFG_KEY_IMPORT_WITH_UFPK_ECC_secp192r1_PRIVATE_ENABLE
    [RSIP_KEY_TYPE_ECC_secp192r1_PRIVATE] = r_rsip_wrapper_pf3_secp192r1,
#else
    [RSIP_KEY_TYPE_ECC_secp192r1_PRIVATE] = NULL,
#endif
#if RSIP_CFG_KEY_IMPORT_WITH_UFPK_ECC_secp224r1_PUBLIC_ENABLE
    [RSIP_KEY_TYPE_ECC_secp224r1_PUBLIC] = r_rsip_wrapper_pfa_secp224r1,
#else
    [RSIP_KEY_TYPE_ECC_secp224r1_PUBLIC] = NULL,
#endif
#if RSIP_CFG_KEY_IMPORT_WITH_UFPK_ECC_secp224r1_PRIVATE_ENABLE
    [RSIP_KEY_TYPE_ECC_secp224r1_PRIVATE] = r_rsip_wrapper_pf3_secp224r1,
#else
    [RSIP_KEY_TYPE_ECC_secp224r1_PRIVATE] = NULL,
#endif
#if RSIP_CFG_KEY_IMPORT_WITH_UFPK_ECC_secp256r1_PUBLIC_ENABLE
    [RSIP_KEY_TYPE_ECC_secp256r1_PUBLIC] = r_rsip_wrapper_pfa_secp256r1,
#else
    [RSIP_KEY_TYPE_ECC_secp256r1_PUBLIC] = NULL,
#endif
#if RSIP_CFG_KEY_IMPORT_WITH_UFPK_ECC_secp256r1_PRIVATE_ENABLE
    [RSIP_KEY_TYPE_ECC_secp256r1_PRIVATE] = r_rsip_wrapper_pf3_secp256r1,
#else
    [RSIP_KEY_TYPE_ECC_secp256r1_PRIVATE] = NULL,
#endif
#if RSIP_CFG_KEY_IMPORT_WITH_UFPK_ECC_BRAINPOOLP256R1_PUBLIC_ENABLE
    [RSIP_KEY_TYPE_ECC_BRAINPOOLP256R1_PUBLIC] = r_rsip_wrapper_pfa_brainpoolp256r1,
#else
    [RSIP_KEY_TYPE_ECC_BRAINPOOLP256R1_PUBLIC] = NULL,
#endif
#if RSIP_CFG_KEY_IMPORT_WITH_UFPK_ECC_BRAINPOOLP256R1_PRIVATE_ENABLE
    [RSIP_KEY_TYPE_ECC_BRAINPOOLP256R1_PRIVATE] = r_rsip_wrapper_pf3_brainpoolp256r1,
#else
    [RSIP_KEY_TYPE_ECC_BRAINPOOLP256R1_PRIVATE] = NULL,
#endif
#if RSIP_CFG_KEY_IMPORT_WITH_UFPK_RSA_1024_PUBLIC_ENHANCED_ENABLE
    [RSIP_KEY_TYPE_RSA_1024_PUBLIC_ENHANCED] = r_rsip_p59,
#else
    [RSIP_KEY_TYPE_RSA_1024_PUBLIC_ENHANCED] = NULL,
#endif
#if RSIP_CFG_KEY_IMPORT_WITH_UFPK_RSA_1024_PRIVATE_ENHANCED_ENABLE
    [RSIP_KEY_TYPE_RSA_1024_PRIVATE_ENHANCED] = r_rsip_p60,
#else
    [RSIP_KEY_TYPE_RSA_1024_PRIVATE_ENHANCED] = NULL,
#endif
#if RSIP_CFG_KEY_IMPORT_WITH_UFPK_RSA_2048_PUBLIC_ENHANCED_ENABLE
    [RSIP_KEY_TYPE_RSA_2048_PUBLIC_ENHANCED] = r_rsip_p62,
#else
    [RSIP_KEY_TYPE_RSA_2048_PUBLIC_ENHANCED] = NULL,
#endif
#if RSIP_CFG_KEY_IMPORT_WITH_UFPK_RSA_2048_PRIVATE_ENHANCED_ENABLE
    [RSIP_KEY_TYPE_RSA_2048_PRIVATE_ENHANCED] = r_rsip_p63,
#else
    [RSIP_KEY_TYPE_RSA_2048_PRIVATE_ENHANCED] = NULL,
#endif
#if RSIP_CFG_KEY_IMPORT_WITH_UFPK_RSA_3072_PUBLIC_ENABLE
    [RSIP_KEY_TYPE_RSA_3072_PUBLIC] = r_rsip_p37,
#else
    [RSIP_KEY_TYPE_RSA_3072_PUBLIC] = NULL,
#endif
#if RSIP_CFG_KEY_IMPORT_WITH_UFPK_RSA_3072_PRIVATE_ENABLE
    [RSIP_KEY_TYPE_RSA_3072_PRIVATE] = r_rsip_p42,
#else
    [RSIP_KEY_TYPE_RSA_3072_PRIVATE] = NULL,
#endif
#if RSIP_CFG_KEY_IMPORT_WITH_UFPK_RSA_4096_PUBLIC_ENABLE
    [RSIP_KEY_TYPE_RSA_4096_PUBLIC] = r_rsip_p43,
#else
    [RSIP_KEY_TYPE_RSA_4096_PUBLIC] = NULL,
#endif
#if RSIP_CFG_KEY_IMPORT_WITH_UFPK_RSA_4096_PRIVATE_ENABLE
    [RSIP_KEY_TYPE_RSA_4096_PRIVATE] = r_rsip_p45,
#else
    [RSIP_KEY_TYPE_RSA_4096_PRIVATE] = NULL,
#endif
#if RSIP_CFG_KEY_IMPORT_WITH_UFPK_HMAC_SHA_ENABLE
    [RSIP_KEY_TYPE_HMAC_SHA1]   = r_rsip_wrapper_p80_hmac_sha1,
    [RSIP_KEY_TYPE_HMAC_SHA224] = r_rsip_wrapper_p80_hmac_sha224,
    [RSIP_KEY_TYPE_HMAC_SHA256] = r_rsip_wrapper_p80_hmac_sha256,
#else
    [RSIP_KEY_TYPE_HMAC_SHA1]   = NULL,
    [RSIP_KEY_TYPE_HMAC_SHA224] = NULL,
    [RSIP_KEY_TYPE_HMAC_SHA256] = NULL,
#endif
#if RSIP_CFG_KEY_IMPORT_WITH_UFPK_KUK_ENABLE
    [RSIP_KEY_TYPE_KEY_UPDATE_KEY] = r_rsip_p1f,
#else
    [RSIP_KEY_TYPE_KEY_UPDATE_KEY] = NULL,
#endif
#if RSIP_CFG_KEY_IMPORT_WITH_UFPK_SECURE_BOOT_DECRYPTION_ENABLE
    [RSIP_KEY_TYPE_SECURE_BOOT_DECRYPTION] = r_rsip_p03,
#else
    [RSIP_KEY_TYPE_SECURE_BOOT_DECRYPTION] = NULL,
#endif
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
 * Imports a user key with UFPK (User Factory Programming Key) within the user routine.
 *
 * @param[in,out] p_ctrl                                 Pointer to control block.
 * @param[in]     p_wrapped_user_factory_programming_key Wrapped User Factory Programming Key (W-UFPK).
 *                                                       The length is 32 bytes.
 * @param[in]     p_initial_vector                       Initialization vector when generating encrypted_key.
 *                                                       The length is 16 bytes.
 * @param[in]     key_type                               Inputs/Outputs key type.
 * @param[in]     p_encrypted_key                        Encrypted user key. The length depends on the key type.
 * @param[out]    p_wrapped_key                          Pointer to destination of wrapped key.
 *                                                       The length depends on the key type.
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_ASSERTION                     A required parameter is NULL.
 * @retval FSP_ERR_NOT_OPEN                      Module is not open.
 * @retval FSP_ERR_INVALID_STATE                 Internal state is illegal.
 * @retval FSP_ERR_NOT_ENABLED                   Input key type is disabled in this function by configuration.
 * @retval FSP_ERR_UNSUPPORTED                   Input key type is unsupported.
 * @retval FSP_ERR_CRYPTO_RSIP_FAIL              Input parameter is invalid.
 *
 * @retval FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource required
 *                                               by the processing is in use by other processing.
 * @retval FSP_ERR_CRYPTO_RSIP_FATAL             Software corruption is detected.
 *
 * @sa Section @ref r-rsip-key-management "Key Management"
 **********************************************************************************************************************/
fsp_err_t R_RSIP_KeyImportWithUFPK (rsip_ctrl_t * const        p_ctrl,
                                    uint8_t const * const      p_wrapped_user_factory_programming_key,
                                    uint8_t const * const      p_initial_vector,
                                    rsip_key_type_t const      key_type,
                                    uint8_t const * const      p_encrypted_key,
                                    rsip_wrapped_key_t * const p_wrapped_key)
{
    rsip_instance_ctrl_t * p_instance_ctrl = (rsip_instance_ctrl_t *) p_ctrl;

    /* Set primitive */
    rsip_func_key_import_with_ufpk_t p_primitive = gsp_func_key_import_with_ufpk[key_type];

#if RSIP_CFG_PARAM_CHECKING_ENABLE
    FSP_ASSERT(p_instance_ctrl);
    FSP_ASSERT(p_wrapped_user_factory_programming_key);
    FSP_ASSERT(p_initial_vector);
    FSP_ASSERT(p_encrypted_key);
    FSP_ASSERT(p_wrapped_key);
    FSP_ERROR_RETURN(RSIP_OPEN == p_instance_ctrl->open, FSP_ERR_NOT_OPEN);

    /* Check key type */
    FSP_ERROR_RETURN(gs_key_import_with_ufpk_supported_algs[key_type], FSP_ERR_UNSUPPORTED);

    /* Check if the key type is enabled on configuration */
    FSP_ERROR_RETURN(p_primitive, FSP_ERR_NOT_ENABLED);
#endif

    /* Check state */
    FSP_ERROR_RETURN(r_rsip_state_check_init(p_instance_ctrl), FSP_ERR_INVALID_STATE);
    /* Read W-HRK from S_FLASH */
    uint32_t whrk_num[RSIP_PRV_WORD_SIZE_WRAPPED_HARDWARE_ROOT_KEY_NUM];
    uint32_t whrk[RSIP_PRV_WORD_SIZE_WRAPPED_HARDWARE_ROOT_KEY];

    memcpy(whrk_num, p_wrapped_user_factory_programming_key, sizeof(whrk_num));
    rsip_ret_t rsip_ret = r_rsip_whrk_read(whrk_num, whrk);

    if (RSIP_RET_PASS == rsip_ret)
    {
        /* Call primitive (cast to match the argument type with the primitive function) */
        rsip_ret =
            p_primitive((uint32_t const *) whrk_num,
                        (uint32_t const *) whrk,
                        (uint32_t const *) &p_wrapped_user_factory_programming_key[sizeof(whrk_num)],
                        (uint32_t const *) p_initial_vector,
                        (uint32_t const *) p_encrypted_key,
                        (uint32_t *) p_wrapped_key->value);
    }

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
 * @} (end addtogroup RSIP)
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Private Functions
 **********************************************************************************************************************/
