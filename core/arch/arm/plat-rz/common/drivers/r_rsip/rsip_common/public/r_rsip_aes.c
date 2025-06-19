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

static fsp_err_t aes_init(rsip_ctrl_t              * p_ctrl,
                          rsip_aes_mode_t            mode,
                          const rsip_wrapped_key_t * p_wrapped_key,
                          const uint8_t            * p_initial_vector,
                          rsip_handle_type_t         handle_type);
static fsp_err_t aes_update(rsip_ctrl_t      * p_ctrl,
                            const uint8_t    * p_input,
                            uint8_t          * p_output,
                            uint32_t           input_length,
                            rsip_handle_type_t handle_type);
static fsp_err_t aes_final(rsip_ctrl_t * p_ctrl, rsip_handle_type_t handle_type);

static fsp_err_t xts_init(rsip_ctrl_t              * p_ctrl,
                          const rsip_wrapped_key_t * p_wrapped_key,
                          const uint8_t            * p_initial_vector,
                          rsip_handle_type_t         handle_type);
static fsp_err_t xts_update(rsip_ctrl_t      * p_ctrl,
                            const uint8_t    * p_input,
                            uint8_t          * p_output,
                            uint32_t           input_length,
                            rsip_handle_type_t handle_type);
static fsp_err_t xts_final(rsip_ctrl_t      * p_ctrl,
                           uint8_t          * p_output,
                           uint32_t         * p_output_length,
                           rsip_handle_type_t handle_type);

static fsp_err_t gcm_init(rsip_ctrl_t              * p_ctrl,
                          const rsip_wrapped_key_t * p_wrapped_key,
                          const uint8_t            * p_initial_vector,
                          uint32_t                   initial_vector_length,
                          rsip_handle_type_t         handle_type);
static fsp_err_t gcm_update(rsip_ctrl_t      * p_ctrl,
                            const uint8_t    * p_input,
                            uint8_t          * p_output,
                            uint32_t           input_length,
                            const uint8_t    * p_aad,
                            uint32_t           aad_length,
                            rsip_handle_type_t handle_type);
static fsp_err_t gcm_iv_prepare(rsip_instance_ctrl_t     * p_instance_ctrl,
                                const uint8_t            * p_initial_vector,
                                uint32_t                   initial_vector_length,
                                const rsip_wrapped_key_t * p_wrapped_key,
                                uint32_t                 * p_hashed_ivec);
static void gcm_aad_input_terminate(rsip_instance_ctrl_t * p_instance_ctrl);

static fsp_err_t cmac_init(rsip_ctrl_t              * p_ctrl,
                           const rsip_wrapped_key_t * p_wrapped_key,
                           rsip_handle_type_t         handle_type);
static fsp_err_t cmac_update(rsip_ctrl_t * const   p_ctrl,
                             uint8_t const * const p_message,
                             uint32_t const        message_length,
                             rsip_handle_type_t    handle_type);

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
 * Prepares an AES encryption.
 *
 * @param[in,out] p_ctrl           Pointer to control block.
 * @param[in]     mode             Block cipher modes of operation.
 * @param[in]     p_wrapped_key    Pointer to wrapped key of AES or AES-XTS key.
 * @param[in]     p_initial_vector Pointer to initialization vector (IV) or nonce. The length is 16 bytes.
 *                                 @arg [ECB] Not needed
 *                                 @arg [CBC] IV
 *                                 @arg [CTR] Nonce
 *                                 @arg [XTS] IV
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_ASSERTION                     A required parameter is NULL.
 * @retval FSP_ERR_NOT_OPEN                      Module is not open.
 * @retval FSP_ERR_INVALID_STATE                 Internal state is illegal.
 * @retval FSP_ERR_NOT_ENABLED                   Input key type is disabled in this function by configuration.
 * @retval FSP_ERR_INVALID_ARGUMENT              Input key type or mode is illegal.
 * @retval FSP_ERR_CRYPTO_RSIP_KEY_SET_FAIL      Input key value is illegal.
 *
 * @retval FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource required
 *                                               by the processing is in use by other processing.
 * @retval FSP_ERR_CRYPTO_RSIP_FATAL             Software corruption is detected.
 **********************************************************************************************************************/
fsp_err_t R_RSIP_AES_Cipher_EncryptInit (rsip_ctrl_t * const              p_ctrl,
                                         rsip_aes_mode_t const            mode,
                                         rsip_wrapped_key_t const * const p_wrapped_key,
                                         uint8_t const * const            p_initial_vector)
{
#if RSIP_CFG_PARAM_CHECKING_ENABLE
    rsip_instance_ctrl_t * p_instance_ctrl = (rsip_instance_ctrl_t *) p_ctrl;

    FSP_ASSERT(p_instance_ctrl);
    FSP_ERROR_RETURN(RSIP_OPEN == p_instance_ctrl->open, FSP_ERR_NOT_OPEN);
#endif

    fsp_err_t err = FSP_ERR_INVALID_ARGUMENT;
    switch (mode)
    {
        /* The same function is used if mode is ECB, CBC, or CTR */
        case RSIP_AES_MODE_ECB:
        case RSIP_AES_MODE_CBC:
        case RSIP_AES_MODE_CTR:
        {
            err = aes_init(p_ctrl, mode, p_wrapped_key, p_initial_vector, RSIP_HANDLE_TYPE_AES_ENCRYPT);
            break;
        }

        case RSIP_AES_MODE_XTS:
        {
            err = xts_init(p_ctrl, p_wrapped_key, p_initial_vector, RSIP_HANDLE_TYPE_XTS_ENCRYPT);
            break;
        }

        default:
        {
            /* Invalid argument */
        }
    }

    return err;
}

/*******************************************************************************************************************//**
 * Encrypts plaintext.
 *
 * @param[in,out] p_ctrl       Pointer to control block.
 * @param[in]     p_plain      Pointer to plaintext. The length is plain_length.
 * @param[out]    p_cipher     Pointer to destination of ciphertext.
 *                             @arg [ECB][CBC][CTR][XTS without fractional block]
 *                             The length is plain_length.
 *                             @arg [XTS with fractional block]
 *                             No outputs. The ciphertext output by R_RSIP_AES_Cipher_EncryptFinal().
 *                             After inputs fractional block, updates will not be possible.
 * @param[in]     plain_length Byte length of plaintext.
 *                             @arg [ECB][CBC][CTR][XTS without fractional block] Must be 0 or a multiple of 16.
 *                             @arg [XTS with fractional block] Must be 17 to 31.
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_ASSERTION                     A required parameter is NULL.
 * @retval FSP_ERR_NOT_OPEN                      Module is not open.
 * @retval FSP_ERR_INVALID_STATE                 Internal state is illegal.
 * @retval FSP_ERR_INVALID_SIZE                  Input length is illegal.
 **********************************************************************************************************************/
fsp_err_t R_RSIP_AES_Cipher_EncryptUpdate (rsip_ctrl_t * const   p_ctrl,
                                           uint8_t const * const p_plain,
                                           uint8_t * const       p_cipher,
                                           uint32_t const        plain_length)
{
    rsip_instance_ctrl_t * p_instance_ctrl = (rsip_instance_ctrl_t *) p_ctrl;

#if RSIP_CFG_PARAM_CHECKING_ENABLE
    FSP_ASSERT(p_instance_ctrl);
    FSP_ERROR_RETURN(RSIP_OPEN == p_instance_ctrl->open, FSP_ERR_NOT_OPEN);
#endif

    fsp_err_t err = FSP_ERR_INVALID_STATE;
    switch (p_instance_ctrl->handle_type)
    {
        case RSIP_HANDLE_TYPE_AES_ENCRYPT:
        {
            err = aes_update(p_ctrl, p_plain, p_cipher, plain_length, RSIP_HANDLE_TYPE_AES_ENCRYPT);
            break;
        }

        case RSIP_HANDLE_TYPE_XTS_ENCRYPT:
        {
            err = xts_update(p_ctrl, p_plain, p_cipher, plain_length, RSIP_HANDLE_TYPE_XTS_ENCRYPT);
            break;
        }

        default:
        {
            /* Invalid state */
        }
    }

    return err;
}

/*******************************************************************************************************************//**
 * Finalizes an AES encryption.
 *
 * @param[in,out] p_ctrl          Pointer to control block.
 * @param[out]    p_cipher        Pointer to destination of ciphertext.
 *                                @arg [ECB][CBC][CTR] No outputs.
 *                                @arg [XTS] Fractional block and the one before block are output.
 * @param[out]    p_cipher_length Pointer to destination of ciphertext length.
 *                                @arg [ECB][CBC][CTR] No outputs.
 *                                @arg [XTS] Output length is output.
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_ASSERTION                     A required parameter is NULL.
 * @retval FSP_ERR_NOT_OPEN                      Module is not open.
 * @retval FSP_ERR_INVALID_STATE                 Internal state is illegal.
 * @retval FSP_ERR_CRYPTO_RSIP_FAIL              Internal error.
 *
 * @retval FSP_ERR_CRYPTO_RSIP_FATAL             Software corruption is detected.
 **********************************************************************************************************************/
fsp_err_t R_RSIP_AES_Cipher_EncryptFinal (rsip_ctrl_t * const p_ctrl,
                                          uint8_t * const     p_cipher,
                                          uint32_t * const    p_cipher_length)
{
    rsip_instance_ctrl_t * p_instance_ctrl = (rsip_instance_ctrl_t *) p_ctrl;

#if RSIP_CFG_PARAM_CHECKING_ENABLE
    FSP_ASSERT(p_instance_ctrl);
    FSP_ERROR_RETURN(RSIP_OPEN == p_instance_ctrl->open, FSP_ERR_NOT_OPEN);
#endif

    fsp_err_t err = FSP_ERR_INVALID_STATE;
    switch (p_instance_ctrl->handle_type)
    {
        case RSIP_HANDLE_TYPE_AES_ENCRYPT:
        {
            err = aes_final(p_ctrl, RSIP_HANDLE_TYPE_AES_ENCRYPT);
            break;
        }

        case RSIP_HANDLE_TYPE_XTS_ENCRYPT:
        {
            err = xts_final(p_ctrl, p_cipher, p_cipher_length, RSIP_HANDLE_TYPE_XTS_ENCRYPT);
            break;
        }

        default:
        {
            /* Invalid state */
        }
    }

    return err;
}

/*******************************************************************************************************************//**
 * Prepares an AES decryption.
 *
 * @param[in,out] p_ctrl           Pointer to control block.
 * @param[in]     mode             Block cipher modes of operation.
 * @param[in]     p_wrapped_key    Pointer to wrapped key of AES or AES-XTS key.
 * @param[in]     p_initial_vector Pointer to initialization vector (IV) or nonce. The length is 16 bytes.
 *                                 @arg [ECB] Not needed
 *                                 @arg [CBC] IV
 *                                 @arg [CTR] Nonce
 *                                 @arg [XTS] IV
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_ASSERTION                     A required parameter is NULL.
 * @retval FSP_ERR_NOT_OPEN                      Module is not open.
 * @retval FSP_ERR_INVALID_STATE                 Internal state is illegal.
 * @retval FSP_ERR_NOT_ENABLED                   Input key type is disabled in this function by configuration.
 * @retval FSP_ERR_INVALID_ARGUMENT              Input key type or mode is illegal.
 * @retval FSP_ERR_CRYPTO_RSIP_KEY_SET_FAIL      Input key value is illegal.
 *
 * @retval FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource required
 *                                               by the processing is in use by other processing.
 * @retval FSP_ERR_CRYPTO_RSIP_FATAL             Software corruption is detected.
 **********************************************************************************************************************/
fsp_err_t R_RSIP_AES_Cipher_DecryptInit (rsip_ctrl_t * const              p_ctrl,
                                         rsip_aes_mode_t const            mode,
                                         rsip_wrapped_key_t const * const p_wrapped_key,
                                         uint8_t const * const            p_initial_vector)
{
#if RSIP_CFG_PARAM_CHECKING_ENABLE
    rsip_instance_ctrl_t * p_instance_ctrl = (rsip_instance_ctrl_t *) p_ctrl;

    FSP_ASSERT(p_instance_ctrl);
    FSP_ERROR_RETURN(RSIP_OPEN == p_instance_ctrl->open, FSP_ERR_NOT_OPEN);
#endif

    fsp_err_t err = FSP_ERR_INVALID_ARGUMENT;
    switch (mode)
    {
        /* The same function is used if mode is ECB, CBC, or CTR */
        case RSIP_AES_MODE_ECB:
        case RSIP_AES_MODE_CBC:
        case RSIP_AES_MODE_CTR:
        {
            err = aes_init(p_ctrl, mode, p_wrapped_key, p_initial_vector, RSIP_HANDLE_TYPE_AES_DECRYPT);
            break;
        }

        case RSIP_AES_MODE_XTS:
        {
            err = xts_init(p_ctrl, p_wrapped_key, p_initial_vector, RSIP_HANDLE_TYPE_XTS_DECRYPT);
            break;
        }

        default:
        {
            /* Invalid argument */
        }
    }

    return err;
}

/*******************************************************************************************************************//**
 * Decrypts ciphertext.
 *
 * @param[in,out] p_ctrl        Pointer to control block.
 * @param[in]     p_cipher      Pointer to ciphertext. The length is cipher_length.
 * @param[out]    p_plain       Pointer to destination of plaintext.
 *                              @arg [ECB][CBC][CTR][XTS without fractional block]
 *                              The length is cipher_length.
 *                              @arg [XTS with fractional block]
 *                              No outputs. The plaintext is output by R_RSIP_AES_Cipher_DecryptFinal().
 *                              After inputs fractional block, updates will not be possible.
 * @param[in]     cipher_length Byte length of ciphertext.
 *                              @arg [ECB][CBC][CTR][XTS without fractional block] Must be 0 or a multiple of 16.
 *                              @arg [XTS with fractional block] Must be 17 to 31.
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_ASSERTION                     A required parameter is NULL.
 * @retval FSP_ERR_NOT_OPEN                      Module is not open.
 * @retval FSP_ERR_INVALID_STATE                 Internal state is illegal.
 * @retval FSP_ERR_INVALID_SIZE                  Input length is illegal.
 **********************************************************************************************************************/
fsp_err_t R_RSIP_AES_Cipher_DecryptUpdate (rsip_ctrl_t * const   p_ctrl,
                                           uint8_t const * const p_cipher,
                                           uint8_t * const       p_plain,
                                           uint32_t const        cipher_length)
{
    rsip_instance_ctrl_t * p_instance_ctrl = (rsip_instance_ctrl_t *) p_ctrl;

#if RSIP_CFG_PARAM_CHECKING_ENABLE
    FSP_ASSERT(p_instance_ctrl);
    FSP_ERROR_RETURN(RSIP_OPEN == p_instance_ctrl->open, FSP_ERR_NOT_OPEN);
#endif

    fsp_err_t err = FSP_ERR_INVALID_STATE;
    switch (p_instance_ctrl->handle_type)
    {
        case RSIP_HANDLE_TYPE_AES_DECRYPT:
        {
            err = aes_update(p_ctrl, p_cipher, p_plain, cipher_length, RSIP_HANDLE_TYPE_AES_DECRYPT);
            break;
        }

        case RSIP_HANDLE_TYPE_XTS_DECRYPT:
        {
            err = xts_update(p_ctrl, p_cipher, p_plain, cipher_length, RSIP_HANDLE_TYPE_XTS_DECRYPT);
            break;
        }

        default:
        {
            /* Invalid state */
        }
    }

    return err;
}

/*******************************************************************************************************************//**
 * Finalizes an AES decryption.
 *
 * @param[in,out] p_ctrl         Pointer to control block.
 * @param[out]    p_plain        Pointer to destination of plaintext.
 *                               @arg [ECB][CBC][CTR] No outputs.
 *                               @arg [XTS] Fractional block and the one before block are output.
 * @param[out]    p_plain_length Pointer to destination of plaintext length.
 *                               @arg [ECB][CBC][CTR] No outputs.
 *                               @arg [XTS] Output length is output.
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_ASSERTION                     A required parameter is NULL.
 * @retval FSP_ERR_NOT_OPEN                      Module is not open.
 * @retval FSP_ERR_INVALID_STATE                 Internal state is illegal.
 * @retval FSP_ERR_CRYPTO_RSIP_FAIL              Internal error.
 *
 * @retval FSP_ERR_CRYPTO_RSIP_FATAL             Software corruption is detected.
 **********************************************************************************************************************/
fsp_err_t R_RSIP_AES_Cipher_DecryptFinal (rsip_ctrl_t * const p_ctrl,
                                          uint8_t * const     p_plain,
                                          uint32_t * const    p_plain_length)
{
    rsip_instance_ctrl_t * p_instance_ctrl = (rsip_instance_ctrl_t *) p_ctrl;

#if RSIP_CFG_PARAM_CHECKING_ENABLE
    FSP_ASSERT(p_instance_ctrl);
    FSP_ERROR_RETURN(RSIP_OPEN == p_instance_ctrl->open, FSP_ERR_NOT_OPEN);
#endif

    fsp_err_t err = FSP_ERR_INVALID_STATE;
    switch (p_instance_ctrl->handle_type)
    {
        case RSIP_HANDLE_TYPE_AES_DECRYPT:
        {
            err = aes_final(p_ctrl, RSIP_HANDLE_TYPE_AES_DECRYPT);
            break;
        }

        case RSIP_HANDLE_TYPE_XTS_DECRYPT:
        {
            err = xts_final(p_ctrl, p_plain, p_plain_length, RSIP_HANDLE_TYPE_XTS_DECRYPT);
            break;
        }

        default:
        {
            /* Invalid state */
        }
    }

    return err;
}

/*******************************************************************************************************************//**
 * Prepares an AES-GCM encryption.
 *
 * @param[in,out] p_ctrl        Pointer to control block.
 * @param[in]     p_wrapped_key Pointer to wrapped key of AES key.
 * @param[in]     p_nonce       Pointer to nonce. The length is nonce_length.
 * @param[in]     nonce_length  Byte length of nonce. Input 1 or more.
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
fsp_err_t R_RSIP_AES_GCM_EncryptInit (rsip_ctrl_t * const              p_ctrl,
                                      rsip_wrapped_key_t const * const p_wrapped_key,
                                      uint8_t const * const            p_nonce,
                                      uint32_t const                   nonce_length)
{
    return gcm_init(p_ctrl, p_wrapped_key, p_nonce, nonce_length, RSIP_HANDLE_TYPE_GCM_ENCRYPT);
}

/*******************************************************************************************************************//**
 * Inputs aad and encrypts plaintext.
 *
 * First process the data that is input from p_aad, and then process the data that is input from p_plain.
 * If p_aad data is input after starting to input p_plain data, an error will occur. If p_aad data and p_plain data
 * are input to this function at the same time, the p_aad data will be processed,
 * and then the function will transition to the p_plain data input state.
 *
 * Inside this function, the data that is input by the user is buffered until the input values of p_aad and p_plain
 * exceed 16 bytes.
 * After the input data from p_plain reaches 16 bytes or more, the encryption result is output to p_cipher.
 * If the input values p_plain and p_aad are not divisible by 16 bytes, they will be padded inside the function.
 *
 * @param[in,out] p_ctrl       Pointer to control block.
 * @param[in]     p_plain      Pointer to ciphertext. The length is plain_length.
 * @param[out]    p_cipher     Pointer to destination of ciphertext.
 * @param[in]     plain_length Byte length of plaintext (0 or more bytes).
 * @param[in]     p_aad        Additional authentication data. The length depends on aad_length.
 * @param[in]     aad_length   Byte length of additional authentication data (0 or more bytes).
 *                             After starting input of plaintext, this value must always be 0.
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_ASSERTION                     A required parameter is NULL.
 * @retval FSP_ERR_NOT_OPEN                      Module is not open.
 * @retval FSP_ERR_INVALID_STATE                 Internal state is illegal.
 * @retval FSP_ERR_INVALID_SIZE                  Input length is illegal.
 **********************************************************************************************************************/
fsp_err_t R_RSIP_AES_GCM_EncryptUpdate (rsip_ctrl_t * const   p_ctrl,
                                        uint8_t const * const p_plain,
                                        uint8_t * const       p_cipher,
                                        uint32_t const        plain_length,
                                        uint8_t const * const p_aad,
                                        uint32_t const        aad_length)
{
    return gcm_update(p_ctrl, p_plain, p_cipher, plain_length, p_aad, aad_length, RSIP_HANDLE_TYPE_GCM_ENCRYPT);
}

/*******************************************************************************************************************//**
 * Finalizes an AES-GCM encryption.
 *
 * If there is 16-byte fractional data indicated by the total data length of the value of p_plain that was input by
 * R_RSIP_AES_GCM_EncryptUpdate(), this API will output the result of encrypting that fractional data to p_cipher.
 * Here, the portion that does not reach 16 bytes will be padded with zeros.
 *
 * @param[in,out] p_ctrl          Pointer to control block.
 * @param[out]    p_cipher        Pointer to destination of ciphertext. The fractional block is output.
 * @param[out]    p_cipher_length Pointer to destination of ciphertext length.
 * @param[out]    p_tag           Pointer to destination of tag for authentication. The length is 16 bytes.
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_ASSERTION                     A required parameter is NULL.
 * @retval FSP_ERR_NOT_OPEN                      Module is not open.
 * @retval FSP_ERR_INVALID_STATE                 Internal state is illegal.
 * @retval FSP_ERR_CRYPTO_RSIP_FAIL              Internal error.
 *
 * @retval FSP_ERR_CRYPTO_RSIP_FATAL             Software corruption is detected.
 **********************************************************************************************************************/
fsp_err_t R_RSIP_AES_GCM_EncryptFinal (rsip_ctrl_t * const p_ctrl,
                                       uint8_t * const     p_cipher,
                                       uint32_t * const    p_cipher_length,
                                       uint8_t * const     p_tag)
{
    rsip_instance_ctrl_t   * p_instance_ctrl = (rsip_instance_ctrl_t *) p_ctrl;
    rsip_func_subset_gcm_t * p_primitive     = ((rsip_func_subset_gcm_t *) (p_instance_ctrl->handle.gcm.p_primitive));
    rsip_handle_type_t       handle_type     = RSIP_HANDLE_TYPE_GCM_ENCRYPT;

#if RSIP_CFG_PARAM_CHECKING_ENABLE
    FSP_ASSERT(p_instance_ctrl);
    FSP_ASSERT(p_cipher);
    FSP_ASSERT(p_cipher_length);
    FSP_ASSERT(p_tag);
    FSP_ERROR_RETURN(RSIP_OPEN == p_instance_ctrl->open, FSP_ERR_NOT_OPEN);
#endif

    /* Check state */
    FSP_ERROR_RETURN(r_rsip_state_check_final(p_instance_ctrl, handle_type), FSP_ERR_INVALID_STATE);

    uint32_t aad_bit_size[2] =
    {
        0
    };
    uint32_t data_bit_size[2] =
    {
        0
    };

    /* If unprocessed AAD still exists in buffer, input it */
    if (!p_instance_ctrl->handle.gcm.has_finished_aad_input)
    {
        gcm_aad_input_terminate(p_instance_ctrl);
    }

    /* Set remaining data */
    if ((0 != (p_instance_ctrl->handle.gcm.total_length % RSIP_BYTE_SIZE_AES_BLOCK)) ||
        (0 == p_instance_ctrl->handle.gcm.total_length))
    {
        memset(p_instance_ctrl->handle.gcm.buffer + p_instance_ctrl->handle.gcm.buffered_length, 0,
               (RSIP_BYTE_SIZE_AES_BLOCK - p_instance_ctrl->handle.gcm.buffered_length));
    }

    /* Set parameters */
    aad_bit_size[0] =
        bswap_32big(r_rsip_byte_to_bit_convert_upper(p_instance_ctrl->handle.gcm.total_aad_length));
    aad_bit_size[1] =
        bswap_32big(r_rsip_byte_to_bit_convert_lower(p_instance_ctrl->handle.gcm.total_aad_length));
    data_bit_size[0] =
        bswap_32big((r_rsip_byte_to_bit_convert_upper(p_instance_ctrl->handle.gcm.total_length)));
    data_bit_size[1] = bswap_32big(r_rsip_byte_to_bit_convert_lower(p_instance_ctrl->handle.gcm.total_length));
    *p_cipher_length = p_instance_ctrl->handle.gcm.total_length;

    /* Call primitive (cast to match the argument type with the primitive function) */
    rsip_ret_t rsip_ret = p_primitive->p_encryptFinal((uint32_t *) (p_instance_ctrl->handle.gcm.buffer),
                                                      aad_bit_size,
                                                      data_bit_size,
                                                      (uint32_t *) p_cipher,
                                                      (uint32_t *) p_tag);

    /* Reset handle */
    r_rsip_handle_reset(&p_instance_ctrl->handle);

    /* State transition*/
    r_rsip_state_transit_init(p_instance_ctrl);

    /* Check error */
    fsp_err_t err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_FATAL;
    switch (rsip_ret)
    {
        case RSIP_RET_PASS:
        {
            err = FSP_SUCCESS;
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
 * Prepares an AES-GCM decryption.
 *
 * @param[in,out] p_ctrl        Pointer to control block.
 * @param[in]     p_wrapped_key Pointer to wrapped key of AES key.
 * @param[in]     p_nonce       Pointer to nonce. The length is nonce_length.
 * @param[in]     nonce_length  Byte length of nonce. Input 1 or more.
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
fsp_err_t R_RSIP_AES_GCM_DecryptInit (rsip_ctrl_t * const              p_ctrl,
                                      rsip_wrapped_key_t const * const p_wrapped_key,
                                      uint8_t const * const            p_nonce,
                                      uint32_t const                   nonce_length)
{
    return gcm_init(p_ctrl, p_wrapped_key, p_nonce, nonce_length, RSIP_HANDLE_TYPE_GCM_DECRYPT);
}

/*******************************************************************************************************************//**
 * Inputs aad and decrypts ciphertext.
 *
 * First process the data that is input from p_aad, and then process the data that is input from p_cipher.
 * If p_aad data is input after starting to input p_cipher data, an error will occur. If p_aad data and p_cipher data
 * are input to this function at the same time, the p_aad data will be processed,
 * and then the function will transition to the p_cipher data input state.
 *
 * Inside this function, the data that is input by the user is buffered until the input values of p_aad and p_cipher
 * exceed 16 bytes.
 * After the input data from p_cipher reaches 16 bytes or more, the decryption result is output to p_cipher.
 * If the input values p_cipher and p_aad are not divisible by 16 bytes, they will be padded inside the function.
 *
 * @param[in,out] p_ctrl        Pointer to control block.
 * @param[in]     p_cipher      Pointer to ciphertext. The length is cipher_length.
 * @param[out]    p_plain       Pointer to destination of plaintext.
 * @param[in]     cipher_length Byte length of ciphertext (0 or more bytes).
 * @param[in]     p_aad         Additional authentication data. The length depends on aad_length.
 * @param[in]     aad_length    Byte length of additional authentication data (0 or more bytes).
 *                              After starting input of ciphertext, this value must always be 0.
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_ASSERTION                     A required parameter is NULL.
 * @retval FSP_ERR_NOT_OPEN                      Module is not open.
 * @retval FSP_ERR_INVALID_STATE                 Internal state is illegal.
 * @retval FSP_ERR_INVALID_SIZE                  Input length is illegal.
 **********************************************************************************************************************/
fsp_err_t R_RSIP_AES_GCM_DecryptUpdate (rsip_ctrl_t * const   p_ctrl,
                                        uint8_t const * const p_cipher,
                                        uint8_t * const       p_plain,
                                        uint32_t const        cipher_length,
                                        uint8_t const * const p_aad,
                                        uint32_t const        aad_length)
{
    return gcm_update(p_ctrl, p_cipher, p_plain, cipher_length, p_aad, aad_length, RSIP_HANDLE_TYPE_GCM_DECRYPT);
}

/*******************************************************************************************************************//**
 * Finalizes an AES-GCM decryption.
 *
 * If there is 16-byte fractional data indicated by the total data length of the value of p_cipher that was input by
 * R_RSIP_AES_GCM_DecryptUpdate(), this API will output the result of decrypting that fractional data to p_cipher.
 * Here, the portion that does not reach 16 bytes will be padded with zeros.
 *
 * @param[in,out] p_ctrl         Pointer to control block.
 * @param[out]    p_plain        Pointer to destination of plaintext. The fractional block is output.
 * @param[out]    p_plain_length Pointer to destination of plaintext length.
 * @param[in]     p_tag          Pointer to tag for authentication. The length depends on tag_length.
 * @param[in]     tag_length     Byte length of tag. Must be 1 to 16.
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_ASSERTION                     A required parameter is NULL.
 * @retval FSP_ERR_NOT_OPEN                      Module is not open.
 * @retval FSP_ERR_INVALID_STATE                 Internal state is illegal.
 * @retval FSP_ERR_INVALID_SIZE                  tag_length is illegal.
 * @retval FSP_ERR_CRYPTO_RSIP_FAIL              Internal error.
 * @retval FSP_ERR_CRYPTO_RSIP_AUTHENTICATION    Authentication is failed.
 *
 * @retval FSP_ERR_CRYPTO_RSIP_FATAL             Software corruption is detected.
 **********************************************************************************************************************/
fsp_err_t R_RSIP_AES_GCM_DecryptFinal (rsip_ctrl_t * const   p_ctrl,
                                       uint8_t * const       p_plain,
                                       uint32_t * const      p_plain_length,
                                       uint8_t const * const p_tag,
                                       uint32_t const        tag_length)
{
    rsip_instance_ctrl_t   * p_instance_ctrl = (rsip_instance_ctrl_t *) p_ctrl;
    rsip_func_subset_gcm_t * p_primitive     = ((rsip_func_subset_gcm_t *) (p_instance_ctrl->handle.gcm.p_primitive));
    rsip_handle_type_t       handle_type     = RSIP_HANDLE_TYPE_GCM_DECRYPT;

#if RSIP_CFG_PARAM_CHECKING_ENABLE
    FSP_ASSERT(p_instance_ctrl);
    FSP_ASSERT(p_plain);
    FSP_ASSERT(p_plain_length);
    FSP_ASSERT(p_tag);
    FSP_ERROR_RETURN(RSIP_OPEN == p_instance_ctrl->open, FSP_ERR_NOT_OPEN);
#endif

    /* tag_length must be from 1 to 16 */
    FSP_ERROR_RETURN((0 < tag_length) && (tag_length <= 16), FSP_ERR_INVALID_SIZE);

    /* Check state */
    FSP_ERROR_RETURN(r_rsip_state_check_final(p_instance_ctrl, handle_type), FSP_ERR_INVALID_STATE);

    uint32_t aad_bit_size[2] =
    {
        0
    };
    uint32_t data_bit_size[2] =
    {
        0
    };
    uint32_t tag_length_tmp[1] =
    {
        0
    };
    uint32_t tag_tmp[RSIP_BYTE_SIZE_AES_BLOCK / sizeof(uint32_t)] =
    {
        0
    };

    /* If unprocessed AAD still exists in buffer, input it */
    if (!p_instance_ctrl->handle.gcm.has_finished_aad_input)
    {
        gcm_aad_input_terminate(p_instance_ctrl);
    }

    /* Set remaining data */
    if ((0 != (p_instance_ctrl->handle.gcm.total_length % RSIP_BYTE_SIZE_AES_BLOCK)) ||
        (0 == p_instance_ctrl->handle.gcm.total_length))
    {
        memset(p_instance_ctrl->handle.gcm.buffer + p_instance_ctrl->handle.gcm.buffered_length, 0,
               (RSIP_BYTE_SIZE_AES_BLOCK - p_instance_ctrl->handle.gcm.buffered_length));
    }

    /* Copy tag */
    memcpy(tag_tmp, p_tag, tag_length);

    /* Set parameters */
    aad_bit_size[0] =
        bswap_32big(r_rsip_byte_to_bit_convert_upper(p_instance_ctrl->handle.gcm.total_aad_length));
    aad_bit_size[1] =
        bswap_32big(r_rsip_byte_to_bit_convert_lower(p_instance_ctrl->handle.gcm.total_aad_length));
    data_bit_size[0] =
        bswap_32big(r_rsip_byte_to_bit_convert_upper(p_instance_ctrl->handle.gcm.total_length));
    data_bit_size[1]  = bswap_32big(r_rsip_byte_to_bit_convert_lower(p_instance_ctrl->handle.gcm.total_length));
    *p_plain_length   = p_instance_ctrl->handle.gcm.total_length;
    tag_length_tmp[0] = bswap_32big(tag_length);

    /* Call primitive (cast to match the argument type with the primitive function) */
    rsip_ret_t rsip_ret = p_primitive->p_decryptFinal((uint32_t *) (p_instance_ctrl->handle.gcm.buffer),
                                                      (uint32_t *) tag_tmp,
                                                      aad_bit_size,
                                                      data_bit_size,
                                                      (uint32_t *) tag_length_tmp,
                                                      (uint32_t *) p_plain);

    /* Reset handle */
    r_rsip_handle_reset(&p_instance_ctrl->handle);

    /* State transition*/
    r_rsip_state_transit_init(p_instance_ctrl);

    /* Check error */
    fsp_err_t err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_FATAL;
    switch (rsip_ret)
    {
        case RSIP_RET_PASS:
        {
            err = FSP_SUCCESS;
            break;
        }

        case RSIP_RET_FAIL:
        {
            err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_FAIL;
            break;
        }

        case RSIP_RET_AUTH_FAIL:
        {
            err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_AUTHENTICATION;
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
 * Prepares an AES-CMAC generation.
 *
 * @param[in,out] p_ctrl        Pointer to control block.
 * @param[in]     p_wrapped_key Pointer to wrapped key of AES key.
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
fsp_err_t R_RSIP_AES_CMAC_GenerateInit (rsip_ctrl_t * const p_ctrl, rsip_wrapped_key_t const * const p_wrapped_key)
{
    return cmac_init(p_ctrl, p_wrapped_key, RSIP_HANDLE_TYPE_CMAC_GENERATE);
}

/*******************************************************************************************************************//**
 * Inputs message.
 *
 * Inside this function, the data that is input by the user is buffered until the input value of p_message
 * exceeds 16 bytes.
 * If the input value, p_message, is not a multiple of 16 bytes, it will be padded within the function.
 *
 * @param[in,out] p_ctrl         Pointer to control block.
 * @param[in]     p_message      Pointer to message. The length is message_length.
 * @param[in]     message_length Byte length of message (0 or more bytes).
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_ASSERTION                     A required parameter is NULL.
 * @retval FSP_ERR_NOT_OPEN                      Module is not open.
 * @retval FSP_ERR_INVALID_STATE                 Internal state is illegal.
 **********************************************************************************************************************/
fsp_err_t R_RSIP_AES_CMAC_GenerateUpdate (rsip_ctrl_t * const   p_ctrl,
                                          uint8_t const * const p_message,
                                          uint32_t const        message_length)
{
    return cmac_update(p_ctrl, p_message, message_length, RSIP_HANDLE_TYPE_CMAC_GENERATE);
}

/*******************************************************************************************************************//**
 * Finalizes an AES-CMAC generation.
 *
 * @param[in,out] p_ctrl Pointer to control block.
 * @param[out]    p_mac  Pointer to destination of MAC. The length is 16 bytes.
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_ASSERTION                     A required parameter is NULL.
 * @retval FSP_ERR_NOT_OPEN                      Module is not open.
 * @retval FSP_ERR_INVALID_STATE                 Internal state is illegal.
 * @retval FSP_ERR_CRYPTO_RSIP_FAIL              Internal error.
 *
 * @retval FSP_ERR_CRYPTO_RSIP_FATAL             Software corruption is detected.
 **********************************************************************************************************************/
fsp_err_t R_RSIP_AES_CMAC_GenerateFinal (rsip_ctrl_t * const p_ctrl, uint8_t * const p_mac)
{
    rsip_instance_ctrl_t    * p_instance_ctrl = (rsip_instance_ctrl_t *) p_ctrl;
    rsip_func_subset_cmac_t * p_primitive     =
        ((rsip_func_subset_cmac_t *) (p_instance_ctrl->handle.cmac.p_primitive));
    rsip_handle_type_t handle_type = RSIP_HANDLE_TYPE_CMAC_GENERATE;

#if RSIP_CFG_PARAM_CHECKING_ENABLE
    FSP_ASSERT(p_instance_ctrl);
    FSP_ASSERT(p_mac);
    FSP_ERROR_RETURN(RSIP_OPEN == p_instance_ctrl->open, FSP_ERR_NOT_OPEN);
#endif

    /* Check state */
    FSP_ERROR_RETURN(r_rsip_state_check_final(p_instance_ctrl, handle_type), FSP_ERR_INVALID_STATE);

    /*
     * Check buffered data
     * If the buffered data is not a complete block, fill the blank with 10/ (NIST SP 800-38B 6.2 Step4).
     */
    if ((0 != (p_instance_ctrl->handle.cmac.buffered_length % RSIP_BYTE_SIZE_AES_BLOCK)) ||
        (0 == p_instance_ctrl->handle.cmac.total_length))
    {
        p_instance_ctrl->handle.cmac.buffer[p_instance_ctrl->handle.cmac.buffered_length] = 1 << 7;
        memset(p_instance_ctrl->handle.cmac.buffer + (p_instance_ctrl->handle.cmac.buffered_length + 1),
               0,
               RSIP_BYTE_SIZE_AES_BLOCK - (p_instance_ctrl->handle.cmac.buffered_length + 1));
    }

    /* Call primitive (cast to match the argument type with the primitive function) */
    rsip_ret_t rsip_ret =
        p_primitive->p_generateFinal((const uint32_t *) p_instance_ctrl->handle.cmac.buffer,
                                     (uint32_t *) p_mac,
                                     p_instance_ctrl->handle.cmac.total_length);

    /* Reset handle */
    r_rsip_handle_reset(&p_instance_ctrl->handle);

    /* State transition*/
    r_rsip_state_transit_init(p_instance_ctrl);

    /* Check error */
    fsp_err_t err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_FATAL;
    switch (rsip_ret)
    {
        case RSIP_RET_PASS:
        {
            err = FSP_SUCCESS;
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
 * Prepares an AES-CMAC verification.
 *
 * @param[in,out] p_ctrl        Pointer to control block.
 * @param[in]     p_wrapped_key Pointer to wrapped key of AES key.
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
fsp_err_t R_RSIP_AES_CMAC_VerifyInit (rsip_ctrl_t * const p_ctrl, rsip_wrapped_key_t const * const p_wrapped_key)
{
    return cmac_init(p_ctrl, p_wrapped_key, RSIP_HANDLE_TYPE_CMAC_VERIFY);
}

/*******************************************************************************************************************//**
 * Inputs message.
 *
 * Inside this function, the data that is input by the user is buffered until the input value of p_message
 * exceeds 16 bytes.
 * If the input value, p_message, is not a multiple of 16 bytes, it will be padded within the function.
 *
 * @param[in,out] p_ctrl         Pointer to control block.
 * @param[in]     p_message      Pointer to message. The length is message_length.
 * @param[in]     message_length Byte length of message (0 or more bytes).
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_ASSERTION                     A required parameter is NULL.
 * @retval FSP_ERR_NOT_OPEN                      Module is not open.
 * @retval FSP_ERR_INVALID_STATE                 Internal state is illegal.
 **********************************************************************************************************************/
fsp_err_t R_RSIP_AES_CMAC_VerifyUpdate (rsip_ctrl_t * const   p_ctrl,
                                        uint8_t const * const p_message,
                                        uint32_t const        message_length)
{
    return cmac_update(p_ctrl, p_message, message_length, RSIP_HANDLE_TYPE_CMAC_VERIFY);
}

/*******************************************************************************************************************//**
 * Finalizes an AES-CMAC generation.
 *
 * @param[in,out] p_ctrl     Pointer to control block.
 * @param[in]     p_mac      Pointer to MAC. The length depends on mac_length.
 * @param[in]     mac_length Byte length of MAC. Must be 2 to 16.
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_ASSERTION                     A required parameter is NULL.
 * @retval FSP_ERR_NOT_OPEN                      Module is not open.
 * @retval FSP_ERR_INVALID_STATE                 Internal state is illegal.
 * @retval FSP_ERR_INVALID_SIZE                  mac_length is illegal.
 * @retval FSP_ERR_CRYPTO_RSIP_FAIL              Internal error.
 * @retval FSP_ERR_CRYPTO_RSIP_AUTHENTICATION    Authentication is failed.
 *
 * @retval FSP_ERR_CRYPTO_RSIP_FATAL             Software corruption is detected.
 **********************************************************************************************************************/
fsp_err_t R_RSIP_AES_CMAC_VerifyFinal (rsip_ctrl_t * const   p_ctrl,
                                       uint8_t const * const p_mac,
                                       uint32_t const        mac_length)
{
    rsip_instance_ctrl_t    * p_instance_ctrl = (rsip_instance_ctrl_t *) p_ctrl;
    rsip_func_subset_cmac_t * p_primitive     =
        ((rsip_func_subset_cmac_t *) (p_instance_ctrl->handle.cmac.p_primitive));
    rsip_handle_type_t handle_type = RSIP_HANDLE_TYPE_CMAC_VERIFY;

#if RSIP_CFG_PARAM_CHECKING_ENABLE
    FSP_ASSERT(p_instance_ctrl);
    FSP_ASSERT(p_mac);
    FSP_ERROR_RETURN(RSIP_OPEN == p_instance_ctrl->open, FSP_ERR_NOT_OPEN);
#endif

    /* Check state */
    FSP_ERROR_RETURN(r_rsip_state_check_final(p_instance_ctrl, handle_type), FSP_ERR_INVALID_STATE);

    /* mac_length must be 2 to 16 */
    FSP_ERROR_RETURN((2 <= mac_length) && (mac_length <= RSIP_BYTE_SIZE_AES_BLOCK), FSP_ERR_INVALID_SIZE);

    /* Set parameters */
    uint32_t mac_length_bit[1] =
    {
        bswap_32big(mac_length * 8)
    };
    uint32_t mac_tmp[RSIP_BYTE_SIZE_AES_BLOCK / sizeof(uint32_t)] =
    {
        0
    };
    memcpy(mac_tmp, p_mac, mac_length);

    /*
     * Check buffered data
     * If the buffered data is not a complete block, fill the blank with 10/ (NIST SP 800-38B 6.2 Step4).
     */
    if ((0 != (p_instance_ctrl->handle.cmac.buffered_length % RSIP_BYTE_SIZE_AES_BLOCK)) ||
        (0 == p_instance_ctrl->handle.cmac.total_length))
    {
        p_instance_ctrl->handle.cmac.buffer[p_instance_ctrl->handle.cmac.buffered_length] = 1 << 7;
        memset(p_instance_ctrl->handle.cmac.buffer + (p_instance_ctrl->handle.cmac.buffered_length + 1),
               0,
               RSIP_BYTE_SIZE_AES_BLOCK - (p_instance_ctrl->handle.cmac.buffered_length + 1));
    }

    /* Call primitive (cast to match the argument type with the primitive function) */
    rsip_ret_t rsip_ret =
        p_primitive->p_verifyFinal((const uint32_t *) p_instance_ctrl->handle.cmac.buffer,
                                   (const uint32_t *) mac_tmp,
                                   mac_length_bit,
                                   p_instance_ctrl->handle.cmac.total_length);

    /* Reset handle */
    r_rsip_handle_reset(&p_instance_ctrl->handle);

    /* State transition*/
    r_rsip_state_transit_init(p_instance_ctrl);

    /* Check error */
    fsp_err_t err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_FATAL;
    switch (rsip_ret)
    {
        case RSIP_RET_PASS:
        {
            err = FSP_SUCCESS;
            break;
        }

        case RSIP_RET_FAIL:
        {
            err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_FAIL;
            break;
        }

        case RSIP_RET_AUTH_FAIL:
        {
            err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_AUTHENTICATION;
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

/*******************************************************************************************************************//**
 * Prepares an AES-ECB/CBC/CTR.
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_ASSERTION                     A required parameter is NULL.
 * @retval FSP_ERR_INVALID_STATE                 Internal state is illegal.
 * @retval FSP_ERR_NOT_ENABLED                   Input key type is disabled in this function by configuration.
 * @retval FSP_ERR_INVALID_ARGUMENT              Input key type or mode is illegal.
 * @retval FSP_ERR_CRYPTO_RSIP_KEY_SET_FAIL      Input key value is illegal.
 *
 * @retval FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource required
 *                                               by the processing is in use by other processing.
 * @retval FSP_ERR_CRYPTO_RSIP_FATAL             Software corruption is detected.
 **********************************************************************************************************************/
static fsp_err_t aes_init (rsip_ctrl_t              * p_ctrl,
                           rsip_aes_mode_t            mode,
                           const rsip_wrapped_key_t * p_wrapped_key,
                           const uint8_t            * p_initial_vector,
                           rsip_handle_type_t         handle_type)
{
    rsip_instance_ctrl_t * p_instance_ctrl = (rsip_instance_ctrl_t *) p_ctrl;

#if RSIP_CFG_PARAM_CHECKING_ENABLE
    FSP_ASSERT(p_wrapped_key);
    FSP_ASSERT(p_wrapped_key->value);
    FSP_ASSERT(p_initial_vector || (RSIP_AES_MODE_ECB == mode));

    /* Check key type */
    FSP_ERROR_RETURN(RSIP_PRV_IS_AES_KEY(p_wrapped_key->type), FSP_ERR_INVALID_ARGUMENT);

    /* Check if the key type is enabled on configuration */
    FSP_ERROR_RETURN(((RSIP_KEY_TYPE_AES_128 == p_wrapped_key->type) && RSIP_CFG_AES_128_ECB_CBC_CTR_ENABLE) ||
                     ((RSIP_KEY_TYPE_AES_256 == p_wrapped_key->type) && RSIP_CFG_AES_256_ECB_CBC_CTR_ENABLE),
                     FSP_ERR_NOT_ENABLED);
#endif

    /* Check state */
    FSP_ERROR_RETURN(r_rsip_state_check_init(p_instance_ctrl), FSP_ERR_INVALID_STATE);

    /* Initialize handle */
    r_rsip_handle_reset(&p_instance_ctrl->handle);

    /* Set primitive */
    p_instance_ctrl->handle.aes.p_primitive = &gp_func_aes[RSIP_PRV_AES_REBASE(p_wrapped_key->type)];

    bool is_decryption = (RSIP_HANDLE_TYPE_AES_DECRYPT == handle_type) ? 1 : 0;

    /* Call primitive (cast to match the argument type with the primitive function) */
    rsip_func_subset_aes_t * p_primitive = ((rsip_func_subset_aes_t *) (p_instance_ctrl->handle.aes.p_primitive));
    rsip_ret_t               rsip_ret    =
        p_primitive->p_init[mode][is_decryption]((const uint32_t *) p_wrapped_key->value,
                                                 (const uint32_t *) p_initial_vector);

    /* Check error */
    fsp_err_t err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_FATAL;
    switch (rsip_ret)
    {
        case RSIP_RET_PASS:
        {
            /* State transition*/
            r_rsip_state_transit_update(p_instance_ctrl, handle_type);

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

        default:
        {
            err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_FATAL;
        }
    }

    return err;
}

/*******************************************************************************************************************//**
 * Executes AES-ECB/CBC/CTR encryption and decryption.
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_ASSERTION                     A required parameter is NULL.
 * @retval FSP_ERR_INVALID_STATE                 Internal state is illegal.
 * @retval FSP_ERR_INVALID_SIZE                  Input length is illegal.
 **********************************************************************************************************************/
static fsp_err_t aes_update (rsip_ctrl_t      * p_ctrl,
                             const uint8_t    * p_input,
                             uint8_t          * p_output,
                             uint32_t           input_length,
                             rsip_handle_type_t handle_type)

{
    rsip_instance_ctrl_t   * p_instance_ctrl = (rsip_instance_ctrl_t *) p_ctrl;
    rsip_func_subset_aes_t * p_primitive     = ((rsip_func_subset_aes_t *) (p_instance_ctrl->handle.aes.p_primitive));

#if RSIP_CFG_PARAM_CHECKING_ENABLE
    FSP_ASSERT(p_input || (0 == input_length));
    FSP_ASSERT(p_output || (0 == input_length));
#endif

    /* input_length must be a multiple of AES block length */
    FSP_ERROR_RETURN(0 == (input_length % RSIP_BYTE_SIZE_AES_BLOCK), FSP_ERR_INVALID_SIZE);

    /* Check state */
    FSP_ERROR_RETURN(r_rsip_state_check_update(p_instance_ctrl, handle_type), FSP_ERR_INVALID_STATE);

    if (0 != input_length)
    {
        /* Call primitive (cast to match the argument type with the primitive function) */
        p_primitive->p_update((const uint32_t *) p_input, (uint32_t *) p_output,
                              r_rsip_byte_to_word_convert(input_length));
    }
    else
    {
        /* Do nothing */
    }

    return FSP_SUCCESS;
}

/*******************************************************************************************************************//**
 * Finalizes an AES-ECB/CBC/CTR.
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_INVALID_STATE                 Internal state is illegal.
 *
 * @retval FSP_ERR_CRYPTO_RSIP_FATAL             Software corruption is detected.
 **********************************************************************************************************************/
static fsp_err_t aes_final (rsip_ctrl_t * p_ctrl, rsip_handle_type_t handle_type)
{
    rsip_instance_ctrl_t   * p_instance_ctrl = (rsip_instance_ctrl_t *) p_ctrl;
    rsip_func_subset_aes_t * p_primitive     = ((rsip_func_subset_aes_t *) (p_instance_ctrl->handle.aes.p_primitive));

    /* Check state */
    FSP_ERROR_RETURN(r_rsip_state_check_final(p_instance_ctrl, handle_type), FSP_ERR_INVALID_STATE);

    /* Call primitive (cast to match the argument type with the primitive function) */
    rsip_ret_t rsip_ret = p_primitive->p_final();

    /* Reset handle */
    r_rsip_handle_reset(&p_instance_ctrl->handle);

    /* State transition*/
    r_rsip_state_transit_init(p_instance_ctrl);

    /* Check error */
    fsp_err_t err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_FATAL;
    switch (rsip_ret)
    {
        case RSIP_RET_PASS:
        {
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
 * Prepares an AES-XTS.
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_ASSERTION                     A required parameter is NULL.
 * @retval FSP_ERR_INVALID_STATE                 Internal state is illegal.
 * @retval FSP_ERR_NOT_ENABLED                   Input key type is disabled in this function by configuration.
 * @retval FSP_ERR_INVALID_ARGUMENT              Input key type or mode is illegal.
 * @retval FSP_ERR_CRYPTO_RSIP_KEY_SET_FAIL      Input key value is illegal.
 *
 * @retval FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource required
 *                                               by the processing is in use by other processing.
 * @retval FSP_ERR_CRYPTO_RSIP_FATAL             Software corruption is detected.
 **********************************************************************************************************************/
static fsp_err_t xts_init (rsip_ctrl_t              * p_ctrl,
                           const rsip_wrapped_key_t * p_wrapped_key,
                           const uint8_t            * p_initial_vector,
                           rsip_handle_type_t         handle_type)
{
    rsip_instance_ctrl_t * p_instance_ctrl = (rsip_instance_ctrl_t *) p_ctrl;

#if RSIP_CFG_PARAM_CHECKING_ENABLE
    FSP_ASSERT(p_wrapped_key);
    FSP_ASSERT(p_wrapped_key->value);
    FSP_ASSERT(p_initial_vector);

    /* Check key type */
    FSP_ERROR_RETURN(RSIP_PRV_IS_XTS_AES_KEY(p_wrapped_key->type), FSP_ERR_INVALID_ARGUMENT);

    /* Check if the key type is enabled on configuration */
    if (RSIP_KEY_TYPE_AES_128_XTS == p_wrapped_key->type)
    {
        FSP_ERROR_RETURN(((RSIP_HANDLE_TYPE_XTS_ENCRYPT == handle_type) && RSIP_CFG_AES_128_XTS_ENCRYPT_ENABLE) ||
                         ((RSIP_HANDLE_TYPE_XTS_DECRYPT == handle_type) && RSIP_CFG_AES_128_XTS_DECRYPT_ENABLE),
                         FSP_ERR_NOT_ENABLED);
    }
    else                               /* RSIP_KEY_TYPE_AES_256_XTS */
    {
        FSP_ERROR_RETURN(((RSIP_HANDLE_TYPE_XTS_ENCRYPT == handle_type) && RSIP_CFG_AES_256_XTS_ENCRYPT_ENABLE) ||
                         ((RSIP_HANDLE_TYPE_XTS_DECRYPT == handle_type) && RSIP_CFG_AES_256_XTS_DECRYPT_ENABLE),
                         FSP_ERR_NOT_ENABLED);
    }
#endif

    /* Check state */
    FSP_ERROR_RETURN(r_rsip_state_check_init(p_instance_ctrl), FSP_ERR_INVALID_STATE);

    /* Initialize handle */
    r_rsip_handle_reset(&p_instance_ctrl->handle);

    /* Set primitive */
    p_instance_ctrl->handle.xts.p_primitive =
        &gp_func_xts[RSIP_PRV_XTS_REBASE(p_wrapped_key->type)][RSIP_PRV_XTS_HANDLE_REBASE(handle_type)];

    /* Call primitive (cast to match the argument type with the primitive function) */
    rsip_func_subset_xts_t * p_primitive = ((rsip_func_subset_xts_t *) (p_instance_ctrl->handle.xts.p_primitive));
    rsip_ret_t               rsip_ret    =
        p_primitive->p_init((const uint32_t *) p_wrapped_key->value, (const uint32_t *) p_initial_vector);

    /* Check error */
    fsp_err_t err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_FATAL;
    switch (rsip_ret)
    {
        case RSIP_RET_PASS:
        {
            /* State transition*/
            r_rsip_state_transit_update(p_instance_ctrl, handle_type);

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

        default:
        {
            err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_FATAL;
        }
    }

    return err;
}

/*******************************************************************************************************************//**
 * Executes AES-XTS encryption and decryption.
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_ASSERTION                     A required parameter is NULL.
 * @retval FSP_ERR_INVALID_STATE                 Internal state is illegal.
 * @retval FSP_ERR_INVALID_SIZE                  Input length is illegal.
 **********************************************************************************************************************/
static fsp_err_t xts_update (rsip_ctrl_t      * p_ctrl,
                             const uint8_t    * p_input,
                             uint8_t          * p_output,
                             uint32_t           input_length,
                             rsip_handle_type_t handle_type)
{
    rsip_instance_ctrl_t   * p_instance_ctrl = (rsip_instance_ctrl_t *) p_ctrl;
    rsip_func_subset_xts_t * p_primitive     = ((rsip_func_subset_xts_t *) (p_instance_ctrl->handle.xts.p_primitive));

#if RSIP_CFG_PARAM_CHECKING_ENABLE
    FSP_ASSERT(p_input || (0 == input_length));
    FSP_ASSERT(p_output || (0 == input_length));
#endif

    /* input_length must be 0, 17 to 31 (AES block length < input_length < (AES block length * 2)), or multiple of AES block length */
    FSP_ERROR_RETURN((0 == (input_length % RSIP_BYTE_SIZE_AES_BLOCK)) || (0 == input_length) ||
                     (RSIP_BYTE_SIZE_AES_BLOCK < input_length && (RSIP_BYTE_SIZE_AES_BLOCK * 2) > input_length),
                     FSP_ERR_INVALID_SIZE);

    /* Check state */
    FSP_ERROR_RETURN(r_rsip_state_check_update(p_instance_ctrl, handle_type), FSP_ERR_INVALID_STATE);

    /* If input_length is a value between 17 and 31, p_input is input in final function */
    if (0 != (input_length % RSIP_BYTE_SIZE_AES_BLOCK))
    {
        /* If a fraction is input, the value and length are stored in handle */
        memset(p_instance_ctrl->handle.xts.buffer, 0, sizeof(p_instance_ctrl->handle.xts.buffer));
        memcpy(p_instance_ctrl->handle.xts.buffer, p_input, input_length);
        p_instance_ctrl->handle.xts.buffered_length = input_length;

        /* After this function returns, final function can be called */
        r_rsip_state_transit_final(p_instance_ctrl);
    }
    /* If input_length is a multiple of 16, call update */
    else if (0 != input_length)
    {
        /* Call primitive (cast to match the argument type with the primitive function) */
        p_primitive->p_update((const uint32_t *) p_input, (uint32_t *) p_output,
                              r_rsip_byte_to_word_convert(input_length));
    }
    /* If input_length = 0, do nothing */
    else
    {
        /* Do nothing */
    }

    return FSP_SUCCESS;
}

/*******************************************************************************************************************//**
 * Finalizes an AES-XTS.
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_ASSERTION                     A required parameter is NULL.
 * @retval FSP_ERR_INVALID_STATE                 Internal state is illegal.
 * @retval FSP_ERR_CRYPTO_RSIP_FAIL              Internal error.
 *
 * @retval FSP_ERR_CRYPTO_RSIP_FATAL             Software corruption is detected.
 **********************************************************************************************************************/
static fsp_err_t xts_final (rsip_ctrl_t      * p_ctrl,
                            uint8_t          * p_output,
                            uint32_t         * p_output_length,
                            rsip_handle_type_t handle_type)
{
    rsip_instance_ctrl_t   * p_instance_ctrl = (rsip_instance_ctrl_t *) p_ctrl;
    rsip_func_subset_xts_t * p_primitive     = ((rsip_func_subset_xts_t *) (p_instance_ctrl->handle.xts.p_primitive));

#if RSIP_CFG_PARAM_CHECKING_ENABLE
    FSP_ASSERT(p_output);
    FSP_ASSERT(p_output_length);
#endif

    /* Check state */
    FSP_ERROR_RETURN(r_rsip_state_check_final(p_instance_ctrl, handle_type), FSP_ERR_INVALID_STATE);

    uint32_t output_length_bit[1] =
    {
        bswap_32big(r_rsip_byte_to_bit_convert_lower(p_instance_ctrl->handle.xts.buffered_length))
    };

    /* Call primitive (cast to match the argument type with the primitive function) */
    rsip_ret_t rsip_ret =
        p_primitive->p_final(output_length_bit, (uint32_t *) p_instance_ctrl->handle.xts.buffer, (uint32_t *) p_output);

    *p_output_length = p_instance_ctrl->handle.xts.buffered_length;

    /* Reset handle */
    r_rsip_handle_reset(&p_instance_ctrl->handle);

    /* State transition*/
    r_rsip_state_transit_init(p_instance_ctrl);

    /* Check error */
    fsp_err_t err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_FATAL;
    switch (rsip_ret)
    {
        case RSIP_RET_PASS:
        {
            err = FSP_SUCCESS;
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
 * Prepares an AES-GCM.
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
static fsp_err_t gcm_init (rsip_ctrl_t              * p_ctrl,
                           const rsip_wrapped_key_t * p_wrapped_key,
                           const uint8_t            * p_initial_vector,
                           uint32_t                   initial_vector_length,
                           rsip_handle_type_t         handle_type)
{
    rsip_instance_ctrl_t * p_instance_ctrl = (rsip_instance_ctrl_t *) p_ctrl;

#if RSIP_CFG_PARAM_CHECKING_ENABLE
    FSP_ASSERT(p_instance_ctrl);
    FSP_ASSERT(p_wrapped_key);
    FSP_ASSERT(p_wrapped_key->value);
    FSP_ASSERT(p_initial_vector);
    FSP_ERROR_RETURN(RSIP_OPEN == p_instance_ctrl->open, FSP_ERR_NOT_OPEN);

    /* Check key type */
    FSP_ERROR_RETURN(RSIP_PRV_IS_AES_KEY(p_wrapped_key->type), FSP_ERR_INVALID_ARGUMENT);

    /* Check if the key type is enabled on configuration */
    if (RSIP_KEY_TYPE_AES_128 == p_wrapped_key->type)
    {
        FSP_ERROR_RETURN(((RSIP_HANDLE_TYPE_GCM_ENCRYPT == handle_type) && RSIP_CFG_AES_128_GCM_ENCRYPT_ENABLE) ||
                         ((RSIP_HANDLE_TYPE_GCM_DECRYPT == handle_type) && RSIP_CFG_AES_128_GCM_DECRYPT_ENABLE),
                         FSP_ERR_NOT_ENABLED);
    }
    else                               /* RSIP_KEY_TYPE_AES_256 */
    {
        FSP_ERROR_RETURN(((RSIP_HANDLE_TYPE_GCM_ENCRYPT == handle_type) && RSIP_CFG_AES_256_GCM_ENCRYPT_ENABLE) ||
                         ((RSIP_HANDLE_TYPE_GCM_DECRYPT == handle_type) && RSIP_CFG_AES_256_GCM_DECRYPT_ENABLE),
                         FSP_ERR_NOT_ENABLED);
    }
#endif

    /* Check state */
    FSP_ERROR_RETURN(r_rsip_state_check_init(p_instance_ctrl), FSP_ERR_INVALID_STATE);

    /* Initialize handle */
    r_rsip_handle_reset(&p_instance_ctrl->handle);

    /* Set primitive */
    p_instance_ctrl->handle.gcm.p_primitive =
        &gp_func_gcm[RSIP_PRV_AES_REBASE(p_wrapped_key->type)][RSIP_PRV_GCM_HANDLE_REBASE(handle_type)];

    /* Generate IV */
    uint32_t hashed_ivec[4] =
    {
        0
    };

    fsp_err_t err =
        gcm_iv_prepare(p_instance_ctrl, p_initial_vector, initial_vector_length, p_wrapped_key, hashed_ivec);

    if (FSP_SUCCESS == err)
    {
        /* Call primitive (cast to match the argument type with the primitive function) */
        rsip_func_subset_gcm_t * p_primitive = ((rsip_func_subset_gcm_t *) (p_instance_ctrl->handle.gcm.p_primitive));
        rsip_ret_t               rsip_ret    =
            p_primitive->p_init((const uint32_t *) p_wrapped_key->value, hashed_ivec);

        /* Check error */
        switch (rsip_ret)
        {
            case RSIP_RET_PASS:
            {
                /* State transition*/
                r_rsip_state_transit_update(p_instance_ctrl, handle_type);

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

            default:
            {
                err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_FATAL;
            }
        }
    }
    else
    {
        /* Do nothing */
    }

    return err;
}

/*******************************************************************************************************************//**
 * Inputs aad and executes encryption and decryption.
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_ASSERTION                     A required parameter is NULL.
 * @retval FSP_ERR_NOT_OPEN                      Module is not open.
 * @retval FSP_ERR_INVALID_STATE                 Internal state is illegal.
 * @retval FSP_ERR_INVALID_SIZE                  Input length is illegal.
 **********************************************************************************************************************/
static fsp_err_t gcm_update (rsip_ctrl_t      * p_ctrl,
                             const uint8_t    * p_input,
                             uint8_t          * p_output,
                             uint32_t           input_length,
                             const uint8_t    * p_aad,
                             uint32_t           aad_length,
                             rsip_handle_type_t handle_type)
{
    rsip_instance_ctrl_t   * p_instance_ctrl = (rsip_instance_ctrl_t *) p_ctrl;
    rsip_func_subset_gcm_t * p_primitive     = ((rsip_func_subset_gcm_t *) (p_instance_ctrl->handle.gcm.p_primitive));

#if RSIP_CFG_PARAM_CHECKING_ENABLE
    FSP_ASSERT(p_instance_ctrl);
    FSP_ASSERT(p_input || (0 == input_length));
    FSP_ASSERT(p_output || (0 == input_length));
    FSP_ASSERT(p_aad || (0 == aad_length));
    FSP_ERROR_RETURN(RSIP_OPEN == p_instance_ctrl->open, FSP_ERR_NOT_OPEN);
#endif

    /* Check state */
    FSP_ERROR_RETURN(r_rsip_state_check_update(p_instance_ctrl, handle_type), FSP_ERR_INVALID_STATE);

    /* If AAD is input, flag_update_input_data must be RSIP_PRV_AES_GCM_INPUT_DATA_AAD */
    /* (AAD must be input before plaintext/ciphertext is input) */
    FSP_ERROR_RETURN((0 == aad_length) || (!p_instance_ctrl->handle.gcm.has_finished_aad_input), FSP_ERR_INVALID_SIZE);

    uint32_t length_rest     = 0;
    uint32_t length_aad_rest = 0;

    /* Input AAD */
    if (0 != aad_length)
    {
        p_instance_ctrl->handle.gcm.total_aad_length += aad_length;

        if ((p_instance_ctrl->handle.gcm.buffered_length + aad_length) >= RSIP_BYTE_SIZE_AES_BLOCK)
        {
            /* Input remaining data in buffer */
            memcpy((&p_instance_ctrl->handle.gcm.buffer[0] + p_instance_ctrl->handle.gcm.buffered_length),
                   p_aad,
                   RSIP_BYTE_SIZE_AES_BLOCK - p_instance_ctrl->handle.gcm.buffered_length);

            /* Call primitive (cast to match the argument type with the p_primitive function) */
            p_primitive->p_updateAad((uint32_t *) (p_instance_ctrl->handle.gcm.buffer),
                                     r_rsip_byte_to_word_convert((RSIP_BYTE_SIZE_AES_BLOCK)));
            length_aad_rest = aad_length -
                              (RSIP_BYTE_SIZE_AES_BLOCK - p_instance_ctrl->handle.gcm.buffered_length);
            memset(p_instance_ctrl->handle.gcm.buffer, 0, sizeof(p_instance_ctrl->handle.gcm.buffer));

            /* Input block data */
            if (length_aad_rest >= RSIP_BYTE_SIZE_AES_BLOCK)
            {
                /* Call primitive (cast to match the argument type with the p_primitive function) */
                p_primitive->p_updateAad((const uint32_t *) (p_aad +
                                                             (RSIP_BYTE_SIZE_AES_BLOCK -
                                                              p_instance_ctrl->handle.gcm.buffered_length)),
                                         r_rsip_byte_to_word_convert((length_aad_rest / RSIP_BYTE_SIZE_AES_BLOCK) *
                                                                     RSIP_BYTE_SIZE_AES_BLOCK));
                length_aad_rest -= ((length_aad_rest / RSIP_BYTE_SIZE_AES_BLOCK) * RSIP_BYTE_SIZE_AES_BLOCK);
            }

            p_instance_ctrl->handle.gcm.buffered_length = 0;

            /* Store remaining data to buffer */
            memcpy(p_instance_ctrl->handle.gcm.buffer, p_aad + (aad_length - length_aad_rest), length_aad_rest);
            p_instance_ctrl->handle.gcm.buffered_length = length_aad_rest;
        }
        else
        {
            /* Store remaining data to buffer */
            memcpy(&p_instance_ctrl->handle.gcm.buffer[0] + p_instance_ctrl->handle.gcm.buffered_length,
                   p_aad,
                   aad_length);
            p_instance_ctrl->handle.gcm.buffered_length += aad_length;
        }
    }

    /* Input plaintext/ciphertext */
    if (0 != input_length)
    {
        /* If plaintext/ciphertext is input for the first time, input remaining AAD and prohibit new AAD input */
        if (!p_instance_ctrl->handle.gcm.has_finished_aad_input)
        {
            gcm_aad_input_terminate(p_instance_ctrl);
        }

        p_instance_ctrl->handle.gcm.total_length += input_length;
        if ((p_instance_ctrl->handle.gcm.buffered_length + input_length) >= RSIP_BYTE_SIZE_AES_BLOCK)
        {
            /* Input remaining data in buffer */
            memcpy((&p_instance_ctrl->handle.gcm.buffer[0] + p_instance_ctrl->handle.gcm.buffered_length),
                   p_input,
                   RSIP_BYTE_SIZE_AES_BLOCK - p_instance_ctrl->handle.gcm.buffered_length);

            /* Call primitive (cast to match the argument type with the p_primitive function) */
            p_primitive->p_update((uint32_t *) (p_instance_ctrl->handle.gcm.buffer),
                                  (uint32_t *) (p_output),
                                  r_rsip_byte_to_word_convert(RSIP_BYTE_SIZE_AES_BLOCK));
            length_rest = input_length - (RSIP_BYTE_SIZE_AES_BLOCK - p_instance_ctrl->handle.gcm.buffered_length);
            memset(p_instance_ctrl->handle.gcm.buffer, 0, sizeof(p_instance_ctrl->handle.gcm.buffer));

            /* Input block data */
            if (length_rest >= RSIP_BYTE_SIZE_AES_BLOCK)
            {
                /* Call primitive (cast to match the argument type with the p_primitive function) */
                p_primitive->p_update((const uint32_t *) (p_input +
                                                          (RSIP_BYTE_SIZE_AES_BLOCK -
                                                           p_instance_ctrl->handle.gcm.buffered_length)),
                                      (uint32_t *) (p_output + RSIP_BYTE_SIZE_AES_BLOCK),
                                      ((length_rest / RSIP_BYTE_SIZE_AES_BLOCK) *
                                       r_rsip_byte_to_word_convert(RSIP_BYTE_SIZE_AES_BLOCK)));
                length_rest -= ((length_rest / RSIP_BYTE_SIZE_AES_BLOCK) * RSIP_BYTE_SIZE_AES_BLOCK);
            }

            p_instance_ctrl->handle.gcm.buffered_length = 0;

            /* Store remaining data to buffer */
            memcpy(p_instance_ctrl->handle.gcm.buffer, p_input + (input_length - length_rest), length_rest);
            p_instance_ctrl->handle.gcm.buffered_length = length_rest;
        }
        else
        {
            /* Store remaining data to buffer */
            memcpy(&p_instance_ctrl->handle.gcm.buffer[0] + p_instance_ctrl->handle.gcm.buffered_length,
                   p_input,
                   input_length);
            p_instance_ctrl->handle.gcm.buffered_length += input_length;
        }
    }

    return FSP_SUCCESS;
}

/*******************************************************************************************************************//**
 * Generates of input parameter for AES-GCM functions.
 *
 * @param[in,out] p_instance_ctrl       Pointer to control block.
 * @param[in]     p_initial_vector      Pointer to initialization vector.
 * @param[in]     initial_vector_length Initial vector byte size.
 * @param[in]     p_wrapped_key         Wrapped key area.
 * @param[out]    p_hashed_ivec         Pointer to destination of initialization vector
 *                                      (using length of initial_vector_length as a condition)
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_CRYPTO_RSIP_KEY_SET_FAIL      Input key value is illegal.
 *
 * @retval FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource required
 *                                               by the processing is in use by other processing.
 * @retval FSP_ERR_CRYPTO_RSIP_FATAL             Software corruption is detected.
 *********************************************************************************************************************/
static fsp_err_t gcm_iv_prepare (rsip_instance_ctrl_t     * p_instance_ctrl,
                                 const uint8_t            * p_initial_vector,
                                 uint32_t                   initial_vector_length,
                                 const rsip_wrapped_key_t * p_wrapped_key,
                                 uint32_t                 * p_hashed_ivec)
{
    rsip_func_subset_gcm_t * p_primitive = ((rsip_func_subset_gcm_t *) (p_instance_ctrl->handle.gcm.p_primitive));

    uint32_t hash_subkey[4] =
    {
        0
    };
    uint32_t hashed_ivec_tmp[4] =
    {
        0
    };
    uint32_t zero[4] =
    {
        0
    };
    uint32_t ivec_length_rest = 0;
    uint32_t ivec_bit_len[4]  =
    {
        0
    };
    uint32_t ivec_tmp[4] =
    {
        0
    };

    fsp_err_t  err      = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_FATAL;
    rsip_ret_t rsip_ret = RSIP_RET_FAIL;

    /* If initial_vector_length is 12 (96 bit), hashed_ivec is (initial_vector || 0^{31} || 1)  */
    if (12U == initial_vector_length)
    {
        memcpy(p_hashed_ivec, p_initial_vector, 12U);
        p_hashed_ivec[3] = bswap_32big(0x00000001U);
        err              = FSP_SUCCESS;
    }
    /* If iv_len is not 12 (96 bit), calculate GHASH */
    else
    {
        /* Call primitive (cast to match the argument type with the p_primitive function) */
        rsip_ret = p_primitive->p_ecb->p_init[RSIP_AES_MODE_ECB][0]((const uint32_t *) p_wrapped_key->value, zero);
        if (RSIP_RET_PASS == rsip_ret)
        {
            p_primitive->p_ecb->p_update(zero, hash_subkey, RSIP_BYTE_SIZE_AES_BLOCK / sizeof(uint32_t));
            rsip_ret = p_primitive->p_ecb->p_final();
        }

        if (RSIP_RET_PASS == rsip_ret)
        {
            if (RSIP_BYTE_SIZE_AES_BLOCK <= initial_vector_length)
            {
                /* Call primitive (cast to match the argument type with the p_primitive function) */
                rsip_ret =
                    gp_func_ghash_compute(hash_subkey, zero, (const uint32_t *) p_initial_vector, hashed_ivec_tmp,
                                          (initial_vector_length / RSIP_BYTE_SIZE_AES_BLOCK) * sizeof(uint32_t));
                if (RSIP_RET_PASS == rsip_ret)
                {
                    ivec_length_rest = initial_vector_length % RSIP_BYTE_SIZE_AES_BLOCK;
                    if (0 != ivec_length_rest)
                    {
                        memcpy(ivec_tmp, p_initial_vector + (initial_vector_length - ivec_length_rest),
                               ivec_length_rest);

                        /* Call primitive (cast to match the argument type with the p_primitive function) */
                        rsip_ret = gp_func_ghash_compute(hash_subkey,
                                                         hashed_ivec_tmp,
                                                         ivec_tmp,
                                                         hashed_ivec_tmp,
                                                         RSIP_BYTE_SIZE_AES_BLOCK / sizeof(uint32_t));
                    }
                }
            }
            else
            {
                memcpy(ivec_tmp, p_initial_vector, initial_vector_length);

                /* Call primitive (cast to match the argument type with the p_primitive function) */
                rsip_ret = gp_func_ghash_compute(hash_subkey,
                                                 zero,
                                                 ivec_tmp,
                                                 hashed_ivec_tmp,
                                                 RSIP_BYTE_SIZE_AES_BLOCK / sizeof(uint32_t));
            }

            if (RSIP_RET_PASS == rsip_ret)
            {
                /* Calculate ivec bit length */
                ivec_bit_len[0] = 0U;
                ivec_bit_len[1] = 0U;
                ivec_bit_len[2] = bswap_32big(r_rsip_byte_to_bit_convert_upper(initial_vector_length));
                ivec_bit_len[3] = bswap_32big(r_rsip_byte_to_bit_convert_lower(initial_vector_length));

                /* Call primitive (cast to match the argument type with the p_primitive function) */
                rsip_ret = gp_func_ghash_compute(hash_subkey,
                                                 hashed_ivec_tmp,
                                                 ivec_bit_len,
                                                 p_hashed_ivec,
                                                 RSIP_BYTE_SIZE_AES_BLOCK / sizeof(uint32_t));
            }
        }

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

            default:
            {
                err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_FATAL;
            }
        }
    }

    return err;
}

static void gcm_aad_input_terminate (rsip_instance_ctrl_t * p_instance_ctrl)
{
    rsip_func_subset_gcm_t * p_primitive = ((rsip_func_subset_gcm_t *) (p_instance_ctrl->handle.gcm.p_primitive));

    if (0 != (p_instance_ctrl->handle.gcm.buffered_length % RSIP_BYTE_SIZE_AES_BLOCK))
    {
        /* Input remaining AAD */
        memset(&p_instance_ctrl->handle.gcm.buffer[0] + p_instance_ctrl->handle.gcm.buffered_length,
               0,
               RSIP_BYTE_SIZE_AES_BLOCK - p_instance_ctrl->handle.gcm.buffered_length);

        /* Call primitive (cast to match the argument type with the p_primitive function) */
        p_primitive->p_updateAad((uint32_t *) (p_instance_ctrl->handle.gcm.
                                               buffer),
                                 r_rsip_byte_to_word_convert(RSIP_BYTE_SIZE_AES_BLOCK));
    }

    /* Reset buffer */
    memset(p_instance_ctrl->handle.gcm.buffer, 0, sizeof(p_instance_ctrl->handle.gcm.buffer));
    p_instance_ctrl->handle.gcm.buffered_length = 0;

    /* Prohibit AAD input and start plaintext/ciphertext input */
    p_instance_ctrl->handle.gcm.has_finished_aad_input = true;
    p_primitive->p_updateTransition();
}

/*******************************************************************************************************************//**
 * Prepares an AES-CMAC.
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
static fsp_err_t cmac_init (rsip_ctrl_t              * p_ctrl,
                            const rsip_wrapped_key_t * p_wrapped_key,
                            rsip_handle_type_t         handle_type)
{
    rsip_instance_ctrl_t * p_instance_ctrl = (rsip_instance_ctrl_t *) p_ctrl;

#if RSIP_CFG_PARAM_CHECKING_ENABLE
    FSP_ASSERT(p_instance_ctrl);
    FSP_ASSERT(p_wrapped_key);
    FSP_ASSERT(p_wrapped_key->value);
    FSP_ERROR_RETURN(RSIP_OPEN == p_instance_ctrl->open, FSP_ERR_NOT_OPEN);

    /* Check key type */
    FSP_ERROR_RETURN(RSIP_PRV_IS_AES_KEY(p_wrapped_key->type), FSP_ERR_INVALID_ARGUMENT);

    /* Check if the key type is enabled on configuration */
    FSP_ERROR_RETURN(((RSIP_KEY_TYPE_AES_128 == p_wrapped_key->type) && RSIP_CFG_AES_128_CMAC_ENABLE) ||
                     ((RSIP_KEY_TYPE_AES_256 == p_wrapped_key->type) && RSIP_CFG_AES_256_CMAC_ENABLE),
                     FSP_ERR_NOT_ENABLED);
#endif

    /* Check state */
    FSP_ERROR_RETURN(r_rsip_state_check_init(p_instance_ctrl), FSP_ERR_INVALID_STATE);

    /* Initialize handle */
    r_rsip_handle_reset(&p_instance_ctrl->handle);

    /* Set primitive */
    p_instance_ctrl->handle.cmac.p_primitive = &gp_func_cmac[RSIP_PRV_AES_REBASE(p_wrapped_key->type)];

    /* Call primitive (cast to match the argument type with the primitive function) */
    rsip_func_subset_cmac_t * p_primitive = ((rsip_func_subset_cmac_t *) (p_instance_ctrl->handle.cmac.p_primitive));
    rsip_ret_t                rsip_ret    = p_primitive->p_init((const uint32_t *) p_wrapped_key->value);

    /* Check error */
    fsp_err_t err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_FATAL;
    switch (rsip_ret)
    {
        case RSIP_RET_PASS:
        {
            /* State transition*/
            r_rsip_state_transit_update(p_instance_ctrl, handle_type);

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

        default:
        {
            err = (fsp_err_t) FSP_ERR_CRYPTO_RSIP_FATAL;
        }
    }

    return err;
}

/*******************************************************************************************************************//**
 * Inputs message.
 *
 * @retval FSP_SUCCESS                           Normal termination.
 * @retval FSP_ERR_ASSERTION                     A required parameter is NULL.
 * @retval FSP_ERR_NOT_OPEN                      Module is not open.
 * @retval FSP_ERR_INVALID_STATE                 Internal state is illegal.
 **********************************************************************************************************************/
static fsp_err_t cmac_update (rsip_ctrl_t      * p_ctrl,
                              const uint8_t    * p_message,
                              uint32_t           message_length,
                              rsip_handle_type_t handle_type)
{
    rsip_instance_ctrl_t    * p_instance_ctrl = (rsip_instance_ctrl_t *) p_ctrl;
    rsip_func_subset_cmac_t * p_primitive     =
        ((rsip_func_subset_cmac_t *) (p_instance_ctrl->handle.cmac.p_primitive));

#if RSIP_CFG_PARAM_CHECKING_ENABLE
    FSP_ASSERT(p_instance_ctrl);
    FSP_ASSERT(p_message || (0 == message_length));
    FSP_ERROR_RETURN(RSIP_OPEN == p_instance_ctrl->open, FSP_ERR_NOT_OPEN);
#endif

    /* Check state */
    FSP_ERROR_RETURN(r_rsip_state_check_update(p_instance_ctrl, handle_type), FSP_ERR_INVALID_STATE);

    uint32_t length_rest = 0;

    p_instance_ctrl->handle.cmac.total_length += message_length;
    if ((p_instance_ctrl->handle.cmac.buffered_length + message_length) > RSIP_BYTE_SIZE_AES_BLOCK)
    {
        /* Input remaining data in buffer */
        memcpy((&p_instance_ctrl->handle.cmac.buffer[0] + p_instance_ctrl->handle.cmac.buffered_length),
               p_message,
               RSIP_BYTE_SIZE_AES_BLOCK - p_instance_ctrl->handle.cmac.buffered_length);

        /* Call primitive (cast to match the argument type with the primitive function) */
        p_primitive->p_update((const uint32_t *) (p_instance_ctrl->handle.cmac.buffer),
                              r_rsip_byte_to_word_convert(RSIP_BYTE_SIZE_AES_BLOCK));
        length_rest = message_length - (RSIP_BYTE_SIZE_AES_BLOCK - p_instance_ctrl->handle.cmac.buffered_length);
        memset(p_instance_ctrl->handle.cmac.buffer, 0, sizeof(p_instance_ctrl->handle.cmac.buffer));

        /* Input block data */
        if (length_rest > RSIP_BYTE_SIZE_AES_BLOCK)
        {
            /* Call primitive (cast to match the argument type with the primitive function) */
            p_primitive->p_update((const uint32_t *) (p_message +
                                                      (RSIP_BYTE_SIZE_AES_BLOCK -
                                                       p_instance_ctrl->handle.cmac.buffered_length)),
                                  r_rsip_byte_to_word_convert(((length_rest - 1) / RSIP_BYTE_SIZE_AES_BLOCK) *
                                                              RSIP_BYTE_SIZE_AES_BLOCK));
            length_rest -= (((length_rest - 1) / RSIP_BYTE_SIZE_AES_BLOCK) * RSIP_BYTE_SIZE_AES_BLOCK);
        }

        p_instance_ctrl->handle.cmac.buffered_length = 0;

        /* Store remaining data to buffer */
        memcpy(p_instance_ctrl->handle.cmac.buffer, p_message + (message_length - length_rest), length_rest);
        p_instance_ctrl->handle.cmac.buffered_length = length_rest;
    }
    else
    {
        /* Store remaining data to buffer */
        memcpy(&p_instance_ctrl->handle.cmac.buffer[0] + p_instance_ctrl->handle.cmac.buffered_length,
               p_message,
               message_length);
        p_instance_ctrl->handle.cmac.buffered_length += message_length;
    }

    return FSP_SUCCESS;
}
