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
 * File Name    : r_sce_aes.c
 * Version      : 1.0
 * Description  : SCE AES Public API source file
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

/* Initialization function call state */
#define CALL_ONLY_INIT            (0)
#define CALL_ONLY_UPDATE_FINAL    (1)

/* Magic numbers */
#ifndef SCE_HEX_E000000
#define SCE_HEX_E000000          (0xe000000U)
#endif
#ifndef SCE_DEC_110
#define SCE_DEC_110              (110)
#endif

/***********************************************************************************************************************
 * Typedef definitions
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Private function prototypes
 **********************************************************************************************************************/
static void cal_current_ivec_ctrmode(sce_aes_handle_t *handle , uint32_t block_num);

/***********************************************************************************************************************
 * Private global variables
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Global variables
 **********************************************************************************************************************/
extern uint32_t g_private_id_counter;
uint32_t        g_aes128ecbenc_private_id;
uint32_t        g_aes128ecbdec_private_id;
uint32_t        g_aes256ecbenc_private_id;
uint32_t        g_aes256ecbdec_private_id;
uint32_t        g_aes128cbcenc_private_id;
uint32_t        g_aes128cbcdec_private_id;
uint32_t        g_aes256cbcenc_private_id;
uint32_t        g_aes256cbcdec_private_id;
uint32_t        g_aes128ctrenc_private_id;
uint32_t        g_aes128ctrdec_private_id;
uint32_t        g_aes256ctrenc_private_id;
uint32_t        g_aes256ctrdec_private_id;
uint32_t        g_aes128cmacgen_private_id;
uint32_t        g_aes128cmacver_private_id;
uint32_t        g_aes256cmacgen_private_id;
uint32_t        g_aes256cmacver_private_id;

/*******************************************************************************************************************//**
 * @addtogroup SCE_PROTECTED
 * @{
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Functions
 **********************************************************************************************************************/

/*******************************************************************************************************************//**
 * The R_SCE_AES128ECB_EncryptInit() function performs preparations for the execution of an AES calculation,
 * and writes the result to the first argument, handle. The value of handle is used as an argument
 * in the subsequent R_SCE_AES128ECB_EncryptUpdate() function and R_SCE_AES128ECB_EncryptFinal() function.
 *
 * @param[in,out] handle      AES handler (work area)
 * @param[in]     wrapped_key 128-bit AES wrapped key
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource needed
 *                                              by the processing routine was in use by another processing routine.
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL      Input illegal wrapped key.
 *
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              Internal error occurred.
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES128ECB_EncryptInit (sce_aes_handle_t * handle, sce_aes_wrapped_key_t * wrapped_key)
{
    memset(handle, 0, sizeof(sce_aes_handle_t));
    handle->flag_call_init = CALL_ONLY_UPDATE_FINAL;
    g_private_id_counter++;
    g_aes128ecbenc_private_id = g_private_id_counter;
    handle->id                = g_aes128ecbenc_private_id;

    return R_SCE_Aes128EcbEncryptInitPrivate(wrapped_key);
}

/*******************************************************************************************************************//**
 * The R_SCE_AES128ECB_EncryptUpdate() function encrypts the second argument, plain, utilizing the key index stored
 * in the handle specified in the first argument, handle, and writes the ongoing status to this first argument.
 * In addition, it writes the encryption result to the third argument, cipher. After plaintext input is completed,
 * call R_SCE_AES128ECB_EncryptFinal().
 *
 * Specify areas for plain and cipher that do not overlap. For plain and cipher,
 * specify RAM addresses that are multiples of 4.
 *
 * @param[in,out] handle       AES handler (work area)
 * @param[in]     plain        plaintext data area
 * @param[in,out] cipher       ciphertext data area
 * @param[in,out] plain_length plaintext data length (must be a multiple of 16)
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_PARAMETER         Input data is illegal.
 * @retval FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION An invalid function was called.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES128ECB_EncryptUpdate (sce_aes_handle_t * handle,
        uint8_t          * plain,
        uint8_t          * cipher,
        uint32_t           plain_length)
{
    if (CALL_ONLY_INIT == handle->flag_call_init)
    {
        return FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION;
    }

    if (handle->id != g_aes128ecbenc_private_id)
    {
        return FSP_ERR_CRYPTO_SCE_PARAMETER;
    }

    memcpy(handle->last_1_block_as_fraction,
            (plain + ((plain_length / HW_SCE_AES_BLOCK_BYTE_SIZE) * HW_SCE_AES_BLOCK_BYTE_SIZE)),
            (plain_length % HW_SCE_AES_BLOCK_BYTE_SIZE));
    handle->current_input_data_size = plain_length;

    /* Casting uint32_t pointer is used for address. */
    return R_SCE_Aes128EcbEncryptUpdatePrivate((uint32_t *) (plain), (uint32_t *) (cipher), plain_length >> 2);
}

/*******************************************************************************************************************//**
 * Using the handle specified in the first argument, handle, the R_SCE_AES128ECB_EncryptFinal() function writes
 * the calculation result to the second argument, cipher, and writes the length of the calculation result
 * to the third argument, cipher_length. The original intent was for a portion of the encryption
 * result that was not a multiple of 16 bytes to be written to the second argument.
 * However, as a result of the restriction that only multiples of 16 can be input to the Update function,
 * nothing is ever written to cipher, and 0 is always written to cipher_length. The arguments cipher and cipher_length
 * are provided for compatibility in anticipation of the time when this restriction is lifted.
 *
 * @param[in,out] handle        AES handler (work area)
 * @param[in,out] cipher        ciphertext data area (nothing ever written here)
 * @param[in,out] cipher_length ciphertext data length (0 always written here)
 *
 * @retval FSP_SUCCESS             Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_FAIL An internal error occurred.
 * @retval FSP_ERR_CRYPTO_SCE_PARAMETER         Input data is illegal.
 * @retval FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION An invalid function was called.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES128ECB_EncryptFinal (sce_aes_handle_t * handle, uint8_t * cipher, uint32_t * cipher_length)
{
    if (CALL_ONLY_INIT == handle->flag_call_init)
    {
        return FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION;
    }

    handle->flag_call_init = CALL_ONLY_INIT;
    if (handle->id != g_aes128ecbenc_private_id)
    {
        return FSP_ERR_CRYPTO_SCE_PARAMETER;
    }

    *cipher_length = 0;
    memset(handle, 0, sizeof(sce_aes_handle_t));

    /* Casting uint32_t pointer is used for address. */
    return R_SCE_Aes128EcbEncryptFinalPrivate((uint32_t *) (cipher), cipher_length);
}

/*******************************************************************************************************************//**
 * The R_SCE_AES128ECB_DecryptInit() function performs preparations for the execution of an AES calculation,
 * and writes the result to the first argument, handle. The value of handle is used as an argument
 * in the subsequent R_SCE_AES128ECB_DecryptUpdate() function and R_SCE_AES128ECB_DecryptFinal() function.
 *
 * @param[in,out] handle      AES handler (work area)
 * @param[in]     wrapped_key 128-bit AES wrapped key
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource needed
 *                                              by the processing routine was in use by another processing routine.
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL      Input illegal wrapped key.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              Internal error occurred.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES128ECB_DecryptInit (sce_aes_handle_t * handle, sce_aes_wrapped_key_t * wrapped_key)
{
    memset(handle, 0, sizeof(sce_aes_handle_t));
    handle->flag_call_init = CALL_ONLY_UPDATE_FINAL;
    g_private_id_counter++;
    g_aes128ecbdec_private_id = g_private_id_counter;
    handle->id                = g_aes128ecbdec_private_id;

    return R_SCE_Aes128EcbDecryptInitPrivate(wrapped_key);
}

/*******************************************************************************************************************//**
 * The R_SCE_AES128ECB_DecryptUpdate() function decrypts the second argument, cipher, utilizing the key index stored
 * in the handle specified in the first argument, handle, and writes the ongoing status to this first argument.
 * In addition, it writes the decryption result to the third argument, plain. After plaintext input is completed,
 * call R_SCE_AES128ECB_DecryptFinal().
 *
 * Specify areas for plain and cipher that do not overlap. For plain and cipher,
 * specify RAM addresses that are multiples of 4.
 *
 * @param[in,out] handle        AES handler (work area)
 * @param[in]     cipher        ciphertext data area
 * @param[in,out] plain         plaintext data area
 * @param[in,out] cipher_length ciphertext data length (must be a multiple of 16)
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_PARAMETER         Input data is illegal.
 * @retval FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION An invalid function was called.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES128ECB_DecryptUpdate (sce_aes_handle_t * handle,
        uint8_t          * cipher,
        uint8_t          * plain,
        uint32_t           cipher_length)
{
    if (CALL_ONLY_INIT == handle->flag_call_init)
    {
        return FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION;
    }

    if (handle->id != g_aes128ecbdec_private_id)
    {
        return FSP_ERR_CRYPTO_SCE_PARAMETER;
    }

    handle->current_input_data_size = cipher_length;
    memcpy(handle->last_1_block_as_fraction,
            (cipher + ((cipher_length / HW_SCE_AES_BLOCK_BYTE_SIZE) * HW_SCE_AES_BLOCK_BYTE_SIZE)),
            (cipher_length % HW_SCE_AES_BLOCK_BYTE_SIZE));

    /* Casting uint32_t pointer is used for address. */
    return R_SCE_Aes128EcbDecryptUpdatePrivate((uint32_t *) (cipher), (uint32_t *) (plain), cipher_length >> 2);
}

/*******************************************************************************************************************//**
 * Using the handle specified in the first argument, handle, the R_SCE_AES128ECB_DecryptFinal() function writes
 * the calculation result to the second argument, plain, and writes the length of the calculation result
 * to the third argument, plain_length. The original intent was for a portion of the decryption
 * result that was not a multiple of 16 bytes to be written to the second argument.
 * However, as a result of the restriction that only multiples of 16 can be input to the Update function,
 * nothing is ever written to plain, and 0 is always written to plain_length. The arguments plain and plain_length
 * are provided for compatibility in anticipation of the time when this restriction is lifted.
 *
 * @param[in,out] handle       AES handler (work area)
 * @param[in,out] plain        plaintext data area (nothing ever written here)
 * @param[in,out] plain_length plaintext data length (0 always written here)
 *
 * @retval FSP_SUCCESS             Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_FAIL An internal error occurred.
 * @retval FSP_ERR_CRYPTO_SCE_PARAMETER         Input data is illegal.
 * @retval FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION An invalid function was called.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES128ECB_DecryptFinal (sce_aes_handle_t * handle, uint8_t * plain, uint32_t * plain_length)
{
    if (CALL_ONLY_INIT == handle->flag_call_init)
    {
        return FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION;
    }

    handle->flag_call_init = CALL_ONLY_INIT;
    if (handle->id != g_aes128ecbdec_private_id)
    {
        return FSP_ERR_CRYPTO_SCE_PARAMETER;
    }

    *plain_length = 0;
    memset(handle, 0, sizeof(sce_aes_handle_t));

    /* Casting uint32_t pointer is used for address. */
    return R_SCE_Aes128EcbDecryptFinalPrivate((uint32_t *) (plain), plain_length);
}

/*******************************************************************************************************************//**
 * The R_SCE_AES256ECB_EncryptInit() function performs preparations for the execution of an AES calculation,
 * and writes the result to the first argument, handle. The value of handle is used as an argument
 * in the subsequent R_SCE_AES256ECB_EncryptUpdate() function and R_SCE_AES256ECB_EncryptFinal() function.
 *
 * @param[in,out] handle      AES handler (work area)
 * @param[in]     wrapped_key 128-bit AES wrapped key
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource needed
 *                                              by the processing routine was in use by another processing routine.
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL      Input illegal wrapped key.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              Internal error occurred.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES256ECB_EncryptInit (sce_aes_handle_t * handle, sce_aes_wrapped_key_t * wrapped_key)
{
    memset(handle, 0, sizeof(sce_aes_handle_t));
    handle->flag_call_init = CALL_ONLY_UPDATE_FINAL;
    g_private_id_counter++;
    g_aes256ecbenc_private_id = g_private_id_counter;
    handle->id                = g_aes256ecbenc_private_id;

    return R_SCE_Aes256EcbEncryptInitPrivate(wrapped_key);
}

/*******************************************************************************************************************//**
 * The R_SCE_AES256ECB_EncryptUpdate() function encrypts the second argument, plain, utilizing the key index stored
 * in the handle specified in the first argument, handle, and writes the ongoing status to this first argument.
 * In addition, it writes the encryption result to the third argument, cipher. After plaintext input is completed,
 * call R_SCE_AES256ECB_EncryptFinal().
 *
 * Specify areas for plain and cipher that do not overlap. For plain and cipher,
 * specify RAM addresses that are multiples of 4.
 *
 * @param[in,out] handle       AES handler (work area)
 * @param[in]     plain        plaintext data area
 * @param[in,out] cipher       ciphertext data area
 * @param[in,out] plain_length plaintext data length (must be a multiple of 16)
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_PARAMETER         Input data is illegal.
 * @retval FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION An invalid function was called.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES256ECB_EncryptUpdate (sce_aes_handle_t * handle,
        uint8_t          * plain,
        uint8_t          * cipher,
        uint32_t           plain_length)
{
    if (CALL_ONLY_INIT == handle->flag_call_init)
    {
        return FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION;
    }

    if (handle->id != g_aes256ecbenc_private_id)
    {
        return FSP_ERR_CRYPTO_SCE_PARAMETER;
    }

    handle->current_input_data_size = plain_length;
    memcpy(handle->last_1_block_as_fraction,
            (plain + ((plain_length / HW_SCE_AES_BLOCK_BYTE_SIZE) * HW_SCE_AES_BLOCK_BYTE_SIZE)),
            (plain_length % HW_SCE_AES_BLOCK_BYTE_SIZE));

    /* Casting uint32_t pointer is used for address. */
    return R_SCE_Aes256EcbEncryptUpdatePrivate((uint32_t *) (plain), (uint32_t *) (cipher), plain_length >> 2);
}

/*******************************************************************************************************************//**
 * Using the handle specified in the first argument, handle, the R_SCE_AES256ECB_EncryptFinal() function writes
 * the calculation result to the second argument, cipher, and writes the length of the calculation result
 * to the third argument, cipher_length. The original intent was for a portion of the encryption
 * result that was not a multiple of 16 bytes to be written to the second argument.
 * However, as a result of the restriction that only multiples of 16 can be input to the Update function,
 * nothing is ever written to cipher, and 0 is always written to cipher_length. The arguments cipher and cipher_length
 * are provided for compatibility in anticipation of the time when this restriction is lifted.
 *
 * @param[in,out] handle        AES handler (work area)
 * @param[in,out] cipher        ciphertext data area (nothing ever written here)
 * @param[in,out] cipher_length ciphertext data length (0 always written here)
 *
 * @retval FSP_SUCCESS             Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_FAIL An internal error occurred.
 * @retval FSP_ERR_CRYPTO_SCE_PARAMETER         Input data is illegal.
 * @retval FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION An invalid function was called.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES256ECB_EncryptFinal (sce_aes_handle_t * handle, uint8_t * cipher, uint32_t * cipher_length)
{
    if (CALL_ONLY_INIT == handle->flag_call_init)
    {
        return FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION;
    }

    handle->flag_call_init = CALL_ONLY_INIT;
    if (handle->id != g_aes256ecbenc_private_id)
    {
        return FSP_ERR_CRYPTO_SCE_PARAMETER;
    }

    *cipher_length = 0;
    memset(handle, 0, sizeof(sce_aes_handle_t));

    /* Casting uint32_t pointer is used for address. */
    return R_SCE_Aes256EcbEncryptFinalPrivate((uint32_t *) (cipher), cipher_length);
}

/*******************************************************************************************************************//**
 * The R_SCE_AES256ECB_DecryptInit() function performs preparations for the execution of an AES calculation,
 * and writes the result to the first argument, handle. The value of handle is used as an argument
 * in the subsequent R_SCE_AES128ECB_DecryptUpdate() function and R_SCE_AES128ECB_DecryptFinal() function.
 *
 * @param[in,out] handle      AES handler (work area)
 * @param[in]     wrapped_key 128-bit AES wrapped key
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource needed
 *                                              by the processing routine was in use by another processing routine.
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL      Input illegal wrapped key.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              Internal error occurred.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES256ECB_DecryptInit (sce_aes_handle_t * handle, sce_aes_wrapped_key_t * wrapped_key)
{
    memset(handle, 0, sizeof(sce_aes_handle_t));
    handle->flag_call_init = CALL_ONLY_UPDATE_FINAL;
    g_private_id_counter++;
    g_aes256ecbdec_private_id = g_private_id_counter;
    handle->id                = g_aes256ecbdec_private_id;
    return R_SCE_Aes256EcbDecryptInitPrivate(wrapped_key);
}

/*******************************************************************************************************************//**
 * The R_SCE_AES256ECB_DecryptUpdate() function decrypts the second argument, cipher, utilizing the key index stored
 * in the handle specified in the first argument, handle, and writes the ongoing status to this first argument.
 * In addition, it writes the decryption result to the third argument, plain. After plaintext input is completed,
 * call R_SCE_AES256ECB_DecryptFinal().
 *
 * Specify areas for plain and cipher that do not overlap. For plain and cipher,
 * specify RAM addresses that are multiples of 4.
 *
 * @param[in,out] handle        AES handler (work area)
 * @param[in]     cipher        ciphertext data area
 * @param[in,out] plain         plaintext data area
 * @param[in,out] cipher_length ciphertext data length (must be a multiple of 16)
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_PARAMETER         Input data is illegal.
 * @retval FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION An invalid function was called.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES256ECB_DecryptUpdate (sce_aes_handle_t * handle,
        uint8_t          * cipher,
        uint8_t          * plain,
        uint32_t           cipher_length)
{
    if (CALL_ONLY_INIT == handle->flag_call_init)
    {
        return FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION;
    }

    if (handle->id != g_aes256ecbdec_private_id)
    {
        return FSP_ERR_CRYPTO_SCE_PARAMETER;
    }

    handle->current_input_data_size = cipher_length;
    memcpy(handle->last_1_block_as_fraction,
            (cipher + ((cipher_length / HW_SCE_AES_BLOCK_BYTE_SIZE) * HW_SCE_AES_BLOCK_BYTE_SIZE)),
            (cipher_length % HW_SCE_AES_BLOCK_BYTE_SIZE));

    /* Casting uint32_t pointer is used for address. */
    return R_SCE_Aes256EcbDecryptUpdatePrivate((uint32_t *) (cipher), (uint32_t *) (plain), cipher_length >> 2);
}

/*******************************************************************************************************************//**
 * Using the handle specified in the first argument, handle, the R_SCE_AES256ECB_DecryptFinal() function writes
 * the calculation result to the second argument, plain, and writes the length of the calculation result
 * to the third argument, plain_length. The original intent was for a portion of the decryption
 * result that was not a multiple of 16 bytes to be written to the second argument.
 * However, as a result of the restriction that only multiples of 16 can be input to the Update function,
 * nothing is ever written to plain, and 0 is always written to plain_length. The arguments plain and plain_length
 * are provided for compatibility in anticipation of the time when this restriction is lifted.
 *
 * @param[in,out] handle       AES handler (work area)
 * @param[in,out] plain        plaintext data area (nothing ever written here)
 * @param[in,out] plain_length plaintext data length (0 always written here)
 *
 * @retval FSP_SUCCESS             Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_FAIL An internal error occurred.
 * @retval FSP_ERR_CRYPTO_SCE_PARAMETER         Input data is illegal.
 * @retval FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION An invalid function was called.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES256ECB_DecryptFinal (sce_aes_handle_t * handle, uint8_t * plain, uint32_t * plain_length)
{
    if (CALL_ONLY_INIT == handle->flag_call_init)
    {
        return FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION;
    }

    handle->flag_call_init = CALL_ONLY_INIT;
    if (handle->id != g_aes256ecbdec_private_id)
    {
        return FSP_ERR_CRYPTO_SCE_PARAMETER;
    }

    *plain_length = 0;
    memset(handle, 0, sizeof(sce_aes_handle_t));

    /* Casting uint32_t pointer is used for address. */
    return R_SCE_Aes256EcbDecryptFinalPrivate((uint32_t *) (plain), plain_length);
}

/*******************************************************************************************************************//**
 * The R_SCE_AES128CBC_EncryptInit() function performs preparations for the execution of an AES calculation,
 * and writes the result to the first argument, handle. The value of handle is used as an argument
 * in the subsequent R_SCE_AES128CBC_EncryptUpdate() function and R_SCE_AES128CBC_EncryptFinal() function.
 *
 * @param[in,out] handle         AES handler (work area)
 * @param[in]     wrapped_key    128-bit AES wrapped key
 * @param[in]     initial_vector initialization vector area (16byte)
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource needed
 *                                              by the processing routine was in use by another processing routine.
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL      Input illegal wrapped key.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              Internal error occurred.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES128CBC_EncryptInit (sce_aes_handle_t      * handle,
        sce_aes_wrapped_key_t * wrapped_key,
        uint8_t               * initial_vector)
{
    memset(handle, 0, sizeof(sce_aes_handle_t));
    handle->flag_call_init = CALL_ONLY_UPDATE_FINAL;
    g_private_id_counter++;
    g_aes128cbcenc_private_id = g_private_id_counter;
    handle->id                = g_aes128cbcenc_private_id;
    memcpy(handle->current_initial_vector, initial_vector, sizeof(handle->current_initial_vector));

    /* Casting uint32_t pointer is used for address. */
    return R_SCE_Aes128CbcEncryptInitPrivate(wrapped_key, (uint32_t *) (initial_vector));
}

/*******************************************************************************************************************//**
 * The R_SCE_AES128CBC_EncryptUpdate() function encrypts the second argument, plain, utilizing the key index stored
 * in the handle specified in the first argument, handle, and writes the ongoing status to this first argument.
 * In addition, it writes the encryption result to the third argument, cipher. After plaintext input is completed,
 * call R_SCE_AES128CBC_EncryptFinal().
 *
 * Specify areas for plain and cipher that do not overlap. For plain and cipher,
 * specify RAM addresses that are multiples of 4.
 *
 * @param[in,out] handle       AES handler (work area)
 * @param[in]     plain        plaintext data area
 * @param[in,out] cipher       ciphertext data area
 * @param[in,out] plain_length plaintext data length (must be a multiple of 16)
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_PARAMETER         Input data is illegal.
 * @retval FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION An invalid function was called.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES128CBC_EncryptUpdate (sce_aes_handle_t * handle,
        uint8_t          * plain,
        uint8_t          * cipher,
        uint32_t           plain_length)
{
    if (CALL_ONLY_INIT == handle->flag_call_init)
    {
        return FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION;
    }

    if (handle->id != g_aes128cbcenc_private_id)
    {
        return FSP_ERR_CRYPTO_SCE_PARAMETER;
    }

    handle->current_input_data_size = plain_length;
    memcpy(handle->last_1_block_as_fraction,
            (plain + ((plain_length / HW_SCE_AES_BLOCK_BYTE_SIZE) * HW_SCE_AES_BLOCK_BYTE_SIZE)),
            (plain_length % HW_SCE_AES_BLOCK_BYTE_SIZE));

    /* Casting uint32_t pointer is used for address. */
    R_SCE_Aes128CbcEncryptUpdatePrivate((uint32_t *) (plain), (uint32_t *) (cipher), plain_length >> 2);
    memcpy(handle->current_initial_vector,
            (cipher + (plain_length - HW_SCE_AES_BLOCK_BYTE_SIZE)),
            HW_SCE_AES_CBC_IV_BYTE_SIZE);

    return FSP_SUCCESS;
}

/*******************************************************************************************************************//**
 * Using the handle specified in the first argument, handle, the R_SCE_AES128CBC_EncryptFinal() function writes
 * the calculation result to the second argument, cipher, and writes the length of the calculation result
 * to the third argument, cipher_length. The original intent was for a portion of the encryption
 * result that was not a multiple of 16 bytes to be written to the second argument.
 * However, as a result of the restriction that only multiples of 16 can be input to the Update function,
 * nothing is ever written to cipher, and 0 is always written to cipher_length. The arguments cipher and cipher_length
 * are provided for compatibility in anticipation of the time when this restriction is lifted.
 *
 * @param[in,out] handle        AES handler (work area)
 * @param[in,out] cipher        ciphertext data area (nothing ever written here)
 * @param[in,out] cipher_length ciphertext data length (0 always written here)
 *
 * @retval FSP_SUCCESS             Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_FAIL An internal error occurred.
 * @retval FSP_ERR_CRYPTO_SCE_PARAMETER         Input data is illegal.
 * @retval FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION An invalid function was called.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES128CBC_EncryptFinal (sce_aes_handle_t * handle, uint8_t * cipher, uint32_t * cipher_length)
{
    if (CALL_ONLY_INIT == handle->flag_call_init)
    {
        return FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION;
    }

    handle->flag_call_init = CALL_ONLY_INIT;
    if (handle->id != g_aes128cbcenc_private_id)
    {
        return FSP_ERR_CRYPTO_SCE_PARAMETER;
    }

    *cipher_length = 0;
    memset(handle, 0, sizeof(sce_aes_handle_t));

    /* Casting uint32_t pointer is used for address. */
    return R_SCE_Aes128CbcEncryptFinalPrivate((uint32_t *) (cipher), cipher_length);
}

/*******************************************************************************************************************//**
 * The R_SCE_AES128CBC_DecryptInit() function performs preparations for the execution of an AES calculation,
 * and writes the result to the first argument, handle. The value of handle is used as an argument
 * in the subsequent R_SCE_AES128CBC_DecryptUpdate() function and R_SCE_AES128CBC_DecryptFinal() function.
 *
 * @param[in,out] handle         AES handler (work area)
 * @param[in]     wrapped_key    128-bit AES wrapped key
 * @param[in]     initial_vector initialization vector area (16byte)
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource needed
 *                                              by the processing routine was in use by another processing routine.
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL      Input illegal wrapped key.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              Internal error occurred.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES128CBC_DecryptInit (sce_aes_handle_t      * handle,
        sce_aes_wrapped_key_t * wrapped_key,
        uint8_t               * initial_vector)
{
    memset(handle, 0, sizeof(sce_aes_handle_t));
    handle->flag_call_init = CALL_ONLY_UPDATE_FINAL;
    g_private_id_counter++;
    g_aes128cbcdec_private_id = g_private_id_counter;
    handle->id                = g_aes128cbcdec_private_id;
    memcpy(handle->current_initial_vector, initial_vector, sizeof(handle->current_initial_vector));

    /* Casting uint32_t pointer is used for address. */
    return R_SCE_Aes128CbcDecryptInitPrivate(wrapped_key, (uint32_t *) (handle->current_initial_vector));
}

/*******************************************************************************************************************//**
 * The R_SCE_AES128CBC_DecryptUpdate() function decrypts the second argument, cipher, utilizing the key index stored
 * in the handle specified in the first argument, handle, and writes the ongoing status to this first argument.
 * In addition, it writes the decryption result to the third argument, plain. After plaintext input is completed,
 * call R_SCE_AES128CBC_DecryptFinal().
 *
 * Specify areas for plain and cipher that do not overlap. For plain and cipher,
 * specify RAM addresses that are multiples of 4.
 *
 * @param[in,out] handle        AES handler (work area)
 * @param[in]     cipher        ciphertext data area
 * @param[in,out] plain         plaintext data area
 * @param[in,out] cipher_length ciphertext data length (must be a multiple of 16)
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_PARAMETER         Input data is illegal.
 * @retval FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION An invalid function was called.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES128CBC_DecryptUpdate (sce_aes_handle_t * handle,
        uint8_t          * cipher,
        uint8_t          * plain,
        uint32_t           cipher_length)
{
    if (CALL_ONLY_INIT == handle->flag_call_init)
    {
        return FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION;
    }

    if (handle->id != g_aes128cbcdec_private_id)
    {
        return FSP_ERR_CRYPTO_SCE_PARAMETER;
    }

    handle->current_input_data_size = cipher_length;
    memcpy(handle->last_1_block_as_fraction,
            (cipher + ((cipher_length / HW_SCE_AES_BLOCK_BYTE_SIZE) * HW_SCE_AES_BLOCK_BYTE_SIZE)),
            (cipher_length % HW_SCE_AES_BLOCK_BYTE_SIZE));

    /* Casting uint32_t pointer is used for address. */
    R_SCE_Aes128CbcDecryptUpdatePrivate((uint32_t *) (cipher), (uint32_t *) (plain), cipher_length >> 2);
    memcpy(handle->current_initial_vector,
            (plain + (cipher_length - HW_SCE_AES_BLOCK_BYTE_SIZE)),
            HW_SCE_AES_CBC_IV_BYTE_SIZE);

    return FSP_SUCCESS;
}

/*******************************************************************************************************************//**
 * Using the handle specified in the first argument, handle, the R_SCE_AES128CBC_DecryptFinal() function writes
 * the calculation result to the second argument, plain, and writes the length of the calculation result
 * to the third argument, plain_length. The original intent was for a portion of the decryption
 * result that was not a multiple of 16 bytes to be written to the second argument.
 * However, as a result of the restriction that only multiples of 16 can be input to the Update function,
 * nothing is ever written to plain, and 0 is always written to plain_length. The arguments plain and plain_length
 * are provided for compatibility in anticipation of the time when this restriction is lifted.
 *
 * @param[in,out] handle       AES handler (work area)
 * @param[in,out] plain        plaintext data area (nothing ever written here)
 * @param[in,out] plain_length plaintext data length (0 always written here)
 *
 * @retval FSP_SUCCESS             Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_FAIL An internal error occurred.
 * @retval FSP_ERR_CRYPTO_SCE_PARAMETER         Input data is illegal.
 * @retval FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION An invalid function was called.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES128CBC_DecryptFinal (sce_aes_handle_t * handle, uint8_t * plain, uint32_t * plain_length)
{
    if (CALL_ONLY_INIT == handle->flag_call_init)
    {
        return FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION;
    }

    handle->flag_call_init = CALL_ONLY_INIT;
    if (handle->id != g_aes128cbcdec_private_id)
    {
        return FSP_ERR_CRYPTO_SCE_PARAMETER;
    }

    *plain_length = 0;
    memset(handle, 0, sizeof(sce_aes_handle_t));

    /* Casting uint32_t pointer is used for address. */
    return R_SCE_Aes128CbcDecryptFinalPrivate((uint32_t *) (plain), plain_length);
}

/*******************************************************************************************************************//**
 * The R_SCE_AES256CBC_EncryptInit() function performs preparations for the execution of an AES calculation,
 * and writes the result to the first argument, handle. The value of handle is used as an argument
 * in the subsequent R_SCE_AES256CBC_EncryptUpdate() function and R_SCE_AES256CBC_EncryptFinal() function.
 *
 * @param[in,out] handle         AES handler (work area)
 * @param[in]     wrapped_key    256-bit AES wrapped key
 * @param[in]     initial_vector initial vector area (16byte)
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource needed
 *                                              by the processing routine was in use by another processing routine.
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL      Input illegal wrapped key.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              Internal error occurred.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES256CBC_EncryptInit (sce_aes_handle_t      * handle,
        sce_aes_wrapped_key_t * wrapped_key,
        uint8_t               * initial_vector)
{
    memset(handle, 0, sizeof(sce_aes_handle_t));
    handle->flag_call_init = CALL_ONLY_UPDATE_FINAL;
    g_private_id_counter++;
    g_aes256cbcenc_private_id = g_private_id_counter;
    handle->id                = g_aes256cbcenc_private_id;
    memcpy(handle->current_initial_vector, initial_vector, sizeof(handle->current_initial_vector));

    /* Casting uint32_t pointer is used for address. */
    return R_SCE_Aes256CbcEncryptInitPrivate(wrapped_key, (uint32_t *) (handle->current_initial_vector));
}

/*******************************************************************************************************************//**
 * The R_SCE_AES256CBC_EncryptUpdate() function encrypts the second argument, plain, utilizing the key index stored
 * in the handle specified in the first argument, handle, and writes the ongoing status to this first argument.
 * In addition, it writes the encryption result to the third argument, cipher. After plaintext input is completed,
 * call R_SCE_AES256CBC_EncryptFinal().
 *
 * Specify areas for plain and cipher that do not overlap. For plain and cipher,
 * specify RAM addresses that are multiples of 4.
 *
 * @param[in,out] handle       AES handler (work area)
 * @param[in]     plain        plaintext data area
 * @param[in,out] cipher       ciphertext data area
 * @param[in,out] plain_length plaintext data length (must be a multiple of 16)
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_PARAMETER         Input data is illegal.
 * @retval FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION An invalid function was called.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES256CBC_EncryptUpdate (sce_aes_handle_t * handle,
        uint8_t          * plain,
        uint8_t          * cipher,
        uint32_t           plain_length)
{
    if (CALL_ONLY_INIT == handle->flag_call_init)
    {
        return FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION;
    }

    if (handle->id != g_aes256cbcenc_private_id)
    {
        return FSP_ERR_CRYPTO_SCE_PARAMETER;
    }

    handle->current_input_data_size = plain_length;
    memcpy(handle->last_1_block_as_fraction,
            (plain + ((plain_length / HW_SCE_AES_BLOCK_BYTE_SIZE) * HW_SCE_AES_BLOCK_BYTE_SIZE)),
            (plain_length % HW_SCE_AES_BLOCK_BYTE_SIZE));

    /* Casting uint32_t pointer is used for address. */
    R_SCE_Aes256CbcEncryptUpdatePrivate((uint32_t *) (plain), (uint32_t *) (cipher), plain_length >> 2);
    memcpy(handle->current_initial_vector,
            cipher + (plain_length - HW_SCE_AES_BLOCK_BYTE_SIZE),
            HW_SCE_AES_CBC_IV_BYTE_SIZE);

    return FSP_SUCCESS;
}

/*******************************************************************************************************************//**
 * Using the handle specified in the first argument, handle, the R_SCE_AES256CBC_EncryptFinal() function writes
 * the calculation result to the second argument, cipher, and writes the length of the calculation result
 * to the third argument, cipher_length. The original intent was for a portion of the encryption
 * result that was not a multiple of 16 bytes to be written to the second argument.
 * However, as a result of the restriction that only multiples of 16 can be input to the Update function,
 * nothing is ever written to cipher, and 0 is always written to cipher_length. The arguments cipher and cipher_length
 * are provided for compatibility in anticipation of the time when this restriction is lifted.
 *
 * @param[in,out] handle        AES handler (work area)
 * @param[in,out] cipher        ciphertext data area (nothing ever written here)
 * @param[in,out] cipher_length ciphertext data length (0 always written here)
 *
 * @retval FSP_SUCCESS             Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_FAIL An internal error occurred.
 * @retval FSP_ERR_CRYPTO_SCE_PARAMETER         Input data is illegal.
 * @retval FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION An invalid function was called.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES256CBC_EncryptFinal (sce_aes_handle_t * handle, uint8_t * cipher, uint32_t * cipher_length)
{
    if (CALL_ONLY_INIT == handle->flag_call_init)
    {
        return FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION;
    }

    handle->flag_call_init = CALL_ONLY_INIT;
    if (handle->id != g_aes256cbcenc_private_id)
    {
        return FSP_ERR_CRYPTO_SCE_PARAMETER;
    }

    *cipher_length = 0;
    memset(handle, 0, sizeof(sce_aes_handle_t));

    /* Casting uint32_t pointer is used for address. */
    return R_SCE_Aes256CbcEncryptFinalPrivate((uint32_t *) (cipher), cipher_length);
}

/*******************************************************************************************************************//**
 * The R_SCE_AES256CBC_DecryptInit() function performs preparations for the execution of an AES calculation,
 * and writes the result to the first argument, handle. The value of handle is used as an argument
 * in the subsequent R_SCE_AES256CBC_DecryptUpdate() function and R_SCE_AES256CBC_DecryptFinal() function.
 *
 * @param[in,out] handle         AES handler (work area)
 * @param[in]     wrapped_key    256-bit AES wrapped key
 * @param[in]     initial_vector initialization vector area (16byte)
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource needed
 *                                              by the processing routine was in use by another processing routine.
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL      Input illegal wrapped key.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              Internal error occurred.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES256CBC_DecryptInit (sce_aes_handle_t      * handle,
        sce_aes_wrapped_key_t * wrapped_key,
        uint8_t               * initial_vector)
{
    memset(handle, 0, sizeof(sce_aes_handle_t));
    handle->flag_call_init = CALL_ONLY_UPDATE_FINAL;
    g_private_id_counter++;
    g_aes256cbcdec_private_id = g_private_id_counter;
    handle->id                = g_aes256cbcdec_private_id;
    memcpy(handle->current_initial_vector, initial_vector, sizeof(handle->current_initial_vector));

    /* Casting uint32_t pointer is used for address. */
    return R_SCE_Aes256CbcDecryptInitPrivate(wrapped_key, (uint32_t *) (handle->current_initial_vector));
}

/*******************************************************************************************************************//**
 * The R_SCE_AES256CBC_DecryptUpdate() function decrypts the second argument, cipher, utilizing the key index stored
 * in the handle specified in the first argument, handle, and writes the ongoing status to this first argument.
 * In addition, it writes the decryption result to the third argument, plain. After plaintext input is completed,
 * call R_SCE_AES256CBC_DecryptFinal().
 *
 * Specify areas for plain and cipher that do not overlap. For plain and cipher,
 * specify RAM addresses that are multiples of 4.
 *
 * @param[in,out] handle        AES handler (work area)
 * @param[in]     cipher        ciphertext data area
 * @param[in,out] plain         plaintext data area
 * @param[in,out] cipher_length ciphertext data length (must be a multiple of 16)
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_PARAMETER         Input data is illegal.
 * @retval FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION An invalid function was called.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES256CBC_DecryptUpdate (sce_aes_handle_t * handle,
        uint8_t          * cipher,
        uint8_t          * plain,
        uint32_t           cipher_length)
{
    if (CALL_ONLY_INIT == handle->flag_call_init)
    {
        return FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION;
    }

    if (handle->id != g_aes256cbcdec_private_id)
    {
        return FSP_ERR_CRYPTO_SCE_PARAMETER;
    }

    handle->current_input_data_size = cipher_length;
    memcpy(handle->last_1_block_as_fraction,
            (cipher + ((cipher_length / HW_SCE_AES_BLOCK_BYTE_SIZE) * HW_SCE_AES_BLOCK_BYTE_SIZE)),
            (cipher_length % HW_SCE_AES_BLOCK_BYTE_SIZE));

    /* Casting uint32_t pointer is used for address. */
    R_SCE_Aes256CbcDecryptUpdatePrivate((uint32_t *) (cipher), (uint32_t *) (plain), cipher_length >> 2);
    memcpy(handle->current_initial_vector,
            plain + (cipher_length - HW_SCE_AES_BLOCK_BYTE_SIZE),
            HW_SCE_AES_CBC_IV_BYTE_SIZE);

    return FSP_SUCCESS;
}

/*******************************************************************************************************************//**
 * Using the handle specified in the first argument, handle, the R_SCE_AES256CBC_DecryptFinal() function writes
 * the calculation result to the second argument, plain, and writes the length of the calculation result
 * to the third argument, plain_length. The original intent was for a portion of the decryption
 * result that was not a multiple of 16 bytes to be written to the second argument.
 * However, as a result of the restriction that only multiples of 16 can be input to the Update function,
 * nothing is ever written to plain, and 0 is always written to plain_length. The arguments plain and plain_length
 * are provided for compatibility in anticipation of the time when this restriction is lifted.
 *
 * @param[in,out] handle       AES handler (work area)
 * @param[in,out] plain        plaintext data area (nothing ever written here)
 * @param[in,out] plain_length plaintext data length (0 always written here)
 *
 * @retval FSP_SUCCESS             Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_FAIL An internal error occurred.
 * @retval FSP_ERR_CRYPTO_SCE_PARAMETER         Input data is illegal.
 * @retval FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION An invalid function was called.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES256CBC_DecryptFinal (sce_aes_handle_t * handle, uint8_t * plain, uint32_t * plain_length)
{
    if (CALL_ONLY_INIT == handle->flag_call_init)
    {
        return FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION;
    }

    handle->flag_call_init = CALL_ONLY_INIT;
    if (handle->id != g_aes256cbcdec_private_id)
    {
        return FSP_ERR_CRYPTO_SCE_PARAMETER;
    }

    *plain_length = 0;
    memset(handle, 0, sizeof(sce_aes_handle_t));

    /* Casting uint32_t pointer is used for address. */
    return R_SCE_Aes256CbcDecryptFinalPrivate((uint32_t *) (plain), plain_length);
}

/*******************************************************************************************************************//**
 * The R_SCE_AES128CTR_EncryptInit() function performs preparations for the execution of an AES calculation,
 * and writes the result to the first argument, handle. The value of handle is used as an argument
 * in the subsequent R_SCE_AES128CTR_EncryptUpdate() function and R_SCE_AES128CTR_EncryptFinal() function.
 *
 * @param[in,out] handle         AES handler (work area)
 * @param[in]     wrapped_key    128-bit AES wrapped key
 * @param[in]     initial_vector initialization vector area (16byte)
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource needed
 *                                              by the processing routine was in use by another processing routine.
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL      Input illegal wrapped key.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              Internal error occurred.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES128CTR_EncryptInit (sce_aes_handle_t      * handle,
        sce_aes_wrapped_key_t * wrapped_key,
        uint8_t               * initial_vector)
{
    memset(handle, 0, sizeof(sce_aes_handle_t));
    handle->flag_call_init = CALL_ONLY_UPDATE_FINAL;
    g_private_id_counter++;
    g_aes128ctrenc_private_id = g_private_id_counter;
    handle->id                = g_aes128ctrenc_private_id;
    memcpy(handle->current_initial_vector, initial_vector, sizeof(handle->current_initial_vector));

    /* Casting uint32_t pointer is used for address. */
    return R_SCE_Aes128CtrEncryptInitPrivate(wrapped_key, (uint32_t *) (initial_vector));
}

/*******************************************************************************************************************//**
 * The R_SCE_AES128CTR_EncryptUpdate() function encrypts the second argument, plain, utilizing the key index stored
 * in the handle specified in the first argument, handle, and writes the ongoing status to this first argument.
 * In addition, it writes the encryption result to the third argument, cipher. After plaintext input is completed,
 * call R_SCE_AES128CTR_EncryptFinal().
 *
 * Specify areas for plain and cipher that do not overlap. For plain and cipher,
 * specify RAM addresses that are multiples of 4.
 *
 * @param[in,out] handle       AES handler (work area)
 * @param[in]     plain        plaintext data area
 * @param[in,out] cipher       ciphertext data area
 * @param[in,out] plain_length plaintext data length (must be a multiple of 16)
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_PARAMETER         Input data is illegal.
 * @retval FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION An invalid function was called.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES128CTR_EncryptUpdate (sce_aes_handle_t * handle,
        uint8_t          * plain,
        uint8_t          * cipher,
        uint32_t           plain_length)
{
    uint32_t block_num = (plain_length / HW_SCE_AES_BLOCK_BYTE_SIZE);
    if (CALL_ONLY_INIT == handle->flag_call_init)
    {
        return FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION;
    }

    if (handle->id != g_aes128ctrenc_private_id)
    {
        return FSP_ERR_CRYPTO_SCE_PARAMETER;
    }

    handle->current_input_data_size = plain_length;
    memcpy(handle->last_1_block_as_fraction,
            (plain + ((plain_length / HW_SCE_AES_BLOCK_BYTE_SIZE) * HW_SCE_AES_BLOCK_BYTE_SIZE)),
            (plain_length % HW_SCE_AES_BLOCK_BYTE_SIZE));

    /* Casting uint32_t pointer is used for address. */
    R_SCE_Aes128CtrEncryptUpdatePrivate((uint32_t *) (plain), (uint32_t *) (cipher), plain_length >> 2);
    cal_current_ivec_ctrmode(handle, block_num);

    return FSP_SUCCESS;
}

/*******************************************************************************************************************//**
 * Using the handle specified in the first argument, handle, the R_SCE_AES128CTR_EncryptFinal() function writes
 * the calculation result to the second argument, cipher, and writes the length of the calculation result
 * to the third argument, cipher_length. The original intent was for a portion of the encryption
 * result that was not a multiple of 16 bytes to be written to the second argument.
 * However, as a result of the restriction that only multiples of 16 can be input to the Update function,
 * nothing is ever written to cipher, and 0 is always written to cipher_length. The arguments cipher and cipher_length
 * are provided for compatibility in anticipation of the time when this restriction is lifted.
 *
 * @param[in,out] handle        AES handler (work area)
 * @param[in,out] cipher        ciphertext data area (nothing ever written here)
 * @param[in,out] cipher_length ciphertext data length (0 always written here)
 *
 * @retval FSP_SUCCESS             Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_FAIL An internal error occurred.
 * @retval FSP_ERR_CRYPTO_SCE_PARAMETER         Input data is illegal.
 * @retval FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION An invalid function was called.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES128CTR_EncryptFinal (sce_aes_handle_t * handle, uint8_t * cipher, uint32_t * cipher_length)
{
    if (CALL_ONLY_INIT == handle->flag_call_init)
    {
        return FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION;
    }

    handle->flag_call_init = CALL_ONLY_INIT;
    if (handle->id != g_aes128ctrenc_private_id)
    {
        return FSP_ERR_CRYPTO_SCE_PARAMETER;
    }

    *cipher_length = 0;
    memset(handle, 0, sizeof(sce_aes_handle_t));

    /* Casting uint32_t pointer is used for address. */
    return R_SCE_Aes128CtrEncryptFinalPrivate((uint32_t *) (cipher), cipher_length);
}

/*******************************************************************************************************************//**
 * The R_SCE_AES128CTR_DecryptInit() function performs preparations for the execution of an AES calculation,
 * and writes the result to the first argument, handle. The value of handle is used as an argument
 * in the subsequent R_SCE_AES128CTR_DecryptUpdate() function and R_SCE_AES128CTR_DecryptFinal() function.
 *
 * @param[in,out] handle         AES handler (work area)
 * @param[in]     wrapped_key    128-bit AES wrapped key
 * @param[in]     initial_vector initialization vector area (16byte)
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource needed
 *                                              by the processing routine was in use by another processing routine.
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL      Input illegal wrapped key.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              Internal error occurred.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES128CTR_DecryptInit (sce_aes_handle_t      * handle,
        sce_aes_wrapped_key_t * wrapped_key,
        uint8_t               * initial_vector)
{
    memset(handle, 0, sizeof(sce_aes_handle_t));
    handle->flag_call_init = CALL_ONLY_UPDATE_FINAL;
    g_private_id_counter++;
    g_aes128ctrdec_private_id = g_private_id_counter;
    handle->id                = g_aes128ctrdec_private_id;
    memcpy(handle->current_initial_vector, initial_vector, sizeof(handle->current_initial_vector));

    /* Casting uint32_t pointer is used for address. */
    return R_SCE_Aes128CtrDecryptInitPrivate(wrapped_key, (uint32_t *) (handle->current_initial_vector));
}

/*******************************************************************************************************************//**
 * The R_SCE_AES128CTR_DecryptUpdate() function decrypts the second argument, cipher, utilizing the key index stored
 * in the handle specified in the first argument, handle, and writes the ongoing status to this first argument.
 * In addition, it writes the decryption result to the third argument, plain. After plaintext input is completed,
 * call R_SCE_AES128CTR_DecryptFinal().
 *
 * Specify areas for plain and cipher that do not overlap. For plain and cipher,
 * specify RAM addresses that are multiples of 4.
 *
 * @param[in,out] handle        AES handler (work area)
 * @param[in]     cipher        ciphertext data area
 * @param[in,out] plain         plaintext data area
 * @param[in,out] cipher_length ciphertext data length (must be a multiple of 16)
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_PARAMETER         Input data is illegal.
 * @retval FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION An invalid function was called.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES128CTR_DecryptUpdate (sce_aes_handle_t * handle,
        uint8_t          * cipher,
        uint8_t          * plain,
        uint32_t           cipher_length)
{
    uint32_t block_num = (cipher_length / HW_SCE_AES_BLOCK_BYTE_SIZE);
    if (CALL_ONLY_INIT == handle->flag_call_init)
    {
        return FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION;
    }

    if (handle->id != g_aes128ctrdec_private_id)
    {
        return FSP_ERR_CRYPTO_SCE_PARAMETER;
    }

    handle->current_input_data_size = cipher_length;
    memcpy(handle->last_1_block_as_fraction,
            (cipher + ((cipher_length / HW_SCE_AES_BLOCK_BYTE_SIZE) * HW_SCE_AES_BLOCK_BYTE_SIZE)),
            (cipher_length % HW_SCE_AES_BLOCK_BYTE_SIZE));

    /* Casting uint32_t pointer is used for address. */
    R_SCE_Aes128CtrDecryptUpdatePrivate((uint32_t *) (cipher), (uint32_t *) (plain), cipher_length >> 2);
    cal_current_ivec_ctrmode(handle, block_num);

    return FSP_SUCCESS;
}

/*******************************************************************************************************************//**
 * Using the handle specified in the first argument, handle, the R_SCE_AES128CTR_DecryptFinal() function writes
 * the calculation result to the second argument, plain, and writes the length of the calculation result
 * to the third argument, plain_length. The original intent was for a portion of the decryption
 * result that was not a multiple of 16 bytes to be written to the second argument.
 * However, as a result of the restriction that only multiples of 16 can be input to the Update function,
 * nothing is ever written to plain, and 0 is always written to plain_length. The arguments plain and plain_length
 * are provided for compatibility in anticipation of the time when this restriction is lifted.
 *
 * @param[in,out] handle       AES handler (work area)
 * @param[in,out] plain        plaintext data area (nothing ever written here)
 * @param[in,out] plain_length plaintext data length (0 always written here)
 *
 * @retval FSP_SUCCESS             Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_FAIL An internal error occurred.
 * @retval FSP_ERR_CRYPTO_SCE_PARAMETER         Input data is illegal.
 * @retval FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION An invalid function was called.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES128CTR_DecryptFinal (sce_aes_handle_t * handle, uint8_t * plain, uint32_t * plain_length)
{
    if (CALL_ONLY_INIT == handle->flag_call_init)
    {
        return FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION;
    }

    handle->flag_call_init = CALL_ONLY_INIT;
    if (handle->id != g_aes128ctrdec_private_id)
    {
        return FSP_ERR_CRYPTO_SCE_PARAMETER;
    }

    *plain_length = 0;
    memset(handle, 0, sizeof(sce_aes_handle_t));

    /* Casting uint32_t pointer is used for address. */
    return R_SCE_Aes128CtrDecryptFinalPrivate((uint32_t *) (plain), plain_length);
}

/*******************************************************************************************************************//**
 * The R_SCE_AES256CTR_EncryptInit() function performs preparations for the execution of an AES calculation,
 * and writes the result to the first argument, handle. The value of handle is used as an argument
 * in the subsequent R_SCE_AES256CTR_EncryptUpdate() function and R_SCE_AES256CTR_EncryptFinal() function.
 *
 * @param[in,out] handle         AES handler (work area)
 * @param[in]     wrapped_key    256-bit AES wrapped key
 * @param[in]     initial_vector initial vector area (16byte)
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource needed
 *                                              by the processing routine was in use by another processing routine.
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL      Input illegal wrapped key.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              Internal error occurred.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES256CTR_EncryptInit (sce_aes_handle_t      * handle,
        sce_aes_wrapped_key_t * wrapped_key,
        uint8_t               * initial_vector)
{
    memset(handle, 0, sizeof(sce_aes_handle_t));
    handle->flag_call_init = CALL_ONLY_UPDATE_FINAL;
    g_private_id_counter++;
    g_aes256ctrenc_private_id = g_private_id_counter;
    handle->id                = g_aes256ctrenc_private_id;
    memcpy(handle->current_initial_vector, initial_vector, sizeof(handle->current_initial_vector));

    /* Casting uint32_t pointer is used for address. */
    return R_SCE_Aes256CtrEncryptInitPrivate(wrapped_key, (uint32_t *) (handle->current_initial_vector));
}

/*******************************************************************************************************************//**
 * The R_SCE_AES256CTR_EncryptUpdate() function encrypts the second argument, plain, utilizing the key index stored
 * in the handle specified in the first argument, handle, and writes the ongoing status to this first argument.
 * In addition, it writes the encryption result to the third argument, cipher. After plaintext input is completed,
 * call R_SCE_AES256CTR_EncryptFinal().
 *
 * Specify areas for plain and cipher that do not overlap. For plain and cipher,
 * specify RAM addresses that are multiples of 4.
 *
 * @param[in,out] handle       AES handler (work area)
 * @param[in]     plain        plaintext data area
 * @param[in,out] cipher       ciphertext data area
 * @param[in,out] plain_length plaintext data length (must be a multiple of 16)
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_PARAMETER         Input data is illegal.
 * @retval FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION An invalid function was called.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES256CTR_EncryptUpdate (sce_aes_handle_t * handle,
        uint8_t          * plain,
        uint8_t          * cipher,
        uint32_t           plain_length)
{
    uint32_t block_num = (plain_length / HW_SCE_AES_BLOCK_BYTE_SIZE);
    if (CALL_ONLY_INIT == handle->flag_call_init)
    {
        return FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION;
    }

    if (handle->id != g_aes256ctrenc_private_id)
    {
        return FSP_ERR_CRYPTO_SCE_PARAMETER;
    }

    handle->current_input_data_size = plain_length;
    memcpy(handle->last_1_block_as_fraction,
            (plain + ((plain_length / HW_SCE_AES_BLOCK_BYTE_SIZE) * HW_SCE_AES_BLOCK_BYTE_SIZE)),
            (plain_length % HW_SCE_AES_BLOCK_BYTE_SIZE));

    /* Casting uint32_t pointer is used for address. */
    R_SCE_Aes256CtrEncryptUpdatePrivate((uint32_t *) (plain), (uint32_t *) (cipher), plain_length >> 2);
    cal_current_ivec_ctrmode(handle, block_num);

    return FSP_SUCCESS;
}

/*******************************************************************************************************************//**
 * Using the handle specified in the first argument, handle, the R_SCE_AES256CTR_EncryptFinal() function writes
 * the calculation result to the second argument, cipher, and writes the length of the calculation result
 * to the third argument, cipher_length. The original intent was for a portion of the encryption
 * result that was not a multiple of 16 bytes to be written to the second argument.
 * However, as a result of the restriction that only multiples of 16 can be input to the Update function,
 * nothing is ever written to cipher, and 0 is always written to cipher_length. The arguments cipher and cipher_length
 * are provided for compatibility in anticipation of the time when this restriction is lifted.
 *
 * @param[in,out] handle        AES handler (work area)
 * @param[in,out] cipher        ciphertext data area (nothing ever written here)
 * @param[in,out] cipher_length ciphertext data length (0 always written here)
 *
 * @retval FSP_SUCCESS             Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_FAIL An internal error occurred.
 * @retval FSP_ERR_CRYPTO_SCE_PARAMETER         Input data is illegal.
 * @retval FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION An invalid function was called.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES256CTR_EncryptFinal (sce_aes_handle_t * handle, uint8_t * cipher, uint32_t * cipher_length)
{
    if (CALL_ONLY_INIT == handle->flag_call_init)
    {
        return FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION;
    }

    handle->flag_call_init = CALL_ONLY_INIT;
    if (handle->id != g_aes256ctrenc_private_id)
    {
        return FSP_ERR_CRYPTO_SCE_PARAMETER;
    }

    *cipher_length = 0;
    memset(handle, 0, sizeof(sce_aes_handle_t));

    /* Casting uint32_t pointer is used for address. */
    return R_SCE_Aes256CtrEncryptFinalPrivate((uint32_t *) (cipher), cipher_length);
}

/*******************************************************************************************************************//**
 * The R_SCE_AES256CTR_DecryptInit() function performs preparations for the execution of an AES calculation,
 * and writes the result to the first argument, handle. The value of handle is used as an argument
 * in the subsequent R_SCE_AES256CTR_DecryptUpdate() function and R_SCE_AES256CTR_DecryptFinal() function.
 *
 * @param[in,out] handle         AES handler (work area)
 * @param[in]     wrapped_key    256-bit AES wrapped key
 * @param[in]     initial_vector initialization vector area (16byte)
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource needed
 *                                              by the processing routine was in use by another processing routine.
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL      Input illegal wrapped key.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              Internal error occurred.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES256CTR_DecryptInit (sce_aes_handle_t      * handle,
        sce_aes_wrapped_key_t * wrapped_key,
        uint8_t               * initial_vector)
{
    memset(handle, 0, sizeof(sce_aes_handle_t));
    handle->flag_call_init = CALL_ONLY_UPDATE_FINAL;
    g_private_id_counter++;
    g_aes256ctrdec_private_id = g_private_id_counter;
    handle->id                = g_aes256ctrdec_private_id;
    memcpy(handle->current_initial_vector, initial_vector, sizeof(handle->current_initial_vector));

    /* Casting uint32_t pointer is used for address. */
    return R_SCE_Aes256CtrDecryptInitPrivate(wrapped_key, (uint32_t *) (handle->current_initial_vector));
}

/*******************************************************************************************************************//**
 * The R_SCE_AES256CTR_DecryptUpdate() function decrypts the second argument, cipher, utilizing the key index stored
 * in the handle specified in the first argument, handle, and writes the ongoing status to this first argument.
 * In addition, it writes the decryption result to the third argument, plain. After plaintext input is completed,
 * call R_SCE_AES256CTR_DecryptFinal().
 *
 * Specify areas for plain and cipher that do not overlap. For plain and cipher,
 * specify RAM addresses that are multiples of 4.
 *
 * @param[in,out] handle        AES handler (work area)
 * @param[in]     cipher        ciphertext data area
 * @param[in,out] plain         plaintext data area
 * @param[in,out] cipher_length ciphertext data length (must be a multiple of 16)
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_PARAMETER         Input data is illegal.
 * @retval FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION An invalid function was called.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES256CTR_DecryptUpdate (sce_aes_handle_t * handle,
        uint8_t          * cipher,
        uint8_t          * plain,
        uint32_t           cipher_length)
{
    uint32_t block_num = (cipher_length / HW_SCE_AES_BLOCK_BYTE_SIZE);
    if (CALL_ONLY_INIT == handle->flag_call_init)
    {
        return FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION;
    }

    if (handle->id != g_aes256ctrdec_private_id)
    {
        return FSP_ERR_CRYPTO_SCE_PARAMETER;
    }

    handle->current_input_data_size = cipher_length;
    memcpy(handle->last_1_block_as_fraction,
            (cipher + ((cipher_length / HW_SCE_AES_BLOCK_BYTE_SIZE) * HW_SCE_AES_BLOCK_BYTE_SIZE)),
            (cipher_length % HW_SCE_AES_BLOCK_BYTE_SIZE));

    /* Casting uint32_t pointer is used for address. */
    R_SCE_Aes256CtrDecryptUpdatePrivate((uint32_t *) (cipher), (uint32_t *) (plain), cipher_length >> 2);
    cal_current_ivec_ctrmode(handle, block_num);

    return FSP_SUCCESS;
}

/*******************************************************************************************************************//**
 * Using the handle specified in the first argument, handle, the R_SCE_AES256CTR_DecryptFinal() function writes
 * the calculation result to the second argument, plain, and writes the length of the calculation result
 * to the third argument, plain_length. The original intent was for a portion of the decryption
 * result that was not a multiple of 16 bytes to be written to the second argument.
 * However, as a result of the restriction that only multiples of 16 can be input to the Update function,
 * nothing is ever written to plain, and 0 is always written to plain_length. The arguments plain and plain_length
 * are provided for compatibility in anticipation of the time when this restriction is lifted.
 *
 * @param[in,out] handle       AES handler (work area)
 * @param[in,out] plain        plaintext data area (nothing ever written here)
 * @param[in,out] plain_length plaintext data length (0 always written here)
 *
 * @retval FSP_SUCCESS             Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_FAIL An internal error occurred.
 * @retval FSP_ERR_CRYPTO_SCE_PARAMETER         Input data is illegal.
 * @retval FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION An invalid function was called.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES256CTR_DecryptFinal (sce_aes_handle_t * handle, uint8_t * plain, uint32_t * plain_length)
{
    if (CALL_ONLY_INIT == handle->flag_call_init)
    {
        return FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION;
    }

    handle->flag_call_init = CALL_ONLY_INIT;
    if (handle->id != g_aes256ctrdec_private_id)
    {
        return FSP_ERR_CRYPTO_SCE_PARAMETER;
    }

    *plain_length = 0;
    memset(handle, 0, sizeof(sce_aes_handle_t));

    /* Casting uint32_t pointer is used for address. */
    return R_SCE_Aes256CtrDecryptFinalPrivate((uint32_t *) (plain), plain_length);
}

/*******************************************************************************************************************//**
 * The R_SCE_AES128CMAC_GenerateInit() function performs preparations for the execution of an CMAC calculation,
 * and writes the result to the first argument, handle. The value of handle is used as an argument in the subsequent
 * R_SCE_AES128CMAC_GenerateUpdate() function and R_SCE_AES128CMAC_GenerateFinal() function.
 *
 * @param[in,out] handle      AES-CMAC handler (work area)
 * @param[in]     wrapped_key 128-bit AES wrapped key
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource needed
 *                                              by the processing routine was in use by another processing routine.
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL      Invalid wrapped key was input.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              Internal error occurred.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES128CMAC_GenerateInit (sce_cmac_handle_t * handle, sce_aes_wrapped_key_t * wrapped_key)
{
    memset(handle, 0, sizeof(sce_cmac_handle_t));
    handle->flag_call_init = CALL_ONLY_UPDATE_FINAL;
    g_private_id_counter++;
    g_aes128cmacgen_private_id = g_private_id_counter;
    handle->id                 = g_aes128cmacgen_private_id;
    memcpy(handle->wrapped_key.value, wrapped_key->value, HW_SCE_AES128_KEY_INDEX_WORD_SIZE * 4);
    memset(handle->cmac_buffer, 0, sizeof(handle->cmac_buffer));

    return R_SCE_Aes128CmacGenerateInitPrivate(wrapped_key);
}

/*******************************************************************************************************************//**
 * The R_SCE_AES128CMAC_GenerateUpdate() function performs MAC value generation based on the message specified
 * in the second argument, message, using the value specified for wrapped_key in R_SCE_AES128CMAC_GenerateInit().
 * Inside this function, the data that is input by the user is buffered until the input value of message
 * exceeds 16 bytes. The length of the message data to input is specified in the third argument, message_len.
 * For these, input not the total byte count for message input data, but rather the message data length
 * to input when the user calls this function. If the input value, message, is not a multiple of 16 bytes,
 * it will be padded within the function. For message, specify a RAM address that are multiples of 4.
 *
 * @param[in,out] handle         AES-CMAC handler (work area)
 * @param[in]     message        message data area (message_length byte)
 * @param[in]     message_length message data length (0 or more bytes)
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_PARAMETER         An invalid handle was input.
 * @retval FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION An invalid function was called.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES128CMAC_GenerateUpdate (sce_cmac_handle_t * handle, uint8_t * message, uint32_t message_length)
{
    uint32_t length_rest = 0;

    if (CALL_ONLY_INIT == handle->flag_call_init)
    {
        return FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION;
    }

    if (handle->id != g_aes128cmacgen_private_id)
    {
        return FSP_ERR_CRYPTO_SCE_PARAMETER;
    }

    handle->all_received_length += message_length;
    if ((handle->buffering_length + message_length) > HW_SCE_AES_BLOCK_BYTE_SIZE)
    {
        memcpy(((&handle->cmac_buffer[0]) + handle->buffering_length),
                message,
                HW_SCE_AES_BLOCK_BYTE_SIZE - handle->buffering_length);

        /* Casting uint32_t pointer is used for address. */
        R_SCE_Aes128CmacGenerateUpdatePrivate((uint32_t *) (handle->cmac_buffer), HW_SCE_AES_BLOCK_BYTE_SIZE >> 2);
        length_rest = message_length - (HW_SCE_AES_BLOCK_BYTE_SIZE - handle->buffering_length);
        memset(handle->cmac_buffer, 0, sizeof(handle->cmac_buffer));
        if (length_rest > HW_SCE_AES_BLOCK_BYTE_SIZE)
        {
            R_SCE_Aes128CmacGenerateUpdatePrivate(
                    /* Casting uint32_t pointer is used for address. */
                    (uint32_t *) (message + (HW_SCE_AES_BLOCK_BYTE_SIZE - handle->buffering_length)),
                    (((length_rest - 1) / HW_SCE_AES_BLOCK_BYTE_SIZE) * HW_SCE_AES_BLOCK_BYTE_SIZE) >> 2);
            length_rest -= (((length_rest - 1) / HW_SCE_AES_BLOCK_BYTE_SIZE) * HW_SCE_AES_BLOCK_BYTE_SIZE);
        }

        handle->buffering_length = 0;
        memcpy(handle->cmac_buffer, message + (message_length - length_rest), length_rest);
        handle->buffering_length = length_rest;
    }
    else
    {
        memcpy((&handle->cmac_buffer[0]) + handle->buffering_length, message, message_length);
        handle->buffering_length += message_length;
    }

    return FSP_SUCCESS;
}

/*******************************************************************************************************************//**
 * The R_SCE_AES128CMAC_GenerateFinal() function outputs the MAC value to the MAC data area specified
 * in the second argument, mac, and ends CMAC mode.
 *
 * @param[in,out] handle AES-CMAC handler (work area)
 * @param[in,out] mac    MAC data area (16byte)
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              An internal error occurred.
 * @retval FSP_ERR_CRYPTO_SCE_PARAMETER         An invalid handle was input.
 * @retval FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION An invalid function was called.
 * @retval FSP_ERR_CRYPTO_SCE_AUTHENTICATION    Not used.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES128CMAC_GenerateFinal (sce_cmac_handle_t * handle, uint8_t * mac)
{
    fsp_err_t ercd = FSP_SUCCESS;

    if (CALL_ONLY_INIT == handle->flag_call_init)
    {
        return FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION;
    }

    handle->flag_call_init = CALL_ONLY_INIT;
    if (handle->id != g_aes128cmacgen_private_id)
    {
        return FSP_ERR_CRYPTO_SCE_PARAMETER;
    }

    if ((0 != (handle->buffering_length % HW_SCE_AES_BLOCK_BYTE_SIZE)) || (0 == handle->all_received_length))
    {
        handle->cmac_buffer[handle->buffering_length] = 1 << 7;
        memset(handle->cmac_buffer + (handle->buffering_length + 1), 0,
                HW_SCE_AES_BLOCK_BYTE_SIZE - (handle->buffering_length + 1));
    }

    ercd = R_SCE_Aes128CmacGenerateFinalPrivate(handle->all_received_length,
            /* Casting uint32_t pointer is used for address. */
            (uint32_t *) (handle->cmac_buffer),
            (uint32_t *) (mac));
    memset(handle, 0, sizeof(sce_cmac_handle_t));

    return ercd;
}

/*******************************************************************************************************************//**
 * The R_SCE_AES128CMAC_VerifyInit() function performs preparations for the execution of a CMAC calculation,
 * and writes the result to the first argument, handle. The value of handle is used as an argumentin the subsequent
 * R_SCE_AES128CMAC_VerifyUpdate() function and R_SCE_AES128CMAC_VerifyFinal() function.
 *
 * @param[in,out] handle      AES-CMAC handler (work area)
 * @param[in]     wrapped_key 128-bit AES wrapped key
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource needed
 *                                              by the processing routine was in use by another processing routine.
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL      Invalid wrapped key was input.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              Internal error occurred.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES128CMAC_VerifyInit (sce_cmac_handle_t * handle, sce_aes_wrapped_key_t * wrapped_key)
{
    memset(handle, 0, sizeof(sce_cmac_handle_t));
    handle->flag_call_init = CALL_ONLY_UPDATE_FINAL;
    g_private_id_counter++;
    g_aes128cmacver_private_id = g_private_id_counter;
    handle->id                 = g_aes128cmacver_private_id;
    memcpy(handle->wrapped_key.value, wrapped_key->value, HW_SCE_AES128_KEY_INDEX_WORD_SIZE * 4);
    memset(handle->cmac_buffer, 0, sizeof(handle->cmac_buffer));

    return R_SCE_Aes128CmacVerifyInitPrivate(wrapped_key);
}

/*******************************************************************************************************************//**
 * The R_SCE_AES128CMAC_VerifyUpdate() function performs MAC value generation based on the message specified
 * in the second argument, message, using the value specified for wrapped_key in R_SCE_AES128CMAC_VerifyInit().
 * Inside this function, the data that is input by the user is buffered until the input value of message
 * exceeds 16 bytes. The length of the message data to input is specified in the third argument, message_len.
 * For these, input not the total byte count for message input data, but rather the message data length to input
 * when the user calls this function. If the input value, message, is not a multiple of 16 bytes,
 * it will be padded within the function. For message, specify a RAM address that are multiples of 4.
 *
 * @param[in,out] handle         AES-CMAC handler (work area)
 * @param[in]     message        message data area (message_length byte)
 * @param[in]     message_length message data length (0 or more bytes)
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_PARAMETER         An invalid handle was input.
 * @retval FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION An invalid function was called.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES128CMAC_VerifyUpdate (sce_cmac_handle_t * handle, uint8_t * message, uint32_t message_length)
{
    uint32_t length_rest = 0;

    if (CALL_ONLY_INIT == handle->flag_call_init)
    {
        return FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION;
    }

    if (handle->id != g_aes128cmacver_private_id)
    {
        return FSP_ERR_CRYPTO_SCE_PARAMETER;
    }

    handle->all_received_length += message_length;
    if ((handle->buffering_length + message_length) > HW_SCE_AES_BLOCK_BYTE_SIZE)
    {
        memcpy(((&handle->cmac_buffer[0]) + handle->buffering_length),
                message,
                HW_SCE_AES_BLOCK_BYTE_SIZE - handle->buffering_length);

        /* Casting uint32_t pointer is used for address. */
        R_SCE_Aes128CmacVerifyUpdatePrivate((uint32_t *) (handle->cmac_buffer), HW_SCE_AES_BLOCK_BYTE_SIZE >> 2);
        length_rest = message_length - (HW_SCE_AES_BLOCK_BYTE_SIZE - handle->buffering_length);
        memset(handle->cmac_buffer, 0, sizeof(handle->cmac_buffer));
        if (length_rest > HW_SCE_AES_BLOCK_BYTE_SIZE)
        {
            R_SCE_Aes128CmacVerifyUpdatePrivate(
                    /* Casting uint32_t pointer is used for address. */
                    (uint32_t *) (message + (HW_SCE_AES_BLOCK_BYTE_SIZE - handle->buffering_length)),
                    (((length_rest - 1) / HW_SCE_AES_BLOCK_BYTE_SIZE) * HW_SCE_AES_BLOCK_BYTE_SIZE) >> 2);
            length_rest -= (((length_rest - 1) / HW_SCE_AES_BLOCK_BYTE_SIZE) * HW_SCE_AES_BLOCK_BYTE_SIZE);
        }

        handle->buffering_length = 0;
        memcpy(handle->cmac_buffer, message + (message_length - length_rest), length_rest);
        handle->buffering_length = length_rest;
    }
    else
    {
        memcpy((&handle->cmac_buffer[0]) + handle->buffering_length, message, message_length);
        handle->buffering_length += message_length;
    }

    return FSP_SUCCESS;
}

/*******************************************************************************************************************//**
 * The R_SCE_AES128CMAC_VerifyFinal() function inputs the MAC value in the MAC data area specified
 * in the second argument, mac, and verifies the MAC value. If authentication fails, the return value will be
 * TSIP_ERR_AUTHENTICATION. If the MAC value is less than 16 bytes, it will be padded with zeros inside the function.
 *
 * @param[in,out] handle     AES-CMAC handler (work area)
 * @param[in,out] mac        MAC data area (mac_length byte)
 * @param[in,out] mac_length MAC data length (2 to 16 bytes)
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              An internal error occurred.
 * @retval FSP_ERR_CRYPTO_SCE_AUTHENTICATION    Authentication failed
 * @retval FSP_ERR_CRYPTO_SCE_PARAMETER         An invalid handle was input.
 * @retval FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION An invalid function was called.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES128CMAC_VerifyFinal (sce_cmac_handle_t * handle, uint8_t * mac, uint32_t mac_length)
{
    fsp_err_t ercd = FSP_SUCCESS;
    uint32_t  mac_tmp[16 / sizeof(uint32_t)] =
    {
            0                              /* mac_tmp is initialized with 0. */
    };
    uint32_t mac_length_bit = 0;

    if (CALL_ONLY_INIT == handle->flag_call_init)
    {
        return FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION;
    }

    handle->flag_call_init = CALL_ONLY_INIT;
    if (handle->id != g_aes128cmacver_private_id)
    {
        return FSP_ERR_CRYPTO_SCE_PARAMETER;
    }

    if ((2 > mac_length) || (mac_length > HW_SCE_AES_BLOCK_BYTE_SIZE))
    {
        return FSP_ERR_CRYPTO_SCE_PARAMETER;
    }

    if ((0 != (handle->buffering_length % HW_SCE_AES_BLOCK_BYTE_SIZE)) || (0 == handle->all_received_length))
    {
        handle->cmac_buffer[handle->buffering_length] = 1 << 7;
        memset(handle->cmac_buffer + (handle->buffering_length + 1), 0,
                HW_SCE_AES_BLOCK_BYTE_SIZE - (handle->buffering_length + 1));
    }

    memcpy(mac_tmp, mac, mac_length);
    mac_length_bit = change_endian_long(mac_length * 8);

    ercd = R_SCE_Aes128CmacVerifyFinalPrivate(handle->all_received_length,
            /* Casting uint32_t pointer is used for address. */
            (uint32_t *) handle->cmac_buffer,
            (uint32_t *) mac_tmp,
            &mac_length_bit);
    memset(handle, 0, sizeof(sce_cmac_handle_t));

    return ercd;
}

/*******************************************************************************************************************//**
 * The R_SCE_AES256CMAC_GenerateInit() function performs preparations for the execution of an CMAC calculation,
 * and writes the result to the first argument, handle. The value of handle is used as an argument in the subsequent
 * R_SCE_AES256CMAC_GenerateUpdate() function and R_SCE_AES256CMAC_GenerateFinal() function.
 *
 * @param[in,out] handle      AES-CMAC handler (work area)
 * @param[in]     wrapped_key 256-bit AES wrapped key
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource needed
 *                                              by the processing routine was in use by another processing routine.
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL      Invalid wrapped key was input.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              Internal error occurred.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES256CMAC_GenerateInit (sce_cmac_handle_t * handle, sce_aes_wrapped_key_t * wrapped_key)
{
    memset(handle, 0, sizeof(sce_cmac_handle_t));
    handle->flag_call_init = CALL_ONLY_UPDATE_FINAL;
    g_private_id_counter++;
    g_aes256cmacgen_private_id = g_private_id_counter;
    handle->id                 = g_aes256cmacgen_private_id;
    memcpy(handle->wrapped_key.value, wrapped_key->value, HW_SCE_AES256_KEY_INDEX_WORD_SIZE * 4);
    memset(handle->cmac_buffer, 0, sizeof(handle->cmac_buffer));

    return R_SCE_Aes256CmacGenerateInitPrivate(wrapped_key);
}

/*******************************************************************************************************************//**
 * The R_SCE_AES256CMAC_GenerateUpdate() function performs MAC value generation based on the message specified
 * in the second argument, message, using the value specified for wrapped_key in R_SCE_AES256CMAC_GenerateInit().
 * Inside this function, the data that is input by the user is buffered until the input value of message
 * exceeds 16 bytes. The length of the message data to input is specified in the third argument, message_len.
 * For these, input not the total byte count for message input data, but rather the message data length
 * to input when the user calls this function. If the input value, message, is not a multiple of 16 bytes,
 * it will be padded within the function. For message, specify a RAM address that are multiples of 4.
 *
 * @param[in,out] handle         AES-CMAC handler (work area)
 * @param[in]     message        message data area (message_length byte)
 * @param[in]     message_length message data length (0 or more bytes)
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_PARAMETER         An invalid handle was input.
 * @retval FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION An invalid function was called.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES256CMAC_GenerateUpdate (sce_cmac_handle_t * handle, uint8_t * message, uint32_t message_length)
{
    uint32_t length_rest = 0;

    if (CALL_ONLY_INIT == handle->flag_call_init)
    {
        return FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION;
    }

    if (handle->id != g_aes256cmacgen_private_id)
    {
        return FSP_ERR_CRYPTO_SCE_PARAMETER;
    }

    handle->all_received_length += message_length;
    if ((handle->buffering_length + message_length) > HW_SCE_AES_BLOCK_BYTE_SIZE)
    {
        memcpy(((&handle->cmac_buffer[0]) + handle->buffering_length),
                message,
                HW_SCE_AES_BLOCK_BYTE_SIZE - handle->buffering_length);

        /* Casting uint32_t pointer is used for address. */
        R_SCE_Aes256CmacGenerateUpdatePrivate((uint32_t *) (handle->cmac_buffer), HW_SCE_AES_BLOCK_BYTE_SIZE >> 2);
        length_rest = message_length - (HW_SCE_AES_BLOCK_BYTE_SIZE - handle->buffering_length);
        memset(handle->cmac_buffer, 0, sizeof(handle->cmac_buffer));
        if (length_rest > HW_SCE_AES_BLOCK_BYTE_SIZE)
        {
            R_SCE_Aes256CmacGenerateUpdatePrivate(
                    /* Casting uint32_t pointer is used for address. */
                    (uint32_t *) (message + (HW_SCE_AES_BLOCK_BYTE_SIZE - handle->buffering_length)),
                    (((length_rest - 1) / HW_SCE_AES_BLOCK_BYTE_SIZE) * HW_SCE_AES_BLOCK_BYTE_SIZE) >> 2);
            length_rest -= (((length_rest - 1) / HW_SCE_AES_BLOCK_BYTE_SIZE) * HW_SCE_AES_BLOCK_BYTE_SIZE);
        }

        handle->buffering_length = 0;
        memcpy(handle->cmac_buffer, message + (message_length - length_rest), length_rest);
        handle->buffering_length = length_rest;
    }
    else
    {
        memcpy((&handle->cmac_buffer[0]) + handle->buffering_length, message, message_length);
        handle->buffering_length += message_length;
    }

    return FSP_SUCCESS;
}

/*******************************************************************************************************************//**
 * The R_SCE_AES256CMAC_GenerateFinal() function outputs the MAC value to the MAC data area specified
 * in the second argument, mac, and ends CMAC mode.
 *
 * @param[in,out] handle AES-CMAC handler (work area)
 * @param[in,out] mac    MAC data area (16byte)
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              An internal error occurred.
 * @retval FSP_ERR_CRYPTO_SCE_PARAMETER         An invalid handle was input.
 * @retval FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION An invalid function was called.
 * @retval FSP_ERR_CRYPTO_SCE_AUTHENTICATION    Not used.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES256CMAC_GenerateFinal (sce_cmac_handle_t * handle, uint8_t * mac)
{
    fsp_err_t ercd = FSP_SUCCESS;

    if (CALL_ONLY_INIT == handle->flag_call_init)
    {
        return FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION;
    }

    handle->flag_call_init = CALL_ONLY_INIT;
    if (handle->id != g_aes256cmacgen_private_id)
    {
        return FSP_ERR_CRYPTO_SCE_PARAMETER;
    }

    if ((0 != (handle->buffering_length % HW_SCE_AES_BLOCK_BYTE_SIZE)) || (0 == handle->all_received_length))
    {
        handle->cmac_buffer[handle->buffering_length] = 1 << 7;
        memset(handle->cmac_buffer + (handle->buffering_length + 1), 0,
                HW_SCE_AES_BLOCK_BYTE_SIZE - (handle->buffering_length + 1));
    }

    ercd = R_SCE_Aes256CmacGenerateFinalPrivate(handle->all_received_length,
            /* Casting uint32_t pointer is used for address. */
            (uint32_t *) (handle->cmac_buffer),
            (uint32_t *) (mac));
    memset(handle, 0, sizeof(sce_cmac_handle_t));

    return ercd;
}

/*******************************************************************************************************************//**
 * The R_SCE_AES256CMAC_VerifyInit() function performs preparations for the execution of a CMAC calculation,
 * and writes the result to the first argument, handle. The value of handle is used as an argumentin the subsequent
 * R_SCE_AES256CMAC_VerifyUpdate() function and R_SCE_AES256CMAC_VerifyFinal() function.
 *
 * @param[in,out] handle      AES-CMAC handler (work area)
 * @param[in]     wrapped_key 256-bit AES wrapped key
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource needed
 *                                              by the processing routine was in use by another processing routine.
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL      Invalid wrapped key was input.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              Internal error occurred.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES256CMAC_VerifyInit (sce_cmac_handle_t * handle, sce_aes_wrapped_key_t * wrapped_key)
{
    memset(handle, 0, sizeof(sce_cmac_handle_t));
    handle->flag_call_init = CALL_ONLY_UPDATE_FINAL;
    g_private_id_counter++;
    g_aes256cmacver_private_id = g_private_id_counter;
    handle->id                 = g_aes256cmacver_private_id;
    memcpy(handle->wrapped_key.value, wrapped_key->value, HW_SCE_AES256_KEY_INDEX_WORD_SIZE * 4);
    memset(handle->cmac_buffer, 0, sizeof(handle->cmac_buffer));

    return R_SCE_Aes256CmacVerifyInitPrivate(wrapped_key);
}

/*******************************************************************************************************************//**
 * The R_SCE_AES256CMAC_VerifyUpdate() function performs MAC value generation based on the message specified
 * in the second argument, message, using the value specified for wrapped_key in R_SCE_AES256CMAC_VerifyInit().
 * Inside this function, the data that is input by the user is buffered until the input value of message
 * exceeds 16 bytes. The length of the message data to input is specified in the third argument, message_len.
 * For these, input not the total byte count for message input data, but rather the message data length to input
 * when the user calls this function. If the input value, message, is not a multiple of 16 bytes,
 * it will be padded within the function. For message, specify a RAM address that are multiples of 4.
 *
 * @param[in,out] handle         AES-CMAC handler (work area)
 * @param[in]     message        message data area (message_length byte)
 * @param[in]     message_length message data length (0 or more bytes)
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_PARAMETER         An invalid handle was input.
 * @retval FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION An invalid function was called.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES256CMAC_VerifyUpdate (sce_cmac_handle_t * handle, uint8_t * message, uint32_t message_length)
{
    uint32_t length_rest = 0;

    if (CALL_ONLY_INIT == handle->flag_call_init)
    {
        return FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION;
    }

    if (handle->id != g_aes256cmacver_private_id)
    {
        return FSP_ERR_CRYPTO_SCE_PARAMETER;
    }

    handle->all_received_length += message_length;
    if ((handle->buffering_length + message_length) > HW_SCE_AES_BLOCK_BYTE_SIZE)
    {
        memcpy(((&handle->cmac_buffer[0]) + handle->buffering_length),
                message,
                HW_SCE_AES_BLOCK_BYTE_SIZE - handle->buffering_length);

        /* Casting uint32_t pointer is used for address. */
        R_SCE_Aes256CmacVerifyUpdatePrivate((uint32_t *) (handle->cmac_buffer), HW_SCE_AES_BLOCK_BYTE_SIZE >> 2);
        length_rest = message_length - (HW_SCE_AES_BLOCK_BYTE_SIZE - handle->buffering_length);
        memset(handle->cmac_buffer, 0, sizeof(handle->cmac_buffer));
        if (length_rest > HW_SCE_AES_BLOCK_BYTE_SIZE)
        {
            R_SCE_Aes256CmacVerifyUpdatePrivate(
                    /* Casting uint32_t pointer is used for address. */
                    (uint32_t *) (message + (HW_SCE_AES_BLOCK_BYTE_SIZE - handle->buffering_length)),
                    (((length_rest - 1) / HW_SCE_AES_BLOCK_BYTE_SIZE) * HW_SCE_AES_BLOCK_BYTE_SIZE) >> 2);
            length_rest -= (((length_rest - 1) / HW_SCE_AES_BLOCK_BYTE_SIZE) * HW_SCE_AES_BLOCK_BYTE_SIZE);
        }

        handle->buffering_length = 0;
        memcpy(handle->cmac_buffer, message + (message_length - length_rest), length_rest);
        handle->buffering_length = length_rest;
    }
    else
    {
        memcpy((&handle->cmac_buffer[0]) + handle->buffering_length, message, message_length);
        handle->buffering_length += message_length;
    }

    return FSP_SUCCESS;
}

/*******************************************************************************************************************//**
 * The R_SCE_AES256CMAC_VerifyFinal() function inputs the MAC value in the MAC data area specified
 * in the second argument, mac, and verifies the MAC value. If authentication fails, the return value will be
 * TSIP_ERR_AUTHENTICATION. If the MAC value is less than 16 bytes, it will be padded with zeros inside the function.
 *
 * @param[in,out] handle     AES-CMAC handler (work area)
 * @param[in,out] mac        MAC data area (mac_length byte)
 * @param[in,out] mac_length MAC data length (2 to 16 bytes)
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              An internal error occurred.
 * @retval FSP_ERR_CRYPTO_SCE_AUTHENTICATION    Authentication failed
 * @retval FSP_ERR_CRYPTO_SCE_PARAMETER         An invalid handle was input.
 * @retval FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION An invalid function was called.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_AES256CMAC_VerifyFinal (sce_cmac_handle_t * handle, uint8_t * mac, uint32_t mac_length)
{
    fsp_err_t ercd = FSP_SUCCESS;
    uint32_t  mac_tmp[16 / sizeof(uint32_t)] =
    {
            0                              /* mac_tmp is initialized with 0. */
    };
    uint32_t mac_length_bit = 0;

    if (CALL_ONLY_INIT == handle->flag_call_init)
    {
        return FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION;
    }

    handle->flag_call_init = CALL_ONLY_INIT;
    if (handle->id != g_aes256cmacver_private_id)
    {
        return FSP_ERR_CRYPTO_SCE_PARAMETER;
    }

    if ((2 > mac_length) || (mac_length > HW_SCE_AES_BLOCK_BYTE_SIZE))
    {
        return FSP_ERR_CRYPTO_SCE_PARAMETER;
    }

    if ((0 != (handle->buffering_length % HW_SCE_AES_BLOCK_BYTE_SIZE)) || (0 == handle->all_received_length))
    {
        handle->cmac_buffer[handle->buffering_length] = 1 << 7;
        memset(handle->cmac_buffer + (handle->buffering_length + 1), 0,
                HW_SCE_AES_BLOCK_BYTE_SIZE - (handle->buffering_length + 1));
    }

    memcpy(mac_tmp, mac, mac_length);
    mac_length_bit = change_endian_long(mac_length * 8);

    ercd = R_SCE_Aes256CmacVerifyFinalPrivate(handle->all_received_length,
            /* Casting uint32_t pointer is used for address. */
            (uint32_t *) handle->cmac_buffer,
            (uint32_t *) mac_tmp,
            &mac_length_bit);
    memset(handle, 0, sizeof(sce_cmac_handle_t));

    return ercd;
}

/*******************************************************************************************************************//**
 * @} (end addtogroup SCE_PROTECTED)
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Private Functions
 **********************************************************************************************************************/

/******************************************************************************
 * calculate curent ivec after update process on AES COUNTER mode
 *
 * @param[in]     block_num        encrypted block number.
 * @param[in,out] handle           Handler for AES(work area).
 *
 * Return Value :none
 *****************************************************************************/
static void cal_current_ivec_ctrmode(sce_aes_handle_t *handle , uint32_t block_num)
{
    uint8_t carry_num = 0;
    for (uint8_t i = 0; i < 16; i++)
    {
        uint16_t current_byte_sum = (uint16_t)(carry_num + handle->current_initial_vector[15 - i]);
        if (i < (sizeof(block_num)))
        {
            current_byte_sum = (uint16_t)((uint32_t)current_byte_sum + ((block_num >> (i * 8)) & 0xFF));
        }
        handle->current_initial_vector[15 - i] = (uint8_t)(current_byte_sum & 0xFF);
        carry_num = (uint8_t)(current_byte_sum >> 8) & 0xFF;
    }
}
