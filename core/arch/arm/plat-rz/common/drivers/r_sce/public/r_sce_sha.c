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
 * File Name    : r_sce_sha.c
 * Version      : 1.0
 * Description  : SCE Hash Public API source file
 *********************************************************************************************************************/
/**********************************************************************************************************************
 * History : DD.MM.YYYY Version  Description
 *         : 03.31.2022 1.00     First Release
 *********************************************************************************************************************/

/***********************************************************************************************************************
 * Includes
 **********************************************************************************************************************/
#include "r_sce_private.h"
#include <string.h>

/***********************************************************************************************************************
 * Macro definitions
 **********************************************************************************************************************/

/* Block length (in bytes) of SHA */
#define SHA_BLOCK8_LEN            (64U)

/* Initialization function call state */
#define CALL_ONLY_INIT            (0)
#define CALL_ONLY_UPDATE_FINAL    (1)

#ifndef SCE_HEX_FF
#define SCE_HEX_FF               (0xff)
#endif
#ifndef SCE_HEX_80
#define SCE_HEX_80               (0x80)
#endif
#ifndef SCE_DEC_32
#define SCE_DEC_32               (32)
#endif
#ifndef SCE_DEC_64
#define SCE_DEC_64               (64)
#endif

/***********************************************************************************************************************
 * Typedef definitions
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Private function prototypes
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Private global variables
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Global variables
 **********************************************************************************************************************/
extern uint32_t g_private_id_counter;
uint32_t        g_sha224_private_id;
uint32_t        g_sha256_private_id;

/*******************************************************************************************************************//**
 * @addtogroup SCE_PROTECTED
 * @{
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Functions
 **********************************************************************************************************************/

/*******************************************************************************************************************//**
 * The R_SCE_SHA224_Init() function performs preparations for the execution of an SHA-224 hash calculation,
 * and writes the result to the first argument, handle. The value of handle is used as an argument in the subsequent
 * R_SCE_SHA224_Update() function and R_SCE_SHA224_Final() function.
 *
 * @param[in,out] handle SHA handler (work area)
 *
 * @retval FSP_SUCCESS Normal termination
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_SHA224_Init (sce_sha_md5_handle_t * handle)
{
    memset(handle, 0, sizeof(sce_sha_md5_handle_t));
    handle->flag_call_init = CALL_ONLY_UPDATE_FINAL;
    g_private_id_counter++;
    g_sha224_private_id = g_private_id_counter;
    handle->id          = g_sha224_private_id;
    memset(handle->sha_buffer, 0, sizeof(handle->sha_buffer));

    return R_SCE_Sha224InitPrivate(handle);
}

/*******************************************************************************************************************//**
 * The R_SCE_SHA224_Update() function calculates a hash value based on the second argument, message,
 * and the third argument, message_length, and writes the ongoing status to the first argument, handle.
 * After message input is completed, call R_SCE_SHA224_Final().
 *
 * @param[in,out] handle         SHA handler (work area)
 * @param[in]     message        message data area
 * @param[in]     message_length message data length
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource needed
 *                                              by the processing routine was in use by another processing routine.
 * @retval FSP_ERR_CRYPTO_SCE_PARAMETER         An invalid handle was input.
 * @retval FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION An invalid function was called.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_SHA224_Update (sce_sha_md5_handle_t * handle, uint8_t * message, uint32_t message_length)
{
    fsp_err_t ercd        = FSP_SUCCESS;
    uint32_t  length_rest = 0;

    if (CALL_ONLY_INIT == handle->flag_call_init)
    {
        return FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION;
    }

    if (handle->id != g_sha224_private_id)
    {
        return FSP_ERR_CRYPTO_SCE_PARAMETER;
    }

    handle->all_received_length += message_length;
    if ((handle->buffering_length + message_length) >= SHA_BLOCK8_LEN)
    {
        memcpy(handle->sha_buffer + handle->buffering_length, message, SHA_BLOCK8_LEN - handle->buffering_length);

        /*Casting uint32_t pointer is used for address.*/
        ercd = R_SCE_Sha224UpdatePrivate(handle, (uint32_t *) (handle->sha_buffer), SHA_BLOCK8_LEN >> 2);
        length_rest = message_length - (SHA_BLOCK8_LEN - handle->buffering_length);
        memset(handle->sha_buffer, 0, sizeof(handle->sha_buffer));
        if (length_rest >= SHA_BLOCK8_LEN)
        {
            ercd = R_SCE_Sha224UpdatePrivate(handle,
                    /* Casting uint32_t pointer is used for address. */
                    (uint32_t *) (message + (SHA_BLOCK8_LEN - handle->buffering_length)),
                    ((length_rest / SHA_BLOCK8_LEN) * SHA_BLOCK8_LEN) >> 2);
            length_rest -= ((length_rest / SHA_BLOCK8_LEN) * SHA_BLOCK8_LEN);
        }

        handle->buffering_length = 0;
        memcpy(handle->sha_buffer, message + (message_length - length_rest), length_rest);
        handle->buffering_length = length_rest;
    }
    else
    {
        memcpy(handle->sha_buffer + handle->buffering_length, message, message_length);
        handle->buffering_length += message_length;
    }

    return ercd;
}

/*******************************************************************************************************************//**
 * Using the handle specified in the first argument, handle, the R_SCE_SHA224_Final() function writes the calculation
 * result to the second argument, digest, and writes the length of the calculation result to the third argument,
 * digest_length.
 *
 * @param[in,out] handle        SHA handler (work area)
 * @param[in,out] digest        hasha data area
 * @param[in,out] digest_length hash data length (32bytes)
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource needed
 *                                              by the processing routine was in use by another processing routine.
 * @retval FSP_ERR_CRYPTO_SCE_PARAMETER         An invalid handle was input.
 * @retval FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION An invalid function was called.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_SHA224_Final (sce_sha_md5_handle_t * handle, uint8_t * digest, uint32_t * digest_length)
{
    uint32_t  max_cnt_byte = 0;
    fsp_err_t ercd         = FSP_SUCCESS;

    if (CALL_ONLY_INIT == handle->flag_call_init)
    {
        return FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION;
    }

    handle->flag_call_init = CALL_ONLY_INIT;
    if (handle->id != g_sha224_private_id)
    {
        return FSP_ERR_CRYPTO_SCE_PARAMETER;
    }

    handle->sha_buffer[handle->buffering_length] = SCE_HEX_80;
    if ((SHA_BLOCK8_LEN - handle->buffering_length) >= 9) /* another block unnecessary */
    {
        memset(handle->sha_buffer + (handle->buffering_length + 1), 0,
                (SHA_BLOCK8_LEN - 4) - (handle->buffering_length + 1));

        /* According c., but support only l < 2**32 case */
        /* Casting uint32_t data to uint8_t data array. */
        handle->sha_buffer[SHA_BLOCK8_LEN - 4] = (uint8_t) ((handle->all_received_length * 8) >> 24);

        /* Casting uint32_t data to uint8_t data array. */
        handle->sha_buffer[SHA_BLOCK8_LEN - 3] = (uint8_t) (((handle->all_received_length * 8) >> 16) & SCE_HEX_FF);

        /* Casting uint32_t data to uint8_t data array. */
        handle->sha_buffer[SHA_BLOCK8_LEN - 2] = (uint8_t) (((handle->all_received_length * 8) >> 8) & SCE_HEX_FF);

        /* Casting uint32_t data to uint8_t data array. */
        handle->sha_buffer[SHA_BLOCK8_LEN - 1] = (uint8_t) ((handle->all_received_length * 8) & SCE_HEX_FF);
        max_cnt_byte = SHA_BLOCK8_LEN;
    }
    else
    {
        /* another block necessary */
        memset(handle->sha_buffer + (handle->buffering_length + 1), 0,
                ((2 * SHA_BLOCK8_LEN) - 4) - (handle->buffering_length + 1));

        /* Casting uint32_t data to uint8_t data array. */
        handle->sha_buffer[(2 * SHA_BLOCK8_LEN) - 4] = (uint8_t) ((handle->all_received_length * 8) >> 24);

        /* Casting uint32_t data to uint8_t data array. */
        handle->sha_buffer[(2 * SHA_BLOCK8_LEN) - 3] =
                (uint8_t) (((handle->all_received_length * 8) >> 16) & SCE_HEX_FF);

        /* Casting uint32_t data to uint8_t data array. */
        handle->sha_buffer[(2 * SHA_BLOCK8_LEN) - 2] =
                (uint8_t) (((handle->all_received_length * 8) >> 8) & SCE_HEX_FF);

        /* Casting uint32_t data to uint8_t data array. */
        handle->sha_buffer[(2 * SHA_BLOCK8_LEN) - 1] = (uint8_t) ((handle->all_received_length * 8) & SCE_HEX_FF);
        max_cnt_byte = 2 * SHA_BLOCK8_LEN;
    }

    ercd = R_SCE_Sha224FinalPrivate(handle,
            /* Casting uint32_t pointer is used for address. */
            (uint32_t *) (handle->sha_buffer),
            max_cnt_byte >> 2,
            (uint32_t *) (digest),
            digest_length);
    handle->all_received_length = 0;
    handle->buffering_length    = 0;
    memset(handle->sha_buffer, 0, sizeof(handle->sha_buffer));

    return ercd;
}

/*******************************************************************************************************************//**
 * The R_SCE_SHA256_Init() function performs preparations for the execution of an SHA-256 hash calculation,
 * and writes the result to the first argument, handle. The value of handle is used as an argument in the subsequent
 * R_SCE_SHA256_Update() function and R_SCE_SHA256_Final() function.
 *
 * @param[in,out] handle SHA handler (work area)
 *
 * @retval FSP_SUCCESS Normal termination
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_SHA256_Init (sce_sha_md5_handle_t * handle)
{
    memset(handle, 0, sizeof(sce_sha_md5_handle_t));
    handle->flag_call_init = CALL_ONLY_UPDATE_FINAL;
    g_private_id_counter++;
    g_sha256_private_id = g_private_id_counter;
    handle->id          = g_sha256_private_id;
    memset(handle->sha_buffer, 0, sizeof(handle->sha_buffer));

    return R_SCE_Sha256InitPrivate(handle);
}

/*******************************************************************************************************************//**
 * The R_SCE_SHA256_Update() function calculates a hash value based on the second argument, message,
 * and the third argument, message_length, and writes the ongoing status to the first argument, handle.
 * After message input is completed, call R_SCE_SHA256_Final().
 *
 * @param[in,out] handle         SHA handler (work area)
 * @param[in]     message        message data area
 * @param[in]     message_length message data length
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource needed
 *                                              by the processing routine was in use by another processing routine.
 * @retval FSP_ERR_CRYPTO_SCE_PARAMETER         An invalid handle was input.
 * @retval FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION An invalid function was called.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_SHA256_Update (sce_sha_md5_handle_t * handle, uint8_t * message, uint32_t message_length)
{
    fsp_err_t ercd        = FSP_SUCCESS;
    uint32_t  length_rest = 0;

    if (CALL_ONLY_INIT == handle->flag_call_init)
    {
        return FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION;
    }

    if (handle->id != g_sha256_private_id)
    {
        return FSP_ERR_CRYPTO_SCE_PARAMETER;
    }

    handle->all_received_length += message_length;
    if ((handle->buffering_length + message_length) >= SHA_BLOCK8_LEN)
    {
        memcpy(handle->sha_buffer + handle->buffering_length, message, SHA_BLOCK8_LEN - handle->buffering_length);

        /*Casting uint32_t pointer is used for address.*/
        ercd        = R_SCE_Sha256UpdatePrivate(handle, (uint32_t *) (handle->sha_buffer), SHA_BLOCK8_LEN >> 2);
        length_rest = message_length - (SHA_BLOCK8_LEN - handle->buffering_length);
        memset(handle->sha_buffer, 0, sizeof(handle->sha_buffer));
        if (length_rest >= SHA_BLOCK8_LEN)
        {
            ercd = R_SCE_Sha256UpdatePrivate(handle,
                    /* Casting uint32_t pointer is used for address. */
                    (uint32_t *) (message + (SHA_BLOCK8_LEN - handle->buffering_length)),
                    ((length_rest / SHA_BLOCK8_LEN) * SHA_BLOCK8_LEN) >> 2);
            length_rest -= ((length_rest / SHA_BLOCK8_LEN) * SHA_BLOCK8_LEN);
        }

        handle->buffering_length = 0;
        memcpy(handle->sha_buffer, message + (message_length - length_rest), length_rest);
        handle->buffering_length = length_rest;
    }
    else
    {
        memcpy(handle->sha_buffer + handle->buffering_length, message, message_length);
        handle->buffering_length += message_length;
    }

    return ercd;
}

/*******************************************************************************************************************//**
 * Using the handle specified in the first argument, handle, the R_SCE_SHA256_Final() function writes the calculation
 * result to the second argument, digest, and writes the length of the calculation result to the third argument,
 * digest_length.
 *
 * @param[in,out] handle        SHA handler (work area)
 * @param[in,out] digest        hasha data area
 * @param[in,out] digest_length hash data length (32bytes)
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource needed
 *                                              by the processing routine was in use by another processing routine.
 * @retval FSP_ERR_CRYPTO_SCE_PARAMETER         An invalid handle was input.
 * @retval FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION An invalid function was called.
 *
 * @note The pre-run state is SCE Enabled State.
 *       After the function runs the state transitions to SCE Enabled State.
 **********************************************************************************************************************/
fsp_err_t R_SCE_SHA256_Final (sce_sha_md5_handle_t * handle, uint8_t * digest, uint32_t * digest_length)
{
    uint32_t  max_cnt_byte = 0;
    fsp_err_t ercd         = FSP_SUCCESS;

    if (CALL_ONLY_INIT == handle->flag_call_init)
    {
        return FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION;
    }

    handle->flag_call_init = CALL_ONLY_INIT;
    if (handle->id != g_sha256_private_id)
    {
        return FSP_ERR_CRYPTO_SCE_PARAMETER;
    }

    handle->sha_buffer[handle->buffering_length] = SCE_HEX_80;
    if ((SHA_BLOCK8_LEN - handle->buffering_length) >= 9) /* another block unnecessary */
    {
        memset(handle->sha_buffer + (handle->buffering_length + 1), 0,
                (SHA_BLOCK8_LEN - 4) - (handle->buffering_length + 1));

        /* According c., but support only l < 2**32 case */
        /* Casting uint32_t data to uint8_t data array. */
        handle->sha_buffer[SHA_BLOCK8_LEN - 4] = (uint8_t) ((handle->all_received_length * 8) >> 24);

        /* Casting uint32_t data to uint8_t data array. */
        handle->sha_buffer[SHA_BLOCK8_LEN - 3] = (uint8_t) (((handle->all_received_length * 8) >> 16) & SCE_HEX_FF);

        /* Casting uint32_t data to uint8_t data array. */
        handle->sha_buffer[SHA_BLOCK8_LEN - 2] = (uint8_t) (((handle->all_received_length * 8) >> 8) & SCE_HEX_FF);

        /* Casting uint32_t data to uint8_t data array. */
        handle->sha_buffer[SHA_BLOCK8_LEN - 1] = (uint8_t) ((handle->all_received_length * 8) & SCE_HEX_FF);
        max_cnt_byte = SHA_BLOCK8_LEN;
    }
    else
    {
        /* another block necessary */
        memset(handle->sha_buffer + (handle->buffering_length + 1), 0,
                ((2 * SHA_BLOCK8_LEN) - 4) - (handle->buffering_length + 1));

        /* Casting uint32_t data to uint8_t data array. */
        handle->sha_buffer[(2 * SHA_BLOCK8_LEN) - 4] = (uint8_t) ((handle->all_received_length * 8) >> 24);

        /* Casting uint32_t data to uint8_t data array. */
        handle->sha_buffer[(2 * SHA_BLOCK8_LEN) - 3] =
                (uint8_t) (((handle->all_received_length * 8) >> 16) & SCE_HEX_FF);

        /* Casting uint32_t data to uint8_t data array. */
        handle->sha_buffer[(2 * SHA_BLOCK8_LEN) - 2] =
                (uint8_t) (((handle->all_received_length * 8) >> 8) & SCE_HEX_FF);

        /* Casting uint32_t data to uint8_t data array. */
        handle->sha_buffer[(2 * SHA_BLOCK8_LEN) - 1] = (uint8_t) ((handle->all_received_length * 8) & SCE_HEX_FF);
        max_cnt_byte = 2 * SHA_BLOCK8_LEN;
    }

    ercd = R_SCE_Sha256FinalPrivate(handle,
            /* Casting uint32_t pointer is used for address. */
            (uint32_t *) (handle->sha_buffer),
            max_cnt_byte >> 2,
            (uint32_t *) (digest),
            digest_length);
    handle->all_received_length = 0;
    handle->buffering_length    = 0;
    memset(handle->sha_buffer, 0, sizeof(handle->sha_buffer));

    return ercd;
}

/*******************************************************************************************************************//**
 * @} (end addtogroup SCE_PROTECTED)
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Private Functions
 **********************************************************************************************************************/
