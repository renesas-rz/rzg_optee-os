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
 * Copyright (C) 2024 Renesas Electronics Corporation. All rights reserved.
 *********************************************************************************************************************/

/***********************************************************************************************************************
 * Includes
 **********************************************************************************************************************/
#include "bsp_api.h"
#include "r_rsip_otp.h"
#include "r_rsip_primitive.h"
#include "r_rsip_util.h"

/***********************************************************************************************************************
 * Macro definitions
 **********************************************************************************************************************/

#define RSIP_PRV_BYTE_SIZE_WRAPPED_HARDWARE_ROOT_KEY           (RSIP_PRV_WORD_SIZE_WRAPPED_HARDWARE_ROOT_KEY << 2)
#define RSIP_PRV_BYTE_SIZE_WRAPPED_HARDWARE_ROOT_KEY_NUM       (RSIP_PRV_WORD_SIZE_WRAPPED_HARDWARE_ROOT_KEY_NUM << 2)

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

/***********************************************************************************************************************
 * Functions
 **********************************************************************************************************************/

rsip_ret_t r_rsip_whrk_read (uint32_t wrapped_hardware_root_key_num[RSIP_PRV_WORD_SIZE_WRAPPED_HARDWARE_ROOT_KEY_NUM],
                             uint32_t wrapped_hardware_root_key[RSIP_PRV_WORD_SIZE_WRAPPED_HARDWARE_ROOT_KEY])
{
    uint8_t err = 1U;

    uint32_t key_num = bswap_32big (wrapped_hardware_root_key_num[0]);

    if (key_num <= 15)
    {
        memcpy ((void*) &wrapped_hardware_root_key[0],
                (void*) &S_FLASH[key_num * RSIP_PRV_WORD_SIZE_WRAPPED_HARDWARE_ROOT_KEY],
                RSIP_PRV_BYTE_SIZE_WRAPPED_HARDWARE_ROOT_KEY);
        err = 0;
    }

    /* Check error */
    return (0U == err) ? RSIP_RET_PASS : RSIP_RET_FAIL;
}

/***********************************************************************************************************************
 * Private Functions
 **********************************************************************************************************************/
