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

#ifndef R_RSIP_OTP_H
#define R_RSIP_OTP_H

/***********************************************************************************************************************
 * Includes
 **********************************************************************************************************************/
#include <stdint.h>
#include "r_rsip_err.h"

/***********************************************************************************************************************
 * Macro definitions
 **********************************************************************************************************************/

#define RSIP_PRV_WORD_SIZE_WRAPPED_HARDWARE_ROOT_KEY        (8U)
#define RSIP_PRV_WORD_SIZE_WRAPPED_HARDWARE_ROOT_KEY_NUM    (1U)

/***********************************************************************************************************************
 * Typedef definitions
 **********************************************************************************************************************/

/**********************************************************************************************************************
 * Exported global variables
 **********************************************************************************************************************/

/**********************************************************************************************************************
 * Public Function Prototypes
 **********************************************************************************************************************/

rsip_ret_t r_rsip_whrk_read(uint32_t wrapped_hardware_root_key_num[RSIP_PRV_WORD_SIZE_WRAPPED_HARDWARE_ROOT_KEY_NUM],
                            uint32_t wrapped_hardware_root_key[RSIP_PRV_WORD_SIZE_WRAPPED_HARDWARE_ROOT_KEY]);

#endif                                 /* R_RSIP_OTP_H */
