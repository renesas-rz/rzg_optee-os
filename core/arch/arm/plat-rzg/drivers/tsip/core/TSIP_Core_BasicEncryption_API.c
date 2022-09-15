/*
 * Copyright (c) 2020, Renesas Electronics Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*! *****************************************************************************
    @file    TSIP_Core_BasicEncryption_API.c
    @brief   Basic encryption
    
    @par    History
    @subsection sub_history 
      - Initial version\n
 ********************************************************************************/

/*------------------------------------------------------------------------------*/
/*                        Include Files                                         */
/*------------------------------------------------------------------------------*/

#include <stddef.h>
#include <stdint.h>

#include "common/TSIP_Common_Define.h"
#include "core/TSIP_Core_API.h"
#include "core/TSIP_Core_Proc_API.h"
#include "core/TSIP_Core_Local_API.h"

/*------------------------------------------------------------------------------*/
/*                        Prototype Definition                                  */
/*------------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------*/
/*                        Function Definition                                   */
/*------------------------------------------------------------------------------*/

/*! *****************************************************************************
    @fn       uint32_t TSIP_BCF_GenerateRandom(uint32_t InData_GenByteSize, uint32_t InData_UseCASE, uint8_t *OutData)
    @brief    Random number generation
    
    @param     [in]        InData_GenByteSize         Bytes number of generated random
    @param     [in]        InData_UseCASE             Use case of random (set only 0)
    @param     [out]       *OutData                   Pointer of random

    @retval    R_PASS                   success
    @retval    R_PARAMETER_FAIL         invalid input parameter
    @retval    R_SEQUENCE_FAIL          cannot perform in current state
    @retval    R_RESOURCE_CONFLICT_FAIL resource for this process already used in other process
    
    @par    Details
    It generates random number \n
    
    @par    Processing flow
    -# check initialization state in TSIP_Core layer
        - Is_TSIP_Core_Init()
    -# check transition state in TSIP Core layer
        - TSIP_Core_Check_State()
    -# check parameter
    -# generate random
        - in the case of InData_UseCASE = 0
            - TSIP_Core_Prc_p3f()
 ********************************************************************************/
uint32_t TSIP_BCF_GenerateRandom(
    uint32_t  InData_GenByteSize,
    uint32_t  InData_UseCASE,
    uint8_t  *OutData)
{
    uint8_t  BoolFg;
    uint32_t RetCode;

    BoolFg = Is_TSIP_Core_Init();
    RetCode = TSIP_Core_Check_State(TSIP_LIB_APIS);
    if((BoolFg == TSIP_TRUE) && (RetCode == R_PASS)) {
        if((InData_GenByteSize > 0U) && (InData_UseCASE == 0U) && (OutData != NULL)) {
            RetCode = TSIP_Core_Prc_p3f(InData_GenByteSize, (uint32_t *)OutData);  /* PRQA S 3305 */
        }
        else if((InData_UseCASE == 1U) && (OutData != NULL)) {
            RetCode = R_PARAMETER_FAIL;
        }
        else {
            RetCode = R_PARAMETER_FAIL;
        }
    }
    else {
        RetCode = R_SEQUENCE_FAIL;
    }

    return RetCode;
}


