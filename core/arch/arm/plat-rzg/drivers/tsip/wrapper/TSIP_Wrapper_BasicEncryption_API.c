/*
 * Copyright (c) 2020, Renesas Electronics Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*! *****************************************************************************
    @file    TSIP_Wrapper_BasicEncryption_API.c
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

#include "wrapper/TSIP_Wrapper_BasicEncryption_API.h"
#include "wrapper/TSIP_Wrapper_Local_API.h"
#include "core/TSIP_Core_API.h"

/*------------------------------------------------------------------------------*/
/*                        Prototype Definition                                  */
/*------------------------------------------------------------------------------*/


/*------------------------------------------------------------------------------*/
/*                        Function Definition                                   */
/*------------------------------------------------------------------------------*/

/*! *****************************************************************************
    @fn       unsigned long R_TSIP_BCF_GenerateRandom(unsigned long InData_GenByteSize,
                                                      unsigned long InData_UseCASE, 
                                                      unsigned char *OutData)
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
    -# check initialization state in TSIP_Wrapper layer
        - Is_TSIP_Wrapper_Init()
    -# generate random number
        - TSIP_BCF_GenerateRandom()
 ********************************************************************************/
unsigned long R_TSIP_BCF_GenerateRandom(
    unsigned long InData_GenByteSize,
    unsigned long InData_UseCASE,
    unsigned char *OutData)
{
    uint8_t BoolFg;
    unsigned long RetCode;

    BoolFg = Is_TSIP_Wrapper_Init();
    if(BoolFg == TSIP_TRUE) {
        RetCode = TSIP_BCF_GenerateRandom((uint32_t)InData_GenByteSize, (uint32_t)InData_UseCASE, (uint8_t *)OutData);
    }
    else {
        RetCode = R_SEQUENCE_FAIL;
    }

    return RetCode;
}


