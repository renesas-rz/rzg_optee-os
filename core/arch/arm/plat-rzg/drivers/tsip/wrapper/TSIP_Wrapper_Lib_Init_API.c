/*
 * Copyright (c) 2020, Renesas Electronics Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*! *****************************************************************************
    @file    TSIP_Wrapper_Lib_Init_API.c
    @brief   Library initialization
    
    @par    History
    @subsection sub_history 
      - Initial version\n
 ********************************************************************************/

/*------------------------------------------------------------------------------*/
/*                        Include Files                                         */
/*------------------------------------------------------------------------------*/

#include <stddef.h>
#include <stdint.h>

#include "wrapper/TSIP_Wrapper_Lib_Init_API.h"
#include "wrapper/TSIP_Wrapper_Local_API.h"
#include "core/TSIP_Core_API.h"

/*------------------------------------------------------------------------------*/
/*                        Prototype Definition                                  */
/*------------------------------------------------------------------------------*/


/*------------------------------------------------------------------------------*/
/*                        Function Definition                                   */
/*------------------------------------------------------------------------------*/
/*! *****************************************************************************
    @fn       unsigned long R_TSIP_Lib_Init(unsigned char *S_RAMData,
                                            unsigned char *S_INSTData, 
                                            unsigned char *TSIP_BaseAddress, 
                                            unsigned char *MSTP_BaseAddress)
    @brief    Library initiaization
    
    @param     [in]        *S_RAMData          Pointer of S_RAM data(it needs 432Byte area)
    @param     [in]        *S_INSTData         Pointer of S_INST data(it needs 1296Byte area)
    @param     [in]        *TSIP_BaseAddress   Logical pointer of TSIP Base Address
    @param     [in]        *MSTP_BaseAddress   Logical pointer of MSTP Base Address
    
    @retval    R_PASS                   success
    @retval    R_SEQUENCE_FAIL          cannot perform in current state
    @retval    R_PARAMETER_FAIL         invalid input parameter
    @retval    R_MMAP_FAIL              error occur of mmap()
    
    @par    Details
    It performs initialization of TSIP library and self-checking of TSIP \n
    
    @par    Processing flow
    -# check initialization state in TSIP_Wrapper layer
        - Is_TSIP_Wrapper_Init()
    -# initialize TSIP library
        - TSIP_Lib_Init()
    -# initialize in TSIP_Wrapper layer
        - TSIP_Wrapper_Init()
 ********************************************************************************/
unsigned long R_TSIP_Lib_Init(unsigned char *S_RAMData, unsigned char *S_INSTData,
                                unsigned char *TSIP_BaseAddress, unsigned char *MSTP_BaseAddress)
{
    uint8_t BoolFg;
    unsigned long RetCode;

    BoolFg = Is_TSIP_Wrapper_Init();
    if(BoolFg == TSIP_FALSE) {
        RetCode = TSIP_Lib_Init(S_RAMData, S_INSTData, TSIP_BaseAddress, MSTP_BaseAddress);
        if(RetCode == R_PASS) {
            RetCode = TSIP_Wrapper_Init();
        }
    }
    else {
        RetCode = R_SEQUENCE_FAIL;
    }
    return RetCode;
}
