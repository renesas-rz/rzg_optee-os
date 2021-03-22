/*
 * Copyright (c) 2020, Renesas Electronics Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*! *****************************************************************************
    @file    TSIP_Wrapper_BasicEncryption_API.h
    @brief   Basic encryption
    
    @par    History
    @subsection sub_history 
      - Initial version\n
 ********************************************************************************/

#ifndef  TSIP_WRAPPER_BASICENCRYPTION_API_H
#define  TSIP_WRAPPER_BASICENCRYPTION_API_H

/*------------------------------------------------------------------------------*/
/*                        Include Files                                         */
/*------------------------------------------------------------------------------*/

#include "common/TSIP_Common_Define.h"

/*------------------------------------------------------------------------------*/
/*                        Prototype Definition                                  */
/*------------------------------------------------------------------------------*/


/*------------------------------------------------------------------------------*/
/*                        Function Definition                                   */
/*------------------------------------------------------------------------------*/
unsigned long R_TSIP_BCF_GenerateRandom(
    unsigned long InData_GenByteSize,
    unsigned long InData_UseCASE,
    unsigned char *OutData);

#endif /* TSIP_WRAPPER_BASICENCRYPTION_API_H */
