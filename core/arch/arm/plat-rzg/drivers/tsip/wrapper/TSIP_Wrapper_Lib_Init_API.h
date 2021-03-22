/*
 * Copyright (c) 2020, Renesas Electronics Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*! *****************************************************************************
    @file    TSIP_Wrapper_Lib_Init_API.h
    @brief   Library initialization
    
    @par    History
    @subsection sub_history 
      - Initial version\n
 ********************************************************************************/

#ifndef  TSIP_WRAPPER_LIB_INIT_API_H
#define  TSIP_WRAPPER_LIB_INIT_API_H

/*------------------------------------------------------------------------------*/
/*                        Include Files                                         */
/*------------------------------------------------------------------------------*/

#include "common/TSIP_Common_Define.h"

unsigned long R_TSIP_Lib_Init(unsigned char *S_RAMData, unsigned char *S_INSTData,
                              unsigned char *TSIP_BaseAddress, unsigned char *MSTP_BaseAddress);

#endif  /* TSIP_WRAPPER_LIB_INIT_API_H */

