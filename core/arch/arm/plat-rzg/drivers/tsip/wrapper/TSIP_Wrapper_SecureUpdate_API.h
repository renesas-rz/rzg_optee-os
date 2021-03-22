/*
 * Copyright (c) 2020, Renesas Electronics Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*! *****************************************************************************
    @file    TSIP_Wrapper_SecureUpdate_API.h
    @brief   SecureUpdate API
    
    @par    History
    @subsection sub_history 
      - Initial version\n
 ********************************************************************************/

#ifndef  TSIP_WRAPPER_SECUREUPDATE_API_H
#define  TSIP_WRAPPER_SECUREUPDATE_API_H

/*------------------------------------------------------------------------------*/
/*                        Include Files                                         */
/*------------------------------------------------------------------------------*/

#include "common/TSIP_Common_Define.h"

typedef struct str_tsip_update_boot_data {
    unsigned long InData_BootData_UpdateFlag;
    unsigned char *InData_BootData;
    unsigned long *InData_BootData_ByteSize;
    unsigned char *OutData_BootData;
} TSIP_UPDATE_BOOT_DATA[UPDATE_BOOT_DATA_MAX];

typedef struct wrap_reenc_boot_data {
    unsigned long InData_BootData_UpdateFlag;
    unsigned char *InData_BootData;
    unsigned long  InData_BootData_ByteSize;
    unsigned char *OutData_BootData;
} WRAP_UP_BOOT_DATA;

unsigned long R_TSIP_SU_Activate(void);
unsigned long R_TSIP_UpdateBootData(TSIP_UPDATE_BOOT_DATA *tsip_update_bootdata);
unsigned long R_TSIP_SU_Key(unsigned char *InData_KeyRingOperationCode);


#endif  /* TSIP_WRAPPER_SECUREUPDATE_API_H */
