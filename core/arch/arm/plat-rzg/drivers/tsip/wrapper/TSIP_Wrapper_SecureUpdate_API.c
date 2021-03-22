/*
 * Copyright (c) 2020, Renesas Electronics Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*! *****************************************************************************
    @file    TSIP_Wrapper_SecureUpdate_API.c
    @brief   Secure Firmware update
    
    @par    History
    @subsection sub_history 
      - Initial version\n
 ********************************************************************************/

/*------------------------------------------------------------------------------*/
/*                        Include Files                                         */
/*------------------------------------------------------------------------------*/

#include <stddef.h>
#include <stdint.h>

#include "wrapper/TSIP_Wrapper_SecureUpdate_API.h"
#include "wrapper/TSIP_Wrapper_Local_API.h"
#include "core/TSIP_Core_API.h"
#include "stub/TSIP_Stub_API.h"

/*------------------------------------------------------------------------------*/
/*                        Prototype Definition                                  */
/*------------------------------------------------------------------------------*/


/*------------------------------------------------------------------------------*/
/*                        Function Definition                                   */
/*------------------------------------------------------------------------------*/
/*! *****************************************************************************
    @fn       unsigned long R_TSIP_SU_Activate(void)
    @brief    Initialization for Secure firmware update
    

    @retval    R_PASS                   success
    @retval    R_SEQUENCE_FAIL          cannot perform in current state
    @retval    R_FALSIFICATION_ERROR    tampering detection error
    @retval    R_RESOURCE_CONFLICT_FAIL resource for this process already used in other process
    
    @par    Details
    It performs initilization for Secure firmware update \n
    
    @par    Processing flow
    -# check initialization state in TSIP_Wrapper layer
        - Is_TSIP_Wrapper_Init()
    -# initialize for Secure firmware update
        - TSIP_SU_Activate()
 ********************************************************************************/
unsigned long R_TSIP_SU_Activate(void)
{
    uint8_t BoolFg;
    unsigned long RetCode;

    BoolFg = Is_TSIP_Wrapper_Init();
    if(BoolFg == TSIP_TRUE) {
        RetCode = TSIP_SU_Activate();
    }
    else {
        RetCode = R_SEQUENCE_FAIL;
    }

    return RetCode;
}

/*! *****************************************************************************
    @fn       unsigned long unsigned long R_TSIP_UpdateBootData(TSIP_UPDATE_BOOT_DATA *tsip_update_bootdata)
    @brief    convert Boot data for update
    
    @param     [in/out]        *tsip_update_bootdata            BootData structure

    @retval    R_PASS                       success
    @retval    R_PARAMETER_FAIL             invalid input parameter
    @retval    R_SEQUENCE_FAIL              cannot perform in current state
    @retval    R_VERIFICATION_FAIL          verification failed
    @retval    R_FALSIFICATION_ERROR        tampering detection error
    @retval    R_RESOURCE_CONFLICT_FAIL     resource for this process already used in other process
    
    @par    Details
    It decrypts encrypted Boot data(max 16 data) and re-encrypts by TSIP key after verification \n
    
    @par    Processing flow
    -# check initialization state in TSIP_Wrapper layer
        - Is_TSIP_Wrapper_Init()
    -# decrypts Boot data and output re-encrypted Boot data
        - TSIP_UpdateBootData()
 ********************************************************************************/
unsigned long R_TSIP_UpdateBootData(TSIP_UPDATE_BOOT_DATA *tsip_update_bootdata)
{
    uint8_t           BoolFg;
    unsigned long     RetCode;
    UPDATE_BOOT_DATA  updatebootdata;
    UPDATEBOOTDATA    *bdata;
    WRAP_UP_BOOT_DATA *wrap_bdata;
    unsigned long     cnt;

    BoolFg = Is_TSIP_Wrapper_Init();
    if(BoolFg == TSIP_TRUE) {
        if(tsip_update_bootdata == NULL) {
            RetCode = TSIP_UpdateBootData(NULL);
        }
        else {
            /* copy each member of structure for common impelemantation between 32bit and 64bit. */
            TSIP_Memset(&updatebootdata, 0, sizeof(updatebootdata));
            bdata = (UPDATEBOOTDATA *)&updatebootdata;
            wrap_bdata = (WRAP_UP_BOOT_DATA *)tsip_update_bootdata;
            for(cnt = 0; cnt < UPDATE_BOOT_DATA_MAX; cnt++, bdata++, wrap_bdata++ ) {
                bdata->InData_BootData_UpdateFlag = (uint32_t)wrap_bdata->InData_BootData_UpdateFlag;
                bdata->InData_BootData = (uint8_t *)wrap_bdata->InData_BootData;
                bdata->InData_BootData_ByteSize = (uint64_t )wrap_bdata->InData_BootData_ByteSize;
                bdata->OutData_BootData = (uint8_t *)wrap_bdata->OutData_BootData;
            }
            RetCode = TSIP_UpdateBootData(&updatebootdata);
        }
    }
    else {
        RetCode = R_SEQUENCE_FAIL;
    }

    return RetCode;
}


/*! *****************************************************************************
    @fn       unsigned long R_TSIP_SU_Key(unsigned char *InData_KeyRingOperationCode)
    @brief    Keyring decryption and re-encryption
    
    @param     [in]        *InData_KeyRingOperationCode        Pointer of Keyring(size:1840Byte)

    @retval    R_PASS                   success
    @retval    R_PARAMETER_FAIL         invalid input parameter
    @retval    R_SEQUENCE_FAIL          cannot perform in current state
    @retval    R_VERIFICATION_FAIL      verification failed
    @retval    R_FALSIFICATION_ERROR    tampering detection error
    @retval    R_RESOURCE_CONFLICT_FAIL resource for this process already used in other process
    
    @par    Details
    It decrypts encrypted Keyring and re-encrypts by TSIP key \n
    
    @par    Processing flow
    -# check initialization state in TSIP_Wrapper layer
        - Is_TSIP_Wrapper_Init()
    -# decrypts and re-encrypts Keyring
        - TSIP_SU_Key()
 ********************************************************************************/
unsigned long R_TSIP_SU_Key(unsigned char *InData_KeyRingOperationCode)
{
    uint8_t BoolFg;
    unsigned long RetCode;

    BoolFg = Is_TSIP_Wrapper_Init();
    if(BoolFg == TSIP_TRUE) {
        RetCode = TSIP_SU_Key((uint8_t *)InData_KeyRingOperationCode);
    }
    else {
        RetCode = R_SEQUENCE_FAIL;
    }

    return RetCode;
}
