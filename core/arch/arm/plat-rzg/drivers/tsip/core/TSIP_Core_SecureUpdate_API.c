/*
 * Copyright (c) 2020, Renesas Electronics Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*! *****************************************************************************
    @file    TSIP_Core_SecureUpdate_API.c
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
static uint32_t Get_UpdateBootData_Num(UPDATE_BOOT_DATA *update_bootdata);

/*! *****************************************************************************
    @fn       static uint32_t Get_UpdateBootData_Num(UPDATE_BOOT_DATA *update_bootdata)
    @brief    get number of valid Boot data
    
    @param     [in]    *update_bootdata     BootData structure
    @param     [in]    *DataNum             number of valid Boot data

    @retval    0                            no valid data
    @retval    1 - 16                       number of valid data
    
    @par    Details
    It gets number of valid Boot data from BootData structure \n
    
    @par    Processing flow
    -# check parameter
    -# get number of valid Boot data
 ********************************************************************************/
static uint32_t Get_UpdateBootData_Num(UPDATE_BOOT_DATA *update_bootdata)
{
    uint32_t DataNum = 0;
    uint32_t LooopCount;
    uint64_t Maximum = 0xFFFFFFE0U;
    uint64_t Minimum = 0x00000110U;
    UPDATEBOOTDATA *bootdata;

    if(update_bootdata == NULL) {
        DataNum = 0;
    }
    else {
        bootdata = (UPDATEBOOTDATA *)update_bootdata;
        for(LooopCount = 0; LooopCount < UPDATE_BOOT_DATA_MAX; LooopCount++, bootdata++) {
            if (bootdata->InData_BootData_UpdateFlag == 0) { /* Not Update */
                continue;
            }

            if ((bootdata->InData_BootData_UpdateFlag != 1)
            || (bootdata->InData_BootData == NULL)
            || (bootdata->OutData_BootData == NULL)
            || (bootdata->InData_BootData_ByteSize < Minimum) 
            || (bootdata->InData_BootData_ByteSize > Maximum)
            || ((bootdata->InData_BootData_ByteSize%16) != 0)) {
                DataNum = 0;
                break;
            }

            DataNum ++;
        }
    }

    return DataNum;
}


/*! *****************************************************************************
    @fn       uint32_t TSIP_SU_Activate(void)
    @brief    Initialization for Secure firmware update
    
    @retval    R_PASS                   success
    @retval    R_SEQUENCE_FAIL          cannot perform in current state
    @retval    R_FALSIFICATION_ERROR    tampering detection error
    @retval    R_RESOURCE_CONFLICT_FAIL resource for this process already used in other process
    
    @par    Details
    It performs initilization for Secure firmware update \n
    
    @par    Processing flow
    -# check initialization state in TSIP_Core layer
        - Is_TSIP_Core_Init()
    -# check transition state in TSIP Core layer
        - TSIP_Core_Check_State()
    -# initialize for Secure firmware update
        - TSIP_Core_Prc_p40()
    -# set transition state in TSIP_Core layer
        - TSIP_Core_Set_State()
 ********************************************************************************/
uint32_t TSIP_SU_Activate(void)
{
    uint8_t  BoolFg;
    uint32_t RetCode;

    BoolFg = Is_TSIP_Core_Init();
    RetCode = TSIP_Core_Check_State(TSIP_LIB_APIS);
    if((BoolFg == TSIP_TRUE) && (RetCode == R_PASS)) {
        RetCode = TSIP_Core_Prc_p40();
        if(RetCode == R_PASS) {
            TSIP_Core_Set_State(TSIP_CORE_STATE11);
        }
    }
    else {
        RetCode = R_SEQUENCE_FAIL;
    }
    return RetCode;
}

/*! *****************************************************************************
    @fn       uint32_t uint32_t TSIP_UpdateBootData(UPDATE_BOOT_DATA *update_bootdata)
    @brief    convert Boot data for update
    
    @param     [in/out]    *update_bootdata Pointer of Boot data

    @retval    R_PASS                       success
    @retval    R_PARAMETER_FAIL             invalid input parameter
    @retval    R_SEQUENCE_FAIL              cannot perform in current state
    @retval    R_VERIFICATION_FAIL          verification failed
    @retval    R_FALSIFICATION_ERROR        tampering detection error
    @retval    R_RESOURCE_CONFLICT_FAIL     resource for this process already used in other process
    
    @par    Details
    It decrypts encrypted Boot data and re-encrypts by TSIP key
    
    @par    Processing flow
    -# check initialization state in TSIP_Core layer
        - Is_TSIP_Core_Init()
    -# check transition state in TSIP Core layer
        - TSIP_Core_Check_State()
    -# decrypt encrypted Boot data and output re-encrypted Boot data
       - TSIP_Core_Prc_p45()  loop for number of valid data
 ********************************************************************************/
uint32_t TSIP_UpdateBootData(UPDATE_BOOT_DATA *update_bootdata)
{
    uint8_t  BoolFg;
    uint32_t RetCode;
    uint32_t DataNum;
    uint32_t LoopCount;
    UPDATEBOOTDATA *bootdata;

    BoolFg = Is_TSIP_Core_Init();
    RetCode = TSIP_Core_Check_State(TSIP_LIB_SECURE_UPDATE_APIS);
    if((BoolFg == TSIP_TRUE) && (RetCode == R_PASS)) {
        DataNum = Get_UpdateBootData_Num(update_bootdata);
        if(DataNum != 0) {
            bootdata  = (UPDATEBOOTDATA *)update_bootdata;
            for(LoopCount = 0; LoopCount < UPDATE_BOOT_DATA_MAX; LoopCount++, bootdata++) {
                if (bootdata->InData_BootData_UpdateFlag != 1) {    /* Not Updateing */
                    continue;
                }
                RetCode = TSIP_Core_Prc_p45( LoopCount,
                                        (const uint32_t *)bootdata->InData_BootData,  /* PRQA S 3305 */
                                                (uint32_t)bootdata->InData_BootData_ByteSize,
                                                (uint32_t *)bootdata->OutData_BootData); /* PRQA S 3305 */
                if(RetCode != R_PASS) {
                    break;
                }
            }
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


/*! *****************************************************************************
    @fn       uint32_t TSIP_SU_Key(uint8_t *InData_KeyRingOperationCode)
    @brief    Keyring decryption and re-encryption
    
    @param     [in]        *InData_KeyRingOperationCode       Pointer of Keyring(size:688Byte)
   
    @retval    R_PASS                   success
    @retval    R_PARAMETER_FAIL         invalid input parameter
    @retval    R_SEQUENCE_FAIL          cannot perform in current state
    @retval    R_VERIFICATION_FAIL      verification failed
    @retval    R_FALSIFICATION_ERROR    tampering detection error
    @retval    R_RESOURCE_CONFLICT_FAIL resource for this process already used in other process
    
    @par    Details
    It decrypts encrypted Keyring and re-encrypts by TSIP key \n
    
    @par    Processing flow
    -# check initialization state in TSIP_Core layer
        - Is_TSIP_Core_Init()
    -# check transition state in TSIP Core layer
        - TSIP_Core_Check_State()
    -# check parameter
    -# re-encrypt Keyring by TSIP key
       - TSIP_Core_Prc_p43()
 ********************************************************************************/
uint32_t TSIP_SU_Key(uint8_t *InData_KeyRingOperationCode)
{
    uint8_t  BoolFg;
    uint32_t RetCode;

    BoolFg = Is_TSIP_Core_Init();
    RetCode = TSIP_Core_Check_State(TSIP_LIB_SECURE_UPDATE_APIS);
    if((BoolFg == TSIP_TRUE) && (RetCode == R_PASS)) {
        if(InData_KeyRingOperationCode != NULL) {
            RetCode = TSIP_Core_Prc_p43((const uint32_t *)InData_KeyRingOperationCode); /* PRQA S 3305 */
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

