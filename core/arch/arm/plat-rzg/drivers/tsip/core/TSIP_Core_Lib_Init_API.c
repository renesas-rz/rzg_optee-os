/*
 * Copyright (c) 2020, Renesas Electronics Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*! *****************************************************************************
    @file    TSIP_Core_Lib_Init_API.c
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

#include "common/TSIP_Common_Define.h"
#include "core/TSIP_Core_API.h"
#include "core/TSIP_Core_Proc_API.h"
#include "core/TSIP_Core_Local_API.h"
#include "proc/TSIP_Procedure.h"
#include "stub/TSIP_Driver.h"

/*------------------------------------------------------------------------------*/
/*                        Prototype Definition                                  */
/*------------------------------------------------------------------------------*/


/*------------------------------------------------------------------------------*/
/*                        Function Definition                                   */
/*------------------------------------------------------------------------------*/
static uint32_t get_TSIP_Core_TSIPStatus(void);

/*! *****************************************************************************
    @fn       static uint32_t get_TSIP_Core_TSIPStatus(void)
    @brief    get TSIP library state
    
    @param     nothing
    
    @retval    R_PASS                  success
    @retval    R_SEQUENCE_FAIL         cannot perform in current state
    @retval    R_FALSIFICATION_ERROR   tampering detection error
    
    @par    Details
    It get library state by checking TSIP state(FSM1,FSM2) and tampering detection flag(REG18H)
    
    @par    Processing flow
    -# get tampering detection flag of TSIP REG18H
        - TSIPDrv_Read()
    -# check tampering detection flag and retrun error in tamper detection
    -# get state of TSIP FSM1
        - TSIPDrv_Read()
    -# get state of TSIP FSM2
        - TSIPDrv_Read()
    -# check FSM1 and FSM2 to confirm if library is available
    -# return check result
 ********************************************************************************/
static uint32_t get_TSIP_Core_TSIPStatus(void)
{
    uint32_t  regData0;
    uint32_t  regData1;
    uint32_t  regData2;

    regData0 = TSIPDrv_Read(REG_18H);  /* read REG18 */
    if ((regData0 & MASK_JUDG_FLAG_NG) == TSIP_JUDG_FLAG_NG) {
        return R_FALSIFICATION_ERROR;  /* tampering detection error */
    }

    regData1 = TSIPDrv_Read(REG_144H); /* read FSM1 */
    regData2 = TSIPDrv_Read(REG_148H); /* read FSM2 */
    if(((regData1 & MASK_DGSTATE_REG) != TSIP_STATE_MAIN07) ||    /* Don't Executed SecureBoot */
       ((regData2 & MASK_DGSTATE_REG) != TSIP_STATE_SECURE01)) {  /* Now Execute SecureUpdate */
        return R_SEQUENCE_FAIL;
    }
    return R_PASS;
}

/*! *****************************************************************************
    @fn       uint32_t TSIP_Lib_Init(uint8_t *S_RAMData,
                                     uint8_t *S_INSTData,
                                     uint8_t *TSIP_BaseAddress,
                                     uint8_t *MSTP_BaseAddress)
    @brief    Library initiaization
    
    @param     [in]        *S_RAMData          Pointer of S_RAM data(it needs 480Byte area)
    @param     [in]        *S_INSTData         Pointer of S_INST data(it needs 1296Byte area)
    @param     [in]        *TSIP_BaseAddress   Logical pointer of TSIP Base Address
    @param     [in]        *MSTP_BaseAddress   Logical pointer of MSTP Base Address
    
    @retval    R_PASS                   success
    @retval    R_PARAMETER_FAIL         invalid input parameter
    @retval    R_SEQUENCE_FAIL          cannot perform in current state
    @retval    R_MMAP_FAIL              error occur of mmap()
    @retval    R_FALSIFICATION_ERROR    tampering detection error
    
    @par    Details
    It performs initialization of TSIP library and self-checking of TSIP \n
    
    @par    Processing flow
    -# check initialization state of TSIP_Core layer
        - Is_TSIP_Core_Init()
    -# check parameter
    -# perform initialization in TSIP driver
        - TSIPDrv_Initialize()
    -# check TSIP state to confirm if library is available
        - Is_TSIP_Core_TSIPCondition_Enable()
    -# set initialization state in TSIP Core layer
        - TSIP_Core_Set_Init()
    -# set transition state in TSIP_Core layer
        - TSIP_Core_Set_State()
 ********************************************************************************/
uint32_t TSIP_Lib_Init(uint8_t *S_RAMData, uint8_t *S_INSTData,
                        uint8_t *TSIP_BaseAddress, uint8_t *MSTP_BaseAddress)
{
    uint8_t  BoolFg;
    uint32_t RetCode;
    uint8_t  Ret;

    BoolFg = Is_TSIP_Core_Init();
    if(BoolFg == TSIP_FALSE) {
        if((S_RAMData != NULL) && (S_INSTData != NULL)
        && (TSIP_BaseAddress != NULL) && (MSTP_BaseAddress != NULL)){
            Ret = TSIPDrv_Initialize(TSIP_BaseAddress, MSTP_BaseAddress);
            if(Ret == DRIVER_OK) {
                RetCode = get_TSIP_Core_TSIPStatus();
                if(RetCode == R_PASS) {
                    RetCode = TSIP_Core_Init(S_RAMData, S_INSTData);
                }

                if(RetCode != R_PASS) {
                    TSIPDrv_Finalize();
                }
            }
            else {
                RetCode = R_MMAP_FAIL;
            }
        }
        else {
            RetCode = R_PARAMETER_FAIL;
        }
    }
    else {
        RetCode = R_SEQUENCE_FAIL;
    }

    if(RetCode == R_PASS) {
        TSIP_Core_Set_Init(TSIP_TRUE);
        TSIP_Core_Set_State(TSIP_CORE_STATE10);
    }

    return RetCode;
}
