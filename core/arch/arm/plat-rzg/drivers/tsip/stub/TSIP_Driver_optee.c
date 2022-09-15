/*
 * Copyright (c) 2020, Renesas Electronics Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*! *****************************************************************************
    @file    TSIP_Driver_optee.c
    @brief   TSIP Driver API for OP-TEE
    
    @par    History
    @subsection sub_history 
      - Initial version\n
 ********************************************************************************/

/*------------------------------------------------------------------------------*/
/*                        Include Files                                         */
/*------------------------------------------------------------------------------*/

#include <stddef.h>
#include <stdint.h>

#include "stub/TSIP_Driver.h"
#include "proc/TSIP_Procedure.h"
#include "common/TSIP_Common_Define.h"

/*------------------------------------------------------------------------------*/
/*                        Macro Definition                                      */
/*------------------------------------------------------------------------------*/

#define  MSTP_BASE_ADDR  (0xE6150000U)
#define  MSTP_SIZE       (0x00001000U)
#define  MSTPSR1         (0x00000038 >> 2)
#define  RMSTPCR1        (0x00000114 >> 2)
#define  SMSTPCR1        (0x00000134 >> 2)


/*------------------------------------------------------------------------------*/
/*                        Prototype Definition                                  */
/*------------------------------------------------------------------------------*/

/*!
    @var      gpTSIP
    @brief    TSIP register
    
    @par    
    - TSIP_Driver.c
        - TSIPDrv_Initialize()
        - TSIPDrv_Finalize()
 */

/*------------------------------------------------------------------------------*/
/*                        Function Definition                                   */
/*------------------------------------------------------------------------------*/

/*! *****************************************************************************
    @fn       uint8_t TSIPDrv_Initialize(void)
    @brief    TSIP Driver initialization
    
    @param     [in]        *TSIP_BaseAddress   TSIP Base Address
    @param     [in]        *MSTP_BaseAddress   MSTP Base Address

    @retval    DRIVER_OK        success
    @retval    DRIVER_ERROR     error
    
    @par    Global veriables
    <table class="params">
    <tr><td class="paramdir"> [out] </td><td> @ref gpTSIP   </td></tr>
    </table>
    
    @post
    - call TSIPDrv_Finalize()
    
    @par    Details
    It initializes TSIP driver. \n
    
    @par    Processing flow
    -# Map the registry
 ********************************************************************************/
uint8_t TSIPDrv_Initialize(uint8_t *TSIP_BaseAddress, uint8_t *MSTP_BaseAddress) {

    volatile uint32_t* pMSTPCR;
    uint8_t ret;

    if (TSIP_BaseAddress == NULL || MSTP_BaseAddress == NULL) {
        ret = DRIVER_ERROR;         /* error */
    } else {
        ret = DRIVER_OK;
        pMSTPCR = (uint32_t *)MSTP_BaseAddress; /* PRQA S 3305 */
        pMSTPCR[RMSTPCR1] &= 0xFFFFFFBFU;
        pMSTPCR[SMSTPCR1] &= 0xFFFFFFBFU;
        gpTSIP = (uint32_t *)TSIP_BaseAddress;  /* PRQA S 3305 */
    }

    return ret;
}

/*! *****************************************************************************
    @fn       void TSIPDrv_Finalize(void)
    @brief    TSIP Driver finalization
    
    @par    Global veriables
    <table class="params">
    <tr><td class="paramdir"> [in,out] </td><td> @ref gpTSIP   </td></tr>
    </table>
    
    @pre
    - call TSIPDrv_Initialize() \n
    
    @par    Details
    It finish TSIP driver \n
    
    @par    Processing flow
    -# Unmap the registry
 ********************************************************************************/
void TSIPDrv_Finalize(void) {

    if (gpTSIP != NULL) {
        gpTSIP = NULL;
    }

    return;
}


