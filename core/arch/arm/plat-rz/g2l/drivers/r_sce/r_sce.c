/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, Renesas Electronics
 */
#include "r_sce.h"

/*******************************************************************************************************************//**
 * Enables use of SCE functionality.
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource needed
 *                                              by the processing routine was in use by another processing routine.
 * @retval FSP_ERR_CRYPTO_SCE_RETRY             Indicates that an entropy evaluation failure occurred.
 *                                              Run the function again.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Open (sce_ctrl_t * const p_ctrl, sce_cfg_t const * const p_cfg)
{
    fsp_err_t error_code = FSP_SUCCESS;

    sce_instance_ctrl_t * p_instance_ctrl = (sce_instance_ctrl_t *) p_ctrl;
    p_instance_ctrl->open = 1;
    (void) p_cfg;

    error_code = R_SCE_SelfCheck2Sub();

    if (FSP_SUCCESS != error_code)
    {
        R_SCE_Close(p_ctrl);
    }

    return error_code;
}

/*******************************************************************************************************************//**
 * Stops supply of power to the SCE.
 *
 * @retval FSP_SUCCESS              Normal termination
 **********************************************************************************************************************/
fsp_err_t R_SCE_Close (sce_ctrl_t * const p_ctrl)
{
    sce_instance_ctrl_t * p_instance_ctrl = (sce_instance_ctrl_t *) p_ctrl;
    p_instance_ctrl->open = 0;

    return FSP_SUCCESS;
}

/*******************************************************************************************************************//**
 * This API can generate 4 words random number.
 *
 * @param[in,out] random Stores 4words (16 bytes) random data.
 *
 * @retval FSP_SUCCESS                          Normal termination
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT A resource conflict occurred because a hardware resource needed
 *                                              by the processing routine was in use by another processing routine.
 **********************************************************************************************************************/
fsp_err_t R_SCE_RandomNumberGenerate (uint32_t * random)
{
    return R_SCE_GenerateRandomNumberSub(random);
}
