/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, Renesas Electronics
 */

#ifndef R_SCE_H
#define R_SCE_H

#include <r_sce_private.h>

/** SCE Control block. Allocate an instance specific control block to pass into the API calls.
 * @par Implemented as
 * - sce_instance_ctrl_t
 */
typedef void sce_ctrl_t;

/** SCE private control block. DO NOT MODIFY. Initialization occurs when R_SCE_Open() is called. */
typedef struct st_sce_instance_ctrl
{
    uint32_t open;                     // Indicates whether the open() API has been successfully
} sce_instance_ctrl_t;

/** User configuration structure, used in open function */
typedef struct st_sce_cfg
{
    void* unused;
} sce_cfg_t;

fsp_err_t R_SCE_Open(sce_ctrl_t * const p_ctrl, sce_cfg_t const * const p_cfg);
fsp_err_t R_SCE_Close (sce_ctrl_t * const p_ctrl);

fsp_err_t R_SCE_RandomNumberGenerate(uint32_t * random);

#endif /* R_SCE_H */
