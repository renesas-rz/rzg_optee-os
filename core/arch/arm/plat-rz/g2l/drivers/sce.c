// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, Renesas Electronics
 */

#include <initcall.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <kernel/panic.h>

#include <r_sce_api.h>

#define SCE_SELF_DIAG_RETRY     (3)

static TEE_Result init_sce(void)
{
    fsp_err_t err;
    
    int32_t retry = SCE_SELF_DIAG_RETRY;

    while (0 < retry_cnt)
    {
        err = R_SCE_SelfCheck2Sub();
        switch (err)
        {
            case FSP_ERR_CRYPTO_SCE_RETRY:
                retry_cnt--;
                break;
            default:
                retry_cnt = 0;
                break;
        }
    }

    if (FSP_SUCCESS != err)
    {
        EMSG("Failed to initialize SCE (0x%08x).", err);
        panic();
    }
    
    return TEE_SUCCESS;
}

driver_init(init_sce);
