// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, Renesas Electronics
 */
#include <string.h>
#include <assert.h>
#include <initcall.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <kernel/panic.h>

#include <r_sce.h>

register_phys_mem_pgdir(MEM_AREA_IO_SEC, HW_SCE_BASE, HW_SCE_SIZE);

static sce_cfg_t sce_cfg;
static sce_instance_ctrl_t sce_instance_ctrl;

static TEE_Result SCE_Init(void)
{
    fsp_err_t err;

    int32_t retry_cnt = 3;

    gp_sce = (uint32_t *) phys_to_virt_io(HW_SCE_BASE, HW_SCE_SIZE);

    while (0 < retry_cnt)
    {
        err = g_sce_protected_on_sce.open(&sce_instance_ctrl, &sce_cfg);
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

driver_init(SCE_Init);
