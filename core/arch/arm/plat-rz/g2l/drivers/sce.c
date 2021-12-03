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

#include "sce.h"
#include "r_sce/r_sce.h"

register_phys_mem_pgdir(MEM_AREA_IO_SEC, R_SCE_CFG_BASE, R_SCE_CFG_SIZE);

static sce_cfg_t sce_cfg;
static sce_instance_ctrl_t sce_instance_ctrl;

TEE_Result SCE_RandomNumberGenerate(uint32_t *buffer, size_t size)
{
    fsp_err_t err;

    size_t n;
    const size_t rand_sz = 4;

    assert(0 == (size % rand_sz));

    for (n = 0; n < size; n += rand_sz)
    {
        err = R_SCE_RandomNumberGenerate(&buffer[n]);
        switch (err)
        {
            case FSP_SUCCESS:
                break;
            default: /* FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT */
                return TEE_ERROR_BUSY;
        }
    }

    return TEE_SUCCESS;
}

static TEE_Result SCE_Init(void)
{
    fsp_err_t err;

    int32_t retry_cnt = 3;

    static uint32_t s_sce_sram[R_SCE_CFG_SRAM_SIZE / sizeof(uint32_t)];

    gp_sce      = (uint32_t *) phys_to_virt_io(R_SCE_CFG_BASE);
    gp_sce_sram = (uint32_t *) &s_sce_sram[0];

    while (0 < retry_cnt)
    {
        err = R_SCE_Open(&sce_instance_ctrl, &sce_cfg);
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
