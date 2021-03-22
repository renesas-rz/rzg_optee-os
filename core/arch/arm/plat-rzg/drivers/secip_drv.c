// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2021 Renesas Electronics Corporation. All rights reserved.
 */

#include <initcall.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <kernel/panic.h>

#include "tsip/R_TSIP_Core_Lib.h"

#define S_INST_DATA_ADDR    (0x440FE000)
#define S_INST_DATA_SIZE    (0x2000)

static uint8_t s_ram_data[480];
vaddr_t s_inst_data = (vaddr_t)NULL;

register_phys_mem_pgdir(MEM_AREA_IO_SEC, TSIP_BASE_ADDR, TSIP_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, S_INST_DATA_ADDR, S_INST_DATA_SIZE);

TEE_Result secip_rng(void *buf, size_t blen)
{
    uint32_t err;
    
    if(!buf){
        EMSG("Invalid buffer");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (0 < blen) {
        err = R_TSIP_BCF_GenerateRandom(blen, 0, buf);
        if (R_PASS != err) {
            EMSG("Failed to generate a random number (0x%08x).", err);
            return TEE_ERROR_GENERIC;
        }
    }

    return TEE_SUCCESS;
}

static TEE_Result init_secip(void)
{
    uint32_t err;
    vaddr_t tsip_base_address;
    vaddr_t mstp_base_address;

    tsip_base_address = (vaddr_t)phys_to_virt_io(TSIP_BASE_ADDR, TSIP_SIZE);
    mstp_base_address = (vaddr_t)phys_to_virt_io(MSTP_BASE_ADDR, MSTP_SIZE);

    s_inst_data = (vaddr_t)phys_to_virt_io(S_INST_DATA_ADDR, S_INST_DATA_SIZE);

    err = R_TSIP_Lib_Init((uint8_t *)s_ram_data, (uint8_t *)s_inst_data, 
                          (uint8_t *)tsip_base_address, (uint8_t *)mstp_base_address);
    if (R_PASS != err)
    {
        EMSG("Failed to initialize TSIP Library (0x%08x).", err);
        panic();
    }
    
    return TEE_SUCCESS;
}

driver_init(init_secip);
