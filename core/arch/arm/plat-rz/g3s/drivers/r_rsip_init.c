// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024, Renesas Electronics
 */
#include <string.h>
#include <assert.h>
#include <initcall.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <kernel/panic.h>

#include <r_rsip.h>
#include <r_rsip_addr.h>

#define RSIP_BASE	(0x11850000)
#define RSIP_SIZE	(0x00010000)

register_phys_mem_pgdir(MEM_AREA_IO_SEC, RSIP_BASE, RSIP_SIZE);

volatile uint32_t * gp_sce;

static TEE_Result RSIP_Init(void)
{
    fsp_err_t err;

    gp_sce = (uint32_t *) phys_to_virt_io(RSIP_BASE, RSIP_SIZE);

    return TEE_SUCCESS;
}

driver_init(RSIP_Init);
