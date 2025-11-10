// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2023-2025, Renesas Electronics Corporation
 */

#include <sys.h>
#include <sys_regs.h>
#include <initcall.h>
#include <mm/core_memprot.h>
#include <io.h>
#include <kernel/panic.h>
#include <mbxsem.h>

vaddr_t sys_base;
vaddr_t sys_ns_base;
vaddr_t sys_safety_base;

void sys_base_unlock(uint32_t unlock_mask)
{
	uint32_t prcrn;

	/* Unlock PRCRN bit(s) in given mask */
	prcrn = io_read32(sys_ns_base + PRCRN) & 0x0000000FU;
	io_write32(sys_ns_base + PRCRN, (prcrn | 0x0000A500U | unlock_mask));
}

void sys_base_lock(uint32_t lock_mask)
{
	uint32_t prcrn;

	/* Lock PRCRN bit(s) in given mask */
	prcrn = io_read32(sys_ns_base + PRCRN) & 0x0000000FU & (~lock_mask);
	io_write32(sys_ns_base + PRCRN, (prcrn | 0x0000A500U));
}

void sys_safetybase_unlock(uint32_t unlock_mask)
{
	uint32_t prcrs;

	/* Unlock PRCRS bit(s) in given mask */
	prcrs = io_read32(sys_safety_base + PRCRS) & 0x0000000FU;
	io_write32(sys_safety_base + PRCRS, (prcrs  | 0x0000A500U | unlock_mask));
}

void sys_safetybase_lock(uint32_t lock_mask)
{
	uint32_t prcrs;

	/* Lock PRCRS bit(s) in given mask */
	prcrs = io_read32(sys_safety_base + PRCRS) & 0x0000000FU & (~lock_mask);
	io_write32(sys_safety_base + PRCRS, (prcrs | 0x0000A500U));
}

void sys_set_end_address(void)
{
	/* Hardware Semaphore lock */
	mbxsem_wait_regprotect();

	sys_base_unlock(PRCRx_SYS_CTRL);
	io_write32(sys_base + XSPI0CS0_END_ADD, (0x47FFFFFFU));
	io_write32(sys_base + XSPI1CS1_END_ADD, (0x57FFFFFFU));
	sys_base_lock(PRCRx_SYS_CTRL);

	/* Hardware Semaphore unlock */
	mbxsem_post_regprotect();
}

static TEE_Result sys_init(void)
{
	sys_base = (vaddr_t)phys_to_virt_io(SYS_BASE, SYS_SIZE);
	sys_ns_base = (vaddr_t)phys_to_virt_io(SYS_NS_BASE, SYS_NS_SIZE);
	sys_safety_base = (vaddr_t)phys_to_virt_io(SYS_SAFETY_BASE, SYS_SAFETY_SIZE);

	sys_set_end_address();

	return TEE_SUCCESS;
}

service_init_late(sys_init);
