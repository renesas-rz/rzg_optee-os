/*
 * Copyright (c) 2023-2024, Renesas Electronics Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <sys.h>
#include <sys_regs.h>
#include <initcall.h>
#include <mm/core_memprot.h>
#include <io.h>
#include <kernel/panic.h>

register_phys_mem_pgdir(MEM_AREA_IO_NSEC, SYS_BASE, SYS_SIZE + SYS_NS_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, SYS_SAFETY_BASE, SYS_SAFETY_SIZE);

vaddr_t sys_base;
vaddr_t sys_ns_base;
vaddr_t sys_safety_base;

boot_mode_t sys_get_boot_mode(void)
{
	uint8_t boot_dev  = (io_read32(sys_ns_base + MD_MON) >> MD_MON_MD0MON_BIT) & MD_MON_MDxMON_MSK;
	boot_mode_t boot_mode;

	switch (boot_dev) {
	case (MD_MON_MODE_ESD):
		boot_mode = SYS_BOOT_MODE_ESD;
		break;

	case (MD_MON_MODE_EMMC):
		boot_mode = SYS_BOOT_MODE_EMMC;
		break;

	case (MD_MON_MODE_XSPI0_x1):
		boot_mode = SYS_BOOT_MODE_XSPI0_x1;
		break;

	case (MD_MON_MODE_XSPI0_x8):
		boot_mode = SYS_BOOT_MODE_XSPI0_x8;
		break;

	case (MD_MON_MODE_XSPI1_x1):
		boot_mode = SYS_BOOT_MODE_XSPI1_x1;
		break;

	default:
		panic();
	}

	return boot_mode;
}

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

uint32_t sys_get_flash_base(void)
{
	return (vaddr_t)phys_to_virt_io(
		(SYS_BOOT_MODE_XSPI1_x1 == sys_get_boot_mode()) ? SPI_FLASH_BASE_1 : SPI_FLASH_BASE_0,
		SPI_FLASH_SIZE);
}

static TEE_Result sys_init(void)
{
	sys_base = (vaddr_t)phys_to_virt_io(SYS_BASE, SYS_SIZE);
	sys_ns_base = (vaddr_t)phys_to_virt_io(SYS_NS_BASE, SYS_NS_SIZE);
	sys_safety_base = (vaddr_t)phys_to_virt_io(SYS_SAFETY_BASE, SYS_SAFETY_SIZE);

	return TEE_SUCCESS;
}

service_init_late(sys_init);