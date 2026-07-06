// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2023-2025, Renesas Electronics Corporation
 */

#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include <initcall.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <sys.h>
#include <sys_regs.h>
#include <hwsem.h>
#include <platform_config.h>

static vaddr_t sys_base;
static vaddr_t sys_base_safety;

static void sys_prcr_lock(vaddr_t base, uint32_t offset, uint32_t mask)
{
	uint32_t value;

	value = io_read32(base + offset) & SYS_PRCR_MASK;
	value |= mask;
	io_write32(base + offset, value | SYS_PRCR_KEY_CODE);
}

static void sys_prcr_unlock(vaddr_t base, uint32_t offset, uint32_t mask)
{
	uint32_t value;

	value = io_read32(base + offset) & SYS_PRCR_MASK;
	value &= ~mask;
	io_write32(base + offset, value | SYS_PRCR_KEY_CODE);
}

static void sys_start_slave(uint32_t offset, uint32_t req_mask,
			    uint32_t ack_mask)
{
	uint32_t value;

	sys_unlock_sysctrl();

	value = io_read32(sys_base_safety + offset);
	value &= ~req_mask;
	io_write32(sys_base_safety + offset, value);

	sys_lock_sysctrl();

	while (0U != (io_read32(sys_base_safety + offset) & ack_mask))
		;
}

static void sys_stop_slave(uint32_t offset, uint32_t req_mask,
			   uint32_t ack_mask)
{
	uint32_t value;

	sys_unlock_sysctrl();

	value = io_read32(sys_base_safety + offset);
	value |= req_mask;
	io_write32(sys_base_safety + offset, value);

	sys_lock_sysctrl();

	while (0U == (io_read32(sys_base_safety + offset) & ack_mask))
		;
}

void sys_lock_cgc(void)
{
	sys_prcr_lock(sys_base, SYS_PRCRN_OFFSET, SYS_PRCR_CGC);
	sys_prcr_lock(sys_base_safety, SYS_PRCRS_OFFSET, SYS_PRCR_CGC);
}

void sys_unlock_cgc(void)
{
	sys_prcr_unlock(sys_base, SYS_PRCRN_OFFSET, SYS_PRCR_CGC);
	sys_prcr_unlock(sys_base_safety, SYS_PRCRS_OFFSET, SYS_PRCR_CGC);
}

void sys_lock_pwr(void)
{
	sys_prcr_lock(sys_base, SYS_PRCRN_OFFSET, SYS_PRCR_PWR);
	sys_prcr_lock(sys_base_safety, SYS_PRCRS_OFFSET, SYS_PRCR_PWR);
}

void sys_unlock_pwr(void)
{
	sys_prcr_unlock(sys_base, SYS_PRCRN_OFFSET, SYS_PRCR_PWR);
	sys_prcr_unlock(sys_base_safety, SYS_PRCRS_OFFSET, SYS_PRCR_PWR);
}

void sys_lock_sysctrl(void)
{
	sys_prcr_lock(sys_base, SYS_PRCRN_OFFSET, SYS_PRCR_SYSCTRL);
	sys_prcr_lock(sys_base_safety, SYS_PRCRS_OFFSET, SYS_PRCR_SYSCTRL);
}

void sys_unlock_sysctrl(void)
{
	sys_prcr_unlock(sys_base, SYS_PRCRN_OFFSET, SYS_PRCR_SYSCTRL);
	sys_prcr_unlock(sys_base_safety, SYS_PRCRS_OFFSET, SYS_PRCR_SYSCTRL);
}

void sys_start_slave_xspi0(void)
{
	sys_start_slave(SYS_SSTPCR6_OFFSET, SYS_SSTPCR6_XSPI0_REQ,
			SYS_SSTPCR6_XSPI0_ACK);
}

void sys_stop_slave_xspi0(void)
{
	sys_stop_slave(SYS_SSTPCR6_OFFSET, SYS_SSTPCR6_XSPI0_REQ,
		       SYS_SSTPCR6_XSPI0_ACK);
}

void sys_start_slave_xspi1(void)
{
	sys_start_slave(SYS_SSTPCR6_OFFSET, SYS_SSTPCR6_XSPI1_REQ,
			SYS_SSTPCR6_XSPI1_ACK);
}

void sys_stop_slave_xspi1(void)
{
	sys_stop_slave(SYS_SSTPCR6_OFFSET, SYS_SSTPCR6_XSPI1_REQ,
		       SYS_SSTPCR6_XSPI1_ACK);
}

static TEE_Result sys_init(void)
{
	sys_base = (vaddr_t)phys_to_virt_io(SYS_BASE, SYS_SIZE);
	sys_base_safety =
		(vaddr_t)phys_to_virt_io(SYS_BASE_SAFETY, SYS_SIZE_SAFETY);
	assert(sys_base && sys_base_safety);

	sem_regprotect_lock();

	sys_unlock_sysctrl();

	io_write32(sys_base + SYS_CS0ENDAD_XSPI0_OFFSET, 0x47FFFFFFU);
	io_write32(sys_base + SYS_CS0ENDAD_XSPI1_OFFSET, 0x57FFFFFFU);

	sys_lock_sysctrl();

	sem_regprotect_unlock();

	return TEE_SUCCESS;
}

service_init_late(sys_init);
