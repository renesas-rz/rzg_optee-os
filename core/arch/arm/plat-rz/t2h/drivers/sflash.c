/*
 * Copyright (c) 2024, Renesas Electronics Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <io.h>
#include <initcall.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <cpg.h>
#include <sflash.h>
#include <xspi.h>
#include <xspi_regs.h>
#include <sys.h>
#include <trace.h>

register_phys_mem_pgdir(MEM_AREA_IO_NSEC, SPI_FLASH_BASE_0, SPI_FLASH_SIZE);
register_phys_mem_pgdir(MEM_AREA_IO_NSEC, SPI_FLASH_BASE_1, SPI_FLASH_SIZE);

static vaddr_t sflash_base;
static uint32_t sflash_work[SPI_SECTOR_SIZE / sizeof(uint32_t)];

static vaddr_t sflash_phys_to_virt(uint32_t addr)
{
	return (vaddr_t)(sflash_base + (addr & 0x00FFFFFF));
}

void sflash_write_buffer(uint32_t addr, uintptr_t buff, size_t len)
{
	uintptr_t sflash_work_base = (uintptr_t)&sflash_work[0];
	uintptr_t base_sector_addr = ROUNDDOWN(addr, SPI_SECTOR_SIZE);
	uintptr_t last_sector_addr = ROUNDDOWN(addr + len - 1, SPI_SECTOR_SIZE);
	uint32_t  write_offset;
	uint32_t  write_length;
	int32_t   secotr_count;

	secotr_count = ((last_sector_addr - base_sector_addr) / SPI_SECTOR_SIZE) + 1;
	write_offset = addr - base_sector_addr;
	write_length = MIN(len, SPI_SECTOR_SIZE - write_offset);

	if (write_offset != 0) {

		vaddr_t virt_addr = sflash_phys_to_virt(base_sector_addr);

		memcpy((void *)sflash_work_base, (void *)virt_addr, SPI_SECTOR_SIZE);

		memcpy((void *)(sflash_work_base + write_offset), (void *)buff, write_length);

		xspi_write(base_sector_addr, sflash_work_base, SPI_SECTOR_SIZE);

		base_sector_addr += SPI_SECTOR_SIZE;

		secotr_count--;
	}

	write_length = (addr + len) - last_sector_addr;

	if ((secotr_count > 0) && ((write_length % SPI_SECTOR_SIZE) > 0)) {

		vaddr_t virt_addr = sflash_phys_to_virt(last_sector_addr);

		memcpy((void *)sflash_work_base, (void *)virt_addr, SPI_SECTOR_SIZE);

		memcpy((void *)sflash_work_base, (void *)((buff + len) - write_length), write_length);

		xspi_write(last_sector_addr, sflash_work_base, SPI_SECTOR_SIZE);

		secotr_count--;
	}

	write_length = secotr_count * SPI_SECTOR_SIZE;

	if(secotr_count > 0) {

		xspi_write(base_sector_addr, buff + (base_sector_addr - addr), write_length);
	}
}

void sflash_open(void)
{
	cpg_xspi_start();

	xspi_setup();
}

void sflash_close(void)
{
	cpg_xspi_stop();
}

static TEE_Result sflash_init(void)
{
	sflash_base = (vaddr_t)phys_to_virt_io(
		(SYS_BOOT_MODE_XSPI1_x1 == sys_get_boot_mode()) ? SPI_FLASH_BASE_1 : SPI_FLASH_BASE_0,
		SPI_FLASH_SIZE);

	return TEE_SUCCESS;
}

driver_init(sflash_init);