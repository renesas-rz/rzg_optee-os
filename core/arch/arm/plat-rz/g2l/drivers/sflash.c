/*
 * Copyright (c) 2023, Renesas Electronics Corporation. All rights reserved.
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
#include <spi_multi.h>
#include <spi_multi_regs.h>
#include <spi_multi_reg_values.h>

register_phys_mem_pgdir(MEM_AREA_IO_NSEC, SPI_FLASH_BASE, SPI_FLASH_SIZE);

static vaddr_t sflash_base;
static uint32_t sflash_work[SPI_SECTOR_SIZE / sizeof(uint32_t)];

static vaddr_t sflash_phys_to_virt(uint32_t addr)
{
	return (vaddr_t)(sflash_base + (addr & 0x00FFFFFF));
}

static void sflash_page_program(uint32_t addr, uintptr_t buff, size_t len)
{
	for (size_t i = 0; i < len; i += SPI_PAGE_SIZE)
		spi_multi_page_program(addr + i, buff + i);

	spi_multi_setup();
}

static void sflash_sector_erase(uint32_t addr, size_t len)
{
	for (size_t i = 0; i < len; i += SPI_SECTOR_SIZE)
		spi_multi_erase_sector(addr + i);

	spi_multi_setup();
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

		sflash_sector_erase(base_sector_addr, SPI_SECTOR_SIZE);

		sflash_page_program(base_sector_addr, sflash_work_base, SPI_SECTOR_SIZE);

		base_sector_addr += SPI_SECTOR_SIZE;

		secotr_count--;
	}

	write_length = (addr + len) - last_sector_addr;

	if ((secotr_count > 0) && ((write_length % SPI_SECTOR_SIZE) > 0)) {

		vaddr_t virt_addr = sflash_phys_to_virt(last_sector_addr);

		memcpy((void *)sflash_work_base, (void *)virt_addr, SPI_SECTOR_SIZE);

		memcpy((void *)sflash_work_base, (void *)((buff + len) - write_length), write_length);

		sflash_sector_erase(last_sector_addr, SPI_SECTOR_SIZE);

		sflash_page_program(last_sector_addr, sflash_work_base, SPI_SECTOR_SIZE);

		secotr_count--;
	}

	write_length = secotr_count * SPI_SECTOR_SIZE;

	if(secotr_count > 0) {

		sflash_sector_erase(base_sector_addr, write_length);

		sflash_page_program(base_sector_addr, buff + (base_sector_addr - addr), write_length);
	}
}

void sflash_open(void)
{
	cpg_spi_multi_start();

	spi_multi_setup();
}

void sflash_close(void)
{
	cpg_spi_multi_stop();
}

static TEE_Result sflash_init(void)
{
	sflash_base = (vaddr_t)phys_to_virt_io(SPI_FLASH_BASE, SPI_FLASH_SIZE);

	return TEE_SUCCESS;
}

driver_init(sflash_init);