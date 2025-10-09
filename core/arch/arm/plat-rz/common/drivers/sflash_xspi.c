// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2023-2025, Renesas Electronics Corporation
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <io.h>
#include <initcall.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <cpg.h>
#include <sflash.h>
#include <xspi.h>
#include <xspi_regs.h>

#if defined(SPI_FLASH_BASE)
#define SPI_FLASH_BASE_0    (SPI_FLASH_BASE)
#endif

static vaddr_t sflash_base[2];
static uint32_t sflash_work[SPI_SECTOR_SIZE / sizeof(uint32_t)];

static uint8_t get_channel(uintptr_t addr)
{
#if defined(SPI_FLASH_BASE_1)
	if ((SPI_FLASH_BASE_1 <= addr) && ((SPI_FLASH_BASE_1 + SPI_FLASH_SIZE) > addr))
		return 1;
#endif
	return 0;
}

static vaddr_t sflash_phys_to_virt(uint32_t addr)
{
	return (vaddr_t)(sflash_base[get_channel(addr)] + (addr & 0x00FFFFFF));
}

void sflash_write_buffer(uintptr_t addr, uintptr_t buff, size_t len)
{
	uintptr_t sflash_work_base = (uintptr_t)&sflash_work[0];
	uintptr_t base_sector_addr = ROUNDDOWN(addr, SPI_SECTOR_SIZE);
	uintptr_t last_sector_addr = ROUNDDOWN(addr + len - 1, SPI_SECTOR_SIZE);
	uint32_t  write_offset;
	uint32_t  write_length;
	int32_t   sector_count;

	sector_count = ((last_sector_addr - base_sector_addr) / SPI_SECTOR_SIZE) + 1;
	write_offset = addr - base_sector_addr;
	write_length = MIN(len, SPI_SECTOR_SIZE - write_offset);

	if (write_offset != 0) {
		sflash_read(base_sector_addr, sflash_work_base, SPI_SECTOR_SIZE);

		memcpy((void *)(sflash_work_base + write_offset), (void *)buff, write_length);

		xspi_write(get_channel(addr), base_sector_addr, sflash_work_base, SPI_SECTOR_SIZE);

		base_sector_addr += SPI_SECTOR_SIZE;

		sector_count--;
	}

	write_length = (addr + len) - last_sector_addr;

	if ((sector_count > 0) && ((write_length % SPI_SECTOR_SIZE) > 0)) {
		sflash_read(last_sector_addr, sflash_work_base, SPI_SECTOR_SIZE);

		memcpy((void *)sflash_work_base, (void *)((buff + len) - write_length), write_length);

		xspi_write(get_channel(addr), last_sector_addr, sflash_work_base, SPI_SECTOR_SIZE);

		sector_count--;
	}

	write_length = sector_count * SPI_SECTOR_SIZE;

	if (sector_count > 0)
		xspi_write(get_channel(addr), base_sector_addr, buff + (base_sector_addr - addr), write_length);
}

void sflash_read(uintptr_t addr, uintptr_t buff, size_t len)
{
	vaddr_t virt_addr = sflash_phys_to_virt(addr);

	memcpy((void *)buff, (void *)virt_addr, len);
}

void sflash_open(void)
{
	cpg_xspi_start();

	xspi_setup(0);

#if defined(SPI_FLASH_BASE_1)
	xspi_setup(1);
#endif
}

void sflash_close(void)
{
	cpg_xspi_stop();
}

static TEE_Result sflash_init(void)
{
	memset(sflash_base, 0, sizeof(sflash_base));

	sflash_base[0] = (vaddr_t)phys_to_virt_io(SPI_FLASH_BASE_0, SPI_FLASH_SIZE);
#if defined(SPI_FLASH_BASE_1)
	sflash_base[1] = (vaddr_t)phys_to_virt_io(SPI_FLASH_BASE_1, SPI_FLASH_SIZE);
#endif

	return TEE_SUCCESS;
}

driver_init(sflash_init);
