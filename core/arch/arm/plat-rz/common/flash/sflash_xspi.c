// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2023-2025, Renesas Electronics Corporation
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <initcall.h>
#include <io.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <cpg.h>
#include <xspi.h>
#include <xspi_reg_values.h>
#include <sflash.h>
#include <platform_config.h>

struct sflash_dev {
	uint8_t ch; /* XSPI channel */
	paddr_t base; /* Flash base address */
	vaddr_t virt; /* Virtual address mapping */
	size_t	size; /* Flash size */
};

/* Work buffer for partial sector updates */
static uint32_t sflash_work[XSPI_SECTOR_SIZE / sizeof(uint32_t)];

static struct sflash_dev sflash_devices[] = {
#ifdef SFLASH_BASE
	{ .ch = 0, .base = SFLASH_BASE, .size = SFLASH_SIZE },
#else
#ifdef SFLASH_0_BASE
	{ .ch = 0, .base = SFLASH_0_BASE, .size = SFLASH_0_SIZE },
#endif
#ifdef SFLASH_1_BASE
	{ .ch = 1, .base = SFLASH_1_BASE, .size = SFLASH_1_SIZE },
#endif
#endif
};

/*
 * Find the flash device containing the specified address range.
 */
static struct sflash_dev *get_flash_device(uintptr_t addr, size_t len)
{
	for (size_t i = 0; i < ARRAY_SIZE(sflash_devices); i++) {
		struct sflash_dev *dev = &sflash_devices[i];

		if ((addr >= dev->base) &&
		    ((addr + len) <= (dev->base + dev->size)))
			return dev;
	}

	return NULL;
}

void sflash_write_buffer(uintptr_t addr, uintptr_t buff, size_t len)
{
	uintptr_t sflash_work_base = (uintptr_t)&sflash_work[0];
	uintptr_t base_sector_addr = ROUNDDOWN(addr, XSPI_SECTOR_SIZE);
	uintptr_t last_sector_addr =
		ROUNDDOWN(addr + len - 1, XSPI_SECTOR_SIZE);
	uint32_t write_offset;
	uint32_t write_length;
	int32_t	 sector_count;

	struct sflash_dev *dev = get_flash_device(addr, len);
	assert(dev);

	/* Calculate affected sector range */
	sector_count =
		((last_sector_addr - base_sector_addr) / XSPI_SECTOR_SIZE) + 1;
	write_offset = addr - base_sector_addr;
	write_length = MIN(len, XSPI_SECTOR_SIZE - write_offset);

	if (write_offset != 0) {
		/* Update first partial sector */
		sflash_read(base_sector_addr, sflash_work_base,
			    XSPI_SECTOR_SIZE);
		memcpy((void *)(sflash_work_base + write_offset), (void *)buff,
		       write_length);

		xspi_write(dev->ch, base_sector_addr, sflash_work_base,
			   XSPI_SECTOR_SIZE);

		base_sector_addr += XSPI_SECTOR_SIZE;
		sector_count--;
	}

	write_length = (addr + len) - last_sector_addr;

	if ((sector_count > 0) && ((write_length % XSPI_SECTOR_SIZE) > 0)) {
		/* Update last partial sector */
		sflash_read(last_sector_addr, sflash_work_base,
			    XSPI_SECTOR_SIZE);
		memcpy((void *)sflash_work_base,
		       (void *)((buff + len) - write_length), write_length);

		xspi_write(dev->ch, last_sector_addr, sflash_work_base,
			   XSPI_SECTOR_SIZE);

		sector_count--;
	}

	write_length = sector_count * XSPI_SECTOR_SIZE;

	/* Write remaining full sectors directly */
	if (sector_count > 0)
		xspi_write(dev->ch, base_sector_addr,
			   buff + (base_sector_addr - addr), write_length);
}

void sflash_read(uintptr_t addr, uintptr_t buff, size_t len)
{
	size_t offset;

	struct sflash_dev *dev = get_flash_device(addr, len);
	assert(dev);

	/* Convert flash address to mapped virtual address */
	offset = addr - dev->base;

	memcpy((uint8_t *)buff, (uint8_t *)dev->virt + offset, len);
}

void sflash_open(void)
{
	/* Enable XSPI controller and initialize flash devices */
	cpg_xspi_start();

	for (size_t i = 0; i < ARRAY_SIZE(sflash_devices); i++) {
		struct sflash_dev *dev = &sflash_devices[i];

		if (XSPI_OK != xspi_setup(dev->ch))
			panic();
	}
}

void sflash_close(void)
{
	/* Disable XSPI controller */
	cpg_xspi_stop();
}

static TEE_Result sflash_init(void)
{
	assert(0 < ARRAY_SIZE(sflash_devices));

	/* Create memory mapping for each flash device */
	for (size_t i = 0; i < ARRAY_SIZE(sflash_devices); i++) {
		struct sflash_dev *dev = &sflash_devices[i];

		dev->virt = (vaddr_t)phys_to_virt_io(dev->base, dev->size);
		if (!dev->virt)
			return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

driver_init(sflash_init);
