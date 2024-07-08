/*
 * Copyright (c) 2020-2023, Renesas Electronics Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include <io.h>
#include <initcall.h>
#include <mm/core_memprot.h>
#include <spi_multi.h>
#include <spi_multi_regs.h>
#include <spi_multi_reg_values.h>
#include <spi_multi_device.h>

register_phys_mem_pgdir(MEM_AREA_IO_NSEC, SPI_MULTI_BASE, SPI_MULTI_SIZE);

vaddr_t spi_multi_base;

void spi_multi_timing_set(void)
{
	/* Timing adjustment register setting */
	spi_io_write(SPIM_PHYADJ2, 0xA5390000);
	spi_io_write(SPIM_PHYADJ1, 0x80000000);
	spi_io_write(SPIM_PHYADJ2, 0x00008080);
	spi_io_write(SPIM_PHYADJ1, 0x80000022);
	spi_io_write(SPIM_PHYADJ2, 0x00008080);
	spi_io_write(SPIM_PHYADJ1, 0x80000024);

	/* SDR mode serial flash settings */
	spi_io_write(SPIM_PHYCNT, SPIM_PHYCNT_SDR_TIM_ADJ_SET_VALUE);

	/* Timing adjustment register setting */
	spi_io_write(SPIM_PHYADJ2, 0x00000030);
	spi_io_write(SPIM_PHYADJ1, 0x80000032);
}

uint8_t spi_multi_cmd_read(uint8_t command)
{
	uint32_t val;
	uint8_t r_status;

	/* SDR mode serial flash settings */
	spi_io_write(SPIM_PHYCNT, SPIM_PHYCNT_SET_VALUE);
	spi_io_write(SPIM_PHYCNT, SPIM_PHYCNT_SDR_TIM_ADJ_SET_VALUE);

	/* Set the QSPIn_SSL setting value & Manual Mode */
	spi_io_write(SPIM_CMNCR, SPIM_CMNCR_MANUAL_SET_VALUE);

	val = command << SMCMR_CMD_BIT_SHIFT;
	spi_io_write(SPIM_SMCMR, val);

	/* Set the Transfer Data size setting value &  command output enable */
	val = SMENR_CDE | SPI_MANUAL_COMMAND_SIZE_16_BIT;
	spi_io_write(SPIM_SMENR, val);

	/* Set the SDR transfer & SPI flash mode setting value */
	spi_io_write(SPIM_SMDRENR, SPIM_SMDRENR_SET_VALUE);

	val = SMCR_SPIE | SMCR_SPIRE;
	spi_io_write(SPIM_SMCR, val);

	/* Wait until the transfer is complete */
	do {
		val = spi_io_read(SPIM_CMNSR);
	} while ((val & CMNSR_TEND) == 0);

	val = spi_io_read(SPIM_SMRDR0);

	r_status = (uint8_t)val;
	return r_status;
}

void spi_multi_cmd_write(uint8_t command, uint8_t size, uint32_t data)
{
	uint32_t val;

	/* SDR mode serial flash settings */
	spi_io_write(SPIM_PHYCNT, SPIM_PHYCNT_SET_VALUE);
	spi_io_write(SPIM_PHYCNT, SPIM_PHYCNT_SDR_TIM_ADJ_SET_VALUE);

	/* Set the QSPIn_SSL setting value & Manual Mode */
	spi_io_write(SPIM_CMNCR, SPIM_CMNCR_MANUAL_SET_VALUE);

	/* Set the Manual Mode Command */
	val = command << SMCMR_CMD_BIT_SHIFT;
	spi_io_write(SPIM_SMCMR, val);

	/* Set the Transfer Data size setting value &  command output enable */
	val = SMENR_CDE | size;
	spi_io_write(SPIM_SMENR, val);

	/* Set the write data in Manual mode */
	spi_io_write(SPIM_SMWDR0, data);

	/* Set the SDR transfer & SPI flash mode setting value */
	spi_io_write(SPIM_SMDRENR, SPIM_SMDRENR_SET_VALUE);

	/* Set the data transfer enable & data write enable  */
	if (size == SPI_MANUAL_COMMAND_SIZE_0) {
		val = SMCR_SPIE;
	} else {
		val = SMCR_SPIE | SMCR_SPIWE;
	}
	spi_io_write(SPIM_SMCR, val);

	/* Wait until the transfer is complete */
	do {
		val = spi_io_read(SPIM_CMNSR);
	} while ((val & CMNSR_TEND) == 0);
}

void spi_multi_page_program(uint32_t addr, uintptr_t buff)
{
	uint32_t val;

	/* Write Enable Command */
	spi_multi_cmd_write(SMCMR_CMD_WRITE_ENABLE, SPI_MANUAL_COMMAND_SIZE_0, 0);

	/* Clear the RCF bit */
	spi_io_write(SPIM_DRCR, SPIM_DRCR_SET_VALUE);

	/* SDR mode serial flash settings & WBUF enable */
	val = spi_io_read(SPIM_PHYCNT) | PHYCNT_CAL_PERFOMED | PHYCNT_WBUF2_USED | PHYCNT_WBUF_USED;
	spi_io_write(SPIM_PHYCNT, val);

	/* Set the QSPIn_SSL setting value & Manual Mode  */
	spi_io_write(SPIM_CMNCR, SPIM_CMNCR_MANUAL_SET_VALUE);

	/* Set the Page Program */
	val = SMCMR_CMD_PAGE_PROGRAM << SMCMR_CMD_BIT_SHIFT;
	spi_io_write(SPIM_SMCMR, val);

	/* Set the Write Address */
	spi_io_write(SPIM_SMADR, addr);

	/* Set the SDR transfer & SPI flash mode setting value */
	spi_io_write(SPIM_SMDRENR, SPIM_SMDRENR_SET_VALUE);

	/* Set the Transfer Data size, address enable &  command output enable */
	val = SMENR_CDE | SMENR_ADE_ADR23_0_OUT | SPI_MANUAL_COMMAND_SIZE_32_BIT;
	spi_io_write(SPIM_SMENR, val);

	for (int i = 0; i < SPI_PAGE_SIZE; i += 4)
		spi_io_write(SPIM_WBUF + i, io_read32(buff + i));

	/* Set the data transfer enable & data write enable  */
	val = SMCR_SPIE | SMCR_SPIWE;
	spi_io_write(SPIM_SMCR, val);

	/* Wait until the transfer is complete */
	do {
		val = spi_io_read(SPIM_CMNSR);
	} while ((val & CMNSR_TEND) == 0);

	/* Clear the RCF bit */
	spi_io_write(SPIM_DRCR, SPIM_DRCR_SET_VALUE);

	spi_multi_busy_wait();
}

void spi_multi_erase_sector(uint32_t addr)
{
	uint32_t val;

	/* Write Enable Command */
	spi_multi_cmd_write(SMCMR_CMD_WRITE_ENABLE, SPI_MANUAL_COMMAND_SIZE_0, 0);

	/* Clear the RCF bit */
	spi_io_write(SPIM_DRCR, SPIM_DRCR_SET_VALUE);

	/* SDR mode serial flash settings */
	val = spi_io_read(SPIM_PHYCNT) | PHYCNT_CAL_PERFOMED;
	spi_io_write(SPIM_PHYCNT, val);

	/* Set the QSPIn_SSL setting value & Manual Mode  */
	spi_io_write(SPIM_CMNCR, SPIM_CMNCR_MANUAL_SET_VALUE);

	/* Set the Erase Command */
	val = SMCMR_CMD_SECTOR_ERASE << SMCMR_CMD_BIT_SHIFT;
	spi_io_write(SPIM_SMCMR, val);

	/* Set the Address within the Sector */
	spi_io_write(SPIM_SMADR, addr);

	/* Set the SDR transfer & SPI flash mode setting value */
	spi_io_write(SPIM_SMDRENR, SPIM_SMDRENR_SET_VALUE);

	/* Set the address enable &  command output enable */
	val = SMENR_CDE | SMENR_ADE_ADR23_0_OUT;
	spi_io_write(SPIM_SMENR, val);

	/* Set the data transfer enable  */
	val = SMCR_SPIE;
	spi_io_write(SPIM_SMCR, val);

	/* Wait until the transfer is complete */
	do {
		val = spi_io_read(SPIM_CMNSR);
	} while ((val & CMNSR_TEND) == 0);

	spi_multi_busy_wait();
}

int spi_multi_setup(void)
{
	uint32_t val;

	/* Wait until the transfer is complete */
	do {
		val = spi_io_read(SPIM_CMNSR);
	} while ((val & CMNSR_TEND) == 0);

	/* Device-specific settings */
	spi_multi_setup_device();
	/* SDR mode serial flash settings */
	spi_io_write(SPIM_PHYCNT, SPIM_PHYCNT_SET_VALUE);

	/* Read timing setting */
	spi_io_write(SPIM_PHYOFFSET1, SPIM_PHYOFFSET1_SET_VALUE);
	spi_io_write(SPIM_PHYOFFSET2, SPIM_PHYOFFSET2_SET_VALUE);

	/* Set the QSPIn_SSL setting value */
	spi_io_write(SPIM_CMNCR, SPIM_CMNCR_EXTREAD_SET_VALUE);
	/* Set SSL delay setting value */
	spi_io_write(SPIM_SSLDR, SPIM_SSLDR_SET_VALUE);

	/* Clear the RBE bit */
	spi_io_write(SPIM_DRCR, SPIM_DRCR_SET_VALUE);
	spi_io_read(SPIM_DRCR);

	/* Set the data read command */
	spi_io_write(SPIM_DRCMR, SPIM_DRCMR_SET_VALUE);

	/* Extended external address setting */
	spi_io_write(SPIM_DREAR, SPIM_DREAR_SET_VALUE);

	/* Set the bit width of command and address output to 1 bit and	*/
	/* the address size to 3 byte									*/
	spi_io_write(SPIM_DRENR, SPIM_DRENR_SET_VALUE);

	/* Dummy cycle setting */
	spi_io_write(SPIM_DRDMCR, SPIM_DRDMCR_SET_VALUE);

	/* Change to SPI flash mode */
	spi_io_write(SPIM_DRDRENR, SPIM_DRDRENR_SET_VALUE);

	/* Timing adjustment register setting */
	spi_multi_timing_set();

	return SPI_MULTI_SUCCESS;
}

static TEE_Result spi_multi_init(void)
{
	spi_multi_base = (vaddr_t)phys_to_virt_io(SPI_MULTI_BASE, SPI_MULTI_SIZE);

	return TEE_SUCCESS;
}

driver_init(spi_multi_init);
