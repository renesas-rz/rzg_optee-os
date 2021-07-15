/*
 * Copyright (c) 2021, Renesas Electronics Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdint.h>
#include <string.h>

#include "rpc_accessor.h"
#include "drivers/spi/spi.h"

static void spi_write_buff(uint64_t buff, uint32_t spi_addr, uint32_t len);
static void spi_erase_1sector(uint32_t sec_addr);
uint32_t page_fraction_buff[QSPI_PAGE_SIZE] = {0};

int32_t rzg_spi_init_driver(void)
{
    rzg_rpc_power_on();
}

int32_t rzg_spi_deinit_driver(void)
{
    rzg_rpc_power_off();
}

int32_t rzg_spi_write_buff(uint32_t spi_addr, uint64_t buff, uint32_t len)
{
    if ((spi_addr + len) > QSPI_END_ADDR)
    {
        return SPI_RET_NG;
    }

    /*
     * If we want to write a value different than 0
     * then we have to erase the full block because
     * otherwise we cannot ensure that the value programmed
     * into the flash is going to be the same than the value
     * requested
     */
    if (rzg_spi_erase_sectors(spi_addr, len))
    {
        return SPI_RET_NG;
    }

    rzg_rpc_manual_mode_init();

    /* write data to spi using write buffer operation */
    spi_write_buff(buff, spi_addr, len);

    rzg_rpc_read_ext_mode_init();

    return SPI_RET_OK;
}

int32_t rzg_spi_erase_sectors(uint32_t spi_addr, uint32_t len)
{
    uint32_t erase_sector_addr;
    uint32_t mask_sec_size;
    uint32_t erase_sec_top_addr, erase_sec_end_addr;

    if ((spi_addr + len) > QSPI_END_ADDR)
    {
        return SPI_RET_NG;
    }

    rzg_rpc_manual_mode_init();

    mask_sec_size = (~QSPI_SEC_SIZE) + 1;
    erase_sec_top_addr = spi_addr & mask_sec_size;
    erase_sec_end_addr = (spi_addr + len) | ~(mask_sec_size);

    for (erase_sector_addr = erase_sec_top_addr;
         erase_sector_addr <= erase_sec_end_addr;
         erase_sector_addr = erase_sector_addr + QSPI_SEC_SIZE)
    {
        spi_erase_1sector(erase_sector_addr);
    }

    rzg_rpc_read_ext_mode_init();

    return SPI_RET_OK;
}

static void spi_erase_1sector(uint32_t sec_addr)
{
    uint32_t status;
    /* WRITE ENABLE */
    rzg_rpc_write_cmd(0x00060000);
    rzg_rpc_erase_sector(sec_addr);

    while (1)
    {
        rzg_rpc_read_status(&status);
        if (!(status & BIT0))
        {
            break;
        }
    }
}

static void spi_write_buff(uint64_t buff, uint32_t spi_addr, uint32_t len)
{
    uint32_t flash_addr;
    uint32_t status;
    uint32_t fraction_len;
    uint8_t *fraction_buff;

    for (int i = 0; i < (QSPI_PAGE_SIZE/4); i++)
    {
        page_fraction_buff[i] = 0xFFFFFFFF;
    }

    fraction_buff = &page_fraction_buff;
    fraction_len = len;

    for (flash_addr = spi_addr; flash_addr < (spi_addr + len); flash_addr += 256)
    {
        if (QSPI_PAGE_SIZE > fraction_len)
        {
            for (uint32_t i = 0; i < fraction_len; i++)
            {
                fraction_buff[i] = *(volatile uint8_t *)(buff + i);
            }
            rzg_rpc_write_cmd(0x00060000);
            rzg_rpc_write_buff(flash_addr, (uint64_t)fraction_buff);
        }
        else
        {
            rzg_rpc_write_cmd(0x00060000);
            rzg_rpc_write_buff(flash_addr, buff);
        }

        while (1)
        {
            rzg_rpc_read_status(&status);
            if (!(status & BIT0))
            {
                break;
            }
        }
        buff = buff + 256;
        fraction_len = fraction_len - 256;
    }
}
