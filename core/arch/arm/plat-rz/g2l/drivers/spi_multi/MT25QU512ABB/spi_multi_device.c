/*
 * Copyright (c) 2021-2023, Renesas Electronics Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stdint.h>
#include <stddef.h>
#include <io.h>
#include <kernel/delay.h>
#include <spi_multi.h>
#include <spi_multi_regs.h>
#include <spi_multi_reg_values.h>
#include <spi_multi_device.h>

void spi_multi_setup_device(void)
{
	return;
}

void spi_multi_busy_wait(void)
{
	while(1) {

		uint8_t read_status = spi_multi_cmd_read(SMCMR_CMD_READ_STATUS_REGISTER);

		if ((read_status & STATUS_BUSY_BIT) != STATUS_BUSY)
			break;

		udelay(STATUS_BUSY_READ_DELAY_TIME);
	}
}
