/*
 * Copyright (c) 2024, Renesas Electronics Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <sys.h>

__weak uint32_t sys_get_flash_base(void)
{
	return SPI_FLASH_BASE;
}