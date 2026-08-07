/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2021-2026, Renesas Electronics Corporation
 */

#ifndef PTA_FLASH_H_
#define PTA_FLASH_H_

#define PTA_FLASH_UUID                                                  \
	{                                                               \
		0x2c0fca92, 0x5ab1, 0x11eb,                             \
		{                                                       \
			0x81, 0x53, 0xc7, 0xd7, 0x50, 0xe0, 0xae, 0x47, \
		}                                                       \
	}

/*
 * Write data to SPI flash.
 * param[0].value.a (in): Offset from the SPI flash base address.
 * param[0].value.b (in): SPI flash channel number.
 * param[1].memref  (in): Data buffer to write.
 */
#define PTA_CMD_FLASH_WRITE_SPI (0x00000001)

#endif /* PTA_FLASH_H_ */
