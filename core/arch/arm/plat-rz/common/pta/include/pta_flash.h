/*
 * Copyright (c) 2021, Renesas Electronics Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PTA_FLASH_H_
#define PTA_FLASH_H_

#define FLASH_UUID                                         \
    {                                                      \
        0x2c0fca92, 0x5ab1, 0x11eb,                        \
        {                                                  \
            0x81, 0x53, 0xc7, 0xd7, 0x50, 0xe0, 0xae, 0x47 \
        }                                                  \
    }

/*
 * FLASH_CMD_WRITE_SPI - Write data to SPI Flash
 * param[0] (value) spi save address
 * param[1] (memref) write data buffer
 * param[2] unused
 * param[3] unused
 */
#define FLASH_CMD_WRITE_SPI 1

#endif /* PTA_FLASH_H_ */
