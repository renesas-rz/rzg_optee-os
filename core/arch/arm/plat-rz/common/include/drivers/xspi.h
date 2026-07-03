/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2023, Renesas Electronics Corporation
 */

#ifndef _XSPI_H_
#define _XSPI_H_

#define XSPI_OK	 (0)
#define XSPI_ERR (-1)

int32_t xspi_setup(uint8_t ch);
int32_t xspi_erase(uint8_t ch, const uintptr_t addr, uint32_t byte_count);
int32_t xspi_write(uint8_t ch, const uintptr_t addr, uintptr_t data,
		   uint32_t byte_count);
int32_t xspi_dummy_read(uint8_t ch);

#endif /* _XSPI_H_ */
