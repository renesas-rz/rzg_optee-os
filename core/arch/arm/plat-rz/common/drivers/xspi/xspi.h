/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2023, Renesas Electronics Corporation
 */

#ifndef _XSPI_H_
#define _XSPI_H_

#define XSPI_SUCCESS				(0)
#define XSPI_ERROR					(-1)

#define XSPI_WRITE_SIZE_SHIFT		(12)	/* 4k bytes */
#define XSPI_WRITE_PROG_SIZE		BIT(XSPI_WRITE_SIZE_SHIFT) /* 2^N bytes */

int xspi_setup(uint8_t ch);
int xspi_erase(uint8_t ch, const uintptr_t addr, uint32_t byte_count);
int xspi_write(uint8_t ch, const uintptr_t addr, uintptr_t data, uint32_t byte_count);
int xspi_dummy_read(uint8_t ch);

#endif	/* _XSPI_H_ */
