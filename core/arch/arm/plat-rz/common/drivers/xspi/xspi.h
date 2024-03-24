/*
 * Copyright (c) 2023, Renesas Electronics Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _XSPI_H_
#define _XSPI_H_


#define XSPI_SUCCESS				(0)
#define XSPI_ERROR					(-1)

#define XSPI_WRITE_SIZE_SHIFT		(12)	/* 4k bytes */
#define XSPI_WRITE_PROG_SIZE		(1 << XSPI_WRITE_SIZE_SHIFT) /* 2^N bytes */

int xspi_setup(void);
int xspi_erase(const uintptr_t addr, uint32_t byte_count);
int xspi_write(const uintptr_t addr, uintptr_t data, uint32_t byte_count);

#endif	/* _XSPI_H_ */
