/*
 * Copyright (c) 2023, Renesas Electronics Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _SFLASH_H_
#define _SFLASH_H_

extern void sflash_open(void);
extern void sflash_close(void);
extern void sflash_write_buffer(uint32_t addr, uintptr_t buff, size_t len);

#endif /* _SFLASH_H_ */
