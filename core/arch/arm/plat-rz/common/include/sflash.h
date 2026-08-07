/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2023-2026, Renesas Electronics Corporation
 */

#ifndef _SFLASH_H_
#define _SFLASH_H_

TEE_Result sflash_open(void);
void sflash_close(void);
TEE_Result sflash_read(uintptr_t addr, uintptr_t buff, size_t len);
TEE_Result sflash_write_buffer(uintptr_t addr, uintptr_t buff, size_t len);

#endif /* _SFLASH_H_ */
