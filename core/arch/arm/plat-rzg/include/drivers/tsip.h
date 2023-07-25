// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2023 Renesas Electronics Corporation. All rights reserved.
 */

#include <stddef.h>

#ifndef TSIP_H
#define TSIP_H

typedef struct {
	uint32_t inst[0x0510 / sizeof(uint32_t)];
	uint32_t head[0x0030 / sizeof(uint32_t)];
	uint32_t sram[0x0200 / sizeof(uint32_t)];
} s_tsip_data_st;

extern s_tsip_data_st *tsip_data;

#endif /* TSIP_H */
