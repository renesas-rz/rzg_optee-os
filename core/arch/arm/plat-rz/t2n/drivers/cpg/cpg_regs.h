/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2024, Renesas Electronics Corporation
 */

#ifndef __CPG_REGS_H__
#define __CPG_REGS_H__

#include <util.h>

#define CPG_MRCTLA_OFFSET UL(0x0240)
#define CPG_MRCTLA_XSPI0 BIT(4)
#define CPG_MRCTLA_XSPI1 BIT(5)

#define CPG_MSTPCRA_OFFSET UL(0x0300)
#define CPG_MSTPCRA_XSPI0 BIT(4)
#define CPG_MSTPCRA_XSPI1 BIT(5)

#endif /* __CPG_REGS_H__ */
