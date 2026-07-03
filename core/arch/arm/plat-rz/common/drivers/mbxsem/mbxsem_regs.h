/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2025, Renesas Electronics Corporation
 */

#ifndef __MBXSEM_REGS_H__
#define __MBXSEM_REGS_H__

/* Semaphore Register n (n = 0～7) */
#define MBXSEM_SEMAR(n)	 (0x0180U + (sizeof(uint32_t) * (n)))
#define MBXSEM_SEMAR_SEM (0x1)

/* Semaphore Read Clear Enable Register */
#define MBXSEM_SEMRCENAR       (0x01A0U)
#define MBXSEM_SEMRCENAR_EN(n) BIT(n)

#endif /* __MBXSEM_REGS_H__ */
