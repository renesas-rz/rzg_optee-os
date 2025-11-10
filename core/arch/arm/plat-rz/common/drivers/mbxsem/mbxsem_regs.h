/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2025, Renesas Electronics Corporation
 */

#ifndef __MBXSEM_REGS_H__
#define __MBXSEM_REGS_H__

#define MBXSEM_SEMAR0		(0x0180)		/* Semaphore Register 0 */
#define MBXSEM_SEMAR1		(0x0184)		/* Semaphore Register 1 */
#define MBXSEM_SEMAR2		(0x0188)		/* Semaphore Register 2 */
#define MBXSEM_SEMAR3		(0x018C)		/* Semaphore Register 3 */
#define MBXSEM_SEMAR4		(0x0190)		/* Semaphore Register 4 */
#define MBXSEM_SEMAR5		(0x0194)		/* Semaphore Register 5 */
#define MBXSEM_SEMAR6		(0x0198)		/* Semaphore Register 6 */
#define MBXSEM_SEMAR7		(0x019C)		/* Semaphore Register 7 */
							/* Semaphore Register num */
#define MBXSEM_SEMAR(num)	(MBXSEM_SEMAR0 + sizeof(uint32_t) * (num))
#define MBXSEM_SEMRCENAR	(0x01A0)		/* Semaphore Read Clear Enable Register */

#define MBXSEM_SEMAR_SEM	(0x1)			/* Semaphore bit */
#define MBXSEM_SEMRCENAR_EN(value, num) \
				((value) & BIT(num))	/* Check SEMAR register read clear Enable bit */

#endif	/* __MBXSEM_REGS_H__ */
