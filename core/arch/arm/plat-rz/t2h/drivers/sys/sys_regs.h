/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2023-2025, Renesas Electronics Corporation
 */

#ifndef __SYS_REGS_H__
#define __SYS_REGS_H__

#include <rzt2h_config.h>				/* Get the System base address */

#define MRCTLA							(0x00000240)
#define MSTPCRA							(0x00000300)

#define MD_MON							(0x00004100)
#define PRCRN							(0x00004200)

#define SSTPCR6							(0x00000208)

#define PRCRS							(0x00006000)

#define XSPI0CS0_END_ADD					(0x00013004)
#define XSPI1CS1_END_ADD					(0x00013104)

/* xSPI0 */
#define MRCTLA_MRCTLA04						UL(4)
/* xSPI1 */
#define MRCTLA_MRCTLA05						UL(5)

#define PRCRx_CLOCK_GEN						UL(1)
#define PRCRx_LOW_POWER						UL(2)
#define PRCRx_GPIO						UL(4)
#define PRCRx_SYS_CTRL						UL(8)

/* xSPI0 */
#define MSTPCRA_MSTPCRA04					UL(4)
#define MSTPCRA_MSTPCRA04_MSK				(0x00000001U << MSTPCRA_MSTPCRA04)
/* xSPI1 */
#define MSTPCRA_MSTPCRA05					UL(5)
#define MSTPCRA_MSTPCRA05_MSK				(0x00000001U << MSTPCRA_MSTPCRA05)

/* xSPI */
#define SSTPCR6_XSPI0_REQ					UL(0)
#define SSTPCR6_XSPI0_REQ_MSK				(0x00000001U << SSTPCR6_XSPI0_REQ)
#define SSTPCR6_XSPI0_ACK					UL(1)
#define SSTPCR6_XSPI0_ACK_MSK				(0x00000001U << SSTPCR6_XSPI0_ACK)
#define SSTPCR6_XSPI1_REQ					UL(4)
#define SSTPCR6_XSPI1_REQ_MSK				(0x00000001U << SSTPCR6_XSPI1_REQ)
#define SSTPCR6_XSPI1_ACK					UL(5)
#define SSTPCR6_XSPI1_ACK_MSK				(0x00000001U << SSTPCR6_XSPI1_ACK)

#endif	/* __SYS_REGS_H__ */
