/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2024, Renesas Electronics Corporation
 */

#ifndef __CPG_REGS_H__
#define __CPG_REGS_H__

#define CPG_SSEL1				(0x0304)	/* Static Mux Control Register   */
#define CPG_CSDIV0				(0x0500)	/* Static Gear Control Register */

#define CPG_CLKON_9				(0x0624)	/* CGC Control Register xSPI */
#define CPG_CLKON_10				(0x0628)	/* CGC Control Register xSPI */

#define CPG_CLKMON_4				(0x0810)	/* CGC Monitor Register xSPI */
#define CPG_CLKMON_5				(0x0814)	/* CGC Monitor Register xSPI */

#define CPG_BUS_4_MSTOP				(0x0D0C)	/* MSTOP register 4 */
#define CPG_BUS_5_MSTOP				(0x0D10)	/* MSTOP register 5 */
#define CPG_RST_10				(0x0928)	/* Reset Control Register xSPI */
#define CPG_RSTMON_4				(0x0A10)	/* Reset Monitor Registers xSPI */

#endif	/* __CPG_REGS_H__ */
