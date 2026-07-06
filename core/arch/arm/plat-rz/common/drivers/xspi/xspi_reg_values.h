/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2026, Renesas Electronics Corporation
 */

#ifndef _XSPI_REG_VALUES_H_
#define _XSPI_REG_VALUES_H_

#include <util.h>

/*
 * Device-specific xSPI configuration values.
 *
 * Future flash devices may provide their own
 * xspi_reg_values.h implementation.
 */

#define XSPI_BMCFG_SET_VALUE (0x00010001UL)
#define XSPI_CMCFG0CS0_SET_VALUE (0x00000008UL)
#define XSPI_CMCFG1CS0_SET_VALUE (0x00000300UL)
#define XSPI_CMCFG2CS0_SET_VALUE (0x00000200UL)
#define XSPI_LIOCFGCS0_SET_VALUE (0x00070000UL)
#define XSPI_BMCTL0_SET_VALUE (0x00000003UL)
#define XSPI_CDTBUF0_SET_VALUE (0x00000000UL)
#define XSPI_INTC_SET_VALUE (0x00000001UL)

#define XSPI_WRITE_SIZE_SHIFT (12) /* 4k bytes */
#define XSPI_WRITE_PROG_SIZE BIT(XSPI_WRITE_SIZE_SHIFT) /* 2^N bytes */

#define XSPI_SECTOR_SIZE (0x10000U)

#endif /* _XSPI_REG_VALUES_H_ */
