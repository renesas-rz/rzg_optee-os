/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2023, Renesas Electronics Corporation
 */

#ifndef _XSPI_REG_H_
#define _XSPI_REG_H_

#define XSPI_WRAPCFG			(0x000UL)
#define XSPI_COMCFG			(0x004UL)
#define XSPI_BMCFG			(0x008UL)
#define XSPI_CMCFG0CS0			(0x010UL)
#define XSPI_CMCFG1CS0			(0x014UL)
#define XSPI_CMCFG2CS0			(0x018UL)
#define XSPI_LIOCFGCS0			(0x050UL)
#define XSPI_BMCTL0			(0x060UL)
#define XSPI_CSSCTL			(0x06CUL)
#define XSPI_CDCTL0			(0x070UL)
#define XSPI_CDTBUF0			(0x080UL)
#define XSPI_CDABUF0			(0x084UL)
#define XSPI_CDD0BUF0			(0x088UL)
#define XSPI_LIOCTL			(0x108UL)
#define XSPI_INTS			(0x190UL)
#define XSPI_INTC			(0x194UL)

#define XSPI_CDTBUF_CMDSIZE_OFFSET	(0U)
#define XSPI_CDTBUF_CMDSIZE_MSK		(0x3U << XSPI_CDTBUF_CMDSIZE_OFFSET)
#define XSPI_CDTBUF_ADDSIZE_OFFSET	(2U)
#define XSPI_CDTBUF_ADDSIZE_MSK		(0x7U << XSPI_CDTBUF_ADDSIZE_OFFSET)
#define XSPI_CDTBUF_DATASIZE_OFFSET	(5U)
#define XSPI_CDTBUF_LATE_OFFSET		(9U)
#define XSPI_CDTBUF_TRTYPE_OFFSET	(15U)
#define XSPI_CDTBUF_CMD_OFFSET		(16U)

#define XSPI_INTC_CMDCMPC		(0U)
#define XSPI_INTC_CMDCMPC_MSK		(0x1U << XSPI_INTC_CMDCMPC)

#define XSPI_INTS_CMDCMP		(0U)
#define XSPI_INTS_CMDCMP_MSK		(0x1U << XSPI_INTS_CMDCMP)

#define XSPI_CDCTL0_TRREQ		(0U)
#define XSPI_CDCTL0_TRREQ_MSK		(0x1U << XSPI_CDCTL0_TRREQ)

#define XSPI_BMCTL0_CH0CS0ACC_READ	(0x1)
#define XSPI_BMCTL0_CH0CS0ACC_WRITE	(0x2)

extern vaddr_t xspi_base;

static inline void xspi_io_write(uint32_t reg, uint32_t data)
{
	io_write32(xspi_base + reg, data);
}

static inline uint32_t xspi_io_read(uint32_t reg)
{
	return io_read32(xspi_base + reg);
}
#endif /* _XSPI_REG_H_ */
