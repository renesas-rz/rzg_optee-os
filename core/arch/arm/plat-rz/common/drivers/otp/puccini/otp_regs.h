/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2023-2024, Renesas Electronics Corporation
 */

#ifndef __OTP_REGS_H__
#define __OTP_REGS_H__

#define OTP_OTPPWR_OFFSET				UL(0x0000)
#define OTP_OTPSTR_OFFSET				UL(0x0004)
#define OTP_OTPADRRD_OFFSET				UL(0x0014)
#define OTP_OTPDATARD_OFFSET				UL(0x0018)
#define OTP_OTPFLAG_OFFSET				UL(0x001C)

#define OTP_OTPPWR					(OTP_OTPPWR_OFFSET)
#define OTP_OTPSTR					(OTP_OTPSTR_OFFSET)
#define OTP_OTPADRRD					(OTP_OTPADRRD_OFFSET)
#define OTP_OTPDATARD					(OTP_OTPDATARD_OFFSET)
#define OTP_OTPFLAG					(OTP_OTPFLAG_OFFSET)

#define OTP_IP_ADDR_MIN					U(0x0E5)
#define OTP_IP_ADDR_MAX					U(0x3FF)
#define OTP_IP_DUMMY_READ_ADDR				U(0x0200)

/* OTPPWR Register */
#define OTP_OTPPWR_PWR					U(0)
#define OTP_OTPPWR_ACCL					U(4)

/* OTPSTR Register */
#define OTP_OTPSTR_CMD_RDY				U(0)
#define OTP_OTPSTR_ERR_RP				U(4)

/* OTPFLAG Register */
#define OTP_OTPFLAG_FLAG				U(0)
#define OTP_OTPFLAG_RREND				U(1)

extern vaddr_t otp_base;

static inline void otp_io_write(uint32_t reg, uint32_t data)
{
	io_write32(otp_base + reg, data);
}

static inline uint32_t otp_io_read(uint32_t reg)
{
	return io_read32(otp_base + reg);
}

#endif /* __OTP_REGS_H__ */
