/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2023-2024, Renesas Electronics Corporation
 */

#ifndef __OTP_REGS_H__
#define __OTP_REGS_H__

#define OTP_OTPPWR (0x0000)
#define OTP_OTPSTR (0x0004)
#define OTP_OTPADRRD (0x0014)
#define OTP_OTPDATARD (0x0018)
#define OTP_OTPFLAG (0x001C)

/* OTPPWR Register */
#define OTP_OTPPWR_PWR U(0)
#define OTP_OTPPWR_ACCL U(4)

/* OTPSTR Register */
#define OTP_OTPSTR_CMD_RDY U(0)
#define OTP_OTPSTR_ERR_RP U(4)

/* OTPFLAG Register */
#define OTP_OTPFLAG_FLAG U(0)
#define OTP_OTPFLAG_RREND U(1)

#endif /* __OTP_REGS_H__ */
