/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2023-2024, Renesas Electronics Corporation
 */

#ifndef __OTP_REGS_H__
#define __OTP_REGS_H__

#include <util.h>

#define OTP_OTPPWR (0x0000)
#define OTP_OTPSTR (0x0004)
#define OTP_OTPADRRD (0x0014)
#define OTP_OTPDATARD (0x0018)
#define OTP_OTPFLAG (0x001C)

/* OTPPWR Register */
#define OTPPWR_PWR BIT(0)
#define OTPPWR_ACCL BIT(4)

/* OTPSTR Register */
#define OTPSTR_CMD_RDY BIT(0)
#define OTPSTR_ERR_RP BIT(4)

/* OTPFLAG Register */
#define OTPFLAG_FLAG BIT(0)
#define OTPFLAG_RREND BIT(1)

#endif /* __OTP_REGS_H__ */
