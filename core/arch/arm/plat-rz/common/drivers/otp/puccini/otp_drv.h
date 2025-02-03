/*
 * Copyright (c) 2023, Renesas Electronics Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __OTP_DRV_H__
#define __OTP_DRV_H__

#include <stdint.h>
#include <stdbool.h>


extern bool r_otp_read(uint32_t addr, uint32_t *p_value, uint32_t count);

#endif /* __OTP_DRV_H__ */
