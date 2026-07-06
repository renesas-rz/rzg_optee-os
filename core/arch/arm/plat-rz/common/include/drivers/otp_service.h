/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2026, Renesas Electronics Corporation
 */

#ifndef __OTP_SERVICE_H
#define __OTP_SERVICE_H

#include <tee_api_types.h>

TEE_Result otp_read_cpid(void *buf, size_t *len);

#endif /* __OTP_SERVICE_H */
