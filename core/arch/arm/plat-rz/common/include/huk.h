/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2026, Renesas Electronics Corporation
 */

#ifndef HUK_H
#define HUK_H

#include <tee_api_types.h>

/*
 * Read platform-specific root material used to derive
 * the Hardware Unique Key (HUK).
 *
 * The common implementation provides a reference method,
 * while platforms may override this function to obtain
 * root material from OTP, Secure IP, or another secure source.
 */
TEE_Result huk_read_root_material(uint8_t *buf, size_t *len);

#endif /* HUK_H */
