// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 * Copyright (c) 2021, Renesas Electronics Corporation
 */

#include <compiler.h>
#include <crypto/crypto.h>
#include <rng_support.h>
#include <tee/tee_cryp_utl.h>
#include <types_ext.h>

#include <string.h>

#include "drivers/secip_drv.h"

TEE_Result crypto_rng_read(void *buf, size_t blen)
{
    if (!buf)
        return TEE_ERROR_BAD_PARAMETERS;

    memset(buf, 0, blen);

    return secip_rng(buf, blen);
}

uint8_t hw_get_random_byte(void)
{
    return 0;
}

