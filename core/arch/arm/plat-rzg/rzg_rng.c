// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 * Copyright (c) 2021, Renesas Electronics Corporation
 */

#include <string.h>
#include <compiler.h>
#include <crypto/crypto.h>
#include <rng_support.h>
#include <tee/tee_cryp_utl.h>
#include <types_ext.h>
#include <trace.h>
#include "drivers/R_TSIP_Core_Lib.h"

TEE_Result hw_get_random_bytes(void *buf, size_t blen)
{
    uint32_t err;

    if(!buf){
        EMSG("Invalid buffer");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    memset(buf, 0, blen);

    if (0 < blen) {
        err = R_TSIP_BCF_GenerateRandom(blen, 0, buf);
        if (R_PASS != err) {
            EMSG("Failed to generate a random number (0x%08x).", err);
            return TEE_ERROR_GENERIC;
        }
    }

    return TEE_SUCCESS;
}
