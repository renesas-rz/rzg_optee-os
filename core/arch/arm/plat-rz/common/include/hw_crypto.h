/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2026, Renesas Electronics Corporation
 */

#ifndef HW_CRYPTO_H
#define HW_CRYPTO_H

#include <tee_api_types.h>

TEE_Result plat_crypto_get_random_bytes(void *buf, size_t len);
TEE_Result plat_crypto_get_key_update_key(uint8_t *key, size_t len);

#endif /* HW_CRYPTO_H */
