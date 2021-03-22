// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2021 Renesas Electronics Corporation. All rights reserved.
 */

#ifndef SECIP_DRV_H
#define SECIP_DRV_H

/* Random Number Generator */
TEE_Result secip_rng(void *buf, size_t blen);

#endif
