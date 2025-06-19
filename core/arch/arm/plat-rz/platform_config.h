/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2021-2025, Renesas Electronics Corporation
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#if defined(CFG_PLATFORM_GROUP_g2l)
#include "g2l/rzg2l_config.h"
#elif defined(CFG_PLATFORM_GROUP_g3s)
#include "g3s/rzg3s_config.h"
#elif defined(CFG_PLATFORM_GROUP_v2h)
#include "v2h/rzv2h_config.h"
#elif defined(CFG_PLATFORM_GROUP_t2h)
#include "t2h/rzt2h_config.h"
#elif defined(CFG_PLATFORM_GROUP_g3e)
#include "g3e/rzg3e_config.h"
#endif

#endif /*PLATFORM_CONFIG_H*/
