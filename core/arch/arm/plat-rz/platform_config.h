/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, Renesas Electronics
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#if defined(CFG_PLATFORM_GROUP_g2l)
#include "g2l/rzg2l_config.h"
#elif defined(CFG_PLATFORM_GROUP_g3s)
#include "g3s/rzg3s_config.h"
#endif

#endif /*PLATFORM_CONFIG_H*/
