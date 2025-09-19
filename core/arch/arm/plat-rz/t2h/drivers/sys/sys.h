/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2023-2024, Renesas Electronics Corporation
 */

#ifndef __SYS_H__
#define __SYS_H__

#include <stdint.h>
#include <types_ext.h>

enum boot_mode_t {
	SYS_BOOT_MODE_XSPI0_x1,
	SYS_BOOT_MODE_XSPI0_x8,
	SYS_BOOT_MODE_XSPI1_x1,
	SYS_BOOT_MODE_ESD,
	SYS_BOOT_MODE_EMMC,
	SYS_BOOT_MODE_MAX,
};

extern vaddr_t sys_base;
extern vaddr_t sys_safety_base;

void sys_base_unlock(uint32_t unlock_mask);
void sys_base_lock(uint32_t lock_mask);
void sys_safetybase_unlock(uint32_t unlock_mask);
void sys_safetybase_lock(uint32_t lock_mask);

#endif	/* __SYS_H__ */
