/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2023-2024, Renesas Electronics Corporation
 */

#ifndef __SYS_H__
#define __SYS_H__

void sys_lock_cgc(void);
void sys_unlock_cgc(void);
void sys_lock_pwr(void);
void sys_unlock_pwr(void);
void sys_lock_sysctrl(void);
void sys_unlock_sysctrl(void);

void sys_start_slave_xspi0(void);
void sys_stop_slave_xspi0(void);
void sys_start_slave_xspi1(void);
void sys_stop_slave_xspi1(void);

#endif /* __SYS_H__ */
