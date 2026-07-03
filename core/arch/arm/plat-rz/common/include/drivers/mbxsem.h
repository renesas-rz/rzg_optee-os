/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2025, Renesas Electronics Corporation
 */

#ifndef _MBXSEM_H_
#define _MBXSEM_H_

enum mbxsem_num {
	MBXSEM_NUM_0 = 0,
	MBXSEM_NUM_1,
	MBXSEM_NUM_2,
	MBXSEM_NUM_3,
	MBXSEM_NUM_4,
	MBXSEM_NUM_5,
	MBXSEM_NUM_6,
	MBXSEM_NUM_7,
	MBXSEM_NUM_MAX,
};

void mbxsem_sem_init(enum mbxsem_num sem_num);
void mbxsem_sem_lock(enum mbxsem_num sem_num);
void mbxsem_sem_unlock(enum mbxsem_num sem_num);

#endif /* _MBXSEM_H_ */
