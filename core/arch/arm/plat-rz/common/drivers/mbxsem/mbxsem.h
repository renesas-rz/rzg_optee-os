/* SPDX-License-Identifier: BSD-3-Clausev */
/*
 * Copyright (c) 2025, Renesas Electronics Corporation
 */

#ifndef _MBXSEM_H_
#define _MBXSEM_H_

enum maxsem_num_t {
	MBXSEM_NUM_0 = 0,
	MBXSEM_NUM_1,
	MBXSEM_NUM_2,
	MBXSEM_NUM_3,
	MBXSEM_NUM_4,
	MBXSEM_NUM_5,
	MBXSEM_NUM_6,
	MBXSEM_NUM_7,
};

void mbxsem_wait(uint8_t sem_num);
void mbxsem_post(uint8_t sem_num);

#define mbxsem_wait_regprotect()	mbxsem_wait(MBXSEM_NUM_7)
#define mbxsem_post_regprotect()	mbxsem_post(MBXSEM_NUM_7)

#endif /* _MBXSEM_H_ */
