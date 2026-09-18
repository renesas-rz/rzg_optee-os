/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2022, Renesas Electronics Corporation
 */

#ifndef __PTA_SCE_SHA_H
#define __PTA_SCE_SHA_H

#define PTA_SCE_SHA_UUID                                                \
	{                                                               \
		0x229007c2, 0x7517, 0x42ba,                             \
		{                                                       \
			0x93, 0x03, 0x20, 0xe3, 0x61, 0xee, 0x45, 0x65, \
		}                                                       \
	}

enum pta_sha_type {
	PTA_SHA_TYPE_SHA224 = 2,
	PTA_SHA_TYPE_SHA256 = 3,
};

/*
 * Initialize SHA hashing.
 * value[0].a (in): Hash algorithm.
 *                  One of enum pta_sha_type.
 */
#define PTA_CMD_SHA_Init (0x39000001)

/*
 * Update SHA hashing.
 * memref[0] (in): Message buffer.
 *                 Length must be a multiple of sizeof(uint32_t).
 */
#define PTA_CMD_SHA_Update (0x39000002)

/*
 * Finalize SHA hashing.
 * memref[0] (in): Final message buffer.
 *                 Length must be less than sizeof(uint32_t).
 * memref[1] (out): Digest buffer.
 *                  Required size depends on the hash algorithm:
 *                  - PTA_SHA_TYPE_SHA224     : 28 bytes
 *                  - PTA_SHA_TYPE_SHA256     : 32 bytes
 */
#define PTA_CMD_SHA_Final (0x39000003)

#endif /* __PTA_SCE_SHA_H */
