/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2024-2026, Renesas Electronics Corporation
 */
#ifndef __PTA_RSIP_SHA_H
#define __PTA_RSIP_SHA_H

#define PTA_RSIP_SHA_UUID                                               \
	{                                                               \
		0xa954d154, 0x18a3, 0x49cb,                             \
		{                                                       \
			0x93, 0x89, 0x27, 0xb6, 0xd6, 0xe5, 0xc9, 0xe8, \
		}                                                       \
	}

enum pta_sha_type {
	PTA_SHA_TYPE_SHA1 = 1,
	PTA_SHA_TYPE_SHA224 = 2,
	PTA_SHA_TYPE_SHA256 = 3,
	PTA_SHA_TYPE_SHA384 = 4,
	PTA_SHA_TYPE_SHA512 = 5,
	PTA_SHA_TYPE_SHA512_224 = 6,
	PTA_SHA_TYPE_SHA512_256 = 7,
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
 *                  - PTA_SHA_TYPE_SHA1       : 20 bytes
 *                  - PTA_SHA_TYPE_SHA224     : 28 bytes
 *                  - PTA_SHA_TYPE_SHA256     : 32 bytes
 *                  - PTA_SHA_TYPE_SHA384     : 48 bytes
 *                  - PTA_SHA_TYPE_SHA512     : 64 bytes
 *                  - PTA_SHA_TYPE_SHA512_224 : 28 bytes
 *                  - PTA_SHA_TYPE_SHA512_256 : 32 bytes
 */
#define PTA_CMD_SHA_Final (0x39000003)

#endif /* __PTA_RSIP_SHA_H */
