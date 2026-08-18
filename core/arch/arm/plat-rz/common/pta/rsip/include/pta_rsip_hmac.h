/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2024-2026, Renesas Electronics Corporation
 */
#ifndef __PTA_RSIP_HMAC_H
#define __PTA_RSIP_HMAC_H

#define PTA_RSIP_HMAC_UUID                                              \
	{                                                               \
		0xded785d5, 0xc912, 0x46cd,                             \
		{                                                       \
			0xb6, 0xd4, 0xcf, 0x74, 0x21, 0xfa, 0xe4, 0xbe, \
		}                                                       \
	}
/*
 * The HMAC hash algorithm is determined from the input wrapped key type:
 */

/*
 * Initialize HMAC generation.
 * memref[0] (in): Wrapped HMAC key buffer.
 */
#define PTA_CMD_HMAC_GenerateInit (0x67060001)

/*
 * Update HMAC generation.
 * memref[0] (in): Message buffer.
 *                 Length must be a multiple of sizeof(uint32_t).
 */
#define PTA_CMD_HMAC_GenerateUpdate (0x67060002)

/*
 * Finalize HMAC generation.
 * memref[0] (in): Final message buffer.
 *                 Length must be less than sizeof(uint32_t).
 * memref[1] (out): MAC buffer.
 *                  Required size depends on the wrapped key type:
 *                  - HMAC-SHA1   : 20 bytes
 *                  - HMAC-SHA224 : 28 bytes
 *                  - HMAC-SHA256 : 32 bytes
 */
#define PTA_CMD_HMAC_GenerateFinal (0x67060003)

/*
 * Initialize HMAC verification.
 * memref[0] (in): Wrapped HMAC key buffer.
 */
#define PTA_CMD_HMAC_VerifyInit (0x67060009)

/*
 * Update HMAC verification.
 * memref[0] (in): Message buffer.
 *                 Length must be a multiple of sizeof(uint32_t).
 */
#define PTA_CMD_HMAC_VerifyUpdate (0x6706000A)

/*
 * Finalize HMAC verification.
 * memref[0] (in): Final message buffer.
 *                 Length must be less than sizeof(uint32_t).
 * memref[1] (in): MAC buffer.
 *                 Required size depends on the wrapped key type:
 *                 - HMAC-SHA1   : 4 to 20 bytes
 *                 - HMAC-SHA224 : 4 to 28 bytes
 *                 - HMAC-SHA256 : 4 to 32 bytes
 */
#define PTA_CMD_HMAC_VerifyFinal (0x6706000B)

#endif /* __PTA_RSIP_HMAC_H */
