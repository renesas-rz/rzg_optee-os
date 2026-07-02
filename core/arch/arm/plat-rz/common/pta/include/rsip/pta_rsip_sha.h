/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2024, Renesas Electronics Corporation
 */

#ifndef __PTA_RSIP_SHA_H
#define __PTA_RSIP_SHA_H

#include <r_rsip_api.h>

#define PTA_RSIP_SHA_UUID \
	{ 0x8fa6b9c0, 0xb59f, 0x4762, \
		{ 0x92, 0x46, 0x38, 0xdc, 0x66, 0x53, 0x57, 0x04 } }

#define SHA1_HASH_SIZE       (20U)
#define SHA224_HASH_SIZE     (28U)
#define SHA256_HASH_SIZE     (32U)
#define SHA384_HASH_SIZE     (48U)
#define SHA512_HASH_SIZE     (64U)
#define SHA512_224_HASH_SIZE (28U)
#define SHA512_256_HASH_SIZE (32U)

/*
 * [in/out]  memref[0] : SHA handler (rsip_sha_handle_t)
 */
#define PTA_CMD_SHA1_Init                   (0x00030200)
/*
 * [in/out]  memref[0] : SHA handler (rsip_sha_handle_t)
 * [in]      memref[1] : Message
 */
#define PTA_CMD_SHA1_Update                 (0x00030201)
/*
 * [in/out]  memref[0] : SHA handler (rsip_sha_handle_t)
 * [in/out]  memref[1] : Digest (20byte)
 */
#define PTA_CMD_SHA1_Final                  (0x00030202)

/*
 * [in/out]  memref[0] : SHA handler (rsip_sha_handle_t)
 */
#define PTA_CMD_SHA224_Init                 (0x00030000)
/*
 * [in/out]  memref[0] : SHA handler (rsip_sha_handle_t)
 * [in]      memref[1] : Message
 */
#define PTA_CMD_SHA224_Update               (0x00030001)
/*
 * [in/out]  memref[0] : SHA handler (rsip_sha_handle_t)
 * [in/out]  memref[1] : Digest (28byte)
 */
#define PTA_CMD_SHA224_Final                (0x00030002)

/*
 * [in/out]  memref[0] : SHA handler (rsip_sha_handle_t)
 */
#define PTA_CMD_SHA256_Init                 (0x00030100)
/*
 * [in/out]  memref[0] : SHA handler (rsip_sha_handle_t)
 * [in]      memref[1] : Message
 */
#define PTA_CMD_SHA256_Update               (0x00030101)
/*
 * [in/out]  memref[0] : SHA handler (rsip_sha_handle_t)
 * [in/out]  memref[1] : Digest (32byte)
 */
#define PTA_CMD_SHA256_Final                (0x00030102)

/*
 * [in/out]  memref[0] : SHA handler (rsip_sha_handle_t)
 */
#define PTA_CMD_SHA384_Init                 (0x00030300)
/*
 * [in/out]  memref[0] : SHA handler (rsip_sha_handle_t)
 * [in]      memref[1] : Message
 */
#define PTA_CMD_SHA384_Update               (0x00030301)
/*
 * [in/out]  memref[0] : SHA handler (rsip_sha_handle_t)
 * [in/out]  memref[1] : Digest (48byte)
 */
#define PTA_CMD_SHA384_Final                (0x00030302)

/*
 * [in/out]  memref[0] : SHA handler (rsip_sha_handle_t)
 */
#define PTA_CMD_SHA512_Init                 (0x00030400)
/*
 * [in/out]  memref[0] : SHA handler (rsip_sha_handle_t)
 * [in]      memref[1] : Message
 */
#define PTA_CMD_SHA512_Update               (0x00030401)
/*
 * [in/out]  memref[0] : SHA handler (rsip_sha_handle_t)
 * [in/out]  memref[1] : Digest (64byte)
 */
#define PTA_CMD_SHA512_Final                (0x00030402)

/*
 * [in/out]  memref[0] : SHA handler (rsip_sha_handle_t)
 */
#define PTA_CMD_SHA512_224_Init             (0x00030500)
/*
 * [in/out]  memref[0] : SHA handler (rsip_sha_handle_t)
 * [in]      memref[1] : Message
 */
#define PTA_CMD_SHA512_224_Update           (0x00030501)
/*
 * [in/out]  memref[0] : SHA handler (rsip_sha_handle_t)
 * [in/out]  memref[1] : Digest (28byte)
 */
#define PTA_CMD_SHA512_224_Final            (0x00030502)

/*
 * [in/out]  memref[0] : SHA handler (rsip_sha_handle_t)
 */
#define PTA_CMD_SHA512_256_Init             (0x00030600)
/*
 * [in/out]  memref[0] : SHA handler (rsip_sha_handle_t)
 * [in]      memref[1] : Message
 */
#define PTA_CMD_SHA512_256_Update           (0x00030601)
/*
 * [in/out]  memref[0] : SHA handler (rsip_sha_handle_t)
 * [in/out]  memref[1] : Digest (32byte)
 */
#define PTA_CMD_SHA512_256_Final            (0x00030602)

#endif /* __PTA_RSIP_SHA_H */
