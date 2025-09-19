/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2024, Renesas Electronics Corporation
 */

#ifndef __PTA_RSIP_HMAC_H
#define __PTA_RSIP_HMAC_H

#include <r_rsip_api.h>

#define PTA_RSIP_HMAC_UUID \
	{ 0xb528d9ee, 0x98d3, 0x4890, \
		{ 0xb0, 0xf2, 0xa7, 0x91, 0xc3, 0xd7, 0x92, 0x08 } }

#define SHA1_MAC_SIZE   (20U)
#define SHA224_MAC_SIZE (28U)
#define SHA256_MAC_SIZE (32U)

/*
 * [in/out]     memref[0] : HMAC handler (rsip_hmac_handle_t)
 * [in]         memref[1] : Wrapped key (rsip_wrapped_key_t:68byte)
 */
#define PTA_CMD_HMAC_SHA1_GenerateInit      (0x00060000)
/*
 * [in/out]     memref[0] : HMAC handler (rsip_hmac_handle_t)
 * [in]         memref[1] : Message
 */
#define PTA_CMD_HMAC_SHA1_GenerateUpdate    (0x00060001)
/*
 * [in/out]     memref[0] : HMAC handler (rsip_hmac_handle_t)
 * [in/out]     memref[1] : MAC (20byte)
 */
#define PTA_CMD_HMAC_SHA1_GenerateFinal     (0x00060002)
/*
 * [in/out]     memref[0] : HMAC handler (rsip_hmac_handle_t)
 * [in]         memref[1] : Wrapped key (rsip_wrapped_key_t:68byte)
 */
#define PTA_CMD_HMAC_SHA1_VerifyInit        (0x00060010)
/*
 * [in/out]     memref[0] : HMAC handler (rsip_hmac_handle_t)
 * [in]         memref[1] : Message
 */
#define PTA_CMD_HMAC_SHA1_VerifyUpdate      (0x00060011)
/*
 * [in/out]     memref[0] : HMAC handler (rsip_hmac_handle_t)
 * [in]         memref[1] : MAC (4 to 20byte)
 */
#define PTA_CMD_HMAC_SHA1_VerifyFinal       (0x00060012)

/*
 * [in/out]     memref[0] : HMAC handler (rsip_hmac_handle_t)
 * [in]         memref[1] : Wrapped key (rsip_wrapped_key_t:68byte)
 */
#define PTA_CMD_HMAC_SHA224_GenerateInit    (0x00060100)
/*
 * [in/out]     memref[0] : HMAC handler (rsip_hmac_handle_t)
 * [in]         memref[1] : Message
 */
#define PTA_CMD_HMAC_SHA224_GenerateUpdate  (0x00060101)
/*
 * [in/out]     memref[0] : HMAC handler (rsip_hmac_handle_t)
 * [in/out]     memref[1] : MAC (28byte)
 */
#define PTA_CMD_HMAC_SHA224_GenerateFinal   (0x00060102)
/*
 * [in/out]     memref[0] : HMAC handler (rsip_hmac_handle_t)
 * [in]         memref[1] : Wrapped key (rsip_wrapped_key_t:68byte)
 */
#define PTA_CMD_HMAC_SHA224_VerifyInit      (0x00060110)
/*
 * [in/out]     memref[0] : HMAC handler (rsip_hmac_handle_t)
 * [in]         memref[1] : Message
 */
#define PTA_CMD_HMAC_SHA224_VerifyUpdate    (0x00060111)
/*
 * [in/out]     memref[0] : HMAC handler (rsip_hmac_handle_t)
 * [in]         memref[1] : MAC (4 to 28byte)
 */
#define PTA_CMD_HMAC_SHA224_VerifyFinal     (0x00060112)

/*
 * [in/out]     memref[0] : HMAC handler (rsip_hmac_handle_t)
 * [in]         memref[1] : Wrapped key (rsip_wrapped_key_t:68byte)
 */
#define PTA_CMD_HMAC_SHA256_GenerateInit    (0x00060200)
/*
 * [in/out]     memref[0] : HMAC handler (rsip_hmac_handle_t)
 * [in]         memref[1] : Message
 */
#define PTA_CMD_HMAC_SHA256_GenerateUpdate  (0x00060201)
/*
 * [in/out]     memref[0] : HMAC handler (rsip_hmac_handle_t)
 * [in/out]     memref[1] : MAC (32byte)
 */
#define PTA_CMD_HMAC_SHA256_GenerateFinal   (0x00060202)
/*
 * [in/out]     memref[0] : HMAC handler (rsip_hmac_handle_t)
 * [in]         memref[1] : Wrapped key (rsip_wrapped_key_t:68byte)
 */
#define PTA_CMD_HMAC_SHA256_VerifyInit      (0x00060210)
/*
 * [in/out]     memref[0] : HMAC handler (rsip_hmac_handle_t)
 * [in]         memref[1] : Message
 */
#define PTA_CMD_HMAC_SHA256_VerifyUpdate    (0x00060211)
/*
 * [in/out]     memref[0] : HMAC handler (rsip_hmac_handle_t)
 * [in]         memref[1] : MAC (4 to 32byte)
 */
#define PTA_CMD_HMAC_SHA256_VerifyFinal     (0x00060212)

#endif /* __PTA_RSIP_HMAC_H */
