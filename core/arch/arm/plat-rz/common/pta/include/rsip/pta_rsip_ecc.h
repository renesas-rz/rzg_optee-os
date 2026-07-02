/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2024, Renesas Electronics Corporation
 */

#ifndef __PTA_RSIP_ECC_H
#define __PTA_RSIP_ECC_H

#include <r_rsip_api.h>

#define PTA_RSIP_ECC_UUID \
	{ 0xf0dd12df, 0x3d26, 0x4bf2, \
		{ 0x93, 0x77, 0x4e, 0x2c, 0x31, 0x82, 0xaf, 0x43 } }

#define SIGNATURE_SIZE (64U)

/*
 * [in]      memref[0] : Message
 * [in/out]  memref[1] : Signature (64byte)
 * [in]      memref[2] : Wrapped key (rsip_wrapped_key_t:68byte)
 */
#define PTA_CMD_ECDSA_secp192r1_SignatureGenerate       (0x00050000)

/*
 * [in]      memref[0] : Signature (64byte)
 * [in]      memref[1] : Message
 * [in]      memref[2] : Wrapped key (rsip_wrapped_key_t:100byte)
 */
#define PTA_CMD_ECDSA_secp192r1_SignatureVerify         (0x00050010)

/*
 * [in]      memref[0] : Message
 * [in/out]  memref[1] : Signature (64byte)
 * [in]      memref[2] : Wrapped key (rsip_wrapped_key_t:68byte)
 */
#define PTA_CMD_ECDSA_secp224r1_SignatureGenerate       (0x00050100)
/*
 * [in]      memref[0] : Signature (64byte)
 * [in]      memref[1] : Message
 * [in]      memref[2] : Wrapped key (rsip_wrapped_key_t:100byte)
 */
#define PTA_CMD_ECDSA_secp224r1_SignatureVerify         (0x00050110)

/*
 * [in]      memref[0] : Message
 * [in/out]  memref[1] : Signature (64byte)
 * [in]      memref[2] : Wrapped key (rsip_wrapped_key_t:68byte)
 */
#define PTA_CMD_ECDSA_secp256r1_SignatureGenerate       (0x00050200)
/*
 * [in]      memref[0] : Signature (64byte)
 * [in]      memref[1] : Message
 * [in]      memref[2] : Wrapped key (rsip_wrapped_key_t:100byte)
 */
#define PTA_CMD_ECDSA_secp256r1_SignatureVerify         (0x00050210)

/*
 * [in]      memref[0] : Message
 * [in/out]  memref[1] : Signature (64byte)
 * [in]      memref[2] : Wrapped key (rsip_wrapped_key_t:68byte)
 */
#define PTA_CMD_ECDSA_BrainpoolP256r1_SignatureGenerate (0x00052000)
/*
 * [in]      memref[0] : Signature (64byte)
 * [in]      memref[1] : Message
 * [in]      memref[2] : Wrapped key (rsip_wrapped_key_t:100byte)
 */
#define PTA_CMD_ECDSA_BrainpoolP256r1_SignatureVerify   (0x00052010)

#endif /* __PTA_RSIP_ECC_H */
