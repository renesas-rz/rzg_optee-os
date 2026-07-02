/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2024, Renesas Electronics Corporation
 */

#ifndef __PTA_RSIP_AES_H
#define __PTA_RSIP_AES_H

#include <r_rsip_api.h>

#define PTA_RSIP_AES_UUID \
	{ 0xa28ddef1, 0xe546, 0x449b, \
		{ 0xb0, 0x61, 0xbf, 0xc4, 0x74, 0xb4, 0x9a, 0x4e } }

#define MAC_BYTE_SIZE    (16)
#define AES_BLOCK_LEN    (16)

/*
 * [in]     memref[0] : Wrapped key (rsip_wrapped_key_t:52byte)
 */
#define PTA_CMD_AES128ECB_EncryptInit       (0x00020001)
/*
 * [in]     memref[0] : Plain (length must be a multiple of 16)
 * [in/out] memref[1] : Cipher
 */
#define PTA_CMD_AES128ECB_EncryptUpdate     (0x00020002)
/*
 * [in/out] memref[0] : Cipher
 */
#define PTA_CMD_AES128ECB_EncryptFinal      (0x00020003)
/*
 * [in]     memref[0] : Wrapped key (rsip_wrapped_key_t:52byte)
 */
#define PTA_CMD_AES128ECB_DecryptInit       (0x00020011)
/*
 * [in]     memref[0] : Cipher (length must be a multiple of 16)
 * [in/out] memref[1] : Plain
 */
#define PTA_CMD_AES128ECB_DecryptUpdate     (0x00020012)
/*
 * [in/out] memref[0] : Plain (No outputs)
 */
#define PTA_CMD_AES128ECB_DecryptFinal      (0x00020013)

/*
 * [in]     memref[0] : Wrapped key (rsip_wrapped_key_t:68byte)
 */
#define PTA_CMD_AES256ECB_EncryptInit       (0x00020101)
/*
 * [in]     memref[0] : Plain (length must be a multiple of 16)
 * [in/out] memref[1] : Cipher
 */
#define PTA_CMD_AES256ECB_EncryptUpdate     (0x00020102)
/*
 * [in/out] memref[0] : Cipher
 */
#define PTA_CMD_AES256ECB_EncryptFinal      (0x00020103)
/*
 * [in]     memref[0] : Wrapped key (rsip_wrapped_key_t:68byte)
 */
#define PTA_CMD_AES256ECB_DecryptInit       (0x00020111)
/*
 * [in]     memref[0] : Cipher (length must be a multiple of 16)
 * [in/out] memref[1] : Plain
 */
#define PTA_CMD_AES256ECB_DecryptUpdate     (0x00020112)
/*
 * [in/out] memref[0] : Plain (No outputs)
 */
#define PTA_CMD_AES256ECB_DecryptFinal      (0x00020113)

/*
 * [in]     memref[0] : Wrapped key (rsip_wrapped_key_t:52byte)
 * [in]     memref[1] : Initial vector (16byte)
 */
#define PTA_CMD_AES128CBC_EncryptInit       (0x00021001)
/*
 * [in]     memref[0] : Plain (length must be a multiple of 16)
 * [in/out] memref[1] : Cipher
 */
#define PTA_CMD_AES128CBC_EncryptUpdate     (0x00021002)
/*
 * [in/out] memref[0] : Cipher
 */
#define PTA_CMD_AES128CBC_EncryptFinal      (0x00021003)
/*
 * [in]     memref[0] : Wrapped key (rsip_wrapped_key_t:52byte)
 * [in]     memref[1] : Initial vector (16byte)
 */
#define PTA_CMD_AES128CBC_DecryptInit       (0x00021011)
/*
 * [in]     memref[0] : Cipher (length must be a multiple of 16)
 * [in/out] memref[1] : Plain
 */
#define PTA_CMD_AES128CBC_DecryptUpdate     (0x00021012)
/*
 * [in/out] memref[0] : Plain (No outputs)
 */
#define PTA_CMD_AES128CBC_DecryptFinal      (0x00021013)

/*
 * [in]     memref[0] : Wrapped key (rsip_wrapped_key_t:68byte)
 * [in]     memref[1] : Initial vector (16byte)
 */
#define PTA_CMD_AES256CBC_EncryptInit       (0x00021101)
/*
 * [in]     memref[0] : Plain (length must be a multiple of 16)
 * [in/out] memref[1] : Cipher
 */
#define PTA_CMD_AES256CBC_EncryptUpdate     (0x00021102)
/*
 * [in/out] memref[0] : Cipher
 */
#define PTA_CMD_AES256CBC_EncryptFinal      (0x00021103)
/*
 * [in]     memref[0] : Wrapped key (rsip_wrapped_key_t:68byte)
 * [in]     memref[1] : Initial vector (16byte)
 */
#define PTA_CMD_AES256CBC_DecryptInit       (0x00021111)
/*
 * [in]     memref[0] : Cipher (length must be a multiple of 16)
 * [in/out] memref[1] : Plain
 */
#define PTA_CMD_AES256CBC_DecryptUpdate     (0x00021112)
/*
 * [in/out] memref[0] : Plain (No outputs)
 */
#define PTA_CMD_AES256CBC_DecryptFinal      (0x00021113)

/*
 * [in]     memref[0] : Wrapped key (rsip_wrapped_key_t:52byte)
 * [in]     memref[1] : Initial vector (16byte)
 */
#define PTA_CMD_AES128CTR_EncryptInit       (0x00022001)
/*
 * [in]     memref[0] : Plain (length must be a multiple of 16)
 * [in/out] memref[1] : Cipher
 */
#define PTA_CMD_AES128CTR_EncryptUpdate     (0x00022002)
/*
 * [in/out] memref[0] : Cipher
 */
#define PTA_CMD_AES128CTR_EncryptFinal      (0x00022003)
/*
 * [in]     memref[0] : Wrapped key (rsip_wrapped_key_t:52byte)
 * [in]     memref[1] : Initial vector (16byte)
 */
#define PTA_CMD_AES128CTR_DecryptInit       (0x00022011)
/*
 * [in]     memref[0] : Cipher (length must be a multiple of 16)
 * [in/out] memref[1] : Plain
 */
#define PTA_CMD_AES128CTR_DecryptUpdate     (0x00022012)
/*
 * [in/out] memref[0] : Plain (No outputs)
 */
#define PTA_CMD_AES128CTR_DecryptFinal      (0x00022013)

/*
 * [in]     memref[0] : Wrapped key (rsip_wrapped_key_t:68byte)
 * [in]     memref[1] : Initial vector (16byte)
 */
#define PTA_CMD_AES256CTR_EncryptInit       (0x00022101)
/*
 * [in]     memref[0] : Plain (length must be a multiple of 16)
 * [in/out] memref[1] : Cipher
 */
#define PTA_CMD_AES256CTR_EncryptUpdate     (0x00022102)
/*
 * [in/out] memref[0] : Cipher
 */
#define PTA_CMD_AES256CTR_EncryptFinal      (0x00022103)
/*
 * [in]     memref[0] : Wrapped key (rsip_wrapped_key_t:68byte)
 * [in]     memref[1] : Initial vector (16byte)
 */
#define PTA_CMD_AES256CTR_DecryptInit       (0x00022111)
/*
 * [in]     memref[0] : Cipher (length must be a multiple of 16)
 * [in/out] memref[1] : Plain
 */
#define PTA_CMD_AES256CTR_DecryptUpdate     (0x00022112)
/*
 * [in/out] memref[0] : Plain (No outputs)
 */
#define PTA_CMD_AES256CTR_DecryptFinal      (0x00022113)

/*
 * [in]     memref[0] : Wrapped key (rsip_wrapped_key_t:52byte)
 */
#define PTA_CMD_AES128CMAC_GenerateInit     (0x00023001)
/*
 * [in]     memref[0] : Message
 */
#define PTA_CMD_AES128CMAC_GenerateUpdate   (0x00023002)
/*
 * [in/out] memref[0] : MAC (16byte)
 */
#define PTA_CMD_AES128CMAC_GenerateFinal    (0x00023003)
/*
 * [in]     memref[0] : Wrapped key (rsip_wrapped_key_t:52byte)
 */
#define PTA_CMD_AES128CMAC_VerifyInit       (0x00023011)
/*
 * [in]     memref[0] : Message
 */
#define PTA_CMD_AES128CMAC_VerifyUpdate     (0x00023012)
/*
 * [in]     memref[0] : MAC (2 to 16byte)
 */
#define PTA_CMD_AES128CMAC_VerifyFinal      (0x00023013)

/*
 * [in]     memref[0] : Wrapped key (rsip_wrapped_key_t:68byte)
 */
#define PTA_CMD_AES256CMAC_GenerateInit     (0x00023101)
/*
 * [in]     memref[0] : Message
 */
#define PTA_CMD_AES256CMAC_GenerateUpdate   (0x00023102)
/*
 * [in/out] memref[0] : MAC (16byte)
 */
#define PTA_CMD_AES256CMAC_GenerateFinal    (0x00023103)
/*
 * [in]     memref[0] : Wrapped key (rsip_wrapped_key_t:68byte)
 */
#define PTA_CMD_AES256CMAC_VerifyInit       (0x00023111)
/*
 * [in]     memref[0] : Message
 */
#define PTA_CMD_AES256CMAC_VerifyUpdate     (0x00023112)
/*
 * [in]     memref[0] : MAC (2 to 16byte)
 */
#define PTA_CMD_AES256CMAC_VerifyFinal      (0x00023113)

/*
 * [in]     memref[0] : Wrapped key (rsip_wrapped_key_t:68byte)
 * [in]     memref[1] : Initial vector (16byte)
 */
#define PTA_CMD_AES128XTS_EncryptInit       (0x00024001)
/*
 * [in]     memref[0] : Plain
 * [in/out] memref[1] : Cipher
 */
#define PTA_CMD_AES128XTS_EncryptUpdate     (0x00024002)
/*
 * [in/out] memref[0] : Cipher
 */
#define PTA_CMD_AES128XTS_EncryptFinal      (0x00024003)
/*
 * [in]     memref[0] : Wrapped key (rsip_wrapped_key_t:68byte)
 * [in]     memref[1] : Initial vector (16byte)
 */
#define PTA_CMD_AES128XTS_DecryptInit       (0x00024011)
/*
 * [in]     memref[0] : Cipher
 * [in/out] memref[1] : Plain
 */
#define PTA_CMD_AES128XTS_DecryptUpdate     (0x00024012)
/*
 * [in/out] memref[0] : Plain
 */
#define PTA_CMD_AES128XTS_DecryptFinal      (0x00024013)

/*
 * [in]     memref[0] : Wrapped key (rsip_wrapped_key_t:100byte)
 * [in]     memref[1] : Initial vector (16byte)
 */
#define PTA_CMD_AES256XTS_EncryptInit       (0x00024101)
/*
 * [in]     memref[0] : Plain
 * [in/out] memref[1] : Cipher
 */
#define PTA_CMD_AES256XTS_EncryptUpdate     (0x00024102)
/*
 * [in/out] memref[0] : Cipher
 */
#define PTA_CMD_AES256XTS_EncryptFinal      (0x00024103)
/*
 * [in]     memref[0] : Wrapped key (rsip_wrapped_key_t:100byte)
 * [in]     memref[1] : Initial vector (16byte)
 */
#define PTA_CMD_AES256XTS_DecryptInit       (0x00024111)
/*
 * [in]     memref[0] : Cipher
 * [in/out] memref[1] : Plain
 */
#define PTA_CMD_AES256XTS_DecryptUpdate     (0x00024112)
/*
 * [in/out] memref[0] : Plain
 */
#define PTA_CMD_AES256XTS_DecryptFinal      (0x00024113)

/*
 * [in]     memref[0] : Wrapped key (rsip_wrapped_key_t:52byte)
 * [in]     memref[1] : Initial vector (16byte)
 */
#define PTA_CMD_AES128GCM_EncryptInit       (0x00025001)
/*
 * [in]     memref[0] : Plain
 * [in/out] memref[1] : Cipher
 * [in]     memref[2] : AAD
 */
#define PTA_CMD_AES128GCM_EncryptUpdate     (0x00025002)
/*
 * [in/out] memref[0] : Cipher
 * [in/out] memref[1] : Tag (16byte)
 */
#define PTA_CMD_AES128GCM_EncryptFinal      (0x00025003)
/*
 * [in]     memref[0] : Wrapped key (rsip_wrapped_key_t:52byte)
 * [in]     memref[1] : Initial vector (16byte)
 */
#define PTA_CMD_AES128GCM_DecryptInit       (0x00025011)
/*
 * [in]     memref[0] : Cipher
 * [in/out] memref[1] : Plain
 * [in]     memref[2] : AAD
 */
#define PTA_CMD_AES128GCM_DecryptUpdate     (0x00025012)
/*
 * [in/out] memref[0] : Plain
 * [in]     memref[1] : Tag (1 to 16byte)
 */
#define PTA_CMD_AES128GCM_DecryptFinal      (0x00025013)

/*
 * [in]     memref[0] : Wrapped key (rsip_wrapped_key_t:68byte)
 * [in]     memref[1] : Initial vector (16byte)
 */
#define PTA_CMD_AES256GCM_EncryptInit       (0x00025101)
/*
 * [in]     memref[0] : Plain
 * [in/out] memref[1] : Cipher
 * [in]     memref[2] : AAD
 */
#define PTA_CMD_AES256GCM_EncryptUpdate     (0x00025102)
/*
 * [in/out] memref[0] : Cipher
 * [in/out] memref[1] : Tag (16byte)
 */
#define PTA_CMD_AES256GCM_EncryptFinal      (0x00025103)
/*
 * [in]     memref[0] : Wrapped key (rsip_wrapped_key_t:68byte)
 * [in]     memref[1] : Initial vector (16byte)
 */
#define PTA_CMD_AES256GCM_DecryptInit       (0x00025111)
/*
 * [in]     memref[0] : Cipher
 * [in/out] memref[1] : Plain
 * [in]     memref[2] : AAD
 */
#define PTA_CMD_AES256GCM_DecryptUpdate     (0x00025112)
/*
 * [in/out] memref[0] : Plain
 * [in]     memref[1] : Tag (1 to 16byte)
 */
#define PTA_CMD_AES256GCM_DecryptFinal      (0x00025113)

#endif /* __PTA_RSIP_AES_H */
