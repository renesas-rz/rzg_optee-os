/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2024, Renesas Electronics Corporation
 */

#ifndef R_RSIP_WRAPPER_H
#define R_RSIP_WRAPPER_H

/***********************************************************************************************************************
 * Includes
 **********************************************************************************************************************/
#include <stdint.h>
#include "r_rsip_err.h"

/***********************************************************************************************************************
 * Macro definitions
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Typedef definitions
 **********************************************************************************************************************/

/**********************************************************************************************************************
 * Exported global variables
 **********************************************************************************************************************/

/**********************************************************************************************************************
 * Public Function Prototypes
 **********************************************************************************************************************/

/* Key pair generation */
rsip_ret_t r_rsip_wrapper_pf4_secp192r1(uint32_t OutData_PubKeyIndex[], uint32_t OutData_PrivKeyIndex[]);
rsip_ret_t r_rsip_wrapper_pf4_secp224r1(uint32_t OutData_PubKeyIndex[], uint32_t OutData_PrivKeyIndex[]);
rsip_ret_t r_rsip_wrapper_pf4_secp256r1(uint32_t OutData_PubKeyIndex[], uint32_t OutData_PrivKeyIndex[]);
rsip_ret_t r_rsip_wrapper_pf4_brainpoolp256r1(uint32_t OutData_PubKeyIndex[], uint32_t OutData_PrivKeyIndex[]);
rsip_ret_t r_rsip_wrapper_p2a(uint32_t OutData_PubKeyIndex[], uint32_t OutData_PrivKeyIndex[]);
rsip_ret_t r_rsip_wrapper_p2b(uint32_t OutData_PubKeyIndex[], uint32_t OutData_PrivKeyIndex[]);
rsip_ret_t r_rsip_wrapper_p3a (uint32_t OutData_PubKeyIndex[], uint32_t OutData_PrivKeyIndex[]);
rsip_ret_t r_rsip_wrapper_p3b (uint32_t OutData_PubKeyIndex[], uint32_t OutData_PrivKeyIndex[]);

/* Key import with KUK */
rsip_ret_t r_rsip_wrapper_p2c_secp192r1(uint32_t const InData_IV[],
                                        uint32_t const InData_InstData[],
                                        uint32_t       OutData_KeyIndex[]);
rsip_ret_t r_rsip_wrapper_p1e_secp192r1(uint32_t const InData_IV[],
                                        uint32_t const InData_InstData[],
                                        uint32_t       OutData_KeyIndex[]);
rsip_ret_t r_rsip_wrapper_p2c_secp224r1(uint32_t const InData_IV[],
                                        uint32_t const InData_InstData[],
                                        uint32_t       OutData_KeyIndex[]);
rsip_ret_t r_rsip_wrapper_p1e_secp224r1(uint32_t const InData_IV[],
                                        uint32_t const InData_InstData[],
                                        uint32_t       OutData_KeyIndex[]);
rsip_ret_t r_rsip_wrapper_p2c_secp256r1(uint32_t const InData_IV[],
                                        uint32_t const InData_InstData[],
                                        uint32_t       OutData_KeyIndex[]);
rsip_ret_t r_rsip_wrapper_p1e_secp256r1(uint32_t const InData_IV[],
                                        uint32_t const InData_InstData[],
                                        uint32_t       OutData_KeyIndex[]);
rsip_ret_t r_rsip_wrapper_p2c_brainpoolp256r1(uint32_t const InData_IV[],
                                              uint32_t const InData_InstData[],
                                              uint32_t       OutData_KeyIndex[]);
rsip_ret_t r_rsip_wrapper_p1e_brainpoolp256r1(uint32_t const InData_IV[],
                                              uint32_t const InData_InstData[],
                                              uint32_t       OutData_KeyIndex[]);
rsip_ret_t r_rsip_wrapper_p0f_hmac_sha1(const uint32_t InData_IV[],
                                        const uint32_t InData_InstData[],
                                        uint32_t       OutData_KeyIndex[]);
rsip_ret_t r_rsip_wrapper_p0f_hmac_sha224(const uint32_t InData_IV[],
                                          const uint32_t InData_InstData[],
                                          uint32_t       OutData_KeyIndex[]);
rsip_ret_t r_rsip_wrapper_p0f_hmac_sha256(const uint32_t InData_IV[],
                                          const uint32_t InData_InstData[],
                                          uint32_t       OutData_KeyIndex[]);

/* AES-ECB/CBC/CTR */
rsip_ret_t r_rsip_wrapper_p48i_ecb_enc(const uint32_t InData_KeyIndex[], const uint32_t InData_IV[]);
rsip_ret_t r_rsip_wrapper_p48i_ecb_dec(const uint32_t InData_KeyIndex[], const uint32_t InData_IV[]);
rsip_ret_t r_rsip_wrapper_p48i_cbc_enc(const uint32_t InData_KeyIndex[], const uint32_t InData_IV[]);
rsip_ret_t r_rsip_wrapper_p48i_cbc_dec(const uint32_t InData_KeyIndex[], const uint32_t InData_IV[]);
rsip_ret_t r_rsip_wrapper_p48i_ctr(const uint32_t InData_KeyIndex[], const uint32_t InData_IV[]);
rsip_ret_t r_rsip_wrapper_p50i_ecb_enc(const uint32_t InData_KeyIndex[], const uint32_t InData_IV[]);
rsip_ret_t r_rsip_wrapper_p50i_ecb_dec(const uint32_t InData_KeyIndex[], const uint32_t InData_IV[]);
rsip_ret_t r_rsip_wrapper_p50i_cbc_enc(const uint32_t InData_KeyIndex[], const uint32_t InData_IV[]);
rsip_ret_t r_rsip_wrapper_p50i_cbc_dec(const uint32_t InData_KeyIndex[], const uint32_t InData_IV[]);
rsip_ret_t r_rsip_wrapper_p50i_ctr(const uint32_t InData_KeyIndex[], const uint32_t InData_IV[]);

/* AES-CMAC */
rsip_ret_t r_rsip_wrapper_p41f_gen(const uint32_t InData_Text[], uint32_t OutData_DataT[], const uint32_t all_msg_len);
rsip_ret_t r_rsip_wrapper_p44f_gen(const uint32_t InData_Text[], uint32_t OutData_DataT[], const uint32_t all_msg_len);
rsip_ret_t r_rsip_wrapper_p41f_veri(const uint32_t InData_Text[],
                                    const uint32_t InData_DataT[],
                                    const uint32_t InData_DataTLen[],
                                    const uint32_t all_msg_len);
rsip_ret_t r_rsip_wrapper_p44f_veri(const uint32_t InData_Text[],
                                    const uint32_t InData_DataT[],
                                    const uint32_t InData_DataTLen[],
                                    const uint32_t all_msg_len);

/* ECDSA */
rsip_ret_t r_rsip_wrapper_pf0_secp192r1(const uint32_t InData_KeyIndex[],
                                        const uint32_t InData_MsgDgst[],
                                        uint32_t       OutData_Signature[]);
rsip_ret_t r_rsip_wrapper_pf1_secp192r1(const uint32_t InData_KeyIndex[],
                                        const uint32_t InData_MsgDgst[],
                                        const uint32_t InData_Signature[]);
rsip_ret_t r_rsip_wrapper_pf0_secp224r1(const uint32_t InData_KeyIndex[],
                                        const uint32_t InData_MsgDgst[],
                                        uint32_t       OutData_Signature[]);
rsip_ret_t r_rsip_wrapper_pf1_secp224r1(const uint32_t InData_KeyIndex[],
                                        const uint32_t InData_MsgDgst[],
                                        const uint32_t InData_Signature[]);
rsip_ret_t r_rsip_wrapper_pf0_secp256r1(const uint32_t InData_KeyIndex[],
                                        const uint32_t InData_MsgDgst[],
                                        uint32_t       OutData_Signature[]);
rsip_ret_t r_rsip_wrapper_pf1_secp256r1(const uint32_t InData_KeyIndex[],
                                        const uint32_t InData_MsgDgst[],
                                        const uint32_t InData_Signature[]);
rsip_ret_t r_rsip_wrapper_pf0_brainpoolp256r1(const uint32_t InData_KeyIndex[],
                                              const uint32_t InData_MsgDgst[],
                                              uint32_t       OutData_Signature[]);
rsip_ret_t r_rsip_wrapper_pf1_brainpoolp256r1(const uint32_t InData_KeyIndex[],
                                              const uint32_t InData_MsgDgst[],
                                              const uint32_t InData_Signature[]);

/* Key import with UFPK */
rsip_ret_t r_rsip_wrapper_pfa_secp192r1(const uint32_t InData_SharedKeyNum[],
                                        const uint32_t InData_SharedKeyIndex[],
                                        const uint32_t InData_SessionKey[],
                                        const uint32_t InData_IV[],
                                        const uint32_t InData_InstData[],
                                        uint32_t       OutData_KeyIndex[]);
rsip_ret_t r_rsip_wrapper_pf3_secp192r1(const uint32_t InData_SharedKeyNum[],
                                        const uint32_t InData_SharedKeyIndex[],
                                        const uint32_t InData_SessionKey[],
                                        const uint32_t InData_IV[],
                                        const uint32_t InData_InstData[],
                                        uint32_t       OutData_KeyIndex[]);
rsip_ret_t r_rsip_wrapper_pfa_secp224r1(const uint32_t InData_SharedKeyNum[],
                                        const uint32_t InData_SharedKeyIndex[],
                                        const uint32_t InData_SessionKey[],
                                        const uint32_t InData_IV[],
                                        const uint32_t InData_InstData[],
                                        uint32_t       OutData_KeyIndex[]);
rsip_ret_t r_rsip_wrapper_pf3_secp224r1(const uint32_t InData_SharedKeyNum[],
                                        const uint32_t InData_SharedKeyIndex[],
                                        const uint32_t InData_SessionKey[],
                                        const uint32_t InData_IV[],
                                        const uint32_t InData_InstData[],
                                        uint32_t       OutData_KeyIndex[]);
rsip_ret_t r_rsip_wrapper_pfa_secp256r1(const uint32_t InData_SharedKeyNum[],
                                        const uint32_t InData_SharedKeyIndex[],
                                        const uint32_t InData_SessionKey[],
                                        const uint32_t InData_IV[],
                                        const uint32_t InData_InstData[],
                                        uint32_t       OutData_KeyIndex[]);
rsip_ret_t r_rsip_wrapper_pf3_secp256r1(const uint32_t InData_SharedKeyNum[],
                                        const uint32_t InData_SharedKeyIndex[],
                                        const uint32_t InData_SessionKey[],
                                        const uint32_t InData_IV[],
                                        const uint32_t InData_InstData[],
                                        uint32_t       OutData_KeyIndex[]);
rsip_ret_t r_rsip_wrapper_pf3_brainpoolp256r1(const uint32_t InData_SharedKeyNum[],
                                              const uint32_t InData_SharedKeyIndex[],
                                              const uint32_t InData_SessionKey[],
                                              const uint32_t InData_IV[],
                                              const uint32_t InData_InstData[],
                                              uint32_t       OutData_KeyIndex[]);
rsip_ret_t r_rsip_wrapper_pfa_brainpoolp256r1(const uint32_t InData_SharedKeyNum[],
                                              const uint32_t InData_SharedKeyIndex[],
                                              const uint32_t InData_SessionKey[],
                                              const uint32_t InData_IV[],
                                              const uint32_t InData_InstData[],
                                              uint32_t       OutData_KeyIndex[]);
rsip_ret_t r_rsip_wrapper_p80_hmac_sha1(const uint32_t InData_SharedKeyNum[],
                                        const uint32_t InData_SharedKeyIndex[],
                                        const uint32_t InData_SessionKey[],
                                        const uint32_t InData_IV[],
                                        const uint32_t InData_InstData[],
                                        uint32_t       OutData_KeyIndex[]);
rsip_ret_t r_rsip_wrapper_p80_hmac_sha224(const uint32_t InData_SharedKeyNum[],
                                          const uint32_t InData_SharedKeyIndex[],
                                          const uint32_t InData_SessionKey[],
                                          const uint32_t InData_IV[],
                                          const uint32_t InData_InstData[],
                                          uint32_t       OutData_KeyIndex[]);
rsip_ret_t r_rsip_wrapper_p80_hmac_sha256(const uint32_t InData_SharedKeyNum[],
                                          const uint32_t InData_SharedKeyIndex[],
                                          const uint32_t InData_SessionKey[],
                                          const uint32_t InData_IV[],
                                          const uint32_t InData_InstData[],
                                          uint32_t       OutData_KeyIndex[]);

/* Password hash generation */
rsip_ret_t r_rsip_wrapper_p15_jtag_level1(const uint32_t InData_SharedKeyNum[],
                                          const uint32_t InData_SharedKeyIndex[],
                                          const uint32_t InData_SessionKey[],
                                          const uint32_t InData_IV[],
                                          const uint32_t InData_EncAuthData[],
                                          uint32_t       OutData_Hash[]);

rsip_ret_t r_rsip_wrapper_p15_jtag_level2(const uint32_t InData_SharedKeyNum[],
                                          const uint32_t InData_SharedKeyIndex[],
                                          const uint32_t InData_SessionKey[],
                                          const uint32_t InData_IV[],
                                          const uint32_t InData_EncAuthData[],
                                          uint32_t       OutData_Hash[]);

#endif                                 /* R_RSIP_WRAPPER_H */
