/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2024, Renesas Electronics Corporation
 */

#ifndef R_RSIP_PRIMITIVE_H
#define R_RSIP_PRIMITIVE_H

/***********************************************************************************************************************
 * Includes
 **********************************************************************************************************************/
#include <stdint.h>
#include "r_rsip_err.h"

/***********************************************************************************************************************
 * Macro definitions
 **********************************************************************************************************************/

#define RSIP_PRV_WORD_SIZE_S_RAM      (16U)
#define RSIP_PRV_WORD_SIZE_S_INST     (16U)
#define RSIP_PRV_WORD_SIZE_S_INST2    (16U)
#define RSIP_PRV_WORD_SIZE_S_HEAP     (940U)

/***********************************************************************************************************************
 * Typedef definitions
 **********************************************************************************************************************/

/**********************************************************************************************************************
 * Exported global variables
 **********************************************************************************************************************/

extern uint32_t S_RAM[RSIP_PRV_WORD_SIZE_S_RAM];
extern uint32_t S_INST[RSIP_PRV_WORD_SIZE_S_INST];
extern uint32_t S_INST2[RSIP_PRV_WORD_SIZE_S_INST2];
extern uint32_t S_HEAP[RSIP_PRV_WORD_SIZE_S_HEAP];

extern uint32_t const S_FLASH[];

/**********************************************************************************************************************
 * Public Function Prototypes
 **********************************************************************************************************************/

/* Sub functions */
void r_rsip_func010(void);
void r_rsip_func011(void);
void r_rsip_func012(void);
void r_rsip_func013(void);
void r_rsip_func016(uint32_t ARG1);
void r_rsip_func017(uint32_t ARG1);
void r_rsip_func022(void);
void r_rsip_func023(void);
void r_rsip_func040(void);
void r_rsip_func041(void);
void r_rsip_func043(void);
void r_rsip_func044(void);
void r_rsip_func045(void);
void r_rsip_func046(void);
void r_rsip_func047(void);
void r_rsip_func050(void);
void r_rsip_func051(void);
void r_rsip_func052(void);
void r_rsip_func053(void);
void r_rsip_func054(void);
void r_rsip_func055(void);
void r_rsip_func056(void);
void r_rsip_func057(void);
void r_rsip_func058(void);
void r_rsip_func059(void);
void r_rsip_func061(void);
void r_rsip_func062(void);
void r_rsip_func073(uint32_t ARG1);
void r_rsip_func084(uint32_t ARG1);
void r_rsip_func085(uint32_t ARG1);
void r_rsip_func086(uint32_t ARG1);
void r_rsip_func087(uint32_t ARG1);
void r_rsip_func088(void);
void r_rsip_func100(uint32_t ARG1, uint32_t ARG2, uint32_t ARG3, uint32_t ARG4);
void r_rsip_func101(uint32_t ARG1, uint32_t ARG2, uint32_t ARG3, uint32_t ARG4);
void r_rsip_func102(uint32_t ARG1, uint32_t ARG2, uint32_t ARG3, uint32_t ARG4);
void r_rsip_func103(void);
void r_rsip_func205(void);
void r_rsip_func206(void);
void r_rsip_func300(void);
void r_rsip_func301(void);
void r_rsip_func302(void);
void r_rsip_func303(void);
void r_rsip_func304(void);
void r_rsip_func305(void);
void r_rsip_func306(void);
void r_rsip_func307(void);
void r_rsip_func308(void);
void r_rsip_func309(void);
void r_rsip_func310(void);
void r_rsip_func311(void);
void r_rsip_func400(const uint32_t ARG1[]);

/* Open */
void       r_rsip_p00(void);
rsip_ret_t r_rsip_p01(void);
rsip_ret_t r_rsip_p02(void);
rsip_ret_t r_rsip_p06(const uint32_t InData_Cmd[]);
rsip_ret_t r_rsip_p25(const uint32_t InData_Cmd[]);
rsip_ret_t r_rsip_p30(uint32_t OutData_KeyIndex[]);
rsip_ret_t r_rsip_p40(const uint32_t InData_KeyIndex[]);

/* Key generation */
rsip_ret_t r_rsip_p07(uint32_t OutData_KeyIndex[]);
rsip_ret_t r_rsip_p08(uint32_t OutData_KeyIndex[]);
rsip_ret_t r_rsip_p16(uint32_t OutData_KeyIndex[]);
rsip_ret_t r_rsip_p17(uint32_t OutData_KeyIndex[]);

/* Key pair generation */
rsip_ret_t r_rsip_pf4(uint32_t const InData_CurveType[],
                      uint32_t const InData_Cmd[],
                      uint32_t       OutData_PubKeyIndex[],
                      uint32_t       OutData_PrivKeyIndex[]);
rsip_ret_t r_rsip_p2a(uint32_t MAX_CNT, uint32_t OutData_PubKeyIndex[], uint32_t OutData_PrivKeyIndex[]);
rsip_ret_t r_rsip_p2b(uint32_t MAX_CNT, uint32_t OutData_PubKeyIndex[], uint32_t OutData_PrivKeyIndex[]);
rsip_ret_t r_rsip_p3a(uint32_t MAX_CNT, uint32_t OutData_PubKeyIndex[], uint32_t OutData_PrivKeyIndex[]);
rsip_ret_t r_rsip_p3b(uint32_t MAX_CNT, uint32_t OutData_PubKeyIndex[], uint32_t OutData_PrivKeyIndex[]);

/* Key import with UFPK */
rsip_ret_t r_rsip_p10(const uint32_t InData_SharedKeyNum[],
                      const uint32_t InData_SharedKeyIndex[],
                      const uint32_t InData_SessionKey[],
                      const uint32_t InData_IV[],
                      const uint32_t InData_InstData[],
                      uint32_t       OutData_KeyIndex[]);
rsip_ret_t r_rsip_p04(const uint32_t InData_SharedKeyNum[],
                      const uint32_t InData_SharedKeyIndex[],
                      const uint32_t InData_SessionKey[],
                      const uint32_t InData_IV[],
                      const uint32_t InData_InstData[],
                      uint32_t       OutData_KeyIndex[]);
rsip_ret_t r_rsip_p18(const uint32_t InData_SharedKeyNum[],
                      const uint32_t InData_SharedKeyIndex[],
                      const uint32_t InData_SessionKey[],
                      const uint32_t InData_IV[],
                      const uint32_t InData_InstData[],
                      uint32_t       OutData_KeyIndex[]);
rsip_ret_t r_rsip_p1a(const uint32_t InData_SharedKeyNum[],
                      const uint32_t InData_SharedKeyIndex[],
                      const uint32_t InData_SessionKey[],
                      const uint32_t InData_IV[],
                      const uint32_t InData_InstData[],
                      uint32_t       OutData_KeyIndex[]);
rsip_ret_t r_rsip_p59(const uint32_t InData_SharedKeyNum[],
                      const uint32_t InData_SharedKeyIndex[],
                      const uint32_t InData_SessionKey[],
                      const uint32_t InData_IV[],
                      const uint32_t InData_InstData[],
                      uint32_t       OutData_KeyIndex[]);
rsip_ret_t r_rsip_p60(const uint32_t InData_SharedKeyNum[],
                      const uint32_t InData_SharedKeyIndex[],
                      const uint32_t InData_SessionKey[],
                      const uint32_t InData_IV[],
                      const uint32_t InData_InstData[],
                      uint32_t       OutData_KeyIndex[]);
rsip_ret_t r_rsip_p62(const uint32_t InData_SharedKeyNum[],
                      const uint32_t InData_SharedKeyIndex[],
                      const uint32_t InData_SessionKey[],
                      const uint32_t InData_IV[],
                      const uint32_t InData_InstData[],
                      uint32_t       OutData_KeyIndex[]);
rsip_ret_t r_rsip_p63(const uint32_t InData_SharedKeyNum[],
                      const uint32_t InData_SharedKeyIndex[],
                      const uint32_t InData_SessionKey[],
                      const uint32_t InData_IV[],
                      const uint32_t InData_InstData[],
                      uint32_t       OutData_KeyIndex[]);
rsip_ret_t r_rsip_p37(const uint32_t InData_SharedKeyNum[],
                      const uint32_t InData_SharedKeyIndex[],
                      const uint32_t InData_SessionKey[],
                      const uint32_t InData_IV[],
                      const uint32_t InData_InstData[],
                      uint32_t       OutData_KeyIndex[]);
rsip_ret_t r_rsip_p42(const uint32_t InData_SharedKeyNum[],
                      const uint32_t InData_SharedKeyIndex[],
                      const uint32_t InData_SessionKey[],
                      const uint32_t InData_IV[],
                      const uint32_t InData_InstData[],
                      uint32_t       OutData_KeyIndex[]);
rsip_ret_t r_rsip_p43(const uint32_t InData_SharedKeyNum[],
                      const uint32_t InData_SharedKeyIndex[],
                      const uint32_t InData_SessionKey[],
                      const uint32_t InData_IV[],
                      const uint32_t InData_InstData[],
                      uint32_t       OutData_KeyIndex[]);
rsip_ret_t r_rsip_p45(const uint32_t InData_SharedKeyNum[],
                      const uint32_t InData_SharedKeyIndex[],
                      const uint32_t InData_SessionKey[],
                      const uint32_t InData_IV[],
                      const uint32_t InData_InstData[],
                      uint32_t       OutData_KeyIndex[]);
rsip_ret_t r_rsip_pfa(const uint32_t InData_SharedKeyNum[],
                      const uint32_t InData_SharedKeyIndex[],
                      const uint32_t InData_SessionKey[],
                      const uint32_t InData_CurveType[],
                      const uint32_t InData_Cmd[],
                      const uint32_t InData_IV[],
                      const uint32_t InData_InstData[],
                      uint32_t       OutData_KeyIndex[]);
rsip_ret_t r_rsip_pf3(const uint32_t InData_SharedKeyNum[],
                      const uint32_t InData_SharedKeyIndex[],
                      const uint32_t InData_SessionKey[],
                      const uint32_t InData_CurveType[],
                      const uint32_t InData_Cmd[],
                      const uint32_t InData_IV[],
                      const uint32_t InData_InstData[],
                      uint32_t       OutData_KeyIndex[]);
rsip_ret_t r_rsip_p80(const uint32_t InData_SharedKeyNum[],
                      const uint32_t InData_SharedKeyIndex[],
                      const uint32_t InData_SessionKey[],
                      const uint32_t InData_Cmd[],
                      const uint32_t InData_IV[],
                      const uint32_t InData_InstData[],
                      uint32_t       OutData_KeyIndex[]);
rsip_ret_t r_rsip_p1f(const uint32_t InData_SharedKeyNum[],
                      const uint32_t InData_SharedKeyIndex[],
                      const uint32_t InData_SessionKey[],
                      const uint32_t InData_IV[],
                      const uint32_t InData_InstData[],
                      uint32_t       OutData_KeyIndex[]);

/* Key import with KUK */
rsip_ret_t r_rsip_p19(const uint32_t InData_IV[], const uint32_t InData_InstData[], uint32_t OutData_KeyIndex[]);
rsip_ret_t r_rsip_p1c(const uint32_t InData_IV[], const uint32_t InData_InstData[], uint32_t OutData_KeyIndex[]);
rsip_ret_t r_rsip_p1b(const uint32_t InData_IV[], const uint32_t InData_InstData[], uint32_t OutData_KeyIndex[]);
rsip_ret_t r_rsip_p1d(const uint32_t InData_IV[], const uint32_t InData_InstData[], uint32_t OutData_KeyIndex[]);
rsip_ret_t r_rsip_p2c(uint32_t const InData_CurveType[],
                      uint32_t const InData_Cmd[],
                      uint32_t const InData_IV[],
                      uint32_t const InData_InstData[],
                      uint32_t       OutData_KeyIndex[]);
rsip_ret_t r_rsip_p1e(uint32_t const InData_CurveType[],
                      uint32_t const InData_Cmd[],
                      uint32_t const InData_IV[],
                      uint32_t const InData_InstData[],
                      uint32_t       OutData_KeyIndex[]);
rsip_ret_t r_rsip_p0b(uint32_t const InData_IV[], uint32_t const InData_InstData[], uint32_t OutData_KeyIndex[]);
rsip_ret_t r_rsip_p0c(uint32_t const InData_IV[], uint32_t const InData_InstData[], uint32_t OutData_KeyIndex[]);
rsip_ret_t r_rsip_p0d(uint32_t const InData_IV[], uint32_t const InData_InstData[], uint32_t OutData_KeyIndex[]);
rsip_ret_t r_rsip_p0e(uint32_t const InData_IV[], uint32_t const InData_InstData[], uint32_t OutData_KeyIndex[]);
rsip_ret_t r_rsip_p38(uint32_t const InData_IV[], uint32_t const InData_InstData[], uint32_t OutData_KeyIndex[]);
rsip_ret_t r_rsip_p9e(uint32_t const InData_IV[], uint32_t const InData_InstData[], uint32_t OutData_KeyIndex[]);
rsip_ret_t r_rsip_p9d(uint32_t const InData_IV[], uint32_t const InData_InstData[], uint32_t OutData_KeyIndex[]);
rsip_ret_t r_rsip_p9f(uint32_t const InData_IV[], uint32_t const InData_InstData[], uint32_t OutData_KeyIndex[]);
rsip_ret_t r_rsip_p0f(const uint32_t InData_Cmd[],
                      const uint32_t InData_IV[],
                      const uint32_t InData_InstData[],
                      uint32_t       OutData_KeyIndex[]);

/* RNG */
rsip_ret_t r_rsip_p20(uint32_t p_random[]);

/* AES-ECB/CBC/CTR */
rsip_ret_t r_rsip_p48i(const uint32_t InData_Cmd[], const uint32_t InData_KeyIndex[], const uint32_t InData_IV[]);
rsip_ret_t r_rsip_p50i(const uint32_t InData_Cmd[], const uint32_t InData_KeyIndex[], const uint32_t InData_IV[]);
void       r_rsip_p48u(const uint32_t InData_Text[], uint32_t OutData_Text[], uint32_t MAX_CNT);
void       r_rsip_p50u(const uint32_t InData_Text[], uint32_t OutData_Text[], uint32_t MAX_CNT);
rsip_ret_t r_rsip_p48f(void);
rsip_ret_t r_rsip_p50f(void);

/* AES-XTS */
rsip_ret_t r_rsip_pb3i(const uint32_t InData_KeyIndex[], const uint32_t InData_IV[]);
rsip_ret_t r_rsip_pb6i(const uint32_t InData_KeyIndex[], const uint32_t InData_IV[]);
rsip_ret_t r_rsip_pb9i(const uint32_t InData_KeyIndex[], const uint32_t InData_IV[]);
rsip_ret_t r_rsip_pc2i(const uint32_t InData_KeyIndex[], const uint32_t InData_IV[]);
void       r_rsip_pb3u(const uint32_t InData_Text[], uint32_t OutData_Text[], uint32_t MAX_CNT);
void       r_rsip_pb6u(const uint32_t InData_Text[], uint32_t OutData_Text[], uint32_t MAX_CNT);
void       r_rsip_pb9u(const uint32_t InData_Text[], uint32_t OutData_Text[], uint32_t MAX_CNT);
void       r_rsip_pc2u(const uint32_t InData_Text[], uint32_t OutData_Text[], uint32_t MAX_CNT);
rsip_ret_t r_rsip_pb3f(const uint32_t InData_TextBitLen[], const uint32_t InData_Text[], uint32_t OutData_Text[]);
rsip_ret_t r_rsip_pb6f(const uint32_t InData_TextBitLen[], const uint32_t InData_Text[], uint32_t OutData_Text[]);
rsip_ret_t r_rsip_pb9f(const uint32_t InData_TextBitLen[], const uint32_t InData_Text[], uint32_t OutData_Text[]);
rsip_ret_t r_rsip_pc2f(const uint32_t InData_TextBitLen[], const uint32_t InData_Text[], uint32_t OutData_Text[]);

/* AES-GCM */
rsip_ret_t r_rsip_p29i(const uint32_t InData_KeyIndex[], const uint32_t InData_IV[]);
rsip_ret_t r_rsip_p32i(const uint32_t InData_KeyIndex[], const uint32_t InData_IV[]);
rsip_ret_t r_rsip_p34i(const uint32_t InData_KeyIndex[], const uint32_t InData_IV[]);
rsip_ret_t r_rsip_p36i(const uint32_t InData_KeyIndex[], const uint32_t InData_IV[]);
void       r_rsip_p29t(void);
void       r_rsip_p32t(void);
void       r_rsip_p34t(void);
void       r_rsip_p36t(void);
void       r_rsip_p29a(const uint32_t InData_DataA[], uint32_t MAX_CNT);
void       r_rsip_p32a(const uint32_t InData_DataA[], uint32_t MAX_CNT);
void       r_rsip_p34a(const uint32_t InData_DataA[], uint32_t MAX_CNT);
void       r_rsip_p36a(const uint32_t InData_DataA[], uint32_t MAX_CNT);
void       r_rsip_p29u(const uint32_t InData_Text[], uint32_t OutData_Text[], uint32_t MAX_CNT);
void       r_rsip_p32u(const uint32_t InData_Text[], uint32_t OutData_Text[], uint32_t MAX_CNT);
void       r_rsip_p34u(const uint32_t InData_Text[], uint32_t OutData_Text[], uint32_t MAX_CNT);
void       r_rsip_p36u(const uint32_t InData_Text[], uint32_t OutData_Text[], uint32_t MAX_CNT);
rsip_ret_t r_rsip_p29f(const uint32_t InData_Text[],
                       const uint32_t InData_DataALen[],
                       const uint32_t InData_TextLen[],
                       uint32_t       OutData_Text[],
                       uint32_t       OutData_DataT[]);
rsip_ret_t r_rsip_p34f(const uint32_t InData_Text[],
                       const uint32_t InData_DataALen[],
                       const uint32_t InData_TextLen[],
                       uint32_t       OutData_Text[],
                       uint32_t       OutData_DataT[]);
rsip_ret_t r_rsip_p32f(const uint32_t InData_Text[],
                       const uint32_t InData_DataT[],
                       const uint32_t InData_DataALen[],
                       const uint32_t InData_TextLen[],
                       const uint32_t InData_DataTLen[],
                       uint32_t       OutData_Text[]);
rsip_ret_t r_rsip_p36f(const uint32_t InData_Text[],
                       const uint32_t InData_DataT[],
                       const uint32_t InData_DataALen[],
                       const uint32_t InData_TextLen[],
                       const uint32_t InData_DataTLen[],
                       uint32_t       OutData_Text[]);
rsip_ret_t r_rsip_p21(const uint32_t InData_HV[],
                      const uint32_t InData_IV[],
                      const uint32_t InData_Text[],
                      uint32_t       OutData_DataT[],
                      uint32_t       MAX_CNT);

/* AES-CMAC */
rsip_ret_t r_rsip_p41i(const uint32_t InData_KeyIndex[]);
rsip_ret_t r_rsip_p44i(const uint32_t InData_KeyIndex[]);
void       r_rsip_p41u(const uint32_t InData_Text[], uint32_t MAX_CNT);
void       r_rsip_p44u(const uint32_t InData_Text[], uint32_t MAX_CNT);
rsip_ret_t r_rsip_p41f(const uint32_t InData_Cmd[],
                       const uint32_t InData_Text[],
                       const uint32_t InData_DataT[],
                       const uint32_t InData_DataTLen[],
                       uint32_t       OutData_DataT[]);
rsip_ret_t r_rsip_p44f(const uint32_t InData_Cmd[],
                       const uint32_t InData_Text[],
                       const uint32_t InData_DataT[],
                       const uint32_t InData_DataTLen[],
                       uint32_t       OutData_DataT[]);

/* ECDSA */
rsip_ret_t r_rsip_pf0(const uint32_t InData_CurveType[],
                      const uint32_t InData_Cmd[],
                      const uint32_t InData_KeyIndex[],
                      const uint32_t InData_MsgDgst[],
                      uint32_t       OutData_Signature[]);
rsip_ret_t r_rsip_pf1(const uint32_t InData_CurveType[],
                      const uint32_t InData_Cmd[],
                      const uint32_t InData_KeyIndex[],
                      const uint32_t InData_MsgDgst[],
                      const uint32_t InData_Signature[]);

/* RSA */
rsip_ret_t r_rsip_p53(const uint32_t InData_KeyIndex[], const uint32_t InData_Text[], uint32_t OutData_Text[]);
rsip_ret_t r_rsip_p54(const uint32_t InData_KeyIndex[], const uint32_t InData_Text[], uint32_t OutData_Text[]);
rsip_ret_t r_rsip_p56(const uint32_t InData_KeyIndex[], const uint32_t InData_Text[], uint32_t OutData_Text[]);
rsip_ret_t r_rsip_p57(const uint32_t InData_KeyIndex[], const uint32_t InData_Text[], uint32_t OutData_Text[]);
rsip_ret_t r_rsip_p79(const uint32_t InData_KeyIndex[], const uint32_t InData_Text[], uint32_t OutData_Text[]);
rsip_ret_t r_rsip_p7a(const uint32_t InData_KeyIndex[], const uint32_t InData_Text[], uint32_t OutData_Text[]);
rsip_ret_t r_rsip_p7b(const uint32_t InData_KeyIndex[], const uint32_t InData_Text[], uint32_t OutData_Text[]);
rsip_ret_t r_rsip_p7c(const uint32_t InData_KeyIndex[], const uint32_t InData_Text[], uint32_t OutData_Text[]);

/* SHA */
rsip_ret_t r_rsip_p71(const uint32_t InData_HashType[],
                      const uint32_t InData_Msg[],
                      const uint32_t InData_MsgLen[],
                      uint32_t       MAX_CNT,
                      uint32_t       OutData_MsgDigest[]);
rsip_ret_t r_rsip_p72(const uint32_t InData_HashType[],
                      const uint32_t InData_Cmd[],
                      const uint32_t InData_Msg[],
                      const uint32_t InData_MsgLen[],
                      const uint32_t InData_State[],
                      uint32_t       MAX_CNT,
                      uint32_t       OutData_MsgDigest[],
                      uint32_t       OutData_State[]);

/* HMAC */
rsip_ret_t r_rsip_p73(const uint32_t InData_KeyIndex[],
                      const uint32_t InData_Cmd[],
                      const uint32_t InData_Msg[],
                      const uint32_t InData_MsgLen[],
                      const uint32_t InData_MAC[],
                      const uint32_t InData_length[],
                      const uint32_t InData_State[],
                      uint32_t       MAX_CNT,
                      uint32_t       OutData_MAC[],
                      uint32_t       OutData_State[]);
rsip_ret_t r_rsip_p76(const uint32_t InData_KeyIndex[],
                      const uint32_t InData_Cmd[],
                      const uint32_t InData_Msg[],
                      const uint32_t InData_MsgLen[],
                      const uint32_t InData_MAC[],
                      const uint32_t InData_length[],
                      const uint32_t InData_State[],
                      uint32_t       MAX_CNT,
                      uint32_t       OutData_MAC[],
                      uint32_t       OutData_State[]);
rsip_ret_t r_rsip_pdc(const uint32_t InData_KeyIndex[],
                      const uint32_t InData_Cmd[],
                      const uint32_t InData_Msg[],
                      const uint32_t InData_MsgLen[],
                      const uint32_t InData_MAC[],
                      const uint32_t InData_length[],
                      const uint32_t InData_State[],
                      uint32_t       MAX_CNT,
                      uint32_t       OutData_MAC[],
                      uint32_t       OutData_State[]);
rsip_ret_t r_rsip_p74(const uint32_t InData_KeyIndex[],
                      const uint32_t InData_Cmd[],
                      const uint32_t InData_Msg[],
                      const uint32_t InData_MsgLen[],
                      const uint32_t InData_MAC[],
                      const uint32_t InData_length[],
                      uint32_t       MAX_CNT,
                      uint32_t       OutData_MAC[]);
rsip_ret_t r_rsip_p77(const uint32_t InData_KeyIndex[],
                      const uint32_t InData_Cmd[],
                      const uint32_t InData_Msg[],
                      const uint32_t InData_MsgLen[],
                      const uint32_t InData_MAC[],
                      const uint32_t InData_length[],
                      uint32_t       MAX_CNT,
                      uint32_t       OutData_MAC[]);
rsip_ret_t r_rsip_pdd(const uint32_t InData_KeyIndex[],
                      const uint32_t InData_Cmd[],
                      const uint32_t InData_Msg[],
                      const uint32_t InData_MsgLen[],
                      const uint32_t InData_MAC[],
                      const uint32_t InData_length[],
                      uint32_t       MAX_CNT,
                      uint32_t       OutData_MAC[]);

/* Secure boot */
rsip_ret_t r_rsip_p03(const uint32_t InData_SharedKeyNum[],
                      const uint32_t InData_SharedKeyIndex[],
                      const uint32_t InData_SessionKey[],
                      const uint32_t InData_IV[],
                      const uint32_t InData_InstData[],
                      uint32_t       OutData_KeyIndex[]);
rsip_ret_t r_rsip_p15(const uint32_t InData_SharedKeyNum[],
                      const uint32_t InData_SharedKeyIndex[],
                      const uint32_t InData_SessionKey[],
                      const uint32_t InData_IV[],
                      const uint32_t InData_EncAuthData[],
                      const uint32_t InData_HashType[],
                      uint32_t       OutData_Hash[]);
rsip_ret_t r_rsip_p24(const uint32_t InData_Cmd[],
                      const uint32_t InData_KeyCertificate[],
                      const uint32_t InData_KeyCertificateLength[],
                      const uint32_t InData_KeyCertificateSignature[],
                      const uint32_t InData_KeyCertificatePubKey[],
                      const uint32_t InData_ImgPkHash[],
                      const uint32_t InData_OemRootPkHash[],
                      const uint32_t InData_CodeCertificate[],
                      const uint32_t InData_CodeCertificateLength[],
                      const uint32_t InData_CodeCertificateSignature[],
                      const uint32_t InData_CodeCertificatePubKey[],
                      const uint32_t InData_ImageHash[],
                      const uint32_t InData_Image[],
                      uint32_t       MAX_CNT);

rsip_ret_t r_rsip_p47i(const uint32_t InData_Cmd[], const uint32_t InData_KeyIndex[], const uint32_t InData_IV[]);
void       r_rsip_p47u(const uint32_t InData_Text[], uint32_t OutData_Text[], const uint32_t MAX_CNT);
rsip_ret_t r_rsip_p47f(void);

#endif                                 /* R_RSIP_PRIMITIVE_H */
