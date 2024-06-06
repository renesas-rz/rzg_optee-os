/**********************************************************************************************************************
 * DISCLAIMER
 * This software is supplied by Renesas Electronics Corporation and is only intended for use with Renesas products. No
 * other uses are authorized. This software is owned by Renesas Electronics Corporation and is protected under all
 * applicable laws, including copyright laws.
 * THIS SOFTWARE IS PROVIDED "AS IS" AND RENESAS MAKES NO WARRANTIES REGARDING
 * THIS SOFTWARE, WHETHER EXPRESS, IMPLIED OR STATUTORY, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. ALL SUCH WARRANTIES ARE EXPRESSLY DISCLAIMED. TO THE MAXIMUM
 * EXTENT PERMITTED NOT PROHIBITED BY LAW, NEITHER RENESAS ELECTRONICS CORPORATION NOR ANY OF ITS AFFILIATED COMPANIES
 * SHALL BE LIABLE FOR ANY DIRECT, INDIRECT, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES FOR ANY REASON RELATED TO
 * THIS SOFTWARE, EVEN IF RENESAS OR ITS AFFILIATES HAVE BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
 * Renesas reserves the right, without notice, to make changes to this software and to discontinue the availability of
 * this software. By using this software, you agree to the additional terms and conditions found by accessing the
 * following link:
 * http://www.renesas.com/disclaimer
 *
 * Copyright (C) 2022 Renesas Electronics Corporation. All rights reserved.
 *********************************************************************************************************************/
/**********************************************************************************************************************
 * File Name    : r_sce_private.h
 * Version      : 1.0
 * Description  : SCE Private API header file
 *********************************************************************************************************************/
/**********************************************************************************************************************
 * History : DD.MM.YYYY Version  Description
 *         : 03.31.2022 1.00     First Release
 *********************************************************************************************************************/
/***********************************************************************************************************************
 * Includes
 **********************************************************************************************************************/
#include "r_sce.h"

#ifndef R_SCE_PRIVATE_HEADER_FILE
#define R_SCE_PRIVATE_HEADER_FILE

/***********************************************************************************************************************
 * Macro definitions
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Typedef definitions
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Private function prototypes
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Private global variables
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Global variables
 **********************************************************************************************************************/
extern uint32_t const S_FLASH2[];
extern uint32_t S_RAM[HW_SCE_SRAM_WORD_SIZE];
extern uint32_t S_HEAP[HW_SCE_SHEAP_WORD_SIZE];
extern uint32_t S_INST2[HW_SCE_SINST2_WORD_SIZE];

/***********************************************************************************************************************
 * Functions
 **********************************************************************************************************************/

/* --------------------- SCE driver wrapper layer ---------------------- */

fsp_err_t R_SCE_SelfCheck1Private(void);
fsp_err_t R_SCE_SelfCheck2Private(void);
fsp_err_t R_SCE_SelfCheck3Private(void);
fsp_err_t R_SCE_LoadHukPrivate(lifecycle_t lifecycle);
fsp_err_t R_SCE_FwIntegrityCheckPrivate(void);

fsp_err_t R_SCE_UpdateOemKeyIndexPrivate(lifecycle_t   lifecycle,
        sce_oem_cmd_t key_type,
        uint8_t     * iv,
        uint8_t     * encrypted_oem_key,
        uint32_t    * key_index);

fsp_err_t R_SCE_Aes128EcbEncryptInitPrivate(sce_aes_wrapped_key_t * InData_KeyIndex);
fsp_err_t R_SCE_Aes128EcbEncryptUpdatePrivate(uint32_t * InData_Text, uint32_t * OutData_Text, uint32_t MAX_CNT);
fsp_err_t R_SCE_Aes128EcbEncryptFinalPrivate(uint32_t * OutData_Text, uint32_t * OutData_length);
fsp_err_t R_SCE_Aes128EcbDecryptInitPrivate(sce_aes_wrapped_key_t * InData_KeyIndex);
fsp_err_t R_SCE_Aes128EcbDecryptUpdatePrivate(uint32_t * InData_Text, uint32_t * OutData_Text, uint32_t MAX_CNT);
fsp_err_t R_SCE_Aes128EcbDecryptFinalPrivate(uint32_t * OutData_Text, uint32_t * OutData_length);
fsp_err_t R_SCE_Aes128CbcEncryptInitPrivate(sce_aes_wrapped_key_t * InData_KeyIndex, uint32_t * InData_IV);
fsp_err_t R_SCE_Aes128CbcEncryptUpdatePrivate(uint32_t * InData_Text, uint32_t * OutData_Text, uint32_t MAX_CNT);
fsp_err_t R_SCE_Aes128CbcEncryptFinalPrivate(uint32_t * OutData_Text, uint32_t * OutData_length);
fsp_err_t R_SCE_Aes128CbcDecryptInitPrivate(sce_aes_wrapped_key_t * InData_KeyIndex, uint32_t * InData_IV);
fsp_err_t R_SCE_Aes128CbcDecryptUpdatePrivate(uint32_t * InData_Text, uint32_t * OutData_Text, uint32_t MAX_CNT);
fsp_err_t R_SCE_Aes128CbcDecryptFinalPrivate(uint32_t * OutData_Text, uint32_t * OutData_length);
fsp_err_t R_SCE_Aes128CtrEncryptInitPrivate(sce_aes_wrapped_key_t * InData_KeyIndex, uint32_t * InData_IV);
fsp_err_t R_SCE_Aes128CtrEncryptUpdatePrivate(uint32_t * InData_Text, uint32_t * OutData_Text, uint32_t MAX_CNT);
fsp_err_t R_SCE_Aes128CtrEncryptFinalPrivate(uint32_t * OutData_Text, uint32_t * OutData_length);
fsp_err_t R_SCE_Aes128CtrDecryptInitPrivate(sce_aes_wrapped_key_t * InData_KeyIndex, uint32_t * InData_IV);
fsp_err_t R_SCE_Aes128CtrDecryptUpdatePrivate(uint32_t * InData_Text, uint32_t * OutData_Text, uint32_t MAX_CNT);
fsp_err_t R_SCE_Aes128CtrDecryptFinalPrivate(uint32_t * OutData_Text, uint32_t * OutData_length);

fsp_err_t R_SCE_Aes256EcbEncryptInitPrivate(sce_aes_wrapped_key_t * InData_KeyIndex);
fsp_err_t R_SCE_Aes256EcbEncryptUpdatePrivate(uint32_t * InData_Text, uint32_t * OutData_Text, uint32_t MAX_CNT);
fsp_err_t R_SCE_Aes256EcbEncryptFinalPrivate(uint32_t * OutData_Text, uint32_t * OutData_length);
fsp_err_t R_SCE_Aes256EcbDecryptInitPrivate(sce_aes_wrapped_key_t * InData_KeyIndex);
fsp_err_t R_SCE_Aes256EcbDecryptUpdatePrivate(uint32_t * InData_Text, uint32_t * OutData_Text, uint32_t MAX_CNT);
fsp_err_t R_SCE_Aes256EcbDecryptFinalPrivate(uint32_t * OutData_Text, uint32_t * OutData_length);
fsp_err_t R_SCE_Aes256CbcEncryptInitPrivate(sce_aes_wrapped_key_t * InData_KeyIndex, uint32_t * InData_IV);
fsp_err_t R_SCE_Aes256CbcEncryptUpdatePrivate(uint32_t * InData_Text, uint32_t * OutData_Text, uint32_t MAX_CNT);
fsp_err_t R_SCE_Aes256CbcEncryptFinalPrivate(uint32_t * OutData_Text, uint32_t * OutData_length);
fsp_err_t R_SCE_Aes256CbcDecryptInitPrivate(sce_aes_wrapped_key_t * InData_KeyIndex, uint32_t * InData_IV);
fsp_err_t R_SCE_Aes256CbcDecryptUpdatePrivate(uint32_t * InData_Text, uint32_t * OutData_Text, uint32_t MAX_CNT);
fsp_err_t R_SCE_Aes256CbcDecryptFinalPrivate(uint32_t * OutData_Text, uint32_t * OutData_length);
fsp_err_t R_SCE_Aes256CtrEncryptInitPrivate(sce_aes_wrapped_key_t * InData_KeyIndex, uint32_t * InData_IV);
fsp_err_t R_SCE_Aes256CtrEncryptUpdatePrivate(uint32_t * InData_Text, uint32_t * OutData_Text, uint32_t MAX_CNT);
fsp_err_t R_SCE_Aes256CtrEncryptFinalPrivate(uint32_t * OutData_Text, uint32_t * OutData_length);
fsp_err_t R_SCE_Aes256CtrDecryptInitPrivate(sce_aes_wrapped_key_t * InData_KeyIndex, uint32_t * InData_IV);
fsp_err_t R_SCE_Aes256CtrDecryptUpdatePrivate(uint32_t * InData_Text, uint32_t * OutData_Text, uint32_t MAX_CNT);
fsp_err_t R_SCE_Aes256CtrDecryptFinalPrivate(uint32_t * OutData_Text, uint32_t * OutData_length);

fsp_err_t R_SCE_Aes128CmacGenerateInitPrivate(sce_aes_wrapped_key_t * InData_KeyIndex);
fsp_err_t R_SCE_Aes128CmacGenerateUpdatePrivate(uint32_t * InData_Text, uint32_t MAX_CNT);
fsp_err_t R_SCE_Aes128CmacGenerateFinalPrivate(uint32_t All_Msg_Len, uint32_t * InData_Text, uint32_t * OutData_DataT);
fsp_err_t R_SCE_Aes128CmacVerifyInitPrivate(sce_aes_wrapped_key_t * InData_KeyIndex);
fsp_err_t R_SCE_Aes128CmacVerifyUpdatePrivate(uint32_t * InData_Text, uint32_t MAX_CNT);
fsp_err_t R_SCE_Aes128CmacVerifyFinalPrivate(uint32_t   All_Msg_Len,
        uint32_t * InData_Text,
        uint32_t * InData_DataT,
        uint32_t * InData_DataTLen);

fsp_err_t R_SCE_Aes256CmacGenerateInitPrivate(sce_aes_wrapped_key_t * InData_KeyIndex);
fsp_err_t R_SCE_Aes256CmacGenerateUpdatePrivate(uint32_t * InData_Text, uint32_t MAX_CNT);
fsp_err_t R_SCE_Aes256CmacGenerateFinalPrivate(uint32_t All_Msg_Len, uint32_t * InData_Text, uint32_t * OutData_DataT);
fsp_err_t R_SCE_Aes256CmacVerifyInitPrivate(sce_aes_wrapped_key_t * InData_KeyIndex);
fsp_err_t R_SCE_Aes256CmacVerifyUpdatePrivate(uint32_t * InData_Text, uint32_t MAX_CNT);
fsp_err_t R_SCE_Aes256CmacVerifyFinalPrivate(uint32_t   All_Msg_Len,
        uint32_t * InData_Text,
        uint32_t * InData_DataT,
        uint32_t * InData_DataTLen);

fsp_err_t R_SCE_Sha224InitPrivate(sce_sha_md5_handle_t * handle);
fsp_err_t R_SCE_Sha224UpdatePrivate(sce_sha_md5_handle_t * handle, uint32_t * InData_PaddedMsg, uint32_t MAX_CNT);
fsp_err_t R_SCE_Sha224FinalPrivate(sce_sha_md5_handle_t * handle,
        uint32_t             * InData_PaddedMsg,
        uint32_t               MAX_CNT,
        uint32_t             * OutData_MsgDigest,
        uint32_t             * OutData_Length);
fsp_err_t R_SCE_Sha256InitPrivate(sce_sha_md5_handle_t * handle);
fsp_err_t R_SCE_Sha256UpdatePrivate(sce_sha_md5_handle_t * handle, uint32_t * InData_PaddedMsg, uint32_t MAX_CNT);
fsp_err_t R_SCE_Sha256FinalPrivate(sce_sha_md5_handle_t * handle,
        uint32_t             * InData_PaddedMsg,
        uint32_t               MAX_CNT,
        uint32_t             * OutData_MsgDigest,
        uint32_t             * OutData_Length);

fsp_err_t R_SCE_Rsa1024ModularExponentEncryptPrivate(uint32_t * InData_KeyIndex,
        uint32_t * InData_Text,
        uint32_t * OutData_Text);
fsp_err_t R_SCE_Rsa1024ModularExponentDecryptPrivate(uint32_t * InData_KeyIndex,
        uint32_t * InData_Text,
        uint32_t * OutData_Text);
fsp_err_t R_SCE_Rsa2048ModularExponentEncryptPrivate(uint32_t * InData_KeyIndex,
        uint32_t * InData_Text,
        uint32_t * OutData_Text);
fsp_err_t R_SCE_Rsa2048ModularExponentDecryptPrivate(uint32_t * InData_KeyIndex,
        uint32_t * InData_Text,
        uint32_t * OutData_Text);
fsp_err_t R_SCE_Rsa4096ModularExponentEncryptPrivate(uint32_t * InData_KeyIndex,
        uint32_t * InData_Text,
        uint32_t * OutData_Text);

/* --------------------- SCE control procedure related ---------------------- */

void R_SCE_SoftwareResetSub(void);

/** @retval FSP_SUCCESS @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT @retval FSP_ERR_CRYPTO_SCE_RETRY **/
fsp_err_t R_SCE_SelfCheck2Sub(void);

/** @retval FSP_SUCCESS @retval FSP_ERR_CRYPTO_SCE_FAIL **/
fsp_err_t R_SCE_StateCheckSub(uint32_t *fsm2_number);

/** @retval FSP_SUCCESS @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT @retval FSP_ERR_CRYPTO_SCE_FAIL **/
fsp_err_t R_SCE_AES128_EncryptedKeyWrapSub(uint32_t *InData_IV,
        uint32_t *InData_InstData,
        uint32_t *OutData_KeyIndex);

/** @retval FSP_SUCCESS @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT @retval FSP_ERR_CRYPTO_SCE_FAIL **/
fsp_err_t R_SCE_AES256_EncryptedKeyWrapSub(uint32_t *InData_IV,
        uint32_t *InData_InstData,
        uint32_t *OutData_KeyIndex);

/** @retval FSP_SUCCESS @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT @retval FSP_ERR_CRYPTO_SCE_FAIL **/
fsp_err_t R_SCE_RSA1024_EncryptedPublicKeyWrapSub(uint32_t *InData_IV,
        uint32_t *InData_InstData,
        uint32_t *OutData_KeyIndex);

/** @retval FSP_SUCCESS @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT @retval FSP_ERR_CRYPTO_SCE_FAIL **/
fsp_err_t R_SCE_RSA1024_EncryptedPrivateKeyWrapSub(uint32_t *InData_IV,
        uint32_t *InData_InstData,
        uint32_t *OutData_KeyIndex);

/** @retval FSP_SUCCESS @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT @retval FSP_ERR_CRYPTO_SCE_FAIL **/
fsp_err_t R_SCE_RSA2048_EncryptedPublicKeyWrapSub(uint32_t *InData_IV,
        uint32_t *InData_InstData,
        uint32_t *OutData_KeyIndex);

/** @retval FSP_SUCCESS @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT @retval FSP_ERR_CRYPTO_SCE_FAIL **/
fsp_err_t R_SCE_RSA2048_EncryptedPrivateKeyWrapSub(uint32_t *InData_IV,
        uint32_t *InData_InstData,
        uint32_t *OutData_KeyIndex);

/** @retval FSP_SUCCESS @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT @retval FSP_ERR_CRYPTO_SCE_FAIL **/
fsp_err_t R_SCE_ECC192224256_EncryptedPublicKeyWrapSub(uint32_t *InData_CurveType,
        uint32_t *InData_Cmd,
        uint32_t *InData_IV,
        uint32_t *InData_InstData,
        uint32_t *OutData_KeyIndex);

/** @retval FSP_SUCCESS @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT @retval FSP_ERR_CRYPTO_SCE_FAIL **/
fsp_err_t R_SCE_ECC192224256_EncryptedPrivateKeyWrapSub(uint32_t *InData_CurveType,
        uint32_t *InData_Cmd,
        uint32_t *InData_IV,
        uint32_t *InData_InstData,
        uint32_t *OutData_KeyIndex);

/** @retval FSP_SUCCESS @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT @retval FSP_ERR_CRYPTO_SCE_FAIL **/
fsp_err_t R_SCE_RSA4096_EncryptedPublicKeyWrapSub(uint32_t *InData_IV,
        uint32_t *InData_InstData,
        uint32_t *OutData_KeyIndex);

/** @retval FSP_SUCCESS @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT @retval FSP_ERR_CRYPTO_SCE_FAIL **/
fsp_err_t R_SCE_ECC_BrainpoolP512r1_EncryptedPublicKeyWrapSub(uint32_t *InData_IV,
        uint32_t *InData_InstData,
        uint32_t *OutData_KeyIndex);

/** @retval FSP_SUCCESS @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT @retval FSP_ERR_CRYPTO_SCE_FAIL **/
fsp_err_t R_SCE_ECC_BrainpoolP512r1_EncryptedPrivateKeyWrapSub(uint32_t *InData_IV,
        uint32_t *InData_InstData,
        uint32_t *OutData_KeyIndex);

/** @retval FSP_SUCCESS @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT **/
fsp_err_t R_SCE_GenerateAes128RandomKeyIndexSub(uint32_t * OutData_KeyIndex);

/** @retval FSP_SUCCESS @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT **/
fsp_err_t R_SCE_GenerateAes256RandomKeyIndexSub(uint32_t * OutData_KeyIndex);

/** @retval FSP_SUCCESS @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT @retval FSP_ERR_CRYPTO_SCE_FAIL **/
fsp_err_t R_SCE_GenerateRsa1024RandomKeyIndexSub(uint32_t   MAX_CNT,
        uint32_t * OutData_PubKeyIndex,
        uint32_t * OutData_PrivKeyIndex);

/** @retval FSP_SUCCESS @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT @retval FSP_ERR_CRYPTO_SCE_FAIL **/
fsp_err_t R_SCE_GenerateRsa2048RandomKeyIndexSub(uint32_t   MAX_CNT,
        uint32_t * OutData_PubKeyIndex,
        uint32_t * OutData_PrivKeyIndex);

/** @retval FSP_SUCCESS @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT @retval FSP_ERR_CRYPTO_SCE_FAIL **/
fsp_err_t R_SCE_GenerateEccRandomKeyIndexSub(uint32_t * InData_CurveType,
        uint32_t * InData_Cmd,
        uint32_t * OutData_PubKeyIndex,
        uint32_t * OutData_PrivKeyIndex);

/** @retval FSP_SUCCESS @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT @retval FSP_ERR_CRYPTO_SCE_FAIL **/
fsp_err_t R_SCE_GenerateEccP512RandomKeyIndexSub (uint32_t *OutData_PubKeyIndex,
        uint32_t *OutData_PrivKeyIndex);

/** @retval FSP_SUCCESS @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT **/
fsp_err_t R_SCE_GenerateRandomNumberSub(uint32_t * OutData_Text);

/** @retval FSP_SUCCESS @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL
 * @retval FSP_ERR_CRYPTO_SCE_FAIL **/
fsp_err_t R_SCE_Aes128EncryptDecryptInitSub(const uint32_t * InData_Cmd,
        const uint32_t * InData_KeyIndex,
        const uint32_t * InData_IV);
void R_SCE_Aes128EncryptDecryptUpdateSub(const uint32_t * InData_Text,
        uint32_t       * OutData_Text,
        const uint32_t   MAX_CNT);

/** @retval FSP_SUCCESS @retval FSP_ERR_CRYPTO_SCE_FAIL **/
fsp_err_t R_SCE_Aes128EncryptDecryptFinalSub(void);


/** @retval FSP_SUCCESS @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL
 * @retval FSP_ERR_CRYPTO_SCE_FAIL **/
fsp_err_t R_SCE_Aes256EncryptDecryptInitSub(const uint32_t * InData_Cmd,
        const uint32_t * InData_KeyIndex,
        const uint32_t * InData_IV);
void R_SCE_Aes256EncryptDecryptUpdateSub(const uint32_t * InData_Text,
        uint32_t       * OutData_Text,
        const uint32_t   MAX_CNT);

/** @retval FSP_SUCCESS @retval FSP_ERR_CRYPTO_SCE_FAIL **/
fsp_err_t R_SCE_Aes256EncryptDecryptFinalSub(void);

/** @retval FSP_SUCCESS @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL
 * @retval FSP_ERR_CRYPTO_SCE_FAIL **/
fsp_err_t R_SCE_Aes128CmacInitSub(uint32_t * InData_KeyIndex);
void      R_SCE_Aes128CmacUpdateSub(uint32_t * InData_Text, uint32_t MAX_CNT);

/** @retval FSP_SUCCESS @retval FSP_ERR_CRYPTO_SCE_FAIL @retval FSP_ERR_CRYPTO_SCE_AUTHENTICATION **/
fsp_err_t R_SCE_Aes128CmacFinalSub(uint32_t * InData_Cmd,
        uint32_t * InData_Text,
        uint32_t * InData_DataT,
        uint32_t * InData_DataTLen,
        uint32_t * OutData_DataT);

/** @retval FSP_SUCCESS @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL
 * @retval FSP_ERR_CRYPTO_SCE_FAIL **/
fsp_err_t R_SCE_Aes256CmacInitSub(uint32_t * InData_KeyIndex);
void      R_SCE_Aes256CmacUpdateSub(uint32_t * InData_Text, uint32_t MAX_CNT);

/** @retval FSP_SUCCESS @retval FSP_ERR_CRYPTO_SCE_FAIL @retval FSP_ERR_CRYPTO_SCE_AUTHENTICATION **/
fsp_err_t R_SCE_Aes256CmacFinalSub(uint32_t * InData_Cmd,
        uint32_t * InData_Text,
        uint32_t * InData_DataT,
        uint32_t * InData_DataTLen,
        uint32_t * OutData_DataT);

/** @retval FSP_SUCCESS @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT **/
fsp_err_t R_SCE_Sha224256GenerateMessageDigestSub(const uint32_t * InData_InitVal,
        const uint32_t * InData_PaddedMsg,
        const uint32_t   MAX_CNT,
        uint32_t       * OutData_MsgDigest);

/** @retval FSP_SUCCESS @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL **/
fsp_err_t R_SCE_Rsa1024ModularExponentEncryptSub(const uint32_t * InData_KeyIndex,
        const uint32_t * InData_Text,
        uint32_t       * OutData_Text);

/** @retval FSP_SUCCESS @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL **/
fsp_err_t R_SCE_Rsa1024ModularExponentDecryptSub(uint32_t       * InData_KeyIndex,
        const uint32_t * InData_Text,
        uint32_t       * OutData_Text);

/** @retval FSP_SUCCESS @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL **/
fsp_err_t R_SCE_Rsa2048ModularExponentEncryptSub(const uint32_t * InData_KeyIndex,
        const uint32_t * InData_Text,
        uint32_t       * OutData_Text);

/** @retval FSP_SUCCESS @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL **/
fsp_err_t R_SCE_Rsa2048ModularExponentDecryptSub(uint32_t       * InData_KeyIndex,
        const uint32_t * InData_Text,
        uint32_t       * OutData_Text);

/** @retval FSP_SUCCESS @retval FSP_ERR_CRYPTO_SCE_FAIL @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL **/
fsp_err_t R_SCE_Rsa4096ModularExponentEncryptSub(const uint32_t * InData_KeyIndex,
        uint32_t       * InData_Text,
        uint32_t       * OutData_Text);

/** @retval FSP_SUCCESS @retval FSP_ERR_CRYPTO_SCE_FAIL @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL **/
fsp_err_t R_SCE_EcdsaSignatureGenerateSub(uint32_t * InData_CurveType,
        uint32_t * InData_Cmd,
        uint32_t * InData_KeyIndex,
        uint32_t * InData_MsgDgst,
        uint32_t * OutData_Signature);

/** @retval FSP_SUCCESS @retval FSP_ERR_CRYPTO_SCE_FAIL @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL **/
fsp_err_t R_SCE_EcdsaSignatureVerificationSub(uint32_t * InData_CurveType,
        uint32_t * InData_Cmd,
        uint32_t * InData_KeyIndex,
        uint32_t * InData_MsgDgst,
        uint32_t * InData_Signature);

/** @retval FSP_SUCCESS @retval FSP_ERR_CRYPTO_SCE_FAIL @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL **/
fsp_err_t R_SCE_EcdsaP512SignatureVerificationSub (uint32_t *InData_KeyIndex,
        uint32_t *InData_MsgDgst,
        uint32_t *InData_Signature);

/** @retval FSP_SUCCESS @retval FSP_ERR_CRYPTO_SCE_FAIL @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL **/
fsp_err_t R_SCE_EcdsaP512SignatureGenerateSub (uint32_t *InData_KeyIndex,
        uint32_t *InData_MsgDgst,
        uint32_t *OutData_Signature);

uint32_t change_endian_long (volatile uint32_t value);

#endif                                 /* R_SCE_PRIVATE_HEADER_FILE */
