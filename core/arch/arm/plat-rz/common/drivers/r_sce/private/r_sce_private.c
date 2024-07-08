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
 * File Name    : r_sce_private.c
 * Version      : 1.0
 * Description  : SCE Private API source file
 *********************************************************************************************************************/
/**********************************************************************************************************************
 * History : DD.MM.YYYY Version  Description
 *         : 03.31.2022 1.00     First Release
 *********************************************************************************************************************/

/***********************************************************************************************************************
 * Includes
 **********************************************************************************************************************/
#include <string.h>
#include "r_sce_private.h"

/***********************************************************************************************************************
 * Macro definitions
 **********************************************************************************************************************/
#ifndef SCE_HEX_6A09E667
#define SCE_HEX_6A09E667    (0x6a09e667UL)
#endif
#ifndef SCE_HEX_BB67AE85
#define SCE_HEX_BB67AE85    (0xbb67ae85UL)
#endif
#ifndef SCE_HEX_3C6EF372
#define SCE_HEX_3C6EF372    (0x3c6ef372UL)
#endif
#ifndef SCE_HEX_A54FF53A
#define SCE_HEX_A54FF53A    (0xa54ff53aUL)
#endif
#ifndef SCE_HEX_510E527F
#define SCE_HEX_510E527F    (0x510e527fUL)
#endif
#ifndef SCE_HEX_9B05688C
#define SCE_HEX_9B05688C    (0x9b05688cUL)
#endif
#ifndef SCE_HEX_1F83D9AB
#define SCE_HEX_1F83D9AB    (0x1f83d9abUL)
#endif
#ifndef SCE_HEX_5BE0CD19
#define SCE_HEX_5BE0CD19    (0x5be0cd19UL)
#endif
#ifndef SCE_HEX_C1059ED8
#define SCE_HEX_C1059ED8    (0xc1059ed8UL)
#endif
#ifndef SCE_HEX_367CD507
#define SCE_HEX_367CD507    (0x367cd507UL)
#endif
#ifndef SCE_HEX_3070DD17
#define SCE_HEX_3070DD17    (0x3070dd17UL)
#endif
#ifndef SCE_HEX_F70E5939
#define SCE_HEX_F70E5939    (0xf70e5939UL)
#endif
#ifndef SCE_HEX_FFC00B31
#define SCE_HEX_FFC00B31    (0xffc00b31UL)
#endif
#ifndef SCE_HEX_68581511
#define SCE_HEX_68581511    (0x68581511UL)
#endif
#ifndef SCE_HEX_64F98FA7
#define SCE_HEX_64F98FA7    (0x64f98fa7UL)
#endif
#ifndef SCE_HEX_BEFA4FA4
#define SCE_HEX_BEFA4FA4    (0xbefa4fa4UL)
#endif

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

/***********************************************************************************************************************
 * Functions
 **********************************************************************************************************************/

/*******************************************************************************************************************//**
 * Encrypt data to cipher using AES ECB mode algorithm with AES 128 key.
 *
 * @param InData_KeyIndex User key generation information area.
 *
 * @retval FSP_SUCCESS                          Normal termination.
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL      Input illegal user Key Generation Information
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT resource conflict
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              Internal error occurred.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes128EcbEncryptInitPrivate (sce_aes_wrapped_key_t * InData_KeyIndex)
{
    uint32_t indata_cmd   = 0;
    uint32_t indata_iv[4] =            /* dummy */
    {
            0
    };

    if (SCE_KEY_INDEX_TYPE_AES128 != InData_KeyIndex->type)
    {
        return FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL;
    }
    indata_cmd = change_endian_long(0); /* ECB-Encrypt command */

    return R_SCE_Aes128EncryptDecryptInitSub(&indata_cmd, InData_KeyIndex->value, indata_iv);
}

/*******************************************************************************************************************//**
 * Encrypt data to cipher using AES ECB mode algorithm with AES 128 key.
 *
 * @param InData_Text  Input plain text.
 * @param OutData_Text Output cipher text.
 * @param MAX_CNT      Input byte size of plain.
 *
 * @retval FSP_SUCCESS Normal termination.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes128EcbEncryptUpdatePrivate (uint32_t * InData_Text, uint32_t * OutData_Text, uint32_t MAX_CNT)
{
    R_SCE_Aes128EncryptDecryptUpdateSub(InData_Text, OutData_Text, MAX_CNT);

    return FSP_SUCCESS;
}

/*******************************************************************************************************************//**
 * Encrypt data to cipher using AES ECB mode algorithm with AES 128 key.
 *
 * @param OutData_Text   Output cipher text.
 * @param OutData_length Output byte size of cipher.
 *
 * @retval FSP_SUCCESS             Normal termination.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL Internal error occurred.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes128EcbEncryptFinalPrivate (uint32_t * OutData_Text, uint32_t * OutData_length)
{
    FSP_PARAMETER_NOT_USED(OutData_Text);
    FSP_PARAMETER_NOT_USED(OutData_length);

    return R_SCE_Aes128EncryptDecryptFinalSub();
}

/*******************************************************************************************************************//**
 * Decrypt data to plain using AES ECB mode algorithm with AES 128 key.
 *
 * @param InData_KeyIndex User key generation information area.
 *
 * @retval FSP_SUCCESS                          Normal termination.
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL      Input illegal user Key Generation Information
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT resource conflict
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              Internal error occurred.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes128EcbDecryptInitPrivate (sce_aes_wrapped_key_t * InData_KeyIndex)
{
    uint32_t indata_cmd   = 0;
    uint32_t indata_iv[4] =            /* dummy */
    {
            0
    };

    if (SCE_KEY_INDEX_TYPE_AES128 != InData_KeyIndex->type)
    {
        return FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL;
    }
    indata_cmd = change_endian_long(1); /* ECB-Decrypt command */

    return R_SCE_Aes128EncryptDecryptInitSub(&indata_cmd, InData_KeyIndex->value, indata_iv);
}

/*******************************************************************************************************************//**
 * Decrypt data to plain using AES ECB mode algorithm with AES 128 key.
 *
 * @param InData_Text  Input cipher text.
 * @param OutData_Text Output plain text.
 * @param MAX_CNT      Input byte size of cipher.
 *
 * @retval FSP_SUCCESS Normal termination.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes128EcbDecryptUpdatePrivate (uint32_t * InData_Text, uint32_t * OutData_Text, uint32_t MAX_CNT)
{
    R_SCE_Aes128EncryptDecryptUpdateSub(InData_Text, OutData_Text, MAX_CNT);

    return FSP_SUCCESS;
}

/*******************************************************************************************************************//**
 * Decrypt data to plain using AES ECB mode algorithm with AES 128 key.
 *
 * @param OutData_Text   Output plain text.
 * @param OutData_length Output byte size of plain.
 *
 * @retval FSP_SUCCESS             Normal termination.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL Internal error occurred.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes128EcbDecryptFinalPrivate (uint32_t * OutData_Text, uint32_t * OutData_length)
{
    FSP_PARAMETER_NOT_USED(OutData_Text);
    FSP_PARAMETER_NOT_USED(OutData_length);

    return R_SCE_Aes128EncryptDecryptFinalSub();
}

/*******************************************************************************************************************//**
 * Encrypt data to cipher using AES ECB mode algorithm with AES 256 key.
 *
 * @param InData_KeyIndex User key generation information area.
 *
 * @retval FSP_SUCCESS                          Normal termination.
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL      Input illegal user Key Generation Information
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT resource conflict
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              Internal error occurred.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes256EcbEncryptInitPrivate (sce_aes_wrapped_key_t * InData_KeyIndex)
{
    uint32_t indata_cmd   = 0;
    uint32_t indata_iv[4] =            /* dummy */
    {
            0
    };

    if (SCE_KEY_INDEX_TYPE_AES256 != InData_KeyIndex->type)
    {
        return FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL;
    }
    indata_cmd = change_endian_long(0); /* ECB-Encrypt command */

    return R_SCE_Aes256EncryptDecryptInitSub(&indata_cmd, InData_KeyIndex->value, indata_iv);
}

/*******************************************************************************************************************//**
 * Encrypt data to cipher using AES ECB mode algorithm with AES 256 key.
 *
 * @param InData_Text  Input plain text.
 * @param OutData_Text Output cipher text.
 * @param MAX_CNT      Input byte size of plain.
 *
 * @retval FSP_SUCCESS Normal termination.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes256EcbEncryptUpdatePrivate (uint32_t * InData_Text, uint32_t * OutData_Text, uint32_t MAX_CNT)
{
    R_SCE_Aes256EncryptDecryptUpdateSub(InData_Text, OutData_Text, MAX_CNT);

    return FSP_SUCCESS;
}

/*******************************************************************************************************************//**
 * Encrypt data to cipher using AES ECB mode algorithm with AES 256 key.
 *
 * @param OutData_Text   Output cipher text.
 * @param OutData_length Output byte size of cipher.
 *
 * @retval FSP_SUCCESS             Normal termination.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL Internal error occurred.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes256EcbEncryptFinalPrivate (uint32_t * OutData_Text, uint32_t * OutData_length)
{
    FSP_PARAMETER_NOT_USED(OutData_Text);
    FSP_PARAMETER_NOT_USED(OutData_length);

    return R_SCE_Aes256EncryptDecryptFinalSub();
}

/*******************************************************************************************************************//**
 * Decrypt data to plain using AES ECB mode algorithm with AES 256 key.
 *
 * @param InData_KeyIndex User key generation information area.
 *
 * @retval FSP_SUCCESS                          Normal termination.
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL      Input illegal user Key Generation Information
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT resource conflict
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              Internal error occurred.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes256EcbDecryptInitPrivate (sce_aes_wrapped_key_t * InData_KeyIndex)
{
    uint32_t indata_cmd   = 0;
    uint32_t indata_iv[4] =            /* dummy */
    {
            0
    };

    if (SCE_KEY_INDEX_TYPE_AES256 != InData_KeyIndex->type)
    {
        return FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL;
    }
    indata_cmd = change_endian_long(1); /* ECB-Decrypt command */

    return R_SCE_Aes256EncryptDecryptInitSub(&indata_cmd, InData_KeyIndex->value, indata_iv);
}

/*******************************************************************************************************************//**
 * Decrypt data to plain using AES ECB mode algorithm with AES 256 key.
 *
 * @param InData_Text  Input cipher text.
 * @param OutData_Text Output plain text.
 * @param MAX_CNT      Input byte size of cipher.
 *
 * @retval FSP_SUCCESS Normal termination.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes256EcbDecryptUpdatePrivate (uint32_t * InData_Text, uint32_t * OutData_Text, uint32_t MAX_CNT)
{
    R_SCE_Aes256EncryptDecryptUpdateSub(InData_Text, OutData_Text, MAX_CNT);

    return FSP_SUCCESS;
}

/*******************************************************************************************************************//**
 * Decrypt data to plain using AES ECB mode algorithm with AES 256 key.
 *
 * @param OutData_Text   Output plain text.
 * @param OutData_length Output byte size of plain.
 *
 * @retval FSP_SUCCESS             Normal termination.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL Internal error occurred.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes256EcbDecryptFinalPrivate (uint32_t * OutData_Text, uint32_t * OutData_length)
{
    FSP_PARAMETER_NOT_USED(OutData_Text);
    FSP_PARAMETER_NOT_USED(OutData_length);

    return R_SCE_Aes256EncryptDecryptFinalSub();
}

/*******************************************************************************************************************//**
 * Encrypt data to cipher using AES CBC mode algorithm with AES 128 key.
 *
 * @param InData_KeyIndex User key generation information area.
 * @param InData_IV       Input initial vector.
 *
 * @retval FSP_SUCCESS                          Normal termination.
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL      Input illegal user Key Generation Information
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT resource conflict
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              Internal error occurred.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes128CbcEncryptInitPrivate (sce_aes_wrapped_key_t * InData_KeyIndex, uint32_t * InData_IV)
{
    uint32_t indata_cmd = 0;

    if (SCE_KEY_INDEX_TYPE_AES128 != InData_KeyIndex->type)
    {
        return FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL;
    }
    indata_cmd = change_endian_long(2); /* CBC-Encrypt command */

    return R_SCE_Aes128EncryptDecryptInitSub(&indata_cmd, InData_KeyIndex->value, InData_IV);
}

/*******************************************************************************************************************//**
 * Encrypt data to cipher using AES CBC mode algorithm with AES 128 key.
 *
 * @param InData_Text  Input plain text.
 * @param OutData_Text Output cipher text.
 * @param MAX_CNT      Input byte size of plain.
 *
 * @retval FSP_SUCCESS Normal termination.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes128CbcEncryptUpdatePrivate (uint32_t * InData_Text, uint32_t * OutData_Text, uint32_t MAX_CNT)
{
    R_SCE_Aes128EncryptDecryptUpdateSub(InData_Text, OutData_Text, MAX_CNT);

    return FSP_SUCCESS;
}

/*******************************************************************************************************************//**
 * Encrypt data to cipher using AES CBC mode algorithm with AES 128 key.
 *
 * @param OutData_Text   Output cipher text.
 * @param OutData_length Output byte size of cipher.
 *
 * @retval FSP_SUCCESS             Normal termination.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL Internal error occurred.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes128CbcEncryptFinalPrivate (uint32_t * OutData_Text, uint32_t * OutData_length)
{
    FSP_PARAMETER_NOT_USED(OutData_Text);
    FSP_PARAMETER_NOT_USED(OutData_length);

    return R_SCE_Aes128EncryptDecryptFinalSub();
}

/*******************************************************************************************************************//**
 * Decrypt data to plain using AES CBC mode algorithm with AES 128 key.
 *
 * @param InData_KeyIndex User key generation information area.
 * @param InData_IV       Input initial vector.
 *
 * @retval FSP_SUCCESS                          Normal termination.
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL      Input illegal user Key Generation Information
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT resource conflict
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              Internal error occurred.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes128CbcDecryptInitPrivate (sce_aes_wrapped_key_t * InData_KeyIndex, uint32_t * InData_IV)
{
    uint32_t indata_cmd = 0;

    if (SCE_KEY_INDEX_TYPE_AES128 != InData_KeyIndex->type)
    {
        return FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL;
    }
    indata_cmd = change_endian_long(3); /* CBC-Decrypt command */

    return R_SCE_Aes128EncryptDecryptInitSub(&indata_cmd, InData_KeyIndex->value, InData_IV);
}

/*******************************************************************************************************************//**
 * Decrypt data to plain using AES CBC mode algorithm with AES 128 key.
 *
 * @param InData_Text  Input cipher text.
 * @param OutData_Text Output plain text.
 * @param MAX_CNT      Input byte size of cipher.
 *
 * @retval FSP_SUCCESS Normal termination.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes128CbcDecryptUpdatePrivate (uint32_t * InData_Text, uint32_t * OutData_Text, uint32_t MAX_CNT)
{
    R_SCE_Aes128EncryptDecryptUpdateSub(InData_Text, OutData_Text, MAX_CNT);

    return FSP_SUCCESS;
}

/*******************************************************************************************************************//**
 * Decrypt data to plain using AES CBC mode algorithm with AES 128 key.
 *
 * @param OutData_Text   Output plain text.
 * @param OutData_length Output byte size of plain.
 *
 * @retval FSP_SUCCESS             Normal termination.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL Internal error occurred.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes128CbcDecryptFinalPrivate (uint32_t * OutData_Text, uint32_t * OutData_length)
{
    FSP_PARAMETER_NOT_USED(OutData_Text);
    FSP_PARAMETER_NOT_USED(OutData_length);

    return R_SCE_Aes128EncryptDecryptFinalSub();
}

/*******************************************************************************************************************//**
 * Encrypt data to cipher using AES CBC mode algorithm with AES 256 key.
 *
 * @param InData_KeyIndex User key generation information area.
 * @param InData_IV       Input initial vector.
 *
 * @retval FSP_SUCCESS                          Normal termination.
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL      Input illegal user Key Generation Information
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT resource conflict
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              Internal error occurred.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes256CbcEncryptInitPrivate (sce_aes_wrapped_key_t * InData_KeyIndex, uint32_t * InData_IV)
{
    uint32_t indata_cmd = 0;

    if (SCE_KEY_INDEX_TYPE_AES256 != InData_KeyIndex->type)
    {
        return FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL;
    }
    indata_cmd = change_endian_long(2); /* CBC-Encrypt command */

    return R_SCE_Aes256EncryptDecryptInitSub(&indata_cmd, InData_KeyIndex->value, InData_IV);
}

/*******************************************************************************************************************//**
 * Encrypt data to cipher using AES CBC mode algorithm with AES 256 key.
 *
 * @param InData_Text  Input plain text.
 * @param OutData_Text Output cipher text.
 * @param MAX_CNT      Input byte size of plain.
 *
 * @retval FSP_SUCCESS Normal termination.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes256CbcEncryptUpdatePrivate (uint32_t * InData_Text, uint32_t * OutData_Text, uint32_t MAX_CNT)
{
    R_SCE_Aes256EncryptDecryptUpdateSub(InData_Text, OutData_Text, MAX_CNT);

    return FSP_SUCCESS;
}

/*******************************************************************************************************************//**
 * Encrypt data to cipher using AES CBC mode algorithm with AES 256 key.
 *
 * @param OutData_Text   Output cipher text.
 * @param OutData_length Output byte size of cipher.
 *
 * @retval FSP_SUCCESS             Normal termination.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL Internal error occurred.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes256CbcEncryptFinalPrivate (uint32_t * OutData_Text, uint32_t * OutData_length)
{
    FSP_PARAMETER_NOT_USED(OutData_Text);
    FSP_PARAMETER_NOT_USED(OutData_length);

    return R_SCE_Aes256EncryptDecryptFinalSub();
}

/*******************************************************************************************************************//**
 * Decrypt data to plain using AES CBC mode algorithm with AES 256 key.
 *
 * @param InData_KeyIndex User key generation information area.
 * @param InData_IV       Input initial vector.
 *
 * @retval FSP_SUCCESS                          Normal termination.
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL      Input illegal user Key Generation Information
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT resource conflict
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              Internal error occurred.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes256CbcDecryptInitPrivate (sce_aes_wrapped_key_t * InData_KeyIndex, uint32_t * InData_IV)
{
    uint32_t indata_cmd = 0;

    if (SCE_KEY_INDEX_TYPE_AES256 != InData_KeyIndex->type)
    {
        return FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL;
    }
    indata_cmd = change_endian_long(3); /* CBC-Decrypt command */

    return R_SCE_Aes256EncryptDecryptInitSub(&indata_cmd, InData_KeyIndex->value, InData_IV);
}

/*******************************************************************************************************************//**
 * Decrypt data to plain using AES CBC mode algorithm with AES 256 key.
 *
 * @param InData_Text  Input cipher text.
 * @param OutData_Text Output plain text.
 * @param MAX_CNT      Input byte size of cipher.
 *
 * @retval FSP_SUCCESS Normal termination.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes256CbcDecryptUpdatePrivate (uint32_t * InData_Text, uint32_t * OutData_Text, uint32_t MAX_CNT)
{
    R_SCE_Aes256EncryptDecryptUpdateSub(InData_Text, OutData_Text, MAX_CNT);

    return FSP_SUCCESS;
}

/*******************************************************************************************************************//**
 * Decrypt data to plain using AES CBC mode algorithm with AES 256 key.
 *
 * @param OutData_Text   Output plain text.
 * @param OutData_length Output byte size of plain.
 *
 * @retval FSP_SUCCESS             Normal termination.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL Internal error occurred.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes256CbcDecryptFinalPrivate (uint32_t * OutData_Text, uint32_t * OutData_length)
{
    FSP_PARAMETER_NOT_USED(OutData_Text);
    FSP_PARAMETER_NOT_USED(OutData_length);

    return R_SCE_Aes256EncryptDecryptFinalSub();
}

/*******************************************************************************************************************//**
 * Encrypt data to cipher using AES CTR mode algorithm with AES 128 key.
 *
 * @param InData_KeyIndex User key generation information area.
 * @param InData_IV       Input initial vector.
 *
 * @retval FSP_SUCCESS                          Normal termination.
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL      Input illegal user Key Generation Information
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT resource conflict
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              Internal error occurred.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes128CtrEncryptInitPrivate (sce_aes_wrapped_key_t * InData_KeyIndex, uint32_t * InData_IV)
{
    uint32_t indata_cmd = 0;

    if (SCE_KEY_INDEX_TYPE_AES128 != InData_KeyIndex->type)
    {
        return FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL;
    }
    indata_cmd = change_endian_long(4); /* CTR-Encrypt command */

    return R_SCE_Aes128EncryptDecryptInitSub(&indata_cmd, InData_KeyIndex->value, InData_IV);
}

/*******************************************************************************************************************//**
 * Encrypt data to cipher using AES CTR mode algorithm with AES 128 key.
 *
 * @param InData_Text  Input plain text.
 * @param OutData_Text Output cipher text.
 * @param MAX_CNT      Input byte size of plain.
 *
 * @retval FSP_SUCCESS Normal termination.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes128CtrEncryptUpdatePrivate (uint32_t * InData_Text, uint32_t * OutData_Text, uint32_t MAX_CNT)
{
    R_SCE_Aes128EncryptDecryptUpdateSub(InData_Text, OutData_Text, MAX_CNT);

    return FSP_SUCCESS;
}

/*******************************************************************************************************************//**
 * Encrypt data to cipher using AES CTR mode algorithm with AES 128 key.
 *
 * @param OutData_Text   Output cipher text.
 * @param OutData_length Output byte size of cipher.
 *
 * @retval FSP_SUCCESS             Normal termination.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL Internal error occurred.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes128CtrEncryptFinalPrivate (uint32_t * OutData_Text, uint32_t * OutData_length)
{
    FSP_PARAMETER_NOT_USED(OutData_Text);
    FSP_PARAMETER_NOT_USED(OutData_length);

    return R_SCE_Aes128EncryptDecryptFinalSub();
}

/*******************************************************************************************************************//**
 * Decrypt data to plain using AES CTR mode algorithm with AES 128 key.
 *
 * @param InData_KeyIndex User key generation information area.
 * @param InData_IV       Input initial vector.
 *
 * @retval FSP_SUCCESS                          Normal termination.
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL      Input illegal user Key Generation Information
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT resource conflict
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              Internal error occurred.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes128CtrDecryptInitPrivate (sce_aes_wrapped_key_t * InData_KeyIndex, uint32_t * InData_IV)
{
    uint32_t indata_cmd = 0;

    if (SCE_KEY_INDEX_TYPE_AES128 != InData_KeyIndex->type)
    {
        return FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL;
    }
    indata_cmd = change_endian_long(4); /* CTR-Decrypt command */

    return R_SCE_Aes128EncryptDecryptInitSub(&indata_cmd, InData_KeyIndex->value, InData_IV);
}

/*******************************************************************************************************************//**
 * Decrypt data to plain using AES CTR mode algorithm with AES 128 key.
 *
 * @param InData_Text  Input cipher text.
 * @param OutData_Text Output plain text.
 * @param MAX_CNT      Input byte size of cipher.
 *
 * @retval FSP_SUCCESS Normal termination.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes128CtrDecryptUpdatePrivate (uint32_t * InData_Text, uint32_t * OutData_Text, uint32_t MAX_CNT)
{
    R_SCE_Aes128EncryptDecryptUpdateSub(InData_Text, OutData_Text, MAX_CNT);

    return FSP_SUCCESS;
}

/*******************************************************************************************************************//**
 * Decrypt data to plain using AES CTR mode algorithm with AES 128 key.
 *
 * @param OutData_Text   Output plain text.
 * @param OutData_length Output byte size of plain.
 *
 * @retval FSP_SUCCESS             Normal termination.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL Internal error occurred.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes128CtrDecryptFinalPrivate (uint32_t * OutData_Text, uint32_t * OutData_length)
{
    FSP_PARAMETER_NOT_USED(OutData_Text);
    FSP_PARAMETER_NOT_USED(OutData_length);

    return R_SCE_Aes128EncryptDecryptFinalSub();
}

/*******************************************************************************************************************//**
 * Encrypt data to cipher using AES CTR mode algorithm with AES 256 key.
 *
 * @param InData_KeyIndex User key generation information area.
 * @param InData_IV       Input initial vector.
 *
 * @retval FSP_SUCCESS                          Normal termination.
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL      Input illegal user Key Generation Information
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT resource conflict
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              Internal error occurred.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes256CtrEncryptInitPrivate (sce_aes_wrapped_key_t * InData_KeyIndex, uint32_t * InData_IV)
{
    uint32_t indata_cmd = 0;

    if (SCE_KEY_INDEX_TYPE_AES256 != InData_KeyIndex->type)
    {
        return FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL;
    }
    indata_cmd = change_endian_long(4); /* CTR-Encrypt command */

    return R_SCE_Aes256EncryptDecryptInitSub(&indata_cmd, InData_KeyIndex->value, InData_IV);
}

/*******************************************************************************************************************//**
 * Encrypt data to cipher using AES CTR mode algorithm with AES 256 key.
 *
 * @param InData_Text  Input plain text.
 * @param OutData_Text Output cipher text.
 * @param MAX_CNT      Input byte size of plain.
 *
 * @retval FSP_SUCCESS Normal termination.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes256CtrEncryptUpdatePrivate (uint32_t * InData_Text, uint32_t * OutData_Text, uint32_t MAX_CNT)
{
    R_SCE_Aes256EncryptDecryptUpdateSub(InData_Text, OutData_Text, MAX_CNT);

    return FSP_SUCCESS;
}

/*******************************************************************************************************************//**
 * Encrypt data to cipher using AES CTR mode algorithm with AES 256 key.
 *
 * @param OutData_Text   Output cipher text.
 * @param OutData_length Output byte size of cipher.
 *
 * @retval FSP_SUCCESS             Normal termination.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL Internal error occurred.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes256CtrEncryptFinalPrivate (uint32_t * OutData_Text, uint32_t * OutData_length)
{
    FSP_PARAMETER_NOT_USED(OutData_Text);
    FSP_PARAMETER_NOT_USED(OutData_length);

    return R_SCE_Aes256EncryptDecryptFinalSub();
}

/*******************************************************************************************************************//**
 * Decrypt data to plain using AES CTR mode algorithm with AES 256 key.
 *
 * @param InData_KeyIndex User key generation information area.
 * @param InData_IV       Input initial vector.
 *
 * @retval FSP_SUCCESS                          Normal termination.
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL      Input illegal user Key Generation Information
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT resource conflict
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              Internal error occurred.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes256CtrDecryptInitPrivate (sce_aes_wrapped_key_t * InData_KeyIndex, uint32_t * InData_IV)
{
    uint32_t indata_cmd = 0;

    if (SCE_KEY_INDEX_TYPE_AES256 != InData_KeyIndex->type)
    {
        return FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL;
    }
    indata_cmd = change_endian_long(4); /* CTR-Decrypt command */

    return R_SCE_Aes256EncryptDecryptInitSub(&indata_cmd, InData_KeyIndex->value, InData_IV);
}

/*******************************************************************************************************************//**
 * Decrypt data to plain using AES CTR mode algorithm with AES 256 key.
 *
 * @param InData_Text  Input cipher text.
 * @param OutData_Text Output plain text.
 * @param MAX_CNT      Input byte size of cipher.
 *
 * @retval FSP_SUCCESS Normal termination.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes256CtrDecryptUpdatePrivate (uint32_t * InData_Text, uint32_t * OutData_Text, uint32_t MAX_CNT)
{
    R_SCE_Aes256EncryptDecryptUpdateSub(InData_Text, OutData_Text, MAX_CNT);

    return FSP_SUCCESS;
}

/*******************************************************************************************************************//**
 * Decrypt data to plain using AES CTR mode algorithm with AES 256 key.
 *
 * @param OutData_Text   Output plain text.
 * @param OutData_length Output byte size of plain.
 *
 * @retval FSP_SUCCESS             Normal termination.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL Internal error occurred.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes256CtrDecryptFinalPrivate (uint32_t * OutData_Text, uint32_t * OutData_length)
{
    FSP_PARAMETER_NOT_USED(OutData_Text);
    FSP_PARAMETER_NOT_USED(OutData_length);

    return R_SCE_Aes256EncryptDecryptFinalSub();
}

/*******************************************************************************************************************//**
 * Prepare to execute AES calculation.
 *
 * @param InData_KeyIndex User key generation information area
 *
 * @retval FSP_SUCCESS                          Normal termination.
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT resource conflict
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL      Input illegal user Key Generation Information
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              Internal error occurred.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes128CmacGenerateInitPrivate (sce_aes_wrapped_key_t * InData_KeyIndex)
{
    return R_SCE_Aes128CmacInitSub(InData_KeyIndex->value);
}

/*******************************************************************************************************************//**
 * Generates a MAC value from the message specified.
 *
 * @param InData_Text Message data area (data_len byte)
 * @param MAX_CNT     Message data length (0 to arbitrary byte)
 *
 * @retval FSP_SUCCESS Normal termination.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes128CmacGenerateUpdatePrivate (uint32_t * InData_Text, uint32_t MAX_CNT)
{
    R_SCE_Aes128CmacUpdateSub(InData_Text, MAX_CNT);

    return FSP_SUCCESS;
}

/*******************************************************************************************************************//**
 * Outputs the Mac value.
 *
 * @param All_Msg_Len   Input byte size of message data.
 * @param InData_Text   Input message data.
 * @param OutData_DataT MAC data area (data_len byte)
 *
 * @retval FSP_SUCCESS                       Normal termination.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL           Internal error occurred.
 * @retval FSP_ERR_CRYPTO_SCE_AUTHENTICATION Reserved.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes128CmacGenerateFinalPrivate (uint32_t All_Msg_Len, uint32_t * InData_Text, uint32_t * OutData_DataT)
{
    uint32_t indata_cmd      = 0;
    uint32_t indata_datat[4] =         /* dummy */
    {
            0
    };
    uint32_t indata_datat_len = 0;     /* dummy */

    if ((0 == (All_Msg_Len % 16)) && (0 != All_Msg_Len))
    {
        indata_cmd = 0;
    }
    else
    {
        indata_cmd = 1;
    }

    return R_SCE_Aes128CmacFinalSub(&indata_cmd, InData_Text, indata_datat, &indata_datat_len, OutData_DataT);
}

/*******************************************************************************************************************//**
 * Prepare to execute CMAC calculation.
 *
 * @param InData_KeyIndex User key generation information area
 *
 * @retval FSP_SUCCESS                          Normal termination.
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT resource conflict
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL      Input illegal user Key Generation Information
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              Internal error occurred.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes128CmacVerifyInitPrivate (sce_aes_wrapped_key_t * InData_KeyIndex)
{
    return R_SCE_Aes128CmacInitSub(InData_KeyIndex->value);
}

/*******************************************************************************************************************//**
 * Verifies the MAC value.
 *
 * @param InData_Text Message data area (data_len byte)
 * @param MAX_CNT     Message data length (0 to arbitrary byte)
 *
 * @retval FSP_SUCCESS Normal termination.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes128CmacVerifyUpdatePrivate (uint32_t * InData_Text, uint32_t MAX_CNT)
{
    R_SCE_Aes128CmacUpdateSub(InData_Text, MAX_CNT);

    return FSP_SUCCESS;
}

/*******************************************************************************************************************//**
 * Validates the Mac value.
 *
 * @param All_Msg_Len     Input byte size of message data.
 * @param InData_Text     Input message data.
 * @param InData_DataT    MAC data area (data_len byte)
 * @param InData_DataTLen MAC data length
 *
 * @retval FSP_SUCCESS                       Normal termination.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL           Internal error occurred.
 * @retval FSP_ERR_CRYPTO_SCE_AUTHENTICATION Authentication NG
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes128CmacVerifyFinalPrivate (uint32_t   All_Msg_Len,
        uint32_t * InData_Text,
        uint32_t * InData_DataT,
        uint32_t * InData_DataTLen)
{
    uint32_t indata_cmd  = 0;
    uint32_t out_data[4] =
    {
            0
    };

    if ((0 == (All_Msg_Len % 16)) && (0 != All_Msg_Len))
    {
        indata_cmd = 2;
    }
    else
    {
        indata_cmd = 3;
    }

    return R_SCE_Aes128CmacFinalSub(&indata_cmd, InData_Text, InData_DataT, InData_DataTLen, out_data);
}

/*******************************************************************************************************************//**
 * Prepare to execute AES calculation.
 *
 * @param InData_KeyIndex User key generation information area
 *
 * @retval FSP_SUCCESS                          Normal termination.
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT resource conflict
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL      Input illegal user Key Generation Information
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              Internal error occurred.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes256CmacGenerateInitPrivate (sce_aes_wrapped_key_t * InData_KeyIndex)
{
    return R_SCE_Aes256CmacInitSub(InData_KeyIndex->value);
}

/*******************************************************************************************************************//**
 * Generates a MAC value from the message specified.
 *
 * @param InData_Text Message data area (data_len byte)
 * @param MAX_CNT     Message data length (0 to arbitrary byte)
 *
 * @retval FSP_SUCCESS Normal termination.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes256CmacGenerateUpdatePrivate (uint32_t * InData_Text, uint32_t MAX_CNT)
{
    R_SCE_Aes256CmacUpdateSub(InData_Text, MAX_CNT);

    return FSP_SUCCESS;
}

/*******************************************************************************************************************//**
 * Outputs the Mac value.
 *
 * @param All_Msg_Len   Input byte size of message data.
 * @param InData_Text   Input message data.
 * @param OutData_DataT MAC data area (data_len byte)
 *
 * @retval FSP_SUCCESS                       Normal termination.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL           Internal error occurred.
 * @retval FSP_ERR_CRYPTO_SCE_AUTHENTICATION Reserved.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes256CmacGenerateFinalPrivate (uint32_t All_Msg_Len, uint32_t * InData_Text, uint32_t * OutData_DataT)
{
    uint32_t indata_cmd      = 0;
    uint32_t indata_datat[4] =         /* dummy */
    {
            0
    };
    uint32_t indata_datat_len = 0;     /* dummy */

    if ((0 == (All_Msg_Len % 16)) && (0 != All_Msg_Len))
    {
        indata_cmd = 0;
    }
    else
    {
        indata_cmd = 1;
    }

    return R_SCE_Aes256CmacFinalSub(&indata_cmd, InData_Text, indata_datat, &indata_datat_len, OutData_DataT);
}

/*******************************************************************************************************************//**
 * Prepare to execute CMAC calculation.
 *
 * @param InData_KeyIndex User key generation information area
 *
 * @retval FSP_SUCCESS                          Normal termination.
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT resource conflict
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL      Input illegal user Key Generation Information
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              Internal error occurred.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes256CmacVerifyInitPrivate (sce_aes_wrapped_key_t * InData_KeyIndex)
{
    return R_SCE_Aes256CmacInitSub(InData_KeyIndex->value);
}

/*******************************************************************************************************************//**
 * Verifies the MAC value.
 *
 * @param InData_Text Message data area (data_len byte)
 * @param MAX_CNT     Message data length (0 to arbitrary byte)
 *
 * @retval FSP_SUCCESS Normal termination.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes256CmacVerifyUpdatePrivate (uint32_t * InData_Text, uint32_t MAX_CNT)
{
    R_SCE_Aes256CmacUpdateSub(InData_Text, MAX_CNT);

    return FSP_SUCCESS;
}

/*******************************************************************************************************************//**
 * Validates the Mac value.
 *
 * @param All_Msg_Len     Input byte size of message data.
 * @param InData_Text     Input message data.
 * @param InData_DataT    MAC data area (data_len byte)
 * @param InData_DataTLen MAC data length
 *
 * @retval FSP_SUCCESS                       Normal termination.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL           Internal error occurred.
 * @retval FSP_ERR_CRYPTO_SCE_AUTHENTICATION Authentication NG
 **********************************************************************************************************************/
fsp_err_t R_SCE_Aes256CmacVerifyFinalPrivate (uint32_t   All_Msg_Len,
        uint32_t * InData_Text,
        uint32_t * InData_DataT,
        uint32_t * InData_DataTLen)
{
    uint32_t indata_cmd  = 0;
    uint32_t out_data[4] =
    {
            0
    };

    if ((0 == (All_Msg_Len % 16)) && (0 != All_Msg_Len))
    {
        indata_cmd = 2;
    }
    else
    {
        indata_cmd = 3;
    }

    return R_SCE_Aes256CmacFinalSub(&indata_cmd, InData_Text, InData_DataT, InData_DataTLen, out_data);
}

/*******************************************************************************************************************//**
 * prepares to execute the SHA256 hash operation
 *
 * @param handle SHA256 handler (work area)
 *
 * @retval FSP_SUCCESS Normal termination.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Sha256InitPrivate (sce_sha_md5_handle_t * handle)
{
    uint32_t indata_sha256initval[8] =
    {
            0
    };

    FSP_PARAMETER_NOT_USED(handle);

    indata_sha256initval[0] = change_endian_long(SCE_HEX_6A09E667);
    indata_sha256initval[1] = change_endian_long(SCE_HEX_BB67AE85);
    indata_sha256initval[2] = change_endian_long(SCE_HEX_3C6EF372);
    indata_sha256initval[3] = change_endian_long(SCE_HEX_A54FF53A);
    indata_sha256initval[4] = change_endian_long(SCE_HEX_510E527F);
    indata_sha256initval[5] = change_endian_long(SCE_HEX_9B05688C);
    indata_sha256initval[6] = change_endian_long(SCE_HEX_1F83D9AB);
    indata_sha256initval[7] = change_endian_long(SCE_HEX_5BE0CD19);

    memcpy(handle->current_hash, indata_sha256initval, HW_SCE_SHA256_HASH_LENGTH_BYTE_SIZE);

    return FSP_SUCCESS;
}

/*******************************************************************************************************************//**
 * calculate a hash value
 *
 * @param handle           SHA256 handler (work area)
 * @param InData_PaddedMsg Input message.
 * @param MAX_CNT          Input message length
 *
 * @retval FSP_SUCCESS                          Normal termination.
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT resource conflict
 **********************************************************************************************************************/
fsp_err_t R_SCE_Sha256UpdatePrivate (sce_sha_md5_handle_t * handle, uint32_t * InData_PaddedMsg, uint32_t MAX_CNT)
{
    uint32_t out_data[8] =
    {
            0
    };
    fsp_err_t ercd = FSP_SUCCESS;

    FSP_PARAMETER_NOT_USED(handle);

    /*Casting uint32_t pointer is used for address.*/
    ercd = R_SCE_Sha224256GenerateMessageDigestSub((uint32_t *) handle->current_hash,
            InData_PaddedMsg,
            MAX_CNT,
            out_data);
    memcpy(handle->current_hash, out_data, HW_SCE_SHA256_HASH_LENGTH_BYTE_SIZE);

    return ercd;
}

/*******************************************************************************************************************//**
 * calculate a hash value
 *
 * @param handle            SHA256 handler (work area).
 * @param InData_PaddedMsg  Input Message data
 * @param MAX_CNT           Input message length
 * @param OutData_MsgDigest Output Hash data
 * @param OutData_Length    Output Hash length
 *
 * @retval FSP_SUCCESS                          Normal termination.
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT resource conflict
 **********************************************************************************************************************/
fsp_err_t R_SCE_Sha256FinalPrivate (sce_sha_md5_handle_t * handle,
        uint32_t             * InData_PaddedMsg,
        uint32_t               MAX_CNT,
        uint32_t             * OutData_MsgDigest,
        uint32_t             * OutData_Length)
{
    fsp_err_t ercd = FSP_SUCCESS;

    FSP_PARAMETER_NOT_USED(handle);

    /*Casting uint32_t pointer is used for address.*/
    ercd = R_SCE_Sha224256GenerateMessageDigestSub((uint32_t *) handle->current_hash,
            InData_PaddedMsg,
            MAX_CNT,
            OutData_MsgDigest);
    memcpy(handle->current_hash, OutData_MsgDigest, HW_SCE_SHA256_HASH_LENGTH_BYTE_SIZE);
    *OutData_Length = HW_SCE_SHA256_HASH_LENGTH_BYTE_SIZE;

    return ercd;
}

/*******************************************************************************************************************//**
 * prepares to execute the SHA224 hash operation
 *
 * @param handle SHA224 handler (work area)
 *
 * @retval FSP_SUCCESS Normal termination.
 **********************************************************************************************************************/
fsp_err_t R_SCE_Sha224InitPrivate (sce_sha_md5_handle_t * handle)
{
    uint32_t indata_sha224initval[8] =
    {
            0
    };

    FSP_PARAMETER_NOT_USED(handle);

    indata_sha224initval[0] = change_endian_long(SCE_HEX_C1059ED8);
    indata_sha224initval[1] = change_endian_long(SCE_HEX_367CD507);
    indata_sha224initval[2] = change_endian_long(SCE_HEX_3070DD17);
    indata_sha224initval[3] = change_endian_long(SCE_HEX_F70E5939);
    indata_sha224initval[4] = change_endian_long(SCE_HEX_FFC00B31);
    indata_sha224initval[5] = change_endian_long(SCE_HEX_68581511);
    indata_sha224initval[6] = change_endian_long(SCE_HEX_64F98FA7);
    indata_sha224initval[7] = change_endian_long(SCE_HEX_BEFA4FA4);

    memcpy(handle->current_hash, indata_sha224initval, HW_SCE_SHA224_HASH_LENGTH_BYTE_SIZE + 4);

    return FSP_SUCCESS;
}

/*******************************************************************************************************************//**
 * calculate a hash value
 *
 * @param handle           SHA224 handler (work area)
 * @param InData_PaddedMsg Input message.
 * @param MAX_CNT          Input message length
 *
 * @retval FSP_SUCCESS                          Normal termination.
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT resource conflict
 **********************************************************************************************************************/
fsp_err_t R_SCE_Sha224UpdatePrivate (sce_sha_md5_handle_t * handle, uint32_t * InData_PaddedMsg, uint32_t MAX_CNT)
{
    uint32_t out_data[8] =
    {
            0
    };
    fsp_err_t ercd = FSP_SUCCESS;

    FSP_PARAMETER_NOT_USED(handle);

    /*Casting uint32_t pointer is used for address.*/
    ercd = R_SCE_Sha224256GenerateMessageDigestSub((uint32_t *) handle->current_hash,
            InData_PaddedMsg,
            MAX_CNT,
            out_data);
    memcpy(handle->current_hash, out_data, HW_SCE_SHA224_HASH_LENGTH_BYTE_SIZE + 4);

    return ercd;
}

/*******************************************************************************************************************//**
 * calculate a hash value
 *
 * @param handle            SHA224 handler (work area).
 * @param InData_PaddedMsg  Input Message data
 * @param MAX_CNT           Input message length
 * @param OutData_MsgDigest Output Hash data
 * @param OutData_Length    Output Hash length
 *
 * @retval FSP_SUCCESS                          Normal termination.
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT resource conflict
 **********************************************************************************************************************/
fsp_err_t R_SCE_Sha224FinalPrivate (sce_sha_md5_handle_t * handle,
        uint32_t             * InData_PaddedMsg,
        uint32_t               MAX_CNT,
        uint32_t             * OutData_MsgDigest,
        uint32_t             * OutData_Length)
{
    fsp_err_t ercd = FSP_SUCCESS;

    FSP_PARAMETER_NOT_USED(handle);

    /*Casting uint32_t pointer is used for address.*/
    ercd = R_SCE_Sha224256GenerateMessageDigestSub((uint32_t *) handle->current_hash,
            InData_PaddedMsg,
            MAX_CNT,
            (uint32_t *) handle->current_hash);
    memcpy(OutData_MsgDigest, handle->current_hash, HW_SCE_SHA224_HASH_LENGTH_BYTE_SIZE);
    *OutData_Length = HW_SCE_SHA224_HASH_LENGTH_BYTE_SIZE;

    return ercd;
}

/*******************************************************************************************************************//**
 * Modular exponentiation operation with RSA 1024bit public key
 *
 * @param InData_KeyIndex the public key index information
 * @param InData_Text     input data
 * @param OutData_Text    output data
 *
 * @retval FSP_SUCCESS                          Normal termination.
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT resource conflict
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL      Input illegal user Key Generation Information
 **********************************************************************************************************************/
fsp_err_t R_SCE_Rsa1024ModularExponentEncryptPrivate (uint32_t * InData_KeyIndex,
        uint32_t * InData_Text,
        uint32_t * OutData_Text)
{
    return R_SCE_Rsa1024ModularExponentEncryptSub(InData_KeyIndex, InData_Text, OutData_Text);
}

/*******************************************************************************************************************//**
 * Modular exponentiation operation with RSA 1024bit private key
 *
 * @param InData_KeyIndex the private key index information
 * @param InData_Text     input data
 * @param OutData_Text    output data
 *
 * @retval FSP_SUCCESS                          Normal termination.
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT resource conflict
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL      Input illegal user Key Generation Information
 **********************************************************************************************************************/
fsp_err_t R_SCE_Rsa1024ModularExponentDecryptPrivate (uint32_t * InData_KeyIndex,
        uint32_t * InData_Text,
        uint32_t * OutData_Text)
{
    return R_SCE_Rsa1024ModularExponentDecryptSub(InData_KeyIndex, InData_Text, OutData_Text);
}

/*******************************************************************************************************************//**
 * Modular exponentiation operation with RSA 2048bit public key
 *
 * @param InData_KeyIndex the public key index information
 * @param InData_Text     input data
 * @param OutData_Text    output data
 *
 * @retval FSP_SUCCESS                          Normal termination.
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT resource conflict
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL      Input illegal user Key Generation Information
 **********************************************************************************************************************/
fsp_err_t R_SCE_Rsa2048ModularExponentEncryptPrivate (uint32_t * InData_KeyIndex,
        uint32_t * InData_Text,
        uint32_t * OutData_Text)
{
    return R_SCE_Rsa2048ModularExponentEncryptSub(InData_KeyIndex, InData_Text, OutData_Text);
}

/*******************************************************************************************************************//**
 * Modular exponentiation operation with RSA 2048bit private key
 *
 * @param InData_KeyIndex the private key index information
 * @param InData_Text     input data
 * @param OutData_Text    output data
 *
 * @retval FSP_SUCCESS                          Normal termination.
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT resource conflict
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL      Input illegal user Key Generation Information
 **********************************************************************************************************************/
fsp_err_t R_SCE_Rsa2048ModularExponentDecryptPrivate (uint32_t * InData_KeyIndex,
        uint32_t * InData_Text,
        uint32_t * OutData_Text)
{
    return R_SCE_Rsa2048ModularExponentDecryptSub(InData_KeyIndex, InData_Text, OutData_Text);
}

/*******************************************************************************************************************//**
 * Modular exponentiation operation with RSA 4096bit public key
 *
 * @param InData_KeyIndex the public key index information
 * @param InData_Text     input data
 * @param OutData_Text    output data
 *
 * @retval FSP_SUCCESS                          Normal termination.
 * @retval FSP_ERR_CRYPTO_SCE_FAIL              Internal error occurred.
 * @retval FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT resource conflict
 * @retval FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL      Input illegal user Key Generation Information
 **********************************************************************************************************************/
fsp_err_t R_SCE_Rsa4096ModularExponentEncryptPrivate (uint32_t * InData_KeyIndex,
        uint32_t * InData_Text,
        uint32_t * OutData_Text)
{
    return R_SCE_Rsa4096ModularExponentEncryptSub(InData_KeyIndex, InData_Text, OutData_Text);
}

/*******************************************************************************************************************//**
 * change endian
 *
 * @param data input data
 *
 * @return the data changing endian
 **********************************************************************************************************************/

uint32_t change_endian_long (volatile uint32_t data)
{
    return ((((data) & 0xFF000000) >> 24) | (((data) & 0x00FF0000) >>  8) | (((data) & 0x0000FF00) << 8) |
            (((data) & 0x000000FF) << 24));
}