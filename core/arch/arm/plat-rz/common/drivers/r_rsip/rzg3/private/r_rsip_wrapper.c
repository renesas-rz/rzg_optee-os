// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2024, Renesas Electronics Corporation
 */

/***********************************************************************************************************************
 * Includes
 **********************************************************************************************************************/
#include <string.h>
#include "r_rsip_wrapper.h"
#include "r_rsip_primitive.h"
#include "r_rsip_util.h"

/***********************************************************************************************************************
 * Macro definitions
 **********************************************************************************************************************/

/* For AES-ECB/CBC/CTR */
#define RSIP_PRV_CMD_AES_CIPHER_ECB_ENCRYPT                  (BSWAP_32BIG_C(0U))
#define RSIP_PRV_CMD_AES_CIPHER_ECB_DECRYPT                  (BSWAP_32BIG_C(1U))
#define RSIP_PRV_CMD_AES_CIPHER_CBC_ENCRYPT                  (BSWAP_32BIG_C(2U))
#define RSIP_PRV_CMD_AES_CIPHER_CBC_DECRYPT                  (BSWAP_32BIG_C(3U))
#define RSIP_PRV_CMD_AES_CIPHER_CTR_CRYPT                    (BSWAP_32BIG_C(4U))

/* For AES-CMAC */
#define RSIP_PRV_CMD_AES_CMAC_GENERATE_WITHOUT_REMAINDER     (BSWAP_32BIG_C(0U))
#define RSIP_PRV_CMD_AES_CMAC_GENERATE_WITH_REMAINDER        (BSWAP_32BIG_C(1U))
#define RSIP_PRV_CMD_AES_CMAC_VERIFY_WITHOUT_REMAINDER       (BSWAP_32BIG_C(2U))
#define RSIP_PRV_CMD_AES_CMAC_VERIFY_WITH_REMAINDER          (BSWAP_32BIG_C(3U))

/* For RSA */
/* Maximum retry count of RSA key generation derived from FIPS186-4 B.3.3. 4.7 and 5.5 */
#define RSIP_PRV_MAX_RETRY_COUNT_KEY_GEN_RSA_1024            (2 * (5 * 1024 / 2))
#define RSIP_PRV_MAX_RETRY_COUNT_KEY_GEN_RSA_2048            (2 * (5 * 2048 / 2))
#define RSIP_PRV_MAX_RETRY_COUNT_KEY_GEN_RSA_3072            (2 * (5 * 3072 / 2))
#define RSIP_PRV_MAX_RETRY_COUNT_KEY_GEN_RSA_4096            (15 * 4096)

/* For ECC */
#define RSIP_PRV_CMD_ECC_TYPE_NIST                           (BSWAP_32BIG_C(0U))
#define RSIP_PRV_CMD_ECC_TYPE_BRAINPOOL                      (BSWAP_32BIG_C(1U))
#define RSIP_PRV_CMD_ECC_KEY_LENGTH_192                      (BSWAP_32BIG_C(2U))
#define RSIP_PRV_CMD_ECC_KEY_LENGTH_224                      (BSWAP_32BIG_C(1U))
#define RSIP_PRV_CMD_ECC_KEY_LENGTH_256                      (BSWAP_32BIG_C(0U))

/* For HMAC */
#define RSIP_PRV_CMD_HMAC_HASH_TYPE_SHA1                     (BSWAP_32BIG_C(0U))
#define RSIP_PRV_CMD_HMAC_HASH_TYPE_SHA224                   (BSWAP_32BIG_C(1U))
#define RSIP_PRV_CMD_HMAC_HASH_TYPE_SHA256                   (BSWAP_32BIG_C(2U))

/* For password hash generation */
#define RSIP_PRV_CMD_PASSWORD_TYPE_JTAG_DEBUG_AUTH_LEVEL1    (BSWAP_32BIG_C(0U))
#define RSIP_PRV_CMD_PASSWORD_TYPE_JTAG_DEBUG_AUTH_LEVEL2    (BSWAP_32BIG_C(1U))

/***********************************************************************************************************************
 * Typedef definitions
 **********************************************************************************************************************/

typedef enum e_rsip_aes_mode_extended
{
    RSIP_AES_MODE_EXTENDED_ECB_ENCRYPT,
    RSIP_AES_MODE_EXTENDED_ECB_DECRYPT,
    RSIP_AES_MODE_EXTENDED_CBC_ENCRYPT,
    RSIP_AES_MODE_EXTENDED_CBC_DECRYPT,
    RSIP_AES_MODE_EXTENDED_CTR_CRYPT
} rsip_aes_mode_extended_t;

typedef enum e_rsip_ecc_type
{
    RSIP_ECC_TYPE_NIST,
    RSIP_ECC_TYPE_BRAINPOOL
} rsip_ecc_type_t;

typedef enum e_rsip_ecc_key_length
{
    RSIP_ECC_KEY_LENGTH_192,
    RSIP_ECC_KEY_LENGTH_224,
    RSIP_ECC_KEY_LENGTH_256
} rsip_ecc_key_length_t;

typedef enum e_hmac_hash_type
{
    HMAC_HASH_TYPE_SHA1,
    HMAC_HASH_TYPE_SHA224,
    HMAC_HASH_TYPE_SHA256
} hmac_hash_type_t;

/***********************************************************************************************************************
 * Private function prototypes
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Private global variables
 **********************************************************************************************************************/

static const uint32_t gs_cmd_aes_mode[] =
{
    [RSIP_AES_MODE_EXTENDED_ECB_ENCRYPT] = RSIP_PRV_CMD_AES_CIPHER_ECB_ENCRYPT,
    [RSIP_AES_MODE_EXTENDED_ECB_DECRYPT] = RSIP_PRV_CMD_AES_CIPHER_ECB_DECRYPT,
    [RSIP_AES_MODE_EXTENDED_CBC_ENCRYPT] = RSIP_PRV_CMD_AES_CIPHER_CBC_ENCRYPT,
    [RSIP_AES_MODE_EXTENDED_CBC_DECRYPT] = RSIP_PRV_CMD_AES_CIPHER_CBC_DECRYPT,
    [RSIP_AES_MODE_EXTENDED_CTR_CRYPT]   = RSIP_PRV_CMD_AES_CIPHER_CTR_CRYPT
};

static const uint32_t gs_cmd_ecc_type[] =
{
    [RSIP_ECC_TYPE_NIST]      = RSIP_PRV_CMD_ECC_TYPE_NIST,
    [RSIP_ECC_TYPE_BRAINPOOL] = RSIP_PRV_CMD_ECC_TYPE_BRAINPOOL
};

static const uint32_t gs_cmd_ecc_key_length[] =
{
    [RSIP_ECC_KEY_LENGTH_192] = RSIP_PRV_CMD_ECC_KEY_LENGTH_192,
    [RSIP_ECC_KEY_LENGTH_224] = RSIP_PRV_CMD_ECC_KEY_LENGTH_224,
    [RSIP_ECC_KEY_LENGTH_256] = RSIP_PRV_CMD_ECC_KEY_LENGTH_256
};

static const uint32_t gs_cmd_hmac_hash_type[] =
{
    [HMAC_HASH_TYPE_SHA1]   = RSIP_PRV_CMD_HMAC_HASH_TYPE_SHA1,
    [HMAC_HASH_TYPE_SHA224] = RSIP_PRV_CMD_HMAC_HASH_TYPE_SHA224,
    [HMAC_HASH_TYPE_SHA256] = RSIP_PRV_CMD_HMAC_HASH_TYPE_SHA256
};

/***********************************************************************************************************************
 * Global variables
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Functions
 **********************************************************************************************************************/

rsip_ret_t r_rsip_wrapper_pf4_secp192r1 (uint32_t OutData_PubKeyIndex[], uint32_t OutData_PrivKeyIndex[])
{
    return r_rsip_pf4(&gs_cmd_ecc_type[RSIP_ECC_TYPE_NIST],
                      &gs_cmd_ecc_key_length[RSIP_ECC_KEY_LENGTH_192],
                      OutData_PubKeyIndex,
                      OutData_PrivKeyIndex);
}

rsip_ret_t r_rsip_wrapper_pf4_secp224r1 (uint32_t OutData_PubKeyIndex[], uint32_t OutData_PrivKeyIndex[])
{
    return r_rsip_pf4(&gs_cmd_ecc_type[RSIP_ECC_TYPE_NIST],
                      &gs_cmd_ecc_key_length[RSIP_ECC_KEY_LENGTH_224],
                      OutData_PubKeyIndex,
                      OutData_PrivKeyIndex);
}

rsip_ret_t r_rsip_wrapper_pf4_secp256r1 (uint32_t OutData_PubKeyIndex[], uint32_t OutData_PrivKeyIndex[])
{
    return r_rsip_pf4(&gs_cmd_ecc_type[RSIP_ECC_TYPE_NIST],
                      &gs_cmd_ecc_key_length[RSIP_ECC_KEY_LENGTH_256],
                      OutData_PubKeyIndex,
                      OutData_PrivKeyIndex);
}

rsip_ret_t r_rsip_wrapper_pf4_brainpoolp256r1 (uint32_t OutData_PubKeyIndex[], uint32_t OutData_PrivKeyIndex[])
{
    return r_rsip_pf4(&gs_cmd_ecc_type[RSIP_ECC_TYPE_BRAINPOOL],
                      &gs_cmd_ecc_key_length[RSIP_ECC_KEY_LENGTH_256],
                      OutData_PubKeyIndex,
                      OutData_PrivKeyIndex);
}

rsip_ret_t r_rsip_wrapper_p2a (uint32_t OutData_PubKeyIndex[], uint32_t OutData_PrivKeyIndex[])
{
    return r_rsip_p2a(RSIP_PRV_MAX_RETRY_COUNT_KEY_GEN_RSA_1024, OutData_PubKeyIndex, OutData_PrivKeyIndex);
}

rsip_ret_t r_rsip_wrapper_p2b (uint32_t OutData_PubKeyIndex[], uint32_t OutData_PrivKeyIndex[])
{
    return r_rsip_p2b(RSIP_PRV_MAX_RETRY_COUNT_KEY_GEN_RSA_2048, OutData_PubKeyIndex, OutData_PrivKeyIndex);
}

rsip_ret_t r_rsip_wrapper_p3a (uint32_t OutData_PubKeyIndex[], uint32_t OutData_PrivKeyIndex[])
{
    return r_rsip_p3a(RSIP_PRV_MAX_RETRY_COUNT_KEY_GEN_RSA_3072, OutData_PubKeyIndex, OutData_PrivKeyIndex);
}

rsip_ret_t r_rsip_wrapper_p3b (uint32_t OutData_PubKeyIndex[], uint32_t OutData_PrivKeyIndex[])
{
    return r_rsip_p3b(RSIP_PRV_MAX_RETRY_COUNT_KEY_GEN_RSA_4096, OutData_PubKeyIndex, OutData_PrivKeyIndex);
}

rsip_ret_t r_rsip_wrapper_p2c_secp192r1 (uint32_t const InData_IV[],
                                         uint32_t const InData_InstData[],
                                         uint32_t       OutData_KeyIndex[])
{
    return r_rsip_p2c(&gs_cmd_ecc_type[RSIP_ECC_TYPE_NIST],
                      &gs_cmd_ecc_key_length[RSIP_ECC_KEY_LENGTH_192],
                      InData_IV,
                      InData_InstData,
                      OutData_KeyIndex);
}

rsip_ret_t r_rsip_wrapper_p1e_secp192r1 (uint32_t const InData_IV[],
                                         uint32_t const InData_InstData[],
                                         uint32_t       OutData_KeyIndex[])
{
    return r_rsip_p1e(&gs_cmd_ecc_type[RSIP_ECC_TYPE_NIST],
                      &gs_cmd_ecc_key_length[RSIP_ECC_KEY_LENGTH_192],
                      InData_IV,
                      InData_InstData,
                      OutData_KeyIndex);
}

rsip_ret_t r_rsip_wrapper_p2c_secp224r1 (uint32_t const InData_IV[],
                                         uint32_t const InData_InstData[],
                                         uint32_t       OutData_KeyIndex[])
{
    return r_rsip_p2c(&gs_cmd_ecc_type[RSIP_ECC_TYPE_NIST],
                      &gs_cmd_ecc_key_length[RSIP_ECC_KEY_LENGTH_224],
                      InData_IV,
                      InData_InstData,
                      OutData_KeyIndex);
}

rsip_ret_t r_rsip_wrapper_p1e_secp224r1 (uint32_t const InData_IV[],
                                         uint32_t const InData_InstData[],
                                         uint32_t       OutData_KeyIndex[])
{
    return r_rsip_p1e(&gs_cmd_ecc_type[RSIP_ECC_TYPE_NIST],
                      &gs_cmd_ecc_key_length[RSIP_ECC_KEY_LENGTH_224],
                      InData_IV,
                      InData_InstData,
                      OutData_KeyIndex);
}

rsip_ret_t r_rsip_wrapper_p2c_secp256r1 (uint32_t const InData_IV[],
                                         uint32_t const InData_InstData[],
                                         uint32_t       OutData_KeyIndex[])
{
    return r_rsip_p2c(&gs_cmd_ecc_type[RSIP_ECC_TYPE_NIST],
                      &gs_cmd_ecc_key_length[RSIP_ECC_KEY_LENGTH_256],
                      InData_IV,
                      InData_InstData,
                      OutData_KeyIndex);
}

rsip_ret_t r_rsip_wrapper_p1e_secp256r1 (uint32_t const InData_IV[],
                                         uint32_t const InData_InstData[],
                                         uint32_t       OutData_KeyIndex[])
{
    return r_rsip_p1e(&gs_cmd_ecc_type[RSIP_ECC_TYPE_NIST],
                      &gs_cmd_ecc_key_length[RSIP_ECC_KEY_LENGTH_256],
                      InData_IV,
                      InData_InstData,
                      OutData_KeyIndex);
}

rsip_ret_t r_rsip_wrapper_p2c_brainpoolp256r1 (uint32_t const InData_IV[],
                                               uint32_t const InData_InstData[],
                                               uint32_t       OutData_KeyIndex[])
{
    return r_rsip_p2c(&gs_cmd_ecc_type[RSIP_ECC_TYPE_BRAINPOOL],
                      &gs_cmd_ecc_key_length[RSIP_ECC_KEY_LENGTH_256],
                      InData_IV,
                      InData_InstData,
                      OutData_KeyIndex);
}

rsip_ret_t r_rsip_wrapper_p1e_brainpoolp256r1 (uint32_t const InData_IV[],
                                               uint32_t const InData_InstData[],
                                               uint32_t       OutData_KeyIndex[])
{
    return r_rsip_p1e(&gs_cmd_ecc_type[RSIP_ECC_TYPE_BRAINPOOL],
                      &gs_cmd_ecc_key_length[RSIP_ECC_KEY_LENGTH_256],
                      InData_IV,
                      InData_InstData,
                      OutData_KeyIndex);
}

rsip_ret_t r_rsip_wrapper_p0f_hmac_sha1 (const uint32_t InData_IV[],
                                         const uint32_t InData_InstData[],
                                         uint32_t       OutData_KeyIndex[])
{
    return r_rsip_p0f(&gs_cmd_hmac_hash_type[HMAC_HASH_TYPE_SHA1], InData_IV, InData_InstData, OutData_KeyIndex);
}

rsip_ret_t r_rsip_wrapper_p0f_hmac_sha224 (const uint32_t InData_IV[],
                                           const uint32_t InData_InstData[],
                                           uint32_t       OutData_KeyIndex[])
{
    return r_rsip_p0f(&gs_cmd_hmac_hash_type[HMAC_HASH_TYPE_SHA224], InData_IV, InData_InstData, OutData_KeyIndex);
}

rsip_ret_t r_rsip_wrapper_p0f_hmac_sha256 (const uint32_t InData_IV[],
                                           const uint32_t InData_InstData[],
                                           uint32_t       OutData_KeyIndex[])
{
    return r_rsip_p0f(&gs_cmd_hmac_hash_type[HMAC_HASH_TYPE_SHA256], InData_IV, InData_InstData, OutData_KeyIndex);
}

rsip_ret_t r_rsip_wrapper_p48i_ecb_enc (const uint32_t InData_KeyIndex[], const uint32_t InData_IV[])
{
    return r_rsip_p48i(&gs_cmd_aes_mode[RSIP_AES_MODE_EXTENDED_ECB_ENCRYPT], InData_KeyIndex, InData_IV);
}

rsip_ret_t r_rsip_wrapper_p48i_ecb_dec (const uint32_t InData_KeyIndex[], const uint32_t InData_IV[])
{
    return r_rsip_p48i(&gs_cmd_aes_mode[RSIP_AES_MODE_EXTENDED_ECB_DECRYPT], InData_KeyIndex, InData_IV);
}

rsip_ret_t r_rsip_wrapper_p48i_cbc_enc (const uint32_t InData_KeyIndex[], const uint32_t InData_IV[])
{
    return r_rsip_p48i(&gs_cmd_aes_mode[RSIP_AES_MODE_EXTENDED_CBC_ENCRYPT], InData_KeyIndex, InData_IV);
}

rsip_ret_t r_rsip_wrapper_p48i_cbc_dec (const uint32_t InData_KeyIndex[], const uint32_t InData_IV[])
{
    return r_rsip_p48i(&gs_cmd_aes_mode[RSIP_AES_MODE_EXTENDED_CBC_DECRYPT], InData_KeyIndex, InData_IV);
}

rsip_ret_t r_rsip_wrapper_p48i_ctr (const uint32_t InData_KeyIndex[], const uint32_t InData_IV[])
{
    return r_rsip_p48i(&gs_cmd_aes_mode[RSIP_AES_MODE_EXTENDED_CTR_CRYPT], InData_KeyIndex, InData_IV);
}

rsip_ret_t r_rsip_wrapper_p50i_ecb_enc (const uint32_t InData_KeyIndex[], const uint32_t InData_IV[])
{
    return r_rsip_p50i(&gs_cmd_aes_mode[RSIP_AES_MODE_EXTENDED_ECB_ENCRYPT], InData_KeyIndex, InData_IV);
}

rsip_ret_t r_rsip_wrapper_p50i_ecb_dec (const uint32_t InData_KeyIndex[], const uint32_t InData_IV[])
{
    return r_rsip_p50i(&gs_cmd_aes_mode[RSIP_AES_MODE_EXTENDED_ECB_DECRYPT], InData_KeyIndex, InData_IV);
}

rsip_ret_t r_rsip_wrapper_p50i_cbc_enc (const uint32_t InData_KeyIndex[], const uint32_t InData_IV[])
{
    return r_rsip_p50i(&gs_cmd_aes_mode[RSIP_AES_MODE_EXTENDED_CBC_ENCRYPT], InData_KeyIndex, InData_IV);
}

rsip_ret_t r_rsip_wrapper_p50i_cbc_dec (const uint32_t InData_KeyIndex[], const uint32_t InData_IV[])
{
    return r_rsip_p50i(&gs_cmd_aes_mode[RSIP_AES_MODE_EXTENDED_CBC_DECRYPT], InData_KeyIndex, InData_IV);
}

rsip_ret_t r_rsip_wrapper_p50i_ctr (const uint32_t InData_KeyIndex[], const uint32_t InData_IV[])
{
    return r_rsip_p50i(&gs_cmd_aes_mode[RSIP_AES_MODE_EXTENDED_CTR_CRYPT], InData_KeyIndex, InData_IV);
}

rsip_ret_t r_rsip_wrapper_p41f_gen (const uint32_t InData_Text[], uint32_t OutData_DataT[], const uint32_t all_msg_len)
{
    uint32_t cmd[1] =
    {
        ((0 == (all_msg_len % 16)) &&
         (0 !=
          all_msg_len)) ? RSIP_PRV_CMD_AES_CMAC_GENERATE_WITHOUT_REMAINDER :
        RSIP_PRV_CMD_AES_CMAC_GENERATE_WITH_REMAINDER
    };

    return r_rsip_p41f(cmd, InData_Text, NULL, NULL, OutData_DataT);
}

rsip_ret_t r_rsip_wrapper_p44f_gen (const uint32_t InData_Text[], uint32_t OutData_DataT[], const uint32_t all_msg_len)
{
    uint32_t cmd[1] =
    {
        ((0 == (all_msg_len % 16)) &&
         (0 !=
          all_msg_len)) ? RSIP_PRV_CMD_AES_CMAC_GENERATE_WITHOUT_REMAINDER :
        RSIP_PRV_CMD_AES_CMAC_GENERATE_WITH_REMAINDER
    };

    return r_rsip_p44f(cmd, InData_Text, NULL, NULL, OutData_DataT);
}

rsip_ret_t r_rsip_wrapper_p41f_veri (const uint32_t InData_Text[],
                                     const uint32_t InData_DataT[],
                                     const uint32_t InData_DataTLen[],
                                     const uint32_t all_msg_len)
{
    uint32_t cmd[1] =
    {
        ((0 == (all_msg_len % 16)) &&
         (0 !=
          all_msg_len)) ? RSIP_PRV_CMD_AES_CMAC_VERIFY_WITHOUT_REMAINDER :
        RSIP_PRV_CMD_AES_CMAC_VERIFY_WITH_REMAINDER
    };

    return r_rsip_p41f(cmd, InData_Text, InData_DataT, InData_DataTLen, NULL);
}

rsip_ret_t r_rsip_wrapper_p44f_veri (const uint32_t InData_Text[],
                                     const uint32_t InData_DataT[],
                                     const uint32_t InData_DataTLen[],
                                     const uint32_t all_msg_len)
{
    uint32_t cmd[1] =
    {
        ((0 == (all_msg_len % 16)) &&
         (0 !=
          all_msg_len)) ? RSIP_PRV_CMD_AES_CMAC_VERIFY_WITHOUT_REMAINDER :
        RSIP_PRV_CMD_AES_CMAC_VERIFY_WITH_REMAINDER
    };

    return r_rsip_p44f(cmd, InData_Text, InData_DataT, InData_DataTLen, NULL);
}

rsip_ret_t r_rsip_wrapper_pf0_secp192r1 (const uint32_t InData_KeyIndex[],
                                         const uint32_t InData_MsgDgst[],
                                         uint32_t       OutData_Signature[])
{
    return r_rsip_pf0(&gs_cmd_ecc_type[RSIP_ECC_TYPE_NIST],
                      &gs_cmd_ecc_key_length[RSIP_ECC_KEY_LENGTH_192],
                      InData_KeyIndex,
                      InData_MsgDgst,
                      OutData_Signature);
}

rsip_ret_t r_rsip_wrapper_pf1_secp192r1 (const uint32_t InData_KeyIndex[],
                                         const uint32_t InData_MsgDgst[],
                                         const uint32_t InData_Signature[])
{
    return r_rsip_pf1(&gs_cmd_ecc_type[RSIP_ECC_TYPE_NIST],
                      &gs_cmd_ecc_key_length[RSIP_ECC_KEY_LENGTH_192],
                      InData_KeyIndex,
                      InData_MsgDgst,
                      InData_Signature);
}

rsip_ret_t r_rsip_wrapper_pf0_secp224r1 (const uint32_t InData_KeyIndex[],
                                         const uint32_t InData_MsgDgst[],
                                         uint32_t       OutData_Signature[])
{
    return r_rsip_pf0(&gs_cmd_ecc_type[RSIP_ECC_TYPE_NIST],
                      &gs_cmd_ecc_key_length[RSIP_ECC_KEY_LENGTH_224],
                      InData_KeyIndex,
                      InData_MsgDgst,
                      OutData_Signature);
}

rsip_ret_t r_rsip_wrapper_pf1_secp224r1 (const uint32_t InData_KeyIndex[],
                                         const uint32_t InData_MsgDgst[],
                                         const uint32_t InData_Signature[])
{
    return r_rsip_pf1(&gs_cmd_ecc_type[RSIP_ECC_TYPE_NIST],
                      &gs_cmd_ecc_key_length[RSIP_ECC_KEY_LENGTH_224],
                      InData_KeyIndex,
                      InData_MsgDgst,
                      InData_Signature);
}

rsip_ret_t r_rsip_wrapper_pf0_secp256r1 (const uint32_t InData_KeyIndex[],
                                         const uint32_t InData_MsgDgst[],
                                         uint32_t       OutData_Signature[])
{
    return r_rsip_pf0(&gs_cmd_ecc_type[RSIP_ECC_TYPE_NIST],
                      &gs_cmd_ecc_key_length[RSIP_ECC_KEY_LENGTH_256],
                      InData_KeyIndex,
                      InData_MsgDgst,
                      OutData_Signature);
}

rsip_ret_t r_rsip_wrapper_pf1_secp256r1 (const uint32_t InData_KeyIndex[],
                                         const uint32_t InData_MsgDgst[],
                                         const uint32_t InData_Signature[])
{
    return r_rsip_pf1(&gs_cmd_ecc_type[RSIP_ECC_TYPE_NIST],
                      &gs_cmd_ecc_key_length[RSIP_ECC_KEY_LENGTH_256],
                      InData_KeyIndex,
                      InData_MsgDgst,
                      InData_Signature);
}

rsip_ret_t r_rsip_wrapper_pf0_brainpoolp256r1 (const uint32_t InData_KeyIndex[],
                                               const uint32_t InData_MsgDgst[],
                                               uint32_t       OutData_Signature[])
{
    return r_rsip_pf0(&gs_cmd_ecc_type[RSIP_ECC_TYPE_BRAINPOOL],
                      &gs_cmd_ecc_key_length[RSIP_ECC_KEY_LENGTH_256],
                      InData_KeyIndex,
                      InData_MsgDgst,
                      OutData_Signature);
}

rsip_ret_t r_rsip_wrapper_pf1_brainpoolp256r1 (const uint32_t InData_KeyIndex[],
                                               const uint32_t InData_MsgDgst[],
                                               const uint32_t InData_Signature[])
{
    return r_rsip_pf1(&gs_cmd_ecc_type[RSIP_ECC_TYPE_BRAINPOOL],
                      &gs_cmd_ecc_key_length[RSIP_ECC_KEY_LENGTH_256],
                      InData_KeyIndex,
                      InData_MsgDgst,
                      InData_Signature);
}

rsip_ret_t r_rsip_wrapper_pfa_secp192r1 (const uint32_t InData_SharedKeyNum[],
                                         const uint32_t InData_SharedKeyIndex[],
                                         const uint32_t InData_SessionKey[],
                                         const uint32_t InData_IV[],
                                         const uint32_t InData_InstData[],
                                         uint32_t       OutData_KeyIndex[])
{
    return r_rsip_pfa(InData_SharedKeyNum,
                      InData_SharedKeyIndex,
                      InData_SessionKey,
                      &gs_cmd_ecc_type[RSIP_ECC_TYPE_NIST],
                      &gs_cmd_ecc_key_length[RSIP_ECC_KEY_LENGTH_192],
                      InData_IV,
                      InData_InstData,
                      OutData_KeyIndex);
}

rsip_ret_t r_rsip_wrapper_pf3_secp192r1 (const uint32_t InData_SharedKeyNum[],
                                         const uint32_t InData_SharedKeyIndex[],
                                         const uint32_t InData_SessionKey[],
                                         const uint32_t InData_IV[],
                                         const uint32_t InData_InstData[],
                                         uint32_t       OutData_KeyIndex[])
{
    return r_rsip_pf3(InData_SharedKeyNum,
                      InData_SharedKeyIndex,
                      InData_SessionKey,
                      &gs_cmd_ecc_type[RSIP_ECC_TYPE_NIST],
                      &gs_cmd_ecc_key_length[RSIP_ECC_KEY_LENGTH_192],
                      InData_IV,
                      InData_InstData,
                      OutData_KeyIndex);
}

rsip_ret_t r_rsip_wrapper_pfa_secp224r1 (const uint32_t InData_SharedKeyNum[],
                                         const uint32_t InData_SharedKeyIndex[],
                                         const uint32_t InData_SessionKey[],
                                         const uint32_t InData_IV[],
                                         const uint32_t InData_InstData[],
                                         uint32_t       OutData_KeyIndex[])
{
    return r_rsip_pfa(InData_SharedKeyNum,
                      InData_SharedKeyIndex,
                      InData_SessionKey,
                      &gs_cmd_ecc_type[RSIP_ECC_TYPE_NIST],
                      &gs_cmd_ecc_key_length[RSIP_ECC_KEY_LENGTH_224],
                      InData_IV,
                      InData_InstData,
                      OutData_KeyIndex);
}

rsip_ret_t r_rsip_wrapper_pf3_secp224r1 (const uint32_t InData_SharedKeyNum[],
                                         const uint32_t InData_SharedKeyIndex[],
                                         const uint32_t InData_SessionKey[],
                                         const uint32_t InData_IV[],
                                         const uint32_t InData_InstData[],
                                         uint32_t       OutData_KeyIndex[])
{
    return r_rsip_pf3(InData_SharedKeyNum,
                      InData_SharedKeyIndex,
                      InData_SessionKey,
                      &gs_cmd_ecc_type[RSIP_ECC_TYPE_NIST],
                      &gs_cmd_ecc_key_length[RSIP_ECC_KEY_LENGTH_224],
                      InData_IV,
                      InData_InstData,
                      OutData_KeyIndex);
}

rsip_ret_t r_rsip_wrapper_pfa_secp256r1 (const uint32_t InData_SharedKeyNum[],
                                         const uint32_t InData_SharedKeyIndex[],
                                         const uint32_t InData_SessionKey[],
                                         const uint32_t InData_IV[],
                                         const uint32_t InData_InstData[],
                                         uint32_t       OutData_KeyIndex[])
{
    return r_rsip_pfa(InData_SharedKeyNum,
                      InData_SharedKeyIndex,
                      InData_SessionKey,
                      &gs_cmd_ecc_type[RSIP_ECC_TYPE_NIST],
                      &gs_cmd_ecc_key_length[RSIP_ECC_KEY_LENGTH_256],
                      InData_IV,
                      InData_InstData,
                      OutData_KeyIndex);
}

rsip_ret_t r_rsip_wrapper_pf3_secp256r1 (const uint32_t InData_SharedKeyNum[],
                                         const uint32_t InData_SharedKeyIndex[],
                                         const uint32_t InData_SessionKey[],
                                         const uint32_t InData_IV[],
                                         const uint32_t InData_InstData[],
                                         uint32_t       OutData_KeyIndex[])
{
    return r_rsip_pf3(InData_SharedKeyNum,
                      InData_SharedKeyIndex,
                      InData_SessionKey,
                      &gs_cmd_ecc_type[RSIP_ECC_TYPE_NIST],
                      &gs_cmd_ecc_key_length[RSIP_ECC_KEY_LENGTH_256],
                      InData_IV,
                      InData_InstData,
                      OutData_KeyIndex);
}

rsip_ret_t r_rsip_wrapper_pfa_brainpoolp256r1 (const uint32_t InData_SharedKeyNum[],
                                               const uint32_t InData_SharedKeyIndex[],
                                               const uint32_t InData_SessionKey[],
                                               const uint32_t InData_IV[],
                                               const uint32_t InData_InstData[],
                                               uint32_t       OutData_KeyIndex[])
{
    return r_rsip_pfa(InData_SharedKeyNum,
                      InData_SharedKeyIndex,
                      InData_SessionKey,
                      &gs_cmd_ecc_type[RSIP_ECC_TYPE_BRAINPOOL],
                      &gs_cmd_ecc_key_length[RSIP_ECC_KEY_LENGTH_256],
                      InData_IV,
                      InData_InstData,
                      OutData_KeyIndex);
}

rsip_ret_t r_rsip_wrapper_pf3_brainpoolp256r1 (const uint32_t InData_SharedKeyNum[],
                                               const uint32_t InData_SharedKeyIndex[],
                                               const uint32_t InData_SessionKey[],
                                               const uint32_t InData_IV[],
                                               const uint32_t InData_InstData[],
                                               uint32_t       OutData_KeyIndex[])
{
    return r_rsip_pf3(InData_SharedKeyNum,
                      InData_SharedKeyIndex,
                      InData_SessionKey,
                      &gs_cmd_ecc_type[RSIP_ECC_TYPE_BRAINPOOL],
                      &gs_cmd_ecc_key_length[RSIP_ECC_KEY_LENGTH_256],
                      InData_IV,
                      InData_InstData,
                      OutData_KeyIndex);
}

rsip_ret_t r_rsip_wrapper_p80_hmac_sha1 (const uint32_t InData_SharedKeyNum[],
                                         const uint32_t InData_SharedKeyIndex[],
                                         const uint32_t InData_SessionKey[],
                                         const uint32_t InData_IV[],
                                         const uint32_t InData_InstData[],
                                         uint32_t       OutData_KeyIndex[])
{
    return r_rsip_p80(InData_SharedKeyNum, InData_SharedKeyIndex, InData_SessionKey,
                      &gs_cmd_hmac_hash_type[HMAC_HASH_TYPE_SHA1], InData_IV, InData_InstData, OutData_KeyIndex);
}

rsip_ret_t r_rsip_wrapper_p80_hmac_sha224 (const uint32_t InData_SharedKeyNum[],
                                           const uint32_t InData_SharedKeyIndex[],
                                           const uint32_t InData_SessionKey[],
                                           const uint32_t InData_IV[],
                                           const uint32_t InData_InstData[],
                                           uint32_t       OutData_KeyIndex[])
{
    return r_rsip_p80(InData_SharedKeyNum, InData_SharedKeyIndex, InData_SessionKey,
                      &gs_cmd_hmac_hash_type[HMAC_HASH_TYPE_SHA224], InData_IV, InData_InstData, OutData_KeyIndex);
}

rsip_ret_t r_rsip_wrapper_p80_hmac_sha256 (const uint32_t InData_SharedKeyNum[],
                                           const uint32_t InData_SharedKeyIndex[],
                                           const uint32_t InData_SessionKey[],
                                           const uint32_t InData_IV[],
                                           const uint32_t InData_InstData[],
                                           uint32_t       OutData_KeyIndex[])
{
    return r_rsip_p80(InData_SharedKeyNum, InData_SharedKeyIndex, InData_SessionKey,
                      &gs_cmd_hmac_hash_type[HMAC_HASH_TYPE_SHA256], InData_IV, InData_InstData, OutData_KeyIndex);
}

rsip_ret_t r_rsip_wrapper_p15_jtag_level1 (const uint32_t InData_SharedKeyNum[],
                                           const uint32_t InData_SharedKeyIndex[],
                                           const uint32_t InData_SessionKey[],
                                           const uint32_t InData_IV[],
                                           const uint32_t InData_EncAuthData[],
                                           uint32_t       OutData_Hash[])
{
    static const uint32_t InData_HashType[1] =
    {
        RSIP_PRV_CMD_PASSWORD_TYPE_JTAG_DEBUG_AUTH_LEVEL1
    };

    return r_rsip_p15(InData_SharedKeyNum,
                      InData_SharedKeyIndex,
                      InData_SessionKey,
                      InData_IV,
                      InData_EncAuthData,
                      InData_HashType,
                      OutData_Hash);
}

rsip_ret_t r_rsip_wrapper_p15_jtag_level2 (const uint32_t InData_SharedKeyNum[],
                                           const uint32_t InData_SharedKeyIndex[],
                                           const uint32_t InData_SessionKey[],
                                           const uint32_t InData_IV[],
                                           const uint32_t InData_EncAuthData[],
                                           uint32_t       OutData_Hash[])
{
    static const uint32_t InData_HashType[1] =
    {
        RSIP_PRV_CMD_PASSWORD_TYPE_JTAG_DEBUG_AUTH_LEVEL2
    };

    return r_rsip_p15(InData_SharedKeyNum,
                      InData_SharedKeyIndex,
                      InData_SessionKey,
                      InData_IV,
                      InData_EncAuthData,
                      InData_HashType,
                      OutData_Hash);
}

/***********************************************************************************************************************
 * Private Functions
 **********************************************************************************************************************/
