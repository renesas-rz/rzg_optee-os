/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2024, Renesas Electronics Corporation
 */

#ifndef R_RSIP_PRIVATE_H
#define R_RSIP_PRIVATE_H

/***********************************************************************************************************************
 * Includes
 **********************************************************************************************************************/
#include "r_rsip.h"
#include "r_rsip_err.h"
#include "r_rsip_util.h"

/***********************************************************************************************************************
 * Macro definitions
 **********************************************************************************************************************/

/* Internal handle base number */
#define RSIP_PRV_XTS_HANDLE_BASE    (RSIP_HANDLE_TYPE_XTS_ENCRYPT)
#define RSIP_PRV_GCM_HANDLE_BASE    (RSIP_HANDLE_TYPE_GCM_ENCRYPT)

/* Rebase handle type */
#define RSIP_PRV_XTS_HANDLE_REBASE(handle_type)    ((handle_type) - (RSIP_PRV_XTS_HANDLE_BASE))
#define RSIP_PRV_GCM_HANDLE_REBASE(handle_type)    ((handle_type) - (RSIP_PRV_GCM_HANDLE_BASE))

/* Internal key type base number */
#define RSIP_PRV_AES_BASE     (RSIP_KEY_TYPE_AES_128)
#define RSIP_PRV_XTS_BASE     (RSIP_KEY_TYPE_AES_128_XTS)
#define RSIP_PRV_ECC_BASE     (RSIP_KEY_TYPE_ECC_secp192r1_PUBLIC)
#define RSIP_PRV_RSA_BASE     (RSIP_KEY_TYPE_RSA_1024_PUBLIC_ENHANCED)
#define RSIP_PRV_HMAC_BASE    (RSIP_KEY_TYPE_HMAC_SHA1)

/* Rebase key type */
#define RSIP_PRV_AES_REBASE(key_type)     ((key_type) - (RSIP_PRV_AES_BASE))
#define RSIP_PRV_XTS_REBASE(key_type)     ((key_type) - (RSIP_PRV_XTS_BASE))
#define RSIP_PRV_ECC_REBASE(key_type)     ((key_type) - (RSIP_PRV_ECC_BASE))
#define RSIP_PRV_RSA_REBASE(key_type)     ((key_type) - (RSIP_PRV_RSA_BASE))
#define RSIP_PRV_HMAC_REBASE(key_type)    ((key_type) - (RSIP_PRV_HMAC_BASE))

/***********************************************************************************************************************
 * Typedef definitions
 **********************************************************************************************************************/

/* Bool tables of key (pair) type */
typedef bool rsip_key_type_bool_table_t[RSIP_KEY_TYPE_NUM];
typedef bool rsip_key_pair_type_bool_table_t[RSIP_KEY_PAIR_TYPE_NUM];

/*
 * Private/Primitive functions
 */

/* Random number generation */
typedef rsip_ret_t (* rsip_func_random_number_generate_t)(uint32_t OutData_Text[]);

/* Key generation */
typedef rsip_ret_t (* rsip_func_key_generate_t)(uint32_t OutData_KeyIndex[]);

/* Key pair generation */
typedef rsip_ret_t (* rsip_func_key_pair_generate_t)(uint32_t OutData_PubKeyIndex[], uint32_t OutData_PrivKeyIndex[]);

/* Key import with KUK */
typedef rsip_ret_t (* rsip_func_key_import_with_kuk_t)(const uint32_t InData_IV[], const uint32_t InData_InstData[],
                                                       uint32_t OutData_KeyIndex[]);

/* AES-ECB/CBC/CTR */
typedef rsip_ret_t (* rsip_func_aes_init_t)(const uint32_t InData_KeyIndex[], const uint32_t InData_IV[]);

/* AES-GCM */
typedef rsip_ret_t (* rsip_func_ghash_t)(const uint32_t InData_HV[], const uint32_t InData_IV[],
                                         const uint32_t InData_Text[], uint32_t OutData_DataT[], uint32_t MAX_CNT);

/* ECC */
typedef rsip_ret_t (* rsip_func_ecdsa_sign_t)(const uint32_t InData_KeyIndex[], const uint32_t InData_MsgDgst[],
                                              uint32_t OutData_Signature[]);
typedef rsip_ret_t (* rsip_func_ecdsa_verify_t)(const uint32_t InData_KeyIndex[], const uint32_t InData_MsgDgst[],
                                                const uint32_t InData_Signature[]);

/* RSA */
typedef rsip_ret_t (* rsip_func_rsa_t)(const uint32_t InData_KeyIndex[], const uint32_t InData_Text[],
                                       uint32_t OutData_Text[]);

/* HMAC */
typedef rsip_ret_t (* rsip_func_hmac_single_t)(const uint32_t InData_KeyIndex[], const uint32_t InData_Cmd[],
                                               const uint32_t InData_Msg[], const uint32_t InData_MsgLen[],
                                               const uint32_t InData_MAC[],
                                               const uint32_t InData_length[], uint32_t MAX_CNT,
                                               uint32_t OutData_MAC[]);
typedef rsip_ret_t (* rsip_func_hmac_multi_t)(const uint32_t InData_KeyIndex[], const uint32_t InData_Cmd[],
                                              const uint32_t InData_Msg[], const uint32_t InData_MsgLen[],
                                              const uint32_t InData_MAC[],
                                              const uint32_t InData_length[], const uint32_t InData_State[],
                                              uint32_t MAX_CNT, uint32_t OutData_MAC[],
                                              uint32_t OutData_State[]);

/*
 * Private/Primitive function subsets
 */

/* AES-ECB/CBC/CTR */
typedef struct st_rsip_func_subset_aes
{
    rsip_func_aes_init_t p_init[3][2];
    void (* p_update)(const uint32_t * InData_Text, uint32_t * OutData_Text, uint32_t MAX_CNT);
    rsip_ret_t (* p_final)();
} rsip_func_subset_aes_t;

/* AES-XTS */
typedef struct st_rsip_func_subset_xts
{
    rsip_ret_t (* p_init)(const uint32_t * InData_KeyIndex, const uint32_t * InData_IV);
    void (* p_update)(const uint32_t * InData_Text, uint32_t * OutData_Text, uint32_t MAX_CNT);
    rsip_ret_t (* p_final)(const uint32_t * InData_TextBitLen, const uint32_t * InData_Text, uint32_t * OutData_Text);
} rsip_func_subset_xts_t;

/* AES-GCM */
typedef struct st_rsip_func_subset_gcm
{
    rsip_ret_t (* p_init)(const uint32_t * InData_KeyIndex, const uint32_t * InData_IV);
    void (* p_updateAad)(const uint32_t * InData_DataA, uint32_t MAX_CNT);
    void (* p_updateTransition)();
    void (* p_update)(const uint32_t * InData_Text, uint32_t * OutData_Text, uint32_t MAX_CNT);
    rsip_ret_t (* p_encryptFinal)(const uint32_t * InData_Text, const uint32_t * InData_DataALen,
                                  const uint32_t * InData_TextLen, uint32_t * OutData_Text, uint32_t * OutData_DataT);
    rsip_ret_t (* p_decryptFinal)(const uint32_t * InData_Text, const uint32_t * InData_DataT,
                                  const uint32_t * InData_DataALen, const uint32_t * InData_TextLen,
                                  const uint32_t * InData_DataTLen,
                                  uint32_t * OutData_Text);
    const rsip_func_subset_aes_t * p_ecb;
} rsip_func_subset_gcm_t;

/* AES-CMAC */
typedef struct st_rsip_func_subset_cmac
{
    rsip_ret_t (* p_init)(const uint32_t * InData_KeyIndex);
    void (* p_update)(const uint32_t * InData_Text, uint32_t MAX_CNT);
    rsip_ret_t (* p_generateFinal)(const uint32_t * InData_Text, uint32_t * OutData_DataT, const uint32_t all_msg_len);
    rsip_ret_t (* p_verifyFinal)(const uint32_t * InData_Text, const uint32_t * InData_DataT,
                                 const uint32_t * InData_DataTLen, const uint32_t all_msg_len);
} rsip_func_subset_cmac_t;

/**********************************************************************************************************************
 * Exported global variables
 **********************************************************************************************************************/

/* Bool tables of key (pair) type */
extern const rsip_key_type_bool_table_t      g_key_generate_supported_algs;
extern const rsip_key_type_bool_table_t      g_key_import_with_kuk_supported_algs;
extern const rsip_key_pair_type_bool_table_t g_key_pair_generate_supported_algs;

/* Private/Primitive function subset tables */
extern const rsip_func_subset_aes_t  gp_func_aes[];
extern const rsip_func_subset_xts_t  gp_func_xts[][2];
extern const rsip_func_subset_gcm_t  gp_func_gcm[][2];
extern const rsip_func_subset_cmac_t gp_func_cmac[];

/* Private/Primitive function tables */
extern const rsip_func_key_generate_t        gp_func_key_generate[];
extern const rsip_func_key_pair_generate_t   gp_func_key_pair_generate[];
extern const rsip_func_key_import_with_kuk_t gp_func_key_import_with_kuk[];
extern const rsip_func_ecdsa_sign_t          gp_func_ecdsa_sign[];
extern const rsip_func_ecdsa_verify_t        gp_func_ecdsa_verify[];
extern const rsip_func_rsa_t                 gp_func_rsa_public[];
extern const rsip_func_rsa_t                 gp_func_rsa_private[];
extern const rsip_func_hmac_single_t         gp_func_hmac_single[];
extern const rsip_func_hmac_multi_t          gp_func_hmac_multi[];

/* Discrete private/primitive functions */
extern const rsip_func_random_number_generate_t gp_func_random_number_generate;
extern const rsip_func_ghash_t gp_func_ghash_compute;

/**********************************************************************************************************************
 * Public Function Prototypes
 **********************************************************************************************************************/

/*******************************************************************************************************************//**
 * Initializes the RSIP engine.
 *
 * @return The return value of the internally called primitive functions.
 **********************************************************************************************************************/
rsip_ret_t r_rsip_open(void);

/*******************************************************************************************************************//**
 * Finalizes the RSIP engine.
 *
 * @return The return value of the internally called primitive functions.
 **********************************************************************************************************************/
rsip_ret_t r_rsip_close(void);

/*******************************************************************************************************************//**
 * Stores input Key Update Key (KUK).
 *
 * @param[in] p_key_update_key_value KUK value.
 **********************************************************************************************************************/
void r_rsip_kuk_store(const uint8_t * p_key_update_key_value);

/*******************************************************************************************************************//**
 * Computes SHA-1 or SHA-2 message digest in single-part operation.
 *
 * @param[in]  InData_Msg        Big-endian message.
 * @param[out] OutData_MsgDigest Big-endian message digest.
 * @param[in]  hash_type         Generating hash type.
 * @param[in]  message_length    Byte size of message.
 *
 * @return The return value of the internally called primitive function.
 **********************************************************************************************************************/
rsip_ret_t r_rsip_sha1sha2_compute_single(const uint32_t   InData_Msg[],
                                          uint32_t         OutData_MsgDigest[],
                                          rsip_hash_type_t hash_type,
                                          uint32_t         message_length);

/*******************************************************************************************************************//**
 * Computes HMAC message digest in single-part operation.
 *
 * @param[in]  InData_Msg     Big-endian message.
 * @param[out] OutData_MAC    Big-endian MAC.
 * @param[in]  p_func         Private/Primitive function.
 * @param[in]  p_wrapped_key  Wrapped HMAC key.
 * @param[in]  message_length Byte size of message.
 *
 * @return The return value of the internally called primitive function.
 **********************************************************************************************************************/
rsip_ret_t r_rsip_hmac_compute_single(const uint32_t                InData_Msg[],
                                      uint32_t                      OutData_MAC[],
                                      const rsip_func_hmac_single_t p_func,
                                      const rsip_wrapped_key_t    * p_wrapped_key,
                                      uint32_t                      message_length);

/*******************************************************************************************************************//**
 * Verifies HMAC message digest in single-part operation.
 *
 * @param[in] InData_Msg     Big-endian message.
 * @param[in] p_mac          Big-endian MAC.
 * @param[in] p_func         Private/Primitive function.
 * @param[in] p_wrapped_key  Wrapped HMAC key.
 * @param[in] message_length Byte size of message.
 * @param[in] mac_length     Byte size of MAC.
 *
 * @return The return value of the internally called primitive function.
 **********************************************************************************************************************/
rsip_ret_t r_rsip_hmac_verify_single(const uint32_t                InData_Msg[],
                                     const uint8_t               * p_mac,
                                     const rsip_func_hmac_single_t p_func,
                                     const rsip_wrapped_key_t    * p_wrapped_key,
                                     uint32_t                      message_length,
                                     uint32_t                      mac_length);

/*******************************************************************************************************************//**
 * Computes SHA-1 or SHA-2 message digest in multi-part operation.
 *
 * @param[in,out] p_handle       User handle.
 * @param[in]     p_message      Big-endian message.
 * @param[in]     message_length Byte size of message.
 * @param[out]    p_digest       Big-endian message digest.
 *                               If it is NULL, the calculation will be suspend.
 *                               Otherwise, the calculation is finalized.
 *
 * @return The return value of the internally called primitive function.
 **********************************************************************************************************************/
rsip_ret_t r_rsip_sha1sha2_calc_multi(rsip_sha_handle_t * p_handle,
                                      const uint8_t     * p_message,
                                      uint32_t            message_length,
                                      uint8_t           * p_digest);

/*******************************************************************************************************************//**
 * Computes or Verifies HMAC in multi-part operation.
 *
 * @param[in,out] p_handle       User handle.
 * @param[in]     p_message      Big-endian message.
 * @param[in]     message_length Byte size of message.
 * @param[in,out] p_mac          Big-endian MAC. For computation finalization, it is output data;
 *                               for verification finalization, it is input data.
 * @param[in]     mac_length     Byte size of MAC. This value is input only verification finalization.
 * @param[in]     is_final       If it is false, the calculation will be suspend.
 *                               Otherwise, the calculation is finalized.
 *
 * @return The return value of the internally called primitive function.
 **********************************************************************************************************************/
rsip_ret_t r_rsip_hmac_calc_multi(rsip_hmac_handle_t * p_handle,
                                  const uint8_t      * p_message,
                                  uint32_t             message_length,
                                  uint8_t            * p_mac,
                                  uint32_t             mac_length,
                                  bool                 is_final);

/*******************************************************************************************************************//**
 * Converts byte data to word (4-byte) and rounds up it.
 ***********************************************************************************************************************/
RSIP_PRV_STATIC_INLINE uint32_t r_rsip_byte_to_word_convert (const uint32_t bytes)
{
    return (bytes + 3) >> 2;
}

/*******************************************************************************************************************//**
 * Converts byte data to bit data. This function returns upper 3 digits.
 ***********************************************************************************************************************/
RSIP_PRV_STATIC_INLINE uint32_t r_rsip_byte_to_bit_convert_upper (const uint64_t bytes)
{
    return (uint32_t) (bytes >> 29);
}

/*******************************************************************************************************************//**
 * Converts byte data to bit data. This function returns lower 32 digits.
 ***********************************************************************************************************************/
RSIP_PRV_STATIC_INLINE uint32_t r_rsip_byte_to_bit_convert_lower (const uint64_t bytes)
{
    return (uint32_t) (bytes << 3);
}

#endif                                 /* R_RSIP_PRIVATE_H */
