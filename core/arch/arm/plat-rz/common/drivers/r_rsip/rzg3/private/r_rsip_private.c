// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2024, Renesas Electronics Corporation
 */

/***********************************************************************************************************************
 * Includes
 **********************************************************************************************************************/
#include "r_rsip_private.h"
#include "r_rsip_primitive.h"
#include "r_rsip_wrapper.h"
#include "r_rsip_util.h"
#include "r_rsip_reg.h"

/***********************************************************************************************************************
 * Macro definitions
 **********************************************************************************************************************/

/* For SHA, HMAC-SHA */
#define RSIP_PRV_SHA_INIT_VAL1                (BSWAP_32BIG_C(0x80000000U))
#define RSIP_PRV_SHA_INIT_VAL2                (BSWAP_32BIG_C(0x00000000U))
#define RSIP_PRV_CMD_INIT_TO_FINAL            (BSWAP_32BIG_C(0U))
#define RSIP_PRV_CMD_INIT_TO_SUSPEND          (BSWAP_32BIG_C(1U))
#define RSIP_PRV_CMD_RESUME_TO_SUSPEND        (BSWAP_32BIG_C(2U))
#define RSIP_PRV_CMD_RESUME_TO_FINAL          (BSWAP_32BIG_C(3U))
#define RSIP_PRV_CMD_INIT_TO_COMP_FINAL       (BSWAP_32BIG_C(4U))
#define RSIP_PRV_CMD_RESUME_TO_COMP_FINAL     (BSWAP_32BIG_C(5U))
#define RSIP_PRV_CMD_OUTPUT                   (BSWAP_32BIG_C(0U))
#define RSIP_PRV_CMD_COMPARE                  (BSWAP_32BIG_C(1U))
#define RSIP_PRV_CMD_SHA_1                    (BSWAP_32BIG_C(0U))
#define RSIP_PRV_CMD_SHA_224                  (BSWAP_32BIG_C(1U))
#define RSIP_PRV_CMD_SHA_256                  (BSWAP_32BIG_C(2U))
#define RSIP_PRV_CMD_SHA_384                  (BSWAP_32BIG_C(5U))
#define RSIP_PRV_CMD_SHA_512                  (BSWAP_32BIG_C(6U))
#define RSIP_PRV_CMD_SHA_512_224              (BSWAP_32BIG_C(3U))
#define RSIP_PRV_CMD_SHA_512_256              (BSWAP_32BIG_C(4U))
#define RSIP_PRV_WORD_SIZE_HMAC_MAC_BUFFER    (8U)

/* Register value */
#define RSIP_PRV_REG_142CH_OPEN               (0x00009000U)

/***********************************************************************************************************************
 * Typedef definitions
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Private function prototypes
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Private global variables
 **********************************************************************************************************************/

static const uint32_t gs_cmd_hash_type[] =
{
    [RSIP_HASH_TYPE_SHA1]       = RSIP_PRV_CMD_SHA_1,
    [RSIP_HASH_TYPE_SHA224]     = RSIP_PRV_CMD_SHA_224,
    [RSIP_HASH_TYPE_SHA256]     = RSIP_PRV_CMD_SHA_256,
    [RSIP_HASH_TYPE_SHA384]     = RSIP_PRV_CMD_SHA_384,
    [RSIP_HASH_TYPE_SHA512]     = RSIP_PRV_CMD_SHA_512,
    [RSIP_HASH_TYPE_SHA512_224] = RSIP_PRV_CMD_SHA_512_224,
    [RSIP_HASH_TYPE_SHA512_256] = RSIP_PRV_CMD_SHA_512_256,
};

/***********************************************************************************************************************
 * Global variables
 **********************************************************************************************************************/

const rsip_key_type_bool_table_t g_key_generate_supported_algs =
{
    [RSIP_KEY_TYPE_AES_128]     = true,
    [RSIP_KEY_TYPE_AES_256]     = true,
    [RSIP_KEY_TYPE_AES_128_XTS] = true,
    [RSIP_KEY_TYPE_AES_256_XTS] = true
};

const rsip_key_type_bool_table_t g_key_import_with_kuk_supported_algs =
{
    [RSIP_KEY_TYPE_AES_128]                     = true,
    [RSIP_KEY_TYPE_AES_256]                     = true,
    [RSIP_KEY_TYPE_AES_128_XTS]                 = true,
    [RSIP_KEY_TYPE_AES_256_XTS]                 = true,
    [RSIP_KEY_TYPE_ECC_secp192r1_PUBLIC]        = true,
    [RSIP_KEY_TYPE_ECC_secp192r1_PRIVATE]       = true,
    [RSIP_KEY_TYPE_ECC_secp224r1_PUBLIC]        = true,
    [RSIP_KEY_TYPE_ECC_secp224r1_PRIVATE]       = true,
    [RSIP_KEY_TYPE_ECC_secp256r1_PUBLIC]        = true,
    [RSIP_KEY_TYPE_ECC_secp256r1_PRIVATE]       = true,
    [RSIP_KEY_TYPE_ECC_BRAINPOOLP256R1_PUBLIC]  = true,
    [RSIP_KEY_TYPE_ECC_BRAINPOOLP256R1_PRIVATE] = true,
    [RSIP_KEY_TYPE_RSA_1024_PUBLIC_ENHANCED]    = true,
    [RSIP_KEY_TYPE_RSA_1024_PRIVATE_ENHANCED]   = true,
    [RSIP_KEY_TYPE_RSA_2048_PUBLIC_ENHANCED]    = true,
    [RSIP_KEY_TYPE_RSA_2048_PRIVATE_ENHANCED]   = true,
    [RSIP_KEY_TYPE_RSA_3072_PUBLIC]             = true,
    [RSIP_KEY_TYPE_RSA_3072_PRIVATE]            = true,
    [RSIP_KEY_TYPE_RSA_4096_PUBLIC]             = true,
    [RSIP_KEY_TYPE_RSA_4096_PRIVATE]            = true,
    [RSIP_KEY_TYPE_HMAC_SHA1]                   = true,
    [RSIP_KEY_TYPE_HMAC_SHA224]                 = true,
    [RSIP_KEY_TYPE_HMAC_SHA256]                 = true
};

const rsip_key_pair_type_bool_table_t g_key_pair_generate_supported_algs =
{
    [RSIP_KEY_PAIR_TYPE_ECC_secp192r1]       = true,
    [RSIP_KEY_PAIR_TYPE_ECC_secp224r1]       = true,
    [RSIP_KEY_PAIR_TYPE_ECC_secp256r1]       = true,
    [RSIP_KEY_PAIR_TYPE_ECC_BRAINPOOLP256R1] = true,
    [RSIP_KEY_PAIR_TYPE_RSA_1024]            = true,
    [RSIP_KEY_PAIR_TYPE_RSA_2048]            = true,
    [RSIP_KEY_PAIR_TYPE_RSA_3072]            = true,
    [RSIP_KEY_PAIR_TYPE_RSA_4096]            = true,
};

const rsip_func_key_generate_t gp_func_key_generate[] =
{
#if RSIP_CFG_KEY_GENERATE_AES_128_ENABLE
    [RSIP_KEY_TYPE_AES_128] = r_rsip_p07,
#else
    [RSIP_KEY_TYPE_AES_128] = NULL,
#endif
#if RSIP_CFG_KEY_GENERATE_AES_256_ENABLE
    [RSIP_KEY_TYPE_AES_256] = r_rsip_p08,
#else
    [RSIP_KEY_TYPE_AES_256] = NULL,
#endif
#if RSIP_CFG_KEY_GENERATE_AES_128_XTS_ENABLE
    [RSIP_KEY_TYPE_AES_128_XTS] = r_rsip_p16,
#else
    [RSIP_KEY_TYPE_AES_128_XTS] = NULL,
#endif
#if RSIP_CFG_KEY_GENERATE_AES_256_XTS_ENABLE
    [RSIP_KEY_TYPE_AES_256_XTS] = r_rsip_p17,
#else
    [RSIP_KEY_TYPE_AES_256_XTS] = NULL,
#endif
};

const rsip_func_key_pair_generate_t gp_func_key_pair_generate[] =
{
#if RSIP_CFG_KEY_PAIR_GENERATE_ECC_secp192r1_ENABLE
    [RSIP_KEY_PAIR_TYPE_ECC_secp192r1] = r_rsip_wrapper_pf4_secp192r1,
#else
    [RSIP_KEY_PAIR_TYPE_ECC_secp192r1] = NULL,
#endif
#if RSIP_CFG_KEY_PAIR_GENERATE_ECC_secp224r1_ENABLE
    [RSIP_KEY_PAIR_TYPE_ECC_secp224r1] = r_rsip_wrapper_pf4_secp224r1,
#else
    [RSIP_KEY_PAIR_TYPE_ECC_secp224r1] = NULL,
#endif
#if RSIP_CFG_KEY_PAIR_GENERATE_ECC_secp256r1_ENABLE
    [RSIP_KEY_PAIR_TYPE_ECC_secp256r1] = r_rsip_wrapper_pf4_secp256r1,
#else
    [RSIP_KEY_PAIR_TYPE_ECC_secp256r1] = NULL,
#endif
#if RSIP_CFG_KEY_PAIR_GENERATE_ECC_BRAINPOOLP256R1_ENABLE
    [RSIP_KEY_PAIR_TYPE_ECC_BRAINPOOLP256R1] = r_rsip_wrapper_pf4_brainpoolp256r1,
#else
    [RSIP_KEY_PAIR_TYPE_ECC_BRAINPOOLP256R1] = NULL,
#endif
#if RSIP_CFG_KEY_PAIR_GENERATE_RSA_1024_ENABLE
    [RSIP_KEY_PAIR_TYPE_RSA_1024] = r_rsip_wrapper_p2a,
#else
    [RSIP_KEY_PAIR_TYPE_RSA_1024] = NULL,
#endif
#if RSIP_CFG_KEY_PAIR_GENERATE_RSA_2048_ENABLE
    [RSIP_KEY_PAIR_TYPE_RSA_2048] = r_rsip_wrapper_p2b,
#else
    [RSIP_KEY_PAIR_TYPE_RSA_2048] = NULL,
#endif
#if RSIP_CFG_KEY_PAIR_GENERATE_RSA_3072_ENABLE
    [RSIP_KEY_PAIR_TYPE_RSA_3072] = r_rsip_wrapper_p3a,
#else
    [RSIP_KEY_PAIR_TYPE_RSA_3072] = NULL,
#endif
#if RSIP_CFG_KEY_PAIR_GENERATE_RSA_4096_ENABLE
    [RSIP_KEY_PAIR_TYPE_RSA_4096] = r_rsip_wrapper_p3b,
#else
    [RSIP_KEY_PAIR_TYPE_RSA_4096] = NULL,
#endif
};

const rsip_func_key_import_with_kuk_t gp_func_key_import_with_kuk[] =
{
#if RSIP_CFG_KEY_IMPORT_WITH_KUK_AES_128_ENABLE
    [RSIP_KEY_TYPE_AES_128] = r_rsip_p19,
#else
    [RSIP_KEY_TYPE_AES_128] = NULL,
#endif
#if RSIP_CFG_KEY_IMPORT_WITH_KUK_AES_256_ENABLE
    [RSIP_KEY_TYPE_AES_256] = r_rsip_p1c,
#else
    [RSIP_KEY_TYPE_AES_256] = NULL,
#endif
#if RSIP_CFG_KEY_IMPORT_WITH_KUK_AES_128_XTS_ENABLE
    [RSIP_KEY_TYPE_AES_128_XTS] = r_rsip_p1b,
#else
    [RSIP_KEY_TYPE_AES_128_XTS] = NULL,
#endif
#if RSIP_CFG_KEY_IMPORT_WITH_KUK_AES_256_XTS_ENABLE
    [RSIP_KEY_TYPE_AES_256_XTS] = r_rsip_p1d,
#else
    [RSIP_KEY_TYPE_AES_256_XTS] = NULL,
#endif
#if RSIP_CFG_KEY_IMPORT_WITH_KUK_ECC_secp192r1_PUBLIC_ENABLE
    [RSIP_KEY_TYPE_ECC_secp192r1_PUBLIC] = r_rsip_wrapper_p2c_secp192r1,
#else
    [RSIP_KEY_TYPE_ECC_secp192r1_PUBLIC] = NULL,
#endif
#if RSIP_CFG_KEY_IMPORT_WITH_KUK_ECC_secp192r1_PRIVATE_ENABLE
    [RSIP_KEY_TYPE_ECC_secp192r1_PRIVATE] = r_rsip_wrapper_p1e_secp192r1,
#else
    [RSIP_KEY_TYPE_ECC_secp192r1_PRIVATE] = NULL,
#endif
#if RSIP_CFG_KEY_IMPORT_WITH_KUK_ECC_secp224r1_PUBLIC_ENABLE
    [RSIP_KEY_TYPE_ECC_secp224r1_PUBLIC] = r_rsip_wrapper_p2c_secp224r1,
#else
    [RSIP_KEY_TYPE_ECC_secp224r1_PUBLIC] = NULL,
#endif
#if RSIP_CFG_KEY_IMPORT_WITH_KUK_ECC_secp224r1_PRIVATE_ENABLE
    [RSIP_KEY_TYPE_ECC_secp224r1_PRIVATE] = r_rsip_wrapper_p1e_secp224r1,
#else
    [RSIP_KEY_TYPE_ECC_secp224r1_PRIVATE] = NULL,
#endif
#if RSIP_CFG_KEY_IMPORT_WITH_KUK_ECC_secp256r1_PUBLIC_ENABLE
    [RSIP_KEY_TYPE_ECC_secp256r1_PUBLIC] = r_rsip_wrapper_p2c_secp256r1,
#else
    [RSIP_KEY_TYPE_ECC_secp256r1_PUBLIC] = NULL,
#endif
#if RSIP_CFG_KEY_IMPORT_WITH_KUK_ECC_secp256r1_PRIVATE_ENABLE
    [RSIP_KEY_TYPE_ECC_secp256r1_PRIVATE] = r_rsip_wrapper_p1e_secp256r1,
#else
    [RSIP_KEY_TYPE_ECC_secp256r1_PRIVATE] = NULL,
#endif
#if RSIP_CFG_KEY_IMPORT_WITH_KUK_ECC_BRAINPOOLP256R1_PUBLIC_ENABLE
    [RSIP_KEY_TYPE_ECC_BRAINPOOLP256R1_PUBLIC] = r_rsip_wrapper_p2c_brainpoolp256r1,
#else
    [RSIP_KEY_TYPE_ECC_BRAINPOOLP256R1_PUBLIC] = NULL,
#endif
#if RSIP_CFG_KEY_IMPORT_WITH_KUK_ECC_BRAINPOOLP256R1_PRIVATE_ENABLE
    [RSIP_KEY_TYPE_ECC_BRAINPOOLP256R1_PRIVATE] = r_rsip_wrapper_p1e_brainpoolp256r1,
#else
    [RSIP_KEY_TYPE_ECC_BRAINPOOLP256R1_PRIVATE] = NULL,
#endif
#if RSIP_CFG_KEY_IMPORT_WITH_KUK_RSA_1024_PUBLIC_ENHANCED_ENABLE
    [RSIP_KEY_TYPE_RSA_1024_PUBLIC_ENHANCED] = r_rsip_p0b,
#else
    [RSIP_KEY_TYPE_RSA_1024_PUBLIC_ENHANCED] = NULL,
#endif
#if RSIP_CFG_KEY_IMPORT_WITH_KUK_RSA_1024_PRIVATE_ENHANCED_ENABLE
    [RSIP_KEY_TYPE_RSA_1024_PRIVATE_ENHANCED] = r_rsip_p0c,
#else
    [RSIP_KEY_TYPE_RSA_1024_PRIVATE_ENHANCED] = NULL,
#endif
#if RSIP_CFG_KEY_IMPORT_WITH_KUK_RSA_2048_PUBLIC_ENHANCED_ENABLE
    [RSIP_KEY_TYPE_RSA_2048_PUBLIC_ENHANCED] = r_rsip_p0d,
#else
    [RSIP_KEY_TYPE_RSA_2048_PUBLIC_ENHANCED] = NULL,
#endif
#if RSIP_CFG_KEY_IMPORT_WITH_KUK_RSA_2048_PRIVATE_ENHANCED_ENABLE
    [RSIP_KEY_TYPE_RSA_2048_PRIVATE_ENHANCED] = r_rsip_p0e,
#else
    [RSIP_KEY_TYPE_RSA_2048_PRIVATE_ENHANCED] = NULL,
#endif
#if RSIP_CFG_KEY_IMPORT_WITH_KUK_RSA_3072_PUBLIC_ENABLE
    [RSIP_KEY_TYPE_RSA_3072_PUBLIC] = r_rsip_p38,
#else
    [RSIP_KEY_TYPE_RSA_3072_PUBLIC] = NULL,
#endif
#if RSIP_CFG_KEY_IMPORT_WITH_KUK_RSA_3072_PRIVATE_ENABLE
    [RSIP_KEY_TYPE_RSA_3072_PRIVATE] = r_rsip_p9d,
#else
    [RSIP_KEY_TYPE_RSA_3072_PRIVATE] = NULL,
#endif
#if RSIP_CFG_KEY_IMPORT_WITH_KUK_RSA_4096_PUBLIC_ENABLE
    [RSIP_KEY_TYPE_RSA_4096_PUBLIC] = r_rsip_p9e,
#else
    [RSIP_KEY_TYPE_RSA_4096_PUBLIC] = NULL,
#endif
#if RSIP_CFG_KEY_IMPORT_WITH_KUK_RSA_4096_PRIVATE_ENABLE
    [RSIP_KEY_TYPE_RSA_4096_PRIVATE] = r_rsip_p9f,
#else
    [RSIP_KEY_TYPE_RSA_4096_PRIVATE] = NULL,
#endif
#if RSIP_CFG_KEY_IMPORT_WITH_KUK_HMAC_SHA_ENABLE
    [RSIP_KEY_TYPE_HMAC_SHA1]   = r_rsip_wrapper_p0f_hmac_sha1,
    [RSIP_KEY_TYPE_HMAC_SHA224] = r_rsip_wrapper_p0f_hmac_sha224,
    [RSIP_KEY_TYPE_HMAC_SHA256] = r_rsip_wrapper_p0f_hmac_sha256,
#else
    [RSIP_KEY_TYPE_HMAC_SHA1]   = NULL,
    [RSIP_KEY_TYPE_HMAC_SHA224] = NULL,
    [RSIP_KEY_TYPE_HMAC_SHA256] = NULL,
#endif
};

const rsip_func_subset_aes_t gp_func_aes[] =
{
    [RSIP_PRV_AES_REBASE(RSIP_KEY_TYPE_AES_128)] =
            {
#if RSIP_CFG_AES_128_ECB_CBC_CTR_ENABLE
            .p_init   =
            {
            [RSIP_AES_MODE_ECB] =
            {
            r_rsip_wrapper_p48i_ecb_enc,
            r_rsip_wrapper_p48i_ecb_dec
            },
            [RSIP_AES_MODE_CBC] =
            {
            r_rsip_wrapper_p48i_cbc_enc,
            r_rsip_wrapper_p48i_cbc_dec
            },
            [RSIP_AES_MODE_CTR] =
            {
            r_rsip_wrapper_p48i_ctr,
            r_rsip_wrapper_p48i_ctr
            }
            },
            .p_update = r_rsip_p48u,
            .p_final  = r_rsip_p48f
#else
            .p_init   =
            {
            [RSIP_AES_MODE_ECB] =
            {
            NULL,
            NULL
            },
            [RSIP_AES_MODE_CBC] =
            {
            NULL,
            NULL
            },
            [RSIP_AES_MODE_CTR] =
            {
            NULL,
            NULL
            }
            },
            .p_update = NULL,
            .p_final  = NULL
#endif
            },
    [RSIP_PRV_AES_REBASE(RSIP_KEY_TYPE_AES_256)] =
            {
#if RSIP_CFG_AES_256_ECB_CBC_CTR_ENABLE
            .p_init   =
            {
            [RSIP_AES_MODE_ECB] =
            {
            r_rsip_wrapper_p50i_ecb_enc,
            r_rsip_wrapper_p50i_ecb_dec
            },
            [RSIP_AES_MODE_CBC] =
            {
            r_rsip_wrapper_p50i_cbc_enc,
            r_rsip_wrapper_p50i_cbc_dec
            },
            [RSIP_AES_MODE_CTR] =
            {
            r_rsip_wrapper_p50i_ctr,
            r_rsip_wrapper_p50i_ctr
            }
            },
            .p_update = r_rsip_p50u,
            .p_final  = r_rsip_p50f
#else
            .p_init   =
            {
            [RSIP_AES_MODE_ECB] =
            {
            NULL,
            NULL
            },
            [RSIP_AES_MODE_CBC] =
            {
            NULL,
            NULL
            },
            [RSIP_AES_MODE_CTR] =
            {
            NULL,
            NULL
            }
            },
            .p_update = NULL,
            .p_final  = NULL
#endif
            },
};

const rsip_func_subset_xts_t gp_func_xts[][2] =
{
    [RSIP_PRV_XTS_REBASE(RSIP_KEY_TYPE_AES_128_XTS)][RSIP_PRV_XTS_HANDLE_REBASE(RSIP_HANDLE_TYPE_XTS_ENCRYPT)] =
    {
#if RSIP_CFG_AES_128_XTS_ENCRYPT_ENABLE
        .p_init   = r_rsip_pb3i,
        .p_update = r_rsip_pb3u,
        .p_final  = r_rsip_pb3f
#else
        .p_init   = NULL,
        .p_update = NULL,
        .p_final  = NULL
#endif
    },

    [RSIP_PRV_XTS_REBASE(RSIP_KEY_TYPE_AES_128_XTS)][RSIP_PRV_XTS_HANDLE_REBASE(RSIP_HANDLE_TYPE_XTS_DECRYPT)] =
    {
#if RSIP_CFG_AES_128_XTS_DECRYPT_ENABLE
        .p_init   = r_rsip_pb6i,
        .p_update = r_rsip_pb6u,
        .p_final  = r_rsip_pb6f
#else
        .p_init   = NULL,
        .p_update = NULL,
        .p_final  = NULL
#endif
    },
    [RSIP_PRV_XTS_REBASE(RSIP_KEY_TYPE_AES_256_XTS)][RSIP_PRV_XTS_HANDLE_REBASE(RSIP_HANDLE_TYPE_XTS_ENCRYPT)] =
    {
#if RSIP_CFG_AES_256_XTS_ENCRYPT_ENABLE
        .p_init   = r_rsip_pb9i,
        .p_update = r_rsip_pb9u,
        .p_final  = r_rsip_pb9f
#else
        .p_init   = NULL,
        .p_update = NULL,
        .p_final  = NULL
#endif
    },
    [RSIP_PRV_XTS_REBASE(RSIP_KEY_TYPE_AES_256_XTS)][RSIP_PRV_XTS_HANDLE_REBASE(RSIP_HANDLE_TYPE_XTS_DECRYPT)] =
    {
#if RSIP_CFG_AES_256_XTS_DECRYPT_ENABLE
        .p_init   = r_rsip_pc2i,
        .p_update = r_rsip_pc2u,
        .p_final  = r_rsip_pc2f
#else
        .p_init   = NULL,
        .p_update = NULL,
        .p_final  = NULL
#endif
    },
};

const rsip_func_subset_gcm_t gp_func_gcm[][2] =
{
    [RSIP_PRV_AES_REBASE(RSIP_KEY_TYPE_AES_128)][RSIP_PRV_GCM_HANDLE_REBASE(RSIP_HANDLE_TYPE_GCM_ENCRYPT)] =
    {
#if RSIP_CFG_AES_128_GCM_ENCRYPT_ENABLE
        .p_init             = r_rsip_p29i,
        .p_updateAad        = r_rsip_p29a,
        .p_updateTransition = r_rsip_p29t,
        .p_update           = r_rsip_p29u,
        .p_encryptFinal     = r_rsip_p29f,
        .p_ecb              = &gp_func_aes[RSIP_PRV_AES_REBASE(RSIP_KEY_TYPE_AES_128)]
#else
        .p_init             = NULL,
        .p_updateAad        = NULL,
        .p_updateTransition = NULL,
        .p_update           = NULL,
        .p_encryptFinal     = NULL,
        .p_ecb              = NULL
#endif
    },
    [RSIP_PRV_AES_REBASE(RSIP_KEY_TYPE_AES_128)][RSIP_PRV_GCM_HANDLE_REBASE(RSIP_HANDLE_TYPE_GCM_DECRYPT)] =
    {
#if RSIP_CFG_AES_128_GCM_DECRYPT_ENABLE
        .p_init             = r_rsip_p32i,
        .p_updateAad        = r_rsip_p32a,
        .p_updateTransition = r_rsip_p32t,
        .p_update           = r_rsip_p32u,
        .p_decryptFinal     = r_rsip_p32f,
        .p_ecb              = &gp_func_aes[RSIP_PRV_AES_REBASE(RSIP_KEY_TYPE_AES_128)]
#else
        .p_init             = NULL,
        .p_updateAad        = NULL,
        .p_updateTransition = NULL,
        .p_update           = NULL,
        .p_encryptFinal     = NULL,
        .p_ecb              = NULL
#endif
    },
    [RSIP_PRV_AES_REBASE(RSIP_KEY_TYPE_AES_256)][RSIP_PRV_GCM_HANDLE_REBASE(RSIP_HANDLE_TYPE_GCM_ENCRYPT)] =
    {
#if RSIP_CFG_AES_256_GCM_ENCRYPT_ENABLE
        .p_init             = r_rsip_p34i,
        .p_updateAad        = r_rsip_p34a,
        .p_updateTransition = r_rsip_p34t,
        .p_update           = r_rsip_p34u,
        .p_encryptFinal     = r_rsip_p34f,
        .p_ecb              = &gp_func_aes[RSIP_PRV_AES_REBASE(RSIP_KEY_TYPE_AES_256)]
#else
        .p_init             = NULL,
        .p_updateAad        = NULL,
        .p_updateTransition = NULL,
        .p_update           = NULL,
        .p_encryptFinal     = NULL,
        .p_ecb              = NULL
#endif
    },

    [RSIP_PRV_AES_REBASE(RSIP_KEY_TYPE_AES_256)][RSIP_PRV_GCM_HANDLE_REBASE(RSIP_HANDLE_TYPE_GCM_DECRYPT)] =
    {
#if RSIP_CFG_AES_256_GCM_DECRYPT_ENABLE
        .p_init             = r_rsip_p36i,
        .p_updateAad        = r_rsip_p36a,
        .p_updateTransition = r_rsip_p36t,
        .p_update           = r_rsip_p36u,
        .p_decryptFinal     = r_rsip_p36f,
        .p_ecb              = &gp_func_aes[RSIP_PRV_AES_REBASE(RSIP_KEY_TYPE_AES_256)]
#else
        .p_init             = NULL,
        .p_updateAad        = NULL,
        .p_updateTransition = NULL,
        .p_update           = NULL,
        .p_encryptFinal     = NULL,
        .p_ecb              = NULL
#endif
    },
};

const rsip_func_subset_cmac_t gp_func_cmac[] =
{
    [RSIP_PRV_AES_REBASE(RSIP_KEY_TYPE_AES_128)] =
    {
#if RSIP_CFG_AES_128_CMAC_ENABLE
    .p_init          = r_rsip_p41i,
    .p_update        = r_rsip_p41u,
    .p_generateFinal = r_rsip_wrapper_p41f_gen,
    .p_verifyFinal   = r_rsip_wrapper_p41f_veri
#else
    .p_init          = NULL,
    .p_update        = NULL,
    .p_generateFinal = NULL,
    .p_verifyFinal   = NULL
#endif
    },
    [RSIP_PRV_AES_REBASE(RSIP_KEY_TYPE_AES_256)] =
    {
#if RSIP_CFG_AES_256_CMAC_ENABLE
    .p_init          = r_rsip_p44i,
    .p_update        = r_rsip_p44u,
    .p_generateFinal = r_rsip_wrapper_p44f_gen,
    .p_verifyFinal   = r_rsip_wrapper_p44f_veri
#else
    .p_init          = NULL,
    .p_update        = NULL,
    .p_generateFinal = NULL,
    .p_verifyFinal   = NULL
#endif
    },
};

const rsip_func_ecdsa_sign_t gp_func_ecdsa_sign[] =
{
    [RSIP_PRV_ECC_REBASE(RSIP_KEY_TYPE_ECC_secp192r1_PRIVATE)]       = r_rsip_wrapper_pf0_secp192r1,
    [RSIP_PRV_ECC_REBASE(RSIP_KEY_TYPE_ECC_secp224r1_PRIVATE)]       = r_rsip_wrapper_pf0_secp224r1,
    [RSIP_PRV_ECC_REBASE(RSIP_KEY_TYPE_ECC_secp256r1_PRIVATE)]       = r_rsip_wrapper_pf0_secp256r1,
    [RSIP_PRV_ECC_REBASE(RSIP_KEY_TYPE_ECC_BRAINPOOLP256R1_PRIVATE)] = r_rsip_wrapper_pf0_brainpoolp256r1,
};

const rsip_func_ecdsa_verify_t gp_func_ecdsa_verify[] =
{
    [RSIP_PRV_ECC_REBASE(RSIP_KEY_TYPE_ECC_secp192r1_PUBLIC)]       = r_rsip_wrapper_pf1_secp192r1,
    [RSIP_PRV_ECC_REBASE(RSIP_KEY_TYPE_ECC_secp224r1_PUBLIC)]       = r_rsip_wrapper_pf1_secp224r1,
    [RSIP_PRV_ECC_REBASE(RSIP_KEY_TYPE_ECC_secp256r1_PUBLIC)]       = r_rsip_wrapper_pf1_secp256r1,
    [RSIP_PRV_ECC_REBASE(RSIP_KEY_TYPE_ECC_BRAINPOOLP256R1_PUBLIC)] = r_rsip_wrapper_pf1_brainpoolp256r1,
};

const rsip_func_rsa_t gp_func_rsa_public[] =
{
#if RSIP_CFG_RSA_1024_ENCRYPT_ENHANCED_ENABLE
    [RSIP_PRV_RSA_REBASE(RSIP_KEY_TYPE_RSA_1024_PUBLIC_ENHANCED)] = r_rsip_p53,
#else
    [RSIP_PRV_RSA_REBASE(RSIP_KEY_TYPE_RSA_1024_PUBLIC_ENHANCED)] = NULL,
#endif
#if RSIP_CFG_RSA_2048_ENCRYPT_ENHANCED_ENABLE
    [RSIP_PRV_RSA_REBASE(RSIP_KEY_TYPE_RSA_2048_PUBLIC_ENHANCED)] = r_rsip_p56,
#else
    [RSIP_PRV_RSA_REBASE(RSIP_KEY_TYPE_RSA_2048_PUBLIC_ENHANCED)] = NULL,
#endif
#if RSIP_CFG_RSA_3072_ENCRYPT_ENABLE
    [RSIP_PRV_RSA_REBASE(RSIP_KEY_TYPE_RSA_3072_PUBLIC)] = r_rsip_p79,
#else
    [RSIP_PRV_RSA_REBASE(RSIP_KEY_TYPE_RSA_3072_PUBLIC)] = NULL,
#endif
#if RSIP_CFG_RSA_4096_ENCRYPT_ENABLE
    [RSIP_PRV_RSA_REBASE(RSIP_KEY_TYPE_RSA_4096_PUBLIC)] = r_rsip_p7b,
#else
    [RSIP_PRV_RSA_REBASE(RSIP_KEY_TYPE_RSA_4096_PUBLIC)] = NULL,
#endif
};

const rsip_func_rsa_t gp_func_rsa_private[] =
{
#if RSIP_CFG_RSA_1024_DECRYPT_ENHANCED_ENABLE
    [RSIP_PRV_RSA_REBASE(RSIP_KEY_TYPE_RSA_1024_PRIVATE_ENHANCED)] = r_rsip_p54,
#else
    [RSIP_PRV_RSA_REBASE(RSIP_KEY_TYPE_RSA_1024_PRIVATE_ENHANCED)] = NULL,
#endif
#if RSIP_CFG_RSA_2048_DECRYPT_ENHANCED_ENABLE
    [RSIP_PRV_RSA_REBASE(RSIP_KEY_TYPE_RSA_2048_PRIVATE_ENHANCED)] = r_rsip_p57,
#else
    [RSIP_PRV_RSA_REBASE(RSIP_KEY_TYPE_RSA_2048_PRIVATE_ENHANCED)] = NULL,
#endif
#if RSIP_CFG_RSA_3072_DECRYPT_ENABLE
    [RSIP_PRV_RSA_REBASE(RSIP_KEY_TYPE_RSA_3072_PRIVATE)] = r_rsip_p7a,
#else
    [RSIP_PRV_RSA_REBASE(RSIP_KEY_TYPE_RSA_3072_PRIVATE)] = NULL,
#endif
#if RSIP_CFG_RSA_4096_DECRYPT_ENABLE
    [RSIP_PRV_RSA_REBASE(RSIP_KEY_TYPE_RSA_4096_PRIVATE)] = r_rsip_p7c,
#else
    [RSIP_PRV_RSA_REBASE(RSIP_KEY_TYPE_RSA_4096_PRIVATE)] = NULL,
#endif
};

const rsip_func_hmac_single_t gp_func_hmac_single[] =
{
#if RSIP_CFG_HMAC_SHA1_ENABLE
    [RSIP_PRV_HMAC_REBASE(RSIP_KEY_TYPE_HMAC_SHA1)] = r_rsip_p74,
#else
    [RSIP_PRV_HMAC_REBASE(RSIP_KEY_TYPE_HMAC_SHA1)] = NULL,
#endif
#if RSIP_CFG_HMAC_SHA224_ENABLE
    [RSIP_PRV_HMAC_REBASE(RSIP_KEY_TYPE_HMAC_SHA224)] = r_rsip_pdd,
#else
    [RSIP_PRV_HMAC_REBASE(RSIP_KEY_TYPE_HMAC_SHA224)] = NULL,
#endif
#if RSIP_CFG_HMAC_SHA256_ENABLE
    [RSIP_PRV_HMAC_REBASE(RSIP_KEY_TYPE_HMAC_SHA256)] = r_rsip_p77,
#else
    [RSIP_PRV_HMAC_REBASE(RSIP_KEY_TYPE_HMAC_SHA256)] = NULL,
#endif
};

const rsip_func_hmac_multi_t gp_func_hmac_multi[] =
{
#if RSIP_CFG_HMAC_SHA1_ENABLE
    [RSIP_PRV_HMAC_REBASE(RSIP_KEY_TYPE_HMAC_SHA1)] = r_rsip_p73,
#else
    [RSIP_PRV_HMAC_REBASE(RSIP_KEY_TYPE_HMAC_SHA1)] = NULL,
#endif
#if RSIP_CFG_HMAC_SHA224_ENABLE
    [RSIP_PRV_HMAC_REBASE(RSIP_KEY_TYPE_HMAC_SHA224)] = r_rsip_pdc,
#else
    [RSIP_PRV_HMAC_REBASE(RSIP_KEY_TYPE_HMAC_SHA224)] = NULL,
#endif
#if RSIP_CFG_HMAC_SHA256_ENABLE
    [RSIP_PRV_HMAC_REBASE(RSIP_KEY_TYPE_HMAC_SHA256)] = r_rsip_p76,
#else
    [RSIP_PRV_HMAC_REBASE(RSIP_KEY_TYPE_HMAC_SHA256)] = NULL,
#endif
};

const rsip_func_random_number_generate_t gp_func_random_number_generate = r_rsip_p20;
const rsip_func_ghash_t gp_func_ghash_compute = r_rsip_p21;

/***********************************************************************************************************************
 * Functions
 **********************************************************************************************************************/

rsip_ret_t r_rsip_open (void)
{
    uint32_t   value;
    rsip_ret_t rsip_ret = RSIP_RET_FAIL;

    RD1_ADDR(REG_142CH, &value);

    if (0 == (value & RSIP_PRV_REG_142CH_OPEN))
    {
        rsip_ret = RSIP_RET_PASS;
    }

    return rsip_ret;
}

rsip_ret_t r_rsip_close (void)
{
    return RSIP_RET_PASS;
}

void r_rsip_kuk_store (const uint8_t * p_key_update_key_value)
{
    memcpy(S_INST2, p_key_update_key_value, sizeof(S_INST2));
}

rsip_ret_t r_rsip_sha1sha2_compute_single (const uint32_t   InData_Msg[],
                                           uint32_t         OutData_MsgDigest[],
                                           rsip_hash_type_t hash_type,
                                           uint32_t         message_length)
{
    uint32_t InData_HashType[1] =
    {
        gs_cmd_hash_type[hash_type]
    };
    uint32_t InData_MsgLen[2] =
    {
        InData_MsgLen[0] = bswap_32big(r_rsip_byte_to_bit_convert_upper(message_length)),
        InData_MsgLen[1] = bswap_32big(r_rsip_byte_to_bit_convert_lower(message_length))
    };

    /** MAX_CNT: message length in word order */
    uint32_t MAX_CNT = r_rsip_byte_to_word_convert(message_length);

    /** Call primitive (cast to match the argument type with the primitive function) */
    return r_rsip_p71(InData_HashType, InData_Msg, InData_MsgLen, MAX_CNT, OutData_MsgDigest);
}

rsip_ret_t r_rsip_hmac_compute_single (const uint32_t                InData_Msg[],
                                       uint32_t                      OutData_MAC[],
                                       const rsip_func_hmac_single_t p_func,
                                       const rsip_wrapped_key_t    * p_wrapped_key,
                                       uint32_t                      message_length)
{
    static const uint32_t InData_Cmd[1] =
    {
        RSIP_PRV_CMD_OUTPUT
    };
    uint32_t InData_MsgLen[2] =
    {
        bswap_32big(r_rsip_byte_to_bit_convert_upper(message_length)),
        bswap_32big(r_rsip_byte_to_bit_convert_lower(message_length))
    };

    /** MAX_CNT: message length in word order */
    uint32_t MAX_CNT = r_rsip_byte_to_word_convert(message_length);

    /** Call primitive (cast to match the argument type with the primitive function) */
    return p_func((const uint32_t *) p_wrapped_key->value,
                  InData_Cmd,
                  InData_Msg,
                  InData_MsgLen,
                  NULL,
                  NULL,
                  MAX_CNT,
                  OutData_MAC);
}

rsip_ret_t r_rsip_hmac_verify_single (const uint32_t                InData_Msg[],
                                      const uint8_t               * p_mac,
                                      const rsip_func_hmac_single_t p_func,
                                      const rsip_wrapped_key_t    * p_wrapped_key,
                                      uint32_t                      message_length,
                                      uint32_t                      mac_length)
{
    static const uint32_t InData_Cmd[1] =
    {
        RSIP_PRV_CMD_COMPARE
    };
    uint32_t InData_MsgLen[2] =
    {
        bswap_32big(r_rsip_byte_to_bit_convert_upper(message_length)),
        bswap_32big(r_rsip_byte_to_bit_convert_lower(message_length))
    };
    uint32_t InData_MAC[RSIP_PRV_WORD_SIZE_HMAC_MAC_BUFFER] =
    {
        0
    };
    memcpy(InData_MAC, p_mac, mac_length);
    uint32_t InData_length[1] =
    {
        bswap_32big(mac_length)
    };

    /** MAX_CNT: message length in word order */
    uint32_t MAX_CNT = r_rsip_byte_to_word_convert(message_length);

    /** Call primitive (cast to match the argument type with the primitive function) */
    return p_func((const uint32_t *) p_wrapped_key->value,
                  InData_Cmd,
                  InData_Msg,
                  InData_MsgLen,
                  InData_MAC,
                  InData_length,
                  MAX_CNT,
                  NULL);
}

rsip_ret_t r_rsip_sha1sha2_calc_multi (rsip_sha_handle_t * p_handle,
                                       const uint8_t     * p_message,
                                       uint32_t            message_length,
                                       uint8_t           * p_digest)
{
    uint32_t hash_type[1] =
    {
        gs_cmd_hash_type[p_handle->type]
    };
    uint32_t cmd[1] =
    {
        0
    };

    /* max_cnt: message length in word order */
    uint32_t max_cnt = r_rsip_byte_to_word_convert(message_length);

    /* Set command and overwrite internal state */
    bool is_init  = (RSIP_USER_HANDLE_STATE_UPDATE_EMPTY == p_handle->state);
    bool is_final = (NULL != p_digest);

    if (!is_final)
    {
        /* Update */
        if (is_init)
        {
            cmd[0] = RSIP_PRV_CMD_INIT_TO_SUSPEND;
            p_handle->internal_state[18] = RSIP_PRV_SHA_INIT_VAL1;
            p_handle->internal_state[19] = RSIP_PRV_SHA_INIT_VAL2;
        }
        else
        {
            cmd[0] = RSIP_PRV_CMD_RESUME_TO_SUSPEND;
        }
    }
    else
    {
        /* Final */
        cmd[0] = is_init ? RSIP_PRV_CMD_INIT_TO_FINAL : RSIP_PRV_CMD_RESUME_TO_FINAL;
        uint64_t len = message_length;
        p_handle->internal_state[16] = bswap_32big(r_rsip_byte_to_bit_convert_lower(len + p_handle->total_length));
        p_handle->internal_state[17] = bswap_32big(r_rsip_byte_to_bit_convert_upper(len + p_handle->total_length));
        p_handle->internal_state[18] = bswap_32big(r_rsip_byte_to_bit_convert_upper(len));
        p_handle->internal_state[19] = bswap_32big(r_rsip_byte_to_bit_convert_lower(len));
    }

    /* Call primitive (cast to match the argument type with the primitive function) */
    rsip_ret_t rsip_ret = r_rsip_p72(hash_type,
                                     cmd,
                                     (const uint32_t *) p_message,
                                     &p_handle->internal_state[18],
                                     p_handle->internal_state,
                                     max_cnt,
                                     (uint32_t *) p_digest,
                                     p_handle->internal_state);

    /* Check error */
    switch (rsip_ret)
    {
        case RSIP_RET_PASS:
        {
            p_handle->state         = is_final ? RSIP_USER_HANDLE_STATE_INIT : RSIP_USER_HANDLE_STATE_UPDATE;
            p_handle->total_length += message_length;
            break;
        }

        default:
        {
            /* Do nothing */
        }
    }

    return rsip_ret;
}

rsip_ret_t r_rsip_hmac_calc_multi (rsip_hmac_handle_t * p_handle,
                                   const uint8_t      * p_message,
                                   uint32_t             message_length,
                                   uint8_t            * p_mac,
                                   uint32_t             mac_length,
                                   bool                 is_final)
{
    uint32_t cmd[1] =
    {
        0
    };
    uint32_t InData_MAC[RSIP_PRV_WORD_SIZE_HMAC_MAC_BUFFER] =
    {
        0
    };

    uint32_t input_mac_length[1] =
    {
        0
    };

    /* max_cnt: message length in word order */
    uint32_t max_cnt = r_rsip_byte_to_word_convert(message_length);

    /* Set command and overwrite internal state */
    bool is_init     = (RSIP_USER_HANDLE_STATE_UPDATE_EMPTY == p_handle->state);
    bool is_generate = p_handle->is_generate;

    if (!is_final)
    {
        /* GenerateUpdate, VerifyUpdate */
        if (is_init)
        {
            cmd[0] = RSIP_PRV_CMD_INIT_TO_SUSPEND;
            p_handle->internal_state[18] = RSIP_PRV_SHA_INIT_VAL1;
            p_handle->internal_state[19] = RSIP_PRV_SHA_INIT_VAL2;
        }
        else
        {
            cmd[0] = RSIP_PRV_CMD_RESUME_TO_SUSPEND;
        }
    }
    else
    {
        if (is_generate)
        {
            /* GenerateFinal */
            cmd[0] = is_init ? RSIP_PRV_CMD_INIT_TO_FINAL : RSIP_PRV_CMD_RESUME_TO_FINAL;
        }
        else
        {
            /* VerifyFinal */
            cmd[0] = is_init ? RSIP_PRV_CMD_INIT_TO_COMP_FINAL : RSIP_PRV_CMD_RESUME_TO_COMP_FINAL;

            /* Set MAC */
            memcpy(InData_MAC, p_mac, mac_length);
            input_mac_length[0] = bswap_32big(mac_length);
        }

        uint64_t len = message_length;
        p_handle->internal_state[16] = bswap_32big(r_rsip_byte_to_bit_convert_lower(len + p_handle->total_length));
        p_handle->internal_state[17] = bswap_32big(r_rsip_byte_to_bit_convert_upper(len + p_handle->total_length));
        p_handle->internal_state[18] = bswap_32big(r_rsip_byte_to_bit_convert_upper(len));
        p_handle->internal_state[19] = bswap_32big(r_rsip_byte_to_bit_convert_lower(len));
    }

    /* Set pointer to primitive functions */
    rsip_func_hmac_multi_t p_primitive = (rsip_func_hmac_multi_t) p_handle->p_primitive;

    /* Call primitive (cast to match the argument type with the primitive function) */
    rsip_ret_t rsip_ret =
        p_primitive((uint32_t *) (((rsip_wrapped_key_t *) p_handle->wrapped_key)->value),
                    cmd,
                    (uint32_t *) p_message,
                    &p_handle->internal_state[18],
                    InData_MAC,
                    input_mac_length,
                    p_handle->internal_state,
                    max_cnt,
                    (uint32_t *) p_mac,
                    p_handle->internal_state);

    /* Check error */
    switch (rsip_ret)
    {
        case RSIP_RET_PASS:
        {
            p_handle->state         = is_final ? RSIP_USER_HANDLE_STATE_INIT : RSIP_USER_HANDLE_STATE_UPDATE;
            p_handle->total_length += message_length;
            break;
        }

        default:
        {
            /* Do nothing */
        }
    }

    return rsip_ret;
}

/***********************************************************************************************************************
 * Private Functions
 **********************************************************************************************************************/
