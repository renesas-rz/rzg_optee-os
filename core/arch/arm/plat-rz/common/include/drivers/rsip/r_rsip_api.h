/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2024, Renesas Electronics Corporation
 */

/*******************************************************************************************************************//**
 * @ingroup RENESAS_INTERFACES
 * @defgroup RSIP_API RSIP Interface
 * @brief Interface for Renesas Secure IP (RSIP) functions.
 *
 * @section RSIP_API_Summary Summary
 * The RSIP interface provides RSIP functionality.
 *
 * The RSIP interface can be implemented by:
 * - @ref RSIP
 *
 * @{
 **********************************************************************************************************************/

#ifndef R_RSIP_API_H
#define R_RSIP_API_H

/***********************************************************************************************************************
 * Includes
 **********************************************************************************************************************/

/* Register definitions, common services and error codes. */
#include "bsp_api.h"

/* Common macro for FSP header files. There is also a corresponding FSP_FOOTER macro at the end of this file. */
FSP_HEADER

/***********************************************************************************************************************
 * Macro definitions
 **********************************************************************************************************************/

/* Return code */
#define FSP_ERR_CRYPTO_RSIP_RESOURCE_CONFLICT      (0x10100)      ///< Hardware resource is busy
#define FSP_ERR_CRYPTO_RSIP_FATAL                  (0x10101)      ///< Hardware fatal error or unexpected return
#define FSP_ERR_CRYPTO_RSIP_FAIL                   (0x10102)      ///< Internal error
#define FSP_ERR_CRYPTO_RSIP_KEY_SET_FAIL           (0x10103)      ///< Input key type is illegal
#define FSP_ERR_CRYPTO_RSIP_AUTHENTICATION         (0x10104)      ///< Authentication failed

/* Return code for SB-Lib */
#define FSP_ERR_SB_INTERNAL_FAIL                   (0x00030000UL) ///< An internal failure
#define FSP_ERR_SB_INVALID_ARG                     (0x00030001UL) ///< An invalid argument was entered
#define FSP_ERR_SB_UNSUPPORTED_FUNCTION            (0x00030002UL) ///< Unsupported function executed
#define FSP_ERR_SB_INVALID_ALIGNMENT               (0x00030003UL) ///< Data entered with incorrect alignment
#define FSP_ERR_SB_MANI_INVALID_MAGIC              (0x00031000UL) ///< An invalid magic number is set
#define FSP_ERR_SB_MANI_UNSUPPORTED_VERSION        (0x00031001UL) ///< Unsupported version is set
#define FSP_ERR_SB_MANI_OUT_OF_RANGE_LEN           (0x00031002UL) ///< Out of range TLV Length is set
#define FSP_ERR_SB_MANI_TLV_FIELD_ERR              (0x00031003UL) ///< Missing required TLV field
#define FSP_ERR_SB_MANI_TLV_INVALID_LEN            (0x00031004UL) ///< The length exceeding the end of the manifest is specified in length of the TLV field
#define FSP_ERR_SB_MANI_INVALID_IMAGE_LEN          (0x00031005UL) ///< An invalid image length is set
#define FSP_ERR_SB_MANI_MISMATCH_SIGN_ALGORITHM    (0x00031006UL) ///< There is a wrong combination of signature algorithms
#define FSP_ERR_SB_MANI_UNSUPPORTED_ALGORITHM      (0x00031007UL) ///< An algorithm was specified that the manifest does not support
#define FSP_ERR_SB_CRYPTO_FAIL                     (0x00032000UL) ///< Cryptographic processing failure
#define FSP_ERR_SB_CRYPTO_AUTH_FAIL                (0x00032001UL) ///< Verification failed
#define FSP_ERR_SB_CRYPTO_UNSUPPORTED_ALGORITHM    (0x00032002UL) ///< Unsupported algorithm
#define FSP_ERR_SB_CRYPTO_RESOURCE_CONFLICT        (0x00032003UL) ///< CryptoIP is in use.
#define FSP_ERR_SB_CRYPTO_PARAM_ERR                (0x00032004UL) ///< Parameter error

/* RSA salt length */

/**
 * When signing, the salt length is set to @ref RSIP_RSA_SALT_LENGTH_MAX or @ref RSIP_RSA_SALT_LENGTH_HASH,
 * whichever is shorter. When verifying, the salt length is detected automatically.
 */
#define RSIP_RSA_SALT_LENGTH_AUTO                  (-1)

/**
 * The salt length is set to the hash length.
 */
#define RSIP_RSA_SALT_LENGTH_HASH                  (-2)

/**
 * The salt length is set to emLen - hLen - 2, where emLen is the same as the key length and hLen is the hash length.
 */
#define RSIP_RSA_SALT_LENGTH_MAX                   (-3)

/* For internal use */
#define RSIP_BYTE_SIZE_SHA_MESSAGE_BUFFER          (128U) // rsip_sha_handle_t, rsip_hmac_handle_t
#define RSIP_WORD_SIZE_SHA_INTERNAL_STATE          (20U)  // rsip_sha_handle_t, rsip_hmac_handle_t

/***********************************************************************************************************************
 * Typedef definitions
 **********************************************************************************************************************/

/**
 * Key types
 * @deprecated
 * - The following member will be renamed in the next major update.
 *   - @ref RSIP_KEY_TYPE_ECC_secp192r1_PUBLIC to RSIP_KEY_TYPE_ECC_SECP192R1_PUBLIC
 *   - @ref RSIP_KEY_TYPE_ECC_secp192r1_PRIVATE to RSIP_KEY_TYPE_ECC_SECP192R1_PRIVATE
 *   - @ref RSIP_KEY_TYPE_ECC_secp224r1_PUBLIC to RSIP_KEY_TYPE_ECC_SECP224R1_PUBLIC
 *   - @ref RSIP_KEY_TYPE_ECC_secp224r1_PRIVATE to RSIP_KEY_TYPE_ECC_SECP224R1_PRIVATE
 *   - @ref RSIP_KEY_TYPE_ECC_secp256r1_PUBLIC to RSIP_KEY_TYPE_ECC_SECP256R1_PUBLIC
 *   - @ref RSIP_KEY_TYPE_ECC_secp256r1_PRIVATE to RSIP_KEY_TYPE_ECC_SECP256R1_PRIVATE
 */
typedef enum e_rsip_key_type
{
    RSIP_KEY_TYPE_INVALID,                      ///< Invalid key

    RSIP_KEY_TYPE_AES_128,                      ///< AES-128
    RSIP_KEY_TYPE_AES_256,                      ///< AES-256

    RSIP_KEY_TYPE_AES_128_XTS,                  ///< AES-128-XTS
    RSIP_KEY_TYPE_AES_256_XTS,                  ///< AES-256-XTS

    RSIP_KEY_TYPE_ECC_secp192r1_PUBLIC,         ///< secp192r1 public key (also known as NIST P-192, prime192v1)
    RSIP_KEY_TYPE_ECC_secp192r1_PRIVATE,        ///< secp192r1 private key (also known as NIST P-192, prime192v1)
    RSIP_KEY_TYPE_ECC_secp224r1_PUBLIC,         ///< secp224r1 public key (also known as NIST P-224, prime224v1)
    RSIP_KEY_TYPE_ECC_secp224r1_PRIVATE,        ///< secp224r1 private key (also known as NIST P-224, prime224v1)
    RSIP_KEY_TYPE_ECC_secp256r1_PUBLIC,         ///< secp256r1 public key (also known as NIST P-256, prime256v1)
    RSIP_KEY_TYPE_ECC_secp256r1_PRIVATE,        ///< secp256r1 private key (also known as NIST P-256, prime256v1)

    RSIP_KEY_TYPE_HMAC_SHA1,                    ///< HMAC-SHA1
    RSIP_KEY_TYPE_HMAC_SHA224,                  ///< HMAC-SHA224
    RSIP_KEY_TYPE_HMAC_SHA256,                  ///< HMAC-SHA256

    RSIP_KEY_TYPE_KEY_UPDATE_KEY,               ///< KUK (Key Update Key)

    RSIP_KEY_TYPE_SECURE_BOOT_DECRYPTION,       ///< Image decryption key for secure boot (supported devices only)

    RSIP_KEY_TYPE_RSA_1024_PUBLIC_ENHANCED,     ///< RSA-1024 public key
    RSIP_KEY_TYPE_RSA_1024_PRIVATE_ENHANCED,    ///< RSA-1024 private key
    RSIP_KEY_TYPE_RSA_2048_PUBLIC_ENHANCED,     ///< RSA-2048 public key
    RSIP_KEY_TYPE_RSA_2048_PRIVATE_ENHANCED,    ///< RSA-2048 private key
    RSIP_KEY_TYPE_RSA_3072_PUBLIC,              ///< RSA-3072 public key
    RSIP_KEY_TYPE_RSA_3072_PRIVATE,             ///< RSA-3072 private key
    RSIP_KEY_TYPE_RSA_4096_PUBLIC,              ///< RSA-4096 public key
    RSIP_KEY_TYPE_RSA_4096_PRIVATE,             ///< RSA-4096 private key

    RSIP_KEY_TYPE_ECC_BRAINPOOLP256R1_PUBLIC,   ///< brainpoolP256r1 public key
    RSIP_KEY_TYPE_ECC_BRAINPOOLP256R1_PRIVATE,  ///< brainpoolP256r1 private key

    RSIP_KEY_TYPE_NUM,                          // Number of key types

    RSIP_KEY_TYPE_MAKE_ENUM_LONG = 0xFFFFFFFFUL // Make this enum 32-bit data
} rsip_key_type_t;

/**
 * Key pair types
 * @deprecated
 * - The following member will be renamed in the next major update.
 *   - @ref RSIP_KEY_PAIR_TYPE_ECC_secp192r1 to RSIP_KEY_PAIR_TYPE_ECC_SECP192R1
 *   - @ref RSIP_KEY_PAIR_TYPE_ECC_secp224r1 to RSIP_KEY_PAIR_TYPE_ECC_SECP224R1
 *   - @ref RSIP_KEY_PAIR_TYPE_ECC_secp256r1 to RSIP_KEY_PAIR_TYPE_ECC_SECP256R1
 */
typedef enum e_rsip_key_pair_type
{
    RSIP_KEY_PAIR_TYPE_INVALID,             ///< Invalid key pair type

    RSIP_KEY_PAIR_TYPE_ECC_secp192r1,       ///< secp192r1 key pair (also known as NIST P-192, prime192v1)
    RSIP_KEY_PAIR_TYPE_ECC_secp224r1,       ///< secp224r1 key pair (also known as NIST P-224, prime224v1)
    RSIP_KEY_PAIR_TYPE_ECC_secp256r1,       ///< secp256r1 key pair (also known as NIST P-256, prime256v1)
    RSIP_KEY_PAIR_TYPE_ECC_BRAINPOOLP256R1, ///< brainpoolP256r1 key pair

    RSIP_KEY_PAIR_TYPE_RSA_1024,            ///< RSA-1024 key pair
    RSIP_KEY_PAIR_TYPE_RSA_2048,            ///< RSA-2048 key pair
    RSIP_KEY_PAIR_TYPE_RSA_3072,            ///< RSA-3072 key pair
    RSIP_KEY_PAIR_TYPE_RSA_4096,            ///< RSA-4096 key pair

    RSIP_KEY_PAIR_TYPE_NUM                  // Number of key pair types
} rsip_key_pair_type_t;

/** Block cipher modes of operation for AES */
typedef enum e_rsip_aes_mode
{
    RSIP_AES_MODE_ECB,                 ///< ECB (Electronic codebook)
    RSIP_AES_MODE_CBC,                 ///< CBC (Cipher block chaining)
    RSIP_AES_MODE_CTR,                 ///< CTR (Counter)
    RSIP_AES_MODE_XTS                  ///< XTS (XEX-based tweaked-codebook mode with ciphertext stealing)
} rsip_aes_mode_t;

/** Hash type */
typedef enum e_rsip_hash_type
{
    RSIP_HASH_TYPE_SHA1,               ///< SHA-1
    RSIP_HASH_TYPE_SHA224,             ///< SHA-224
    RSIP_HASH_TYPE_SHA256,             ///< SHA-256
    RSIP_HASH_TYPE_SHA384,             ///< SHA-384
    RSIP_HASH_TYPE_SHA512,             ///< SHA-512
    RSIP_HASH_TYPE_SHA512_224,         ///< SHA-512/224
    RSIP_HASH_TYPE_SHA512_256          ///< SHA-512/256
} rsip_hash_type_t;

/** MGF type */
typedef enum e_rsip_mgf_type
{
    RSIP_MGF_TYPE_MGF1_SHA1       = RSIP_HASH_TYPE_SHA1,       ///< MGF1 with SHA-1
    RSIP_MGF_TYPE_MGF1_SHA224     = RSIP_HASH_TYPE_SHA224,     ///< MGF1 with SHA-224
    RSIP_MGF_TYPE_MGF1_SHA256     = RSIP_HASH_TYPE_SHA256,     ///< MGF1 with SHA-256
    RSIP_MGF_TYPE_MGF1_SHA384     = RSIP_HASH_TYPE_SHA384,     ///< MGF1 with SHA-384
    RSIP_MGF_TYPE_MGF1_SHA512     = RSIP_HASH_TYPE_SHA512,     ///< MGF1 with SHA-512
    RSIP_MGF_TYPE_MGF1_SHA512_224 = RSIP_HASH_TYPE_SHA512_224, ///< MGF1 with SHA-512/224
    RSIP_MGF_TYPE_MGF1_SHA512_256 = RSIP_HASH_TYPE_SHA512_256  ///< MGF1 with SHA-512/256
} rsip_mgf_type_t;

/** Password type. This enumerated type is used only on specific devices. */
typedef enum e_password_type
{
    RSIP_PASSWORD_TYPE_JTAG_DEBUG_AUTHENTICATION_LEVEL1, ///< JTAG debug authentication level 1
    RSIP_PASSWORD_TYPE_JTAG_DEBUG_AUTHENTICATION_LEVEL2, ///< JTAG debug authentication level 2
} rsip_password_type_t;

/* State that specifies functions that can be called next. This enum is private. */
typedef enum e_rsip_user_handle_state
{
    RSIP_USER_HANDLE_STATE_INIT,         // Init function can be called.
    RSIP_USER_HANDLE_STATE_UPDATE_EMPTY, // Update and Final function can be called. No data has been entered yet.
    RSIP_USER_HANDLE_STATE_UPDATE        // Update and Final function can be called. Some data has been entered.
} rsip_user_handle_state_t;

/** Wrapped key structure for all supported algorithms. The struct length of each algorithm is defined by RSIP_BYTE_SIZE_WRAPPED_KEY macro. */
typedef struct st_rsip_wrapped_key
{
    rsip_key_type_t type;              ///< type of wrapped key
    uint8_t         value[];           ///< variable length array to store the key value
} rsip_wrapped_key_t;

/**
 * Byte size of encrypted key
 * @deprecated
 * - The following member will be renamed in the next major update.
 *   - @ref RSIP_BYTE_SIZE_ENCRYPTED_KEY_ECC_secp192r1_PUBLIC to RSIP_BYTE_SIZE_ENCRYPTED_KEY_ECC_SECP192R1_PUBLIC
 *   - @ref RSIP_BYTE_SIZE_ENCRYPTED_KEY_ECC_secp192r1_PRIVATE to RSIP_BYTE_SIZE_ENCRYPTED_KEY_ECC_SECP192R1_PRIVATE
 *   - @ref RSIP_BYTE_SIZE_ENCRYPTED_KEY_ECC_secp224r1_PUBLIC to RSIP_BYTE_SIZE_ENCRYPTED_KEY_ECC_SECP224R1_PUBLIC
 *   - @ref RSIP_BYTE_SIZE_ENCRYPTED_KEY_ECC_secp224r1_PRIVATE to RSIP_BYTE_SIZE_ENCRYPTED_KEY_ECC_SECP224R1_PRIVATE
 *   - @ref RSIP_BYTE_SIZE_ENCRYPTED_KEY_ECC_secp256r1_PUBLIC to RSIP_BYTE_SIZE_ENCRYPTED_KEY_ECC_SECP256R1_PUBLIC
 *   - @ref RSIP_BYTE_SIZE_ENCRYPTED_KEY_ECC_secp256r1_PRIVATE to RSIP_BYTE_SIZE_ENCRYPTED_KEY_ECC_SECP256R1_PRIVATE
 * - The following member will be obsoleted in the next major update.
 *   - @ref RSIP_BYTE_SIZE_ENCRYPTED_KEY_AES_MAX
 *   - @ref RSIP_BYTE_SIZE_ENCRYPTED_KEY_ECC_PUBLIC_MAX
 *   - @ref RSIP_BYTE_SIZE_ENCRYPTED_KEY_ECC_PRIVATE_MAX
 *   - @ref RSIP_BYTE_SIZE_ENCRYPTED_KEY_RSA_PUBLIC_MAX
 *   - @ref RSIP_BYTE_SIZE_ENCRYPTED_KEY_RSA_PRIVATE_MAX
 *   - @ref RSIP_BYTE_SIZE_ENCRYPTED_KEY_HMAC_MAX
 *   - @ref RSIP_BYTE_SIZE_ENCRYPTED_KEY_MAX
 */
typedef enum e_rsip_byte_size_encrypted_key
{
    RSIP_BYTE_SIZE_ENCRYPTED_KEY_AES_128                     = 32U,   ///< AES-128
    RSIP_BYTE_SIZE_ENCRYPTED_KEY_AES_256                     = 48U,   ///< AES-256
    RSIP_BYTE_SIZE_ENCRYPTED_KEY_AES_128_XTS                 = 48U,   ///< AES-128-XTS
    RSIP_BYTE_SIZE_ENCRYPTED_KEY_AES_256_XTS                 = 80U,   ///< AES-256-XTS
    RSIP_BYTE_SIZE_ENCRYPTED_KEY_ECC_secp192r1_PUBLIC        = 80U,   ///< secp192r1 public key
    RSIP_BYTE_SIZE_ENCRYPTED_KEY_ECC_secp192r1_PRIVATE       = 48U,   ///< secp192r1 private key
    RSIP_BYTE_SIZE_ENCRYPTED_KEY_ECC_secp224r1_PUBLIC        = 80U,   ///< secp224r1 public key
    RSIP_BYTE_SIZE_ENCRYPTED_KEY_ECC_secp224r1_PRIVATE       = 48U,   ///< secp224r1 private key
    RSIP_BYTE_SIZE_ENCRYPTED_KEY_ECC_secp256r1_PUBLIC        = 80U,   ///< secp256r1 public key
    RSIP_BYTE_SIZE_ENCRYPTED_KEY_ECC_secp256r1_PRIVATE       = 48U,   ///< secp256r1 private key
    RSIP_BYTE_SIZE_ENCRYPTED_KEY_ECC_BRAINPOOLP256R1_PUBLIC  = 80U,   ///< brainpoolP256r1 public key
    RSIP_BYTE_SIZE_ENCRYPTED_KEY_ECC_BRAINPOOLP256R1_PRIVATE = 48U,   ///< brainpoolP256r1 private key
    RSIP_BYTE_SIZE_ENCRYPTED_KEY_RSA_1024_PUBLIC_ENHANCED    = 160U,  ///< RSA-1024 public key
    RSIP_BYTE_SIZE_ENCRYPTED_KEY_RSA_1024_PRIVATE_ENHANCED   = 272U,  ///< RSA-1024 private key
    RSIP_BYTE_SIZE_ENCRYPTED_KEY_RSA_2048_PUBLIC_ENHANCED    = 288U,  ///< RSA-2048 public key
    RSIP_BYTE_SIZE_ENCRYPTED_KEY_RSA_2048_PRIVATE_ENHANCED   = 528U,  ///< RSA-2048 private key
    RSIP_BYTE_SIZE_ENCRYPTED_KEY_RSA_3072_PUBLIC             = 416U,  ///< RSA-3072 public key
    RSIP_BYTE_SIZE_ENCRYPTED_KEY_RSA_3072_PRIVATE            = 784U,  ///< RSA-3072 private key
    RSIP_BYTE_SIZE_ENCRYPTED_KEY_RSA_4096_PUBLIC             = 544U,  ///< RSA-4096 public key
    RSIP_BYTE_SIZE_ENCRYPTED_KEY_RSA_4096_PRIVATE            = 1040U, ///< RSA-4096 private key
    RSIP_BYTE_SIZE_ENCRYPTED_KEY_HMAC_SHA1                   = 48U,   ///< HMAC-SHA1 private key
    RSIP_BYTE_SIZE_ENCRYPTED_KEY_HMAC_SHA224                 = 48U,   ///< HMAC-SHA224 private key
    RSIP_BYTE_SIZE_ENCRYPTED_KEY_HMAC_SHA256                 = 48U,   ///< HMAC-SHA256 private key
    RSIP_BYTE_SIZE_ENCRYPTED_KEY_KEY_UPDATE_KEY              = 48U,   ///< Key Update Key (KUK)

    RSIP_BYTE_SIZE_ENCRYPTED_KEY_AES_MAX =
        RSIP_BYTE_SIZE_ENCRYPTED_KEY_AES_256_XTS,                     ///< Maximum length in AES keys
    RSIP_BYTE_SIZE_ENCRYPTED_KEY_ECC_PUBLIC_MAX =
        RSIP_BYTE_SIZE_ENCRYPTED_KEY_ECC_secp256r1_PUBLIC,            ///< Maximum length in ECC public keys
    RSIP_BYTE_SIZE_ENCRYPTED_KEY_ECC_PRIVATE_MAX =
        RSIP_BYTE_SIZE_ENCRYPTED_KEY_ECC_secp256r1_PRIVATE,           ///< Maximum length in ECC private keys
    RSIP_BYTE_SIZE_ENCRYPTED_KEY_RSA_PUBLIC_MAX =
        RSIP_BYTE_SIZE_ENCRYPTED_KEY_RSA_4096_PUBLIC,                 ///< Maximum length in RSA public keys
    RSIP_BYTE_SIZE_ENCRYPTED_KEY_RSA_PRIVATE_MAX =
        RSIP_BYTE_SIZE_ENCRYPTED_KEY_RSA_4096_PRIVATE,                ///< Maximum length in RSA private keys
    RSIP_BYTE_SIZE_ENCRYPTED_KEY_HMAC_MAX =
        RSIP_BYTE_SIZE_ENCRYPTED_KEY_HMAC_SHA256,                     ///< Maximum length in HMAC keys
    RSIP_BYTE_SIZE_ENCRYPTED_KEY_MAX =
        RSIP_BYTE_SIZE_ENCRYPTED_KEY_RSA_PRIVATE_MAX,                 ///< Maximum length in all RSIP keys
} rsip_byte_size_encrypted_key_t;

/** Byte size of wrapped key (value)
 * @deprecated
 * - The following member will be renamed in the next major update.
 *   - @ref RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_ECC_secp192r1_PUBLIC to RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_ECC_SECP192R1_PUBLIC
 *   - @ref RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_ECC_secp192r1_PRIVATE to RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_ECC_SECP192R1_PRIVATE
 *   - @ref RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_ECC_secp224r1_PUBLIC to RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_ECC_SECP224R1_PUBLIC
 *   - @ref RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_ECC_secp224r1_PRIVATE to RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_ECC_SECP224R1_PRIVATE
 *   - @ref RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_ECC_secp256r1_PUBLIC to RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_ECC_SECP256R1_PUBLIC
 *   - @ref RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_ECC_secp256r1_PRIVATE to RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_ECC_SECP256R1_PRIVATE
 * - The following member will be obsoleted in the next major update.
 *   - @ref RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_AES_MAX
 *   - @ref RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_ECC_PUBLIC_MAX
 *   - @ref RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_ECC_PRIVATE_MAX
 *   - @ref RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_RSA_PUBLIC_MAX
 *   - @ref RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_RSA_PRIVATE_MAX
 *   - @ref RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_HMAC_MAX
 *   - @ref RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_MAX
 */
typedef enum e_rsip_byte_size_wrapped_key_value
{
    RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_AES_128                     = 48U,   ///< AES-128
    RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_AES_256                     = 64U,   ///< AES-256
    RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_AES_128_XTS                 = 64U,   ///< AES-128-XTS
    RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_AES_256_XTS                 = 96U,   ///< AES-256-XTS
    RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_ECC_secp192r1_PUBLIC        = 96U,   ///< secp192r1 public key
    RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_ECC_secp192r1_PRIVATE       = 64U,   ///< secp192r1 private key
    RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_ECC_secp224r1_PUBLIC        = 96U,   ///< secp224r1 public key
    RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_ECC_secp224r1_PRIVATE       = 64U,   ///< secp224r1 private key
    RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_ECC_secp256r1_PUBLIC        = 96U,   ///< secp256r1 public key
    RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_ECC_secp256r1_PRIVATE       = 64U,   ///< secp256r1 private key
    RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_ECC_BRAINPOOLP256R1_PUBLIC  = 96U,   ///< brainpoolP256r1 public key
    RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_ECC_BRAINPOOLP256R1_PRIVATE = 64U,   ///< brainpoolP256r1 private key
    RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_RSA_1024_PUBLIC_ENHANCED    = 176U,  ///< RSA-1024 public key
    RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_RSA_1024_PRIVATE_ENHANCED   = 288U,  ///< RSA-1024 private key
    RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_RSA_2048_PUBLIC_ENHANCED    = 304U,  ///< RSA-2048 public key
    RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_RSA_2048_PRIVATE_ENHANCED   = 544U,  ///< RSA-2048 private key
    RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_RSA_3072_PUBLIC             = 432U,  ///< RSA-3072 public key
    RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_RSA_3072_PRIVATE            = 800U,  ///< RSA-3072 private key
    RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_RSA_4096_PUBLIC             = 560U,  ///< RSA-4096 public key
    RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_RSA_4096_PRIVATE            = 1056U, ///< RSA-4096 private key
    RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_HMAC_SHA1                   = 64U,   ///< HMAC-SHA1 private key
    RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_HMAC_SHA224                 = 64U,   ///< HMAC-SHA224 private key
    RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_HMAC_SHA256                 = 64U,   ///< HMAC-SHA256 private key
    RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_KEY_UPDATE_KEY              = 64U,   ///< Key Update Key (KUK)

    RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_AES_MAX =
        RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_AES_256_XTS,                     ///< Maximum length in AES keys
    RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_ECC_PUBLIC_MAX =
        RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_ECC_secp256r1_PUBLIC,            ///< Maximum length in ECC public keys
    RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_ECC_PRIVATE_MAX =
        RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_ECC_secp256r1_PRIVATE,           ///< Maximum length in ECC private keys
    RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_RSA_PUBLIC_MAX =
        RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_RSA_4096_PUBLIC,                 ///< Maximum length in RSA public keys
    RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_RSA_PRIVATE_MAX =
        RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_RSA_4096_PRIVATE,                ///< Maximum length in RSA private keys
    RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_HMAC_MAX =
        RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_HMAC_SHA256,                     ///< Maximum length in HMAC keys
    RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_MAX =
        RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_RSA_PRIVATE_MAX,                 ///< Maximum length in all RSIP keys
} rsip_byte_size_wrapped_key_value_t;

/**
 * Byte size of wrapped key (header + value)
 * @deprecated
 * - The following member will be renamed in the next major update.
 *   - @ref RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_secp192r1_PUBLIC to RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_SECP192R1_PUBLIC
 *   - @ref RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_secp192r1_PRIVATE to RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_SECP192R1_PRIVATE
 *   - @ref RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_secp224r1_PUBLIC to RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_SECP224R1_PUBLIC
 *   - @ref RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_secp224r1_PRIVATE to RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_SECP224R1_PRIVATE
 *   - @ref RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_secp256r1_PUBLIC to RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_SECP256R1_PUBLIC
 *   - @ref RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_secp256r1_PRIVATE to RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_SECP256R1_PRIVATE
 * - The following member will be obsoleted in the next major update.
 *   - @ref RSIP_BYTE_SIZE_WRAPPED_KEY_AES_MAX
 *   - @ref RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_PUBLIC_MAX
 *   - @ref RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_PRIVATE_MAX
 *   - @ref RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_PUBLIC_MAX
 *   - @ref RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_PRIVATE_MAX
 *   - @ref RSIP_BYTE_SIZE_WRAPPED_KEY_HMAC_MAX
 *   - @ref RSIP_BYTE_SIZE_WRAPPED_KEY_MAX
 */
typedef enum e_rsip_byte_size_wrapped_key
{
    RSIP_BYTE_SIZE_WRAPPED_KEY_AES_128 =
        sizeof(rsip_wrapped_key_t) +
        RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_AES_128,                     ///< AES-128
    RSIP_BYTE_SIZE_WRAPPED_KEY_AES_256 =
        sizeof(rsip_wrapped_key_t) +
        RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_AES_256,                     ///< AES-256
    RSIP_BYTE_SIZE_WRAPPED_KEY_AES_128_XTS =
        sizeof(rsip_wrapped_key_t) +
        RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_AES_128_XTS,                 ///< AES-128-XTS
    RSIP_BYTE_SIZE_WRAPPED_KEY_AES_256_XTS =
        sizeof(rsip_wrapped_key_t) +
        RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_AES_256_XTS,                 ///< AES-256-XTS
    RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_secp192r1_PUBLIC =
        sizeof(rsip_wrapped_key_t) +
        RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_ECC_secp192r1_PUBLIC,        ///< secp192r1 public key
    RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_secp192r1_PRIVATE =
        sizeof(rsip_wrapped_key_t) +
        RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_ECC_secp192r1_PRIVATE,       ///< secp192r1 private key
    RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_secp224r1_PUBLIC =
        sizeof(rsip_wrapped_key_t) +
        RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_ECC_secp224r1_PUBLIC,        ///< secp224r1 public key
    RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_secp224r1_PRIVATE =
        sizeof(rsip_wrapped_key_t) +
        RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_ECC_secp224r1_PRIVATE,       ///< secp224r1 private key
    RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_secp256r1_PUBLIC =
        sizeof(rsip_wrapped_key_t) +
        RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_ECC_secp256r1_PUBLIC,        ///< secp256r1 public key
    RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_secp256r1_PRIVATE =
        sizeof(rsip_wrapped_key_t) +
        RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_ECC_secp256r1_PRIVATE,       ///< secp256r1 private key
    RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_BRAINPOOLP256R1_PUBLIC =
        sizeof(rsip_wrapped_key_t) +
        RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_ECC_BRAINPOOLP256R1_PUBLIC,  ///< brainpoolP256r1 public key
    RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_BRAINPOOLP256R1_PRIVATE =
        sizeof(rsip_wrapped_key_t) +
        RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_ECC_BRAINPOOLP256R1_PRIVATE, ///< brainpoolP256r1 private key
    RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_1024_PUBLIC_ENHANCED =
        sizeof(rsip_wrapped_key_t) +
        RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_RSA_1024_PUBLIC_ENHANCED,    ///< RSA-1024 public key
    RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_1024_PRIVATE_ENHANCED =
        sizeof(rsip_wrapped_key_t) +
        RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_RSA_1024_PRIVATE_ENHANCED,   ///< RSA-1024 private key
    RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_2048_PUBLIC_ENHANCED =
        sizeof(rsip_wrapped_key_t) +
        RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_RSA_2048_PUBLIC_ENHANCED,    ///< RSA-2048 public key
    RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_2048_PRIVATE_ENHANCED =
        sizeof(rsip_wrapped_key_t) +
        RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_RSA_2048_PRIVATE_ENHANCED,   ///< RSA-2048 private key
    RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_3072_PUBLIC =
        sizeof(rsip_wrapped_key_t) +
        RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_RSA_3072_PUBLIC,             ///< RSA-3072 public key
    RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_3072_PRIVATE =
        sizeof(rsip_wrapped_key_t) +
        RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_RSA_3072_PRIVATE,            ///< RSA-3072 private key
    RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_4096_PUBLIC =
        sizeof(rsip_wrapped_key_t) +
        RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_RSA_4096_PUBLIC,             ///< RSA-4096 public key
    RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_4096_PRIVATE =
        sizeof(rsip_wrapped_key_t) +
        RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_RSA_4096_PRIVATE,            ///< RSA-4096 private key
    RSIP_BYTE_SIZE_WRAPPED_KEY_HMAC_SHA1 =
        sizeof(rsip_wrapped_key_t) +
        RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_HMAC_SHA1,                   ///< HMAC-SHA1 private key
    RSIP_BYTE_SIZE_WRAPPED_KEY_HMAC_SHA224 =
        sizeof(rsip_wrapped_key_t) +
        RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_HMAC_SHA224,                 ///< HMAC-SHA224 private key
    RSIP_BYTE_SIZE_WRAPPED_KEY_HMAC_SHA256 =
        sizeof(rsip_wrapped_key_t) +
        RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_HMAC_SHA256,                 ///< HMAC-SHA256 private key
    RSIP_BYTE_SIZE_WRAPPED_KEY_KEY_UPDATE_KEY =
        sizeof(rsip_wrapped_key_t) +
        RSIP_BYTE_SIZE_WRAPPED_KEY_VALUE_KEY_UPDATE_KEY,              ///< Key Update Key (KUK)

    RSIP_BYTE_SIZE_WRAPPED_KEY_AES_MAX =
        RSIP_BYTE_SIZE_WRAPPED_KEY_AES_256_XTS,                       ///< Maximum length in AES keys
    RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_PUBLIC_MAX =
        RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_secp256r1_PUBLIC,              ///< Maximum length in ECC public keys
    RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_PRIVATE_MAX =
        RSIP_BYTE_SIZE_WRAPPED_KEY_ECC_secp256r1_PRIVATE,             ///< Maximum length in ECC private keys
    RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_PUBLIC_MAX =
        RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_4096_PUBLIC,                   ///< Maximum length in RSA public keys
    RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_PRIVATE_MAX =
        RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_4096_PRIVATE,                  ///< Maximum length in RSA private keys
    RSIP_BYTE_SIZE_WRAPPED_KEY_HMAC_MAX =
        RSIP_BYTE_SIZE_WRAPPED_KEY_HMAC_SHA256,                       ///< Maximum length in HMAC keys
    RSIP_BYTE_SIZE_WRAPPED_KEY_MAX =
        RSIP_BYTE_SIZE_WRAPPED_KEY_RSA_PRIVATE_MAX,                   ///< Maximum length in all RSIP keys
} rsip_byte_size_wrapped_key_t;

/** Working area for SHA cipher functions. DO NOT MODIFY. */
typedef struct st_rsip_sha_handle
{
    rsip_hash_type_t         type;                                              // Hash type
    uint8_t                  buffer[RSIP_BYTE_SIZE_SHA_MESSAGE_BUFFER];         // Stored message
    uint32_t                 buffered_length;                                   // Buffered message length
    uint32_t                 total_length;                                      // Total message length input to primitive
    uint32_t                 block_size;                                        // Block size
    rsip_user_handle_state_t state;                                             // Handle state
    uint32_t                 internal_state[RSIP_WORD_SIZE_SHA_INTERNAL_STATE]; // Internal state
} rsip_sha_handle_t;

/** Working area for HMAC cipher functions. DO NOT MODIFY. */
typedef struct st_rsip_hmac_handle
{
    const void             * p_primitive;                                       // Pointer to primitive functions
    uint8_t                  wrapped_key[RSIP_BYTE_SIZE_WRAPPED_KEY_HMAC_MAX];  // Stored wrapped key
    uint8_t                  buffer[RSIP_BYTE_SIZE_SHA_MESSAGE_BUFFER];         // Stored message
    uint32_t                 buffered_length;                                   // Buffered message length
    uint32_t                 total_length;                                      // Total message length input to primitive
    uint32_t                 block_size;                                        // Block size
    rsip_user_handle_state_t state;                                             // Handle state
    uint32_t                 internal_state[RSIP_WORD_SIZE_SHA_INTERNAL_STATE]; // Internal state
    bool is_generate;                                                           // true: generate, false: verify
} rsip_hmac_handle_t;

/** RSIP Control block. Allocate an instance specific control block to pass into the API calls.
 * @par Implemented as
 * - rsip_instance_ctrl_t
 */
typedef void rsip_ctrl_t;

/** User configuration structure, used in open function */
typedef struct st_rsip_cfg
{
    void const * p_extend;             ///< Hardware-dependent configuration
} rsip_cfg_t;

/** This structure encompasses everything that is needed to use an instance of this interface. */
typedef struct st_rsip_instance
{
    rsip_ctrl_t      * p_ctrl;         ///< Pointer to the control structure for this instance
    rsip_cfg_t const * p_cfg;          ///< Pointer to the configuration structure for this instance
} rsip_instance_t;

/* Common macro for FSP header files. There is also a corresponding FSP_HEADER macro at the top of this file. */
FSP_FOOTER

#endif                                 /* R_RSIP_API_H */

/*******************************************************************************************************************//**
 * @} (end addtogroup RSIP_API)
 **********************************************************************************************************************/
