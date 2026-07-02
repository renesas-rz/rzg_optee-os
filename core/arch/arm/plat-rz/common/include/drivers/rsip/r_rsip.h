/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2024, Renesas Electronics Corporation
 */

/*******************************************************************************************************************//**
 * @addtogroup RSIP
 * @{
 **********************************************************************************************************************/

#ifndef R_RSIP_H
#define R_RSIP_H

#include "bsp_api.h"
#include "r_rsip_cfg.h"
#include "r_rsip_api.h"

/* Common macro for FSP header files. There is also a corresponding FSP_FOOTER macro at the end of this file. */
FSP_HEADER

/***********************************************************************************************************************
 * Macro definitions
 **********************************************************************************************************************/

#define RSIP_BYTE_SIZE_AES_BLOCK    (16U)

/***********************************************************************************************************************
 * Typedef definitions
 **********************************************************************************************************************/

/* Handle of algorithms that cannot be suspended. This union is included in private control block. */
typedef union u_rsip_handle
{
    struct
    {
        const void * p_primitive;                          // Pointer to primitive functions
    } aes;
    struct
    {
        const void * p_primitive;                          // Pointer to primitive functions
        uint8_t      buffer[RSIP_BYTE_SIZE_AES_BLOCK * 2]; // Buffer for computing final partial block
        uint32_t     buffered_length;                      // Length of second to last and final partial block
    } xts;
    struct
    {
        const void * p_primitive;                          // Pointer to primitive functions
        uint8_t      buffer[RSIP_BYTE_SIZE_AES_BLOCK];     // Buffer for AAD or plaintext/ciphertext
        uint32_t     buffered_length;                      // Buffered AAD or plaintext/ciphertext length
        uint32_t     total_length;                         // Total plaintext/ciphertext length
        uint32_t     total_aad_length;                     // Total AAD length
        bool         has_finished_aad_input;               // Whether AAD input has been finished
    } gcm;
    struct
    {
        const void * p_primitive;                          // Pointer to primitive functions
        uint8_t      buffer[RSIP_BYTE_SIZE_AES_BLOCK];     // Buffer for message
        uint32_t     buffered_length;                      // Buffered message length
        uint32_t     total_length;                         // Total message length
    } cmac;
} rsip_handle_t;

/* Types of algorithm being execute */
typedef enum e_rsip_handle_type
{
    RSIP_HANDLE_TYPE_INVALID,          // Invalid handle type
    RSIP_HANDLE_TYPE_AES_ENCRYPT,      // AES-ECB/CBC/CTR encryption
    RSIP_HANDLE_TYPE_AES_DECRYPT,      // AES-ECB/CBC/CTR decryption
    RSIP_HANDLE_TYPE_XTS_ENCRYPT,      // AES-XTS encryption
    RSIP_HANDLE_TYPE_XTS_DECRYPT,      // AES-XTS decryption
    RSIP_HANDLE_TYPE_GCM_ENCRYPT,      // AES-GCM encryption
    RSIP_HANDLE_TYPE_GCM_DECRYPT,      // AES-GCM decryption
    RSIP_HANDLE_TYPE_CMAC_GENERATE,    // AES-CMAC MAC generation
    RSIP_HANDLE_TYPE_CMAC_VERIFY       // AES-CMAC MAC verification
} rsip_handle_type_t;

/* State that specifies functions that can be called next */
typedef enum e_rsip_state
{
    RSIP_STATE_INIT,                   // All Init function or single-part function can be called
    RSIP_STATE_UPDATE,                 // Update and Final function related to the executing algorithm can be called
    RSIP_STATE_FINAL                   // Final function related to the executing algorithm can be called
} rsip_state_t;

/** RSIP private control block. DO NOT MODIFY. Initialization occurs when R_RSIP_Open() is called. */
typedef struct st_rsip_instance_ctrl
{
    uint32_t           open;           // Indicates whether the open() API has been successfully
    rsip_cfg_t const * p_cfg;          // Pointer to the configuration block
    rsip_handle_t      handle;         // Handle of algorithms that cannot be suspended
    rsip_handle_type_t handle_type;    // Current handle type
    rsip_state_t       state;          // Flags to limit the next API to call
} rsip_instance_ctrl_t;

/**********************************************************************************************************************
 * Exported global variables
 **********************************************************************************************************************/

/**********************************************************************************************************************
 * Public Function Prototypes
 **********************************************************************************************************************/

/* r_rsip.c */
fsp_err_t R_RSIP_Open(rsip_ctrl_t * const p_ctrl, rsip_cfg_t const * const p_cfg);
fsp_err_t R_RSIP_Close(rsip_ctrl_t * const p_ctrl);
fsp_err_t R_RSIP_RandomNumberGenerate(rsip_ctrl_t * const p_ctrl, uint8_t * const p_random);
fsp_err_t R_RSIP_KeyGenerate(rsip_ctrl_t * const        p_ctrl,
                             rsip_key_type_t const      key_type,
                             rsip_wrapped_key_t * const p_wrapped_key);
fsp_err_t R_RSIP_KeyPairGenerate(rsip_ctrl_t * const        p_ctrl,
                                 rsip_key_pair_type_t const key_pair_type,
                                 rsip_wrapped_key_t * const p_wrapped_public_key,
                                 rsip_wrapped_key_t * const p_wrapped_private_key);
fsp_err_t R_RSIP_KeyImportWithKUK(rsip_ctrl_t * const              p_ctrl,
                                  rsip_wrapped_key_t const * const p_key_update_key,
                                  uint8_t const * const            p_initial_vector,
                                  rsip_key_type_t const            key_type,
                                  uint8_t const * const            p_encrypted_key,
                                  rsip_wrapped_key_t * const       p_wrapped_key);
fsp_err_t R_RSIP_ECCPublicKeyExport(rsip_wrapped_key_t const * const p_wrapped_public_key,
                                    uint8_t const ** const           pp_raw_public_key_qx,
                                    uint8_t const ** const           pp_raw_public_key_qy);
fsp_err_t R_RSIP_RSAPublicKeyExport(rsip_wrapped_key_t const * const p_wrapped_public_key,
                                    uint8_t const ** const           pp_raw_public_key_n,
                                    uint8_t const ** const           pp_raw_public_key_e);

/* r_rsip_aes.c */
fsp_err_t R_RSIP_AES_Cipher_EncryptInit(rsip_ctrl_t * const              p_ctrl,
                                        rsip_aes_mode_t const            mode,
                                        rsip_wrapped_key_t const * const p_wrapped_key,
                                        uint8_t const * const            p_initial_vector);
fsp_err_t R_RSIP_AES_Cipher_EncryptUpdate(rsip_ctrl_t * const   p_ctrl,
                                          uint8_t const * const p_plain,
                                          uint8_t * const       p_cipher,
                                          uint32_t const        plain_length);
fsp_err_t R_RSIP_AES_Cipher_EncryptFinal(rsip_ctrl_t * const p_ctrl,
                                         uint8_t * const     p_cipher,
                                         uint32_t * const    p_cipher_length);
fsp_err_t R_RSIP_AES_Cipher_DecryptInit(rsip_ctrl_t * const              p_ctrl,
                                        rsip_aes_mode_t const            mode,
                                        rsip_wrapped_key_t const * const p_wrapped_key,
                                        uint8_t const * const            p_initial_vector);
fsp_err_t R_RSIP_AES_Cipher_DecryptUpdate(rsip_ctrl_t * const   p_ctrl,
                                          uint8_t const * const p_cipher,
                                          uint8_t * const       p_plain,
                                          uint32_t const        cipher_length);
fsp_err_t R_RSIP_AES_Cipher_DecryptFinal(rsip_ctrl_t * const p_ctrl,
                                         uint8_t * const     p_plain,
                                         uint32_t * const    p_plain_length);
fsp_err_t R_RSIP_AES_GCM_EncryptInit(rsip_ctrl_t * const              p_ctrl,
                                     rsip_wrapped_key_t const * const p_wrapped_key,
                                     uint8_t const * const            p_nonce,
                                     uint32_t const                   nonce_length);
fsp_err_t R_RSIP_AES_GCM_EncryptUpdate(rsip_ctrl_t * const   p_ctrl,
                                       uint8_t const * const p_plain,
                                       uint8_t * const       p_cipher,
                                       uint32_t const        plain_length,
                                       uint8_t const * const p_aad,
                                       uint32_t const        aad_length);
fsp_err_t R_RSIP_AES_GCM_EncryptFinal(rsip_ctrl_t * const p_ctrl,
                                      uint8_t * const     p_cipher,
                                      uint32_t * const    p_cipher_length,
                                      uint8_t * const     p_tag);
fsp_err_t R_RSIP_AES_GCM_DecryptInit(rsip_ctrl_t * const              p_ctrl,
                                     rsip_wrapped_key_t const * const p_wrapped_key,
                                     uint8_t const * const            p_nonce,
                                     uint32_t const                   nonce_length);
fsp_err_t R_RSIP_AES_GCM_DecryptUpdate(rsip_ctrl_t * const   p_ctrl,
                                       uint8_t const * const p_cipher,
                                       uint8_t * const       p_plain,
                                       uint32_t const        cipher_length,
                                       uint8_t const * const p_aad,
                                       uint32_t const        aad_length);
fsp_err_t R_RSIP_AES_GCM_DecryptFinal(rsip_ctrl_t * const   p_ctrl,
                                      uint8_t * const       p_plain,
                                      uint32_t * const      p_plain_length,
                                      uint8_t const * const p_tag,
                                      uint32_t const        tag_length);
fsp_err_t R_RSIP_AES_CMAC_GenerateInit(rsip_ctrl_t * const p_ctrl, rsip_wrapped_key_t const * const p_wrapped_key);
fsp_err_t R_RSIP_AES_CMAC_GenerateUpdate(rsip_ctrl_t * const   p_ctrl,
                                         uint8_t const * const p_message,
                                         uint32_t const        message_length);
fsp_err_t R_RSIP_AES_CMAC_GenerateFinal(rsip_ctrl_t * const p_ctrl, uint8_t * const p_mac);
fsp_err_t R_RSIP_AES_CMAC_VerifyInit(rsip_ctrl_t * const p_ctrl, rsip_wrapped_key_t const * const p_wrapped_key);
fsp_err_t R_RSIP_AES_CMAC_VerifyUpdate(rsip_ctrl_t * const   p_ctrl,
                                       uint8_t const * const p_message,
                                       uint32_t const        message_length);
fsp_err_t R_RSIP_AES_CMAC_VerifyFinal(rsip_ctrl_t * const p_ctrl, uint8_t const * const p_mac,
                                      uint32_t const mac_length);

/* r_rsip_ecc.c */
fsp_err_t R_RSIP_ECDSA_Sign(rsip_ctrl_t * const              p_ctrl,
                            rsip_wrapped_key_t const * const p_wrapped_private_key,
                            uint8_t const * const            p_hash,
                            uint8_t * const                  p_signature);
fsp_err_t R_RSIP_ECDSA_Verify(rsip_ctrl_t * const              p_ctrl,
                              rsip_wrapped_key_t const * const p_wrapped_public_key,
                              uint8_t const * const            p_hash,
                              uint8_t const * const            p_signature);

/* r_rsip_rsa.c */
fsp_err_t R_RSIP_RSA_Encrypt(rsip_ctrl_t * const              p_ctrl,
                             rsip_wrapped_key_t const * const p_wrapped_public_key,
                             uint8_t const * const            p_plain,
                             uint8_t * const                  p_cipher);
fsp_err_t R_RSIP_RSA_Decrypt(rsip_ctrl_t * const              p_ctrl,
                             rsip_wrapped_key_t const * const p_wrapped_private_key,
                             uint8_t const * const            p_cipher,
                             uint8_t * const                  p_plain);
fsp_err_t R_RSIP_RSAES_PKCS1_V1_5_Encrypt(rsip_ctrl_t * const              p_ctrl,
                                          rsip_wrapped_key_t const * const p_wrapped_public_key,
                                          uint8_t const * const            p_plain,
                                          uint32_t const                   plain_length,
                                          uint8_t * const                  p_cipher);
fsp_err_t R_RSIP_RSAES_PKCS1_V1_5_Decrypt(rsip_ctrl_t * const              p_ctrl,
                                          rsip_wrapped_key_t const * const p_wrapped_private_key,
                                          uint8_t const * const            p_cipher,
                                          uint8_t * const                  p_plain,
                                          uint32_t * const                 p_plain_length,
                                          uint32_t const                   plain_buffer_length);
fsp_err_t R_RSIP_RSAES_OAEP_Encrypt(rsip_ctrl_t * const              p_ctrl,
                                    rsip_wrapped_key_t const * const p_wrapped_public_key,
                                    rsip_hash_type_t const           hash_function,
                                    rsip_mgf_type_t const            mask_generation_function,
                                    uint8_t const * const            p_label,
                                    uint32_t const                   label_length,
                                    uint8_t const * const            p_plain,
                                    uint32_t const                   plain_length,
                                    uint8_t * const                  p_cipher);
fsp_err_t R_RSIP_RSAES_OAEP_Decrypt(rsip_ctrl_t * const              p_ctrl,
                                    rsip_wrapped_key_t const * const p_wrapped_private_key,
                                    rsip_hash_type_t const           hash_function,
                                    rsip_mgf_type_t const            mask_generation_function,
                                    uint8_t const * const            p_label,
                                    uint32_t const                   label_length,
                                    uint8_t const * const            p_cipher,
                                    uint8_t * const                  p_plain,
                                    uint32_t * const                 p_plain_length,
                                    uint32_t const                   plain_buffer_length);
fsp_err_t R_RSIP_RSASSA_PKCS1_V1_5_Sign(rsip_ctrl_t * const              p_ctrl,
                                        rsip_wrapped_key_t const * const p_wrapped_private_key,
                                        rsip_hash_type_t const           hash_function,
                                        uint8_t const * const            p_hash,
                                        uint8_t * const                  p_signature);
fsp_err_t R_RSIP_RSASSA_PKCS1_V1_5_Verify(rsip_ctrl_t * const              p_ctrl,
                                          rsip_wrapped_key_t const * const p_wrapped_public_key,
                                          rsip_hash_type_t const           hash_function,
                                          uint8_t const * const            p_hash,
                                          uint8_t const * const            p_signature);
fsp_err_t R_RSIP_RSASSA_PSS_Sign(rsip_ctrl_t * const              p_ctrl,
                                 rsip_wrapped_key_t const * const p_wrapped_private_key,
                                 rsip_hash_type_t const           hash_function,
                                 rsip_mgf_type_t const            mask_generation_function,
                                 int32_t const                    salt_length,
                                 uint8_t const * const            p_hash,
                                 uint8_t * const                  p_signature);
fsp_err_t R_RSIP_RSASSA_PSS_Verify(rsip_ctrl_t * const              p_ctrl,
                                   rsip_wrapped_key_t const * const p_wrapped_public_key,
                                   rsip_hash_type_t const           hash_function,
                                   rsip_mgf_type_t const            mask_generation_function,
                                   int32_t const                    salt_length,
                                   uint8_t const * const            p_hash,
                                   uint8_t const * const            p_signature);

/* r_rsip_sha.c */
fsp_err_t R_RSIP_SHA_Compute(rsip_ctrl_t * const    p_ctrl,
                             rsip_hash_type_t const hash_type,
                             uint8_t const * const  p_message,
                             uint32_t const         message_length,
                             uint8_t * const        p_digest);
fsp_err_t R_RSIP_HMAC_Compute(rsip_ctrl_t * const        p_ctrl,
                              const rsip_wrapped_key_t * p_wrapped_key,
                              uint8_t const * const      p_message,
                              uint32_t const             message_length,
                              uint8_t * const            p_mac);
fsp_err_t R_RSIP_HMAC_Verify(rsip_ctrl_t * const        p_ctrl,
                             const rsip_wrapped_key_t * p_wrapped_key,
                             uint8_t const * const      p_message,
                             uint32_t const             message_length,
                             uint8_t const * const      p_mac,
                             uint32_t const             mac_length);
fsp_err_t R_RSIP_SHA_GenerateInit(rsip_ctrl_t * const       p_ctrl,
                                  rsip_sha_handle_t * const p_handle,
                                  rsip_hash_type_t const    hash_type);
fsp_err_t R_RSIP_SHA_GenerateUpdate(rsip_ctrl_t * const       p_ctrl,
                                    rsip_sha_handle_t * const p_handle,
                                    uint8_t const * const     p_message,
                                    uint32_t const            message_length);
fsp_err_t R_RSIP_SHA_GenerateFinal(rsip_ctrl_t * const       p_ctrl,
                                   rsip_sha_handle_t * const p_handle,
                                   uint8_t * const           p_digest);
fsp_err_t R_RSIP_HMAC_GenerateInit(rsip_ctrl_t * const              p_ctrl,
                                   rsip_hmac_handle_t * const       p_handle,
                                   rsip_wrapped_key_t const * const p_wrapped_key);
fsp_err_t R_RSIP_HMAC_GenerateUpdate(rsip_ctrl_t * const        p_ctrl,
                                     rsip_hmac_handle_t * const p_handle,
                                     uint8_t const * const      p_message,
                                     uint32_t const             message_length);
fsp_err_t R_RSIP_HMAC_GenerateFinal(rsip_ctrl_t * const        p_ctrl,
                                    rsip_hmac_handle_t * const p_handle,
                                    uint8_t * const            p_mac);
fsp_err_t R_RSIP_HMAC_VerifyInit(rsip_ctrl_t * const              p_ctrl,
                                 rsip_hmac_handle_t * const       p_handle,
                                 rsip_wrapped_key_t const * const p_wrapped_key);
fsp_err_t R_RSIP_HMAC_VerifyUpdate(rsip_ctrl_t * const        p_ctrl,
                                   rsip_hmac_handle_t * const p_handle,
                                   uint8_t const * const      p_message,
                                   uint32_t const             message_length);
fsp_err_t R_RSIP_HMAC_VerifyFinal(rsip_ctrl_t * const        p_ctrl,
                                  rsip_hmac_handle_t * const p_handle,
                                  uint8_t const * const      p_mac,
                                  uint32_t const             mac_length);

/* For specific devices */
fsp_err_t R_RSIP_KeyImportWithUFPK(rsip_ctrl_t * const        p_ctrl,
                                   uint8_t const * const      p_wrapped_user_factory_programming_key,
                                   uint8_t const * const      p_initial_vector,
                                   rsip_key_type_t const      key_type,
                                   uint8_t const * const      p_encrypted_key,
                                   rsip_wrapped_key_t * const p_wrapped_key);

/* Common macro for FSP header files. There is also a corresponding FSP_HEADER macro at the top of this file. */
FSP_FOOTER

#endif                                 /* R_RSIP_H */

/*******************************************************************************************************************//**
 * @} (end addtogroup RSIP)
 **********************************************************************************************************************/
