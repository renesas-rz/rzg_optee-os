/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2024, Renesas Electronics Corporation
 */

#ifndef R_RSIP_COMMON_H
#define R_RSIP_COMMON_H

/***********************************************************************************************************************
 * Includes
 **********************************************************************************************************************/
#include "r_rsip.h"
#include "r_rsip_private.h"
#include "r_rsip_util.h"

/***********************************************************************************************************************
 * Macro definitions
 **********************************************************************************************************************/

#define RSIP_PRV_IS_AES_KEY(key_type) \
    ((RSIP_KEY_TYPE_AES_128 == (key_type)) || (RSIP_KEY_TYPE_AES_256 == (key_type)))
#define RSIP_PRV_IS_XTS_AES_KEY(key_type) \
    ((RSIP_KEY_TYPE_AES_128_XTS == (key_type)) || (RSIP_KEY_TYPE_AES_256_XTS == (key_type)))
#define RSIP_PRV_IS_ECC_PUBKEY(key_type) \
    ((RSIP_KEY_TYPE_ECC_secp192r1_PUBLIC == (key_type)) || (RSIP_KEY_TYPE_ECC_secp224r1_PUBLIC == (key_type)) || \
     (RSIP_KEY_TYPE_ECC_secp256r1_PUBLIC == (key_type)) || (RSIP_KEY_TYPE_ECC_BRAINPOOLP256R1_PUBLIC == (key_type)))
#define RSIP_PRV_IS_ECC_PRIVKEY(key_type) \
    ((RSIP_KEY_TYPE_ECC_secp192r1_PRIVATE == (key_type)) || (RSIP_KEY_TYPE_ECC_secp224r1_PRIVATE == (key_type)) || \
     (RSIP_KEY_TYPE_ECC_secp256r1_PRIVATE == (key_type)) || (RSIP_KEY_TYPE_ECC_BRAINPOOLP256R1_PRIVATE == (key_type)))
#define RSIP_PRV_IS_RSA_PUBKEY(key_type)                                                               \
    ((RSIP_KEY_TYPE_RSA_3072_PUBLIC == (key_type)) || (RSIP_KEY_TYPE_RSA_4096_PUBLIC == (key_type))   || \
     (RSIP_KEY_TYPE_RSA_1024_PUBLIC_ENHANCED == (key_type)) || (RSIP_KEY_TYPE_RSA_2048_PUBLIC_ENHANCED == (key_type)))
#define RSIP_PRV_IS_RSA_PRIVKEY(key_type)                                                                \
    ((RSIP_KEY_TYPE_RSA_3072_PRIVATE == (key_type)) || (RSIP_KEY_TYPE_RSA_4096_PRIVATE == (key_type)) || \
     (RSIP_KEY_TYPE_RSA_1024_PRIVATE_ENHANCED == (key_type)) || (RSIP_KEY_TYPE_RSA_2048_PRIVATE_ENHANCED == (key_type)))
#define RSIP_PRV_IS_HMAC_KEY(key_type)                                                       \
    ((RSIP_KEY_TYPE_HMAC_SHA1 == (key_type)) || (RSIP_KEY_TYPE_HMAC_SHA224 == (key_type)) || \
     (RSIP_KEY_TYPE_HMAC_SHA256 == (key_type)))

/* "RSIP" in ASCII, used to determine if channel is open. */
#define RSIP_OPEN    (0x52534950ULL)

/***********************************************************************************************************************
 * Typedef definitions
 **********************************************************************************************************************/

/**********************************************************************************************************************
 * Exported global variables
 **********************************************************************************************************************/

/**********************************************************************************************************************
 * Public Function Prototypes
 **********************************************************************************************************************/

/* Internal public functions */
fsp_err_t r_rsip_random_number_generate(rsip_ctrl_t * const p_ctrl, uint8_t * const p_random);
fsp_err_t r_rsip_sha_generate_init(rsip_ctrl_t * const       p_ctrl,
                                   rsip_sha_handle_t * const p_handle,
                                   rsip_hash_type_t const    hash_type);
fsp_err_t r_rsip_sha_generate_update(rsip_ctrl_t * const       p_ctrl,
                                     rsip_sha_handle_t * const p_handle,
                                     uint8_t const * const     p_message,
                                     uint32_t const            message_length);
fsp_err_t r_rsip_sha_generate_final(rsip_ctrl_t * const       p_ctrl,
                                    rsip_sha_handle_t * const p_handle,
                                    uint8_t * const           p_digest);

/*******************************************************************************************************************//**
 * Clears handle.
 ***********************************************************************************************************************/
RSIP_PRV_STATIC_INLINE void r_rsip_handle_reset (rsip_handle_t * handle)
{
    memset(handle, 0, sizeof(rsip_handle_t));
}

/*******************************************************************************************************************//**
 * Change state to RSIP_STATE_INIT
 ***********************************************************************************************************************/
RSIP_PRV_STATIC_INLINE void r_rsip_state_transit_init (rsip_instance_ctrl_t * p_instance_ctrl)
{
    p_instance_ctrl->state       = RSIP_STATE_INIT;
    p_instance_ctrl->handle_type = RSIP_HANDLE_TYPE_INVALID;
}

/*******************************************************************************************************************//**
 * Change state to RSIP_STATE_UPDATE
 ***********************************************************************************************************************/
RSIP_PRV_STATIC_INLINE void r_rsip_state_transit_update (rsip_instance_ctrl_t * p_instance_ctrl,
                                                         rsip_handle_type_t     handle_type)
{
    p_instance_ctrl->state       = RSIP_STATE_UPDATE;
    p_instance_ctrl->handle_type = handle_type;
}

/*******************************************************************************************************************//**
 * Change state to RSIP_STATE_FINAL
 ***********************************************************************************************************************/
RSIP_PRV_STATIC_INLINE void r_rsip_state_transit_final (rsip_instance_ctrl_t * p_instance_ctrl)
{
    p_instance_ctrl->state = RSIP_STATE_FINAL;
}

/*******************************************************************************************************************//**
 * Check state (RSIP_STATE_INIT)
 ***********************************************************************************************************************/
RSIP_PRV_STATIC_INLINE bool r_rsip_state_check_init (rsip_instance_ctrl_t * p_instance_ctrl)
{
    return RSIP_STATE_INIT == p_instance_ctrl->state;
}

/*******************************************************************************************************************//**
 * Check state (RSIP_STATE_UPDATE)
 ***********************************************************************************************************************/
RSIP_PRV_STATIC_INLINE bool r_rsip_state_check_update (rsip_instance_ctrl_t   * p_instance_ctrl,
                                                       const rsip_handle_type_t handle_type)
{
    return (RSIP_STATE_UPDATE == p_instance_ctrl->state) && (handle_type == p_instance_ctrl->handle_type);
}

/*******************************************************************************************************************//**
 * Check state (RSIP_STATE_FINAL)
 ***********************************************************************************************************************/
RSIP_PRV_STATIC_INLINE bool r_rsip_state_check_final (rsip_instance_ctrl_t   * p_instance_ctrl,
                                                      const rsip_handle_type_t handle_type)
{
    return ((RSIP_STATE_UPDATE == p_instance_ctrl->state) || (RSIP_STATE_FINAL == p_instance_ctrl->state)) &&
           (handle_type == p_instance_ctrl->handle_type);
}

#endif                                 /* R_RSIP_COMMON_H */
