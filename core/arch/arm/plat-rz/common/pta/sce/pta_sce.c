// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2022-2026, Renesas Electronics Corporation
 */

#include <stdint.h>
#include <string.h>
#include <kernel/pseudo_ta.h>
#include <r_sce.h>
#include <pta_sce.h>
#include <hw_crypto.h>

#include "pta_sce_cmd.h"
#include "pta_sce_util.h"

#define PTA_NAME "sce.pta"

static sce_key_update_key_t wkuk;

/* Generate wrapped AES-128 key */
static TEE_Result aes128_gen_wrapped_key(struct sce_wrapped_key *wrapped_key)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;
	sce_aes_wrapped_key_t key = { 0 };

	err = R_SCE_AES128_WrappedKeyGenerate(&key);
	if (err != FSP_SUCCESS)
		return sce_err_to_tee(err);

	memcpy(wrapped_key, &key, sizeof(key));
	return TEE_SUCCESS;
}

/* Generate wrapped AES-256 key */
static TEE_Result aes256_gen_wrapped_key(struct sce_wrapped_key *wrapped_key)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;
	sce_aes_wrapped_key_t key = { 0 };

	err = R_SCE_AES256_WrappedKeyGenerate(&key);
	if (err != FSP_SUCCESS)
		return sce_err_to_tee(err);

	memcpy(wrapped_key, &key, sizeof(key));
	return TEE_SUCCESS;
}

/* Generate wrapped RSA-1024 key pair */
static TEE_Result
rsa1024_gen_wrapped_key(struct sce_wrapped_key *wrapped_pubkey,
			struct sce_wrapped_key *wrapped_prikey)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;
	sce_rsa1024_wrapped_pair_key_t key_pair = { 0 };

	err = R_SCE_RSA1024_WrappedKeyPairGenerate(&key_pair);
	if (err != FSP_SUCCESS)
		return sce_err_to_tee(err);

	memcpy(wrapped_pubkey, &key_pair.pub_key, sizeof(key_pair.pub_key));
	memcpy(wrapped_prikey, &key_pair.priv_key, sizeof(key_pair.priv_key));
	return TEE_SUCCESS;
}

/* Generate wrapped RSA-2048 key pair */
static TEE_Result
rsa2048_gen_wrapped_key(struct sce_wrapped_key *wrapped_pubkey,
			struct sce_wrapped_key *wrapped_prikey)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;
	sce_rsa2048_wrapped_pair_key_t key_pair = { 0 };

	err = R_SCE_RSA2048_WrappedKeyPairGenerate(&key_pair);
	if (err != FSP_SUCCESS)
		return sce_err_to_tee(err);

	memcpy(wrapped_pubkey, &key_pair.pub_key, sizeof(key_pair.pub_key));
	memcpy(wrapped_prikey, &key_pair.priv_key, sizeof(key_pair.priv_key));
	return TEE_SUCCESS;
}

/* Generate wrapped secp192r1 key pair */
static TEE_Result
secp192r1_gen_wrapped_key(struct sce_wrapped_key *wrapped_pubkey,
			  struct sce_wrapped_key *wrapped_prikey)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;
	sce_ecc_wrapped_pair_key_t key_pair = { 0 };

	err = R_SCE_ECC_secp192r1_WrappedKeyPairGenerate(&key_pair);
	if (err != FSP_SUCCESS)
		return sce_err_to_tee(err);

	memcpy(wrapped_pubkey, &key_pair.pub_key, sizeof(key_pair.pub_key));
	memcpy(wrapped_prikey, &key_pair.priv_key, sizeof(key_pair.priv_key));
	return TEE_SUCCESS;
}

/* Generate wrapped secp224r1 key pair */
static TEE_Result
secp224r1_gen_wrapped_key(struct sce_wrapped_key *wrapped_pubkey,
			  struct sce_wrapped_key *wrapped_prikey)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;
	sce_ecc_wrapped_pair_key_t key_pair = { 0 };

	err = R_SCE_ECC_secp224r1_WrappedKeyPairGenerate(&key_pair);
	if (err != FSP_SUCCESS)
		return sce_err_to_tee(err);

	memcpy(wrapped_pubkey, &key_pair.pub_key, sizeof(key_pair.pub_key));
	memcpy(wrapped_prikey, &key_pair.priv_key, sizeof(key_pair.priv_key));
	return TEE_SUCCESS;
}

/* Generate wrapped secp256r1 key pair */
static TEE_Result
secp256r1_gen_wrapped_key(struct sce_wrapped_key *wrapped_pubkey,
			  struct sce_wrapped_key *wrapped_prikey)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;
	sce_ecc_wrapped_pair_key_t key_pair = { 0 };

	err = R_SCE_ECC_secp256r1_WrappedKeyPairGenerate(&key_pair);
	if (err != FSP_SUCCESS)
		return sce_err_to_tee(err);

	memcpy(wrapped_pubkey, &key_pair.pub_key, sizeof(key_pair.pub_key));
	memcpy(wrapped_prikey, &key_pair.priv_key, sizeof(key_pair.priv_key));
	return TEE_SUCCESS;
}

/* Generate wrapped BrainpoolP512r1 key pair */
static TEE_Result
bp512r1_gen_wrapped_key(struct sce_wrapped_key *wrapped_pubkey,
			struct sce_wrapped_key *wrapped_prikey)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;
	sce_ecc_wrapped_pair_key_t key_pair = { 0 };

	err = R_SCE_ECC_BrainpoolP512r1_WrappedKeyPairGenerate(&key_pair);
	if (err != FSP_SUCCESS)
		return sce_err_to_tee(err);

	memcpy(wrapped_pubkey, &key_pair.pub_key, sizeof(key_pair.pub_key));
	memcpy(wrapped_prikey, &key_pair.priv_key, sizeof(key_pair.priv_key));
	return TEE_SUCCESS;
}

/* Import encrypted AES-128 key */
static TEE_Result aes128_import_key(uint8_t *iv, uint8_t *ekey,
				    struct sce_wrapped_key *wrapped_key)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;
	sce_aes_wrapped_key_t key = { 0 };

	err = R_SCE_AES128_EncryptedKeyWrap(iv, ekey, &wkuk, &key);
	if (err != FSP_SUCCESS)
		return sce_err_to_tee(err);

	memcpy(wrapped_key, &key, sizeof(key));
	return TEE_SUCCESS;
}

/* Import encrypted AES-256 key */
static TEE_Result aes256_import_key(uint8_t *iv, uint8_t *ekey,
				    struct sce_wrapped_key *wrapped_key)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;
	sce_aes_wrapped_key_t key = { 0 };

	err = R_SCE_AES256_EncryptedKeyWrap(iv, ekey, &wkuk, &key);
	if (err != FSP_SUCCESS)
		return sce_err_to_tee(err);

	memcpy(wrapped_key, &key, sizeof(key));
	return TEE_SUCCESS;
}

/* Import encrypted RSA-1024 public key */
static TEE_Result rsa1024_import_pubkey(uint8_t *iv, uint8_t *ekey,
					struct sce_wrapped_key *wrapped_pubkey)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;
	sce_rsa1024_public_wrapped_key_t pubkey = { 0 };

	err = R_SCE_RSA1024_EncryptedPublicKeyWrap(iv, ekey, &wkuk, &pubkey);
	if (err != FSP_SUCCESS)
		return sce_err_to_tee(err);

	memcpy(wrapped_pubkey, &pubkey, sizeof(pubkey));
	return TEE_SUCCESS;
}

/* Import encrypted RSA-1024 private key */
static TEE_Result rsa1024_import_prikey(uint8_t *iv, uint8_t *ekey,
					struct sce_wrapped_key *wrapped_prikey)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;
	sce_rsa1024_private_wrapped_key_t prikey = { 0 };

	err = R_SCE_RSA1024_EncryptedPrivateKeyWrap(iv, ekey, &wkuk, &prikey);
	if (err != FSP_SUCCESS)
		return sce_err_to_tee(err);

	memcpy(wrapped_prikey, &prikey, sizeof(prikey));
	return TEE_SUCCESS;
}

/* Import encrypted RSA-2048 public key */
static TEE_Result rsa2048_import_pubkey(uint8_t *iv, uint8_t *ekey,
					struct sce_wrapped_key *wrapped_pubkey)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;
	sce_rsa2048_public_wrapped_key_t pubkey = { 0 };

	err = R_SCE_RSA2048_EncryptedPublicKeyWrap(iv, ekey, &wkuk, &pubkey);
	if (err != FSP_SUCCESS)
		return sce_err_to_tee(err);

	memcpy(wrapped_pubkey, &pubkey, sizeof(pubkey));
	return TEE_SUCCESS;
}

/* Import encrypted RSA-2048 private key */
static TEE_Result rsa2048_import_prikey(uint8_t *iv, uint8_t *ekey,
					struct sce_wrapped_key *wrapped_prikey)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;
	sce_rsa2048_private_wrapped_key_t prikey = { 0 };

	err = R_SCE_RSA2048_EncryptedPrivateKeyWrap(iv, ekey, &wkuk, &prikey);
	if (err != FSP_SUCCESS)
		return sce_err_to_tee(err);

	memcpy(wrapped_prikey, &prikey, sizeof(prikey));
	return TEE_SUCCESS;
}

/* Import encrypted RSA-4096 public key */
static TEE_Result rsa4096_import_pubkey(uint8_t *iv, uint8_t *ekey,
					struct sce_wrapped_key *wrapped_pubkey)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;
	sce_rsa4096_public_wrapped_key_t pubkey = { 0 };

	err = R_SCE_RSA4096_EncryptedPublicKeyWrap(iv, ekey, &wkuk, &pubkey);
	if (err != FSP_SUCCESS)
		return sce_err_to_tee(err);

	memcpy(wrapped_pubkey, &pubkey, sizeof(pubkey));
	return TEE_SUCCESS;
}

/* Import encrypted secp192r1 public key */
static TEE_Result
secp192r1_import_pubkey(uint8_t *iv, uint8_t *ekey,
			struct sce_wrapped_key *wrapped_pubkey)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;
	sce_ecc_public_wrapped_key_t pubkey = { 0 };

	err = R_SCE_ECC_secp192r1_EncryptedPublicKeyWrap(iv, ekey, &wkuk,
							 &pubkey);
	if (err != FSP_SUCCESS)
		return sce_err_to_tee(err);

	memcpy(wrapped_pubkey, &pubkey, sizeof(pubkey));
	return TEE_SUCCESS;
}

/* Import encrypted secp192r1 private key */
static TEE_Result
secp192r1_import_prikey(uint8_t *iv, uint8_t *ekey,
			struct sce_wrapped_key *wrapped_prikey)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;
	sce_ecc_private_wrapped_key_t prikey = { 0 };

	err = R_SCE_ECC_secp192r1_EncryptedPrivateKeyWrap(iv, ekey, &wkuk,
							  &prikey);
	if (err != FSP_SUCCESS)
		return sce_err_to_tee(err);

	memcpy(wrapped_prikey, &prikey, sizeof(prikey));
	return TEE_SUCCESS;
}

/* Import encrypted secp224r1 public key */
static TEE_Result
secp224r1_import_pubkey(uint8_t *iv, uint8_t *ekey,
			struct sce_wrapped_key *wrapped_pubkey)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;
	sce_ecc_public_wrapped_key_t pubkey = { 0 };

	err = R_SCE_ECC_secp224r1_EncryptedPublicKeyWrap(iv, ekey, &wkuk,
							 &pubkey);
	if (err != FSP_SUCCESS)
		return sce_err_to_tee(err);

	memcpy(wrapped_pubkey, &pubkey, sizeof(pubkey));
	return TEE_SUCCESS;
}

/* Import encrypted secp224r1 private key */
static TEE_Result
secp224r1_import_prikey(uint8_t *iv, uint8_t *ekey,
			struct sce_wrapped_key *wrapped_prikey)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;
	sce_ecc_private_wrapped_key_t prikey = { 0 };

	err = R_SCE_ECC_secp224r1_EncryptedPrivateKeyWrap(iv, ekey, &wkuk,
							  &prikey);
	if (err != FSP_SUCCESS)
		return sce_err_to_tee(err);

	memcpy(wrapped_prikey, &prikey, sizeof(prikey));
	return TEE_SUCCESS;
}

/* Import encrypted secp256r1 public key */
static TEE_Result
secp256r1_import_pubkey(uint8_t *iv, uint8_t *ekey,
			struct sce_wrapped_key *wrapped_pubkey)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;
	sce_ecc_public_wrapped_key_t pubkey = { 0 };

	err = R_SCE_ECC_secp256r1_EncryptedPublicKeyWrap(iv, ekey, &wkuk,
							 &pubkey);
	if (err != FSP_SUCCESS)
		return sce_err_to_tee(err);

	memcpy(wrapped_pubkey, &pubkey, sizeof(pubkey));
	return TEE_SUCCESS;
}

/* Import encrypted secp256r1 private key */
static TEE_Result
secp256r1_import_prikey(uint8_t *iv, uint8_t *ekey,
			struct sce_wrapped_key *wrapped_prikey)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;
	sce_ecc_private_wrapped_key_t prikey = { 0 };

	err = R_SCE_ECC_secp256r1_EncryptedPrivateKeyWrap(iv, ekey, &wkuk,
							  &prikey);
	if (err != FSP_SUCCESS)
		return sce_err_to_tee(err);

	memcpy(wrapped_prikey, &prikey, sizeof(prikey));
	return TEE_SUCCESS;
}

/* Import encrypted BrainpoolP512r1 public key */
static TEE_Result bp512r1_import_pubkey(uint8_t *iv, uint8_t *ekey,
					struct sce_wrapped_key *wrapped_pubkey)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;
	sce_ecc_public_wrapped_key_t pubkey = { 0 };

	err = R_SCE_ECC_BrainpoolP512r1_EncryptedPublicKeyWrap(iv, ekey, &wkuk,
							       &pubkey);
	if (err != FSP_SUCCESS)
		return sce_err_to_tee(err);

	memcpy(wrapped_pubkey, &pubkey, sizeof(pubkey));
	return TEE_SUCCESS;
}

/* Import encrypted BrainpoolP512r1 private key */
static TEE_Result bp512r1_import_prikey(uint8_t *iv, uint8_t *ekey,
					struct sce_wrapped_key *wrapped_prikey)
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;
	sce_ecc_private_wrapped_key_t prikey = { 0 };

	err = R_SCE_ECC_BrainpoolP512r1_EncryptedPrivateKeyWrap(iv, ekey, &wkuk,
								&prikey);
	if (err != FSP_SUCCESS)
		return sce_err_to_tee(err);

	memcpy(wrapped_prikey, &prikey, sizeof(prikey));
	return TEE_SUCCESS;
}

/*
 * Generate a wrapped symmetric key.
 */
static TEE_Result generate_wrapped_key(uint32_t types,
				       TEE_Param params[TEE_NUM_PARAMS],
				       sce_key_type_t key_type)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	size_t wrapped_buf_size = 0;
	struct sce_wrapped_key *wrapped_key = NULL;
	const struct sce_key_desc *key_desc = NULL;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
				     TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	res = get_key_desc(key_type, &key_desc);
	if (res != TEE_SUCCESS)
		return res;

	wrapped_key = params[0].memref.buffer;
	wrapped_buf_size = params[0].memref.size;
	params[0].memref.size = key_desc->wrapped_size;
	if (!wrapped_key || !IS_ALIGNED_WITH_UINT32(wrapped_key))
		return TEE_ERROR_BAD_PARAMETERS;
	if (wrapped_buf_size < params[0].memref.size)
		return TEE_ERROR_SHORT_BUFFER;

	switch (key_type) {
	case SCE_KEY_INDEX_TYPE_AES128:
		return aes128_gen_wrapped_key(wrapped_key);
	case SCE_KEY_INDEX_TYPE_AES256:
		return aes256_gen_wrapped_key(wrapped_key);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

/*
 * Generate a wrapped public/private key pair.
 */
static TEE_Result generate_wrapped_key_pair(uint32_t types,
					    TEE_Param params[TEE_NUM_PARAMS],
					    enum sce_key_pair_type pair_type)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	size_t wrapped_privbuf_size = 0;
	struct sce_wrapped_key *wrapped_prikey = NULL;
	const struct sce_key_desc *priv_desc = NULL;

	size_t wrapped_pubbuf_size = 0;
	struct sce_wrapped_key *wrapped_pubkey = NULL;
	const struct sce_key_desc *pub_desc = NULL;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
				     TEE_PARAM_TYPE_MEMREF_OUTPUT,
				     TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	res = get_key_pair_desc(pair_type, &priv_desc, &pub_desc);
	if (res != TEE_SUCCESS)
		return res;

	wrapped_prikey = params[0].memref.buffer;
	wrapped_privbuf_size = params[0].memref.size;
	params[0].memref.size = priv_desc->wrapped_size;
	if (!wrapped_prikey || !IS_ALIGNED_WITH_UINT32(wrapped_prikey))
		return TEE_ERROR_BAD_PARAMETERS;
	if (wrapped_privbuf_size < params[0].memref.size)
		return TEE_ERROR_SHORT_BUFFER;

	wrapped_pubkey = params[1].memref.buffer;
	wrapped_pubbuf_size = params[1].memref.size;
	params[1].memref.size = pub_desc->wrapped_size;
	if (!wrapped_pubkey || !IS_ALIGNED_WITH_UINT32(wrapped_pubkey))
		return TEE_ERROR_BAD_PARAMETERS;
	if (wrapped_pubbuf_size < params[1].memref.size)
		return TEE_ERROR_SHORT_BUFFER;

	switch (pair_type) {
	case SCE_KEY_PAIR_TYPE_RSA_1024:
		return rsa1024_gen_wrapped_key(wrapped_pubkey, wrapped_prikey);
	case SCE_KEY_PAIR_TYPE_RSA_2048:
		return rsa2048_gen_wrapped_key(wrapped_pubkey, wrapped_prikey);
	case SCE_KEY_PAIR_TYPE_ECC_secp192r1:
		return secp192r1_gen_wrapped_key(wrapped_pubkey,
						 wrapped_prikey);
	case SCE_KEY_PAIR_TYPE_ECC_secp224r1:
		return secp224r1_gen_wrapped_key(wrapped_pubkey,
						 wrapped_prikey);
	case SCE_KEY_PAIR_TYPE_ECC_secp256r1:
		return secp256r1_gen_wrapped_key(wrapped_pubkey,
						 wrapped_prikey);
	case SCE_KEY_PAIR_TYPE_ECC_BRAINPOOLP512R1:
		return bp512r1_gen_wrapped_key(wrapped_pubkey, wrapped_prikey);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

/*
 * Calculate the CRC32 of a buffer.
 */
static uint32_t calc_crc32(const uint8_t *ptr, uint32_t len)
{
	uint32_t crc = 0xFFFFFFFF;

	while (0 < (len--)) {
		uint8_t val = *ptr;

		crc ^= ((uint32_t)val << 24);
		for (int32_t j = 0; j < 8; j++) {
			if ((crc >> 31) & 1)
				crc = (crc << 1) ^ 0x04C11DB7;
			else
				crc <<= 1;
		}
		ptr++;
	}
	return crc;
}

/*
 * Parse an encrypted key blob and validate its CRC.
 *
 * On success, iv and key point to the IV and encrypted
 * key payload stored in the original blob.
 */
static bool parse_encrypted_key_blob(const uint8_t *blob, size_t blob_size,
				     size_t key_size, uint8_t **iv,
				     uint8_t **ekey)
{
	struct {
		uint32_t unused[2];
		uint8_t iv[16];
	} *hdr = (void *)blob;

	size_t blob_len = sizeof(*hdr) + key_size;

	if (blob_size >= (blob_len + sizeof(uint32_t))) {
		uint32_t blob_crc = 0;
		uint32_t calc_crc = calc_crc32(blob, blob_len);

		memcpy(&blob_crc, blob + blob_len, sizeof(blob_crc));

		if (blob_crc == TEE_U32_BSWAP(calc_crc)) {
			*iv = hdr->iv;
			*ekey = (uint8_t *)blob + sizeof(*hdr);
			return true;
		}
	}

	return false;
}

/*
 * Import an encrypted key using the loaded KUK.
 */
static TEE_Result import_key_with_kuk(uint32_t types,
				      TEE_Param params[TEE_NUM_PARAMS],
				      sce_key_type_t key_type)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	uint8_t *init_vec = NULL;
	uint8_t *encrypted_key = NULL;

	size_t key_blob_size = 0;
	uint8_t *key_blob = NULL;

	size_t wrapped_buf_size = 0;
	struct sce_wrapped_key *wrapped_key = NULL;
	const struct sce_key_desc *key_desc = NULL;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_OUTPUT,
				     TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	res = get_key_desc(key_type, &key_desc);
	if (res != TEE_SUCCESS)
		return res;

	key_blob = params[0].memref.buffer;
	key_blob_size = params[0].memref.size;
	if (!key_blob || !IS_ALIGNED_WITH_UINT32(key_blob))
		return TEE_ERROR_BAD_PARAMETERS;
	if (!parse_encrypted_key_blob(key_blob, key_blob_size,
				      key_desc->encrypted_size, &init_vec,
				      &encrypted_key))
		return TEE_ERROR_BAD_PARAMETERS;

	wrapped_key = params[1].memref.buffer;
	wrapped_buf_size = params[1].memref.size;
	params[1].memref.size = key_desc->wrapped_size;
	if (!wrapped_key || !IS_ALIGNED_WITH_UINT32(wrapped_key))
		return TEE_ERROR_BAD_PARAMETERS;
	if (wrapped_buf_size < params[1].memref.size)
		return TEE_ERROR_SHORT_BUFFER;

	switch (key_type) {
	case SCE_KEY_INDEX_TYPE_AES128:
		return aes128_import_key(init_vec, encrypted_key, wrapped_key);
	case SCE_KEY_INDEX_TYPE_AES256:
		return aes256_import_key(init_vec, encrypted_key, wrapped_key);
	case SCE_KEY_INDEX_TYPE_RSA1024_PUBLIC:
		return rsa1024_import_pubkey(init_vec, encrypted_key,
					     wrapped_key);
	case SCE_KEY_INDEX_TYPE_RSA1024_PRIVATE:
		return rsa1024_import_prikey(init_vec, encrypted_key,
					     wrapped_key);
	case SCE_KEY_INDEX_TYPE_RSA2048_PUBLIC:
		return rsa2048_import_pubkey(init_vec, encrypted_key,
					     wrapped_key);
	case SCE_KEY_INDEX_TYPE_RSA2048_PRIVATE:
		return rsa2048_import_prikey(init_vec, encrypted_key,
					     wrapped_key);
	case SCE_KEY_INDEX_TYPE_RSA4096_PUBLIC:
		return rsa4096_import_pubkey(init_vec, encrypted_key,
					     wrapped_key);
	case SCE_KEY_INDEX_TYPE_ECC_P192_PUBLIC:
		return secp192r1_import_pubkey(init_vec, encrypted_key,
					       wrapped_key);
	case SCE_KEY_INDEX_TYPE_ECC_P192_PRIVATE:
		return secp192r1_import_prikey(init_vec, encrypted_key,
					       wrapped_key);
	case SCE_KEY_INDEX_TYPE_ECC_P224_PUBLIC:
		return secp224r1_import_pubkey(init_vec, encrypted_key,
					       wrapped_key);
	case SCE_KEY_INDEX_TYPE_ECC_P224_PRIVATE:
		return secp224r1_import_prikey(init_vec, encrypted_key,
					       wrapped_key);
	case SCE_KEY_INDEX_TYPE_ECC_P256_PUBLIC:
		return secp256r1_import_pubkey(init_vec, encrypted_key,
					       wrapped_key);
	case SCE_KEY_INDEX_TYPE_ECC_P256_PRIVATE:
		return secp256r1_import_prikey(init_vec, encrypted_key,
					       wrapped_key);
	case SCE_KEY_INDEX_TYPE_ECC_P512_PUBLIC:
		return bp512r1_import_pubkey(init_vec, encrypted_key,
					     wrapped_key);
	case SCE_KEY_INDEX_TYPE_ECC_P512_PRIVATE:
		return bp512r1_import_prikey(init_vec, encrypted_key,
					     wrapped_key);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

/*
 * Fill the output buffer with random data generated by
 * the SCE random number generator.
 */
static TEE_Result generate_random_number(uint32_t types,
					 TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err = FSP_ERR_CRYPTO_SCE_FAIL;

	uint8_t *rand = NULL;
	uint32_t rand_len = 0;
	uint32_t rand_buff[4] = { 0 };

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
				     TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	rand = params[0].memref.buffer;
	rand_len = (uint32_t)params[0].memref.size;
	if ((rand_len && !rand) || !IS_ALIGNED_WITH_UINT32(rand))
		return TEE_ERROR_BAD_PARAMETERS;

	for (size_t i = 0; i < rand_len; i += sizeof(rand_buff)) {
		const size_t chunk = MIN(rand_len - i, sizeof(rand_buff));

		err = R_SCE_RandomNumberGenerate(rand_buff);
		if (err != FSP_SUCCESS)
			return sce_err_to_tee(err);

		memcpy(rand + i, rand_buff, chunk);
	}

	return TEE_SUCCESS;
}

/*
 * PTA session entry point.
 */
static TEE_Result open_session(uint32_t nParamTypes __unused,
			       TEE_Param pParams[TEE_NUM_PARAMS] __unused,
			       void **ppSessionContext __unused)
{
	DMSG("open entry point for pseudo ta \"%s\"", PTA_NAME);

	return plat_crypto_get_key_update_key((uint8_t *)&wkuk, sizeof(wkuk));
}

/*
 * PTA session exit point.
 */
static void close_session(void *pSessionContext __unused)
{
	DMSG("close entry point for pseudo ta \"%s\"", PTA_NAME);
}

/*
 * Dispatch PTA commands to the corresponding SCE handler.
 */
static TEE_Result invoke_command_gen_key(uint32_t cmd, uint32_t ptypes,
					 TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	sce_key_type_t type = SCE_KEY_INDEX_TYPE_INVALID;

	res = get_sce_key_type(cmd, &type);
	if (res != TEE_SUCCESS)
		return res;

	switch (cmd) {
	case PTA_CMD_AES128_WrappedKeyGenerate:
	case PTA_CMD_AES256_WrappedKeyGenerate:
		return generate_wrapped_key(ptypes, params, type);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

static TEE_Result invoke_command_gen_key_pair(uint32_t cmd, uint32_t ptypes,
					      TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	enum sce_key_pair_type type = SCE_KEY_PAIR_TYPE_INVALID;

	res = get_sce_key_pair_type(cmd, &type);
	if (res != TEE_SUCCESS)
		return res;

	switch (cmd) {
	case PTA_CMD_RSA_1024_WrappedKeyPairGenerate:
	case PTA_CMD_RSA_2048_WrappedKeyPairGenerate:
	case PTA_CMD_ECC_secp192r1_WrappedKeyPairGenerate:
	case PTA_CMD_ECC_secp224r1_WrappedKeyPairGenerate:
	case PTA_CMD_ECC_secp256r1_WrappedKeyPairGenerate:
	case PTA_CMD_ECC_BrainpoolP512r1_WrappedKeyPairGenerate:
		return generate_wrapped_key_pair(ptypes, params, type);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

static TEE_Result invoke_command_import_key(uint32_t cmd, uint32_t ptypes,
					    TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	sce_key_type_t type = SCE_KEY_INDEX_TYPE_INVALID;

	res = get_sce_key_type(cmd, &type);
	if (res != TEE_SUCCESS)
		return res;

	switch (cmd) {
	case PTA_CMD_AES128_EncryptedKeyWrap:
	case PTA_CMD_AES256_EncryptedKeyWrap:
	case PTA_CMD_RSA_1024_EncryptedPublicKeyWrap:
	case PTA_CMD_RSA_1024_EncryptedPrivateKeyWrap:
	case PTA_CMD_RSA_2048_EncryptedPublicKeyWrap:
	case PTA_CMD_RSA_2048_EncryptedPrivateKeyWrap:
	case PTA_CMD_RSA_4096_EncryptedPublicKeyWrap:
	case PTA_CMD_ECC_secp192r1_EncryptedPublicKeyWrap:
	case PTA_CMD_ECC_secp192r1_EncryptedPrivateKeyWrap:
	case PTA_CMD_ECC_secp224r1_EncryptedPublicKeyWrap:
	case PTA_CMD_ECC_secp224r1_EncryptedPrivateKeyWrap:
	case PTA_CMD_ECC_secp256r1_EncryptedPublicKeyWrap:
	case PTA_CMD_ECC_secp256r1_EncryptedPrivateKeyWrap:
	case PTA_CMD_ECC_BrainpoolP512r1_EncryptedPublicKeyWrap:
	case PTA_CMD_ECC_BrainpoolP512r1_EncryptedPrivateKeyWrap:
		return import_key_with_kuk(ptypes, params, type);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

static TEE_Result invoke_command(void *session __unused, uint32_t cmd,
				 uint32_t ptypes,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	DMSG(PTA_NAME " command %#" PRIx32 " ptypes %#" PRIx32, cmd, ptypes);

	switch (PTA_CMD_GET_FEATURE(cmd)) {
	case PTA_FEATURE_KEY_GEN:
		return invoke_command_gen_key(cmd, ptypes, params);
	case PTA_FEATURE_KEYPAIR_GEN:
		return invoke_command_gen_key_pair(cmd, ptypes, params);
	case PTA_FEATURE_KEY_IMPORT:
		return invoke_command_import_key(cmd, ptypes, params);
	case PTA_FEATURE_RANDOM:
		return generate_random_number(ptypes, params);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}

pseudo_ta_register(.uuid = PTA_SCE_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .open_session_entry_point = open_session,
		   .close_session_entry_point = close_session,
		   .invoke_command_entry_point = invoke_command);
