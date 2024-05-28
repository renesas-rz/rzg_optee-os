// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, Renesas Electronics
 */

#include <kernel/pseudo_ta.h>

#include <r_sce.h>
#include <pta_sce_aes.h>

#define PTA_NAME "sce_aes.pta"

static TEE_Result aes128ecb_encryptinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_aes_handle_t * handle;
	sce_aes_wrapped_key_t * wrapped_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_aes_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_aes_handle_t) > params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	wrapped_key = (sce_aes_wrapped_key_t *)params[1].memref.buffer;
	if ((NULL == wrapped_key) || (sizeof(sce_aes_wrapped_key_t) != params[1].memref.size)){
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = g_sce_protected_on_sce.AES128ECB_EncryptInit(handle, wrapped_key);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
			return TEE_ERROR_ACCESS_CONFLICT;
		case FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL:
			return TEE_ERROR_BAD_PARAMETERS;
		default: /* FSP_ERR_CRYPTO_SCE_FAIL */
			return TEE_ERROR_GENERIC;
	}

	params[0].memref.size = sizeof(sce_aes_handle_t);

	return TEE_SUCCESS;
}

static TEE_Result aes128ecb_encryptupdate(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_aes_handle_t * handle;
	uint8_t * plain;
	uint8_t * cipher;
	uint32_t plain_length;
	uint32_t cipher_length;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_aes_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_aes_handle_t) != params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	plain = (uint8_t *)params[1].memref.buffer;
	plain_length = (uint32_t)params[1].memref.size;
	if ((NULL == plain) || (0 != (plain_length % HW_SCE_AES_BLOCK_BYTE_SIZE))) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	cipher = (uint8_t *)params[2].memref.buffer;
	cipher_length = (uint32_t)params[2].memref.size;
	if ((NULL == cipher) || (cipher_length < plain_length)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = g_sce_protected_on_sce.AES128ECB_EncryptUpdate(handle, plain, cipher, plain_length);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case FSP_ERR_CRYPTO_SCE_PARAMETER:
			return TEE_ERROR_BAD_PARAMETERS;
		default: /* FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION */
			return TEE_ERROR_BAD_STATE;
	}

	params[2].memref.size = plain_length;

	return TEE_SUCCESS;
}

static TEE_Result aes128ecb_encryptfinal(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_aes_handle_t * handle;
	uint8_t * cipher;
	uint32_t cipher_length;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_aes_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_aes_handle_t) != params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	cipher = NULL;		// nothing ever written here
	cipher_length = 0;	// 0 always written here

	err = g_sce_protected_on_sce.AES128ECB_EncryptFinal(handle, cipher, &cipher_length);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case FSP_ERR_CRYPTO_SCE_FAIL:
			return TEE_ERROR_GENERIC;
		case FSP_ERR_CRYPTO_SCE_PARAMETER:
			return TEE_ERROR_BAD_PARAMETERS;
		default: /* FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION */
			return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

static TEE_Result aes128ecb_decryptinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_aes_handle_t * handle;
	sce_aes_wrapped_key_t * wrapped_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_aes_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_aes_handle_t) > params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	wrapped_key = (sce_aes_wrapped_key_t *)params[1].memref.buffer;
	if ((NULL == wrapped_key) || (sizeof(sce_aes_wrapped_key_t) != params[1].memref.size)){
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = g_sce_protected_on_sce.AES128ECB_DecryptInit(handle, wrapped_key);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
			return TEE_ERROR_ACCESS_CONFLICT;
		case FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL:
			return TEE_ERROR_BAD_PARAMETERS;
		default: /* FSP_ERR_CRYPTO_SCE_FAIL */
			return TEE_ERROR_GENERIC;
	}

	params[0].memref.size = sizeof(sce_aes_handle_t);

	return TEE_SUCCESS;
}

static TEE_Result aes128ecb_decryptupdate(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_aes_handle_t * handle;
	uint8_t * cipher;
	uint8_t * plain;
	uint32_t cipher_length;
	uint32_t plain_length;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_aes_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_aes_handle_t) != params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	cipher = (uint8_t *)params[1].memref.buffer;
	cipher_length = (uint32_t)params[1].memref.size;
	if ((NULL == cipher) || (0 != (cipher_length % HW_SCE_AES_BLOCK_BYTE_SIZE))) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	plain = (uint8_t *)params[2].memref.buffer;
	plain_length = (uint32_t)params[2].memref.size;
	if ((NULL == plain) || (plain_length < cipher_length)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = g_sce_protected_on_sce.AES128ECB_DecryptUpdate(handle, cipher, plain, cipher_length);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case FSP_ERR_CRYPTO_SCE_PARAMETER:
			return TEE_ERROR_BAD_PARAMETERS;
		default: /*FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION */
			return TEE_ERROR_BAD_STATE;
	}

	params[2].memref.size = cipher_length;

	return TEE_SUCCESS;
}

static TEE_Result aes128ecb_decryptfinal(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_aes_handle_t * handle;
	uint8_t * plain;
	uint32_t plain_length;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_aes_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_aes_handle_t) != params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	plain = NULL;		// nothing ever written here
	plain_length = 0;	// 0 always written here

	err = g_sce_protected_on_sce.AES128ECB_DecryptFinal(handle, plain, &plain_length);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case FSP_ERR_CRYPTO_SCE_FAIL:
			return TEE_ERROR_GENERIC;
		case FSP_ERR_CRYPTO_SCE_PARAMETER:
			return TEE_ERROR_BAD_PARAMETERS;
		default: /* FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION */
			return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

static TEE_Result aes256ecb_encryptinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_aes_handle_t * handle;
	sce_aes_wrapped_key_t * wrapped_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_aes_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_aes_handle_t) > params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	wrapped_key = (sce_aes_wrapped_key_t *)params[1].memref.buffer;
	if ((NULL == wrapped_key) || (sizeof(sce_aes_wrapped_key_t) != params[1].memref.size)){
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = g_sce_protected_on_sce.AES256ECB_EncryptInit(handle, wrapped_key);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
			return TEE_ERROR_ACCESS_CONFLICT;
		case FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL:
			return TEE_ERROR_BAD_PARAMETERS;
		default: /* FSP_ERR_CRYPTO_SCE_FAIL */
			return TEE_ERROR_GENERIC;
	}

	params[0].memref.size = sizeof(sce_aes_handle_t);

	return TEE_SUCCESS;
}

static TEE_Result aes256ecb_encryptupdate(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_aes_handle_t * handle;
	uint8_t * plain;
	uint8_t * cipher;
	uint32_t plain_length;
	uint32_t cipher_length;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_aes_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_aes_handle_t) != params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	plain = (uint8_t *)params[1].memref.buffer;
	plain_length = (uint32_t)params[1].memref.size;
	if ((NULL == plain) || (0 != (plain_length % HW_SCE_AES_BLOCK_BYTE_SIZE))) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	cipher = (uint8_t *)params[2].memref.buffer;
	cipher_length = (uint32_t)params[2].memref.size;
	if ((NULL == cipher) || (cipher_length < plain_length)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = g_sce_protected_on_sce.AES256ECB_EncryptUpdate(handle, plain, cipher, plain_length);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case FSP_ERR_CRYPTO_SCE_PARAMETER:
			return TEE_ERROR_BAD_PARAMETERS;
		default: /* FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION */
			return TEE_ERROR_BAD_STATE;
	}

	params[2].memref.size = plain_length;

	return TEE_SUCCESS;
}

static TEE_Result aes256ecb_encryptfinal(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_aes_handle_t * handle;
	uint8_t * cipher;
	uint32_t cipher_length;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_aes_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_aes_handle_t) != params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	cipher = NULL;		// nothing ever written here
	cipher_length = 0;	// 0 always written here

	err = g_sce_protected_on_sce.AES256ECB_EncryptFinal(handle, cipher, &cipher_length);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case FSP_ERR_CRYPTO_SCE_FAIL:
			return TEE_ERROR_GENERIC;
		case FSP_ERR_CRYPTO_SCE_PARAMETER:
			return TEE_ERROR_BAD_PARAMETERS;
		default: /* FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION */
			return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

static TEE_Result aes256ecb_decryptinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_aes_handle_t * handle;
	sce_aes_wrapped_key_t * wrapped_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_aes_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_aes_handle_t) > params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	wrapped_key = (sce_aes_wrapped_key_t *)params[1].memref.buffer;
	if ((NULL == wrapped_key) || (sizeof(sce_aes_wrapped_key_t) != params[1].memref.size)){
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = g_sce_protected_on_sce.AES256ECB_DecryptInit(handle, wrapped_key);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
			return TEE_ERROR_ACCESS_CONFLICT;
		case FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL:
			return TEE_ERROR_BAD_PARAMETERS;
		default: /* FSP_ERR_CRYPTO_SCE_FAIL */
			return TEE_ERROR_GENERIC;
	}

	params[0].memref.size = sizeof(sce_aes_handle_t);

	return TEE_SUCCESS;
}

static TEE_Result aes256ecb_decryptupdate(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_aes_handle_t * handle;
	uint8_t * cipher;
	uint8_t * plain;
	uint32_t cipher_length;
	uint32_t plain_length;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_aes_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_aes_handle_t) != params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	cipher = (uint8_t *)params[1].memref.buffer;
	cipher_length = (uint32_t)params[1].memref.size;
	if ((NULL == cipher) || (0 != (cipher_length % HW_SCE_AES_BLOCK_BYTE_SIZE))) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	plain = (uint8_t *)params[2].memref.buffer;
	plain_length = (uint32_t)params[2].memref.size;
	if ((NULL == plain) || (plain_length < cipher_length)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = g_sce_protected_on_sce.AES256ECB_DecryptUpdate(handle, cipher, plain, cipher_length);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case FSP_ERR_CRYPTO_SCE_PARAMETER:
			return TEE_ERROR_BAD_PARAMETERS;
		default: /*FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION */
			return TEE_ERROR_BAD_STATE;
	}

	params[2].memref.size = cipher_length;

	return TEE_SUCCESS;
}

static TEE_Result aes256ecb_decryptfinal(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_aes_handle_t * handle;
	uint8_t * plain;
	uint32_t plain_length;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_aes_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_aes_handle_t) != params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	plain = NULL;		// nothing ever written here
	plain_length = 0;	// 0 always written here

	err = g_sce_protected_on_sce.AES256ECB_DecryptFinal(handle, plain, &plain_length);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case FSP_ERR_CRYPTO_SCE_FAIL:
			return TEE_ERROR_GENERIC;
		case FSP_ERR_CRYPTO_SCE_PARAMETER:
			return TEE_ERROR_BAD_PARAMETERS;
		default: /* FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION */
			return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

static TEE_Result aes128cbc_encryptinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_aes_handle_t * handle;
	sce_aes_wrapped_key_t * wrapped_key;
	uint8_t * initial_vector;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_aes_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_aes_handle_t) > params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	wrapped_key = (sce_aes_wrapped_key_t *)params[1].memref.buffer;
	if ((NULL == wrapped_key) || (sizeof(sce_aes_wrapped_key_t) != params[1].memref.size)){
		return TEE_ERROR_BAD_PARAMETERS;
	}

	initial_vector = (uint8_t *)params[2].memref.buffer;
	if ((NULL == initial_vector) || (HW_SCE_AES_CBC_IV_BYTE_SIZE != params[2].memref.size)){
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = g_sce_protected_on_sce.AES128CBC_EncryptInit(handle, wrapped_key, initial_vector);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
			return TEE_ERROR_ACCESS_CONFLICT;
		case FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL:
			return TEE_ERROR_BAD_PARAMETERS;
		default: /* FSP_ERR_CRYPTO_SCE_FAIL */
			return TEE_ERROR_GENERIC;
	}

	params[0].memref.size = sizeof(sce_aes_handle_t);

	return TEE_SUCCESS;
}

static TEE_Result aes128cbc_encryptupdate(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_aes_handle_t * handle;
	uint8_t * plain;
	uint8_t * cipher;
	uint32_t plain_length;
	uint32_t cipher_length;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_aes_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_aes_handle_t) != params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	plain = (uint8_t *)params[1].memref.buffer;
	plain_length = (uint32_t)params[1].memref.size;
	if ((NULL == plain) || (0 != (plain_length % HW_SCE_AES_BLOCK_BYTE_SIZE))) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	cipher = (uint8_t *)params[2].memref.buffer;
	cipher_length = (uint32_t)params[2].memref.size;
	if ((NULL == cipher) || (cipher_length < plain_length)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = g_sce_protected_on_sce.AES128CBC_EncryptUpdate(handle, plain, cipher, plain_length);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case FSP_ERR_CRYPTO_SCE_PARAMETER:
			return TEE_ERROR_BAD_PARAMETERS;
		default: /* FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION */
			return TEE_ERROR_BAD_STATE;
	}

	params[2].memref.size = plain_length;

	return TEE_SUCCESS;
}

static TEE_Result aes128cbc_encryptfinal(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_aes_handle_t * handle;
	uint8_t * cipher;
	uint32_t cipher_length;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_aes_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_aes_handle_t) != params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	cipher = NULL;		// nothing ever written here
	cipher_length = 0;	// 0 always written here

	err = g_sce_protected_on_sce.AES128CBC_EncryptFinal(handle, cipher, &cipher_length);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case FSP_ERR_CRYPTO_SCE_FAIL:
			return TEE_ERROR_GENERIC;
		case FSP_ERR_CRYPTO_SCE_PARAMETER:
			return TEE_ERROR_BAD_PARAMETERS;
		default: /* FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION */
			return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

static TEE_Result aes128cbc_decryptinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_aes_handle_t * handle;
	sce_aes_wrapped_key_t * wrapped_key;
	uint8_t * initial_vector;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_aes_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_aes_handle_t) > params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	wrapped_key = (sce_aes_wrapped_key_t *)params[1].memref.buffer;
	if ((NULL == wrapped_key) || (sizeof(sce_aes_wrapped_key_t) != params[1].memref.size)){
		return TEE_ERROR_BAD_PARAMETERS;
	}

	initial_vector = (uint8_t *)params[2].memref.buffer;
	if ((NULL == initial_vector) || (HW_SCE_AES_CBC_IV_BYTE_SIZE != params[2].memref.size)){
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = g_sce_protected_on_sce.AES128CBC_DecryptInit(handle, wrapped_key, initial_vector);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case  FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
			return TEE_ERROR_ACCESS_CONFLICT;
		case FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL:
			return TEE_ERROR_BAD_PARAMETERS;
		default: /* FSP_ERR_CRYPTO_SCE_FAIL */
			return TEE_ERROR_GENERIC;
	}

	params[0].memref.size = sizeof(sce_aes_handle_t);

	return TEE_SUCCESS;
}

static TEE_Result aes128cbc_decryptupdate(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_aes_handle_t * handle;
	uint8_t * cipher;
	uint8_t * plain;
	uint32_t cipher_length;
	uint32_t plain_length;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_aes_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_aes_handle_t) != params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	cipher = (uint8_t *)params[1].memref.buffer;
	cipher_length = (uint32_t)params[1].memref.size;
	if ((NULL == cipher) || (0 != (cipher_length % HW_SCE_AES_BLOCK_BYTE_SIZE))) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	plain = (uint8_t *)params[2].memref.buffer;
	plain_length = (uint32_t)params[2].memref.size;
	if ((NULL == plain) || (plain_length < cipher_length)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = g_sce_protected_on_sce.AES128CBC_DecryptUpdate(handle, cipher, plain, cipher_length);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case FSP_ERR_CRYPTO_SCE_PARAMETER:
			return TEE_ERROR_BAD_PARAMETERS;
		default: /*FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION */
			return TEE_ERROR_BAD_STATE;
	}

	params[2].memref.size = cipher_length;

	return TEE_SUCCESS;
}

static TEE_Result aes128cbc_decryptfinal(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_aes_handle_t * handle;
	uint8_t * plain;
	uint32_t plain_length;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_aes_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_aes_handle_t) != params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	plain = NULL;		// nothing ever written here
	plain_length = 0;	// 0 always written here

	err = g_sce_protected_on_sce.AES128CBC_DecryptFinal(handle, plain, &plain_length);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case FSP_ERR_CRYPTO_SCE_FAIL:
			return TEE_ERROR_GENERIC;
		case FSP_ERR_CRYPTO_SCE_PARAMETER:
			return TEE_ERROR_BAD_PARAMETERS;
		default: /* FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION */
			return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

static TEE_Result aes256cbc_encryptinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_aes_handle_t * handle;
	sce_aes_wrapped_key_t * wrapped_key;
	uint8_t * initial_vector;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_aes_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_aes_handle_t) > params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	wrapped_key = (sce_aes_wrapped_key_t *)params[1].memref.buffer;
	if ((NULL == wrapped_key) || (sizeof(sce_aes_wrapped_key_t) != params[1].memref.size)){
		return TEE_ERROR_BAD_PARAMETERS;
	}

	initial_vector = (uint8_t *)params[2].memref.buffer;
	if ((NULL == initial_vector) || (HW_SCE_AES_CBC_IV_BYTE_SIZE != params[2].memref.size)){
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = g_sce_protected_on_sce.AES256CBC_EncryptInit(handle, wrapped_key, initial_vector);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
			return TEE_ERROR_ACCESS_CONFLICT;
		case FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL:
			return TEE_ERROR_BAD_PARAMETERS;
		default: /* FSP_ERR_CRYPTO_SCE_FAIL */
			return TEE_ERROR_GENERIC;
	}

	params[0].memref.size = sizeof(sce_aes_handle_t);

	return TEE_SUCCESS;
}

static TEE_Result aes256cbc_encryptupdate(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_aes_handle_t * handle;
	uint8_t * plain;
	uint8_t * cipher;
	uint32_t plain_length;
	uint32_t cipher_length;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_aes_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_aes_handle_t) != params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	plain = (uint8_t *)params[1].memref.buffer;
	plain_length = (uint32_t)params[1].memref.size;
	if ((NULL == plain) || (0 != (plain_length % HW_SCE_AES_BLOCK_BYTE_SIZE))) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	cipher = (uint8_t *)params[2].memref.buffer;
	cipher_length = (uint32_t)params[2].memref.size;
	if ((NULL == cipher) || (cipher_length < plain_length)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = g_sce_protected_on_sce.AES256CBC_EncryptUpdate(handle, plain, cipher, plain_length);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case FSP_ERR_CRYPTO_SCE_PARAMETER:
			return TEE_ERROR_BAD_PARAMETERS;
		default: /* FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION */
			return TEE_ERROR_BAD_STATE;
	}

	params[2].memref.size = plain_length;

	return TEE_SUCCESS;
}

static TEE_Result aes256cbc_encryptfinal(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_aes_handle_t * handle;
	uint8_t * cipher;
	uint32_t cipher_length;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_aes_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_aes_handle_t) != params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	cipher = NULL;		// nothing ever written here
	cipher_length = 0;	// 0 always written here

	err = g_sce_protected_on_sce.AES256CBC_EncryptFinal(handle, cipher, &cipher_length);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case FSP_ERR_CRYPTO_SCE_FAIL:
			return TEE_ERROR_GENERIC;
		case FSP_ERR_CRYPTO_SCE_PARAMETER:
			return TEE_ERROR_BAD_PARAMETERS;
		default: /* FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION */
			return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

static TEE_Result aes256cbc_decryptinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_aes_handle_t * handle;
	sce_aes_wrapped_key_t * wrapped_key;
	uint8_t * initial_vector;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_aes_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_aes_handle_t) > params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	wrapped_key = (sce_aes_wrapped_key_t *)params[1].memref.buffer;
	if ((NULL == wrapped_key) || (sizeof(sce_aes_wrapped_key_t) != params[1].memref.size)){
		return TEE_ERROR_BAD_PARAMETERS;
	}

	initial_vector = (uint8_t *)params[2].memref.buffer;
	if ((NULL == initial_vector) || (HW_SCE_AES_CBC_IV_BYTE_SIZE != params[2].memref.size)){
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = g_sce_protected_on_sce.AES256CBC_DecryptInit(handle, wrapped_key, initial_vector);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
			return TEE_ERROR_ACCESS_CONFLICT;
		case FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL:
			return TEE_ERROR_BAD_PARAMETERS;
		default: /* FSP_ERR_CRYPTO_SCE_FAIL */
			return TEE_ERROR_GENERIC;
	}

	params[0].memref.size = sizeof(sce_aes_handle_t);

	return TEE_SUCCESS;
}

static TEE_Result aes256cbc_decryptupdate(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_aes_handle_t * handle;
	uint8_t * cipher;
	uint8_t * plain;
	uint32_t cipher_length;
	uint32_t plain_length;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_aes_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_aes_handle_t) != params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	cipher = (uint8_t *)params[1].memref.buffer;
	cipher_length = (uint32_t)params[1].memref.size;
	if ((NULL == cipher) || (0 != (cipher_length % HW_SCE_AES_BLOCK_BYTE_SIZE))) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	plain = (uint8_t *)params[2].memref.buffer;
	plain_length = (uint32_t)params[2].memref.size;
	if ((NULL == plain) || (plain_length < cipher_length)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = g_sce_protected_on_sce.AES256CBC_DecryptUpdate(handle, cipher, plain, cipher_length);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case FSP_ERR_CRYPTO_SCE_PARAMETER:
			return TEE_ERROR_BAD_PARAMETERS;
		default: /*FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION */
			return TEE_ERROR_BAD_STATE;
	}

	params[2].memref.size = cipher_length;

	return TEE_SUCCESS;
}

static TEE_Result aes256cbc_decryptfinal(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_aes_handle_t * handle;
	uint8_t * plain;
	uint32_t plain_length;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_aes_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_aes_handle_t) != params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	plain = NULL;		// nothing ever written here
	plain_length = 0;	// 0 always written here

	err = g_sce_protected_on_sce.AES256CBC_DecryptFinal(handle, plain, &plain_length);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case FSP_ERR_CRYPTO_SCE_FAIL:
			return TEE_ERROR_GENERIC;
		case FSP_ERR_CRYPTO_SCE_PARAMETER:
			return TEE_ERROR_BAD_PARAMETERS;
		default: /* FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION */
			return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

static TEE_Result aes128ctr_encryptinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_aes_handle_t * handle;
	sce_aes_wrapped_key_t * wrapped_key;
	uint8_t * initial_vector;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_aes_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_aes_handle_t) > params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	wrapped_key = (sce_aes_wrapped_key_t *)params[1].memref.buffer;
	if ((NULL == wrapped_key) || (sizeof(sce_aes_wrapped_key_t) != params[1].memref.size)){
		return TEE_ERROR_BAD_PARAMETERS;
	}

	initial_vector = (uint8_t *)params[2].memref.buffer;
	if ((NULL == initial_vector) || (HW_SCE_AES_CBC_IV_BYTE_SIZE != params[2].memref.size)){
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = g_sce_protected_on_sce.AES128CTR_EncryptInit(handle, wrapped_key, initial_vector);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
			return TEE_ERROR_ACCESS_CONFLICT;
		case FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL:
			return TEE_ERROR_BAD_PARAMETERS;
		default: /* FSP_ERR_CRYPTO_SCE_FAIL */
			return TEE_ERROR_GENERIC;
	}

	params[0].memref.size = sizeof(sce_aes_handle_t);

	return TEE_SUCCESS;
}

static TEE_Result aes128ctr_encryptupdate(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_aes_handle_t * handle;
	uint8_t * plain;
	uint8_t * cipher;
	uint32_t plain_length;
	uint32_t cipher_length;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_aes_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_aes_handle_t) != params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	plain = (uint8_t *)params[1].memref.buffer;
	plain_length = (uint32_t)params[1].memref.size;
	if ((NULL == plain) || (0 != (plain_length % HW_SCE_AES_BLOCK_BYTE_SIZE))) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	cipher = (uint8_t *)params[2].memref.buffer;
	cipher_length = (uint32_t)params[2].memref.size;
	if ((NULL == cipher) || (cipher_length < plain_length)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = g_sce_protected_on_sce.AES128CTR_EncryptUpdate(handle, plain, cipher, plain_length);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case FSP_ERR_CRYPTO_SCE_PARAMETER:
			return TEE_ERROR_BAD_PARAMETERS;
		default: /* FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION */
			return TEE_ERROR_BAD_STATE;
	}

	params[2].memref.size = plain_length;

	return TEE_SUCCESS;
}

static TEE_Result aes128ctr_encryptfinal(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_aes_handle_t * handle;
	uint8_t * cipher;
	uint32_t cipher_length;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_aes_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_aes_handle_t) != params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	cipher = NULL;		// nothing ever written here
	cipher_length = 0;	// 0 always written here

	err = g_sce_protected_on_sce.AES128CTR_EncryptFinal(handle, cipher, &cipher_length);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case FSP_ERR_CRYPTO_SCE_FAIL:
			return TEE_ERROR_GENERIC;
		case FSP_ERR_CRYPTO_SCE_PARAMETER:
			return TEE_ERROR_BAD_PARAMETERS;
		default: /* FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION */
			return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

static TEE_Result aes128ctr_decryptinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_aes_handle_t * handle;
	sce_aes_wrapped_key_t * wrapped_key;
	uint8_t * initial_vector;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_aes_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_aes_handle_t) > params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	wrapped_key = (sce_aes_wrapped_key_t *)params[1].memref.buffer;
	if ((NULL == wrapped_key) || (sizeof(sce_aes_wrapped_key_t) != params[1].memref.size)){
		return TEE_ERROR_BAD_PARAMETERS;
	}

	initial_vector = (uint8_t *)params[2].memref.buffer;
	if ((NULL == initial_vector) || (HW_SCE_AES_CBC_IV_BYTE_SIZE != params[2].memref.size)){
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = g_sce_protected_on_sce.AES128CTR_DecryptInit(handle, wrapped_key, initial_vector);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
			return TEE_ERROR_ACCESS_CONFLICT;
		case FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL:
			return TEE_ERROR_BAD_PARAMETERS;
		default: /* FSP_ERR_CRYPTO_SCE_FAIL */
			return TEE_ERROR_GENERIC;
	}

	params[0].memref.size = sizeof(sce_aes_handle_t);

	return TEE_SUCCESS;
}

static TEE_Result aes128ctr_decryptupdate(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_aes_handle_t * handle;
	uint8_t * cipher;
	uint8_t * plain;
	uint32_t cipher_length;
	uint32_t plain_length;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_aes_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_aes_handle_t) != params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	cipher = (uint8_t *)params[1].memref.buffer;
	cipher_length = (uint32_t)params[1].memref.size;
	if ((NULL == cipher) || (0 != (cipher_length % HW_SCE_AES_BLOCK_BYTE_SIZE))) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	plain = (uint8_t *)params[2].memref.buffer;
	plain_length = (uint32_t)params[2].memref.size;
	if ((NULL == plain) || (plain_length < cipher_length)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = g_sce_protected_on_sce.AES128CTR_DecryptUpdate(handle, cipher, plain, cipher_length);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case FSP_ERR_CRYPTO_SCE_PARAMETER:
			return TEE_ERROR_BAD_PARAMETERS;
		default: /*FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION */
			return TEE_ERROR_BAD_STATE;
	}

	params[2].memref.size = cipher_length;

	return TEE_SUCCESS;
}

static TEE_Result aes128ctr_decryptfinal(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_aes_handle_t * handle;
	uint8_t * plain;
	uint32_t plain_length;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_aes_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_aes_handle_t) != params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	plain = NULL;		// nothing ever written here
	plain_length = 0;	// 0 always written here

	err = g_sce_protected_on_sce.AES128CTR_DecryptFinal(handle, plain, &plain_length);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case FSP_ERR_CRYPTO_SCE_FAIL:
			return TEE_ERROR_GENERIC;
		case FSP_ERR_CRYPTO_SCE_PARAMETER:
			return TEE_ERROR_BAD_PARAMETERS;
		default: /* FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION */
			return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

static TEE_Result aes256ctr_encryptinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_aes_handle_t * handle;
	sce_aes_wrapped_key_t * wrapped_key;
	uint8_t * initial_vector;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_aes_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_aes_handle_t) > params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	wrapped_key = (sce_aes_wrapped_key_t *)params[1].memref.buffer;
	if ((NULL == wrapped_key) || (sizeof(sce_aes_wrapped_key_t) != params[1].memref.size)){
		return TEE_ERROR_BAD_PARAMETERS;
	}

	initial_vector = (uint8_t *)params[2].memref.buffer;
	if ((NULL == initial_vector) || (HW_SCE_AES_CBC_IV_BYTE_SIZE != params[2].memref.size)){
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = g_sce_protected_on_sce.AES256CTR_EncryptInit(handle, wrapped_key, initial_vector);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
			return TEE_ERROR_ACCESS_CONFLICT;
		case FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL:
			return TEE_ERROR_BAD_PARAMETERS;
		default: /* FSP_ERR_CRYPTO_SCE_FAIL */
			return TEE_ERROR_GENERIC;
	}

	params[0].memref.size = sizeof(sce_aes_handle_t);

	return TEE_SUCCESS;
}

static TEE_Result aes256ctr_encryptupdate(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_aes_handle_t * handle;
	uint8_t * plain;
	uint8_t * cipher;
	uint32_t plain_length;
	uint32_t cipher_length;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_aes_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_aes_handle_t) != params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	plain = (uint8_t *)params[1].memref.buffer;
	plain_length = (uint32_t)params[1].memref.size;
	if ((NULL == plain) || (0 != (plain_length % HW_SCE_AES_BLOCK_BYTE_SIZE))) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	cipher = (uint8_t *)params[2].memref.buffer;
	cipher_length = (uint32_t)params[2].memref.size;
	if ((NULL == cipher) || (cipher_length < plain_length)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = g_sce_protected_on_sce.AES256CTR_EncryptUpdate(handle, plain, cipher, plain_length);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case FSP_ERR_CRYPTO_SCE_PARAMETER:
			return TEE_ERROR_BAD_PARAMETERS;
		default: /* FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION */
			return TEE_ERROR_BAD_STATE;
	}

	params[2].memref.size = plain_length;

	return TEE_SUCCESS;
}

static TEE_Result aes256ctr_encryptfinal(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_aes_handle_t * handle;
	uint8_t * cipher;
	uint32_t cipher_length;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_aes_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_aes_handle_t) != params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	cipher = NULL;		// nothing ever written here
	cipher_length = 0;	// 0 always written here

	err = g_sce_protected_on_sce.AES256CTR_EncryptFinal(handle, cipher, &cipher_length);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case FSP_ERR_CRYPTO_SCE_FAIL:
			return TEE_ERROR_GENERIC;
		case FSP_ERR_CRYPTO_SCE_PARAMETER:
			return TEE_ERROR_BAD_PARAMETERS;
		default: /* FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION */
			return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

static TEE_Result aes256ctr_decryptinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_aes_handle_t * handle;
	sce_aes_wrapped_key_t * wrapped_key;
	uint8_t * initial_vector;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_aes_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_aes_handle_t) > params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	wrapped_key = (sce_aes_wrapped_key_t *)params[1].memref.buffer;
	if ((NULL == wrapped_key) || (sizeof(sce_aes_wrapped_key_t) != params[1].memref.size)){
		return TEE_ERROR_BAD_PARAMETERS;
	}

	initial_vector = (uint8_t *)params[2].memref.buffer;
	if ((NULL == initial_vector) || (HW_SCE_AES_CBC_IV_BYTE_SIZE != params[2].memref.size)){
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = g_sce_protected_on_sce.AES256CTR_DecryptInit(handle, wrapped_key, initial_vector);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
			return TEE_ERROR_ACCESS_CONFLICT;
		case FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL:
			return TEE_ERROR_BAD_PARAMETERS;
		default: /* FSP_ERR_CRYPTO_SCE_FAIL */
			return TEE_ERROR_GENERIC;
	}

	params[0].memref.size = sizeof(sce_aes_handle_t);

	return TEE_SUCCESS;
}

static TEE_Result aes256ctr_decryptupdate(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_aes_handle_t * handle;
	uint8_t * cipher;
	uint8_t * plain;
	uint32_t cipher_length;
	uint32_t plain_length;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_aes_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_aes_handle_t) != params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	cipher = (uint8_t *)params[1].memref.buffer;
	cipher_length = (uint32_t)params[1].memref.size;
	if ((NULL == cipher) || (0 != (cipher_length % HW_SCE_AES_BLOCK_BYTE_SIZE))) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	plain = (uint8_t *)params[2].memref.buffer;
	plain_length = (uint32_t)params[2].memref.size;
	if ((NULL == plain) || (plain_length < cipher_length)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = g_sce_protected_on_sce.AES256CTR_DecryptUpdate(handle, cipher, plain, cipher_length);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case FSP_ERR_CRYPTO_SCE_PARAMETER:
			return TEE_ERROR_BAD_PARAMETERS;
		default: /*FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION */
			return TEE_ERROR_BAD_STATE;
	}

	params[2].memref.size = cipher_length;

	return TEE_SUCCESS;
}

static TEE_Result aes256ctr_decryptfinal(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_aes_handle_t * handle;
	uint8_t * plain;
	uint32_t plain_length;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_aes_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_aes_handle_t) != params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	plain = NULL;		// nothing ever written here
	plain_length = 0;	// 0 always written here

	err = g_sce_protected_on_sce.AES256CTR_DecryptFinal(handle, plain, &plain_length);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case FSP_ERR_CRYPTO_SCE_FAIL:
			return TEE_ERROR_GENERIC;
		case FSP_ERR_CRYPTO_SCE_PARAMETER:
			return TEE_ERROR_BAD_PARAMETERS;
		default: /* FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION */
			return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

static TEE_Result aes128cmac_generateinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_cmac_handle_t * handle;
	sce_aes_wrapped_key_t * wrapped_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_cmac_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_cmac_handle_t) > params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	wrapped_key = (sce_aes_wrapped_key_t *)params[1].memref.buffer;
	if ((NULL == wrapped_key) || (sizeof(sce_aes_wrapped_key_t) != params[1].memref.size)){
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = g_sce_protected_on_sce.AES128CMAC_GenerateInit(handle, wrapped_key);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
			return TEE_ERROR_ACCESS_CONFLICT;
		case FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL:
			return TEE_ERROR_BAD_PARAMETERS;
		default: /* FSP_ERR_CRYPTO_SCE_FAIL */
			return TEE_ERROR_GENERIC;
	}

	params[0].memref.size = sizeof(sce_cmac_handle_t);

	return TEE_SUCCESS;
}

static TEE_Result aes128cmac_generateupdate(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_cmac_handle_t * handle;
	uint8_t * message;
	uint32_t message_length;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_cmac_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_cmac_handle_t) != params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	message = (uint8_t *)params[1].memref.buffer;
	message_length = (uint32_t)params[1].memref.size;
	if (NULL == message) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = g_sce_protected_on_sce.AES128CMAC_GenerateUpdate(handle, message, message_length);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case FSP_ERR_CRYPTO_SCE_PARAMETER:
			return TEE_ERROR_BAD_PARAMETERS;
		default: /* FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION */
			return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

static TEE_Result aes128cmac_generatefinal(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_cmac_handle_t * handle;
	uint8_t * mac;
	uint32_t mac_length;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_cmac_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_cmac_handle_t) != params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	mac = (uint8_t *)params[1].memref.buffer;
	mac_length = params[1].memref.size;
	if ((NULL == mac) || (HW_SCE_AES_BLOCK_BYTE_SIZE > mac_length)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = g_sce_protected_on_sce.AES128CMAC_GenerateFinal(handle, mac);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case FSP_ERR_CRYPTO_SCE_FAIL:
			return TEE_ERROR_GENERIC;
		case FSP_ERR_CRYPTO_SCE_PARAMETER:
			return TEE_ERROR_BAD_PARAMETERS;
		case FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION:
			return TEE_ERROR_BAD_STATE;
		default: /* FSP_ERR_CRYPTO_SCE_AUTHENTICATION */
			return TEE_ERROR_MAC_INVALID;
	}

	params[1].memref.size = HW_SCE_AES_BLOCK_BYTE_SIZE;

	return TEE_SUCCESS;
}

static TEE_Result aes128cmac_verifyinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_cmac_handle_t * handle;
	sce_aes_wrapped_key_t * wrapped_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_cmac_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_cmac_handle_t) > params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	wrapped_key = (sce_aes_wrapped_key_t *)params[1].memref.buffer;
	if ((NULL == wrapped_key) || (sizeof(sce_aes_wrapped_key_t) != params[1].memref.size)){
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = g_sce_protected_on_sce.AES128CMAC_VerifyInit(handle, wrapped_key);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
			return TEE_ERROR_ACCESS_CONFLICT;
		case FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL:
			return TEE_ERROR_BAD_PARAMETERS;
		default: /* FSP_ERR_CRYPTO_SCE_FAIL */
			return TEE_ERROR_GENERIC;
	}

	params[0].memref.size = sizeof(sce_cmac_handle_t);

	return TEE_SUCCESS;
}

static TEE_Result aes128cmac_verifyupdate(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_cmac_handle_t * handle;
	uint8_t * message;
	uint32_t message_length;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_cmac_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_cmac_handle_t) != params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	message = (uint8_t *)params[1].memref.buffer;
	message_length = (uint32_t)params[1].memref.size;
	if (NULL == message) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = g_sce_protected_on_sce.AES128CMAC_VerifyUpdate(handle, message, message_length);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case FSP_ERR_CRYPTO_SCE_PARAMETER:
			return TEE_ERROR_BAD_PARAMETERS;
		default: /*FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION */
			return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

static TEE_Result aes128cmac_verifyfinal(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_cmac_handle_t * handle;
	uint8_t * mac;
	uint32_t mac_length;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_cmac_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_cmac_handle_t) != params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	mac = (uint8_t *)params[1].memref.buffer;
	mac_length = params[1].memref.size;
	if ((NULL == mac) || (2 > mac_length) || (HW_SCE_AES_BLOCK_BYTE_SIZE < mac_length)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = g_sce_protected_on_sce.AES128CMAC_VerifyFinal(handle, mac, mac_length);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case FSP_ERR_CRYPTO_SCE_FAIL:
			return TEE_ERROR_GENERIC;
		case FSP_ERR_CRYPTO_SCE_AUTHENTICATION:
			return TEE_ERROR_MAC_INVALID;
		case FSP_ERR_CRYPTO_SCE_PARAMETER:
			return TEE_ERROR_BAD_PARAMETERS;
		default: /* FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION */
			return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

static TEE_Result aes256cmac_generateinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_cmac_handle_t * handle;
	sce_aes_wrapped_key_t * wrapped_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_cmac_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_cmac_handle_t) > params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	wrapped_key = (sce_aes_wrapped_key_t *)params[1].memref.buffer;
	if ((NULL == wrapped_key) || (sizeof(sce_aes_wrapped_key_t) != params[1].memref.size)){
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = g_sce_protected_on_sce.AES256CMAC_GenerateInit(handle, wrapped_key);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
			return TEE_ERROR_ACCESS_CONFLICT;
		case FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL:
			return TEE_ERROR_BAD_PARAMETERS;
		default: /* FSP_ERR_CRYPTO_SCE_FAIL */
			return TEE_ERROR_GENERIC;
	}

	params[0].memref.size = sizeof(sce_cmac_handle_t);

	return TEE_SUCCESS;
}

static TEE_Result aes256cmac_generateupdate(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_cmac_handle_t * handle;
	uint8_t * message;
	uint32_t message_length;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_cmac_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_cmac_handle_t) != params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	message = (uint8_t *)params[1].memref.buffer;
	message_length = (uint32_t)params[1].memref.size;
	if (NULL == message) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = g_sce_protected_on_sce.AES256CMAC_GenerateUpdate(handle, message, message_length);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case FSP_ERR_CRYPTO_SCE_PARAMETER:
			return TEE_ERROR_BAD_PARAMETERS;
		default: /* FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION */
			return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

static TEE_Result aes256cmac_generatefinal(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_cmac_handle_t * handle;
	uint8_t * mac;
	uint32_t mac_length;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_cmac_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_cmac_handle_t) != params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	mac = (uint8_t *)params[1].memref.buffer;
	mac_length = params[1].memref.size;
	if ((NULL == mac) || (HW_SCE_AES_BLOCK_BYTE_SIZE > mac_length)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = g_sce_protected_on_sce.AES256CMAC_GenerateFinal(handle, mac);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case FSP_ERR_CRYPTO_SCE_FAIL:
			return TEE_ERROR_GENERIC;
		case FSP_ERR_CRYPTO_SCE_PARAMETER:
			return TEE_ERROR_BAD_PARAMETERS;
		case FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION:
			return TEE_ERROR_BAD_STATE;
		default: /* FSP_ERR_CRYPTO_SCE_AUTHENTICATION */
			return TEE_ERROR_MAC_INVALID;
	}

	params[1].memref.size = HW_SCE_AES_BLOCK_BYTE_SIZE;
	
	return TEE_SUCCESS;
}

static TEE_Result aes256cmac_verifyinit(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_cmac_handle_t * handle;
	sce_aes_wrapped_key_t * wrapped_key;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_cmac_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_cmac_handle_t) > params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	wrapped_key = (sce_aes_wrapped_key_t *)params[1].memref.buffer;
	if ((NULL == wrapped_key) || (sizeof(sce_aes_wrapped_key_t) != params[1].memref.size)){
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = g_sce_protected_on_sce.AES256CMAC_VerifyInit(handle, wrapped_key);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT:
			return TEE_ERROR_ACCESS_CONFLICT;
		case FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL:
			return TEE_ERROR_BAD_PARAMETERS;
		default: /* FSP_ERR_CRYPTO_SCE_FAIL */
			return TEE_ERROR_GENERIC;
	}

	params[0].memref.size = sizeof(sce_cmac_handle_t);

	return TEE_SUCCESS;
}

static TEE_Result aes256cmac_verifyupdate(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_cmac_handle_t * handle;
	uint8_t * message;
	uint32_t message_length;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_cmac_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_cmac_handle_t) != params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	message = (uint8_t *)params[1].memref.buffer;
	message_length = (uint32_t)params[1].memref.size;
	if (NULL == message) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = g_sce_protected_on_sce.AES256CMAC_VerifyUpdate(handle, message, message_length);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case FSP_ERR_CRYPTO_SCE_PARAMETER:
			return TEE_ERROR_BAD_PARAMETERS;
		default: /*FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION */
			return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

static TEE_Result aes256cmac_verifyfinal(uint32_t types, TEE_Param params[TEE_NUM_PARAMS])
{
	fsp_err_t err;

	sce_cmac_handle_t * handle;
	uint8_t * mac;
	uint32_t mac_length;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
					TEE_PARAM_TYPE_MEMREF_INPUT,
					TEE_PARAM_TYPE_NONE,
					TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	handle = (sce_cmac_handle_t *)params[0].memref.buffer;
	if ((NULL == handle) || (sizeof(sce_cmac_handle_t) != params[0].memref.size)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	mac = (uint8_t *)params[1].memref.buffer;
	mac_length = params[1].memref.size;
	if ((NULL == mac) || (2 > mac_length) || (HW_SCE_AES_BLOCK_BYTE_SIZE < mac_length)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	err = g_sce_protected_on_sce.AES256CMAC_VerifyFinal(handle, mac, mac_length);
	switch (err)
	{
		case FSP_SUCCESS:
			break;
		case FSP_ERR_CRYPTO_SCE_FAIL:
			return TEE_ERROR_GENERIC;
		case FSP_ERR_CRYPTO_SCE_AUTHENTICATION:
			return TEE_ERROR_MAC_INVALID;
		case FSP_ERR_CRYPTO_SCE_PARAMETER:
			return TEE_ERROR_BAD_PARAMETERS;
		default: /* FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION */
			return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

static TEE_Result invoke_command(
						void *session __unused,
						uint32_t cmd,
						uint32_t ptypes,
						TEE_Param params[TEE_NUM_PARAMS]
					)
{
	DMSG(PTA_NAME" command %#"PRIx32" ptypes %#"PRIx32, cmd, ptypes);

	switch (cmd) {
		case PTA_CMD_AES128ECB_EncryptInit :
			return aes128ecb_encryptinit(ptypes, params);
		case PTA_CMD_AES128ECB_EncryptUpdate :
			return aes128ecb_encryptupdate(ptypes, params);
		case PTA_CMD_AES128ECB_EncryptFinal :
			return aes128ecb_encryptfinal(ptypes, params);
		case PTA_CMD_AES128ECB_DecryptInit :
			return aes128ecb_decryptinit(ptypes, params);
		case PTA_CMD_AES128ECB_DecryptUpdate :
			return aes128ecb_decryptupdate(ptypes, params);
		case PTA_CMD_AES128ECB_DecryptFinal :
			return aes128ecb_decryptfinal(ptypes, params);
		case PTA_CMD_AES256ECB_EncryptInit :
			return aes256ecb_encryptinit(ptypes, params);
		case PTA_CMD_AES256ECB_EncryptUpdate :
			return aes256ecb_encryptupdate(ptypes, params);
		case PTA_CMD_AES256ECB_EncryptFinal :
			return aes256ecb_encryptfinal(ptypes, params);
		case PTA_CMD_AES256ECB_DecryptInit :
			return aes256ecb_decryptinit(ptypes, params);
		case PTA_CMD_AES256ECB_DecryptUpdate :
			return aes256ecb_decryptupdate(ptypes, params);
		case PTA_CMD_AES256ECB_DecryptFinal :
			return aes256ecb_decryptfinal(ptypes, params);
		case PTA_CMD_AES128CBC_EncryptInit :
			return aes128cbc_encryptinit(ptypes, params);
		case PTA_CMD_AES128CBC_EncryptUpdate :
			return aes128cbc_encryptupdate(ptypes, params);
		case PTA_CMD_AES128CBC_EncryptFinal :
			return aes128cbc_encryptfinal(ptypes, params);
		case PTA_CMD_AES128CBC_DecryptInit :
			return aes128cbc_decryptinit(ptypes, params);
		case PTA_CMD_AES128CBC_DecryptUpdate :
			return aes128cbc_decryptupdate(ptypes, params);
		case PTA_CMD_AES128CBC_DecryptFinal :
			return aes128cbc_decryptfinal(ptypes, params);
		case PTA_CMD_AES256CBC_EncryptInit :
			return aes256cbc_encryptinit(ptypes, params);
		case PTA_CMD_AES256CBC_EncryptUpdate :
			return aes256cbc_encryptupdate(ptypes, params);
		case PTA_CMD_AES256CBC_EncryptFinal :
			return aes256cbc_encryptfinal(ptypes, params);
		case PTA_CMD_AES256CBC_DecryptInit :
			return aes256cbc_decryptinit(ptypes, params);
		case PTA_CMD_AES256CBC_DecryptUpdate :
			return aes256cbc_decryptupdate(ptypes, params);
		case PTA_CMD_AES256CBC_DecryptFinal :
			return aes256cbc_decryptfinal(ptypes, params);
		case PTA_CMD_AES128CTR_EncryptInit :
			return aes128ctr_encryptinit(ptypes, params);
		case PTA_CMD_AES128CTR_EncryptUpdate :
			return aes128ctr_encryptupdate(ptypes, params);
		case PTA_CMD_AES128CTR_EncryptFinal :
			return aes128ctr_encryptfinal(ptypes, params);
		case PTA_CMD_AES128CTR_DecryptInit :
			return aes128ctr_decryptinit(ptypes, params);
		case PTA_CMD_AES128CTR_DecryptUpdate :
			return aes128ctr_decryptupdate(ptypes, params);
		case PTA_CMD_AES128CTR_DecryptFinal :
			return aes128ctr_decryptfinal(ptypes, params);
		case PTA_CMD_AES256CTR_EncryptInit :
			return aes256ctr_encryptinit(ptypes, params);
		case PTA_CMD_AES256CTR_EncryptUpdate :
			return aes256ctr_encryptupdate(ptypes, params);
		case PTA_CMD_AES256CTR_EncryptFinal :
			return aes256ctr_encryptfinal(ptypes, params);
		case PTA_CMD_AES256CTR_DecryptInit :
			return aes256ctr_decryptinit(ptypes, params);
		case PTA_CMD_AES256CTR_DecryptUpdate :
			return aes256ctr_decryptupdate(ptypes, params);
		case PTA_CMD_AES256CTR_DecryptFinal :
			return aes256ctr_decryptfinal(ptypes, params);
		case PTA_CMD_AES128CMAC_GenerateInit :
			return aes128cmac_generateinit(ptypes, params);
		case PTA_CMD_AES128CMAC_GenerateUpdate :
			return aes128cmac_generateupdate(ptypes, params);
		case PTA_CMD_AES128CMAC_GenerateFinal :
			return aes128cmac_generatefinal(ptypes, params);
		case PTA_CMD_AES128CMAC_VerifyInit :
			return aes128cmac_verifyinit(ptypes, params);
		case PTA_CMD_AES128CMAC_VerifyUpdate :
			return aes128cmac_verifyupdate(ptypes, params);
		case PTA_CMD_AES128CMAC_VerifyFinal :
			return aes128cmac_verifyfinal(ptypes, params);
		case PTA_CMD_AES256CMAC_GenerateInit :
			return aes256cmac_generateinit(ptypes, params);
		case PTA_CMD_AES256CMAC_GenerateUpdate :
			return aes256cmac_generateupdate(ptypes, params);
		case PTA_CMD_AES256CMAC_GenerateFinal :
			return aes256cmac_generatefinal(ptypes, params);
		case PTA_CMD_AES256CMAC_VerifyInit :
			return aes256cmac_verifyinit(ptypes, params);
		case PTA_CMD_AES256CMAC_VerifyUpdate :
			return aes256cmac_verifyupdate(ptypes, params);
		case PTA_CMD_AES256CMAC_VerifyFinal :
			return aes256cmac_verifyfinal(ptypes, params);
		default:
			return TEE_ERROR_NOT_SUPPORTED;
	}
}

pseudo_ta_register(
	.uuid = PTA_SCE_AES_UUID,
	.name = PTA_NAME,
	.flags = PTA_DEFAULT_FLAGS | TA_FLAG_DEVICE_ENUM,
	.invoke_command_entry_point = invoke_command
);
