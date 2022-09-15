/*
 * Copyright (c) 2021, Renesas Electronics Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <compiler.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <trace.h>
#include <kernel/pseudo_ta.h>
#include <kernel/thread.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>

#include "drivers/tsip/R_TSIP_Core_Lib.h" 
#include "pta/tsip_pta.h"

#define TA_NAME "tsip.ta"

#define S_INSTDATA_ADDR (0x440FE000)
#define S_INSTDATA_SIZE (0x510)

#define TEMP_ENC_KEYRING_SIZE (0x2B0)
#define BOOT_HEADER_SIZE (0x30)


static bool tsip_su_activate = false;
vaddr_t s_instdata;

static TEE_Result tsip_update_keyring(uint32_t type, TEE_Param p[TEE_NUM_PARAMS])
{
    uint32_t err;
    uint8_t *input_keyring = NULL;

    uint32_t exp_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                        TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                        TEE_PARAM_TYPE_NONE,
                                        TEE_PARAM_TYPE_NONE);

    DMSG("has been called");

    if (type != exp_type)
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    
    if (!tsip_su_activate)
    {
        DMSG("Enable Firmware Update Process !");

        err = R_TSIP_SU_Activate();
        if (R_PASS != err) {
            EMSG("Failed to enable Firmware Update Process (0x%08x).", err);
            return TEE_ERROR_GENERIC;
        }
        tsip_su_activate = true;
    }

    s_instdata = (vaddr_t)phys_to_virt_io(S_INSTDATA_ADDR, S_INSTDATA_SIZE);

    if ((TEMP_ENC_KEYRING_SIZE > p[0].memref.size) || (S_INSTDATA_SIZE > p[1].memref.size))
        return TEE_ERROR_BAD_PARAMETERS;

    /* Re-encrypt Keyring data */
    input_keyring = (uint8_t *)p[0].memref.buffer;

    DMSG("Re-Encrypt Keyring data via TSIP");
    err = R_TSIP_SU_Key(input_keyring);
    if (R_PASS != err) {
        EMSG("Failed to Re-Encrypt Keyring data via TSIP (0x%08x).", err);
        return TEE_ERROR_GENERIC;
    }

    memcpy((uint8_t *)p[1].memref.buffer,(void *)s_instdata, S_INSTDATA_SIZE);
    p[1].memref.size = S_INSTDATA_SIZE;

    return TEE_SUCCESS;
}

static TEE_Result tsip_update_firmware(uint32_t type, TEE_Param p[TEE_NUM_PARAMS])
{

    uint32_t err;
    uint32_t data_max;

    uint8_t *boot_header_src = NULL;
    uint8_t *boot_header_dst = NULL;
    update_fw_t *input_update_fw;
    update_fw_t *output_update_fw;
    TSIP_UPDATE_BOOT_DATA tsip_update_boot_data;

    uint32_t exp_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
                                        TEE_PARAM_TYPE_MEMREF_INPUT,
                                        TEE_PARAM_TYPE_MEMREF_INOUT,
                                        TEE_PARAM_TYPE_NONE);

    DMSG("has been called");

    if (type != exp_type)
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if ((0 == p[1].memref.size) || (0 == p[2].memref.size))
        return TEE_ERROR_BAD_PARAMETERS;

    if (!tsip_su_activate)
    {
        DMSG("Enable Firmware Update Process !");

        err = R_TSIP_SU_Activate();
        if (R_PASS != err) {
            EMSG("Failed to enable Firmware Update Process (0x%08x).", err);
            return TEE_ERROR_GENERIC;
        }
        tsip_su_activate = true;
    }
    
    s_instdata = (vaddr_t)phys_to_virt_io(S_INSTDATA_ADDR, S_INSTDATA_SIZE);

    data_max = p[0].value.a;
    input_update_fw = (update_fw_t *)p[1].memref.buffer;
    output_update_fw = (update_fw_t *)p[2].memref.buffer;

    for (int i = 0; i < data_max; i++)
    {
        tsip_update_boot_data[i].InData_BootData_UpdateFlag = 0;
        if ((0 != input_update_fw[i].size))
        {
            if (0 == i)
            {
                if (output_update_fw[i].size < (input_update_fw[i].size + 64))
                {
                    return TEE_ERROR_BAD_PARAMETERS;
                }
                output_update_fw[i].size = input_update_fw[i].size + 64;
            }
            else
            {
                if (output_update_fw[i].size < (input_update_fw[i].size + 16))
                {
                    return TEE_ERROR_BAD_PARAMETERS;
                }
                output_update_fw[i].size = input_update_fw[i].size + 16;
            }

            tsip_update_boot_data[i].InData_BootData_UpdateFlag = 1;
            tsip_update_boot_data[i].InData_BootData = input_update_fw[i].data;
            tsip_update_boot_data[i].InData_BootData_ByteSize = input_update_fw[i].size;
            tsip_update_boot_data[i].OutData_BootData = output_update_fw[i].data;
        }
    }

    err = R_TSIP_UpdateBootData(&tsip_update_boot_data);
    if (R_PASS != err) {
        EMSG("Failed to Re-Encypt Firmware data via TSIP (0x%08x).", err);
        return TEE_ERROR_GENERIC;
    }

    /* Get boot header information for 1st boot data */
    if (tsip_update_boot_data[0].InData_BootData_UpdateFlag)
    {
        boot_header_src = s_instdata + S_INSTDATA_SIZE;
        boot_header_dst = (output_update_fw[0].data + output_update_fw[0].size) - BOOT_HEADER_SIZE;
        memcpy(boot_header_dst, boot_header_src, BOOT_HEADER_SIZE);
    }

    return TEE_SUCCESS;
}

/*
 * Trusted Application Entry Points
 */

static TEE_Result create_ta(void)
{
    DMSG("create entry point for pseudo TA \"%s\"", TA_NAME);
    return TEE_SUCCESS;
}

static void destroy_ta(void)
{
    DMSG("destroy entry point for pseudo ta \"%s\"", TA_NAME);
}

static TEE_Result open_session(uint32_t nParamTypes __unused,
                               TEE_Param pParams[TEE_NUM_PARAMS] __unused,
                               void **ppSessionContext __unused)
{
    DMSG("open entry point for pseudo ta \"%s\"", TA_NAME);
    return TEE_SUCCESS;
}

static void close_session(void *pSessionContext __unused)
{
    DMSG("close entry point for pseudo ta \"%s\"", TA_NAME);
}

static TEE_Result invoke_command(void *psess __unused,
                                 uint32_t cmd, uint32_t ptypes,
                                 TEE_Param params[TEE_NUM_PARAMS])
{
    switch (cmd)
    {
    case TSIP_CMD_UPDATE_KEYRING:
        return tsip_update_keyring(ptypes, params);
    case TSIP_CMD_UPDATE_FIRMWARE:
        return tsip_update_firmware(ptypes, params);
    default:
        break;
    }
    return TEE_ERROR_NOT_IMPLEMENTED;
}

pseudo_ta_register(.uuid = TSIP_UUID, .name = TA_NAME,
                   .flags = PTA_DEFAULT_FLAGS,
                   .create_entry_point = create_ta,
                   .destroy_entry_point = destroy_ta,
                   .open_session_entry_point = open_session,
                   .close_session_entry_point = close_session,
                   .invoke_command_entry_point = invoke_command);
