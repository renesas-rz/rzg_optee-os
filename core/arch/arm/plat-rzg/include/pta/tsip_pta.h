/*
 * Copyright (c) 2021, Renesas Electronics Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TSIP_PTA_H_
#define TSIP_PTA_H_

#define TSIP_UUID                                          \
    {                                                      \
        0x5f20b54e, 0x5a26, 0x11eb,                        \
        {                                                  \
            0x89, 0xb9, 0x2b, 0x53, 0x8d, 0xa4, 0xb7, 0xec \
        }                                                  \
    }

/*
 * TSIP_CMD_UPDATE_KEYRING - Re-encrypt Keyring
 * param[0] (memref) Input Temp-encrypt Keyring data (688 bytes size)
 * param[1] (memref) Output Re-encrypted Keyring data (1296 bytes size)
 * param[2] unused
 * param[3] unused
 */
#define TSIP_CMD_UPDATE_KEYRING 1

/*
 * TSIP_CMD_UPDATE_FIRMWARE - Re-Encrypt Firmware data
 * param[0] (value.a) Firmware data index number (maximum 16)
 * param[1] (memref) Input Temp-Encrypt firmware data (update_fw_t array)
 * param[2] (memref) Output Re-Encrypt firmware data (update_fw_t array)
 * param[3] unused
 */
#define TSIP_CMD_UPDATE_FIRMWARE 2

/*
 * Input/Output structure for TSIP_CMD_UPDATE_FIRMWARE
 * [Input]
 *   unsigned long size  : Input data size
 *   unsigned char *data : Input data
 * [Output] 
 *   unsigned long size  : Input data size + 64 (update_fw_t[0])
 *                         Input data size + 16 (update_fw_t[1-15])
 *   unsigned char *data : Output data
 */
typedef struct {
    unsigned long size;
    unsigned char *data;
} update_fw_t;

#endif /* TSIP_PTA_H_ */
