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
 * TSIP_CMD_UPDATE_KEYRING - re-encrypt keyring
 * param[0] (memref)  [in]     input temp-encrypted keyring (688 bytes)
 * param[1] (memref)  [out]    output re-encrypted keyring (1296 bytes)
 * param[2] unused
 * param[3] unused
 */
#define TSIP_CMD_UPDATE_KEYRING		1

/*
 * TSIP_CMD_UPDATE_FIRMWARE - re-encrypt firmware
 * param[0] (value.a) [in]     Number of firmware info (maximum 16)
 * param[1] (memref)  [in/out] firmware info (array of st_update_fw_t)
 * param[2] (memref)  [in]     input temp-encrypted firmware buffer
 *                             place all temp-encrypted firmware in this area.
 * param[3] (memref)  [out]    output re-encrypted firmware buffer
 *                             (input length + 48 + (Number * 16) bytes)
 */
#define TSIP_CMD_UPDATE_FIRMWARE	2

/*
 * firmware info structure
 *
 * [in]
 *   offset : offset from input buffer
 *   length : length of input data
 * [out]
 *   offset : offset from output buffer
 *   length : length of output data
 */
typedef struct {
    unsigned long offset;
    unsigned long length;
} st_update_fw_t;

#endif /* TSIP_PTA_H_ */
