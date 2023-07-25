/*
 * Copyright (c) 2020, Renesas Electronics Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*! *****************************************************************************
    @file    R_TSIP_Core_Lib.h
    @brief   TSIP Security Driver Core Library API

    @par    History
    @subsection sub_history
      - Initial version
 ********************************************************************************/

#ifndef  R_TSIP_CORE_LIB_H_
#define  R_TSIP_CORE_LIB_H_

/* Define */
#define R_PASS                       (0x00000000)
#define R_INITIALIZATION_FAIL        (0x00000001)
#define R_PARAMETER_FAIL             (0x00000002)
#define R_SEQUENCE_FAIL              (0x00000003)
#define R_RESOURCE_CONFLICT_FAIL     (0x00000004)
#define R_VERIFICATION_FAIL          (0x00000005)
#define R_SERVERMESSAGE_FAIL         (0x00000006)
#define R_SERVER_VERIFICATION_FAIL   (0x00000007)
#define R_ROOTCA_CERTIFICATION_FAIL  (0x00000008)
#define R_USEKEY_FAIL                (0x00000009)
#define R_CONNECTSESSION_FAIL        (0x0000000A)
#define R_INDATA_OUTDATA_ACCESS_FAIL (0x0000000B)
#define R_PROVISIONING_KEY_FAIL      (0x0000000C)
#define R_GENERATION_FAIL            (0x0000000D)
#define R_KEYRING_FORMAT_FAIL        (0x0000000E)
#define R_ALLOCATE_MEMORY_FAIL       (0x00000020)
#define R_MMAP_FAIL                  (0x00000021)
#define R_FALSIFICATION_ERROR        (0x00000022)
#define R_INITIALIZATION_ERROR       (0x00000080)

/* MSTP Base Address and size */
#define  MSTP_BASE_ADDR             (0xE6150000U)
#define  MSTP_SIZE                  (0x00001000U)
/* TSIP Base Address and size */
#define  TSIP_BASE_ADDR             (0xE7800000U)
#define  TSIP_SIZE                  (0x00000200U)

#define UPDATE_BOOT_DATA_MAX             (16)

/* typedef */
typedef struct str_tsip_update_boot_data {
    unsigned long InData_BootData_UpdateFlag;
    unsigned char *InData_BootData;
    unsigned long InData_BootData_ByteSize;
    unsigned char *OutData_BootData;
} TSIP_UPDATE_BOOT_DATA[UPDATE_BOOT_DATA_MAX];


/* API */
/*                             */
/*  TSIP Library Initial API   */
/*                             */
unsigned long R_TSIP_Lib_Init(unsigned char *S_RAMData, unsigned char *S_INSTData, unsigned char *TSIP_BaseAddress, unsigned char *MSTP_BaseAddress);


/*                           */
/*  TSIP Secure Update API   */
/*                           */
unsigned long R_TSIP_SU_Activate(void);
unsigned long R_TSIP_UpdateBootData(TSIP_UPDATE_BOOT_DATA *tsip_update_bootdata);
unsigned long R_TSIP_SU_Key(unsigned char *InData_KeyRingOperationCode);


/*                          */
/*  TSIP Basic Encrypt API  */
/*                          */
unsigned long R_TSIP_BCF_GenerateRandom(
    unsigned long InData_GenByteSize,
    unsigned long InData_UseCASE,
    unsigned char *OutData);



#endif  /* R_TSIP_CORE_LIB_H_ */
