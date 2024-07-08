###################################################################################
1.About 
###################################################################################

*************************************************************************
1.1.Overview
*************************************************************************

This document describes the architecture of the driver for the Secure Crypto Engine (SCE) on RZ MPUs.

*************************************************************************
1.2.Features
*************************************************************************
The SCE module supports for the following features.

 - Cryptography
     - Symmetric Encryption/Decryption
          - AES
             - ECB 128/256bit
             - CBC 128/256bit
             - CTR 128/256bit
     - Asymmetric Encryption/Decryption
          - RSA
             - RSAES-PKCS1-V1_5 1024/2048bit
             - RSAES-PKCS1-V1_5 4096bit (Encryption only)
             - RSASSA-PKCS1-V1_5 1024/2048bit
             - RSASSA-PKCS1-V1_5 4096bit (Verification only)
          - ECC
             - ECDSA secp192r1/secp224r1/secp256r1/BrainpoolP512r1
     - Hash Functions
          - SHA-2
             - SHA-256/224
 - Message Authentication Code
     - AES-CMAC 128/256bit
 - Key Support
     - AES 128/256bit
     - RSA 1024/2048bit
     - RSA 4096bit (public key only)
     - ECC secp192r1/secp224r1/secp256r1/BrainpoolP512r1
 - TRNG

*************************************************************************
1.3.Terminology
*************************************************************************

*************************************************************************
1.4.Operating Environment
*************************************************************************
-------------------------------------------------------
1.4.1.Hardware Environment
-------------------------------------------------------
The following table lists the hardware needed to use this utility.

.. csv-table:: Hardware environment
    :header: "Name", "Note"

    Target board,"RZ/G2L Device"

-------------------------------------------------------
1.4.1.Software Environment
-------------------------------------------------------
This driver are designed for use with generic (or no specific) operating systems. 

*************************************************************************
1.5.Requirement
*************************************************************************

 - RZ Secure Crypto Engine library 1.0.0

*************************************************************************
1.6.Notice
*************************************************************************

This driver is distributed as a sample software from Renesas without any warranty or support.

For inquiries regarding the provision of the RZ Secure Crypto Engine library, please contact Renesas Electronics distributor or contact us.

###################################################################################
2.SCE Driver API Specifications
###################################################################################

This chapter presents the API specifications for the RZ SCE driver.

*************************************************************************
2.1.File Structure
*************************************************************************

This SCE driver file structure is shown below.

+------------------------+-------------------+---------------------------------------------------+
|Folder Name             |File Name          |Description                                        |
+=====+==================+===================+===================================================+
|sce  |doc               |sce_usage_notes.rst|This document.                                     |
|     +---------+--------+-------------------+---------------------------------------------------+
|     |inc      |api     |r_sce_api.h        |sce API interface header file                      |
|     |         +--------+-------------------+---------------------------------------------------+
|     |         |instance|r_sce.h            |cryptographic function API header file             |
|     +---------+--------+-------------------+---------------------------------------------------+
|     |private  |        |r_sce_private.c    |private function API header file                   |
|     |         +--------+-------------------+---------------------------------------------------+
|     |         |inc     |r_sce_private.h    |private function API module                        |
|     +---------+--------+-------------------+---------------------------------------------------+
|     |public            |r_sce_aes.c        |Public AES function API module                     |
|     |                  +-------------------+---------------------------------------------------+
|     |                  |r_sce_ecc.c        |Public ECC function API module                     |
|     |                  +-------------------+---------------------------------------------------+
|     |                  |r_sce_rsa.c        |Public RSA function API module                     |
|     |                  +-------------------+---------------------------------------------------+
|     |                  |r_sce_sha.c        |Public SHA function API module                     |
|     |                  +-------------------+---------------------------------------------------+
|     |                  |r_sce.c            |Common API module                                  |
+-----+------------------+-------------------+---------------------------------------------------+

*************************************************************************
2.2.Functions
*************************************************************************

+----------------------------------------------------------------------+---------------------------------+
|Functions                                                             |Description                      |
+=======+==============================================================+=================================+
|Common |`R_SCE_Open <2.6.1.R_SCE_Open_>`_                             |Enables use of SCE functionality.|
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_Close                                                  |Stops supply of power to the SCE.|
|       |<2.6.2.R_SCE_Close_>`_                                        |                                 |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_SoftwareReset                                          |Software reset to SCE.           |
|       |<2.6.3.R_SCE_SoftwareReset_>`_                                |                                 |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES128_WrappedKeyGenerate                              |Random AES 128bit wrapped        |
|       |<2.6.4.R_SCE_AES128_WrappedKeyGenerate_>`_                    |Key generate                     |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES256_WrappedKeyGenerate                              |Random AES 256bit wrapped        |
|       |<2.6.5.R_SCE_AES256_WrappedKeyGenerate_>`_                    |Key generate                     |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_RSA1024_WrappedKeyPairGenerate                         |Random RSA 1024bit wrapped       |
|       |<2.6.6.R_SCE_RSA1024_WrappedKeyPairGenerate_>`_               |Key Pair generate                |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_RSA2048_WrappedKeyPairGenerate                         |Random RSA 2048bit wrapped       |
|       |<2.6.7.R_SCE_RSA2048_WrappedKeyPairGenerate_>`_               |Key Pair generate                |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_ECC_secp192r1_WrappedKeyPairGenerate                   |Random ECC 192bit wrapped        |
|       |<2.6.8.R_SCE_ECC_secp192r1_WrappedKeyPairGenerate_>`_         |Key Pair generate                |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_ECC_secp224r1_WrappedKeyPairGenerate                   |Random ECC 224bit wrapped        |
|       |<2.6.9.R_SCE_ECC_secp224r1_WrappedKeyPairGenerate_>`_         |Key Pair generate                |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_ECC_secp256r1_WrappedKeyPairGenerate                   |Random ECC 256bit wrapped        |
|       |<2.6.10.R_SCE_ECC_secp256r1_WrappedKeyPairGenerate_>`_        |Key Pair generate                |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_ECC_BrainpoolP512r1_WrappedKeyPairGenerate             |Random ECC 512bit wrapped        |
|       |<2.6.11.R_SCE_ECC_BrainpoolP512r1_WrappedKeyPairGenerate_>`_  |Key Pair generate                |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_RandomNumberGenerate                                   |Generate 4 words random number   |
|       |<2.6.12.R_SCE_RandomNumberGenerate_>`_                        |                                 |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES128_EncryptedKeyWrap                                |Update AES 128bit installed Key  |
|       |<2.6.13.R_SCE_AES128_EncryptedKeyWrap_>`_                     |                                 |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES256_EncryptedKeyWrap                                |Update AES 256bit installed Key  |
|       |<2.6.14.R_SCE_AES256_EncryptedKeyWrap_>`_                     |                                 |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_RSA1024_EncryptedPublicKeyWrap                         |Update installed RSA 1024bit     |
|       |<2.6.15.R_SCE_RSA1024_EncryptedPublicKeyWrap_>`_              |publickey                        |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_RSA1024_EncryptedPrivateKeyWrap                        |Update installed RSA 1024bit     |
|       |<2.6.16.R_SCE_RSA1024_EncryptedPrivateKeyWrap_>`_             |PrivateKey                       |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_RSA2048_EncryptedPublicKeyWrap                         |Update installed RSA 2048bit     |
|       |<2.6.17.R_SCE_RSA2048_EncryptedPublicKeyWrap_>`_              |publickey                        |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_RSA2048_EncryptedPrivateKeyWrap                        |Update installed RSA 2048bit     |
|       |<2.6.18.R_SCE_RSA2048_EncryptedPrivateKeyWrap_>`_             |PrivateKey                       |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_RSA4096_EncryptedPublicKeyWrap                         |Update installed RSA 4096bit     |
|       |<2.6.19.R_SCE_RSA4096_EncryptedPublicKeyWrap_>`_              |publickey                        |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_ECC_secp192r1_EncryptedPublicKeyWrap                   |Update installed ECC 192bit      |
|       |<2.6.20.R_SCE_ECC_secp192r1_EncryptedPublicKeyWrap_>`_        |publickey                        |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_ECC_secp224r1_EncryptedPublicKeyWrap                   |Update installed ECC 224bit      |
|       |<2.6.21.R_SCE_ECC_secp224r1_EncryptedPublicKeyWrap_>`_        |publickey                        |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_ECC_secp256r1_EncryptedPublicKeyWrap                   |Update installed ECC 256bit      |
|       |<2.6.22.R_SCE_ECC_secp256r1_EncryptedPublicKeyWrap_>`_        |publickey                        |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_ECC_BrainpoolP512r1_EncryptedPublicKeyWrap             |Update installed ECC 512bit      |
|       |<2.6.23.R_SCE_ECC_BrainpoolP512r1_EncryptedPublicKeyWrap_>`_  |publickey                        |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_ECC_secp192r1_EncryptedPrivateKeyWrap                  |Update installed ECC 192bit      |
|       |<2.6.24.R_SCE_ECC_secp192r1_EncryptedPrivateKeyWrap_>`_       |PrivateKey                       |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_ECC_secp224r1_EncryptedPrivateKeyWrap                  |Update installed ECC 224bit      |
|       |<2.6.25.R_SCE_ECC_secp224r1_EncryptedPrivateKeyWrap_>`_       |PrivateKey                       |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_ECC_secp256r1_EncryptedPrivateKeyWrap                  |Update installed ECC 256bit      |
|       |<2.6.26.R_SCE_ECC_secp256r1_EncryptedPrivateKeyWrap_>`_       |PrivateKey                       |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_ECC_BrainpoolP512r1_EncryptedPrivateKeyWrap            |Update installed ECC 512bit      |
|       |<2.6.27.R_SCE_ECC_BrainpoolP512r1_EncryptedPrivateKeyWrap_>`_ |PrivateKey                       |
+-------+--------------------------------------------------------------+---------------------------------+
|AES    |`R_SCE_AES128ECB_EncryptInit                                  |Initialization function          |
|       |<2.6.28.R_SCE_AES128ECB_EncryptInit_>`_                       |(AES-128 ECB encryption)         |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES128ECB_EncryptUpdate                                |Update function                  |
|       |<2.6.29.R_SCE_AES128ECB_EncryptUpdate_>`_                     |(AES-128 ECB encryption)         |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES128ECB_EncryptFinal                                 |Termination function             |
|       |<2.6.30.R_SCE_AES128ECB_EncryptFinal_>`_                      |(AES-128 ECB encryption)         |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES128ECB_DecryptInit                                  |Initialization function          |
|       |<2.6.31.R_SCE_AES128ECB_DecryptInit_>`_                       |(AES-128 ECB decryption)         |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES128ECB_DecryptUpdate                                |Update function                  |
|       |<2.6.32.R_SCE_AES128ECB_DecryptUpdate_>`_                     |(AES-128 ECB decryption)         |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES128ECB_DecryptFinal                                 |Termination function             |
|       |<2.6.33.R_SCE_AES128ECB_DecryptFinal_>`_                      |(AES-256 ECB decryption)         |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES256ECB_EncryptInit                                  |Initialization function          |
|       |<2.6.34.R_SCE_AES256ECB_EncryptInit_>`_                       |(AES-256 ECB encryption)         |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES256ECB_EncryptUpdate                                |Update function                  |
|       |<2.6.35.R_SCE_AES256ECB_EncryptUpdate_>`_                     |(AES-256 ECB encryption)         |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES256ECB_EncryptFinal                                 |Termination function             |
|       |<2.6.36.R_SCE_AES256ECB_EncryptFinal_>`_                      |(AES-256 ECB encryption)         |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES256ECB_DecryptInit                                  |Initialization function          |
|       |<2.6.37.R_SCE_AES256ECB_DecryptInit_>`_                       |(AES-256 ECB decryption)         |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES256ECB_DecryptUpdate                                |Update function                  |
|       |<2.6.38.R_SCE_AES256ECB_DecryptUpdate_>`_                     |(AES-256 ECB decryption)         |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES256ECB_DecryptFinal                                 |Termination function             |
|       |<2.6.39.R_SCE_AES256ECB_DecryptFinal_>`_                      |(AES-256 ECB decryption)         |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES128CBC_EncryptInit                                  |Initialization function          |
|       |<2.6.40.R_SCE_AES128CBC_EncryptInit_>`_                       |(AES-128 CBC encryption)         |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES128CBC_EncryptUpdate                                |Update function                  |
|       |<2.6.41.R_SCE_AES128CBC_EncryptUpdate_>`_                     |(AES-128 CBC encryption)         |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES128CBC_EncryptFinal                                 |Termination function             |
|       |<2.6.42.R_SCE_AES128CBC_EncryptFinal_>`_                      |(AES-128 CBC encryption)         |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES128CBC_DecryptInit                                  |Initialization function          |
|       |<2.6.43.R_SCE_AES128CBC_DecryptInit_>`_                       |(AES-128 CBC decryption)         |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES128CBC_DecryptUpdate                                |Update function                  |
|       |<2.6.44.R_SCE_AES128CBC_DecryptUpdate_>`_                     |(AES-128 CBC decryption)         |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES128CBC_DecryptFinal                                 |Termination function             |
|       |<2.6.45.R_SCE_AES128CBC_DecryptFinal_>`_                      |(AES-128 CBC decryption)         |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES256CBC_EncryptInit                                  |Initialization function          |
|       |<2.6.46.R_SCE_AES256CBC_EncryptInit_>`_                       |(AES-256 CBC encryption)         |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES256CBC_EncryptUpdate                                |Update function                  |
|       |<2.6.47.R_SCE_AES256CBC_EncryptUpdate_>`_                     |(AES-256 CBC encryption)         |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES256CBC_EncryptFinal                                 |Termination function             |
|       |<2.6.48.R_SCE_AES256CBC_EncryptFinal_>`_                      |(AES-256 CBC encryption)         |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES256CBC_DecryptInit                                  |Initialization function          |
|       |<2.6.49.R_SCE_AES256CBC_DecryptInit_>`_                       |(AES-256 CBC decryption)         |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES256CBC_DecryptUpdate                                |Update function                  |
|       |<2.6.50.R_SCE_AES256CBC_DecryptUpdate_>`_                     |(AES-256 CBC decryption)         |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES256CBC_DecryptFinal                                 |Termination function             |
|       |<2.6.51.R_SCE_AES256CBC_DecryptFinal_>`_                      |(AES-256 CBC decryption)         |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES128CTR_EncryptInit                                  |Initialization function          |
|       |<2.6.52.R_SCE_AES128CTR_EncryptInit_>`_                       |(AES-128 CTR encryption)         |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES128CTR_EncryptUpdate                                |Update function                  |
|       |<2.6.53.R_SCE_AES128CTR_EncryptUpdate_>`_                     |(AES-128 CTR encryption)         |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES128CTR_EncryptFinal                                 |Termination function             |
|       |<2.6.54.R_SCE_AES128CTR_EncryptFinal_>`_                      |(AES-128 CTR encryption)         |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES128CTR_DecryptInit                                  |Initialization function          |
|       |<2.6.55.R_SCE_AES128CTR_DecryptInit_>`_                       |(AES-128 CTR decryption)         |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES128CTR_DecryptUpdate                                |Update function                  |
|       |<2.6.56.R_SCE_AES128CTR_DecryptUpdate_>`_                     |(AES-128 CTR decryption)         |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES128CTR_DecryptFinal                                 |Termination function             |
|       |<2.6.57.R_SCE_AES128CTR_DecryptFinal_>`_                      |(AES-128 CTR decryption)         |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES256CTR_EncryptInit                                  |Initialization function          |
|       |<2.6.58.R_SCE_AES256CTR_EncryptInit_>`_                       |(AES-256 CTR encryption)         |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES256CTR_EncryptUpdate                                |Update function                  |
|       |<2.6.59.R_SCE_AES256CTR_EncryptUpdate_>`_                     |(AES-256 CTR encryption)         |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES256CTR_EncryptFinal                                 |Termination function             |
|       |<2.6.60.R_SCE_AES256CTR_EncryptFinal_>`_                      |(AES-256 CTR encryption)         |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES256CTR_DecryptInit                                  |Initialization function          |
|       |<2.6.61.R_SCE_AES256CTR_DecryptInit_>`_                       |(AES-256 CTR decryption)         |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES256CTR_DecryptUpdate                                |Update function                  |
|       |<2.6.62.R_SCE_AES256CTR_DecryptUpdate_>`_                     |(AES-256 CTR decryption)         |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES256CTR_DecryptFinal                                 |Termination function             |
|       |<2.6.63.R_SCE_AES256CTR_DecryptFinal_>`_                      |(AES-256 CTR decryption)         |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES128CMAC_GenerateInit                                |Initialization function          |
|       |<2.6.64.R_SCE_AES128CMAC_GenerateInit_>`_                     |(AES-128 CMAC generation)        |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES128CMAC_GenerateUpdate                              |Update function                  |
|       |<2.6.65.R_SCE_AES128CMAC_GenerateUpdate_>`_                   |(AES-128 CMAC generation)        |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES128CMAC_GenerateFinal                               |Termination function             |
|       |<2.6.66.R_SCE_AES128CMAC_GenerateFinal_>`_                    |(AES-128 CMAC generation)        |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES128CMAC_VerifyInit                                  |Initialization function          |
|       |<2.6.67.R_SCE_AES128CMAC_VerifyInit_>`_                       |(AES-128 CMAC verification)      |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES128CMAC_VerifyUpdate                                |Update function                  |
|       |<2.6.68.R_SCE_AES128CMAC_VerifyUpdate_>`_                     |(AES-128 CMAC verification)      |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES128CMAC_VerifyFinal                                 |Termination function             |
|       |<2.6.69.R_SCE_AES128CMAC_VerifyFinal_>`_                      |(AES-128 CMAC verification)      |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES256CMAC_GenerateInit                                |Initialization function          |
|       |<2.6.70.R_SCE_AES256CMAC_GenerateInit_>`_                     |(AES-256 CMAC generation)        |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES256CMAC_GenerateUpdate                              |Update function                  |
|       |<2.6.71.R_SCE_AES256CMAC_GenerateUpdate_>`_                   |(AES-256 CMAC generation)        |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES256CMAC_GenerateFinal                               |Termination function             |
|       |<2.6.72.R_SCE_AES256CMAC_GenerateFinal_>`_                    |(AES-256 CMAC generation)        |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES256CMAC_VerifyInit                                  |Initialization function          |
|       |<2.6.73.R_SCE_AES256CMAC_VerifyInit_>`_                       |(AES-256 CMAC verification)      |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES256CMAC_VerifyUpdate                                |Update function                  |
|       |<2.6.74.R_SCE_AES256CMAC_VerifyUpdate_>`_                     |(AES-256 CMAC verification)      |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_AES256CMAC_VerifyFinal                                 |Termination function             |
|       |<2.6.75.R_SCE_AES256CMAC_VerifyFinal_>`_                      |(AES-256 CMAC verification)      |
+-------+--------------------------------------------------------------+---------------------------------+
|SHA    |`R_SCE_SHA256_Init                                            |Initialization function          |
|       |<2.6.76.R_SCE_SHA256_Init_>`_                                 |(SHA-256 hash value generation)  |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_SHA256_Update                                          |Update function                  |
|       |<2.6.77.R_SCE_SHA256_Update_>`_                               |(SHA-256 hash value generation)  |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_SHA256_Final                                           |Termination function             |
|       |<2.6.78.R_SCE_SHA256_Final_>`_                                |(SHA-256 hash value generation)  |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_SHA224_Init                                            |Initialization function          |
|       |<2.6.79.R_SCE_SHA224_Init_>`_                                 |(SHA-224 hash value generation)  |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_SHA224_Update                                          |Update function                  |
|       |<2.6.80.R_SCE_SHA224_Update_>`_                               |(SHA-224 hash value generation)  |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_SHA224_Final                                           |Termination function             |
|       |<2.6.81.R_SCE_SHA224_Final_>`_                                |(SHA-224 hash value generation)  |
+-------+--------------------------------------------------------------+---------------------------------+
|RSA    |`R_SCE_RSASSA_PKCS1024_SignatureGenerate                      |RSA Signature Generation         |
|       |<2.6.82.R_SCE_RSASSA_PKCS1024_SignatureGenerate_>`_           |with 1024bit key                 |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_RSASSA_PKCS1024_SignatureVerify                        |RSA Signature verification       |
|       |<2.6.83.R_SCE_RSASSA_PKCS1024_SignatureVerify_>`_             |with 1024bit key                 |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_RSASSA_PKCS2048_SignatureGenerate                      |RSA Signature Generation         |
|       |<2.6.84.R_SCE_RSASSA_PKCS2048_SignatureGenerate_>`_           |with 2048bit key                 |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_RSASSA_PKCS2048_SignatureVerify                        |RSA Signature verification       |
|       |<2.6.85.R_SCE_RSASSA_PKCS2048_SignatureVerify_>`_             |with 2048bit key                 |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_RSASSA_PKCS4096_SignatureVerify                        |RSA Signature verification       |
|       |<2.6.86.R_SCE_RSASSA_PKCS4096_SignatureVerify_>`_             |with 4096bit key                 |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_RSAES_PKCS1024_Encrypt                                 |RSA 1024bit encryption function  |
|       |<2.6.87.R_SCE_RSAES_PKCS1024_Encrypt_>`_                      |                                 |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_RSAES_PKCS1024_Decrypt                                 |RSA 1024bit decryption function  |
|       |<2.6.88.R_SCE_RSAES_PKCS1024_Decrypt_>`_                      |                                 |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_RSAES_PKCS2048_Encrypt                                 |RSA 2048bit encryption function  |
|       |<2.6.89.R_SCE_RSAES_PKCS2048_Encrypt_>`_                      |                                 |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_RSAES_PKCS2048_Decrypt                                 |RSA 1024bit decryption function  |
|       |<2.6.90.R_SCE_RSAES_PKCS2048_Decrypt_>`_                      |                                 |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_RSAES_PKCS4096_Encrypt                                 |RSA 4096bit encryption function  |
|       |<2.6.91.R_SCE_RSAES_PKCS4096_Encrypt_>`_                      |                                 |
+-------+--------------------------------------------------------------+---------------------------------+
|ECC    |`R_SCE_ECDSA_secp192r1_SignatureGenerate                      |192bit ECC Signature Generation  |
|       |<2.6.92.R_SCE_ECDSA_secp192r1_SignatureGenerate_>`_           |                                 |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_ECDSA_secp224r1_SignatureGenerate                      |224bit ECC Signature Generation  |
|       |<2.6.93.R_SCE_ECDSA_secp224r1_SignatureGenerate_>`_           |                                 |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_ECDSA_secp256r1_SignatureGenerate                      |256bit ECC Signature Generation  |
|       |<2.6.94.R_SCE_ECDSA_secp256r1_SignatureGenerate_>`_           |                                 |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_ECDSA_BrainpoolP512r1_SignatureGenerate                |512bit ECC Signature verification|
|       |<2.6.95.R_SCE_ECDSA_BrainpoolP512r1_SignatureGenerate_>`_     |                                 |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_ECDSA_secp192r1_SignatureVerify                        |192bit ECC Signature verification|
|       |<2.6.96.R_SCE_ECDSA_secp192r1_SignatureVerify_>`_             |                                 |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_ECDSA_secp224r1_SignatureVerify                        |224bit ECC Signature verification|
|       |<2.6.97.R_SCE_ECDSA_secp224r1_SignatureVerify_>`_             |                                 |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_ECDSA_secp256r1_SignatureVerify                        |256bit ECC Signature verification|
|       |<2.6.98.R_SCE_ECDSA_secp256r1_SignatureVerify_>`_             |                                 |
|       +--------------------------------------------------------------+---------------------------------+
|       |`R_SCE_ECDSA_BrainpoolP512r1_SignatureVerify                  |512bit ECC Signature verification|
|       |<2.6.99.R_SCE_ECDSA_BrainpoolP512r1_SignatureVerify_>`_       |                                 |
+-------+--------------------------------------------------------------+---------------------------------+


*************************************************************************
2.3.Return Values and Constants
*************************************************************************
The return values for the SCE driver API functions is shown below.

.. csv-table:: Return values for the SCE driver API functions
    :header: "Return Code", "Value", "Description"

    FSP_SUCCESS,0,"Normal termination"
    FSP_ERR_CRYPTO_CONTINUE,0x10000,"Continue executing function"
    FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT,0x10001,"Hardware resource busy"
    FSP_ERR_CRYPTO_SCE_FAIL,0x10002,"Internal I/O buffer is not empty"
    FSP_ERR_CRYPTO_SCE_HRK_INVALID_INDEX,0x10003,"Invalid index"
    FSP_ERR_CRYPTO_SCE_RETRY,0x10004,"Retry"
    FSP_ERR_CRYPTO_SCE_VERIFY_FAIL,0x10005,"Verify is failed"
    FSP_ERR_CRYPTO_SCE_ALREADY_OPEN,0x10006,"HW SCE module is already opened"
    FSP_ERR_CRYPTO_NOT_OPEN,0x10007,"Hardware module is not initialized"
    FSP_ERR_CRYPTO_UNKNOWN,0x10008,"Some unknown error occurred"
    FSP_ERR_CRYPTO_NULL_POINTER,0x10009,"Null pointer input as a parameter"
    FSP_ERR_CRYPTO_NOT_IMPLEMENTED,0x1000a,"Algorithm/size not implemented"
    FSP_ERR_CRYPTO_RNG_INVALID_PARAM,0x1000b,"An invalid parameter is specified"
    FSP_ERR_CRYPTO_RNG_FATAL_ERROR,0x1000c,"A fatal error occurred"
    FSP_ERR_CRYPTO_INVALID_SIZE,0x1000d,"Size specified is invalid"
    FSP_ERR_CRYPTO_INVALID_STATE,0x1000e,"Function used in an valid state"
    FSP_ERR_CRYPTO_ALREADY_OPEN,0x1000f,"control block is already opened"
    FSP_ERR_CRYPTO_INSTALL_KEY_FAILED,0x10010,"Specified input key is invalid."
    FSP_ERR_CRYPTO_AUTHENTICATION_FAILED,0x10011,"Authentication failed"
    FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL,0x10012,"Failure to Init Cipher"
    FSP_ERR_CRYPTO_SCE_AUTHENTICATION,0x10013,"Authentication failed"
    FSP_ERR_CRYPTO_SCE_PARAMETER,0x10014,"Input date is illegal."
    FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION,0x10015,"An invalid function call occurred."
    FSP_ERR_CRYPTO_COMMON_NOT_OPENED,0x20000,"Crypto Framework Common is not opened"
    FSP_ERR_CRYPTO_HAL_ERROR,0x20001,"Cryoto HAL module returned an error"
    FSP_ERR_CRYPTO_KEY_BUF_NOT_ENOUGH,0x20002,"Key buffer size is not enough to generate a key"
    FSP_ERR_CRYPTO_BUF_OVERFLOW,0x20003,"Attempt to write data larger than what the buffer can hold"
    FSP_ERR_CRYPTO_INVALID_OPERATION_MODE,0x20004,"Invalid operation mode."
    FSP_ERR_MESSAGE_TOO_LONG,0x20005,"Message for RSA encryption is too long."
    FSP_ERR_RSA_DECRYPTION_ERROR,0x20006,"RSA Decryption error."

The macro constants defined by the SCE driver is shown below.

.. csv-table:: Macro define for Common operation
    :header: "Macro Code", "Value"

    HW_SCE_SRAM_WORD_SIZE,32U
    HW_SCE_SINST_WORD_SIZE,140U
    HW_SCE_SINST2_WORD_SIZE,16U
    HW_SCE_SHEAP_WORD_SIZE,1504U
    HW_SCE_MAC_SIZE,16U

.. csv-table:: Macro define for AES operation
    :header: "Macro Code", "Value"

    HW_SCE_AES128_KEY_INDEX_WORD_SIZE,12U
    HW_SCE_AES256_KEY_INDEX_WORD_SIZE,16U
    HW_SCE_AES128_KEY_WORD_SIZE,4U
    HW_SCE_AES256_KEY_WORD_SIZE,8U
    HW_SCE_AES128_KEY_BYTE_SIZE,16U
    HW_SCE_AES256_KEY_BYTE_SIZE,32U
    HW_SCE_AES_BLOCK_BYTE_SIZE,16U
    HW_SCE_AES_BLOCK_BIT_SIZE,128U
    HW_SCE_AES_CBC_IV_BYTE_SIZE,16U
    HW_SCE_AES_CTR_IV_BYTE_SIZE,16U

.. csv-table:: Macro define for SHA operation
    :header: "Macro Code", "Value"

    HW_SCE_SHA224_HASH_LENGTH_BYTE_SIZE,28U
    HW_SCE_SHA256_HASH_LENGTH_BYTE_SIZE,32U
    HW_SCE_SHA512_HASH_LENGTH_BYTE_SIZE,64U

.. csv-table:: Macro define for RSA operation
    :header: "Macro Code", "Value"

    HW_SCE_RSA_1024_KEY_N_LENGTH_BYTE_SIZE,128U
    HW_SCE_RSA_1024_KEY_E_LENGTH_BYTE_SIZE,4U
    HW_SCE_RSA_1024_KEY_D_LENGTH_BYTE_SIZE,128U
    HW_SCE_RSA_2048_KEY_N_LENGTH_BYTE_SIZE,256U
    HW_SCE_RSA_2048_KEY_E_LENGTH_BYTE_SIZE,4U
    HW_SCE_RSA_2048_KEY_D_LENGTH_BYTE_SIZE,256U
    HW_SCE_RSA_4096_KEY_N_LENGTH_BYTE_SIZE,128*4U
    HW_SCE_RSA_4096_KEY_E_LENGTH_BYTE_SIZE,4U
    HW_SCE_RSA_4096_KEY_D_LENGTH_BYTE_SIZE,128*4U
    HW_SCE_RSA_1024_PUBLIC_KEY_MANAGEMENT_INFO1_WORD_SIZE,4U
    HW_SCE_RSA_1024_PUBLIC_KEY_MANAGEMENT_INFO2_WORD_SIZE,36U
    HW_SCE_RSA_1024_PRIVATE_KEY_MANAGEMENT_INFO1_WORD_SIZE,4U
    HW_SCE_RSA_1024_PRIVATE_KEY_MANAGEMENT_INFO2_WORD_SIZE,68U
    HW_SCE_RSA_2048_PUBLIC_KEY_MANAGEMENT_INFO1_WORD_SIZE,4U
    HW_SCE_RSA_2048_PUBLIC_KEY_MANAGEMENT_INFO2_WORD_SIZE,68U
    HW_SCE_RSA_2048_PRIVATE_KEY_MANAGEMENT_INFO1_WORD_SIZE,4U
    HW_SCE_RSA_2048_PRIVATE_KEY_MANAGEMENT_INFO2_WORD_SIZE,132U
    HW_SCE_RSA_4096_PUBLIC_KEY_MANAGEMENT_INFO1_WORD_SIZE,4U
    HW_SCE_RSA_4096_PUBLIC_KEY_MANAGEMENT_INFO2_WORD_SIZE,4U
    HW_SCE_RSA_KEY_GENERATION_DUMMY_BYTE_SIZE,12U
    HW_SCE_RSA1024_RANDOM_PUBLIC_KEY_INDEX_WORD_SIZE,76U
    HW_SCE_RSA1024_RANDOM_PRIVATE_KEY_INDEX_WORD_SIZE,104U
    HW_SCE_RSA2048_RANDOM_PUBLIC_KEY_INDEX_WORD_SIZE,140U
    HW_SCE_RSA2048_RANDOM_PRIVATE_KEY_INDEX_WORD_SIZE,200U
    HW_SCE_RSA_RSAES_PKCS_MIN_KEY_N_BYTE_SIZE,11U
    HW_SCE_RSA_1024_DATA_BYTE_SIZE,128U
    HW_SCE_RSA_2048_DATA_BYTE_SIZE,256U
    HW_SCE_RSA_4096_DATA_BYTE_SIZE,128*4U
    HW_SCE_SHARED_SECRET_KEY_INDEX_WORD_SIZE,13U

.. csv-table:: Macro define for ECC operation
    :header: "Macro Code", "Value"

    HW_SCE_ECC_KEY_LENGTH_BYTE_SIZE,144U
    HW_SCE_ECC_PUBLIC_KEY_MANAGEMENT_INFO_WORD_SIZE,4U
    HW_SCE_ECC_PRIVATE_KEY_MANAGEMENT_INFO_WORD_SIZE,24U
    HW_SCE_ECDSA_DATA_BYTE_SIZE,64U
    HW_SCE_ECDSA_P512_DATA_BYTE_SIZE,128U
    SCE_ECC_CURVE_TYPE_NIST,0
    SCE_ECC_CURVE_TYPE_BRAINPOOL,1
    SCE_ECC_CURVE_TYPE_KOBLITZ,2
    SCE_ECC_KEY_LENGTH_256,0
    SCE_ECC_KEY_LENGTH_224,1
    SCE_ECC_KEY_LENGTH_192,2

.. csv-table:: Macro define for HASH type
    :header: "Macro Code", "Value"

    HW_SCE_RSA_HASH_SHA256,0x03

.. csv-table:: Macro define for Key update
    :header: "Macro Code", "Value"

    HW_SCE_UPDATE_KEY_RING_INDEX_WORD_SIZE,16U
    SCE_OEM_KEY_SIZE_DUMMY_INST_DATA_WORD,0
    SCE_OEM_KEY_SIZE_AES128_INST_DATA_WORD,8
    SCE_OEM_KEY_SIZE_AES256_INST_DATA_WORD,12
    SCE_OEM_KEY_SIZE_RSA1024_PUBLIC_KEY_INST_DATA_WORD,40
    SCE_OEM_KEY_SIZE_RSA1024_PRIVATE_KEY_INST_DATA_WORD,68
    SCE_OEM_KEY_SIZE_RSA2048_PUBLIC_KEY_INST_DATA_WORD,72
    SCE_OEM_KEY_SIZE_RSA2048_PRIVATE_KEY_INST_DATA_WORD,132
    SCE_OEM_KEY_SIZE_RSA4096_PUBLIC_KEY_INST_DATA_WORD,136
    SCE_OEM_KEY_SIZE_RSA4096_PRIVATE_KEY_INST_DATA_WORD,260
    SCE_OEM_KEY_SIZE_ECCP192_PUBLIC_KEY_INST_DATA_WORD,20
    SCE_OEM_KEY_SIZE_ECCP192_PRIVATE_KEY_INST_DATA_WORD,12
    SCE_OEM_KEY_SIZE_ECCP224_PUBLIC_KEY_INST_DATA_WORD,20
    SCE_OEM_KEY_SIZE_ECCP224_PRIVATE_KEY_INST_DATA_WORD,12
    SCE_OEM_KEY_SIZE_ECCP256_PUBLIC_KEY_INST_DATA_WORD,20
    SCE_OEM_KEY_SIZE_ECCP256_PRIVATE_KEY_INST_DATA_WORD,12
    SCE_INSTALL_KEY_RING_INDEX,0


*************************************************************************
2.4.Structure and Enumerations
*************************************************************************

-------------------------------------------------------
SCE_KEY_INDEX_TYPE
-------------------------------------------------------

.. code:: c

    typedef enum
    {
        SCE_KEY_INDEX_TYPE_INVALID = 0U,
        SCE_KEY_INDEX_TYPE_AES128,
        SCE_KEY_INDEX_TYPE_AES256,
        SCE_KEY_INDEX_TYPE_TDES,
        SCE_KEY_INDEX_TYPE_HMAC_SHA1,
        SCE_KEY_INDEX_TYPE_HMAC_SHA256,
        SCE_KEY_INDEX_TYPE_RSA1024_PUBLIC,
        SCE_KEY_INDEX_TYPE_RSA1024_PRIVATE,
        SCE_KEY_INDEX_TYPE_RSA2048_PUBLIC,
        SCE_KEY_INDEX_TYPE_RSA2048_PRIVATE,
        SCE_KEY_INDEX_TYPE_RSA3072_PUBLIC,
        SCE_KEY_INDEX_TYPE_RSA3072_PRIVATE,
        SCE_KEY_INDEX_TYPE_RSA4096_PUBLIC,
        SCE_KEY_INDEX_TYPE_RSA4096_PRIVATE,
        SCE_KEY_INDEX_TYPE_AES128_FOR_TLS,
        SCE_KEY_INDEX_TYPE_AES192_FOR_TLS,
        SCE_KEY_INDEX_TYPE_AES256_FOR_TLS,
        SCE_KEY_INDEX_TYPE_HMAC_SHA1_FOR_TLS,
        SCE_KEY_INDEX_TYPE_HMAC_SHA256_FOR_TLS,
        SCE_KEY_INDEX_TYPE_UPDATE_KEY_RING,
        SCE_KEY_INDEX_TYPE_TLS_CA_CERTIFICATION_PUBLIC_KEY,
        SCE_KEY_INDEX_TYPE_TLS_P256_ECC_KEY,
        SCE_KEY_INDEX_TYPE_ECC_P192_PUBLIC,
        SCE_KEY_INDEX_TYPE_ECC_P224_PUBLIC,
        SCE_KEY_INDEX_TYPE_ECC_P256_PUBLIC,
        SCE_KEY_INDEX_TYPE_ECC_P512_PUBLIC,
        SCE_KEY_INDEX_TYPE_ECC_P192_PRIVATE,
        SCE_KEY_INDEX_TYPE_ECC_P224_PRIVATE,
        SCE_KEY_INDEX_TYPE_ECC_P256_PRIVATE,
        SCE_KEY_INDEX_TYPE_ECC_P512_PRIVATE,
        SCE_KEY_INDEX_TYPE_ECC_P256R1_PUBLIC,
        SCE_KEY_INDEX_TYPE_ECC_P512R1_PUBLIC,
        SCE_KEY_INDEX_TYPE_ECC_P256R1_PRIVATE,
        SCE_KEY_INDEX_TYPE_ECC_P512R1_PRIVATE,
        SCE_KEY_INDEX_TYPE_ECC_SECP256K1_PUBLIC,
        SCE_KEY_INDEX_TYPE_ECC_SECP256K1_PRIVATE,
        SCE_KEY_INDEX_TYPE_ECDH_SHARED_SECRET,
        SCE_KEY_INDEX_TYPE_AES128_FOR_ECDH,
        SCE_KEY_INDEX_TYPE_AES256_FOR_ECDH,
        SCE_KEY_INDEX_TYPE_HMAC_SHA256_FOR_ECDH,
        SCE_KEY_INDEX_TYPE_AES128_GCM_FOR_DLMS_COSEM,
        SCE_KEY_INDEX_TYPE_AES256_GCM_FOR_DLMS_COSEM,
        SCE_KEY_INDEX_TYPE_AES128_KEY_WRAP_FOR_DLMS_COSEM,
        SCE_KEY_INDEX_TYPE_AES128_GCM_WITH_IV,
    } SCE_KEY_INDEX_TYPE;

-------------------------------------------------------
sce_oem_cmd
-------------------------------------------------------

.. code:: c

         typedef enum e_sce_oem_cmd
         {
            SCE_OEM_CMD_AES128 = 5,
            SCE_OEM_CMD_AES256 = 7,
            SCE_OEM_CMD_RSA1024_PUBLIC = 10,
            SCE_OEM_CMD_RSA1024_PRIVATE,
            SCE_OEM_CMD_RSA2048_PUBLIC,
            SCE_OEM_CMD_RSA2048_PRIVATE,
            SCE_OEM_CMD_RSA3072_PUBLIC,
            SCE_OEM_CMD_RSA3072_PRIVATE,
            SCE_OEM_CMD_RSA4096_PUBLIC,
            SCE_OEM_CMD_RSA4096_PRIVATE,
            SCE_OEM_CMD_ECC_P192_PUBLIC,
            SCE_OEM_CMD_ECC_P192_PRIVATE,
            SCE_OEM_CMD_ECC_P224_PUBLIC,
            SCE_OEM_CMD_ECC_P224_PRIVATE,
            SCE_OEM_CMD_ECC_P256_PUBLIC,
            SCE_OEM_CMD_ECC_P256_PRIVATE,
            SCE_OEM_CMD_ECC_P384_PUBLIC,
            SCE_OEM_CMD_ECC_P384_PRIVATE,
            SCE_OEM_CMD_ECC_P512_PUBLIC,
            SCE_OEM_CMD_ECC_P512_PRIVATE,
            SCE_OEM_CMD_HMAC_SHA256 = 28,
            SCE_OEM_CMD_NUM
         } sce_oem_cmd_t;

-------------------------------------------------------
sce_byte_data
-------------------------------------------------------
Byte data structure 

.. code:: c

        typedef struct sce_byte_data
        {
            uint8_t * pdata;                           ///< pointer
            uint32_t  data_length;                     ///< data_length
            uint32_t  data_type;                       ///< data type
        } sce_byte_data_t;

-------------------------------------------------------
sce_rsa_byte_data_t
-------------------------------------------------------
RSA byte data structure

.. code:: c

    typedef sce_byte_data_t sce_rsa_byte_data_t;   ///< byte data

-------------------------------------------------------
sce_ecdsa_byte_data_t
-------------------------------------------------------
ECDSA byte data structure

.. code:: c

    typedef sce_byte_data_t sce_ecdsa_byte_data_t; ///< byte data

-------------------------------------------------------
sce_aes_wrapped_key_t
-------------------------------------------------------
AES wrapped key data structure. DO NOT MODIFY.

.. code:: c

    typedef struct sce_aes_wrapped_key
    {
        uint32_t type;                                     ///< key type

        /* AES128, AES256 are supported */
        uint32_t value[SCE_TLS_AES256_KEY_INDEX_WORD_SIZE]; ///< wrapped key value   
    } sce_aes_wrapped_key_t;

-------------------------------------------------------
sce_rsa1024_public_wrapped_key_t
-------------------------------------------------------
RSA 1024bit public wrapped key data structure. DO NOT MODIFY.

.. code:: c

    typedef struct sce_rsa1024_public_wrapped_key
    {
        uint32_t type;                                                                            ///< key type
        struct
        {
            uint32_t key_management_info1[HW_SCE_RSA_1024_PUBLIC_KEY_MANAGEMENT_INFO1_WORD_SIZE]; ///< key management information
            uint8_t  key_n[HW_SCE_RSA_1024_KEY_N_LENGTH_BYTE_SIZE];                               ///< RSA 1024-bit public key n (plaintext)
            uint8_t  key_e[HW_SCE_RSA_1024_KEY_E_LENGTH_BYTE_SIZE];                               ///< RSA 1024-bit public key e (plaintext)
            uint8_t  dummy[HW_SCE_RSA_KEY_GENERATION_DUMMY_BYTE_SIZE];                            ///< dummy
            uint32_t key_management_info2[HW_SCE_AES256_KEY_INDEX_WORD_SIZE]; ///< key management information
        } value;
    } sce_rsa1024_public_wrapped_key_t;

-------------------------------------------------------
sce_rsa1024_private_wrapped_key_t
-------------------------------------------------------
RSA 1024bit private wrapped key data structure. DO NOT MODIFY.

.. code:: c

    typedef struct sce_rsa1024_private_wrapped_key
    {
        uint32_t type;                                                                             ///< key type
        struct
        {
            uint32_t key_management_info1[HW_SCE_RSA_1024_PRIVATE_KEY_MANAGEMENT_INFO1_WORD_SIZE]; ///< key management information
            uint8_t  key_n[HW_SCE_RSA_1024_KEY_N_LENGTH_BYTE_SIZE];                                ///< RSA 1024-bit private key n (plaintext)
            uint32_t key_management_info2[HW_SCE_RSA_1024_PRIVATE_KEY_MANAGEMENT_INFO2_WORD_SIZE]; ///< key management information
        } value;
    } sce_rsa1024_private_wrapped_key_t;

-------------------------------------------------------
sce_rsa2048_public_wrapped_key_t
-------------------------------------------------------
RSA 2048bit public wrapped key data structure. DO NOT MODIFY.

.. code:: c

    typedef struct sce_rsa2048_public_wrapped_key
    {
        uint32_t type;                                                                            ///< Key type
        struct
        {
            uint32_t key_management_info1[HW_SCE_RSA_2048_PUBLIC_KEY_MANAGEMENT_INFO1_WORD_SIZE]; ///< key management information
            uint8_t  key_n[HW_SCE_RSA_2048_KEY_N_LENGTH_BYTE_SIZE];                               ///< RSA 2048-bit public key n (plaintext)
            uint8_t  key_e[HW_SCE_RSA_2048_KEY_E_LENGTH_BYTE_SIZE];                               ///< RSA 2048-bit public key e (plaintext)
            uint8_t  dummy[HW_SCE_RSA_KEY_GENERATION_DUMMY_BYTE_SIZE];                            ///< dummy
            uint32_t key_management_info2[HW_SCE_RSA_2048_PUBLIC_KEY_MANAGEMENT_INFO2_WORD_SIZE]; ///< key management information
        } value;
    } sce_rsa2048_public_wrapped_key_t;

-------------------------------------------------------
sce_rsa2048_private_wrapped_key_t
-------------------------------------------------------
RSA 2048bit private wrapped key data structure. DO NOT MODIFY.

.. code:: c

    typedef struct sce_rsa2048_private_wrapped_key
    {
        uint32_t type;                                                                             ///< key type
        struct
        {
            uint32_t key_management_info1[HW_SCE_RSA_2048_PRIVATE_KEY_MANAGEMENT_INFO1_WORD_SIZE]; ///< key management information
            uint8_t  key_n[HW_SCE_RSA_2048_KEY_N_LENGTH_BYTE_SIZE];                                ///< RSA 2048-bit private key n (plaintext)
            uint32_t key_management_info2[HW_SCE_RSA_2048_PRIVATE_KEY_MANAGEMENT_INFO2_WORD_SIZE]; ///< key management information
        } value;
    } sce_rsa2048_private_wrapped_key_t;

-------------------------------------------------------
sce_rsa4096_public_wrapped_key_t
-------------------------------------------------------
RSA 4096bit public wrapped key data structure. DO NOT MODIFY.

.. code:: c

    typedef struct sce_rsa4096_public_wrapped_key
    {
        uint32_t type;                                                                            ///< Key type
        struct
        {
            uint32_t key_management_info1[HW_SCE_RSA_4096_PUBLIC_KEY_MANAGEMENT_INFO1_WORD_SIZE]; ///< key management information
            uint8_t  key_n[HW_SCE_RSA_4096_KEY_N_LENGTH_BYTE_SIZE];                               ///< RSA 4096-bit public key n (plaintext)
            uint8_t  key_e[HW_SCE_RSA_4096_KEY_E_LENGTH_BYTE_SIZE];                               ///< RSA 4096-bit public key e (plaintext)
            uint8_t  dummy[HW_SCE_RSA_KEY_GENERATION_DUMMY_BYTE_SIZE];                            ///< dummy
            uint32_t key_management_info2[HW_SCE_RSA_4096_PUBLIC_KEY_MANAGEMENT_INFO2_WORD_SIZE]; ///< key management information
        } value;
    } sce_rsa4096_public_wrapped_key_t;

-------------------------------------------------------
sce_rsa1024_wrapped_pair_key_t
-------------------------------------------------------
RSA 1024bit wrapped key pair structure. DO NOT MODIFY.

.. code:: c

    typedef struct sce_rsa1024_wrapped_pair_key
    {
        sce_rsa1024_private_wrapped_key_t priv_key; ///< RSA 1024-bit private wrapped key
        sce_rsa1024_public_wrapped_key_t pub_key;   ///< RSA 1024-bit public wrapped key
    } sce_rsa1024_wrapped_pair_key_t;

-------------------------------------------------------
sce_rsa2048_wrapped_pair_key_t
-------------------------------------------------------
RSA 2048bit wrapped key pair structure. DO NOT MODIFY.

.. code:: c

    typedef struct sce_rsa2048_wrapped_pair_key
    {
        sce_rsa2048_private_wrapped_key_t priv_key; ///< RSA 2048-bit private wrapped key
        sce_rsa2048_public_wrapped_key_t pub_key;   ///< RSA 2048-bit public wrapped key
    } sce_rsa2048_wrapped_pair_key_t;

-------------------------------------------------------
sce_ecc_private_wrapped_key_t
-------------------------------------------------------
ECC P-192/224/256/512 private wrapped key data structure.

.. code:: c

    typedef struct sce_ecc_private_wrapped_key
    {
        uint32_t type;                                                    ///< key type
        uint32_t value[HW_SCE_ECC_PRIVATE_KEY_MANAGEMENT_INFO_WORD_SIZE]; ///< wrapped key value   
    } sce_ecc_private_wrapped_key_t;


-------------------------------------------------------
sce_ecc_public_wrapped_key_t
-------------------------------------------------------
ECC P-192/224/256/512 public wrapped key data structure.

.. code:: c

    typedef struct sce_ecc_public_wrapped_key
    {
        uint32_t type;                                                                     ///< key type
        struct
        {
            uint32_t key_management_info[HW_SCE_ECC_PUBLIC_KEY_MANAGEMENT_INFO_WORD_SIZE]; ///< key management information
            uint8_t  key_q[HW_SCE_ECC_KEY_LENGTH_BYTE_SIZE];                               ///< ECC public key Q (plaintext)
        } value;
    } sce_ecc_public_wrapped_key_t;

-------------------------------------------------------
sce_ecc_wrapped_pair_key_t
-------------------------------------------------------
ECC P-192/224/256/512 wrapped key pair structure.

.. code:: c

    typedef struct sce_ecc_wrapped_pair_key
    {
        sce_ecc_private_wrapped_key_t priv_key; ///< ECC private wrapped key
        sce_ecc_public_wrapped_key_t pub_key;   ///< ECC public wrapped key
    } sce_ecc_wrapped_pair_key_t;

-------------------------------------------------------
sce_key_update_key_t
-------------------------------------------------------
Update key ring index data structure. DO NOT MODIFY.

.. code:: c

    typedef struct sce_key_update_key
    {
        uint32_t type;                                          ///< key type
        uint32_t value[HW_SCE_UPDATE_KEY_RING_INDEX_WORD_SIZE]; ///< wrapped key value   
    } sce_key_update_key_t;

-------------------------------------------------------
sce_aes_handle_t
-------------------------------------------------------
The work area for AES. DO NOT MODIFY.

.. code:: c

    typedef struct sce_aes_handle
    {
        uint32_t              id;                                                       ///< serial number of this handle
        sce_aes_wrapped_key_t wrapped_key;                                              ///< wrapped key
        uint32_t              current_input_data_size;                                  ///< text size under encryption / decryption
        uint8_t               last_1_block_as_fraction[HW_SCE_AES_BLOCK_BYTE_SIZE];     ///< text array less than the block long
        uint8_t               last_2_block_as_fraction[HW_SCE_AES_BLOCK_BYTE_SIZE * 2]; ///< reserved
        uint8_t               current_initial_vector[HW_SCE_AES_CBC_IV_BYTE_SIZE];      ///< current initialization vector used in CBC mode
        uint8_t               flag_call_init;                                           ///< control flag of calling function
    } sce_aes_handle_t;

-------------------------------------------------------
sce_cmac_handle_t
-------------------------------------------------------
The work area for CMAC. DO NOT MODIFY.

.. code:: c

    typedef struct sce_cmac_handle
    {
        uint32_t              id;                                      ///< serial number of this handle
        sce_aes_wrapped_key_t wrapped_key;                             ///< wrapped key
        uint8_t               cmac_buffer[HW_SCE_AES_BLOCK_BYTE_SIZE]; ///< message array less than the block long
        uint32_t              all_received_length;                     ///< entire length of message
        uint32_t              buffering_length;                        ///< message array length less than the block long
        uint8_t               flag_call_init;                          ///< control flag of calling function
    } sce_cmac_handle_t;

-------------------------------------------------------
sce_sha_md5_handle_t
-------------------------------------------------------
The work area for SHA. DO NOT MODIFY.

.. code:: c

    typedef struct sce_sha_md5_handle
    {
        uint32_t id;                                                  ///< serial number of this handle
        uint8_t  sha_buffer[HW_SCE_SHA256_HASH_LENGTH_BYTE_SIZE * 4]; ///< message array length less than the block long
        uint32_t all_received_length;                                 ///< entire length of message
        uint32_t buffering_length;                                    ///< message array length less than the block long

        /* SHA1(20byte), SHA256(32byte), MD5(16byte) are supported */
        uint8_t current_hash[HW_SCE_SHA256_HASH_LENGTH_BYTE_SIZE];    ///< last hash value
        uint8_t flag_call_init;                                       ///< control flag of calling function
    } sce_sha_md5_handle_t;

-------------------------------------------------------
sce_ctrl_t
-------------------------------------------------------

.. code:: c

    typedef void sce_ctrl_t;

-------------------------------------------------------
sce_cfg_t
-------------------------------------------------------

.. code:: c

    typedef void sce_cfg_t;


-------------------------------------------------------
sce_api_t
-------------------------------------------------------
Functions implemented in sce driver.

.. code:: c

    typedef struct st_sce_api
    {
    
        fsp_err_t (* open)(sce_ctrl_t * const p_ctrl, sce_cfg_t const * const p_cfg);
    
        fsp_err_t (* close)(sce_ctrl_t * const p_ctrl);
    
        fsp_err_t (* softwareReset)(void);
    
        fsp_err_t (* randomNumberGenerate)(uint32_t * random);
    
        fsp_err_t (* AES128_WrappedKeyGenerate)(sce_aes_wrapped_key_t * wrapped_key);
    
        fsp_err_t (* AES256_WrappedKeyGenerate)(sce_aes_wrapped_key_t * wrapped_key);
    
        fsp_err_t (* AES128_EncryptedKeyWrap)(uint8_t * initial_vector, uint8_t * encrypted_key,
                                              sce_key_update_key_t * key_update_key, sce_aes_wrapped_key_t * wrapped_key);
    
        fsp_err_t (* AES256_EncryptedKeyWrap)(uint8_t * initial_vector, uint8_t * encrypted_key,
                                              sce_key_update_key_t * key_update_key, sce_aes_wrapped_key_t * wrapped_key);
    
        fsp_err_t (* AES128ECB_EncryptInit)(sce_aes_handle_t * handle, sce_aes_wrapped_key_t * wrapped_key);
    
        fsp_err_t (* AES128ECB_EncryptUpdate)(sce_aes_handle_t * handle, uint8_t * plain, uint8_t * cipher,
                                              uint32_t plain_length);
    
        fsp_err_t (* AES128ECB_EncryptFinal)(sce_aes_handle_t * handle, uint8_t * cipher, uint32_t * cipher_length);
    
        fsp_err_t (* AES128ECB_DecryptInit)(sce_aes_handle_t * handle, sce_aes_wrapped_key_t * wrapped_key);
    
        fsp_err_t (* AES128ECB_DecryptUpdate)(sce_aes_handle_t * handle, uint8_t * cipher, uint8_t * plain,
                                              uint32_t cipher_length);
    
        fsp_err_t (* AES128ECB_DecryptFinal)(sce_aes_handle_t * handle, uint8_t * plain, uint32_t * plain_length);
    
        fsp_err_t (* AES256ECB_EncryptInit)(sce_aes_handle_t * handle, sce_aes_wrapped_key_t * wrapped_key);
    
        fsp_err_t (* AES256ECB_EncryptUpdate)(sce_aes_handle_t * handle, uint8_t * plain, uint8_t * cipher,
                                              uint32_t plain_length);
    
        fsp_err_t (* AES256ECB_EncryptFinal)(sce_aes_handle_t * handle, uint8_t * cipher, uint32_t * cipher_length);
    
        fsp_err_t (* AES256ECB_DecryptInit)(sce_aes_handle_t * handle, sce_aes_wrapped_key_t * wrapped_key);
    
        fsp_err_t (* AES256ECB_DecryptUpdate)(sce_aes_handle_t * handle, uint8_t * cipher, uint8_t * plain,
                                              uint32_t cipher_length);
    
        fsp_err_t (* AES256ECB_DecryptFinal)(sce_aes_handle_t * handle, uint8_t * plain, uint32_t * plain_length);
    
        fsp_err_t (* AES128CBC_EncryptInit)(sce_aes_handle_t * handle, sce_aes_wrapped_key_t * wrapped_key,
                                            uint8_t * initial_vector);
    
        fsp_err_t (* AES128CBC_EncryptUpdate)(sce_aes_handle_t * handle, uint8_t * plain, uint8_t * cipher,
                                              uint32_t plain_length);
    
        fsp_err_t (* AES128CBC_EncryptFinal)(sce_aes_handle_t * handle, uint8_t * cipher, uint32_t * cipher_length);
    
        fsp_err_t (* AES128CBC_DecryptInit)(sce_aes_handle_t * handle, sce_aes_wrapped_key_t * wrapped_key,
                                            uint8_t * initial_vector);
    
        fsp_err_t (* AES128CBC_DecryptUpdate)(sce_aes_handle_t * handle, uint8_t * cipher, uint8_t * plain,
                                              uint32_t cipher_length);
    
        fsp_err_t (* AES128CBC_DecryptFinal)(sce_aes_handle_t * handle, uint8_t * plain, uint32_t * plain_length);
    
        fsp_err_t (* AES256CBC_EncryptInit)(sce_aes_handle_t * handle, sce_aes_wrapped_key_t * wrapped_key,
                                            uint8_t * initial_vector);
    
        fsp_err_t (* AES256CBC_EncryptUpdate)(sce_aes_handle_t * handle, uint8_t * plain, uint8_t * cipher,
                                              uint32_t plain_length);
    
        fsp_err_t (* AES256CBC_EncryptFinal)(sce_aes_handle_t * handle, uint8_t * cipher, uint32_t * cipher_length);
    
        fsp_err_t (* AES256CBC_DecryptInit)(sce_aes_handle_t * handle, sce_aes_wrapped_key_t * wrapped_key,
                                            uint8_t * initial_vector);
    
        fsp_err_t (* AES256CBC_DecryptUpdate)(sce_aes_handle_t * handle, uint8_t * cipher, uint8_t * plain,
                                              uint32_t cipher_length);
    
        fsp_err_t (* AES256CBC_DecryptFinal)(sce_aes_handle_t * handle, uint8_t * plain, uint32_t * plain_length);

        fsp_err_t (* AES128CTR_EncryptInit)(sce_aes_handle_t * handle, sce_aes_wrapped_key_t * wrapped_key,
                                            uint8_t * initial_vector);
    
        fsp_err_t (* AES128CTR_EncryptUpdate)(sce_aes_handle_t * handle, uint8_t * plain, uint8_t * cipher,
                                              uint32_t plain_length);
    
        fsp_err_t (* AES128CTR_EncryptFinal)(sce_aes_handle_t * handle, uint8_t * cipher, uint32_t * cipher_length);
    
        fsp_err_t (* AES128CTR_DecryptInit)(sce_aes_handle_t * handle, sce_aes_wrapped_key_t * wrapped_key,
                                            uint8_t * initial_vector);
    
        fsp_err_t (* AES128CTR_DecryptUpdate)(sce_aes_handle_t * handle, uint8_t * cipher, uint8_t * plain,
                                              uint32_t cipher_length);
    
        fsp_err_t (* AES128CTR_DecryptFinal)(sce_aes_handle_t * handle, uint8_t * plain, uint32_t * plain_length);
    
        fsp_err_t (* AES256CTR_EncryptInit)(sce_aes_handle_t * handle, sce_aes_wrapped_key_t * wrapped_key,
                                            uint8_t * initial_vector);
    
        fsp_err_t (* AES256CTR_EncryptUpdate)(sce_aes_handle_t * handle, uint8_t * plain, uint8_t * cipher,
                                              uint32_t plain_length);
    
        fsp_err_t (* AES256CTR_EncryptFinal)(sce_aes_handle_t * handle, uint8_t * cipher, uint32_t * cipher_length);
    
        fsp_err_t (* AES256CTR_DecryptInit)(sce_aes_handle_t * handle, sce_aes_wrapped_key_t * wrapped_key,
                                            uint8_t * initial_vector);
    
        fsp_err_t (* AES256CTR_DecryptUpdate)(sce_aes_handle_t * handle, uint8_t * cipher, uint8_t * plain,
                                              uint32_t cipher_length);
    
        fsp_err_t (* AES256CTR_DecryptFinal)(sce_aes_handle_t * handle, uint8_t * plain, uint32_t * plain_length);

        fsp_err_t (* AES128CMAC_GenerateInit)(sce_cmac_handle_t * handle, sce_aes_wrapped_key_t * wrapped_key);
    
        fsp_err_t (* AES128CMAC_GenerateUpdate)(sce_cmac_handle_t * handle, uint8_t * message, uint32_t message_length);
    
        fsp_err_t (* AES128CMAC_GenerateFinal)(sce_cmac_handle_t * handle, uint8_t * mac);
    
        fsp_err_t (* AES128CMAC_VerifyInit)(sce_cmac_handle_t * handle, sce_aes_wrapped_key_t * wrapped_key);
    
        fsp_err_t (* AES128CMAC_VerifyUpdate)(sce_cmac_handle_t * handle, uint8_t * message, uint32_t message_length);
    
        fsp_err_t (* AES128CMAC_VerifyFinal)(sce_cmac_handle_t * handle, uint8_t * mac, uint32_t mac_length);
    
        fsp_err_t (* AES256CMAC_GenerateInit)(sce_cmac_handle_t * handle, sce_aes_wrapped_key_t * wrapped_key);
    
        fsp_err_t (* AES256CMAC_GenerateUpdate)(sce_cmac_handle_t * handle, uint8_t * message, uint32_t message_length);
    
        fsp_err_t (* AES256CMAC_GenerateFinal)(sce_cmac_handle_t * handle, uint8_t * mac);
    
        fsp_err_t (* AES256CMAC_VerifyInit)(sce_cmac_handle_t * handle, sce_aes_wrapped_key_t * wrapped_key);
    
        fsp_err_t (* AES256CMAC_VerifyUpdate)(sce_cmac_handle_t * handle, uint8_t * message, uint32_t message_length);
    
        fsp_err_t (* AES256CMAC_VerifyFinal)(sce_cmac_handle_t * handle, uint8_t * mac, uint32_t mac_length);
    
        fsp_err_t (* SHA256_Init)(sce_sha_md5_handle_t * handle);
    
        fsp_err_t (* SHA256_Update)(sce_sha_md5_handle_t * handle, uint8_t * message, uint32_t message_length);
    
        fsp_err_t (* SHA256_Final)(sce_sha_md5_handle_t * handle, uint8_t * digest, uint32_t * digest_length);

        fsp_err_t (* SHA224_Init)(sce_sha_md5_handle_t * handle);
    
        fsp_err_t (* SHA224_Update)(sce_sha_md5_handle_t * handle, uint8_t * message, uint32_t message_length);
    
        fsp_err_t (* SHA224_Final)(sce_sha_md5_handle_t * handle, uint8_t * digest, uint32_t * digest_length);
    
        fsp_err_t (* RSA1024_WrappedKeyPairGenerate)(sce_rsa1024_wrapped_pair_key_t * wrapped_pair_key);
    
        fsp_err_t (* RSA2048_WrappedKeyPairGenerate)(sce_rsa2048_wrapped_pair_key_t * wrapped_pair_key);
    
        fsp_err_t (* RSA1024_EncryptedPublicKeyWrap)(uint8_t * initial_vector, uint8_t * encrypted_key,
                                                     sce_key_update_key_t * key_update_key,
                                                     sce_rsa1024_public_wrapped_key_t * wrapped_key);
    
        fsp_err_t (* RSA1024_EncryptedPrivateKeyWrap)(uint8_t * initial_vector, uint8_t * encrypted_key,
                                                      sce_key_update_key_t * key_update_key,
                                                      sce_rsa1024_private_wrapped_key_t * wrapped_key);
    
        fsp_err_t (* RSA2048_EncryptedPublicKeyWrap)(uint8_t * initial_vector, uint8_t * encrypted_key,
                                                     sce_key_update_key_t * key_update_key,
                                                     sce_rsa2048_public_wrapped_key_t * wrapped_key);
    
        fsp_err_t (* RSA2048_EncryptedPrivateKeyWrap)(uint8_t * initial_vector, uint8_t * encrypted_key,
                                                      sce_key_update_key_t * key_update_key,
                                                      sce_rsa2048_private_wrapped_key_t * wrapped_key);
    
        fsp_err_t (* RSA4096_EncryptedPublicKeyWrap)(uint8_t * initial_vector, uint8_t * encrypted_key,
                                                     sce_key_update_key_t * key_update_key,
                                                     sce_rsa4096_public_wrapped_key_t * wrapped_key);
    
        fsp_err_t (* RSASSA_PKCS1024_SignatureGenerate)(sce_rsa_byte_data_t * message_hash, sce_rsa_byte_data_t * signature,
                                                        sce_rsa1024_private_wrapped_key_t * wrapped_key, uint8_t hash_type);
    
        fsp_err_t (* RSASSA_PKCS2048_SignatureGenerate)(sce_rsa_byte_data_t * message_hash, sce_rsa_byte_data_t * signature,
                                                        sce_rsa2048_private_wrapped_key_t * wrapped_key, uint8_t hash_type);
    
        fsp_err_t (* RSASSA_PKCS1024_SignatureVerify)(sce_rsa_byte_data_t * signature, sce_rsa_byte_data_t * message_hash,
                                                      sce_rsa1024_public_wrapped_key_t * wrapped_key, uint8_t hash_type);
    
        fsp_err_t (* RSASSA_PKCS2048_SignatureVerify)(sce_rsa_byte_data_t * signature, sce_rsa_byte_data_t * message_hash,
                                                      sce_rsa2048_public_wrapped_key_t * wrapped_key, uint8_t hash_type);
    
        fsp_err_t (* RSASSA_PKCS4096_SignatureVerify)(sce_rsa_byte_data_t * signature, sce_rsa_byte_data_t * message_hash,
                                                      sce_rsa4096_public_wrapped_key_t * wrapped_key, uint8_t hash_type);
    
        fsp_err_t (* RSAES_PKCS1024_Encrypt)(sce_rsa_byte_data_t * plain, sce_rsa_byte_data_t * cipher,
                                             sce_rsa1024_public_wrapped_key_t * wrapped_key);
    
        fsp_err_t (* RSAES_PKCS2048_Encrypt)(sce_rsa_byte_data_t * plain, sce_rsa_byte_data_t * cipher,
                                             sce_rsa2048_public_wrapped_key_t * wrapped_key);
    
        fsp_err_t (* RSAES_PKCS4096_Encrypt)(sce_rsa_byte_data_t * plain, sce_rsa_byte_data_t * cipher,
                                             sce_rsa4096_public_wrapped_key_t * wrapped_key);
    
        fsp_err_t (* RSAES_PKCS1024_Decrypt)(sce_rsa_byte_data_t * cipher, sce_rsa_byte_data_t * plain,
                                             sce_rsa1024_private_wrapped_key_t * wrapped_key);
    
        fsp_err_t (* RSAES_PKCS2048_Decrypt)(sce_rsa_byte_data_t * cipher, sce_rsa_byte_data_t * plain,
                                             sce_rsa2048_private_wrapped_key_t * wrapped_key);
    
        fsp_err_t (* ECC_secp192r1_WrappedKeyPairGenerate)(sce_ecc_wrapped_pair_key_t * wrapped_pair_key);
    
        fsp_err_t (* ECC_secp224r1_WrappedKeyPairGenerate)(sce_ecc_wrapped_pair_key_t * wrapped_pair_key);
    
        fsp_err_t (* ECC_secp256r1_WrappedKeyPairGenerate)(sce_ecc_wrapped_pair_key_t * wrapped_pair_key);
    
        fsp_err_t (* ECC_secp192r1_EncryptedPublicKeyWrap)(uint8_t * initial_vector, uint8_t * encrypted_key,
                                                           sce_key_update_key_t * key_update_key,
                                                           sce_ecc_public_wrapped_key_t * wrapped_key);
    
        fsp_err_t (* ECC_secp224r1_EncryptedPublicKeyWrap)(uint8_t * initial_vector, uint8_t * encrypted_key,
                                                           sce_key_update_key_t * key_update_key,
                                                           sce_ecc_public_wrapped_key_t * wrapped_key);
    
        fsp_err_t (* ECC_secp256r1_EncryptedPublicKeyWrap)(uint8_t * initial_vector, uint8_t * encrypted_key,
                                                           sce_key_update_key_t * key_update_key,
                                                           sce_ecc_public_wrapped_key_t * wrapped_key);
    
        fsp_err_t (* ECC_BrainpoolP512r1_EncryptedPublicKeyWrap)(uint8_t * initial_vector, uint8_t * encrypted_key,
                                                           sce_key_update_key_t * key_update_key,
                                                           sce_ecc_public_wrapped_key_t * wrapped_key);
    
        fsp_err_t (* ECC_secp192r1_EncryptedPrivateKeyWrap)(uint8_t * initial_vector, uint8_t * encrypted_key,
                                                            sce_key_update_key_t * key_update_key,
                                                            sce_ecc_private_wrapped_key_t * wrapped_key);
    
        fsp_err_t (* ECC_secp224r1_EncryptedPrivateKeyWrap)(uint8_t * initial_vector, uint8_t * encrypted_key,
                                                            sce_key_update_key_t * key_update_key,
                                                            sce_ecc_private_wrapped_key_t * wrapped_key);
    
        fsp_err_t (* ECC_secp256r1_EncryptedPrivateKeyWrap)(uint8_t * initial_vector, uint8_t * encrypted_key,
                                                            sce_key_update_key_t * key_update_key,
                                                            sce_ecc_private_wrapped_key_t * wrapped_key);
    
        fsp_err_t (* ECC_BrainpoolP512r1_EncryptedPrivateKeyWrap)(uint8_t * initial_vector, uint8_t * encrypted_key,
                                                            sce_key_update_key_t * key_update_key,
                                                            sce_ecc_private_wrapped_key_t * wrapped_key);
    
        fsp_err_t (* ECDSA_secp192r1_SignatureGenerate)(sce_ecdsa_byte_data_t         * message_hash,
                                                        sce_ecdsa_byte_data_t         * signature,
                                                        sce_ecc_private_wrapped_key_t * wrapped_key);
    
        fsp_err_t (* ECDSA_secp224r1_SignatureGenerate)(sce_ecdsa_byte_data_t         * message_hash,
                                                        sce_ecdsa_byte_data_t         * signature,
                                                        sce_ecc_private_wrapped_key_t * wrapped_key);
    
        fsp_err_t (* ECDSA_secp256r1_SignatureGenerate)(sce_ecdsa_byte_data_t         * message_hash,
                                                        sce_ecdsa_byte_data_t         * signature,
                                                        sce_ecc_private_wrapped_key_t * wrapped_key);
    
        fsp_err_t (* ECDSA_BrainpoolP512r1_SignatureGenerate)(sce_ecdsa_byte_data_t         * message_hash,
                                                        sce_ecdsa_byte_data_t         * signature,
                                                        sce_ecc_private_wrapped_key_t * wrapped_key);
    
        fsp_err_t (* ECDSA_secp192r1_SignatureVerify)(sce_ecdsa_byte_data_t        * signature,
                                                      sce_ecdsa_byte_data_t        * message_hash,
                                                      sce_ecc_public_wrapped_key_t * wrapped_key);
    
        fsp_err_t (* ECDSA_secp224r1_SignatureVerify)(sce_ecdsa_byte_data_t        * signature,
                                                      sce_ecdsa_byte_data_t        * message_hash,
                                                      sce_ecc_public_wrapped_key_t * wrapped_key);
    
        fsp_err_t (* ECDSA_secp256r1_SignatureVerify)(sce_ecdsa_byte_data_t        * signature,
                                                      sce_ecdsa_byte_data_t        * message_hash,
                                                      sce_ecc_public_wrapped_key_t * wrapped_key);
    
        fsp_err_t (* ECDSA_BrainpoolP512r1_SignatureVerify)(sce_ecdsa_byte_data_t        * signature,
                                                      sce_ecdsa_byte_data_t        * message_hash,
                                                      sce_ecc_public_wrapped_key_t * wrapped_key);
    } sce_api_t;

-------------------------------------------------------
sce_instance_t
-------------------------------------------------------
This structure encompasses everything that is needed to use an instance of this interface.

.. code:: c

    typedef struct st_sce_instance
    {
        sce_ctrl_t      * p_ctrl;          ///< Pointer to the control structure for this instance
        sce_cfg_t const * p_cfg;           ///< Pointer to the configuration structure for this instance
        sce_api_t const * p_api;           ///< Pointer to the API structure for this instance
    } sce_instance_t;

*************************************************************************
2.5.Global Variables
*************************************************************************
There are no global variables that can be used by users.


*************************************************************************
2.6.Function Specifications
*************************************************************************

-------------------------------------------------------
2.6.1.R_SCE_Open
-------------------------------------------------------
+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_Open ( sce_ctrl_t const \*\p_ctrl, sce_cfg_t const \*\const p_cfg )             |
+--------------+---------------------------------------------------------------------------------+
| Description  | Enables use of SCE functionality.                                               |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |IN       |p_ctrl                    |Pointer to control structure.               |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |p_cfg                     |Pointer to pin configuration structure.     |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |The error-detection self-test failed to     |
|              |                                    ||br| terminate normally.                    |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RETRY            |Indicates that an entropy evaluation failure|
|              |                                    ||br| occurred. Run the function again.      |
+--------------+------------------------------------+--------------------------------------------+
| Note         |                                                                                 |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.2.R_SCE_Close
-------------------------------------------------------
+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_Close ( sce_ctrl_t \*\const p_ctrl)                                             |
+--------------+---------------------------------------------------------------------------------+
| Description  | Stops supply of power to the SCE.                                               |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |IN       |p_ctrl                    |Pointer to control structure.               |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
+--------------+------------------------------------+--------------------------------------------+
| Note         |                                                                                 |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.3.R_SCE_SoftwareReset
-------------------------------------------------------
+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_SoftwareReset ( void )                                                          |
+--------------+---------------------------------------------------------------------------------+
| Description  | Software reset to SCE.                                                          |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |none     |none                      |none                                        |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
+--------------+------------------------------------+--------------------------------------------+
| Note         |                                                                                 |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.4.R_SCE_AES128_WrappedKeyGenerate
-------------------------------------------------------
+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES128_WrappedKeyGenerate ( sce_aes_wrapped_key_t \*\ wrapped_key)              |
+--------------+---------------------------------------------------------------------------------+
| Description  |This API outputs 128-bit AES wrapped key from a random number.                   |
|              ||br| This API generates a wrapped key from a random number in the SCE.           |
|              ||br| Accordingly, user key input is unnecessary.                                 |
|              ||br| By encrypting data using the wrapped key is output by this API,             |
|              ||br| dead copying of data can be prevented.                                      |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |wrapped_key               |128-bit AES wrapped key                     |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
+--------------+------------------------------------+--------------------------------------------+
| Note         |                                                                                 |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.5.R_SCE_AES256_WrappedKeyGenerate
-------------------------------------------------------
+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES256_WrappedKeyGenerate ( sce_aes_wrapped_key_t \*\ wrapped_key)              |
+--------------+---------------------------------------------------------------------------------+
| Description  |This API outputs 256-bit AES wrapped key from a random number.                   |
|              ||br| This API generates a wrapped key from a random number in the SCE.           |
|              ||br| Accordingly, user key input is unnecessary.                                 |
|              ||br| By encrypting data using the wrapped key is output by this API,             |
|              ||br| dead copying of data can be prevented.                                      |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |wrapped_key               |256-bit AES wrapped key                     |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
+--------------+------------------------------------+--------------------------------------------+
| Note         |                                                                                 |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.6.R_SCE_RSA1024_WrappedKeyPairGenerate
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t                                                                                       |
|R_SCE_RSA1024_WrappedKeyPairGenerate ( sce_rsa1024_wrapped_pair_key_t \*\wrapped_pair_key)      |
+--------------+---------------------------------------------------------------------------------+
| Description  |This API outputs a wrapped key pair                                              |
|              ||br| for a 1024-bit RSA public key and private key pair.These keys are generated |
|              ||br| from a random value produced internally by the SCE.                         |
|              ||br| Consequently, there is no need to input a user key.                         |
|              ||br| Dead copying of data can be prevented by encrypting the data using the      |
|              ||br| wrapped key output by this API. A public wrapped key is generated by        |
|              ||br| wrapped_pair_key->pub_key, and a private wrapped key is generated by        |
|              ||br| wrapped_pair_key->priv_key.                                                 |
|              ||br| As the public key exponent, only 0x00010001 is generated.                   |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |wrapped_pair_key          |User key index for RSA 1024-bit public key  |
|              |         |                          ||br| and private key pair                   |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
|              |                                    ||br| Key generation failed.                 |
+--------------+------------------------------------+--------------------------------------------+
| Note         |                                                                                 |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.7.R_SCE_RSA2048_WrappedKeyPairGenerate
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t                                                                                       |
|R_SCE_RSA2048_WrappedKeyPairGenerate ( sce_rsa2048_wrapped_pair_key_t \*\wrapped_pair_key)      |
+--------------+---------------------------------------------------------------------------------+
| Description  |This API outputs a wrapped key pair                                              |
|              ||br| for a 2048-bit RSA public key and private key pair.These keys are generated |
|              ||br| from a random value produced internally by the SCE.                         |
|              ||br| Consequently, there is no need to input a user key.                         |
|              ||br| Dead copying of data can be prevented by encrypting the data using the      |
|              ||br| wrapped key output by this API. A public wrapped key is generated by        |
|              ||br| wrapped_pair_key->pub_key, and a private wrapped key is generated by        |
|              ||br| wrapped_pair_key->priv_key.                                                 |
|              ||br| As the public key exponent, only 0x00010001 is generated.                   |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |wrapped_pair_key          |User key index for RSA 2048-bit public key  |
|              |         |                          ||br| and private key pair                   |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
|              |                                    ||br| Key generation failed.                 |
+--------------+------------------------------------+--------------------------------------------+
| Note         |                                                                                 |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.8.R_SCE_ECC_secp192r1_WrappedKeyPairGenerate
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t                                                                                       |
|R_SCE_ECC_secp192r1_WrappedKeyPairGenerate ( sce_ecc_wrapped_pair_key_t \*\wrapped_pair_key)    |
+--------------+---------------------------------------------------------------------------------+
| Description  |This is an API for outputting a wrapped key pair for secp192r1 public key        |
|              ||br| and private key pair. These keys are generated from a random number value   |
|              ||br| internally within the SCE. There is therefore no need to input user keys.   |
|              ||br| Consequently, there is no need to input a user key.                         |
|              ||br| It is possible to prevent dead copying of data by using                     |
|              ||br| wrapped key output by this API. A public wrapped key is generated by        |
|              ||br| the wrapped key output by this API to encrypt the data.                     |
|              ||br| The public key index is generated in wrapped_pair_key->pub_key,             |
|              ||br| and the private key index is generated in wrapped_pair_key->priv_key.       |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |wrapped_pair_key          |Wrapped pair key forsecp192r1 public key    |
|              |         |                          ||br| and private key pair                   |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
|              |                                    ||br| Key generation failed.                 |
+--------------+------------------------------------+--------------------------------------------+
| Note         |                                                                                 |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.9.R_SCE_ECC_secp224r1_WrappedKeyPairGenerate
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t                                                                                       |
| R_SCE_ECC_secp224r1_WrappedKeyPairGenerate ( sce_ecc_wrapped_pair_key_t \*\wrapped_pair_key)   |
+--------------+---------------------------------------------------------------------------------+
| Description  |This is an API for outputting a wrapped key pair for secp224r1 public key        |
|              ||br| and private key pair. These keys are generated from a random number value   |
|              ||br| internally within the SCE. There is therefore no need to input user keys.   |
|              ||br| Consequently, there is no need to input a user key.                         |
|              ||br| It is possible to prevent dead copying of data by using                     |
|              ||br| wrapped key output by this API. A public wrapped key is generated by        |
|              ||br| the wrapped key output by this API to encrypt the data.                     |
|              ||br| The public key index is generated in wrapped_pair_key->pub_key,             |
|              ||br| and the private key index is generated in wrapped_pair_key->priv_key.       |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |wrapped_pair_key          |Wrapped pair key forsecp224r1 public key    |
|              |         |                          ||br| and private key pair                   |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
|              |                                    ||br| Key generation failed.                 |
+--------------+------------------------------------+--------------------------------------------+
| Note         |                                                                                 |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.10.R_SCE_ECC_secp256r1_WrappedKeyPairGenerate
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t                                                                                       |
|R_SCE_ECC_secp256r1_WrappedKeyPairGenerate ( sce_ecc_wrapped_pair_key_t \*\wrapped_pair_key)    |
+--------------+---------------------------------------------------------------------------------+
| Description  |This is an API for outputting a wrapped key pair for secp256r1 public key        |
|              ||br| and private key pair. These keys are generated from a random number value   |
|              ||br| internally within the SCE. There is therefore no need to input user keys.   |
|              ||br| Consequently, there is no need to input a user key.                         |
|              ||br| It is possible to prevent dead copying of data by using                     |
|              ||br| wrapped key output by this API. A public wrapped key is generated by        |
|              ||br| the wrapped key output by this API to encrypt the data.                     |
|              ||br| The public key index is generated in wrapped_pair_key->pub_key,             |
|              ||br| and the private key index is generated in wrapped_pair_key->priv_key.       |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |wrapped_pair_key          |Wrapped pair key forsecp256r1 public key    |
|              |         |                          ||br| and private key pair                   |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
|              |                                    ||br| Key generation failed.                 |
+--------------+------------------------------------+--------------------------------------------+
| Note         |                                                                                 |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.11.R_SCE_ECC_BrainpoolP512r1_WrappedKeyPairGenerate
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t                                                                                       |
|R_SCE_ECC_BrainpoolP512r1_WrappedKeyPairGenerate(sce_ecc_wrapped_pair_key_t \*\wrapped_pair_key)|
+--------------+---------------------------------------------------------------------------------+
| Description  |This is an API for outputting a wrapped key pair for BrainpoolP512r1 public key  |
|              ||br| and private key pair. These keys are generated from a random number value   |
|              ||br| internally within the SCE. There is therefore no need to input user keys.   |
|              ||br| Consequently, there is no need to input a user key.                         |
|              ||br| It is possible to prevent dead copying of data by using                     |
|              ||br| wrapped key output by this API. A public wrapped key is generated by        |
|              ||br| the wrapped key output by this API to encrypt the data.                     |
|              ||br| The public key index is generated in wrapped_pair_key->pub_key,             |
|              ||br| and the private key index is generated in wrapped_pair_key->priv_key.       |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |wrapped_pair_key          |Wrapped pair key for BrainpoolP512r1        |
|              |         |                          ||br|  key pair                              |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
|              |                                    ||br| Key generation failed.                 |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.12.R_SCE_RandomNumberGenerate
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_RandomNumberGenerate ( uint32_t \*\random)                                      |
+--------------+---------------------------------------------------------------------------------+
| Description  |This API can generate 4 words random number.                                     |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |random                    |Stores 4words (16 bytes) random data.       |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.13.R_SCE_AES128_EncryptedKeyWrap
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES128_EncryptedKeyWrap ( uint8_t \*\ initial_vector, uint8_t \*\ encrypted_key,|
||br| sce_key_update_key_t \*\ key_update_key, sce_aes_wrapped_key_t \*\ wrapped_key )           |
+--------------+---------------------------------------------------------------------------------+
| Description  |This API wraps 128-bit AES key within the user routine.                          |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |IN       |initial_vector            |Initialization vector when                  |
|              |         |                          ||br| generating encrypted_key               |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |encrypted_key             |User key encryptedand MAC appended          |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |key_update_key            |Key update keyring                          |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |wrapped_key               |128-bit AES wrapped key                     |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
+--------------+------------------------------------+--------------------------------------------+
| Note         |For information on how to create and update keys, refer to Security Manual       |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.14.R_SCE_AES256_EncryptedKeyWrap
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES256_EncryptedKeyWrap ( uint8_t \*\ initial_vector, uint8_t \*\ encrypted_key,|
||br| sce_key_update_key_t \*\ key_update_key, sce_aes_wrapped_key_t \*\ wrapped_key )           |
+--------------+---------------------------------------------------------------------------------+
| Description  |This API wraps 256-bit AES key within the user routine.                          |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |IN       |initial_vector            |Initialization vector when                  |
|              |         |                          ||br| generating encrypted_key               |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |encrypted_key             |User key encrypted and MAC appended         |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |key_update_key            |Key update keyring                          |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |wrapped_key               |256-bit AES wrapped key                     |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
+--------------+------------------------------------+--------------------------------------------+
| Note         |For information on how to create and update keys, refer to Security Manual       |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.15.R_SCE_RSA1024_EncryptedPublicKeyWrap
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_RSA1024_EncryptedPublicKeyWrap ( uint8_t \*\initial_vector,                     |
||br| uint8_t \*\ encrypted_key, sce_key_update_key_t \*\ key_update_key,                        |
||br| sce_rsa1024_public_wrapped_key_t \*\ wrapped_key )                                         |
+--------------+---------------------------------------------------------------------------------+
| Description  |This API wraps 1024-bit RSA public key within the user routine.                  |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |IN       |initial_vector            |Initialization vector when                  |
|              |         |                          ||br| generating encrypted_key               |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |encrypted_key             |User key encrypted and MAC appended         |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |key_update_key            |Key update keyring                          |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |wrapped_key               |1024-bit RSA public wrapped key             |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
+--------------+------------------------------------+--------------------------------------------+
| Note         |For information on how to create and update keys, refer to Security Manual       |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.16.R_SCE_RSA1024_EncryptedPrivateKeyWrap
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_RSA1024_EncryptedPrivateKeyWrap ( uint8_t \*\ initial_vector,                   |
||br| uint8_t \*\ encrypted_key, sce_key_update_key_t \*\ key_update_key,                        |
||br| sce_rsa1024_private_wrapped_key_t \*\ wrapped_key )                                        |
+--------------+---------------------------------------------------------------------------------+
| Description  |This API wraps 1024-bit RSA private key within the user routine.                 |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |IN       |initial_vector            |Initialization vector when                  |
|              |         |                          ||br| generating encrypted_key               |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |encrypted_key             |User key encrypted and MAC appended         |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |key_update_key            |Key update keyring                          |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |wrapped_key               |1024-bit RSA private wrapped key            |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
+--------------+------------------------------------+--------------------------------------------+
| Note         |For information on how to create and update keys, refer to Security Manual       |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.17.R_SCE_RSA2048_EncryptedPublicKeyWrap
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_RSA2048_EncryptedPublicKeyWrap ( uint8_t \*\ initial_vector,                    |
||br| uint8_t \*\ encrypted_key, sce_key_update_key_t \*\ key_update_key,                        |
||br| sce_rsa2048_public_wrapped_key_t \*\ wrapped_key )                                         |
+--------------+---------------------------------------------------------------------------------+
| Description  |This API wraps 2048-bit RSA public key within the user routine.                  |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |IN       |initial_vector            |Initialization vector when                  |
|              |         |                          ||br| generating encrypted_key               |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |encrypted_key             |User key encrypted and MAC appended         |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |key_update_key            |Key update keyring                          |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |wrapped_key               |2048-bit RSA public wrapped key             |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
+--------------+------------------------------------+--------------------------------------------+
| Note         |For information on how to create and update keys, refer to Security Manual       |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.18.R_SCE_RSA2048_EncryptedPrivateKeyWrap
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_RSA2048_EncryptedPrivateKeyWrap ( uint8_t \*\ initial_vector,                   |
||br| uint8_t \*\ encrypted_key, sce_key_update_key_t \*\ key_update_key,                        |
||br| sce_rsa2048_private_wrapped_key_t \*\ wrapped_key )                                        |
+--------------+---------------------------------------------------------------------------------+
| Description  |This API wraps 2048-bit RSA private key within the user routine.                 |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |IN       |initial_vector            |Initialization vector when                  |
|              |         |                          ||br| generating encrypted_key               |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |encrypted_key             |User key encrypted and MAC appended         |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |key_update_key            |Key update keyring                          |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |wrapped_key               |2048-bit RSA private wrapped key            |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
+--------------+------------------------------------+--------------------------------------------+
| Note         |For information on how to create and update keys, refer to Security Manual       |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.19.R_SCE_RSA4096_EncryptedPublicKeyWrap
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_RSA4096_EncryptedPublicKeyWrap ( uint8_t \*\ initial_vector,                    |
||br| uint8_t \*\ encrypted_key, sce_key_update_key_t \*\ key_update_key,                        |
||br| sce_rsa4096_public_wrapped_key_t \*\ wrapped_key )                                         |
+--------------+---------------------------------------------------------------------------------+
| Description  |This API wraps 4096-bit RSA public key within the user routine.                  |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |IN       |initial_vector            |Initialization vector when                  |
|              |         |                          ||br| generating encrypted_key               |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |encrypted_key             |User key encrypted and MAC appended         |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |key_update_key            |Key update keyring                          |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |wrapped_key               |4096-bit RSA public wrapped key             |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
+--------------+------------------------------------+--------------------------------------------+
| Note         |For information on how to create and update keys, refer to Security Manual       |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.20.R_SCE_ECC_secp192r1_EncryptedPublicKeyWrap
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_ECC_secp192r1_EncryptedPublicKeyWrap ( uint8_t \*\ initial_vector,              |
||br| uint8_t \*\ encrypted_key, sce_key_update_key_t \*\ key_update_key,                        |
||br| sce_ecc_public_wrapped_key_t \*\ wrapped_key )                                             |
+--------------+---------------------------------------------------------------------------------+
| Description  |This API wraps secp192r1 public key within the user routine.                     |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |IN       |initial_vector            |Initialization vector when                  |
|              |         |                          ||br| generating encrypted_key               |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |encrypted_key             |User key encrypted and MAC appended         |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |key_update_key            |Key update keyring                          |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |wrapped_key               |secp192r1 public wrapped key                |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
+--------------+------------------------------------+--------------------------------------------+
| Note         |For information on how to create and update keys, refer to Security Manual       |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.21.R_SCE_ECC_secp224r1_EncryptedPublicKeyWrap
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_ECC_secp224r1_EncryptedPublicKeyWrap ( uint8_t \*\ initial_vector,              |
||br| uint8_t \*\ encrypted_key, sce_key_update_key_t \*\ key_update_key,                        |
||br| sce_ecc_public_wrapped_key_t \*\ wrapped_key )                                             |
+--------------+---------------------------------------------------------------------------------+
| Description  |This API wraps secp224r1 public key within the user routine.                     |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |IN       |initial_vector            |Initialization vector when                  |
|              |         |                          ||br| generating encrypted_key               |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |encrypted_key             |User key encrypted and MAC appended         |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |key_update_key            |Key update keyring                          |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |wrapped_key               |secp224r1 public wrapped key                |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
+--------------+------------------------------------+--------------------------------------------+
| Note         |For information on how to create and update keys, refer to Security Manual       |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.22.R_SCE_ECC_secp256r1_EncryptedPublicKeyWrap
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_ECC_secp256r1_EncryptedPublicKeyWrap ( uint8_t \*\ initial_vector,              |
||br| uint8_t \*\ encrypted_key, sce_key_update_key_t \*\ key_update_key,                        |
||br| sce_ecc_public_wrapped_key_t \*\ wrapped_key )                                             |
+--------------+---------------------------------------------------------------------------------+
| Description  |This API wraps secp256r1 public key within the user routine.                     |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |IN       |initial_vector            |Initialization vector when                  |
|              |         |                          ||br| generating encrypted_key               |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |encrypted_key             |User key encrypted and MAC appended         |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |key_update_key            |Key update keyring                          |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |wrapped_key               |secp256r1 public wrapped key                |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processingroutine.          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
+--------------+------------------------------------+--------------------------------------------+
| Note         |For information on how to create and update keys, refer to Security Manual       |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.23.R_SCE_ECC_BrainpoolP512r1_EncryptedPublicKeyWrap
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_ECC_BrainpoolP512r1_EncryptedPublicKeyWrap ( uint8_t \*\ initial_vector,        |
||br| uint8_t \*\ encrypted_key, sce_key_update_key_t \*\ key_update_key,                        |
||br| sce_ecc_public_wrapped_key_t \*\ wrapped_key )                                             |
+--------------+---------------------------------------------------------------------------------+
| Description  |This API wraps BrainpoolP512r1 public key within the user routine.               |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |IN       |initial_vector            |Initialization vector when                  |
|              |         |                          ||br| generating encrypted_key               |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |encrypted_key             |User key encrypted and MAC appended         |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |key_update_key            |Key update keyring                          |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |wrapped_key               |BrainpoolP512r1 public wrapped key          |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
+--------------+------------------------------------+--------------------------------------------+
| Note         |For information on how to create and update keys, refer to Security Manual       |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.24.R_SCE_ECC_secp192r1_EncryptedPrivateKeyWrap
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_ECC_secp192r1_EncryptedPrivateKeyWrap ( uint8_t \*\ initial_vector,             |
||br| uint8_t \*\ encrypted_key, sce_key_update_key_t \*\ key_update_key,                        |
||br| sce_ecc_private_wrapped_key_t \*\ wrapped_key )                                            |
+--------------+---------------------------------------------------------------------------------+
| Description  |This API wraps secp192r1 private key within the user routine.                    |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |IN       |initial_vector            |Initialization vector when                  |
|              |         |                          ||br| generating encrypted_key               |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |encrypted_key             |User key encrypted and MAC appended         |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |key_update_key            |Key update keyring                          |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |wrapped_key               |secp192r1 private wrapped key               |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
+--------------+------------------------------------+--------------------------------------------+
| Note         |For information on how to create and update keys, refer to Security Manual       |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.25.R_SCE_ECC_secp224r1_EncryptedPrivateKeyWrap
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_ECC_secp224r1_EncryptedPrivateKeyWrap ( uint8_t \*\ initial_vector,             |
||br| uint8_t \*\ encrypted_key, sce_key_update_key_t \*\ key_update_key,                        |
||br| sce_ecc_private_wrapped_key_t \*\ wrapped_key )                                            |
+--------------+---------------------------------------------------------------------------------+
| Description  |This API wraps secp224r1 private key within the user routine.                    |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |IN       |initial_vector            |Initialization vector when                  |
|              |         |                          ||br| generating encrypted_key               |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |encrypted_key             |User key encrypted and MAC appended         |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |key_update_key            |Key update keyring                          |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |wrapped_key               |secp224r1 private wrapped key               |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
+--------------+------------------------------------+--------------------------------------------+
| Note         |For information on how to create and update keys, refer to Security Manual       |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.26.R_SCE_ECC_secp256r1_EncryptedPrivateKeyWrap
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_ECC_secp256r1_EncryptedPrivateKeyWrap ( uint8_t \*\ initial_vector,             |
||br| uint8_t \*\ encrypted_key, sce_key_update_key_t \*\ key_update_key,                        |
||br| sce_ecc_private_wrapped_key_t \*\ wrapped_key )                                            |
+--------------+---------------------------------------------------------------------------------+
| Description  |This API wraps secp256r1 private key within the user routine.                    |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |IN       |initial_vector            |Initialization vector when                  |
|              |         |                          ||br| generating encrypted_key               |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |encrypted_key             |User key encrypted and MAC appended         |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |key_update_key            |Key update keyring                          |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |wrapped_key               |secp256r1 private wrapped key               |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processingroutine.          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
+--------------+------------------------------------+--------------------------------------------+
| Note         |For information on how to create and update keys, refer to Security Manual       |
+--------------+---------------------------------------------------------------------------------+

----------------------------------------------------------
2.6.27.R_SCE_ECC_BrainpoolP512r1_EncryptedPrivateKeyWrap
----------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_ECC_BrainpoolP512r1_EncryptedPrivateKeyWrap ( uint8_t \*\ initial_vector,       |
||br| uint8_t \*\ encrypted_key, sce_key_update_key_t \*\ key_update_key,                        |
||br| sce_ecc_private_wrapped_key_t \*\ wrapped_key )                                            |
+--------------+---------------------------------------------------------------------------------+
| Description  |This API wraps BrainpoolP512r1 private key within the user routine.              |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |IN       |initial_vector            |Initialization vector when                  |
|              |         |                          ||br| generating encrypted_key               |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |encrypted_key             |User key encrypted and MAC appended         |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |key_update_key            |Key update keyring                          |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |wrapped_key               |BrainpoolP512r1 private wrapped key         |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
+--------------+------------------------------------+--------------------------------------------+
| Note         |For information on how to create and update keys, refer to Security Manual       |
+--------------+---------------------------------------------------------------------------------+

----------------------------------------------------------
2.6.27.R_SCE_SelfCheck2Private
----------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_SelfCheck2Private (void)                                                        |
+--------------+---------------------------------------------------------------------------------+
| Description  |Self check No2.                                                                  |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |none     |none                      |none                                        |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RETRY            |self-test2 fail                             |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|resource conflict                           |
+--------------+------------------------------------+--------------------------------------------+
| Note         |For information on how to create and update keys, refer to Security Manual       |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.28.R_SCE_AES128ECB_EncryptInit
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES128ECB_EncryptInit ( sce_aes_handle_t \*\ handle,                            |
||br| sce_aes_wrapped_key_t \*\ wrapped_key )                                                    |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_AES128ECB_EncryptInit() function performs preparations for the         |
|              ||br| execution of an AES calculation, and writes the result                      |
|              ||br| to the first argument, handle. The value of handle is used as an argument   |
|              ||br| in the subsequent R_SCE_AES128ECB_EncryptUpdate() function and              |
|              ||br| R_SCE_AES128ECB_EncryptFinal() function.                                    |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES handler (work area)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |wrapped_key               |128-bit AES wrapped key                     |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL     |Input illegal wrapped key.                  |
|              +------------------------------------+--------------------------------------------+
|              |FSP_SUCCESS                         |Normal termination                          |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.29.R_SCE_AES128ECB_EncryptUpdate
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES128ECB_EncryptUpdate ( sce_aes_handle_t \*\ handle,                          |
||br| uint8_t \*\ plain, uint8_t \*\ cipher, uint32_t plain_length )                             |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_AES128ECB_EncryptUpdate function encrypts the second argument, plain,  |
|              ||br| utilizing the key index stored in the handle specified                      |
|              ||br| in the first argument, handle,and writes the ongoing status                 |
|              ||br| to this first argument. In addition, it writes the encryption result        |
|              ||br| to the third argument, cipher. After plaintext input is completed,          |
|              ||br| call R_SCE_AES128ECB_EncryptFinal().                                        |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES handler (work area)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |plain                     |plaintext data area                         |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |cipher                    |ciphertext data area                        |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |plain_length              |plaintext data length                       |
|              |         |                          ||br| (must be a multiple of 16)             |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
+--------------+------------------------------------+--------------------------------------------+
| Note         |Specify areas for plain and cipher that do not overlap.                          |
|              ||br| For plain and cipher, specify RAM addresses that are multiples of 4.        |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.30.R_SCE_AES128ECB_EncryptFinal
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES128ECB_EncryptFinal ( sce_aes_handle_t \*\ handle,                           |
||br| uint8_t \*\ cipher, uint32_t \*\ cipher_length )                                           |
+--------------+---------------------------------------------------------------------------------+
| Description  |Using the handle specified in the first argument, handle,                        |
|              ||br| the R_SCE_AES128ECB_EncryptFinal() function writes the calculation result   |
|              ||br| to the second argument, cipher, and writes the length of the                |
|              ||br| calculation result to the third argument, cipher_length.                    |
|              ||br| The original intent was for a portion of the encryption result              |
|              ||br| that was not a multiple of 16 bytes to be written to the second argument.   |
|              ||br| However, as a result of the restriction that only multiples of 16           |
|              ||br| can be input to the Update function, nothing is ever written to cipher,     |
|              ||br| and 0 is always written to cipher_length. The arguments cipher              |
|              ||br| and cipher_length are provided for compatibility in anticipation of         |
|              ||br| the time when this restriction is lifted.                                   |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES handler (work area)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |cipher                    |ciphertext data area                        |
|              |         |                          ||br| (nothing ever written here)            |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |cipher_length             |ciphertext data length                      |
|              |         |                          ||br| (0 always written here)                |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.31.R_SCE_AES128ECB_DecryptInit
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES128ECB_DecryptInit ( sce_aes_handle_t \*\ handle,                            |
||br| sce_aes_wrapped_key_t \*\ wrapped_key )                                                    |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_AES128ECB_DecryptInit() function performs preparations for the         |
|              ||br| execution of an AES calculation, and writes the result                      |
|              ||br| to the first argument, handle. The value of handle is used as an argument   |
|              ||br| in the subsequent R_SCE_AES128ECB_DecryptUpdate() function and              |
|              ||br| R_SCE_AES128ECB_DecryptFinal() function.                                    |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES handler (work area)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |wrapped_key               |128-bit AES wrapped key                     |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL     |Input illegal wrapped key.                  |
|              +------------------------------------+--------------------------------------------+
|              |FSP_SUCCESS                         |Normal termination                          |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.32.R_SCE_AES128ECB_DecryptUpdate
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES128ECB_DecryptUpdate ( sce_aes_handle_t \*\ handle,                          |
||br| uint8_t \*\ cipher, uint8_t \*\ plain, uint32_t cipher_length )                            |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_AES128ECB_DecryptUpdate function encrypts the second argument, cipher, |
|              ||br| utilizing the key index stored in the handle specified                      |
|              ||br| in the first argument, handle,and writes the ongoing status                 |
|              ||br| to this first argument. In addition, it writes the encryption result        |
|              ||br| to the third argument, plain. After ciphertext input is completed,          |
|              ||br| call R_SCE_AES128ECB_DecryptFinal.                                          |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES handler (work area)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |cipher                    |ciphertext data area                        |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |plain                     |plaintext data area                         |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |cipher_length             |ciphertext data length                      |
|              |         |                          ||br| (must be a multiple of 16)             |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
+--------------+------------------------------------+--------------------------------------------+
| Note         |Specify areas for plain and cipher that do not overlap.                          |
|              ||br| For plain and cipher, specify RAM addresses that are multiples of 4.        |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.33.R_SCE_AES128ECB_DecryptFinal
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES128ECB_DecryptFinal ( sce_aes_handle_t \*\ handle,                           |
||br| uint8_t \*\ plain, uint32_t \*\ plain_length )                                             |
+--------------+---------------------------------------------------------------------------------+
| Description  |Using the handle specified in the first argument, handle,                        |
|              ||br| the R_SCE_AES128ECB_DecryptFinal() function writes the calculation result   |
|              ||br| to the second argument, plain, and writes the length of the                 |
|              ||br| calculation result to the third argument, plain_length.                     |
|              ||br| The original intent was for a portion of the Decryption result              |
|              ||br| that was not a multiple of 16 bytes to be written to the second argument.   |
|              ||br| However, as a result of the restriction that only multiples of 16           |
|              ||br| can be input to the Update function, nothing is ever written to plain,      |
|              ||br| and 0 is always written to plain_length. The arguments plain                |
|              ||br| and plain_length are provided for compatibility in anticipation of          |
|              ||br| the time when this restriction is lifted.                                   |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES handler (work area)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |plain                     |plaintext data area                         |
|              |         |                          ||br| (nothing ever written here)            |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |plain_length              |plaintext data length                       |
|              |         |                          ||br| (0 always written here)                |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.34.R_SCE_AES256ECB_EncryptInit
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES256ECB_EncryptInit ( sce_aes_handle_t \*\ handle,                            |
||br| sce_aes_wrapped_key_t \*\ wrapped_key )                                                    |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_AES256ECB_EncryptInit() function performs preparations for the         |
|              ||br| execution of an AES calculation, and writes the result                      |
|              ||br| to the first argument, handle. The value of handle is used as an argument   |
|              ||br| in the subsequent R_SCE_AES256ECB_EncryptUpdate() function and              |
|              ||br| R_SCE_AES256ECB_EncryptFinal() function.                                    |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES handler (work area)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |wrapped_key               |256-bit AES wrapped key                     |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL     |Input illegal wrapped key.                  |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.35.R_SCE_AES256ECB_EncryptUpdate
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES256ECB_EncryptUpdate ( sce_aes_handle_t \*\ handle,                          |
||br| uint8_t \*\ plain, uint8_t \*\ cipher, uint32_t plain_length )                             |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_AES256ECB_EncryptUpdate function encrypts the second argument, plain,  |
|              ||br| utilizing the key index stored in the handle specified                      |
|              ||br| in the first argument, handle,and writes the ongoing status                 |
|              ||br| to this first argument. In addition, it writes the encryption result        |
|              ||br| to the third argument, cipher. After plaintext input is completed,          |
|              ||br| call R_SCE_AES256ECB_EncryptFinal().                                        |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES handler (work area)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |plain                     |plaintext data area                         |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |cipher                    |ciphertext data area                        |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |plain_length              |plaintext data length                       |
|              |         |                          ||br| (must be a multiple of 16)             |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
+--------------+------------------------------------+--------------------------------------------+
| Note         |Specify areas for plain and cipher that do not overlap.                          |
|              ||br| For plain and cipher, specify RAM addresses that are multiples of 4.        |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.36.R_SCE_AES256ECB_EncryptFinal
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES256ECB_EncryptFinal ( sce_aes_handle_t \*\ handle,                           |
||br| uint8_t \*\ cipher, uint32_t \*\ cipher_length )                                           |
+--------------+---------------------------------------------------------------------------------+
| Description  |Using the handle specified in the first argument, handle,                        |
|              ||br| the R_SCE_AES256ECB_EncryptFinal() function writes the calculation result   |
|              ||br| to the second argument, cipher, and writes the length of the                |
|              ||br| calculation result to the third argument, cipher_length.                    |
|              ||br| The original intent was for a portion of the encryption result              |
|              ||br| that was not a multiple of 16 bytes to be written to the second argument.   |
|              ||br| However, as a result of the restriction that only multiples of 16           |
|              ||br| can be input to the Update function, nothing is ever written to cipher,     |
|              ||br| and 0 is always written to cipher_length. The arguments cipher              |
|              ||br| and cipher_length are provided for compatibility in anticipation of         |
|              ||br| the time when this restriction is lifted.                                   |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES handler (work area)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |cipher                    |ciphertext data area                        |
|              |         |                          ||br| (nothing ever written here)            |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |cipher_length             |ciphertext data length                      |
|              |         |                          ||br| (0 always written here)                |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.37.R_SCE_AES256ECB_DecryptInit
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES256ECB_DecryptInit ( sce_aes_handle_t \*\ handle,                            |
||br| sce_aes_wrapped_key_t \*\ wrapped_key )                                                    |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_AES256ECB_DecryptInit() function performs preparations for the         |
|              ||br| execution of an AES calculation, and writes the result                      |
|              ||br| to the first argument, handle. The value of handle is used as an argument   |
|              ||br| in the subsequent R_SCE_AES256ECB_DecryptUpdate() function and              |
|              ||br| R_SCE_AES256ECB_DecryptFinal() function.                                    |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES handler (work area)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |wrapped_key               |256-bit AES wrapped key                     |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL     |Input illegal wrapped key.                  |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.38.R_SCE_AES256ECB_DecryptUpdate
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES256ECB_DecryptUpdate ( sce_aes_handle_t \*\ handle,                          |
||br| uint8_t \*\ cipher, uint8_t \*\ plain, uint32_t cipher_length )                            |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_AES256ECB_DecryptUpdate function encrypts the second argument, cipher, |
|              ||br| utilizing the key index stored in the handle specified                      |
|              ||br| in the first argument, handle,and writes the ongoing status                 |
|              ||br| to this first argument. In addition, it writes the encryption result        |
|              ||br| to the third argument, plain. After ciphertext input is completed,          |
|              ||br| call R_SCE_AES256ECB_DecryptFinal.                                          |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES handler (work area)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |cipher                    |ciphertext data area                        |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |plain                     |plaintext data area                         |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |cipher_length             |ciphertext data length                      |
|              |         |                          ||br| (must be a multiple of 16)             |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
+--------------+------------------------------------+--------------------------------------------+
| Note         |Specify areas for plain and cipher that do not overlap.                          |
|              ||br| For plain and cipher, specify RAM addresses that are multiples of 4.        |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.39.R_SCE_AES256ECB_DecryptFinal
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES256ECB_DecryptFinal ( sce_aes_handle_t \*\ handle,                           |
||br| uint8_t \*\ plain, uint32_t \*\ plain_length )                                             |
+--------------+---------------------------------------------------------------------------------+
| Description  |Using the handle specified in the first argument, handle,                        |
|              ||br| the R_SCE_AES256ECB_DecryptFinal() function writes the calculation result   |
|              ||br| to the second argument, plain, and writes the length of the                 |
|              ||br| calculation result to the third argument, plain_length.                     |
|              ||br| The original intent was for a portion of the Decryption result              |
|              ||br| that was not a multiple of 16 bytes to be written to the second argument.   |
|              ||br| However, as a result of the restriction that only multiples of 16           |
|              ||br| can be input to the Update function, nothing is ever written to plain,      |
|              ||br| and 0 is always written to plain_length. The arguments plain                |
|              ||br| and plain_length are provided for compatibility in anticipation of          |
|              ||br| the time when this restriction is lifted.                                   |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES handler (work area)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |plain                     |plaintext data area                         |
|              |         |                          ||br| (nothing ever written here)            |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |plain_length              |plaintext data length                       |
|              |         |                          ||br| (0 always written here)                |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+


-------------------------------------------------------
2.6.40.R_SCE_AES128CBC_EncryptInit
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES128CBC_EncryptInit ( sce_aes_handle_t \*\ handle,                            |
||br| sce_aes_wrapped_key_t \*\ wrapped_key, uint8_t \*\ initial_vector )                        |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_AES128CBC_EncryptInit() function performs preparations for the         |
|              ||br| execution of an AES calculation, and writes the result                      |
|              ||br| to the first argument, handle. The value of handle is used as an argument   |
|              ||br| in the subsequent R_SCE_AES128CBC_EncryptUpdate() function and              |
|              ||br| R_SCE_AES128CBC_EncryptFinal() function.                                    |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES handler (work area)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |wrapped_key               |128-bit AES wrapped key                     |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |initial_vector            |initialization vector area (16byte)         |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL     |Input illegal wrapped key.                  |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.41.R_SCE_AES128CBC_EncryptUpdate
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES128CBC_EncryptUpdate ( sce_aes_handle_t \*\ handle,                          |
||br| uint8_t \*\ plain, uint8_t \*\ cipher, uint32_t plain_length )                             |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_AES128CBC_EncryptUpdate function encrypts the second argument, plain,  |
|              ||br| utilizing the key index stored in the handle specified                      |
|              ||br| in the first argument, handle,and writes the ongoing status                 |
|              ||br| to this first argument. In addition, it writes the encryption result        |
|              ||br| to the third argument, cipher. After plaintext input is completed,          |
|              ||br| call R_SCE_AES128CBC_EncryptFinal().                                        |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES handler (work area)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |plain                     |plaintext data area                         |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |cipher                    |ciphertext data area                        |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |plain_length              |plaintext data length                       |
|              |         |                          ||br| (must be a multiple of 16)             |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
+--------------+------------------------------------+--------------------------------------------+
| Note         |Specify areas for plain and cipher that do not overlap.                          |
|              ||br| For plain and cipher, specify RAM addresses that are multiples of 4.        |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.42.R_SCE_AES128CBC_EncryptFinal
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES128CBC_EncryptFinal ( sce_aes_handle_t \*\ handle,                           |
||br| uint8_t \*\ cipher, uint32_t \*\ cipher_length )                                           |
+--------------+---------------------------------------------------------------------------------+
| Description  |Using the handle specified in the first argument, handle,                        |
|              ||br| the R_SCE_AES128CBC_EncryptFinal() function writes the calculation result   |
|              ||br| to the second argument, cipher, and writes the length of the                |
|              ||br| calculation result to the third argument, cipher_length.                    |
|              ||br| The original intent was for a portion of the encryption result              |
|              ||br| that was not a multiple of 16 bytes to be written to the second argument.   |
|              ||br| However, as a result of the restriction that only multiples of 16           |
|              ||br| can be input to the Update function, nothing is ever written to cipher,     |
|              ||br| and 0 is always written to cipher_length. The arguments cipher              |
|              ||br| and cipher_length are provided for compatibility in anticipation of         |
|              ||br| the time when this restriction is lifted.                                   |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES handler (work area)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |cipher                    |ciphertext data area                        |
|              |         |                          ||br| (nothing ever written here)            |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |cipher_length             |ciphertext data length                      |
|              |         |                          ||br| (0 always written here)                |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.43.R_SCE_AES128CBC_DecryptInit
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES128CBC_DecryptInit ( sce_aes_handle_t \*\ handle,                            |
||br| sce_aes_wrapped_key_t \*\ wrapped_key, uint8_t \*\ initial_vector )                        |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_AES128CBC_DecryptInit() function performs preparations for the         |
|              ||br| execution of an AES calculation, and writes the result                      |
|              ||br| to the first argument, handle. The value of handle is used as an argument   |
|              ||br| in the subsequent R_SCE_AES128CBC_DecryptUpdate() function and              |
|              ||br| R_SCE_AES128CBC_DecryptFinal() function.                                    |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES handler (work area)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |wrapped_key               |128-bit AES wrapped key                     |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |initial_vector            |initialization vector area (16byte)         |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL     |Input illegal wrapped key.                  |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.44.R_SCE_AES128CBC_DecryptUpdate
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES128CBC_DecryptUpdate ( sce_aes_handle_t \*\ handle,                          |
||br| uint8_t \*\ cipher, uint8_t \*\ plain, uint32_t cipher_length )                            |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_AES128CBC_DecryptUpdate function encrypts the second argument, cipher, |
|              ||br| utilizing the key index stored in the handle specified                      |
|              ||br| in the first argument, handle,and writes the ongoing status                 |
|              ||br| to this first argument. In addition, it writes the encryption result        |
|              ||br| to the third argument, plain. After ciphertext input is completed,          |
|              ||br| call R_SCE_AES128CBC_DecryptFinal.                                          |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES handler (work area)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |cipher                    |ciphertext data area                        |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |plain                     |plaintext data area                         |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |cipher_length             |ciphertext data length                      |
|              |         |                          ||br| (must be a multiple of 16)             |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
+--------------+------------------------------------+--------------------------------------------+
| Note         |Specify areas for plain and cipher that do not overlap.                          |
|              ||br| For plain and cipher, specify RAM addresses that are multiples of 4.        |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.45.R_SCE_AES128CBC_DecryptFinal
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES128CBC_DecryptFinal ( sce_aes_handle_t \*\ handle,                           |
||br| uint8_t \*\ plain, uint32_t \*\ plain_length )                                             |
+--------------+---------------------------------------------------------------------------------+
| Description  |Using the handle specified in the first argument, handle,                        |
|              ||br| the R_SCE_AES128CBC_DecryptFinal() function writes the calculation result   |
|              ||br| to the second argument, plain, and writes the length of the                 |
|              ||br| calculation result to the third argument, plain_length.                     |
|              ||br| The original intent was for a portion of the Decryption result              |
|              ||br| that was not a multiple of 16 bytes to be written to the second argument.   |
|              ||br| However, as a result of the restriction that only multiples of 16           |
|              ||br| can be input to the Update function, nothing is ever written to plain,      |
|              ||br| and 0 is always written to plain_length. The arguments plain                |
|              ||br| and plain_length are provided for compatibility in anticipation of          |
|              ||br| the time when this restriction is lifted.                                   |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES handler (work area)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |plain                     |plaintext data area                         |
|              |         |                          ||br| (nothing ever written here)            |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |plain_length              |plaintext data length                       |
|              |         |                          ||br| (0 always written here)                |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.46.R_SCE_AES256CBC_EncryptInit
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES256CBC_EncryptInit ( sce_aes_handle_t \*\ handle,                            |
||br| sce_aes_wrapped_key_t \*\ wrapped_key, uint8_t \*\ initial_vector )                        |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_AES256CBC_EncryptInit() function performs preparations for the         |
|              ||br| execution of an AES calculation, and writes the result                      |
|              ||br| to the first argument, handle. The value of handle is used as an argument   |
|              ||br| in the subsequent R_SCE_AES256CBC_EncryptUpdate() function and              |
|              ||br| R_SCE_AES256CBC_EncryptFinal() function.                                    |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES handler (work area)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |wrapped_key               |256-bit AES wrapped key                     |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |initial_vector            |initialization vector area (16byte)         |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL     |Input illegal wrapped key.                  |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.47.R_SCE_AES256CBC_EncryptUpdate
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES256CBC_EncryptUpdate ( sce_aes_handle_t \*\ handle,                          |
||br| uint8_t \*\ plain, uint8_t \*\ cipher, uint32_t plain_length )                             |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_AES256CBC_EncryptUpdate function encrypts the second argument, plain,  |
|              ||br| utilizing the key index stored in the handle specified                      |
|              ||br| in the first argument, handle,and writes the ongoing status                 |
|              ||br| to this first argument. In addition, it writes the encryption result        |
|              ||br| to the third argument, cipher. After plaintext input is completed,          |
|              ||br| call R_SCE_AES256CBC_EncryptFinal().                                        |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES handler (work area)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |plain                     |plaintext data area                         |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |cipher                    |ciphertext data area                        |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |plain_length              |plaintext data length                       |
|              |         |                          ||br| (must be a multiple of 16)             |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
+--------------+------------------------------------+--------------------------------------------+
| Note         |Specify areas for plain and cipher that do not overlap.                          |
|              ||br| For plain and cipher, specify RAM addresses that are multiples of 4.        |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.48.R_SCE_AES256CBC_EncryptFinal
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES256CBC_EncryptFinal ( sce_aes_handle_t \*\ handle,                           |
||br| uint8_t \*\ cipher, uint32_t \*\ cipher_length )                                           |
+--------------+---------------------------------------------------------------------------------+
| Description  |Using the handle specified in the first argument, handle,                        |
|              ||br| the R_SCE_AES256CBC_EncryptFinal() function writes the calculation result   |
|              ||br| to the second argument, cipher, and writes the length of the                |
|              ||br| calculation result to the third argument, cipher_length.                    |
|              ||br| The original intent was for a portion of the encryption result              |
|              ||br| that was not a multiple of 16 bytes to be written to the second argument.   |
|              ||br| However, as a result of the restriction that only multiples of 16           |
|              ||br| can be input to the Update function, nothing is ever written to cipher,     |
|              ||br| and 0 is always written to cipher_length. The arguments cipher              |
|              ||br| and cipher_length are provided for compatibility in anticipation of         |
|              ||br| the time when this restriction is lifted.                                   |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES handler (work area)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |cipher                    |ciphertext data area                        |
|              |         |                          ||br| (nothing ever written here)            |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |cipher_length             |ciphertext data length                      |
|              |         |                          ||br| (0 always written here)                |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.49.R_SCE_AES256CBC_DecryptInit
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES256CBC_DecryptInit ( sce_aes_handle_t \*\ handle,                            |
||br| sce_aes_wrapped_key_t \*\ wrapped_key, uint8_t \*\ initial_vector )                        |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_AES256CBC_DecryptInit() function performs preparations for the         |
|              ||br| execution of an AES calculation, and writes the result                      |
|              ||br| to the first argument, handle. The value of handle is used as an argument   |
|              ||br| in the subsequent R_SCE_AES256CBC_DecryptUpdate() function and              |
|              ||br| R_SCE_AES256CBC_DecryptFinal() function.                                    |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES handler (work area)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |wrapped_key               |256-bit AES wrapped key                     |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |initial_vector            |initialization vector area (16byte)         |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL     |Input illegal wrapped key.                  |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.50.R_SCE_AES256CBC_DecryptUpdate
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES256CBC_DecryptUpdate ( sce_aes_handle_t \*\ handle,                          |
||br| uint8_t \*\ cipher, uint8_t \*\ plain, uint32_t cipher_length )                            |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_AES256CBC_DecryptUpdate function encrypts the second argument, cipher, |
|              ||br| utilizing the key index stored in the handle specified                      |
|              ||br| in the first argument, handle,and writes the ongoing status                 |
|              ||br| to this first argument. In addition, it writes the encryption result        |
|              ||br| to the third argument, plain. After ciphertext input is completed,          |
|              ||br| call R_SCE_AES256CBC_DecryptFinal.                                          |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES handler (work area)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |cipher                    |ciphertext data area                        |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |plain                     |plaintext data area                         |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |cipher_length             |ciphertext data length                      |
|              |         |                          ||br| (must be a multiple of 16)             |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
+--------------+------------------------------------+--------------------------------------------+
| Note         |Specify areas for plain and cipher that do not overlap.                          |
|              ||br| For plain and cipher, specify RAM addresses that are multiples of 4.        |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.51.R_SCE_AES256CBC_DecryptFinal
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES256CBC_DecryptFinal ( sce_aes_handle_t \*\ handle,                           |
||br| uint8_t \*\ plain, uint32_t \*\ plain_length )                                             |
+--------------+---------------------------------------------------------------------------------+
| Description  |Using the handle specified in the first argument, handle,                        |
|              ||br| the R_SCE_AES256CBC_DecryptFinal() function writes the calculation result   |
|              ||br| to the second argument, plain, and writes the length of the                 |
|              ||br| calculation result to the third argument, plain_length.                     |
|              ||br| The original intent was for a portion of the Decryption result              |
|              ||br| that was not a multiple of 16 bytes to be written to the second argument.   |
|              ||br| However, as a result of the restriction that only multiples of 16           |
|              ||br| can be input to the Update function, nothing is ever written to plain,      |
|              ||br| and 0 is always written to plain_length. The arguments plain                |
|              ||br| and plain_length are provided for compatibility in anticipation of          |
|              ||br| the time when this restriction is lifted.                                   |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES handler (work area)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |plain                     |plaintext data area                         |
|              |         |                          ||br| (nothing ever written here)            |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |plain_length              |plaintext data length                       |
|              |         |                          ||br| (0 always written here)                |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.52.R_SCE_AES128CTR_EncryptInit
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES128CTR_EncryptInit ( sce_aes_handle_t \*\ handle,                            |
||br| sce_aes_wrapped_key_t \*\ wrapped_key, uint8_t \*\ initial_vector )                        |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_AES128CTR_EncryptInit() function performs preparations for the         |
|              ||br| execution of an AES calculation, and writes the result                      |
|              ||br| to the first argument, handle. The value of handle is used as an argument   |
|              ||br| in the subsequent R_SCE_AES128CTR_EncryptUpdate() function and              |
|              ||br| R_SCE_AES128CTR_EncryptFinal() function.                                    |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES handler (work area)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |wrapped_key               |128-bit AES wrapped key                     |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |initial_vector            |initialization vector area (16byte)         |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL     |Input illegal wrapped key.                  |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.53.R_SCE_AES128CTR_EncryptUpdate
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES128CTR_EncryptUpdate ( sce_aes_handle_t \*\ handle,                          |
||br| uint8_t \*\ plain, uint8_t \*\ cipher, uint32_t plain_length )                             |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_AES128CTR_EncryptUpdate function encrypts the second argument, plain,  |
|              ||br| utilizing the key index stored in the handle specified                      |
|              ||br| in the first argument, handle,and writes the ongoing status                 |
|              ||br| to this first argument. In addition, it writes the encryption result        |
|              ||br| to the third argument, cipher. After plaintext input is completed,          |
|              ||br| call R_SCE_AES128CTR_EncryptFinal().                                        |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES handler (work area)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |plain                     |plaintext data area                         |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |cipher                    |ciphertext data area                        |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |plain_length              |plaintext data length                       |
|              |         |                          ||br| (must be a multiple of 16)             |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
+--------------+------------------------------------+--------------------------------------------+
| Note         |Specify areas for plain and cipher that do not overlap.                          |
|              ||br| For plain and cipher, specify RAM addresses that are multiples of 4.        |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.54.R_SCE_AES128CTR_EncryptFinal
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES128CTR_EncryptFinal ( sce_aes_handle_t \*\ handle,                           |
||br| uint8_t \*\ cipher, uint32_t \*\ cipher_length )                                           |
+--------------+---------------------------------------------------------------------------------+
| Description  |Using the handle specified in the first argument, handle,                        |
|              ||br| the R_SCE_AES128CTR_EncryptFinal() function writes the calculation result   |
|              ||br| to the second argument, cipher, and writes the length of the                |
|              ||br| calculation result to the third argument, cipher_length.                    |
|              ||br| The original intent was for a portion of the encryption result              |
|              ||br| that was not a multiple of 16 bytes to be written to the second argument.   |
|              ||br| However, as a result of the restriction that only multiples of 16           |
|              ||br| can be input to the Update function, nothing is ever written to cipher,     |
|              ||br| and 0 is always written to cipher_length. The arguments cipher              |
|              ||br| and cipher_length are provided for compatibility in anticipation of         |
|              ||br| the time when this restriction is lifted.                                   |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES handler (work area)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |cipher                    |ciphertext data area                        |
|              |         |                          ||br| (nothing ever written here)            |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |cipher_length             |ciphertext data length                      |
|              |         |                          ||br| (0 always written here)                |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.55.R_SCE_AES128CTR_DecryptInit
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES128CTR_DecryptInit ( sce_aes_handle_t \*\ handle,                            |
||br| sce_aes_wrapped_key_t \*\ wrapped_key, uint8_t \*\ initial_vector )                        |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_AES128CTR_DecryptInit() function performs preparations for the         |
|              ||br| execution of an AES calculation, and writes the result                      |
|              ||br| to the first argument, handle. The value of handle is used as an argument   |
|              ||br| in the subsequent R_SCE_AES128CTR_DecryptUpdate() function and              |
|              ||br| R_SCE_AES128CTR_DecryptFinal() function.                                    |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES handler (work area)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |wrapped_key               |128-bit AES wrapped key                     |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |initial_vector            |initialization vector area (16byte)         |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL     |Input illegal wrapped key.                  |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.56.R_SCE_AES128CTR_DecryptUpdate
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES128CTR_DecryptUpdate ( sce_aes_handle_t \*\ handle,                          |
||br| uint8_t \*\ cipher, uint8_t \*\ plain, uint32_t cipher_length )                            |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_AES128CTR_DecryptUpdate function encrypts the second argument, cipher, |
|              ||br| utilizing the key index stored in the handle specified                      |
|              ||br| in the first argument, handle,and writes the ongoing status                 |
|              ||br| to this first argument. In addition, it writes the encryption result        |
|              ||br| to the third argument, plain. After ciphertext input is completed,          |
|              ||br| call R_SCE_AES128CTR_DecryptFinal.                                          |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES handler (work area)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |cipher                    |ciphertext data area                        |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |plain                     |plaintext data area                         |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |cipher_length             |ciphertext data length                      |
|              |         |                          ||br| (must be a multiple of 16)             |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
+--------------+------------------------------------+--------------------------------------------+
| Note         |Specify areas for plain and cipher that do not overlap.                          |
|              ||br| For plain and cipher, specify RAM addresses that are multiples of 4.        |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.57.R_SCE_AES128CTR_DecryptFinal
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES128CTR_DecryptFinal ( sce_aes_handle_t \*\ handle,                           |
||br| uint8_t \*\ plain, uint32_t \*\ plain_length )                                             |
+--------------+---------------------------------------------------------------------------------+
| Description  |Using the handle specified in the first argument, handle,                        |
|              ||br| the R_SCE_AES128CTR_DecryptFinal() function writes the calculation result   |
|              ||br| to the second argument, plain, and writes the length of the                 |
|              ||br| calculation result to the third argument, plain_length.                     |
|              ||br| The original intent was for a portion of the Decryption result              |
|              ||br| that was not a multiple of 16 bytes to be written to the second argument.   |
|              ||br| However, as a result of the restriction that only multiples of 16           |
|              ||br| can be input to the Update function, nothing is ever written to plain,      |
|              ||br| and 0 is always written to plain_length. The arguments plain                |
|              ||br| and plain_length are provided for compatibility in anticipation of          |
|              ||br| the time when this restriction is lifted.                                   |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES handler (work area)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |plain                     |plaintext data area                         |
|              |         |                          ||br| (nothing ever written here)            |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |plain_length              |plaintext data length                       |
|              |         |                          ||br| (0 always written here)                |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.58.R_SCE_AES256CTR_EncryptInit
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES256CTR_EncryptInit ( sce_aes_handle_t \*\ handle,                            |
||br| sce_aes_wrapped_key_t \*\ wrapped_key, uint8_t \*\ initial_vector )                        |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_AES256CTR_EncryptInit() function performs preparations for the         |
|              ||br| execution of an AES calculation, and writes the result                      |
|              ||br| to the first argument, handle. The value of handle is used as an argument   |
|              ||br| in the subsequent R_SCE_AES256CTR_EncryptUpdate() function and              |
|              ||br| R_SCE_AES256CTR_EncryptFinal() function.                                    |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES handler (work area)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |wrapped_key               |256-bit AES wrapped key                     |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |initial_vector            |initialization vector area (16byte)         |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL     |Input illegal wrapped key.                  |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.59.R_SCE_AES256CTR_EncryptUpdate
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES256CTR_EncryptUpdate ( sce_aes_handle_t \*\ handle,                          |
||br| uint8_t \*\ plain, uint8_t \*\ cipher, uint32_t plain_length )                             |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_AES256CTR_EncryptUpdate function encrypts the second argument, plain,  |
|              ||br| utilizing the key index stored in the handle specified                      |
|              ||br| in the first argument, handle,and writes the ongoing status                 |
|              ||br| to this first argument. In addition, it writes the encryption result        |
|              ||br| to the third argument, cipher. After plaintext input is completed,          |
|              ||br| call R_SCE_AES256CTR_EncryptFinal().                                        |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES handler (work area)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |plain                     |plaintext data area                         |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |cipher                    |ciphertext data area                        |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |plain_length              |plaintext data length                       |
|              |         |                          ||br| (must be a multiple of 16)             |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
+--------------+------------------------------------+--------------------------------------------+
| Note         |Specify areas for plain and cipher that do not overlap.                          |
|              ||br| For plain and cipher, specify RAM addresses that are multiples of 4.        |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.60.R_SCE_AES256CTR_EncryptFinal
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES256CTR_EncryptFinal ( sce_aes_handle_t \*\ handle,                           |
||br| uint8_t \*\ cipher, uint32_t \*\ cipher_length )                                           |
+--------------+---------------------------------------------------------------------------------+
| Description  |Using the handle specified in the first argument, handle,                        |
|              ||br| the R_SCE_AES256CTR_EncryptFinal() function writes the calculation result   |
|              ||br| to the second argument, cipher, and writes the length of the                |
|              ||br| calculation result to the third argument, cipher_length.                    |
|              ||br| The original intent was for a portion of the encryption result              |
|              ||br| that was not a multiple of 16 bytes to be written to the second argument.   |
|              ||br| However, as a result of the restriction that only multiples of 16           |
|              ||br| can be input to the Update function, nothing is ever written to cipher,     |
|              ||br| and 0 is always written to cipher_length. The arguments cipher              |
|              ||br| and cipher_length are provided for compatibility in anticipation of         |
|              ||br| the time when this restriction is lifted.                                   |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES handler (work area)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |cipher                    |ciphertext data area                        |
|              |         |                          ||br| (nothing ever written here)            |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |cipher_length             |ciphertext data length                      |
|              |         |                          ||br| (0 always written here)                |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.61.R_SCE_AES256CTR_DecryptInit
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES256CTR_DecryptInit ( sce_aes_handle_t \*\ handle,                            |
||br| sce_aes_wrapped_key_t \*\ wrapped_key, uint8_t \*\ initial_vector )                        |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_AES256CTR_DecryptInit() function performs preparations for the         |
|              ||br| execution of an AES calculation, and writes the result                      |
|              ||br| to the first argument, handle. The value of handle is used as an argument   |
|              ||br| in the subsequent R_SCE_AES256CTR_DecryptUpdate() function and              |
|              ||br| R_SCE_AES256CTR_DecryptFinal() function.                                    |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES handler (work area)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |wrapped_key               |256-bit AES wrapped key                     |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |initial_vector            |initialization vector area (16byte)         |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL     |Input illegal wrapped key.                  |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.62.R_SCE_AES256CTR_DecryptUpdate
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES256CTR_DecryptUpdate ( sce_aes_handle_t \*\ handle,                          |
||br| uint8_t \*\ cipher, uint8_t \*\ plain, uint32_t cipher_length )                            |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_AES256CTR_DecryptUpdate function encrypts the second argument, cipher, |
|              ||br| utilizing the key index stored in the handle specified                      |
|              ||br| in the first argument, handle,and writes the ongoing status                 |
|              ||br| to this first argument. In addition, it writes the encryption result        |
|              ||br| to the third argument, plain. After ciphertext input is completed,          |
|              ||br| call R_SCE_AES256CTR_DecryptFinal.                                          |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES handler (work area)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |cipher                    |ciphertext data area                        |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |plain                     |plaintext data area                         |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |cipher_length             |ciphertext data length                      |
|              |         |                          ||br| (must be a multiple of 16)             |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
+--------------+------------------------------------+--------------------------------------------+
| Note         |Specify areas for plain and cipher that do not overlap.                          |
|              ||br| For plain and cipher, specify RAM addresses that are multiples of 4.        |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.63.R_SCE_AES256CTR_DecryptFinal
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES256CTR_DecryptFinal ( sce_aes_handle_t \*\ handle,                           |
||br| uint8_t \*\ plain, uint32_t \*\ plain_length )                                             |
+--------------+---------------------------------------------------------------------------------+
| Description  |Using the handle specified in the first argument, handle,                        |
|              ||br| the R_SCE_AES256CTR_DecryptFinal() function writes the calculation result   |
|              ||br| to the second argument, plain, and writes the length of the                 |
|              ||br| calculation result to the third argument, plain_length.                     |
|              ||br| The original intent was for a portion of the Decryption result              |
|              ||br| that was not a multiple of 16 bytes to be written to the second argument.   |
|              ||br| However, as a result of the restriction that only multiples of 16           |
|              ||br| can be input to the Update function, nothing is ever written to plain,      |
|              ||br| and 0 is always written to plain_length. The arguments plain                |
|              ||br| and plain_length are provided for compatibility in anticipation of          |
|              ||br| the time when this restriction is lifted.                                   |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES handler (work area)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |plain                     |plaintext data area                         |
|              |         |                          ||br| (nothing ever written here)            |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |plain_length              |plaintext data length                       |
|              |         |                          ||br| (0 always written here)                |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.64.R_SCE_AES128CMAC_GenerateInit
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES128CMAC_GenerateInit ( sce_cmac_handle_t \*\ handle,                         |
||br| sce_aes_wrapped_key_t \*\ wrapped_key )                                                    |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_AES128CMAC_GenerateInit function performs preparations for the         |
|              ||br| execution of an CMAC calculation, and writes the result                     |
|              ||br| to the first argument, handle. The value of handle is used as an argument   |
|              ||br| in the subsequent R_SCE_AES128CMAC_GenerateUpdate function and              |
|              ||br| R_SCE_AES128CMAC_GenerateFinal function.                                    |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES-CMAC handler (work area)                |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |wrapped_key               |128-bit AES wrapped key                     |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL     |Input illegal wrapped key.                  |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.65.R_SCE_AES128CMAC_GenerateUpdate
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES128CMAC_GenerateUpdate ( sce_cmac_handle_t \*\ handle,                       |
||br| uint8_t \*\ message, uint32_t message_length )                                             |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_AES128CMAC_GenerateUpdate() function performs MAC value generation     |
|              ||br| based on the message specified in the second argument, message,             |
|              ||br| using the value specified for wrapped_key in R_SCE_AES128CMAC_GenerateInit. |
|              ||br| Inside this function, the data that is input by the user is buffered        |
|              ||br| until the input value of message exceeds 16 bytes.                          |
|              ||br| The length of the message data to input is specified in the third argument, |
|              ||br| message_len. For these, input not the total byte count                      |
|              ||br| for message input data, but rather the message data length to input         |
|              ||br| when the user calls this function. If the input value, message,             |
|              ||br| is not a multiple of 16 bytes, it will be padded within the function.       |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES-CMAC handler (work area)                |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |message                   |plaintext data area                         |
|              |         |                          ||br| (message_length byte)                  |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |message_length            |message data length                         |
|              |         |                          ||br| (0 or more bytes)                      |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
+--------------+------------------------------------+--------------------------------------------+
| Note         |For message, specify a RAM address that are multiples of 4.                      |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.66.R_SCE_AES128CMAC_GenerateFinal
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES128CMAC_GenerateFinal ( sce_cmac_handle_t \*\ handle, uint8_t \*\ mac )      |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_AES128CMAC_GenerateFinal() function outputs the MAC value in           |
|              ||br| the MAC data area specified in the second argument, mac, and ends CMAC mode.|
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES handler (work area)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |mac                       |MAC data area (16byte)                      |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_AUTHENTICATION   |Not used.                                   |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.67.R_SCE_AES128CMAC_VerifyInit
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES128CMAC_VerifyInit   ( sce_cmac_handle_t \*\ handle,                         |
||br| sce_aes_wrapped_key_t \*\ wrapped_key )                                                    |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_AES128CMAC_VerifyInit   function performs preparations for the         |
|              ||br| execution of an CMAC calculation, and writes the result                     |
|              ||br| to the first argument, handle. The value of handle is used as an argument   |
|              ||br| in the subsequent R_SCE_AES128CMAC_VerifyUpdate function and                |
|              ||br| R_SCE_AES128CMAC_VerifyFinal function.                                      |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES-CMAC handler (work area)                |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |wrapped_key               |128-bit AES wrapped key                     |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL     |Input illegal wrapped key.                  |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.68.R_SCE_AES128CMAC_VerifyUpdate
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES128CMAC_VerifyUpdate ( sce_cmac_handle_t \*\ handle,                         |
||br| uint8_t \*\ message, uint32_t message_length )                                             |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_AES128CMAC_VerifyUpdate function performs MAC value generation         |
|              ||br| based on the message specified in the second argument, message,             |
|              ||br| using the value specified for wrapped_key in R_SCE_AES128CMAC_VerifyInit.   |
|              ||br| Inside this function, the data that is input by the user is buffered        |
|              ||br| until the input value of message exceeds 16 bytes.                          |
|              ||br| The length of the message data to input is specified in the third argument, |
|              ||br| message_len. For these, input not the total byte count                      |
|              ||br| for message input data, but rather the message data length to input         |
|              ||br| when the user calls this function. If the input value, message,             |
|              ||br| is not a multiple of 16 bytes, it will be padded within the function.       |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES-CMAC handler (work area)                |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |message                   |plaintext data area                         |
|              |         |                          ||br| (message_length byte)                  |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |message_length            |message data length                         |
|              |         |                          ||br| (0 or more bytes)                      |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
+--------------+------------------------------------+--------------------------------------------+
| Note         |For message, specify a RAM address that are multiples of 4.                      |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.69.R_SCE_AES128CMAC_VerifyFinal
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES128CMAC_VerifyFinal ( sce_cmac_handle_t \*\ handle, uint8_t \*\ mac,         |
||br| uint32_t mac_length )                                                                      |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_AES128CMAC_VerifyFinal() function inputs the MAC value in the MAC      |
|              ||br| data area specified in the second argument, mac, and verifies the MAC value.|
|              ||br| If authentication fails, the return value will be TSIP_ERR_AUTHENTICATION.  |
|              ||br| If the MAC value is less than 16 bytes,                                     |
|              ||br| it will be padded with zeros inside the function.                           |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES handler (work area)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |mac                       |MAC data area (mac_length byte)             |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |mac_length                |MAC data length (2 to 16 bytes)             |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_AUTHENTICATION   |Authentication failed                       |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.70.R_SCE_AES256CMAC_GenerateInit
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES256CMAC_GenerateInit ( sce_cmac_handle_t \*\ handle,                         |
||br| sce_aes_wrapped_key_t \*\ wrapped_key )                                                    |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_AES256CMAC_GenerateInit function performs preparations for the         |
|              ||br| execution of an CMAC calculation, and writes the result                     |
|              ||br| to the first argument, handle. The value of handle is used as an argument   |
|              ||br| in the subsequent R_SCE_AES256CMAC_GenerateUpdate function and              |
|              ||br| R_SCE_AES256CMAC_GenerateFinal function.                                    |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES-CMAC handler (work area)                |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |wrapped_key               |256-bit AES wrapped key                     |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL     |Input illegal wrapped key.                  |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.71.R_SCE_AES256CMAC_GenerateUpdate
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES256CMAC_GenerateUpdate ( sce_cmac_handle_t \*\ handle,                       |
||br| uint8_t \*\ message, uint32_t message_length )                                             |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_AES256CMAC_GenerateUpdate() function performs MAC value generation     |
|              ||br| based on the message specified in the second argument, message,             |
|              ||br| using the value specified for wrapped_key in R_SCE_AES256CMAC_GenerateInit. |
|              ||br| Inside this function, the data that is input by the user is buffered        |
|              ||br| until the input value of message exceeds 16 bytes.                          |
|              ||br| The length of the message data to input is specified in the third argument, |
|              ||br| message_len. For these, input not the total byte count                      |
|              ||br| for message input data, but rather the message data length to input         |
|              ||br| when the user calls this function. If the input value, message,             |
|              ||br| is not a multiple of 16 bytes, it will be padded within the function.       |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES-CMAC handler (work area)                |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |message                   |plaintext data area                         |
|              |         |                          ||br| (message_length byte)                  |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |message_length            |message data length                         |
|              |         |                          ||br| (0 or more bytes)                      |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
+--------------+------------------------------------+--------------------------------------------+
| Note         |For message, specify a RAM address that are multiples of 4.                      |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.72.R_SCE_AES256CMAC_GenerateFinal
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES256CMAC_GenerateFinal ( sce_cmac_handle_t \*\ handle, uint8_t \*\ mac )      |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_AES256CMAC_GenerateFinal() function outputs the MAC value in           |
|              ||br| the MAC data area specified in the second argument, mac, and ends CMAC mode.|
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES handler (work area)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |mac                       |MAC data area (16byte)                      |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_AUTHENTICATION   |Not used.                                   |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.73.R_SCE_AES256CMAC_VerifyInit
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES256CMAC_VerifyInit   ( sce_cmac_handle_t \*\ handle,                         |
||br| sce_aes_wrapped_key_t \*\ wrapped_key )                                                    |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_AES256CMAC_VerifyInit   function performs preparations for the         |
|              ||br| execution of an CMAC calculation, and writes the result                     |
|              ||br| to the first argument, handle. The value of handle is used as an argument   |
|              ||br| in the subsequent R_SCE_AES256CMAC_VerifyUpdate function and                |
|              ||br| R_SCE_AES256CMAC_VerifyFinal function.                                      |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES-CMAC handler (work area)                |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |wrapped_key               |256-bit AES wrapped key                     |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL     |Input illegal wrapped key.                  |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.74.R_SCE_AES256CMAC_VerifyUpdate
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES256CMAC_VerifyUpdate ( sce_cmac_handle_t \*\ handle,                         |
||br| uint8_t \*\ message, uint32_t message_length )                                             |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_AES256CMAC_VerifyUpdate function performs MAC value generation         |
|              ||br| based on the message specified in the second argument, message,             |
|              ||br| using the value specified for wrapped_key in R_SCE_AES256CMAC_VerifyInit.   |
|              ||br| Inside this function, the data that is input by the user is buffered        |
|              ||br| until the input value of message exceeds 16 bytes.                          |
|              ||br| The length of the message data to input is specified in the third argument, |
|              ||br| message_len. For these, input not the total byte count                      |
|              ||br| for message input data, but rather the message data length to input         |
|              ||br| when the user calls this function. If the input value, message,             |
|              ||br| is not a multiple of 16 bytes, it will be padded within the function.       |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES-CMAC handler (work area)                |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |message                   |plaintext data area                         |
|              |         |                          ||br| (message_length byte)                  |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |message_length            |message data length                         |
|              |         |                          ||br| (0 or more bytes)                      |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
+--------------+------------------------------------+--------------------------------------------+
| Note         |For message, specify a RAM address that are multiples of 4.                      |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.75.R_SCE_AES256CMAC_VerifyFinal
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_AES256CMAC_VerifyFinal ( sce_cmac_handle_t \*\ handle, uint8_t \*\ mac,         |
||br| uint32_t mac_length )                                                                      |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_AES256CMAC_VerifyFinal() function inputs the MAC value in the MAC      |
|              ||br| data area specified in the second argument, mac, and verifies the MAC value.|
|              ||br| If authentication fails, the return value will be TSIP_ERR_AUTHENTICATION.  |
|              ||br| If the MAC value is less than 16 bytes,                                     |
|              ||br| it will be padded with zeros inside the function.                           |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |AES handler (work area)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |mac                       |MAC data area (mac_length byte)             |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |mac_length                |MAC data length (2 to 16 bytes)             |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_AUTHENTICATION   |Authentication failed                       |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.76.R_SCE_SHA256_Init
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_SHA256_Init ( sce_sha_md5_handle_t \*\ handle)                                  |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_SHA256_Init() function performs preparations for the execution         |
|              ||br| of an SHA-256 hash calculation, and writes the result                       |
|              ||br| to the first argument, handle. The value of handle is used as an argument   |
|              ||br| in the subsequent R_SCE_SHA256_Update() function                            |
|              ||br| and R_SCE_SHA256_Final() function.                                          |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |SHA handler (work area)                     |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.77.R_SCE_SHA256_Update
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_SHA256_Update ( sce_sha_md5_handle_t \*\ handle,                                |
||br| uint8_t \*\ message, uint32_t message_length )                                             |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_SHA256_Update() function calculates a hash value based on              |
|              ||br| the second argument, message, and the third argument, message_length,       |
|              ||br| and writes the ongoing status to the first argument, handle.                |
|              ||br| After message input is completed, call R_SCE_SHA256_Final().                |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |SHA handler (work area)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |message                   |message data area                           |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |message_length            |message data length                         |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.78.R_SCE_SHA256_Final
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_SHA256_Final ( sce_sha_md5_handle_t \*\ handle,                                 |
||br| uint8_t \*\ digest, uint32_t \*\ digest_length )                                           |
+--------------+---------------------------------------------------------------------------------+
| Description  |Using the handle specified in the first argument, handle, the R_SCE_SHA256_Final |
|              ||br| function writes the calculation result to the second argument, digest,      |
|              ||br| and writes the length of the calculation result                             |
|              ||br| to the third argument, digest_length.                                       |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |SHA handler (work area)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |digest                    |hash data area                              |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |digest_length             |hash data length (32bytes)                  |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.79.R_SCE_SHA224_Init
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_SHA224_Init ( sce_sha_md5_handle_t \*\ handle)                                  |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_SHA224_Init() function performs preparations for the execution         |
|              ||br| of an SHA-224 hash calculation, and writes the result                       |
|              ||br| to the first argument, handle. The value of handle is used as an argument   |
|              ||br| in the subsequent R_SCE_SHA224_Update() function                            |
|              ||br| and R_SCE_SHA224_Final() function.                                          |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |SHA handler (work area)                     |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.80.R_SCE_SHA224_Update
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_SHA224_Update ( sce_sha_md5_handle_t \*\ handle,                                |
||br| uint8_t \*\ message, uint32_t message_length )                                             |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_SHA224_Update() function calculates a hash value based on              |
|              ||br| the second argument, message, and the third argument, message_length,       |
|              ||br| and writes the ongoing status to the first argument, handle.                |
|              ||br| After message input is completed, call R_SCE_SHA224_Final().                |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |SHA handler (work area)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |message                   |message data area                           |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |message_length            |message data length                         |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.81.R_SCE_SHA224_Final
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_SHA224_Final ( sce_sha_md5_handle_t \*\ handle,                                 |
||br| uint8_t \*\ digest, uint32_t \*\ digest_length )                                           |
+--------------+---------------------------------------------------------------------------------+
| Description  |Using the handle specified in the first argument, handle, the R_SCE_SHA224_Final |
|              ||br| function writes the calculation result to the second argument, digest,      |
|              ||br| and writes the length of the calculation result                             |
|              ||br| to the third argument, digest_length.                                       |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |INOUT    |handle                    |SHA handler (work area)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |digest                    |hash data area                              |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |digest_length             |hash data length (32bytes)                  |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.82.R_SCE_RSASSA_PKCS1024_SignatureGenerate
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_RSASSA_PKCS1024_SignatureGenerate ( sce_rsa_byte_data_t \*\ message_hash,       |
||br| sce_rsa_byte_data_t \*\ signature, sce_rsa1024_private_wrapped_key_t \*\ wrapped_key,      |
||br| uint8_t hash_type )                                                                        |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_RSASSA_PKCS1024_SignatureGenerate function generates, in accordance    |
|              ||br| with RSASSA-PKCS1-V1_5, a signature from the message text or hash value     |
|              ||br| that is input in the first argument, message_hash, using the                |
|              ||br| private wrapped key input to the third argument, wrapped_key,               |
|              ||br| and writes the signature text to the second argument, signature.            |
|              ||br| When a message is specified in the first argument, message_hash->data_type, |
|              ||br| a hash value is calculated for the message as specified by                  |
|              ||br| the fourth argument, hash_type. When specifying a hash value,               |
|              ||br| a hash value calculated with a hash algorithm as specified by               |
|              ||br| by the fourth argument, hash_type, must be input to message_hash->pdata.    |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |IN       |message_hash              |Message or hash value to                    |
|              |         |                          ||br| which to attach signature              |
|              |         |                          |                                            |
|              |         |                          | - message_hash->pdata : Specifies pointer  |
|              |         |                          |   |br| to array storing the message or     |
|              |         |                          |   |br| hash value                          |
|              |         |                          | - message_hash->data_length : Specifies    |
|              |         |                          |   |br| effective data length of the array  |
|              |         |                          |   |br| (Specify when Message is selected)  |
|              |         |                          | - message_hash->data_type : Selects the    |
|              |         |                          |   |br| data type of message_hash           |
|              |         |                          |   |br| (Message: 0 Hash value: 1)          |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |signature                 |Signature text storage                      |
|              |         |                          ||br| destination information                |
|              |         |                          |                                            |
|              |         |                          | - signature->pdata : Specifies pointer     |
|              |         |                          |   |br| to array storing the signature text |
|              |         |                          | - signature->data_length : data length     |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |wrapped_key               |Inputs the 1024-bit RSA private wrapped key.|
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |hash_type                 |Only HW_SCE_RSA_HASH_SHA256 is supported    |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL     |Invalid wrapped key was input.              |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.83.R_SCE_RSASSA_PKCS1024_SignatureVerify
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_RSASSA_PKCS1024_SignatureVerify ( sce_rsa_byte_data_t \*\ signature,            |
||br| sce_rsa_byte_data_t \*\ message_hash, sce_rsa1024_public_wrapped_key_t \*\ wrapped_key,    |
||br| uint8_t hash_type )                                                                        |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_RSASSA_PKCS1024_SignatureVerify() function verifies, in accordance     |
|              ||br| with RSASSA-PKCS1-V1_5, the signature text input to the                     |
|              ||br| the first argument signature, and the message text or hash value input      |
|              ||br| to the second argument, message_hash, using the public wrapped key input    |
|              ||br| to the third argument, wrapped_key. When a message is specified             |
|              ||br| in the second argument, message_hash->data_type, a hash value is calculated |
|              ||br| using the public wrapped key input to the third argument, wrapped_key,      |
|              ||br| and as specified by the fourth argument, hash_type. When specifying         |
|              ||br| a hash value in the second argument, message_hash->data_type,               |
|              ||br| a hash value calculated with a hash algorithm as specified                  |
|              ||br| by the fourth argument, hash_type, must be input to message_hash->pdata.    |
+--------------+---------+--------------------------+--------------------------------------------+
|  Arguments   |IN       |signature                 |Signature text information to verify        |
|              |         |                          |                                            |
|              |         |                          | - signature->pdata : Specifies pointer     |
|              |         |                          |   |br| to array storing the signature text |
|              |         |                          | - signature->data_length : Specifies       |
|              |         |                          |   |br| effective data length of the array  |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |message_hash              |Message text or hash value to verify        |
|              |         |                          |                                            |
|              |         |                          | - message_hash->pdata : Specifies pointer  |
|              |         |                          |   |br| to array storing the message or     |
|              |         |                          |   |br| hash value                          |
|              |         |                          | - message_hash->data_length : Specifies    |
|              |         |                          |   |br| effective data length of the array  |
|              |         |                          |   |br| (Specify when Message is selected)  |
|              |         |                          | - message_hash->data_type : Selects the    |
|              |         |                          |   |br| data type of message_hash           |
|              |         |                          |   |br| (Message: 0 Hash value: 1)          |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |wrapped_key               |Inputs the 1024-bit RSA private wrapped key.|
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |hash_type                 |Only HW_SCE_RSA_HASH_SHA256 is supported    |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL     |Invalid wrapped key was input.              |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_AUTHENTICATION   |Authentication failed                       |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.84.R_SCE_RSASSA_PKCS2048_SignatureGenerate
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_RSASSA_PKCS2048_SignatureGenerate ( sce_rsa_byte_data_t \*\ message_hash,       |
||br| sce_rsa_byte_data_t \*\ signature, sce_rsa2048_private_wrapped_key_t \*\ wrapped_key,      |
||br| uint8_t hash_type )                                                                        |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_RSASSA_PKCS2048_SignatureGenerate function generates, in accordance    |
|              ||br| with RSASSA-PKCS1-V1_5, a signature from the message text or hash value     |
|              ||br| that is input in the first argument, message_hash, using the                |
|              ||br| private wrapped key input to the third argument, wrapped_key,               |
|              ||br| and writes the signature text to the second argument, signature.            |
|              ||br| When a message is specified in the first argument, message_hash->data_type, |
|              ||br| a hash value is calculated for the message as specified by                  |
|              ||br| the fourth argument, hash_type. When specifying a hash value,               |
|              ||br| a hash value calculated with a hash algorithm as specified by               |
|              ||br| by the fourth argument, hash_type, must be input to message_hash->pdata.    |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |IN       |message_hash              |Message or hash value to                    |
|              |         |                          ||br| which to attach signature              |
|              |         |                          |                                            |
|              |         |                          | - message_hash->pdata : Specifies pointer  |
|              |         |                          |   |br| to array storing the message or     |
|              |         |                          |   |br| hash value                          |
|              |         |                          | - message_hash->data_length : Specifies    |
|              |         |                          |   |br| effective data length of the array  |
|              |         |                          |   |br| (Specify when Message is selected)  |
|              |         |                          | - message_hash->data_type : Selects the    |
|              |         |                          |   |br| data type of message_hash           |
|              |         |                          |   |br| (Message: 0 Hash value: 1)          |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |signature                 |Signature text storage                      |
|              |         |                          ||br| destination information                |
|              |         |                          |                                            |
|              |         |                          | - signature->pdata : Specifies pointer     |
|              |         |                          |   |br| to array storing the signature text |
|              |         |                          | - signature->data_length : data length     |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |wrapped_key               |Inputs the 2048-bit RSA private wrapped key.|
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |hash_type                 |Only HW_SCE_RSA_HASH_SHA256 is supported    |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL     |Invalid wrapped key was input.              |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.85.R_SCE_RSASSA_PKCS2048_SignatureVerify
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_RSASSA_PKCS2048_SignatureVerify ( sce_rsa_byte_data_t \*\ signature,            |
||br| sce_rsa_byte_data_t \*\ message_hash, sce_rsa2048_public_wrapped_key_t \*\ wrapped_key,    |
||br| uint8_t hash_type )                                                                        |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_RSASSA_PKCS2048_SignatureVerify() function verifies, in accordance     |
|              ||br| with RSASSA-PKCS1-V1_5, the signature text input to the                     |
|              ||br| the first argument signature, and the message text or hash value input      |
|              ||br| to the second argument, message_hash, using the public wrapped key input    |
|              ||br| to the third argument, wrapped_key. When a message is specified             |
|              ||br| in the second argument, message_hash->data_type, a hash value is calculated |
|              ||br| using the public wrapped key input to the third argument, wrapped_key,      |
|              ||br| and as specified by the fourth argument, hash_type. When specifying         |
|              ||br| a hash value in the second argument, message_hash->data_type,               |
|              ||br| a hash value calculated with a hash algorithm as specified                  |
|              ||br| by the fourth argument, hash_type, must be input to message_hash->pdata.    |
+--------------+---------+--------------------------+--------------------------------------------+
|  Arguments   |IN       |signature                 |Signature text information to verify        |
|              |         |                          |                                            |
|              |         |                          | - signature->pdata : Specifies pointer     |
|              |         |                          |   |br| to array storing the signature text |
|              |         |                          | - signature->data_length : Specifies       |
|              |         |                          |   |br| effective data length of the array  |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |message_hash              |Message text or hash value to verify        |
|              |         |                          |                                            |
|              |         |                          | - message_hash->pdata : Specifies pointer  |
|              |         |                          |   |br| to array storing the message or     |
|              |         |                          |   |br| hash value                          |
|              |         |                          | - message_hash->data_length : Specifies    |
|              |         |                          |   |br| effective data length of the array  |
|              |         |                          |   |br| (Specify when Message is selected)  |
|              |         |                          | - message_hash->data_type : Selects the    |
|              |         |                          |   |br| data type of message_hash           |
|              |         |                          |   |br| (Message: 0 Hash value: 1)          |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |wrapped_key               |Inputs the 2048-bit RSA private wrapped key.|
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |hash_type                 |Only HW_SCE_RSA_HASH_SHA256 is supported    |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL     |Invalid wrapped key was input.              |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_AUTHENTICATION   |Authentication failed                       |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.86.R_SCE_RSASSA_PKCS4096_SignatureVerify
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_RSASSA_PKCS4096_SignatureVerify ( sce_rsa_byte_data_t \*\ signature,            |
||br| sce_rsa_byte_data_t \*\ message_hash, sce_rsa4096_public_wrapped_key_t \*\ wrapped_key,    |
||br| uint8_t hash_type )                                                                        |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_RSASSA_PKCS4096_SignatureVerify() function verifies, in accordance     |
|              ||br| with RSASSA-PKCS1-V1_5, the signature text input to the                     |
|              ||br| the first argument signature, and the message text or hash value input      |
|              ||br| to the second argument, message_hash, using the public wrapped key input    |
|              ||br| to the third argument, wrapped_key. When a message is specified             |
|              ||br| in the second argument, message_hash->data_type, a hash value is calculated |
|              ||br| using the public wrapped key input to the third argument, wrapped_key,      |
|              ||br| and as specified by the fourth argument, hash_type. When specifying         |
|              ||br| a hash value in the second argument, message_hash->data_type,               |
|              ||br| a hash value calculated with a hash algorithm as specified                  |
|              ||br| by the fourth argument, hash_type, must be input to message_hash->pdata.    |
+--------------+---------+--------------------------+--------------------------------------------+
|  Arguments   |IN       |signature                 |Signature text information to verify        |
|              |         |                          |                                            |
|              |         |                          | - signature->pdata : Specifies pointer     |
|              |         |                          |   |br| to array storing the signature text |
|              |         |                          | - signature->data_length : Specifies       |
|              |         |                          |   |br| effective data length of the array  |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |message_hash              |Message text or hash value to verify        |
|              |         |                          |                                            |
|              |         |                          | - message_hash->pdata : Specifies pointer  |
|              |         |                          |   |br| to array storing the message or     |
|              |         |                          |   |br| hash value                          |
|              |         |                          | - message_hash->data_length : Specifies    |
|              |         |                          |   |br| effective data length of the array  |
|              |         |                          |   |br| (Specify when Message is selected)  |
|              |         |                          | - message_hash->data_type : Selects the    |
|              |         |                          |   |br| data type of message_hash           |
|              |         |                          |   |br| (Message: 0 Hash value: 1)          |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |wrapped_key               |Inputs the 4096-bit RSA private wrapped key.|
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |hash_type                 |Only HW_SCE_RSA_HASH_SHA256 is supported    |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL     |Invalid wrapped key was input.              |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_AUTHENTICATION   |Authentication failed                       |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.87.R_SCE_RSAES_PKCS1024_Encrypt
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_RSAES_PKCS1024_Encrypt ( sce_rsa_byte_data_t \*\ plain,                         |
||br| sce_rsa_byte_data_t \*\ cipher, sce_rsa1024_public_wrapped_key_t \*\ wrapped_key )         |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_RSAES_PKCS1024_Encrypt() function RSA-encrypts the plaintext           |
|              ||br| input to the first argument, plain, according to RSAES-PKCS1-V1_5.          |
|              ||br| It writes the encryption result to the second argument, cipher.             |
+--------------+---------+--------------------------+--------------------------------------------+
|  Arguments   |IN       |plain                     |plaintext                                   |
|              |         |                          |                                            |
|              |         |                          | - plain->pdata : Specifies pointer to      |
|              |         |                          |   |br| array containing plaintext.         |
|              |         |                          | - plain->data_length : Specifies valid data|
|              |         |                          |   |br| length of plaintext array.          |
|              |         |                          |   |br| data size <= public key n size - 11 |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |cipher                    |ciphertext                                  |
|              |         |                          |                                            |
|              |         |                          | - cipher->pdata : Specifies pointer to     |
|              |         |                          |   |br| array containing ciphertext.        |
|              |         |                          | - cipher->data_length : Inputs ciphertext  |
|              |         |                          |   |br| buffer size. Outputs valid data     |
|              |         |                          |   |br| length after encryption             |
|              |         |                          |   |br| (public key n size).                |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |wrapped_key               |Inputs the 1024-bit RSA public wrapped key. |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL     |Invalid wrapped key was input.              |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.88.R_SCE_RSAES_PKCS1024_Decrypt
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_RSAES_PKCS1024_Decrypt ( sce_rsa_byte_data_t \*\ cipher,                        |
||br| sce_rsa_byte_data_t \*\ plain, sce_rsa1024_private_wrapped_key_t \*\ wrapped_key )         |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_RSAES_PKCS1024_Decrypt() function RSA-decrypts the ciphertext          |
|              ||br| input to the first argument, cipher, according to RSAES-PKCS1-V1_5.         |
|              ||br| It writes the encryption result to the second argument, plain.              |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |IN       |cipher                    |ciphertext                                  |
|              |         |                          |                                            |
|              |         |                          | - cipher->pdata : Specifies pointer to     |
|              |         |                          |   |br| array containing ciphertext.        |
|              |         |                          | - cipher->data_length : Inputs ciphertext  |
|              |         |                          |   |br| buffer size. Outputs valid data     |
|              |         |                          |   |br| length after encryption             |
|              |         |                          |   |br| (public key n size).                |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |plain                     |plaintext                                   |
|              |         |                          |                                            |
|              |         |                          | - plain->pdata : Specifies pointer to      |
|              |         |                          |   |br| array containing plaintext.         |
|              |         |                          | - plain->data_length : Inputs plaintext    |
|              |         |                          |   |br| buffer size. The following size     |
|              |         |                          |   |br| is required.                        |
|              |         |                          |   |br| Plaintext buffer size >=            |
|              |         |                          |   |br| publickey n size - 11.              |
|              |         |                          |   |br| Outputs valid data length after     |
|              |         |                          |   |br| decryption (publickey n size).      |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |wrapped_key               |Inputs the 1024-bit RSA private wrapped key.|
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL     |Invalid wrapped key was input.              |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.89.R_SCE_RSAES_PKCS2048_Encrypt
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_RSAES_PKCS2048_Encrypt ( sce_rsa_byte_data_t \*\ plain,                         |
||br| sce_rsa_byte_data_t \*\ cipher, sce_rsa2048_public_wrapped_key_t \*\ wrapped_key )         |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_RSAES_PKCS2048_Encrypt() function RSA-encrypts the plaintext           |
|              ||br| input to the first argument, plain, according to RSAES-PKCS1-V1_5.          |
|              ||br| It writes the encryption result to the second argument, cipher.             |
+--------------+---------+--------------------------+--------------------------------------------+
|  Arguments   |IN       |plain                     |plaintext                                   |
|              |         |                          |                                            |
|              |         |                          | - plain->pdata : Specifies pointer to      |
|              |         |                          |   |br| array containing plaintext.         |
|              |         |                          | - plain->data_length : Specifies valid data|
|              |         |                          |   |br| length of plaintext array.          |
|              |         |                          |   |br| data size <= public key n size - 11 |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |cipher                    |ciphertext                                  |
|              |         |                          |                                            |
|              |         |                          | - cipher->pdata : Specifies pointer to     |
|              |         |                          |   |br| array containing ciphertext.        |
|              |         |                          | - cipher->data_length : Inputs ciphertext  |
|              |         |                          |   |br| buffer size. Outputs valid data     |
|              |         |                          |   |br| length after encryption             |
|              |         |                          |   |br| (public key n size).                |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |wrapped_key               |Inputs the 2048-bit RSA public wrapped key. |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL     |Invalid wrapped key was input.              |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.90.R_SCE_RSAES_PKCS2048_Decrypt
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_RSAES_PKCS2048_Decrypt ( sce_rsa_byte_data_t \*\ cipher,                        |
||br| sce_rsa_byte_data_t \*\ plain, sce_rsa2048_private_wrapped_key_t \*\ wrapped_key )         |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_RSAES_PKCS2048_Decrypt() function RSA-decrypts the ciphertext          |
|              ||br| input to the first argument, cipher, according to RSAES-PKCS1-V1_5.         |
|              ||br| It writes the encryption result to the second argument, plain.              |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |IN       |cipher                    |ciphertext                                  |
|              |         |                          |                                            |
|              |         |                          | - cipher->pdata : Specifies pointer to     |
|              |         |                          |   |br| array containing ciphertext.        |
|              |         |                          | - cipher->data_length : Inputs ciphertext  |
|              |         |                          |   |br| buffer size. Outputs valid data     |
|              |         |                          |   |br| length after encryption             |
|              |         |                          |   |br| (public key n size).                |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |plain                     |plaintext                                   |
|              |         |                          |                                            |
|              |         |                          | - plain->pdata : Specifies pointer to      |
|              |         |                          |   |br| array containing plaintext.         |
|              |         |                          | - plain->data_length : Inputs plaintext    |
|              |         |                          |   |br| buffer size. The following size     |
|              |         |                          |   |br| is required.                        |
|              |         |                          |   |br| Plaintext buffer size >=            |
|              |         |                          |   |br| publickey n size - 11.              |
|              |         |                          |   |br| Outputs valid data length after     |
|              |         |                          |   |br| decryption (publickey n size).      |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |wrapped_key               |Inputs the 2048-bit RSA private wrapped key.|
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL     |Invalid wrapped key was input.              |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.91.R_SCE_RSAES_PKCS4096_Encrypt
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_RSAES_PKCS4096_Encrypt ( sce_rsa_byte_data_t \*\ plain,                         |
||br| sce_rsa_byte_data_t \*\ cipher, sce_rsa4096_public_wrapped_key_t \*\ wrapped_key )         |
+--------------+---------------------------------------------------------------------------------+
| Description  |The R_SCE_RSAES_PKCS4096_Encrypt() function RSA-encrypts the plaintext           |
|              ||br| input to the first argument, plain, according to RSAES-PKCS1-V1_5.          |
|              ||br| It writes the encryption result to the second argument, cipher.             |
+--------------+---------+--------------------------+--------------------------------------------+
|  Arguments   |IN       |plain                     |plaintext                                   |
|              |         |                          |                                            |
|              |         |                          | - plain->pdata : Specifies pointer to      |
|              |         |                          |   |br| array containing plaintext.         |
|              |         |                          | - plain->data_length : Specifies valid data|
|              |         |                          |   |br| length of plaintext array.          |
|              |         |                          |   |br| data size <= public key n size - 11 |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |cipher                    |ciphertext                                  |
|              |         |                          |                                            |
|              |         |                          | - cipher->pdata : Specifies pointer to     |
|              |         |                          |   |br| array containing ciphertext.        |
|              |         |                          | - cipher->data_length : Inputs ciphertext  |
|              |         |                          |   |br| buffer size. Outputs valid data     |
|              |         |                          |   |br| length after encryption             |
|              |         |                          |   |br| (public key n size).                |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |wrapped_key               |Inputs the 4096-bit RSA public wrapped key. |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL     |Invalid wrapped key was input.              |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.92.R_SCE_ECDSA_secp192r1_SignatureGenerate
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_ECDSA_secp192r1_SignatureGenerate ( sce_ecdsa_byte_data_t \*\ message_hash,     |
||br| sce_ecdsa_byte_data_t \*\ signature, sce_ecc_private_wrapped_key_t \*\ wrapped_key )       |
+--------------+---------------------------------------------------------------------------------+
| Description  |When a message is specified in the first argument, message_hash->data_type,      |
|              ||br| a SHA-256 hash of the message text input as the first argument,             |
|              ||br| message_hash->pdata, is calculated, and the signature text is written to    |
|              ||br| the second argument, signature, in accordance with secp192r1 using          |
|              ||br| the private wrapped key input as the third argument, wrapped_key.           |
|              ||br| When a hash value is specified in the first argument,                       |
|              ||br| message_hash->data_type, the signature text for the first 24 bytes          |
|              ||br| of the SHA-256 hash value input to the first argument, message_hash->pdata, |
|              ||br| is written to the second argument, signature, in accordance with secp192r1  |
|              ||br| using the private wrapped key input as the third argument, wrapped_key.     |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |IN       |message_hash              |Message or hash value to                    |
|              |         |                          ||br| which to attach signature              |
|              |         |                          |                                            |
|              |         |                          | - message_hash->pdata : Specifies pointer  |
|              |         |                          |   |br| to array storing the message or     |
|              |         |                          |   |br| hash value                          |
|              |         |                          | - message_hash->data_length : Specifies    |
|              |         |                          |   |br| effective data length of the array  |
|              |         |                          |   |br| (Specify when Message is selected)  |
|              |         |                          | - message_hash->data_type : Selects the    |
|              |         |                          |   |br| data type of message_hash           |
|              |         |                          |   |br| (Message: 0 Hash value: 1)          |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |signature                 |Signature text storage                      |
|              |         |                          ||br| destination information                |
|              |         |                          |                                            |
|              |         |                          | - signature->pdata : Specifies pointer     |
|              |         |                          |   |br| to array storing the signature text |
|              |         |                          |   |br| The signature format is             |
|              |         |                          |   |br| "0 padding (64 bits)                |
|              |         |                          |   |br| || signature r (192bits)            |
|              |         |                          |   |br| || 0 padding (64 bits)              |
|              |         |                          |   |br| || signature s (192 bits)".         |
|              |         |                          | - signature->data_length : data length     |
|              |         |                          |   |br| || (byte units)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |wrapped_key               |Input wrapped key of secp192r1 private key. |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL     |Invalid wrapped key was input.              |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.93.R_SCE_ECDSA_secp224r1_SignatureGenerate
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_ECDSA_secp224r1_SignatureGenerate ( sce_ecdsa_byte_data_t \*\ message_hash,     |
||br| sce_ecdsa_byte_data_t \*\ signature, sce_ecc_private_wrapped_key_t \*\ wrapped_key )       |
+--------------+---------------------------------------------------------------------------------+
| Description  |When a message is specified in the first argument, message_hash->data_type,      |
|              ||br| a SHA-256 hash of the message text input as the first argument,             |
|              ||br| message_hash->pdata, is calculated, and the signature text is written to    |
|              ||br| the second argument, signature, in accordance with secp224r1 using          |
|              ||br| the private wrapped key input as the third argument, wrapped_key.           |
|              ||br| When a hash value is specified in the first argument,                       |
|              ||br| message_hash->data_type, the signature text for the first 28 bytes          |
|              ||br| of the SHA-256 hash value input to the first argument, message_hash->pdata, |
|              ||br| is written to the second argument, signature, in accordance with secp224r1  |
|              ||br| using the private wrapped key input as the third argument, wrapped_key.     |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |IN       |message_hash              |Message or hash value to                    |
|              |         |                          ||br| which to attach signature              |
|              |         |                          |                                            |
|              |         |                          | - message_hash->pdata : Specifies pointer  |
|              |         |                          |   |br| to array storing the message or     |
|              |         |                          |   |br| hash value                          |
|              |         |                          | - message_hash->data_length : Specifies    |
|              |         |                          |   |br| effective data length of the array  |
|              |         |                          |   |br| (Specify when Message is selected)  |
|              |         |                          | - message_hash->data_type : Selects the    |
|              |         |                          |   |br| data type of message_hash           |
|              |         |                          |   |br| (Message: 0 Hash value: 1)          |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |signature                 |Signature text storage                      |
|              |         |                          ||br| destination information                |
|              |         |                          |                                            |
|              |         |                          | - signature->pdata : Specifies pointer     |
|              |         |                          |   |br| to array storing the signature text |
|              |         |                          |   |br| The signature format is             |
|              |         |                          |   |br| "0 padding (32 bits)                |
|              |         |                          |   |br| || signature r (224bits)            |
|              |         |                          |   |br| || 0 padding (32 bits)              |
|              |         |                          |   |br| || signature s (224 bits)".         |
|              |         |                          | - signature->data_length : data length     |
|              |         |                          |   |br| || (byte units)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |wrapped_key               |Input wrapped key of secp224r1 private key. |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL     |Invalid wrapped key was input.              |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.94.R_SCE_ECDSA_secp256r1_SignatureGenerate
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_ECDSA_secp256r1_SignatureGenerate ( sce_ecdsa_byte_data_t \*\ message_hash,     |
||br| sce_ecdsa_byte_data_t \*\ signature, sce_ecc_private_wrapped_key_t \*\ wrapped_key )       |
+--------------+---------------------------------------------------------------------------------+
| Description  |When a message is specified in the first argument, message_hash->data_type,      |
|              ||br| a SHA-256 hash of the message text input as the first argument,             |
|              ||br| message_hash->pdata, is calculated, and the signature text is written to    |
|              ||br| the second argument, signature, in accordance with secp256r1 using          |
|              ||br| the private wrapped key input as the third argument, wrapped_key.           |
|              ||br| When a hash value is specified in the first argument,                       |
|              ||br| message_hash->data_type, the signature text for the first 32 bytes          |
|              ||br| of the SHA-256 hash value input to the first argument, message_hash->pdata, |
|              ||br| is written to the second argument, signature, in accordance with secp256r1  |
|              ||br| using the private wrapped key input as the third argument, wrapped_key.     |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |IN       |message_hash              |Message or hash value to                    |
|              |         |                          ||br| which to attach signature              |
|              |         |                          |                                            |
|              |         |                          | - message_hash->pdata : Specifies pointer  |
|              |         |                          |   |br| to array storing the message or     |
|              |         |                          |   |br| hash value                          |
|              |         |                          | - message_hash->data_length : Specifies    |
|              |         |                          |   |br| effective data length of the array  |
|              |         |                          |   |br| (Specify when Message is selected)  |
|              |         |                          | - message_hash->data_type : Selects the    |
|              |         |                          |   |br| data type of message_hash           |
|              |         |                          |   |br| (Message: 0 Hash value: 1)          |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |signature                 |Signature text storage                      |
|              |         |                          ||br| destination information                |
|              |         |                          |                                            |
|              |         |                          | - signature->pdata : Specifies pointer     |
|              |         |                          |   |br| to array storing the signature text |
|              |         |                          |   |br| The signature format is             |
|              |         |                          |   |br| "signature r (256bits)              |
|              |         |                          |   |br| || signature s (256 bits)".         |
|              |         |                          | - signature->data_length : data length     |
|              |         |                          |   |br| || (byte units)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |wrapped_key               |Input wrapped key of secp256r1 private key. |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL     |Invalid wrapped key was input.              |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.95.R_SCE_ECDSA_BrainpoolP512r1_SignatureGenerate
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_ECDSA_BrainpoolP512r1_SignatureGenerate( sce_ecdsa_byte_data_t \*\ message_hash,|
||br| sce_ecdsa_byte_data_t \*\ signature, sce_ecc_private_wrapped_key_t \*\ wrapped_key )       |
+--------------+---------------------------------------------------------------------------------+
| Description  |When a hash value is specified in the first argument,                            |
|              ||br| message_hash->data_type, the signature text for the first 64 bytes          |
|              ||br| of the SHA-512 hash value input to the first argument, message_hash->pdata, |
|              ||br| is written to the second argument, in accordance with BrainpoolP512r1       |
|              ||br| using the private wrapped key input as the third argument, wrapped_key.     |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |IN       |message_hash              |Message or hash value to                    |
|              |         |                          ||br| which to attach signature              |
|              |         |                          |                                            |
|              |         |                          | - message_hash->pdata : Specifies pointer  |
|              |         |                          |   |br| to array storing the message or     |
|              |         |                          |   |br| hash value                          |
|              |         |                          | - message_hash->data_length : Specifies    |
|              |         |                          |   |br| effective data length of the array  |
|              |         |                          |   |br| (Specify when Message is selected)  |
|              |         |                          | - message_hash->data_type : Selects the    |
|              |         |                          |   |br| data type of message_hash           |
|              |         |                          |   |br| (only Hash value(1) is support)     |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |signature                 |Signature text storage                      |
|              |         |                          ||br| destination information                |
|              |         |                          |                                            |
|              |         |                          | - signature->pdata : Specifies pointer     |
|              |         |                          |   |br| to array storing the signature text |
|              |         |                          |   |br| The signature format is             |
|              |         |                          |   |br| "signature r (512bits)              |
|              |         |                          |   |br| || signature s (512 bits)".         |
|              |         |                          | - signature->data_length : data length     |
|              |         |                          |   |br| || (byte units)                     |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |wrapped_key               |wrapped key of BrainpoolP512r1 private key. |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL     |Invalid wrapped key was input.              |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.96.R_SCE_ECDSA_secp192r1_SignatureVerify
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_ECDSA_secp192r1_SignatureVerify ( sce_ecdsa_byte_data_t \*\ signature,          |
||br| sce_ecdsa_byte_data_t \*\ message_hash, sce_ecc_public_wrapped_key_t \*\ wrapped_key )     |
+--------------+---------------------------------------------------------------------------------+
| Description  |When a message is specified in the second argument, message_hash->data_type,     |
|              ||br| a SHA-256 hash of the message text input as the second argument,            |
|              ||br| message_hash->pdata, is calculated, and the signature text input to the     |
|              ||br| first argument, signature, is validated in accordance with secp192r1 using  |
|              ||br| the public wrapped key input as the third argument, wrapped_key.            |
|              ||br| When a hash value is specified in the second argument,                      |
|              ||br| message_hash->data_type, the signature text for the first 24 bytes          |
|              ||br| of the SHA-256 hash value input to the second argument, message_hash->pdata,|
|              ||br| is written to the first argument, signature,                                |
|              ||br| is validated in accordance with secp192r1                                   |
|              ||br| using the public wrapped key input as the third argument, wrapped_key.      |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |IN       |signature                 |Signature text information to be verified   |
|              |         |                          |                                            |
|              |         |                          | - signature->pdata : Specifies pointer     |
|              |         |                          |   |br| to array storing the signature text |
|              |         |                          |   |br| The signature format is             |
|              |         |                          |   |br| "0 padding (64 bits)                |
|              |         |                          |   |br| || signature r (192bits)            |
|              |         |                          |   |br| || 0 padding (64 bits)              |
|              |         |                          |   |br| || signature s (192 bits)".         |
|              |         |                          | - signature->data_length : data length     |
|              |         |                          |   |br| || (byte units) (nonuse)            |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |message_hash              |Message or hash value to                    |
|              |         |                          ||br| which to attach signature              |
|              |         |                          |                                            |
|              |         |                          | - message_hash->pdata : Specifies pointer  |
|              |         |                          |   |br| to array storing the message or     |
|              |         |                          |   |br| hash value                          |
|              |         |                          | - message_hash->data_length : Specifies    |
|              |         |                          |   |br| effective data length of the array  |
|              |         |                          |   |br| (Specify when Message is selected)  |
|              |         |                          | - message_hash->data_type : Selects the    |
|              |         |                          |   |br| data type of message_hash           |
|              |         |                          |   |br| (Message: 0 Hash value: 1)          |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |wrapped_key               |Input wrapped key of secp192r1 private key. |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL     |Invalid wrapped key was input.              |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
|              |                                    ||br| or signature verification failed.      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.97.R_SCE_ECDSA_secp224r1_SignatureVerify
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_ECDSA_secp224r1_SignatureVerify ( sce_ecdsa_byte_data_t \*\ signature,          |
||br| sce_ecdsa_byte_data_t \*\ message_hash, sce_ecc_public_wrapped_key_t \*\ wrapped_key )     |
+--------------+---------------------------------------------------------------------------------+
| Description  |When a message is specified in the second argument, message_hash->data_type,     |
|              ||br| a SHA-224 hash of the message text input as the second argument,            |
|              ||br| message_hash->pdata, is calculated, and the signature text input to the     |
|              ||br| first argument, signature, is validated in accordance with secp224r1 using  |
|              ||br| the public wrapped key input as the third argument, wrapped_key.            |
|              ||br| When a hash value is specified in the second argument,                      |
|              ||br| message_hash->data_type, the signature text for the first 28 bytes          |
|              ||br| of the SHA-224 hash value input to the second argument, message_hash->pdata,|
|              ||br| is written to the first argument, signature,                                |
|              ||br| is validated in accordance with secp224r1                                   |
|              ||br| using the public wrapped key input as the third argument, wrapped_key.      |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |IN       |signature                 |Signature text information to be verified   |
|              |         |                          |                                            |
|              |         |                          | - signature->pdata : Specifies pointer     |
|              |         |                          |   |br| to array storing the signature text |
|              |         |                          |   |br| The signature format is             |
|              |         |                          |   |br| "0 padding (32 bits)                |
|              |         |                          |   |br| || signature r (224bits)            |
|              |         |                          |   |br| || 0 padding (32 bits)              |
|              |         |                          |   |br| || signature s (224 bits)".         |
|              |         |                          | - signature->data_length : data length     |
|              |         |                          |   |br| || (byte units) (nonuse)            |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |message_hash              |Message or hash value to                    |
|              |         |                          ||br| which to attach signature              |
|              |         |                          |                                            |
|              |         |                          | - message_hash->pdata : Specifies pointer  |
|              |         |                          |   |br| to array storing the message or     |
|              |         |                          |   |br| hash value                          |
|              |         |                          | - message_hash->data_length : Specifies    |
|              |         |                          |   |br| effective data length of the array  |
|              |         |                          |   |br| (Specify when Message is selected)  |
|              |         |                          | - message_hash->data_type : Selects the    |
|              |         |                          |   |br| data type of message_hash           |
|              |         |                          |   |br| (Message: 0 Hash value: 1)          |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |wrapped_key               |Input wrapped key of secp224r1 private key. |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL     |Invalid wrapped key was input.              |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
|              |                                    ||br| or signature verification failed.      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.98.R_SCE_ECDSA_secp256r1_SignatureVerify
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_ECDSA_secp256r1_SignatureVerify ( sce_ecdsa_byte_data_t \*\ signature,          |
||br| sce_ecdsa_byte_data_t \*\ message_hash, sce_ecc_public_wrapped_key_t \*\ wrapped_key )     |
+--------------+---------------------------------------------------------------------------------+
| Description  |When a message is specified in the second argument, message_hash->data_type,     |
|              ||br| a SHA-256 hash of the message text input as the second argument,            |
|              ||br| message_hash->pdata, is calculated, and the signature text input to the     |
|              ||br| first argument, signature, is validated in accordance with secp256r1 using  |
|              ||br| the public wrapped key input as the third argument, wrapped_key.            |
|              ||br| When a hash value is specified in the second argument,                      |
|              ||br| message_hash->data_type, the signature text for the first 32 bytes          |
|              ||br| of the SHA-256 hash value input to the second argument, message_hash->pdata,|
|              ||br| is written to the first argument, signature,                                |
|              ||br| is validated in accordance with secp256r1                                   |
|              ||br| using the public wrapped key input as the third argument, wrapped_key.      |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |IN       |signature                 |Signature text information to be verified   |
|              |         |                          |                                            |
|              |         |                          | - signature->pdata : Specifies pointer     |
|              |         |                          |   |br| to array storing the signature text |
|              |         |                          |   |br| The signature format is             |
|              |         |                          |   |br| "signature r (256bits)              |
|              |         |                          |   |br| || signature s (256 bits)".         |
|              |         |                          | - signature->data_length : data length     |
|              |         |                          |   |br| || (byte units) (nonuse)            |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |message_hash              |Message or hash value to                    |
|              |         |                          ||br| which to attach signature              |
|              |         |                          |                                            |
|              |         |                          | - message_hash->pdata : Specifies pointer  |
|              |         |                          |   |br| to array storing the message or     |
|              |         |                          |   |br| hash value                          |
|              |         |                          | - message_hash->data_length : Specifies    |
|              |         |                          |   |br| effective data length of the array  |
|              |         |                          |   |br| (Specify when Message is selected)  |
|              |         |                          | - message_hash->data_type : Selects the    |
|              |         |                          |   |br| data type of message_hash           |
|              |         |                          |   |br| (Message: 0 Hash value: 1)          |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |wrapped_key               |Input wrapped key of secp256r1 private key. |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL     |Invalid wrapped key was input.              |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
|              |                                    ||br| or signature verification failed.      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+

-------------------------------------------------------
2.6.99.R_SCE_ECDSA_BrainpoolP512r1_SignatureVerify
-------------------------------------------------------

+------------------------------------------------------------------------------------------------+
|fsp_err_t R_SCE_ECDSA_BrainpoolP512r1_SignatureVerify ( sce_ecdsa_byte_data_t \*\ signature,    |
||br| sce_ecdsa_byte_data_t \*\ message_hash, sce_ecc_public_wrapped_key_t \*\ wrapped_key )     |
+--------------+---------------------------------------------------------------------------------+
| Description  |When a hash value is specified in the second argument,                           |
|              ||br| message_hash->data_type, the signature text for the first 64 bytes          |
|              ||br| of the SHA-512 hash value input to the second argument, message_hash->pdata,|
|              ||br| is written to the first argument, signature,                                |
|              ||br| is validated in accordance with BrainpoolP512r1                             |
|              ||br| using the public wrapped key input as the third argument, wrapped_key.      |
+--------------+---------+--------------------------+--------------------------------------------+
| Arguments    |IN       |signature                 |Signature text information to be verified   |
|              |         |                          |                                            |
|              |         |                          | - signature->pdata : Specifies pointer     |
|              |         |                          |   |br| to array storing the signature text |
|              |         |                          |   |br| The signature format is             |
|              |         |                          |   |br| "signature r (512bits)              |
|              |         |                          |   |br| || signature s (512 bits)".         |
|              |         |                          | - signature->data_length : data length     |
|              |         |                          |   |br| || (byte units) (nonuse)            |
|              +---------+--------------------------+--------------------------------------------+
|              |INOUT    |message_hash              |Message or hash value to                    |
|              |         |                          ||br| which to attach signature              |
|              |         |                          |                                            |
|              |         |                          | - message_hash->pdata : Specifies pointer  |
|              |         |                          |   |br| to array storing the message or     |
|              |         |                          |   |br| hash value                          |
|              |         |                          | - message_hash->data_length : Specifies    |
|              |         |                          |   |br| effective data length of the array  |
|              |         |                          |   |br| (Specify when Message is selected)  |
|              |         |                          | - message_hash->data_type : Selects the    |
|              |         |                          |   |br| data type of message_hash           |
|              |         |                          |   |br| (only Hash value(1) is support)     |
|              +---------+--------------------------+--------------------------------------------+
|              |IN       |wrapped_key               |wrapped key of BrainpoolP512r1 private key. |
+--------------+---------+--------------------------+--------------------------------------------+
| Return value |FSP_SUCCESS                         |Normal termination                          |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_RESOURCE_CONFLICT|A resource conflict occurred because a      |
|              |                                    ||br| hardware resource needed by the        |
|              |                                    ||br| processing routine was in use          |
|              |                                    ||br| by another processing routine.         |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_KEY_SET_FAIL     |Invalid wrapped key was input.              |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_FAIL             |An internal error occurred.                 |
|              |                                    ||br| or signature verification failed.      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PARAMETER        |Input data is illegal.                      |
|              +------------------------------------+--------------------------------------------+
|              |FSP_ERR_CRYPTO_SCE_PROHIBIT_FUNCTION|An invalid function was called.             |
+--------------+------------------------------------+--------------------------------------------+
| Note         |none                                                                             |
+--------------+---------------------------------------------------------------------------------+



.. |br| raw:: html
      
    <br>