/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2024, Renesas Electronics Corporation
 */

#ifndef BSP_API_H
#define BSP_API_H

/***********************************************************************************************************************
 * Includes
 **********************************************************************************************************************/
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>

/***********************************************************************************************************************
 * Macro definitions
 **********************************************************************************************************************/
/** Determine if a C++ compiler is being used.
 * If so, ensure that standard C is used to process the API information.  */
/** FSP Header and Footer definitions */
#define FSP_HEADER
#define FSP_FOOTER

#define __STATIC_FORCEINLINE         __attribute__((always_inline)) static inline
#define __STDC_WANT_LIB_EXT1__       (0)
#define __ARM_BIG_ENDIAN             (0)

/**
  \brief   Reverse byte order (32 bit)
  \details Reverses the byte order in unsigned integer value. For example, 0x12345678 becomes 0x78563412.
  \param [in]    value  Value to reverse
  \return               Reversed value
 */
#define __REV(value)   __builtin_bswap32(value)

/** Specify what to do if FSP_ASSERT fails
 * - 0 = Return FSP_ERR_ASSERTION.
 * - 1 = Call fsp_error_log, then return FSP_ERR_ASSERTION.  Note that fsp_error_log is a weak function and should be
 *       overridden in user code based on the prototype.
 * - 2 = Use standard assert library to halt execution.
 */
#ifndef BSP_CFG_ASSERT
    #define BSP_CFG_ASSERT              (0)
#endif

/** Specify what to do when error codes are returned from FSP functions
 * - 0 = Return error code.
 * - 1 = Call fsp_error_log, then return error code.  Note that fsp_error_log is a weak function and should be
 *       overridden in user code based on the prototype.
 */
#ifndef BSP_CFG_ERROR_LOG
    #define BSP_CFG_ERROR_LOG           (0)
#endif

/** This function is called before returning an error code. To stop on a runtime error, define fsp_error_log in
 * user code and do required debugging (breakpoints, stack dump, etc) in this function.*/
#if (1 == BSP_CFG_ERROR_LOG)
    #ifndef FSP_ERROR_LOG
        #define FSP_ERROR_LOG(err) \
        fsp_error_log((err), __FILE__, __LINE__);
    #endif
#else
    #define FSP_ERROR_LOG(err)
#endif

/** Default assertion calls ::FSP_ERROR_RETURN if condition "a" is false. Used to identify incorrect use of API's in FSP
 * functions. */
#if (3 == BSP_CFG_ASSERT)
    #define FSP_ASSERT(a)
#elif (2 == BSP_CFG_ASSERT)
    #define FSP_ASSERT(a)    {assert(a);}
#else
    #define FSP_ASSERT(a)    FSP_ERROR_RETURN((a), FSP_ERR_ASSERTION)
#endif                       // ifndef FSP_ASSERT

/** All FSP error codes are returned using this macro. Calls ::FSP_ERROR_LOG function if condition "a" is false. Used
 * to identify runtime errors in FSP functions. */
#define FSP_ERROR_RETURN(a, err)                        \
    {                                                   \
        if ((a))                                        \
        {                                               \
            (void) 0;                  /* Do nothing */ \
        }                                               \
        else                                            \
        {                                               \
            FSP_ERROR_LOG(err);                         \
            return err;                                 \
        }                                               \
    }

/* Return error codes fsp */
typedef enum e_fsp_err
{
    FSP_SUCCESS = 0,

    FSP_ERR_ASSERTION             = 1,                      ///< A critical assertion has failed
    FSP_ERR_INVALID_POINTER       = 2,                      ///< Pointer points to invalid memory location
    FSP_ERR_INVALID_ARGUMENT      = 3,                      ///< Invalid input parameter
    FSP_ERR_INVALID_CHANNEL       = 4,                      ///< Selected channel does not exist
    FSP_ERR_INVALID_MODE          = 5,                      ///< Unsupported or incorrect mode
    FSP_ERR_UNSUPPORTED           = 6,                      ///< Selected mode not supported by this API
    FSP_ERR_NOT_OPEN              = 7,                      ///< Requested channel is not configured or API not open
    FSP_ERR_IN_USE                = 8,                      ///< Channel/peripheral is running/busy
    FSP_ERR_OUT_OF_MEMORY         = 9,                      ///< Allocate more memory in the driver's cfg.h
    FSP_ERR_HW_LOCKED             = 10,                     ///< Hardware is locked
    FSP_ERR_IRQ_BSP_DISABLED      = 11,                     ///< IRQ not enabled in BSP
    FSP_ERR_OVERFLOW              = 12,                     ///< Hardware overflow
    FSP_ERR_UNDERFLOW             = 13,                     ///< Hardware underflow
    FSP_ERR_ALREADY_OPEN          = 14,                     ///< Requested channel is already open in a different configuration
    FSP_ERR_APPROXIMATION         = 15,                     ///< Could not set value to exact result
    FSP_ERR_CLAMPED               = 16,                     ///< Value had to be limited for some reason
    FSP_ERR_INVALID_RATE          = 17,                     ///< Selected rate could not be met
    FSP_ERR_ABORTED               = 18,                     ///< An operation was aborted
    FSP_ERR_NOT_ENABLED           = 19,                     ///< Requested operation is not enabled
    FSP_ERR_TIMEOUT               = 20,                     ///< Timeout error
    FSP_ERR_INVALID_BLOCKS        = 21,                     ///< Invalid number of blocks supplied
    FSP_ERR_INVALID_ADDRESS       = 22,                     ///< Invalid address supplied
    FSP_ERR_INVALID_SIZE          = 23,                     ///< Invalid size/length supplied for operation
    FSP_ERR_WRITE_FAILED          = 24,                     ///< Write operation failed
    FSP_ERR_ERASE_FAILED          = 25,                     ///< Erase operation failed
    FSP_ERR_INVALID_CALL          = 26,                     ///< Invalid function call is made
    FSP_ERR_INVALID_HW_CONDITION  = 27,                     ///< Detected hardware is in invalid condition
    FSP_ERR_INVALID_FACTORY_FLASH = 28,                     ///< Factory flash is not available on this MCU
    FSP_ERR_INVALID_STATE         = 30,                     ///< API or command not valid in the current state
    FSP_ERR_NOT_ERASED            = 31,                     ///< Erase verification failed
    FSP_ERR_SECTOR_RELEASE_FAILED = 32,                     ///< Sector release failed
    FSP_ERR_NOT_INITIALIZED       = 33,                     ///< Required initialization not complete
    FSP_ERR_NOT_FOUND             = 34,                     ///< The requested item could not be found
    FSP_ERR_NO_CALLBACK_MEMORY    = 35,                     ///< Non-secure callback memory not provided for non-secure callback
    FSP_ERR_BUFFER_EMPTY          = 36,                     ///< No data available in buffer
} fsp_err_t;

/***********************************************************************************************************************
 * Typedef definitions
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Exported global variables
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Exported global functions (to be accessed by other files)
 **********************************************************************************************************************/

extern void fsp_error_log (fsp_err_t err, const char * file, int32_t line);

#endif                                 /* BSP_API_H */
