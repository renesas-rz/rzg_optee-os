// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2024, Renesas Electronics Corporation
 */

/***********************************************************************************************************************
 * Includes
 **********************************************************************************************************************/
#include "bsp_api.h"

/***********************************************************************************************************************
 * Macro definitions
 **********************************************************************************************************************/
#if defined(__GNUC__)
  #define WEAK_ERROR_ATTRIBUTE    __attribute__((weak, alias("fsp_error_log_internal")))
#endif

/***********************************************************************************************************************
 * Typedef definitions
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Private function prototypes
 **********************************************************************************************************************/
#if ((1 == BSP_CFG_ERROR_LOG) || (1 == BSP_CFG_ASSERT))

/** Prototype of function called before errors are returned in FSP code if BSP_CFG_ERROR_LOG is set to 1.  This
 * prototype sets the weak association of this function to an internal example implementation. */
void fsp_error_log(fsp_err_t err, const char * file, int32_t line) WEAK_ERROR_ATTRIBUTE;

void fsp_error_log_internal(fsp_err_t err, const char * file, int32_t line); /// Default error logger function

#endif

/***********************************************************************************************************************
 * Private global variables
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Global variables
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Functions
 **********************************************************************************************************************/

/*******************************************************************************************************************//**
 * Default error logger function, used only if fsp_error_log is not defined in the user application.
 *
 * @param[in]  err     The error code encountered.
 * @param[in]  file    The file name in which the error code was encountered.
 * @param[in]  line    The line number at which the error code was encountered.
 **********************************************************************************************************************/
void fsp_error_log_internal (fsp_err_t err, const char * file, int32_t line)
{
    /** Do nothing. Do not generate any 'unused' warnings. */
    (void)err;
    (void)file;
    (void)line;
}
