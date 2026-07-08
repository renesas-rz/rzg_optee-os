// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2023-2025, Renesas Electronics Corporation
 */

#include <assert.h>
#include <initcall.h>
#include <trace.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <otp_drv.h>
#include <otp_regs.h>
#include <platform_config.h>

#define OTP_MAP_MIN (OTPM_BASE)
#define OTP_MAP_MAX ((OTPM_BASE + OTPM_WORDS) - 1)

static vaddr_t otp_base;

static inline void otp_io_write(uint32_t reg, uint32_t data)
{
	io_write32(otp_base + reg, data);
}

static inline uint32_t otp_io_read(uint32_t reg)
{
	return io_read32(otp_base + reg);
}

static inline uint32_t otp_io_getbits(uint32_t reg, uint32_t mask)
{
	return otp_io_read(reg) & mask;
}

static void otp_dummy_read(void)
{
#ifdef OTPM_DUMMY
	otp_io_write(OTP_OTPADRRD, OTPM_DUMMY);
	(void)otp_io_read(OTP_OTPDATARD);
#endif
}

static bool otp_open(void)
{
	bool ready = false;
	bool ret = false;

	if (0U != otp_io_getbits(OTP_OTPPWR, OTPPWR_PWR))
		return false;

	if (0U != otp_io_getbits(OTP_OTPSTR, OTPSTR_CMD_RDY))
		return false;

	if (0U == otp_io_getbits(OTP_OTPFLAG, OTPFLAG_FLAG))
		return false;

	if (0U != otp_io_getbits(OTP_OTPFLAG, OTPFLAG_RREND))
		/* RDY bit should be clear */
		ready = true;
	else if (0U != otp_io_getbits(OTP_OTPSTR, OTPSTR_CMD_RDY))
		/* Not powered off so RDY bit should be set */
		ready = true;
	else
		ready = false;

	if (true == ready) {
		/* Enable power and switch to APB interface */
		otp_io_write(OTP_OTPPWR, OTPPWR_PWR | OTPPWR_ACCL);
		ret = true;
	}

	return ret;
}

static void otp_close(void)
{
	while (1 != otp_io_getbits(OTP_OTPSTR, OTPSTR_CMD_RDY))
		; /* Polling */

	/* Dummy read */
	otp_dummy_read();

	/* Switch off OTP PWR and ACCL bits */
	otp_io_write(OTP_OTPPWR, 0U);

	/* Wait for ready bit to clear */
	while (0U != otp_io_getbits(OTP_OTPSTR, OTPSTR_CMD_RDY))
		isb(); /* Not sure if this is necessary */
}

bool r_otp_read(uint32_t addr, uint32_t *p_value, uint32_t count)
{
	bool ret = false;

	if (otp_open()) {
		if ((addr >= OTP_MAP_MIN) && (addr <= OTP_MAP_MAX) &&
		    ((addr + count - 1U) <= OTP_MAP_MAX)) {
			/* Wait for OTP access enable */
			while (1U != otp_io_getbits(OTP_OTPSTR, OTPSTR_CMD_RDY))
				isb(); /* Not sure if this is necessary */

			otp_io_write(OTP_OTPADRRD, addr);

			while (count > 0U) {
				*p_value = otp_io_read(OTP_OTPDATARD);
				if (0U !=
				    otp_io_getbits(OTP_OTPSTR, OTPSTR_ERR_RP))
					/* Error - reading protected area */
					break;
				/* The address in OTP_OTPDATARD auto increments */
				p_value++;
				count -= 1U;
			}

			if (count == 0U)
				ret = true;
		}

		otp_close();
	}

	return ret;
}

static TEE_Result otp_init(void)
{
	otp_base = (vaddr_t)phys_to_virt_io(OTP_BASE, OTP_SIZE);
	assert(otp_base);
	return TEE_SUCCESS;
}

early_init(otp_init);
