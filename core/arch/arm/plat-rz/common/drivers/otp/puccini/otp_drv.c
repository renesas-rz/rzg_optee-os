// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2023-2025, Renesas Electronics Corporation
 */

#include <initcall.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <util.h>
#include "otp_drv.h"
#include "otp_regs.h"
#include <trace.h>

vaddr_t otp_base;

static bool r_otp_open(void);
static void r_otp_close(void);
static void r_otp_dummy_read(void);

static bool r_otp_open(void)
{
	bool ready = false;
	bool ret = false;

	/* On power up OTP is powered on but on returning to this */
	/* function it is probably powered off. */
	if (0U == (otp_io_read(OTP_OTPPWR) & (1U << OTP_OTPPWR_PWR)))
		if ((0U == (otp_io_read(OTP_OTPSTR) & (1U << OTP_OTPSTR_CMD_RDY))))
			if (0U != (otp_io_read(OTP_OTPFLAG) & (1U << OTP_OTPFLAG_FLAG)))
				if (0U != (otp_io_read(OTP_OTPFLAG) & (1U << OTP_OTPFLAG_RREND)))
					/* RDY bit should be clear */
					ready = true;
	else if (0U != (otp_io_read(OTP_OTPSTR) & (1U << OTP_OTPSTR_CMD_RDY))) /* Not powered off so RDY bit should be set */
		ready = true;
	else
		ready = false;

	if (true == ready) {
		/* Enable power and switch to APB interface */
		otp_io_write(OTP_OTPPWR, (1U << OTP_OTPPWR_PWR) | (1U << OTP_OTPPWR_ACCL));
		ret = true;
	}

	return ret;
}

static void r_otp_close(void)
{
	/* Dummy read */
	r_otp_dummy_read();

	/* Switch off OTP PWR and ACCL bits */
	otp_io_write(OTP_OTPPWR, 0U);

	/* Wait for ready bit to clear */
	while (0U != (otp_io_read(OTP_OTPSTR) & (1U << OTP_OTPSTR_CMD_RDY)))
		isb();	  /* Not sure if this is necessary */
}

static void r_otp_dummy_read(void)
{
	while (1 != (otp_io_read(OTP_OTPSTR) & (1U << OTP_OTPSTR_CMD_RDY)))
		; /* Polling */

	otp_io_write(OTP_OTPADRRD, OTP_IP_DUMMY_READ_ADDR);

	(void)otp_io_read(OTP_OTPDATARD);
}

bool r_otp_read(uint32_t addr, uint32_t *p_value, uint32_t count)
{
	bool ret = false;

	if (true == r_otp_open()) {
		if ((addr >= OTP_IP_ADDR_MIN) && (addr <= OTP_IP_ADDR_MAX) && ((addr + count - 1U) <= OTP_IP_ADDR_MAX)) {
			/* Wait for OTP access enable */
			while (1U != (otp_io_read(OTP_OTPSTR) & (1U << OTP_OTPSTR_CMD_RDY)))
				isb();	  /* Not sure if this is necessary */

			otp_io_write(OTP_OTPADRRD, addr);

			while (count > 0U) {
				*p_value = otp_io_read(OTP_OTPDATARD);
				if (0U != (otp_io_read(OTP_OTPSTR) & (1U << OTP_OTPSTR_ERR_RP)))
					/* Error - reading protected area */
					break;
				/* The address in OTP_OTPDATARD auto increments */
				p_value++;
				count -= 1U;
			}

			if (count == 0U)
				ret = true;
		}

		r_otp_close();
	}

	return ret;
}

static TEE_Result otp_init(void)
{
	otp_base = (vaddr_t)phys_to_virt_io(OTP_BASE, OTP_REG_SIZE);

	return TEE_SUCCESS;
}

service_init(otp_init);
