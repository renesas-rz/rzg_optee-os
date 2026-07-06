
srcs-y += otp_service.c

incdirs-$(CFG_RZ_OTP_PUCCINI) += puccini
srcs-$(CFG_RZ_OTP_PUCCINI) += puccini/otp_drv.c
