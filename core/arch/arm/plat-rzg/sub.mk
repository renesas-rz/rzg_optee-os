global-incdirs-y += .
srcs-y += main.c
srcs-y += tee_common_otp.c

cppflags-y += -DLTC_NO_PROTOTYPES -DRZG_DRAM_ECC=$(RZG_DRAM_ECC) -DRZG_ECC_FULL=$(RZG_ECC_FULL)
