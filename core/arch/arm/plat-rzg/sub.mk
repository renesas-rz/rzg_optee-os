global-incdirs-y += .
global-incdirs-y += include
srcs-y += main.c
srcs-y += tee_common_otp.c

ifeq (${PLATFORM_FLAVOR_hihope_rzg2n},y)
  ifeq (${PMIC_ROHM_BD9571},1)
    srcs-y += rzg_suspend_to_ram.c
  endif
endif

cppflags-y += -DLTC_NO_PROTOTYPES -DRZG_DRAM_ECC=$(RZG_DRAM_ECC) -DRZG_ECC_FULL=$(RZG_ECC_FULL) -DPMIC_ROHM_BD9571=$(PMIC_ROHM_BD9571)
subdirs-y += drivers
