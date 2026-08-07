PLATFORM_FLAVOR ?= smarc_rzg2l

PLAT_FLAVORS_G2L := smarc_rzg2l smarc_rzg2lc smarc_rzg2ul g2l_dev13_1 g2l_dev15_4 g2l_dev21_4 g2l_smarc_4
PLAT_FLAVORS_G3S := smarc_rzg3s g3s_dev14_1
PLAT_FLAVORS_G3E := smarc_rzg3e
PLAT_FLAVORS_G3L := smarc_rzg3l
PLAT_FLAVORS_V2H := v2h_evk_1 v2n_evk
PLAT_FLAVORS_T2H := t2h_dev_1 n2h_eval

ifneq ($(filter $(PLATFORM_FLAVOR),$(PLAT_FLAVORS_G2L)),)
    $(call force,CFG_PLATFORM_DEV,g2l)
else ifneq ($(filter $(PLATFORM_FLAVOR),$(PLAT_FLAVORS_G3S)),)
    $(call force,CFG_PLATFORM_DEV,g3s)
else ifneq ($(filter $(PLATFORM_FLAVOR),$(PLAT_FLAVORS_G3E)),)
    $(call force,CFG_PLATFORM_DEV,g3e)
else ifneq ($(filter $(PLATFORM_FLAVOR),$(PLAT_FLAVORS_G3L)),)
    $(call force,CFG_PLATFORM_DEV,g3l)
else ifneq ($(filter $(PLATFORM_FLAVOR),$(PLAT_FLAVORS_V2H)),)
    $(call force,CFG_PLATFORM_DEV,v2h)
else ifneq ($(filter $(PLATFORM_FLAVOR),$(PLAT_FLAVORS_T2H)),)
    $(call force,CFG_PLATFORM_DEV,t2h)
else
    $(error Unsupported PLATFORM_FLAVOR "$(PLATFORM_FLAVOR)")
endif

include core/arch/arm/plat-rz/$(CFG_PLATFORM_DEV)/plat_conf.mk
