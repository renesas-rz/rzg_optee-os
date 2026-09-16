PLATFORM_FLAVOR ?= smarc_rzg2l

PLAT_FLAVORS_G2L := smarc_rzg2l smarc_rzg2lc smarc_rzg2ul smarc_rzv2l
PLAT_FLAVORS_G3S := smarc_rzg3s
PLAT_FLAVORS_G3E := smarc_rzg3e
PLAT_FLAVORS_G3L := smarc_rzg3l
PLAT_FLAVORS_V2H := rzv2h_evk rzv2n_evk
PLAT_FLAVORS_T2H := rzt2h_dev rzn2h_dev
PLAT_FLAVORS_T2N := rzt2n_dev rzt2n_dev_537 rzt2n_dev_489

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
else ifneq ($(filter $(PLATFORM_FLAVOR),$(PLAT_FLAVORS_T2N)),)
    $(call force,CFG_PLATFORM_DEV,t2n)
else
    $(error Unsupported PLATFORM_FLAVOR "$(PLATFORM_FLAVOR)")
endif

include core/arch/arm/plat-rz/$(CFG_PLATFORM_DEV)/plat_conf.mk
