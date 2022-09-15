PLATFORM_FLAVOR ?= g2l_smarc_2

ifeq ($(PLATFORM_FLAVOR),g2l_dev13_1)
$(call force,CFG_PLATFORM_GROUP_g2l,y)
include core/arch/arm/plat-rz/g2l/rzg2l_conf.mk
else ifeq ($(PLATFORM_FLAVOR),g2l_dev15_4)
$(call force,CFG_PLATFORM_GROUP_g2l,y)
include core/arch/arm/plat-rz/g2l/rzg2l_conf.mk
else ifeq ($(PLATFORM_FLAVOR),g2l_dev21_4)
$(call force,CFG_PLATFORM_GROUP_g2l,y)
include core/arch/arm/plat-rz/g2l/rzg2l_conf.mk
else ifeq ($(PLATFORM_FLAVOR),g2lc_smarc_1)
$(call force,CFG_PLATFORM_GROUP_g2l,y)
include core/arch/arm/plat-rz/g2l/rzg2l_conf.mk
else ifeq ($(PLATFORM_FLAVOR),g2l_smarc_2)
$(call force,CFG_PLATFORM_GROUP_g2l,y)
include core/arch/arm/plat-rz/g2l/rzg2l_conf.mk
else ifeq ($(PLATFORM_FLAVOR),g2l_smarc_4)
$(call force,CFG_PLATFORM_GROUP_g2l,y)
include core/arch/arm/plat-rz/g2l/rzg2l_conf.mk
else ifeq ($(PLATFORM_FLAVOR),g2ul_smarc)
$(call force,CFG_PLATFORM_GROUP_g2l,y)
include core/arch/arm/plat-rz/g2l/rzg2l_conf.mk
else
$(error Unsupported PLATFORM_FLAVOR "$(PLATFORM_FLAVOR)")
endif
