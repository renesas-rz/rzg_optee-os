global-incdirs-y += .

srcs-$(CFG_RZ_SCIF) += scif.c

subdirs-$(CFG_RZ_XSPI) += xspi

srcs-$(CFG_RZ_SCE) += sce.c hw_rng.c
subdirs-$(CFG_RZ_SCE) += r_sce

ifeq ($(CFG_PLATFORM_GROUP_v2h),y)
ldflags-external += $(CFG_RZ_SCE_LIB_DIR)/libr_secure_ip_2_0.a.1.0.0
endif