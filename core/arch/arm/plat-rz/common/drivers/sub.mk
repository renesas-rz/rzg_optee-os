global-incdirs-y += .

srcs-$(CFG_RZ_SCIF) += scif.c

subdirs-$(CFG_RZ_SPI_MULTI) += spi_multi

subdirs-$(CFG_RZ_XSPI) += xspi

srcs-$(CFG_RZ_TSIP) += sce.c hw_rng.c
subdirs-$(CFG_RZ_TSIP) += r_sce

srcs-$(CFG_RZ_RSIP) += rsip.c hw_rng_rsip.c
subdirs-$(CFG_RZ_RSIP) += r_rsip

ifeq ($(CFG_PLATFORM_GROUP_g2l),y)
ldflags-external += $(CFG_RZ_SCE_LIB_DIR)/libr_secure_ip_1_0.a.1.0.0
endif
