global-incdirs-y += .

srcs-$(CFG_RZ_SCIF) += scif.c

subdirs-$(CFG_RZ_SPI_MULTI) += spi_multi

subdirs-$(CFG_RZ_XSPI) += xspi

srcs-$(CFG_RZ_TSIP) += sce.c
subdirs-$(CFG_RZ_TSIP) += r_sce

srcs-$(CFG_RZ_RSIP) += rsip.c
subdirs-$(CFG_RZ_RSIP) += r_rsip