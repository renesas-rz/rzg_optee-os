global-incdirs-y += .

srcs-$(CFG_RZ_SCIF) += scif.c
srcs-$(CFG_RZ_SCI) += sci.c

subdirs-$(CFG_RZ_SPI_MULTI) += spi_multi
srcs-$(CFG_RZ_SPI_MULTI) += sflash_spi_multi.c

subdirs-$(CFG_RZ_XSPI) += xspi
srcs-$(CFG_RZ_XSPI) += sflash_xspi.c

subdirs-$(CFG_RZ_OTP_PUCCINI) += otp/puccini

srcs-$(CFG_RZ_TSIP) += sce.c
subdirs-$(CFG_RZ_TSIP) += r_sce

srcs-$(CFG_RZ_RSIP) += rsip.c
subdirs-$(CFG_RZ_RSIP) += r_rsip

subdirs-$(CFG_RZ_MBXSEM) += mbxsem
