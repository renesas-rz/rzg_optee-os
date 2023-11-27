global-incdirs-y += .
srcs-y += cpg.c
srcs-y += sflash.c
srcs-$(CFG_RZ_SCE) += sce.c

subdirs-y += spi_multi
subdirs-$(CFG_RZ_SCE) += r_sce
