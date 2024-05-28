global-incdirs-y += .

srcs-$(CFG_RZ_SCIF) += scif.c

subdirs-$(CFG_RZ_XSPI) += xspi

srcs-$(CFG_RZ_SCE) += sce.c hw_rng.c
subdirs-$(CFG_RZ_SCE) += r_sce