global-incdirs-y += .
srcs-y += main.c

srcs-$(CFG_RZ_SCE) += hw_rng.c

subdirs-y += drivers pta
