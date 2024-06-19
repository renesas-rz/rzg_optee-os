srcs-$(CFG_RZ_HUK) += huk.c
srcs-$(CFG_RZ_RSIP) += hw_rng_rsip.c

subdirs-y += drivers
subdirs-$(CFG_RZ_XSPI) += pta
