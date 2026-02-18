srcs-$(CFG_RZ_HUK) += huk.c
ifneq ($(filter y,$(CFG_RZ_TSIP) $(CFG_RZ_RSIP)),)
	srcs-y+= hw_rng.c
endif

subdirs-y += drivers
subdirs-y += pta
