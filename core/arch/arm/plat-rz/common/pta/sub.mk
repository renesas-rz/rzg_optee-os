global-incdirs-y += include

srcs-y += pta_flash.c

subdirs-$(CFG_RZ_RSIP) += rsip

subdirs-$(CFG_RZ_TSIP) += tsip