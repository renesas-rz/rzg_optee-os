global-incdirs-y += include
global-incdirs-$(CFG_RZ_RSIP) += include/rsip
global-incdirs-$(CFG_RZ_TSIP) += include/sce

subdirs-$(CFG_RZ_RSIP) += rsip
subdirs-$(CFG_RZ_TSIP) += sce
srcs-y += pta_flash.c
