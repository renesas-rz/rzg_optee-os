global-incdirs-y += include

global-incdirs-$(CFG_RZ_RSIP_PROTECTED) += include/rsip
subdirs-$(CFG_RZ_RSIP_PROTECTED) += rsip

global-incdirs-$(CFG_RZ_TSIP_PROTECTED) += include/sce
subdirs-$(CFG_RZ_TSIP_PROTECTED) += sce

CFG_RZ_FLASH_PTA ?= y
srcs-$(CFG_RZ_FLASH_PTA) += pta_flash.c
