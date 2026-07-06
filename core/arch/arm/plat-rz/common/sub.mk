global-incdirs-y += include include/drivers
global-incdirs-$(CFG_RZ_TSIP_PROTECTED) += include/drivers/sce
global-incdirs-$(CFG_RZ_RSIP_PROTECTED) += include/drivers/rsip

subdirs-y += crypto flash drivers pta
