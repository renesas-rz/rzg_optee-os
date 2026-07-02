global-incdirs-y += include include/drivers
global-incdirs-$(CFG_RZ_TSIP) += include/drivers/sce
global-incdirs-$(CFG_RZ_RSIP) += include/drivers/rsip

subdirs-y += crypto flash drivers pta
