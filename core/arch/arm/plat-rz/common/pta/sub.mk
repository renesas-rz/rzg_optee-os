CFG_RZ_RSIP_PTA ?= $(CFG_RZ_RSIP_PROTECTED)
subdirs-$(CFG_RZ_RSIP_PTA) += rsip

CFG_RZ_SCE_PTA ?= $(CFG_RZ_TSIP_PROTECTED)
subdirs-$(CFG_RZ_SCE_PTA) += sce

CFG_RZ_FLASH_PTA ?= y
subdirs-$(CFG_RZ_FLASH_PTA) += flash

define copy-file
$2/$$(notdir $1): $1
	@set -e; \
	mkdir -p $$(dir $$@) ; \
	$(cmd-echo-silent) '  INSTALL $$@' ; \
	cp -P $$< $$@
cleanfiles += $2/$$(notdir $1)
ta_dev_kit: $2/$$(notdir $1)
ta_dev_kit-files += $2/$$(notdir $1)
endef

define export-incfiles-host
$(foreach ta,$(ta-targets), \
	$(foreach f,$(foreach d,$1,$(wildcard $(sub-dir)/$(d)/*.h)), \
		$(eval $(call copy-file,$(f), $(out-dir)/export-$(ta)/host_include))))
endef
