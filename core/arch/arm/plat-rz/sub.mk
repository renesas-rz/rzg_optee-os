ifneq ($(CFG_PLATFORM_DEV),)
subdirs-y += $(CFG_PLATFORM_DEV)
endif

subdirs-y += common
