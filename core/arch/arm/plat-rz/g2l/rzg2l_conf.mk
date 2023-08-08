
include core/arch/arm/cpu/cortex-armv8-0.mk
include core/arch/arm/plat-rz/g2l/link.mk

$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
$(call force,CFG_SCIF,n)
$(call force,CFG_RZ_SCIF,y)
$(call force,CFG_CORE_LARGE_PHYS_ADDR,y)
$(call force,CFG_CORE_ARM64_PA_BITS,36)
$(call force,CFG_GIC,y)
$(call force,CFG_ARM_GICV3,y)
$(call force,CFG_CORE_ASLR,n)

ifeq ($(PLATFORM_FLAVOR),g2ul_smarc)
CFG_TEE_CORE_NB_CORE ?= 1
else
CFG_TEE_CORE_NB_CORE ?= 2
endif

CFG_TZDRAM_START ?= 0x44100000
CFG_TZDRAM_SIZE ?= 0x03D00000
CFG_TEE_RAM_VA_SIZE ?= 0x100000
ifeq ($(CFG_ARM64_core),y)
$(call force,CFG_WITH_LPAE,y)
supported-ta-targets = ta_arm64
else
$(call force,CFG_ARM32_core,y)
endif

CFG_RZ_SCE ?= n
ifeq ($(CFG_RZ_SCE),y)
CFG_WITH_SOFTWARE_PRNG ?= n
endif

ifeq ($(PLATFORM_FLAVOR),g2ul_smarc)
CFG_SPI_FLASH_DEV ?= AT25QL128A
else
CFG_SPI_FLASH_DEV ?= MT25QU512ABB
endif
