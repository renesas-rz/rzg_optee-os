
include core/arch/arm/cpu/cortex-armv8-0.mk
include core/arch/arm/plat-rz/link.mk

$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
$(call force,CFG_SCIF,n)
$(call force,CFG_RZ_SCI,y)
$(call force,CFG_CORE_LARGE_PHYS_ADDR,y)
$(call force,CFG_CORE_ARM64_PA_BITS,36)
$(call force,CFG_GIC,y)
$(call force,CFG_ARM_GICV3,y)
$(call force,CFG_RZ_XSPI,y)
$(call force,CFG_RZ_OTP_PUCCINI,y)
$(call force,CFG_RZ_MBXSEM,y)

CFG_TEE_CORE_NB_CORE ?= 4
CFG_NUM_THREADS ?= 4
CFG_MMAP_REGIONS ?= 32

CFG_TZDRAM_START ?= 0xC0100000
CFG_TZDRAM_SIZE ?= 0x03D00000
CFG_TEE_RAM_VA_SIZE ?= 0x200000
ifeq ($(CFG_ARM64_core),y)
$(call force,CFG_WITH_LPAE,y)
supported-ta-targets = ta_arm64
else
$(call force,CFG_ARM32_core,y)
endif

ifeq ($(CFG_RZ_SCE),y)
CFG_RZ_RSIP ?= y
CFG_KUK_BASE ?= 0x40A00000
ldflags-external	+=	$(CFG_RZ_SCE_LIB_DIR)/libr_secure_ip_4_0.a.1.0.0
endif

ifeq ($(CFG_RZ_RSIP),y)
CFG_WITH_SOFTWARE_PRNG ?= n
endif