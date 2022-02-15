srcs-y += r_sce.c

core-platform-cflags += -I$(CFG_RZ_SCE_LIB_DIR)/include
ldflags-external += $(CFG_RZ_SCE_LIB_DIR)/libr_secure_ip_1_0.a.1.0.0
