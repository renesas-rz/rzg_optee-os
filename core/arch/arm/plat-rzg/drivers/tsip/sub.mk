

incdirs-y += .

srcs-y += wrapper/TSIP_Wrapper_BasicEncryption_API.c
srcs-y += wrapper/TSIP_Wrapper_Local_API.c
srcs-y += wrapper/TSIP_Wrapper_Lib_Init_API.c
srcs-y += wrapper/TSIP_Wrapper_SecureUpdate_API.c
srcs-y += core/TSIP_Core_Proc_API.c
srcs-y += core/TSIP_Core_SecureUpdate_API.c
srcs-y += core/TSIP_Core_Lib_Init_API.c
srcs-y += core/TSIP_Core_Local_API.c
srcs-y += core/TSIP_Core_BasicEncryption_API.c
srcs-y += stub/TSIP_Stub_API_optee.c
srcs-y += stub/TSIP_Driver_optee.c

ifeq ($(PLATFORM_FLAVOR),ek874)
libdeps += $(CFG_RZG_SEC_LIB_DIR)/libr_secure_ip_lib_g2e.a
endif
ifeq ($(PLATFORM_FLAVOR),hihope_rzg2m)
libdeps += $(CFG_RZG_SEC_LIB_DIR)/libr_secure_ip_lib_g2m.a
endif
ifeq ($(PLATFORM_FLAVOR),hihope_rzg2n)
libdeps += $(CFG_RZG_SEC_LIB_DIR)/libr_secure_ip_lib_g2n.a
endif
ifeq ($(PLATFORM_FLAVOR),hihope_rzg2h)
libdeps += $(CFG_RZG_SEC_LIB_DIR)/libr_secure_ip_lib_g2h.a
endif
