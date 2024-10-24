srcs-y	+=	\
		bsp_api.c				\
		rsip_common/public/r_rsip.c			\
		rsip_common/public/r_rsip_aes.c		\
		rsip_common/public/r_rsip_ecc.c		\
		rsip_common/public/r_rsip_rsa.c		\
		rsip_common/public/r_rsip_sha.c

srcs-$(CFG_PLATFORM_GROUP_g3s)	+=	\
		rsip_common/public/r_rsip_rzg3.c	\
		rzg3/private/r_rsip_private.c		\
		rzg3/private/r_rsip_wrapper.c		\
		rzg3/private/r_rsip_otp.c

srcs-$(CFG_PLATFORM_GROUP_t2h)	+=	\
		rsip_common/public/r_rsip_rzg3.c	\
		rzg3/private/r_rsip_private.c		\
		rzg3/private/r_rsip_wrapper.c		\
		rzg3/private/r_rsip_otp.c

global-incdirs-y	+=	\
		.							\
		rsip_common/inc				\
		rsip_common/inc/api			\
		rsip_common/inc/instances	\
		rsip_common/public			\
		rsip_common/private

global-incdirs-$(CFG_PLATFORM_GROUP_g3s)	+=	\
		rzg3/private				\
		rzg3/primitive

global-incdirs-$(CFG_PLATFORM_GROUP_t2h)	+=	\
		rzg3/private				\
		rzg3/primitive

ifeq	($(CFG_PLATFORM_GROUP_g3s),y)
ldflags-external	+=	$(CFG_RZ_SCE_LIB_DIR)/libr_secure_ip_3_0.a.1.0.0
else ifeq	($(CFG_PLATFORM_GROUP_t2h),y)
ldflags-external	+=	$(CFG_RZ_SCE_LIB_DIR)/libr_secure_ip_4_0.a.1.0.0
endif