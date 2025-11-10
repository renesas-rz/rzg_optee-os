srcs-y += \
		bsp_api.c							\
		rsip_common/public/r_rsip.c			\
		rsip_common/public/r_rsip_aes.c		\
		rsip_common/public/r_rsip_ecc.c		\
		rsip_common/public/r_rsip_rsa.c		\
		rsip_common/public/r_rsip_sha.c

srcs-y += \
		rsip_common/public/r_rsip_rzg3.c	\
		rzg3/private/r_rsip_private.c		\
		rzg3/private/r_rsip_wrapper.c		\
		rzg3/private/r_rsip_otp.c

global-incdirs-y += \
		.							\
		rsip_common/inc				\
		rsip_common/inc/api			\
		rsip_common/inc/instances	\
		rsip_common/public			\
		rsip_common/private

global-incdirs-y += \
		rzg3/private				\
		rzg3/primitive
