LIB_MAJOR := \
    $(word 4,$(subst _, ,$(notdir $(CFG_SECURE_IP_LIB))))
$(info LIB_MAJOR=$(LIB_MAJOR))

srcs-y += \
	bsp/bsp_api.c \
	rsip_common/public/r_rsip.c \
	rsip_common/public/r_rsip_aes.c \
	rsip_common/public/r_rsip_ecc.c \
	rsip_common/public/r_rsip_rsa.c \
	rsip_common/public/r_rsip_sha.c \
	rsip_common/public/r_rsip_rzg3.c

global-incdirs-y += \
	bsp \
	rsip_common/public \
	rsip_common/private

ifeq ($(shell [ $(LIB_MAJOR) -ge 5 ] && echo y),y)
srcs-y += \
	rzt2/private/r_rsip_private.c \
	rzt2/private/r_rsip_wrapper.c \
	rzt2/private/r_rsip_otp.c
global-incdirs-y += \
	rzt2/private \
	rzt2/primitive
else
srcs-y += \
	rzg3/private/r_rsip_private.c \
	rzg3/private/r_rsip_wrapper.c \
	rzg3/private/r_rsip_otp.c
global-incdirs-y += \
	rzg3/private \
	rzg3/primitive
endif
