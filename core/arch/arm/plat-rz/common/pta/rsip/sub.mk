incdirs-y += include
srcs-y += \
	pta_rsip.c \
	pta_rsip_aes.c \
	pta_rsip_sha.c \
	pta_rsip_hmac.c \
	pta_rsip_ecc.c \
	pta_rsip_rsa.c \
	pta_rsip_cmd.c \
	pta_rsip_util.c

$(eval $(call export-incfiles-host,include))
