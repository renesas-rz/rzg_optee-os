global-incdirs-y += include

srcs-$(CFG_RZ_RSIP) += \
					pta_rsip.c \
					pta_rsip_aes.c \
					pta_rsip_rsa.c \
					pta_rsip_sha.c \
					pta_rsip_ecc.c \
					pta_rsip_hmac.c