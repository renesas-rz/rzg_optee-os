incdirs-y += include
srcs-y += \
	pta_sce.c \
	pta_sce_ecc.c \
	pta_sce_rsa.c \
	pta_sce_sha.c \
	pta_sce_aes.c \
	pta_sce_cmd.c \
	pta_sce_util.c

$(eval $(call export-incfiles-host,include))
