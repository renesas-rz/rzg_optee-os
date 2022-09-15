srcs-y += public/r_sce_aes.c
srcs-y += public/r_sce_ecc.c
srcs-y += public/r_sce_rsa.c
srcs-y += public/r_sce_sha.c
srcs-y += public/r_sce.c
srcs-y += private/r_sce_private.c
global-incdirs-y += private/inc
global-incdirs-y += inc/api
global-incdirs-y += inc/instances

ldflags-external += $(CFG_RZ_SCE_LIB_DIR)/libr_secure_ip_1_0.a.1.0.0
