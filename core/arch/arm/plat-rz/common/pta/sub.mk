global-incdirs-y += include

srcs-y += pta_flash.c
srcs-$(CFG_RZ_SCE) += pta_sce.c pta_sce_ecc.c pta_sce_rsa.c pta_sce_sha.c pta_sce_aes.c
