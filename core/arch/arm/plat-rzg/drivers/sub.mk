
ifeq ($(CFG_RZG_SEC_IP_DRV),y)
srcs-y += tsip_init.c
subdirs-y += tsip
endif
