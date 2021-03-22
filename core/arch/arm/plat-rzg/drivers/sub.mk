
ifeq ($(CFG_RZG_SEC_IP_DRV),y)
srcs-y += secip_drv.c
subdirs-y += tsip
endif
