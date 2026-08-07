
ifeq ($(CFG_RZG_SEC_IP_DRV),y)
srcs-y += tsip_init.c
subdirs-y += tsip
endif

ifeq ($(CFG_RZG_SPI_DRV),y)
subdirs-y += spi
endif
