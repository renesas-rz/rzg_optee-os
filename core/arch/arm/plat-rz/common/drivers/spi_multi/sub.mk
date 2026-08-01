srcs-y += spi_multi.c
global-incdirs-y += .

subdirs-y += devices/$(CFG_SPI_FLASH_DEV)
