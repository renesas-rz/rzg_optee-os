// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2023-2026, Renesas Electronics Corporation
 */

#include <stdint.h>
#include <initcall.h>
#include <io.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <util.h>
#include <xspi_regs.h>
#include <xspi_reg_values.h>
#include <xspi.h>

#define RDID (0)
#define RSTEN (1)
#define RESET (2)
#define WTEN (3)
#define ERASE (4)
#define RDSTA (5)
#define WRITE (6)

#define IN_DIR (0u)
#define OUT_DIR (1u)

#define DEVID_ID_MASK (0x00FFFFFFu)
#define DEVICE_ID_BAD (0u)
#define DEVICE_ID_ERROR (0x00FFFFFFu)

#define XSPI_COMMAND_TIMEOUT (100000u)

struct xspi_dev {
	paddr_t phys; /* Physical register base */
	vaddr_t virt; /* Mapped virtual register base */
	size_t size; /* Register region size */
};

struct xspi_cmd {
	uint16_t instruction;
	uint8_t direction : 3; /* Transfer direction */
	uint8_t latency : 5; /* Dummy/latency cycles */
	uint8_t data_size : 4; /* Data length in bytes */
	uint8_t addr_size : 4; /* Address length in bytes */
	uint8_t cmd_size : 4; /* Instruction length in bytes */
};

struct xspi_cmd_info {
	uint8_t cmd_id; /* Command table index */
	uint32_t addr; /* Target address */
	uint32_t data; /* Write data */
};

/* Flash command definitions */
static const struct xspi_cmd cmds[] = {
	/* instruction, direction, latency, data_size, addr_size, cmd_size */
	{ 0x9F00u, IN_DIR,  0u, 3u, 0u, 1u }, /* RDID */
	{ 0x6600u, OUT_DIR, 0u, 0u, 0u, 1u }, /* RSTEN */
	{ 0x9900u, OUT_DIR, 0u, 0u, 0u, 1u }, /* RESET */
	{ 0x0600u, OUT_DIR, 0u, 0u, 0u, 1u }, /* WTEN */
	{ 0x2000u, OUT_DIR, 0u, 0u, 3u, 1u }, /* ERASE */
	{ 0x0500u, IN_DIR,  0u, 1u, 0u, 1u }, /* RDSTA */
	{ 0x0200u, OUT_DIR, 0u, 4u, 3u, 1u }, /* WRITE */
};

/* Available XSPI controllers */
static struct xspi_dev xspi_devices[] = {
#ifdef SPI_BASE
	{ .phys = SPI_BASE, .size = SPI_SIZE },
#else
#ifdef SPI_0_BASE
	{ .phys = SPI_0_BASE, .size = SPI_SIZE },
#endif
#ifdef SPI_1_BASE
	{ .phys = SPI_1_BASE, .size = SPI_SIZE },
#endif
#endif
};

static inline void xspi_io_write(const struct xspi_dev *dev, uint32_t reg,
				 uint32_t value)
{
	io_write32(dev->virt + reg, value);
}

static inline uint32_t xspi_io_read(const struct xspi_dev *dev, uint32_t reg)
{
	return io_read32(dev->virt + reg);
}

/* Get XSPI controller from channel number */
static struct xspi_dev *get_xspi_device(uint8_t ch)
{
	if (ch < ARRAY_SIZE(xspi_devices))
		return &xspi_devices[ch];

	return NULL;
}

/* Execute a single manual command transaction */
static int32_t xspi_single_command(const struct xspi_dev *dev,
				   const struct xspi_cmd_info *const cmd_info)
{
	uint32_t timeout = XSPI_COMMAND_TIMEOUT;

	const struct xspi_cmd *cmd = &cmds[cmd_info->cmd_id];

	xspi_io_write(dev, XSPI_CDCTL0,
		      xspi_io_read(dev, XSPI_CDCTL0) &
			      (~XSPI_CDCTL0_TRREQ_MSK));

	/* Configure command format */
	xspi_io_write(
		dev, XSPI_CDTBUF0,
		(((uint32_t)cmd->instruction << XSPI_CDTBUF_CMD_OFFSET) |
		 ((uint32_t)cmd->direction << XSPI_CDTBUF_TRTYPE_OFFSET) |
		 ((uint32_t)cmd->latency << XSPI_CDTBUF_LATE_OFFSET) |
		 ((uint32_t)cmd->data_size << XSPI_CDTBUF_DATASIZE_OFFSET) |
		 ((uint32_t)cmd->addr_size << XSPI_CDTBUF_ADDSIZE_OFFSET) |
		 ((uint32_t)cmd->cmd_size << XSPI_CDTBUF_CMDSIZE_OFFSET)));

	/* Set command address */
	xspi_io_write(dev, XSPI_CDABUF0, cmd_info->addr);

	/* Set write data if required */
	if (cmd->direction == OUT_DIR)
		xspi_io_write(dev, XSPI_CDD0BUF0, cmd_info->data);

	/* Start command transaction */
	xspi_io_write(dev, XSPI_CDCTL0,
		      xspi_io_read(dev, XSPI_CDCTL0) | XSPI_CDCTL0_TRREQ_MSK);

	/* Wait for command to complete */
	while ((0u == (xspi_io_read(dev, XSPI_INTS) & XSPI_INTS_CMDCMP_MSK)) &&
	       (timeout > 0u)) {
		timeout--;
		__asm__("nop");
		dsb();
	}

	/* Clear completion status */
	xspi_io_write(dev, XSPI_INTC,
		      xspi_io_read(dev, XSPI_INTC) | XSPI_INTC_CMDCMPC_MSK);

	return (timeout == 0u) ? XSPI_ERR : XSPI_OK;
}

/* Reset flash device */
static int32_t xspi_reset(const struct xspi_dev *dev)
{
	int32_t ret = XSPI_ERR;

	/* Issue the reset command */
	struct xspi_cmd_info cmd_rsten = { RSTEN, 0, 0 };
	struct xspi_cmd_info cmd_reset = { RESET, 0, 0 };

	ret = xspi_single_command(dev, &cmd_rsten);
	if (ret == XSPI_OK)
		ret = xspi_single_command(dev, &cmd_reset);

	return ret;
}

/*
 * Wait until the flash device becomes operational.
 * A valid device ID must be returned twice consecutively.
 */
static int32_t xspi_wait_flash_ready(const struct xspi_dev *dev)
{
	int32_t ret = XSPI_ERR;

	int32_t count = 1000;
	uint32_t id = DEVICE_ID_BAD;
	uint32_t prev_id = DEVICE_ID_BAD;

	struct xspi_cmd_info cmd_rdid = { RDID, 0, 0 };

	while (count > 0) {
		if (xspi_single_command(dev, &cmd_rdid) == XSPI_OK) {
			/* Command success */
			id = xspi_io_read(dev, XSPI_CDD0BUF0) & DEVID_ID_MASK;

			/* Hardware ID is valid and has been repeated on two consecutive reads so exit the while loop and then function */
			if ((id != DEVICE_ID_BAD) && (id != DEVICE_ID_ERROR) &&
			    (prev_id == id)) {
				ret = XSPI_OK;
				break;
			}

			prev_id = id;
		}
		/* Allow retry of Id read in case Flash device has not had enough time to start-up*/
		count--;
	}

	return ret;
}

/* Read flash status register */
static int32_t xspi_read_status(const struct xspi_dev *dev)
{
	volatile uint32_t status = 0xFFFFFFFF;

	struct xspi_cmd_info cmd_rdsta = { RDSTA, 0, 0 };

	if (xspi_single_command(dev, &cmd_rdsta) == XSPI_OK)
		/* Command success */
		status = xspi_io_read(dev, XSPI_CDD0BUF0);

	return status;
}

/* Erase flash sectors */
int32_t xspi_erase(uint8_t ch, const uintptr_t addr, uint32_t byte_count)
{
	int32_t ret = XSPI_ERR;

	uint32_t i;
	uint32_t count = DIV_ROUND_UP(byte_count, XSPI_WRITE_PROG_SIZE);

	struct xspi_cmd_info cmd_wten = { WTEN, 0, 0 };
	struct xspi_cmd_info cmd_erase = { ERASE, addr, 0 };

	volatile uint32_t status = 0xFFFFFFFF;

	struct xspi_dev *dev = get_xspi_device(ch);
	assert(dev);

	for (i = 0; i < count; i++) {
		/* Enable write operation */
		ret = xspi_single_command(dev, &cmd_wten);
		if (ret != XSPI_OK)
			return ret;

		/* Wait for WEL bit */
		do {
			status = xspi_read_status(dev);
		} while (0 == (status & 0x02));

		/* Erase one erase unit */
		ret = xspi_single_command(dev, &cmd_erase);
		if (ret != XSPI_OK)
			return ret;

		/* Wait until erase completes */
		do {
			status = xspi_read_status(dev);
		} while (0 != (status & 0x01));

		/* Advance to next erase unit */
		cmd_erase.addr = cmd_erase.addr + XSPI_WRITE_PROG_SIZE;
	}

	return ret;
}

/* Program flash data */
int32_t xspi_write(uint8_t ch, const uintptr_t addr, uintptr_t data,
		   uint32_t byte_count)
{
	int32_t ret = XSPI_ERR;

	uint32_t i;
	uint32_t *src = (uint32_t *)data;
	uint32_t count = byte_count / sizeof(uint32_t);

	struct xspi_cmd_info cmd_wten = { WTEN, 0, 0 };
	struct xspi_cmd_info cmd_write = { WRITE, addr, 0 };

	volatile uint32_t status = 0xFFFFFFFF;

	struct xspi_dev *dev = get_xspi_device(ch);
	assert(dev);

	/* Erase target region before programming */
	ret = xspi_erase(ch, addr, byte_count);
	if (ret != XSPI_OK)
		return ret;

	for (i = 0; i < count; i++) {
		/* Enable write operation */
		ret = xspi_single_command(dev, &cmd_wten);
		if (ret != XSPI_OK)
			return ret;

		/* Wait for WEL bit */
		do {
			status = xspi_read_status(dev);
		} while (0 == (status & 0x02));

		cmd_write.data = src[i];
		/* Program one word */
		ret = xspi_single_command(dev, &cmd_write);
		if (ret != XSPI_OK)
			return ret;

		/* Wait until programming completes */
		do {
			status = xspi_read_status(dev);
		} while (0 != (status & 0x01));

		cmd_write.addr += sizeof(uint32_t);
	}

	return ret;
}

/* Dummy read to ensure pending access completion */
int32_t xspi_dummy_read(uint8_t ch)
{
	struct xspi_dev *dev = get_xspi_device(ch);
	assert(dev);

	(void)xspi_io_read(dev, XSPI_WRAPCFG);

	return XSPI_OK;
}

/* Initialize controller and flash device */
int32_t xspi_setup(uint8_t ch)
{
	int32_t ret = XSPI_ERR;

	struct xspi_dev *dev = get_xspi_device(ch);
	assert(dev);

	/* Configure controller registers */
	xspi_io_write(dev, XSPI_BMCFG, XSPI_BMCFG_SET_VALUE);
	xspi_io_write(dev, XSPI_CMCFG0CS0, XSPI_CMCFG0CS0_SET_VALUE);
	xspi_io_write(dev, XSPI_CMCFG1CS0, XSPI_CMCFG1CS0_SET_VALUE);
	xspi_io_write(dev, XSPI_CMCFG2CS0, XSPI_CMCFG2CS0_SET_VALUE);
	xspi_io_write(dev, XSPI_LIOCFGCS0, XSPI_LIOCFGCS0_SET_VALUE);
	xspi_io_write(dev, XSPI_BMCTL0, XSPI_BMCTL0_SET_VALUE);
	xspi_io_write(dev, XSPI_INTC, XSPI_INTC_SET_VALUE);

	/* Reset flash device */
	ret = xspi_reset(dev);

	/* Wait until flash is ready */
	if (ret == XSPI_OK)
		ret = xspi_wait_flash_ready(dev);

	return ret;
}

static TEE_Result xspi_init(void)
{
	for (size_t i = 0; i < ARRAY_SIZE(xspi_devices); i++) {
		struct xspi_dev *dev = &xspi_devices[i];

		dev->virt = (vaddr_t)phys_to_virt_io(dev->phys, dev->size);
		if (!dev->virt)
			return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

driver_init(xspi_init);
