// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2024, Renesas Electronics Corporation
 */

#include <drivers/scif.h>
#include <io.h>
#include <keep.h>
#include <util.h>

#define SCIF_SCFTDR		(0x04)
#define SCIF_SCCCR0		(0x08)
#define SCIF_SCFTSR		(0x54)

#define SCCCR0_TE		BIT(4)
#define SCCCR0_TEIE		BIT(21)

#define SCIF_TX_FIFO_SIZE	16

static vaddr_t chip_to_base(struct serial_chip *chip)
{
	struct scif_uart_data *pd =
		container_of(chip, struct scif_uart_data, chip);

	return io_pa_or_va(&pd->base, SCIF_REG_SIZE);
}

static void scif_uart_flush(struct serial_chip *chip)
{
	vaddr_t base = chip_to_base(chip);

	/* Wait until there is space in the FIFO */
	while ((io_read16(base + SCIF_SCFTSR)) >= SCIF_TX_FIFO_SIZE)
		;
}

static void scif_uart_putc(struct serial_chip *chip, int ch)
{
	vaddr_t base = chip_to_base(chip);

	/* Workaround:Set CCR0 register. Enable TE and TEIE bits. */
	io_setbits32(base + SCIF_SCCCR0, SCCCR0_TE | SCCCR0_TEIE);

	scif_uart_flush(chip);
	io_write8(base + SCIF_SCFTDR, ch);
}

static const struct serial_ops scif_uart_ops = {
	.flush = scif_uart_flush,
	.putc = scif_uart_putc,
};
DECLARE_KEEP_PAGER(scif_uart_ops);

void scif_uart_init(struct scif_uart_data *pd, paddr_t pbase)
{
	pd->base.pa = pbase;
	pd->chip.ops = &scif_uart_ops;

	/* Do not initialize CCR0 register. */
}
