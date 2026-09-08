// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2024-2026, Renesas Electronics Corporation
 */

#include <drivers/scif.h>
#include <io.h>
#include <keep.h>
#include <util.h>

#define SCI_SCTDR (0x04)
#define SCI_SCCCR0 (0x08)
#define SCI_SCFTSR (0x54)

#define SCCCR0_TE BIT(4)
#define SCCCR0_TEIE BIT(21)

#define SCFTSR_FIFO_SIZE 16

static vaddr_t chip_to_base(struct serial_chip *chip)
{
	struct scif_uart_data *pd =
		container_of(chip, struct scif_uart_data, chip);

	return io_pa_or_va(&pd->base, SCIF_REG_SIZE);
}

static void sci_uart_flush(struct serial_chip *chip)
{
	vaddr_t base = chip_to_base(chip);

	/*  Wait until the FIFO is empty */
	while ((io_read16(base + SCI_SCFTSR)) > 0)
		if ((io_read32(base + SCI_SCCCR0) & SCCCR0_TE) == 0)
			io_setbits32(base + SCI_SCCCR0, SCCCR0_TE);
}

static void sci_uart_putc(struct serial_chip *chip, int ch)
{
	vaddr_t base = chip_to_base(chip);

	do {
		if ((io_read32(base + SCI_SCCCR0) & SCCCR0_TE) == 0)
			io_setbits32(base + SCI_SCCCR0, SCCCR0_TE);
	} while ((io_read16(base + SCI_SCFTSR)) >= SCFTSR_FIFO_SIZE);

	sci_uart_flush(chip);
	io_write8(base + SCI_SCTDR, ch);
}

static const struct serial_ops sci_uart_ops = {
	.flush = sci_uart_flush,
	.putc = sci_uart_putc,
};
DECLARE_KEEP_PAGER(sci_uart_ops);

void scif_uart_init(struct scif_uart_data *pd, paddr_t pbase)
{
	pd->base.pa = pbase;
	pd->chip.ops = &sci_uart_ops;

	/* Do not initialize CCR0 register. */
}
