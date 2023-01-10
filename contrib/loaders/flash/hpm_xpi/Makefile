# SPDX-License-Identifier: BSD-3-Clause

BIN2C = ../../../../src/helper/bin2char.sh

SRCS += hpm_xpi_flash.bin
OBJS=hpm_xpi_flash.inc

all: $(OBJS)

hpm_xpi_flash.inc: $(SRCS)
	$(BIN2C) < $< > $@

clean:
	-rm -f *.bin *.inc

.PHONY:	all clean
