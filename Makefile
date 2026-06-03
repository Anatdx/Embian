# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0

ifneq ($(KERNELRELEASE),)
include $(src)/Kbuild
else

KDIR ?= /lib/modules/$(shell uname -r)/build

.PHONY: all modules clean

all: modules

modules:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean

endif
