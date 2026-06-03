# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0

obj-m += embian.o

embian-y := \
	src/embian.o \
	src/symbols.o \
	src/control.o \
	src/patch_memory.o \
	src/prctl.o \
	src/netlink.o \
	src/binder.o

ccflags-y += -I$(src)/src
ccflags-y += -I$(src)/include
ccflags-y += -I$(srctree)/drivers/android

# Do not globally disable CFI/KCFI. Functions that call runtime-resolved
# symbols must use EMBIAN_NOCFI so module init/exit keep kernel-expected types.
