/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Embian - Runtime kernel symbol resolution.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */

#define pr_fmt(fmt) "embian: symbols: " fmt

#include <linux/err.h>
#include <linux/kprobes.h>
#include <linux/printk.h>

#include "embian.h"

typedef unsigned long (*embian_kallsyms_lookup_name_t)(const char *name);

static embian_kallsyms_lookup_name_t embian_kallsyms_lookup_name;

static bool embian_valid_symbol_addr(unsigned long addr)
{
	return addr && !IS_ERR_VALUE(addr);
}

static unsigned long embian_kprobe_lookup(const char *name, bool quiet)
{
	struct kprobe kp = {
		.symbol_name = name,
	};
	unsigned long addr;
	int ret;

	ret = register_kprobe(&kp);
	if (ret) {
		if (!quiet)
			pr_warn("kprobe lookup failed for %s: %d\n", name, ret);
		return 0;
	}

	addr = (unsigned long)kp.addr;
	unregister_kprobe(&kp);

	if (!embian_valid_symbol_addr(addr)) {
		if (!quiet)
			pr_warn("invalid address for %s: 0x%lx\n", name, addr);
		return 0;
	}

	return addr;
}

int embian_symbols_init(void)
{
	unsigned long addr;

	addr = embian_kprobe_lookup("kallsyms_lookup_name", true);
	if (!addr) {
		pr_warn("kallsyms_lookup_name unavailable, falling back to per-symbol kprobe\n");
		return 0;
	}

	embian_kallsyms_lookup_name = (embian_kallsyms_lookup_name_t)addr;
	pr_info("kallsyms_lookup_name resolved @ 0x%lx\n", addr);
	return 0;
}

void embian_symbols_exit(void)
{
	embian_kallsyms_lookup_name = NULL;
}

EMBIAN_NOCFI unsigned long embian_lookup_name_quiet(const char *name)
{
	unsigned long addr;

	if (!name)
		return 0;

	if (embian_kallsyms_lookup_name) {
		addr = embian_kallsyms_lookup_name(name);
		if (embian_valid_symbol_addr(addr))
			return addr;
	}

	return embian_kprobe_lookup(name, true);
}

EMBIAN_NOCFI unsigned long embian_lookup_name(const char *name)
{
	unsigned long addr;

	if (!name)
		return 0;

	addr = embian_lookup_name_quiet(name);
	if (!addr)
		pr_warn("symbol not found: %s\n", name);

	return addr;
}
