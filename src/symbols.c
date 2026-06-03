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

struct embian_symbol_entry {
	const char *primary;
	const char *fallback;
	unsigned long addr;
	bool looked_up;
	bool required;
};

static struct embian_symbol_entry embian_symbol_table[EMBIAN_SYM_COUNT] = {
	[EMBIAN_SYM_SYS_CALL_TABLE] = {
		.primary = "sys_call_table",
		.required = true,
	},
	[EMBIAN_SYM_INIT_MM] = {
		.primary = "init_mm",
		.required = true,
	},
	[EMBIAN_SYM_SET_FIXMAP] = {
		.primary = "__set_fixmap",
		.fallback = "set_fixmap",
		.required = true,
	},
	[EMBIAN_SYM_DCACHE_CLEAN_INVAL_POC] = {
		.primary = "dcache_clean_inval_poc",
	},
	[EMBIAN_SYM_FLUSH_DCACHE_AREA] = {
		.primary = "__flush_dcache_area",
	},
	[EMBIAN_SYM_CACHES_CLEAN_INVAL_POU] = {
		.primary = "caches_clean_inval_pou",
	},
	[EMBIAN_SYM_BINDER_TRANSACTION] = {
		.primary = "binder_transaction",
	},
	[EMBIAN_SYM_BINDER_PROC_TRANSACTION] = {
		.primary = "binder_proc_transaction",
	},
	[EMBIAN_SYM_BINDER_TRANSACTION_BUFFER_RELEASE] = {
		.primary = "binder_transaction_buffer_release",
	},
	[EMBIAN_SYM_BINDER_ALLOC_FREE_BUF] = {
		.primary = "binder_alloc_free_buf",
	},
	[EMBIAN_SYM_BINDER_STATS] = {
		.primary = "binder_stats",
	},
	[EMBIAN_SYM_COPY_FROM_USER_NOFAULT] = {
		.primary = "copy_from_user_nofault",
	},
	[EMBIAN_SYM_SECURITY_CURRENT_GETSECID_SUBJ] = {
		.primary = "security_current_getsecid_subj",
	},
	[EMBIAN_SYM_SECURITY_CRED_GETSECID] = {
		.primary = "security_cred_getsecid",
	},
};

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

unsigned long embian_lookup_name_any(const char * const *names, bool quiet)
{
	unsigned long addr;
	int i;

	if (!names)
		return 0;

	for (i = 0; names[i]; i++) {
		addr = embian_lookup_name_quiet(names[i]);
		if (addr)
			return addr;
	}

	if (!quiet)
		pr_warn("none of candidate symbols resolved\n");

	return 0;
}

int embian_symbols_init(void)
{
	unsigned long addr;
	size_t i;

	addr = embian_kprobe_lookup("kallsyms_lookup_name", true);
	if (!addr) {
		pr_warn("kallsyms_lookup_name unavailable, falling back to per-symbol kprobe\n");
		return 0;
	}

	embian_kallsyms_lookup_name = (embian_kallsyms_lookup_name_t)addr;
	pr_info("kallsyms_lookup_name resolved @ 0x%lx\n", addr);

	for (i = 0; i < ARRAY_SIZE(embian_symbol_table); i++) {
		embian_symbol_table[i].addr = 0;
		embian_symbol_table[i].looked_up = false;
	}

	return 0;
}

void embian_symbols_exit(void)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(embian_symbol_table); i++) {
		embian_symbol_table[i].addr = 0;
		embian_symbol_table[i].looked_up = false;
	}

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

const char *embian_symbol_name(enum embian_symbol_id id)
{
	if (id < 0 || id >= EMBIAN_SYM_COUNT)
		return NULL;

	return embian_symbol_table[id].primary;
}

unsigned long embian_symbol_addr(enum embian_symbol_id id)
{
	struct embian_symbol_entry *entry;
	const char *names[3];
	unsigned long addr;

	if (id < 0 || id >= EMBIAN_SYM_COUNT)
		return 0;

	entry = &embian_symbol_table[id];
	if (entry->looked_up)
		return entry->addr;

	names[0] = entry->primary;
	names[1] = entry->fallback;
	names[2] = NULL;
	addr = embian_lookup_name_any(names, !entry->required);
	entry->addr = addr;
	entry->looked_up = true;

	if (addr) {
		pr_info("resolved %s @ 0x%lx\n", entry->primary, addr);
	} else if (entry->required) {
		pr_warn("required symbol missing: %s\n", entry->primary);
	} else {
		pr_debug("optional symbol missing: %s\n", entry->primary);
	}

	return addr;
}
