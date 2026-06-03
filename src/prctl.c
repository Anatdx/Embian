/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Embian - Hidden prctl control hook.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */

#define pr_fmt(fmt) "embian: prctl: " fmt

#include <asm/ptrace.h>
#include <asm/unistd.h>
#include <linux/errno.h>
#include <linux/printk.h>
#include <linux/srcu.h>
#include <linux/uaccess.h>

#include "embian.h"

typedef long (*embian_syscall_fn)(const struct pt_regs *regs);

static void **embian_sys_call_table;
static embian_syscall_fn embian_orig_prctl;
static bool embian_prctl_tsr_registered;
DEFINE_STATIC_SRCU(embian_prctl_srcu);

static int embian_prctl_write_result(struct embian_prctl_args __user *uargs,
				     int status)
{
	struct embian_prctl_args args = {
		.status = status,
		.netlink_unit = embian_netlink_unit(),
		.abi_version = EMBIAN_CTL_ABI_VERSION,
	};
	struct embian_control_snapshot snapshot;

	if (!uargs)
		return -EINVAL;

	embian_control_get_snapshot(&snapshot);
	args.portid = snapshot.active ? snapshot.portid : 0;

	if (copy_to_user(uargs, &args, sizeof(args)))
		return -EFAULT;

	return 0;
}

static int embian_prctl_handle(unsigned long magic, unsigned long command,
			       unsigned long arg)
{
	struct embian_prctl_args __user *uargs;
	u32 portid;
	int ret;

	if (magic != EMBIAN_PRCTL_MAGIC)
		return -EINVAL;

	uargs = (struct embian_prctl_args __user *)arg;

	switch (command) {
	case EMBIAN_PRCTL_GET_NETLINK_UNIT:
		ret = 0;
		break;
	case EMBIAN_PRCTL_REGISTER_CLIENT:
		if (!uargs)
			return -EINVAL;
		if (get_user(portid, &uargs->portid))
			return -EFAULT;
		ret = embian_control_register_current(portid, magic);
		break;
	case EMBIAN_PRCTL_DETACH_CLIENT:
		embian_control_detach_current();
		ret = 0;
		break;
	default:
		ret = -EINVAL;
		break;
	}

	(void)embian_prctl_write_result(uargs, ret);
	return ret;
}

static long EMBIAN_NOCFI embian_call_orig_prctl(const struct pt_regs *regs)
{
	embian_syscall_fn orig = READ_ONCE(embian_orig_prctl);

	if (!orig)
		return -EINVAL;

	return orig(regs);
}

static long EMBIAN_NOCFI embian_prctl_tsr(const struct pt_regs *regs)
{
	unsigned long option;
	unsigned long magic;
	unsigned long command;
	unsigned long arg;
	long ret;
	int idx;

	idx = srcu_read_lock(&embian_prctl_srcu);

#if defined(__aarch64__)
	option = regs->regs[0];
	magic = regs->regs[1];
	command = regs->regs[2];
	arg = regs->regs[3];
#elif defined(__x86_64__)
	option = regs->di;
	magic = regs->si;
	command = regs->dx;
	arg = regs->cx;
#else
	ret = embian_call_orig_prctl(regs);
	goto out;
#endif

	if (option != EMBIAN_PRCTL_OPTION) {
		ret = embian_call_orig_prctl(regs);
		goto out;
	}

	if (magic == EMBIAN_PRCTL_MAGIC)
		(void)embian_prctl_handle(magic, command, arg);

	ret = -EINVAL;

out:
	srcu_read_unlock(&embian_prctl_srcu, idx);

	return ret;
}

int embian_prctl_init(void)
{
	embian_syscall_fn hook = embian_prctl_tsr;
	int ret;

	embian_sys_call_table = (void **)embian_lookup_name("sys_call_table");
	if (!embian_sys_call_table) {
		pr_warn("sys_call_table not found; prctl control unavailable\n");
		return 0;
	}

	embian_orig_prctl = (embian_syscall_fn)
		READ_ONCE(embian_sys_call_table[__NR_prctl]);
	if (!embian_orig_prctl) {
		pr_warn("original prctl syscall is NULL\n");
		return 0;
	}

	ret = embian_patch_text(&embian_sys_call_table[__NR_prctl],
				&hook, sizeof(hook));
	if (ret) {
		pr_warn("patch prctl syscall failed: %d\n", ret);
		embian_orig_prctl = NULL;
		return 0;
	}

	embian_prctl_tsr_registered = true;
	pr_info("registered prctl TSR hook table=%px orig=%px hook=%px\n",
		embian_sys_call_table, embian_orig_prctl, embian_prctl_tsr);
	return 0;
}

void embian_prctl_exit(void)
{
	if (embian_prctl_tsr_registered && embian_sys_call_table &&
	    embian_orig_prctl) {
		embian_syscall_fn orig = embian_orig_prctl;

		(void)embian_patch_text(&embian_sys_call_table[__NR_prctl],
					&orig, sizeof(orig));
		embian_prctl_tsr_registered = false;
		synchronize_srcu(&embian_prctl_srcu);
	}

	embian_orig_prctl = NULL;
	embian_sys_call_table = NULL;
}
