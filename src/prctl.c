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
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/srcu.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "embian.h"

#ifndef EMBIAN_PRCTL_ALLOW_ROOT_CALLER
#define EMBIAN_PRCTL_ALLOW_ROOT_CALLER 1
#endif

#define EMBIAN_PRCTL_SYSTEM_SERVER_COMM "system_server"
#define EMBIAN_PRCTL_SYSTEM_SERVER_CTX "u:r:system_server:s0"

typedef long (*embian_syscall_fn)(const struct pt_regs *regs);
typedef void (*embian_security_current_getsecid_subj_fn)(u32 *secid);
typedef void (*embian_security_cred_getsecid_fn)(const struct cred *cred,
						 u32 *secid);

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

static bool embian_prctl_secctx_equals(const char *secctx, u32 seclen,
				       const char *expected)
{
	size_t expected_len = strlen(expected);

	if (!secctx)
		return false;

	if (seclen == expected_len)
		return !memcmp(secctx, expected, expected_len);

	if (seclen == expected_len + 1 && secctx[expected_len] == '\0')
		return !memcmp(secctx, expected, expected_len);

	return false;
}

static void EMBIAN_NOCFI embian_prctl_current_getsecid(u32 *secid)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	embian_security_current_getsecid_subj_fn fn;

	fn = (embian_security_current_getsecid_subj_fn)
		embian_symbol_addr(EMBIAN_SYM_SECURITY_CURRENT_GETSECID_SUBJ);
#else
	embian_security_cred_getsecid_fn fn;

	fn = (embian_security_cred_getsecid_fn)
		embian_symbol_addr(EMBIAN_SYM_SECURITY_CRED_GETSECID);
#endif
	if (!fn)
		return;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	fn(secid);
#else
	fn(current_cred(), secid);
#endif
}

static bool embian_prctl_current_selinux_allowed(void)
{
	char *secctx = NULL;
	u32 seclen = 0;
	u32 secid = 0;
	bool allowed;

	embian_prctl_current_getsecid(&secid);
	if (!secid)
		return false;

	if (security_secid_to_secctx(secid, &secctx, &seclen))
		return false;

	allowed = embian_prctl_secctx_equals(secctx, seclen,
					     EMBIAN_PRCTL_SYSTEM_SERVER_CTX);
	security_release_secctx(secctx, seclen);
	return allowed;
}

static bool embian_prctl_current_comm_allowed(void)
{
	return strncmp(current->comm, EMBIAN_PRCTL_SYSTEM_SERVER_COMM,
		       TASK_COMM_LEN) == 0;
}

static bool embian_prctl_current_root_allowed(void)
{
#if EMBIAN_PRCTL_ALLOW_ROOT_CALLER
	return uid_eq(current_uid(), GLOBAL_ROOT_UID) ||
	       uid_eq(current_euid(), GLOBAL_ROOT_UID);
#else
	return false;
#endif
}

static bool embian_prctl_current_allowed(void)
{
	if (embian_prctl_current_root_allowed())
		return true;

	return embian_prctl_current_comm_allowed() &&
	       embian_prctl_current_selinux_allowed();
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

	if (magic == EMBIAN_PRCTL_MAGIC && embian_prctl_current_allowed())
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

	embian_sys_call_table =
		(void **)embian_symbol_addr(EMBIAN_SYM_SYS_CALL_TABLE);
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

static void embian_prctl_remove_hook(void)
{
	embian_syscall_fn orig;

	if (!embian_prctl_tsr_registered || !embian_sys_call_table ||
	    !embian_orig_prctl)
		return;

	orig = embian_orig_prctl;
	(void)embian_patch_text(&embian_sys_call_table[__NR_prctl], &orig,
				sizeof(orig));
	embian_prctl_tsr_registered = false;
	synchronize_srcu(&embian_prctl_srcu);
	pr_info("TSR hook unregistered\n");
}

bool embian_prctl_is_armed(void)
{
	return READ_ONCE(embian_prctl_tsr_registered);
}

int embian_prctl_disarm(void)
{
	if (!embian_prctl_is_armed())
		return -EALREADY;

	embian_prctl_remove_hook();
	return 0;
}

void embian_prctl_exit(void)
{
	embian_prctl_remove_hook();
	embian_orig_prctl = NULL;
	embian_sys_call_table = NULL;
}
