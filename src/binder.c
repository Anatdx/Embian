/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Embian - Binder monitor scaffold.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */

#define pr_fmt(fmt) "embian: binder: " fmt

#include <linux/container_of.h>
#include <linux/cgroup.h>
#include <linux/freezer.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/jobctl.h>
#include <linux/uidgid.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <trace/hooks/binder.h>
#include <binder_alloc.h>
#include <binder_internal.h>
#include <uapi/linux/android/binder.h>

#include "embian.h"

struct embian_binder_symbol {
	const char *name;
	unsigned long addr;
	bool required;
};

static struct embian_binder_symbol embian_binder_symbols[] = {
	{ "binder_transaction", 0, false },
	{ "binder_proc_transaction", 0, false },
	{ "binder_transaction_buffer_release", 0, false },
	{ "binder_alloc_free_buf", 0, false },
	{ "binder_stats", 0, false },
};

static void embian_binder_resolve_symbols(void)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(embian_binder_symbols); i++) {
		struct embian_binder_symbol *symbol = &embian_binder_symbols[i];

		symbol->addr = embian_lookup_name_quiet(symbol->name);
		if (symbol->addr) {
			pr_info("resolved %s @ 0x%lx\n", symbol->name,
				symbol->addr);
		} else if (symbol->required) {
			pr_warn("required symbol missing: %s\n", symbol->name);
		} else {
			pr_debug("optional symbol missing: %s\n", symbol->name);
		}
	}
}

static u32 embian_task_uid_value(const struct task_struct *task)
{
	if (!task)
		return 0;

	return __kuid_val(task_uid((struct task_struct *)task));
}

static bool embian_task_frozen_state(const struct task_struct *task)
{
	if (!task)
		return false;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	return READ_ONCE(task->__state) & TASK_FROZEN;
#else
	return frozen((struct task_struct *)task);
#endif
}

static bool embian_task_jobctl_frozen(const struct task_struct *task)
{
	if (!task)
		return false;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(5, 10, 0)
	return cgroup_task_freeze((struct task_struct *)task);
#else
	return READ_ONCE(task->jobctl) & JOBCTL_TRAP_FREEZE;
#endif
}

static bool embian_task_is_frozen(const struct task_struct *task)
{
	const struct task_struct *leader;

	if (!task)
		return false;

	if (cgroup_task_frozen((struct task_struct *)task) ||
	    embian_task_jobctl_frozen(task))
		return true;

	leader = READ_ONCE(task->group_leader);
	if (!leader)
		return true;

	return embian_task_frozen_state(leader) ||
	       freezing((struct task_struct *)leader);
}

static bool embian_uid_is_app(u32 uid)
{
	return uid >= EMBIAN_ANDROID_APP_UID_MIN;
}

static bool embian_uid_is_system(u32 uid)
{
	return uid <= EMBIAN_ANDROID_SYSTEM_UID_MAX;
}

static bool embian_binder_common_allowed(struct binder_proc *target_proc,
					 struct binder_proc *proc,
					 struct binder_transaction_data *tr,
					 u32 *from_uid, u32 *target_uid)
{
	if (!embian_control_has_client())
		return false;

	if (!target_proc || !proc || !tr)
		return false;

	if (!target_proc->tsk || !proc->tsk)
		return false;

	if (proc->pid == target_proc->pid)
		return false;

	*from_uid = embian_task_uid_value(proc->tsk);
	*target_uid = embian_task_uid_value(target_proc->tsk);

	if (*from_uid == *target_uid)
		return false;

	return embian_task_is_frozen(target_proc->tsk);
}

static void embian_binder_send_event(const struct embian_binder_event *event)
{
	if (!embian_control_has_client())
		return;

	(void)embian_netlink_send_payload(EMBIAN_NL_MSG_EVENT, 0, 0, 0,
					  event, sizeof(*event));
}

static void embian_binder_decode_utf16_ascii(struct embian_binder_event *event,
					     const u8 *raw, size_t raw_len)
{
	size_t raw_pos;
	size_t out = 0;

	for (raw_pos = 0; raw_pos + 1 < raw_len &&
			  out + 1 < sizeof(event->interface_token);
	     raw_pos += 2) {
		u16 ch = raw[raw_pos] | ((u16)raw[raw_pos + 1] << 8);

		if (!ch)
			break;

		event->interface_token[out++] = ch <= 0x7f ? (char)ch : '?';
	}

	if (!out)
		return;

	event->interface_token[out] = '\0';
	event->interface_len = (u32)out;
	event->binder_flags |= EMBIAN_BINDER_EVENT_FLAG_INTERFACE;

	if (raw_pos + 1 < raw_len && out + 1 >= sizeof(event->interface_token))
		event->binder_flags |=
			EMBIAN_BINDER_EVENT_FLAG_INTERFACE_TRUNCATED;
}

static void embian_binder_parse_interface(struct embian_binder_event *event,
					  struct binder_transaction_data *tr)
{
	u8 raw[EMBIAN_BINDER_INTERFACE_MAX * 2];
	const void __user *user;
	size_t copy_len;

	if (!event || !tr)
		return;

	if (tr->data_size <= EMBIAN_BINDER_INTERFACE_TOKEN_OFFSET)
		return;

	user = (const void __user *)((uintptr_t)tr->data.ptr.buffer +
				    EMBIAN_BINDER_INTERFACE_TOKEN_OFFSET);
	copy_len = min_t(binder_size_t,
			 tr->data_size - EMBIAN_BINDER_INTERFACE_TOKEN_OFFSET,
			 sizeof(raw));
	if (!copy_len)
		return;

	if (copy_from_user_nofault(raw, user, copy_len)) {
		event->binder_flags |=
			EMBIAN_BINDER_EVENT_FLAG_INTERFACE_COPY_FAILED;
		return;
	}

	embian_binder_decode_utf16_ascii(event, raw, copy_len);
}

static void embian_binder_transaction_event(u32 event_type,
					    struct binder_proc *target_proc,
					    struct binder_proc *proc,
					    struct binder_transaction_data *tr)
{
	struct embian_binder_event event = {
		.event_type = event_type,
		.binder_flags = EMBIAN_BINDER_EVENT_FLAG_TARGET_FROZEN,
	};
	u32 from_uid;
	u32 target_uid;
	bool oneway;

	if (!embian_binder_common_allowed(target_proc, proc, tr, &from_uid,
					  &target_uid))
		return;

	oneway = tr->flags & TF_ONE_WAY;

	if (event_type == EMBIAN_EVENT_BINDER_TRANSACTION) {
		if (!embian_uid_is_app(target_uid))
			return;
	} else if (event_type == EMBIAN_EVENT_BINDER_REPLY) {
		if (!embian_uid_is_system(target_uid))
			return;
	}

	event.from_pid = proc->pid;
	event.from_uid = from_uid;
	event.target_pid = target_proc->pid;
	event.target_uid = target_uid;
	event.binder_flags |= tr->flags;
	event.code = tr->code;
	event.data_size = (u32)min_t(binder_size_t, tr->data_size, U32_MAX);
	event.offsets_size = (u32)min_t(binder_size_t, tr->offsets_size,
					U32_MAX);

	if (event_type == EMBIAN_EVENT_BINDER_TRANSACTION && oneway &&
	    (tr->code < 29 || tr->code > 32))
		return;

	if (event_type == EMBIAN_EVENT_BINDER_TRANSACTION)
		embian_binder_parse_interface(&event, tr);

	embian_binder_send_event(&event);
}

static void embian_binder_trans(void *data, struct binder_proc *target_proc,
				struct binder_proc *proc,
				struct binder_thread *thread,
				struct binder_transaction_data *tr)
{
	embian_binder_transaction_event(EMBIAN_EVENT_BINDER_TRANSACTION,
					target_proc, proc, tr);
}

static void embian_binder_reply(void *data, struct binder_proc *target_proc,
				struct binder_proc *proc,
				struct binder_thread *thread,
				struct binder_transaction_data *tr)
{
	embian_binder_transaction_event(EMBIAN_EVENT_BINDER_REPLY, target_proc,
					proc, tr);
}

static void embian_binder_alloc_new_buf_locked(void *data, size_t size,
					       size_t *free_async_space,
					       int is_async, bool *should_fail)
{
	struct binder_alloc *alloc;
	struct task_struct *target;
	struct embian_binder_event event = {
		.event_type = EMBIAN_EVENT_BINDER_ASYNC_PRESSURE,
		.binder_flags = EMBIAN_BINDER_EVENT_FLAG_TARGET_FROZEN,
		.requested_size = (u32)min_t(size_t, size, U32_MAX),
	};

	if (!embian_control_has_client())
		return;

	if (!is_async || !free_async_space)
		return;

	alloc = container_of(free_async_space, struct binder_alloc,
			     free_async_space);
	event.target_pid = alloc->pid;
	event.free_async_space = (u32)min_t(size_t, *free_async_space,
					   U32_MAX);

	if (!should_fail && event.free_async_space >= EMBIAN_BINDER_ASYNC_WARN_SPACE)
		return;

	if (should_fail && !*should_fail &&
	    event.free_async_space >= EMBIAN_BINDER_ASYNC_WARN_SPACE)
		return;

	if (should_fail && *should_fail)
		event.binder_flags |= EMBIAN_BINDER_EVENT_FLAG_SHOULD_FAIL;

	rcu_read_lock();
	target = find_task_by_vpid(alloc->pid);
	if (!target || !embian_task_is_frozen(target)) {
		rcu_read_unlock();
		return;
	}
	event.target_uid = embian_task_uid_value(target);
	rcu_read_unlock();

	if (!embian_uid_is_app(event.target_uid))
		return;

	embian_binder_send_event(&event);
}

int embian_binder_init(void)
{
	int ret;

	embian_binder_resolve_symbols();

	ret = register_trace_android_vh_binder_trans(embian_binder_trans, NULL);
	if (ret) {
		pr_warn("register binder_trans hook failed: %d\n", ret);
		return ret;
	}

	ret = register_trace_android_vh_binder_reply(embian_binder_reply, NULL);
	if (ret) {
		pr_warn("register binder_reply hook failed: %d\n", ret);
		goto err_trans;
	}

	ret = register_trace_android_vh_binder_alloc_new_buf_locked(
		embian_binder_alloc_new_buf_locked, NULL);
	if (ret) {
		pr_warn("register binder_alloc_new_buf_locked hook failed: %d\n",
			ret);
		goto err_reply;
	}

	pr_info("vendor hook monitor initialized\n");
	return 0;

err_reply:
	unregister_trace_android_vh_binder_reply(embian_binder_reply, NULL);
err_trans:
	unregister_trace_android_vh_binder_trans(embian_binder_trans, NULL);
	return ret;
}

void embian_binder_exit(void)
{
	unregister_trace_android_vh_binder_alloc_new_buf_locked(
		embian_binder_alloc_new_buf_locked, NULL);
	unregister_trace_android_vh_binder_reply(embian_binder_reply, NULL);
	unregister_trace_android_vh_binder_trans(embian_binder_trans, NULL);
	pr_info("vendor hook monitor exited\n");
}
