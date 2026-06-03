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

#include <linux/cgroup.h>
#include <linux/errno.h>
#include <linux/freezer.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/printk.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/jobctl.h>
#include <linux/slab.h>
#include <linux/uidgid.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <trace/hooks/binder.h>
#include <binder_alloc.h>
#include <binder_internal.h>
#include <uapi/linux/android/binder.h>

#include "embian.h"

typedef long (*embian_copy_from_user_nofault_fn)(void *dst,
						 const void __user *src,
						 size_t size);
typedef void (*embian_binder_transaction_buffer_release_fn)(
	struct binder_proc *proc, struct binder_thread *thread,
	struct binder_buffer *buffer, binder_size_t off_end_offset,
	bool is_failure);
typedef void (*embian_binder_alloc_free_buf_fn)(struct binder_alloc *alloc,
						struct binder_buffer *buffer);

static bool embian_binder_cleanup_registered;
static struct kprobe embian_binder_proc_transaction_kp;

static void embian_binder_resolve_symbols(void)
{
	static const enum embian_symbol_id ids[] = {
		EMBIAN_SYM_BINDER_TRANSACTION,
		EMBIAN_SYM_BINDER_PROC_TRANSACTION,
		EMBIAN_SYM_BINDER_TRANSACTION_BUFFER_RELEASE,
		EMBIAN_SYM_BINDER_ALLOC_FREE_BUF,
		EMBIAN_SYM_BINDER_STATS,
	};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(ids); i++)
		(void)embian_symbol_addr(ids[i]);
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

static void embian_binder_inner_proc_lock(struct binder_proc *proc)
__acquires(&proc->inner_lock)
{
	spin_lock(&proc->inner_lock);
}

static void embian_binder_inner_proc_unlock(struct binder_proc *proc)
__releases(&proc->inner_lock)
{
	spin_unlock(&proc->inner_lock);
}

static void embian_binder_node_lock(struct binder_node *node)
__acquires(&node->lock)
{
	spin_lock(&node->lock);
}

static void embian_binder_node_unlock(struct binder_node *node)
__releases(&node->lock)
{
	spin_unlock(&node->lock);
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

static bool embian_binder_can_replace_async(struct binder_transaction *queued,
					    struct binder_transaction *incoming)
{
	struct binder_buffer *queued_buffer;
	struct binder_buffer *incoming_buffer;
	struct binder_node *queued_node;
	struct binder_node *incoming_node;

	if (!queued || !incoming)
		return false;

	if ((queued->flags & incoming->flags & TF_ONE_WAY) != TF_ONE_WAY)
		return false;

	if (!queued->to_proc || !incoming->to_proc ||
	    queued->to_proc->tsk != incoming->to_proc->tsk)
		return false;

	if (queued->code != incoming->code || queued->flags != incoming->flags)
		return false;

	queued_buffer = queued->buffer;
	incoming_buffer = incoming->buffer;
	if (!queued_buffer || !incoming_buffer)
		return false;

	queued_node = queued_buffer->target_node;
	incoming_node = incoming_buffer->target_node;
	if (!queued_node || !incoming_node)
		return false;

	return queued_buffer->pid == incoming_buffer->pid &&
	       queued_node->ptr == incoming_node->ptr &&
	       queued_node->cookie == incoming_node->cookie;
}

static struct binder_transaction *embian_binder_find_stale_async_locked(
	struct binder_transaction *incoming, struct list_head *target_list)
{
	struct binder_work *work;
	bool kept_first = false;

	list_for_each_entry(work, target_list, entry) {
		struct binder_transaction *queued;

		if (work->type != BINDER_WORK_TRANSACTION)
			continue;

		queued = container_of(work, struct binder_transaction, work);
		if (!embian_binder_can_replace_async(queued, incoming))
			continue;

		if (kept_first)
			return queued;
		kept_first = true;
	}

	return NULL;
}

static void embian_binder_send_event(const struct embian_binder_event *event)
{
	if (!embian_control_has_client())
		return;

	(void)embian_netlink_send_payload(EMBIAN_NL_MSG_EVENT, 0, 0, 0,
					  event, sizeof(*event));
}

static void embian_binder_send_cleanup_event(struct binder_proc *proc,
					     struct binder_transaction *incoming,
					     struct binder_buffer *buffer)
{
	struct embian_binder_event event = {
		.event_type = EMBIAN_EVENT_BINDER_ASYNC_CLEANUP,
		.binder_flags = EMBIAN_BINDER_EVENT_FLAG_TARGET_FROZEN |
				TF_ONE_WAY,
	};

	if (!proc || !incoming || !buffer)
		return;

	event.from_pid = task_tgid_nr(current);
	event.from_uid = __kuid_val(current_uid());
	event.target_pid = proc->pid;
	event.target_uid = embian_task_uid_value(proc->tsk);
	event.code = incoming->code;
	event.data_size = (u32)min_t(size_t, buffer->data_size, U32_MAX);
	event.offsets_size = (u32)min_t(size_t, buffer->offsets_size, U32_MAX);

	embian_binder_send_event(&event);
}

static void EMBIAN_NOCFI embian_binder_release_stale_transaction(
	struct binder_proc *proc, struct binder_transaction *incoming,
	struct binder_transaction *stale)
{
	embian_binder_transaction_buffer_release_fn release_buffer;
	embian_binder_alloc_free_buf_fn free_buffer;
	struct binder_stats *stats;
	struct binder_buffer *buffer;
	binder_size_t off_end_offset;

	if (!proc || !stale || !stale->buffer)
		return;

	release_buffer = (embian_binder_transaction_buffer_release_fn)
		embian_symbol_addr(EMBIAN_SYM_BINDER_TRANSACTION_BUFFER_RELEASE);
	free_buffer = (embian_binder_alloc_free_buf_fn)
		embian_symbol_addr(EMBIAN_SYM_BINDER_ALLOC_FREE_BUF);
	stats = (struct binder_stats *)embian_symbol_addr(EMBIAN_SYM_BINDER_STATS);
	if (!release_buffer || !free_buffer || !stats)
		return;

	buffer = stale->buffer;
	embian_binder_send_cleanup_event(proc, incoming, buffer);
	stale->buffer = NULL;
	buffer->transaction = NULL;
	off_end_offset = ALIGN(buffer->data_size, sizeof(void *));
	off_end_offset += buffer->offsets_size;

	release_buffer(proc, NULL, buffer, off_end_offset, false);
	free_buffer(&proc->alloc, buffer);
	atomic_inc(&stats->obj_deleted[BINDER_STAT_TRANSACTION]);
	kfree(stale);
}

static bool embian_binder_cleanup_candidate(struct binder_transaction *incoming,
					    struct binder_proc *proc,
					    struct binder_thread *thread)
{
	if (!embian_control_has_client())
		return false;

	if (!incoming || !proc || thread)
		return false;

	if (!(incoming->flags & TF_ONE_WAY))
		return false;

	if (!proc->tsk || !embian_uid_is_app(embian_task_uid_value(proc->tsk)))
		return false;

	if (!embian_task_is_frozen(proc->tsk))
		return false;

	if (!incoming->buffer || !incoming->buffer->target_node)
		return false;

	return true;
}

static void embian_binder_cleanup_async(struct binder_transaction *incoming,
					struct binder_proc *proc,
					struct binder_thread *thread)
{
	struct binder_transaction *stale = NULL;
	struct binder_node *node;

	if (!embian_binder_cleanup_candidate(incoming, proc, thread))
		return;

	node = incoming->buffer->target_node;
	embian_binder_node_lock(node);
	if (!node->has_async_transaction) {
		embian_binder_node_unlock(node);
		return;
	}

	embian_binder_inner_proc_lock(proc);
	if (!proc->is_dead) {
		stale = embian_binder_find_stale_async_locked(incoming,
							      &node->async_todo);
		if (stale) {
			list_del_init(&stale->work.entry);
			if (proc->outstanding_txns > 0)
				proc->outstanding_txns--;
			else
				pr_warn("async cleanup saw empty outstanding_txns for pid=%d\n",
					proc->pid);
		}
	}
	embian_binder_inner_proc_unlock(proc);
	embian_binder_node_unlock(node);

	if (stale)
		embian_binder_release_stale_transaction(proc, incoming, stale);
}

static int embian_binder_proc_transaction_pre(struct kprobe *kp,
					      struct pt_regs *regs)
{
#if defined(__aarch64__)
	struct binder_transaction *incoming;
	struct binder_proc *proc;
	struct binder_thread *thread;

	incoming = (struct binder_transaction *)regs->regs[0];
	proc = (struct binder_proc *)regs->regs[1];
	thread = (struct binder_thread *)regs->regs[2];
	embian_binder_cleanup_async(incoming, proc, thread);
#endif
	return 0;
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

static long EMBIAN_NOCFI embian_binder_copy_from_user_nofault(
	void *dst, const void __user *src, size_t size)
{
	embian_copy_from_user_nofault_fn fn;

	fn = (embian_copy_from_user_nofault_fn)
		embian_symbol_addr(EMBIAN_SYM_COPY_FROM_USER_NOFAULT);
	if (!fn)
		return -ENOENT;

	return fn(dst, src, size);
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

	if (embian_binder_copy_from_user_nofault(raw, user, copy_len)) {
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

static void embian_binder_alloc_pressure_event(size_t size,
					       struct binder_alloc *alloc,
					       size_t free_async_space,
					       int is_async, const bool *should_fail)
{
	struct task_struct *target;
	struct embian_binder_event event = {
		.event_type = EMBIAN_EVENT_BINDER_ASYNC_PRESSURE,
		.binder_flags = EMBIAN_BINDER_EVENT_FLAG_TARGET_FROZEN,
		.requested_size = (u32)min_t(size_t, size, U32_MAX),
	};

	if (!embian_control_has_client())
		return;

	if (!is_async || !alloc)
		return;

	event.target_pid = alloc->pid;
	event.free_async_space = (u32)min_t(size_t, free_async_space,
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
static void embian_binder_alloc_new_buf_locked(void *data, size_t size,
					       size_t *free_async_space,
					       int is_async, bool *should_fail)
{
	struct binder_alloc *alloc;

	if (!free_async_space)
		return;

	alloc = container_of(free_async_space, struct binder_alloc,
			     free_async_space);
	embian_binder_alloc_pressure_event(size, alloc, *free_async_space,
					   is_async, should_fail);
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
static void embian_binder_alloc_new_buf_locked(void *data, size_t size,
					       size_t *free_async_space,
					       int is_async)
{
	struct binder_alloc *alloc;

	if (!free_async_space)
		return;

	alloc = container_of(free_async_space, struct binder_alloc,
			     free_async_space);
	embian_binder_alloc_pressure_event(size, alloc, *free_async_space,
					   is_async, NULL);
}
#else
static void embian_binder_alloc_new_buf_locked(void *data, size_t size,
					       struct binder_alloc *alloc,
					       int is_async)
{
	embian_binder_alloc_pressure_event(size, alloc,
					   alloc ? alloc->free_async_space : 0,
					   is_async, NULL);
}
#endif

static void embian_binder_cleanup_exit(void)
{
	if (!embian_binder_cleanup_registered)
		return;

	unregister_kprobe(&embian_binder_proc_transaction_kp);
	embian_binder_cleanup_registered = false;
	pr_info("async cleanup hook unregistered\n");
}

static void embian_binder_cleanup_init(void)
{
	int ret;

	if (!embian_symbol_addr(EMBIAN_SYM_BINDER_PROC_TRANSACTION)) {
		pr_warn("binder_proc_transaction unavailable; async cleanup disabled\n");
		return;
	}

	embian_binder_proc_transaction_kp.symbol_name = "binder_proc_transaction";
	embian_binder_proc_transaction_kp.pre_handler =
		embian_binder_proc_transaction_pre;
	ret = register_kprobe(&embian_binder_proc_transaction_kp);
	if (ret) {
		pr_warn("register binder_proc_transaction cleanup hook failed: %d\n",
			ret);
		return;
	}

	embian_binder_cleanup_registered = true;
	pr_info("async cleanup hook registered\n");
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

	embian_binder_cleanup_init();
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
	embian_binder_cleanup_exit();
	unregister_trace_android_vh_binder_alloc_new_buf_locked(
		embian_binder_alloc_new_buf_locked, NULL);
	unregister_trace_android_vh_binder_reply(embian_binder_reply, NULL);
	unregister_trace_android_vh_binder_trans(embian_binder_trans, NULL);
	pr_info("vendor hook monitor exited\n");
}
