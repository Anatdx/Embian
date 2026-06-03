/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Embian - Shared task-state helpers (uid, freezer state).
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */

#define pr_fmt(fmt) "embian: task: " fmt

#include <linux/cgroup.h>
#include <linux/freezer.h>
#include <linux/sched.h>
#include <linux/sched/jobctl.h>
#include <linux/uidgid.h>
#include <linux/version.h>

#include "embian.h"

u32 embian_task_uid_value(const struct task_struct *task)
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

bool embian_task_is_frozen(const struct task_struct *task)
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
