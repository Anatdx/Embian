/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Embian - Signal monitor scaffold.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */

#define pr_fmt(fmt) "embian: signal: " fmt

#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/uidgid.h>
#include <trace/hooks/signal.h>

#include "embian.h"

static bool embian_signal_registered;

static bool embian_signal_of_interest(int sig)
{
	switch (sig) {
	case SIGKILL:
	case SIGTERM:
	case SIGABRT:
	case SIGQUIT:
		return true;
	default:
		return false;
	}
}

static void embian_signal_do_send_sig_info(void *data, int sig,
					   struct task_struct *killer,
					   struct task_struct *dst)
{
	struct embian_signal_event event = {
		.event_type = EMBIAN_EVENT_SIGNAL,
	};

	if (!embian_control_has_client())
		return;

	if (!killer || !dst)
		return;

	if (!embian_signal_of_interest(sig))
		return;

	if (!embian_task_is_frozen(dst))
		return;

	event.signo = sig;
	event.killer_pid = task_tgid_nr(killer);
	event.killer_uid = embian_task_uid_value(killer);
	event.dst_pid = task_tgid_nr(dst);
	event.dst_uid = embian_task_uid_value(dst);

	(void)embian_netlink_send_payload(EMBIAN_NL_MSG_EVENT, 0, 0, 0,
					  &event, sizeof(event));
}

int embian_signal_init(void)
{
	int ret;

	ret = register_trace_android_vh_do_send_sig_info(
		embian_signal_do_send_sig_info, NULL);
	if (ret) {
		pr_warn("register do_send_sig_info hook failed: %d\n", ret);
		return 0;
	}

	embian_signal_registered = true;
	pr_info("vendor hook monitor initialized\n");
	return 0;
}

void embian_signal_exit(void)
{
	if (!embian_signal_registered)
		return;

	unregister_trace_android_vh_do_send_sig_info(
		embian_signal_do_send_sig_info, NULL);
	embian_signal_registered = false;
	pr_info("vendor hook monitor exited\n");
}
