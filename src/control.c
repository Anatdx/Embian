/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Embian - Hidden user-space control registration.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */

#define pr_fmt(fmt) "embian: control: " fmt

#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/uidgid.h>

#include "embian.h"

struct embian_control_client {
	bool active;
	pid_t tgid;
	kuid_t uid;
	u32 portid;
};

static DEFINE_MUTEX(embian_control_lock);
static struct embian_control_client embian_client;

int embian_control_init(void)
{
	mutex_lock(&embian_control_lock);
	WRITE_ONCE(embian_client.active, false);
	WRITE_ONCE(embian_client.tgid, 0);
	WRITE_ONCE(embian_client.portid, 0);
	embian_client.uid = GLOBAL_ROOT_UID;
	mutex_unlock(&embian_control_lock);

	pr_info("initialized prctl ABI option=0x%x magic=0x%x version=%u\n",
		EMBIAN_PRCTL_OPTION, EMBIAN_PRCTL_MAGIC,
		EMBIAN_CTL_ABI_VERSION);
	return 0;
}

void embian_control_exit(void)
{
	mutex_lock(&embian_control_lock);
	WRITE_ONCE(embian_client.active, false);
	WRITE_ONCE(embian_client.tgid, 0);
	WRITE_ONCE(embian_client.portid, 0);
	mutex_unlock(&embian_control_lock);
}

int embian_control_register_current(u32 portid, u32 magic)
{
	return embian_control_register(portid, magic, current->tgid,
				       current_uid());
}

int embian_control_register(u32 portid, u32 magic, pid_t tgid, kuid_t uid)
{
	if (magic != EMBIAN_PRCTL_MAGIC)
		return -EINVAL;

	if (!portid)
		return -EINVAL;

	mutex_lock(&embian_control_lock);
	WRITE_ONCE(embian_client.tgid, tgid);
	embian_client.uid = uid;
	WRITE_ONCE(embian_client.portid, portid);
	WRITE_ONCE(embian_client.active, true);
	mutex_unlock(&embian_control_lock);

	pr_info("registered client tgid=%d portid=%u uid=%u\n",
		tgid, portid, __kuid_val(uid));
	return 0;
}

void embian_control_detach_current(void)
{
	mutex_lock(&embian_control_lock);
	if (READ_ONCE(embian_client.active) &&
	    READ_ONCE(embian_client.tgid) == current->tgid) {
		pr_info("detached client tgid=%d\n",
			READ_ONCE(embian_client.tgid));
		WRITE_ONCE(embian_client.active, false);
		WRITE_ONCE(embian_client.tgid, 0);
		WRITE_ONCE(embian_client.portid, 0);
	}
	mutex_unlock(&embian_control_lock);
}

void embian_control_detach_portid(u32 portid)
{
	mutex_lock(&embian_control_lock);
	if (READ_ONCE(embian_client.active) &&
	    READ_ONCE(embian_client.portid) == portid) {
		pr_info("detached client portid=%u tgid=%d\n", portid,
			READ_ONCE(embian_client.tgid));
		WRITE_ONCE(embian_client.active, false);
		WRITE_ONCE(embian_client.tgid, 0);
		WRITE_ONCE(embian_client.portid, 0);
	}
	mutex_unlock(&embian_control_lock);
}

bool embian_control_has_client(void)
{
	return READ_ONCE(embian_client.active);
}

u32 embian_control_portid(void)
{
	if (!READ_ONCE(embian_client.active))
		return 0;

	return READ_ONCE(embian_client.portid);
}

void embian_control_get_snapshot(struct embian_control_snapshot *snapshot)
{
	if (!snapshot)
		return;

	mutex_lock(&embian_control_lock);
	snapshot->active = READ_ONCE(embian_client.active);
	snapshot->tgid = READ_ONCE(embian_client.tgid);
	snapshot->uid = embian_client.uid;
	snapshot->portid = READ_ONCE(embian_client.portid);
	mutex_unlock(&embian_control_lock);
}
