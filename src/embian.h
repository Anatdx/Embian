/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Embian - Shared module definitions.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */

#ifndef EMBIAN_H
#define EMBIAN_H

#include <linux/types.h>
#include <linux/uidgid.h>

struct task_struct;

#include "uapi/embian_uapi.h"

#define EMBIAN_NAME "embian"
#define EMBIAN_VERSION "0.1.0-dev"

#if defined(__clang__)
#if __clang_major__ >= 17
#define EMBIAN_NOCFI __attribute__((no_sanitize("cfi", "kcfi")))
#else
#define EMBIAN_NOCFI __attribute__((no_sanitize("cfi")))
#endif
#else
#define EMBIAN_NOCFI
#endif

struct embian_control_snapshot {
	bool active;
	pid_t tgid;
	kuid_t uid;
	u32 portid;
};

int embian_control_init(void);
void embian_control_exit(void);
int embian_control_register_current(u32 portid, u32 magic);
int embian_control_register(u32 portid, u32 magic, pid_t tgid, kuid_t uid);
void embian_control_detach_current(void);
void embian_control_detach_portid(u32 portid);
bool embian_control_has_client(void);
u32 embian_control_portid(void);
void embian_control_get_snapshot(struct embian_control_snapshot *snapshot);

int embian_prctl_init(void);
void embian_prctl_exit(void);

u32 embian_task_uid_value(const struct task_struct *task);
bool embian_task_is_frozen(const struct task_struct *task);

int embian_symbols_init(void);
void embian_symbols_exit(void);
EMBIAN_NOCFI unsigned long embian_lookup_name(const char *name);
EMBIAN_NOCFI unsigned long embian_lookup_name_quiet(const char *name);
unsigned long embian_lookup_name_any(const char * const *names, bool quiet);

enum embian_symbol_id {
	EMBIAN_SYM_SYS_CALL_TABLE,
	EMBIAN_SYM_INIT_MM,
	EMBIAN_SYM_SET_FIXMAP,
	EMBIAN_SYM_DCACHE_CLEAN_INVAL_POC,
	EMBIAN_SYM_FLUSH_DCACHE_AREA,
	EMBIAN_SYM_CACHES_CLEAN_INVAL_POU,
	EMBIAN_SYM_BINDER_TRANSACTION,
	EMBIAN_SYM_BINDER_PROC_TRANSACTION,
	EMBIAN_SYM_BINDER_TRANSACTION_BUFFER_RELEASE,
	EMBIAN_SYM_BINDER_ALLOC_FREE_BUF,
	EMBIAN_SYM_BINDER_STATS,
	EMBIAN_SYM_COPY_FROM_USER_NOFAULT,
	EMBIAN_SYM_SECURITY_CURRENT_GETSECID_SUBJ,
	EMBIAN_SYM_SECURITY_CRED_GETSECID,
	EMBIAN_SYM_COUNT,
};

unsigned long embian_symbol_addr(enum embian_symbol_id id);
const char *embian_symbol_name(enum embian_symbol_id id);

int embian_patch_text(void *dst, const void *src, size_t len);

int embian_netlink_init(void);
void embian_netlink_exit(void);
int embian_netlink_unit(void);
int embian_netlink_send(const void *payload, size_t len);
int embian_netlink_send_msg(u16 type, u32 seq, s32 status, u32 flags);
int embian_netlink_send_payload(u16 type, u32 seq, s32 status, u32 flags,
				const void *payload, size_t len);

int embian_binder_init(void);
void embian_binder_exit(void);

int embian_signal_init(void);
void embian_signal_exit(void);

int embian_network_init(void);
void embian_network_exit(void);
int embian_network_add_uid(u32 uid);
int embian_network_remove_uid(u32 uid);
void embian_network_clear(void);
u32 embian_network_uid_count(void);

#endif /* EMBIAN_H */
