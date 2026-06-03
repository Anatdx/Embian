/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Embian - User-space ABI definitions.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */

#ifndef EMBIAN_UAPI_H
#define EMBIAN_UAPI_H

#ifdef __KERNEL__
#include <linux/types.h>
typedef u16 embian_u16;
typedef u32 embian_u32;
typedef s32 embian_s32;
#else
#include <stdint.h>
typedef uint16_t embian_u16;
typedef uint32_t embian_u32;
typedef int32_t embian_s32;
#endif

#define EMBIAN_PRCTL_OPTION 0x454d4249u
#define EMBIAN_PRCTL_MAGIC 0x45424941u
#define EMBIAN_CTL_ABI_VERSION 2u

#define EMBIAN_NETLINK_MIN 25
#define EMBIAN_NETLINK_MAX 31
#define EMBIAN_BINDER_ASYNC_WARN_SPACE (1U << 17)
#define EMBIAN_BINDER_INTERFACE_TOKEN_OFFSET 16U
#define EMBIAN_BINDER_INTERFACE_MAX 96U
#define EMBIAN_ANDROID_APP_UID_MIN 10000U
#define EMBIAN_ANDROID_SYSTEM_UID_MAX 2000U

#define EMBIAN_BINDER_EVENT_FLAG_INTERFACE (1U << 27)
#define EMBIAN_BINDER_EVENT_FLAG_INTERFACE_TRUNCATED (1U << 28)
#define EMBIAN_BINDER_EVENT_FLAG_INTERFACE_COPY_FAILED (1U << 29)
#define EMBIAN_BINDER_EVENT_FLAG_SHOULD_FAIL (1U << 30)
#define EMBIAN_BINDER_EVENT_FLAG_TARGET_FROZEN (1U << 31)

enum embian_prctl_command {
	EMBIAN_PRCTL_GET_NETLINK_UNIT = 1,
	EMBIAN_PRCTL_REGISTER_CLIENT = 2,
	EMBIAN_PRCTL_DETACH_CLIENT = 3,
};

struct embian_prctl_args {
	embian_u32 portid;
	embian_s32 status;
	embian_s32 netlink_unit;
	embian_u32 abi_version;
};

enum embian_netlink_command {
	EMBIAN_NL_CMD_HELLO = 1,
	EMBIAN_NL_CMD_PING = 2,
	EMBIAN_NL_CMD_STATUS = 3,
	EMBIAN_NL_CMD_DETACH = 4,
};

enum embian_netlink_message_type {
	EMBIAN_NL_MSG_ACK = 0x8001,
	EMBIAN_NL_MSG_STATUS = 0x8002,
	EMBIAN_NL_MSG_EVENT = 0x8003,
};

enum embian_event_type {
	EMBIAN_EVENT_BINDER_TRANSACTION = 1,
	EMBIAN_EVENT_BINDER_REPLY = 2,
	EMBIAN_EVENT_BINDER_ASYNC_PRESSURE = 3,
	EMBIAN_EVENT_BINDER_ASYNC_CLEANUP = 4,
	EMBIAN_EVENT_SIGNAL = 5,
};

struct embian_netlink_msg {
	embian_u32 magic;
	embian_u16 version;
	embian_u16 type;
	embian_u32 seq;
	embian_s32 status;
	embian_u32 portid;
	embian_s32 netlink_unit;
	embian_u32 abi_version;
	embian_u32 flags;
};

struct embian_binder_event {
	embian_u32 event_type;
	embian_u32 binder_flags;
	embian_s32 from_pid;
	embian_u32 from_uid;
	embian_s32 target_pid;
	embian_u32 target_uid;
	embian_u32 code;
	embian_u32 data_size;
	embian_u32 offsets_size;
	embian_u32 free_async_space;
	embian_u32 requested_size;
	embian_u32 interface_len;
	char interface_token[EMBIAN_BINDER_INTERFACE_MAX];
};

struct embian_signal_event {
	embian_u32 event_type;
	embian_s32 signo;
	embian_s32 killer_pid;
	embian_u32 killer_uid;
	embian_s32 dst_pid;
	embian_u32 dst_uid;
};

#endif /* EMBIAN_UAPI_H */
