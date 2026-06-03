/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Embian - Kernel-to-user netlink transport.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */

#define pr_fmt(fmt) "embian: netlink: " fmt

#include <linux/errno.h>
#include <linux/gfp.h>
#include <linux/netlink.h>
#include <linux/printk.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/string.h>
#include <net/net_namespace.h>
#include <net/sock.h>

#include "embian.h"

static struct sock *embian_nl_sock;
static int embian_nl_unit = -1;

static int embian_netlink_send_to(u32 portid, u16 type, u32 seq, s32 status,
				  u32 flags, const void *payload,
				  size_t payload_len)
{
	struct embian_netlink_msg header = {
		.magic = EMBIAN_PRCTL_MAGIC,
		.version = EMBIAN_CTL_ABI_VERSION,
		.type = type,
		.seq = seq,
		.status = status,
		.portid = portid,
		.netlink_unit = embian_nl_unit,
		.abi_version = EMBIAN_CTL_ABI_VERSION,
		.flags = flags,
	};
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	size_t total_len = sizeof(header) + payload_len;

	if (!embian_nl_sock)
		return -ENODEV;

	if (!portid)
		return -EINVAL;

	if (payload_len && !payload)
		return -EINVAL;

	skb = nlmsg_new(total_len, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;

	nlh = nlmsg_put(skb, 0, 0, type, total_len, 0);
	if (!nlh) {
		kfree_skb(skb);
		return -EMSGSIZE;
	}

	memcpy(nlmsg_data(nlh), &header, sizeof(header));
	if (payload_len)
		memcpy((u8 *)nlmsg_data(nlh) + sizeof(header), payload,
		       payload_len);
	NETLINK_CB(skb).dst_group = 0;

	return netlink_unicast(embian_nl_sock, skb, portid, MSG_DONTWAIT);
}

static bool embian_netlink_portid_is_client(u32 portid)
{
	return portid && portid == embian_control_portid();
}

static s32 embian_netlink_handle_network_uid(const void *payload,
					     size_t payload_len, u32 portid,
					     int (*action)(u32))
{
	struct embian_network_uid_args args;

	if (!embian_netlink_portid_is_client(portid))
		return -EPERM;

	if (payload_len < sizeof(args))
		return -EINVAL;

	memcpy(&args, payload, sizeof(args));
	return action(args.uid);
}

static void embian_netlink_handle_msg(const struct embian_netlink_msg *msg,
				      const void *payload, size_t payload_len,
				      u32 portid)
{
	struct embian_control_snapshot snapshot;
	s32 status = 0;
	u32 flags = 0;

	if (msg->magic != EMBIAN_PRCTL_MAGIC) {
		status = -EINVAL;
		goto out;
	}

	if (msg->version != EMBIAN_CTL_ABI_VERSION) {
		status = -EINVAL;
		goto out;
	}

	switch (msg->type) {
	case EMBIAN_NL_CMD_HELLO:
		status = embian_control_register(portid, msg->magic,
						 current->tgid, current_uid());
		break;
	case EMBIAN_NL_CMD_PING:
		status = 0;
		break;
	case EMBIAN_NL_CMD_STATUS:
		embian_control_get_snapshot(&snapshot);
		flags = snapshot.active ? 1u : 0u;
		status = 0;
		break;
	case EMBIAN_NL_CMD_DETACH:
		embian_control_detach_portid(portid);
		status = 0;
		break;
	case EMBIAN_NL_CMD_NETWORK_ADD_UID:
		status = embian_netlink_handle_network_uid(
			payload, payload_len, portid, embian_network_add_uid);
		break;
	case EMBIAN_NL_CMD_NETWORK_REMOVE_UID:
		status = embian_netlink_handle_network_uid(
			payload, payload_len, portid,
			embian_network_remove_uid);
		break;
	case EMBIAN_NL_CMD_NETWORK_CLEAR:
		if (!embian_netlink_portid_is_client(portid)) {
			status = -EPERM;
			break;
		}
		embian_network_clear();
		status = 0;
		break;
	default:
		status = -EINVAL;
		break;
	}

out:
	(void)embian_netlink_send_to(portid,
				     msg->type == EMBIAN_NL_CMD_STATUS ?
				     EMBIAN_NL_MSG_STATUS : EMBIAN_NL_MSG_ACK,
				     msg->seq, status, flags, NULL, 0);
}

static void embian_netlink_recv(struct sk_buff *skb)
{
	struct nlmsghdr *nlh;
	struct embian_netlink_msg msg;
	u32 portid;

	if (!skb)
		return;

	nlh = nlmsg_hdr(skb);
	if (!nlh || !nlmsg_ok(nlh, skb->len)) {
		pr_debug("dropped malformed message\n");
		return;
	}

	pr_debug("received message type=%u len=%u portid=%u\n",
		 nlh->nlmsg_type, nlh->nlmsg_len, NETLINK_CB(skb).portid);

	if (nlmsg_len(nlh) < sizeof(msg)) {
		pr_debug("dropped short message len=%u\n", nlmsg_len(nlh));
		return;
	}

	memcpy(&msg, nlmsg_data(nlh), sizeof(msg));
	portid = NETLINK_CB(skb).portid;
	embian_netlink_handle_msg(&msg,
				  (const u8 *)nlmsg_data(nlh) + sizeof(msg),
				  nlmsg_len(nlh) - sizeof(msg), portid);
}

int embian_netlink_init(void)
{
	struct netlink_kernel_cfg cfg = {
		.input = embian_netlink_recv,
	};
	int unit;

	for (unit = EMBIAN_NETLINK_MAX; unit >= EMBIAN_NETLINK_MIN; unit--) {
		embian_nl_sock = netlink_kernel_create(&init_net, unit, &cfg);
		if (embian_nl_sock) {
			embian_nl_unit = unit;
			pr_info("created socket unit=%d\n", embian_nl_unit);
			return 0;
		}
	}

	pr_err("failed to create netlink socket in range %d..%d\n",
	       EMBIAN_NETLINK_MIN, EMBIAN_NETLINK_MAX);
	return -EADDRINUSE;
}

void embian_netlink_exit(void)
{
	if (embian_nl_sock) {
		netlink_kernel_release(embian_nl_sock);
		embian_nl_sock = NULL;
	}

	embian_nl_unit = -1;
}

int embian_netlink_unit(void)
{
	return embian_nl_unit;
}

int embian_netlink_send(const void *payload, size_t len)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	u32 portid;

	if (!embian_nl_sock)
		return -ENODEV;

	if (!payload || !len)
		return -EINVAL;

	portid = embian_control_portid();
	if (!portid)
		return -ENOTCONN;

	skb = nlmsg_new(len, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;

	nlh = nlmsg_put(skb, 0, 0, 0, len, 0);
	if (!nlh) {
		kfree_skb(skb);
		return -EMSGSIZE;
	}

	memcpy(nlmsg_data(nlh), payload, len);
	NETLINK_CB(skb).dst_group = 0;

	return netlink_unicast(embian_nl_sock, skb, portid, MSG_DONTWAIT);
}

int embian_netlink_send_msg(u16 type, u32 seq, s32 status, u32 flags)
{
	return embian_netlink_send_to(embian_control_portid(), type, seq,
				      status, flags, NULL, 0);
}

int embian_netlink_send_payload(u16 type, u32 seq, s32 status, u32 flags,
				const void *payload, size_t len)
{
	return embian_netlink_send_to(embian_control_portid(), type, seq,
				      status, flags, payload, len);
}
