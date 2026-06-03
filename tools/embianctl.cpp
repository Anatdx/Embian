/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Embian - Android user-space smoke test client.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */

#include <errno.h>
#include <linux/netlink.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "uapi/embian_uapi.h"

#ifndef TF_ONE_WAY
#define TF_ONE_WAY 0x01u
#endif

namespace {

volatile sig_atomic_t g_stop;

constexpr int MAX_NET_UIDS = 32;

struct Options {
	int unit = -1;
	int timeout_ms = -1;
	int max_events = -1;
	int drop_uid = -1;
	bool once = false;
	bool status_only = false;
	bool detach = false;
	bool no_prctl = false;
	bool clear_net_uids = false;
	bool disarm_prctl = false;
	int add_net_uid_count = 0;
	int remove_net_uid_count = 0;
	uint32_t add_net_uids[MAX_NET_UIDS] = {};
	uint32_t remove_net_uids[MAX_NET_UIDS] = {};
};

struct PrctlResult {
	long syscall_rc = -1;
	int syscall_errno = 0;
	embian_prctl_args args = {};
};

void on_signal(int)
{
	g_stop = 1;
}

const char *nl_type_name(uint16_t type)
{
	switch (type) {
	case EMBIAN_NL_MSG_ACK:
		return "ack";
	case EMBIAN_NL_MSG_STATUS:
		return "status";
	case EMBIAN_NL_MSG_EVENT:
		return "event";
	default:
		return "unknown";
	}
}

const char *event_name(uint32_t type)
{
	switch (type) {
	case EMBIAN_EVENT_BINDER_TRANSACTION:
		return "binder_transaction";
	case EMBIAN_EVENT_BINDER_REPLY:
		return "binder_reply";
	case EMBIAN_EVENT_BINDER_ASYNC_PRESSURE:
		return "binder_async_pressure";
	case EMBIAN_EVENT_BINDER_ASYNC_CLEANUP:
		return "binder_async_cleanup";
	case EMBIAN_EVENT_SIGNAL:
		return "signal";
	case EMBIAN_EVENT_NETWORK:
		return "network";
	default:
		return "unknown";
	}
}

void print_tcp_flags(uint32_t flags)
{
	printf(" tcp_flags=");
	bool first = true;
	auto emit = [&](const char *name) {
		printf("%s%s", first ? "" : "|", name);
		first = false;
	};
	if (flags & EMBIAN_NETWORK_TCP_FIN) emit("FIN");
	if (flags & EMBIAN_NETWORK_TCP_SYN) emit("SYN");
	if (flags & EMBIAN_NETWORK_TCP_RST) emit("RST");
	if (flags & EMBIAN_NETWORK_TCP_PSH) emit("PSH");
	if (flags & EMBIAN_NETWORK_TCP_ACK) emit("ACK");
	if (flags & EMBIAN_NETWORK_TCP_URG) emit("URG");
	if (first)
		emit("0");
}

void print_network_event(const uint8_t *payload, size_t len)
{
	const embian_network_event *event;

	if (len < sizeof(*event)) {
		printf("  short network payload len=%zu\n", len);
		return;
	}

	event = reinterpret_cast<const embian_network_event *>(payload);
	printf("  event=%s(%u) uid=%u proto=ipv%u src=%u dst=%u data_len=%u",
	       event_name(event->event_type), event->event_type, event->uid,
	       event->proto, event->src_port, event->dst_port,
	       event->data_len);
	print_tcp_flags(event->tcp_flags);
	printf("\n");
}

void print_escaped_token(const char *token, uint32_t len)
{
	uint32_t limit = len;

	if (limit > EMBIAN_BINDER_INTERFACE_MAX)
		limit = EMBIAN_BINDER_INTERFACE_MAX;

	printf(" iface=\"");
	for (uint32_t i = 0; i < limit && token[i]; i++) {
		unsigned char ch = static_cast<unsigned char>(token[i]);

		if (ch == '\\' || ch == '"') {
			printf("\\%c", ch);
		} else if (ch >= 0x20 && ch < 0x7f) {
			putchar(ch);
		} else {
			printf("\\x%02x", ch);
		}
	}
	printf("\"");
}

void usage(const char *argv0)
{
	fprintf(stderr,
		"usage: %s [--unit N] [--status] [--once] [--timeout MS] "
		"[--max-events N] [--drop-uid N] [--detach] [--no-prctl]\n"
		"           [--add-net-uid N]... [--remove-net-uid N]... "
		"[--clear-net-uids]\n"
		"           [--disarm-prctl]\n"
		"\n"
		"Default flow: prctl discover unit, bind netlink, prctl register, "
		"send status, then listen.\n",
		argv0);
}

bool parse_int(const char *text, int *out)
{
	char *end = nullptr;
	long value;

	errno = 0;
	value = strtol(text, &end, 0);
	if (errno || !end || *end || value < INT32_MIN || value > INT32_MAX)
		return false;

	*out = static_cast<int>(value);
	return true;
}

bool parse_args(int argc, char **argv, Options *options)
{
	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--unit")) {
			if (++i >= argc || !parse_int(argv[i], &options->unit))
				return false;
		} else if (!strcmp(argv[i], "--timeout")) {
			if (++i >= argc || !parse_int(argv[i], &options->timeout_ms))
				return false;
		} else if (!strcmp(argv[i], "--max-events")) {
			if (++i >= argc || !parse_int(argv[i], &options->max_events))
				return false;
		} else if (!strcmp(argv[i], "--drop-uid")) {
			if (++i >= argc || !parse_int(argv[i], &options->drop_uid))
				return false;
		} else if (!strcmp(argv[i], "--once")) {
			options->once = true;
		} else if (!strcmp(argv[i], "--status")) {
			options->status_only = true;
		} else if (!strcmp(argv[i], "--detach")) {
			options->detach = true;
			options->once = true;
		} else if (!strcmp(argv[i], "--no-prctl")) {
			options->no_prctl = true;
		} else if (!strcmp(argv[i], "--add-net-uid")) {
			int uid;
			if (++i >= argc || !parse_int(argv[i], &uid) || uid < 0)
				return false;
			if (options->add_net_uid_count >= MAX_NET_UIDS)
				return false;
			options->add_net_uids[options->add_net_uid_count++] =
				static_cast<uint32_t>(uid);
		} else if (!strcmp(argv[i], "--remove-net-uid")) {
			int uid;
			if (++i >= argc || !parse_int(argv[i], &uid) || uid < 0)
				return false;
			if (options->remove_net_uid_count >= MAX_NET_UIDS)
				return false;
			options->remove_net_uids[options->remove_net_uid_count++] =
				static_cast<uint32_t>(uid);
		} else if (!strcmp(argv[i], "--clear-net-uids")) {
			options->clear_net_uids = true;
		} else if (!strcmp(argv[i], "--disarm-prctl")) {
			options->disarm_prctl = true;
		} else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			usage(argv[0]);
			exit(0);
		} else {
			return false;
		}
	}

	return true;
}

PrctlResult call_embian_prctl(uint32_t command, uint32_t portid)
{
	PrctlResult result;

	result.args.portid = portid;
	result.args.status = INT32_MIN;
	result.args.netlink_unit = -1;
	result.args.abi_version = 0;

	errno = 0;
	result.syscall_rc = syscall(__NR_prctl, EMBIAN_PRCTL_OPTION,
				    EMBIAN_PRCTL_MAGIC, command,
				    reinterpret_cast<unsigned long>(&result.args),
				    0UL);
	result.syscall_errno = errno;
	return result;
}

bool valid_unit(int unit)
{
	return unit >= EMBIAN_NETLINK_MIN && unit <= EMBIAN_NETLINK_MAX;
}

int discover_unit()
{
	PrctlResult result = call_embian_prctl(EMBIAN_PRCTL_GET_NETLINK_UNIT, 0);

	printf("prctl discover: syscall_rc=%ld errno=%d status=%d unit=%d abi=%u\n",
	       result.syscall_rc, result.syscall_errno, result.args.status,
	       result.args.netlink_unit, result.args.abi_version);

	if (result.args.status == 0 && valid_unit(result.args.netlink_unit))
		return result.args.netlink_unit;

	return -1;
}

int open_netlink(int unit, uint32_t *portid)
{
	sockaddr_nl local = {};
	socklen_t local_len = sizeof(local);
	int fd;

	fd = socket(AF_NETLINK, SOCK_DGRAM, unit);
	if (fd < 0) {
		perror("socket(AF_NETLINK)");
		return -1;
	}

	local.nl_family = AF_NETLINK;
	local.nl_pid = 0;
	local.nl_groups = 0;

	if (bind(fd, reinterpret_cast<sockaddr *>(&local), sizeof(local)) < 0) {
		perror("bind(AF_NETLINK)");
		close(fd);
		return -1;
	}

	if (getsockname(fd, reinterpret_cast<sockaddr *>(&local),
			&local_len) < 0) {
		perror("getsockname(AF_NETLINK)");
		close(fd);
		return -1;
	}

	*portid = local.nl_pid;
	printf("netlink: unit=%d portid=%u\n", unit, *portid);
	return fd;
}

constexpr size_t MAX_CMD_PAYLOAD = 64;

bool send_command_payload(int fd, uint16_t type, uint32_t seq,
			  const void *payload, size_t payload_len)
{
	embian_netlink_msg msg = {};

	if (payload_len > MAX_CMD_PAYLOAD) {
		fprintf(stderr, "payload too large: %zu\n", payload_len);
		return false;
	}

	size_t total_len = sizeof(msg) + payload_len;
	alignas(nlmsghdr) uint8_t
		buf[NLMSG_SPACE(sizeof(msg) + MAX_CMD_PAYLOAD)] = {};
	nlmsghdr *nlh = reinterpret_cast<nlmsghdr *>(buf);
	sockaddr_nl kernel = {};
	ssize_t sent;

	msg.magic = EMBIAN_PRCTL_MAGIC;
	msg.version = EMBIAN_CTL_ABI_VERSION;
	msg.type = type;
	msg.seq = seq;

	kernel.nl_family = AF_NETLINK;

	nlh->nlmsg_len = NLMSG_LENGTH(total_len);
	nlh->nlmsg_type = type;
	nlh->nlmsg_seq = seq;
	memcpy(NLMSG_DATA(nlh), &msg, sizeof(msg));
	if (payload_len && payload)
		memcpy(reinterpret_cast<uint8_t *>(NLMSG_DATA(nlh)) + sizeof(msg),
		       payload, payload_len);

	sent = sendto(fd, buf, nlh->nlmsg_len, 0,
		      reinterpret_cast<sockaddr *>(&kernel), sizeof(kernel));
	if (sent != static_cast<ssize_t>(nlh->nlmsg_len)) {
		perror("sendto(AF_NETLINK)");
		return false;
	}

	return true;
}

bool send_command(int fd, uint16_t type, uint32_t seq)
{
	return send_command_payload(fd, type, seq, nullptr, 0);
}

bool send_net_uid(int fd, uint16_t cmd, uint32_t uid, uint32_t seq)
{
	embian_network_uid_args args{};
	args.uid = uid;
	return send_command_payload(fd, cmd, seq, &args, sizeof(args));
}

void print_signal_event(const uint8_t *payload, size_t len)
{
	const embian_signal_event *event;

	if (len < sizeof(*event)) {
		printf("  short signal payload len=%zu\n", len);
		return;
	}

	event = reinterpret_cast<const embian_signal_event *>(payload);
	printf("  event=%s(%u) signo=%d killer=%d/%u dst=%d/%u\n",
	       event_name(event->event_type), event->event_type,
	       event->signo, event->killer_pid, event->killer_uid,
	       event->dst_pid, event->dst_uid);
}

void print_event(const uint8_t *payload, size_t len)
{
	uint32_t event_type;

	if (len < sizeof(event_type)) {
		printf("  short event payload len=%zu\n", len);
		return;
	}

	memcpy(&event_type, payload, sizeof(event_type));
	if (event_type == EMBIAN_EVENT_SIGNAL) {
		print_signal_event(payload, len);
		return;
	}
	if (event_type == EMBIAN_EVENT_NETWORK) {
		print_network_event(payload, len);
		return;
	}

	const embian_binder_event *event;

	if (len < sizeof(*event)) {
		printf("  short binder payload len=%zu\n", len);
		return;
	}

	event = reinterpret_cast<const embian_binder_event *>(payload);
	printf("  event=%s(%u) flags=0x%x from=%d/%u target=%d/%u "
	       "code=%u data=%u offsets=%u free_async=%u requested=%u",
	       event_name(event->event_type), event->event_type,
	       event->binder_flags, event->from_pid, event->from_uid,
	       event->target_pid, event->target_uid, event->code,
	       event->data_size, event->offsets_size,
	       event->free_async_space, event->requested_size);

	if (event->event_type == EMBIAN_EVENT_BINDER_ASYNC_PRESSURE) {
		if (event->binder_flags & EMBIAN_BINDER_EVENT_FLAG_SHOULD_FAIL)
			printf(" should_fail=1");
	} else {
		printf(" oneway=%u", !!(event->binder_flags & TF_ONE_WAY));
	}
	if (event->binder_flags & EMBIAN_BINDER_EVENT_FLAG_TARGET_FROZEN)
		printf(" target_frozen=1");
	if (event->binder_flags & EMBIAN_BINDER_EVENT_FLAG_INTERFACE)
		print_escaped_token(event->interface_token, event->interface_len);
	if (event->binder_flags & EMBIAN_BINDER_EVENT_FLAG_INTERFACE_TRUNCATED)
		printf(" iface_truncated=1");
	if (event->binder_flags & EMBIAN_BINDER_EVENT_FLAG_INTERFACE_COPY_FAILED)
		printf(" iface_copy_failed=1");
	printf("\n");
}

bool recv_one(int fd, int timeout_ms, uint16_t *out_type)
{
	uint8_t buf[4096];
	pollfd pfd = {
		.fd = fd,
		.events = POLLIN,
		.revents = 0,
	};
	ssize_t len;
	const nlmsghdr *nlh;
	const embian_netlink_msg *msg;
	const uint8_t *data;
	size_t data_len;
	size_t payload_len;

	if (out_type)
		*out_type = 0;

	int rc = poll(&pfd, 1, timeout_ms);
	if (rc < 0) {
		if (errno == EINTR)
			return true;
		perror("poll");
		return false;
	}
	if (rc == 0) {
		printf("timeout\n");
		return false;
	}

	len = recv(fd, buf, sizeof(buf), 0);
	if (len < 0) {
		perror("recv");
		return false;
	}
	if (static_cast<size_t>(len) < sizeof(nlmsghdr)) {
		printf("short netlink frame len=%zd\n", len);
		return true;
	}

	nlh = reinterpret_cast<const nlmsghdr *>(buf);
	data = reinterpret_cast<const uint8_t *>(NLMSG_DATA(nlh));
	data_len = NLMSG_PAYLOAD(nlh, 0);
	if (data_len < sizeof(*msg)) {
		printf("short embian message len=%zu\n", data_len);
		return true;
	}

	msg = reinterpret_cast<const embian_netlink_msg *>(data);
	payload_len = data_len - sizeof(*msg);
	printf("rx type=%s(0x%x) seq=%u status=%d portid=%u unit=%d "
	       "abi=%u flags=0x%x payload=%zu\n",
	       nl_type_name(msg->type), msg->type, msg->seq, msg->status,
	       msg->portid, msg->netlink_unit, msg->abi_version, msg->flags,
	       payload_len);

	if (msg->magic != EMBIAN_PRCTL_MAGIC)
		printf("  bad magic=0x%x\n", msg->magic);

	if (msg->type == EMBIAN_NL_MSG_EVENT)
		print_event(data + sizeof(*msg), payload_len);

	if (out_type)
		*out_type = msg->type;
	return true;
}

void detach(int fd, bool no_prctl)
{
	if (!no_prctl) {
		PrctlResult result = call_embian_prctl(EMBIAN_PRCTL_DETACH_CLIENT,
						       0);
		printf("prctl detach: syscall_rc=%ld errno=%d status=%d\n",
		       result.syscall_rc, result.syscall_errno,
		       result.args.status);
	}

	if (fd >= 0)
		(void)send_command(fd, EMBIAN_NL_CMD_DETACH, 0);
}

} // namespace

int main(int argc, char **argv)
{
	Options options;
	uint32_t portid = 0;
	uint32_t seq = 1;
	int unit;
	int fd;

	if (!parse_args(argc, argv, &options)) {
		usage(argv[0]);
		return 2;
	}

	if (options.drop_uid >= 0) {
		if (setresgid(options.drop_uid, options.drop_uid,
			      options.drop_uid) ||
		    setresuid(options.drop_uid, options.drop_uid,
			      options.drop_uid)) {
			perror("drop uid");
			return 1;
		}
		printf("dropped uid/gid to %d\n", options.drop_uid);
	}

	unit = options.unit;
	if (unit < 0 && !options.no_prctl)
		unit = discover_unit();
	if (!valid_unit(unit)) {
		fprintf(stderr, "netlink unit unavailable; pass --unit N if needed\n");
		return 1;
	}

	fd = open_netlink(unit, &portid);
	if (fd < 0)
		return 1;

	if (!options.no_prctl && !options.status_only) {
		PrctlResult result = call_embian_prctl(
			options.detach ? EMBIAN_PRCTL_DETACH_CLIENT :
					 EMBIAN_PRCTL_REGISTER_CLIENT,
			portid);
		printf("prctl %s: syscall_rc=%ld errno=%d status=%d "
		       "unit=%d abi=%u portid=%u\n",
		       options.detach ? "detach" : "register",
		       result.syscall_rc, result.syscall_errno,
		       result.args.status, result.args.netlink_unit,
		       result.args.abi_version, result.args.portid);
	}

	uint16_t initial_cmd = EMBIAN_NL_CMD_HELLO;

	if (options.detach)
		initial_cmd = EMBIAN_NL_CMD_DETACH;
	else if (options.status_only)
		initial_cmd = EMBIAN_NL_CMD_STATUS;

	if (!send_command(fd, initial_cmd, seq++)) {
		close(fd);
		return 1;
	}

	if (!options.detach && !options.status_only) {
		if (options.clear_net_uids) {
			(void)recv_one(fd, 1000, nullptr); /* drain HELLO ack */
			(void)send_command(fd, EMBIAN_NL_CMD_NETWORK_CLEAR, seq++);
		}
		for (int i = 0; i < options.remove_net_uid_count; i++)
			(void)send_net_uid(fd, EMBIAN_NL_CMD_NETWORK_REMOVE_UID,
					   options.remove_net_uids[i], seq++);
		for (int i = 0; i < options.add_net_uid_count; i++)
			(void)send_net_uid(fd, EMBIAN_NL_CMD_NETWORK_ADD_UID,
					   options.add_net_uids[i], seq++);
		if (options.disarm_prctl)
			(void)send_command(fd, EMBIAN_NL_CMD_DISARM_PRCTL,
					   seq++);
	}

	if (options.detach) {
		(void)recv_one(fd, 1000, nullptr);
		close(fd);
		return 0;
	}

	if (!options.status_only)
		(void)send_command(fd, EMBIAN_NL_CMD_PING, seq++);

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	int events = 0;
	do {
		uint16_t type = 0;

		if (!recv_one(fd, options.timeout_ms, &type))
			break;

		if (type == EMBIAN_NL_MSG_EVENT)
			events++;

		if (options.status_only && type == EMBIAN_NL_MSG_STATUS)
			break;

		if (options.max_events >= 0 && events >= options.max_events)
			break;

		if (options.once)
			break;
	} while (!g_stop);

	detach(fd, options.no_prctl);
	close(fd);
	return 0;
}
