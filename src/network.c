/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0 */
/*
 * Embian - Netfilter-based per-uid network monitor.
 *
 * License: Author's work under Apache-2.0; when used as a kernel module
 * (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
 *
 * Author: Anatdx
 */

#define pr_fmt(fmt) "embian: network: " fmt

#include <linux/errno.h>
#include <linux/hashtable.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/mutex.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/printk.h>
#include <linux/rculist.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/tcp.h>
#include <linux/uidgid.h>
#include <net/ipv6.h>
#include <net/net_namespace.h>
#include <net/sock.h>

#include "embian.h"

#define EMBIAN_NETWORK_UID_HASH_BITS 6

struct embian_network_uid_entry {
	u32 uid;
	struct hlist_node hnode;
	struct rcu_head rcu;
};

static DEFINE_HASHTABLE(embian_network_uid_map, EMBIAN_NETWORK_UID_HASH_BITS);
static DEFINE_MUTEX(embian_network_uid_lock);
static bool embian_network_pernet_registered;

static bool embian_network_uid_monitored(u32 uid)
{
	struct embian_network_uid_entry *entry;

	hash_for_each_possible_rcu(embian_network_uid_map, entry, hnode, uid) {
		if (entry->uid == uid)
			return true;
	}
	return false;
}

static void embian_network_free_entry_rcu(struct rcu_head *rcu)
{
	struct embian_network_uid_entry *entry =
		container_of(rcu, struct embian_network_uid_entry, rcu);

	kfree(entry);
}

int embian_network_add_uid(u32 uid)
{
	struct embian_network_uid_entry *entry;

	entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

	entry->uid = uid;

	mutex_lock(&embian_network_uid_lock);
	if (embian_network_uid_monitored(uid)) {
		mutex_unlock(&embian_network_uid_lock);
		kfree(entry);
		return -EEXIST;
	}
	hash_add_rcu(embian_network_uid_map, &entry->hnode, uid);
	mutex_unlock(&embian_network_uid_lock);

	pr_info("monitor uid=%u\n", uid);
	return 0;
}

int embian_network_remove_uid(u32 uid)
{
	struct embian_network_uid_entry *entry;
	bool found = false;

	mutex_lock(&embian_network_uid_lock);
	hash_for_each_possible(embian_network_uid_map, entry, hnode, uid) {
		if (entry->uid == uid) {
			hash_del_rcu(&entry->hnode);
			call_rcu(&entry->rcu, embian_network_free_entry_rcu);
			found = true;
			break;
		}
	}
	mutex_unlock(&embian_network_uid_lock);

	if (found)
		pr_info("unmonitor uid=%u\n", uid);

	return found ? 0 : -ENOENT;
}

void embian_network_clear(void)
{
	struct embian_network_uid_entry *entry;
	struct hlist_node *tmp;
	int bkt;

	mutex_lock(&embian_network_uid_lock);
	hash_for_each_safe(embian_network_uid_map, bkt, tmp, entry, hnode) {
		hash_del_rcu(&entry->hnode);
		call_rcu(&entry->rcu, embian_network_free_entry_rcu);
	}
	mutex_unlock(&embian_network_uid_lock);

	pr_info("cleared uid list\n");
}

u32 embian_network_uid_count(void)
{
	struct embian_network_uid_entry *entry;
	u32 count = 0;
	int bkt;

	mutex_lock(&embian_network_uid_lock);
	hash_for_each(embian_network_uid_map, bkt, entry, hnode) {
		count++;
	}
	mutex_unlock(&embian_network_uid_lock);
	return count;
}

static u32 embian_network_sock_uid(struct sock *sk)
{
	struct socket *socket;

	if (!sk)
		return 0;

	socket = sk->sk_socket;
	if (!socket || !SOCK_INODE(socket))
		return 0;

	return __kuid_val(SOCK_INODE(socket)->i_uid);
}

static u32 embian_network_tcp_flags(const struct tcphdr *th)
{
	u32 flags = 0;

	if (th->fin)
		flags |= EMBIAN_NETWORK_TCP_FIN;
	if (th->syn)
		flags |= EMBIAN_NETWORK_TCP_SYN;
	if (th->rst)
		flags |= EMBIAN_NETWORK_TCP_RST;
	if (th->psh)
		flags |= EMBIAN_NETWORK_TCP_PSH;
	if (th->ack)
		flags |= EMBIAN_NETWORK_TCP_ACK;
	if (th->urg)
		flags |= EMBIAN_NETWORK_TCP_URG;
	return flags;
}

static void embian_network_emit(u32 uid, u32 proto, int data_len,
				const struct tcphdr *th)
{
	struct embian_network_event event = {
		.event_type = EMBIAN_EVENT_NETWORK,
		.uid = uid,
		.proto = proto,
		.data_len = data_len > 0 ? (u32)data_len : 0,
		.tcp_flags = embian_network_tcp_flags(th),
		.src_port = ntohs(th->source),
		.dst_port = ntohs(th->dest),
	};

	(void)embian_netlink_send_payload(EMBIAN_NL_MSG_EVENT, 0, 0, 0,
					  &event, sizeof(event));
}

static unsigned int embian_network_hook_v4(void *priv, struct sk_buff *skb,
					   const struct nf_hook_state *state)
{
	struct sock *sk;
	struct iphdr *iph;
	struct tcphdr _th;
	const struct tcphdr *th;
	unsigned int iphdrlen;
	int data_len;
	u32 uid;

	if (!skb || !skb->len)
		return NF_ACCEPT;

	if (!embian_control_has_client())
		return NF_ACCEPT;

	sk = skb_to_full_sk(skb);
	if (!sk || !sk_fullsock(sk))
		return NF_ACCEPT;

	uid = embian_network_sock_uid(sk);
	if (uid < EMBIAN_ANDROID_APP_UID_MIN)
		return NF_ACCEPT;

	rcu_read_lock();
	if (!embian_network_uid_monitored(uid)) {
		rcu_read_unlock();
		return NF_ACCEPT;
	}
	rcu_read_unlock();

	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP)
		return NF_ACCEPT;

	iphdrlen = iph->ihl << 2;
	if (!pskb_may_pull(skb, iphdrlen + sizeof(struct tcphdr)))
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	th = skb_header_pointer(skb, iphdrlen, sizeof(_th), &_th);
	if (!th)
		return NF_ACCEPT;

	data_len = ntohs(iph->tot_len) - iphdrlen - (th->doff << 2);
	if (data_len <= 0 && !th->syn && !th->fin && !th->rst)
		return NF_ACCEPT;

	embian_network_emit(uid, EMBIAN_NETWORK_PROTO_IPV4, data_len, th);
	return NF_ACCEPT;
}

#if IS_ENABLED(CONFIG_IPV6)
static unsigned int embian_network_hook_v6(void *priv, struct sk_buff *skb,
					   const struct nf_hook_state *state)
{
	struct sock *sk;
	struct ipv6hdr *iph;
	struct tcphdr _th;
	const struct tcphdr *th;
	unsigned int thoff = 0;
	unsigned short frag_off = 0;
	int data_len;
	u32 uid;
	int ret;

	if (!skb || !skb->len)
		return NF_ACCEPT;

	if (!embian_control_has_client())
		return NF_ACCEPT;

	sk = skb_to_full_sk(skb);
	if (!sk || !sk_fullsock(sk))
		return NF_ACCEPT;

	uid = embian_network_sock_uid(sk);
	if (uid < EMBIAN_ANDROID_APP_UID_MIN)
		return NF_ACCEPT;

	rcu_read_lock();
	if (!embian_network_uid_monitored(uid)) {
		rcu_read_unlock();
		return NF_ACCEPT;
	}
	rcu_read_unlock();

	if (!pskb_may_pull(skb, sizeof(struct ipv6hdr)))
		return NF_ACCEPT;

	ret = ipv6_find_hdr(skb, &thoff, -1, &frag_off, NULL);
	if (ret != IPPROTO_TCP)
		return NF_ACCEPT;

	if (!pskb_may_pull(skb, thoff + sizeof(struct tcphdr)))
		return NF_ACCEPT;

	iph = ipv6_hdr(skb);
	th = skb_header_pointer(skb, thoff, sizeof(_th), &_th);
	if (!th)
		return NF_ACCEPT;

	data_len = ntohs(iph->payload_len) -
		   (thoff - sizeof(struct ipv6hdr)) - (th->doff << 2);
	if (data_len <= 0 && !th->syn && !th->fin && !th->rst)
		return NF_ACCEPT;

	embian_network_emit(uid, EMBIAN_NETWORK_PROTO_IPV6, data_len, th);
	return NF_ACCEPT;
}
#endif

static const struct nf_hook_ops embian_network_nf_ops[] = {
	{
		.hook = embian_network_hook_v4,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_LOCAL_IN,
		.priority = NF_IP_PRI_SELINUX_LAST + 1,
	},
#if IS_ENABLED(CONFIG_IPV6)
	{
		.hook = embian_network_hook_v6,
		.pf = NFPROTO_IPV6,
		.hooknum = NF_INET_LOCAL_IN,
		.priority = NF_IP6_PRI_SELINUX_LAST + 1,
	},
#endif
};

static int __net_init embian_network_pernet_init(struct net *net)
{
	int ret;

	ret = nf_register_net_hooks(net, embian_network_nf_ops,
				    ARRAY_SIZE(embian_network_nf_ops));
	if (ret)
		pr_warn("nf_register_net_hooks failed for net=%px: %d\n",
			net, ret);
	return ret;
}

static void __net_exit embian_network_pernet_exit(struct net *net)
{
	nf_unregister_net_hooks(net, embian_network_nf_ops,
				ARRAY_SIZE(embian_network_nf_ops));
}

static struct pernet_operations embian_network_pernet_ops = {
	.init = embian_network_pernet_init,
	.exit = embian_network_pernet_exit,
};

int embian_network_init(void)
{
	int ret;

	hash_init(embian_network_uid_map);

	ret = register_pernet_subsys(&embian_network_pernet_ops);
	if (ret) {
		pr_warn("register_pernet_subsys failed: %d\n", ret);
		return 0;
	}

	embian_network_pernet_registered = true;
	pr_info("netfilter monitor initialized\n");
	return 0;
}

void embian_network_exit(void)
{
	if (embian_network_pernet_registered) {
		unregister_pernet_subsys(&embian_network_pernet_ops);
		embian_network_pernet_registered = false;
	}
	embian_network_clear();
	rcu_barrier();
	pr_info("netfilter monitor exited\n");
}
