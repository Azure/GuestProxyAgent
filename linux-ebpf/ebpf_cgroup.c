// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#include <linux/bpf.h>
#include <asm/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "socket.h"

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, sock_addr_skip_process_entry);
    __type(value, sock_addr_skip_process_entry);
    __uint(max_entries, 10);
} skip_process_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, destination_entry);
    __type(value, destination_entry);
    __uint(max_entries, 10);
} policy_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, sock_addr_aduit_key);     // source port and protocol
    __type(value, sock_addr_audit_entry); // audit entry
    __uint(max_entries, 200);             // some older kernel version cannot support over 200 entries.
} audit_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u64);                   // socket cookie or pid-tgid
    __type(value, sock_addr_local_entry); // audit local entry
    __uint(max_entries, 200);             // some older kernel version cannot support over 200 entries.
} local_map SEC(".maps");


/*
    check the current pid in the skip_process map.
    return 1 if found, otherwise return 0.
*/
static __always_inline int
check_skip_process_map_entry(__u32 pid)
{
    sock_addr_skip_process_entry key = {0};
    key.pid = pid;

    // Find the entry in the skip_process map.
    sock_addr_skip_process_entry *skip_entry = bpf_map_lookup_elem(&skip_process_map, &key);
    return (skip_entry != NULL) ? 1 : 0;
}

/*
    update audit map entry if not skip redirecting.
    return 0 if the entry is updated, otherwise
    return 1 if pid found in the skip_process_map.
*/
static __always_inline int
update_local_map_entry(struct bpf_sock_addr *ctx)
{
    __u64 pid_tip = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tip >> 32);

    if (check_skip_process_map_entry(pid) == 1)
    {
        return 1;
    }

    sock_addr_local_entry entry = {0};
    entry.process_id = pid;
    __u32 uid = (__u32)(bpf_get_current_uid_gid() >> 32);
    entry.logon_id = uid;
    entry.is_root = (uid == 0) ? 1 : 0;     // root uid is 0.
    entry.destination_ipv4 = ctx->user_ip4; // we only support ipv4 so far.
    entry.destination_port = ctx->user_port;
    entry.protocol = ctx->protocol;

    __u64 ret = bpf_map_update_elem(&local_map, &pid_tip, &entry, 0);
    if (ret != 0)
    {
        bpf_printk("update_local_map_entry: Failed to update local map entry with results:%u.", ret);
    }
    else
    {
        bpf_printk("update_local_map_entry: Updated local map entry with key:%u.", pid_tip);
    }

    return 0;
}

static __always_inline int
authorize_v4(struct bpf_sock_addr *ctx)
{
    destination_entry entry = {0};
    entry.destination_ip.ipv4 = ctx->user_ip4;
    entry.destination_port = ctx->user_port;
    entry.protocol = ctx->protocol;

    // Find the entry in the policy map.
    destination_entry *policy = bpf_map_lookup_elem(&policy_map, &entry);
    if (policy != NULL)
    {
        bpf_printk("authorize_v4: Found v4 proxy entry value: %u, %u", policy->destination_ip.ipv4, policy->destination_port);

        // update to the audit map before changing the destination ip and port.
        if (update_local_map_entry(ctx) == 1)
        {
            bpf_printk("authorize_v4: Found skip process entry, skip the redirection.");
            return BPF_SOCK_ADDR_VERDICT_PROCEED;
        }

        // TODO: check if the local ip is set.
        // __u32 local_ip;
        // __u64 read = bpf_probe_read_kernel(&local_ip, sizeof(__u32), &ctx->msg_src_ip4);
        // if (read == 0 && local_ip != 0)
        // {
        //     // read the local ip from the msg_src_ip4 successfully and ip is set.
        //     ctx->user_ip4 = local_ip;
        //     bpf_printk("authorize_v4: Local/source ip is set, redirect to source ip:%u.", local_ip);
        // }
        // else
        {
            ctx->user_ip4 = policy->destination_ip.ipv4;
            bpf_printk("authorize_v4: Local/source ip is not set, redirect to loopback ip.");
        }
        ctx->user_port = policy->destination_port;
    }

    return BPF_SOCK_ADDR_VERDICT_PROCEED;
}

SEC("cgroup/connect4")
int connect4(struct bpf_sock_addr *ctx)
{
    __u64 cokkie = bpf_get_socket_cookie(ctx);
    return authorize_v4(ctx);
}

static __always_inline int
update_audit_map_entry_sk(__u32 local_port, sock_addr_local_entry *local_entry)
{
    sock_addr_aduit_key key = {0};
    key.protocol = local_entry->protocol;
    key.source_port = local_port;

    sock_addr_audit_entry entry = {0};
    entry.process_id = local_entry->process_id;
    entry.logon_id = local_entry->logon_id;
    entry.is_root = local_entry->is_root;
    entry.destination_ipv4 = local_entry->destination_ipv4;
    entry.destination_port = local_entry->destination_port;

    __u64 ret = bpf_map_update_elem(&audit_map, &key, &entry, 0);
    if (ret != 0)
    {
        bpf_printk("update_audit_map_entry_sk: Failed to update audit map entry with results:%u.", ret);
    }
    else
    {
        bpf_printk("update_audit_map_entry_sk: Updated audit map entry with local port:%u.", key.source_port);
    }

    return 0;
}

static __always_inline int
trace_v4(struct pt_regs *ctx, struct probe_sock *sk)
{
    struct sock_common skc;
    // bpf_probe_read_kernel helper function requires kernel version 5.5+
    // hence have to use bpf_probe_read helper function instead.
    long re = bpf_probe_read(&skc, sizeof(struct sock_common), &sk->__sk_common);
    if (re != 0)
    {
        // 0 is success.
        return 0;
    }
    if (skc.skc_family != AF_INET)
    {
        // Only support IPv4.
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    if (check_skip_process_map_entry(pid) == 1)
    {
        bpf_printk("trace_v4: Found skip process entry %u, skip the trace.", pid);
        return 0;
    }

    // Find the entry in the local map.
    sock_addr_local_entry *local_entry = bpf_map_lookup_elem(&local_map, &pid_tgid);
    if (local_entry != NULL)
    {
        update_audit_map_entry_sk(skc.skc_num, local_entry);
        __u64 ret = bpf_map_delete_elem(&local_map, &pid_tgid);
        if (ret != 0)
        {
            bpf_printk("trace_v4: Failed to delete local map entry with results:%u.", ret);
        }
        else
        {
            bpf_printk("trace_v4: Deleted local map entry with key:%u.", pid_tgid);
        }
        return 0;
    }

    destination_entry entry = {0};
    entry.destination_ip.ipv4 = skc.skc_daddr;
    entry.destination_port = skc.skc_dport;
    entry.protocol = IPPROTO_TCP;
    // Find the entry in the policy map.
    destination_entry *policy = bpf_map_lookup_elem(&policy_map, &entry);
    if (policy != NULL)
    {
        __u32 uid = (__u32)(bpf_get_current_uid_gid() >> 32);
        sock_addr_aduit_key key = {0};
        key.protocol = IPPROTO_TCP;
        key.source_port = skc.skc_num;

        sock_addr_audit_entry entry = {0};
        entry.process_id = pid;
        entry.logon_id = uid;
        entry.is_root = (uid == 0) ? 1 : 0; // root uid is 0.
        entry.destination_ipv4 = skc.skc_daddr;
        entry.destination_port = skc.skc_dport;

        __u64 ret = bpf_map_update_elem(&audit_map, &key, &entry, 0);
        if (ret != 0)
        {
            bpf_printk("trace_v4: Failed to update audit map entry with results:%u.", ret);
        }
        else
        {
            bpf_printk("trace_v4: Updated audit map entry with local port:%u.", key.source_port);
        }
    }

    return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct probe_sock *sk)
{
    return trace_v4(ctx, sk);
}

char _license[] SEC("license") = "GPL";