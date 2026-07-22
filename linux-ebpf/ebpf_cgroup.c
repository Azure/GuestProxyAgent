// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
//
// eBPF cgroup/connect4 program for connection interception and audit
// Uses CO-RE (Compile Once, Run Everywhere) for kernel compatibility

#include <linux/bpf.h>
#include <asm/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "socket.h"

// BPF maps for policy and audit
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct gpa_skip_process_entry);
    __type(value, struct gpa_skip_process_entry);
    __uint(max_entries, 10);
} skip_process_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct gpa_destination_entry);
    __type(value, struct gpa_destination_entry);
    __uint(max_entries, 10);
} policy_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct gpa_audit_key);        // source port and protocol
    __type(value, struct gpa_audit_event);    // audit event (canonical struct)
    __uint(max_entries, 200);                 // LRU evicts oldest on overflow
} audit_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u64);                       // pid-tgid or socket cookie
    __type(value, struct gpa_sock_addr_local_entry);
    __uint(max_entries, 200);
} local_map SEC(".maps");


/*
    check the current pid in the skip_process map.
    return 1 if found, otherwise return 0.
*/
static __always_inline int
check_skip_process_map_entry(__u32 pid)
{
    struct gpa_skip_process_entry key = {0};
    key.pid = pid;

    // Find the entry in the skip_process map.
    struct gpa_skip_process_entry *skip_entry = bpf_map_lookup_elem(&skip_process_map, &key);
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

    struct gpa_sock_addr_local_entry entry = {0};
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
    struct gpa_destination_entry entry = {0};
    entry.destination_ip.ipv4 = ctx->user_ip4;
    entry.destination_port = ctx->user_port;
    entry.protocol = ctx->protocol;

    // Find the entry in the policy map.
    struct gpa_destination_entry *policy = bpf_map_lookup_elem(&policy_map, &entry);
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
    __u64 cookie = bpf_get_socket_cookie(ctx);
    return authorize_v4(ctx);
}

static __always_inline int
update_audit_map_entry_sk(__u32 local_port, struct gpa_sock_addr_local_entry *local_entry)
{
    struct gpa_audit_key key = {0};
    key.protocol = local_entry->protocol;
    key.source_port = local_port;

    struct gpa_audit_event entry = {0};
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
trace_v4(struct pt_regs *ctx, struct sock *sk)
{
    // CO-RE relocatable reads of kernel struct sock fields.
    // BPF_CORE_READ relocates each field offset on the KERNEL-side type
    // (struct sock, which carries preserve_access_index in socket.h) to the
    // running kernel's layout at load time. The destinations below are plain
    // local scalars (no preserve_access_index), so their offsets are NOT
    // relocated - this is required, otherwise the verifier rejects writes that
    // would land outside our local stack copy.
    __u16 skc_family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (skc_family != AF_INET)
    {
        // Only support IPv4.
        return 0;
    }
    __be32 skc_daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    __be16 skc_dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    __u16 skc_num = BPF_CORE_READ(sk, __sk_common.skc_num);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    if (check_skip_process_map_entry(pid) == 1)
    {
        bpf_printk("trace_v4: Found skip process entry %u, skip the trace.", pid);
        return 0;
    }

    // Find the entry in the local map.
    struct gpa_sock_addr_local_entry *local_entry = bpf_map_lookup_elem(&local_map, &pid_tgid);
    if (local_entry != NULL)
    {
        update_audit_map_entry_sk(skc_num, local_entry);
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

    struct gpa_destination_entry entry = {0};
    entry.destination_ip.ipv4 = skc_daddr;
    entry.destination_port = skc_dport;
    entry.protocol = IPPROTO_TCP;
    // Find the entry in the policy map.
    struct gpa_destination_entry *policy = bpf_map_lookup_elem(&policy_map, &entry);
    if (policy != NULL)
    {
        __u32 uid = (__u32)(bpf_get_current_uid_gid() >> 32);
        struct gpa_audit_key key = {0};
        key.protocol = IPPROTO_TCP;
        key.source_port = skc_num;

        struct gpa_audit_event audit_entry = {0};
        audit_entry.process_id = pid;
        audit_entry.logon_id = uid;
        audit_entry.is_root = (uid == 0) ? 1 : 0; // root uid is 0.
        audit_entry.destination_ipv4 = skc_daddr;
        audit_entry.destination_port = skc_dport;

        __u64 ret = bpf_map_update_elem(&audit_map, &key, &audit_entry, 0);
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
int BPF_KPROBE(tcp_v4_connect, struct sock *sk)
{
    return trace_v4(ctx, sk);
}

char _license[] SEC("license") = "GPL";