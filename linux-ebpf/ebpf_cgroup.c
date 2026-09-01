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
#include <bpf/bpf_endian.h>

#include "socket.h"

// BPF maps for policy and audit
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct gpa_skip_process_entry);
    __type(value, struct gpa_skip_process_entry);
    __uint(max_entries, 10);
} skip_process_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct gpa_destination_entry);
    __type(value, struct gpa_destination_entry);
    __uint(max_entries, 10);
} policy_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct gpa_config_entry);
    __uint(max_entries, 1);
} config_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct gpa_audit_key);     // source port and protocol
    __type(value, struct gpa_audit_event); // audit event (canonical struct)
    __uint(max_entries, 200);              // LRU evicts oldest on overflow
} audit_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} audit_only_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u64); // pid-tgid or socket cookie
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

static __always_inline int
local_ip_bind_monitor_only_enabled(void)
{
    __u32 key = GPA_CONFIG_LOCAL_IP_BIND_MONITOR_ONLY;
    struct gpa_config_entry *entry = bpf_map_lookup_elem(&config_map, &key);
    return entry != NULL && entry->enabled != 0;
}

/*
    update audit map entry if not skip redirecting.
    return 0 if the entry is updated, otherwise
    return 1 if pid found in the skip_process_map.
*/
static __always_inline int
update_local_map_entry(struct bpf_sock_addr *ctx, __u32 audit_only, __be32 destination_ipv4, __u32 address_family)
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
    entry.is_root = (uid == 0) ? 1 : 0; // root uid is 0.
    entry.destination_ipv4 = destination_ipv4;
    entry.destination_port = ctx->user_port;
    entry.protocol = ctx->protocol;
    entry.audit_only = audit_only;
    entry.address_family = address_family;

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

        // At connect4, msg_src_ip4 is not valid; it is only populated for
        // UDP sendmsg hooks. A concrete address set by bind(2) is available
        // from the socket before TCP performs automatic source selection.
        __u32 source_ip = ctx->sk != NULL ? ctx->sk->src_ip4 : 0;
        __u32 source_ip_host = bpf_ntohl(source_ip);
        __u32 audit_only = local_ip_bind_monitor_only_enabled() &&
                           source_ip != 0 &&
                           (source_ip_host & 0xff000000) != 0x7f000000;

        // update to the audit map before changing the destination ip and port.
        if (update_local_map_entry(ctx, audit_only, ctx->user_ip4, GPA_ADDRESS_FAMILY_IPV4) == 1)
        {
            bpf_printk("authorize_v4: Found skip process entry, skip the redirection.");
            return BPF_SOCK_ADDR_VERDICT_PROCEED;
        }

        if (audit_only)
        {
            bpf_printk("authorize_v4: Source address is explicitly bound, audit without redirecting.");
            return BPF_SOCK_ADDR_VERDICT_PROCEED;
        }

        ctx->user_ip4 = policy->destination_ip.ipv4;
        bpf_printk("authorize_v4: Local/source ip is not set, redirect to loopback ip.");
        ctx->user_port = policy->destination_port;
    }

    return BPF_SOCK_ADDR_VERDICT_PROCEED;
}

SEC("cgroup/connect4")
int connect4(struct bpf_sock_addr *ctx)
{
    return authorize_v4(ctx);
}

/// @brief Extract the IPv4 address from an IPv4-mapped IPv6 address.
/// @param ctx The socket address context containing the IPv6 address.
/// @param destination_ipv4 Pointer to store the extracted IPv4 address.
/// @return 1 if the address is IPv4-mapped, 0 otherwise.
static __always_inline int
get_ipv4_mapped_address(struct bpf_sock_addr *ctx, __be32 *destination_ipv4)
{
    if (ctx->user_ip6[0] != 0 ||
        ctx->user_ip6[1] != 0 ||
        ctx->user_ip6[2] != bpf_htonl(0x0000ffff))
    {
        return 0;
    }

    *destination_ipv4 = ctx->user_ip6[3];
    return 1;
}

SEC("cgroup/connect6")
int connect6(struct bpf_sock_addr *ctx)
{
    __be32 destination_ipv4;
    if (get_ipv4_mapped_address(ctx, &destination_ipv4) == 0)
    {
        // Native IPv6 destinations are not supported yet and must remain unchanged.
        return BPF_SOCK_ADDR_VERDICT_PROCEED;
    }

    struct gpa_destination_entry entry = {0};
    entry.destination_ip.ipv4 = destination_ipv4;
    entry.destination_port = ctx->user_port;
    entry.protocol = ctx->protocol;

    struct gpa_destination_entry *policy = bpf_map_lookup_elem(&policy_map, &entry);
    if (policy != NULL)
    {
        bpf_printk("connect6: Found IPv4-mapped proxy entry.");
        // TODO: check bind to IPv4 mapped address, if so, skip the redirection and update the audit map.
        __u32 audit_only = 0;
        if (update_local_map_entry(ctx, audit_only, destination_ipv4, GPA_ADDRESS_FAMILY_IPV6) == 1)
        {
            bpf_printk("connect6: Found skip process entry, skip the redirection.");
            return BPF_SOCK_ADDR_VERDICT_PROCEED;
        }

        // Keep the socket in AF_INET6 and redirect it to IPv4-mapped loopback.
        ctx->user_ip6[0] = 0;
        ctx->user_ip6[1] = 0;
        ctx->user_ip6[2] = bpf_htonl(0x0000ffff);
        ctx->user_ip6[3] = policy->destination_ip.ipv4;
        ctx->user_port = policy->destination_port;
    }

    return BPF_SOCK_ADDR_VERDICT_PROCEED;
}

static __always_inline int
update_audit_map_entry_sk(__u32 local_port, __u32 local_ipv4, struct gpa_sock_addr_local_entry *local_entry)
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
    entry.address_family = local_entry->address_family;

    __u64 ret;
    if (local_entry->audit_only)
    {
        struct gpa_audit_only_event event = {0};
        event.kernel_timestamp_ns = bpf_ktime_get_ns();
        event.local_ipv4 = local_ipv4;
        event.audit = entry;
        ret = bpf_ringbuf_output(&audit_only_map, &event, sizeof(event), 0);
    }
    else
    {
        ret = bpf_map_update_elem(&audit_map, &key, &entry, 0);
    }
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
trace_tcp_connect(struct sock *sk)
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
    __be32 skc_rcv_saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    __be16 skc_dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    __u16 skc_num = BPF_CORE_READ(sk, __sk_common.skc_num);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    if (check_skip_process_map_entry(pid) == 1)
    {
        bpf_printk("trace_tcp_connect: Found skip process entry %u, skip the trace.", pid);
        return 0;
    }

    // Find the entry in the local map.
    struct gpa_sock_addr_local_entry *local_entry = bpf_map_lookup_elem(&local_map, &pid_tgid);
    if (local_entry != NULL)
    {
        update_audit_map_entry_sk(skc_num, skc_rcv_saddr, local_entry);
        __u64 ret = bpf_map_delete_elem(&local_map, &pid_tgid);
        if (ret != 0)
        {
            bpf_printk("trace_tcp_connect: Failed to delete local map entry with results:%u.", ret);
        }
        else
        {
            bpf_printk("trace_tcp_connect: Deleted local map entry with key:%u.", pid_tgid);
        }
        return 0;
    }

    return 0;
}

SEC("kprobe/tcp_connect")         // ELF program type/section metadata
int BPF_KPROBE(tcp_connect_probe, // eBPF program name used by Aya
               struct sock *sk)
{
    return trace_tcp_connect(sk);
}

char _license[] SEC("license") = "GPL";