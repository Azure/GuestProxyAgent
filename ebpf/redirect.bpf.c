// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "socket.h"

// SEC("maps")
#pragma clang section data = "maps"
struct bpf_map_def policy_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(destination_entry_t),
    .value_size = sizeof(destination_entry_t),
    .max_entries = 10};

#pragma clang section data = "maps"
struct bpf_map_def config_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(struct gpa_config_entry),
    .max_entries = 1};

#pragma clang section data = "maps"
struct bpf_map_def skip_process_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(sock_addr_skip_process_entry),
    .value_size = sizeof(sock_addr_skip_process_entry),
    .max_entries = 10};

#pragma clang section data = "maps"
struct bpf_map_def audit_map = {
    .type = BPF_MAP_TYPE_LRU_HASH,             // retain the latest records automatically
    .key_size = sizeof(sock_addr_audit_key_t), // source port and protocol
    .value_size = sizeof(sock_addr_audit_entry_t),
    .max_entries = 1000};

#pragma clang section data = "maps"
struct bpf_map_def audit_only_map = {
    .type = BPF_MAP_TYPE_RINGBUF,
    .key_size = 0,
    .value_size = 0,
    .max_entries = 256 * 1024};

/*
    check the current pid in the skip_process map.
    return 1 if found, otherwise return 0.
*/
inline __attribute__((always_inline)) int
check_skip_process_map_entry(uint32_t pid)
{
    sock_addr_skip_process_entry key = {0};
    key.pid = pid;

    // Find the entry in the skip_process map.
    sock_addr_skip_process_entry *skip_entry = bpf_map_lookup_elem(&skip_process_map, &key);
    return (skip_entry != NULL) ? 1 : 0;
}

inline __attribute__((always_inline)) int
local_ip_bind_monitor_only_enabled(void)
{
    uint32_t key = GPA_CONFIG_LOCAL_IP_BIND_MONITOR_ONLY;
    struct gpa_config_entry *entry = bpf_map_lookup_elem(&config_map, &key);
    return entry != NULL && entry->enabled != 0;
}

/*
    update audit map entry if not skip redirecting.
    return 0 if the entry is updated, otherwise
    return 1 if pid found in the skip_process_map.
*/
inline __attribute__((always_inline)) int
update_audit_map_entry(bpf_sock_addr_t *ctx, int audit_only, uint32_t destination_ipv4, uint32_t address_family)
{
    uint64_t pid_tip = bpf_get_current_pid_tgid();
    uint32_t pid = (uint32_t)(pid_tip >> 32);

    if (check_skip_process_map_entry(pid) == 1)
    {
        return 1;
    }

    sock_addr_audit_entry_t entry = {0};
    entry.process_id = pid;
    entry.logon_id = (uint32_t)bpf_get_current_logon_id(ctx);
    if (entry.logon_id == 0)
    {
        bpf_printk("Failed to get logon id.");
    }
    int32_t is_admin = bpf_is_current_admin(ctx);
    if (is_admin < 0)
    {
        bpf_printk("Failed to get admin status %d.", is_admin);
        entry.is_root = 0;
    }
    else
    {
        entry.is_root = (is_admin > 0) ? 1 : 0;
    }
    entry.destination_ipv4 = destination_ipv4;
    entry.destination_port = ctx->user_port;
    entry.address_family = address_family;
    uint16_t source_port = ctx->msg_src_port;
    if (audit_only)
    {
        struct gpa_audit_only_event event = {0};
        event.kernel_timestamp_ns = bpf_ktime_get_ns();
        event.local_ipv4 = ctx->msg_src_ip4;
        event.audit = entry;
        uint64_t ret = bpf_ringbuf_output(&audit_only_map, &event, sizeof(event), 0);
        if (ret != 0)
        {
            bpf_printk("Failed to emit audit-only event with results: %u.", ret);
        }
        return 0;
    }

    if (source_port == 0)
    {
        int32_t result = bpf_sock_addr_set_redirect_context(ctx, &entry, sizeof(sock_addr_audit_entry_t));
        if (result != 0)
        {
            bpf_printk("Failed to add audit entry to redirect context with result %u.", result);
        }
        else
        {
            bpf_printk("Added audit entry to redirect context.");
        }
    }
    else
    {
        sock_addr_audit_key_t key = {0};
        key.protocol = ctx->protocol;
        key.source_port = source_port;
        uint64_t ret = bpf_map_update_elem(&audit_map, &key, &entry, 0);
        if (ret != 0)
        {
            bpf_printk("Failed to update audit map with results: %u.", ret);
        }
        else
        {
            bpf_printk("Added audit entry with source port: %u", source_port);
        }
    }
    return 0;
}

inline __attribute__((always_inline)) int
authorize_v4(bpf_sock_addr_t *ctx)
{
    destination_entry_t entry = {0};
    entry.destination_ip.ipv4 = ctx->user_ip4;
    entry.destination_port = ctx->user_port;
    entry.protocol = ctx->protocol;

    // Find the entry in the policy map.
    destination_entry_t *policy = bpf_map_lookup_elem(&policy_map, &entry);
    if (policy != NULL)
    {
        bpf_printk("Found v4 proxy entry value: %u, %u", policy->destination_ip.ipv4, policy->destination_port);

        uint32_t source_ip = ctx->msg_src_ip4;
        int audit_only = local_ip_bind_monitor_only_enabled() && // check the config map for localIPBindMonitorOnly
                         source_ip != 0 && (source_ip & 0xff) != 0x7f; // check if the source ip is set and not loopback

        // update to the audit map before changing the destination ip and port.
        if (update_audit_map_entry(ctx, audit_only, ctx->user_ip4, GPA_ADDRESS_FAMILY_IPV4) == 1)
        {
            bpf_printk("Found skip process entry, skip the redirection.");
            return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
        }

        if (audit_only)
        {
            bpf_printk("Source address is explicitly bound, audit without redirecting.");
            return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
        }

        bpf_printk("redirecting to destination loopback ip.");
        ctx->user_ip4 = policy->destination_ip.ipv4;
        ctx->user_port = policy->destination_port;
    }

    return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
}

// SEC("cgroup/connect4")
#pragma clang section text = "cgroup/connect4"
int authorize_connect4(bpf_sock_addr_t *ctx)
{
    return authorize_v4(ctx);
}

inline __attribute__((always_inline)) int
get_ipv4_mapped_address(bpf_sock_addr_t *ctx, uint32_t *destination_ipv4)
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

// SEC("cgroup/connect6")
#pragma clang section text = "cgroup/connect6"
int authorize_connect6(bpf_sock_addr_t *ctx)
{
    // Check if the destination address is an IPv4-mapped IPv6 address.
    // While the current eBPF_for_Windows detects the IPv4-mapped address, 
    // explicitly classify/convert dual-stack IPv4-mapped connections as IPv4.
    // refer to https://github.com/microsoft/ebpf-for-windows/issues/5536
    // We keep this logic here to support dual-stack IPv4-mapped connections in connect6,
    // just in case windows eBPF may change the behavior to align with Linux eBPF.
    uint32_t destination_ipv4;
    if (get_ipv4_mapped_address(ctx, &destination_ipv4) == 0)
    {
        // Native IPv6 destinations are not redirected by the IPv4 policy map.
        return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
    }

    destination_entry_t entry = {0};
    entry.destination_ip.ipv4 = destination_ipv4;
    entry.destination_port = ctx->user_port;
    entry.protocol = ctx->protocol;

    destination_entry_t *policy = bpf_map_lookup_elem(&policy_map, &entry);
    if (policy != NULL)
    {
        bpf_printk("Found IPv4-mapped proxy entry.");
        //TODO: check bind to IPv4 mapped address, if so, skip the redirection and update the audit map.
        int audit_only = 0;
        if (update_audit_map_entry(ctx, audit_only, destination_ipv4, GPA_ADDRESS_FAMILY_IPV6) == 1)
        {
            bpf_printk("Found skip process entry, skip the redirection.");
            return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
        }

        ctx->user_ip6[0] = 0;
        ctx->user_ip6[1] = 0;
        ctx->user_ip6[2] = bpf_htonl(0x0000ffff);
        ctx->user_ip6[3] = policy->destination_ip.ipv4;
        ctx->user_port = policy->destination_port;
    }

    return BPF_SOCK_ADDR_VERDICT_PROCEED_SOFT;
}
