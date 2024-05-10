// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// clang -target bpf -Werror -O2 -c redirect.bpf.c -o redirect.bpf.o

#include "bpf_helpers.h"
#include "socket.h"

// SEC("maps")
#pragma clang section data = "maps"
struct bpf_map_def policy_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(destination_entry_t),
    .value_size = sizeof(destination_entry_t),
    .max_entries = 10};

#pragma clang section data = "maps"
struct bpf_map_def skip_process_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(sock_addr_skip_process_entry),
    .value_size = sizeof(sock_addr_skip_process_entry),
    .max_entries = 10};

#pragma clang section data = "maps"
struct bpf_map_def audit_map = {
    .type = BPF_MAP_TYPE_LRU_HASH,             // retain the latest records automatically
    .key_size = sizeof(sock_addr_aduit_key_t), // source port and protocol
    .value_size = sizeof(sock_addr_audit_entry_t),
    .max_entries = 1000};

/*
    check the current pid in the skip_process map.
    return 1 if found, otherwise return 0.
*/
__attribute__((always_inline)) int
check_skip_process_map_entry(uint32_t pid)
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
__attribute__((always_inline)) int
update_audit_map_entry(bpf_sock_addr_t *ctx)
{
    uint64_t pid_tip = bpf_sock_addr_get_current_pid_tgid(ctx);
    uint32_t pid = (uint32_t)(pid_tip >> 32);

    if (check_skip_process_map_entry(pid) == 1)
    {
        return 1;
    }

    sock_addr_audit_entry_t entry = {0};
    entry.process_id = pid;
    entry.logon_id = bpf_get_current_logon_id(ctx);
    if (entry.logon_id == 0)
    {
        bpf_printk("Failed to get logon id.");
    }
    entry.is_admin = bpf_is_current_admin(ctx);
    if (entry.is_admin < 0)
    {
        bpf_printk("Failed to get admin status %u.", entry.is_admin);
    }
    entry.destination_ipv4 = ctx->user_ip4; // we only support ipv4 so far.
    entry.destination_port = ctx->user_port;
    uint16_t source_port = ctx->msg_src_port;
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
        sock_addr_aduit_key_t key = {0};
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

__attribute__((always_inline)) int
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

        // update to the audit map before changing the destination ip and port.
        if (update_audit_map_entry(ctx) == 1)
        {
            bpf_printk("Found skip process entry, skip the redirection.");
            return BPF_SOCK_ADDR_VERDICT_PROCEED;
        }

        if (ctx->msg_src_ip4 == 0)
        {
            bpf_printk("Local/source ip is not set, redirect to loopback ip.");
            ctx->user_ip4 = policy->destination_ip.ipv4;
        }
        else
        {
            ctx->user_ip4 = ctx->msg_src_ip4;
            bpf_printk("Local/source ip is set, redirect to source ip:%u.", ctx->user_ip4);
        }
        ctx->user_port = policy->destination_port;
    }

    return BPF_SOCK_ADDR_VERDICT_PROCEED;
}

// SEC("cgroup/connect4")
#pragma clang section text = "cgroup/connect4"
int authorize_connect4(bpf_sock_addr_t *ctx)
{
    return authorize_v4(ctx);
}
