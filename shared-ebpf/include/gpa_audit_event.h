// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
//
// Shared eBPF header for audit events - used by both Linux and Windows eBPF programs
// This header defines the canonical, platform-neutral struct layout for audit data
// that flows between kernel eBPF programs and user-space policy/audit handlers.
//
// IMPORTANT: These layouts are binary-compatible with the Rust loader in
// proxy_agent/src/redirector/linux/ebpf_obj.rs. The Rust side maps these to
// fixed-size [u32; N] arrays, so field order and sizes MUST NOT change without
// updating both sides simultaneously.

#pragma once

// IP address - union allows IPv4 (first element) or IPv6 (all 4 elements)
// Size: 16 bytes (4 x u32) - matches Rust _ip_address { ip: [u32; 4] }
struct gpa_ip_address {
    union {
        __u32 ipv4;
        __u32 ipv6[4];
    };
};

// Policy destination entry - defines where traffic should be redirected
// Size: 24 bytes - matches Rust destination_entry -> [u32; 6]
//   ip_address(16) + destination_port(4) + protocol(4)
struct gpa_destination_entry {
    struct gpa_ip_address destination_ip;
    __u32 destination_port;    // Port stored as u32 (network byte order in lower 16 bits)
    __u32 protocol;            // IPPROTO_TCP (6) or IPPROTO_UDP (17)
};

// Minimal audit key for map lookups (protocol + source port)
// Size: 8 bytes - matches Rust sock_addr_audit_key -> [u32; 2]
struct gpa_audit_key {
    __u32 protocol;            // IPPROTO_TCP or IPPROTO_UDP
    __u32 source_port;         // Local source port (stored as u32)
};

// Canonical audit event entry - the record stored in the audit map
// Size: 20 bytes - matches Rust sock_addr_audit_entry -> [u32; 5]
//
// NOTE: Field names use Linux semantics (logon_id=uid, is_root). The Windows
// side maps these to its own naming (logon_id, is_admin) at user-space.
// This is the CANONICAL shared struct - both platforms agree on this layout.
struct gpa_audit_event {
    __u32 logon_id;            // Linux: uid;  Windows: logon_id (lower 32 bits)
    __u32 process_id;          // Process ID
    __u32 is_root;             // 1 if root/admin, 0 otherwise
    __u32 destination_ipv4;    // Destination IPv4 address
    __u32 destination_port;    // Destination port (stored as u32)
};

// Skip process entry - processes in this map bypass audit/redirect
// Size: 4 bytes - matches Rust sock_addr_skip_process_entry -> [u32; 1]
struct gpa_skip_process_entry {
    __u32 pid;
};

// Local address entry - tracks current connection state in the local_map
// Size: 24 bytes (6 x u32)
struct gpa_sock_addr_local_entry {
    __u32 logon_id;            // uid
    __u32 process_id;
    __u32 is_root;
    __u32 destination_ipv4;
    __u32 destination_port;
    __u32 protocol;
};

// Compile-time layout assertions to guarantee binary compatibility with Rust loader.
// If these fail, the Rust [u32; N] mappings in ebpf_obj.rs must be updated too.
_Static_assert(sizeof(struct gpa_destination_entry) == 24, "destination_entry must be 24 bytes ([u32; 6])");
_Static_assert(sizeof(struct gpa_audit_key) == 8, "audit_key must be 8 bytes ([u32; 2])");
_Static_assert(sizeof(struct gpa_audit_event) == 20, "audit_event must be 20 bytes ([u32; 5])");
_Static_assert(sizeof(struct gpa_skip_process_entry) == 4, "skip_process_entry must be 4 bytes ([u32; 1])");
