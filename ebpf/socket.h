// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
//
// Windows eBPF socket definitions
// Uses shared audit event structures from gpa_audit_event.h
// This header bridges Windows typedefs (uint32_t) with shared kernel definitions (__u32)

#pragma once

#include <stdbool.h>
#include <stdint.h>

// Standard protocol constants
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

#define AF_INET 2
#define AF_INET6 0x17

// ============================================================================
// MIGRATION IN PROGRESS: These typedefs bridge to shared structures
// See ../shared-ebpf/include/gpa_audit_event.h for canonical definitions
// ============================================================================

// Destination entry for policy routing
// Note: In CO-RE, this will be unified with Linux version
typedef struct _destination_entry
{
    union {
        uint32_t ipv4;
        uint32_t ipv6[4];
    } destination_ip;
    uint16_t destination_port;
    uint32_t protocol;
} destination_entry_t;

// Audit key for efficient map lookups
// Replaces: struct gpa_audit_key (from shared header)
typedef struct _sock_addr_audit_key
{
    uint32_t protocol;
    uint16_t source_port;
} sock_addr_audit_key_t;

// Audit entry - IMPORTANT: This is being unified with gpa_audit_event
// The canonical structure is now at ../shared-ebpf/include/gpa_audit_event.h
// TODO: Migrate to use the shared struct gpa_audit_event when Windows eBPF
//       updates its event ring buffer handling to match Linux/shared layout
typedef struct _sock_addr_audit_entry
{
    uint64_t logon_id;           // Will map to uid in shared struct
    uint32_t process_id;         // Same as pid in shared struct
    int32_t is_admin;            // Same as is_admin in shared struct
    uint32_t destination_ipv4;   // Same in shared struct
    uint16_t destination_port;   // Same in shared struct
} sock_addr_audit_entry_t;

// Skip process entry
typedef struct _sock_addr_skip_process_entry
{
    uint32_t pid;
} sock_addr_skip_process_entry;