// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
//
// Linux-specific eBPF helpers and definitions
// Includes shared audit event structures from gpa_audit_event.h

#pragma once

#include "../shared-ebpf/include/gpa_audit_event.h"
#include "../shared-ebpf/include/gpa_libbpf_helpers.h"

// Linux-specific verdicts
#define BPF_SOCK_ADDR_VERDICT_PROCEED 1

// Standard protocol constants
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define AF_INET 2
#define AF_INET6 10

// Type aliases for backward compatibility with existing code
typedef struct gpa_skip_process_entry sock_addr_skip_process_entry;
typedef struct gpa_destination_entry destination_entry;
typedef struct gpa_audit_key sock_addr_audit_key;
typedef struct gpa_audit_event sock_addr_audit_entry;
typedef struct gpa_sock_addr_local_entry sock_addr_local_entry;

// IPv4 socket tuple (used for connection tracking)
typedef struct _bpf_sock_tuple_ipv4
{
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
} bpf_sock_tuple_ipv4;

// ============================================================================
// CO-RE kernel struct definitions
// ============================================================================
// These minimal kernel struct definitions are marked with
// __attribute__((preserve_access_index)) which is the CORE of CO-RE:
// instead of hardcoding field offsets at compile time, the BPF loader
// (libbpf/aya) relocates each field access to the TARGET kernel's actual
// offset at load time, using the kernel's BTF (/sys/kernel/btf/vmlinux).
//
// This is what makes "Compile Once, Run Everywhere" work: the same .bpf.o
// adapts to different kernel versions automatically.

#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)

// Minimal sock_common - only the fields we actually read.
// Field offsets are relocated by CO-RE; we only need the names to match
// the kernel's struct sock_common (verified against vmlinux BTF).
struct sock_common {
    union {
        struct {
            __be32 skc_daddr;
            __be32 skc_rcv_saddr;
        };
    };
    union {
        struct {
            __be16 skc_dport;
            __u16 skc_num;
        };
    };
    short unsigned int skc_family;
};

// Minimal sock wrapper - we only access __sk_common.
// IMPORTANT: this must be named exactly "sock" (the kernel's type name) so the
// CO-RE relocation against &sk->__sk_common resolves to struct sock in the
// target kernel's BTF. A custom name (e.g. probe_sock) does not exist in
// kernel BTF and makes the program fail to load.
struct sock {
    struct sock_common __sk_common;
};

#pragma clang attribute pop