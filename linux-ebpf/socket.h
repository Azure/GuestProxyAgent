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

// Linux-only executable identity captured from the connecting task's mm->exe_file.
// Kept out of the shared gpa_audit_event so the Windows eBPF ABI is unchanged.
// Size: 16 bytes - matches Rust LinuxExecutableIdentity -> [u32; 4]
struct gpa_linux_executable_identity
{
    __u32 device;   // super_block s_dev (kernel dev_t encoding)
    __u32 inode_low;
    __u32 inode_high;
    __u32 valid;    // 1 when the identity was read successfully
};

// Linux audit_map value: the shared audit event followed by the executable identity.
// Size: 44 bytes - matches Rust LinuxAuditMapValue -> [u32; 11]
struct gpa_linux_audit_event
{
    struct gpa_audit_event audit;
    struct gpa_linux_executable_identity executable;
};

// Linux local_map value. Size: 48 bytes (12 x u32)
struct gpa_linux_sock_addr_local_entry
{
    __u32 protocol;
    struct gpa_linux_audit_event audit;
};

_Static_assert(sizeof(struct gpa_linux_executable_identity) == 16, "executable identity must be 16 bytes");
_Static_assert(sizeof(struct gpa_linux_audit_event) == 44, "linux audit event must be 44 bytes ([u32; 11])");
_Static_assert(sizeof(struct gpa_linux_sock_addr_local_entry) == 48, "linux local entry must be 48 bytes");

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

// Minimal kernel structs used to read the connecting task's executable identity:
//   task_struct->mm->exe_file->f_inode->{i_sb->s_dev, i_ino}
// As with the structs above, only the named fields are declared; CO-RE relocates
// them against the running kernel's BTF, and the type names must match the kernel's.

// Filesystem superblock; s_dev is the backing device (dev_t encoding) of the file's
// filesystem. Together with i_ino it identifies the file independent of any path or
// mount namespace.
struct super_block {
    __u32 s_dev;
};

// On-disk file object; (s_dev, i_ino) is the executable identity compared by user mode.
struct inode {
    unsigned long i_ino;
    struct super_block *i_sb;
};

// Open file object; f_inode is the inode backing the file.
struct file {
    struct inode *f_inode;
};

// Process address space; exe_file is the file execve() mapped as the main
// executable (the same file /proc/<pid>/exe resolves to), but read here without a
// path lookup, so a bind mount or symlink cannot change what is observed.
// May be NULL for kernel threads.
struct mm_struct {
    struct file *exe_file;
};

// Current task (from bpf_get_current_task()); mm is NULL for kernel threads.
struct task_struct {
    struct mm_struct *mm;
};

#pragma clang attribute pop