// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
//
// Windows eBPF socket definitions
// Uses shared audit event structures from gpa_audit_event.h
// This header bridges Windows typedefs (uint32_t) with shared kernel definitions (__u32)

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "../shared-ebpf/include/gpa_audit_event.h"

// Standard protocol constants
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

#define AF_INET 2
#define AF_INET6 0x17

typedef struct gpa_destination_entry destination_entry_t;
typedef struct gpa_audit_key sock_addr_audit_key_t;
typedef struct gpa_audit_event sock_addr_audit_entry_t;
typedef struct gpa_skip_process_entry sock_addr_skip_process_entry;