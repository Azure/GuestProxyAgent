// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
//
// Shared libbpf helpers and macros for portable eBPF code
// Provides unified interface for both Linux and Windows eBPF programs
//
// For CO-RE kernel struct access, include <bpf/bpf_core_read.h> directly and
// use bpf_core_read() / BPF_CORE_READ(). Those macros rely on the
// preserve_access_index attribute applied to kernel structs (see socket.h),
// which lets the loader relocate field offsets to the target kernel at load time.

#pragma once

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// EOF
