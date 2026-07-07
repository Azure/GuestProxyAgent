## Sections

1.  [1. Overview](#overview)
2.  [2. Today](#today)
3.  [3. CO-RE design](#design)
4.  [4. Shared headers](#shared)
5.  [5. Build system](#build)
6.  [6. BTF strategy](#btf)
7.  [7. Integration](#integration)
8.  [8. Tests](#tests)
9.  [9. Risks](#risks)
10. [10. Milestones](#milestones)

**GPA** · **Direction 4.2** · **eBPF**

# Detailed Design — Unify Linux/Windows eBPF on CO-RE

Replace today's per-kernel-version eBPF source duplication with CO-RE (Compile Once, Run Everywhere). Share data structures between Linux (`linux-ebpf/`) and Windows (`ebpf/`), reduce build matrix to one object per program per platform.

**Files affected:** `shared-ebpf/include/`, `linux-ebpf/`, `ebpf/`, `proxy_agent/build.rs`, `build-linux.sh`, `proxy_agent/src/redirector/`.

> **Prerequisites:** None — foundational eBPF layer. Unblocks [4.1](Innovation-4.1-sk-lookup-bpf-lsm.md), [4.3](Innovation-4.3-ipv6-dual-stack.md), [4.4](Innovation-4.4-ebpf-throttling-lru.md), [5.1](Innovation-5.1-aks-container-native.md), [5.3](Innovation-5.3-cross-cloud-port.md).

> **Status (Linux/Windows):** ✅ Implemented for Linux CO-RE. ✅ Windows now uses shared audit structs in `ebpf/` and keeps runtime compatibility with both new and legacy Windows eBPF audit layouts during mixed-version rollout.

## 1. Overview & Goals

| Impact                             | Effort     | Risk    | Scope            |
|------------------------------------|------------|---------|------------------|
| **Medium** maintainability + reach | **Medium** | **Low** | **eBPF + build** |

### Goals

- One eBPF object per program, portable across kernel versions via CO-RE relocations.
- Shared C header for the audit event struct, consumed by both Linux and Windows.
- Lower QA burden — no need to rebuild per kernel.

## 2. Today

Linux and Windows have two source trees with similar logic but separate definitions of the audit event struct, depending on platform tooling. Some Linux fields are hardcoded to specific kernel offsets, requiring per-distro builds for older targets.

## 3. CO-RE Design

**Implemented (Linux):**

- The Linux loader is **aya** (`EbpfLoader::new().btf(Btf::from_sys_fs().ok().as_ref()).load_file(...)` in `proxy_agent/src/redirector/linux.rs`). Passing the kernel BTF from `/sys/kernel/btf/vmlinux` is what enables aya to apply CO-RE relocations at load time.
- Rather than pulling in a full generated `vmlinux.h`, `linux-ebpf/socket.h` declares **minimal kernel structs** (`struct sock`, `struct sock_common` — only the fields we read) inside a `#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)` block. `preserve_access_index` is the mechanism that turns each field access into a CO-RE relocation record (emitted into `.BTF`/`.BTF.ext` by `clang -g`).
- Kernel fields are read with `BPF_CORE_READ(sk, __sk_common.skc_daddr)` etc. into **plain local scalars**, e.g.:

      __u16  skc_family = BPF_CORE_READ(sk, __sk_common.skc_family);
      __be32 skc_daddr  = BPF_CORE_READ(sk, __sk_common.skc_daddr);
      __be16 skc_dport  = BPF_CORE_READ(sk, __sk_common.skc_dport);
      __u16  skc_num    = BPF_CORE_READ(sk, __sk_common.skc_num);

  This replaces the old `bpf_probe_read()` blob read against hardcoded offsets.

**Two non-obvious requirements** (both caused load failures during bring-up):

1. The kernel wrapper type **must be named `sock`** (the real kernel type name). A custom name such as `probe_sock` does not exist in the kernel BTF, so the `<byte_off> ... struct probe_sock.__sk_common` relocation fails and the program is rejected at load.
2. The **destination of the read must be a plain (non-relocatable) type**. If you read into a local `struct sock_common` that also carries `preserve_access_index`, the write offset is relocated to the *kernel's* offset (e.g. `skc_family` at 16) and overflows the local stack copy — the verifier rejects it with `invalid write to stack`.

- For Windows, `ebpf/socket.h` now aliases to the canonical shared header (`shared-ebpf/include/gpa_audit_event.h`) so map and redirect-context layouts align with the shared contract. The shared Rust decoder in `proxy_agent/src/redirector/shared_ebpf.rs` accepts both the canonical layout and the legacy layout to preserve compatibility with previously shipped eBPF programs.

## 4. Shared Headers

The canonical, platform-neutral structs live in `shared-ebpf/include/gpa_audit_event.h` and are consumed by `linux-ebpf/` today (and referenced by `ebpf/` for the Windows bridge). Their layouts are **binary-compatible with the shared Rust model** in `proxy_agent/src/redirector/shared_ebpf.rs`, which maps each to a fixed-size `[u32; N]` array and exports Linux/Windows-specific aliases from one place — so field order/size cannot change without updating both sides.

    // shared-ebpf/include/gpa_audit_event.h
    #pragma once

    struct gpa_ip_address {                 // 16 B  ([u32; 4])
        union { __u32 ipv4; __u32 ipv6[4]; };
    };
    struct gpa_destination_entry {          // 24 B  ([u32; 6])
        struct gpa_ip_address destination_ip;
        __u32 destination_port;
        __u32 protocol;
    };
    struct gpa_audit_key {                  //  8 B  ([u32; 2])
        __u32 protocol;
        __u32 source_port;
    };
    struct gpa_audit_event {                // 20 B  ([u32; 5])
        __u32 logon_id;        // Linux: uid;  Windows: logon_id
        __u32 process_id;
        __u32 is_root;         // 1 if root/admin
        __u32 destination_ipv4;
        __u32 destination_port;
    };
    struct gpa_skip_process_entry { __u32 pid; };   // 4 B ([u32; 1])

- The layout is locked at compile time with `_Static_assert(sizeof(...) == N, ...)` for each struct, so an accidental layout drift fails the eBPF build immediately instead of silently corrupting map data.
- `linux-ebpf/socket.h` provides backward-compatible `typedef`s (`destination_entry`, `sock_addr_audit_key`, `sock_addr_audit_entry`, ...) onto the `gpa_*` structs so existing code reads unchanged.
- The matching Rust layout is asserted by the `redirector::shared_ebpf` unit tests (`destination_entry_ipv4_roundtrip_array_shape`, `skip_process_entry_pid_roundtrip`, `audit_entry_canonical_array_roundtrip`, ...).

## 5. Build System

Linux eBPF objects are compiled by **`proxy_agent/build.rs`** during normal `cargo build`:

- Invokes `clang -target bpf -Werror -O2 -g <arch-define> -I shared-ebpf/include -I linux-ebpf -c linux-ebpf/ebpf_cgroup.c -o ebpf_cgroup.o`. `-g` emits the `.BTF`/`.BTF.ext` sections that carry the CO-RE relocation records.
- **Arch-aware:** reads `CARGO_CFG_TARGET_ARCH` and selects `-D__TARGET_ARCH_x86` (x86_64) or `-D__TARGET_ARCH_arm64 -I/usr/include/aarch64-linux-gnu` (aarch64), mirroring the two branches that used to live in `build-linux.sh`.
- **Fails the build on any eBPF error** (`-Werror` + `panic!` on non-zero clang exit), so a broken program is never shipped.
- **Deterministic placement:** after compiling into `OUT_DIR`, the object is copied to the profile dir (e.g. `target/debug`, `out/<triple>/release`) and its `deps/` subdir. This guarantees the runtime loader (current-exe dir) and the test harness always load the freshly compiled object instead of a stale copy from another `azure-proxy-agent-<hash>` build directory.
- `cargo:rerun-if-changed` on `shared-ebpf/include` and `linux-ebpf` recompiles whenever sources change.

**`build-linux.sh`** no longer compiles eBPF itself: it adds the shared include path, lets `build.rs` produce `ebpf_cgroup.o`, then verifies the object exists at `$out_dir/ebpf_cgroup.o` before packaging.

Windows eBPF objects are compiled by **`build.cmd`** (`redirect.bpf.o` then `redirect.bpf.sys` via `Convert-BpfToNative.ps1`), matching existing Windows packaging/signing workflow.

- Output name is `ebpf_cgroup.o`, matching `ebpfProgramName` in `proxy_agent/config/GuestProxyAgent.linux.json`. (Future programs — `sk_lookup.o`, `lsm.o` — slot into the `ebpf_programs` list in `build.rs`.)
- Requires `clang` 15+.

## 6. BTF Strategy

- At load time aya reads the kernel-provided `/sys/kernel/btf/vmlinux` (`Btf::from_sys_fs()`) and relocates the program's field accesses to the running kernel's layout.
- We deliberately **do not** ship or commit a generated `vmlinux.h`. The program only touches a handful of `struct sock_common` fields, so minimal hand-declared structs with `preserve_access_index` cover the relocation set and keep the source small. (A generated `vmlinux.h` remains the fallback if future programs touch many kernel structs.)
- Minimum kernel target remains 5.4 (per README), served by CO-RE relocations rather than per-kernel builds.

## 7. Integration

- `proxy_agent/src/redirector/linux.rs` loads the object with **aya** (`EbpfLoader` + BTF), attaches the two programs by name (`connect4` via `CgroupSockAddr`, `tcp_v4_connect` via `KProbe` on `tcp_connect`), and imports its map key/value layouts directly from `proxy_agent/src/redirector/shared_ebpf.rs`.
- `proxy_agent/src/redirector/shared_ebpf.rs` now owns the `[u32; N]` ↔ `gpa_*` binary contract for map keys/values plus the shared audit decode path used by both Linux and Windows.
- Windows side uses the shared header and shared dual-decode compatibility in user-space: `lookup_audit` and redirect-context parsing decode canonical `sock_addr_audit_entry` values when present and fall back to `sock_addr_audit_entry_legacy` when needed.
- Removed: hardcoded-offset blob read of `sock_common`; replaced with per-field CO-RE reads.

## 8. Tests

- `redirector::shared_ebpf` layout unit tests assert the Rust `[u32; N]` mappings match the shared C structs, including Linux key/value roundtrips and Windows-compatible audit decode paths (run on every build).
- `redirector::linux::tests::linux_ebpf_test` (feature `test-with-root`, run by `build-linux.sh`) actually **loads and attaches** the CO-RE object on the build host, exercising the kprobe relocation path end-to-end. Bring-up validated it loads cleanly via `bpftool prog loadall` (no unresolved CO-RE relocations, verifier accepts the program).
- Pending: cross-kernel matrix CI (5.4, 5.15, 6.1, 6.8) loading the same object; load-time budget \< 100 ms; broader Windows compatibility tests that exercise both canonical and legacy audit layouts through the live map and redirect-context paths.

## 9. Risks

- **CO-RE relocation name mismatch** — kernel wrapper types must use real kernel names (`sock`, not `probe_sock`) or relocations fail at load. Mitigation: covered by the `linux_ebpf_test` load test.
- **Relocating a local copy** — reading into a `preserve_access_index` type overflows the stack copy; always read CO-RE fields into plain scalars. Mitigation: documented in `ebpf_cgroup.c`; load test catches regressions.
- **clang/LLVM bugs** in CO-RE relocation. Mitigation: pin clang 15+.
- **Stale object pickup** — multiple build-output dirs can leave old objects around. Mitigation: `build.rs` writes the object to a deterministic profile/`deps` path; `build-linux.sh` verifies it.
- **Mixed-version Windows rollout** — new agent with old eBPF program (or inverse) can misinterpret audit value bytes. Mitigation: user-space decode path validates canonical fields and falls back to legacy layout for map lookup and redirect-context reads.

## 10. Milestones

| M   | Deliverable                                  | Exit                                                 |
|-----|----------------------------------------------|------------------------------------------------------|
| M1  | Linux CO-RE object via aya + preserve_access_index | ✅ `ebpf_cgroup.o` loads/attaches on supported kernels |
| M2  | Shared header + Rust layout assertions       | ✅ `shared_ebpf` layout tests green on Linux and shared decode path in place |
| M3  | Arch-aware, fail-fast, deterministic build   | ✅ `build.rs` (x86_64 + arm64) owns the compile        |
| M4  | Windows migration to shared structs          | ✅ Shared structs active + legacy decode fallback; `build.cmd` owns `redirect.bpf` build |
| M5  | Drop per-kernel builds + cross-kernel CI     | CI matrix \< 1/3 of previous count                   |

Detail design for direction 4.2. Parent: [Innovation-Directions.md](Innovation-Directions.md).
