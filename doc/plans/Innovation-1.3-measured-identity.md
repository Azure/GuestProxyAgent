## Sections

1.  [1. Overview](#overview)
2.  [2. Today](#today)
3.  [3. Hash sources](#sources)
4.  [4. eBPF event shape](#ebpf)
5.  [5. Rule schema](#rule)
6.  [6. Matcher](#matcher)
7.  [7. Hash enrollment tool](#enroll)
8.  [8. Rollout](#rollout)
9.  [9. Tests](#tests)
10. [10. Risks](#risks)
11. [11. Milestones](#milestones)

**GPA** · **Direction 1.3** · **Identity**

# Detailed Design — Measured Caller Identity

Replace path-string identity matching with a kernel-measured binary hash (IMA / fs-verity on Linux; code-integrity hash on Windows) so that bind-mount tricks, symlinks, and renamed exploits cannot impersonate allow-listed binaries.

**Files affected:** `linux-ebpf/ebpf_cgroup.c`, `ebpf/redirect.bpf.c`, `proxy_agent/src/redirector/`, `proxy_agent/src/key_keeper/key.rs`, `proxy_agent/src/proxy/authorization_rules.rs`.

> **Prerequisites:** [1.2 vTPM sealing](Innovation-1.2-vtpm-sealing.md)

## 1. Overview & Goals

| Impact                 | Effort     | Risk                      | Scope            |
|------------------------|------------|---------------------------|------------------|
| **High** kills C3 / D2 | **Medium** | **Kernel feature matrix** | **agent + eBPF** |

### Goals

- Identity rules match the binary that ran, not a filesystem path the caller can control.
- Bind-mount `/proc/self/exe` (pentest `C3`) and symlink-as-allowed-binary (pentest `D2`) both fail.
- Path rules continue to work for back-compat; hash rules are opt-in per identity.

### Non-goals

- Full TCB attestation of the executing process — that needs IPE/eBPF-LSM and is broader scope.
- Hash-based identity for scripts (the interpreter is what matters; document this).

## 2. Today's Behavior

The redirector reads the caller's executable via `/proc/<pid>/exe` (Linux) or `NtQueryInformationProcess` (Windows) and reports the textual path as `processFullPath`. The rule engine compares this path string against `Identity::exePath`. Both ends can be spoofed in a user namespace by a non-root attacker with mount privileges in their own ns.

## 3. Hash Sources by Platform

| Platform            | Source                                                                                                               | Notes                                                                                       |
|---------------------|----------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------|
| Linux (modern)      | **fs-verity** root hash via `FS_IOC_MEASURE_VERITY` or `ima_file_hash` kfunc                                         | Available on ext4/btrfs/f2fs with kernel ≥ 5.4; root hash is signed and cannot be modified. |
| Linux (fallback)    | **IMA-Measurement** from `/sys/kernel/security/ima/ascii_runtime_measurements`                                       | Requires `ima_policy=tcb`; agent reads at process exec via kprobe.                          |
| Linux (last resort) | SHA-256 of mmap'd file from kernel side via bpf helper `bpf_d_path` + read                                           | More CPU; mark as "advisory" in rule.                                                       |
| Windows             | **Code Integrity** Authenticode hash from `NtQuerySystemInformation(SystemModuleInformationEx)` or WDAC policy cache | Already computed by CI; reuse.                                                              |

## 4. eBPF Event Shape

Extend the audit map value to carry the measurement:

    // linux-ebpf/audit_event.h (shared with userspace via libbpf)
    struct gpa_audit_event {
        __u64 cgroup_id;
        __u32 pid;
        __u64 pid_starttime_ns;
        __u32 uid;
        __u32 gid;
        __u32 measurement_kind;   // 0=none, 1=fs-verity, 2=ima, 3=fallback-sha256
        __u8  measurement[32];    // sha256 truncated to 32 bytes (fs-verity uses root hash)
        char  exe_path[256];      // kept for diagnostics, NEVER used for matching when measurement_kind != 0
    };

The collector populates `measurement` in-kernel for fs-verity (single ioctl-equivalent), and lazily for IMA paths (cache by cgroup+pid_starttime).

## 5. Rule Schema

    // JSON
    "identities": [
      {
        "name": "walinuxagent",
        "userName": "root",
        "exePath": "/usr/sbin/walinuxagent",          // legacy, advisory
        "exeMeasurement": {
          "kind": "fs-verity|ima|sha256",
          "value": "0x9f8a...",                        // hex sha256
          "enforce": true                              // when true, path mismatch -> reject
        }
      }
    ]

### 5.1 Compatibility

- Rules without `exeMeasurement` behave as today.
- If `exeMeasurement.enforce == true` and the caller has no measurement available, identity does *not* match (fail-closed).
- `enforce=false` is "audit only": agent logs measurement mismatch but still applies path-based decision.

## 6. Matcher Changes

    impl Identity {
        pub fn is_match(&self, logger: &mut ConnectionLogger, claims: &Claims) -> bool {
            // existing user/group/processName checks ...

            match (&self.exeMeasurement, &claims.exe_measurement) {
                (Some(rule_m), Some(claim_m)) if rule_m.kind == claim_m.kind => {
                    if !constant_time_eq(&rule_m.value, &claim_m.value) {
                        logger.warn("measurement mismatch");
                        return false;
                    }
                }
                (Some(rule_m), _) if rule_m.enforce => {
                    logger.warn("measurement required but unavailable");
                    return false;  // fail-closed
                }
                _ => {} // advisory mode or no measurement rule
            }

            // existing exePath fallback ...
        }
    }

## 7. Hash Enrollment Tool

New CLI: `gpa identity hash <path>`.

- Detects available measurement source (fs-verity enabled? IMA active? otherwise sha256).
- Prints a ready-to-paste JSON snippet for the rules file.
- `--enable-verity` flag enables fs-verity on the file (`FS_IOC_ENABLE_VERITY`) if FS supports it.
- Batch mode for enumerating allow-listed extension handlers during package build.

## 8. Rollout

1.  Ship eBPF + claims plumbing, no rule changes. Audit-log measurement values only.
2.  Customers add `exeMeasurement.enforce=false` entries; observe divergence in logs.
3.  Flip to `enforce=true` per rule when customers are ready.
4.  Document fs-verity prerequisites and provide enable scripts for standard images.

## 9. Tests

- Bind-mount a copy of `/bin/cat` over `/usr/sbin/walinuxagent` path → measurement mismatch → deny (pentest `C3`).
- Symlink an allowed binary → fs-verity / IMA root hash differs → deny (pentest `D2`).
- Disable IMA, no fs-verity → with `enforce=true`, deny; with `enforce=false`, allow + audit warning.
- Property test: scriptable interpreter (`python /opt/foo.py`) reports interpreter hash, not script — assert documentation explicit.

## 10. Risks

- **fs-verity coverage is partial.** Mitigation: tooling to enable per file; document IMA fallback.
- **Updates flip the hash.** Mitigation: rule schema accepts `"value": ["hash_a", "hash_b"]` list during rolling upgrade windows.
- **Interpreter scripts.** Document — hash is over the interpreter; identify scripts by additional `cmdline` match if needed.

## 11. Milestones

| M   | Deliverable                                                           | Exit                                                             |
|-----|-----------------------------------------------------------------------|------------------------------------------------------------------|
| M1  | Extend eBPF audit event + claims                                      | Measurements visible in connection log; no rule semantics change |
| M2  | Rule schema + matcher                                                 | Round-trip tests for advisory mode                               |
| M3  | `gpa identity hash` CLI                                               | Shipped in setup package                                         |
| M4  | Enforce-mode for first-party rules (walinuxagent, host-side handlers) | Pentest C3, D2 PASS                                              |

Detail design for direction 1.3. Parent: [Innovation-Directions.md](Innovation-Directions.md).
