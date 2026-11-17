**TL;DR:** Windows and Linux eBPF hooks redirect policy-matched connections while retaining original destinations and process identity for user-mode audit correlation. Both platforms let connections proceed despite audit failures; Linux defers TCP correlation until source selection, while Windows uses source-keyed records or socket redirect context.

# eBPF Socket Redirection


<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L2-platform/ebpf-socket-redirection.content.md` for implementation details; stay here for overviews.
> Search the companion for the source-file heading and range-read that section, starting with Purpose and Functionality.
> Verify behavior in source when needed; do not load the entire companion.
<!-- TIER2-POINTER:END -->
## Why

Redirection changes a connection's destination, so the proxy needs a separate
record of the original endpoint and caller. Shared binary layouts keep kernel
records compatible with user-mode consumers without duplicating platform-neutral
definitions. These hooks intercept traffic; their proceed verdicts are not
user-mode authorization decisions.

## What

| Surface | Responsibility |
|---|---|
| `policy_map` | Match destination address, port, and protocol to a replacement endpoint |
| `config_map` | Enable monitor-only handling for explicit non-loopback local bindings |
| `skip_process_map` | Exclude processes from interception |
| `audit_map` | Correlate source address, source port, and protocol with original destination and identity |
| `alert_only_map` | Emit local-bind alerts through a ring buffer |
| Linux `local_map` | Hold pending connection records keyed by process/thread identity until TCP source selection |

### Code Pointers

Paths are repository-relative. Key Classes includes C functions, structures,
typedefs, and Rust constants; declaration-only files have no runtime methods.

| Component | File Path | Key Classes |
|---|---|---|
| Windows interception | `ebpf\redirect.bpf.c` | `authorize_connect4`, `authorize_connect6`, `authorize_v4`, `update_audit_map_entry` |
| Windows socket aliases | `ebpf\socket.h` | `destination_entry_t`, `sock_addr_audit_key_t`, `sock_addr_audit_entry_t`, `sock_addr_skip_process_entry` |
| Linux interception and correlation | `linux-ebpf\ebpf_cgroup.c` | `connect4`, `connect6`, `update_local_map_entry`, `capture_executable_identity`, `tcp_connect_probe`, `trace_tcp_connect`, `update_audit_map_entry_sk` |
| Linux layouts and CO-RE types | `linux-ebpf\socket.h` | `gpa_linux_executable_identity`, `gpa_linux_audit_event`, `gpa_linux_sock_addr_local_entry`, `sock`, `task_struct` |
| Agent constants and re-exports | `proxy_agent\src\common\constants.rs` | `PROXY_AGENT_IP_NETWORK_BYTE_ORDER`, `WIRE_SERVER_IP_NETWORK_BYTE_ORDER`, `IMDS_IP_NETWORK_BYTE_ORDER`, `CGROUP_ROOT` |
| Shared endpoint/service constants | `proxy_agent_shared\src\constants.rs` | `PROXY_AGENT_IP`, `PROXY_AGENT_PORT`, `WIRE_SERVER_IP`, `GA_PLUGIN_IP`, `IMDS_IP`, `PROXY_AGENT_SERVICE_NAME` |
| Canonical kernel/user ABI | `shared-ebpf\include\gpa_audit_event.h` | `gpa_destination_entry`, `gpa_audit_key`, `gpa_audit_event`, `gpa_alert_only_event`, `gpa_config_entry` |
| Shared libbpf includes | `shared-ebpf\include\gpa_libbpf_helpers.h` | No custom symbols; includes Linux BPF definitions and libbpf helpers |

## How

### Match and rewrite without rejecting connections

IPv4 hooks consult destination policy and process exclusions. Policy-matched
connections retain their original destination before rewriting. An explicit
non-loopback local binding produces an alert; when local-bind monitor-only
configuration is enabled, that connection remains unchanged.

IPv6 hooks intercept only IPv4-mapped destinations and preserve the mapped
representation when rewriting. Native IPv6 passes unchanged. Explicit local
IPv6 binding handling remains unimplemented on both platforms.

Both platforms always return a proceed verdict; Windows uses a soft proceed.
Map writes, identity queries, redirect-context operations, and ring-buffer
failures are logged rather than used to reject connections. An audit failure
does not prevent destination rewriting, so redirection does not guarantee a
corresponding audit record.

### Correlate at the platform's source-selection boundary

| Platform | Identity and correlation path |
|---|---|
| Windows | Capture process ID, logon ID, administrator status, original destination, and address family. Concrete source endpoints key `audit_map`; wildcard addresses or zero source ports use socket redirect context instead. Mapped IPv6 sources normalize to IPv4. A failed administrator query records a non-root value. |
| Linux | Store pending original destination, UID/root status, protocol, and executable identity in `local_map`. The `tcp_connect` kprobe reads the selected source through CO-RE, writes `audit_map`, then deletes the pending entry even when the audit write fails. |

Linux executable identity comes from the current task's executable file and
contains device, split inode, and validity fields. Unavailable executable
metadata leaves identity invalid. Source-key construction normalizes mapped
IPv6 to IPv4 and handles IPv6 fields that are still unset with an IPv4 fallback.
The described deferred audit path is TCP-specific; TCP/UDP constants and policy
fields do not establish equivalent UDP correlation.

### Preserve the kernel/user binary contract

The shared header owns address storage, policy destinations, audit keys/events,
alerts, configuration, skipped-process records, and local state. Eight static
assertions enforce exact shared sizes, including 28-byte audit keys/events and
56-byte alerts. Network-order address and destination-port representations must
match consumers; mapped IPv6 audit sources use their embedded IPv4 address.

Linux appends executable identity without changing the Windows event layout:
its identity, extended audit event, and pending local entry are respectively
16, 44, and 48 bytes, each guarded by a static assertion. Minimal kernel type
declarations use `preserve_access_index` so CO-RE relocates accessed fields
against target-kernel BTF instead of assuming host offsets.

Shared audit identity means UID/root on Linux and logon ID/admin on Windows.
Alert timestamps are monotonic kernel time; user mode adds UTC on receipt.
Coordinate layout changes with Rust loader array mappings, notably
`proxy_agent\src\redirector\linux\ebpf_obj.rs`; assertions alone do not update
consumers. The libbpf wrapper supplies includes, not custom helpers or relocation
logic; CO-RE field readers must include the dedicated core-read header.

### Keep constants separate from runtime behavior

Shared Rust constants centralize proxy, WireServer, guest-agent plugin, and IMDS
endpoints plus compile-time platform service names. Agent constants re-export
them and add network-order addresses, headers, key-delivery labels, cgroup
fallback, and logging/runtime defaults. These files do not open sockets,
validate configuration, or enforce limits. The non-Windows service selection
does not imply eBPF support on every non-Windows OS.

## Related Components and Change Boundaries

- **User-mode redirector/loader:** correlate audit records and maintain matching
  Rust ABI mappings; kernel redirection, audit availability, and authorization
  must remain distinct.
- [Agent platform utilities](agent-platform-utilities.md): configuration,
  diagnostics, and OS-specific identity utilities adjacent to these hooks.
- **Validation scope:** the supplied summaries declare no tests in these eight
  files. Compile-time layout checks cover sizes, not runtime redirection,
  source-selection timing, failure paths, or OS/kernel compatibility.
