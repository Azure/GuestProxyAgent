# Compose Content for: L2-platform/ebpf-socket-redirection.md

Total files: 8

---

## ebpf/redirect.bpf.c

### Purpose and Functionality
This Windows eBPF program redirects policy-matched connections while recording their original destinations and process identity. It defines destination-policy, configuration, skipped-process, LRU audit, and alert ring-buffer maps.
### Key Components
The IPv4 connect hook looks up destination address, port, and protocol. Explicitly bound non-loopback sources generate alerts; configured monitor-only mode leaves them unchanged. Skipped processes bypass redirection. Audit records include process ID, logon ID, administrator status, destination, and address family. Concrete source endpoints become audit-map keys, normalizing mapped IPv6 sources to IPv4; wildcard addresses or zero source ports instead use socket redirect context.
### Behavior and Interactions
The IPv6 hook redirects only IPv4-mapped destinations, preserving the mapped representation; native IPv6 passes unchanged. Explicit local IPv6 binding remains unhandled. Both hooks always return a soft proceed verdict. Identity-query, map-write, redirect-context, and ring-buffer failures are logged rather than blocking connections; failed administrator queries record a non-root value. Audit failures do not prevent destination rewriting. The file contains no tests.

---

## ebpf/socket.h

### Purpose and Functionality
This declarations-only header adapts shared socket-audit definitions for the Windows eBPF implementation. It contains no executable logic, resource ownership, or tests.
### Key Components
It includes standard Boolean and fixed-width integer definitions plus the shared audit-event header. It defines TCP and UDP protocol constants and Windows-specific IPv4 and IPv6 address-family constants. Four typedefs expose the shared destination, audit-key, audit-event, and skipped-process structures under names used by Windows redirection code.
### Behavior and Interactions
The structures themselves are defined in the shared header rather than duplicated here. A pragma-once guard prevents repeated inclusion. The header supplies compile-time types and constants only; it performs no validation or error handling.

---

## linux-ebpf/ebpf_cgroup.c

### Purpose and Functionality
This Linux CO-RE eBPF program combines cgroup connection redirection with TCP audit correlation. Policy, configuration, skipped-process, audit, alert-ring, and temporary local maps coordinate interception.
### Key Components
IPv4 policy matches use destination address, port, and protocol. Explicit non-loopback socket bindings generate alerts and bypass rewriting when monitor-only configuration is enabled. IPv6 handling redirects only IPv4-mapped destinations; native IPv6 remains unchanged. Process exclusions bypass interception. Pending records keyed by process/thread identity retain original destinations, UID/root status, protocol, and executable device/inode identity captured through the current task's executable file.
### Behavior and Interactions
A tcp_connect kprobe retrieves pending records after source selection, builds source-address/port/protocol audit keys using CO-RE socket reads, writes the audit map, and deletes the pending entry. Mapped sources normalize to IPv4, including a fallback when IPv6 fields are still unset. Missing executable metadata leaves identity invalid. Map and ring-buffer failures are logged without rejecting connections; pending entries are deleted even after an audit-write failure. Connect hooks always proceed. Local IPv6 binding handling remains unimplemented.

---

## linux-ebpf/socket.h

### Purpose and Functionality
This Linux-only declarations header supplies socket constants, compatibility aliases, audit layouts, and minimal kernel types for CO-RE field access. It includes shared audit structures and libbpf helpers rather than duplicating the common ABI.
### Key Components
The executable-identity structure holds device, split inode, and validity fields. Linux audit records append that identity to the shared audit event, and temporary local entries add protocol. Compile-time assertions enforce respective sizes of 16, 44, and 48 bytes, keeping Linux extensions separate from the Windows event layout. An IPv4 tuple type describes addresses and ports.
### Behavior and Interactions
Minimal socket, IPv6-address, task, address-space, file, inode, and superblock declarations expose only fields required by the eBPF implementation. A preserve-access-index attribute allows field offsets to relocate against target-kernel BTF instead of assuming host layouts. Kernel-compatible type names support that matching. The header contains no runtime processing, allocation, or tests; invalid asserted layouts fail compilation.

---

## proxy_agent/src/common/constants.rs

### Purpose and Functionality
Provides shared names and fixed defaults used by the agent's configuration, networking, key delivery, and logging code. This file contains constant declarations and re-exports only; it performs no initialization, I/O, synchronization, or runtime validation.
### Key Components
Endpoint addresses, ports, and the service name are re-exported from proxy_agent_shared. Local constants include network-byte-order address representations, a platform identification label, HTTP and vTPM key-delivery method names, and connection, timing, and notification header names.
### Behavior and Interactions
Configuration defaults specify thirty event files and two proxy runtime workers. Logging limits specify five files of ten mebibytes each. A cgroup root provides the non-Windows configuration fallback. These values are inputs to consuming modules, not enforced limits within this file. There are no functions, types, error paths, resource owners, or tests declared here.

---

## proxy_agent_shared/src/constants.rs

### Purpose and Functionality
Declares workspace-wide service names and network endpoint constants shared by the agent, extension, and setup crates. The module centralizes values that its documentation says previously existed in separate constants modules and had drifted apart.
### Key Components
Conditional declarations select the service name for Windows Service Control Manager or the non-Windows systemd service. A separate constant supplies the human-readable service display name. Additional string and unsigned-port constants identify the local proxy listener, wire server, guest-agent plugin endpoint, and instance metadata service.
### Behavior and Interactions
This file contains constants only: it does not open sockets, register services, resolve names, validate configuration, or choose endpoints dynamically. Platform selection occurs at compilation, with the Linux service name selected for all non-Windows targets. Consumers obtain shared immutable values rather than runtime state. No functions, custom types, error paths, resource management, or tests are declared here.

---

## shared-ebpf/include/gpa_audit_event.h

### Purpose and Functionality
Declares the canonical cross-platform binary layouts used to exchange eBPF policy, connection audit, configuration, and alert data between kernel programs and user mode. This header contains structure declarations, macros, and compile-time size assertions, not executable processing functions.
### Key Components
The address union supports IPv4 or four-word IPv6 storage. Destination entries hold an address, port, and protocol. Audit keys combine protocol, source port, address family, and address; IPv4-mapped IPv6 sources use embedded IPv4 addresses. Audit events contain user/logon identity, process identity, privilege status, destination information, address family, and a reserved word. Additional records represent alert-only notifications, enabled configuration, bypassed processes, and local connection state.
### Behavior and Interactions
Comments specify network-order address handling and destination-port representation, and explain Linux user/root versus Windows logon/admin interpretation. Alert records combine a monotonic kernel timestamp, local address, and audit data; user mode supplies UTC on receipt. Eight static assertions enforce exact structure sizes, including the 56-byte alert record, against Rust loader array mappings. Layout changes therefore require coordinated updates. The header defines no allocation, runtime errors, synchronization, or platform-specific conditional branches.

---

## shared-ebpf/include/gpa_libbpf_helpers.h

### Purpose and Functionality
Provides a minimal shared include wrapper for portable eBPF code. Despite its helper-oriented name, this file declares no custom functions, types, or macros beyond its single-inclusion directive.
### Key Components
It includes the Linux BPF definitions and libbpf helper header, making their declarations available to consumers.
### Behavior and Interactions
Comments direct consumers needing CO-RE kernel-field access to include the dedicated core-read header themselves. They explain that those access macros depend on preserve_access_index annotations on kernel structures so loaders can relocate offsets for the target kernel. This file does not implement relocation, conditional Windows/Linux behavior, resource management, runtime error handling, synchronization, or tests.

---
