## Sections

1. [1. Overview](#1-overview--goals)
2. [2. Implementation status](#2-implementation-status)
3. [3. Address-family semantics](#3-address-family-semantics)
4. [4. eBPF programs](#4-ebpf-programs)
5. [5. Shared audit ABI and telemetry](#5-shared-audit-abi-and-telemetry)
6. [6. Listener and forwarding](#6-listener-and-forwarding)
7. [7. Tests](#7-tests)
8. [8. Remaining native IPv6 work](#8-remaining-native-ipv6-work)
9. [9. Risks](#9-risks)
10. [10. Milestones](#10-milestones)

**GPA** · **Direction 4.3** · **Network**

# Detailed Design — IPv6 / Dual-stack Support

Add dual-stack protection in two stages. The implemented first stage closes the IPv4-mapped IPv6 bypass (`::ffff:a.b.c.d`) while preserving the existing IPv4 policy and forwarding model. Native IPv6 fabric endpoints remain a later stage.

**Primary files affected:** `linux-ebpf/ebpf_cgroup.c`, `ebpf/redirect.bpf.c`, `shared-ebpf/include/gpa_audit_event.h`, `proxy_agent/src/redirector/`, and `proxy_agent/src/proxy/`.

> **Prerequisites:** [4.2 Core eBPF unification](Innovation-4.2-core-unify-ebpf.md)

## 1. Overview & Goals

| Impact                     | Effort     | Risk    | Scope            |
|----------------------------|------------|---------|------------------|
| **Medium** future-proofing | **Medium** | **Low** | **eBPF + agent** |

### Current goals

- Intercept IPv4-mapped IPv6 destinations such as `::ffff:169.254.169.254`.
- Reuse the existing IPv4 policy-map keys and original-destination forwarding path.
- Attach both connect4 and connect6 programs on Linux and Windows.
- Emit the connect address family in request and aggregate telemetry.
- Keep existing IPv4 behavior and released Windows audit-layout compatibility.

### Deferred goals

- Redirect native IPv6 fabric endpoints, including link-local addresses.
- Store full 128-bit original destinations in the policy and audit models.
- Forward requests to native IPv6 upstream endpoints.
- Bind and expose a native IPv6 proxy listener where required.

## 2. Implementation status

The current implementation supports IPv4-mapped IPv6 only:

- Linux attaches `connect4` and `connect6` cgroup programs.
- Windows loads `authorize_connect4` and `authorize_connect6` and retains both eBPF links for the object lifetime.
- The connect6 programs recognize the `::ffff:0:0/96` prefix, extract the low-order IPv4 address, and look it up in the existing IPv4 policy map.
- A matched connection is redirected to IPv4-mapped loopback while remaining usable by the originating dual-stack socket.
- Native IPv6 addresses do not match the IPv4 policy map and pass through unchanged.
- No new native IPv6 endpoint configuration is introduced in this stage.

## 3. Address-family semantics

The telemetry field describes the connect hook/API family observed by eBPF, not necessarily the packet transport used after mapped-address conversion.

| Platform | Application destination | Observed hook | Telemetry |
|----------|-------------------------|---------------|-----------|
| Linux | IPv4 `169.254.169.254` | `connect4` | `IPv4` |
| Linux | Mapped `::ffff:169.254.169.254` passed as `sockaddr_in6` | `connect6` | `IPv6` |
| Windows (current eBPF-for-Windows behavior) | IPv4 `169.254.169.254` | `authorize_connect4` | `IPv4` |
| Windows (current eBPF-for-Windows behavior) | Mapped `::ffff:169.254.169.254` on a dual-mode socket | normalized to `authorize_connect4` | `IPv4` |
| Either platform | Native IPv6 | connect6 path, no IPv4 policy match | not redirected |

Linux hook selection follows the address family supplied to `connect()`. Windows currently classifies IPv4-mapped dual-stack connections as IPv4 before the GPA hook. The Windows connect6 mapped-address logic remains as a compatibility fallback if eBPF-for-Windows later aligns with Linux behavior. See [eBPF-for-Windows issue #5536](https://github.com/microsoft/ebpf-for-windows/issues/5536).

## 4. eBPF programs

The Linux and Windows connect6 programs use the same decision model:

```c
if (!get_ipv4_mapped_address(ctx, &destination_ipv4))
    return PROCEED;

key = { destination_ipv4, destination_port, protocol };
policy = bpf_map_lookup_elem(&policy_map, &key);
if (policy) {
    record_original_destination_and_family();
    redirect_to_ipv4_mapped_loopback(policy);
}
```

Linux carries the original destination and family through `local_map` until the TCP source port is available. Windows writes the same information to `audit_map` or the WFP redirect context.

## 5. Shared audit ABI and telemetry

`gpa_audit_event` is shared by Linux and Windows and now contains:

- Existing identity, process, original IPv4 destination, and port fields.
- `address_family`, normalized to `GPA_ADDRESS_FAMILY_IPV4` (`4`) or `GPA_ADDRESS_FAMILY_IPV6` (`6`).
- A reserved word for future ABI-compatible metadata.

The canonical audit value is 28 bytes (`[u32; 7]`). The Rust decoder also accepts the officially released 24-byte legacy Windows layout and treats it as IPv4. The unreleased 20-byte intermediate layout is intentionally not supported.

The family is propagated through `AuditEntry` and `TcpConnectionContext` into:

- Per-request `ProxySummary` JSON as `addressFamily: "IPv4" | "IPv6"`.
- `ProxyConnectionSummary` aggregate status.
- The aggregation key, so IPv4 and IPv6 requests do not collapse into one bucket.

Older serialized summaries that omit `addressFamily` default to `IPv4`.

## 6. Listener and forwarding

The current mapped-IPv6 stage keeps the existing IPv4 proxy listener and IPv4 upstream forwarding path. The audit record stores the extracted IPv4 destination, so authorization and forwarding remain unchanged.

A native IPv6 listener, 128-bit original-destination storage, and native IPv6 upstream sender are not part of the current implementation.

## 7. Tests

Implemented validation includes:

- Shared audit-layout round trips and IPv6 family decoding.
- Released legacy Windows audit-layout decoding as IPv4.
- Family-aware connection-summary aggregation and JSON serialization.
- Windows-target Cargo checks and focused Rust tests.
- Windows eBPF compilation with both `cgroup/connect4` and `cgroup/connect6` sections.

Required environment tests:

- Linux dual-mode client using `sockaddr_in6(::ffff:a.b.c.d)` reports `IPv6` and is redirected.
- Windows dual-mode client may report `IPv4` because the platform normalizes the mapped address before the hook; it must still be redirected.
- Native IPv6 destinations pass through unchanged until the next milestone.

## 8. Remaining native IPv6 work

1. Define production native IPv6 fabric endpoint addresses and configuration.
2. Replace the IPv4-only policy key with a normalized 16-byte address plus family, port, and protocol.
3. Expand audit and connection models to retain a full 128-bit original destination.
4. Add native IPv6 listener and upstream forwarding support.
5. Fold mapped and native representations into canonical endpoint identities.
6. Add native IPv6 end-to-end and bypass tests.

## 9. Risks

- **Telemetry interpretation:** `addressFamily` records the observed connect family, not guaranteed on-wire IP transport. Platform normalization makes mapped-address results differ between Linux and Windows.
- **Kernel variation:** Linux cgroup connect hooks require kernel 4.17 or later; enterprise distributions may backport them. IPv6 or mapped-address support can also be disabled by host configuration.
- **Windows behavior may change:** the connect6 fallback must remain tested even though current eBPF-for-Windows routes mapped connections through connect4.
- **ABI coordination:** shared C map layouts and Rust `[u32; N]` representations must change together.
- **Native endpoint uncertainty:** fabric IPv6 addresses are not finalized in all environments.

## 10. Milestones

| M | Deliverable | Status / exit criteria |
|---|-------------|------------------------|
| M1 | Mapped-IPv6 interception on Linux | Implemented: connect6 maps `::ffff:a.b.c.d` to existing IPv4 policy and forwarding |
| M2 | Mapped-IPv6 compatibility on Windows | Implemented: both links attached; current connect4 normalization and connect6 fallback supported |
| M3 | Cross-platform family telemetry | Implemented: shared audit ABI and `addressFamily` request/aggregate telemetry |
| M4 | Native IPv6 interception and forwarding | Planned: 128-bit policy, audit, listener, sender, and end-to-end tests |
| M5 | Data-driven native endpoint table | Planned: region updates without eBPF redeployment |

Detail design for direction 4.3. Parent: [Innovation-Directions.md](Innovation-Directions.md).
