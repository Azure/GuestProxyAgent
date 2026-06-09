## Sections

1.  [1. Overview](#overview)
2.  [2. Today](#today)
3.  [3. Design](#design)
4.  [4. eBPF v6 programs](#ebpf)
5.  [5. Listener](#listener)
6.  [6. Canonical Destination v6](#canon)
7.  [7. Integration](#integration)
8.  [8. Tests](#tests)
9.  [9. Risks](#risks)
10. [10. Milestones](#milestones)

**GPA** · **Direction 4.3** · **Network**

# Detailed Design — IPv6 / Dual-stack Support

Extend the redirect, listener, canonical model, and rule engine to handle IPv6 fabric endpoints uniformly with IPv4. Closes the gap on dual-stack VMs.

**Files affected:** `linux-ebpf/sk_lookup.bpf.c`, `ebpf/redirect.bpf.c`, `proxy_agent/src/proxy/proxy_server.rs`, `proxy_agent/src/proxy/canonical/destination.rs`.

> **Prerequisites:** [4.2 Core eBPF unification](Innovation-4.2-core-unify-ebpf.md)

## 1. Overview & Goals

| Impact                     | Effort     | Risk    | Scope            |
|----------------------------|------------|---------|------------------|
| **Medium** future-proofing | **Medium** | **Low** | **eBPF + agent** |

### Goals

- IPv6 fabric link-local addresses (e.g. `fe80::a9fe:a9fe`) caught by eBPF and routed through agent.
- Canonical destination enum unified across families; rule engine sees one `Destination::Imds` regardless of family.
- Defeat IPv4-mapped IPv6 bypasses (pentest C7) at the kernel layer.

## 2. Today

Redirect handles IPv4 only. Dual-stack VMs that route fabric over v6 (uncommon today but increasing) bypass the agent. The canonical model in direction 2.1 already plans for v6 typed destinations; this direction wires it through the kernel.

## 3. Design

- Add v6 sibling programs: `cgroup_connect6`, `sk_lookup_v6`.
- Listener binds IPv6 socket with `IPV6_V6ONLY=0` dual-stack on Linux, or two sockets where dual-stack is unavailable.
- Canonical `Destination` resolves IPv4-mapped IPv6 (`::ffff:a.b.c.d`) to the v4 destination — there is exactly one `Destination::Imds` regardless of family.
- Per-destination address tables published to BPF programs via a `BPF_MAP_TYPE_HASH` keyed on a 16-byte normalized address.

## 4. eBPF v6 Programs

    SEC("cgroup/connect6")
    int gpa_connect6(struct bpf_sock_addr *ctx) {
        struct in6_addr dst;
        __builtin_memcpy(&dst, ctx->user_ip6, sizeof(dst));
        if (!is_fabric_dest6(&dst, bpf_ntohs(ctx->user_port))) return 1;
        // Redirect: rewrite to agent's v6 listener
        set_user_dest_v6(ctx, &agent_v6, agent_port);
        return 1;
    }

- `is_fabric_dest6` recognizes the v6 link-local equivalent (typically `fe80::a9fe:a9fe` if used) and IPv4-mapped forms.
- SO_ORIGINAL_DST equivalent for v6 via `IP6T_SO_ORIGINAL_DST`; reachable from user space.

## 5. Listener

- Bind `[::1]:3080` in addition to `127.0.0.1:3080` (or single dual-stack socket).
- Original destination read on accept via family-appropriate `getsockopt`.
- Listener exposed via attestation endpoint (3.3) with all bound addresses.

## 6. Canonical Destination v6

    impl Destination {
        pub fn from_ip(ip: IpAddr, port: u16) -> Destination {
            let v4 = match ip {
                IpAddr::V4(v) => Some(v),
                IpAddr::V6(v) => v.to_ipv4_mapped(),
            };
            match (v4, port) {
                (Some(Ipv4Addr::new(169,254,169,254)), 80)   => Destination::Imds,
                (Some(Ipv4Addr::new(168,63,129,16)), 80)     => Destination::WireServer,
                (Some(Ipv4Addr::new(168,63,129,16)), 32526)  => Destination::HostGaPlugin,
                _ => Destination::Unknown { /* ... */ },
            }
        }
    }

## 7. Integration

- Loader (4.2) detects v6 enablement on the host and loads v6 programs only when needed.
- PoP token (1.1) `dip` claim is always a 16-byte normalized form so signatures cover both families.
- Telemetry: per-family labels on `gpa_requests_total`.

## 8. Tests

- Dual-stack pod test: v4 and v6 requests both reach the agent and produce identical `Destination`.
- Pentest C7 v6 variants: all map to `Destination::Imds` after canonicalization.
- Linkup test for hosts without v6 — programs not loaded; no warnings.

## 9. Risks

- **Fabric v6 endpoints not finalized** in some regions — make destinations data-driven via the BPF map so production can update without redeploying eBPF.
- **Dual-stack socket semantics** vary on Windows — keep two sockets there.

## 10. Milestones

| M   | Deliverable                  | Exit                                        |
|-----|------------------------------|---------------------------------------------|
| M1  | v6 listener + canonical fold | v4 behavior unchanged                       |
| M2  | connect6 + sk_lookup_v6      | v6 fabric traffic captured in dual-stack VM |
| M3  | Data-driven dest table       | Region rollout without rebuild              |

Detail design for direction 4.3. Parent: [Innovation-Directions.md](Innovation-Directions.md).
