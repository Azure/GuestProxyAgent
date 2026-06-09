## Sections

1.  [1. Overview](#overview)
2.  [2. Today](#today)
3.  [3. Design](#design)
4.  [4. sk_lookup program](#sklookup)
5.  [5. bpf_lsm hook](#lsm)
6.  [6. Loader strategy](#loader)
7.  [7. Integration](#integration)
8.  [8. Tests](#tests)
9.  [9. Risks](#risks)
10. [10. Milestones](#milestones)

**GPA** · **Direction 4.1** · **eBPF**

# Detailed Design — sk_lookup + bpf_lsm Redirect

Move from `cgroup/connect4` SNAT-style redirect to `sk_lookup` (listener-side steering, preserves original destination) augmented with `bpf_lsm` socket hooks that close netns/cgroup escape paths (pentest `C5`, `C6`, `C7`).

**Files affected:** `linux-ebpf/` (split into `cgroup_connect.bpf.c`, `sk_lookup.bpf.c`, `lsm.bpf.c`), `proxy_agent/src/redirector/linux/`.

> **Prerequisites:** [4.2 Core eBPF unification](Innovation-4.2-core-unify-ebpf.md)

## 1. Overview & Goals

| Impact               | Effort     | Risk              | Scope                       |
|----------------------|------------|-------------------|-----------------------------|
| **High** kills C5–C7 | **Medium** | **Kernel matrix** | **linux-ebpf + redirector** |

### Goals

- Original destination IP is preserved end-to-end (no SNAT to localhost) so the agent can authoritatively match on it after netns shenanigans.
- An LSM hook denies connect attempts to fabric IPs from sockets the redirect cannot capture (different netns, unshared cgroup).
- Fallback path retains today's `cgroup/connect4` for older kernels.

## 2. Today

A `cgroup/connect4` program rewrites the destination of outbound TCP connect calls from fabric IPs to `127.0.0.1:3080`. Caveats:

- It's a destination rewrite — the agent has to recover the original IP from a side channel.
- It's attached to the root cgroup, so a workload that escapes to a sibling cgroup hierarchy (pentest C5) or new netns (C6) escapes the redirect.
- Address-encoding bypasses (C7) are mitigated only by string parsing in user space.

## 3. Design

client connect(168.63.129.16:80) │ ▼ (1) cgroup/connect4 — kept for back-compat; sets sk_storage.original_dest │ ▼ (2) bpf_lsm socket_connect — DENY if dest is fabric AND sk is outside the agent's view │ kernel routing │ ▼ (3) sk_lookup at agent's listener — selects the agent's accept socket │ and preserves SO_ORIGINAL_DST for the agent to read │ agent accept()

## 4. sk_lookup Program

    // linux-ebpf/sk_lookup.bpf.c
    SEC("sk_lookup")
    int gpa_sk_lookup(struct bpf_sk_lookup *ctx) {
        __u32 dip = ctx->remote_ip4 ? ctx->local_ip4 : 0;
        __u16 dport = ctx->local_port;
        if (!is_fabric_dest(dip, dport)) return SK_PASS;
        bpf_sk_assign(ctx, &agent_listener_sk, 0);
        return SK_PASS;
    }

- The agent registers its listener socket via `BPF_MAP_TYPE_SK_LOOKUP` map; the kernel preserves the original destination tuple, available to the agent via `SO_ORIGINAL_DST`.
- No payload mutation, no SNAT, so the agent reads the real destination IP for AuthZ.
- IPv6 variant attached as separate program.

## 5. bpf_lsm Hook

    // linux-ebpf/lsm.bpf.c
    SEC("lsm/socket_connect")
    int BPF_PROG(gpa_block, struct socket *sock, struct sockaddr *addr, int addrlen, int ret) {
        if (ret) return ret;
        if (!is_fabric_dest_sockaddr(addr)) return 0;
        // If this socket's cgroup is not under the GPA-attached cgroup root,
        // or sk_lookup is not present for this netns, deny.
        if (!cgroup_is_under_root(sock->sk) || !sk_lookup_present_in_netns(sock->sk)) return -EPERM;
        return 0;
    }

- This is the "you didn't go through GPA → you can't reach the fabric" rule, enforced at the kernel boundary.
- Compiled as `bpf_lsm`; requires kernel with `CONFIG_BPF_LSM=y` and `lsm=bpf` on kernel cmdline.

## 6. Loader Strategy

| Kernel feature               | Programs loaded                                     | Behavior                                    |
|------------------------------|-----------------------------------------------------|---------------------------------------------|
| bpf_lsm + sk_lookup (≥ 5.13) | LSM + sk_lookup + cgroup_connect (defense-in-depth) | Best case                                   |
| sk_lookup only               | sk_lookup + cgroup_connect                          | No LSM deny; sk_lookup still preserves dest |
| cgroup_connect only          | cgroup_connect (legacy)                             | Today's behavior                            |

Loader probes feature availability at startup using `libbpf` feature probes; logs the chosen mode and exposes it via the attestation endpoint (3.3).

## 7. Integration

- `proxy_agent/src/redirector/linux/` — refactor to manage three programs with per-program lifecycle (load, attach, detach, pin under `/sys/fs/bpf/gpa/`).
- `proxy_agent/src/proxy/proxy_server.rs` — read original destination via `SO_ORIGINAL_DST` (IPv4) and `IPV6_RECVORIGDSTADDR` (IPv6).
- `linux-ebpf/` — adopt CO-RE (see 4.2) so we ship one object per program for all supported kernels.

## 8. Tests

- Pentest `C5` (unshare cgroup): LSM denies; without LSM, sk_lookup still captures.
- Pentest `C6` (new netns): LSM denies because sk_lookup is not present in the new netns.
- Pentest `C7` (address-encoding): all encodings reach `sk_lookup` at the same destination tuple; canonical model (2.1) then handles host normalization for AuthZ.
- IPv6 path: same checks on link-local fabric equivalents.

## 9. Risks

- **Kernel feature matrix** — older distros lack `bpf_lsm`. Mitigation: tiered loader, telemetry exposes which mode is in use.
- **BTF availability** on stripped kernels — vendor BTF in the package as a fallback.
- **Performance** of an extra LSM hook per connect — micro-benchmarked; expected ≤ 200 ns.

## 10. Milestones

| M   | Deliverable                               | Exit                                         |
|-----|-------------------------------------------|----------------------------------------------|
| M1  | sk_lookup program + loader tier detection | Original dest preserved on supported kernels |
| M2  | bpf_lsm deny hook                         | C5, C6 pentest PASS on lsm-enabled kernels   |
| M3  | IPv6 variants (ties to direction 4.3)     | Dual-stack VMs covered                       |

Detail design for direction 4.1. Parent: [Innovation-Directions.md](Innovation-Directions.md).
