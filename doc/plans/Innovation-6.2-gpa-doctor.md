## Sections

1.  [1. Overview](#overview)
2.  [2. Checks](#checks)
3.  [3. Report](#report)
4.  [4. Production safety](#safety)
5.  [5. Integration](#integration)
6.  [6. Tests](#tests)
7.  [7. Risks](#risks)
8.  [8. Milestones](#milestones)

**GPA** · **Direction 6.2** · **Operability**

# Detailed Design — gpa-doctor

One-command hardening check derived from the pentest suite. Runs read-only probes that mirror specific pentest cases (A1, E1, E4, G4, D4) and emits a coloured green/yellow/red report. Safe to run on production.

**Files affected:** new `proxy_agent/src/bin/gpa_doctor.rs`; reuses telemetry endpoints.

> **Prerequisites:** [3.1 Hash-chained log](Innovation-3.1-hash-chained-log.md)[3.2 OTel export](Innovation-3.2-otel-export.md)

## 1. Overview & Goals

| Impact                      | Effort    | Risk              | Scope   |
|-----------------------------|-----------|-------------------|---------|
| **High** support deflection | **Small** | **Low** read-only | **CLI** |

### Goals

- One command. One report. Zero side effects.
- Each finding cites the pentest case it derives from.
- Run by support engineers and by customers themselves.

## 2. Checks

| Check                           | Maps to | What it does                                                                    |
|---------------------------------|---------|---------------------------------------------------------------------------------|
| eBPF programs loaded & attached | A1      | Verifies the redirect program is live; tests connect-to-fabric path is captured |
| Loopback bypass                 | E1      | Probes whether non-agent local processes can reach upstream fabric directly     |
| Header smuggling                | E4      | Confirms agent strips/rejects suspicious headers known to bypass authorization  |
| State file integrity            | G4      | Checks owner/mode/SELinux label on `/var/lib/azure/proxyagent/*`                |
| Time/clock sanity               | D4      | Verifies system clock skew vs WireServer; PoP token expirations                 |
| Audit log shape                 | —       | Last 1000 entries parse cleanly; no broken hash chain (ties to 3.1)             |

## 3. Report

    $ gpa-doctor
    [ OK   ] eBPF programs loaded (cgroup_connect4, sk_lookup)         [A1]
    [ WARN ] Loopback bypass possible: nginx on :8080 has direct route [E1]
    [ OK   ] Header strip configured                                   [E4]
    [ FAIL ] /var/lib/azure/proxyagent/state.json mode is 0644 (want 0640) [G4]
    [ OK   ] Clock skew 12 ms                                          [D4]
    [ OK   ] Audit log chain intact (last 1000 entries)
    2 OK · 1 WARN · 1 FAIL · suggested actions printed below

- Each line ends with the pentest case ID so customers can find the public write-up.
- `--json` mode for monitoring integration.
- Suggestions reference exact `chmod` / config edits.

## 4. Production Safety

- All probes are read or self-targeted (we only test our own listener).
- No upstream traffic generated except a single benign IMDS "instance" GET (idempotent).
- Runtime \< 1 second; CPU bounded.
- Refuses to run as a non-root user with a clear message — except for the read-only checks that don't need root.

## 5. Integration

- Optional cron/systemd timer publishes the report to Geneva/OTel daily.
- Linked from the README, troubleshooting docs, and CES/CSS playbooks.

## 6. Tests

- Each check has a positive and a negative fixture.
- Idempotency: 100 runs produce identical reports given a static system.

## 7. Risks

- **False positives** on heterogeneous host configurations. Mitigation: WARN (not FAIL) for ambiguous findings; "more info" link.

## 8. Milestones

| M   | Deliverable                  | Exit                          |
|-----|------------------------------|-------------------------------|
| M1  | Six built-in checks + report | Used by CSS in one ticket     |
| M2  | JSON mode + nightly reporter | Telemetry shows fleet posture |

Detail design for direction 6.2. Parent: [Innovation-Directions.md](Innovation-Directions.md).
