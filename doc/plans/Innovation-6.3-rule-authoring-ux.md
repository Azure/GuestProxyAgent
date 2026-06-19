## Sections

1.  [1. Overview](#overview)
2.  [2. JSON Schema](#schema)
3.  [3. VS Code extension](#ext)
4.  [4. Diff view](#diff)
5.  [5. Integration](#integration)
6.  [6. Tests](#tests)
7.  [7. Risks](#risks)
8.  [8. Milestones](#milestones)

**GPA** · **Direction 6.3** · **DX**

# Detailed Design — Rule Authoring UX

A JSON Schema for the rule format and a VS Code extension that gives autocomplete, validation, hover docs, and a diff view between the remote rule set and the local override (`local_rules.rs`).

**Files affected:** new `schema/rules.schema.json`; new `tools/vscode-gpa-rules/` extension; uses the simulator from 6.1.

> **Prerequisites:** [2.2 Typed policy (Cedar)](Innovation-2.2-typed-policy-cedar.md)[2.3 Versioned snapshots](Innovation-2.3-versioned-snapshots.md)[6.1 Policy simulator](Innovation-6.1-policy-simulator.md)

## 1. Overview & Goals

| Impact                     | Effort     | Risk    | Scope       |
|----------------------------|------------|---------|-------------|
| **Medium** author velocity | **Medium** | **Low** | **tooling** |

### Goals

- Schema-driven authoring; no need to memorize field names.
- Real-time decision preview using simulator (6.1).
- Make local-override drift obvious.

## 2. JSON Schema

    {
      "$schema": "https://json-schema.org/draft/2020-12/schema",
      "$id": "https://gpa.azure.com/schema/rules.json",
      "type": "object",
      "required": ["version","grants"],
      "properties": {
        "version": { "const": 2 },
        "grants": {
          "type": "array",
          "items": { "$ref": "#/$defs/grant" }
        }
      },
      "$defs": {
        "grant": {
          "type": "object",
          "required": ["principal","scopes"],
          "properties": {
            "principal": { "$ref": "#/$defs/principal" },
            "scopes":    { "type": "array", "items": { "pattern":
                           "^(imds|wireserver|hostga|keyvault|arm):" } },
            "conditions": { "$ref": "#/$defs/conditions" }
          }
        }
      }
    }

- Schema is the source of truth; agent parser is generated from it (or tested against it).
- Published at a stable URL so editors auto-fetch.

## 3. VS Code Extension

- Activates on files matching `**/gpa.rules.json` or with the JSON schema header.
- Autocomplete for principal kinds, scope strings, conditions.
- Hover docs explain each scope (e.g. "imds:identity:read — allows the token endpoint, response includes the access token").
- Status-bar shows simulator verdict for a focused request (loaded from a sibling `.req.json`).
- Quick fix: convert `identity: "*"` to scoped rules using cluster/fleet audit data.

## 4. Diff View

- "GPA: Compare Local Override to Remote" command opens a diff between the remote rule set and the compiled-in overrides from `proxy_agent/src/authorization/local_rules.rs`.
- Renders both as canonical JSON for clean diff regardless of source format.
- Flags any local rule that is broader than the remote rule.

## 5. Integration

- Extension invokes `gpa policy simulate` via a sidecar process (no remote dependencies).
- Schema versioned alongside the agent; CI generates updated schema on each release.

## 6. Tests

- Schema validation matches agent parser on a corpus of known-good + known-bad rule files.
- Extension contract tests using `vscode-test`.

## 7. Risks

- **Schema drift** vs. parser. Mitigation: generate parser tests from schema; CI fails on drift.

## 8. Milestones

| M   | Deliverable                                 | Exit                                     |
|-----|---------------------------------------------|------------------------------------------|
| M1  | JSON Schema + drift CI                      | Schema used in agent tests               |
| M2  | VS Code extension (autocomplete + simulate) | Used by ≥ 3 rule authors                 |
| M3  | Diff view                                   | Local override drift visible at a glance |

Detail design for direction 6.3. Parent: [Innovation-Directions.md](Innovation-Directions.md).
