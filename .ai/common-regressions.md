# Common regression scenarios

Status, requested owner role, and evidence revision: [context registry](context.json).

These are regression contracts supported by checked-in tests or implementation
comments. They are **not claims of production incidents**, exhaustive coverage,
or successful execution at the current commit. Search the named test in its linked
source and inspect its assertions before relying on it.

| Scenario and rationale | Existing evidence |
|---|---|
| Audit denial still forwards, while enforce denial and elevation checks retain endpoint-specific meaning | `wireserver_authenticate_test`, `imds_authenticate_test`, `hostga_authenticate_test`, and `authorize_skip_sig_test` in [proxy_authorizer.rs](../proxy_agent/src/proxy/proxy_authorizer.rs) |
| Canonicalization rejects unsupported inputs and remains idempotent; shadow/enforce handoff does not silently change which result decides | `userinfo_rejected_at_pipeline_entry`, `allowed_methods_are_accepted_others_rejected`, `non_http_schemes_rejected`, and `canonical_form_is_idempotent` in [canonical/mod.rs](../proxy_agent/src/proxy/canonical/mod.rs); `shadow_compare_returns_canonical_decision_for_enforce_handoff` in [authorization_rules.rs](../proxy_agent/src/proxy/authorization_rules.rs) |
| Skip-signature behavior must remain stable rather than being "simplified" during HTTP changes | `should_skip_sig_test` in [hyper_client.rs](../proxy_agent_shared/src/hyper_client.rs) |
| Runtime handoff cancels old bind retries without overwriting the desired listener; policy-update failure must not make old ports permanently unusable | `handoff_cancels_bind_retries_without_overwriting_desired_listener` and `policy_update_failure_keeps_new_runtime_and_allows_old_port_reuse` in [runtime_coordinator.rs](../proxy_agent/src/runtime_coordinator.rs) |
| Soft audit must not suppress port reconciliation or repeatedly restart a non-running pair | `soft_audit_does_not_suppress_proxy_port_reconciliation` and `disabling_soft_audit_restarts_a_non_running_pair_once` in [runtime_coordinator.rs](../proxy_agent/src/runtime_coordinator.rs); `wire_server_soft_audit_status_updates_gpa_status` in [key_keeper.rs](../proxy_agent/src/key_keeper.rs) |
| Equal installed/bundled versions can still require update recovery when running status is absent or reports an old version | `test_determine_update_action` and the `ResumeInterruptedUpdate` rationale in [service_main.rs](../proxy_agent_extension/src/service_main.rs) |
| Health reporting must distinguish stale status from fresh status | `test_stale_status_timestamp_greater_than_5_minutes` and `test_fresh_status_timestamp_within_5_minutes` in [service_main.rs](../proxy_agent_extension/src/service_main.rs) |
| Windows setup diagnostics must name the actual missing/stopped eBPF dependencies | `both_not_installed_returns_both_names`, `core_running_ext_stopped_returns_ext_only`, and related Windows-only tests in [setup main.rs](../proxy_agent_setup/src/main.rs) |
| Secret redaction must remain correct with concurrent callers, but its existence must not be mistaken for automatic logger protection | `test_redact_secrets`, `test_redact_secrets_string`, and `test_redact_secrets_from_concurrent_callers` in [secrets_redactor.rs](../proxy_agent_shared/src/secrets_redactor.rs) |

## Gaps and history

Unit assertions do not establish full VM restart, kernel load, power interruption,
or rollout safety. Select additional scenarios from [deployment safety](deployment-safety.md)
and record what was not run.

No external incident or PR archive is enrolled: `approved_history` in the
[registry](context.json) is empty. Do not fill missing history with guesses.
When approved historical evidence becomes available, add the minimized reference,
affected contract, synthetic reproducer or regression-test link, and remaining
limitations. Keep observed test contracts separate from confirmed historical
failures and from future failure hypotheses.
