# Deployment safety

Status, requested owner role, and evidence revision: [context registry](context.json).

## Existing lifecycle surfaces

- [Setup commands](../proxy_agent_setup/src/main.rs) include install, backup,
  restore, uninstall, and purge. These mutate files and services; they are not
  safe diagnostic commands to run on a developer or production machine casually.
- [Linux setup](../proxy_agent_setup/src/linux.rs) installs the executable,
  configuration, eBPF object, service configuration, and optional man page into
  different locations. Backup/restore must account for the whole artifact set.
- The [systemd unit](../proxy_agent_setup/src/linux/azure-proxy-agent.service)
  establishes early-boot/shutdown ordering, restart behavior, filesystem
  restrictions, and network restrictions. Preserve their rationale when changing
  paths, dependencies, capabilities, or supported endpoints.
- The [extension monitor](../proxy_agent_extension/src/service_main.rs) distinguishes
  file-version mismatch from `ResumeInterruptedUpdate`. Matching installed and
  bundled files do not establish that the running service completed its update.
- Windows packaging generates an extension catalog with
  [New-ExtensionCatalog.ps1](../proxy_agent_extension/scripts/New-ExtensionCatalog.ps1).
  [Windows guidance](../doc/GettingStartedWindows.md) explicitly distinguishes
  unsigned local/public-CI catalogs from official production-signed artifacts.
- [CD](../.github/workflows/cd.yml) calls the reusable build with release generation
  enabled. Release publishing configuration is not proof of production signing or
  release approval.

## Required review questions for affected changes

1. Are binaries, configuration, eBPF artifacts, handler scripts, and catalogs from
   one consistent version/architecture?
2. What happens if stop, copy, service creation, dependency start, or health
   reporting fails halfway through?
3. Can the next run detect and recover from interruption, stale status, duplicate
   handler invocation, or a reboot?
4. Is rollback supported for the exact change? Which backup and persisted-state
   versions are compatible, and what is deliberately retained or removed?
5. Are service identity, ACLs, systemd restrictions, and Windows eBPF dependencies
   preserved? Do diagnostics identify the failed dependency?
6. What executed evidence covers reboot, restart, upgrade/downgrade, and recovery
   on the affected platform? Which scenarios remain unverified?

Use an approved disposable test VM for lifecycle validation. Do not infer atomic
installation, comprehensive rollback, or failure propagation from command names;
inspect actual return handling and state transitions. Treat connectivity,
privilege, install/update, rollback, and release-control behavior changes as
high-risk review candidates under the [checklist](review-checklist.md).
