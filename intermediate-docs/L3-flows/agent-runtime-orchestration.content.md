# Compose Content for: L3-flows/agent-runtime-orchestration.md

Total files: 23

---

## proxy_agent/src/acl/linux_acl.rs

### Purpose and Functionality
The non-Windows ACL backend attempts to restrict a directory to root ownership and owner-only access. acl_directory takes an owned PathBuf and uses the agent logger for progress and failures.
### Key Components
It first calls nix chown with root user and group identifiers, then constructs Unix permissions with mode 0700 and applies them through std::fs::set_permissions. The path is borrowed for ownership changes and consumed by the permission-setting call.
### Behavior and Interactions
Both operations are attempted independently: a failed chown does not prevent chmod. Each failure is logged, but neither is returned; the function always returns success, so callers cannot infer successful hardening from its Result. Tests are compiled only when both testing and the test-with-root feature are enabled. The asynchronous test creates a temporary directory, invokes the backend, checks success, and asserts that all owner permission bits are present. It does not assert root ownership or absence of group/other bits. Temporary-directory setup and cleanup errors are ignored.

---

## proxy_agent/src/acl/windows_acl.rs

### Purpose and Functionality
The Windows ACL backend attempts to replace directory access rules with inheritable full-control grants for Local System and built-in administrators. It uses windows_acl helpers and converts library errors into the agent's ACL error variants.
### Key Components
acl_directory opens the directory ACL, resolves both well-known identities, enumerates existing entries, and requests removal by identity and ACE type without a flag filter. Missing entry identities and individual removal failures generate warnings but do not stop processing. It then adds allow entries inheritable by both child containers and objects.
### Behavior and Interactions
ACL creation, identity conversion, enumeration, and grant failures propagate immediately, potentially after partial modification. The administrator-grant failure is currently labeled with the system identity in its error payload. The test creates a temporary directory, adds an Everyone allow entry, applies hardening, and asserts no Everyone allow entries and exactly one allow entry for each privileged identity. It also invokes the backend on an invalid path without asserting its result. No rollback is implemented.

---

## proxy_agent/src/acl.rs

### Purpose and Functionality
This module exposes the agent's platform-independent directory-permission entry point, acl_directory, and selects its platform implementation at compile time.
### Key Components
Windows builds include windows_acl; non-Windows builds include linux_acl. The public function accepts an owned PathBuf and returns the shared agent Result type.
### Behavior and Interactions
Missing paths and paths that are not directories return success without invoking either backend. Existing directories are passed to the selected backend, and any returned error propagates through the question-mark operator. Consequently, platform-specific logging and error behavior remain the backend's responsibility. The module includes a documentation usage example but declares no local unit tests.

---

## proxy_agent/src/common.rs

### Purpose and Functionality
This declarations-only module organizes shared agent facilities. It publicly exposes cli, config, constants, error, helpers, logger, and result submodules.
### Key Components
Conditional compilation exposes the windows submodule on Windows and the linux submodule on non-Windows platforms. Windows builds also re-export store_key_data and fetch_key_data from the Windows module. Windows test builds additionally re-export clear_mock_key_data, has_mock_key_data, and mock_key_data_count.
### Behavior and Interactions
The file provides module visibility and convenient imports; it does not implement key storage, configuration, logging, synchronization, or error handling itself. Those behaviors belong to the referenced modules. It declares no functions, types, or tests of its own.

---

## proxy_agent/src/key_keeper/key.rs

### Purpose and Functionality
Defines secure-channel key/status payloads and authorization rules, implements request/process matching, and asynchronously fetches status, acquires keys, and attests keys through WireServer.
### Key Components
Serde models represent keys, endpoint rules, privileges, roles, identities, and assignments. Cloning produces owned copies, including nested rules. Rule descriptors accept legacy IDs or base64 JSON carrying local-rule, soft-audit, and port options; malformed encodings remain legacy IDs, and zero ports become absent.
### Behavior and Interactions
Status GET accepts successful HTTP responses, refreshes stale host-time information from headers, deserializes, and validates version-dependent channel fields. Scheme/delivery mismatches only accumulate messages, not validation failure. Acquisition and signed attestation POSTs require HTTP 200; request, transport, response, and decoding errors propagate. HostGA accessors reuse WireServer rules/modes. Privileges prefix-match predecoded, lowercased paths after backslash normalization and compare decoded query constraints, including embedded query separators. Identities require every configured constraint: exact user/process/group matching, Windows path equality, or Linux executable device/inode identity with mount-device fallback; missing metadata/kernel identity denies matching. Tests assert payload parsing, version modes, HostGA reuse, encoded queries/backslashes, identity mismatches, Linux fail-closed behavior, non-Unicode process-name safety, and descriptor fallback.

---

## proxy_agent/src/key_keeper/local_rules.rs

### Purpose and Functionality
Combines remote WireServer and IMDS policy with optional local JSON rules. The sibling rules directory is capitalized on Windows and lowercase otherwise.
### Key Components
LocalRuleTarget selects the file. LocalRuleFileState tracks metadata errors, absence, or modification time; LocalRuleMonitorState owns cached rules and failure flags. LocalAuthorizationRulesFile permits optional default access, identifier, and access-control definitions. Validation rejects invalid default access, blank identifiers, duplicate names, missing selectors, and invalid references.
### Behavior and Interactions
Resolution mutably borrows the tracker, refreshing on remote, enablement, or metadata changes and previous failure. Disabled or missing local rules return normalized remote policy; unchanged state returns a cached clone. Synchronous reads make three attempts with asynchronous 50-millisecond delays; semantic validation errors propagate immediately. Merging preserves remote mode, optionally overrides default access, appends the local identifier, and prefixes local names and references only when both rule sets exist. Metadata or parsing failures deny default access and remove explicit rules, preserving existing mode or using enforce without remote policy. Events record transitions and results. Tests assert platform paths, merging, reference rewriting, validation errors, missing-file fallback, and failure-state tracking.

---

## proxy_agent/src/key_keeper.rs

### Purpose and Functionality
Coordinates asynchronous WireServer secure-channel polling, key persistence, authorization rules, and provisioning readiness. KeyKeeper owns configuration, cloned shared-state handles, and a cancellation token; cancellation drops polling and marks the module stopped.
### Key Components
Tokio notifications and timers govern polling, with one-second retries for unknown state during the first five minutes, a two-minute provisioning timeout, and delayed event-thread startup. Disabled/unknown notifications reset readiness and provisioning timing; stable-state notifications preserve remaining sleep. Rule processing resolves local WireServer/IMDS overrides, keeps HostGA server-only, publishes desired listener port and descriptor-gated soft audit, and logs changed effective/computed rules.
### Behavior and Interactions
Changed keys load locally first; otherwise acquisition must persist, read-back-check, and attest before readiness. Windows uses encrypted storage helpers and additionally ACLs the executable directory; Linux/non-Windows writes JSON with owner-only permissions. Persistence failures propagate; polling reports failures and retries, while shared-state publication failures can merely warn before readiness proceeds. Disabled transitions clear the shared key. Redirect policies require proxy provisioning and retry failures. Identical status events are suppressed. Tests assert key round-trips, disabled/enabled persistence, port-change detection, case-insensitive soft-audit eligibility, fallback reporting, and event deduplication.

---

## proxy_agent/src/main.rs

### Purpose and Functionality
Provides the executable entry point, selecting version reporting, provisioning-status queries, console operation, or operating-system service startup. It declares top-level modules.
### Key Components
main owns a multithreaded Tokio runtime, configures worker count through a helper, enables runtime facilities, and blocks on async_main. Construction failures panic through unwrap. On Windows, a static Tokio OnceCell stores a runtime handle for the macro-generated synchronous service callback.
### Behavior and Interactions
async_main initializes elapsed-time tracking and stores the Windows runtime handle before processing CLI options. Version reporting prints the executable version. Status queries await provisioning on the configured proxy port, with an optional wait duration defaulting to zero. Unfinished provisioning exits with code 1; completed provisioning with an error prints the message and exits with code 2; success returns normally. Console mode starts shared state, passes clones to service startup and shutdown, and waits synchronously for Enter, ignoring the input result. Windows service mode invokes the dispatcher and logs startup errors; its callback requires the saved handle, blocks on run_service, and logs returned errors. Non-Windows service mode awaits start_service_wait. This file contains no tests.

---

## proxy_agent/src/provision.rs

### Purpose and Functionality
Coordinates redirector, key-latch, and listener readiness, persists provisioning results, and implements CLI status queries. ProvisionFlags tracks readiness; ProvisionStateInternal combines completion time, errors, and secure-channel state, treating disabled or unknown channels as unlatched.
### Key Components
Async readiness updates use shared-state wrappers. Full readiness updates endpoint redirect policies from authorization modes, records completion, writes tags, and starts reporting tasks. Missing rules disable redirection. Resetting key readiness recomputes completion; timeout records an incomplete result. Soft audit suppresses provisioning error messages.
### Behavior and Interactions
Tag persistence creates a compatibility marker and writes XML-escaped failures through a temporary status file and rename; filesystem failures are logged. Non-Windows permissions are restricted to owner access. Deferred limits apply 15% CPU, plus a 20 MB Windows memory limit. Five telemetry/status tasks run on the service runtime, survive listener-runtime shutdown, and return owned join handles; an initialized flag suppresses subsequent startup. ProvisionQuery polls localhost HTTP with metadata, timestamp, and first-attempt notification headers, retrying a different WireServer-discovered port after failure. Query errors are printed; expiration returns unfinished. Tests assert task survival, custom-port discovery, soft-audit suppression, readiness resets, timestamp-sensitive queries, successful empty tags, and escaped failure tags.

---

## proxy_agent/src/proxy/canonical/mod.rs

### Purpose and Functionality
Defines the canonical request model and coordinates destination, path, query, and rule modules for authorization matching. canonicalize borrows a Hyper URI and method, returning owned normalized data or typed errors. Processing is synchronous and platform-neutral, without locks.
### Key Components
CanonicalRequest owns its method, destination, path segments, trailing-slash flag, and a BTreeMap grouping query values by key. render emits only path/query text, percent-encoding delimiter-sensitive bytes and preserving within-key value order. Display combines method, destination label, and rendered target. CanonError exposes stable audit codes. CanonicalMode defines Off, Shadow, and Enforce; this file parses settings but does not execute rollout decisions.
### Behavior and Interactions
The pipeline accepts HTTP or absent schemes and seven methods, rejects userinfo, and propagates destination, path, and query errors. Already-decoded embedded queries merge after regular query values without another percent-decode. canonicalize_str uses GET and maps URI parse failures to BadHost. Mode parsing ignores case and surrounding whitespace, defaults empty input to Off, and rejects unknown values. Unit tests cover gating, selected rendering round trips with restored authority, query compatibility, adversarial inputs, audit codes, and mode defaults. Additional property tests require test configuration and the proptests feature.

---

## proxy_agent/src/proxy.rs

### Purpose and Functionality
Builds authorization claims from redirector audit entries, combining process details, user identity and groups, executable identity metadata, elevation, and client address/port. Declares authorization, canonicalization, connection, server, and summary submodules, with Windows helpers conditionally compiled.
### Key Components
Claims is cloneable and serializable, with defaulted executable device, inode, and validity fields for deserialization compatibility. A custom serializer represents processName as a string, replacing non-UTF-8 content lossily. Private Process and public User hold owned identity data. Async get_user consults the shared cache, resolves misses, and attempts insertion; insertion errors are reported only in tests.
### Behavior and Interactions
Non-Windows process lookup reads the executable symlink and null-separated command line from procfs, retaining four nonempty arguments and propagating contextual I/O errors. Windows opens a process handle, closes it on lookup failures and success, and propagates lookup errors. Command lines remain unredacted for authorization, with later redaction expected before logging. Non-Windows user resolution returns an undefined name when absent; Windows lookup errors propagate. Tests assert platform-specific user/group results, unchanged cache counts, elevated claims, populated process fields, and distinct executable basename/path. Repeated cache-check calls are unawaited futures and do not exercise lookups.

---

## proxy_agent/src/proxy_agent_status.rs

### Purpose and Functionality
ProxyAgentStatusTask assembles agent health and connection summaries, writes status.json, and reports telemetry. It owns its interval, output directory, cancellation token, and shared-state handles.
### Key Components
Startup marks the monitor running, updates its message, and selects between the reporting loop and cancellation. The loop attempts directory creation, gathers status immediately, sleeps between iterations, and emits extension status telemetry every fifteen minutes. Overall success requires the key keeper, redirector, and proxy listener to be running; telemetry logger health is included but does not determine overall success. Key-keeper details include secure-channel state, rule identifiers, and available key metadata. An available fallback reason adds audit-fallback information.
### Behavior and Interactions
Shared-state reads are asynchronous. Failed connection-count or summary reads log errors and substitute zero or empty collections; unavailable channel and rule values use the unknown state. File-write failures update the monitor message. Successful non-Windows writes attempt mode 0640, logging permission failures; non-Windows memory monitoring only logs process memory information. The test verifies file creation, JSON deserialization, and nonempty timestamp and version. Its connection-summary assertion is tautological.

---

## proxy_agent/src/redirector/linux.rs

### Purpose and Functionality
Implements the non-Windows redirector backend using Aya to load eBPF, attach TCP probes and IPv4/IPv6 cgroup programs, maintain maps, and retrieve audits.
### Key Components
BpfObject owns an optional Ebpf and event-task runtime. LinuxAuditMapValue extends shared audits with executable device, split inode, and validity fields. Operations configure skipped processes, bind monitoring, destination policies, and peer-specific audit lookup/deletion. Loading attempts system BTF; cgroup discovery falls back to configuration. Most failures become contextual BPF errors. Boolean policy updates log insertion/removal failures but still return true after successful map conversion.
### Behavior and Interactions
Alert subscription transfers ring-buffer ownership into an AsyncFd task, forwarding decoded records with kernel and UTC timestamps through an unbounded channel. Malformed records generate warnings; cancellation, readiness failure, or receiver closure terminates reading. Shutdown removes the shared object, extracts resources under a mutex, drops Ebpf to detach links, then awaits task shutdown outside the lock. Endpoint wrappers await shared state and unwrap mutex acquisition. Root-feature tests cover loading, attachment, updates, peer isolation, mapped-IPv4 equivalence, and deletion, with a specific container skip. Decoding tests assert executable identity reconstruction, validity handling, and the 44-byte layout.

---

## proxy_agent/src/redirector/shared_ebpf.rs

### Purpose and Functionality
Defines shared C-compatible eBPF layouts, array conversions, protocol/address-family constants, and map identifiers. These serialization helpers own no asynchronous tasks or kernel resources.
### Key Components
_ip_address stores four words; IPv4 occupies the first. _destination_entry defaults to TCP and encodes destination ports in network byte order. sock_addr_skip_process_entry wraps a PID. sock_addr_audit_key serializes protocol, source port, family, and complete source address into seven words. sock_addr_audit_entry converts seven-word values into agent AuditEntry objects, leaving executable identity unavailable. alert_only_event combines a kernel timestamp, local address, and audit record.
### Behavior and Interactions
Peer conversion canonicalizes mapped IPv4 and preserves address bytes through native-endian words. Source ports use network byte order on Windows and host order otherwise. Audit conversion narrows destination ports without byte swapping and treats non-IPv6 families as IPv4. Alert decoding requires an exact size, returns a BPF lookup error on mismatch, and uses an unaligned read. Conditional modules re-export platform-specific names. Tests assert destination encoding, key roundtrips, peer/protocol isolation, mapped-address equivalence, native IPv6 distinction, PID preservation, audit conversion, and 28-byte key and 56-byte alert layouts, including truncated-record rejection.

---

## proxy_agent/src/redirector/windows/bpf_api.rs

### Purpose and Functionality
Provides Windows-gated dynamic bindings to the eBPF DLL's object, program, map, link, and ring-buffer APIs. Two Tokio OnceCells retain the library and optional product version for process-wide reuse; initialization and access here are synchronous.
### Key Components
try_load_ebpf_api initializes the library when absent and reports availability. Initialization first tries the installation beneath ProgramFiles, then falls back to the DLL name through the system search path. Product-version discovery occurs only after loading from the installation path; discovery failure is logged without rejecting the library. Function-pointer aliases describe native calling signatures, and a generic helper resolves exports on demand.
### Behavior and Interactions
String arguments become owned CStrings kept alive through each native call; embedded nulls return typed errors. Missing libraries or exports produce BPF errors, with loader failures including the last OS error. Initialization warnings and OnceCell set failures emit telemetry. Wrapper Results represent binding/conversion failures, while native pointers and numeric return codes pass through for callers to interpret. Ring-buffer construction forwards callback/context pointers and null options; polling and freeing leave ownership discipline to higher-level code. No tests are declared.

---

## proxy_agent/src/redirector/windows/bpf_obj.rs

### Purpose and Functionality
Defines native data declarations used by the Windows redirector's dynamically loaded eBPF API. Included through the Windows-gated parent, it contains mostly C-layout structs, enums, and aliases rather than executable behavior.
### Key Components
Aliases represent identifiers, descriptors, handles, UUID program/attachment types, and libbpf integer names. Enums describe map kinds, pinning, execution modes, and attachment categories. Structs describe instructions, programs, links, in-memory map definitions, maps, and objects, including raw pointers, handles, descriptors, and state flags. The object declaration contains vectors of program and map pointers. ring_buffer is an opaque zero-sized declaration. Shared destination/process-skip layouts and the parent audit-value wrapper are re-exported rather than redefined.
### Behavior and Interactions
ebpf_link_t::empty initializes a link with a null pin path, zero handle/descriptor, and disconnected false. Map key/value size helpers directly dereference a caller-provided map pointer to read its embedded definition; they perform no null or lifetime validation and return no recoverable errors. These declarations provide no automatic native allocation, cleanup, synchronization, or pointer ownership enforcement. Higher-level code supplies resource operations. No tests are declared.

---

## proxy_agent/src/redirector/windows/bpf_prog.rs

### Purpose and Functionality
Implements Windows BpfObject operations for program loading/attachment, redirect policies, audits, process bypass, bind monitoring, and alert-only events. No tests are declared.
### Key Components
Loading closes previous resources, opens and loads the replacement, and stores its pointer after success; load-error paths do not close the newly opened pointer. Attachment requires IPv4 authorization, tolerates an absent IPv6 program with a warning, and retains links. Map helpers reject null objects/maps and retrieve descriptors plus key/value sizes. Audit lookup and deletion select compatibility keys by size.
### Behavior and Interactions
Policy updates map IPv4 destinations to the local proxy; mutations and lookups convert binding errors and nonzero native results into contextual BPF errors. Closing drains links, disconnects/destroys them, closes the object, and clears its pointer, logging wrapper errors. Alert subscription boxes an unbounded-channel sender as callback context. The callback validates event bytes, adds a userspace timestamp, and returns failure for invalid data or a closed receiver. A tracked blocking task polls with bounded waits until cancellation; negative results log and retry, binding errors stop polling. Creation failures reclaim the sender; task exit attempts ring freeing and reclaims context.

---

## proxy_agent/src/redirector/windows.rs

### Purpose and Functionality
Implements the Windows-only redirector facade, resource wrapper, and audit compatibility decoding. Initialization retries DLL loading with blocking sleeps; loading prefers an existing program matching the DLL's major/minor version, otherwise retaining the default path.
### Key Components
BpfObject holds the native object pointer, retained links, and event-task runtime, with an explicit Send implementation. AuditKeyEntry selects canonical peer-address keys or released port-only legacy keys by size, rejecting unsupported sizes. AuditValueEntry supports canonical/legacy layouts and an owned buffer for unknown sizes; conversion validates lengths and uses unaligned reads. Legacy values become IPv4 audit entries with executable identity unavailable.
### Behavior and Interactions
Socket audit retrieval uses the WFP redirect-context ioctl and validates its returned byte count. Endpoint-policy helpers asynchronously retrieve shared state, then lock the object for map updates; map/port failures log and return false, while poisoned policy locks can panic. Shutdown removes the shared object, extracts its runtime under a mutex, awaits task shutdown outside the lock, and closes native resources before propagating shutdown errors. Tests cover legacy key collisions and byte order, canonical IPv6 acceptance, invalid sizes, buffer selection, and canonical/legacy audit conversion.

---

## proxy_agent/src/redirector.rs

### Purpose and Functionality
This module coordinates eBPF redirection, selecting Windows or non-Windows Linux implementations. AuditEntry carries identity, network-order destination fields, address family, and executable identity metadata.
### Key Components
Redirector clones shared state and retains a cancellation token. Startup retries up to five times with ten-millisecond delays, loads and attaches the program, excludes the agent process, and leaves redirect policies to provisioning. It stores the BPF object behind Arc and Mutex and notifies provisioning. Subscription and shared-state update failures are logged without necessarily failing startup. Cancellation detected after successful startup triggers closure.
### Behavior and Interactions
EventTaskRuntime owns event tasks: shutdown cancels and joins all tasks, returning the first join error; drop cancels and aborts remaining tasks. Alert processing selects cancellation against channel input, enriches records with claims, and logs unavailable details on enrichment failure. A fifteen-minute limiter keys on user, process, destination, and address family; local address rendering remains IPv4-only. Audit lookup, removal, and bind-monitor updates lock the shared object or return a missing-object error. Closure delegates platform cleanup before marking stopped. Tests cover limiter identity differences and expiry, address round-trips, and invalid-address zero returns.

---

## proxy_agent/src/runtime_coordinator.rs

### Purpose and Functionality
Coordinates the proxy listener and redirector as an owned runtime pair, reconciling desired listener ports and soft-audit transitions independently of listener health.
### Key Components
RuntimeCoordinator owns optional listener-thread and redirector-task records, child cancellation tokens, and startup timestamps. PairAction and evaluate_status determine stable-state pair actions; starting_timed_out tracks a sixty-second STARTING limit. The fallback helper collects stopped-module messages into the agent fallback reason.
### Behavior and Interactions
A spawned coordinator starts the default listener and redirector, then observes runtime-status updates or a one-second reconciliation timer. Port changes take priority over timeout and soft-audit handling. A replacement waits for readiness but remains selectable despite bind failure or readiness timeout. When the redirector is running, failure to stage its local port discards the candidate; subsequent policy-update failures do not roll selection back. Committing enables provisioning notifications, replaces the owned runtime, and cancels and joins the old listener through spawn_blocking. Redirector shutdown awaits its startup task before closing resources. Cancellation or publisher loss stops both modules; operational failures are logged. Tests assert failed-listener ownership, handoff and old-port reuse, desired-port status isolation, soft-audit stop/restart decisions, and timeout boundaries.

---

## proxy_agent/src/service/windows_main.rs

### Purpose and Functionality
Integrates the agent with the Windows Service Control Manager. Its parent module compiles this implementation only on Windows.
### Key Components
run_service creates SharedState and a synchronous service-control closure. A process-global Tokio OnceCell holds the ServiceStatusHandle so the non-async callback can publish status without asynchronous state access.
### Behavior and Interactions
The agent service starts before control-handler registration. Registration and reporting Running propagate failures through the repository Result type. The service runs in its own process and accepts stop requests. Configuring default service-failure actions is best effort: errors are logged, and initialization continues. The status handle is then stored with unwrap, so repeated initialization can panic. A Stop control invokes service shutdown and immediately reports Stopped with a successful Windows exit code, without awaiting worker cleanup. Failure to publish Stopped is logged. If the global handle is unavailable, the callback logs a warning and exits the process successfully. Interrogate returns success without changing status; other controls return NotImplemented. After initialization, run_service returns rather than running its own wait loop. No tests are declared here.

---

## proxy_agent/src/service.rs

### Purpose and Functionality
Provides platform-aware service startup and shutdown around shared agent state, logging, secure-channel polling, and runtime-pair coordination.
### Key Components
start_service configures optional system-event logging and managed rotating agent and connection logs. It records version, operating-system, architecture, worker-count, and elapsed-time information. A KeyKeeper receives configured storage locations and polling duration, while RuntimeCoordinator manages the proxy and redirector.
### Behavior and Interactions
Startup spawns secure-channel polling and launches the coordinator without awaiting either task's completion or retaining their join handles. An empty log directory skips managed file logging and prints a notice. Non-Windows builds additionally write the startup message to the serial console; start_service_wait initializes shared state and then sleeps indefinitely in one-second intervals. Windows builds start an ETW listener for two eBPF-related providers, filtering at warning level; provider-registration and listener-run errors are logged without propagating them. stop_service logs shutdown, cancels the shared cancellation token, stops Windows ETW when applicable, and stops telemetry event logging. It does not synchronously join the spawned workers. This file contains no unit-test module.

---

## proxy_agent/src/shared_state.rs

### Purpose and Functionality
Collects clonable handles to the agent's shared-state components and exposes a common cancellation mechanism. The module also declares the access-control, agent-status, connection-summary, key-keeper, provision, proxy-server, and redirector wrapper modules.
### Key Components
SharedState privately owns a CancellationToken, CommonState, and one handle for each wrapper. start_all creates a fresh token, passes a clone into CommonState initialization, and initializes every wrapper through its start_new constructor. Getters return cloned handles rather than transferring ownership or exposing mutable fields.
### Behavior and Interactions
Cloning SharedState or retrieving its cancellation token preserves shared cancellation behavior; cancel_cancellation_token signals that token rather than synchronously stopping or joining workers. The constructor returns Self directly and provides no local error-propagation path. EventThreadsSharedState is a second clonable bundle with public fields intended for lower-priority event and status work. Its new constructor borrows SharedState and clones the cancellation, common, access-control, redirector, key-keeper, provision, agent-status, and connection-summary handles, omitting proxy-server state. This file defines no platform-specific branches or unit tests; its usage example illustrates handle retrieval and cancellation.

---
