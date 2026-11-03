# Compose Content for: L2-platform/agent-cloud-test-utilities.md

Total files: 13

---

## e2etest/GuestProxyAgentTest/Utilities/CertificateUtility.cs

### Purpose and Functionality
Provides certificate discovery and optional private-key accessibility checks for the end-to-end harness. Certificates can come from an X.509 store or a base64-encoded environment variable whose name is supplied by the caller; the environment-variable overload does not contact a vault.
### Key Components
CertificateUtility exposes IsCertInstalled and several GetCertificate overloads. IsCertInstalled removes spaces and uppercases the thumbprint before searching without certificate-validity filtering. The store-specific lookup returns the first matching certificate or null. The convenience lookup searches CurrentUser before LocalMachine, accepting a match only when any requested private-key check succeeds.
### Behavior and Interactions
Environment loading first attempts passwordless PKCS#12 parsing, then falls back to certificate parsing on a cryptographic exception. Loading failures are logged and return null. CanAccessPrivateKey checks key presence, a non-null PrivateKey, and positive key size; cryptographic access failures become false. Store-specific lookup closes its store in finally and logs exceptions, whereas IsCertInstalled only closes after a successful search. Returned certificates are not disposed by this utility, and rejected certificate objects are not explicitly disposed either.

---

## e2etest/GuestProxyAgentTest/Utilities/Constants.cs

### Purpose and Functionality
Centralizes names shared by the test harness, including storage containers, standard command-output files, the custom-output parameter, cleanup and architecture tags, and environment-variable names used to obtain access tokens. It declares names rather than storing token values or performing storage operations.
### Key Components
Constants is a static class with fixed fields and platform-dependent script-name fields. Its static constructor selects installation, log collection, validation, metadata ping, extension, local-address ping, and penetration-test scripts. A separate constant names the Linux package-installation script.
### Behavior and Interactions
IS_WINDOWS delegates to RuntimeInformation.IsOSPlatform. The static constructor chooses PowerShell script names on Windows and shell-script names otherwise, so the non-Windows branch is not explicitly restricted to Linux. The cgroup setup script is an empty string on Windows and a shell-script name on other platforms. Selection occurs when the class is initialized, based on the harness process platform rather than a supplied target-VM setting. No files are opened and no scripts are executed here.

---

## e2etest/GuestProxyAgentTest/Utilities/ResourceNamer.cs

### Purpose and Functionality
Generates lowercase resource-name candidates from a caller-supplied seed and prefix, plus random numeric and GUID-derived components. It also exposes a separate method returning a normally formatted new GUID.
### Key Components
ResourceNamer stores a lowercase seed extended with three hexadecimal GUID characters. A shared Random produces a five-digit, zero-padded numeric component. RandomName is virtual and selects whether to include the stored seed according to the requested maximum length. RandomString builds hexadecimal suffixes from new GUIDs. An unused static date-format array has no effect on generation.
### Behavior and Interactions
Construction and RandomName lock the shared Random instance. When the prefix, stored seed, and digits would exceed the limit, RandomName omits the seed and appends a suffix calculated from half the remaining space. Otherwise it includes the seed and uses the same half-space calculation. It does not truncate an oversized prefix or validate the length argument, so maxLen is not a guaranteed bound. RandomString can overshoot its requested length across multiple iterations because each chunk uses the original requested length.

---

## e2etest/GuestProxyAgentTest/Utilities/RunCommandRunner.cs

### Purpose and Functionality
Executes an Azure managed Run Command against a supplied virtual-machine resource and returns output locations together with an execution-success flag. It relies on RunCommandSettingBuilder to prepare the script, parameters, and output blobs rather than downloading command output itself.
### Key Components
ExecuteRunCommandOnVM optionally passes the builder through a caller-provided transformation before building settings. The private toVMRunCommandData helper creates the Azure request using the configured test location, a script URI, standard-output and error-output blob URIs, and ordinary input parameters copied from the settings dictionary.
### Behavior and Interactions
The request disables asynchronous guest execution and sets a one-hour timeout. Creation or update is awaited to completion with the supplied cancellation token. The runner then synchronously retrieves InstanceView without forwarding that token. Success requires both a Succeeded execution state and exit code zero. RunCommandOutputDetails contains the configured standard, error, and custom-output SAS locations. SDK, URI-construction, builder, and instance-view access errors propagate; the runner neither retries nor removes the managed command resource.

---

## e2etest/GuestProxyAgentTest/Utilities/RunCommandSettingBuilder.cs

### Purpose and Functionality
Provides a fluent, mutable builder for RunCommandSetting, combining scenario context, a command name, script selection, script parameters, and optional custom-output storage. It owns one settings instance and returns that same instance from Build.
### Key Components
Setters record a local script path or an already available script SAS URI, with the URI taking precedence. Parameter methods insert dictionary entries; the list overload ignores null or empty lists. CustomOutputSas records a separate destination, while TestScenarioSetting supplies the storage-folder prefix.
### Behavior and Interactions
Build throws when neither script source is provided or the command name is null. A local script is synchronously uploaded through StorageHelper only when no script URI exists. Build then creates standard-output and error-output append blobs beneath the scenario and command prefix and attaches the scenario settings. A nonempty custom-output URI is UTF-8 encoded, base64 converted, and inserted as a script parameter. Missing scenario initialization can fail during prefix access. Duplicate parameter names propagate dictionary errors; repeated builds can repeat storage operations and duplicate the custom parameter. No reset or defensive copy is performed.

---

## e2etest/GuestProxyAgentTest/Utilities/StorageHelper.cs

### Purpose and Functionality
Wraps synchronous Azure Blob Storage operations against the shared account configured in TestSetting. It supports append-blob creation, local-file uploads, SAS URI generation, and deletion of blobs selected by a name prefix.
### Key Components
StorageHelper is an internal singleton with a private constructor. Init ignores its tenant and client arguments, initializes a GuestProxyAgentE2EStorageAccountTokenCredential once, and returns immediately on later calls. Instance throws a generic exception if initialization has not occurred. Upload overloads use either the local basename or an explicit destination name and optionally prepend a parent path.
### Behavior and Interactions
Append blobs are created only if absent; ordinary uploads overwrite existing blobs. Both operations return a generated SAS URI. SAS generation requests a user-delegation key starting six hours earlier and expiring one day later, but sets the SAS expiry seven days ahead. The SAS resource is the container and permissions include all container permissions, even though the returned URI addresses one blob. Cleanup enumerates the supplied prefix and deletes every matching blob. There is no retry, cancellation, exception translation, or initialization synchronization in this file.

---

## e2etest/GuestProxyAgentTest/Utilities/TestAssertUtils.cs

### Purpose and Functionality
Defines a minimal assertion helper for the end-to-end harness rather than a collection of tests or framework-specific assertions.
### Key Components
TestAssertUtils is static and contains AssertIsTrue, which accepts a parameterless Boolean delegate and a caller-supplied explanatory message.
### Behavior and Interactions
The method invokes the delegate once. A true result returns normally; a false result throws a generic Exception with an assertion-failure prefix followed by the message. Delegate exceptions propagate unchanged, and a null delegate is not checked before invocation. The helper does not log, retry, create test-result records, or manage resources.

---

## e2etest/GuestProxyAgentTest/Utilities/TestCommonUtilities.cs

### Purpose and Functionality
Collects harness initialization, synchronous HTTP download helpers, and environment-token deserialization. TestSetup parses YAML into TestConfig, initializes TestSetting with artifact and result paths plus the requested version, then initializes storage and VM helpers from those settings.
### Key Components
DownloadContentAsString returns a success/content or failure/message tuple. DownloadFile writes a successful HTTP response to a local destination and returns a Boolean. GetAccessTokenFromEnv deserializes a nested TokenEnvModel and constructs an Azure AccessToken from its token text and parsed expiration. The model declares serialization names for both fields.
### Behavior and Interactions
Downloads reject empty URLs and require successful HTTP status codes. Each attempt creates and disposes an HttpClient; file downloads also dispose their output stream and delete any existing destination before attempting the request. String-download failures optionally log and sleep one second, including after the final failed attempt. File retries have no delay and dereference the logger unconditionally in the catch block despite its optional default. Missing or null-deserialized token data throws; malformed JSON and expiration errors propagate. The null-deserialization error includes the original environment text.

---

## e2etest/GuestProxyAgentTest/Utilities/TestLogger.cs

### Purpose and Functionality
Provides a small console logger that associates harness messages with a caller-selected prefix. The file contains only this logging class, not tests or logging configuration.
### Key Components
TestLogger captures the prefix in its constructor and exposes it through a get-only Prefix property. Log is its sole output method.
### Behavior and Interactions
Each Log call writes one formatted line through Console.WriteLine, containing the bracketed prefix, the current local date and time with millisecond precision, and the supplied message. It does not filter levels, redact text, buffer entries, create files, add explicit synchronization, or handle output exceptions.

---

## e2etest/GuestProxyAgentTest/Utilities/TestMapReader.cs

### Purpose and Functionality
Loads the harness's YAML test-map hierarchy and flattens included test groups into individual TestScenarioSetting objects. It translates configuration metadata into scenario inputs rather than instantiating or executing scenario classes.
### Key Components
The private TestMapFile method chooses among four map filenames using the requested ARM64 flag and Constants.IS_WINDOWS. ReadFlattenTestScenarioSettingFromTestMap locates the executing assembly's directory, reads the selected map beneath its TestMap subdirectory, and deserializes each included group with YamlUtils.
### Behavior and Interactions
SelectMany combines each group with its scenarios. Every resulting setting receives marketplace image offer, publisher, SKU, and version; the shared-gallery image identifier; the group name; and the scenario's configured class name and display name. ToList materializes the complete result before returning. Map selection uses the harness platform, with all non-Windows hosts taking the Linux-named branch, and ARM64 selection defaults to false. This file adds no validation, deduplication, logging, cancellation, or error recovery; path, deserialization, and missing-data failures propagate.

---

## e2etest/GuestProxyAgentTest/Utilities/VMBuilder.cs

### Purpose and Functionality
Provisions Azure test VMs and supporting networking from scenario settings. GuestProxyAgentSettings holds three initially false switches for enablement, extension installation, and local-file rules. Loading settings records the resource group and generates resource names.
### Key Components
VMBuilder checks initialization, creates credential-backed ARM clients, and selects a VM size unless overridden. Availability resolution excludes subscription-unavailable SKUs, prefers the configured size, then architecture-specific fallbacks, then a two-vCPU architecture match; exhaustion logs a warning and returns the configured size.
### Behavior and Interactions
Build can delete an existing resource group, creates a cleanup-tagged group, and provisions a VM. Networking creates a subnet with default outbound access disabled, a public IP with optional service tagging, and a NIC. VM data supports marketplace or shared-gallery images, managed OS storage, credentials, required purchase plans, and ARM64 extension tags. Proxy endpoints use local rules or profile references, defaulting to Enforce when references are absent. Harness OS selects Windows/Linux configuration; explicit extension control applies only to non-Windows, non-gallery creation. Cancellation reaches VM creation, not the other provisioning calls. Errors propagate without rollback of partially created resources.

---

## e2etest/GuestProxyAgentTest/Utilities/VMHelper.cs

### Purpose and Functionality
VMHelper centralizes Azure virtual-machine lookup and cleanup of end-to-end test resources. It is an internal singleton whose Instance property throws until Init has run. Initialization creates an ArmClient using GuestProxyAgentE2ETokenCredential and the supplied default subscription; the tenant and application-client parameters are not used. Repeated initialization returns without replacing the client.
### Key Components
GetVMResource resolves a resource group and virtual machine through the default subscription. CleanupTestResources deletes the scenario resource group, if present, waiting for completion, then cleans the scenario-prefixed folders in two shared blob containers through StorageHelper.
### Behavior and Interactions
CleanupOldTestResourcesAndForget asynchronously obtains the subscription, filters resource groups by a case-insensitive enabled cleanup tag, and selects each group's earliest deployment with a timestamp. Groups whose earliest deployment is at least two days old are deleted with a wait-until-started request; groups without a qualifying deployment remain untouched. Despite its name, this method returns an awaitable Task. There is no local exception handling, so Azure and storage failures propagate and can prevent subsequent cleanup steps.

---

## e2etest/GuestProxyAgentTest/Utilities/YamlUtils.cs

### Purpose and Functionality
YamlUtils is a small static utility that loads a YAML file into a caller-selected generic type.
### Key Components
DeserializeYaml<T> constructs a fresh YamlDotNet deserializer configured with CamelCaseNamingConvention, opens the supplied path using StreamReader, reads the entire file, and deserializes that text as T.
### Behavior and Interactions
The reader is owned by a using block and is disposed when the operation completes or throws. The method is synchronous and provides no additional validation, caching, exception translation, or recovery. File-access and YAML-deserialization errors propagate to the caller. This file contains no tests.

---
