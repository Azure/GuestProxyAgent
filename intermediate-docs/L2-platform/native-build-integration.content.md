# Compose Content for: L2-platform/native-build-integration.md

Total files: 3

---

## proxy_agent/build.rs

### Purpose and Functionality
This Cargo build script configures Windows resources or compiles the Linux eBPF connection program. Windows builds invoke static VCRuntime setup and compile Windows resources, panicking if resource compilation fails. Non-Windows builds run compile_ebpf_with_core.
### Key Components
The compiler helper derives repository and output paths from Cargo environment variables and registers eBPF source/header directories for rebuilds. Cargo's target architecture selects ARM64 or default x86 defines and multiarch includes. Clang receives BPF targeting, optimization, debug/BTF emission, and warnings-as-errors flags, producing the connection-program object in OUT_DIR.
### Behavior and Interactions
Missing sources, required environment failures, compiler launch failures, and unsuccessful compilation terminate the build with diagnostics. After successful compilation, copy_obj_to publishes the object beside profile binaries and, if present, into their deps directory so runtime and tests find a fresh copy. Copy failures only emit Cargo warnings; the canonical OUT_DIR object remains. Missing build-host kernel BTF also produces a warning because relocation needs target-kernel BTF at load time. No tests are declared.

---

## proxy_agent_extension/build.rs

### Purpose and Functionality
Defines the extension package's Cargo build-script entry point, rather than runtime extension behavior.
### Key Components
The main function contains a Windows-only compilation block that invokes static_vcruntime build setup and constructs a winres WindowsResource.
### Behavior and Interactions
On Windows, the script requests static VCRuntime configuration and compiles Windows resources using the helper's defaults. Resource compilation is unwrapped, so failure panics and fails the build instead of returning a recoverable extension error. On non-Windows build hosts, the conditional block is excluded and main performs no work. The file declares no additional metadata, runtime resources, or tests.

---

## proxy_agent_setup/build.rs

### Purpose and Functionality
Supplies Cargo build-time setup for the setup executable, not runtime installation behavior.
### Key Components
The build script declares only main. Its Windows-gated block invokes static_vcruntime metadata generation and compiles a newly constructed WindowsResource through winres.
### Behavior and Interactions
Resource compilation is unwrapped, so failure panics and fails the build script. On non-Windows platforms the function performs no work. No tests or custom resource properties are declared.

---
