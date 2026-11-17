**TL;DR:** Cargo build scripts configure static VCRuntime and Windows resources for the agent, extension, and setup executables. On non-Windows build hosts, only the agent script performs native compilation, producing and publishing the Linux eBPF connection-program object.

# Native Build Integration


<!-- TIER2-POINTER:BEGIN (managed by step8_inject_tier2_pointer.py) -->
> **Need a specific class, method, error code, config key, or flow step?**
> Read `intermediate-docs/L2-platform/native-build-integration.content.md` for implementation details; stay here for overviews.
> Search the companion for the source-file heading and range-read that section, starting with Purpose and Functionality.
> Verify behavior in source when needed; do not load the entire companion.
<!-- TIER2-POINTER:END -->
## Why

Native prerequisites must be built alongside Rust binaries: Windows executables
need resource compilation and runtime-linkage setup, while the Linux agent needs
a fresh eBPF object discoverable by its runtime loader and test executables.
These scripts provide build-time integration, not extension lifecycle or runtime
installation behavior.

## What

| Build-script host | Agent | Extension and setup |
|---|---|---|
| Windows | Static VCRuntime setup and default Windows resources | Same Windows setup |
| Non-Windows | Compile and publish the Linux eBPF object | No work |

Platform branches use host-side `cfg(windows)` / `cfg(not(windows))`; they are
not selected by the Cargo target OS. Within the non-Windows agent branch,
`CARGO_CFG_TARGET_ARCH` selects ARM64 defines/includes for `aarch64`, otherwise
x86 defaults, including when that variable is unavailable.

## How

### Windows resource setup

Each `main` invokes `static_vcruntime::metabuild`, constructs
`winres::WindowsResource` through `WindowsResource::new`, and calls
`WindowsResource::compile`. Compilation errors are unwrapped and fail the build.
The scripts do not set custom resource properties.

### Linux eBPF compilation and publication

1. `compile_ebpf_with_core` obtains the repository root from
   `CARGO_MANIFEST_DIR` and the canonical output directory from `OUT_DIR`.
   It registers `shared-ebpf\include` and `linux-ebpf` for Cargo rebuilds.
2. Clang compiles `linux-ebpf\ebpf_cgroup.c` into `OUT_DIR\ebpf_cgroup.o`.
   BPF targeting, optimization, debug/BTF emission, and warnings-as-errors
   support CO-RE (Compile Once, Run Everywhere) relocation. Includes cover shared
   headers, Linux eBPF sources, and the selected architecture's system headers.
3. After successful compilation, `copy_obj_to` copies the object to the profile
   directory three parents above `OUT_DIR`, and to its `deps` directory if that
   directory exists. These copies keep runtime and test discovery aligned with
   the newly built object rather than stale build-script output directories.
4. The script checks build-host kernel BTF availability. Missing BTF only warns;
   target-kernel BTF is needed when the runtime loader performs CO-RE relocation.

### Failure boundaries

Missing required environment values or source files, failure to launch Clang,
and unsuccessful compilation terminate the build with diagnostics. Object-copy
failures only emit Cargo warnings; the canonical `OUT_DIR` object remains.
Successful compilation therefore does not guarantee that adjacent runtime/test
copies were refreshed. None of these three scripts declares tests.

## Code Pointers

| Component | File Path | Key Classes |
|---|---|---|
| Agent native build | `proxy_agent\build.rs` | No classes; `main`, `compile_ebpf_with_core`, `copy_obj_to` |
| Extension native build | `proxy_agent_extension\build.rs` | No classes; `main`, `WindowsResource` |
| Setup native build | `proxy_agent_setup\build.rs` | No classes; `main`, `WindowsResource` |

## Related Components

- [Linux eBPF sources](../../linux-ebpf) and
  [shared eBPF headers](../../shared-ebpf/include): compilation inputs and rebuild dependencies.
- [Redirector](../../proxy_agent/src/redirector.rs): runtime object discovery;
  preserve the `ebpf_cgroup.o` name expected by `ebpfProgramName`.
- [Linux build entry point](../../build-linux.sh): parallel native-build path
  whose architecture selection and compiler flags should remain aligned.
