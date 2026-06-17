// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

fn main() {
    // Windows build setup
    #[cfg(windows)]
    {
        static_vcruntime::metabuild();
        let res = winres::WindowsResource::new();
        res.compile().unwrap();
    }

    // Linux eBPF compilation with CO-RE support
    #[cfg(not(windows))]
    {
        compile_ebpf_with_core();
    }
}

#[cfg(not(windows))]
fn compile_ebpf_with_core() {
    use std::env;
    use std::path::PathBuf;
    use std::process::Command;

    let out_dir = env::var("OUT_DIR").unwrap();
    let out_path = PathBuf::from(&out_dir);
    let workspace_root = env::var("CARGO_MANIFEST_DIR")
        .map(|d| PathBuf::from(d).parent().unwrap().to_path_buf())
        .expect("Failed to determine workspace root");

    // Re-run this build script when any eBPF source or shared header changes.
    println!(
        "cargo:rerun-if-changed={}/shared-ebpf/include",
        workspace_root.display()
    );
    println!(
        "cargo:rerun-if-changed={}/linux-ebpf",
        workspace_root.display()
    );

    // Select the architecture-specific defines/includes based on the cargo
    // build target so we produce a correct object for both x86_64 and arm64.
    // This mirrors the arm64/x86 branches in build-linux.sh.
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "x86_64".to_string());
    let (arch_define, arch_include) = match target_arch.as_str() {
        "aarch64" => (
            "-D__TARGET_ARCH_arm64",
            Some("-I/usr/include/aarch64-linux-gnu".to_string()),
        ),
        _ => ("-D__TARGET_ARCH_x86", None),
    };

    // Build flags for CO-RE compilation. These mirror build-linux.sh so both
    // paths produce identical, portable objects.
    // -g emits BTF debug info; -target bpf + clang relocations produce a
    // portable object whose kernel-struct field offsets are resolved at load
    // time against the target kernel's BTF (CO-RE).
    // -Werror makes any eBPF compile warning fail the build (matches build-linux.sh).
    let core_flags = vec![
        "-target".to_string(),
        "bpf".to_string(),
        "-Werror".to_string(),
        "-O2".to_string(),
        "-g".to_string(),
        arch_define.to_string(),
    ];

    // Include paths
    let mut include_paths = vec![
        format!("-I{}/shared-ebpf/include", workspace_root.display()),
        format!("-I{}/linux-ebpf", workspace_root.display()),
    ];
    if let Some(inc) = arch_include {
        include_paths.push(inc);
    }

    // eBPF programs to compile (CO-RE compatible).
    // Output name matches the runtime config (`ebpfProgramName`) so the loader
    // in src/redirector.rs can find it. This mirrors what build-linux.sh
    // produces, but with CO-RE relocations enabled.
    let ebpf_programs = vec![
        ("linux-ebpf/ebpf_cgroup.c", "ebpf_cgroup.o"),
        // Add more programs here as they're converted to CO-RE:
        // ("linux-ebpf/sk_lookup.c", "sk_lookup.o"),
        // ("linux-ebpf/lsm.c", "lsm.o"),
    ];

    for (src, out_obj) in ebpf_programs {
        let src_path = workspace_root.join(src);
        let obj_path = out_path.join(out_obj);

        if !src_path.exists() {
            panic!("eBPF source not found: {}", src_path.display());
        }

        // Compile with clang (requires clang-15+)
        let mut cmd = Command::new("clang");
        cmd.args(&core_flags)
            .args(&include_paths)
            .arg("-c")
            .arg(&src_path)
            .arg("-o")
            .arg(&obj_path);

        match cmd.output() {
            Ok(output) => {
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    // Fail the cargo build so a broken eBPF program is never shipped.
                    panic!("Failed to compile {src}:\n{stderr}");
                } else {
                    println!("cargo:warning=Compiled {} -> {}", src, obj_path.display());
                    // Also place the freshly compiled object at a deterministic
                    // location next to the built binaries so the runtime loader
                    // (get_ebpf_file_path -> current exe dir) and the test
                    // harness always pick up THIS object, not a stale copy left
                    // in some other build-script-output hash directory.
                    // OUT_DIR = <target>/<triple?>/<profile>/build/<pkg-hash>/out
                    // so three parents up is the profile dir (e.g. target/debug).
                    if let Some(profile_dir) = out_path
                        .parent()
                        .and_then(|p| p.parent())
                        .and_then(|p| p.parent())
                    {
                        copy_obj_to(&obj_path, &profile_dir.join(out_obj));
                        let deps_dir = profile_dir.join("deps");
                        if deps_dir.is_dir() {
                            copy_obj_to(&obj_path, &deps_dir.join(out_obj));
                        }
                    }
                }
            }
            Err(e) => {
                panic!("Error running clang for {src}: {e}. Make sure clang-15+ is installed.");
            }
        }
    }

    // Report whether kernel BTF is available on the build host. At runtime the
    // aya loader reads /sys/kernel/btf/vmlinux to perform CO-RE relocations.
    let vmlinux_btf = PathBuf::from("/sys/kernel/btf/vmlinux");
    if !vmlinux_btf.exists() {
        println!(
            "cargo:warning=vmlinux BTF not found at {:?}; CO-RE relocations require kernel BTF at load time",
            vmlinux_btf
        );
    }
}

#[cfg(not(windows))]
fn copy_obj_to(src: &std::path::Path, dst: &std::path::Path) {
    if let Err(e) = std::fs::copy(src, dst) {
        // Non-fatal: the canonical object still exists in OUT_DIR. Warn so a
        // stale copy is never silently relied upon.
        println!(
            "cargo:warning=failed to copy {} -> {}: {e}",
            src.display(),
            dst.display()
        );
    }
}
