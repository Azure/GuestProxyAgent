// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use proxy_agent_shared::misc_helpers;
use std::path::PathBuf;

pub fn acl_directory(dir_to_acl: PathBuf) -> std::io::Result<()> {
    let dir_str = misc_helpers::path_to_string(dir_to_acl);
    tracing::info!(
        "acl_directory: start to set root-only permission to folder {}.",
        dir_str
    );

    let output = misc_helpers::execute_command("chown", vec!["-R", "root:root", &dir_str], -1);
    tracing::info!(
        "acl_directory: set folder {} to owner root, result: '{}'-'{}'-'{}'.",
        dir_str,
        output.0,
        output.1,
        output.2
    );

    let output = misc_helpers::execute_command("chmod", vec!["-cR", "700", &dir_str], -1);
    tracing::info!(
        "acl_directory: set root access only permission to folder {} result: '{}'-'{}'-'{}'.",
        dir_str,
        output.0,
        output.1,
        output.2
    );

    Ok(())
}

#[cfg(feature = "test-with-root")]
#[cfg(test)]
mod tests {
    use proxy_agent_shared::misc_helpers;

    #[test]
    fn acl_directory_test() {
        let temp_dir = tempfile::TempDir::new().unwrap();

        _ = super::acl_directory(temp_dir.path().into());
        let out_put =
            misc_helpers::execute_command("ls", vec!["-ld", temp_dir.path().to_str().unwrap()], -1);
        assert_eq!(0, out_put.0, "exit code mismatch");
        assert!(
            out_put.1.contains("drwx------ 2 root root"),
            "stdout message mismatch"
        );
    }
}
