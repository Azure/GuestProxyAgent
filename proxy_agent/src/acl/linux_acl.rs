// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::common::logger;
use proxy_agent_shared::misc_helpers;
use std::path::PathBuf;

pub fn acl_directory(dir_to_acl: PathBuf) -> std::io::Result<()> {
    let dir_str = misc_helpers::path_to_string(dir_to_acl);
    logger::write(format!(
        "acl_directory: start to set root-only permission to folder {}.",
        dir_str.to_string()
    ));

    let output =
        misc_helpers::execute_command("chown", vec!["-R", "root:root", &dir_str], -1);
    logger::write(format!(
        "acl_directory: set folder {} to owner root, result: '{}'-'{}'-'{}'.",
        dir_str.to_string(),
        output.0,
        output.1,
        output.2
    ));

    let output =
        misc_helpers::execute_command("chmod", vec!["-cR", "700", &dir_str], -1);
    logger::write(format!(
        "acl_directory: set root access only permission to folder {} result: '{}'-'{}'-'{}'.",
        dir_str.to_string(),
        output.0,
        output.1,
        output.2
    ));

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::common::logger;
    use proxy_agent_shared::{logger_manager, misc_helpers};
    use std::env;
    use std::fs;

    #[test]
    fn acl_directory_test() {
        let mut temp_test_path = env::temp_dir();
        let logger_key = "acl_directory_test";
        temp_test_path.push(logger_key);
        // clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);
        logger_manager::init_logger(
            logger::AGENT_LOGGER_KEY.to_string(), // production code uses 'Agent_Log' to write.
            temp_test_path.clone(),
            logger_key.to_string(),
            10 * 1024 * 1024,
            20,
        );

        _ = super::acl_directory(temp_test_path.to_path_buf());
        let out_put =
            misc_helpers::execute_command("ls", vec!["-ld", &temp_test_path.to_str().unwrap()], -1);
        assert_eq!(0, out_put.0, "exit code mismatch");
        assert!(
            out_put.1.contains("drwx------ 2 root root"),
            "stdout message mismatch"
        );

        _ = fs::remove_dir_all(&temp_test_path);
    }
}
