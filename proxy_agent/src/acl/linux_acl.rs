// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::common::{logger, result::Result};
use nix::unistd::{chown, Gid, Uid};
use proxy_agent_shared::misc_helpers;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

pub fn acl_directory(dir_to_acl: PathBuf) -> Result<()> {
    let dir_str = misc_helpers::path_to_string(&dir_to_acl);
    logger::write(format!(
        "acl_directory: start to set root-only permission to folder {dir_str}."
    ));

    match chown(&dir_to_acl, Some(Uid::from_raw(0)), Some(Gid::from_raw(0))) {
        Ok(_) => logger::write(format!(
            "acl_directory: successfully set root-only permission to folder {dir_str}."
        )),
        Err(e) => {
            logger::write(format!(
                "acl_directory: failed to set root-only permission to folder {dir_str}. Error: {e:?}"
            ));
        }
    }

    // Set permissions to 700
    let permissions = fs::Permissions::from_mode(0o700);
    match fs::set_permissions(dir_to_acl, permissions) {
        Ok(_) => logger::write(format!(
            "acl_directory: successfully set root-only permission to folder {dir_str}."
        )),
        Err(e) => {
            logger::write(format!(
                "acl_directory: failed to set root-only permission to folder {dir_str}. Error: {e:?}"
            ));
        }
    }

    Ok(())
}

#[cfg(feature = "test-with-root")]
#[cfg(test)]
mod tests {
    use proxy_agent_shared::misc_helpers;
    use std::env;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    #[tokio::test]
    async fn acl_directory_test() {
        let mut temp_test_path = env::temp_dir();
        let logger_key = "acl_directory_test";
        temp_test_path.push(logger_key);
        // clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);
        _ = misc_helpers::try_create_folder(&temp_test_path);

        let output = super::acl_directory(temp_test_path.to_path_buf());
        assert!(
            output.is_ok(),
            "failed to set root-only permission to folder"
        );
        match fs::metadata(temp_test_path.to_path_buf()) {
            Ok(metadata) => {
                let permissions = metadata.permissions().mode();
                assert_eq!(permissions & 0o700, 0o700, "Permissions are not set to 700");
            }
            Err(e) => panic!("Failed to get metadata: {:?}", e),
        }

        _ = fs::remove_dir_all(&temp_test_path);
    }
}
