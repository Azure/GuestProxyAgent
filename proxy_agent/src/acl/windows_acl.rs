// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#![cfg(windows)]

use crate::common::logger;
use proxy_agent_shared::misc_helpers;
use std::io::{Error, ErrorKind};
use std::path::PathBuf;
use winapi::um::winnt::PSID;
use windows_acl::acl::{AceType, ACL};
use windows_acl::helper;
use windows_sys::Win32::Security::{CONTAINER_INHERIT_ACE, OBJECT_INHERIT_ACE};

// https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids
const LOCAL_SYSTEM_SID: &str = "S-1-5-18";
const BUILDIN_ADMIN_SID: &str = "S-1-5-32-544";
const FULL_CONTROL: u32 = 2032127;

pub fn acl_directory(dir_to_acl: PathBuf) -> std::io::Result<()> {
    let dir_str = misc_helpers::path_to_string(dir_to_acl);
    let mut acl;
    match ACL::from_file_path(&dir_str, true) {
        Ok(a) => acl = a,
        Err(e) => {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "acl_directory: failed to get ACL object for folder {}, error: {}",
                    dir_str, e
                ),
            ));
        }
    }

    let system_sid;
    match helper::string_to_sid(LOCAL_SYSTEM_SID) {
        Ok(sid) => system_sid = sid,
        Err(e) => {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "acl_directory: failed to get sid for {}, error: {}",
                    LOCAL_SYSTEM_SID, e
                ),
            ));
        }
    }
    let admin_sid;
    match helper::string_to_sid(BUILDIN_ADMIN_SID) {
        Ok(sid) => admin_sid = sid,
        Err(e) => {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "acl_directory: failed to get sid for {}, error: {}",
                    BUILDIN_ADMIN_SID, e
                ),
            ));
        }
    }

    logger::write(format!(
        "acl_directory: removing all the remaining access rules for folder {}.",
        dir_str
    ));
    match acl.all() {
        Ok(entries) => {
            logger::write(format!(
                "acl_directory: get '{}' access rules for folder {}.",
                entries.len(),
                dir_str
            ));
            for entry in entries {
                match entry.sid {
                    Some(ref sid) => {
                        match acl.remove_entry(
                            sid.as_ptr() as PSID,
                            Some(entry.entry_type),
                            Some(entry.flags),
                        ) {
                            Ok(r) => {
                                logger::write(format!("acl_directory: removed '{}' entry.", r));
                            }
                            Err(e) => {
                                logger::write_warning(format!(
                                    "acl_directory: remove_entry failed with error '{}' entry.",
                                    e
                                ));
                            }
                        }
                    }
                    None => {
                        logger::write_warning("acl_directory: entry.sid is NONE.".to_string());
                    }
                }
            }
        }
        Err(e) => {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "acl_directory: failed to get ACL entries for folder {}, error: {}",
                    dir_str, e
                ),
            ));
        }
    }

    logger::write(format!(
        "acl_directory: Adding new access rules for the target directory {}.",
        dir_str
    ));
    let flags = (CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE) as u8;
    let mask = FULL_CONTROL;
    match acl.add_entry(
        system_sid.as_ptr() as PSID,
        AceType::AccessAllow,
        flags,
        mask,
    ) {
        Ok(r) => {
            logger::write(format!(
                "acl_directory: Adding new access rules for sid {} with result {}.",
                LOCAL_SYSTEM_SID, r
            ));
        }
        Err(e) => {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "acl_directory: failed to add_entry for sid {}, error: {}",
                    LOCAL_SYSTEM_SID, e
                ),
            ));
        }
    }
    match acl.add_entry(
        admin_sid.as_ptr() as PSID,
        AceType::AccessAllow,
        flags,
        mask,
    ) {
        Ok(r) => {
            logger::write(format!(
                "acl_directory: Adding new access rules for sid {} with result {}.",
                BUILDIN_ADMIN_SID, r
            ));
        }
        Err(e) => {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "acl_directory: failed to add_entry for sid {}, error: {}",
                    BUILDIN_ADMIN_SID, e
                ),
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::common::logger;
    use proxy_agent_shared::logger_manager;
    use std::env;
    use std::fs;
    use std::path::PathBuf;
    use winapi::um::winnt::PSID;
    use windows_acl::acl::{AceType, ACL};
    use windows_acl::helper;

    const EVERY_ONE_SID: &str = "S-1-1-0";

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

        // test when dir_to_acl does not exist
        let invalid_path = PathBuf::from("invalid_path");
        _ = super::acl_directory(invalid_path);

        // add everyone to log directory
        let every_one_sid = helper::string_to_sid(EVERY_ONE_SID).unwrap();
        let flags = (super::CONTAINER_INHERIT_ACE | super::OBJECT_INHERIT_ACE) as u8;
        let mask = super::FULL_CONTROL;

        let mut acl = ACL::from_file_path(temp_test_path.to_str().unwrap(), true).unwrap();
        acl.add_entry(
            every_one_sid.as_ptr() as PSID,
            AceType::AccessAllow,
            flags,
            mask,
        )
        .unwrap();

        // acl the log directory
        _ = super::acl_directory(temp_test_path.to_path_buf());
        let acl = ACL::from_file_path(temp_test_path.to_str().unwrap(), false).unwrap();
        let entries = acl
            .get(every_one_sid.as_ptr() as PSID, Some(AceType::AccessAllow))
            .unwrap();
        assert_eq!(0, entries.len(), "ACL rule entry should be 0 for everyone");

        let admin_sid = helper::string_to_sid(super::BUILDIN_ADMIN_SID).unwrap();
        let entries = acl
            .get(admin_sid.as_ptr() as PSID, Some(AceType::AccessAllow))
            .unwrap();
        assert_eq!(1, entries.len(), "ACL rule entry should be 1 for admins");

        let system_sid = helper::string_to_sid(super::LOCAL_SYSTEM_SID).unwrap();
        let entries = acl
            .get(system_sid.as_ptr() as PSID, Some(AceType::AccessAllow))
            .unwrap();
        assert_eq!(
            1,
            entries.len(),
            "ACL rule entry should be 1 for system_sid"
        );

        _ = fs::remove_dir_all(&temp_test_path);
    }
}
