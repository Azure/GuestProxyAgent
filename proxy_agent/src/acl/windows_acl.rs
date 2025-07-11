// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use crate::common::{
    error::{AclErrorType, Error},
    logger,
    result::Result,
};
use proxy_agent_shared::misc_helpers;
use std::path::PathBuf;
use winapi::um::winnt::PSID;
use windows_acl::acl::{AceType, ACL};
use windows_acl::helper;
use windows_sys::Win32::Security::{CONTAINER_INHERIT_ACE, OBJECT_INHERIT_ACE};

// https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids
const LOCAL_SYSTEM_SID: &str = "S-1-5-18";
const BUILDIN_ADMIN_SID: &str = "S-1-5-32-544";
const FULL_CONTROL: u32 = 2032127;

pub fn acl_directory(dir_to_acl: PathBuf) -> Result<()> {
    let dir_str = misc_helpers::path_to_string(&dir_to_acl);

    let mut acl = ACL::from_file_path(&dir_str, true)
        .map_err(|e| Error::Acl(AclErrorType::AclObject(dir_str.to_string()), e))?;

    let system_sid = helper::string_to_sid(LOCAL_SYSTEM_SID)
        .map_err(|e| Error::Acl(AclErrorType::Sid(LOCAL_SYSTEM_SID.to_string()), e))?;

    let admin_sid = helper::string_to_sid(BUILDIN_ADMIN_SID)
        .map_err(|e| Error::Acl(AclErrorType::Sid(BUILDIN_ADMIN_SID.to_string()), e))?;

    logger::write(format!(
        "acl_directory: removing all the remaining access rules for folder {dir_str}."
    ));

    match acl.all() {
        Ok(entries) => {
            logger::write(format!(
                "acl_directory: get '{len}' access rules for folder {dir_str}.",
                len = entries.len()
            ));
            for entry in entries {
                match entry.sid {
                    Some(ref sid) => {
                        logger::write(format!(
                            "acl_directory: removing ACL entry '{}-{}-{}-{}' .",
                            entry.string_sid, entry.entry_type, entry.flags, entry.mask
                        ));
                        match acl.remove_entry(
                            sid.as_ptr() as PSID,
                            Some(entry.entry_type),
                            None, // remove all, including inherited permissions
                        ) {
                            Ok(r) => {
                                logger::write(format!("acl_directory: removed '{r}' entry."));
                            }
                            Err(e) => {
                                logger::write_warning(format!(
                                    "acl_directory: remove_entry failed with error '{e}' entry.",
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
            return Err(Error::Acl(AclErrorType::AclEntries(dir_str), e));
        }
    }

    logger::write(format!(
        "acl_directory: Adding new access rules for the target directory {dir_str}."
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
                "acl_directory: Adding new access rules for sid {LOCAL_SYSTEM_SID} with result {r}.",
            ));
        }
        Err(e) => {
            return Err(Error::Acl(
                AclErrorType::AddEntry(LOCAL_SYSTEM_SID.to_string()),
                e,
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
                "acl_directory: Adding new access rules for sid {BUILDIN_ADMIN_SID} with result {r}."
            ));
        }
        Err(e) => {
            return Err(Error::Acl(
                AclErrorType::AddEntry(LOCAL_SYSTEM_SID.to_string()),
                e,
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use proxy_agent_shared::misc_helpers;
    use std::env;
    use std::fs;
    use std::path::PathBuf;
    use winapi::um::winnt::PSID;
    use windows_acl::acl::{AceType, ACL};
    use windows_acl::helper;

    const EVERY_ONE_SID: &str = "S-1-1-0";

    #[tokio::test]
    async fn acl_directory_test() {
        let mut temp_test_path = env::temp_dir();
        let logger_key = "acl_directory_test";
        temp_test_path.push(logger_key);
        // clean up and ignore the clean up errors
        _ = fs::remove_dir_all(&temp_test_path);
        _ = misc_helpers::try_create_folder(&temp_test_path);

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
