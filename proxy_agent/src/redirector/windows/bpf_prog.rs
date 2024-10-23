// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use super::bpf_api::*;
use super::bpf_obj::*;
use super::BpfObject;
use crate::common::constants;
use crate::common::logger;
use crate::common::{
    error::{BpfErrorType, Error},
    result::Result,
};
use crate::redirector::AuditEntry;
use proxy_agent_shared::misc_helpers;
use std::ffi::c_void;
use std::mem::size_of_val;
use std::path::PathBuf;

const EBPF_OBJECT_NULL: i32 = 2022;
const EBPF_OPEN_ERROR: i32 = 2023;
const EBPF_LOAD_ERROR: i32 = 2024;
const EBPF_FIND_PROGRAM_ERROR: i32 = 2025;
const EBPF_ATTACH_PROGRAM_ERROR: i32 = 2026;
const EBPF_FIND_MAP_ERROR: i32 = 2027;
const EBPF_UPDATE_MAP_ERROR: i32 = 2028;
const EBPF_DELETE_MAP_ERROR: i32 = 2029;

impl BpfObject {
    fn is_null(&self) -> bool {
        self.0.is_null()
    }

    pub fn new() -> Self {
        Self(std::ptr::null::<bpf_object>().cast_mut())
    }

    /**
    Routine Description:

        This routine load bpf object.

    Arguments:

        bpf_file_path - Path to the bpf object file.

    Return Value:

        0 on success. On failure appropriate RESULT is returned.
     */
    pub fn load_bpf_object(&mut self, bpf_file_path: PathBuf) -> i32 {
        logger::write_information(format!(
            "Starting redirector with ebpf file {}",
            misc_helpers::path_to_string(&bpf_file_path)
        ));
        self.close_bpf_object();
        let obj = match bpf_object__open(&misc_helpers::path_to_string(&bpf_file_path)) {
            Ok(obj) => obj,
            Err(e) => {
                logger::write_error(format!("{}", e));
                return EBPF_OPEN_ERROR;
            }
        };

        if obj.is_null() {
            logger::write_error("bpf_object__open return null".to_string());
            return EBPF_OBJECT_NULL;
        }

        let result = match bpf_object__load(obj) {
            Ok(r) => r,
            Err(e) => {
                logger::write_error(format!("{}", e));
                return EBPF_LOAD_ERROR;
            }
        };

        if result == 0 {
            self.0 = obj;
        }

        result
    }

    /**
    Routine Description:

        This routine attach authorize_connect4 to bpf.

    Arguments:

    Return Value:

        0 on success. On failure appropriate RESULT is returned.
     */
    pub fn attach_bpf_prog(&self) -> i32 {
        if self.is_null() {
            return EBPF_OBJECT_NULL;
        }

        let connect4_program = match bpf_object__find_program_by_name(self.0, "authorize_connect4")
        {
            Ok(p) => {
                logger::write_information("Found authorize_connect4 program.".to_string());
                p
            }
            Err(e) => {
                logger::write_error(format!("{}", e));
                return EBPF_FIND_PROGRAM_ERROR;
            }
        };
        if connect4_program.is_null() {
            logger::write_error(
                "bpf_object__find_program_by_name 'authorize_connect4' return null".to_string(),
            );
            return EBPF_FIND_PROGRAM_ERROR;
        }

        let compartment_id = 1;
        let mut link: ebpf_link_t = ebpf_link_t::empty();
        let mut link: *mut ebpf_link_t = &mut link as *mut ebpf_link_t;
        let link: *mut *mut ebpf_link_t = &mut link as *mut *mut ebpf_link_t;
        match ebpf_prog_attach(
            connect4_program,
            std::ptr::null(),
            &compartment_id as *const i32 as *const c_void,
            size_of_val(&compartment_id),
            link,
        ) {
            Ok(r) => {
                if r != 0 {
                    logger::write_error(format!(
                        "Failed to attach authorize_connect4 program with error code: {}.",
                        r
                    ));
                    return EBPF_ATTACH_PROGRAM_ERROR;
                }
                logger::write_information(
                    "Success attached authorize_connect4 program.".to_string(),
                );

                match bpf_link_disconnect(unsafe { *link }) {
                    Ok(_r) => {
                        logger::write_information("Success disconnected link.".to_string());

                        match bpf_link_destroy(unsafe { *link }) {
                            Ok(r) => {
                                if r != 0 {
                                    logger::write_error(format!(
                                        "Failed to destroy link with error code: {}.",
                                        r
                                    ));
                                    return EBPF_ATTACH_PROGRAM_ERROR;
                                }
                                logger::write_information("Success destroyed link.".to_string());
                                r
                            }
                            Err(e) => {
                                logger::write_error(format!("{}", e));
                                EBPF_ATTACH_PROGRAM_ERROR
                            }
                        }
                    }
                    Err(e) => {
                        logger::write_error(format!("{}", e));
                        EBPF_ATTACH_PROGRAM_ERROR
                    }
                }
            }
            Err(e) => {
                logger::write_error(format!("{}", e));
                EBPF_ATTACH_PROGRAM_ERROR
            }
        }
    }

    /**
    Routine Description:

        This routine add element to policy_map.

    Arguments:

        local_port - proxy local port.
        dest_ipv4  - destination ipv4 address.
        dest_port  - destination port.
        shared_state - shared state.

    Return Value:

        0 on success. On failure appropriate RESULT is returned.
     */
    pub fn update_policy_elem_bpf_map(
        &self,
        local_port: u16,
        dest_ipv4: u32,
        dest_port: u16,
    ) -> i32 {
        if self.is_null() {
            return EBPF_OBJECT_NULL;
        }

        let proxy_map = match bpf_object__find_map_by_name(self.0, "policy_map") {
            Ok(m) => m,
            Err(e) => {
                logger::write_error(format!("{}", e));
                return EBPF_FIND_MAP_ERROR;
            }
        };
        if proxy_map.is_null() {
            logger::write_error(
                "bpf_object__find_map_by_name 'policy_map' return null".to_string(),
            );
            return EBPF_FIND_MAP_ERROR;
        }

        let map_fd = match bpf_map__fd(proxy_map) {
            Ok(fd) => fd,
            Err(e) => {
                logger::write_error(format!("{}", e));
                return EBPF_FIND_MAP_ERROR;
            }
        };

        let key = destination_entry_t::from_ipv4(dest_ipv4, dest_port);
        let value = destination_entry_t::from_ipv4(
            constants::PROXY_AGENT_IP_NETWORK_BYTE_ORDER, //0x100007F - 127.0.0.1
            local_port,
        );

        match bpf_map_update_elem(
            map_fd,
            &key as *const destination_entry_t as *const c_void,
            &value as *const destination_entry_t as *const c_void,
            0,
        ) {
            Ok(r) => r,
            Err(e) => {
                logger::write_error(format!("{}", e));
                EBPF_UPDATE_MAP_ERROR
            }
        }
    }

    /**
    Routine Description:

        This routine close bpf object.

    Arguments:

    Return Value:

     */
    pub fn close_bpf_object(&mut self) {
        if self.0.is_null() {
            return;
        }
        if let Err(e) = bpf_object__close(self.0) {
            logger::write_error(format!("bpf_object__close with error: {}", e));
        }

        self.0 = std::ptr::null::<bpf_object>().cast_mut();
    }

    /**
    Routine Description:

        This routine lookup element from audit_map.

    Arguments:

        source_port - source local port.

        entry - element from audit_map.

    Return Value:

        0 on success. On failure appropriate RESULT is returned.
     */
    pub fn lookup_bpf_audit_map(&self, source_port: u16) -> Result<AuditEntry> {
        if self.is_null() {
            return Err(Error::bpf(BpfErrorType::MapLookupElem(
                source_port.to_string(),
                "BPF has not loaded".to_string(),
            )));
        }

        let audit_map = bpf_object__find_map_by_name(self.0, "audit_map")
            .map_err(|e| Error::bpf(BpfErrorType::GetBpfMap(e.to_string())))?;
        if audit_map.is_null() {
            return Err(Error::bpf(BpfErrorType::GetBpfMap(
                "bpf_object__find_map_by_name 'audit_map' returns null pointer".to_string(),
            )));
        }

        let map_fd = bpf_map__fd(audit_map)
            .map_err(|e| Error::bpf(BpfErrorType::MapFileDescriptor(e.to_string())))?;

        // query by source port.
        let key = sock_addr_audit_key_t::from_source_port(source_port);
        let value = AuditEntry::empty();

        let result = bpf_map_lookup_elem(
            map_fd,
            &key as *const sock_addr_audit_key_t as *const c_void,
            &value as *const AuditEntry as *mut c_void,
        )
        .map_err(|e| {
            Error::bpf(BpfErrorType::MapLookupElem(
                source_port.to_string(),
                format!("Error: {}", e),
            ))
        })?;

        if result != 0 {
            return Err(Error::bpf(BpfErrorType::MapLookupElem(
                source_port.to_string(),
                format!("Result: {}", result),
            )));
        }

        Ok(value)
    }

    /**
    Routine Description:

        This routine add element to skip_process_map.

    Arguments:

        pid - process pid to skip redirect.

    Return Value:

        0 on success. On failure appropriate RESULT is returned.
     */
    pub fn update_bpf_skip_process_map(&self, pid: u32) -> i32 {
        if self.is_null() {
            return EBPF_OBJECT_NULL;
        }

        let skip_process_map = match bpf_object__find_map_by_name(self.0, "skip_process_map") {
            Ok(m) => m,
            Err(e) => {
                logger::write_error(format!("{}", e));
                return EBPF_FIND_MAP_ERROR;
            }
        };
        if skip_process_map.is_null() {
            logger::write_error(
                "bpf_object__find_map_by_name 'skip_process_map' return null".to_string(),
            );
            return EBPF_FIND_MAP_ERROR;
        }

        let map_fd = match bpf_map__fd(skip_process_map) {
            Ok(fd) => fd,
            Err(e) => {
                logger::write_error(format!("{}", e));
                return EBPF_FIND_MAP_ERROR;
            }
        };

        // insert process id entry.
        let key = sock_addr_skip_process_entry { pid };
        let value = sock_addr_skip_process_entry { pid };

        match bpf_map_update_elem(
            map_fd,
            &key as *const sock_addr_skip_process_entry as *const c_void,
            &value as *const sock_addr_skip_process_entry as *const c_void,
            0,
        ) {
            Ok(r) => r,
            Err(e) => {
                logger::write_error(format!("{}", e));
                EBPF_UPDATE_MAP_ERROR
            }
        }
    }

    /**
    Routine Description:
        This routine delete element from policy_map.
    Arguments:
        dest_ipv4  - destination ipv4 address.
        dest_port  - destination port.
    Return Value:
        0 on success. On failure appropriate RESULT is returned.
     */
    pub fn remove_policy_elem_bpf_map(&self, dest_ipv4: u32, dest_port: u16) -> i32 {
        if self.is_null() {
            return EBPF_OBJECT_NULL;
        }

        let proxy_map = match bpf_object__find_map_by_name(self.0, "policy_map") {
            Ok(m) => m,
            Err(e) => {
                logger::write_error(format!("{}", e));
                return EBPF_FIND_MAP_ERROR;
            }
        };
        if proxy_map.is_null() {
            logger::write_error(
                "bpf_object__find_map_by_name 'policy_map' return null".to_string(),
            );
            return EBPF_FIND_MAP_ERROR;
        }

        let map_fd = match bpf_map__fd(proxy_map) {
            Ok(fd) => fd,
            Err(e) => {
                logger::write_error(format!("{}", e));
                return EBPF_FIND_MAP_ERROR;
            }
        };

        let key = destination_entry_t::from_ipv4(dest_ipv4, dest_port);
        match bpf_map_delete_elem(map_fd, &key as *const destination_entry_t as *const c_void) {
            Ok(r) => r,
            Err(e) => {
                logger::write_error(format!("{}", e));
                EBPF_DELETE_MAP_ERROR
            }
        }
    }
}
