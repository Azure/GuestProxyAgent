// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use super::bpf_api::*;
use super::bpf_obj::*;
use crate::common::constants;
use crate::common::logger;
use crate::redirector::AuditEntry;
use proxy_agent_shared::misc_helpers;
use std::env;
use std::ffi::c_void;
use std::io::{Error, ErrorKind};
use std::path::PathBuf;

const EBPF_API_FILE_NAME: &str = "EbpfApi.dll";
const EBPF_OBJECT_NULL: i32 = 2022;
const EBPF_OPEN_ERROR: i32 = 2023;
const EBPF_LOAD_ERROR: i32 = 2024;
const EBPF_FIND_PROGRAM_ERROR: i32 = 2025;
const EBPF_ATTACH_PROGRAM_ERROR: i32 = 2026;
const EBPF_FIND_MAP_ERROR: i32 = 2027;
const EBPF_UPDATE_MAP_ERROR: i32 = 2028;

pub static mut BPF_OBJECT: Option<*mut bpf_object> = None;

pub fn init() -> std::io::Result<()> {
    let program_files_dir = env::var("ProgramFiles").unwrap_or("C:\\Program Files".to_string());
    let program_files_dir = PathBuf::from(program_files_dir);
    let ebpf_for_windows_dir = program_files_dir.join("ebpf-for-windows");
    let bpf_api_file_path = ebpf_for_windows_dir.join(EBPF_API_FILE_NAME);

    logger::write_information(format!(
        "Try to load ebpf api file from: {}",
        misc_helpers::path_to_string(bpf_api_file_path.to_path_buf())
    ));
    match load_ebpf_api(bpf_api_file_path) {
        Ok(_) => Ok(()),
        Err(e) => {
            let message = format!("{}", e);
            logger::write_warning(message);
            logger::write_warning("Try to load ebpf api file from default system path".to_string());
            load_ebpf_api(PathBuf::from(EBPF_API_FILE_NAME))
        }
    }
}

/**
Routine Description:

    This routine load bpf object.

Arguments:

    bpf_file_path - Path to the bpf object file.

Return Value:

    0 on success. On failure appropriate RESULT is returned.
 */
pub fn load_bpf_object(bpf_file_path: PathBuf) -> i32 {
    logger::write_information(format!(
        "Starting redirector with ebpf file {}",
        misc_helpers::path_to_string(bpf_file_path.to_path_buf())
    ));
    close_bpf_object();
    unsafe {
        let obj = match bpf_object__open(&misc_helpers::path_to_string(bpf_file_path.to_path_buf()))
        {
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
            BPF_OBJECT = Some(obj);
        }

        result
    }
}

/**
Routine Description:

    This routine attach authorize_connect4 to bpf.

Arguments:

Return Value:

    0 on success. On failure appropriate RESULT is returned.
 */
pub fn attach_bpf_prog() -> i32 {
    unsafe {
        match BPF_OBJECT {
            Some(obj) => {
                let connect4_program =
                    match bpf_object__find_program_by_name(obj, "authorize_connect4") {
                        Ok(p) => p,
                        Err(e) => {
                            logger::write_error(format!("{}", e));
                            return EBPF_FIND_PROGRAM_ERROR;
                        }
                    };
                if connect4_program.is_null() {
                    logger::write_error(
                        "bpf_object__find_program_by_name 'authorize_connect4' return null"
                            .to_string(),
                    );
                    return EBPF_FIND_PROGRAM_ERROR;
                }
                let fd_id = match bpf_program__fd(connect4_program) {
                    Ok(fd) => fd,
                    Err(e) => {
                        logger::write_error(format!("{}", e));
                        return EBPF_FIND_PROGRAM_ERROR;
                    }
                };
                match bpf_prog_attach(fd_id, 0, bpf_attach_type::BPF_CGROUP_INET4_CONNECT, 0) {
                    Ok(r) => r,
                    Err(e) => {
                        logger::write_error(format!("{}", e));
                        return EBPF_ATTACH_PROGRAM_ERROR;
                    }
                }
            }
            None => {
                return EBPF_OBJECT_NULL;
            }
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

Return Value:

    0 on success. On failure appropriate RESULT is returned.
 */
pub fn update_bpf_map(local_port: u16, dest_ipv4: u32, dest_port: u16) -> i32 {
    unsafe {
        match BPF_OBJECT {
            Some(obj) => {
                let proxy_map = match bpf_object__find_map_by_name(obj, "policy_map") {
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
                        return EBPF_UPDATE_MAP_ERROR;
                    }
                }
            }
            None => {
                return EBPF_OBJECT_NULL;
            }
        }
    }
}

/**
Routine Description:

    This routine close bpf object.

Arguments:

Return Value:

 */
pub fn close_bpf_object() {
    unsafe {
        match BPF_OBJECT {
            Some(obj) => {
                _ = bpf_object__close(obj);
                BPF_OBJECT = None;
            }
            None => {}
        }
    }
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
pub fn lookup_bpf_audit_map(source_port: u16) -> std::io::Result<AuditEntry> {
    unsafe {
        match BPF_OBJECT {
            Some(obj) => {
                let audit_map = match bpf_object__find_map_by_name(obj, "audit_map") {
                    Ok(m) => m,
                    Err(e) => {
                        let message = format!(
                            "Failed to find audit map in bpf object with error: {error}.",
                            error = e
                        );
                        return Err(Error::new(ErrorKind::InvalidInput, message));
                    }
                };
                if audit_map.is_null() {
                    let message =
                        "bpf_object__find_map_by_name 'audit_map' return null.".to_string();
                    return Err(Error::new(ErrorKind::InvalidInput, message));
                }
                let map_fd = match bpf_map__fd(audit_map) {
                    Ok(fd) => fd,
                    Err(e) => {
                        let message = format!(
                            "Failed to get audit map fd in bpf object with error: {error}.",
                            error = e
                        );
                        return Err(Error::new(ErrorKind::InvalidInput, message));
                    }
                };

                // query by source port.
                let key = sock_addr_aduit_key_t::from_source_port(source_port);
                let value = AuditEntry::empty();

                let result = match bpf_map_lookup_elem(
                    map_fd,
                    &key as *const sock_addr_aduit_key_t as *const c_void,
                    &value as *const AuditEntry as *mut c_void,
                ) {
                    Ok(r) => r,
                    Err(e) => {
                        let message = format!(
                            "Failed to lookup {source_port} in bpf audit map with error: {e}."
                        );
                        return Err(Error::new(ErrorKind::InvalidInput, message));
                    }
                };

                if result != 0 {
                    let message = format!(
                        "Failed to lookup {source_port} in bpf audit map with result: {result}."
                    );
                    return Err(Error::new(ErrorKind::InvalidInput, message));
                }

                Ok(value)
            }
            None => {
                let message = format!(
                    "Failed to lookup {source_port} in bpf audit map because bpf has not loaded."
                );
                return Err(Error::new(ErrorKind::InvalidInput, message));
            }
        }
    }
}

/**
Routine Description:

    This routine add element to skip_process_map.

Arguments:

    pid - process pid to skip redirect.

Return Value:

    0 on success. On failure appropriate RESULT is returned.
 */
pub fn update_bpf_skip_process_map(pid: u32) -> i32 {
    unsafe {
        match BPF_OBJECT {
            Some(obj) => {
                let skip_process_map = match bpf_object__find_map_by_name(obj, "skip_process_map") {
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
                let key = sock_addr_skip_process_entry { pid: pid };
                let value = sock_addr_skip_process_entry { pid: pid };

                match bpf_map_update_elem(
                    map_fd,
                    &key as *const sock_addr_skip_process_entry as *const c_void,
                    &value as *const sock_addr_skip_process_entry as *const c_void,
                    0,
                ) {
                    Ok(r) => r,
                    Err(e) => {
                        logger::write_error(format!("{}", e));
                        return EBPF_UPDATE_MAP_ERROR;
                    }
                }
            }
            None => {
                return EBPF_OBJECT_NULL;
            }
        }
    }
}
