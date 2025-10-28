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
use std::path::Path;

// This module contains the logic to interact with the windows eBPF program & maps.
impl BpfObject {
    fn is_null(&self) -> bool {
        self.0.is_null()
    }

    pub fn new() -> Self {
        Self(
            std::ptr::null::<bpf_object>().cast_mut(),
            std::ptr::null::<ebpf_link_t>().cast_mut(),
        )
    }

    /**
    Routine Description:

        This routine load bpf object.

    Arguments:

        bpf_file_path - Path to the bpf object file.

    Return Value:

        On failure appropriate BpfErrorType is returned.
     */
    pub fn load_bpf_object(&mut self, bpf_file_path: &Path) -> Result<()> {
        logger::write_information(format!(
            "Starting redirector with ebpf file {}",
            misc_helpers::path_to_string(bpf_file_path)
        ));
        self.close_bpf_object();
        let obj = match bpf_object__open(&misc_helpers::path_to_string(bpf_file_path)) {
            Ok(obj) => obj,
            Err(e) => {
                //logger::write_error(format!("{}", e));
                // return EBPF_OPEN_ERROR;
                return Err(Error::Bpf(BpfErrorType::OpenBpfObject(
                    bpf_file_path.display().to_string(),
                    e.to_string(),
                )));
            }
        };

        if obj.is_null() {
            let error_code = libbpf_get_error()?;
            return Err(Error::Bpf(BpfErrorType::OpenBpfObject(
                bpf_file_path.display().to_string(),
                format!("bpf_object__open return null pointer with error code '{error_code}'",),
            )));
        }

        let result = match bpf_object__load(obj) {
            Ok(r) => r,
            Err(e) => {
                // logger::write_error(format!("{}", e));
                // return EBPF_LOAD_ERROR;
                return Err(Error::Bpf(BpfErrorType::LoadBpfObject(
                    bpf_file_path.display().to_string(),
                    e.to_string(),
                )));
            }
        };

        if result == 0 {
            self.0 = obj;
        } else {
            return Err(Error::Bpf(BpfErrorType::LoadBpfObject(
                bpf_file_path.display().to_string(),
                format!("bpf_object__load return with error code '{result}'"),
            )));
        }

        Ok(())
    }

    /**
    Routine Description:

        This routine attach authorize_connect4 to bpf.

    Arguments:

    Return Value:

        On failure appropriate RESULT is returned.
     */
    pub fn attach_bpf_prog(&mut self) -> Result<()> {
        if self.is_null() {
            return Err(Error::Bpf(BpfErrorType::NullBpfObject));
        }
        let program_name = "authorize_connect4";
        let connect4_program = match bpf_object__find_program_by_name(self.0, program_name) {
            Ok(p) => {
                logger::write_information(format!("Found {program_name} program."));
                p
            }
            Err(e) => {
                return Err(Error::Bpf(BpfErrorType::AttachBpfProgram(
                    program_name.to_string(),
                    e.to_string(),
                )));
            }
        };
        if connect4_program.is_null() {
            return Err(Error::Bpf(BpfErrorType::AttachBpfProgram(
                program_name.to_string(),
                "bpf_object__find_program_by_name return null".to_string(),
            )));
        }

        let compartment_id = 1;
        let mut link: ebpf_link_t = ebpf_link_t::empty();
        let mut link: *mut ebpf_link_t = &mut link as *mut ebpf_link_t;
        //let link: *mut *mut ebpf_link_t = &mut link as *mut *mut ebpf_link_t;
        match ebpf_prog_attach(
            connect4_program,
            std::ptr::null(),
            &compartment_id as *const i32 as *const c_void,
            size_of_val(&compartment_id),
            &mut link as *mut *mut ebpf_link_t,
        ) {
            Ok(r) => {
                if r != 0 {
                    return Err(Error::Bpf(BpfErrorType::AttachBpfProgram(
                        program_name.to_string(),
                        format!("ebpf_prog_attach return with error code '{r}'"),
                    )));
                }
                logger::write_information(
                    "Success attached authorize_connect4 program.".to_string(),
                );
                self.1 = link;
            }
            Err(e) => {
                return Err(Error::Bpf(BpfErrorType::AttachBpfProgram(
                    program_name.to_string(),
                    format!("ebpf_prog_attach return with error '{e}'"),
                )));
            }
        }

        Ok(())
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

        On failure appropriate RESULT is returned.
     */
    pub fn update_policy_elem_bpf_map(
        &self,
        endpoint_name: &str,
        local_port: u16,
        dest_ipv4: u32,
        dest_port: u16,
    ) -> Result<()> {
        let map_name = "policy_map";
        let map_fd = self.get_bpf_map_fd(map_name)?;

        let key = destination_entry_t::from_ipv4(dest_ipv4, dest_port);
        let value = destination_entry_t::from_ipv4(
            constants::PROXY_AGENT_IP_NETWORK_BYTE_ORDER, //0x100007F - 127.0.0.1
            local_port,
        );

        let result = bpf_map_update_elem(
            map_fd,
            &key as *const destination_entry_t as *const c_void,
            &value as *const destination_entry_t as *const c_void,
            0,
        )
        .map_err(|e| {
            Error::Bpf(BpfErrorType::UpdateBpfMapHashMap(
                map_name.to_string(),
                endpoint_name.to_string(),
                format!("bpf_map_update_elem returned error {e}"),
            ))
        })?;
        if result != 0 {
            return Err(Error::Bpf(BpfErrorType::UpdateBpfMapHashMap(
                map_name.to_string(),
                endpoint_name.to_string(),
                format!("bpf_map_update_elem returned error code {result}"),
            )));
        }

        Ok(())
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
            logger::write_error(format!("bpf_object__close with error: {e}"));
        }
        self.0 = std::ptr::null::<bpf_object>().cast_mut();

        if self.1.is_null() {
            return;
        }
        if let Err(e) = bpf_link_disconnect(self.1) {
            logger::write_error(format!("bpf_link_disconnect with error: {e}"));
        }
        if let Err(e) = bpf_link_destroy(self.1) {
            logger::write_error(format!("bpf_link_destroy with error: {e}"));
        }
        self.1 = std::ptr::null::<ebpf_link_t>().cast_mut();
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
    pub fn lookup_audit(&self, source_port: u16) -> Result<AuditEntry> {
        let map_name = "audit_map";
        let map_fd = self.get_bpf_map_fd(map_name)?;

        // query by source port.
        let key = sock_addr_audit_key_t::from_source_port(source_port);
        let value = AuditEntry::empty();

        let result = bpf_map_lookup_elem(
            map_fd,
            &key as *const sock_addr_audit_key_t as *const c_void,
            &value as *const AuditEntry as *mut c_void,
        )
        .map_err(|e| {
            Error::Bpf(BpfErrorType::MapLookupElem(
                source_port.to_string(),
                format!("Error: {e}"),
            ))
        })?;

        if result != 0 {
            return Err(Error::Bpf(BpfErrorType::MapLookupElem(
                source_port.to_string(),
                format!("Result: {result}"),
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

        On failure appropriate RESULT is returned.
     */
    pub fn update_skip_process_map(&self, pid: u32) -> Result<()> {
        let map_name = "skip_process_map";
        let map_fd = self.get_bpf_map_fd(map_name)?;

        // insert process id entry.
        let key = sock_addr_skip_process_entry { pid };
        let value = sock_addr_skip_process_entry { pid };

        let result = bpf_map_update_elem(
            map_fd,
            &key as *const sock_addr_skip_process_entry as *const c_void,
            &value as *const sock_addr_skip_process_entry as *const c_void,
            0,
        )
        .map_err(|e| {
            Error::Bpf(BpfErrorType::UpdateBpfMapHashMap(
                map_name.to_string(),
                format!("insert pid: {pid}"),
                format!("bpf_map_update_elem returned error {e}"),
            ))
        })?;
        if result != 0 {
            return Err(Error::Bpf(BpfErrorType::UpdateBpfMapHashMap(
                map_name.to_string(),
                format!("insert pid: {pid}"),
                format!("bpf_map_update_elem returned error code {result}"),
            )));
        }

        Ok(())
    }

    /**
    Routine Description:
        This routine delete element from policy_map.
    Arguments:
        dest_ipv4  - destination ipv4 address.
        dest_port  - destination port.
    Return Value:
        On failure appropriate RESULT is returned.
     */
    pub fn remove_policy_elem_bpf_map(&self, dest_ipv4: u32, dest_port: u16) -> Result<()> {
        let map_name = "policy_map";
        let map_fd = self.get_bpf_map_fd(map_name)?;

        let key = destination_entry_t::from_ipv4(dest_ipv4, dest_port);
        let result =
            bpf_map_delete_elem(map_fd, &key as *const destination_entry_t as *const c_void)
                .map_err(|e| {
                    Error::Bpf(BpfErrorType::MapDeleteElem(
                        format!("dest_ipv4: {dest_ipv4}, dest_port: {dest_port}"),
                        format!("Error: {e}"),
                    ))
                })?;
        if result != 0 {
            return Err(Error::Bpf(BpfErrorType::MapDeleteElem(
                format!("dest_ipv4: {dest_ipv4}, dest_port: {dest_port}"),
                format!("Result: {result}"),
            )));
        }

        Ok(())
    }

    pub fn remove_audit_map_entry(&self, source_port: u16) -> Result<()> {
        let audit_map_name = "audit_map";
        let map_fd = self.get_bpf_map_fd(audit_map_name)?;

        let key = sock_addr_audit_key_t::from_source_port(source_port);
        let result = bpf_map_delete_elem(
            map_fd,
            &key as *const sock_addr_audit_key_t as *const c_void,
        )
        .map_err(|e| {
            Error::Bpf(BpfErrorType::MapDeleteElem(
                source_port.to_string(),
                format!("Error: {e}"),
            ))
        })?;

        if result != 0 {
            return Err(Error::Bpf(BpfErrorType::MapDeleteElem(
                source_port.to_string(),
                format!("Result: {result}"),
            )));
        }

        Ok(())
    }

    fn get_bpf_map_fd(&self, map_name: &str) -> Result<i32> {
        if self.is_null() {
            return Err(Error::Bpf(BpfErrorType::NullBpfObject));
        }

        let bpf_map = bpf_object__find_map_by_name(self.0, map_name).map_err(|e| {
            Error::Bpf(BpfErrorType::GetBpfMap(map_name.to_string(), e.to_string()))
        })?;
        if bpf_map.is_null() {
            return Err(Error::Bpf(BpfErrorType::GetBpfMap(
                map_name.to_string(),
                "bpf_object__find_map_by_name returns null pointer".to_string(),
            )));
        }

        bpf_map__fd(bpf_map).map_err(|e| Error::Bpf(BpfErrorType::MapFileDescriptor(e.to_string())))
    }
}
