// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#![allow(non_camel_case_types)]
#![cfg_attr(windows, allow(dead_code))]

use crate::common::{
    error::{BpfErrorType, Error},
    result::Result,
};
use std::ffi::c_void;

#[repr(C)]
pub struct _ip_address {
    pub ip: [u32; 4], // ipv4 uses the first element; ipv6 uses all 4 elements
}
impl _ip_address {
    fn empty() -> Self {
        _ip_address { ip: [0, 0, 0, 0] }
    }

    pub fn from_ipv4(ipv4: u32) -> Self {
        let mut ip = Self::empty();
        ip.ip[0] = ipv4;
        ip
    }

    #[allow(dead_code)]
    pub fn from_ipv6(ipv6: [u32; 4]) -> Self {
        let mut ip = Self::empty();
        ip.ip.copy_from_slice(&ipv6);
        ip
    }
}
pub type ip_address = _ip_address;

#[repr(C)]
pub struct _destination_entry {
    pub destination_ip: ip_address,
    pub destination_port: u32,
    pub protocol: u32,
}
impl _destination_entry {
    pub fn empty() -> Self {
        _destination_entry {
            destination_ip: ip_address::empty(),
            destination_port: 0,
            protocol: IPPROTO_TCP,
        }
    }

    pub fn from_ipv4(ipv4: u32, port: u16) -> Self {
        let mut entry = Self::empty();
        entry.destination_ip = ip_address::from_ipv4(ipv4);
        entry.destination_port = u32::from(port.to_be());
        entry
    }

    pub fn to_array(&self) -> [u32; 6] {
        let mut array: [u32; 6] = [0; 6];
        array[..4].copy_from_slice(&self.destination_ip.ip);
        array[4] = self.destination_port;
        array[5] = self.protocol;
        array
    }
}
pub type destination_entry = _destination_entry;

pub const IPPROTO_TCP: u32 = 6;
#[allow(dead_code)]
pub const IPPROTO_UDP: u32 = 17;

#[repr(C)]
pub struct sock_addr_skip_process_entry {
    pub pid: u32,
}
impl sock_addr_skip_process_entry {
    fn empty() -> Self {
        sock_addr_skip_process_entry { pid: 0 }
    }

    pub fn from_pid(pid: u32) -> Self {
        let mut entry = Self::empty();
        entry.pid = pid;
        entry
    }

    pub fn to_array(&self) -> [u32; 1] {
        [self.pid]
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct sock_addr_audit_key {
    pub protocol: u32,
    pub source_port: u32,
}
#[allow(dead_code)]
impl sock_addr_audit_key {
    #[cfg(windows)]
    pub fn from_source_port(port: u16) -> Self {
        sock_addr_audit_key {
            protocol: IPPROTO_TCP,
            source_port: u32::from(port.to_be()),
        }
    }

    #[cfg(not(windows))]
    pub fn from_source_port(port: u16) -> Self {
        sock_addr_audit_key {
            protocol: IPPROTO_TCP,
            source_port: u32::from(port),
        }
    }

    pub fn to_array(&self) -> [u32; 2] {
        [self.protocol, self.source_port]
    }

    pub fn from_array(array: [u32; 2]) -> Self {
        sock_addr_audit_key {
            protocol: array[0],
            source_port: array[1],
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct sock_addr_audit_entry {
    pub logon_id: u32,
    pub process_id: u32,
    pub is_root: u32,
    pub destination_ipv4: u32,
    pub destination_port: u32,
}
impl sock_addr_audit_entry {
    pub fn empty() -> Self {
        sock_addr_audit_entry {
            logon_id: 0,
            process_id: 0,
            is_root: 0,
            destination_ipv4: 0,
            destination_port: 0,
        }
    }

    pub fn from_array(array: [u32; 5]) -> Self {
        sock_addr_audit_entry {
            logon_id: array[0],
            process_id: array[1],
            is_root: array[2],
            destination_ipv4: array[3],
            destination_port: array[4],
        }
    }

    #[allow(dead_code)]
    pub fn to_array(&self) -> [u32; 5] {
        [
            self.logon_id,
            self.process_id,
            self.is_root,
            self.destination_ipv4,
            self.destination_port,
        ]
    }

    pub fn to_audit_entry(&self) -> crate::redirector::AuditEntry {
        crate::redirector::AuditEntry {
            logon_id: u64::from(self.logon_id),
            process_id: self.process_id,
            is_admin: self.is_root as i32,
            destination_ipv4: self.destination_ipv4,
            destination_port: self.destination_port as u16,
        }
    }
}

/// Legacy eBPF audit entry layout used by older Windows eBPF programs.
#[repr(C)]
pub struct sock_addr_audit_entry_legacy {
    pub logon_id: u64,
    pub process_id: u32,
    pub is_admin: i32,
    pub destination_ipv4: u32,
    pub destination_port: u16,
}
impl sock_addr_audit_entry_legacy {
    pub fn empty() -> Self {
        sock_addr_audit_entry_legacy {
            logon_id: 0,
            process_id: 0,
            is_admin: 0,
            destination_ipv4: 0,
            destination_port: 0,
        }
    }

    pub fn to_audit_entry(&self) -> crate::redirector::AuditEntry {
        crate::redirector::AuditEntry {
            logon_id: self.logon_id,
            process_id: self.process_id,
            is_admin: self.is_admin,
            destination_ipv4: self.destination_ipv4,
            destination_port: self.destination_port,
        }
    }
}

/// Represents an unknown audit value entry.
pub struct GenericAuditValueEntry {
    /// Owned bytes for unknown layout values.
    ///
    /// We keep this as raw bytes and decode based on `read_size` to avoid
    /// assuming a concrete Rust type up front.
    pub buffer: Vec<u8>,
    /// Allocated size of the audit value data.
    pub data_size: u32,
    /// Number of bytes read from the unknown audit value data.
    pub read_size: u32,
}

pub(crate) enum AuditValueEntry {
    New(sock_addr_audit_entry),
    Legacy(sock_addr_audit_entry_legacy),
    // If unknown type, use the generic audit value entry.
    Unknown(GenericAuditValueEntry),
}

impl AuditValueEntry {
    const VALUE_SIZE_NEW: u32 = std::mem::size_of::<sock_addr_audit_entry>() as u32;
    const VALUE_SIZE_LEGACY: u32 = std::mem::size_of::<sock_addr_audit_entry_legacy>() as u32;

    /// Returns the maximum value size among all supported audit entry types.
    fn max_value_size() -> u32 {
        Self::VALUE_SIZE_NEW.max(Self::VALUE_SIZE_LEGACY)
    }

    pub fn empty(value_size: u32) -> Self {
        match value_size {
            Self::VALUE_SIZE_NEW => AuditValueEntry::New(sock_addr_audit_entry::empty()),
            Self::VALUE_SIZE_LEGACY => {
                AuditValueEntry::Legacy(sock_addr_audit_entry_legacy::empty())
            }
            _ => {
                let max_value_size = Self::max_value_size();
                AuditValueEntry::Unknown(GenericAuditValueEntry {
                    // Allocate empty buffer with the maximum value size currently supported.
                    buffer: vec![0u8; max_value_size as usize],
                    data_size: max_value_size,
                    // For map lookups, value_size is fixed per map and equals the
                    // number of bytes written by bpf_map_lookup_elem.
                    read_size: value_size,
                })
            }
        }
    }

    pub fn value_size(&self) -> u32 {
        match self {
            AuditValueEntry::New(_) => Self::VALUE_SIZE_NEW,
            AuditValueEntry::Legacy(_) => Self::VALUE_SIZE_LEGACY,
            AuditValueEntry::Unknown(entry) => entry.data_size,
        }
    }

    pub fn value_pointer_mut(&mut self) -> *mut c_void {
        match self {
            AuditValueEntry::New(entry) => entry as *mut sock_addr_audit_entry as *mut c_void,
            AuditValueEntry::Legacy(entry) => {
                entry as *mut sock_addr_audit_entry_legacy as *mut c_void
            }
            AuditValueEntry::Unknown(entry) => entry.buffer.as_mut_ptr() as *mut c_void,
        }
    }

    pub fn to_audit_entry(&self) -> Result<crate::redirector::AuditEntry> {
        match self {
            AuditValueEntry::New(entry) => Ok(entry.to_audit_entry()),
            AuditValueEntry::Legacy(entry) => Ok(entry.to_audit_entry()),
            AuditValueEntry::Unknown(entry) => {
                // Cast raw bytes to concrete audit value type based on bytes read.
                match entry.read_size {
                    Self::VALUE_SIZE_NEW => {
                        if entry.buffer.len() < Self::VALUE_SIZE_NEW as usize {
                            return Err(Error::Bpf(BpfErrorType::MapLookupElem(
                                "to_audit_entry".to_string(),
                                format!(
                                    "Insufficient buffer length {} for canonical audit entry size {}",
                                    entry.buffer.len(),
                                    Self::VALUE_SIZE_NEW
                                ),
                            )));
                        }

                        let value = unsafe {
                            std::ptr::read_unaligned(
                                entry.buffer.as_ptr() as *const sock_addr_audit_entry,
                            )
                        };
                        Ok(value.to_audit_entry())
                    }
                    Self::VALUE_SIZE_LEGACY => {
                        if entry.buffer.len() < Self::VALUE_SIZE_LEGACY as usize {
                            return Err(Error::Bpf(BpfErrorType::MapLookupElem(
                                "to_audit_entry".to_string(),
                                format!(
                                    "Insufficient buffer length {} for legacy audit entry size {}",
                                    entry.buffer.len(),
                                    Self::VALUE_SIZE_LEGACY
                                ),
                            )));
                        }

                        let value = unsafe {
                            std::ptr::read_unaligned(
                                entry.buffer.as_ptr() as *const sock_addr_audit_entry_legacy,
                            )
                        };
                        Ok(value.to_audit_entry())
                    }
                    _ => Err(Error::Bpf(BpfErrorType::MapLookupElem(
                        "to_audit_entry".to_string(),
                        format!(
                            "Invalid audit value size read: {}, allocated: {}",
                            entry.read_size, entry.data_size
                        ),
                    ))),
                }
            }
        }
    }
}

#[cfg(not(windows))]
pub mod linux_types {
    pub use super::{
        destination_entry, ip_address, sock_addr_audit_entry, sock_addr_audit_key,
        sock_addr_skip_process_entry, IPPROTO_TCP,
    };
}

#[cfg(windows)]
pub mod windows_types {
    pub use super::{
        destination_entry as destination_entry_t, sock_addr_audit_key as sock_addr_audit_key_t,
        sock_addr_skip_process_entry,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destination_entry_ipv4_roundtrip_array_shape() {
        let entry = destination_entry::from_ipv4(0x1081_3FA8, 80);
        let array = entry.to_array();

        assert_eq!(array[0], 0x1081_3FA8, "destination ipv4 should be in slot 0");
        assert_eq!(array[4], u32::from(80u16.to_be()), "port should be network byte order");
        assert_eq!(array[5], IPPROTO_TCP, "protocol should be TCP by default");
    }

    #[test]
    fn audit_key_array_roundtrip() {
        let key = sock_addr_audit_key::from_source_port(1234);
        let array = key.to_array();
        let rebuilt = sock_addr_audit_key::from_array(array);

        assert_eq!(rebuilt.protocol, IPPROTO_TCP, "protocol mismatch");

        #[cfg(windows)]
        assert_eq!(rebuilt.source_port, u32::from(1234u16.to_be()), "source_port mismatch");

        #[cfg(not(windows))]
        assert_eq!(rebuilt.source_port, 1234u32, "source_port mismatch");
    }

    #[test]
    fn skip_process_entry_pid_roundtrip() {
        let pid = 4321;
        let key = sock_addr_skip_process_entry::from_pid(pid);

        assert_eq!(key.to_array(), [pid], "pid should roundtrip through the map key layout");
    }

    #[test]
    fn audit_entry_canonical_array_roundtrip() {
        let canonical = sock_addr_audit_entry {
            logon_id: 1,
            process_id: 2,
            is_root: 1,
            destination_ipv4: 4,
            destination_port: 5,
        };

        let rebuilt = sock_addr_audit_entry::from_array(canonical.to_array());

        assert_eq!(rebuilt.logon_id, canonical.logon_id);
        assert_eq!(rebuilt.process_id, canonical.process_id);
        assert_eq!(rebuilt.is_root, canonical.is_root);
        assert_eq!(rebuilt.destination_ipv4, canonical.destination_ipv4);
        assert_eq!(rebuilt.destination_port, canonical.destination_port);
    }

    #[test]
    fn audit_entry_canonical_to_agent_audit_entry() {
        let canonical = sock_addr_audit_entry {
            logon_id: 42,
            process_id: 1000,
            is_root: 1,
            destination_ipv4: 0x0102_0304,
            destination_port: u32::from(8080u16.to_be()),
        };

        let audit = canonical.to_audit_entry();
        assert_eq!(audit.logon_id, 42);
        assert_eq!(audit.process_id, 1000);
        assert_eq!(audit.is_admin, 1);
        assert_eq!(audit.destination_ipv4, 0x0102_0304);
        assert_eq!(audit.destination_port, 8080u16.to_be());
    }

    #[test]
    fn audit_entry_legacy_to_agent_audit_entry() {
        let legacy = sock_addr_audit_entry_legacy {
            logon_id: 7,
            process_id: 2000,
            is_admin: 0,
            destination_ipv4: 0xAABB_CCDD,
            destination_port: 53,
        };

        let audit = legacy.to_audit_entry();
        assert_eq!(audit.logon_id, 7);
        assert_eq!(audit.process_id, 2000);
        assert_eq!(audit.is_admin, 0);
        assert_eq!(audit.destination_ipv4, 0xAABB_CCDD);
        assert_eq!(audit.destination_port, 53);
    }
}
