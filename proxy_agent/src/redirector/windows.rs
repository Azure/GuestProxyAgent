// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

mod bpf_api;
mod bpf_obj;
mod bpf_prog;

use crate::common::error::{BpfErrorType, Error, WindowsApiErrorType};
use crate::common::{constants, logger, result::Result};
use crate::redirector::shared_ebpf::{sock_addr_audit_entry, sock_addr_audit_key, AUDIT_MAP_NAME};
use crate::redirector::AuditEntry;
use crate::shared_state::redirector_wrapper::RedirectorSharedState;
use std::ffi::c_void;
use std::net::SocketAddr;
use std::ptr;
use windows_sys::Win32::Networking::WinSock;

/// Wrapper for eBPF object and link
/// This struct holds a pointer to the eBPF object and its associated links.
/// Start from ebpf-for-windows v1.0.0-rc, eBPF programs need to keep the link alive
/// to ensure the eBPF program remains attached.
pub struct BpfObject(
    pub *mut bpf_obj::bpf_object,
    pub Vec<*mut bpf_obj::ebpf_link_t>,
    super::EventTaskRuntime,
);
// Safety: bpf_object, which is a reference to an eBPF object, has no dependencies on thread-local storage and can
// safely be sent to another thread. This is not explicitly documented in the Windows eBPF library, but the library does
// document it aims to be source-compatible with libbpf[0]. Note that synchronization is required to share this object
// between threads, and care must be taken when using it as libbpf APIs make use of errno[1], which is thread-local.
//
// [0] https://github.com/microsoft/ebpf-for-windows/tree/Release-v0.17.1#2-does-this-provide-app-compatibility-with-ebpf-programs-written-for-linux
// [1] https://libbpf.readthedocs.io/en/v1.4.5/api.html#error-handling
unsafe impl Send for BpfObject {}

impl BpfObject {
    pub(crate) fn event_runtime_mut(&mut self) -> &mut super::EventTaskRuntime {
        &mut self.2
    }

    fn take_event_runtime(&mut self) -> super::EventTaskRuntime {
        std::mem::take(&mut self.2)
    }
}

impl Default for BpfObject {
    fn default() -> Self {
        Self::new()
    }
}

// Redirector implementation for Windows platform
impl super::Redirector {
    pub fn initialized(&self) -> Result<()> {
        // Add retry logic to load the eBPF API
        // This is a workaround for the issue where the eBPF API is not loaded properly
        for _ in 0..Self::MAX_RETRIES {
            if bpf_api::try_load_ebpf_api() {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(Self::RETRY_INTERVAL_MS));
        }

        // If the eBPF API is still not loaded, last retry and return error if it fails
        if !bpf_api::try_load_ebpf_api() {
            return Err(Error::Bpf(BpfErrorType::GetBpfApi));
        }
        Ok(())
    }

    pub fn load_bpf_object(&self) -> Result<BpfObject> {
        let mut bpf_file_path = super::get_ebpf_file_path();

        if let Some(ebpf_api_version) = bpf_api::get_ebpf_api_version() {
            // eBPF program has to work with the same version of eBPF API if windows eBPF had break changes
            // our latest eBPF program may not work with the older version of windows eBPF API
            // in some cases, the windows eBPF may not able, or be allowed to update,
            // so we need to load the eBPF program with the same version of eBPF API
            // the versioned eBPF program is named as <program_name>.<major>.<minor>.<extension>
            let file_ext = bpf_file_path.extension().unwrap_or_default();
            let file_name = bpf_file_path.file_stem().unwrap_or_default();
            let file_name = format!(
                "{}.{}.{}.{}",
                file_name.to_string_lossy(),
                ebpf_api_version.major,
                ebpf_api_version.minor,
                file_ext.to_string_lossy()
            );
            let file_path = bpf_file_path.with_file_name(file_name);
            let file_found: bool;
            if file_path.exists() && file_path.is_file() {
                bpf_file_path = file_path.to_path_buf();
                file_found = true;
            } else {
                file_found = false;
            }

            logger::write(format!(
                "eBPF API version: '{}' found, eBPF program file with api version: '{}'{}found.",
                ebpf_api_version,
                file_path.display(),
                if file_found { " " } else { " not " },
            ));
        }

        let mut bpf_object = BpfObject::new();
        bpf_object.load_bpf_object(&bpf_file_path)?;
        Ok(bpf_object)
    }

    pub fn attach_bpf_prog(&self, bpf_object: &mut BpfObject) -> Result<()> {
        bpf_object.attach_bpf_prog()
    }
}

pub async fn close_bpf_object(redirector_shared_state: RedirectorSharedState) -> Result<()> {
    let Some(bpf_object) = redirector_shared_state.take_bpf_object().await? else {
        return Ok(());
    };

    let event_runtime = {
        let mut bpf_object = bpf_object.lock().map_err(|e| {
            Error::Bpf(BpfErrorType::CloseBpfObject(format!(
                "BPF object lock is poisoned: {e}"
            )))
        })?;
        bpf_object.take_event_runtime()
    };
    let shutdown_result = event_runtime.shutdown().await;

    bpf_object
        .lock()
        .map_err(|e| {
            Error::Bpf(BpfErrorType::CloseBpfObject(format!(
                "BPF object lock is poisoned: {e}"
            )))
        })?
        .close_bpf_object();

    shutdown_result?;
    logger::write("Success closed bpf object.".to_string());
    Ok(())
}

pub fn get_audit_from_redirect_context(raw_socket_id: usize) -> Result<AuditEntry> {
    // We do not know the value size here, pass 0 to use its max_value_size
    let mut audit_value_entry = AuditValueEntry::empty(0);
    let mut redirect_context_returned: u32 = 0;
    let result = unsafe {
        WinSock::WSAIoctl(
            raw_socket_id,
            WinSock::SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT,
            ptr::null(),
            0,
            audit_value_entry.value_pointer_mut(),
            audit_value_entry.value_size(), // large enough for either layout
            &mut redirect_context_returned,
            ptr::null_mut(),
            None,
        )
    };

    if result != 0 {
        let wsa_error = unsafe { WinSock::WSAGetLastError() };
        return Err(Error::WindowsApi(WindowsApiErrorType::WSAIoctl(format!(
            "SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT failed: result={result}, WSAGetLastError={wsa_error}",
        ))));
    }

    // The value size returned by WSAIoctl is the actual size of the data returned in the buffer.
    audit_value_entry.set_value_size(redirect_context_returned)?;

    audit_value_entry.to_audit_entry()
}

pub async fn update_wire_server_redirect_policy(
    redirect: bool,
    redirector_shared_state: RedirectorSharedState,
) -> bool {
    if let Ok(Some(bpf_object)) = redirector_shared_state.get_bpf_object().await {
        if redirect {
            if let Ok(local_port) = redirector_shared_state.get_local_port().await {
                if let Err(e) = bpf_object.lock().unwrap().update_policy_elem_bpf_map(
                    "WireServer endpoints",
                    local_port,
                    constants::WIRE_SERVER_IP_NETWORK_BYTE_ORDER,
                    constants::WIRE_SERVER_PORT,
                ) {
                    logger::write_error(format!(
                        "Failed to update bpf map for wireserver redirect policy with result: {e}"
                    ));
                } else {
                    logger::write(
                        "Success updated bpf map for wireserver redirect policy.".to_string(),
                    );
                }
            }
        } else if let Err(e) = bpf_object.lock().unwrap().remove_policy_elem_bpf_map(
            constants::WIRE_SERVER_IP_NETWORK_BYTE_ORDER,
            constants::WIRE_SERVER_PORT,
        ) {
            logger::write_error(format!(
                "Failed to delete bpf map for wireserver redirect policy with result: {e}"
            ));
        } else {
            logger::write("Success deleted bpf map for wireserver redirect policy.".to_string());
        }
        true
    } else {
        false
    }
}

pub async fn update_imds_redirect_policy(
    redirect: bool,
    redirector_shared_state: RedirectorSharedState,
) -> bool {
    if let Ok(Some(bpf_object)) = redirector_shared_state.get_bpf_object().await {
        if redirect {
            if let Ok(local_port) = redirector_shared_state.get_local_port().await {
                if let Err(e) = bpf_object.lock().unwrap().update_policy_elem_bpf_map(
                    "IMDS endpoints",
                    local_port,
                    constants::IMDS_IP_NETWORK_BYTE_ORDER,
                    constants::IMDS_PORT,
                ) {
                    logger::write_error(format!(
                        "Failed to update bpf map for IMDS redirect policy with result: {e}"
                    ));
                } else {
                    logger::write("Success updated bpf map for IMDS redirect policy.".to_string());
                }
            }
        } else if let Err(e) = bpf_object
            .lock()
            .unwrap()
            .remove_policy_elem_bpf_map(constants::IMDS_IP_NETWORK_BYTE_ORDER, constants::IMDS_PORT)
        {
            logger::write_error(format!(
                "Failed to delete bpf map for IMDS redirect policy with result: {e}"
            ));
        } else {
            logger::write("Success deleted bpf map for IMDS redirect policy.".to_string());
        }
        true
    } else {
        false
    }
}

pub async fn update_hostga_redirect_policy(
    redirect: bool,
    redirector_shared_state: RedirectorSharedState,
) -> bool {
    if let Ok(Some(bpf_object)) = redirector_shared_state.get_bpf_object().await {
        if redirect {
            if let Ok(local_port) = redirector_shared_state.get_local_port().await {
                if let Err(e) = bpf_object.lock().unwrap().update_policy_elem_bpf_map(
                    "Host GAPlugin endpoints",
                    local_port,
                    constants::GA_PLUGIN_IP_NETWORK_BYTE_ORDER,
                    constants::GA_PLUGIN_PORT,
                ) {
                    logger::write_error(format!(
                        "Failed to update bpf map for HostGAPlugin redirect policy with result: {e}"
                    ));
                } else {
                    logger::write(
                        "Success updated bpf map for HostGAPlugin redirect policy.".to_string(),
                    );
                }
            }
        } else if let Err(e) = bpf_object.lock().unwrap().remove_policy_elem_bpf_map(
            constants::GA_PLUGIN_IP_NETWORK_BYTE_ORDER,
            constants::GA_PLUGIN_PORT,
        ) {
            logger::write_error(format!(
                "Failed to delete bpf map for HostGAPlugin redirect policy with result: {e}"
            ));
        } else {
            logger::write("Success deleted bpf map for HostGAPlugin redirect policy.".to_string());
        }

        true
    } else {
        false
    }
}

/// Original Windows audit key. Port-only keys cannot safely identify a peer.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct sock_addr_audit_key_legacy {
    pub protocol: u32,
    pub source_port: u32,
}

pub(crate) enum AuditKeyEntry {
    New(sock_addr_audit_key),
    Legacy(sock_addr_audit_key_legacy),
}

impl AuditKeyEntry {
    pub fn from_peer(peer: &SocketAddr, key_size: u32) -> Result<Self> {
        match key_size as usize {
            size if size == std::mem::size_of::<sock_addr_audit_key>() => {
                Ok(Self::New(sock_addr_audit_key::from_peer(peer)?))
            }
            size if size == std::mem::size_of::<sock_addr_audit_key_legacy>() => {
                let key = sock_addr_audit_key::from_peer(peer)?;
                Ok(Self::Legacy(sock_addr_audit_key_legacy {
                    protocol: key.protocol,
                    source_port: key.source_port,
                }))
            }
            _ => Err(Error::Bpf(BpfErrorType::GetBpfMap(
                AUDIT_MAP_NAME.to_string(),
                format!("Unsupported audit key size: {key_size}; expected 8 or 28 bytes"),
            ))),
        }
    }

    pub fn value_pointer(&self) -> *const c_void {
        match self {
            Self::New(key) => key as *const sock_addr_audit_key as *const c_void,
            Self::Legacy(key) => key as *const sock_addr_audit_key_legacy as *const c_void,
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
            address_family: crate::redirector::AddressFamily::IPv4,
            executable_device: 0,
            executable_inode: 0,
            executable_identity_valid: false,
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

    pub fn set_value_size(&mut self, value_size: u32) -> Result<()> {
        match self {
            AuditValueEntry::Unknown(entry) => {
                // check the value size is valid for the current entry types
                if value_size != Self::VALUE_SIZE_NEW && value_size != Self::VALUE_SIZE_LEGACY {
                    return Err(Error::Bpf(BpfErrorType::MapLookupElem(
                        "set_value_size".to_string(),
                        format!(
                            "Invalid audit value size: {}, expected: {} or {}",
                            value_size,
                            Self::VALUE_SIZE_NEW,
                            Self::VALUE_SIZE_LEGACY,
                        ),
                    )));
                }

                entry.read_size = value_size;
            }
            _ => {
                // No-op, value size is fixed for other known types.
            }
        }
        Ok(())
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
                                entry.buffer.as_ptr() as *const sock_addr_audit_entry
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
                                entry.buffer.as_ptr() as *const sock_addr_audit_entry_legacy
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

#[cfg(test)]
mod tests {
    use crate::redirector::shared_ebpf::{
        sock_addr_audit_entry, sock_addr_audit_key, GPA_ADDRESS_FAMILY_IPV6, IPPROTO_TCP,
    };
    use crate::redirector::windows::{
        sock_addr_audit_entry_legacy, sock_addr_audit_key_legacy, AuditKeyEntry, AuditValueEntry,
    };

    #[test]
    fn audit_key_legacy_layout_selection() {
        assert_eq!(std::mem::size_of::<sock_addr_audit_key_legacy>(), 8);
        let peer = "127.0.0.1:40000".parse().unwrap();
        let canonical = sock_addr_audit_key::from_peer(&peer).unwrap();
        let AuditKeyEntry::New(key) = AuditKeyEntry::from_peer(&peer, 28).unwrap() else {
            panic!("Expected canonical key");
        };
        assert_eq!(key.as_array(), canonical.as_array());
        let AuditKeyEntry::Legacy(key) = AuditKeyEntry::from_peer(&peer, 8).unwrap() else {
            panic!("Expected released legacy key");
        };
        assert_eq!(key.protocol, IPPROTO_TCP);
        assert_eq!(key.source_port, canonical.source_port);

        for size in [0, 4, 12, 16, 24, 32, u32::MAX] {
            assert!(AuditKeyEntry::from_peer(&peer, size).is_err());
        }
        assert!(AuditKeyEntry::from_peer(&"[::1]:40000".parse().unwrap(), 12).is_err());
        assert!(AuditKeyEntry::from_peer(&"[::1]:40000".parse().unwrap(), 28).is_ok());
    }

    #[test]
    fn audit_key_legacy_preserves_released_port_only_layout() {
        let key_bytes = |peer: &str| {
            let key = AuditKeyEntry::from_peer(&peer.parse().unwrap(), 8).unwrap();
            // The legacy variant owns an initialized 8-byte repr(C) key.
            unsafe { std::slice::from_raw_parts(key.value_pointer().cast::<u8>(), 8).to_vec() }
        };
        let key = key_bytes("127.0.0.1:40000");
        assert_eq!(&key[..4], &IPPROTO_TCP.to_ne_bytes());
        #[cfg(windows)]
        assert_eq!(&key[4..], &u32::from(40000u16.to_be()).to_ne_bytes());
        #[cfg(not(windows))]
        assert_eq!(&key[4..], &40000u32.to_ne_bytes());
        assert_eq!(key, key_bytes("[::ffff:127.0.0.1]:40000"));
        assert_eq!(key, key_bytes("127.0.0.2:40000"));
        assert_ne!(key, key_bytes("127.0.0.1:40001"));
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

    /// Copies the raw bytes of an audit value into an Unknown entry's buffer.
    fn fill_unknown_buffer<T>(entry: &mut AuditValueEntry, value: &T, size: u32) {
        if let AuditValueEntry::Unknown(unknown) = entry {
            let bytes = unsafe {
                std::slice::from_raw_parts(value as *const T as *const u8, size as usize)
            };
            unknown.buffer[..bytes.len()].copy_from_slice(bytes);
        } else {
            panic!("expected Unknown variant");
        }
    }

    #[test]
    fn audit_value_entry_empty_selects_expected_variant() {
        // Canonical size -> New.
        let new_entry = AuditValueEntry::empty(AuditValueEntry::VALUE_SIZE_NEW);
        assert!(matches!(new_entry, AuditValueEntry::New(_)));
        assert_eq!(new_entry.value_size(), AuditValueEntry::VALUE_SIZE_NEW);

        // Legacy size -> Legacy.
        let legacy_entry = AuditValueEntry::empty(AuditValueEntry::VALUE_SIZE_LEGACY);
        assert!(matches!(legacy_entry, AuditValueEntry::Legacy(_)));
        assert_eq!(
            legacy_entry.value_size(),
            AuditValueEntry::VALUE_SIZE_LEGACY
        );

        // Any other size -> Unknown, buffer allocated to the max value size.
        let odd_size = AuditValueEntry::VALUE_SIZE_NEW + 1;
        let unknown_entry = AuditValueEntry::empty(odd_size);
        let max_value_size = AuditValueEntry::max_value_size();
        match &unknown_entry {
            AuditValueEntry::Unknown(unknown) => {
                assert_eq!(unknown.buffer.len(), max_value_size as usize);
                assert_eq!(unknown.data_size, max_value_size);
                assert_eq!(unknown.read_size, odd_size);
            }
            _ => panic!("unexpected variant for unknown value size"),
        }
        // value_size() returns the allocated data_size for unknown entries.
        assert_eq!(unknown_entry.value_size(), max_value_size);

        // value_pointer_mut() is non-null for every variant.
        let mut new_entry = new_entry;
        let mut legacy_entry = legacy_entry;
        let mut unknown_entry = unknown_entry;
        assert!(!new_entry.value_pointer_mut().is_null());
        assert!(!legacy_entry.value_pointer_mut().is_null());
        assert!(!unknown_entry.value_pointer_mut().is_null());
    }

    #[test]
    fn audit_value_entry_set_value_size() {
        // Valid size updates read_size for Unknown entries.
        let mut unknown = AuditValueEntry::empty(AuditValueEntry::VALUE_SIZE_NEW + 1);
        unknown
            .set_value_size(AuditValueEntry::VALUE_SIZE_LEGACY)
            .expect("valid value size should be accepted");
        match &unknown {
            AuditValueEntry::Unknown(entry) => {
                assert_eq!(entry.read_size, AuditValueEntry::VALUE_SIZE_LEGACY);
            }
            _ => panic!("expected Unknown variant"),
        }

        // Invalid size is rejected for Unknown entries.
        let mut unknown = AuditValueEntry::empty(AuditValueEntry::VALUE_SIZE_NEW + 1);
        assert!(
            unknown
                .set_value_size(AuditValueEntry::VALUE_SIZE_NEW + 1)
                .is_err(),
            "an invalid value size should be rejected for unknown entries"
        );

        // Any size is a no-op (and never errors) for known variants.
        let mut known = AuditValueEntry::empty(AuditValueEntry::VALUE_SIZE_NEW);
        known
            .set_value_size(AuditValueEntry::VALUE_SIZE_NEW + 1)
            .expect("set_value_size should be a no-op for known variants");
        assert!(matches!(known, AuditValueEntry::New(_)));
        assert_eq!(known.value_size(), AuditValueEntry::VALUE_SIZE_NEW);
    }

    #[test]
    fn audit_value_entry_to_audit_entry() {
        // New variant converts directly.
        let new_entry = AuditValueEntry::New(sock_addr_audit_entry {
            logon_id: 11,
            process_id: 22,
            is_root: 1,
            destination_ipv4: 0x0A00_0001,
            destination_port: u32::from(443u16.to_be()),
            address_family: GPA_ADDRESS_FAMILY_IPV6,
            reserved: 0,
        });
        let audit = new_entry.to_audit_entry().expect("New should convert");
        assert_eq!(audit.logon_id, 11);
        assert_eq!(audit.process_id, 22);
        assert_eq!(audit.is_admin, 1);
        assert_eq!(audit.destination_ipv4, 0x0A00_0001);
        assert_eq!(audit.destination_port, 443u16.to_be());
        assert_eq!(audit.address_family, crate::redirector::AddressFamily::IPv6);

        // Legacy variant converts directly.
        let legacy_entry = AuditValueEntry::Legacy(sock_addr_audit_entry_legacy {
            logon_id: 99,
            process_id: 100,
            is_admin: 1,
            destination_ipv4: 0x0102_0304,
            destination_port: 8080,
        });
        let audit = legacy_entry
            .to_audit_entry()
            .expect("Legacy should convert");
        assert_eq!(audit.logon_id, 99);
        assert_eq!(audit.process_id, 100);
        assert_eq!(audit.is_admin, 1);
        assert_eq!(audit.destination_ipv4, 0x0102_0304);
        assert_eq!(audit.destination_port, 8080);

        // Unknown variant decodes a canonical (New) layout from raw bytes.
        let canonical = sock_addr_audit_entry {
            logon_id: 5,
            process_id: 6,
            is_root: 1,
            destination_ipv4: 0x0808_0808,
            destination_port: u32::from(53u16.to_be()),
            address_family: GPA_ADDRESS_FAMILY_IPV6,
            reserved: 0,
        };
        let mut unknown_new = AuditValueEntry::empty(AuditValueEntry::VALUE_SIZE_NEW + 1);
        fill_unknown_buffer(
            &mut unknown_new,
            &canonical,
            AuditValueEntry::VALUE_SIZE_NEW,
        );
        unknown_new
            .set_value_size(AuditValueEntry::VALUE_SIZE_NEW)
            .expect("value size should be valid");
        let audit = unknown_new
            .to_audit_entry()
            .expect("unknown New should decode");
        assert_eq!(audit.logon_id, 5);
        assert_eq!(audit.process_id, 6);
        assert_eq!(audit.is_admin, 1);
        assert_eq!(audit.destination_ipv4, 0x0808_0808);
        assert_eq!(audit.destination_port, 53u16.to_be());
        assert_eq!(audit.address_family, crate::redirector::AddressFamily::IPv6);

        // Unknown variant decodes a legacy layout from raw bytes.
        let legacy = sock_addr_audit_entry_legacy {
            logon_id: 77,
            process_id: 88,
            is_admin: 0,
            destination_ipv4: 0xDEAD_BEEF,
            destination_port: 22,
        };
        let mut unknown_legacy = AuditValueEntry::empty(AuditValueEntry::VALUE_SIZE_NEW + 1);
        fill_unknown_buffer(
            &mut unknown_legacy,
            &legacy,
            AuditValueEntry::VALUE_SIZE_LEGACY,
        );
        unknown_legacy
            .set_value_size(AuditValueEntry::VALUE_SIZE_LEGACY)
            .expect("value size should be valid");
        let audit = unknown_legacy
            .to_audit_entry()
            .expect("unknown Legacy should decode");
        assert_eq!(audit.logon_id, 77);
        assert_eq!(audit.process_id, 88);
        assert_eq!(audit.is_admin, 0);
        assert_eq!(audit.destination_ipv4, 0xDEAD_BEEF);
        assert_eq!(audit.destination_port, 22);

        // Unknown variant with an invalid read_size fails to decode.
        let invalid = AuditValueEntry::empty(AuditValueEntry::VALUE_SIZE_NEW + 1);
        assert!(
            invalid.to_audit_entry().is_err(),
            "decoding an unknown entry with an invalid read_size should fail"
        );
    }
}
