// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#![allow(non_camel_case_types)]
#![allow(dead_code)]

use crate::common::{
    error::{BpfErrorType, Error},
    result::Result,
};
use std::net::{IpAddr, SocketAddr};

#[repr(C)]
#[derive(Debug, Clone, Copy)]
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

    pub fn as_array(&self) -> [u32; 6] {
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
pub const GPA_ADDRESS_FAMILY_IPV4: u32 = 4;
pub const GPA_ADDRESS_FAMILY_IPV6: u32 = 6;
pub const GPA_CONFIG_LOCAL_IP_BIND_MONITOR_ONLY: u32 = 0;

pub const AUDIT_MAP_NAME: &str = "audit_map";
pub const POLICY_MAP_NAME: &str = "policy_map";
pub const SKIP_PROCESS_MAP_NAME: &str = "skip_process_map";
pub const CONFIG_MAP_NAME: &str = "config_map";
pub const ALERT_ONLY_MAP_NAME: &str = "alert_only_map";

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

    pub fn as_array(&self) -> [u32; 1] {
        [self.pid]
    }
}
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct alert_only_event {
    pub kernel_timestamp_ns: u64,
    pub local_ip_address: [u32; 4],
    pub audit_entry: sock_addr_audit_entry,
}
impl alert_only_event {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != std::mem::size_of::<Self>() {
            return Err(Error::Bpf(BpfErrorType::MapLookupElem(
                ALERT_ONLY_MAP_NAME.to_string(),
                format!(
                    "Invalid ring-buffer record size for alert_only_event: {}, expected {}",
                    bytes.len(),
                    std::mem::size_of::<Self>()
                ),
            )));
        }
        Ok(unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const Self) })
    }

    pub fn to_audit_entry(self) -> crate::redirector::AuditEntry {
        self.audit_entry.to_audit_entry()
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct sock_addr_audit_key {
    pub protocol: u32,
    pub source_port: u32,
    pub source_address_family: u32,
    pub source_ip: ip_address,
}
pub type AuditMapKey =
    [u32; std::mem::size_of::<sock_addr_audit_key>() / std::mem::size_of::<u32>()];
#[allow(dead_code)]
impl sock_addr_audit_key {
    pub fn from_peer(peer: &SocketAddr) -> Result<Self> {
        let (source_address_family, source_ip) = match peer.ip().to_canonical() {
            IpAddr::V4(ip) => (
                GPA_ADDRESS_FAMILY_IPV4,
                ip_address::from_ipv4(u32::from_ne_bytes(ip.octets())),
            ),
            IpAddr::V6(ip) => {
                let octets = ip.octets();
                let words = std::array::from_fn(|i| {
                    let offset = i * 4;
                    u32::from_ne_bytes([
                        octets[offset],
                        octets[offset + 1],
                        octets[offset + 2],
                        octets[offset + 3],
                    ])
                });
                (GPA_ADDRESS_FAMILY_IPV6, ip_address::from_ipv6(words))
            }
        };
        #[cfg(windows)]
        let source_port = u32::from(peer.port().to_be());
        #[cfg(not(windows))]
        let source_port = u32::from(peer.port());
        Ok(sock_addr_audit_key {
            protocol: IPPROTO_TCP,
            source_port,
            source_address_family,
            source_ip,
        })
    }

    pub fn as_array(&self) -> AuditMapKey {
        [
            self.protocol,
            self.source_port,
            self.source_address_family,
            self.source_ip.ip[0],
            self.source_ip.ip[1],
            self.source_ip.ip[2],
            self.source_ip.ip[3],
        ]
    }

    pub fn from_array(array: AuditMapKey) -> Self {
        sock_addr_audit_key {
            protocol: array[0],
            source_port: array[1],
            source_address_family: array[2],
            source_ip: ip_address {
                ip: [array[3], array[4], array[5], array[6]],
            },
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct sock_addr_audit_entry {
    pub logon_id: u32,
    pub process_id: u32,
    pub is_root: u32,
    pub destination_ipv4: u32,
    pub destination_port: u32,
    pub address_family: u32,
    pub reserved: u32,
}
pub type AuditMapValue =
    [u32; std::mem::size_of::<sock_addr_audit_entry>() / std::mem::size_of::<u32>()];
impl sock_addr_audit_entry {
    pub fn empty() -> Self {
        sock_addr_audit_entry {
            logon_id: 0,
            process_id: 0,
            is_root: 0,
            destination_ipv4: 0,
            destination_port: 0,
            address_family: GPA_ADDRESS_FAMILY_IPV4,
            reserved: 0,
        }
    }

    pub fn from_array(array: AuditMapValue) -> Self {
        sock_addr_audit_entry {
            logon_id: array[0],
            process_id: array[1],
            is_root: array[2],
            destination_ipv4: array[3],
            destination_port: array[4],
            address_family: array[5],
            reserved: array[6],
        }
    }

    #[allow(dead_code)]
    pub fn as_array(&self) -> AuditMapValue {
        [
            self.logon_id,
            self.process_id,
            self.is_root,
            self.destination_ipv4,
            self.destination_port,
            self.address_family,
            self.reserved,
        ]
    }

    pub fn to_audit_entry(self) -> crate::redirector::AuditEntry {
        crate::redirector::AuditEntry {
            logon_id: u64::from(self.logon_id),
            process_id: self.process_id,
            is_admin: self.is_root as i32,
            destination_ipv4: self.destination_ipv4,
            destination_port: self.destination_port as u16,
            address_family: if self.address_family == GPA_ADDRESS_FAMILY_IPV6 {
                crate::redirector::AddressFamily::IPv6
            } else {
                crate::redirector::AddressFamily::IPv4
            },
            executable_device: 0,
            executable_inode: 0,
            executable_identity_valid: false,
        }
    }
}

#[cfg(not(windows))]
pub mod linux_types {
    pub use super::{
        alert_only_event, destination_entry, sock_addr_audit_entry, sock_addr_audit_key,
        sock_addr_skip_process_entry, AuditMapKey, ALERT_ONLY_MAP_NAME, AUDIT_MAP_NAME,
        CONFIG_MAP_NAME, GPA_CONFIG_LOCAL_IP_BIND_MONITOR_ONLY, POLICY_MAP_NAME,
        SKIP_PROCESS_MAP_NAME,
    };
}

#[cfg(windows)]
pub mod windows_types {
    pub use super::{
        alert_only_event, destination_entry as destination_entry_t, sock_addr_skip_process_entry,
        ALERT_ONLY_MAP_NAME, AUDIT_MAP_NAME, CONFIG_MAP_NAME,
        GPA_CONFIG_LOCAL_IP_BIND_MONITOR_ONLY, POLICY_MAP_NAME, SKIP_PROCESS_MAP_NAME,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destination_entry_ipv4_roundtrip_array_shape() {
        let entry = destination_entry::from_ipv4(0x1081_3FA8, 80);
        let array = entry.as_array();

        assert_eq!(
            array[0], 0x1081_3FA8,
            "destination ipv4 should be in slot 0"
        );
        assert_eq!(
            array[4],
            u32::from(80u16.to_be()),
            "port should be network byte order"
        );
        assert_eq!(array[5], IPPROTO_TCP, "protocol should be TCP by default");
    }

    #[test]
    fn audit_key_array_roundtrip() {
        let key = sock_addr_audit_key::from_peer(&"127.0.0.1:1234".parse().unwrap()).unwrap();
        let array = key.as_array();
        let rebuilt = sock_addr_audit_key::from_array(array);

        assert_eq!(rebuilt.protocol, IPPROTO_TCP, "protocol mismatch");
        assert_eq!(std::mem::size_of::<sock_addr_audit_key>(), 28);
        assert_eq!(rebuilt.source_address_family, GPA_ADDRESS_FAMILY_IPV4);
        assert_eq!(rebuilt.source_ip.ip[0].to_ne_bytes(), [127, 0, 0, 1]);
        assert_eq!(&rebuilt.source_ip.ip[1..], &[0; 3]);
        assert_eq!(rebuilt.as_array(), array);

        #[cfg(windows)]
        assert_eq!(
            rebuilt.source_port,
            u32::from(1234u16.to_be()),
            "source_port mismatch"
        );

        #[cfg(not(windows))]
        assert_eq!(rebuilt.source_port, 1234u32, "source_port mismatch");
    }

    #[test]
    fn audit_key_matches_only_the_redirected_peer() {
        let key = |peer: &str| {
            sock_addr_audit_key::from_peer(&peer.parse().unwrap())
                .unwrap()
                .as_array()
        };
        let victim = key("127.0.0.1:40000");
        let shadow = key("127.0.0.2:40000");
        let mapped = key("[::ffff:127.0.0.1]:40000");
        assert_ne!(victim, shadow);
        assert_ne!(victim, key("127.0.0.1:40001"));
        assert_eq!(victim, mapped);
        let mut udp = victim;
        udp[0] = IPPROTO_UDP;
        assert_ne!(victim, udp);

        let mut audit_map = std::collections::HashMap::from([(victim, 42)]);
        assert_eq!(audit_map.remove(&shadow), None);
        assert_eq!(audit_map.remove(&udp), None);
        assert_eq!(audit_map.remove(&mapped), Some(42));
        assert_eq!(audit_map.remove(&victim), None);
    }

    #[test]
    fn audit_key_native_ipv6_roundtrip() {
        let peer: SocketAddr = "[2001:db8:1234:5678:90ab:cdef:1122:3344]:40000"
            .parse()
            .unwrap();
        let key = sock_addr_audit_key::from_peer(&peer).unwrap();
        assert_eq!(key.source_address_family, GPA_ADDRESS_FAMILY_IPV6);
        let octets: Vec<u8> = key
            .source_ip
            .ip
            .iter()
            .flat_map(|word| word.to_ne_bytes())
            .collect();
        let IpAddr::V6(ip) = peer.ip() else {
            panic!("Expected IPv6 peer")
        };
        assert_eq!(octets, ip.octets());
        assert_eq!(
            sock_addr_audit_key::from_array(key.as_array()).as_array(),
            key.as_array()
        );

        for peer in [
            "[2001:db8:1234:5678:90ab:cdef:1122:3345]:40000",
            "[2001:db9:1234:5678:90ab:cdef:1122:3344]:40000",
            "[2001:db8:1234:5678:90ab:cdef:1122:3344]:40001",
        ] {
            assert_ne!(
                key.as_array(),
                sock_addr_audit_key::from_peer(&peer.parse().unwrap())
                    .unwrap()
                    .as_array()
            );
        }
        let ipv4 = sock_addr_audit_key::from_peer(&"127.0.0.1:40000".parse().unwrap()).unwrap();
        let ipv6 = sock_addr_audit_key::from_peer(&"[7f00:1::]:40000".parse().unwrap()).unwrap();
        assert_eq!(ipv4.source_ip.ip, ipv6.source_ip.ip);
        assert_ne!(ipv4.as_array(), ipv6.as_array());
    }

    #[test]
    fn skip_process_entry_pid_roundtrip() {
        let pid = 4321;
        let key = sock_addr_skip_process_entry::from_pid(pid);

        assert_eq!(
            key.as_array(),
            [pid],
            "pid should roundtrip through the map key layout"
        );
    }

    #[test]
    fn audit_entry_canonical_array_roundtrip() {
        let canonical = sock_addr_audit_entry {
            logon_id: 1,
            process_id: 2,
            is_root: 1,
            destination_ipv4: 4,
            destination_port: 5,
            address_family: GPA_ADDRESS_FAMILY_IPV6,
            reserved: 0,
        };

        let rebuilt = sock_addr_audit_entry::from_array(canonical.as_array());

        assert_eq!(rebuilt.logon_id, canonical.logon_id);
        assert_eq!(rebuilt.process_id, canonical.process_id);
        assert_eq!(rebuilt.is_root, canonical.is_root);
        assert_eq!(rebuilt.destination_ipv4, canonical.destination_ipv4);
        assert_eq!(rebuilt.destination_port, canonical.destination_port);
        assert_eq!(rebuilt.address_family, canonical.address_family);
    }

    #[test]
    fn audit_entry_canonical_to_agent_audit_entry() {
        let canonical = sock_addr_audit_entry {
            logon_id: 42,
            process_id: 1000,
            is_root: 1,
            destination_ipv4: 0x0102_0304,
            destination_port: u32::from(8080u16.to_be()),
            address_family: GPA_ADDRESS_FAMILY_IPV6,
            reserved: 0,
        };

        let audit = canonical.to_audit_entry();
        assert_eq!(audit.logon_id, 42);
        assert_eq!(audit.process_id, 1000);
        assert_eq!(audit.is_admin, 1);
        assert_eq!(audit.destination_ipv4, 0x0102_0304);
        assert_eq!(audit.destination_port, 8080u16.to_be());
        assert_eq!(audit.address_family, crate::redirector::AddressFamily::IPv6);
    }

    #[test]
    fn audit_only_event_binary_layout_and_decode() {
        let event = alert_only_event {
            kernel_timestamp_ns: 123,
            local_ip_address: [0x0A00_0001, 0, 0, 0],
            audit_entry: sock_addr_audit_entry {
                logon_id: 42,
                process_id: 1000,
                is_root: 1,
                destination_ipv4: 0x1081_3FA8,
                destination_port: u32::from(80u16.to_be()),
                address_family: GPA_ADDRESS_FAMILY_IPV4,
                reserved: 0,
            },
        };
        assert_eq!(std::mem::size_of::<alert_only_event>(), 56);

        let bytes = unsafe {
            std::slice::from_raw_parts(
                &event as *const alert_only_event as *const u8,
                std::mem::size_of::<alert_only_event>(),
            )
        };
        let decoded = alert_only_event::from_bytes(bytes).expect("record should decode");
        let audit = decoded.to_audit_entry();

        assert_eq!(decoded.kernel_timestamp_ns, 123);
        assert_eq!(decoded.local_ip_address[0], 0x0A00_0001);
        assert_eq!(audit.logon_id, 42);
        assert_eq!(audit.process_id, 1000);
        assert_eq!(audit.destination_port, 80u16.to_be());
        assert!(alert_only_event::from_bytes(&bytes[..bytes.len() - 1]).is_err());
    }
}
