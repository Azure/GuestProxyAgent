// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#![allow(non_camel_case_types)]

#[repr(C)]
pub struct _ip_address {
    //pub ipv4: u32,
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
        for i in 0..4 {
            ip.ip[i] = ipv6[i];
        }
        ip
    }
}
pub type ip_address = _ip_address;

#[repr(C)]
pub struct _destination_entry {
    pub destination_ip: ip_address,
    pub destination_port: u32, // first element is the port number, second element is empty
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
        entry.destination_port = port.to_be() as u32;
        entry
    }

    pub fn to_array(&self) -> [u32; 6] {
        let mut array: [u32; 6] = [0; 6];
        for i in 0..4 {
            array[i] = self.destination_ip.ip[i];
        }
        array[4] = self.destination_port;
        array[5] = self.protocol;
        array
    }
}
pub type destination_entry = _destination_entry;
pub const IPPROTO_TCP: u32 = 6;

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
        let mut array: [u32; 1] = [0; 1];
        array[0] = self.pid;
        array
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct sock_addr_aduit_key {
    pub protocol: u32,
    pub source_port: u32,
}
#[allow(dead_code)]
impl sock_addr_aduit_key {
    pub fn from_source_port(port: u16) -> Self {
        sock_addr_aduit_key {
            protocol: IPPROTO_TCP,
            source_port: port as u32,
        }
    }

    pub fn to_array(&self) -> [u32; 2] {
        let mut array: [u32; 2] = [0; 2];
        array[0] = self.protocol;
        array[1] = self.source_port;
        array
    }

    pub fn from_array(array: [u32; 2]) -> Self {
        sock_addr_aduit_key {
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

#[allow(dead_code)]
impl sock_addr_audit_entry {
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
        let mut array: [u32; 5] = [0; 5];
        array[0] = self.logon_id;
        array[1] = self.process_id;
        array[2] = self.is_root;
        array[3] = self.destination_ipv4;
        array[4] = self.destination_port;
        array
    }
}

#[cfg(test)]
mod tests {
    use crate::common::constants;

    #[test]
    fn destination_entry_test() {
        let key = super::destination_entry::from_ipv4(
            constants::WIRE_SERVER_IP_NETWORK_BYTE_ORDER,
            constants::WIRE_SERVER_PORT,
        );

        let array = key.to_array();
        assert_eq!(
            array[0],
            constants::WIRE_SERVER_IP_NETWORK_BYTE_ORDER,
            "ip is not equal"
        );
        assert_eq!(
            array[4],
            constants::WIRE_SERVER_PORT.to_be() as u32,
            "port is not equal"
        );
    }

    #[test]
    fn sock_addr_skip_process_entry_test() {
        let pid = std::process::id();
        let key = super::sock_addr_skip_process_entry::from_pid(pid);
        let array = key.to_array();
        assert_eq!(array[0], pid, "pid is not equal");
    }

    #[test]
    fn sock_addr_aduit_key_test() {
        let source_port = 1234;
        let key = super::sock_addr_aduit_key::from_source_port(source_port);
        let array = key.to_array();
        assert_eq!(array[1], source_port as u32, "port is not equal");
        let key2 = super::sock_addr_aduit_key::from_array(array);
        assert_eq!(
            key2.source_port, source_port as u32,
            "port is not equal from_array"
        );
    }

    #[test]
    fn sock_addr_audit_entry_test() {
        let audit = super::sock_addr_audit_entry {
            logon_id: 1,
            process_id: 2,
            is_root: 1,
            destination_ipv4: 4,
            destination_port: 5,
        };
        let audit_value = super::sock_addr_audit_entry::from_array(audit.to_array());
        assert_eq!(
            audit_value.logon_id, audit.logon_id,
            "logon_id is not equal"
        );
        assert_eq!(
            audit_value.process_id, audit.process_id,
            "process_id is not equal"
        );
        assert_eq!(audit_value.is_root, audit.is_root, "is_root is not equal");
        assert_eq!(
            audit_value.destination_ipv4, audit.destination_ipv4,
            "destination_ipv4 is not equal"
        );
        assert_eq!(
            audit_value.destination_port, audit.destination_port,
            "destination_port is not equal"
        );
    }
}
