// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use super::shared_ebpf;

#[test]
fn destination_entry_ipv4_roundtrip_array_shape() {
    let entry = shared_ebpf::destination_entry::from_ipv4(0x1081_3FA8, 80);
    let array = entry.to_array();

    assert_eq!(array[0], 0x1081_3FA8, "destination ipv4 should be in slot 0");
    assert_eq!(array[4], u32::from(80u16.to_be()), "port should be network byte order");
    assert_eq!(array[5], shared_ebpf::IPPROTO_TCP, "protocol should be TCP by default");
}

#[test]
fn audit_key_array_roundtrip() {
    let key = shared_ebpf::sock_addr_audit_key::from_source_port(1234);
    let array = key.to_array();
    let rebuilt = shared_ebpf::sock_addr_audit_key::from_array(array);

    assert_eq!(rebuilt.protocol, shared_ebpf::IPPROTO_TCP, "protocol mismatch");

    #[cfg(windows)]
    assert_eq!(rebuilt.source_port, u32::from(1234u16.to_be()), "source_port mismatch");

    #[cfg(not(windows))]
    assert_eq!(rebuilt.source_port, 1234u32, "source_port mismatch");
}

#[test]
fn audit_entry_canonical_to_agent_audit_entry() {
    let canonical = shared_ebpf::sock_addr_audit_entry {
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
    let legacy = shared_ebpf::sock_addr_audit_entry_legacy {
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
