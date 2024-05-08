// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
#![allow(non_camel_case_types)]

use std::ffi::c_char;

pub type ebpf_id_t = u32;
pub type fd_t = i32;
pub type ebpf_handle_t = i64;
pub type ebpf_program_type_t = uuid::Uuid;
pub type ebpf_attach_type_t = uuid::Uuid;

// Type aliases used by libbpf headers.
pub type __s32 = i32;
pub type __s64 = i64;
pub type __be16 = u64;
pub type __u16 = u16;
pub type __be32 = u32;
pub type __u32 = u32;
pub type __wsum = u32;
pub type __u64 = u64;

#[allow(dead_code)]
#[repr(C)]
pub enum ebpf_map_type_t {
    BPF_MAP_TYPE_UNSPEC = 0,
    ///< Unspecified map type.
    BPF_MAP_TYPE_HASH = 1,
    ///< Hash table.
    BPF_MAP_TYPE_ARRAY = 2,
    ///< Array, where the map key is the array index.
    BPF_MAP_TYPE_PROG_ARRAY = 3,
    ///< Array of program fds usable with bpf_tail_call, where the map key is the array index.
    BPF_MAP_TYPE_PERCPU_HASH = 4, //< Per-CPU hash table.
    BPF_MAP_TYPE_PERCPU_ARRAY = 5,     //< Per-CPU array.
    BPF_MAP_TYPE_HASH_OF_MAPS = 6,     //< Hash table, where the map value is another map.
    BPF_MAP_TYPE_ARRAY_OF_MAPS = 7,    //< Array, where the map value is another map.
    BPF_MAP_TYPE_LRU_HASH = 8,         //< Least-recently-used hash table.
    BPF_MAP_TYPE_LPM_TRIE = 9,         //< Longest prefix match trie.
    BPF_MAP_TYPE_QUEUE = 10,           //< Queue.
    BPF_MAP_TYPE_LRU_PERCPU_HASH = 11, //< Per-CPU least-recently-used hash table.
    BPF_MAP_TYPE_STACK = 12,           //< Stack.
    BPF_MAP_TYPE_RINGBUF = 13,         //< Ring buffer map type.
}

#[allow(dead_code)]
#[repr(C)]
pub enum ebpf_pin_type_t {
    PIN_NONE,      //< Object is not pinned.
    PIN_OBJECT_NS, //< Pinning that is local to an object.
    PIN_GLOBAL_NS, //< Pinning with a global namespace.
    PIN_CUSTOM_NS, //< Pinning with a custom path given as section parameter.
}

#[allow(dead_code)]
#[repr(C)]
pub enum ebpf_execution_type_t {
    EBPF_EXECUTION_ANY, //< Execute in JIT-compiled or interpreted mode, per system policy.
    EBPF_EXECUTION_JIT, //< Execute in JIT-compiled mode.
    EBPF_EXECUTION_INTERPRET, //< Execute in interpreted mode.
    EBPF_EXECUTION_NATIVE, //< Execute from native driver.
}

#[allow(dead_code)]
#[repr(C)]
pub enum bpf_attach_type {
    BPF_ATTACH_TYPE_UNSPEC, //< Unspecified attach type.

    /** @brief Attach type for handling incoming packets as early as possible.
     *
     * **Program type:** \ref BPF_PROG_TYPE_XDP
     */
    BPF_XDP,

    /** @brief Attach type for handling socket bind() requests.
     *
     * **Program type:** \ref BPF_PROG_TYPE_BIND
     */
    BPF_ATTACH_TYPE_BIND,

    /** @brief Attach type for handling IPv4 TCP connect() or UDP send
     * to a unique remote address/port tuple.
     *
     * **Program type:** \ref BPF_PROG_TYPE_CGROUP_SOCK_ADDR
     */
    BPF_CGROUP_INET4_CONNECT,

    /** @brief Attach type for handling IPv6 TCP connect() or UDP send
     * to a unique remote address/port tuple.
     *
     * **Program type:** \ref BPF_PROG_TYPE_CGROUP_SOCK_ADDR
     */
    BPF_CGROUP_INET6_CONNECT,

    /** @brief Attach type for handling IPv4 TCP accept() or on receiving
     * the first unicast UDP packet from a unique remote address/port tuple.
     *
     * **Program type:** \ref BPF_PROG_TYPE_CGROUP_SOCK_ADDR
     */
    BPF_CGROUP_INET4_RECV_ACCEPT,

    /** @brief Attach type for handling IPv6 TCP accept() or on receiving
     * the first unicast UDP packet from a unique remote address/port tuple.
     *
     * **Program type:** \ref BPF_PROG_TYPE_CGROUP_SOCK_ADDR
     */
    BPF_CGROUP_INET6_RECV_ACCEPT,

    /** @brief Attach type for handling various socket event notifications.
     *
     * **Program type:** \ref BPF_PROG_TYPE_SOCK_OPS
     */
    BPF_CGROUP_SOCK_OPS,

    /** @brief Attach type implemented by eBPF Sample Extension driver, used for testing.
     *
     * **Program type:** \ref BPF_PROG_TYPE_SAMPLE
     */
    BPF_ATTACH_TYPE_SAMPLE,

    __MAX_BPF_ATTACH_TYPE,
}

// ebpf instruction schema
#[repr(C)]
pub struct ebpf_inst {
    opcode: u8,
    dst: u8, //< Destination register
    src: u8, //< Source register
    offset: i16,
    imm: i32, //< Immediate constant
}

#[repr(C)]
pub struct ebpf_program_t {
    object: *mut bpf_object,
    section_name: *mut c_char,
    program_name: *mut c_char,
    instructions: *mut ebpf_inst,
    instruction_count: usize,
    program_type: ebpf_program_type_t,
    attach_type: ebpf_attach_type_t,
    handle: ebpf_handle_t,
    fd: fd_t,
    pinned: bool,
    log_buffer: *mut c_char,
    log_buffer_size: u32,
}

/**
* @brief eBPF Map Definition as it is stored in memory.
*/
#[repr(C)]
pub struct _ebpf_map_definition_in_memory {
    map_type: ebpf_map_type_t, //< Type of map.
    key_size: u32,             //< Size in bytes of a map key.
    value_size: u32,           //< Size in bytes of a map value.
    max_entries: u32,          //< Maximum number of entries allowed in the map.
    inner_map_id: ebpf_id_t,
    pinning: ebpf_pin_type_t,
}
pub type ebpf_map_definition_in_memory_t = _ebpf_map_definition_in_memory;

#[repr(C)]
pub struct bpf_map {
    object: *mut bpf_object, //< Pointer to the object containing this map.
    name: *mut c_char,       //< Name of the map. ;

    // Map handle generated by the execution context.
    map_handle: ebpf_handle_t,

    // Map ID generated by the execution context.
    map_id: ebpf_id_t,

    // File descriptor specific to the caller's process.
    map_fd: fd_t,

    // Original fd as it appears in the eBPF byte code
    // before relocation.
    original_fd: fd_t,

    // Original fd of the inner_map.
    inner_map_original_fd: fd_t,

    inner_map: *mut bpf_map,
    map_definition: ebpf_map_definition_in_memory_t,
    pin_path: *mut c_char,
    pinned: bool,
    // Whether this map is newly created or reused
    // from an existing map.
    reused: bool,
}
pub type ebpf_map_t = bpf_map;

#[repr(C)]
pub struct bpf_object {
    object_name: *mut c_char,
    file_name: *mut c_char,
    programs: std::vec::Vec<*mut ebpf_program_t>,
    maps: std::vec::Vec<*mut ebpf_map_t>,
    loaded: bool,
    execution_type: ebpf_execution_type_t,
}

#[repr(C)]
pub struct _sock_addr_aduit_key {
    pub protocol: u32,
    pub source_port: [u16; 2],
}
pub type sock_addr_aduit_key_t = _sock_addr_aduit_key;
impl sock_addr_aduit_key_t {
    pub fn from_source_port(port: u16) -> Self {
        sock_addr_aduit_key_t {
            protocol: IPPROTO_TCP,
            source_port: [port.to_be(), 0],
        }
    }
}

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
pub type ip_address_t = _ip_address;

#[repr(C)]
pub struct _destination_entry {
    pub destination_ip: ip_address_t,
    pub destination_port: [u16; 2], // first element is the port number, second element is empty
    pub protocol: u32,
}
impl _destination_entry {
    pub fn empty() -> Self {
        _destination_entry {
            destination_ip: ip_address_t::empty(),
            destination_port: [0, 0],
            protocol: IPPROTO_TCP,
        }
    }

    pub fn from_ipv4(ipv4: u32, port: u16) -> Self {
        let mut entry = Self::empty();
        entry.destination_ip = ip_address_t::from_ipv4(ipv4);
        entry.destination_port[0] = port.to_be();
        entry
    }
}

pub type destination_entry_t = _destination_entry;
pub const IPPROTO_TCP: u32 = 6;
#[allow(dead_code)]
pub const IPPROTO_UDP: u32 = 17;

#[repr(C)]
pub struct _sock_addr_skip_process_entry {
    pub pid: u32,
}
pub type sock_addr_skip_process_entry = _sock_addr_skip_process_entry;
