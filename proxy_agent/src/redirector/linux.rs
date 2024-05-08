// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
mod ebpf_obj;
mod iptable_redirect;

use crate::common::{config, constants, helpers, logger};
use crate::provision;
use crate::redirector::AuditEntry;
use aya::maps::{HashMap, MapData};
use aya::programs::{CgroupSockAddr, KProbe};
use aya::{Bpf, BpfLoader, Btf};
use ebpf_obj::{
    destination_entry, sock_addr_aduit_key, sock_addr_audit_entry, sock_addr_skip_process_entry,
};
use once_cell::unsync::Lazy;
use proxy_agent_shared::misc_helpers;
use proxy_agent_shared::telemetry::event_logger;
use std::convert::TryFrom;
use std::path::PathBuf;

static mut IS_STARTED: bool = false;
static mut STATUS_MESSAGE: Lazy<String> =
    Lazy::new(|| String::from("Redirector has not started yet."));
static mut BPF_OBJECT: Option<Bpf> = None;

pub fn start(local_port: u16) -> bool {
    let mut bpf_file_path = misc_helpers::get_current_exe_dir();
    bpf_file_path.push(config::get_ebpf_program_name());

    let mut bpf = match open_ebpf_file(bpf_file_path) {
        Ok(value) => value,
        Err(value) => return value,
    };

    for (name, _map) in bpf.maps() {
        logger::write(format!("found map '{}'", name));
    }

    for (name, prog) in bpf.programs() {
        logger::write(format!(
            "found program '{}' with type '{:?}'",
            name,
            prog.prog_type()
        ));
    }

    // maps
    if update_skip_process_map(&mut bpf) == false {
        return false;
    }
    if update_policy_map(&mut bpf, local_port) == false {
        return false;
    }

    if attach_kprobe_program(&mut bpf) == false {
        return false;
    }

    // Try remove the iptable redirection rules before setup Cgroup redirection.
    iptable_redirect::cleanup_firewall_redirection(local_port);
    let mut iptable_redirect = false;
    let cgroup2_path = match proxy_agent_shared::linux::get_cgroup2_mount_path() {
        Ok(path) => {
            logger::write(format!(
                "Got cgroup2 mount path: '{}'",
                misc_helpers::path_to_string(path.to_path_buf())
            ));
            path
        }
        Err(e) => {
            event_logger::write_event(
                event_logger::WARN_LEVEL,
                format!("Failed to get the cgroup2 mpunt path {}, fallback to use the cgroup2 path from config file.", e),
                "start",
                "redirector/linux",
                logger::AGENT_LOGGER_KEY,
            );
            config::get_cgroup_root()
        }
    };
    if attach_cgroup_program(&mut bpf, cgroup2_path) == false {
        let message = "Failed to attach cgroup program for redirection.";
        event_logger::write_event(
            event_logger::WARN_LEVEL,
            message.to_string(),
            "start",
            "redirector/linux",
            logger::AGENT_LOGGER_KEY,
        );

        if config::get_fallback_with_iptable_redirect() == false {
            return false;
        }

        // setup firewall rules for redirection
        if iptable_redirect::setup_firewall_redirection(local_port) == false {
            return false;
        }
        iptable_redirect = true;
    }

    unsafe {
        BPF_OBJECT = Some(bpf);
        IS_STARTED = true;
    }

    let message;
    if iptable_redirect {
        message = helpers::write_startup_event(
            "Started Redirector with iptables redirection",
            "start",
            "redirector/linux",
            logger::AGENT_LOGGER_KEY,
        );
    } else {
        message = helpers::write_startup_event(
            "Started Redirector with cgroup redirection",
            "start",
            "redirector/linux",
            logger::AGENT_LOGGER_KEY,
        );
    }
    unsafe {
        *STATUS_MESSAGE = message.to_string();
    }
    provision::redirector_ready();

    return true;
}

fn open_ebpf_file(bpf_file_path: PathBuf) -> Result<Bpf, bool> {
    let bpf: Bpf;
    match BpfLoader::new()
        // load the BTF data from /sys/kernel/btf/vmlinux
        .btf(Btf::from_sys_fs().ok().as_ref())
        // finally load the code
        .load_file(bpf_file_path.to_path_buf())
    {
        Ok(b) => bpf = b,
        Err(err) => {
            set_error_status(format!(
                "Failed to load eBPF program from file {}: {}",
                misc_helpers::path_to_string(bpf_file_path.to_path_buf()),
                err
            ));
            return Err(false);
        }
    }
    Ok(bpf)
}

fn update_skip_process_map(bpf: &mut Bpf) -> bool {
    match bpf.map_mut("skip_process_map") {
        Some(map) => match HashMap::<&mut MapData, [u32; 1], [u32; 1]>::try_from(map) {
            Ok(mut skip_process_map) => {
                let pid = std::process::id();
                let key = sock_addr_skip_process_entry::from_pid(pid);
                let value = sock_addr_skip_process_entry::from_pid(pid);
                match skip_process_map.insert(key.to_array(), value.to_array(), 0) {
                    Ok(_) => logger::write(format!("skip_process_map updated with {}", pid)),
                    Err(err) => {
                        set_error_status(format!(
                            "Failed to insert pid {} to skip_process_map with error: {}",
                            pid, err
                        ));
                        return false;
                    }
                }
            }
            Err(err) => {
                set_error_status(format!(
                    "Failed to load HashMap 'skip_process_map' with error: {}",
                    err
                ));
                return false;
            }
        },
        None => {
            set_error_status("Failed to get map 'skip_process_map'.".to_string());
            return false;
        }
    }
    return true;
}

fn get_local_ip() -> Option<String> {
    let network_interfaces = match nix::ifaddrs::getifaddrs() {
        Ok(interfaces) => interfaces,
        Err(err) => {
            set_error_status(format!("Failed to get local ip with error: {}", err));
            return None;
        }
    };

    for nic in network_interfaces {
        if nic
            .flags
            .contains(nix::net::if_::InterfaceFlags::IFF_LOOPBACK)
        {
            continue;
        }
        if nic.flags.contains(nix::net::if_::InterfaceFlags::IFF_UP) == false {
            continue;
        }
        if nic
            .flags
            .contains(nix::net::if_::InterfaceFlags::IFF_RUNNING)
            == false
        {
            continue;
        }
        if nic
            .flags
            .contains(nix::net::if_::InterfaceFlags::IFF_BROADCAST)
            == false
        {
            continue;
        }
        // need to filter out the bridge interface
        let bridge_path = PathBuf::from("/sys/class/net/")
            .join(nic.interface_name.to_string())
            .join("bridge");
        if bridge_path.exists() {
            continue;
        }

        match nic.address {
            Some(addr) => {
                if let Some(socketAddr) = addr.as_sockaddr_in() {
                    return Some(socketAddr.ip().to_string());
                }
            }
            _ => {}
        }
    }

    return None;
}

fn update_policy_map(bpf: &mut Bpf, local_port: u16) -> bool {
    match bpf.map_mut("policy_map") {
        Some(map) => {
            match HashMap::<&mut MapData, [u32; 6], [u32; 6]>::try_from(map) {
                Ok(mut policy_map) => {
                    let local_ip = match get_local_ip() {
                        Some(ip) => ip,
                        None => constants::PROXY_AGENT_IP.to_string(),
                    };
                    event_logger::write_event(
                        event_logger::WARN_LEVEL,
                        format!(
                            "update_policy_map with local ip address: {}",
                            local_ip.to_string()
                        ),
                        "update_policy_map",
                        "redirector/linux",
                        logger::AGENT_LOGGER_KEY,
                    );
                    let local_ip = super::string_to_ip(&local_ip);
                    let key = destination_entry::from_ipv4(
                        constants::WIRE_SERVER_IP_NETWORK_BYTE_ORDER,
                        constants::WIRE_SERVER_PORT,
                    );
                    let value = destination_entry::from_ipv4(local_ip, local_port);
                    match policy_map.insert(key.to_array(), value.to_array(), 0) {
                        Ok(_) => {
                            logger::write("policy_map updated for WireServer endpoints".to_string())
                        }
                        Err(err) => {
                            set_error_status(format!("Failed to insert WireServer endpoints to policy_map with error: {}", err));
                            return false;
                        }
                    }

                    let key = destination_entry::from_ipv4(
                        constants::IMDS_IP_NETWORK_BYTE_ORDER,
                        constants::IMDS_PORT,
                    );
                    match policy_map.insert(key.to_array(), value.to_array(), 0) {
                        Ok(_) => logger::write("policy_map updated for IMDS endpoints".to_string()),
                        Err(err) => {
                            set_error_status(format!(
                                "Failed to insert IMDS endpoints to policy_map with error: {}",
                                err
                            ));
                            return false;
                        }
                    }

                    let key = destination_entry::from_ipv4(
                        constants::GA_PLUGIN_IP_NETWORK_BYTE_ORDER,
                        constants::GA_PLUGIN_PORT,
                    );
                    match policy_map.insert(key.to_array(), value.to_array(), 0) {
                        Ok(_) => logger::write(
                            "policy_map updated for HostGAPlugin endpoints".to_string(),
                        ),
                        Err(err) => {
                            set_error_status( format!(
                                "Failed to insert HostGAPlugin endpoints to policy_map with error: {}",
                                err
                            ));
                            return false;
                        }
                    }
                }
                Err(err) => {
                    set_error_status(format!(
                        "Failed to load HashMap 'policy_map' with error: {}",
                        err
                    ));
                    return false;
                }
            }
        }
        None => {
            set_error_status(format!("Failed to get map 'policy_map'."));
            return false;
        }
    }
    return true;
}

fn attach_cgroup_program(bpf: &mut Bpf, cgroup2_root_path: PathBuf) -> bool {
    match std::fs::File::open(cgroup2_root_path) {
        Ok(cgroup) => match bpf.program_mut("connect4") {
            Some(program) => match program.try_into() {
                Ok(p) => {
                    let program: &mut CgroupSockAddr = p;
                    match program.load() {
                        Ok(_) => logger::write("connect4 program loaded.".to_string()),
                        Err(err) => {
                            let message =
                                format!("Failed to load program 'connect4' with error: {}", err);
                            set_error_status(message.to_string());
                            return false;
                        }
                    }
                    match program.attach(cgroup) {
                        Ok(link_id) => {
                            logger::write(format!(
                                "connect4 program attached with id {:?}.",
                                link_id
                            ));
                        }
                        Err(err) => {
                            let message =
                                format!("Failed to attach program 'connect4' with error: {}", err);
                            set_error_status(message.to_string());
                            return false;
                        }
                    }
                }
                Err(err) => {
                    let message = format!(
                        "Failed to convert program to CgroupSockAddr with error: {}",
                        err
                    );
                    set_error_status(message.to_string());
                    return false;
                }
            },
            None => {
                let message = "Failed to get program 'connect4'";
                set_error_status(message.to_string());
                return false;
            }
        },
        Err(err) => {
            let message = format!("Failed to open cgroup with error: {}", err);
            set_error_status(message.to_string());
            return false;
        }
    }

    return true;
}

fn attach_kprobe_program(bpf: &mut Bpf) -> bool {
    match bpf.program_mut("tcp_v4_connect") {
        Some(program) => match program.try_into() {
            Ok(p) => {
                let program: &mut KProbe = p;
                match program.load() {
                    Ok(_) => logger::write("tcp_v4_connect program loaded.".to_string()),
                    Err(err) => {
                        set_error_status(format!(
                            "Failed to load program 'tcp_v4_connect' with error: {}",
                            err
                        ));
                        return false;
                    }
                }
                match program.attach("tcp_connect", 0) {
                    Ok(link_id) => {
                        logger::write(format!(
                            "tcp_v4_connect program attached with id {:?}.",
                            link_id
                        ));
                    }
                    Err(err) => {
                        set_error_status(format!(
                            "Failed to attach program 'tcp_v4_connect' with error: {}",
                            err
                        ));
                        return false;
                    }
                }
            }
            Err(err) => {
                set_error_status(format!(
                    "Failed to convert program to KProbe with error: {}",
                    err
                ));
                return false;
            }
        },
        None => {
            set_error_status("Failed to get program 'tcp_v4_connect'".to_string());
            return false;
        }
    }
    return true;
}

pub fn is_started() -> bool {
    unsafe { IS_STARTED }
}

fn set_error_status(message: String) {
    unsafe {
        *STATUS_MESSAGE = message.to_string();
    }

    event_logger::write_event(
        event_logger::ERROR_LEVEL,
        message,
        "start",
        "redirector/linux",
        logger::AGENT_LOGGER_KEY,
    );
}

pub fn get_status() -> String {
    unsafe { STATUS_MESSAGE.to_string() }
}

pub fn close(local_port: u16) {
    // remove the firewall rules for redirection if has
    iptable_redirect::cleanup_firewall_redirection(local_port);
    // reset ebpf object
    unsafe {
        BPF_OBJECT = None;
    }
}

pub fn lookup_audit(source_port: u16) -> std::io::Result<AuditEntry> {
    unsafe {
        match BPF_OBJECT {
            Some(ref bpf) => lookup_audit_internal(bpf, source_port),
            None => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "BPF object is not initialized",
            )),
        }
    }
}

fn lookup_audit_internal(bpf: &Bpf, source_port: u16) -> std::io::Result<AuditEntry> {
    match bpf.map("audit_map") {
        Some(map) => match HashMap::try_from(map) {
            Ok(audit_map) => {
                let key = sock_addr_aduit_key::from_source_port(source_port);
                match audit_map.get(&key.to_array(), 0) {
                    Ok(value) => {
                        let audit_value = sock_addr_audit_entry::from_array(value);
                        Ok(AuditEntry {
                            logon_id: audit_value.logon_id as u64,
                            process_id: audit_value.process_id,
                            is_admin: audit_value.is_root as i32,
                            destination_ipv4: audit_value.destination_ipv4,
                            destination_port: audit_value.destination_port as u16,
                        })
                    }
                    Err(err) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("Failed to lookup audit entry {}: {}", source_port, err),
                        ));
                    }
                }
            }
            Err(err) => {
                let message = format!("Failed to load HashMap 'audit_map' with error: {}", err);
                Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    message.to_string(),
                ))
            }
        },
        None => {
            let message = "Failed to get map 'audit_map'.";
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                message.to_string(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::common::config;
    use crate::common::logger;
    use crate::redirector::linux::ebpf_obj::sock_addr_aduit_key;
    use crate::redirector::linux::ebpf_obj::sock_addr_audit_entry;
    use aya::maps::HashMap;
    use proxy_agent_shared::logger_manager;
    use proxy_agent_shared::misc_helpers;
    use std::env;

    #[test]
    fn linux_ebpf_test() {
        let logger_key = "linux_ebpf_test";
        let mut temp_test_path = env::temp_dir();
        temp_test_path.push(logger_key);
        logger_manager::init_logger(
            logger::AGENT_LOGGER_KEY.to_string(), // production code uses 'Agent_Log' to write.
            temp_test_path.clone(),
            logger_key.to_string(),
            10 * 1024 * 1024,
            20,
        );

        let mut bpf_file_path = misc_helpers::get_current_exe_dir();
        bpf_file_path.push("config::get_ebpf_program_name()");
        let bpf = super::open_ebpf_file(bpf_file_path);
        assert!(!bpf.is_ok(), "open_ebpf_file should not return Ok");

        let mut bpf_file_path = misc_helpers::get_current_exe_dir();
        bpf_file_path.push(config::get_ebpf_program_name());
        let bpf = super::open_ebpf_file(bpf_file_path);
        match bpf {
            Ok(_) => {}
            Err(err) => {
                println!("open_ebpf_file error: {}", err);
                if std::fs::metadata("/.dockerenv").is_ok() {
                    println!("This docker image does not have BPF capacity, skip this test.");
                    return;
                } else {
                    assert!(false, "open_ebpf_file should not return Err");
                }
            }
        }
        assert!(bpf.is_ok(), "open_ebpf_file should return Ok");
        let mut bpf = bpf.unwrap();

        let result = super::update_skip_process_map(&mut bpf);
        assert!(result, "update_skip_process_map should return true");
        let result = super::update_policy_map(&mut bpf, 80);
        assert!(result, "update_policy_map should return true");

        // donot attach the program to real cgroup2 path
        // it should fail for both attach
        let result = super::attach_kprobe_program(&mut bpf);
        assert!(result, "attach_kprobe_program should return true");
        let result = super::attach_cgroup_program(&mut bpf, temp_test_path.clone());
        assert!(!result, "attach_connect4_program should not return true");

        let source_port = 1;
        let audit = super::lookup_audit_internal(&bpf, source_port);
        assert!(!audit.is_ok(), "lookup_audit should not return Ok");
        // insert to map an then look up
        let key = sock_addr_aduit_key::from_source_port(source_port);
        let value = sock_addr_audit_entry {
            logon_id: 999,
            process_id: 888,
            is_root: 1,
            destination_ipv4: 0x10813FA8,
            destination_port: 80,
        };
        {
            // drop map_mut("audit_map") within this scope
            let mut audit_map: HashMap<&mut aya::maps::MapData, [u32; 2], [u32; 5]> =
                HashMap::<&mut aya::maps::MapData, [u32; 2], [u32; 5]>::try_from(
                    bpf.map_mut("audit_map").unwrap(),
                )
                .unwrap();
            audit_map
                .insert(key.to_array(), value.to_array(), 0)
                .unwrap();
        }
        let audit = super::lookup_audit_internal(&bpf, source_port);
        match audit {
            Ok(entry) => {
                assert_eq!(
                    entry.logon_id as u32, value.logon_id,
                    "logon_id is not equal"
                );
                assert_eq!(
                    entry.process_id, value.process_id,
                    "process_id is not equal"
                );
                assert_eq!(entry.is_admin as u32, value.is_root, "is_root is not equal");
                assert_eq!(
                    entry.destination_ipv4, value.destination_ipv4,
                    "destination_ipv4 is not equal"
                );
                assert_eq!(
                    entry.destination_port as u32, value.destination_port,
                    "destination_port is not equal"
                );
            }
            Err(err) => {
                println!("lookup_audit_internal error: {}", err);
                assert!(false, "lookup_audit_internal should not return Err");
            }
        }
    }
}
