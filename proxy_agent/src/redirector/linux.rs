// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
mod ebpf_obj;

use crate::common::{
    config, constants,
    error::{BpfErrorType, Error},
    helpers, logger,
    result::Result,
};
use crate::provision;
use crate::redirector::{ip_to_string, AuditEntry};
use crate::shared_state::{redirector_wrapper, SharedState};
use aya::maps::{HashMap, MapData};
use aya::programs::{CgroupSockAddr, KProbe};
use aya::{Bpf, BpfLoader, Btf};
use ebpf_obj::{
    destination_entry, sock_addr_audit_entry, sock_addr_audit_key, sock_addr_skip_process_entry,
};
use proxy_agent_shared::misc_helpers;
use proxy_agent_shared::telemetry::event_logger;
use std::convert::TryFrom;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub struct BpfObject(Bpf);

pub fn start_internal(local_port: u16, shared_state: Arc<Mutex<SharedState>>) -> bool {
    let mut bpf_object = match BpfObject::from_ebpf_file(super::get_ebpf_file_path()) {
        Ok(value) => value,
        Err(e) => {
            set_error_status(format!("{}", e), shared_state.clone());
            return false;
        }
    };

    for (name, _map) in bpf_object.0.maps() {
        logger::write(format!("found map '{}'", name));
    }

    for (name, prog) in bpf_object.0.programs() {
        logger::write(format!(
            "found program '{}' with type '{:?}'",
            name,
            prog.prog_type()
        ));
    }

    // maps
    if let Err(e) = bpf_object.update_skip_process_map() {
        set_error_status(format!("{}", e), shared_state.clone());
        return false;
    }
    if let Err(e) = bpf_object.update_policy_map(local_port) {
        set_error_status(format!("{}", e), shared_state.clone());
        return false;
    }
    if let Err(e) = bpf_object.attach_kprobe_program() {
        set_error_status(format!("{}", e), shared_state.clone());
        return false;
    }

    let cgroup2_path = match proxy_agent_shared::linux::get_cgroup2_mount_path() {
        Ok(path) => {
            logger::write(format!(
                "Got cgroup2 mount path: '{}'",
                misc_helpers::path_to_string(&path)
            ));
            path
        }
        Err(e) => {
            event_logger::write_event(
                event_logger::WARN_LEVEL,
                format!("Failed to get the cgroup2 mount path {}, fallback to use the cgroup2 path from config file.", e),
                "start",
                "redirector/linux",
                logger::AGENT_LOGGER_KEY,
            );
            config::get_cgroup_root()
        }
    };
    if let Err(e) = bpf_object.attach_cgroup_program(cgroup2_path) {
        let message = format!("Failed to attach cgroup program for redirection. {}", e);
        set_error_status(message.to_string(), shared_state.clone());

        event_logger::write_event(
            event_logger::WARN_LEVEL,
            message.to_string(),
            "start",
            "redirector/linux",
            logger::AGENT_LOGGER_KEY,
        );
        return false;
    }

    redirector_wrapper::set_bpf_object(shared_state.clone(), bpf_object);
    redirector_wrapper::set_is_started(shared_state.clone(), true);
    redirector_wrapper::set_local_port(shared_state.clone(), local_port);

    let message = helpers::write_startup_event(
        "Started Redirector with cgroup redirection",
        "start",
        "redirector/linux",
        logger::AGENT_LOGGER_KEY,
    );
    redirector_wrapper::set_status_message(shared_state.clone(), message.to_string());
    provision::redirector_ready(shared_state);

    true
}

impl BpfObject {
    pub fn new(bpf: Bpf) -> Self {
        BpfObject(bpf)
    }

    pub fn get_bpf(&self) -> &Bpf {
        &self.0
    }

    pub fn from_ebpf_file(bpf_file_path: PathBuf) -> Result<BpfObject> {
        match BpfLoader::new()
            // load the BTF data from /sys/kernel/btf/vmlinux
            .btf(Btf::from_sys_fs().ok().as_ref())
            // finally load the code
            .load_file(&bpf_file_path)
        {
            Ok(bpf) => Ok(BpfObject::new(bpf)),
            Err(err) => Err(Error::general(format!(
                "Failed to load eBPF program from file {}: {}",
                misc_helpers::path_to_string(&bpf_file_path),
                err
            ))),
        }
    }

    pub fn update_skip_process_map(&mut self) -> Result<()> {
        match self.0.map_mut("skip_process_map") {
            Some(map) => match HashMap::<&mut MapData, [u32; 1], [u32; 1]>::try_from(map) {
                Ok(mut skip_process_map) => {
                    let pid = std::process::id();
                    let key = sock_addr_skip_process_entry::from_pid(pid);
                    let value = sock_addr_skip_process_entry::from_pid(pid);
                    match skip_process_map.insert(key.to_array(), value.to_array(), 0) {
                        Ok(_) => logger::write(format!("skip_process_map updated with {}", pid)),
                        Err(err) => {
                            return Err(Error::general(format!(
                                "Failed to insert pid {} to skip_process_map with error: {}",
                                pid, err
                            )));
                        }
                    }
                }
                Err(err) => {
                    return Err(Error::general(format!(
                        "Failed to load HashMap 'skip_process_map' with error: {}",
                        err
                    )));
                }
            },
            None => {
                return Err(Error::general(
                    "Failed to get map 'skip_process_map'.".to_string(),
                ));
            }
        }
        Ok(())
    }

    fn update_policy_map(&mut self, local_port: u16) -> Result<()> {
        match self.0.map_mut("policy_map") {
            Some(map) => match HashMap::<&mut MapData, [u32; 6], [u32; 6]>::try_from(map) {
                Ok(mut policy_map) => {
                    let local_ip = constants::PROXY_AGENT_IP.to_string();
                    event_logger::write_event(
                        event_logger::WARN_LEVEL,
                        format!("update_policy_map with local ip address: {}", local_ip),
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
                            return Err(Error::general(format!("Failed to insert WireServer endpoints to policy_map with error: {}", err)));
                        }
                    }

                    let key = destination_entry::from_ipv4(
                        constants::IMDS_IP_NETWORK_BYTE_ORDER,
                        constants::IMDS_PORT,
                    );
                    match policy_map.insert(key.to_array(), value.to_array(), 0) {
                        Ok(_) => logger::write("policy_map updated for IMDS endpoints".to_string()),
                        Err(err) => {
                            return Err(Error::general(format!(
                                "Failed to insert IMDS endpoints to policy_map with error: {}",
                                err
                            )));
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
                            return Err(Error::general( format!(
                                 "Failed to insert HostGAPlugin endpoints to policy_map with error: {}",
                                    err
                                )));
                        }
                    }
                }
                Err(err) => {
                    return Err(Error::general(format!(
                        "Failed to load HashMap 'policy_map' with error: {}",
                        err
                    )));
                }
            },
            None => {
                return Err(Error::general(
                    "Failed to get map 'policy_map'.".to_string(),
                ));
            }
        }
        Ok(())
    }

    pub fn attach_cgroup_program(&mut self, cgroup2_root_path: PathBuf) -> Result<()> {
        match std::fs::File::open(cgroup2_root_path) {
            Ok(cgroup) => match self.0.program_mut("connect4") {
                Some(program) => match program.try_into() {
                    Ok(p) => {
                        let program: &mut CgroupSockAddr = p;
                        match program.load() {
                            Ok(_) => logger::write("connect4 program loaded.".to_string()),
                            Err(err) => {
                                return Err(Error::general(format!(
                                    "Failed to load program 'connect4' with error: {}",
                                    err
                                )));
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
                                return Err(Error::general(format!(
                                    "Failed to attach program 'connect4' with error: {}",
                                    err
                                )));
                            }
                        }
                    }
                    Err(err) => {
                        return Err(Error::general(format!(
                            "Failed to convert program to CgroupSockAddr with error: {}",
                            err
                        )));
                    }
                },
                None => {
                    return Err(Error::general(
                        "Failed to get program 'connect4'".to_string(),
                    ));
                }
            },
            Err(err) => {
                return Err(Error::general(format!(
                    "Failed to open cgroup with error: {}",
                    err
                )));
            }
        }

        Ok(())
    }

    pub fn attach_kprobe_program(&mut self) -> Result<()> {
        match self.0.program_mut("tcp_v4_connect") {
            Some(program) => match program.try_into() {
                Ok(p) => {
                    let program: &mut KProbe = p;
                    match program.load() {
                        Ok(_) => logger::write("tcp_v4_connect program loaded.".to_string()),
                        Err(err) => {
                            return Err(Error::general(format!(
                                "Failed to load program 'tcp_v4_connect' with error: {}",
                                err
                            )));
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
                            return Err(Error::general(format!(
                                "Failed to attach program 'tcp_v4_connect' with error: {}",
                                err
                            )));
                        }
                    }
                }
                Err(err) => {
                    return Err(Error::general(format!(
                        "Failed to convert program to KProbe with error: {}",
                        err
                    )));
                }
            },
            None => {
                return Err(Error::general(
                    "Failed to get program 'tcp_v4_connect'".to_string(),
                ));
            }
        }
        Ok(())
    }

    pub fn lookup_audit(&self, source_port: u16) -> Result<AuditEntry> {
        match self.0.map("audit_map") {
            Some(map) => match HashMap::try_from(map) {
                Ok(audit_map) => {
                    let key = sock_addr_audit_key::from_source_port(source_port);
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
                        Err(err) => Err(Error::bpf(BpfErrorType::MapLookupElem(
                            source_port.to_string(),
                            err.to_string(),
                        ))),
                    }
                }
                Err(err) => Err(Error::bpf(BpfErrorType::LoadBpfMapHashMap(err.to_string()))),
            },
            None => Err(Error::bpf(BpfErrorType::GetBpfMap(
                "Map does not exist".to_string(),
            ))),
        }
    }

    pub fn update_redirect_policy(
        &mut self,
        dest_ipv4: u32,
        dest_port: u16,
        local_port: u16,
        redirect: bool,
    ) {
        match self.0.map_mut("policy_map") {
            Some(map) => match HashMap::<&mut MapData, [u32; 6], [u32; 6]>::try_from(map) {
                Ok(mut policy_map) => {
                    let key = destination_entry::from_ipv4(dest_ipv4, dest_port);
                    if !redirect {
                        match policy_map.remove(&key.to_array()) {
                            Ok(_) => {
                                event_logger::write_event(
                                    event_logger::INFO_LEVEL,
                                    format!(
                                        "policy_map removed for destination: {}:{}",
                                        ip_to_string(dest_ipv4),
                                        dest_port
                                    ),
                                    "update_redirect_policy_internal",
                                    "redirector/linux",
                                    logger::AGENT_LOGGER_KEY,
                                );
                            }
                            Err(err) => {
                                logger::write(format!("Failed to remove destination: {}:{} from policy_map with error: {}", ip_to_string(dest_ipv4), dest_port, err));
                            }
                        };
                    } else {
                        let local_ip = constants::PROXY_AGENT_IP.to_string();
                        event_logger::write_event(
                            event_logger::WARN_LEVEL,
                            format!(
                                "update_redirect_policy_internal with local ip address: {}, dest_ipv4: {}, dest_port: {}, local_port: {}",
                                local_ip, ip_to_string(dest_ipv4), dest_port, local_port
                            ),
                            "update_redirect_policy_internal",
                            "redirector/linux",
                            logger::AGENT_LOGGER_KEY,
                        );
                        let local_ip: u32 = super::string_to_ip(&local_ip);
                        let value = destination_entry::from_ipv4(local_ip, local_port);
                        match policy_map.insert(key.to_array(), value.to_array(), 0) {
                            Ok(_) => event_logger::write_event(
                                event_logger::INFO_LEVEL,
                                format!(
                                    "policy_map updated for destination: {}:{}",
                                    ip_to_string(dest_ipv4),
                                    dest_port
                                ),
                                "update_redirect_policy_internal",
                                "redirector/linux",
                                logger::AGENT_LOGGER_KEY,
                            ),
                            Err(err) => {
                                logger::write(format!("Failed to insert destination: {}:{} to policy_map with error: {}", ip_to_string(dest_ipv4), dest_port, err));
                            }
                        }
                    }
                }
                Err(err) => {
                    logger::write(format!(
                        "Failed to load HashMap 'policy_map' with error: {}",
                        err
                    ));
                }
            },
            None => {
                logger::write("Failed to get map 'policy_map'.".to_string());
            }
        }
    }
}

pub fn is_started(shared_state: Arc<Mutex<SharedState>>) -> bool {
    redirector_wrapper::get_is_started(shared_state)
}

fn set_error_status(message: String, shared_state: Arc<Mutex<SharedState>>) {
    redirector_wrapper::set_status_message(shared_state, message.to_string());
    event_logger::write_event(
        event_logger::ERROR_LEVEL,
        message,
        "start",
        "redirector/linux",
        logger::AGENT_LOGGER_KEY,
    );
}

pub fn get_status(shared_state: Arc<Mutex<SharedState>>) -> String {
    redirector_wrapper::get_status_message(shared_state)
}

pub fn close(shared_state: Arc<Mutex<SharedState>>) {
    // reset ebpf object
    redirector_wrapper::clear_bpf_object(shared_state);
}

pub fn lookup_audit(source_port: u16, shared_state: Arc<Mutex<SharedState>>) -> Result<AuditEntry> {
    match redirector_wrapper::get_bpf_object(shared_state.clone()) {
        Some(ref bpf) => bpf.lock().unwrap().lookup_audit(source_port),
        None => Err(Error::bpf(BpfErrorType::GetBpfObject)),
    }
}

pub fn update_wire_server_redirect_policy(redirect: bool, shared_state: Arc<Mutex<SharedState>>) {
    if let Some(bpf_object) = redirector_wrapper::get_bpf_object(shared_state.clone()) {
        let local_port = redirector_wrapper::get_local_port(shared_state.clone());
        bpf_object.lock().unwrap().update_redirect_policy(
            constants::WIRE_SERVER_IP_NETWORK_BYTE_ORDER,
            constants::WIRE_SERVER_PORT,
            local_port,
            redirect,
        );
    }
}

pub fn update_imds_redirect_policy(redirect: bool, shared_state: Arc<Mutex<SharedState>>) {
    if let Some(bpf_object) = redirector_wrapper::get_bpf_object(shared_state.clone()) {
        let local_port = redirector_wrapper::get_local_port(shared_state.clone());
        bpf_object.lock().unwrap().update_redirect_policy(
            constants::IMDS_IP_NETWORK_BYTE_ORDER,
            constants::IMDS_PORT,
            local_port,
            redirect,
        );
    }
}

#[cfg(test)]
#[cfg(feature = "test-with-root")]
mod tests {
    use crate::common::config;
    use crate::common::logger;
    use crate::redirector::linux::ebpf_obj::sock_addr_audit_entry;
    use crate::redirector::linux::ebpf_obj::sock_addr_audit_key;
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
        let shared_state = crate::shared_state::SharedState::new();

        let mut bpf_file_path = misc_helpers::get_current_exe_dir();
        bpf_file_path.push("config::get_ebpf_program_name()");
        let bpf = super::BpfObject::from_ebpf_file(bpf_file_path);
        assert!(
            bpf.is_err(),
            "BpfObject::from_ebpf_file should return error from invalid file path"
        );

        let mut bpf_file_path = misc_helpers::get_current_exe_dir();
        bpf_file_path.push(config::get_ebpf_program_name());
        let bpf = super::BpfObject::from_ebpf_file(bpf_file_path);
        if bpf.is_err() {
            println!("BpfObject::from_ebpf_file error");
            if std::fs::metadata("/.dockerenv").is_ok() {
                println!("This docker image does not have BPF capacity, skip this test.");
                return;
            } else {
                assert!(false, "open_ebpf_file should not return Err");
            }
        }
        let mut bpf = bpf.unwrap();

        let result = bpf.update_skip_process_map();
        assert!(
            result.is_ok(),
            "update_skip_process_map should return success"
        );
        let result = bpf.update_policy_map(80);
        assert!(result.is_ok(), "update_policy_map should return success");

        // Do not attach the program to real cgroup2 path
        // it should fail for both attach
        let result = bpf.attach_kprobe_program();
        assert!(
            result.is_ok(),
            "attach_kprobe_program should return success"
        );
        let result = bpf.attach_cgroup_program(temp_test_path.clone());
        assert!(
            result.is_err(),
            "attach_connect4_program should return error for invalid cgroup2 path"
        );

        let source_port = 1;
        let audit = bpf.lookup_audit(source_port);
        assert!(
            audit.is_err(),
            "lookup_audit should return error for invalid source port"
        );
        // insert to map an then look up
        let key = sock_addr_audit_key::from_source_port(source_port);
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
                    bpf.0.map_mut("audit_map").unwrap(),
                )
                .unwrap();
            audit_map
                .insert(key.to_array(), value.to_array(), 0)
                .unwrap();
        }
        let audit = bpf.lookup_audit(source_port);
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
