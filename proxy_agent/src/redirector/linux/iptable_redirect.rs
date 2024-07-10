// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use crate::{
    common::{constants, logger},
    shared_state::SharedState,
};
use proxy_agent_shared::misc_helpers;
use std::sync::Arc;
use std::sync::Mutex;

pub fn setup_firewall_redirection(local_port: u16, shared_state: Arc<Mutex<SharedState>>) -> bool {
    unsafe {
        // set our current GuestProxyAgent process to gid 3080
        let ret = libc::setegid(constants::EGID);
        logger::write_information(format!(
            "libc::setegid gid '{}' with result '{}'",
            constants::EGID,
            ret
        ))
    }

    let gid = constants::EGID.to_string();
    let local_port_str = local_port.to_string();
    if !config_one_firewall_redirection(
        constants::WIRE_SERVER_IP,
        &constants::WIRE_SERVER_PORT.to_string(),
        &local_port_str,
        true,
        &gid,
        shared_state.clone(),
    ) {
        return false;
    }
    if !config_one_firewall_redirection(
        constants::IMDS_IP,
        &constants::IMDS_PORT.to_string(),
        &local_port_str,
        true,
        &gid,
        shared_state.clone(),
    ) {
        return false;
    }
    if !config_one_firewall_redirection(
        constants::GA_PLUGIN_IP,
        &constants::GA_PLUGIN_PORT.to_string(),
        &local_port_str,
        true,
        &gid,
        shared_state.clone(),
    ) {
        return false;
    }

    true
}

pub fn cleanup_firewall_redirection(local_port: u16, shared_state: Arc<Mutex<SharedState>>) {
    let gid = constants::EGID.to_string();
    let local_port_str = local_port.to_string();

    // loop until the firewall rules are removed
    while config_one_firewall_redirection(
        constants::WIRE_SERVER_IP,
        &constants::WIRE_SERVER_PORT.to_string(),
        &local_port_str,
        false,
        &gid,
        shared_state.clone(),
    ) {}
    while config_one_firewall_redirection(
        constants::IMDS_IP,
        &constants::IMDS_PORT.to_string(),
        &local_port_str,
        false,
        &gid,
        shared_state.clone(),
    ) {}
    while config_one_firewall_redirection(
        constants::GA_PLUGIN_IP,
        &constants::GA_PLUGIN_PORT.to_string(),
        &local_port_str,
        false,
        &gid,
        shared_state.clone(),
    ) {}
}

fn config_one_firewall_redirection(
    dest_ip: &str,
    dest_port: &str,
    local_port: &str,
    enable: bool,
    exclude_gid: &str,
    shared_state: Arc<Mutex<SharedState>>,
) -> bool {
    let iptable_cmd = if enable { "-A" } else { "-D" };
    let local_endpoint = format!("127.0.0.1:{}", local_port);

    let args = vec![
        "-t",
        "nat",
        iptable_cmd,
        "OUTPUT",
        "-p",
        "tcp",
        "-d",
        dest_ip,
        "--dport",
        dest_port,
        "-m",
        "owner",
        "!",
        "--gid-owner",
        exclude_gid,
        "-j",
        "DNAT",
        "--to-destination",
        &local_endpoint,
    ];
    let output = misc_helpers::execute_command("iptables", args, -1);

    let message = format!(
        "config_one_firewall_redirection: {} redirect {}:{} to {} result: '{}'-'{}'-'{}'.",
        iptable_cmd, dest_ip, dest_port, local_endpoint, output.0, output.1, output.2
    );
    if enable && output.0 != 0 {
        // only set error status when enable is true and the command failed
        super::set_error_status(message, shared_state.clone());
        return false;
    }
    logger::write_information(message);

    output.0 == 0
}
