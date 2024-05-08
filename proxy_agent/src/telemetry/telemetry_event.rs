// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use super::event_reader;
use crate::common::helpers;
use once_cell::sync::Lazy;
use serde_derive::{Deserialize, Serialize};
use proxy_agent_shared::telemetry::Event;

pub struct TelemetryData {
    events: Vec<TelemetryEvent>,
}

impl TelemetryData {
    pub fn new() -> Self {
        TelemetryData { events: Vec::new() }
    }

    pub fn to_xml(&self) -> String {
        let mut xml: String = String::new();

        xml.push_str("<?xml version=\"1.0\"?><TelemetryData version=\"1.0\"><Provider id=\"FFF0196F-EE4C-4EAF-9AA5-776F622DEB4F\">");

        for e in &self.events {
            xml.push_str(&e.to_xml_event());
        }

        xml.push_str("</Provider></TelemetryData>");
        xml
    }

    pub fn get_size(&self) -> usize {
        self.to_xml().as_bytes().len()
    }

    pub fn add_event(&mut self, event: TelemetryEvent) {
        self.events.push(event);
    }

    pub fn remove_last_event(&mut self) -> Option<TelemetryEvent> {
        self.events.pop()
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }
}

pub struct TelemetryEvent {
    event_pid: u64,
    event_tid: u64,
    ga_version: String,
    container_id: String,
    task_name: String,
    opcode_name: String,
    keyword_name: String,
    os_version: String,
    execution_mode: String,
    ram: u64,
    processors: u64,
    tenant_name: String,
    role_name: String,
    role_instance_name: String,
    subscription_id: String,
    resource_group_name: String,
    vm_id: String,
    image_origin: u64,

    event_name: String,
    capability_used: String,
    context1: String,
    context2: String,
    context3: String,
}

impl TelemetryEvent {
    pub fn from_event_log(event_log: &Event) -> Self {
        let vm_meta_data = event_reader::get_vm_meta_data();
        TelemetryEvent {
            event_pid: match event_log.EventPid.parse::<u64>() {
                Ok(pid) => pid,
                Err(_) => 0, // 0 - default event pid
            },
            event_tid: match event_log.EventTid.parse::<u64>() {
                Ok(tid) => tid,
                Err(_) => 0, // 0 - default event tid
            },
            ga_version: event_log.Version.to_string(),
            task_name: event_log.TaskName.to_string(),
            opcode_name: event_log.TimeStamp.to_string(),
            capability_used: event_log.EventLevel.to_string(),
            context1: event_log.Message.to_string(),
            context2: event_log.TimeStamp.to_string(),
            context3: event_log.OperationId.to_string(),

            execution_mode: "ProxyAgent".to_string(),
            event_name: "MicrosoftAzureGuestProxyAgent".to_string(),
            os_version: helpers::get_long_os_version(),
            keyword_name: CURRENT_KEYWORD_NAME.to_string(),
            ram: helpers::get_ram_in_mb(),
            processors: helpers::get_cpu_count() as u64,

            container_id: vm_meta_data.container_id,
            tenant_name: vm_meta_data.tenant_name,
            role_name: vm_meta_data.role_name,
            role_instance_name: vm_meta_data.role_instance_name,
            subscription_id: vm_meta_data.subscription_id,
            resource_group_name: vm_meta_data.resource_group_name,
            vm_id: vm_meta_data.vm_id,
            image_origin: vm_meta_data.image_origin,
        }
    }

    fn to_xml_event(&self) -> String {
        let mut xml: String = String::new();
        xml.push_str("<Event id=\"7\"><![CDATA[");

        xml.push_str(&format!(
            "<Param Name=\"OpcodeName\" Value=\"{}\" T=\"mt:wstr\" />",
            helpers::xml_escape(self.opcode_name.to_string())
        ));
        xml.push_str(&format!(
            "<Param Name=\"KeywordName\" Value=\"{}\" T=\"mt:wstr\" />",
            helpers::xml_escape(self.keyword_name.to_string())
        ));
        xml.push_str(&format!(
            "<Param Name=\"TaskName\" Value=\"{}\" T=\"mt:wstr\" />",
            helpers::xml_escape(self.task_name.to_string())
        ));
        xml.push_str(&format!(
            "<Param Name=\"TenantName\" Value=\"{}\" T=\"mt:wstr\" />",
            helpers::xml_escape(self.tenant_name.to_string())
        ));
        xml.push_str(&format!(
            "<Param Name=\"RoleName\" Value=\"{}\" T=\"mt:wstr\" />",
            helpers::xml_escape(self.role_name.to_string())
        ));
        xml.push_str(&format!(
            "<Param Name=\"RoleInstanceName\" Value=\"{}\" T=\"mt:wstr\" />",
            helpers::xml_escape(self.role_instance_name.to_string())
        ));
        xml.push_str(&format!(
            "<Param Name=\"ContainerId\" Value=\"{}\" T=\"mt:wstr\" />",
            helpers::xml_escape(self.container_id.to_string())
        ));
        xml.push_str(&format!(
            "<Param Name=\"ResourceGroupName\" Value=\"{}\" T=\"mt:wstr\" />",
            helpers::xml_escape(self.resource_group_name.to_string())
        ));
        xml.push_str(&format!(
            "<Param Name=\"SubscriptionId\" Value=\"{}\" T=\"mt:wstr\" />",
            helpers::xml_escape(self.subscription_id.to_string())
        ));
        xml.push_str(&format!(
            "<Param Name=\"VMId\" Value=\"{}\" T=\"mt:wstr\" />",
            helpers::xml_escape(self.vm_id.to_string())
        ));
        xml.push_str(&format!(
            "<Param Name=\"EventPid\" Value=\"{}\" T=\"mt:uint64\" />",
            self.event_pid
        ));
        xml.push_str(&format!(
            "<Param Name=\"EventTid\" Value=\"{}\" T=\"mt:uint64\" />",
            self.event_tid
        ));
        xml.push_str(&format!(
            "<Param Name=\"ImageOrigin\" Value=\"{}\" T=\"mt:uint64\" />",
            self.image_origin
        ));

        xml.push_str(&format!(
            "<Param Name=\"ExecutionMode\" Value=\"{}\" T=\"mt:wstr\" />",
            helpers::xml_escape(self.execution_mode.to_string())
        ));
        xml.push_str(&format!(
            "<Param Name=\"OSVersion\" Value=\"{}\" T=\"mt:wstr\" />",
            helpers::xml_escape(self.os_version.to_string())
        ));
        xml.push_str(&format!(
            "<Param Name=\"GAVersion\" Value=\"{}\" T=\"mt:wstr\" />",
            helpers::xml_escape(self.ga_version.to_string())
        ));
        xml.push_str(&format!(
            "<Param Name=\"RAM\" Value=\"{}\" T=\"mt:uint64\" />",
            self.ram
        ));
        xml.push_str(&format!(
            "<Param Name=\"Processors\" Value=\"{}\" T=\"mt:uint64\" />",
            self.processors
        ));

        xml.push_str(&format!(
            "<Param Name=\"EventName\" Value=\"{}\" T=\"mt:wstr\" />",
            helpers::xml_escape(self.event_name.to_string())
        ));
        xml.push_str(&format!(
            "<Param Name=\"CapabilityUsed\" Value=\"{}\" T=\"mt:wstr\" />",
            helpers::xml_escape(self.capability_used.to_string())
        ));
        xml.push_str(&format!(
            "<Param Name=\"Context1\" Value=\"{}\" T=\"mt:wstr\" />",
            helpers::xml_escape(self.context1.to_string())
        ));
        xml.push_str(&format!(
            "<Param Name=\"Context2\" Value=\"{}\" T=\"mt:wstr\" />",
            helpers::xml_escape(self.context2.to_string())
        ));
        xml.push_str(&format!(
            "<Param Name=\"Context3\" Value=\"{}\" T=\"mt:wstr\" />",
            helpers::xml_escape(self.context3.to_string())
        ));

        xml.push_str("]]></Event>");
        xml
    }
}

static CURRENT_KEYWORD_NAME: Lazy<String> =
    Lazy::new(|| KeywordName::new(helpers::get_cpu_arch()).to_json());

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct KeywordName {
    CpuArchitecture: String,
}

impl KeywordName {
    pub fn new(arch: String) -> Self {
        KeywordName {
            CpuArchitecture: arch,
        }
    }

    pub fn to_json(&self) -> String {
        match serde_json::to_string(self) {
            Ok(json) => json,
            Err(_) => "".to_owned(),
        }
    }
}
