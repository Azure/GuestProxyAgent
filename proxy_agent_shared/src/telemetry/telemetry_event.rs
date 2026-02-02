// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! This module contains the logic to generate the telemetry data to be send to wire server.

use crate::telemetry::Event;
use crate::{current_info, misc_helpers};
use once_cell::sync::Lazy;
use serde_derive::{Deserialize, Serialize};

const METRICS_PROVIDER_ID: &str = "FFF0196F-EE4C-4EAF-9AA5-776F622DEB4F";

/// VmMetaData contains the metadata of the VM.
/// The metadata is used to identify the VM and the image origin.
/// It will be part of the telemetry data send to the wire server.
/// The metadata is updated by the wire server and the IMDS client.
#[derive(Clone, Debug)]
pub struct VmMetaData {
    pub container_id: String,
    pub tenant_name: String,
    pub role_name: String,
    pub role_instance_name: String,
    pub subscription_id: String,
    pub resource_group_name: String,
    pub vm_id: String,
    pub image_origin: u64,
}

/// Base struct containing common fields shared between telemetry event types.
#[derive(PartialEq, Eq, Hash, Clone)]
pub struct TelemetryEventVMData {
    pub container_id: String,
    pub keyword_name: String,
    pub os_version: String,
    pub ram: u64,
    pub processors: u64,
    pub tenant_name: String,
    pub role_name: String,
    pub role_instance_name: String,
    pub subscription_id: String,
    pub resource_group_name: String,
    pub vm_id: String,
    pub image_origin: u64,
}

impl TelemetryEventVMData {
    pub fn new_from_vm_meta_data(vm_meta_data: &VmMetaData) -> Self {
        TelemetryEventVMData {
            keyword_name: CURRENT_KEYWORD_NAME.to_string(),
            os_version: current_info::get_long_os_version(),
            ram: current_info::get_ram_in_mb(),
            processors: current_info::get_cpu_count() as u64,
            container_id: vm_meta_data.container_id.clone(),
            tenant_name: vm_meta_data.tenant_name.clone(),
            role_name: vm_meta_data.role_name.clone(),
            role_instance_name: vm_meta_data.role_instance_name.clone(),
            subscription_id: vm_meta_data.subscription_id.clone(),
            resource_group_name: vm_meta_data.resource_group_name.clone(),
            vm_id: vm_meta_data.vm_id.clone(),
            image_origin: vm_meta_data.image_origin,
        }
    }

    /// Convert the base fields to XML format.
    pub fn to_xml_params(&self) -> String {
        let mut xml = String::new();
        xml.push_str(&format!(
            "<Param Name=\"KeywordName\" Value=\"{}\" T=\"mt:wstr\" />",
            misc_helpers::xml_escape(self.keyword_name.to_string())
        ));
        xml.push_str(&format!(
            "<Param Name=\"TenantName\" Value=\"{}\" T=\"mt:wstr\" />",
            misc_helpers::xml_escape(self.tenant_name.to_string())
        ));
        xml.push_str(&format!(
            "<Param Name=\"RoleName\" Value=\"{}\" T=\"mt:wstr\" />",
            misc_helpers::xml_escape(self.role_name.to_string())
        ));
        xml.push_str(&format!(
            "<Param Name=\"RoleInstanceName\" Value=\"{}\" T=\"mt:wstr\" />",
            misc_helpers::xml_escape(self.role_instance_name.to_string())
        ));
        xml.push_str(&format!(
            "<Param Name=\"ContainerId\" Value=\"{}\" T=\"mt:wstr\" />",
            misc_helpers::xml_escape(self.container_id.to_string())
        ));
        xml.push_str(&format!(
            "<Param Name=\"ResourceGroupName\" Value=\"{}\" T=\"mt:wstr\" />",
            misc_helpers::xml_escape(self.resource_group_name.to_string())
        ));
        xml.push_str(&format!(
            "<Param Name=\"SubscriptionId\" Value=\"{}\" T=\"mt:wstr\" />",
            misc_helpers::xml_escape(self.subscription_id.to_string())
        ));
        xml.push_str(&format!(
            "<Param Name=\"VMId\" Value=\"{}\" T=\"mt:wstr\" />",
            misc_helpers::xml_escape(self.vm_id.to_string())
        ));
        xml.push_str(&format!(
            "<Param Name=\"ImageOrigin\" Value=\"{}\" T=\"mt:uint64\" />",
            self.image_origin
        ));
        xml.push_str(&format!(
            "<Param Name=\"OSVersion\" Value=\"{}\" T=\"mt:wstr\" />",
            misc_helpers::xml_escape(self.os_version.to_string())
        ));
        xml.push_str(&format!(
            "<Param Name=\"RAM\" Value=\"{}\" T=\"mt:uint64\" />",
            self.ram
        ));
        xml.push_str(&format!(
            "<Param Name=\"Processors\" Value=\"{}\" T=\"mt:uint64\" />",
            self.processors
        ));
        xml
    }
}

/// TelemetryProvider struct to hold the telemetry events for a specific provider.
pub struct TelemetryProvider {
    pub id: String,
    events: Vec<TelemetryEvent>,
}

impl TelemetryProvider {
    pub fn new(id: String) -> Self {
        TelemetryProvider {
            id,
            events: Vec::new(),
        }
    }

    pub fn add_event(&mut self, event: TelemetryEvent) {
        self.events.push(event);
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    pub fn remove_event(&mut self, event: TelemetryEvent) -> Option<TelemetryEvent> {
        if let Some(pos) = self.events.iter().position(|x| *x == event) {
            Some(self.events.remove(pos))
        } else {
            None
        }
    }

    pub fn to_xml(&self, vm_data: &TelemetryEventVMData) -> String {
        let mut xml: String = String::new();
        xml.push_str(&format!(
            "<Provider id=\"{}\">",
            misc_helpers::xml_escape(self.id.to_string())
        ));

        for e in &self.events {
            match e {
                TelemetryEvent::GenericLogsEvent(event) => {
                    xml.push_str(&event.to_xml_event(vm_data));
                }
            }
        }

        xml.push_str("</Provider>");
        xml
    }
}

/// TelemetryData struct to hold the telemetry events send to wire server.
pub struct TelemetryData {
    providers: Vec<TelemetryProvider>,
    vm_data: TelemetryEventVMData,
}

impl TelemetryData {
    /// Create a new TelemetryData instance with VM data.
    pub fn new_with_vm_data(vm_data: TelemetryEventVMData) -> Self {
        TelemetryData {
            providers: Vec::new(),
            vm_data,
        }
    }

    /// Convert the telemetry data to xml format.
    /// The xml format is defined by the wire server.
    pub fn to_xml(&self) -> String {
        let mut xml: String = String::new();

        xml.push_str("<?xml version=\"1.0\"?><TelemetryData version=\"1.0\">");

        for provider in &self.providers {
            xml.push_str(&provider.to_xml(&self.vm_data));
        }

        xml.push_str("</TelemetryData>");
        xml
    }

    /// Get the size of the telemetry data in bytes.
    pub fn get_size(&self) -> usize {
        self.to_xml().len()
    }

    /// Add a telemetry event to the telemetry data.
    /// It will be added to the corresponding provider.
    pub fn add_event(&mut self, event: TelemetryEvent) {
        for provider in &mut self.providers {
            match &event {
                TelemetryEvent::GenericLogsEvent(_) => {
                    if provider.id == METRICS_PROVIDER_ID {
                        provider.add_event(event);
                        return;
                    }
                }
            }
        }
        let mut p = TelemetryProvider::new(match &event {
            TelemetryEvent::GenericLogsEvent(_) => METRICS_PROVIDER_ID.to_string(),
        });
        p.add_event(event);
        self.providers.push(p);
    }

    /// Remove the last added telemetry event from the telemetry data.
    /// This is used when the telemetry data size exceeds the maximum allowed size.
    pub fn remove_last_event(&mut self, last_event: TelemetryEvent) -> Option<TelemetryEvent> {
        for provider in &mut self.providers {
            match &last_event {
                TelemetryEvent::GenericLogsEvent(_) => {
                    if provider.id == METRICS_PROVIDER_ID {
                        return provider.remove_event(last_event);
                    }
                }
            }
        }
        None
    }

    /// Get the total number of events in the telemetry data.
    /// It adds up the event counts from all providers.
    pub fn event_count(&self) -> usize {
        self.providers.iter().map(|p| p.event_count()).sum()
    }
}

#[derive(PartialEq, Eq, Hash, Clone)]
pub enum TelemetryEvent {
    GenericLogsEvent(TelemetryGenericLogsEvent),
}

impl TelemetryEvent {
    pub fn get_provider_id(&self) -> String {
        match self {
            TelemetryEvent::GenericLogsEvent(_) => TelemetryGenericLogsEvent::get_provider_id(),
        }
    }

    pub fn to_xml_event(&self, vm_data: &TelemetryEventVMData) -> String {
        match self {
            TelemetryEvent::GenericLogsEvent(event) => event.to_xml_event(vm_data),
        }
    }
}

/// Struct to hold Generic Logs telemetry event data without VM metadata.
#[derive(PartialEq, Eq, Hash, Clone)]
pub struct TelemetryGenericLogsEvent {
    event_pid: u64,
    event_tid: u64,
    ga_version: String,
    task_name: String,
    opcode_name: String,
    execution_mode: String,

    event_name: String,
    capability_used: String,
    context1: String,
    context2: String,
    context3: String,
}

impl TelemetryGenericLogsEvent {
    pub fn from_event_log(
        event_log: &Event,
        execution_mode: String,
        event_name: String,
        ga_version: Option<String>,
    ) -> Self {
        // if ga_version is provided, append event_log.version to event_name
        // if ga_version is None, use event_log.Version as ga_version and keep event_name unchanged
        let (ga_version, event_name) = match ga_version {
            Some(version) => (version, format!("{}-{}", event_name, event_log.Version)),
            None => (event_log.Version.to_string(), event_name),
        };
        TelemetryGenericLogsEvent {
            event_name,
            ga_version,
            execution_mode,
            event_pid: event_log.EventPid.parse::<u64>().unwrap_or(0),
            event_tid: event_log.EventTid.parse::<u64>().unwrap_or(0),
            task_name: event_log.TaskName.to_string(),
            opcode_name: event_log.TimeStamp.to_string(),
            capability_used: event_log.EventLevel.to_string(),
            context1: event_log.Message.to_string(),
            context2: event_log.TimeStamp.to_string(),
            context3: event_log.OperationId.to_string(),
        }
    }

    pub fn get_provider_id() -> String {
        METRICS_PROVIDER_ID.to_string()
    }

    fn to_xml_event(&self, vm_data: &TelemetryEventVMData) -> String {
        let mut xml: String = String::new();
        // Event ID 7 is for Generic Logs Events
        xml.push_str("<Event id=\"7\"><![CDATA[");

        xml.push_str(&vm_data.to_xml_params());

        xml.push_str(&format!(
            "<Param Name=\"EventName\" Value=\"{}\" T=\"mt:wstr\" />",
            misc_helpers::xml_escape(self.event_name.to_string())
        ));
        xml.push_str(&format!(
            "<Param Name=\"CapabilityUsed\" Value=\"{}\" T=\"mt:wstr\" />",
            misc_helpers::xml_escape(self.capability_used.to_string())
        ));
        xml.push_str(&format!(
            "<Param Name=\"Context1\" Value=\"{}\" T=\"mt:wstr\" />",
            misc_helpers::xml_escape(self.context1.to_string())
        ));
        xml.push_str(&format!(
            "<Param Name=\"Context2\" Value=\"{}\" T=\"mt:wstr\" />",
            misc_helpers::xml_escape(self.context2.to_string())
        ));
        xml.push_str(&format!(
            "<Param Name=\"Context3\" Value=\"{}\" T=\"mt:wstr\" />",
            misc_helpers::xml_escape(self.context3.to_string())
        ));

        xml.push_str("]]></Event>");
        xml
    }
}

static CURRENT_KEYWORD_NAME: Lazy<String> =
    Lazy::new(|| KeywordName::new(current_info::get_cpu_arch()).to_json());

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
        serde_json::to_string(self).unwrap_or_else(|_| "".to_owned())
    }
}
