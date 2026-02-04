// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! This module contains the logic to generate the telemetry data to be send to wire server.

use crate::telemetry::{Event, ExtensionStatusEvent};
use crate::{current_info, misc_helpers};
use once_cell::sync::Lazy;
use serde_derive::{Deserialize, Serialize};

const METRICS_PROVIDER_ID: &str = "FFF0196F-EE4C-4EAF-9AA5-776F622DEB4F";
const STATUS_PROVIDER_ID: &str = "69B669B9-4AF8-4C50-BDC4-6006FA76E975";

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
                TelemetryEvent::ExtensionEvent(event) => {
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
                TelemetryEvent::ExtensionEvent(_) => {
                    if provider.id == STATUS_PROVIDER_ID {
                        provider.add_event(event);
                        return;
                    }
                }
            }
        }
        let mut p = TelemetryProvider::new(match &event {
            TelemetryEvent::GenericLogsEvent(_) => METRICS_PROVIDER_ID.to_string(),
            TelemetryEvent::ExtensionEvent(_) => STATUS_PROVIDER_ID.to_string(),
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
                TelemetryEvent::ExtensionEvent(_) => {
                    if provider.id == STATUS_PROVIDER_ID {
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
    ExtensionEvent(TelemetryExtensionEventsEvent),
}

impl TelemetryEvent {
    pub fn get_provider_id(&self) -> String {
        match self {
            TelemetryEvent::GenericLogsEvent(_) => TelemetryGenericLogsEvent::get_provider_id(),
            TelemetryEvent::ExtensionEvent(_) => TelemetryExtensionEventsEvent::get_provider_id(),
        }
    }

    pub fn to_xml_event(&self, vm_data: &TelemetryEventVMData) -> String {
        match self {
            TelemetryEvent::GenericLogsEvent(event) => event.to_xml_event(vm_data),
            TelemetryEvent::ExtensionEvent(event) => event.to_xml_event(vm_data),
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

#[derive(PartialEq, Eq, Hash, Clone)]
pub struct TelemetryExtensionEventsEvent {
    event_pid: u64,
    event_tid: u64,
    ga_version: String,
    task_name: String,
    opcode_name: String,
    execution_mode: String,

    extension_type: String,
    is_internal: bool,
    name: String,
    version: String,
    operation: String,
    operation_success: bool,
    message: String,
    duration: u64,
}

impl TelemetryExtensionEventsEvent {
    pub fn from_extension_status_event(
        event: &ExtensionStatusEvent,
        execution_mode: String,
        ga_version: String,
    ) -> Self {
        TelemetryExtensionEventsEvent {
            ga_version,
            execution_mode,
            event_pid: event.event_pid.parse::<u64>().unwrap_or(0),
            event_tid: event.event_tid.parse::<u64>().unwrap_or(0),
            opcode_name: event.time_stamp.to_string(),
            extension_type: event.extension.extension_type.to_string(),
            is_internal: event.extension.is_internal,
            name: event.extension.name.to_string(),
            version: event.extension.version.to_string(),
            operation: event.operation_status.operation.to_string(),
            task_name: event.operation_status.task_name.to_string(),
            operation_success: event.operation_status.operation_success,
            message: event.operation_status.message.to_string(),
            duration: event.operation_status.duration as u64,
        }
    }

    pub fn get_provider_id() -> String {
        STATUS_PROVIDER_ID.to_string()
    }

    fn to_xml_event(&self, vm_data: &TelemetryEventVMData) -> String {
        let mut xml: String = String::new();
        // Event ID 1 is for Extension Events
        xml.push_str("<Event id=\"1\"><![CDATA[");

        xml.push_str(&vm_data.to_xml_params());

        // ... Additional parameters similar to TelemetryGenericLogsEvent
        xml.push_str(&format!(
            "<Param Name=\"ExtensionType\" Value=\"{}\" T=\"mt:wstr\" />",
            misc_helpers::xml_escape(self.extension_type.to_string())
        ));
        xml.push_str(&format!(
            "<Param Name=\"IsInternal\" Value=\"{}\" T=\"mt:bool\" />",
            if self.is_internal { "True" } else { "False" }
        ));
        xml.push_str(&format!(
            "<Param Name=\"Name\" Value=\"{}\" T=\"mt:wstr\" />",
            misc_helpers::xml_escape(self.name.to_string())
        ));
        xml.push_str(&format!(
            "<Param Name=\"Version\" Value=\"{}\" T=\"mt:wstr\" />",
            misc_helpers::xml_escape(self.version.to_string())
        ));
        xml.push_str(&format!(
            "<Param Name=\"Operation\" Value=\"{}\" T=\"mt:wstr\" />",
            misc_helpers::xml_escape(self.operation.to_string())
        ));
        xml.push_str(&format!(
            "<Param Name=\"OperationSuccess\" Value=\"{}\" T=\"mt:bool\" />",
            if self.operation_success {
                "True"
            } else {
                "False"
            }
        ));
        xml.push_str(&format!(
            "<Param Name=\"Message\" Value=\"{}\" T=\"mt:wstr\" />",
            misc_helpers::xml_escape(self.message.to_string())
        ));
        xml.push_str(&format!(
            "<Param Name=\"Duration\" Value=\"{}\" T=\"mt:uint64\" />",
            self.duration
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

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_vm_meta_data() -> VmMetaData {
        VmMetaData {
            container_id: "test-container-id".to_string(),
            tenant_name: "test-tenant".to_string(),
            role_name: "test-role".to_string(),
            role_instance_name: "test-role-instance".to_string(),
            subscription_id: "test-subscription-id".to_string(),
            resource_group_name: "test-resource-group".to_string(),
            vm_id: "test-vm-id".to_string(),
            image_origin: 1,
        }
    }

    fn create_test_vm_data() -> TelemetryEventVMData {
        TelemetryEventVMData::new_from_vm_meta_data(&create_test_vm_meta_data())
    }

    fn create_test_event(message: &str) -> Event {
        Event::new(
            "Informational".to_string(),
            message.to_string(),
            "test_task".to_string(),
            "test_module".to_string(),
        )
    }

    fn create_test_telemetry_event(message: &str) -> TelemetryEvent {
        let event_log = create_test_event(message);
        TelemetryEvent::GenericLogsEvent(TelemetryGenericLogsEvent::from_event_log(
            &event_log,
            "test_execution_mode".to_string(),
            "test_event_name".to_string(),
            Some("1.0.0".to_string()),
        ))
    }

    /// Tests VmMetaData, TelemetryEventVMData creation and XML params generation
    #[test]
    fn test_vm_meta_data_and_vm_data() {
        // Test VmMetaData clone
        let meta_data = create_test_vm_meta_data();
        let cloned = meta_data.clone();
        assert_eq!(cloned.container_id, "test-container-id");
        assert_eq!(cloned.tenant_name, "test-tenant");
        assert_eq!(cloned.vm_id, "test-vm-id");
        assert_eq!(cloned.image_origin, 1);

        // Test TelemetryEventVMData creation from VmMetaData
        let vm_data = TelemetryEventVMData::new_from_vm_meta_data(&meta_data);
        assert_eq!(vm_data.container_id, "test-container-id");
        assert_eq!(vm_data.tenant_name, "test-tenant");
        assert_eq!(vm_data.role_name, "test-role");
        assert_eq!(vm_data.role_instance_name, "test-role-instance");
        assert_eq!(vm_data.subscription_id, "test-subscription-id");
        assert_eq!(vm_data.resource_group_name, "test-resource-group");
        assert_eq!(vm_data.vm_id, "test-vm-id");
        assert_eq!(vm_data.image_origin, 1);
        // These are populated from current_info
        assert!(!vm_data.keyword_name.is_empty());
        assert!(!vm_data.os_version.is_empty());
        assert!(vm_data.ram > 0);
        assert!(vm_data.processors > 0);

        // Test XML params generation
        let xml = vm_data.to_xml_params();
        assert!(xml.contains("KeywordName"));
        assert!(xml.contains("TenantName"));
        assert!(xml.contains("test-tenant"));
        assert!(xml.contains("RoleName"));
        assert!(xml.contains("ContainerId"));
        assert!(xml.contains("ResourceGroupName"));
        assert!(xml.contains("SubscriptionId"));
        assert!(xml.contains("VMId"));
        assert!(xml.contains("ImageOrigin"));
        assert!(xml.contains("OSVersion"));
        assert!(xml.contains("RAM"));
        assert!(xml.contains("Processors"));
    }

    /// Tests TelemetryProvider operations: add, remove, count, and XML generation
    #[test]
    fn test_telemetry_provider() {
        let mut provider = TelemetryProvider::new(METRICS_PROVIDER_ID.to_string());
        assert_eq!(provider.id, METRICS_PROVIDER_ID);
        assert_eq!(provider.event_count(), 0);

        // Add events
        let event1 = create_test_telemetry_event("Test message 1");
        let event2 = create_test_telemetry_event("Test message 2");

        provider.add_event(event1.clone());
        assert_eq!(provider.event_count(), 1);

        provider.add_event(event2);
        assert_eq!(provider.event_count(), 2);

        // Remove event
        let removed = provider.remove_event(event1.clone());
        assert!(removed.is_some());
        assert_eq!(provider.event_count(), 1);

        // Remove non-existent event returns None
        let removed = provider.remove_event(event1);
        assert!(removed.is_none());

        // Test XML generation
        let vm_data = create_test_vm_data();
        let xml = provider.to_xml(&vm_data);
        assert!(xml.starts_with(&format!("<Provider id=\"{}\">", METRICS_PROVIDER_ID)));
        assert!(xml.ends_with("</Provider>"));
        assert!(xml.contains("<Event id=\"7\">"));
    }

    /// Tests TelemetryData operations: add, remove, count, size, and XML generation
    #[test]
    fn test_telemetry_data() {
        let vm_data = create_test_vm_data();
        let mut telemetry_data = TelemetryData::new_with_vm_data(vm_data);
        assert_eq!(telemetry_data.event_count(), 0);

        // Test empty XML
        let empty_xml = telemetry_data.to_xml();
        assert!(empty_xml.starts_with("<?xml version=\"1.0\"?>"));
        assert!(empty_xml.contains("<TelemetryData version=\"1.0\">"));
        assert!(empty_xml.contains("</TelemetryData>"));
        assert!(!empty_xml.contains("<Provider")); // No provider when empty

        let initial_size = telemetry_data.get_size();
        assert!(initial_size > 0);

        // Add events
        let event1 = create_test_telemetry_event("Test message 1");
        let event2 = create_test_telemetry_event("Test message 2");
        let event3 = create_test_telemetry_event("Test message 3");

        telemetry_data.add_event(event1);
        assert_eq!(telemetry_data.event_count(), 1);

        telemetry_data.add_event(event2);
        telemetry_data.add_event(event3.clone());
        assert_eq!(telemetry_data.event_count(), 3);

        // Size should increase after adding events
        let new_size = telemetry_data.get_size();
        assert!(new_size > initial_size);

        // Remove last event
        let removed = telemetry_data.remove_last_event(event3);
        assert!(removed.is_some());
        assert_eq!(telemetry_data.event_count(), 2);

        // Test XML with events
        let xml = telemetry_data.to_xml();
        assert!(xml.starts_with("<?xml version=\"1.0\"?>"));
        assert!(xml.contains("<TelemetryData version=\"1.0\">"));
        assert!(xml.contains(&format!("<Provider id=\"{}\">", METRICS_PROVIDER_ID)));
        assert!(xml.contains("<Event id=\"7\">"));
    }

    /// Tests TelemetryEvent and TelemetryGenericLogsEvent
    #[test]
    fn test_telemetry_event() {
        // Test provider ID
        let event = create_test_telemetry_event("Test message");
        assert_eq!(event.get_provider_id(), METRICS_PROVIDER_ID);
        assert_eq!(
            TelemetryGenericLogsEvent::get_provider_id(),
            METRICS_PROVIDER_ID
        );

        // Test XML event generation
        let vm_data = create_test_vm_data();
        let xml = event.to_xml_event(&vm_data);
        assert!(xml.contains("<Event id=\"7\">"));
        assert!(xml.contains("<![CDATA["));
        assert!(xml.contains("]]></Event>"));
        assert!(xml.contains("EventName"));
        assert!(xml.contains("CapabilityUsed"));
        assert!(xml.contains("Context1"));
        assert!(xml.contains("Context2"));
        assert!(xml.contains("Context3"));

        // Test that different messages produce different events
        let event2 = create_test_telemetry_event("Different message");
        assert!(event != event2); // Different messages create different events
    }

    /// Tests TelemetryGenericLogsEvent from_event_log with and without ga_version
    #[test]
    fn test_telemetry_generic_logs_event_creation() {
        let event_log = create_test_event("Test message");

        // With ga_version provided
        let event_with_version = TelemetryGenericLogsEvent::from_event_log(
            &event_log,
            "execution_mode".to_string(),
            "event_name".to_string(),
            Some("1.0.0".to_string()),
        );
        assert_eq!(event_with_version.ga_version, "1.0.0");
        assert!(event_with_version.event_name.starts_with("event_name-"));
        assert_eq!(event_with_version.execution_mode, "execution_mode");

        // Without ga_version (None)
        let event_without_version = TelemetryGenericLogsEvent::from_event_log(
            &event_log,
            "execution_mode".to_string(),
            "event_name".to_string(),
            None,
        );
        assert_eq!(event_without_version.ga_version, event_log.Version);
        assert_eq!(event_without_version.event_name, "event_name");
    }

    /// Tests KeywordName JSON serialization
    #[test]
    fn test_keyword_name() {
        let keyword = KeywordName::new("x86_64".to_string());
        let json = keyword.to_json();

        assert!(json.contains("CpuArchitecture"));
        assert!(json.contains("x86_64"));
    }
}
