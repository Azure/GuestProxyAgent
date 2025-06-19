// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
//! This module provides functionality for ETW (Event Tracing for Windows) logging.

pub mod application;

use serde_derive::{Deserialize, Serialize};

/// Represents an ETW event structure
/// as defined in the XML schema.
/// The structure is used to deserialize ETW events from XML format.
/// The `Event` struct contains a `System` and `EventData` field,
/// which hold the metadata and data of the event respectively.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename = "Event")]
pub struct Event {
    #[serde(rename = "System")]
    pub system: System,
    #[serde(rename = "EventData")]
    pub event_data: EventData,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct System {
    #[serde(rename = "Provider")]
    pub provider: Provider,
    #[serde(rename = "EventID")]
    pub event_id: u32,
    #[serde(rename = "Version")]
    pub version: u8,
    #[serde(rename = "Level")]
    pub level: u8,
    #[serde(rename = "Task")]
    pub task: u8,
    #[serde(rename = "Opcode")]
    pub opcode: u8,
    #[serde(rename = "Keywords")]
    pub keywords: String,
    #[serde(rename = "TimeCreated")]
    pub time_created: TimeCreated,
    #[serde(rename = "EventRecordID")]
    pub event_record_id: u64,
    #[serde(rename = "Execution")]
    pub execution: Execution,
    #[serde(rename = "Channel")]
    pub channel: String,
    #[serde(rename = "Computer")]
    pub computer: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Provider {
    #[serde(rename = "@Name", skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "@EventSourceName", skip_serializing_if = "Option::is_none")]
    pub event_source_name: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TimeCreated {
    #[serde(rename = "@SystemTime", skip_serializing_if = "Option::is_none")]
    pub system_time: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Execution {
    #[serde(rename = "@ProcessID")]
    pub process_id: u32,
    #[serde(rename = "@ThreadID")]
    pub thread_id: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EventData {
    #[serde(rename = "Data")]
    pub data: Vec<String>,
}
