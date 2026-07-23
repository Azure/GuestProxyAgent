// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use serde_derive::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// A decoded ETW event, with all available metadata and payload fields.
#[derive(Debug, Serialize)]
pub struct WindowsEvent {
    #[serde(rename = "Provider")]
    pub provider: String,
    #[serde(rename = "EventId")]
    pub event_id: u16,
    #[serde(rename = "Version")]
    pub version: u8,
    #[serde(rename = "Level")]
    pub level: u8,
    #[serde(rename = "Opcode")]
    pub opcode: u8,
    #[serde(rename = "Keyword")]
    pub keyword: u64,
    /// ISO-8601 string, or a numeric FILETIME when out of range.
    #[serde(rename = "Timestamp")]
    pub timestamp: String,
    #[serde(rename = "ProcessId")]
    pub process_id: u32,
    #[serde(rename = "ThreadId")]
    pub thread_id: u32,
    #[serde(rename = "ActivityId")]
    pub activity_id: String,
    #[serde(rename = "ProviderName", skip_serializing_if = "Option::is_none")]
    pub provider_name: Option<String>,
    #[serde(rename = "TaskName", skip_serializing_if = "Option::is_none")]
    pub task_name: Option<String>,
    #[serde(rename = "EventName", skip_serializing_if = "Option::is_none")]
    pub event_name: Option<String>,
    /// Human-readable message from the provider manifest, with `%N` placeholders
    /// substituted by the decoded property values. Present when the schema
    /// defines a message template.
    #[serde(rename = "Message", skip_serializing_if = "Option::is_none")]
    pub formatted_message: Option<String>,
    /// Decoded top-level properties (name -> value); present when a TDH schema exists.
    #[serde(rename = "Properties", skip_serializing_if = "Option::is_none")]
    pub properties: Option<Map<String, Value>>,
    /// Raw hex payload; present when no TDH schema is available.
    #[serde(rename = "UserData", skip_serializing_if = "Option::is_none")]
    pub user_data: Option<String>,
}

impl WindowsEvent {
    /// Returns the best available message for the event. Uses the formatted message if available,
    /// otherwise falls back to the decoded properties, then the raw user data, and finally an empty string.
    pub fn get_message(&self) -> String {
        // Use formatted_message first
        if let Some(message) = &self.formatted_message {
            if !message.is_empty() {
                return message.clone();
            }
        }

        // Second use properties,
        // third use user_data
        // last return empty string
        self.message_from_properties()
            .unwrap_or_else(|| self.user_data.clone().unwrap_or_default())
    }

    /// Builds a message string from an event's decoded properties, used when the
    /// event has no rendered manifest message. A single string property is treated
    /// as the message text itself; otherwise the properties are serialized to a
    /// compact JSON object. Returns `None` when there are no properties.
    fn message_from_properties(&self) -> Option<String> {
        if self.properties.is_none() || self.properties.as_ref().unwrap().is_empty() {
            return None;
        }
        let properties = self.properties.as_ref().unwrap();
        if properties.len() == 1 {
            if let Some(serde_json::Value::String(s)) = properties.values().next() {
                return Some(s.clone());
            }
        }
        serde_json::to_string(properties).ok()
    }

    /// Returns the string representation of the event's level.
    /// Level values 0 through 5 are defined by Microsoft (see evntrace.h).
    pub fn get_level_string(&self) -> String {
        match self.level {
            0 => "LogAlways".to_string(),
            1 => "Critical".to_string(),
            2 => "Error".to_string(),
            3 => "Warning".to_string(),
            4 => "Informational".to_string(),
            5 => "Verbose".to_string(),
            _ => "Unknown".to_string(),
        }
    }
}

/// A single Windows Event Log entry.
///
/// Contains a [`System`] block holding the entry metadata and an optional
/// [`EventData`] block holding the entry payload. The same model deserializes
/// both classic Event Log entries and ETW-backed channel entries.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename = "Event")]
pub struct EvtEvent {
    #[serde(rename = "System")]
    pub system: System,
    /// Classic / manifest events place their payload in `<EventData>`.
    #[serde(rename = "EventData", default, skip_serializing_if = "Option::is_none")]
    pub event_data: Option<EventData>,
    /// Modern manifest providers place their payload in `<UserData>` instead of
    /// `<EventData>`. The wrapper element name and fields are provider-defined,
    /// so the payload is captured generically as `wrapper -> (field -> text)`.
    #[serde(rename = "UserData", default, skip_serializing_if = "Option::is_none")]
    pub user_data: Option<UserData>,
}

/// The `<System>` block: metadata common to every event log entry.
#[derive(Debug, Deserialize, Serialize)]
pub struct System {
    #[serde(rename = "Provider")]
    pub provider: Provider,
    #[serde(rename = "EventID")]
    pub event_id: u32,
    /// Version is only present in ETW events, not classic event log entries
    #[serde(rename = "Version", default)]
    pub version: u8,
    #[serde(rename = "Level")]
    pub level: u8,
    /// Task is only present in ETW events, not classic event log entries
    #[serde(rename = "Task", default)]
    pub task: u8,
    /// Opcode is only present in ETW events, not classic event log entries
    #[serde(rename = "Opcode", default)]
    pub opcode: u8,
    #[serde(rename = "Keywords", default)]
    pub keywords: String,
    #[serde(rename = "TimeCreated")]
    pub time_created: TimeCreated,
    #[serde(rename = "EventRecordID")]
    pub event_record_id: u64,
    /// Correlation carries the activity IDs; present mainly in ETW-backed events
    #[serde(
        rename = "Correlation",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub correlation: Option<Correlation>,
    /// Execution may not be present in some classic event log entries
    #[serde(rename = "Execution", default)]
    pub execution: Execution,
    /// Channel/log name. Occasionally absent or empty on classic entries, in
    /// which case callers fall back to the subscription's channel argument.
    #[serde(rename = "Channel", default)]
    pub channel: String,
    #[serde(rename = "Computer")]
    pub computer: String,
    /// Security carries the originating user's SID; often omitted
    #[serde(rename = "Security", default, skip_serializing_if = "Option::is_none")]
    pub security: Option<Security>,
}

/// The `<Provider>` element identifying the event source.
#[derive(Debug, Deserialize, Serialize)]
pub struct Provider {
    #[serde(rename = "@Name", skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "@EventSourceName", skip_serializing_if = "Option::is_none")]
    pub event_source_name: Option<String>,
    /// Provider GUID, present for manifest / ETW-backed publishers.
    #[serde(rename = "@Guid", default, skip_serializing_if = "Option::is_none")]
    pub guid: Option<String>,
}

/// The `<Correlation>` element carrying activity correlation identifiers.
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct Correlation {
    #[serde(
        rename = "@ActivityID",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub activity_id: Option<String>,
    #[serde(
        rename = "@RelatedActivityID",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub related_activity_id: Option<String>,
}

/// The `<Security>` element carrying the originating user's SID.
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct Security {
    #[serde(rename = "@UserID", default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
}

/// The `<TimeCreated>` element carrying the entry's system time.
#[derive(Debug, Deserialize, Serialize)]
pub struct TimeCreated {
    #[serde(rename = "@SystemTime", skip_serializing_if = "Option::is_none")]
    pub system_time: Option<String>,
}

/// The `<Execution>` element carrying the writing process/thread identifiers.
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct Execution {
    #[serde(rename = "@ProcessID", default)]
    pub process_id: u32,
    #[serde(rename = "@ThreadID", default)]
    pub thread_id: u32,
}

/// The `<EventData>` block carrying the entry's payload entries.
#[derive(Debug, Deserialize, Serialize)]
pub struct EventData {
    #[serde(rename = "Data", default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Vec<Data>>,
}

/// A single `<Data>` payload entry.
///
/// Manifest events emit named entries (`<Data Name="Foo">bar</Data>`), while
/// classic events emit positional entries (`<Data>bar</Data>`). Both forms are
/// captured: [`name`](Self::name) is `None` for positional entries.
#[derive(Debug, Deserialize, Serialize)]
pub struct Data {
    #[serde(rename = "@Name", default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The element's text content (serde-xml-rs 0.8 names it `#text`).
    #[serde(rename = "#text", default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// The `<UserData>` payload used by modern manifest providers.
///
/// `<UserData>` wraps a single provider-defined element whose children carry the
/// payload. Because both the wrapper name and its fields are provider-defined,
/// the payload is captured generically as
/// `wrapper element name -> (field name -> text value)`. Attribute values (for
/// example `xmlns`) appear under `@`-prefixed keys.
pub type UserData = BTreeMap<String, BTreeMap<String, String>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_classic_positional_data() {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="MySource" EventSourceName="MySource" />
    <EventID>1000</EventID>
    <Level>2</Level>
    <Keywords>0x80000000000000</Keywords>
    <TimeCreated SystemTime="2024-01-01T00:00:00.000000000Z" />
    <EventRecordID>42</EventRecordID>
    <Channel>Application</Channel>
    <Computer>HOST</Computer>
  </System>
  <EventData>
    <Data>first</Data>
    <Data>second</Data>
  </EventData>
</Event>"#;

        let event: EvtEvent = serde_xml_rs::from_str(xml).expect("classic event should parse");
        let data = event.event_data.unwrap().data.unwrap();
        assert_eq!(data.len(), 2);
        assert!(data[0].name.is_none());
        assert_eq!(data[0].value.as_deref(), Some("first"));
        assert_eq!(data[1].value.as_deref(), Some("second"));
    }

    #[test]
    fn parses_named_data_correlation_security_and_guid() {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Test" Guid="{11111111-2222-3333-4444-555555555555}" />
    <EventID>7</EventID>
    <Version>1</Version>
    <Level>4</Level>
    <Task>0</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2024-01-01T00:00:00.000000000Z" />
    <EventRecordID>99</EventRecordID>
    <Correlation ActivityID="{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}" />
    <Execution ProcessID="4" ThreadID="8" />
    <Channel>System</Channel>
    <Computer>HOST</Computer>
    <Security UserID="S-1-5-18" />
  </System>
  <EventData>
    <Data Name="Field1">alpha</Data>
    <Data Name="Field2">beta</Data>
  </EventData>
</Event>"#;

        let event: EvtEvent = serde_xml_rs::from_str(xml).expect("manifest event should parse");
        assert_eq!(
            event.system.provider.guid.as_deref(),
            Some("{11111111-2222-3333-4444-555555555555}")
        );
        assert_eq!(
            event
                .system
                .correlation
                .and_then(|c| c.activity_id)
                .as_deref(),
            Some("{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}")
        );
        assert_eq!(
            event.system.security.and_then(|s| s.user_id).as_deref(),
            Some("S-1-5-18")
        );
        let data = event.event_data.unwrap().data.unwrap();
        assert_eq!(data[0].name.as_deref(), Some("Field1"));
        assert_eq!(data[0].value.as_deref(), Some("alpha"));
        assert_eq!(data[1].name.as_deref(), Some("Field2"));
        assert_eq!(data[1].value.as_deref(), Some("beta"));
    }

    #[test]
    fn parses_user_data_payload() {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Test" />
    <EventID>3</EventID>
    <Level>4</Level>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2024-01-01T00:00:00.000000000Z" />
    <EventRecordID>5</EventRecordID>
    <Channel>System</Channel>
    <Computer>HOST</Computer>
  </System>
  <UserData>
    <RuleData xmlns="myns">
      <RuleName>block</RuleName>
      <TargetUser>SYSTEM</TargetUser>
    </RuleData>
  </UserData>
</Event>"#;

        let event: EvtEvent = serde_xml_rs::from_str(xml).expect("user data event should parse");
        assert!(event.event_data.is_none());
        let user_data = event.user_data.expect("user data present");
        let rule = user_data.get("RuleData").expect("wrapper captured");
        assert_eq!(rule.get("RuleName").map(String::as_str), Some("block"));
        assert_eq!(rule.get("TargetUser").map(String::as_str), Some("SYSTEM"));
    }
}
