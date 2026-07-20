// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! - [`EtwListener`]: a real-time ETW / TraceLogging consumer that subscribes to
//!   one or more ETW *providers* and delivers each decoded [`WindowsEvent`] to a
//!   handler (or the telemetry logger via [`EtwListener::run`]).
//!
//! ETW providers can be specified as:
//!   - A GUID: `{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}` or the same without braces.
//!   - A registered provider name: `Microsoft-Windows-Kernel-Process`.

use crate::error::Error;
use crate::logger::logger_manager;
use crate::result::Result;
use crate::windows_events::models::WindowsEvent;
use serde_json::{Map, Value};
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::IsValidSid;
use windows_sys::Win32::System::Diagnostics::Etw::{
    // Advapi32.dll
    CloseTrace,
    ControlTraceW,
    EnableTraceEx2,
    OpenTraceW,
    ProcessTrace,
    PropertyStruct,
    StartTraceW,
    TdhEnumerateProviders,
    TdhGetEventInformation,
    TdhGetProperty,
    TdhGetPropertySize,
    CONTROLTRACE_HANDLE,
    ENABLE_TRACE_PARAMETERS,
    ENABLE_TRACE_PARAMETERS_VERSION_2,
    EVENT_CONTROL_CODE_DISABLE_PROVIDER,
    EVENT_CONTROL_CODE_ENABLE_PROVIDER,
    EVENT_FILTER_DESCRIPTOR,
    EVENT_FILTER_EVENT_ID,
    EVENT_FILTER_TYPE_EVENT_ID,
    EVENT_HEADER_FLAG_64_BIT_HEADER,
    EVENT_RECORD,
    EVENT_TRACE_CONTROL_STOP,
    EVENT_TRACE_LOGFILEW,
    EVENT_TRACE_PROPERTIES,
    EVENT_TRACE_REAL_TIME_MODE,
    MAX_EVENT_FILTER_EVENT_ID_COUNT,
    PROCESSTRACE_HANDLE,
    PROCESS_TRACE_MODE_EVENT_RECORD,
    PROCESS_TRACE_MODE_REAL_TIME,
    PROPERTY_DATA_DESCRIPTOR,
    PROVIDER_ENUMERATION_INFO,
    TDH_INTYPE_ANSISTRING,
    TDH_INTYPE_BOOLEAN,
    TDH_INTYPE_DOUBLE,
    TDH_INTYPE_FILETIME,
    TDH_INTYPE_FLOAT,
    TDH_INTYPE_GUID,
    TDH_INTYPE_HEXINT32,
    TDH_INTYPE_HEXINT64,
    TDH_INTYPE_INT16,
    TDH_INTYPE_INT32,
    TDH_INTYPE_INT64,
    TDH_INTYPE_INT8,
    TDH_INTYPE_POINTER,
    TDH_INTYPE_SID,
    TDH_INTYPE_SIZET,
    TDH_INTYPE_SYSTEMTIME,
    TDH_INTYPE_UINT16,
    TDH_INTYPE_UINT32,
    TDH_INTYPE_UINT64,
    TDH_INTYPE_UINT8,
    TDH_INTYPE_UNICODESTRING,
    TRACE_EVENT_INFO,
    TRACE_LEVEL_CRITICAL,
    TRACE_LEVEL_ERROR,
    TRACE_LEVEL_INFORMATION,
    TRACE_LEVEL_NONE,
    TRACE_LEVEL_VERBOSE,
    TRACE_LEVEL_WARNING,
    WNODE_FLAG_TRACED_GUID,
};

/// Value returned by `OpenTrace` on failure and used to mean "no trace handle".
const INVALID_PROCESSTRACE_HANDLE: u64 = u64::MAX;

/// Signals the running trace to stop (set by the Ctrl+C handler).
static STOPPED: AtomicBool = AtomicBool::new(false);
/// The active `ProcessTrace` handle, shared with the Ctrl+C handler.
static TRACE_HANDLE: AtomicU64 = AtomicU64::new(INVALID_PROCESSTRACE_HANDLE);

/// Configuration for an ETW listener session.
///
/// # Example
/// ```no_run
/// use proxy_agent_shared::windows_events::etw_listener::EtwListener;
/// use windows_sys::Win32::System::Diagnostics::Etw::TRACE_LEVEL_VERBOSE;
///
/// let mut listener = EtwListener::new("my_session");
/// listener.add_provider("Microsoft-Windows-Kernel-Process", TRACE_LEVEL_VERBOSE as u8).unwrap();
/// listener.run().unwrap(); // blocks until process stopped.
/// ```
pub struct EtwListener {
    session_name: String,
    providers: Vec<EtwProvider>,
}

#[derive(Clone)]
struct EtwProvider {
    provider_id: GUID,
    event_ids: Vec<u16>,
    level: u8,
}

impl EtwListener {
    /// Creates a new listener with the specified session name and verbose level.
    pub fn new(name: &str) -> Self {
        EtwListener {
            session_name: name.to_string(),
            providers: Vec::new(),
        }
    }

    /// Adds a provider specified as a GUID string or a registered provider name.
    pub fn add_provider(&mut self, provider_id: &str, max_level: u8) -> Result<()> {
        if let Some(provider_guid) = parse_guid_string(provider_id) {
            self.providers.push(EtwProvider {
                provider_id: provider_guid,
                level: max_level,
                event_ids: Vec::new(),
            });
            return Ok(());
        }
        if let Some(provider_guid) = resolve_provider_name(provider_id) {
            self.providers.push(EtwProvider {
                provider_id: provider_guid,
                level: max_level,
                event_ids: Vec::new(),
            });
            return Ok(());
        }
        Err(Error::WindowsApi(
            format!("'{provider_id}' is not a valid GUID and was not found as a registered provider name"),
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "unknown provider"),
        ))
    }

    /// Adds a provider specified as a GUID string or a registered provider name,
    /// limited to the given event IDs.
    pub fn add_provider_by_event_ids(
        &mut self,
        provider_id: &str,
        max_level: u8,
        event_ids: Vec<u16>,
    ) -> Result<()> {
        if let Some(provider_guid) = parse_guid_string(provider_id) {
            self.providers.push(EtwProvider {
                provider_id: provider_guid,
                level: max_level,
                event_ids,
            });
            return Ok(());
        }
        if let Some(provider_guid) = resolve_provider_name(provider_id) {
            self.providers.push(EtwProvider {
                provider_id: provider_guid,
                level: max_level,
                event_ids,
            });
            return Ok(());
        }
        Err(Error::WindowsApi(
            format!("'{provider_id}' is not a valid GUID and was not found as a registered provider name"),
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "unknown provider"),
        ))
    }

    /// Starts the trace session, enables the providers, and processing
    /// events until [`stop`] is called, forwarding each decoded event to the
    /// telemetry event logger.
    pub fn run(&self) -> Result<()> {
        self.run_with_handler(|event| {
            crate::telemetry::event_logger::push_windows_event(event);
        })?; // Propagate any error
        Ok(())
    }

    /// Like [`EtwListener::run`], but delivers each decoded [`WindowsEvent`] to the
    /// supplied `handler` instead of the telemetry logger. Blocks until
    /// [`stop`] is called. The handler runs on the ETW consumer thread, so it
    /// must be `Send + Sync`.
    pub fn run_with_handler<F>(&self, handler: F) -> Result<()>
    where
        F: Fn(WindowsEvent) + Send + Sync + 'static,
    {
        let providers = self.providers.clone();
        if providers.is_empty() {
            return Err(Error::InvalidInput("No providers specified".to_string()));
        }

        STOPPED.store(false, Ordering::SeqCst);
        TRACE_HANDLE.store(INVALID_PROCESSTRACE_HANDLE, Ordering::SeqCst);

        let session_name = self.session_name.clone();

        // `run_trace` blocks on `ProcessTrace` for the lifetime of the session,
        // so run it on a dedicated OS thread.
        // Note: do not use tokio::spawn because the async block runs on a tokio worker thread. 
        // Since run_trace blocks without ever yielding, it monopolizes that worker thread for the whole session.
        // Tokio's worker pool is small (roughly one per core), so, it permanently removes a worker from the pool,
        //  starving other async tasks and risking degradation/deadlock.
        // This is exactly the "don't block the async runtime" anti-pattern.
        std::thread::spawn(move || {
            let handler: EtwEventHandler = Box::new(handler);
            if let Err(e) = run_trace(&session_name, &providers, &handler) {
                logger_manager::write_warn(format!("ETW trace ended with error: {e}"));
            }
        });

        Ok(())
    }
}

/// Boxed callback invoked with each decoded real-time ETW event.
type EtwEventHandler = Box<dyn Fn(WindowsEvent) + Send + Sync + 'static>;

pub fn stop() {
    STOPPED.store(true, Ordering::SeqCst);
    let handle = TRACE_HANDLE.load(Ordering::SeqCst);
    if handle != INVALID_PROCESSTRACE_HANDLE {
        unsafe {
            CloseTrace(PROCESSTRACE_HANDLE { Value: handle });
        }
    }
}

/// Runs the full trace lifecycle: start session, enable providers, open and
/// process the real-time trace, then clean up. Each decoded event is delivered
/// to `handler`, whose address is passed to ETW via the log file `Context` and
/// recovered in the callback from `EVENT_RECORD.UserContext`. `handler` must
/// outlive this call (it does: this function blocks until the trace stops).
fn run_trace(
    session_name: &str,
    providers: &[EtwProvider],
    handler: &EtwEventHandler,
) -> Result<()> {
    let name_wide = super::to_wide(session_name);
    // Allocate session properties: EVENT_TRACE_PROPERTIES followed by room for
    // the session name. Backed by a Vec<u64> to guarantee 8-byte alignment.
    let props_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
    let total_size = props_size + name_wide.len() * std::mem::size_of::<u16>();
    let mut buffer: Vec<u64> = vec![0u64; total_size.div_ceil(std::mem::size_of::<u64>())];
    let props = buffer.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;

    // Stop any stale session left over from a previous crash.
    unsafe {
        (*props).Wnode.BufferSize = total_size as u32;
        (*props).LoggerNameOffset = props_size as u32;
        ControlTraceW(
            CONTROLTRACE_HANDLE { Value: 0 },
            name_wide.as_ptr(),
            props,
            EVENT_TRACE_CONTROL_STOP,
        );
    }

    // Configure and start the new real-time session.
    let mut session_handle = CONTROLTRACE_HANDLE { Value: 0 };
    let status = unsafe {
        std::ptr::write_bytes(buffer.as_mut_ptr(), 0, buffer.len());
        (*props).Wnode.BufferSize = total_size as u32;
        (*props).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        (*props).Wnode.ClientContext = 1; // QPC clock resolution
        (*props).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        (*props).LoggerNameOffset = props_size as u32;
        (*props).FlushTimer = 1; // 1-second flush for low latency
        StartTraceW(&mut session_handle, name_wide.as_ptr(), props)
    };
    if status != ERROR_SUCCESS {
        return Err(Error::WindowsApi(
            "StartTraceW".to_string(),
            std::io::Error::from_raw_os_error(status as i32),
        ));
    }
    logger_manager::write_info(format!("Trace session \"{session_name}\" started."));

    // Enable each provider.
    for provider in providers {
        // Optionally build an event-ID scope filter. The backing buffer and the
        // filter/param structs must stay alive until EnableTraceEx2 returns, so
        // they are declared here and referenced by `enable_params`.
        let id_filter_buf = build_event_id_filter(&provider.event_ids);
        let mut filter_desc: EVENT_FILTER_DESCRIPTOR = unsafe { std::mem::zeroed() };
        let mut params: ENABLE_TRACE_PARAMETERS = unsafe { std::mem::zeroed() };
        let enable_params: *const ENABLE_TRACE_PARAMETERS = if let Some(buf) = &id_filter_buf {
            filter_desc.Ptr = buf.as_ptr() as u64;
            filter_desc.Size = buf.len() as u32;
            filter_desc.Type = EVENT_FILTER_TYPE_EVENT_ID;
            params.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
            params.EnableFilterDesc = &mut filter_desc;
            params.FilterDescCount = 1;
            &params
        } else {
            std::ptr::null()
        };

        let status = unsafe {
            EnableTraceEx2(
                session_handle,
                &provider.provider_id,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                provider.level,
                0xFFFF_FFFF_FFFF_FFFF, // MatchAnyKeyword - capture all
                0,                     // MatchAllKeyword
                0,                     // Timeout
                enable_params,         // event-ID scope filter, if any
            )
        };
        if status != ERROR_SUCCESS {
            let provider_id = format_guid(&provider.provider_id);
            logger_manager::write_warn(format!(
                "Warning: EnableTraceEx2 failed for provider '{provider_id}' (error {status})"
            ));
        }
    }
    logger_manager::write_info(format!(
        "Enabled {} provider(s). Listening...",
        providers.len()
    ));

    // Process events until `stop()` sets `STOPPED`. `ProcessTrace` blocks until
    // the trace handle is closed (by `stop()`) or it returns for some other
    // reason. A `ProcessTrace` handle can't be reused once it returns, so if it
    // ends unexpectedly while we haven't been asked to stop, we log the status,
    // close the handle, reopen the trace, and keep listening. This keeps a
    // transient failure from tearing the whole listener down.
    while !STOPPED.load(Ordering::SeqCst) {
        // Open the trace for real-time consumption.
        let mut log_file: EVENT_TRACE_LOGFILEW = unsafe { std::mem::zeroed() };
        log_file.LoggerName = name_wide.as_ptr() as *mut u16;
        log_file.Anonymous1.ProcessTraceMode =
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        log_file.Anonymous2.EventRecordCallback = Some(event_record_callback);
        // ETW copies this into each event's `UserContext`, letting the callback
        // reach the caller's handler without a global.
        log_file.Context = handler as *const EtwEventHandler as *mut c_void;

        let trace_handle = unsafe { OpenTraceW(&mut log_file) };
        if trace_handle.Value == INVALID_PROCESSTRACE_HANDLE {
            let open_err = std::io::Error::last_os_error();
            cleanup(session_handle, providers, props, total_size, &name_wide);
            return Err(Error::WindowsApi("OpenTraceW".to_string(), open_err));
        }
        TRACE_HANDLE.store(trace_handle.Value, Ordering::SeqCst);

        // `stop()` may have run between the loop check and storing the handle.
        if STOPPED.load(Ordering::SeqCst) {
            unsafe { CloseTrace(trace_handle) };
            break;
        }

        // Block and process events.
        let handles = [trace_handle];
        let status =
            unsafe { ProcessTrace(handles.as_ptr(), 1, std::ptr::null(), std::ptr::null()) };

        if STOPPED.load(Ordering::SeqCst) {
            // `stop()` already closed the handle; we're done.
            break;
        }

        // ProcessTrace returned on its own (not via `stop()`). Log any real
        // error, close this handle, and loop to reopen and keep listening.
        // ERROR_CANCELLED (1223) and ERROR_CTX_CLOSE_PENDING (7007) are benign.
        if status != ERROR_SUCCESS && status != 1223 && status != 7007 {
            logger_manager::write_warn(format!(
                "ProcessTrace returned {status}; reopening trace to continue."
            ));
        }
        TRACE_HANDLE.store(INVALID_PROCESSTRACE_HANDLE, Ordering::SeqCst);
        unsafe { CloseTrace(trace_handle) };

        // Avoid a tight spin if ProcessTrace keeps returning immediately.
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    cleanup(session_handle, providers, props, total_size, &name_wide);
    logger_manager::write_info("Session stopped.".to_string());
    Ok(())
}

/// Builds a packed `EVENT_FILTER_EVENT_ID` buffer for an event-ID scope filter,
/// or `None` when `ids` is empty. The list is capped at the ETW maximum of 64
/// IDs. `FilterIn` is set to TRUE so only the listed event IDs are delivered.
///
/// The returned `Vec<u8>` is the variable-length filter payload; its address is
/// passed to ETW via `EVENT_FILTER_DESCRIPTOR.Ptr`, so it must outlive the
/// `EnableTraceEx2` call.
fn build_event_id_filter(ids: &[u16]) -> Option<Vec<u8>> {
    if ids.is_empty() {
        return None;
    }
    let count = ids.len().min(MAX_EVENT_FILTER_EVENT_ID_COUNT as usize);
    // `EVENT_FILTER_EVENT_ID` already includes room for one ID (`Events: [u16; 1]`),
    // so add space for the remaining `count - 1` IDs.
    let total =
        std::mem::size_of::<EVENT_FILTER_EVENT_ID>() + (count - 1) * std::mem::size_of::<u16>();
    let mut buf = vec![0u8; total];
    unsafe {
        let filter = buf.as_mut_ptr() as *mut EVENT_FILTER_EVENT_ID;
        (*filter).FilterIn = 1; // TRUE: deliver only these event IDs
        (*filter).Reserved = 0;
        (*filter).Count = count as u16;
        // Write the IDs into the inline (over-allocated) `Events` array.
        let events = std::ptr::addr_of_mut!((*filter).Events) as *mut u16;
        for (i, id) in ids.iter().take(count).enumerate() {
            events.add(i).write(*id);
        }
    }
    Some(buf)
}

/// Disables providers and stops the trace session.
fn cleanup(
    session_handle: CONTROLTRACE_HANDLE,
    providers: &[EtwProvider],
    props: *mut EVENT_TRACE_PROPERTIES,
    total_size: usize,
    name_wide: &[u16],
) {
    unsafe {
        for provider in providers {
            EnableTraceEx2(
                session_handle,
                &provider.provider_id,
                EVENT_CONTROL_CODE_DISABLE_PROVIDER,
                0,
                0,
                0,
                0,
                std::ptr::null(),
            );
        }

        std::ptr::write_bytes(props as *mut u8, 0, total_size);
        (*props).Wnode.BufferSize = total_size as u32;
        (*props).LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
        ControlTraceW(
            session_handle,
            name_wide.as_ptr(),
            props,
            EVENT_TRACE_CONTROL_STOP,
        );
    }
}

/// ETW event callback: decodes each event and hands it to the caller's handler
/// (recovered from `EVENT_RECORD.UserContext`).
unsafe extern "system" fn event_record_callback(event: *mut EVENT_RECORD) {
    if STOPPED.load(Ordering::SeqCst) || event.is_null() {
        return;
    }

    // Guard against panics crossing the FFI boundary.
    let _ = std::panic::catch_unwind(|| {
        let record = &*event;
        let ctx = record.UserContext;
        if ctx.is_null() {
            return;
        }
        let handler = &*(ctx as *const EtwEventHandler);
        let etw_event = decode_event(record);
        handler(etw_event);
    });
}

/// Builds the decoded event for a single ETW event record.
unsafe fn decode_event(event: &EVENT_RECORD) -> WindowsEvent {
    let header = &event.EventHeader;
    let pointer_size: u32 = if header.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER as u16 != 0 {
        8
    } else {
        4
    };

    let mut etw_event = WindowsEvent {
        provider: format_guid(&header.ProviderId),
        event_id: header.EventDescriptor.Id,
        version: header.EventDescriptor.Version,
        level: header.EventDescriptor.Level,
        opcode: header.EventDescriptor.Opcode,
        keyword: header.EventDescriptor.Keyword,
        timestamp: format_filetime(header.TimeStamp),
        process_id: header.ProcessId,
        thread_id: header.ThreadId,
        activity_id: format_guid(&header.ActivityId),
        provider_name: None,
        task_name: None,
        event_name: None,
        formatted_message: None,
        properties: None,
        user_data: None,
    };

    // Decode the event schema via TDH.
    let mut buffer_size: u32 = 0;
    let status = TdhGetEventInformation(
        event,
        0,
        std::ptr::null(),
        std::ptr::null_mut(),
        &mut buffer_size,
    );
    let mut info_buf: Vec<u8> = Vec::new();
    let mut p_info: *const TRACE_EVENT_INFO = std::ptr::null();
    if status == ERROR_INSUFFICIENT_BUFFER && buffer_size > 0 {
        info_buf = vec![0u8; buffer_size as usize];
        let status = TdhGetEventInformation(
            event,
            0,
            std::ptr::null(),
            info_buf.as_mut_ptr() as *mut TRACE_EVENT_INFO,
            &mut buffer_size,
        );
        if status == ERROR_SUCCESS {
            p_info = info_buf.as_ptr() as *const TRACE_EVENT_INFO;
        }
    }

    if !p_info.is_null() {
        let base = info_buf.as_ptr();
        let info = &*p_info;

        etw_event.provider_name = wide_string_at_offset(base, info.ProviderNameOffset);
        etw_event.task_name = wide_string_at_offset(base, info.TaskNameOffset);
        etw_event.event_name = wide_string_at_offset(base, info.Anonymous1.EventNameOffset);

        // Decode top-level properties. `ordered_args` holds the string form of
        // each property in declaration order so the manifest message template
        // can substitute `%1`, `%2`, ... below. Skipped/failed properties push
        // an empty placeholder to keep the `%N` indices aligned.
        let mut ordered_args: Vec<String> = Vec::new();
        if info.TopLevelPropertyCount > 0 {
            let mut props = Map::new();
            ordered_args.reserve(info.TopLevelPropertyCount as usize);
            let prop_array = info.EventPropertyInfoArray.as_ptr();
            for i in 0..info.TopLevelPropertyCount as usize {
                let p_prop = &*prop_array.add(i);

                // Skip struct properties.
                if p_prop.Flags & PropertyStruct != 0 {
                    ordered_args.push(String::new());
                    continue;
                }

                let prop_name_ptr = base.add(p_prop.NameOffset as usize) as *const u16;
                let prop_name = read_wide_string(prop_name_ptr);
                let in_type = p_prop.Anonymous1.nonStructType.InType;

                let desc = PROPERTY_DATA_DESCRIPTOR {
                    PropertyName: prop_name_ptr as u64,
                    ArrayIndex: u32::MAX,
                    Reserved: 0,
                };

                let mut prop_size: u32 = 0;
                let status =
                    TdhGetPropertySize(event, 0, std::ptr::null(), 1, &desc, &mut prop_size);
                if status != ERROR_SUCCESS || prop_size == 0 {
                    ordered_args.push(String::new());
                    continue;
                }

                let mut prop_buf = vec![0u8; prop_size as usize];
                let status = TdhGetProperty(
                    event,
                    0,
                    std::ptr::null(),
                    1,
                    &desc,
                    prop_size,
                    prop_buf.as_mut_ptr(),
                );
                if status == ERROR_SUCCESS {
                    let value = emit_property_value(in_type, &prop_buf, pointer_size);
                    ordered_args.push(value_to_display(&value));
                    props.insert(prop_name, value);
                } else {
                    ordered_args.push(String::new());
                }
            }
            etw_event.properties = Some(props);
        }

        // Human-readable message from the manifest template, if any.
        if let Some(template) = wide_string_at_offset(base, info.EventMessageOffset) {
            etw_event.formatted_message = Some(format_event_message(&template, &ordered_args));
        }
    } else if event.UserDataLength > 0 && !event.UserData.is_null() {
        // No TDH schema available - emit raw payload as hex.
        let data =
            std::slice::from_raw_parts(event.UserData as *const u8, event.UserDataLength as usize);
        etw_event.user_data = Some(hex_upper(data));
    }

    etw_event
}

/// Decodes a single property value into a JSON value based on its TDH in-type.
fn emit_property_value(in_type: u16, data: &[u8], pointer_size: u32) -> Value {
    if data.is_empty() {
        return Value::Null;
    }
    let in_type = in_type as i32;

    match in_type {
        TDH_INTYPE_UNICODESTRING => Value::String(decode_utf16(data)),
        TDH_INTYPE_ANSISTRING => {
            let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
            Value::String(String::from_utf8_lossy(&data[..end]).into_owned())
        }
        TDH_INTYPE_INT8 => read_int::<1>(data).map_or(Value::Null, |b| Value::from(b[0] as i8)),
        TDH_INTYPE_UINT8 => Value::from(data[0]),
        TDH_INTYPE_INT16 => {
            read_int::<2>(data).map_or(Value::Null, |b| Value::from(i16::from_le_bytes(b)))
        }
        TDH_INTYPE_UINT16 => {
            read_int::<2>(data).map_or(Value::Null, |b| Value::from(u16::from_le_bytes(b)))
        }
        TDH_INTYPE_INT32 => {
            read_int::<4>(data).map_or(Value::Null, |b| Value::from(i32::from_le_bytes(b)))
        }
        TDH_INTYPE_UINT32 => {
            read_int::<4>(data).map_or(Value::Null, |b| Value::from(u32::from_le_bytes(b)))
        }
        TDH_INTYPE_HEXINT32 => read_int::<4>(data).map_or(Value::Null, |b| {
            Value::String(format!("0x{:08X}", u32::from_le_bytes(b)))
        }),
        TDH_INTYPE_INT64 => {
            read_int::<8>(data).map_or(Value::Null, |b| Value::from(i64::from_le_bytes(b)))
        }
        TDH_INTYPE_UINT64 => {
            read_int::<8>(data).map_or(Value::Null, |b| Value::from(u64::from_le_bytes(b)))
        }
        TDH_INTYPE_HEXINT64 => read_int::<8>(data).map_or(Value::Null, |b| {
            Value::String(format!("0x{:016X}", u64::from_le_bytes(b)))
        }),
        TDH_INTYPE_FLOAT => {
            read_int::<4>(data).map_or(Value::Null, |b| Value::from(f32::from_le_bytes(b) as f64))
        }
        TDH_INTYPE_DOUBLE => {
            read_int::<8>(data).map_or(Value::Null, |b| Value::from(f64::from_le_bytes(b)))
        }
        TDH_INTYPE_BOOLEAN => {
            if data.len() >= 4 {
                Value::Bool(u32::from_le_bytes([data[0], data[1], data[2], data[3]]) != 0)
            } else {
                Value::Bool(data[0] != 0)
            }
        }
        TDH_INTYPE_GUID => {
            if data.len() >= std::mem::size_of::<GUID>() {
                // Safety: length checked above; GUID is repr(C) and Copy.
                let guid = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const GUID) };
                Value::String(format_guid(&guid))
            } else {
                Value::String(hex_upper(data))
            }
        }
        TDH_INTYPE_POINTER | TDH_INTYPE_SIZET => {
            if pointer_size == 8 {
                read_int::<8>(data).map_or(Value::Null, |b| {
                    Value::String(format!("0x{:X}", u64::from_le_bytes(b)))
                })
            } else {
                read_int::<4>(data).map_or(Value::Null, |b| {
                    Value::String(format!("0x{:X}", u32::from_le_bytes(b)))
                })
            }
        }
        TDH_INTYPE_FILETIME => read_int::<8>(data).map_or_else(
            || Value::String(hex_upper(data)),
            |b| Value::String(format_filetime(i64::from_le_bytes(b))),
        ),
        TDH_INTYPE_SYSTEMTIME => format_systemtime(data),
        TDH_INTYPE_SID => format_sid(data),
        _ => Value::String(hex_upper(data)),
    }
}

/// Renders a decoded property value as the plain string used for message
/// substitution (no surrounding quotes for strings).
fn value_to_display(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Substitutes a provider manifest message `template` using `args` (1-based
/// `%N` placeholders). Handles `%%` (literal percent) and an optional
/// FormatMessage width/format spec of the form `%N!printf!`, which is ignored.
fn format_event_message(template: &str, args: &[String]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.peek() {
            Some('%') => {
                out.push('%');
                chars.next();
            }
            Some(d) if d.is_ascii_digit() => {
                let mut num = String::new();
                while let Some(d) = chars.peek() {
                    if d.is_ascii_digit() {
                        num.push(*d);
                        chars.next();
                    } else {
                        break;
                    }
                }
                // Skip an optional `!printf-format!` spec after the index.
                if chars.peek() == Some(&'!') {
                    chars.next();
                    for ch in chars.by_ref() {
                        if ch == '!' {
                            break;
                        }
                    }
                }
                if let Ok(idx) = num.parse::<usize>() {
                    if idx >= 1 && idx <= args.len() {
                        out.push_str(&args[idx - 1]);
                    }
                }
            }
            // Other `%x` escapes: drop the `%` and keep the next char (e.g. `%!`, `%.`).
            Some(_) => {
                let next = chars.next().unwrap();
                out.push(next);
            }
            // Trailing lone `%`.
            None => out.push('%'),
        }
    }
    out
}

/// Returns a fixed-size array from the front of `data`, or `None` if too short.
fn read_int<const N: usize>(data: &[u8]) -> Option<[u8; N]> {
    data.get(..N).map(|s| {
        let mut b = [0u8; N];
        b.copy_from_slice(s);
        b
    })
}

/// Formats a GUID as an upper-case `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX` string.
fn format_guid(g: &GUID) -> String {
    format!(
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        g.data1,
        g.data2,
        g.data3,
        g.data4[0],
        g.data4[1],
        g.data4[2],
        g.data4[3],
        g.data4[4],
        g.data4[5],
        g.data4[6],
        g.data4[7],
    )
}

/// Converts a Windows FILETIME (100ns intervals since 1601-01-01 UTC) to an
/// ISO-8601 JSON string. Falls back to a numeric value if out of range.
fn format_filetime(filetime: i64) -> String {
    // 116444736000000000 = 100ns intervals between 1601-01-01 and 1970-01-01.
    const EPOCH_DIFF_100NS: i64 = 116_444_736_000_000_000;
    let unix_100ns = filetime - EPOCH_DIFF_100NS;
    let secs = unix_100ns.div_euclid(10_000_000);
    let nanos = (unix_100ns.rem_euclid(10_000_000) * 100) as u32;
    match chrono::DateTime::from_timestamp(secs, nanos) {
        Some(dt) => dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
        None => filetime.to_string(),
    }
}

/// Formats a Windows SYSTEMTIME (16 bytes, 8 u16 fields) as an ISO-8601 string.
fn format_systemtime(data: &[u8]) -> Value {
    if data.len() < 16 {
        return Value::String(hex_upper(data));
    }
    let field = |i: usize| u16::from_le_bytes([data[i * 2], data[i * 2 + 1]]);
    // Fields: wYear, wMonth, wDayOfWeek, wDay, wHour, wMinute, wSecond, wMilliseconds
    Value::String(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        field(0),
        field(1),
        field(3),
        field(4),
        field(5),
        field(6),
        field(7),
    ))
}

/// Formats a SID payload as an `S-...` string, falling back to hex.
fn format_sid(data: &[u8]) -> Value {
    unsafe {
        let psid = data.as_ptr() as *mut std::ffi::c_void;
        if IsValidSid(psid) != 0 {
            let mut string_sid: *mut u16 = std::ptr::null_mut();
            if ConvertSidToStringSidW(psid, &mut string_sid) != 0 && !string_sid.is_null() {
                let s = read_wide_string(string_sid);
                windows_sys::Win32::Foundation::LocalFree(string_sid as *mut std::ffi::c_void);
                return Value::String(s);
            }
        }
    }
    Value::String(hex_upper(data))
}

/// Decodes a UTF-16LE byte buffer (possibly null-terminated) into a `String`.
fn decode_utf16(data: &[u8]) -> String {
    let units: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

/// Reads a null-terminated wide (UTF-16) string from a raw pointer.
///
/// # Safety
/// `ptr` must point to a valid, null-terminated UTF-16 string.
unsafe fn read_wide_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    let slice = std::slice::from_raw_parts(ptr, len);
    String::from_utf16_lossy(slice)
}

/// Reads a null-terminated wide string at `offset` bytes from `base`.
/// Returns `None` when the offset is zero (meaning "not present").
///
/// # Safety
/// `base + offset` must point at a valid null-terminated UTF-16 string.
unsafe fn wide_string_at_offset(base: *const u8, offset: u32) -> Option<String> {
    if offset == 0 {
        return None;
    }
    let ptr = base.add(offset as usize) as *const u16;
    Some(read_wide_string(ptr))
}

/// Hex-encodes bytes as an upper-case string (e.g. `1AFF`).
fn hex_upper(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push_str(&format!("{b:02X}"));
    }
    s
}

/// Parses a GUID string in `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` form
/// (braces optional). Returns `None` if the string is not a valid GUID.
pub fn parse_guid_string(s: &str) -> Option<GUID> {
    let s = s.trim();
    let s = s.strip_prefix('{').unwrap_or(s);
    let s = s.strip_suffix('}').unwrap_or(s);

    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 5
        || parts[0].len() != 8
        || parts[1].len() != 4
        || parts[2].len() != 4
        || parts[3].len() != 4
        || parts[4].len() != 12
    {
        return None;
    }

    let data1 = u32::from_str_radix(parts[0], 16).ok()?;
    let data2 = u16::from_str_radix(parts[1], 16).ok()?;
    let data3 = u16::from_str_radix(parts[2], 16).ok()?;

    let mut data4 = [0u8; 8];
    let tail = format!("{}{}", parts[3], parts[4]); // 16 hex chars
    for (i, byte) in data4.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&tail[i * 2..i * 2 + 2], 16).ok()?;
    }

    Some(GUID {
        data1,
        data2,
        data3,
        data4,
    })
}

/// Resolves a registered provider name to its GUID using `TdhEnumerateProviders`.
pub fn resolve_provider_name(name: &str) -> Option<GUID> {
    unsafe {
        let mut buf_size: u32 = 0;
        let status = TdhEnumerateProviders(std::ptr::null_mut(), &mut buf_size);
        if status != ERROR_INSUFFICIENT_BUFFER || buf_size == 0 {
            return None;
        }

        let mut buffer = vec![0u8; buf_size as usize];
        let p_enum = buffer.as_mut_ptr() as *mut PROVIDER_ENUMERATION_INFO;
        let status = TdhEnumerateProviders(p_enum, &mut buf_size);
        if status != ERROR_SUCCESS {
            return None;
        }

        let base = buffer.as_ptr();
        let enum_info = &*p_enum;
        let array = enum_info.TraceProviderInfoArray.as_ptr();
        for i in 0..enum_info.NumberOfProviders as usize {
            let info = &*array.add(i);
            let prov_name_ptr = base.add(info.ProviderNameOffset as usize) as *const u16;
            let prov_name = read_wide_string(prov_name_ptr);
            if prov_name.eq_ignore_ascii_case(name) {
                return Some(info.ProviderGuid);
            }
        }
    }
    None
}

/// Parses a textual trace level (name or `0`-`5`) into an ETW level byte.
/// Defaults to verbose for unknown input.
pub fn parse_level(s: &str) -> u8 {
    let level = match s.to_ascii_lowercase().as_str() {
        "critical" => TRACE_LEVEL_CRITICAL,
        "error" => TRACE_LEVEL_ERROR,
        "warning" => TRACE_LEVEL_WARNING,
        "info" => TRACE_LEVEL_INFORMATION,
        "verbose" => TRACE_LEVEL_VERBOSE,
        "none" => TRACE_LEVEL_NONE,
        other => match other.parse::<u8>() {
            Ok(n) if n <= 5 => n as u32,
            _ => {
                eprintln!("Warning: unknown level '{s}', defaulting to verbose.");
                TRACE_LEVEL_VERBOSE
            }
        },
    };
    level as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_guid_with_braces() {
        let guid = parse_guid_string("{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}").unwrap();
        assert_eq!(guid.data1, 0x22FB_2CD6);
        assert_eq!(guid.data2, 0x0E7B);
        assert_eq!(guid.data3, 0x422B);
        assert_eq!(guid.data4, [0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16]);
    }

    #[test]
    fn parse_guid_without_braces() {
        let guid = parse_guid_string("EDD08927-9CC4-4E65-B970-C2560FB5C289").unwrap();
        assert_eq!(guid.data1, 0xEDD0_8927);
        assert_eq!(guid.data4[7], 0x89);
    }

    #[test]
    fn parse_guid_rejects_invalid() {
        assert!(parse_guid_string("not-a-guid").is_none());
        assert!(parse_guid_string("22FB2CD6-0E7B-422B-A0C7").is_none());
        assert!(parse_guid_string("Microsoft-Windows-Kernel-Process").is_none());
    }

    #[test]
    fn format_guid_round_trip() {
        let guid = parse_guid_string("22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716").unwrap();
        assert_eq!(
            format_guid(&guid),
            "22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716".to_string()
        );
    }

    #[test]
    fn parse_level_values() {
        assert_eq!(parse_level("critical"), 1);
        assert_eq!(parse_level("ERROR"), 2);
        assert_eq!(parse_level("warning"), 3);
        assert_eq!(parse_level("info"), 4);
        assert_eq!(parse_level("verbose"), 5);
        assert_eq!(parse_level("none"), 0);
        assert_eq!(parse_level("3"), 3);
        assert_eq!(parse_level("unknown"), 5);
    }

    #[test]
    fn emit_integer_values() {
        assert_eq!(
            emit_property_value(TDH_INTYPE_UINT32 as u16, &7u32.to_le_bytes(), 8),
            Value::from(7u32)
        );
        assert_eq!(
            emit_property_value(TDH_INTYPE_INT16 as u16, &(-3i16).to_le_bytes(), 8),
            Value::from(-3i16)
        );
        assert_eq!(
            emit_property_value(TDH_INTYPE_HEXINT32 as u16, &0xABu32.to_le_bytes(), 8),
            Value::String("0x000000AB".to_string())
        );
    }

    #[test]
    fn emit_unicode_string() {
        let mut bytes = Vec::new();
        for u in "hello".encode_utf16() {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        assert_eq!(
            emit_property_value(TDH_INTYPE_UNICODESTRING as u16, &bytes, 8),
            Value::String("hello".to_string())
        );
    }

    #[test]
    fn format_event_message_substitutes_args() {
        let args = vec!["explorer.exe".to_string(), "1234".to_string()];
        assert_eq!(
            format_event_message("Process %1 started with PID %2.", &args),
            "Process explorer.exe started with PID 1234."
        );
        // Literal percent and an ignored printf-format spec.
        assert_eq!(
            format_event_message("100%% done, id=%1!d!", &args),
            "100% done, id=explorer.exe"
        );
        // Out-of-range index yields empty; unknown args left blank.
        assert_eq!(format_event_message("%3", &args), "");
    }

    #[test]
    fn format_filetime_known_value() {
        // 1601-01-01 + 1 day worth of 100ns = still in range; check unix epoch.
        // FILETIME for 1970-01-01T00:00:00Z is exactly the epoch diff.
        let epoch = 116_444_736_000_000_000i64;
        assert_eq!(
            format_filetime(epoch),
            Value::String("1970-01-01T00:00:00.000Z".to_string())
        );
    }
}
