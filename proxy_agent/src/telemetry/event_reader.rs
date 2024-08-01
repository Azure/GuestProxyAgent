// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
use super::telemetry_event::TelemetryData;
use super::telemetry_event::TelemetryEvent;
use crate::common::constants;
use crate::common::logger;
use crate::host_clients::imds_client::ImdsClient;
use crate::host_clients::wire_server_client::WireServerClient;
use crate::shared_state::shared_state_wrapper;
use crate::shared_state::telemetry_wrapper;
use crate::shared_state::SharedState;
use proxy_agent_shared::misc_helpers;
use proxy_agent_shared::telemetry::event_logger;
use proxy_agent_shared::telemetry::Event;
use std::fs::remove_file;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use thread_priority::ThreadPriority;

#[derive(Clone)]
pub struct VMMetaData {
    pub container_id: String,
    pub tenant_name: String,
    pub role_name: String,
    pub role_instance_name: String,
    pub subscription_id: String,
    pub resource_group_name: String,
    pub vm_id: String,
    pub image_origin: u64,
}

impl VMMetaData {
    fn default() -> Self {
        VMMetaData {
            container_id: constants::EMPTY_GUID.to_string(),
            tenant_name: constants::EMPTY_GUID.to_string(),
            role_name: constants::EMPTY_GUID.to_string(),
            role_instance_name: constants::EMPTY_GUID.to_string(),
            subscription_id: constants::EMPTY_GUID.to_string(),
            resource_group_name: constants::EMPTY_GUID.to_string(),
            vm_id: constants::EMPTY_GUID.to_string(),
            image_origin: 3, // unknown
        }
    }
}

pub fn start_async(
    dir_path: PathBuf,
    interval: Duration,
    delay_start: bool,
    shared_state: Arc<Mutex<SharedState>>,
    verify_thread_priority_test_only: Option<fn(Result<ThreadPriority, thread_priority::Error>)>, // for test only
) {
    _ = thread::Builder::new()
        .name("event_reader".to_string())
        .spawn(move || {
            let runtime = shared_state_wrapper::get_runtime(shared_state.clone());
            match runtime {
                Some(rt) => {
                    let _ = rt.lock().unwrap().block_on(async move {
                        tokio::spawn(start(
                            dir_path,
                            Some(interval),
                            delay_start,
                            shared_state,
                            verify_thread_priority_test_only,
                        ))
                        .await
                    });
                }
                None => {
                    let message = "Failed to get runtime.".to_string();
                    logger::write_error(message);
                }
            }
        });
}

async fn start(
    dir_path: PathBuf,
    interval: Option<Duration>,
    delay_start: bool,
    shared_state: Arc<Mutex<SharedState>>,
    verify_thread_priority_test_only: Option<fn(Result<ThreadPriority, thread_priority::Error>)>, // for test only
) {
    logger::write("telemetry event reader thread started.".to_string());

    let interval = interval.unwrap_or(Duration::from_secs(300));
    let mut first = true;

    loop {
        if telemetry_wrapper::get_reader_shutdown(shared_state.clone()) {
            logger::write_warning(
                "Stop signal received, closing event telemetry thread.".to_string(),
            );
            break;
        }

        if first {
            if delay_start {
                // delay start the event_reader thread to give additional CPU cycles to more important threads
                tokio::time::sleep(Duration::from_secs(60)).await;
            }

            match thread_priority::set_current_thread_priority(ThreadPriority::Min) {
                Ok(_) => {
                    if let Some(verify_thread_priority) = verify_thread_priority_test_only {
                        verify_thread_priority(thread_priority::get_current_thread_priority());
                    }
                    logger::write(
                        "Successfully set the event_reader thread priority to min.".to_string(),
                    );
                }
                Err(_) => {
                    logger::write_warning(
                        "Failed to set the event_reader thread priority to min with error."
                            .to_string(),
                    );
                }
            }
            first = false;
        }

        // refresh vm metadata
        match update_vm_meta_data(shared_state.clone()).await {
            Ok(()) => {
                logger::write("success updated the vm metadata.".to_string());
            }
            Err(e) => {
                logger::write_warning(format!("Failed to read vm metadata with error {}.", e));
            }
        }

        if telemetry_wrapper::get_vm_metadata(shared_state.clone()).is_some() {
            // vm metadata is updated, process events
            match misc_helpers::get_files(&dir_path) {
                Ok(files) => {
                    let file_count = files.len();
                    let event_count = process_events_and_clean(files, shared_state.clone()).await;
                    let message = format!("Send {} events from {} files", event_count, file_count);
                    event_logger::write_event(
                        event_logger::INFO_LEVEL,
                        message,
                        "start",
                        "event_reader",
                        logger::AGENT_LOGGER_KEY,
                    )
                }
                Err(e) => {
                    logger::write_warning(format!(
                        "Event Files not found in directory {}: {}",
                        dir_path.display(),
                        e
                    ));
                }
            }
        }
        tokio::time::sleep(interval).await;
    }
}

pub fn stop(shared_state: Arc<Mutex<SharedState>>) {
    telemetry_wrapper::set_reader_shutdown(shared_state.clone(), true);
}

async fn update_vm_meta_data(shared_state: Arc<Mutex<SharedState>>) -> std::io::Result<()> {
    let wire_server_client = WireServerClient::new(
        get_wire_server_ip(shared_state.clone()),
        get_wire_server_port(shared_state.clone()),
        shared_state.clone(),
    );
    let goal_state = wire_server_client.get_goalstate().await?;
    let shared_config = wire_server_client
        .get_shared_config(goal_state.get_shared_config_uri())
        .await?;

    let imds_client = ImdsClient::new(
        get_imds_ip(shared_state.clone()),
        get_imds_port(shared_state.clone()),
        shared_state.clone(),
    );
    let instance_info = imds_client.get_imds_instance_info().await?;
    let vm_meta_data = VMMetaData {
        container_id: goal_state.get_container_id(),
        role_name: shared_config.get_role_name(),
        role_instance_name: shared_config.get_role_instance_name(),
        tenant_name: shared_config.get_deployment_name(),
        subscription_id: instance_info.get_subscription_id(),
        resource_group_name: instance_info.get_resource_group_name(),
        vm_id: instance_info.get_vm_id(),
        image_origin: instance_info.get_image_origin(),
    };
    telemetry_wrapper::set_vm_metadata(shared_state, vm_meta_data);

    Ok(())
}
pub fn get_vm_meta_data(shared_state: Arc<Mutex<SharedState>>) -> VMMetaData {
    match telemetry_wrapper::get_vm_metadata(shared_state) {
        Some(vm_meta_data) => vm_meta_data,
        None => VMMetaData::default(),
    }
}
async fn process_events_and_clean(
    files: Vec<PathBuf>,
    shared_state: Arc<Mutex<SharedState>>,
) -> usize {
    let mut num_events_logged = 0;
    for file in files {
        match misc_helpers::json_read_from_file::<Vec<Event>>(file.to_path_buf()) {
            Ok(events) => {
                num_events_logged += events.len();
                send_events(events, shared_state.clone()).await;
                clean_files(file);
            }
            Err(e) => {
                logger::write_warning(format!(
                    "Failed to read events from file {}: {}",
                    file.display(),
                    e
                ));
                continue;
            }
        }
    }
    num_events_logged
}

const MAX_MESSAGE_SIZE: usize = 1024 * 64;

async fn send_events(mut events: Vec<Event>, shared_state: Arc<Mutex<SharedState>>) {
    while !events.is_empty() {
        let mut telemetry_data = TelemetryData::new();
        let mut add_more_events = true;
        while !events.is_empty() && add_more_events {
            match events.pop() {
                Some(event) => {
                    telemetry_data
                        .add_event(TelemetryEvent::from_event_log(&event, shared_state.clone()));

                    if telemetry_data.get_size() >= MAX_MESSAGE_SIZE {
                        telemetry_data.remove_last_event();
                        if telemetry_data.event_count() == 0 {
                            match serde_json::to_string(&event) {
                                Ok(json) => {
                                    logger::write_warning(format!(
                                        "Event data too large. Not sending to wire-server. Event: {}.",
                                        json
                                    ));
                                }
                                Err(_) => {
                                    logger::write_warning(
                                        "Event data too large. Not sending to wire-server. Event cannot be displayed.".to_string()
                                        );
                                }
                            }
                        } else {
                            events.push(event);
                        }
                        add_more_events = false;
                    }
                }
                None => {
                    break;
                }
            }
        }

        send_data_to_wire_server(telemetry_data, shared_state.clone()).await;
    }
}

fn get_wire_server_ip(shared_state: Arc<Mutex<SharedState>>) -> String {
    match telemetry_wrapper::get_mock_server_ip(shared_state) {
        Some(ip) => ip,
        None => constants::WIRE_SERVER_IP.to_string(),
    }
}
fn get_wire_server_port(shared_state: Arc<Mutex<SharedState>>) -> u16 {
    match telemetry_wrapper::get_mock_server_port(shared_state) {
        Some(port) => port,
        None => constants::WIRE_SERVER_PORT,
    }
}
fn get_imds_ip(shared_state: Arc<Mutex<SharedState>>) -> String {
    match telemetry_wrapper::get_mock_server_ip(shared_state) {
        Some(ip) => ip,
        None => constants::IMDS_IP.to_string(),
    }
}
fn get_imds_port(shared_state: Arc<Mutex<SharedState>>) -> u16 {
    match telemetry_wrapper::get_mock_server_port(shared_state) {
        Some(port) => port,
        None => constants::IMDS_PORT,
    }
}

async fn send_data_to_wire_server(
    telemetry_data: TelemetryData,
    shared_state: Arc<Mutex<SharedState>>,
) {
    if telemetry_data.event_count() == 0 {
        return;
    }

    let wire_server_client = WireServerClient::new(
        get_wire_server_ip(shared_state.clone()),
        get_wire_server_port(shared_state.clone()),
        shared_state.clone(),
    );
    for _ in [0; 5] {
        match wire_server_client
            .send_telemetry_data(telemetry_data.to_xml())
            .await
        {
            Ok(()) => {
                break;
            }
            Err(e) => {
                logger::write_warning(format!(
                    "Failed to send telemetry data to host with error: {}",
                    e
                ));
                // wait 15 seconds and retry
                tokio::time::sleep(Duration::from_secs(15)).await;
            }
        }
    }
}

fn clean_files(file: PathBuf) {
    match remove_file(&file) {
        Ok(_) => {
            logger::write(format!("Removed File: {}", file.display()));
        }
        Err(e) => {
            logger::write_warning(format!("Failed to remove file {}: {}", file.display(), e));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::logger;
    use crate::key_keeper::key::Key;
    use crate::shared_state::key_keeper_wrapper;
    use crate::test_mock::server_mock;
    use proxy_agent_shared::{logger_manager, misc_helpers};
    #[cfg(windows)]
    use std::sync::Mutex;
    use std::{env, fs};
    #[cfg(windows)]
    use thread_priority::ThreadPriorityOsValue;
    #[cfg(windows)]
    use thread_priority::WinAPIThreadPriority;

    #[test]
    #[cfg(windows)]
    fn test_event_reader_thread_priority() {
        use once_cell::sync::Lazy;
        use std::sync::atomic::{AtomicBool, Ordering};

        static THREAD_PRIORITY_VERIFY_DONE: AtomicBool = AtomicBool::new(false);
        static THREAD_PRIORITY_VERIFY_RESULT: Lazy<Arc<Mutex<String>>> =
            Lazy::new(|| Arc::new(Mutex::new(String::from(""))));
        const THREAD_PRIORITY_VERIFY_SUCCESS: &str =
            "EVENT READER THREAD PRIORITY VERIFICATION SUCCEED.";
        let verify_thread_priority_test: Option<
            fn(Result<ThreadPriority, thread_priority::Error>),
        > = Some(
            |thread_priority_result: Result<ThreadPriority, thread_priority::Error>| {
                let mut verify_result_message = String::from("");
                match thread_priority_result {
                    Ok(priority) => {
                        match priority {
                            ThreadPriority::Min => {
                                println!("event reader thread priority is min");
                                verify_result_message.push_str(THREAD_PRIORITY_VERIFY_SUCCESS);
                            }
                            ThreadPriority::Os(priority_os_value) => {
                                println!(
                                    "event reader thread priority is Os with value: {:?}",
                                    priority_os_value
                                );
                                #[cfg(windows)]
                                {
                                    let win_low_priority =
                                        ThreadPriorityOsValue::from(WinAPIThreadPriority::Lowest);
                                    println!(
                                        "Windows Thread Lowest priority value: {:?}",
                                        win_low_priority
                                    );
                                    if priority_os_value == win_low_priority {
                                        verify_result_message
                                            .push_str(THREAD_PRIORITY_VERIFY_SUCCESS);
                                    } else {
                                        verify_result_message.push_str(&format!("Thread priority verify failed, expected value: {:?}, action value: {:?}", win_low_priority, priority_os_value));
                                    }
                                }
                                #[cfg(not(windows))]
                                {
                                    // TODO: add check linux thread priority value
                                }
                            }
                            _ => {
                                verify_result_message.push_str(
                                    "event reader thread priority is not check list: min or Os",
                                );
                            }
                        }
                    }
                    Err(_) => {
                        verify_result_message
                            .push_str("Failed to get event reader thread priority");
                    }
                }
                THREAD_PRIORITY_VERIFY_RESULT
                    .lock()
                    .as_mut()
                    .unwrap()
                    .push_str(&verify_result_message);
                THREAD_PRIORITY_VERIFY_DONE.store(true, Ordering::Relaxed);
            },
        );

        let temp_dir = env::temp_dir();
        let shared_state = SharedState::new();
        key_keeper_wrapper::set_key(shared_state.clone(), Key::empty());
        start_async(
            temp_dir,
            Duration::from_millis(1000),
            false,
            shared_state,
            verify_thread_priority_test,
        );

        let mut wait_milli_sec: i32 = 100;
        while wait_milli_sec <= 500 && !THREAD_PRIORITY_VERIFY_DONE.load(Ordering::Relaxed) {
            println!(
                "waiting {} milliseconds to verify event reader thread priority.",
                wait_milli_sec
            );
            thread::sleep(Duration::from_millis(100));
            wait_milli_sec += 100;
        }

        assert_eq!(
            THREAD_PRIORITY_VERIFY_RESULT
                .lock()
                .as_ref()
                .unwrap()
                .to_string(),
            THREAD_PRIORITY_VERIFY_SUCCESS
        );
        assert!(THREAD_PRIORITY_VERIFY_DONE.load(Ordering::Relaxed));
    }

    // this test is to test the event reader thread, it reads events from the events folder and send to wire server
    // it requires more threads to run server and client
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_event_reader_thread() {
        let mut temp_dir = env::temp_dir();
        temp_dir.push("test_event_reader_thread");

        _ = fs::remove_dir_all(&temp_dir);

        let mut log_dir = temp_dir.to_path_buf();
        log_dir.push("Logs");
        let mut events_dir = temp_dir.to_path_buf();
        events_dir.push("Events");

        logger_manager::init_logger(
            logger::AGENT_LOGGER_KEY.to_string(), // production code uses 'Agent_Log' to write.
            log_dir.clone(),
            "logger_key".to_string(),
            10 * 1024 * 1024,
            20,
        );
        let shared_state = SharedState::new();

        // start wire_server listener
        let ip = "127.0.0.1";
        let port = 7071u16;
        telemetry_wrapper::set_mock_server_ip(shared_state.clone(), ip.to_string());
        telemetry_wrapper::set_mock_server_port(shared_state.clone(), port);

        key_keeper_wrapper::set_key(shared_state.clone(), Key::empty());
        let cloned_shared_state = shared_state.clone();
        tokio::spawn(async move {
            let _ = server_mock::start(ip.to_string(), port, cloned_shared_state.clone()).await;
        });
        tokio::time::sleep(Duration::from_millis(100)).await;

        println!("start update_vm_meta_data");
        match update_vm_meta_data(shared_state.clone()).await {
            Ok(()) => {
                logger::write("Success updated the vm metadata.".to_string());
            }
            Err(e) => {
                logger::write_warning(format!("Failed to read vm metadata with error {}.", e));
            }
        }

        // Write 10 events to events dir
        let message = r#"{\"method\":\"GET\",\"url\":\"/machine/37569ad2-69a3-44fd-b653-813e62a177cf/68938c06%2D5233%2D4ff9%2Da173%2D0ac0a2754f8a.%5FWS2022?comp=config&type=hostingEnvironmentConfig&incarnation=2\",\"ip\":\"168.63.129.16\",\"port\":80,\"userId\":999,\"userName\":\"WS2022$\",\"processName\":\"C:\\\\WindowsAzure\\\\GuestAgent_2.7.41491.1071_2023-03-02_185502\\\\WindowsAzureGuestAgent.exe\",\"runAsElevated\":true,\"responseStatus\":\"200 OK\",\"elapsedTime\":8}"#;
        let mut events: Vec<Event> = Vec::new();
        for _ in [0; 10] {
            events.push(Event::new(
                "Informational".to_string(),
                message.to_string(),
                "test_deserialize_events_from_file".to_string(),
                "test_deserialize_events_from_file".to_string(),
            ));
        }
        misc_helpers::try_create_folder(events_dir.to_path_buf()).unwrap();
        let mut file_path = events_dir.to_path_buf();
        file_path.push(format!("{}.json", misc_helpers::get_date_time_unix_nano()));
        misc_helpers::json_write_to_file(&events, file_path.to_path_buf()).unwrap();

        // Check the events processed
        let files = misc_helpers::get_files(&events_dir).unwrap();
        println!("Get '{}' event files.", files.len());
        let events_read = process_events_and_clean(files, shared_state.clone()).await;

        //Should be 10 events written and read into events Vector
        assert_eq!(events_read, 10);

        _ = fs::remove_dir_all(&temp_dir);
        telemetry_wrapper::reset_mock_server(shared_state.clone());
        server_mock::stop(ip.to_string(), port, shared_state.clone());
    }
}
